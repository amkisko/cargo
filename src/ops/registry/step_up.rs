//! Handle registry interactive step-up challenges for publish, yank, and owner operations.
//!
//! When a registry returns `errors[].id == "step_up_required"`, Cargo prefers a localhost proof
//! callback when it can bind `127.0.0.1`, and falls back to polling `poll_url` until acknowledged.
//! Callback challenges remain pollable, so either channel can finish the handshake. See the
//! registry web API docs.

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use crates_io::Error as RegistryError;
use crates_io::Registry;
use crates_io::StepUpHeaders;
use crates_io::StepUpRequired;
use jiff::Timestamp;
use rand::distr::{Alphanumeric, SampleString};
use url::Url;

use crate::CargoResult;
use crate::GlobalContext;
use crate::util::Progress;
use crate::util::ProgressStyle;
use crate::util::network::http_async;

use super::RegistryClient;

/// Default poll interval when the registry omits `recommended_poll_interval_secs`.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Fastest allowed poll rate (avoids busy-loops from `recommended_poll_interval_secs: 0`).
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Slowest allowed poll rate (avoids malicious registries hanging cargo with huge intervals).
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// Fallback step-up ceremony timeout when `expires_at` is missing or unparsable.
const DEFAULT_STEP_UP_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Cap how many step-up handshakes a single mutate call may perform.
const MAX_STEP_UP_HANDSHAKES: u32 = 3;
/// Maximum time a single localhost callback connection may remain incomplete.
const CALLBACK_IO_TIMEOUT: Duration = Duration::from_secs(1);
/// Maximum accepted HTTP request-line size for localhost callbacks.
const MAX_CALLBACK_REQUEST_LINE_BYTES: usize = 4 * 1024;
/// Maximum combined HTTP header size for localhost callbacks.
const MAX_CALLBACK_HEADER_BYTES: usize = 16 * 1024;
/// Maximum individual HTTP header-line size for localhost callbacks.
const MAX_CALLBACK_HEADER_LINE_BYTES: usize = 8 * 1024;
/// Accepted proof length range for registry implementations.
const MIN_PROOF_LENGTH: usize = 22;
const MAX_PROOF_LENGTH: usize = 128;
/// Env override so tests / demos can force the localhost OTP path without a TTY.
const PREFER_LOCALHOST_ENV: &str = "CARGO_STEP_UP_PREFER_LOCALHOST";
/// Env override so tests can exercise the interactive handshake (poll or localhost)
/// when stdin is not a TTY / `CI` is set.
const INTERACTIVE_ENV: &str = "CARGO_STEP_UP_INTERACTIVE";
/// Selects `auto`, `localhost`, `poll`, or `disabled` completion behavior.
const CHANNEL_ENV: &str = "CARGO_REGISTRY_STEP_UP_CHANNEL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StepUpChannel {
    Auto,
    Localhost,
    Poll,
    Disabled,
}

/// Runs a mutating registry call, completing step-up handshakes and retrying as needed.
pub(super) fn with_step_up_retry<T, F>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
{
    let channel = step_up_channel(gctx)?;
    let mut listener = maybe_start_otp_listener(gctx, channel);
    let mut proof: Option<String> = None;
    let mut handshakes = 0u32;

    let result = (|| {
        loop {
            registry.set_step_up_headers(StepUpHeaders {
                port: listener.as_ref().map(|l| l.port),
                callback_secret: listener.as_ref().map(|l| l.callback_secret.clone()),
                proof: proof.clone(),
            });
            match op(registry) {
                Ok(value) => return Ok(value),
                Err(RegistryError::StepUpRequired(step_up)) => {
                    validate_step_up_url(registry, &step_up)?;
                    let detail = detail_for_user(
                        &step_up.detail,
                        registry.host(),
                        listener
                            .as_ref()
                            .map(|listener| listener.callback_secret.as_str()),
                    )?;
                    handshakes += 1;
                    if handshakes > MAX_STEP_UP_HANDSHAKES {
                        bail!(
                            "exceeded {MAX_STEP_UP_HANDSHAKES} step-up handshake attempts; \
                             {}",
                            detail
                        );
                    }
                    if channel == StepUpChannel::Disabled {
                        bail!(
                            "additional authentication is required but step-up interaction is \\
                             disabled by {CHANNEL_ENV}; {}",
                            detail
                        );
                    }
                    if is_noninteractive_step_up(gctx, channel) {
                        bail!(
                            "additional authentication is required but Cargo is running \
                             non-interactively; {}",
                            detail
                        );
                    }
                    proof = wait_for_step_up(
                        gctx,
                        registry,
                        &step_up,
                        &detail,
                        listener.as_ref(),
                    )?;
                }
                Err(err) => return Err(err.into()),
            }
        }
    })();

    registry.clear_step_up_headers();
    if let Some(listener) = listener.take() {
        listener.shutdown();
    }
    result
}

fn wait_for_step_up(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    step_up: &StepUpRequired,
    detail: &str,
    listener: Option<&OtpListener>,
) -> CargoResult<Option<String>> {
    gctx.shell().note(detail)?;

    let timeout = timeout_from_expires_at(step_up.expires_at.as_deref());
    if let Some(listener) = listener {
        return wait_for_callback_or_poll(
            gctx,
            registry,
            step_up,
            detail,
            listener,
            timeout,
        );
    }

    wait_for_poll_ack(gctx, registry, step_up, detail, timeout)?;
    Ok(None)
}

/// Adds client-held callback state to the first same-origin URL in the
/// registry's human-readable instructions.
fn detail_for_user(
    detail: &str,
    registry_host: &str,
    callback_secret: Option<&str>,
) -> CargoResult<String> {
    let Some(callback_secret) = callback_secret else {
        return Ok(detail.to_owned());
    };

    for word in detail.split_whitespace() {
        let candidate = word.trim_matches(|character: char| {
            matches!(
                character,
                '(' | ')' | '[' | ']' | '<' | '>' | ',' | ';' | '.' | '!'
            )
        });
        let Ok(mut url) = Url::parse(candidate) else {
            continue;
        };
        if !crates_io::url_shares_origin_with_registry(candidate, registry_host) {
            continue;
        }
        if url.fragment().is_some() {
            bail!("step-up instruction URL must not contain a fragment");
        }
        let fragment = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("callback_secret", callback_secret)
            .finish();
        url.set_fragment(Some(&fragment));
        return Ok(detail.replacen(candidate, url.as_str(), 1));
    }

    Ok(detail.to_owned())
}

fn validate_step_up_url(
    registry: &Registry<RegistryClient<'_>>,
    step_up: &StepUpRequired,
) -> CargoResult<()> {
    let registry_origin = registry.host().trim_end_matches('/');
    if !crates_io::url_shares_origin_with_registry(&step_up.poll_url, registry.host()) {
        bail!(
            "refusing to poll step-up status at `{}`; URL must use the same origin as the registry API ({})",
            step_up.poll_url,
            registry_origin
        );
    }
    Ok(())
}

fn wait_for_callback_or_poll(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    step_up: &StepUpRequired,
    detail: &str,
    listener: &OtpListener,
    timeout: Duration,
) -> CargoResult<Option<String>> {
    let started = Instant::now();
    let mut interval = clamp_poll_interval(step_up.recommended_poll_interval_secs);
    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for callback or step-up acknowledgment")?;

    loop {
        let elapsed = started.elapsed();
        if elapsed > timeout {
            bail!(
                "timed out waiting for callback or step-up acknowledgment; {}",
                detail
            );
        }
        let remaining = timeout.saturating_sub(elapsed);
        match listener.receiver.recv_timeout(remaining.min(interval)) {
            Ok(otp) => {
                gctx.shell()
                    .note("step-up proof received; retrying request")?;
                return Ok(Some(otp));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let (acknowledged, recommended_interval) = poll_step_up_once(registry, step_up)?;
                if acknowledged {
                    gctx.shell()
                        .note("step-up acknowledged; retrying request")?;
                    return Ok(None);
                }
                if recommended_interval.is_some() {
                    interval = clamp_poll_interval(recommended_interval);
                }
                let elapsed = started.elapsed();
                progress.tick_now(
                    elapsed.as_secs().min(max as u64) as usize,
                    max,
                    "for callback or step-up acknowledgment",
                )?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                wait_for_poll_ack(
                    gctx,
                    registry,
                    step_up,
                    detail,
                    timeout.saturating_sub(elapsed),
                )?;
                return Ok(None);
            }
        }
    }
}

fn wait_for_poll_ack(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    step_up: &StepUpRequired,
    detail: &str,
    timeout: Duration,
) -> CargoResult<()> {
    let started = Instant::now();
    let mut interval = clamp_poll_interval(step_up.recommended_poll_interval_secs);

    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for step-up acknowledgment")?;

    loop {
        let elapsed = started.elapsed();
        if elapsed > timeout {
            bail!(
                "timed out waiting for step-up acknowledgment; {}",
                detail
            );
        }
        let sleep_for = interval.min(timeout.saturating_sub(elapsed));
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }

        let elapsed = started.elapsed();
        if elapsed > timeout {
            bail!(
                "timed out waiting for step-up acknowledgment; {}",
                detail
            );
        }
        progress.tick_now(
            elapsed.as_secs().min(max as u64) as usize,
            max,
            "for step-up acknowledgment",
        )?;

        let (acknowledged, recommended_interval) = poll_step_up_once(registry, step_up)?;
        if recommended_interval.is_some() {
            interval = clamp_poll_interval(recommended_interval);
        }
        if acknowledged {
            gctx.shell()
                .note("step-up acknowledged; retrying request")?;
            return Ok(());
        }
    }
}

fn poll_step_up_once(
    registry: &mut Registry<RegistryClient<'_>>,
    step_up: &StepUpRequired,
) -> CargoResult<(bool, Option<u64>)> {
    let status = match registry.poll_step_up_challenge(&step_up.poll_url) {
        Ok(status) => status,
        Err(RegistryError::InvalidStepUpPollUrl {
            poll_url,
            registry_host,
        }) => {
            bail!(
                "refusing to poll step-up status at `{poll_url}`; \
                 URL must use the same origin as the registry API ({registry_host})"
            );
        }
        Err(RegistryError::InvalidStepUpPollRedirect { poll_url, location }) => {
            bail!(
                "refusing to follow step-up poll redirect from `{poll_url}`{}",
                match location {
                    Some(loc) => format!(" to `{loc}`"),
                    None => String::new(),
                }
            );
        }
        Err(RegistryError::Code { code, .. }) | Err(RegistryError::Api { code, .. })
            if code.as_u16() == 404 =>
        {
            bail!(
                "step-up challenge expired or was not found; {}",
                step_up.detail
            );
        }
        Err(err) => return Err(err.into()),
    };

    let acknowledged = status.status == "acknowledged" || status.acknowledged;
    if !acknowledged && status.status != "pending" {
        bail!("unexpected step-up challenge status: {}", status.status);
    }
    Ok((acknowledged, status.recommended_poll_interval_secs))
}

fn maybe_start_otp_listener(gctx: &GlobalContext, channel: StepUpChannel) -> Option<OtpListener> {
    let use_localhost = match channel {
        StepUpChannel::Auto => prefer_localhost_otp(gctx),
        StepUpChannel::Localhost => true,
        StepUpChannel::Poll | StepUpChannel::Disabled => false,
    };
    if !use_localhost {
        return None;
    }
    match OtpListener::bind() {
        Ok(listener) => Some(listener),
        Err(err) => {
            let _ = gctx.shell().verbose(|s| {
                s.note(format!(
                    "could not bind step-up localhost OTP listener ({err}); using poll fallback"
                ))
            });
            None
        }
    }
}

fn step_up_channel(gctx: &GlobalContext) -> CargoResult<StepUpChannel> {
    let Some(value) = gctx.get_env(CHANNEL_ENV).ok() else {
        return Ok(StepUpChannel::Auto);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(StepUpChannel::Auto),
        "localhost" => Ok(StepUpChannel::Localhost),
        "poll" => Ok(StepUpChannel::Poll),
        "disabled" => Ok(StepUpChannel::Disabled),
        _ => bail!(
            "invalid {CHANNEL_ENV} value `{value}`; expected auto, localhost, poll, or disabled"
        ),
    }
}

fn prefer_localhost_otp(gctx: &GlobalContext) -> bool {
    if env_flag_set(gctx, PREFER_LOCALHOST_ENV) {
        return true;
    }
    // Auto-bind localhost only on a real interactive TTY outside CI.
    std::io::stdin().is_terminal() && !is_ci_env(gctx)
}

/// Non-interactive contexts must not sit on the step-up poll / localhost deadline.
///
/// Heuristics: `CI=true`/`CI=1`, or stdin is not a terminal. Tests and demos can
/// set `CARGO_STEP_UP_INTERACTIVE` / `CARGO_STEP_UP_PREFER_LOCALHOST` to opt in.
fn is_noninteractive_step_up(gctx: &GlobalContext, channel: StepUpChannel) -> bool {
    if matches!(channel, StepUpChannel::Localhost | StepUpChannel::Poll) {
        return false;
    }
    if env_flag_set(gctx, INTERACTIVE_ENV) || env_flag_set(gctx, PREFER_LOCALHOST_ENV) {
        return false;
    }
    is_ci_env(gctx) || !std::io::stdin().is_terminal()
}

fn env_flag_set(gctx: &GlobalContext, name: &str) -> bool {
    gctx.get_env_os(name).is_some()
}

fn is_ci_env(gctx: &GlobalContext) -> bool {
    matches!(
        gctx.get_env("CI")
            .ok()
            .as_deref()
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1"),
        Some(true)
    )
}

fn clamp_poll_interval(recommended_secs: Option<u64>) -> Duration {
    recommended_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
        .clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

fn timeout_from_expires_at(expires_at: Option<&str>) -> Duration {
    let Some(expires_at) = expires_at else {
        return DEFAULT_STEP_UP_TIMEOUT;
    };
    let Ok(expires) = expires_at.parse::<Timestamp>() else {
        return DEFAULT_STEP_UP_TIMEOUT;
    };
    let remaining = expires.duration_since(Timestamp::now());
    if remaining.is_negative() || remaining.as_secs() <= 0 {
        // Nearly/already expired: still allow one poll attempt.
        return Duration::from_secs(1);
    }
    Duration::from_secs(remaining.as_secs() as u64).min(DEFAULT_STEP_UP_TIMEOUT)
}

/// Short-lived `127.0.0.1` HTTP listener that accepts a one-shot proof callback.
struct OtpListener {
    port: u16,
    callback_secret: String,
    receiver: mpsc::Receiver<String>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl OtpListener {
    fn bind() -> CargoResult<Self> {
        // Bind IPv4 loopback only (matches crates.io callback `http://127.0.0.1:{port}/`).
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        if port < 1024 {
            bail!("step-up localhost port {port} is below the registry minimum (1024)");
        }

        let (tx, rx) = mpsc::channel();
        let callback_secret = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let expected_callback_secret = callback_secret.clone();
        let done = Arc::new(AtomicBool::new(false));
        let done_thread = done.clone();
        let thread = thread::spawn(move || {
            run_otp_listener(listener, tx, done_thread, &expected_callback_secret);
        });
        Ok(Self {
            port,
            callback_secret,
            receiver: rx,
            done,
            thread: Some(thread),
        })
    }

    fn shutdown(mut self) {
        self.done.store(true, Ordering::SeqCst);
        // Wake a blocking accept so the thread can exit.
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_otp_listener(
    listener: TcpListener,
    tx: mpsc::Sender<String>,
    done: Arc<AtomicBool>,
    expected_callback_secret: &str,
) {
    while !done.load(Ordering::SeqCst) {
        let Ok((stream, peer)) = listener.accept() else {
            continue;
        };
        if done.load(Ordering::SeqCst) {
            break;
        }
        if !peer.ip().is_loopback() {
            let _ = write_otp_response(&stream, 403, "forbidden");
            continue;
        }
        match read_otp_from_request(stream, expected_callback_secret) {
            Some(otp) => {
                let _ = tx.send(otp);
                break;
            }
            None => continue,
        }
    }
}

fn read_otp_from_request(stream: TcpStream, expected_callback_secret: &str) -> Option<String> {
    stream.set_read_timeout(Some(CALLBACK_IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(CALLBACK_IO_TIMEOUT)).ok()?;
    let mut reader = BufReader::new(stream);
    let request_line = read_bounded_line(&mut reader, MAX_CALLBACK_REQUEST_LINE_BYTES)?;

    // Drain headers so clients can finish the HTTP exchange.
    let mut header_bytes = 0;
    loop {
        let remaining = MAX_CALLBACK_HEADER_BYTES.checked_sub(header_bytes)?;
        let line = read_bounded_line(&mut reader, remaining.min(MAX_CALLBACK_HEADER_LINE_BYTES))?;
        header_bytes += line.len();
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    let stream = reader.into_inner();

    let request_line = std::str::from_utf8(&request_line).ok()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || method != "GET" || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        let _ = write_otp_response(&stream, 405, "method not allowed");
        return None;
    }

    let url = Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    let otp = url
        .query_pairs()
        .find(|(k, _)| k == "code" || k == "otp")
        .map(|(_, v)| v.into_owned())
        .filter(|otp| {
            (MIN_PROOF_LENGTH..=MAX_PROOF_LENGTH).contains(&otp.len())
                && otp
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })?;
    let callback_secret = url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned());
    if callback_secret.as_deref() != Some(expected_callback_secret) {
        let _ = write_otp_response(&stream, 403, "invalid callback state");
        return None;
    }

    let _ = write_otp_success_response(&stream);
    let _ = stream.shutdown(Shutdown::Both);
    Some(otp)
}

fn read_bounded_line(reader: &mut impl BufRead, max_bytes: usize) -> Option<Vec<u8>> {
    if max_bytes == 0 {
        return None;
    }
    let mut line = Vec::new();
    let bytes_read = reader
        .take(max_bytes.saturating_add(1) as u64)
        .read_until(b'\n', &mut line)
        .ok()?;
    if bytes_read == 0 || bytes_read > max_bytes || !line.ends_with(b"\n") {
        return None;
    }
    Some(line)
}

fn write_otp_response(mut stream: &TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn write_otp_success_response(mut stream: &TcpStream) -> std::io::Result<()> {
    const BODY: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>"#;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn callback_secret_is_added_only_to_instruction_url() {
        let detail = detail_for_user(
            "Authenticate at https://registry.example/verify/stp_test.",
            "https://registry.example",
            Some("callback_secret-_"),
        )
        .unwrap();
        assert_eq!(
            detail,
            "Authenticate at https://registry.example/verify/stp_test#callback_secret=callback_secret-_."
        );
        assert_eq!(
            detail_for_user(
                "Press the registered hardware button.",
                "https://registry.example",
                None,
            )
            .unwrap(),
            "Press the registered hardware button."
        );
    }

    #[test]
    fn callback_secret_does_not_replace_a_registry_fragment() {
        let error = detail_for_user(
            "Authenticate at https://registry.example/verify/stp_test#registry-state",
            "https://registry.example",
            Some("callback_secret"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("instruction URL must not contain a fragment")
        );
    }

    #[test]
    fn localhost_listener_accepts_valid_proof() {
        let listener = OtpListener::bind().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            stream,
            "GET /?code=TestProof0123456789abcdef&state={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            listener.callback_secret
        )
        .unwrap();

        assert_eq!(
            listener
                .receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            "TestProof0123456789abcdef"
        );
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: image/svg+xml\r\n"));
        listener.shutdown();
    }

    #[test]
    fn localhost_listener_ignores_invalid_proof_or_state() {
        let listener = OtpListener::bind().unwrap();
        let mut invalid = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            invalid,
            "GET /?code=short&state={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            listener.callback_secret
        )
        .unwrap();
        drop(invalid);

        let mut wrong_state = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            wrong_state,
            "GET /?code=PoisonProof0123456789abcdef&state=0123456789abcdef0123456789abcdef HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        drop(wrong_state);

        let mut valid = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            valid,
            "GET /?code=TestProof1123456789abcdef&state={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            listener.callback_secret
        )
        .unwrap();

        assert_eq!(
            listener
                .receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            "TestProof1123456789abcdef"
        );
        listener.shutdown();
    }

    #[test]
    fn localhost_listener_shutdown_is_bounded_for_partial_request() {
        let listener = OtpListener::bind().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            stream,
            "GET /?code=TestProof2123456789abcdef&state={}",
            listener.callback_secret
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        listener.shutdown();
        assert!(
            started.elapsed() < CALLBACK_IO_TIMEOUT + Duration::from_secs(1),
            "listener shutdown exceeded callback I/O timeout"
        );
    }
}
