//! Handle registry API MFA challenges for publish / yank / owners.
//!
//! When a registry returns `errors[].id == "mfa_required"`, Cargo prefers a
//! RubyGems-style localhost OTP callback when it can bind `127.0.0.1`, and falls
//! back to polling `poll_url` until acknowledged. See the registry web API docs.

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use crates_io::ApiMfaHeaders;
use crates_io::Error as RegistryError;
use crates_io::MfaRequired;
use crates_io::Registry;
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
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Fastest allowed poll rate (avoids busy-loops from `recommended_poll_interval_secs: 0`).
const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Slowest allowed poll rate (avoids malicious registries hanging cargo with huge intervals).
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// Fallback MFA ceremony timeout when `expires_at` is missing or unparsable.
const DEFAULT_MFA_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Cap how many MFA handshakes a single mutate call may perform.
const MAX_MFA_HANDSHAKES: u32 = 3;
/// Maximum time a single localhost callback connection may remain incomplete.
const CALLBACK_IO_TIMEOUT: Duration = Duration::from_secs(1);
/// Maximum accepted HTTP request-line size for localhost callbacks.
const MAX_CALLBACK_REQUEST_LINE_BYTES: usize = 4 * 1024;
/// Maximum combined HTTP header size for localhost callbacks.
const MAX_CALLBACK_HEADER_BYTES: usize = 16 * 1024;
/// Maximum individual HTTP header-line size for localhost callbacks.
const MAX_CALLBACK_HEADER_LINE_BYTES: usize = 8 * 1024;
/// Accepted OTP length range for registry implementations.
const MIN_OTP_LENGTH: usize = 8;
const MAX_OTP_LENGTH: usize = 128;
/// Env override so tests / demos can force the localhost OTP path without a TTY.
const PREFER_LOCALHOST_ENV: &str = "CARGO_API_MFA_PREFER_LOCALHOST";
/// Env override so tests can exercise the interactive handshake (poll or localhost)
/// when stdin is not a TTY / `CI` is set.
const INTERACTIVE_ENV: &str = "CARGO_API_MFA_INTERACTIVE";

/// Runs a mutating registry call, completing MFA handshakes and retrying as needed.
pub(super) fn with_api_mfa_retry<T, F>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
{
    let mut listener = maybe_start_otp_listener(gctx);
    let mut otp: Option<String> = None;
    let mut handshakes = 0u32;

    let result = (|| {
        loop {
            registry.set_api_mfa_headers(ApiMfaHeaders {
                port: listener.as_ref().map(|l| l.port),
                callback_secret: listener.as_ref().map(|l| l.callback_secret.clone()),
                otp: otp.clone(),
            });
            match op(registry) {
                Ok(value) => return Ok(value),
                Err(RegistryError::MfaRequired(mfa)) => {
                    handshakes += 1;
                    if handshakes > MAX_MFA_HANDSHAKES {
                        bail!(
                            "exceeded {MAX_MFA_HANDSHAKES} API MFA handshake attempts; \
                             visit {} and retry, or authorize MFA with your registry",
                            mfa.verification_url
                        );
                    }
                    if is_noninteractive_mfa(gctx) {
                        bail!(
                            "API MFA required but Cargo is running non-interactively; \
                             visit {} from an interactive session, use Trusted Publishing{}",
                            mfa.verification_url,
                            timeout_hint(registry)
                        );
                    }
                    otp = wait_for_api_mfa(gctx, registry, &mfa, listener.as_ref())?;
                }
                Err(err) => return Err(err.into()),
            }
        }
    })();

    registry.clear_api_mfa_headers();
    if let Some(listener) = listener.take() {
        listener.shutdown();
    }
    result
}

fn wait_for_api_mfa(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mfa: &MfaRequired,
    listener: Option<&OtpListener>,
) -> CargoResult<Option<String>> {
    gctx.shell()
        .note("API MFA required; complete verification in your browser, then Cargo will retry")?;
    let context = mfa_context_label(mfa);
    gctx.shell().status(
        "Verifying",
        format!("please visit {}{context}", mfa.verification_url),
    )?;

    let timeout = timeout_from_expires_at(mfa.expires_at.as_deref());
    // When a localhost port was advertised (`Crates-MFA-Port`), the registry
    // skips the scoped grant — poll-then-retry alone cannot finish the mutate.
    if let Some(listener) = listener {
        let otp = wait_for_localhost_otp(gctx, listener, timeout)?.ok_or_else(|| {
            anyhow::anyhow!(
                "timed out waiting for API MFA OTP on localhost:{}; \
                 visit {} and retry{}",
                listener.port,
                mfa.verification_url,
                timeout_hint(registry)
            )
        })?;
        gctx.shell()
            .note("API MFA OTP received; retrying request")?;
        return Ok(Some(otp));
    }

    wait_for_poll_ack(gctx, registry, mfa, timeout)?;
    Ok(None)
}

fn wait_for_localhost_otp(
    gctx: &GlobalContext,
    listener: &OtpListener,
    timeout: Duration,
) -> CargoResult<Option<String>> {
    let started = Instant::now();
    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for MFA OTP on localhost")?;

    loop {
        let elapsed = started.elapsed();
        if elapsed > timeout {
            return Ok(None);
        }
        let remaining = timeout.saturating_sub(elapsed);
        let wait = remaining.min(Duration::from_millis(200));
        match listener.receiver.recv_timeout(wait) {
            Ok(otp) => return Ok(Some(otp)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                progress.tick_now(
                    elapsed.as_secs().min(max as u64) as usize,
                    max,
                    "for MFA OTP on localhost",
                )?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("API MFA localhost listener closed unexpectedly");
            }
        }
    }
}

fn wait_for_poll_ack(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mfa: &MfaRequired,
    timeout: Duration,
) -> CargoResult<()> {
    let started = Instant::now();
    let mut interval = clamp_poll_interval(mfa.recommended_poll_interval_secs);

    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for MFA acknowledgment")?;

    loop {
        let elapsed = started.elapsed();
        if elapsed > timeout {
            bail!(
                "timed out waiting for API MFA acknowledgment; \
                 visit {} and retry{}",
                mfa.verification_url,
                timeout_hint(registry)
            );
        }
        let sleep_for = interval.min(timeout.saturating_sub(elapsed));
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }

        let elapsed = started.elapsed();
        if elapsed > timeout {
            bail!(
                "timed out waiting for API MFA acknowledgment; \
                 visit {} and retry{}",
                mfa.verification_url,
                timeout_hint(registry)
            );
        }
        progress.tick_now(
            elapsed.as_secs().min(max as u64) as usize,
            max,
            "for MFA acknowledgment",
        )?;

        let status = match registry.poll_mfa_challenge(&mfa.poll_url) {
            Ok(status) => status,
            Err(RegistryError::InvalidMfaPollUrl {
                poll_url,
                registry_host,
            }) => {
                bail!(
                    "refusing to poll MFA status at `{poll_url}`; \
                     URL must use the same origin as the registry API ({registry_host})"
                );
            }
            Err(RegistryError::InvalidMfaPollRedirect { poll_url, location }) => {
                bail!(
                    "refusing to follow MFA poll redirect from `{poll_url}`{}",
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
                    "API MFA challenge expired or was not found; \
                     visit {} and retry the original command",
                    mfa.verification_url
                );
            }
            Err(err) => return Err(err.into()),
        };

        if status.recommended_poll_interval_secs.is_some() {
            interval = clamp_poll_interval(status.recommended_poll_interval_secs);
        }

        let acknowledged = status.status == "acknowledged" || status.acknowledged;
        if acknowledged {
            gctx.shell()
                .note("API MFA acknowledged; retrying request")?;
            return Ok(());
        }
        match status.status.as_str() {
            "pending" => continue,
            other => bail!("unexpected API MFA challenge status: {other}"),
        }
    }
}

fn maybe_start_otp_listener(gctx: &GlobalContext) -> Option<OtpListener> {
    if !prefer_localhost_otp(gctx) {
        return None;
    }
    match OtpListener::bind() {
        Ok(listener) => Some(listener),
        Err(err) => {
            let _ = gctx.shell().verbose(|s| {
                s.note(format!(
                    "could not bind API MFA localhost OTP listener ({err}); using poll fallback"
                ))
            });
            None
        }
    }
}

fn prefer_localhost_otp(gctx: &GlobalContext) -> bool {
    if gctx.get_env_os(PREFER_LOCALHOST_ENV).is_some() {
        return true;
    }
    // Auto-bind localhost only on a real interactive TTY outside CI.
    std::io::stdin().is_terminal() && !is_ci_env(gctx)
}

/// Non-interactive contexts must not sit on the MFA poll / localhost deadline.
///
/// Heuristics: `CI=true`/`CI=1`, or stdin is not a terminal. Tests and demos can
/// set `CARGO_API_MFA_INTERACTIVE` or `CARGO_API_MFA_PREFER_LOCALHOST` to opt in.
fn is_noninteractive_mfa(gctx: &GlobalContext) -> bool {
    if gctx.get_env_os(INTERACTIVE_ENV).is_some() || gctx.get_env_os(PREFER_LOCALHOST_ENV).is_some()
    {
        return false;
    }
    is_ci_env(gctx) || !std::io::stdin().is_terminal()
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

fn mfa_context_label(mfa: &MfaRequired) -> String {
    match (mfa.operation.as_deref(), mfa.crate_name.as_deref()) {
        (Some(op), Some(krate)) => format!(" ({op} {krate})"),
        (Some(op), None) => format!(" ({op})"),
        (None, Some(krate)) => format!(" ({krate})"),
        (None, None) => String::new(),
    }
}

fn clamp_poll_interval(recommended_secs: Option<u64>) -> Duration {
    recommended_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
        .clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

fn timeout_from_expires_at(expires_at: Option<&str>) -> Duration {
    let Some(expires_at) = expires_at else {
        return DEFAULT_MFA_TIMEOUT;
    };
    let Ok(expires) = expires_at.parse::<Timestamp>() else {
        return DEFAULT_MFA_TIMEOUT;
    };
    let remaining = expires.duration_since(Timestamp::now());
    if remaining.is_negative() || remaining.as_secs() <= 0 {
        // Nearly/already expired: still allow one poll attempt.
        return Duration::from_secs(1);
    }
    Duration::from_secs(remaining.as_secs() as u64).min(DEFAULT_MFA_TIMEOUT)
}

fn timeout_hint(registry: &Registry<RegistryClient<'_>>) -> &'static str {
    if registry.host_is_crates_io() {
        "; restart the exact command to create a fresh challenge"
    } else {
        ", or authorize MFA with your registry"
    }
}

/// Short-lived `127.0.0.1` HTTP listener that accepts a one-shot OTP callback.
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
            bail!("API MFA localhost port {port} is below the registry minimum (1024)");
        }

        let (tx, rx) = mpsc::channel();
        let callback_secret = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let done = Arc::new(AtomicBool::new(false));
        let done_thread = done.clone();
        let thread = thread::spawn(move || {
            run_otp_listener(listener, tx, done_thread);
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

fn run_otp_listener(listener: TcpListener, tx: mpsc::Sender<String>, done: Arc<AtomicBool>) {
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
        match read_otp_from_request(stream) {
            Some(otp) => {
                let _ = tx.send(otp);
                break;
            }
            None => continue,
        }
    }
}

fn read_otp_from_request(stream: TcpStream) -> Option<String> {
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
            (MIN_OTP_LENGTH..=MAX_OTP_LENGTH).contains(&otp.len())
                && otp
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })?;

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
    fn localhost_listener_accepts_valid_otp() {
        let listener = OtpListener::bind().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            stream,
            "GET /?code=TestOtp1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();

        assert_eq!(
            listener
                .receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            "TestOtp1"
        );
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: image/svg+xml\r\n"));
        listener.shutdown();
    }

    #[test]
    fn localhost_listener_ignores_invalid_otp() {
        let listener = OtpListener::bind().unwrap();
        let mut invalid = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            invalid,
            "GET /?code=short HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        drop(invalid);

        let mut valid = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            valid,
            "GET /?code=TestOtp2 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        .unwrap();

        assert_eq!(
            listener
                .receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap(),
            "TestOtp2"
        );
        listener.shutdown();
    }

    #[test]
    fn localhost_listener_shutdown_is_bounded_for_partial_request() {
        let listener = OtpListener::bind().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(stream, "GET /?code=TestOtp3").unwrap();
        std::thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        listener.shutdown();
        assert!(
            started.elapsed() < CALLBACK_IO_TIMEOUT + Duration::from_secs(1),
            "listener shutdown exceeded callback I/O timeout"
        );
    }
}
