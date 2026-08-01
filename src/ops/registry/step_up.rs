//! Authorize exact registry mutations before sending their ordinary requests.
//!
//! A loopback callback is only a wake-up signal. Readiness comes exclusively
//! from the registry's poll-token URL, and the final request carries only the
//! mutation id in addition to its ordinary primary credential.

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
use crates_io::MutationAuthorizationResponse;
use crates_io::MutationCallback;
use crates_io::MutationDescriptor;
use crates_io::MutationHeaders;
use crates_io::Registry;
use rand::RngExt;
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
/// Maximum time a single localhost callback connection may remain incomplete.
const CALLBACK_IO_TIMEOUT: Duration = Duration::from_secs(1);
/// Maximum accepted HTTP request-line size for localhost callbacks.
const MAX_CALLBACK_REQUEST_LINE_BYTES: usize = 4 * 1024;
/// Maximum combined HTTP header size for localhost callbacks.
const MAX_CALLBACK_HEADER_BYTES: usize = 16 * 1024;
/// Maximum individual HTTP header-line size for localhost callbacks.
const MAX_CALLBACK_HEADER_LINE_BYTES: usize = 8 * 1024;
/// Env override so tests / demos can force the localhost OTP path without a TTY.
const PREFER_LOCALHOST_ENV: &str = "CARGO_STEP_UP_PREFER_LOCALHOST";
/// Env override so tests can exercise the interactive handshake (poll or localhost)
/// when stdin is not a TTY / `CI` is set.
const INTERACTIVE_ENV: &str = "CARGO_STEP_UP_INTERACTIVE";
/// Selects `auto`, `loopback`, `poll`, or `disabled` completion behavior.
const CHANNEL_ENV: &str = "CARGO_REGISTRY_MUTATION_AUTHORIZATION_CHANNEL";
const IDEMPOTENT_FINAL_EXTENSION: &str = "idempotent-final";
const LOOPBACK_CALLBACK_EXTENSION: &str = "loopback-callback";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorizationChannel {
    Auto,
    Loopback,
    Poll,
    Disabled,
}

/// Runs a registry mutation after any advertised authorization preflight.
pub(super) fn with_step_up_retry<T, F>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    reg_or_index: Option<&super::RegistryOrIndex>,
    channel_override: Option<&str>,
    descriptor: MutationDescriptor,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
{
    let channel = authorization_channel(gctx, reg_or_index, channel_override)?;
    if channel == AuthorizationChannel::Disabled {
        return op(registry).map_err(Into::into);
    }
    if registry.mutation_authorization_version_unsupported() {
        bail!("registry advertises a mutation authorization version unsupported by this Cargo");
    }
    if !registry.supports_mutation_authorization() {
        return op(registry).map_err(Into::into);
    }

    validate_step_up_transport(registry.host())?;
    with_preflight(gctx, registry, descriptor, channel, op)
}

/// Preflights an exact mutation before transmitting its ordinary request body.
fn with_preflight<T, F>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    descriptor: MutationDescriptor,
    channel: AuthorizationChannel,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
{
    let loopback_supported =
        registry.supports_mutation_authorization_extension(LOOPBACK_CALLBACK_EXTENSION);
    if channel == AuthorizationChannel::Loopback && !loopback_supported {
        bail!("registry does not advertise the `loopback-callback` authorization extension");
    }
    let idempotent_final =
        registry.supports_mutation_authorization_extension(IDEMPOTENT_FINAL_EXTENSION);
    let mut listener = maybe_start_callback_listener(gctx, channel, loopback_supported);
    let callback = listener.as_ref().map(|listener| MutationCallback {
        url: listener.url(),
    });
    let allow_pending = !is_noninteractive_authorization(gctx, channel);
    let preflight_id = random_protocol_id("pf");

    let result = (|| {
        let preflight = registry.preflight_mutation(
            &descriptor,
            &preflight_id,
            allow_pending,
            idempotent_final,
            callback.as_ref(),
        );
        let (http_status, response) = match preflight {
            Err(RegistryError::Transport(_) | RegistryError::Timeout(_)) => registry
                .preflight_mutation(
                    &descriptor,
                    &preflight_id,
                    allow_pending,
                    idempotent_final,
                    callback.as_ref(),
                )?,
            result => result?,
        };
        let (mutation_id, grant_lifetime) = match response.status.as_str() {
            "ready" if http_status == http::StatusCode::OK => {
                validate_protocol_version(&response)?;
                let grant_lifetime = Duration::from_secs(validate_lifetime(
                    "grant_expires_in",
                    response.grant_expires_in,
                )?);
                let mutation_id = response
                    .mutation_id
                    .ok_or_else(|| anyhow::format_err!("ready preflight omitted mutation_id"))?;
                validate_protocol_id("mutation_id", &mutation_id)?;
                (mutation_id, grant_lifetime)
            }
            "pending" if http_status == http::StatusCode::ACCEPTED && allow_pending => {
                let pending = validate_pending(registry, response)?;
                let detail = detail_for_user(&pending.detail, registry.host())?;
                let grant_lifetime =
                    wait_for_authorization(gctx, registry, &pending, &detail, listener.as_ref())?;
                (pending.mutation_id, grant_lifetime)
            }
            "interaction_required" if http_status == http::StatusCode::FORBIDDEN => {
                validate_interaction_required(&response)?;
                let detail = response
                    .detail
                    .as_deref()
                    .map(sanitize_step_up_detail)
                    .unwrap_or_else(|| "This operation requires registry authorization.".into());
                bail!(
                    "{detail}\nno authorization challenge was created; rerun with \
                     --registry-authorization=poll"
                );
            }
            "denied" | "expired" if http_status == http::StatusCode::OK => {
                bail!("registry authorization was {}", response.status);
            }
            status => bail!(
                "registry returned invalid mutation preflight status `{status}` with HTTP {}",
                http_status.as_u16()
            ),
        };

        registry.set_mutation_headers(MutationHeaders {
            mutation_id: Some(mutation_id),
        });

        if !idempotent_final {
            return op(registry).map_err(Into::into);
        }

        // A single bounded retry covers an interrupted or response-ambiguous
        // transport when the registry promises terminal replay.
        let retry_deadline = Instant::now() + grant_lifetime;
        match op(registry) {
            Err(error) if final_request_is_retryable(&error) => {
                let retry_after = final_request_retry_after(&error);
                let Some(delay) = bounded_retry_delay(retry_after, retry_deadline) else {
                    return Err(error.into());
                };
                if !delay.is_zero() {
                    std::thread::sleep(delay);
                }
                op(registry).map_err(Into::into)
            }
            result => result.map_err(Into::into),
        }
    })();

    registry.clear_mutation_headers();
    if let Some(listener) = listener.take() {
        listener.shutdown();
    }
    result
}

#[derive(Debug)]
struct PendingAuthorization {
    detail: String,
    mutation_id: String,
    poll_url: String,
    challenge_expires_in: u64,
    recommended_poll_interval_secs: Option<u64>,
}

fn validate_protocol_version(response: &MutationAuthorizationResponse) -> CargoResult<()> {
    if response.protocol_version != 1 {
        bail!(
            "registry returned mutation authorization protocol version {} instead of 1",
            response.protocol_version
        );
    }
    Ok(())
}

fn validate_lifetime(name: &str, value: Option<u64>) -> CargoResult<u64> {
    match value {
        Some(value @ 1..=300) => Ok(value),
        _ => bail!("{name} must be an integer from 1 through 300"),
    }
}

fn validate_protocol_id(name: &str, value: &str) -> CargoResult<()> {
    if !(22..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("{name} must be 22–128 URL-safe ASCII characters");
    }
    Ok(())
}

fn validate_pending(
    registry: &Registry<RegistryClient<'_>>,
    response: MutationAuthorizationResponse,
) -> CargoResult<PendingAuthorization> {
    validate_protocol_version(&response)?;
    let detail = response
        .detail
        .filter(|detail| !detail.is_empty())
        .ok_or_else(|| anyhow::format_err!("pending preflight omitted detail"))?;
    if detail.len() > crates_io::STEP_UP_DETAIL_MAX_BYTES {
        bail!("registry authorization instructions exceed the 8192-byte limit");
    }
    let mutation_id = response
        .mutation_id
        .ok_or_else(|| anyhow::format_err!("pending preflight omitted mutation_id"))?;
    validate_protocol_id("mutation_id", &mutation_id)?;
    let poll_url = response
        .poll_url
        .ok_or_else(|| anyhow::format_err!("pending preflight omitted poll_url"))?;
    if poll_url.len() > crates_io::STEP_UP_DETAIL_MAX_BYTES
        || !crates_io::url_shares_origin_with_registry(&poll_url, registry.host())
    {
        bail!("mutation authorization poll_url must share the registry API origin");
    }
    let challenge_expires_in =
        validate_lifetime("challenge_expires_in", response.challenge_expires_in)?;
    Ok(PendingAuthorization {
        detail,
        mutation_id,
        poll_url,
        challenge_expires_in,
        recommended_poll_interval_secs: response.recommended_poll_interval_secs,
    })
}

fn validate_interaction_required(response: &MutationAuthorizationResponse) -> CargoResult<()> {
    validate_protocol_version(response)?;
    if response.mutation_id.is_some() || response.poll_url.is_some() {
        bail!("interaction_required response created an actionable challenge");
    }
    Ok(())
}

fn wait_for_authorization(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
    detail: &str,
    listener: Option<&CallbackListener>,
) -> CargoResult<Duration> {
    essential_note(gctx, detail)?;
    essential_note(
        gctx,
        &format!(
            "Waiting up to {} seconds for registry authorization; press Ctrl-C to cancel.",
            pending.challenge_expires_in
        ),
    )?;

    let timeout = Duration::from_secs(pending.challenge_expires_in);
    if let Some(listener) = listener {
        return wait_for_callback_or_poll(gctx, registry, pending, detail, listener, timeout);
    }

    wait_for_poll_ready(gctx, registry, pending, detail, timeout)
}

fn essential_note(gctx: &GlobalContext, message: &str) -> CargoResult<()> {
    let mut shell = gctx.shell();
    if shell.verbosity() == cargo_util_terminal::Verbosity::Quiet {
        writeln!(shell.err(), "note: {message}")?;
        Ok(())
    } else {
        shell.note(message)
    }
}

fn detail_for_user(detail: &str, registry_host: &str) -> CargoResult<String> {
    if detail.len() > crates_io::STEP_UP_DETAIL_MAX_BYTES {
        bail!(
            "registry step-up instructions exceed the {}-byte limit",
            crates_io::STEP_UP_DETAIL_MAX_BYTES
        );
    }

    let detail = sanitize_step_up_detail(detail);
    let detail = label_external_instruction_urls(&detail, registry_host);
    let registry_origin = Url::parse(registry_host)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| registry_host.trim_end_matches('/').to_owned());
    Ok(format!(
        "Instructions from registry {registry_origin}:\n{detail}"
    ))
}

fn sanitize_step_up_detail(detail: &str) -> String {
    detail
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .map(|character| match character {
            '\n' => '\n',
            character if character.is_control() || is_bidi_formatting_control(character) => {
                '\u{fffd}'
            }
            character => character,
        })
        .collect()
}

fn is_bidi_formatting_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn instruction_url_candidate(word: &str) -> &str {
    word.trim().trim_matches(|character: char| {
        matches!(
            character,
            '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '\'' | '"' | ',' | ';' | '.' | '!'
        )
    })
}

fn label_external_instruction_urls(detail: &str, registry_host: &str) -> String {
    detail
        .split_inclusive(char::is_whitespace)
        .map(|word| {
            let candidate = instruction_url_candidate(word);
            let Ok(url) = Url::parse(candidate) else {
                return word.to_owned();
            };
            if !matches!(url.scheme(), "http" | "https")
                || crates_io::url_shares_origin_with_registry(candidate, registry_host)
            {
                return word.to_owned();
            }
            word.replacen(candidate, &format!("[external URL: {url}]"), 1)
        })
        .collect()
}

fn validate_step_up_transport(registry_host: &str) -> CargoResult<()> {
    let url = Url::parse(registry_host)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.scheme() != "https" && !loopback {
        bail!(
            "mutation authorization requires HTTPS for non-loopback registries; configured registry is `{registry_host}`"
        );
    }
    Ok(())
}

fn wait_for_callback_or_poll(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
    detail: &str,
    listener: &CallbackListener,
    timeout: Duration,
) -> CargoResult<Duration> {
    let started = Instant::now();
    let mut deadline = started + timeout;
    let mut interval = clamp_poll_interval(pending.recommended_poll_interval_secs);
    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for callback or step-up acknowledgment")?;

    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for registry authorization; {detail}");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match listener.receiver.recv_timeout(remaining.min(interval)) {
            Ok(()) => match poll_authorization_once(registry, pending)? {
                PollResult::Ready { grant_lifetime } => {
                    gctx.shell()
                        .note("registry authorization ready; continuing")?;
                    return Ok(grant_lifetime);
                }
                PollResult::Pending {
                    expires_in,
                    recommended_interval,
                } => {
                    deadline = deadline.min(Instant::now() + expires_in);
                    interval = clamp_poll_interval(recommended_interval);
                }
                PollResult::Transient { retry_after } => {
                    interval = transient_poll_delay(interval, retry_after, deadline);
                }
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {
                match poll_authorization_once(registry, pending)? {
                    PollResult::Ready { grant_lifetime } => {
                        gctx.shell()
                            .note("registry authorization ready; continuing")?;
                        return Ok(grant_lifetime);
                    }
                    PollResult::Pending {
                        expires_in,
                        recommended_interval,
                    } => {
                        deadline = deadline.min(Instant::now() + expires_in);
                        interval = clamp_poll_interval(recommended_interval);
                    }
                    PollResult::Transient { retry_after } => {
                        interval = transient_poll_delay(interval, retry_after, deadline);
                    }
                }
                let elapsed = started.elapsed();
                progress.tick_now(
                    elapsed.as_secs().min(max as u64) as usize,
                    max,
                    "for registry authorization",
                )?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return wait_for_poll_ready(
                    gctx,
                    registry,
                    pending,
                    detail,
                    deadline.saturating_duration_since(Instant::now()),
                );
            }
        }
    }
}

fn wait_for_poll_ready(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
    detail: &str,
    timeout: Duration,
) -> CargoResult<Duration> {
    let started = Instant::now();
    let mut deadline = started + timeout;
    let mut interval = clamp_poll_interval(pending.recommended_poll_interval_secs);

    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for step-up acknowledgment")?;

    loop {
        if Instant::now() >= deadline {
            bail!("timed out waiting for registry authorization; {detail}");
        }
        let sleep_for = interval.min(deadline.saturating_duration_since(Instant::now()));
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }

        let elapsed = started.elapsed();
        if Instant::now() >= deadline {
            bail!("timed out waiting for registry authorization; {detail}");
        }
        progress.tick_now(
            elapsed.as_secs().min(max as u64) as usize,
            max,
            "for registry authorization",
        )?;

        match poll_authorization_once(registry, pending)? {
            PollResult::Ready { grant_lifetime } => {
                gctx.shell()
                    .note("registry authorization ready; continuing")?;
                return Ok(grant_lifetime);
            }
            PollResult::Pending {
                expires_in,
                recommended_interval,
            } => {
                deadline = deadline.min(Instant::now() + expires_in);
                interval = clamp_poll_interval(recommended_interval);
            }
            PollResult::Transient { retry_after } => {
                interval = transient_poll_delay(interval, retry_after, deadline);
            }
        }
    }
}

enum PollResult {
    Pending {
        expires_in: Duration,
        recommended_interval: Option<u64>,
    },
    Ready {
        grant_lifetime: Duration,
    },
    Transient {
        retry_after: Option<Duration>,
    },
}

fn poll_authorization_once(
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
) -> CargoResult<PollResult> {
    let status = match registry.poll_mutation_authorization(&pending.poll_url) {
        Ok(status) => status,
        Err(RegistryError::InvalidStepUpPollUrl {
            poll_url,
            registry_host,
        }) => {
            bail!(
                "refusing to poll mutation authorization at `{poll_url}`; \
                 URL must use the same origin as the registry API ({registry_host})"
            );
        }
        Err(RegistryError::InvalidStepUpPollRedirect { poll_url, location }) => {
            bail!(
                "refusing to follow mutation-authorization poll redirect from `{poll_url}`{}",
                match location {
                    Some(loc) => format!(" to `{loc}`"),
                    None => String::new(),
                }
            );
        }
        Err(RegistryError::Code { code, .. }) | Err(RegistryError::Api { code, .. })
            if code.as_u16() == 404 =>
        {
            bail!("mutation authorization record was not found");
        }
        Err(RegistryError::Transport(_) | RegistryError::Timeout(_)) => {
            return Ok(PollResult::Transient { retry_after: None });
        }
        Err(
            RegistryError::Code { code, headers, .. } | RegistryError::Api { code, headers, .. },
        ) if matches!(
            code,
            http::StatusCode::REQUEST_TIMEOUT
                | http::StatusCode::TOO_EARLY
                | http::StatusCode::TOO_MANY_REQUESTS
                | http::StatusCode::INTERNAL_SERVER_ERROR
                | http::StatusCode::BAD_GATEWAY
                | http::StatusCode::SERVICE_UNAVAILABLE
                | http::StatusCode::GATEWAY_TIMEOUT
        ) =>
        {
            return Ok(PollResult::Transient {
                retry_after: parse_retry_after(code, &headers),
            });
        }
        Err(err) => return Err(err.into()),
    };

    match status.status.as_str() {
        "ready" => {
            let grant_lifetime = Duration::from_secs(validate_lifetime(
                "grant_expires_in",
                status.grant_expires_in,
            )?);
            Ok(PollResult::Ready { grant_lifetime })
        }
        "pending" => Ok(PollResult::Pending {
            expires_in: Duration::from_secs(validate_lifetime(
                "challenge_expires_in",
                status.challenge_expires_in,
            )?),
            recommended_interval: status.recommended_poll_interval_secs,
        }),
        "denied" | "expired" => {
            let detail = status
                .detail
                .map(|detail| format!(": {}", sanitize_step_up_detail(&detail)))
                .unwrap_or_default();
            bail!("registry authorization was {}{detail}", status.status);
        }
        _ => bail!(
            "unexpected mutation-authorization status: {}",
            status.status
        ),
    }
}

fn maybe_start_callback_listener(
    gctx: &GlobalContext,
    channel: AuthorizationChannel,
    loopback_supported: bool,
) -> Option<CallbackListener> {
    let use_localhost = match channel {
        AuthorizationChannel::Auto => loopback_supported && prefer_localhost_callback(gctx),
        AuthorizationChannel::Loopback => loopback_supported,
        AuthorizationChannel::Poll | AuthorizationChannel::Disabled => false,
    };
    if !use_localhost {
        return None;
    }
    match CallbackListener::bind() {
        Ok(listener) => Some(listener),
        Err(err) => {
            let _ = gctx.shell().verbose(|s| {
                s.note(format!(
                    "could not bind mutation-authorization loopback listener ({err}); using poll fallback"
                ))
            });
            None
        }
    }
}

fn authorization_channel(
    gctx: &GlobalContext,
    reg_or_index: Option<&super::RegistryOrIndex>,
    channel_override: Option<&str>,
) -> CargoResult<AuthorizationChannel> {
    let configured: String;
    let value = if let Some(value) = channel_override {
        value
    } else if let Ok(value) = gctx.get_env(CHANNEL_ENV) {
        configured = value.to_owned();
        &configured
    } else {
        let key = match reg_or_index {
            Some(super::RegistryOrIndex::Registry(name)) if name != "crates-io" => {
                format!("registries.{name}.mutation-authorization-channel")
            }
            _ => "registry.mutation-authorization-channel".to_owned(),
        };
        configured = gctx.get::<Option<String>>(&key)?.unwrap_or_default();
        &configured
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(AuthorizationChannel::Auto),
        "loopback" => Ok(AuthorizationChannel::Loopback),
        "poll" => Ok(AuthorizationChannel::Poll),
        "disabled" => Ok(AuthorizationChannel::Disabled),
        _ => bail!(
            "invalid {CHANNEL_ENV} value `{value}`; expected auto, loopback, poll, or disabled"
        ),
    }
}

fn prefer_localhost_callback(gctx: &GlobalContext) -> bool {
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
fn is_noninteractive_authorization(gctx: &GlobalContext, channel: AuthorizationChannel) -> bool {
    if matches!(
        channel,
        AuthorizationChannel::Loopback | AuthorizationChannel::Poll
    ) {
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

fn transient_poll_delay(
    previous: Duration,
    retry_after: Option<Duration>,
    deadline: Instant,
) -> Duration {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if let Some(retry_after) = retry_after
        && retry_after <= remaining
    {
        return retry_after;
    }

    let maximum = (previous * 2).min(MAX_POLL_INTERVAL);
    let maximum_millis = maximum.as_millis().max(1) as u64;
    let minimum_millis = (maximum_millis / 2).max(1);
    Duration::from_millis(rand::rng().random_range(minimum_millis..=maximum_millis))
}

fn final_request_is_retryable(error: &RegistryError<http_async::Error>) -> bool {
    match error {
        RegistryError::Transport(_) | RegistryError::Timeout(_) => true,
        RegistryError::Code { code, .. } | RegistryError::Api { code, .. } => matches!(
            *code,
            http::StatusCode::REQUEST_TIMEOUT
                | http::StatusCode::TOO_EARLY
                | http::StatusCode::TOO_MANY_REQUESTS
                | http::StatusCode::INTERNAL_SERVER_ERROR
                | http::StatusCode::BAD_GATEWAY
                | http::StatusCode::SERVICE_UNAVAILABLE
                | http::StatusCode::GATEWAY_TIMEOUT
        ),
        _ => false,
    }
}

fn final_request_retry_after(error: &RegistryError<http_async::Error>) -> Option<Duration> {
    match error {
        RegistryError::Code { code, headers, .. } | RegistryError::Api { code, headers, .. } => {
            parse_retry_after(*code, headers)
        }
        _ => None,
    }
}

fn bounded_retry_delay(retry_after: Option<Duration>, deadline: Instant) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    if let Some(retry_after) = retry_after {
        return (retry_after <= remaining).then_some(retry_after);
    }
    let maximum = remaining.min(Duration::from_millis(750));
    if maximum.is_zero() {
        return None;
    }
    let maximum_millis = maximum.as_millis().max(1) as u64;
    Some(Duration::from_millis(
        rand::rng().random_range(0..=maximum_millis),
    ))
}

fn parse_retry_after(code: http::StatusCode, headers: &[String]) -> Option<Duration> {
    if !matches!(
        code,
        http::StatusCode::TOO_MANY_REQUESTS | http::StatusCode::SERVICE_UNAVAILABLE
    ) {
        return None;
    }
    let value = headers
        .iter()
        .filter_map(|header| header.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("retry-after"))?
        .1
        .trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let retry_at = jiff::fmt::rfc2822::parse(value).ok()?;
    let milliseconds = jiff::Timestamp::now()
        .until(&retry_at)
        .ok()?
        .total(jiff::Unit::Millisecond)
        .ok()?;
    (milliseconds > 0.0).then(|| Duration::from_millis(milliseconds as u64))
}

fn random_protocol_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        Alphanumeric.sample_string(&mut rand::rng(), 32)
    )
}

/// Short-lived `127.0.0.1` listener accepting one authenticated wake-up.
struct CallbackListener {
    port: u16,
    callback_state: String,
    receiver: mpsc::Receiver<()>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CallbackListener {
    fn bind() -> CargoResult<Self> {
        // Bind IPv4 loopback only, matching the registered callback URL.
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(false)?;
        let port = listener.local_addr()?.port();
        if port < 1024 {
            bail!("loopback port {port} is below the registry minimum (1024)");
        }

        let (tx, rx) = mpsc::channel();
        let callback_state = Alphanumeric.sample_string(&mut rand::rng(), 32);
        let expected_callback_state = callback_state.clone();
        let done = Arc::new(AtomicBool::new(false));
        let done_thread = done.clone();
        let thread = thread::spawn(move || {
            run_callback_listener(listener, tx, done_thread, &expected_callback_state);
        });
        Ok(Self {
            port,
            callback_state,
            receiver: rx,
            done,
            thread: Some(thread),
        })
    }

    fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/cargo/registry-authorization?state={}",
            self.port, self.callback_state
        )
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

fn run_callback_listener(
    listener: TcpListener,
    tx: mpsc::Sender<()>,
    done: Arc<AtomicBool>,
    expected_callback_state: &str,
) {
    while !done.load(Ordering::SeqCst) {
        let Ok((stream, peer)) = listener.accept() else {
            continue;
        };
        if done.load(Ordering::SeqCst) {
            break;
        }
        if !peer.ip().is_loopback() {
            let _ = write_callback_response(&stream, 403, "forbidden");
            continue;
        }
        match read_callback_request(stream, expected_callback_state) {
            Some(()) => {
                let _ = tx.send(());
                break;
            }
            None => continue,
        }
    }
}

fn read_callback_request(stream: TcpStream, expected_callback_state: &str) -> Option<()> {
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
        let _ = write_callback_response(&stream, 405, "method not allowed");
        return None;
    }

    let url = Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != "/cargo/registry-authorization" {
        let _ = write_callback_response(&stream, 404, "not found");
        return None;
    }
    let states: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .collect();
    if states.len() != 1
        || !constant_time_eq(states[0].as_bytes(), expected_callback_state.as_bytes())
    {
        let _ = write_callback_response(&stream, 403, "invalid callback state");
        return None;
    }

    let _ = write_callback_success_response(&stream);
    let _ = stream.shutdown(Shutdown::Both);
    Some(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
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

fn write_callback_response(mut stream: &TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn write_callback_success_response(mut stream: &TcpStream) -> std::io::Result<()> {
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
    fn detail_is_plain_text_and_external_urls_are_labeled() {
        let detail = detail_for_user(
            "Run\u{1b}[31m this\u{202e} command or visit https://evil.example/login.\r\nThen continue.",
            "https://registry.example",
        )
        .unwrap();

        assert_eq!(
            detail,
            "Instructions from registry https://registry.example:\nRun�[31m this� command or visit [external URL: https://evil.example/login].\nThen continue."
        );
    }

    #[test]
    fn step_up_transport_requires_https_except_on_loopback() {
        validate_step_up_transport("https://registry.example").unwrap();
        validate_step_up_transport("http://127.0.0.1:1234").unwrap();
        validate_step_up_transport("http://[::1]:1234").unwrap();
        assert!(validate_step_up_transport("http://registry.example").is_err());
    }

    #[test]
    fn retry_after_accepts_delta_seconds_only_for_supported_statuses() {
        let headers = vec!["Retry-After: 7".to_owned()];
        assert_eq!(
            parse_retry_after(http::StatusCode::TOO_MANY_REQUESTS, &headers),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            parse_retry_after(http::StatusCode::SERVICE_UNAVAILABLE, &headers),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            parse_retry_after(http::StatusCode::BAD_GATEWAY, &headers),
            None
        );
    }

    #[test]
    fn retry_after_accepts_future_http_dates() {
        let headers = vec!["Retry-After: Wed, 21 Oct 2099 07:28:00 GMT".to_owned()];
        assert!(
            parse_retry_after(http::StatusCode::SERVICE_UNAVAILABLE, &headers)
                .is_some_and(|delay| !delay.is_zero())
        );
    }

    #[test]
    fn final_retry_does_not_outlive_the_grant() {
        let deadline = Instant::now() + Duration::from_secs(2);
        assert_eq!(
            bounded_retry_delay(Some(Duration::from_secs(3)), deadline),
            None
        );
        assert_eq!(
            bounded_retry_delay(Some(Duration::from_secs(1)), deadline),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn localhost_listener_accepts_valid_wakeup() {
        let listener = CallbackListener::bind().unwrap();
        let registered_url = Url::parse(&listener.url()).unwrap();
        assert_eq!(registered_url.host_str(), Some("127.0.0.1"));
        assert_eq!(registered_url.port(), Some(listener.port));
        assert_eq!(
            registered_url.query_pairs().collect::<Vec<_>>(),
            vec![("state".into(), listener.callback_state.as_str().into())]
        );
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            stream,
            "GET /cargo/registry-authorization?state={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            listener.callback_state
        )
        .unwrap();

        listener
            .receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: image/svg+xml\r\n"));
        listener.shutdown();
    }

    #[test]
    fn localhost_listener_ignores_invalid_path_or_state() {
        let listener = CallbackListener::bind().unwrap();
        let mut invalid = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            invalid,
            "GET /wrong?state={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            listener.callback_state
        )
        .unwrap();
        drop(invalid);

        let mut wrong_state = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            wrong_state,
            "GET /cargo/registry-authorization?state=0123456789abcdef0123456789abcdef HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\r\n"
        )
        .unwrap();
        drop(wrong_state);

        let mut valid = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            valid,
            "GET /cargo/registry-authorization?state={} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            listener.callback_state
        )
        .unwrap();

        listener
            .receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        listener.shutdown();
    }

    #[test]
    fn localhost_listener_shutdown_is_bounded_for_partial_request() {
        let listener = CallbackListener::bind().unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port)).unwrap();
        write!(
            stream,
            "GET /cargo/registry-authorization?state={}",
            listener.callback_state
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
