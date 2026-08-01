//! Poll-based completion, optionally accelerated by a loopback wake-up.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::bail;
use crates_io::{Error as RegistryError, Registry};

use crate::util::network::http_async;
use crate::util::{Progress, ProgressStyle};
use crate::{CargoResult, GlobalContext};

use super::super::RegistryClient;
use super::callback::CallbackListener;
use super::display::{detail_for_user, essential_note};
use super::preflight::{PendingAuthorization, validate_lifetime, validate_receive_lease_secs};
use super::retry::{clamp_poll_interval, parse_retry_after, transient_poll_delay};

pub(super) fn wait_for_authorization(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
    detail: &str,
    listener: Option<&CallbackListener>,
) -> CargoResult<Option<Duration>> {
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
        return wait_for_callback(gctx, registry, pending, detail, listener, timeout);
    }
    wait_for_ready(gctx, registry, pending, detail, timeout)
}

fn wait_for_callback(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
    detail: &str,
    listener: &CallbackListener,
    timeout: Duration,
) -> CargoResult<Option<Duration>> {
    let started = Instant::now();
    let mut deadline = started + timeout;
    let mut interval = clamp_poll_interval(pending.recommended_poll_interval_secs);
    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for callback or registry authorization")?;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match listener.receiver.recv_timeout(remaining.min(interval)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {
                match poll_once(registry, pending)? {
                    PollResult::Ready(receive_lease) => return ready(gctx, receive_lease),
                    PollResult::Pending(expires_in, recommended) => {
                        deadline = deadline.min(Instant::now() + expires_in);
                        interval = clamp_poll_interval(recommended);
                    }
                    PollResult::Transient(retry_after) => {
                        interval = transient_poll_delay(interval, retry_after, deadline);
                    }
                }
                progress.tick_now(
                    started.elapsed().as_secs().min(max as u64) as usize,
                    max,
                    "for registry authorization",
                )?;
                if Instant::now() >= deadline {
                    bail!("timed out waiting for registry authorization; {detail}");
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return wait_for_ready(
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

fn wait_for_ready(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
    detail: &str,
    timeout: Duration,
) -> CargoResult<Option<Duration>> {
    let started = Instant::now();
    let mut deadline = started + timeout;
    let mut interval = clamp_poll_interval(pending.recommended_poll_interval_secs);
    let max = timeout.as_secs().max(1) as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for registry authorization")?;

    loop {
        progress.tick_now(
            started.elapsed().as_secs().min(max as u64) as usize,
            max,
            "for registry authorization",
        )?;

        match poll_once(registry, pending)? {
            PollResult::Ready(receive_lease) => return ready(gctx, receive_lease),
            PollResult::Pending(expires_in, recommended) => {
                deadline = deadline.min(Instant::now() + expires_in);
                interval = clamp_poll_interval(recommended);
            }
            PollResult::Transient(retry_after) => {
                interval = transient_poll_delay(interval, retry_after, deadline);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for registry authorization; {detail}");
        }
        std::thread::sleep(interval.min(remaining));
    }
}

fn ready(gctx: &GlobalContext, receive_lease: Option<Duration>) -> CargoResult<Option<Duration>> {
    gctx.shell()
        .note("registry authorization ready; continuing")?;
    Ok(receive_lease)
}

enum PollResult {
    Pending(Duration, Option<u64>),
    Ready(Option<Duration>),
    Transient(Option<Duration>),
}

fn poll_once(
    registry: &mut Registry<RegistryClient<'_>>,
    pending: &PendingAuthorization,
) -> CargoResult<PollResult> {
    let status = match registry.poll_mutation_authorization(&pending.poll_url) {
        Ok(status) => status,
        Err(RegistryError::InvalidMutationAuthorizationPollUrl {
            poll_url,
            registry_host,
        }) => bail!(
            "refusing to poll mutation authorization at `{poll_url}`; \
             URL must use the same origin as the registry API ({registry_host})"
        ),
        Err(RegistryError::InvalidMutationAuthorizationPollRedirect { poll_url, location }) => {
            bail!(
                "refusing to follow mutation-authorization poll redirect from `{poll_url}`{}",
                location.map_or_else(String::new, |value| format!(" to `{value}`"))
            )
        }
        Err(RegistryError::Code { code, .. } | RegistryError::Api { code, .. })
            if code == http::StatusCode::NOT_FOUND =>
        {
            bail!("mutation authorization record was not found")
        }
        Err(RegistryError::Transport(error @ http_async::Error::ResponseBodyTooLarge { .. })) => {
            return Err(RegistryError::Transport(error).into());
        }
        Err(RegistryError::Transport(_) | RegistryError::Timeout(_)) => {
            return Ok(PollResult::Transient(None));
        }
        Err(
            RegistryError::Code { code, headers, .. } | RegistryError::Api { code, headers, .. },
        ) if is_transient(code) => {
            return Ok(PollResult::Transient(parse_retry_after(code, &headers)));
        }
        Err(error) => return Err(error.into()),
    };

    match status.status.as_str() {
        "ready" => {
            if status.detail.is_some()
                || status.challenge_expires_in.is_some()
                || status.recommended_poll_interval_secs.is_some()
            {
                bail!("ready poll included fields from another status");
            }
            validate_lifetime("grant_expires_in", status.grant_expires_in)?;
            let lease =
                validate_receive_lease_secs(status.receive_lease_secs, pending.idempotent_final)?;
            Ok(PollResult::Ready(lease))
        }
        "pending" => {
            if status.detail.is_some()
                || status.grant_expires_in.is_some()
                || status.receive_lease_secs.is_some()
            {
                bail!("pending poll included fields from another status");
            }
            Ok(PollResult::Pending(
                Duration::from_secs(validate_lifetime(
                    "challenge_expires_in",
                    status.challenge_expires_in,
                )?),
                status.recommended_poll_interval_secs,
            ))
        }
        "denied" | "expired" => {
            if status.challenge_expires_in.is_some()
                || status.grant_expires_in.is_some()
                || status.receive_lease_secs.is_some()
                || status.recommended_poll_interval_secs.is_some()
            {
                bail!("{} poll included fields from another status", status.status);
            }
            let detail = status
                .detail
                .map(|value| detail_for_user(&value, registry.host()))
                .transpose()?
                .map(|value| format!("\n{value}"))
                .unwrap_or_default();
            bail!("registry authorization was {}{detail}", status.status)
        }
        _ => bail!(
            "unexpected mutation-authorization status: {}",
            status.status
        ),
    }
}

fn is_transient(code: http::StatusCode) -> bool {
    matches!(
        code,
        http::StatusCode::REQUEST_TIMEOUT
            | http::StatusCode::TOO_EARLY
            | http::StatusCode::TOO_MANY_REQUESTS
            | http::StatusCode::INTERNAL_SERVER_ERROR
            | http::StatusCode::BAD_GATEWAY
            | http::StatusCode::SERVICE_UNAVAILABLE
            | http::StatusCode::GATEWAY_TIMEOUT
    )
}
