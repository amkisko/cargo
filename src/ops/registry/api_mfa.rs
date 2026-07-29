//! Handle registry API MFA challenges for publish / yank / owners.
//!
//! When a registry returns an error with `errors[].id == "mfa_required"`, Cargo
//! prints the verification URL, polls until the challenge is acknowledged, then
//! retries. See the registry web API docs for the wire format.

use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use crates_io::Error as RegistryError;
use crates_io::MfaRequired;
use crates_io::Registry;
use jiff::Timestamp;

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

/// Runs a mutating registry call, completing MFA handshakes and retrying as needed.
pub(super) fn with_api_mfa_retry<T, F>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
{
    let mut handshakes = 0u32;
    loop {
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
                wait_for_api_mfa(gctx, registry, &mfa)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

fn wait_for_api_mfa(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mfa: &MfaRequired,
) -> CargoResult<()> {
    gctx.shell()
        .note("API MFA required; complete verification in your browser, then Cargo will retry")?;
    gctx.shell().status(
        "Verifying",
        format!("please visit {}", mfa.verification_url),
    )?;

    let timeout = timeout_from_expires_at(mfa.expires_at.as_deref());
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
        ", or authorize for 15 minutes under Settings → API MFA on crates.io"
    } else {
        ", or authorize MFA with your registry"
    }
}
