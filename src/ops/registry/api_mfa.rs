//! Handle crates.io-style API MFA challenges for publish / yank / owners.
//!
//! When a registry returns `403` with `errors[].id == "mfa_required"`, Cargo prints
//! the verification URL, polls until the challenge is acknowledged, then retries.

use std::time::Duration;
use std::time::Instant;

use anyhow::bail;
use crates_io::Error as RegistryError;
use crates_io::MfaRequired;
use crates_io::Registry;

use crate::CargoResult;
use crate::GlobalContext;
use crate::util::Progress;
use crate::util::ProgressStyle;
use crate::util::network::http_async;

use super::RegistryClient;

/// Default poll interval when the registry omits `recommended_poll_interval_secs`.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// MFA ceremony timeout (crates.io challenges expire after five minutes).
const MFA_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Runs a mutating registry call, completing an MFA handshake and retrying once if needed.
pub(super) fn with_api_mfa_retry<T, F>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
{
    match op(registry) {
        Ok(value) => Ok(value),
        Err(RegistryError::MfaRequired(mfa)) => {
            wait_for_api_mfa(gctx, registry, &mfa)?;
            Ok(op(registry)?)
        }
        Err(err) => Err(err.into()),
    }
}

fn wait_for_api_mfa(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    mfa: &MfaRequired,
) -> CargoResult<()> {
    gctx.shell().note(
        "API MFA required; complete passkey verification in your browser, then Cargo will retry",
    )?;
    gctx.shell().status(
        "Verifying",
        format!("please visit {}", mfa.verification_url),
    )?;

    let started = Instant::now();
    let mut interval = mfa
        .recommended_poll_interval_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL);

    let max = MFA_TIMEOUT.as_secs() as usize;
    let mut progress = Progress::with_style("Waiting", ProgressStyle::Ratio, gctx);
    progress.tick_now(0, max, "for MFA acknowledgment")?;

    loop {
        if !interval.is_zero() {
            std::thread::sleep(interval);
        }

        let elapsed = started.elapsed();
        if elapsed > MFA_TIMEOUT {
            bail!(
                "timed out waiting for API MFA acknowledgment; \
                 visit {} and retry, or authorize for 15 minutes under Settings → API MFA",
                mfa.verification_url
            );
        }
        progress.tick_now(elapsed.as_secs() as usize, max, "for MFA acknowledgment")?;

        let status = match registry.poll_mfa_challenge(&mfa.poll_url) {
            Ok(status) => status,
            Err(RegistryError::Code { code, .. }) if code.as_u16() == 404 => {
                bail!(
                    "API MFA challenge expired or was not found; \
                     visit {} and retry the original command",
                    mfa.verification_url
                );
            }
            Err(err) => return Err(err.into()),
        };

        if let Some(secs) = status.recommended_poll_interval_secs {
            interval = Duration::from_secs(secs);
        }

        match status.status.as_str() {
            "pending" => continue,
            "acknowledged" => {
                gctx.shell()
                    .note("API MFA acknowledged; retrying request")?;
                return Ok(());
            }
            other => bail!("unexpected API MFA challenge status: {other}"),
        }
    }
}
