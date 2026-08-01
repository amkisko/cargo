//! Authorize exact registry mutations before sending their ordinary requests.
//!
//! A loopback callback is only a wake-up signal. Readiness comes exclusively
//! from the registry's poll-token URL, and the final request carries only the
//! mutation id in addition to its ordinary primary credential.

mod callback;
mod display;
mod poll;
mod preflight;
mod retry;

use std::time::Instant;

use anyhow::bail;
use crates_io::Error as RegistryError;
use crates_io::MutationCallback;
use crates_io::MutationDescriptor;
use crates_io::MutationHeaders;
use crates_io::Registry;

use crate::CargoResult;
use crate::GlobalContext;
use crate::util::network::http_async;

use super::RegistryClient;
#[cfg(test)]
use callback::CallbackListener;
use display::{detail_for_user, sanitize_detail};
use poll::wait_for_authorization;
use preflight::{
    AuthorizationChannel, IDEMPOTENT_FINAL, LOOPBACK_CALLBACK, authorization_channel,
    is_noninteractive_authorization, maybe_start_callback_listener, random_protocol_id,
    validate_active_extensions, validate_interaction_required, validate_lifetime, validate_pending,
    validate_protocol_id, validate_protocol_version, validate_receive_lease, validate_transport,
};
use retry::{bounded_retry_delay, final_request_is_retryable, final_request_retry_after};

/// Runs a registry mutation after authorization preflight when supported.
pub(super) fn with_mutation_authorization<T, F, R>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    reg_or_index: Option<&super::RegistryOrIndex>,
    channel_override: Option<&str>,
    descriptor: MutationDescriptor,
    mut refresh_credential: R,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
    R: FnMut() -> CargoResult<String>,
{
    let channel = authorization_channel(gctx, reg_or_index, channel_override)?;
    if channel == AuthorizationChannel::Disabled {
        return op(registry).map_err(Into::into);
    }
    validate_transport(registry.host())?;
    with_preflight(
        gctx,
        registry,
        descriptor,
        channel,
        &mut refresh_credential,
        op,
    )
}

/// Preflights an exact mutation before transmitting its ordinary request body.
fn with_preflight<T, F, R>(
    gctx: &GlobalContext,
    registry: &mut Registry<RegistryClient<'_>>,
    descriptor: MutationDescriptor,
    channel: AuthorizationChannel,
    refresh_credential: &mut R,
    mut op: F,
) -> CargoResult<T>
where
    F: FnMut(&mut Registry<RegistryClient<'_>>) -> Result<T, RegistryError<http_async::Error>>,
    R: FnMut() -> CargoResult<String>,
{
    let mut listener = maybe_start_callback_listener(gctx, channel)?;
    let callback = listener.as_ref().map(|listener| MutationCallback {
        url: listener.url(),
    });
    let mut requested_extensions = vec![IDEMPOTENT_FINAL];
    if callback.is_some() {
        requested_extensions.push(LOOPBACK_CALLBACK);
    }
    let allow_pending = !is_noninteractive_authorization(gctx, channel);
    let preflight_id = random_protocol_id("pf");

    let result = (|| {
        let preflight = registry.preflight_mutation(
            &descriptor,
            &preflight_id,
            allow_pending,
            &requested_extensions,
            callback.as_ref(),
        );
        let response = match preflight {
            Err(RegistryError::Transport(
                error @ http_async::Error::ResponseBodyTooLarge { .. },
            )) => return Err(RegistryError::Transport(error).into()),
            Err(RegistryError::Transport(_) | RegistryError::Timeout(_)) => registry
                .preflight_mutation(
                    &descriptor,
                    &preflight_id,
                    allow_pending,
                    &requested_extensions,
                    callback.as_ref(),
                )?,
            result => result?,
        };
        let Some((http_status, response)) = response else {
            if channel == AuthorizationChannel::Loopback {
                bail!(
                    "registry does not implement mutation authorization and cannot activate the \
                     `loopback-callback` extension"
                );
            }
            return op(registry).map_err(Into::into);
        };
        let active_extensions = validate_active_extensions(&response, &requested_extensions)?;
        if channel == AuthorizationChannel::Loopback && !active_extensions.loopback_callback {
            bail!("registry did not activate the `loopback-callback` authorization extension");
        }
        if !active_extensions.loopback_callback
            && let Some(listener) = listener.take()
        {
            listener.shutdown();
        }

        let (mutation_id, receive_lease) = match response.status.as_str() {
            "ready" if http_status == http::StatusCode::OK => {
                validate_protocol_version(&response)?;
                validate_lifetime("grant_expires_in", response.grant_expires_in)?;
                let receive_lease =
                    validate_receive_lease(&response, active_extensions.idempotent_final)?;
                let mutation_id = response
                    .mutation_id
                    .ok_or_else(|| anyhow::format_err!("ready preflight omitted mutation_id"))?;
                validate_protocol_id("mutation_id", &mutation_id)?;
                (mutation_id, receive_lease)
            }
            "pending" if http_status == http::StatusCode::ACCEPTED && allow_pending => {
                let pending =
                    validate_pending(registry, response, active_extensions.idempotent_final)?;
                let detail = detail_for_user(&pending.detail, registry.host())?;
                let receive_lease =
                    wait_for_authorization(gctx, registry, &pending, &detail, listener.as_ref())?;
                (pending.mutation_id, receive_lease)
            }
            "interaction_required" if http_status == http::StatusCode::FORBIDDEN => {
                validate_interaction_required(&response)?;
                let detail = response
                    .detail
                    .as_deref()
                    .map(sanitize_detail)
                    .unwrap_or_else(|| "This operation requires registry authorization.".into());
                bail!(
                    "{detail}\nno authorization challenge was created; rerun with \
                     --registry-authorization=poll"
                );
            }
            "denied" | "expired" if http_status == http::StatusCode::OK => {
                validate_protocol_version(&response)?;
                let mutation_id = response.mutation_id.as_deref().ok_or_else(|| {
                    anyhow::format_err!("{} preflight omitted mutation_id", response.status)
                })?;
                validate_protocol_id("mutation_id", mutation_id)?;
                bail!("registry authorization was {}", response.status);
            }
            status => bail!(
                "registry returned invalid mutation preflight status `{status}` with HTTP {}",
                http_status.as_u16()
            ),
        };

        // The callback is only a wake-up signal. Once polling has established
        // readiness, stop accepting loopback traffic before sending the final
        // mutation and its ordinary registry credential.
        if let Some(listener) = listener.take() {
            listener.shutdown();
        }

        registry.set_token(Some(refresh_credential()?));
        registry.set_mutation_headers(MutationHeaders {
            mutation_id: Some(mutation_id),
        });
        registry.set_response_body_limit(Some(crates_io::MUTATION_RESPONSE_MAX_BYTES));

        let Some(receive_lease) = receive_lease else {
            return op(registry).map_err(Into::into);
        };

        // A single bounded retry covers an interrupted or response-ambiguous
        // transport when the registry promises terminal replay.
        let retry_deadline = Instant::now() + receive_lease;
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
    registry.set_response_body_limit(None);
    if let Some(listener) = listener.take() {
        listener.shutdown();
    }
    result
}

#[cfg(test)]
mod tests;
