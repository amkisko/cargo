//! Validation and state extracted from mutation-authorization preflight responses.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::bail;
use crates_io::{MutationAuthorizationResponse, Registry};
use rand::distr::{Alphanumeric, SampleString};
use url::Url;

use crate::{CargoResult, GlobalContext};

use super::super::{RegistryClient, RegistryOrIndex};
use super::callback::CallbackListener;

pub(super) const IDEMPOTENT_FINAL: &str = "idempotent-final";
pub(super) const LOOPBACK_CALLBACK: &str = "loopback-callback";
const PREFER_LOOPBACK_ENV: &str = "CARGO_REGISTRY_MUTATION_AUTHORIZATION_PREFER_LOOPBACK";
const INTERACTIVE_ENV: &str = "CARGO_REGISTRY_MUTATION_AUTHORIZATION_INTERACTIVE";
const CHANNEL_ENV: &str = "CARGO_REGISTRY_MUTATION_AUTHORIZATION_CHANNEL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorizationChannel {
    Auto,
    Loopback,
    Poll,
    Disabled,
}

pub(super) fn validate_transport(registry_host: &str) -> CargoResult<()> {
    let url = Url::parse(registry_host)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(_)) | None => false,
    };
    if url.scheme() != "https" && !loopback {
        bail!(
            "mutation authorization requires HTTPS for non-loopback registries; configured registry is `{registry_host}`"
        );
    }
    Ok(())
}

pub(super) fn authorization_channel(
    gctx: &GlobalContext,
    reg_or_index: Option<&RegistryOrIndex>,
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
            Some(RegistryOrIndex::Registry(name)) if name != "crates-io" => {
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

pub(super) fn maybe_start_callback_listener(
    gctx: &GlobalContext,
    channel: AuthorizationChannel,
) -> Option<CallbackListener> {
    let use_loopback = match channel {
        AuthorizationChannel::Auto => prefer_loopback_callback(gctx),
        AuthorizationChannel::Loopback => true,
        AuthorizationChannel::Poll | AuthorizationChannel::Disabled => false,
    };
    if !use_loopback {
        return None;
    }
    match CallbackListener::bind() {
        Ok(listener) => Some(listener),
        Err(err) => {
            let _ = gctx.shell().verbose(|shell| {
                shell.note(format!(
                    "could not bind mutation-authorization loopback listener ({err}); using poll fallback"
                ))
            });
            None
        }
    }
}

pub(super) fn is_noninteractive_authorization(
    gctx: &GlobalContext,
    channel: AuthorizationChannel,
) -> bool {
    if matches!(
        channel,
        AuthorizationChannel::Loopback | AuthorizationChannel::Poll
    ) {
        return false;
    }
    if env_flag_set(gctx, INTERACTIVE_ENV) || env_flag_set(gctx, PREFER_LOOPBACK_ENV) {
        return false;
    }
    is_ci_env(gctx) || !std::io::stdin().is_terminal()
}

fn prefer_loopback_callback(gctx: &GlobalContext) -> bool {
    env_flag_set(gctx, PREFER_LOOPBACK_ENV) || (std::io::stdin().is_terminal() && !is_ci_env(gctx))
}

fn env_flag_set(gctx: &GlobalContext, name: &str) -> bool {
    gctx.get_env_os(name).is_some()
}

fn is_ci_env(gctx: &GlobalContext) -> bool {
    matches!(
        gctx.get_env("CI")
            .ok()
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("true") || value == "1"),
        Some(true)
    )
}

#[derive(Debug)]
pub(super) struct PendingAuthorization {
    pub(super) detail: String,
    pub(super) mutation_id: String,
    pub(super) poll_url: String,
    pub(super) challenge_expires_in: u64,
    pub(super) recommended_poll_interval_secs: Option<u64>,
    pub(super) idempotent_final: bool,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ActiveExtensions {
    pub(super) idempotent_final: bool,
    pub(super) loopback_callback: bool,
}

pub(super) fn validate_protocol_version(
    response: &MutationAuthorizationResponse,
) -> CargoResult<()> {
    if response.protocol_version != 1 {
        bail!(
            "registry returned mutation authorization protocol version {} instead of 1",
            response.protocol_version
        );
    }
    Ok(())
}

pub(super) fn validate_active_extensions(
    response: &MutationAuthorizationResponse,
    requested: &[&str],
) -> CargoResult<ActiveExtensions> {
    let mut active = ActiveExtensions {
        idempotent_final: false,
        loopback_callback: false,
    };
    for (index, extension) in response.active_extensions.iter().enumerate() {
        if response.active_extensions[..index].contains(extension) {
            bail!("registry returned duplicate active extension `{extension}`");
        }
        if !requested.contains(&extension.as_str()) {
            bail!("registry activated unrequested extension `{extension}`");
        }
        match extension.as_str() {
            IDEMPOTENT_FINAL => active.idempotent_final = true,
            LOOPBACK_CALLBACK => active.loopback_callback = true,
            _ => bail!("registry activated unsupported extension `{extension}`"),
        }
    }
    Ok(active)
}

pub(super) fn validate_lifetime(name: &str, value: Option<u64>) -> CargoResult<u64> {
    match value {
        Some(value @ 1..=300) => Ok(value),
        _ => bail!("{name} must be an integer from 1 through 300"),
    }
}

pub(super) fn validate_receive_lease(
    response: &MutationAuthorizationResponse,
    idempotent_final: bool,
) -> CargoResult<Option<Duration>> {
    if !idempotent_final {
        return Ok(None);
    }
    match response.receive_lease_secs {
        Some(value @ 1..=3600) => Ok(Some(Duration::from_secs(value))),
        _ => bail!("receive_lease_secs must be an integer from 1 through 3600"),
    }
}

pub(super) fn validate_protocol_id(name: &str, value: &str) -> CargoResult<()> {
    if !(22..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("{name} must be 22–128 URL-safe ASCII characters");
    }
    Ok(())
}

pub(super) fn validate_pending(
    registry: &Registry<RegistryClient<'_>>,
    response: MutationAuthorizationResponse,
    idempotent_final: bool,
) -> CargoResult<PendingAuthorization> {
    validate_protocol_version(&response)?;
    let detail = response
        .detail
        .filter(|detail| !detail.is_empty())
        .ok_or_else(|| anyhow::format_err!("pending preflight omitted detail"))?;
    if detail.len() > crates_io::MUTATION_AUTHORIZATION_DETAIL_MAX_BYTES {
        bail!("registry authorization instructions exceed the 8192-byte limit");
    }
    let mutation_id = response
        .mutation_id
        .ok_or_else(|| anyhow::format_err!("pending preflight omitted mutation_id"))?;
    validate_protocol_id("mutation_id", &mutation_id)?;
    let poll_url = response
        .poll_url
        .ok_or_else(|| anyhow::format_err!("pending preflight omitted poll_url"))?;
    if poll_url.len() > crates_io::MUTATION_AUTHORIZATION_DETAIL_MAX_BYTES
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
        idempotent_final,
    })
}

pub(super) fn validate_interaction_required(
    response: &MutationAuthorizationResponse,
) -> CargoResult<()> {
    validate_protocol_version(response)?;
    if response.mutation_id.is_some() || response.poll_url.is_some() {
        bail!("interaction_required response created an actionable challenge");
    }
    Ok(())
}

pub(super) fn random_protocol_id(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        Alphanumeric.sample_string(&mut rand::rng(), 32)
    )
}
