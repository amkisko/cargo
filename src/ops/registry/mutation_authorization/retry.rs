//! Bounded poll and final-request retry decisions.

use std::time::{Duration, Instant};

use crates_io::Error as RegistryError;
use rand::RngExt;

use crate::util::network::http_async;

pub(super) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);
pub(super) const MIN_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);

pub(super) fn clamp_poll_interval(recommended_secs: Option<u64>) -> Duration {
    recommended_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_POLL_INTERVAL)
        .clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

pub(super) fn transient_poll_delay(
    previous: Duration,
    retry_after: Option<Duration>,
    deadline: Instant,
) -> Duration {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if let Some(retry_after) = retry_after {
        return retry_after
            .max(MIN_POLL_INTERVAL)
            .min(MAX_POLL_INTERVAL)
            .min(remaining);
    }

    let maximum = (previous * 2).min(MAX_POLL_INTERVAL);
    let maximum_millis = maximum.as_millis().max(1) as u64;
    let minimum_millis = (maximum_millis / 2).max(1);
    Duration::from_millis(rand::rng().random_range(minimum_millis..=maximum_millis))
}

pub(super) fn final_request_is_retryable(error: &RegistryError<http_async::Error>) -> bool {
    match error {
        RegistryError::Transport(http_async::Error::ResponseBodyTooLarge { .. }) => false,
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

pub(super) fn final_request_retry_after(
    error: &RegistryError<http_async::Error>,
) -> Option<Duration> {
    match error {
        RegistryError::Code { code, headers, .. } | RegistryError::Api { code, headers, .. } => {
            parse_retry_after(*code, headers)
        }
        _ => None,
    }
}

pub(super) fn bounded_retry_delay(
    retry_after: Option<Duration>,
    deadline: Instant,
) -> Option<Duration> {
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

pub(super) fn parse_retry_after(code: http::StatusCode, headers: &[String]) -> Option<Duration> {
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
