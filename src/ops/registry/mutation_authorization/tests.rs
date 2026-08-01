use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crates_io::Error as RegistryError;
use url::Url;

use super::retry::{
    DEFAULT_POLL_INTERVAL, MIN_POLL_INTERVAL, parse_retry_after, transient_poll_delay,
};
use super::*;

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
fn mutation_authorization_requires_https_except_on_loopback() {
    validate_transport("https://registry.example").unwrap();
    validate_transport("http://127.0.0.1:1234").unwrap();
    validate_transport("http://[::1]:1234").unwrap();
    assert!(validate_transport("http://localhost:1234").is_err());
    assert!(validate_transport("http://registry.example").is_err());
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
fn zero_retry_after_uses_the_minimum_poll_interval() {
    let deadline = Instant::now() + Duration::from_secs(10);
    assert_eq!(
        transient_poll_delay(DEFAULT_POLL_INTERVAL, Some(Duration::ZERO), deadline),
        MIN_POLL_INTERVAL
    );
}

#[test]
fn oversized_final_response_is_not_retryable() {
    let error = RegistryError::Transport(http_async::Error::ResponseBodyTooLarge {
        limit: crates_io::MUTATION_RESPONSE_MAX_BYTES,
    });
    assert!(!final_request_is_retryable(&error));
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
fn loopback_listener_accepts_valid_wakeup() {
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
fn loopback_listener_ignores_invalid_path_or_state() {
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
fn loopback_listener_shutdown_is_bounded_for_partial_request() {
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
        started.elapsed() < callback::TEST_IO_TIMEOUT + Duration::from_secs(1),
        "listener shutdown exceeded callback I/O timeout"
    );
}
