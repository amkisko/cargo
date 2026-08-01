//! Literal-loopback callback listener used only as a polling wake-up signal.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::bail;
use rand::distr::{Alphanumeric, SampleString};
use url::Url;

use crate::CargoResult;

const IO_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_REQUEST_LINE_BYTES: usize = 4 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_LINE_BYTES: usize = 8 * 1024;

/// Short-lived `127.0.0.1` listener accepting one authenticated wake-up.
pub(super) struct CallbackListener {
    pub(super) port: u16,
    pub(super) callback_state: String,
    pub(super) receiver: mpsc::Receiver<()>,
    done: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CallbackListener {
    pub(super) fn bind() -> CargoResult<Self> {
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
            run_listener(listener, tx, done_thread, &expected_callback_state);
        });
        Ok(Self {
            port,
            callback_state,
            receiver: rx,
            done,
            thread: Some(thread),
        })
    }

    pub(super) fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/cargo/registry-authorization?state={}",
            self.port, self.callback_state
        )
    }

    pub(super) fn shutdown(mut self) {
        self.done.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_listener(
    listener: TcpListener,
    tx: mpsc::Sender<()>,
    done: Arc<AtomicBool>,
    expected_state: &str,
) {
    while !done.load(Ordering::SeqCst) {
        let Ok((stream, peer)) = listener.accept() else {
            break;
        };
        if done.load(Ordering::SeqCst) {
            break;
        }
        if !peer.ip().is_loopback() {
            let _ = write_response(&stream, 403, "forbidden");
            continue;
        }
        if read_request(stream, expected_state).is_some() {
            let _ = tx.send(());
            break;
        }
    }
}

fn read_request(stream: TcpStream, expected_state: &str) -> Option<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    let mut reader = BufReader::new(stream);
    let request_line = read_bounded_line(&mut reader, MAX_REQUEST_LINE_BYTES)?;

    let mut header_bytes = 0;
    loop {
        let remaining = MAX_HEADER_BYTES.checked_sub(header_bytes)?;
        let line = read_bounded_line(&mut reader, remaining.min(MAX_HEADER_LINE_BYTES))?;
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
        let _ = write_response(&stream, 405, "method not allowed");
        return None;
    }

    let url = Url::parse(&format!("http://127.0.0.1{target}")).ok()?;
    if url.path() != "/cargo/registry-authorization" {
        let _ = write_response(&stream, 404, "not found");
        return None;
    }
    let states: Vec<_> = url
        .query_pairs()
        .filter(|(key, _)| key == "state")
        .map(|(_, value)| value.into_owned())
        .collect();
    if states.len() != 1 || !constant_time_eq(states[0].as_bytes(), expected_state.as_bytes()) {
        let _ = write_response(&stream, 403, "invalid callback state");
        return None;
    }

    let _ = write_success(&stream);
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

fn write_response(mut stream: &TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}

fn write_success(mut stream: &TcpStream) -> std::io::Result<()> {
    const BODY: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>"#;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )?;
    stream.flush()
}

#[cfg(test)]
pub(super) const TEST_IO_TIMEOUT: Duration = IO_TIMEOUT;
