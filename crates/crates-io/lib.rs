//! > This crate is maintained by the Cargo team for use by the wider
//! > ecosystem. This crate follows semver compatibility for its APIs.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom};
use std::time::Instant;

use http::{Method, Request, Response, StatusCode};
use percent_encoding::{NON_ALPHANUMERIC, percent_encode};
use serde::{Deserialize, Serialize};
use url::Url;

type RegistryResult<T, E> = Result<T, Error<E>>;

/// Perform an HTTP request and return the response.
///
/// Users of this crate must provide an implementation of this
/// trait using an HTTP crate such as `curl`, `reqwest`, etc.
pub trait HttpClient {
    type Error: std::error::Error + Send + Sync;
    fn request(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error>;

    /// Like [`Self::request`], but HTTP redirects must not be followed.
    ///
    /// Used for MFA challenge polls so a same-origin `poll_url` cannot redirect
    /// the client to loopback or other internal addresses. The default
    /// implementation calls [`Self::request`]; production clients should override
    /// this to disable redirect following.
    fn request_no_redirect(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
        self.request(req)
    }
}

pub struct Registry<T: HttpClient> {
    /// The base URL for issuing API requests.
    host: String,
    /// Optional authorization token.
    /// If None, commands requiring authorization will fail.
    token: Option<String>,
    /// HTTP handle for issuing requests.
    handle: T,
    /// Whether to include the authorization token with all requests.
    auth_required: bool,
    /// Extra headers for interactive MFA (localhost port / OTP retry).
    api_mfa_headers: ApiMfaHeaders,
}

/// Optional headers for the registry interactive MFA handshake.
///
/// When `port` is set, cargo listens on `127.0.0.1:{port}` for a one-shot OTP
/// from the registry verify page (`Crates-MFA-Port`). `callback_secret`
/// authorizes callback port refreshes without allowing a leaked API token to
/// downgrade the challenge to a polling grant. After verification, the OTP is
/// sent on retry as `Crates-OTP`.
#[derive(Clone, Default)]
pub struct ApiMfaHeaders {
    pub port: Option<u16>,
    pub callback_secret: Option<String>,
    pub otp: Option<String>,
}

#[derive(PartialEq, Clone, Copy)]
pub enum Auth {
    Authorized,
    Unauthorized,
}

#[derive(Deserialize)]
pub struct Crate {
    pub name: String,
    pub description: Option<String>,
    pub max_version: String,
}

/// This struct is serialized as JSON and sent as metadata ahead of the crate
/// tarball when publishing crates to a crate registry like crates.io.
///
/// see <https://doc.rust-lang.org/cargo/reference/registry-web-api.html#publish>
#[derive(Serialize, Deserialize)]
pub struct NewCrate {
    pub name: String,
    pub vers: String,
    pub deps: Vec<NewCrateDependency>,
    pub features: BTreeMap<String, Vec<String>>,
    pub authors: Vec<String>,
    pub description: Option<String>,
    pub documentation: Option<String>,
    pub homepage: Option<String>,
    pub readme: Option<String>,
    pub readme_file: Option<String>,
    pub keywords: Vec<String>,
    pub categories: Vec<String>,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub repository: Option<String>,
    pub badges: BTreeMap<String, BTreeMap<String, String>>,
    pub links: Option<String>,
    pub rust_version: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct NewCrateDependency {
    pub optional: bool,
    pub default_features: bool,
    pub name: String,
    pub features: Vec<String>,
    pub version_req: String,
    pub target: Option<String>,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explicit_name_in_toml: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindep_target: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub lib: bool,
}

#[derive(Deserialize)]
pub struct User {
    pub id: u32,
    pub login: String,
    pub avatar: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
}

pub struct Warnings {
    pub invalid_categories: Vec<String>,
    pub invalid_badges: Vec<String>,
    pub other: Vec<String>,
}

#[derive(Deserialize)]
struct R {
    ok: bool,
}
#[derive(Deserialize)]
struct OwnerResponse {
    ok: bool,
    msg: String,
}
#[derive(Deserialize)]
struct ApiErrorList {
    errors: Vec<ApiError>,
}
#[derive(Deserialize)]
struct ApiError {
    detail: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    verification_url: Option<String>,
    #[serde(default)]
    poll_url: Option<String>,
    #[serde(default)]
    recommended_poll_interval_secs: Option<u64>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    operation: Option<String>,
    #[serde(default, rename = "crate")]
    crate_name: Option<String>,
}

/// Registry response when a dangerous API call needs interactive MFA acknowledgment.
///
/// See the crates.io API MFA handshake (`errors[].id == "mfa_required"`).
#[derive(Debug, Clone)]
pub struct MfaRequired {
    pub detail: String,
    pub operation_id: Option<String>,
    pub operation: Option<String>,
    pub crate_name: Option<String>,
    pub verification_url: String,
    pub poll_url: String,
    pub recommended_poll_interval_secs: Option<u64>,
    pub expires_at: Option<String>,
}

/// Poll response body for `GET` of [`MfaRequired::poll_url`].
#[derive(Debug, Deserialize)]
pub struct MfaChallengeStatus {
    pub status: String,
    #[serde(default)]
    pub acknowledged: bool,
    #[serde(default)]
    pub recommended_poll_interval_secs: Option<u64>,
}
#[derive(Serialize)]
struct OwnersReq<'a> {
    users: &'a [&'a str],
}
#[derive(Deserialize)]
struct Users {
    users: Vec<User>,
}
#[derive(Deserialize)]
struct TotalCrates {
    total: u32,
}
#[derive(Deserialize)]
struct Crates {
    crates: Vec<Crate>,
    meta: TotalCrates,
}

/// Error returned when interacting with a registry.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error<T> {
    /// Error from underlying transport.
    #[error(transparent)]
    Transport(T),

    /// Error from http.
    #[error(transparent)]
    Http(#[from] http::Error),

    /// Error from serializing the request payload and deserializing the
    /// response body (like response body didn't match expected structure).
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error from IO. Mostly from reading the tarball to upload.
    #[error("failed to seek tarball")]
    Io(#[from] std::io::Error),

    /// Response body was not valid utf8.
    #[error("invalid response body from server")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// Error from API response containing JSON field `errors.details`.
    #[error(
        "the remote server responded with an error{}: {}",
        status(*code),
        errors.join(", "),
    )]
    Api {
        code: StatusCode,
        headers: Vec<String>,
        errors: Vec<String>,
    },

    /// Registry requires interactive MFA (e.g. crates.io passkey step-up).
    ///
    /// The CLI should print [`MfaRequired::verification_url`], complete the
    /// handshake via localhost OTP (preferred) or by polling
    /// [`MfaRequired::poll_url`], then retry the request (with `Crates-OTP`
    /// when using the OTP path).
    #[error("{}", .0.detail)]
    MfaRequired(MfaRequired),

    /// `poll_url` from an MFA challenge did not share the registry API origin.
    ///
    /// Cargo refuses to follow cross-origin poll URLs to avoid SSRF from a
    /// malicious registry response.
    #[error(
        "refusing to poll MFA status at `{poll_url}`; \
         URL must use the same origin as the registry API ({registry_host})"
    )]
    InvalidMfaPollUrl {
        poll_url: String,
        registry_host: String,
    },

    /// MFA poll responded with an HTTP redirect.
    ///
    /// Poll requests do not follow redirects so a malicious registry cannot
    /// bounce the client onto loopback or link-local addresses after the
    /// same-origin check passes.
    #[error("refusing to follow MFA poll redirect from `{poll_url}`")]
    InvalidMfaPollRedirect {
        poll_url: String,
        location: Option<String>,
    },

    /// Error from API response which didn't have pre-programmed `errors.details`.
    #[error(
        "failed to get a 200 OK response, got {}\nheaders:\n\t{}\nbody:\n{body}",
        code.as_u16(),
        headers.join("\n\t"),
    )]
    Code {
        code: StatusCode,
        headers: Vec<String>,
        body: String,
    },

    #[error(transparent)]
    InvalidToken(#[from] TokenError),

    /// Server was unavailable and timed out. Happened when uploading a way
    /// too large tarball to crates.io.
    #[error(
        "Request timed out after 30 seconds. If you're trying to \
         upload a crate it may be too large. If the crate is under \
         10MB in size, you can email help@crates.io for assistance.\n\
         Total size was {0}."
    )]
    Timeout(u64),
}

impl<T: HttpClient> Registry<T> {
    /// Creates a new `Registry`.
    ///
    /// ## Example
    ///
    /// ```rust
    /// use crates_io::{Registry, HttpClient};
    /// use http::{Request, Response};
    ///
    /// struct Client {}
    /// impl HttpClient for Client {
    ///     type Error = std::io::Error;
    ///     fn request(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
    ///         todo!()
    ///     }
    /// }
    /// let client = Client {};
    ///
    /// let mut reg = Registry::new_handle(String::from("https://crates.io"), None, client, false);
    /// ```
    pub fn new_handle(host: String, token: Option<String>, handle: T, auth_required: bool) -> Self {
        Self {
            host,
            token,
            handle,
            auth_required,
            api_mfa_headers: ApiMfaHeaders::default(),
        }
    }

    pub fn set_token(&mut self, token: Option<String>) {
        self.token = token;
    }

    /// Sets MFA headers applied to subsequent mutating API requests.
    pub fn set_api_mfa_headers(&mut self, headers: ApiMfaHeaders) {
        self.api_mfa_headers = headers;
    }

    /// Clears MFA headers after a successful mutate or when abandoning a handshake.
    pub fn clear_api_mfa_headers(&mut self) {
        self.api_mfa_headers = ApiMfaHeaders::default();
    }

    fn token(&self) -> RegistryResult<&str, T::Error> {
        let token = self.token.as_ref().ok_or_else(|| TokenError::Missing)?;
        check_token(token)?;
        Ok(token)
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn host_is_crates_io(&self) -> bool {
        is_url_crates_io(&self.host)
    }

    pub fn add_owners(&mut self, krate: &str, owners: &[&str]) -> RegistryResult<String, T::Error> {
        let body = serde_json::to_string(&OwnersReq { users: owners })?;
        let body = self.put(&format!("/crates/{}/owners", krate), Some(body.as_bytes()))?;
        assert!(serde_json::from_str::<OwnerResponse>(&body)?.ok);
        Ok(serde_json::from_str::<OwnerResponse>(&body)?.msg)
    }

    pub fn remove_owners(&mut self, krate: &str, owners: &[&str]) -> RegistryResult<(), T::Error> {
        let body = serde_json::to_string(&OwnersReq { users: owners })?;
        let body = self.delete(&format!("/crates/{}/owners", krate), Some(body.as_bytes()))?;
        assert!(serde_json::from_str::<OwnerResponse>(&body)?.ok);
        Ok(())
    }

    pub fn list_owners(&mut self, krate: &str) -> RegistryResult<Vec<User>, T::Error> {
        let body = self.get(&format!("/crates/{}/owners", krate))?;
        Ok(serde_json::from_str::<Users>(&body)?.users)
    }

    /// Builds the `/crates/new` request body (crate metadata + tarball).
    ///
    /// Callers that may retry the upload (for example after an MFA handshake)
    /// should build the body once and pass it to [`Self::publish_body`].
    pub fn prepare_publish_body(
        krate: &NewCrate,
        mut tarball: &File,
    ) -> RegistryResult<(Vec<u8>, u64), T::Error> {
        let json = serde_json::to_string(krate)?;
        // Prepare the body. The format of the upload request is:
        //
        //      <le u32 of json>
        //      <json request> (metadata for the package)
        //      <le u32 of tarball>
        //      <source tarball>

        // NOTE: This can be replaced with `stream_len` if it is ever stabilized.
        //
        // This checks the length using seeking instead of metadata, because
        // on some filesystems, getting the metadata will fail because
        // the file was renamed in ops::package.
        let tarball_len = tarball.seek(SeekFrom::End(0))?;
        tarball.seek(SeekFrom::Start(0))?;
        let header = {
            let mut w = Vec::new();
            w.extend(&(json.len() as u32).to_le_bytes());
            w.extend(json.as_bytes().iter().cloned());
            w.extend(&(tarball_len as u32).to_le_bytes());
            w
        };
        let mut body = Vec::new();
        Cursor::new(header).chain(tarball).read_to_end(&mut body)?;
        Ok((body, tarball_len))
    }

    /// Uploads a body previously built by [`Self::prepare_publish_body`].
    pub fn publish_body(
        &mut self,
        body: &[u8],
        tarball_len: u64,
    ) -> RegistryResult<Warnings, T::Error> {
        let url = self.api_url("/crates/new");

        let request = self
            .apply_api_mfa_headers(
                http::Request::put(url)
                    .header(http::header::CONTENT_TYPE, "application/octet-stream")
                    .header(http::header::ACCEPT, "application/json")
                    .header(http::header::AUTHORIZATION, self.token()?),
            )
            .body(body.to_vec())?;
        let started = Instant::now();
        let response = self.handle.request(request).map_err(Error::Transport)?;
        let body = self.handle(response).map_err(|e| match e {
            Error::Code { code, .. }
                if code == StatusCode::SERVICE_UNAVAILABLE
                    && started.elapsed().as_secs() >= 29
                    && self.host_is_crates_io() =>
            {
                Error::Timeout(tarball_len)
            }
            _ => e.into(),
        })?;

        let response = if body.is_empty() {
            "{}".parse()?
        } else {
            body.parse::<serde_json::Value>()?
        };

        let invalid_categories: Vec<String> = response
            .get("warnings")
            .and_then(|j| j.get("invalid_categories"))
            .and_then(|j| j.as_array())
            .map(|x| x.iter().flat_map(|j| j.as_str()).map(Into::into).collect())
            .unwrap_or_else(Vec::new);

        let invalid_badges: Vec<String> = response
            .get("warnings")
            .and_then(|j| j.get("invalid_badges"))
            .and_then(|j| j.as_array())
            .map(|x| x.iter().flat_map(|j| j.as_str()).map(Into::into).collect())
            .unwrap_or_else(Vec::new);

        let other: Vec<String> = response
            .get("warnings")
            .and_then(|j| j.get("other"))
            .and_then(|j| j.as_array())
            .map(|x| x.iter().flat_map(|j| j.as_str()).map(Into::into).collect())
            .unwrap_or_else(Vec::new);

        Ok(Warnings {
            invalid_categories,
            invalid_badges,
            other,
        })
    }

    pub fn publish(
        &mut self,
        krate: &NewCrate,
        tarball: &File,
    ) -> RegistryResult<Warnings, T::Error> {
        let (body, tarball_len) = Self::prepare_publish_body(krate, tarball)?;
        self.publish_body(&body, tarball_len)
    }

    pub fn search(
        &mut self,
        query: &str,
        limit: u32,
    ) -> RegistryResult<(Vec<Crate>, u32), T::Error> {
        let formatted_query = percent_encode(query.as_bytes(), NON_ALPHANUMERIC);
        let body = self.req(
            Method::GET,
            &format!("/crates?q={}&per_page={}", formatted_query, limit),
            None,
            Auth::Unauthorized,
        )?;

        let crates = serde_json::from_str::<Crates>(&body)?;
        Ok((crates.crates, crates.meta.total))
    }

    pub fn yank(&mut self, krate: &str, version: &str) -> RegistryResult<(), T::Error> {
        let body = self.delete(&format!("/crates/{}/{}/yank", krate, version), None)?;
        assert!(serde_json::from_str::<R>(&body)?.ok);
        Ok(())
    }

    pub fn unyank(&mut self, krate: &str, version: &str) -> RegistryResult<(), T::Error> {
        let body = self.put(&format!("/crates/{}/{}/unyank", krate, version), None)?;
        assert!(serde_json::from_str::<R>(&body)?.ok);
        Ok(())
    }

    /// Polls an MFA challenge status endpoint.
    ///
    /// `poll_url` must share scheme/host/port with [`Registry::host`]. Redirects
    /// are not followed.
    pub fn poll_mfa_challenge(
        &mut self,
        poll_url: &str,
    ) -> RegistryResult<MfaChallengeStatus, T::Error> {
        if !url_shares_origin_with_registry(poll_url, &self.host) {
            return Err(Error::InvalidMfaPollUrl {
                poll_url: poll_url.to_owned(),
                registry_host: self.host.clone(),
            });
        }

        let mut request = http::Request::builder()
            .method(Method::GET)
            .uri(poll_url)
            .header(http::header::ACCEPT, "application/json");
        if let Some(token) = self.token.as_deref() {
            if check_token(token).is_ok() {
                request = request.header(http::header::AUTHORIZATION, token);
            }
        }
        let request = request.body(Vec::new())?;
        let response = self
            .handle
            .request_no_redirect(request)
            .map_err(Error::Transport)?;

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(http::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            return Err(Error::InvalidMfaPollRedirect {
                poll_url: poll_url.to_owned(),
                location,
            });
        }

        let body = self.handle(response)?;
        Ok(serde_json::from_str(&body)?)
    }

    fn put(&mut self, path: &str, b: Option<&[u8]>) -> RegistryResult<String, T::Error> {
        self.req(Method::PUT, path, b, Auth::Authorized)
    }

    fn get(&mut self, path: &str) -> RegistryResult<String, T::Error> {
        self.req(Method::GET, path, None, Auth::Authorized)
    }

    fn delete(&mut self, path: &str, b: Option<&[u8]>) -> RegistryResult<String, T::Error> {
        self.req(Method::DELETE, path, b, Auth::Authorized)
    }

    fn api_url(&self, path: &str) -> String {
        // http::Uri doesn't support file urls without an authority, even though it's optional.
        // We insert localhost here to make it work.
        let host = &self.host;
        if let Some(file_url) = host.strip_prefix("file:///") {
            format!("file://localhost/{file_url}/api/v1{path}")
        } else {
            format!("{host}/api/v1{path}")
        }
    }

    fn req(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        authorized: Auth,
    ) -> RegistryResult<String, T::Error> {
        let url = self.api_url(path);
        let mut request = http::Request::builder()
            .method(method)
            .uri(url)
            .header(http::header::ACCEPT, "application/json");
        if body.is_some() {
            request = request.header(http::header::CONTENT_TYPE, "application/json");
        }

        if self.auth_required || authorized == Auth::Authorized {
            request = request.header(http::header::AUTHORIZATION, self.token()?);
            request = self.apply_api_mfa_headers(request);
        }
        let request = request.body(body.unwrap_or_default().to_vec())?;
        let response = self.handle.request(request).map_err(Error::Transport)?;
        self.handle(response)
    }

    fn apply_api_mfa_headers(&self, mut request: http::request::Builder) -> http::request::Builder {
        if let Some(port) = self.api_mfa_headers.port {
            request = request.header("Crates-MFA-Port", port.to_string());
        }
        if let Some(secret) = self.api_mfa_headers.callback_secret.as_deref() {
            request = request.header("Crates-MFA-Callback-Secret", secret);
        }
        if let Some(otp) = self.api_mfa_headers.otp.as_deref() {
            request = request.header("Crates-OTP", otp);
        }
        request
    }

    fn handle(&mut self, response: http::Response<Vec<u8>>) -> RegistryResult<String, T::Error> {
        let (head, body) = response.into_parts();
        let body = String::from_utf8(body)?;
        let api_errors = serde_json::from_str::<ApiErrorList>(&body).ok();

        let headers = head
            .headers
            .iter()
            .filter_map(|(k, v)| Some((k, v.to_str().ok()?)))
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();

        // Only treat MFA from error bodies. crates.io historically returns
        // `200 OK` for cargo endpoints even on failures (`cargo_compat`
        // AdjustAll), so do not gate on HTTP status — look for the structured
        // `mfa_required` error object whenever the body parses as an error list.
        if let Some(list) = &api_errors
            && let Some(mfa) = list.errors.iter().find_map(mfa_required_from_api_error)
        {
            return Err(Error::MfaRequired(mfa));
        }

        let errors = api_errors.map(|s| s.errors.into_iter().map(|s| s.detail).collect::<Vec<_>>());

        match (head.status, errors) {
            (code, None) if code.is_success() => Ok(body),
            (code, Some(errors)) => Err(Error::Api {
                code,
                headers,
                errors,
            }),
            (code, None) => Err(Error::Code {
                code,
                headers,
                body,
            }),
        }
    }
}

fn mfa_required_from_api_error(err: &ApiError) -> Option<MfaRequired> {
    if err.id.as_deref() != Some("mfa_required") {
        return None;
    }
    let verification_url = err.verification_url.clone()?;
    let poll_url = err.poll_url.clone()?;
    Some(MfaRequired {
        detail: err.detail.clone(),
        operation_id: err.operation_id.clone(),
        operation: err.operation.clone(),
        crate_name: err.crate_name.clone(),
        verification_url,
        poll_url,
        recommended_poll_interval_secs: err.recommended_poll_interval_secs,
        expires_at: err.expires_at.clone(),
    })
}

/// Returns true when `url` shares scheme, host, and port with `registry_host`.
pub fn url_shares_origin_with_registry(url: &str, registry_host: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    let Ok(host) = Url::parse(registry_host) else {
        return false;
    };
    url.scheme() == host.scheme()
        && url.host() == host.host()
        && url.port_or_known_default() == host.port_or_known_default()
}

fn status(code: StatusCode) -> String {
    if code.is_success() {
        String::new()
    } else {
        format!(" (status {code})")
    }
}

/// Returns `true` if the host of the given URL is "crates.io".
pub fn is_url_crates_io(url: &str) -> bool {
    Url::parse(url)
        .map(|u| u.host_str() == Some("crates.io"))
        .unwrap_or(false)
}

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("no upload token found, please run `cargo login`")]
    Missing,

    #[error("please provide a non-empty token")]
    Empty,

    #[error(
        "token contains invalid characters.\nOnly printable ISO-8859-1 characters \
             are allowed as it is sent in a HTTPS header."
    )]
    InvalidCharacters,
}

/// Checks if a token is valid or malformed.
///
/// This check is necessary to prevent sending tokens which create an invalid HTTP request.
/// It would be easier to check just for alphanumeric tokens, but we can't be sure that all
/// registries only create tokens in that format so that is as less restricted as possible.
pub fn check_token(token: &str) -> Result<(), TokenError> {
    if token.is_empty() {
        return Err(TokenError::Empty);
    }
    if token.bytes().all(|b| {
        // This is essentially the US-ASCII limitation of
        // https://www.rfc-editor.org/rfc/rfc9110#name-field-values. That is,
        // visible ASCII characters (0x21-0x7e), space, and tab. We want to be
        // able to pass this in an HTTP header without encoding.
        b >= 32 && b < 127 || b == b'\t'
    }) {
        Ok(())
    } else {
        Err(TokenError::InvalidCharacters)
    }
}

#[cfg(test)]
mod tests {
    use super::url_shares_origin_with_registry;

    #[test]
    fn mfa_poll_url_same_origin() {
        assert!(url_shares_origin_with_registry(
            "https://crates.io/api/v1/mfa/challenges/mfa_x",
            "https://crates.io",
        ));
        assert!(url_shares_origin_with_registry(
            "http://127.0.0.1:1234/api/v1/mfa/challenges/mfa_x",
            "http://127.0.0.1:1234",
        ));
    }

    #[test]
    fn mfa_poll_url_rejects_cross_origin() {
        assert!(!url_shares_origin_with_registry(
            "http://127.0.0.1:9/secret",
            "https://crates.io",
        ));
        assert!(!url_shares_origin_with_registry(
            "https://evil.example/api/v1/mfa/challenges/mfa_x",
            "https://crates.io",
        ));
        assert!(!url_shares_origin_with_registry(
            "https://crates.io:443/api/v1/mfa/challenges/mfa_x",
            "http://crates.io",
        ));
        assert!(!url_shares_origin_with_registry(
            "not a url",
            "https://crates.io"
        ));
    }
}
