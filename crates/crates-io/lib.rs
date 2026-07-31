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
use sha2::{Digest, Sha256};
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
    /// Used for step-up challenge polls so a same-origin `poll_url` cannot redirect
    /// the client to loopback or other internal addresses.
    ///
    /// Implementations must perform the request with redirect following disabled.
    fn request_no_redirect(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error>;
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
    /// Advertised version of the idempotency-first step-up protocol.
    step_up_auth_version: Option<u64>,
    /// Extra headers for interactive step-up (localhost port / proof retry).
    step_up_headers: StepUpHeaders,
}

/// Optional headers for the registry interactive step-up handshake.
///
/// When `port` is set, Cargo listens on `127.0.0.1:{port}` for a one-shot proof
/// from the registry verify page (`Cargo-Step-Up-Port`). `callback_secret`
/// authorizes callback port refreshes and is returned as listener callback
/// state. Callback challenges remain pollable through an exact scoped grant.
/// When the callback wins, the proof is sent on retry as `Cargo-Step-Up-Proof`.
#[derive(Clone, Default)]
pub struct StepUpHeaders {
    pub port: Option<u16>,
    pub callback_secret: Option<String>,
    pub proof: Option<String>,
    pub mutation_id: Option<String>,
}

/// Exact mutation descriptor sent before an idempotency-first registry mutation.
#[derive(Debug, Clone, Serialize)]
pub struct MutationDescriptor {
    protocol_version: u64,
    operation: String,
    method: String,
    endpoint: String,
    #[serde(rename = "crate")]
    crate_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    request_sha256: String,
    request_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owners: Option<Vec<String>>,
}

impl MutationDescriptor {
    fn base(
        operation: &str,
        method: Method,
        endpoint: String,
        crate_name: &str,
        request_body: &[u8],
    ) -> Self {
        Self {
            protocol_version: 1,
            operation: operation.to_owned(),
            method: method.as_str().to_owned(),
            endpoint,
            crate_name: crate_name.to_owned(),
            version: None,
            request_sha256: hex::encode(Sha256::digest(request_body)),
            request_size: request_body.len() as u64,
            archive_sha256: None,
            archive_size: None,
            direction: None,
            owners: None,
        }
    }

    /// Describes an ordinary publish request using its already-buffered bytes.
    pub fn publish(crate_name: &str, version: &str, body: &[u8], archive_size: u64) -> Self {
        let archive_start = body
            .len()
            .checked_sub(archive_size as usize)
            .expect("archive size must not exceed publish body size");
        let mut descriptor = Self::base(
            "publish",
            Method::PUT,
            "/api/v1/crates/new".to_owned(),
            crate_name,
            body,
        );
        descriptor.version = Some(version.to_owned());
        descriptor.archive_sha256 = Some(hex::encode(Sha256::digest(&body[archive_start..])));
        descriptor.archive_size = Some(archive_size);
        descriptor
    }

    /// Describes a bodyless yank or unyank request.
    pub fn yank(crate_name: &str, version: &str, undo: bool) -> Self {
        let operation = if undo { "unyank" } else { "yank" };
        let action = if undo { "unyank" } else { "yank" };
        let method = if undo { Method::PUT } else { Method::DELETE };
        let mut descriptor = Self::base(
            operation,
            method,
            format!("/api/v1/crates/{crate_name}/{version}/{action}"),
            crate_name,
            &[],
        );
        descriptor.version = Some(version.to_owned());
        descriptor
    }

    /// Describes an owner mutation and the exact JSON bytes Cargo will send.
    pub fn owners(crate_name: &str, owners: &[&str], add: bool) -> Result<Self, serde_json::Error> {
        let body = serde_json::to_vec(&OwnersReq { users: owners })?;
        let method = if add { Method::PUT } else { Method::DELETE };
        let mut descriptor = Self::base(
            "change-owners",
            method,
            format!("/api/v1/crates/{crate_name}/owners"),
            crate_name,
            &body,
        );
        descriptor.direction = Some(if add { "add" } else { "remove" }.to_owned());
        descriptor.owners = Some(owners.iter().map(|owner| (*owner).to_owned()).collect());
        Ok(descriptor)
    }
}

/// A mutation record returned by a successful preflight.
#[derive(Debug, Clone, Deserialize)]
pub struct StepUpReady {
    /// Must be `acknowledged` before Cargo sends the mutation.
    pub status: String,
    /// Canonical mutation ID to send on the final request and retries.
    pub challenge_id: String,
    /// End of the mutation record's advertised replay lifetime.
    pub expires_at: Option<String>,
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
#[derive(Default, Deserialize)]
struct ApiError {
    detail: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    protocol_version: Option<u64>,
    #[serde(default)]
    poll_url: Option<String>,
    #[serde(default)]
    recommended_poll_interval_secs: Option<u64>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    challenge_id: Option<String>,
    #[serde(default)]
    operation: Option<String>,
    #[serde(default, rename = "crate")]
    crate_name: Option<String>,
}

/// Registry response when a dangerous API call needs an interactive step-up challenge.
///
/// See the crates.io step-up handshake (`errors[].id == "step_up_required"`).
#[derive(Debug, Clone)]
pub struct StepUpRequired {
    pub detail: String,
    /// Canonical mutation id returned by preflight.
    pub challenge_id: String,
    /// Version of the step-up wire contract.
    pub protocol_version: u64,
    pub operation: Option<String>,
    pub crate_name: Option<String>,
    pub poll_url: String,
    pub recommended_poll_interval_secs: Option<u64>,
    pub expires_at: Option<String>,
}

/// Poll response body for `GET` of [`StepUpRequired::poll_url`].
#[derive(Debug, Deserialize)]
pub struct StepUpChallengeStatus {
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

    /// Registry requires interactive step-up (e.g. crates.io passkey).
    ///
    /// The CLI should print [`StepUpRequired::detail`], complete the handshake
    /// via a localhost proof (preferred) or by polling
    /// [`StepUpRequired::poll_url`], then retry the request (with
    /// `Cargo-Step-Up-Proof` when using the callback path).
    #[error("{}", .0.detail)]
    StepUpRequired(StepUpRequired),

    /// `poll_url` from a step-up challenge did not share the registry API origin.
    ///
    /// Cargo refuses to follow cross-origin poll URLs to avoid SSRF from a
    /// malicious registry response.
    #[error(
        "refusing to poll step-up status at `{poll_url}`; \
         URL must use the same origin as the registry API ({registry_host})"
    )]
    InvalidStepUpPollUrl {
        poll_url: String,
        registry_host: String,
    },

    /// Step-up poll responded with an HTTP redirect.
    ///
    /// Poll requests do not follow redirects so a malicious registry cannot
    /// bounce the client onto loopback or link-local addresses after the
    /// same-origin check passes.
    #[error("refusing to follow step-up poll redirect from `{poll_url}`")]
    InvalidStepUpPollRedirect {
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
    ///     fn request_no_redirect(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
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
            step_up_auth_version: None,
            step_up_headers: StepUpHeaders::default(),
        }
    }

    /// Sets the step-up protocol version advertised by registry `config.json`.
    pub fn set_step_up_auth_version(&mut self, version: Option<u64>) {
        self.step_up_auth_version = version;
    }

    /// Whether this registry advertises idempotency-first step-up version 1.
    pub fn supports_step_up_preflight(&self) -> bool {
        self.step_up_auth_version == Some(1)
    }

    pub fn set_token(&mut self, token: Option<String>) {
        self.token = token;
    }

    /// Sets step-up headers applied to subsequent mutating API requests.
    pub fn set_step_up_headers(&mut self, headers: StepUpHeaders) {
        self.step_up_headers = headers;
    }

    /// Clears step-up headers after a successful mutate or when abandoning a handshake.
    pub fn clear_step_up_headers(&mut self) {
        self.step_up_headers = StepUpHeaders::default();
    }

    /// Creates or reuses the mutation record for an exact mutation descriptor.
    pub fn preflight_mutation(
        &mut self,
        descriptor: &MutationDescriptor,
    ) -> RegistryResult<StepUpReady, T::Error> {
        let body = serde_json::to_vec(descriptor)?;
        let response = self.req(
            Method::POST,
            "/auth/challenges",
            Some(&body),
            Auth::Authorized,
        )?;
        Ok(serde_json::from_str(&response)?)
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
    /// Callers that may retry the upload (for example after a step-up handshake)
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
            .apply_step_up_headers(
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

    /// Polls a step-up challenge status endpoint.
    ///
    /// `poll_url` must share scheme/host/port with [`Registry::host`]. Redirects
    /// are not followed.
    pub fn poll_step_up_challenge(
        &mut self,
        poll_url: &str,
    ) -> RegistryResult<StepUpChallengeStatus, T::Error> {
        if !url_shares_origin_with_registry(poll_url, &self.host) {
            return Err(Error::InvalidStepUpPollUrl {
                poll_url: poll_url.to_owned(),
                registry_host: self.host.clone(),
            });
        }

        let request = http::Request::builder()
            .method(Method::GET)
            .uri(poll_url)
            .header(http::header::ACCEPT, "application/json");
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
            return Err(Error::InvalidStepUpPollRedirect {
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
            request = self.apply_step_up_headers(request);
        }
        let request = request.body(body.unwrap_or_default().to_vec())?;
        let response = self.handle.request(request).map_err(Error::Transport)?;
        self.handle(response)
    }

    fn apply_step_up_headers(&self, mut request: http::request::Builder) -> http::request::Builder {
        if let Some(port) = self.step_up_headers.port {
            request = request.header("Cargo-Step-Up-Port", port.to_string());
        }
        if let Some(secret) = self.step_up_headers.callback_secret.as_deref() {
            request = request.header("Cargo-Step-Up-Callback-Secret", secret);
        }
        if let Some(proof) = self.step_up_headers.proof.as_deref() {
            request = request.header("Cargo-Step-Up-Proof", proof);
        }
        if let Some(mutation_id) = self.step_up_headers.mutation_id.as_deref() {
            request = request.header("Cargo-Mutation-Id", mutation_id);
        }
        request
    }

    fn handle(&mut self, response: http::Response<Vec<u8>>) -> RegistryResult<String, T::Error> {
        let (head, body) = response.into_parts();
        let body = redact_step_up_credentials(String::from_utf8(body)?, &self.step_up_headers);
        let api_errors = serde_json::from_str::<ApiErrorList>(&body).ok();

        let headers = head
            .headers
            .iter()
            .filter_map(|(k, v)| Some((k, v.to_str().ok()?)))
            .map(|(k, v)| format!("{k}: {v}"))
            .map(|line| redact_step_up_credentials(line, &self.step_up_headers))
            .collect();

        // Only treat step-up challenges from error bodies. crates.io historically
        // returns `200 OK` for cargo endpoints even on failures (`cargo_compat`
        // AdjustAll), so do not gate on HTTP status — look for the structured
        // `step_up_required` error object whenever the body parses as an error list.
        if let Some(list) = &api_errors
            && let Some(step_up) = list.errors.iter().find_map(step_up_required_from_api_error)
        {
            return Err(Error::StepUpRequired(step_up));
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

/// Removes client-held step-up credentials from a response before parsing,
/// displaying, or including it in an error.
fn redact_step_up_credentials(mut body: String, headers: &StepUpHeaders) -> String {
    for credential in [headers.callback_secret.as_deref(), headers.proof.as_deref()]
        .into_iter()
        .flatten()
        .filter(|credential| !credential.is_empty())
    {
        body = body.replace(credential, "[REDACTED]");
    }
    body
}

fn step_up_required_from_api_error(err: &ApiError) -> Option<StepUpRequired> {
    if err.id.as_deref() != Some("step_up_required") || err.protocol_version != Some(1) {
        return None;
    }
    let poll_url = err.poll_url.clone()?;
    let challenge_id = err.challenge_id.clone()?;
    Some(StepUpRequired {
        detail: err.detail.clone(),
        challenge_id,
        protocol_version: 1,
        operation: err.operation.clone(),
        crate_name: err.crate_name.clone(),
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
    use super::{
        ApiError, MutationDescriptor, StepUpHeaders, redact_step_up_credentials,
        step_up_required_from_api_error, url_shares_origin_with_registry,
    };
    use sha2::{Digest, Sha256};

    #[test]
    fn step_up_poll_url_same_origin() {
        assert!(url_shares_origin_with_registry(
            "https://crates.io/api/v1/auth/challenges/stp_x",
            "https://crates.io",
        ));
        assert!(url_shares_origin_with_registry(
            "http://127.0.0.1:1234/api/v1/auth/challenges/stp_x",
            "http://127.0.0.1:1234",
        ));
    }

    #[test]
    fn step_up_poll_url_rejects_cross_origin() {
        assert!(!url_shares_origin_with_registry(
            "http://127.0.0.1:9/secret",
            "https://crates.io",
        ));
        assert!(!url_shares_origin_with_registry(
            "https://evil.example/api/v1/auth/challenges/stp_x",
            "https://crates.io",
        ));
        assert!(!url_shares_origin_with_registry(
            "https://crates.io:443/api/v1/auth/challenges/stp_x",
            "http://crates.io",
        ));
        assert!(!url_shares_origin_with_registry(
            "not a url",
            "https://crates.io"
        ));
    }

    #[test]
    fn step_up_required_parses_version_one_contract() {
        let error = valid_step_up_error();
        let step_up = step_up_required_from_api_error(&error).unwrap();
        assert_eq!(step_up.protocol_version, 1);
        assert_eq!(step_up.detail, "Additional authentication is required");
        assert_eq!(
            step_up.poll_url,
            "https://crates.io/api/v1/auth/challenges/stp_x"
        );
    }

    #[test]
    fn step_up_required_rejects_incomplete_or_unknown_contracts() {
        let mut missing_version = valid_step_up_error();
        missing_version.protocol_version = None;
        assert!(step_up_required_from_api_error(&missing_version).is_none());

        let mut unknown_version = valid_step_up_error();
        unknown_version.protocol_version = Some(2);
        assert!(step_up_required_from_api_error(&unknown_version).is_none());

        let mut missing_poll_url = valid_step_up_error();
        missing_poll_url.poll_url = None;
        assert!(step_up_required_from_api_error(&missing_poll_url).is_none());

        let mut missing_challenge_id = valid_step_up_error();
        missing_challenge_id.challenge_id = None;
        assert!(step_up_required_from_api_error(&missing_challenge_id).is_none());
    }

    fn valid_step_up_error() -> ApiError {
        ApiError {
            detail: "Additional authentication is required".into(),
            id: Some("step_up_required".into()),
            protocol_version: Some(1),
            challenge_id: Some("stp_x".into()),
            poll_url: Some("https://crates.io/api/v1/auth/challenges/stp_x".into()),
            ..ApiError::default()
        }
    }

    #[test]
    fn step_up_credentials_are_redacted_from_registry_responses() {
        let headers = StepUpHeaders {
            callback_secret: Some("callback-secret".into()),
            proof: Some("one-time-proof".into()),
            ..StepUpHeaders::default()
        };
        let body = "callback-secret and one-time-proof".to_owned();

        assert_eq!(
            redact_step_up_credentials(body, &headers),
            "[REDACTED] and [REDACTED]"
        );
    }

    #[test]
    fn publish_descriptor_hashes_exact_body_and_archive() {
        let mut body = b"metadata-prefix".to_vec();
        body.extend_from_slice(b"archive");
        let descriptor = MutationDescriptor::publish("demo", "1.2.3", &body, 7);
        let descriptor = serde_json::to_value(descriptor).unwrap();

        assert_eq!(descriptor["request_size"], body.len());
        assert_eq!(
            descriptor["request_sha256"],
            hex::encode(Sha256::digest(&body))
        );
        assert_eq!(descriptor["archive_size"], 7);
        assert_eq!(
            descriptor["archive_sha256"],
            hex::encode(Sha256::digest(b"archive"))
        );
    }

    #[test]
    fn owner_descriptor_hashes_the_mutation_json() {
        let owners = ["alice", "github:org:team"];
        let descriptor = MutationDescriptor::owners("demo", &owners, true).unwrap();
        let descriptor = serde_json::to_value(descriptor).unwrap();
        let body = br#"{"users":["alice","github:org:team"]}"#;

        assert_eq!(descriptor["direction"], "add");
        assert_eq!(descriptor["owners"], serde_json::json!(owners));
        assert_eq!(descriptor["request_size"], body.len());
        assert_eq!(
            descriptor["request_sha256"],
            hex::encode(Sha256::digest(body))
        );
    }
}
