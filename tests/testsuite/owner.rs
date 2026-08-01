//! Tests for the `cargo owner` command.

use std::fs;
use std::sync::{Arc, Mutex};

use crate::prelude::*;
use cargo_test_support::project;
use cargo_test_support::registry::{self, RegistryBuilder, Response, api_path};
use cargo_test_support::str;

fn setup(name: &str, content: Option<&str>) {
    let dir = api_path().join(format!("api/v1/crates/{}", name));
    dir.mkdir_p();
    if let Some(body) = content {
        fs::write(dir.join("owners"), body).unwrap();
    }
}

#[cargo_test]
fn simple_list() {
    let registry = registry::init();
    let content = r#"{
        "users": [
            {
                "id": 70,
                "login": "github:rust-lang:core",
                "name": "Core"
            },
            {
                "id": 123,
                "login": "octocat"
            }
        ]
    }"#;
    setup("foo", Some(content));

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []
                license = "MIT"
                description = "foo"
            "#,
        )
        .file("src/main.rs", "fn main() {}")
        .build();

    p.cargo("owner -l")
        .replace_crates_io(registry.index_url())
        .with_stdout_data(str![[r#"
github:rust-lang:core (Core)
octocat

"#]])
        .run();
}

#[cargo_test]
fn simple_add() {
    let registry = registry::init();
    setup("foo", None);

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []
                license = "MIT"
                description = "foo"
            "#,
        )
        .file("src/main.rs", "fn main() {}")
        .build();

    p.cargo("owner -a username")
        .replace_crates_io(registry.index_url())
        .with_status(101)
        .with_stderr_data(str![[r#"
[UPDATING] crates.io index
[ERROR] failed to invite owners to crate `foo` on registry at [ROOTURL]/api

Caused by:
  EOF while parsing a value at line 1 column 0

"#]])
        .run();
}

#[cargo_test]
fn simple_add_with_asymmetric() {
    let registry = registry::RegistryBuilder::new()
        .http_api()
        .token(cargo_test_support::registry::Token::rfc_key())
        .build();
    setup("foo", None);

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [project]
                name = "foo"
                version = "0.0.1"
                authors = []
                license = "MIT"
                description = "foo"
            "#,
        )
        .file("src/main.rs", "fn main() {}")
        .build();

    // The http_api server will check that the authorization is correct.
    // If the authorization was not sent then we would get an unauthorized error.
    p.cargo("owner -a username")
        .arg("-Zasymmetric-token")
        .masquerade_as_nightly_cargo(&["asymmetric-token"])
        .replace_crates_io(registry.index_url())
        .with_status(0)
        .run();
}

#[cargo_test]
fn simple_remove() {
    let registry = registry::init();
    setup("foo", None);

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []
                license = "MIT"
                description = "foo"
            "#,
        )
        .file("src/main.rs", "fn main() {}")
        .build();

    p.cargo("owner -r username")
        .replace_crates_io(registry.index_url())
        .with_status(101)
        .with_stderr_data(str![[r#"
[UPDATING] crates.io index
[OWNER] removing ["username"] from crate foo
[ERROR] failed to remove owners from crate `foo` on registry at [ROOTURL]/api

Caused by:
  EOF while parsing a value at line 1 column 0

"#]])
        .run();
}

#[cargo_test]
fn simple_remove_with_asymmetric() {
    let registry = registry::RegistryBuilder::new()
        .http_api()
        .token(cargo_test_support::registry::Token::rfc_key())
        .build();
    setup("foo", None);

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [project]
                name = "foo"
                version = "0.0.1"
                authors = []
                license = "MIT"
                description = "foo"
            "#,
        )
        .file("src/main.rs", "fn main() {}")
        .build();

    // The http_api server will check that the authorization is correct.
    // If the authorization was not sent then we would get an unauthorized error.
    p.cargo("owner -r username")
        .arg("-Zasymmetric-token")
        .replace_crates_io(registry.index_url())
        .masquerade_as_nightly_cargo(&["asymmetric-token"])
        .with_status(0)
        .run();
}

/// Cargo binds an advertised owner change before sending it.
#[cargo_test]
fn step_up_required_then_retry() {
    let owner_count = Arc::new(Mutex::new(0u32));
    let poll_count = Arc::new(Mutex::new(0u32));

    let registry = RegistryBuilder::new()
        .http_api()
        .step_up_auth()
        .add_responder(
            "/api/v1/auth/mutation-challenges",
            move |req, _server| {
                let origin = req.url.origin().ascii_serialization();
                let descriptor: serde_json::Value =
                    serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                assert_eq!(descriptor["operation"], "owners");
                assert_eq!(descriptor["content_type"], "application/json");
                let body = format!(
                    r#"{{"status":"pending","detail":"Authorize this owner change.","protocol_version":1,"mutation_id":"mut_owners_01234567890123","poll_url":"{origin}/api/v1/auth/mutation-challenges/poll/poll_owners_01234567","challenge_expires_in":300,"recommended_poll_interval_secs":1}}"#
                );
                Response {
                    code: 202,
                    headers: vec!["Cache-Control: no-store".into()],
                    body: body.into_bytes(),
                }
            },
        )
        .add_responder("/api/v1/crates/foo/owners", move |req, server| {
            if req.method != "put" {
                return server.ok(req);
            }
            let mut n = owner_count.lock().unwrap();
            *n += 1;
            assert_eq!(
                req.cargo_mutation_id.as_deref(),
                Some("mut_owners_01234567890123")
            );
            server.ok(req)
        })
        .add_responder("/api/v1/auth/mutation-challenges/poll/poll_owners_01234567", move |_req, _server| {
            let mut n = poll_count.lock().unwrap();
            *n += 1;
            Response {
                code: 200,
                headers: vec!["Cache-Control: no-store".into()],
                body: br#"{"status":"ready","grant_expires_in":300}"#.to_vec(),
            }
        })
        .build();

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []
                license = "MIT"
                description = "foo"
            "#,
        )
        .file("src/main.rs", "fn main() {}")
        .build();

    p.cargo("owner -a username --registry-authorization=poll")
        .replace_crates_io(registry.index_url())
        .with_stderr_contains("[NOTE] registry authorization ready; continuing")
        .run();
}
