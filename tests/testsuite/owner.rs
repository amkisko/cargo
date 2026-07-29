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

/// Registry returns `mfa_required`; Cargo polls until acknowledged, then retries owner add.
#[cargo_test]
fn api_mfa_required_then_retry() {
    let owner_count = Arc::new(Mutex::new(0u32));
    let poll_count = Arc::new(Mutex::new(0u32));

    let registry = RegistryBuilder::new()
        .http_api()
        .add_responder("/api/v1/crates/foo/owners", move |req, server| {
            if req.method != "put" {
                return server.ok(req);
            }
            let mut n = owner_count.lock().unwrap();
            *n += 1;
            if *n == 1 {
                let origin = req.url.origin().ascii_serialization();
                let body = format!(
                    r#"{{"errors":[{{"detail":"API MFA required","id":"mfa_required","operation_id":"mfa_owners","operation":"change-owners","crate":"foo","verification_url":"{origin}/mfa/verify/mfa_owners","poll_url":"{origin}/api/v1/mfa/challenges/mfa_owners","expires_at":"2099-01-01T00:00:00Z","recommended_poll_interval_secs":1}}]}}"#
                );
                Response {
                    code: 403,
                    headers: vec![],
                    body: body.into_bytes(),
                }
            } else {
                server.ok(req)
            }
        })
        .add_responder("/api/v1/mfa/challenges/mfa_owners", move |_req, _server| {
            let mut n = poll_count.lock().unwrap();
            *n += 1;
            let status = if *n == 1 { "pending" } else { "acknowledged" };
            let acknowledged = status == "acknowledged";
            let body = format!(
                r#"{{"operation_id":"mfa_owners","status":"{status}","acknowledged":{acknowledged},"verified":{acknowledged},"operation":"change-owners","crate_name":"foo","expires_at":"2099-01-01T00:00:00Z","localhost_port":null,"recommended_poll_interval_secs":1}}"#
            );
            Response {
                code: 200,
                headers: vec![],
                body: body.into_bytes(),
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

    p.cargo("owner -a username")
        .replace_crates_io(registry.index_url())
        .with_stderr_data(str![[r#"
[UPDATING] crates.io index
[NOTE] API MFA required; complete verification in your browser, then Cargo will retry
[VERIFYING] please visit http://127.0.0.1:[..]/mfa/verify/mfa_owners
[NOTE] API MFA acknowledged; retrying request
[OWNER] completed!

"#]])
        .run();
}
