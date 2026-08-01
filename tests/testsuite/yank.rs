//! Tests for the `cargo yank` command.

use std::fs;
use std::sync::{Arc, Mutex};

use crate::prelude::*;
use cargo_test_support::project;
use cargo_test_support::registry::{self, RegistryBuilder, Response};
use cargo_test_support::str;

fn setup(name: &str, version: &str) {
    let dir = registry::api_path().join(format!("api/v1/crates/{}/{}", name, version));
    dir.mkdir_p();
    fs::write(dir.join("yank"), r#"{"ok": true}"#).unwrap();
}

#[cargo_test]
fn explicit_version() {
    let registry = registry::init();
    setup("foo", "0.0.1");

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

    p.cargo("yank --version 0.0.1")
        .replace_crates_io(registry.index_url())
        .run();

    p.cargo("yank --undo --version 0.0.1")
        .replace_crates_io(registry.index_url())
        .with_status(101)
        .with_stderr_data(str![[r#"
[UPDATING] crates.io index
      Unyank foo@0.0.1
[ERROR] failed to undo a yank from the registry at [ROOTURL]/api

Caused by:
  EOF while parsing a value at line 1 column 0

"#]])
        .run();
}

#[cargo_test]
fn explicit_version_with_asymmetric() {
    let registry = registry::RegistryBuilder::new()
        .http_api()
        .token(cargo_test_support::registry::Token::rfc_key())
        .build();
    setup("foo", "0.0.1");

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
    p.cargo("yank --version 0.0.1")
        .arg("-Zasymmetric-token")
        .masquerade_as_nightly_cargo(&["asymmetric-token"])
        .replace_crates_io(registry.index_url())
        .run();

    p.cargo("yank --undo --version 0.0.1")
        .arg("-Zasymmetric-token")
        .masquerade_as_nightly_cargo(&["asymmetric-token"])
        .replace_crates_io(registry.index_url())
        .run();
}

#[cargo_test]
fn inline_version() {
    let registry = registry::init();
    setup("foo", "0.0.1");

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

    p.cargo("yank foo@0.0.1")
        .replace_crates_io(registry.index_url())
        .run();

    p.cargo("yank --undo foo@0.0.1")
        .replace_crates_io(registry.index_url())
        .with_status(101)
        .with_stderr_data(str![[r#"
[UPDATING] crates.io index
      Unyank foo@0.0.1
[ERROR] failed to undo a yank from the registry at [ROOTURL]/api

Caused by:
  EOF while parsing a value at line 1 column 0

"#]])
        .run();
}

#[cargo_test]
fn version_required() {
    setup("foo", "0.0.1");

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

    p.cargo("yank foo")
        .with_status(101)
        .with_stderr_data(str![[r#"
[ERROR] `--version` is required

"#]])
        .run();
}

#[cargo_test]
fn inline_version_without_name() {
    setup("foo", "0.0.1");

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

    p.cargo("yank @0.0.1")
        .with_status(101)
        .with_stderr_data(str![[r#"
[ERROR] missing crate name for `@0.0.1`

"#]])
        .run();
}

#[cargo_test]
fn inline_and_explicit_version() {
    setup("foo", "0.0.1");

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

    p.cargo("yank foo@0.0.1 --version 0.0.1")
        .with_status(101)
        .with_stderr_data(str![[r#"
[ERROR] cannot specify both `@0.0.1` and `--version`

"#]])
        .run();
}

#[cargo_test]
fn bad_version() {
    let registry = registry::init();
    setup("foo", "0.0.1");

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

    p.cargo("yank foo@bar")
        .replace_crates_io(registry.index_url())
        .with_status(101)
        .with_stderr_data(str![[r#"
[ERROR] invalid version `bar`

Caused by:
  unexpected character 'b' while parsing major version number

"#]])
        .run();
}

#[cargo_test]
fn prefixed_v_in_version() {
    let registry = registry::init();
    setup("foo", "0.0.1");

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

    p.cargo("yank bar@v0.0.1")
        .replace_crates_io(registry.index_url())
        .with_status(101)
        .with_stderr_data(str![[r#"
[ERROR] the version provided, `v0.0.1` is not a valid SemVer version

[HELP] try changing the version to `0.0.1`

Caused by:
  unexpected character 'v' while parsing major version number

"#]])
        .run();
}

/// Core-only mutation authorization polls until ready, then sends the yank once.
#[cargo_test]
fn mutation_authorization_required_then_retry() {
    let yank_count = Arc::new(Mutex::new(0u32));
    let poll_count = Arc::new(Mutex::new(0u32));
    let yank_responder_count = yank_count.clone();
    let poll_responder_count = poll_count.clone();

    let registry = RegistryBuilder::new()
        .http_api()
        .add_responder(
            "/api/v1/auth/mutation-challenges",
            move |req, _server| {
                let origin = req.url.origin().ascii_serialization();
                let descriptor: serde_json::Value =
                    serde_json::from_slice(req.body.as_deref().unwrap()).unwrap();
                assert_eq!(descriptor["operation"], "yank");
                assert_eq!(descriptor["allow_pending"], true);
                assert_eq!(descriptor["method"], "DELETE");
                assert_eq!(
                    descriptor["request_target"],
                    "/api/v1/crates/foo/0.0.1/yank"
                );
                assert!(descriptor["content_type"].is_null());
                let body = format!(
                    r#"{{"status":"pending","detail":"Authorize this yank at {origin}/verify/mut_yank.","protocol_version":1,"active_extensions":[],"mutation_id":"mut_yank_0123456789012345","poll_url":"{origin}/api/v1/auth/mutation-challenges/poll/poll_yank_0123456789","challenge_expires_in":300,"recommended_poll_interval_secs":1}}"#
                );
                Response {
                    code: 202,
                    headers: vec!["Cache-Control: no-store".into()],
                    body: body.into_bytes(),
                }
            },
        )
        .add_responder("/api/v1/crates/foo/0.0.1/yank", move |req, server| {
            let mut n = yank_responder_count.lock().unwrap();
            *n += 1;
            assert_eq!(
                req.cargo_mutation_id.as_deref(),
                Some("mut_yank_0123456789012345")
            );
            server.ok(req)
        })
        .add_responder(
            "/api/v1/auth/mutation-challenges/poll/poll_yank_0123456789",
            move |_req, _server| {
                let mut n = poll_responder_count.lock().unwrap();
                *n += 1;
                let body = if *n == 1 {
                    r#"{"status":"pending","challenge_expires_in":240,"recommended_poll_interval_secs":1}"#
                } else {
                    r#"{"status":"ready","grant_expires_in":300}"#
                };
                Response {
                    code: 200,
                    headers: vec!["Cache-Control: no-store".into()],
                    body: body.as_bytes().to_vec(),
                }
            },
        )
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

    p.cargo("yank --quiet --version 0.0.1 --mutation-authorization-channel=poll")
        .replace_crates_io(registry.index_url())
        .with_stderr_contains("[..]Instructions from registry http://127.0.0.1:[..]:[..]")
        .with_stderr_contains(
            "[..]Waiting up to 300 seconds for registry authorization; press Ctrl-C to cancel.[..]",
        )
        .run();

    assert_eq!(*yank_count.lock().unwrap(), 1);
    assert_eq!(*poll_count.lock().unwrap(), 2);
}
