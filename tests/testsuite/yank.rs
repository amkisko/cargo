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

/// Registry returns `mfa_required`; Cargo polls until acknowledged, then retries yank.
#[cargo_test]
fn api_mfa_required_then_retry() {
    let yank_count = Arc::new(Mutex::new(0u32));
    let poll_count = Arc::new(Mutex::new(0u32));

    let registry = RegistryBuilder::new()
        .http_api()
        .add_responder("/api/v1/crates/foo/0.0.1/yank", move |req, server| {
            let mut n = yank_count.lock().unwrap();
            *n += 1;
            if *n == 1 {
                let origin = req.url.origin().ascii_serialization();
                let body = format!(
                    r#"{{"errors":[{{"detail":"API MFA required","id":"mfa_required","operation_id":"mfa_yank","operation":"yank","crate":"foo","verification_url":"{origin}/mfa/verify/mfa_yank","poll_url":"{origin}/api/v1/mfa/challenges/mfa_yank","expires_at":"2099-01-01T00:00:00Z","recommended_poll_interval_secs":0}}]}}"#
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
        .add_responder("/api/v1/mfa/challenges/mfa_yank", move |_req, _server| {
            let mut n = poll_count.lock().unwrap();
            *n += 1;
            let status = if *n == 1 { "pending" } else { "acknowledged" };
            let acknowledged = status == "acknowledged";
            let body = format!(
                r#"{{"operation_id":"mfa_yank","status":"{status}","acknowledged":{acknowledged},"verified":{acknowledged},"operation":"yank","crate_name":"foo","expires_at":"2099-01-01T00:00:00Z","localhost_port":null,"recommended_poll_interval_secs":0}}"#
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

    p.cargo("yank --version 0.0.1")
        .replace_crates_io(registry.index_url())
        .with_stderr_data(str![[r#"
[UPDATING] crates.io index
[YANK] foo@0.0.1
[NOTE] API MFA required; complete passkey verification in your browser, then Cargo will retry
[VERIFYING] please visit http://127.0.0.1:[..]/mfa/verify/mfa_yank
[NOTE] API MFA acknowledged; retrying request

"#]])
        .run();
}
