//! Safe terminal rendering for registry-controlled authorization instructions.

use anyhow::bail;
use url::Url;

use crate::{CargoResult, GlobalContext};

pub(super) fn essential_note(gctx: &GlobalContext, message: &str) -> CargoResult<()> {
    let mut shell = gctx.shell();
    if shell.verbosity() == cargo_util_terminal::Verbosity::Quiet {
        writeln!(shell.err(), "note: {message}")?;
        Ok(())
    } else {
        shell.note(message)
    }
}

pub(super) fn detail_for_user(detail: &str, registry_host: &str) -> CargoResult<String> {
    if detail.len() > crates_io::MUTATION_AUTHORIZATION_DETAIL_MAX_BYTES {
        bail!(
            "registry authorization instructions exceed the {}-byte limit",
            crates_io::MUTATION_AUTHORIZATION_DETAIL_MAX_BYTES
        );
    }

    let detail = sanitize_detail(detail);
    let detail = label_external_urls(&detail, registry_host);
    let registry_origin = Url::parse(registry_host)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| registry_host.trim_end_matches('/').to_owned());
    Ok(format!(
        "Instructions from registry {registry_origin}:\n{detail}"
    ))
}

pub(super) fn sanitize_detail(detail: &str) -> String {
    detail
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .chars()
        .map(|character| match character {
            '\n' => '\n',
            character if character.is_control() || is_bidi_control(character) => '\u{fffd}',
            character => character,
        })
        .collect()
}

fn is_bidi_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

fn url_candidate(word: &str) -> &str {
    word.trim().trim_matches(|character: char| {
        matches!(
            character,
            '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '\'' | '"' | ',' | ';' | '.' | '!'
        )
    })
}

fn label_external_urls(detail: &str, registry_host: &str) -> String {
    detail
        .split_inclusive(char::is_whitespace)
        .map(|word| {
            let candidate = url_candidate(word);
            let Ok(url) = Url::parse(candidate) else {
                return word.to_owned();
            };
            if !matches!(url.scheme(), "http" | "https")
                || crates_io::url_shares_origin_with_registry(candidate, registry_host)
            {
                return word.to_owned();
            }
            word.replacen(candidate, &format!("[external URL: {url}]"), 1)
        })
        .collect()
}
