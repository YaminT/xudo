//! Every manual page names the workspace version in its `.TH` header.
//!
//! The fourth argument is `product version`. A page left on `0.0.1` after the
//! workspace moved on is the page the package installs.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::Path;

fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `version` under `[workspace.package]`, not a later crate's version.
fn workspace_version(manifest: &str) -> String {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[workspace.package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some(rest) = line.strip_prefix("version") else {
            continue;
        };
        let rest = rest.trim_start().strip_prefix('=').unwrap().trim();
        return rest
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap()
            .to_owned();
    }
    panic!("Cargo.toml has no [workspace.package] version");
}

/// Arguments of a `.TH` line. Quoted fields keep their spaces.
fn roff_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        if ch == '"' {
            let mut field = String::new();
            for inner in chars.by_ref() {
                if inner == '"' {
                    break;
                }
                field.push(inner);
            }
            fields.push(field);
            continue;
        }
        let mut field = String::from(ch);
        while let Some(next) = chars.peek().copied() {
            if next.is_whitespace() {
                break;
            }
            field.push(next);
            chars.next();
        }
        fields.push(field);
    }
    fields
}

/// The version token in `.TH name section date "product version" manual`.
/// That product field is the fourth argument, after the date.
fn header_version(line: &str) -> String {
    let fields = roff_fields(line.trim());
    assert!(
        fields.first().is_some_and(|field| field == ".TH") && fields.len() >= 6,
        "not a .TH header: {line}"
    );
    fields
        .get(4)
        .unwrap()
        .split_whitespace()
        .next_back()
        .unwrap()
        .to_owned()
}

#[test]
fn every_man_header_names_the_workspace_version() {
    let root = workspace_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let version = workspace_version(&manifest);
    let mut pages = Vec::new();
    for entry in fs::read_dir(root.join("docs/man")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            pages.push(path);
        }
    }
    assert!(!pages.is_empty(), "docs/man has no pages");
    let stale: Vec<_> = pages
        .iter()
        .filter_map(|path| {
            let text = fs::read_to_string(path).unwrap();
            let header = text.lines().next().unwrap();
            (header_version(header) != version).then(|| {
                format!(
                    "{} names {}",
                    path.file_name().unwrap().to_str().unwrap(),
                    header_version(header)
                )
            })
        })
        .collect();
    assert!(
        stale.is_empty(),
        "man headers must name workspace version {version}: {stale:?}"
    );
}

#[test]
fn the_header_reader_rejects_a_stale_version() {
    assert_eq!(
        header_version(r#".TH XUDO 1 "2026-11-07" "xudo 0.0.1" "User Commands""#),
        "0.0.1"
    );
    assert_eq!(
        header_version(r#".TH IDO-QUEUE 5 "2026-10-14" "ido 0.1.0-beta.1" "File Formats""#),
        "0.1.0-beta.1"
    );
    let manifest =
        "[workspace]\nversion = \"9.9.9\"\n\n[workspace.package]\nversion = \"0.1.0-beta.1\"\n";
    assert_eq!(workspace_version(manifest), "0.1.0-beta.1");
}
