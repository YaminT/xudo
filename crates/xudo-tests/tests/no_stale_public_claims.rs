//! Public docs must describe the shipped M3 confirmation and telemetry check.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;

fn stale_confirmation_claim(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.split(['.', '!', '?']).any(|sentence| {
        sentence.contains("out-of-band confirmation")
            && (sentence.contains("not in this release")
                || sentence.contains("not in this beta")
                || sentence.contains("does not exist")
                || sentence.contains("is not built"))
    })
}

fn stale_telemetry_claim(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("strace")
        && (lower.contains("does not exist")
            || lower.contains("doesn't exist")
            || lower.contains("planned"))
}

fn markdown_and_html_files(directory: &Path, found: &mut Vec<String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            markdown_and_html_files(&path, found);
        } else if matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("md" | "html")
        ) {
            found.push(path.display().to_string());
        }
    }
}

#[test]
fn public_docs_do_not_claim_m3_or_strace_check_is_absent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = vec![
        "README.md".to_owned(),
        "SECURITY.md".to_owned(),
        "CHANGELOG.md".to_owned(),
    ];
    markdown_and_html_files(&root.join("site"), &mut files);

    let stale: Vec<_> = files
        .iter()
        .filter_map(|file| {
            let path = root.join(file);
            let text = fs::read_to_string(&path).unwrap();
            (stale_confirmation_claim(&text) || stale_telemetry_claim(&text)).then(|| file.clone())
        })
        .collect();

    assert!(
        stale.is_empty(),
        "stale public release claims in: {stale:?}"
    );
}

#[test]
fn changelog_puts_an_empty_unreleased_above_the_shipped_version() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let changelog = fs::read_to_string(root.join("CHANGELOG.md")).unwrap();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let version = manifest
        .lines()
        .skip_while(|line| line.trim() != "[workspace.package]")
        .skip(1)
        .find_map(|line| {
            line.trim()
                .strip_prefix("version")?
                .trim_start()
                .strip_prefix('=')?
                .trim()
                .strip_prefix('"')?
                .strip_suffix('"')
                .map(str::to_owned)
        })
        .unwrap();
    let headings: Vec<_> = changelog
        .lines()
        .filter(|line| line.starts_with("## "))
        .collect();
    assert_eq!(headings.first().copied(), Some("## Unreleased"));
    assert!(
        headings
            .get(1)
            .is_some_and(|heading| heading.starts_with(&format!("## {version}"))),
        "shipped section is not {version}: {headings:?}"
    );
    let unreleased = changelog.split("## Unreleased").nth(1).unwrap();
    let body = unreleased.split("\n## ").next().unwrap();
    assert!(
        body.trim().is_empty(),
        "Unreleased should stay empty until the next release: {body}"
    );
}

#[test]
fn the_check_catches_stale_claims_and_allows_current_status() {
    assert!(stale_confirmation_claim(
        "Out-of-band confirmation is not in this release."
    ));
    assert!(stale_confirmation_claim(
        "Out-of-band confirmation is not in this beta."
    ));
    assert!(!stale_confirmation_claim(
        "Out-of-band confirmation is built and off by default. The passwordless path is not in this beta."
    ));
    assert!(stale_confirmation_claim(
        "The passwordless path and out-of-band confirmation are not in this release."
    ));
    assert!(stale_telemetry_claim(
        "The planned strace CI check does not exist yet."
    ));
    assert!(stale_telemetry_claim(
        "strace check is planned for a later release."
    ));
    assert!(!stale_confirmation_claim(
        "Out-of-band confirmation is built and off by default."
    ));
    assert!(!stale_telemetry_claim(
        "just telemetry runs the strace no-telemetry check."
    ));
}
