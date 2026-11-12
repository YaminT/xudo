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

/// Public prose with markup and line breaks collapsed, so a claim split by
/// `<code>` or a backtick still matches the words a reader sees.
fn flatten_claim(text: &str) -> String {
    let stripped = text
        .replace("<code>", "")
        .replace("</code>", "")
        .replace('`', "");
    let mut flat = String::new();
    for word in stripped.split_whitespace() {
        if !flat.is_empty() {
            flat.push(' ');
        }
        flat.push_str(&word.to_ascii_lowercase());
    }
    flat
}

fn gnu_id_workaround(flat: &str) -> bool {
    flat.contains("install gnu id") || flat.contains("gnu coreutils")
}

/// "Near" is the same sentence. The version dot in `26.04` is not a boundary,
/// so the next sentence may name the release and `NOT VERIFIED` separately.
fn ubuntu_2604_near_not_verified(flat: &str) -> bool {
    flat.replace("26.04", "26-04")
        .split(['.', '!', '?'])
        .any(|sentence| sentence.contains("26-04") && sentence.contains("not verified"))
}

fn stale_probe_claim(text: &str) -> bool {
    let flat = flatten_claim(text);
    gnu_id_workaround(&flat) || ubuntu_2604_near_not_verified(&flat)
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
            (stale_confirmation_claim(&text)
                || stale_telemetry_claim(&text)
                || stale_probe_claim(&text))
            .then(|| file.clone())
        })
        .collect();

    assert!(
        stale.is_empty(),
        "stale public release claims in: {stale:?}"
    );
}

#[test]
fn changelog_puts_unreleased_above_the_shipped_version() {
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
    // The shipped section stays as it was released: its own heading, followed
    // by what it shipped, below an Unreleased that carries what comes next.
    let shipped = changelog.split("\n## ").nth(2).unwrap();
    assert!(
        shipped.starts_with(&version) && shipped.contains("M3 out-of-band confirmation"),
        "the shipped section changed: {shipped}"
    );
    let unreleased = changelog.split("\n## ").nth(1).unwrap();
    assert!(unreleased.starts_with("Unreleased"), "{unreleased}");
}

#[test]
fn the_changelog_check_catches_a_rewritten_shipped_section() {
    // Canary: the same split applied to a changelog whose shipped section was
    // emptied must not satisfy the assertion above.
    let rewritten = "# C\n\n## Unreleased\n\n- x\n\n## 0.1.0-beta.1 - 2026-11-10\n\n- other\n";
    let shipped = rewritten.split("\n## ").nth(2).unwrap();
    assert!(!shipped.contains("M3 out-of-band confirmation"));
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

#[test]
fn stale_probe_claims_fail_the_old_readme_and_allow_current_wording() {
    const OLD_README: &str = "The install probe reports `installed, but NOT VERIFIED` on doas and \
         multicall-coreutils systems. Examples include stock Ubuntu 26.04 and Alpine, where \
         `/usr/bin/id` is uutils or a multicall applet. The Ubuntu 26.04 systemd and differential \
         lanes pass because they install GNU `id`.";
    assert!(stale_probe_claim(OLD_README));
    assert!(gnu_id_workaround(&flatten_claim(
        "The lanes pass because they install GNU `id`."
    )));
    assert!(gnu_id_workaround(&flatten_claim(
        "The 26.04 lanes install GNU <code>id</code>."
    )));
    assert!(gnu_id_workaround(&flatten_claim(
        "The disposable lane installs GNU coreutils for the probe."
    )));
    assert!(!gnu_id_workaround(&flatten_claim(
        "Alpine is a multicall-coreutils system with no regular probe program."
    )));
    assert!(ubuntu_2604_near_not_verified(&flatten_claim(
        "Stock Ubuntu 26.04 reports NOT VERIFIED."
    )));
    assert!(ubuntu_2604_near_not_verified(&flatten_claim(
        "Is Ubuntu 26.04 NOT VERIFIED?"
    )));
    assert!(!ubuntu_2604_near_not_verified(&flatten_claim(
        "Ubuntu 26.04 verifies through gnuid."
    )));
    assert!(!ubuntu_2604_near_not_verified(&flatten_claim(
        "The doas install probe remains NOT VERIFIED."
    )));
    assert!(!ubuntu_2604_near_not_verified(&flatten_claim(
        "Ubuntu 26.04! The probe is NOT VERIFIED on doas."
    )));
    assert!(!ubuntu_2604_near_not_verified(&flatten_claim(
        "Nothing about the install probe."
    )));
    assert!(stale_probe_claim(
        "Stock Ubuntu 26.04 reports NOT VERIFIED for the install probe."
    ));
    assert!(!stale_probe_claim(
        "The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a regular file, so \
         stock Ubuntu 26.04 verifies. It reports `installed, but NOT VERIFIED` on doas and on a \
         multicall-coreutils system with no regular probe program, such as Alpine."
    ));
    assert_eq!(flatten_claim(""), "");
    assert_eq!(flatten_claim("GNU"), "gnu");
}
