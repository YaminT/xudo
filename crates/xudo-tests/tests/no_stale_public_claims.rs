//! Public docs must describe what ships, and no permanent claim of the old approval model.

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
    lower.split(['.', '!', '?']).any(|sentence| {
        sentence.contains("strace")
            && (sentence.contains("does not exist")
                || sentence.contains("doesn't exist")
                || sentence.contains("planned"))
    })
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

/// Claims made obsolete by the service enrollment, broker queue, agent path,
/// and reviewed rule packs shipped in beta.2.
fn stale_shipped_feature_claim(text: &str) -> bool {
    let flat = flatten_claim(text);
    [
        "every caller is unattested",
        "no caller can be a registered agent",
        "nothing in this release creates such a scope",
        "empty until agents can be registered",
        "enrollment is not built",
        "enrolment is not built",
        "rule packs are not built",
        "rule packs are not in this release",
        "passwordless agent path is not in this release",
        "passwordless agent path is not yet shipped",
        "does not enroll or authenticate agents",
    ]
    .iter()
    .any(|claim| flat.contains(claim))
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
fn public_docs_do_not_claim_built_checks_or_features_are_absent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = vec![
        "README.md".to_owned(),
        "SECURITY.md".to_owned(),
        "CHANGELOG.md".to_owned(),
        "llms.txt".to_owned(),
    ];
    markdown_and_html_files(&root.join("site"), &mut files);

    let stale: Vec<_> = files
        .iter()
        .filter_map(|file| {
            let path = root.join(file);
            let text = fs::read_to_string(&path).unwrap();
            (stale_confirmation_claim(&text)
                || stale_telemetry_claim(&text)
                || stale_probe_claim(&text)
                || (file != "CHANGELOG.md" && stale_shipped_feature_claim(&text)))
            .then(|| file.clone())
        })
        .collect();

    assert!(stale.is_empty(), "stale public status claims in: {stale:?}");
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
    // The beta.1 section stays as it was released: found by its heading, so
    // later sections above it do not move it.
    let shipped = changelog
        .split("\n## ")
        .find(|section| section.starts_with("0.1.0-beta.1"))
        .unwrap();
    assert!(
        shipped.contains("M3 out-of-band confirmation"),
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
    let shipped = rewritten
        .split("\n## ")
        .find(|section| section.starts_with("0.1.0-beta.1"))
        .unwrap();
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
    let current_status = "Out-of-band confirmation is built and off by default. The passwordless path is built and off by default.";
    assert!(!stale_confirmation_claim(current_status));
    assert!(!stale_shipped_feature_claim(current_status));
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

/// Words that make a password claim a statement about the current release.
const RELEASE_QUALIFIERS: [&str; 6] = [
    "beta",
    "this release",
    "today",
    "currently",
    "this build",
    "for now",
];

/// Phrases of the approval model the owner replaced on 2026-11-16: the agent
/// path is not confirmed live, and invariant 2 is no longer "never broader".
const REPLACED_MODEL: [&str; 6] = [
    "never broader than the human path",
    "passwordless but confirmed",
    "confirmation always",
    "always confirmed",
    "a human approves every",
    "confirmation lives outside",
];

/// A sentence that states the old model, or says every request asks for a
/// password as a permanent property instead of as this release's status.
fn stale_approval_claim(text: &str) -> bool {
    flatten_claim(text)
        .split(['.', '!', '?', ';'])
        .any(|sentence| {
            let every_request_password = [
                "every request",
                "every privileged request",
                "every invocation",
                "always prompt",
                "always asks",
            ]
            .iter()
            .any(|phrase| sentence.contains(phrase))
                && sentence.contains("password");
            REPLACED_MODEL
                .iter()
                .any(|phrase| sentence.contains(phrase))
                || (every_request_password
                    && !RELEASE_QUALIFIERS
                        .iter()
                        .any(|qualifier| sentence.contains(qualifier)))
        })
}

#[test]
fn public_docs_describe_the_current_approval_model() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // CHANGELOG.md is excluded: shipped sections are history and say
    // "Every request uses the human password path" about their own release.
    let mut files = vec![
        "README.md".to_owned(),
        "SECURITY.md".to_owned(),
        "howiwork.md".to_owned(),
        "llms.txt".to_owned(),
        "packaging/deb/first-install-notice".to_owned(),
        "docs/man/xudo.1".to_owned(),
        "docs/man/xudo-rules.5".to_owned(),
        "docs/man/ido.1".to_owned(),
        "docs/man/ido-queue.5".to_owned(),
        "site/llms.txt".to_owned(),
    ];
    markdown_and_html_files(&root.join("site"), &mut files);
    let stale: Vec<_> = files
        .iter()
        .filter(|file| {
            let text = fs::read_to_string(root.join(file)).unwrap();
            stale_approval_claim(&text) || stale_shipped_feature_claim(&text)
        })
        .cloned()
        .collect();
    assert!(
        stale.is_empty(),
        "replaced approval model stated in: {stale:?}"
    );
}

#[test]
fn the_approval_check_catches_permanent_claims_and_allows_the_beta_status() {
    assert!(stale_approval_claim("Every request asks for a password."));
    assert!(stale_approval_claim(
        "A human is always prompted for a password."
    ));
    assert!(stale_approval_claim(
        "The agent path is never broader than the human path in authentication."
    ));
    assert!(stale_approval_claim(
        "An enrolled agent is passwordless but confirmed."
    ));
    assert!(stale_approval_claim(
        "Confirmation lives outside the requester's process tree."
    ));
    assert!(!stale_approval_claim(
        "In this release every privileged request asks for a password."
    ));
    assert!(!stale_approval_claim(
        "This beta always prompts for a password."
    ));
    assert!(!stale_approval_claim(
        "Today's beta builds both the passwordless harness path and the human password path."
    ));
    assert!(!stale_approval_claim(
        "A command runs without a password only for a verified harness."
    ));
    assert!(stale_shipped_feature_claim(
        "No caller can be a registered agent in this release."
    ));
    assert!(stale_shipped_feature_claim(
        "The passwordless agent path is not in this release."
    ));
    assert!(stale_shipped_feature_claim(
        "The root-held queue is empty until agents can be registered."
    ));
    assert!(!stale_shipped_feature_claim(
        "Session start and attach are not implemented in this beta."
    ));
    assert!(!stale_shipped_feature_claim(
        "Passwordless execution is off by default and can be enabled by root."
    ));
}
