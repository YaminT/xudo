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

const STALE_PRIVILEGED_RUST_DOC_CLAIMS: [&str; 5] = [
    "every caller is unattested",
    "no caller is a verified harness",
    "no caller can be a registered agent",
    "every caller takes the human path",
    "every caller takes the password path",
];

fn rust_doc_comments(text: &str) -> String {
    let docs = text
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix("//!")
                .or_else(|| trimmed.strip_prefix("///"))
        })
        .collect::<Vec<_>>()
        .join(" ");
    flatten_claim(&docs)
}

fn stale_privileged_rust_doc_claim(text: &str) -> bool {
    let docs = rust_doc_comments(text);
    STALE_PRIVILEGED_RUST_DOC_CLAIMS
        .iter()
        .any(|claim| docs.contains(claim))
}

fn rust_files(directory: &Path, found: &mut Vec<String>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            found.push(path.display().to_string());
        }
    }
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
fn privileged_rust_docs_do_not_make_stale_public_claims() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let crates = root.join("crates");
    let mut files = Vec::new();
    for entry in fs::read_dir(&crates).unwrap() {
        let source = entry.unwrap().path().join("src");
        if source.is_dir() {
            rust_files(&source, &mut files);
        }
    }
    let stale: Vec<_> = files
        .iter()
        .filter(|file| stale_privileged_rust_doc_claim(&fs::read_to_string(file).unwrap()))
        .cloned()
        .collect();
    assert!(
        stale.is_empty(),
        "stale claims in Rust doc comments: {stale:?}"
    );
}

#[test]
fn rust_doc_comment_check_catches_stale_claims_and_allows_current_wording() {
    assert!(stale_privileged_rust_doc_claim(
        "//! every caller is Unattested; no caller is a verified harness in this release"
    ));
    assert!(stale_privileged_rust_doc_claim(
        "/// every caller takes the\n/// password path"
    ));
    assert!(!stale_privileged_rust_doc_claim(
        "//! The broker classifies the peer from kernel facts and the root registry.\n\
         //! A live service harness in a root-registered scope is an enrolled agent;\n\
         //! every other caller takes the password path."
    ));
    assert!(!stale_privileged_rust_doc_claim(
        "// every caller is unattested\nfn internal() {}"
    ));
}

#[test]
fn public_docs_pin_correct_queue_freeze_session_and_audit_limits() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let how = fs::read_to_string(root.join("howiwork.md")).unwrap();
    let security = fs::read_to_string(root.join("SECURITY.md")).unwrap();
    let manual = fs::read_to_string(root.join("docs/man/xudo.1")).unwrap();
    let queue_manual = fs::read_to_string(root.join("docs/man/ido.1")).unwrap();
    let rules_manual = fs::read_to_string(root.join("docs/man/xudo-rules.5")).unwrap();

    for text in [&how, &security, &queue_manual] {
        let flat = flatten_claim(text);
        assert!(flat.contains("can see its own entry"));
        assert!(flat.contains("cannot edit, claim, release, or answer"));
    }
    for text in [&how, &security, &manual] {
        let flat = flatten_claim(text);
        assert!(flat.contains("root's thaw lifts every"));
        assert!(flat.contains("same-uid watcher on another tty"));
        assert!(flat.contains("no start command"));
    }
    assert!(flatten_claim(&how).contains("bounded, caller-controlled argv[0]"));
    assert!(flatten_claim(&security).contains("bounded, caller-controlled argv[0]"));
    assert!(how.contains("must set `owners`"));
    assert!(how.contains("not a supported operation outcome"));
    assert!(rules_manual.contains("must set"));
    assert!(rules_manual.contains("not supported for operations"));
}

#[test]
fn public_docs_say_a_fuse_mount_can_stall_the_reviewed_pack_read() {
    // An agent-owned FUSE mount with allow_other under the path the operator
    // names can block the root step; the docs must say so and say what to do.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for file in ["howiwork.md", "SECURITY.md"] {
        let flat = flatten_claim(&fs::read_to_string(root.join(file)).unwrap());
        for needle in [
            "opens a path the operator names",
            "fuse mount with allow_other",
            "can stall the root step",
            "o_nonblock does not help",
            "the operator can interrupt it",
            "review packs from a directory you own",
        ] {
            assert!(flat.contains(needle), "{file}: {needle}");
        }
    }
}

#[test]
fn public_docs_say_a_same_uid_process_can_answer_a_watch_prompt() {
    // The watcher must only be in another session on another terminal: a
    // process of the requester's uid can openpty and setsid. The docs must
    // not promise more, and must say the password still applies.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for file in ["howiwork.md", "SECURITY.md", "docs/man/xudo.1"] {
        let flat = flatten_claim(&fs::read_to_string(root.join(file)).unwrap());
        assert!(
            flat.contains("can open a pty in a new session and answer"),
            "{file}"
        );
    }
    for file in ["howiwork.md", "SECURITY.md"] {
        let flat = flatten_claim(&fs::read_to_string(root.join(file)).unwrap());
        assert!(
            flat.contains("the password at -auth still applies"),
            "{file}"
        );
    }
}

#[test]
fn public_docs_say_the_agent_path_refuses_at_ptrace_scope_zero() {
    // At 0 a process of the service account outside its unit (an SSH key
    // login, a cron job) can attach to the harness: the docs once said such
    // a login "is not enough", which is false there.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let how = fs::read_to_string(root.join("howiwork.md")).unwrap();
    let security = fs::read_to_string(root.join("SECURITY.md")).unwrap();
    let manual = fs::read_to_string(root.join("docs/man/xudo.1")).unwrap();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    for text in [&how, &security, &manual] {
        let flat = flatten_claim(text);
        assert!(!flat.contains("an ssh login as the service account is not enough"));
        assert!(flat.contains("an ssh key login, a cron or at job, a lingering user manager"));
        assert!(flat.contains("is 0 or cannot be read"));
        assert!(flat.contains("leaves the agent path off"));
    }
    assert!(flatten_claim(&readme).contains("refuses while kernel.yama.ptrace_scope is 0"));
}

/// A sentence that says a process of the service account outside its unit
/// "is not enough": false, because such a process can edit the harness's
/// home and configuration, or restart it with edited settings.
fn stale_service_account_claim(flat: &str) -> bool {
    flat.split(['.', ';'])
        .any(|sentence| sentence.contains("service account") && sentence.contains("not enough"))
}

/// Every public page, the site's HTML included.
fn public_pages() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = vec![
        "README.md".to_owned(),
        "SECURITY.md".to_owned(),
        "howiwork.md".to_owned(),
        "docs/man/xudo.1".to_owned(),
    ];
    let mut site = Vec::new();
    markdown_and_html_files(&root.join("site"), &mut site);
    assert!(site.len() >= 5, "{site:?}");
    files.extend(site);
    files
        .into_iter()
        .map(|file| {
            let text = fs::read_to_string(root.join(&file)).unwrap();
            let name = Path::new(&file)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            (name, flatten_claim(&text))
        })
        .collect()
}

#[test]
fn no_public_page_says_the_service_account_outside_its_unit_is_harmless() {
    for (file, flat) in public_pages() {
        assert!(!stale_service_account_claim(&flat), "{file}");
        assert!(
            !flat.contains("an ssh login as the service account is not enough"),
            "{file}"
        );
    }
    // The pages that describe the service way say what the account is.
    for (file, flat) in public_pages() {
        if [
            "howiwork.md",
            "SECURITY.md",
            "xudo.1",
            "security.html",
            "how-it-works.html",
        ]
        .contains(&file.as_str())
        {
            assert!(flat.contains("trusted exactly like the harness"), "{file}");
            assert!(flat.contains("no logins"), "{file}");
        }
    }
}

#[test]
fn public_pages_say_broker_and_gate_recheck_ptrace_scope_on_every_run() {
    for (file, flat) in public_pages() {
        if ["howiwork.md", "SECURITY.md", "xudo.1", "security.html"].contains(&file.as_str()) {
            assert!(
                flat.contains("read the live value again on every passwordless run"),
                "{file}"
            );
            assert!(flat.contains("ptrace_scope_open"), "{file}");
            assert!(flat.contains("disabled"), "{file}");
            assert!(flat.contains("is 0 or cannot be read"), "{file}");
        }
        if ["README.md", "how-it-works.html"].contains(&file.as_str()) {
            assert!(flat.contains("on every passwordless run"), "{file}");
        }
    }
}

#[test]
fn the_site_says_a_same_uid_process_can_answer_a_watch_prompt() {
    let pages = public_pages();
    let security = &pages
        .iter()
        .find(|(file, _)| file == "security.html")
        .unwrap()
        .1;
    assert!(security.contains("can open a pty in a new session and answer"));
    assert!(security.contains("the password at -auth still applies"));
    assert!(security.contains("a same-uid watcher on another tty"));
}

#[test]
fn the_service_account_check_catches_the_old_claim() {
    let old = flatten_claim(
        "A similarly named process is not enough, and neither is a process of the service \
         account outside the unit (an SSH key login): it is not in the scope.",
    );
    assert!(stale_service_account_claim(&old));
    let new = flatten_claim(
        "A similarly named process is not. A process of the service account outside the unit \
         is not in the scope, but it can edit the harness's home directory.",
    );
    assert!(!stale_service_account_claim(&new));
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
