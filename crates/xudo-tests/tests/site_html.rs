//! The public site is HTML. A Markdown backtick is shown as a character, so a
//! name belongs in `code`. The index also states, in one sentence, what this
//! passwordless execution is opt-in and names the current confinement limits.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;

fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A backtick in the page source is shown to the reader. `<code>` is not.
fn shows_markdown_backtick(html: &str) -> bool {
    html.contains('`')
}

/// The old claim conflated a disabled-by-default path with an unimplemented one.
fn claims_passwordless_path_unavailable(text: &str) -> bool {
    text.to_ascii_lowercase()
        .split(['.', '!', '?'])
        .any(|sentence| {
            sentence.contains("passwordless agent path")
                && sentence.contains("landlock")
                && sentence.contains("not in this release")
        })
}

#[test]
fn site_pages_do_not_show_markdown_backticks() {
    let site = workspace_root().join("site");
    let mut pages = Vec::new();
    for entry in fs::read_dir(&site).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("html") {
            pages.push(path);
        }
    }
    assert!(
        pages.len() >= 5,
        "site HTML scan saw {:?}; a short list would hide a page",
        pages
            .iter()
            .map(|path| path.file_name().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    let marked: Vec<_> = pages
        .iter()
        .filter(|path| shows_markdown_backtick(&fs::read_to_string(path).unwrap()))
        .map(|path| path.file_name().unwrap().to_str().unwrap().to_owned())
        .collect();
    assert!(
        marked.is_empty(),
        "wrap names in <code>, not Markdown backticks: {marked:?}"
    );
}

#[test]
fn index_states_the_opt_in_and_security_page_states_the_landlock_limit() {
    let index = fs::read_to_string(workspace_root().join("site/index.html")).unwrap();
    assert!(
        index.contains("The agent path is off by default")
            && index.contains("sudo xudo install --agent-path"),
        "index.html must state the default and the opt-in"
    );
    let security = fs::read_to_string(workspace_root().join("site/security.html")).unwrap();
    assert!(security.contains("does not confine code inside the account with Landlock"));
    assert!(!claims_passwordless_path_unavailable(&index));
}

#[test]
fn site_pins_session_uid_and_broker_queue_limits() {
    let root = workspace_root();
    let security = fs::read_to_string(root.join("site/security.html")).unwrap();
    let how = fs::read_to_string(root.join("site/how-it-works.html")).unwrap();
    let faq = fs::read_to_string(root.join("site/faq.html")).unwrap();
    assert!(security.contains("a same-uid watcher on another tty"));
    assert!(security.contains("--raise-ptrace-scope</code> takes effect after"));
    assert!(security.contains("refuses while the live value is 0 or cannot be read"));
    assert!(
        how.contains("The agent path is refused while the live <code>ptrace_scope</code> is 0")
    );
    for page in [&how, &faq] {
        assert!(page.contains("can see its own"));
        assert!(page.contains("cannot edit, claim, release, or answer"));
        assert!(page.contains("asks the broker to release or run"));
        assert!(page.contains("does not rewrite queue files"));
    }
}

#[test]
fn the_checks_catch_a_backtick_and_the_old_unavailable_claim() {
    assert!(!shows_markdown_backtick(
        "<p>Use <code>xudo exec</code>.</p>"
    ));
    assert!(shows_markdown_backtick("<p>Run `xudo exec`.</p>"));
    assert!(claims_passwordless_path_unavailable(
        "The passwordless agent path and Landlock are not in this release."
    ));
    assert!(claims_passwordless_path_unavailable(
        "The passwordless agent path and Landlock confinement are not in this release."
    ));
    assert!(!claims_passwordless_path_unavailable(
        "Next: M4 enrollment and the passwordless path. Landlock is later."
    ));
    assert!(!claims_passwordless_path_unavailable(
        "The passwordless agent path is not in this release. Landlock confinement comes after."
    ));
    assert!(!claims_passwordless_path_unavailable(
        "The agent path is off by default. Landlock is not implemented."
    ));
}
