//! The public site is HTML. A Markdown backtick is shown as a character, so a
//! name belongs in `code`. The index also states, in one sentence, what this
//! release does not ship.

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

/// One sentence names both absences. A roadmap mention of either is not that.
fn states_passwordless_and_landlock_absent(text: &str) -> bool {
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
fn index_states_passwordless_path_and_landlock_are_not_in_this_release() {
    let index = fs::read_to_string(workspace_root().join("site/index.html")).unwrap();
    assert!(
        states_passwordless_and_landlock_absent(&index),
        "index.html must say the passwordless agent path and Landlock are not in this release"
    );
}

#[test]
fn the_checks_catch_a_backtick_and_a_split_absence() {
    assert!(!shows_markdown_backtick(
        "<p>Use <code>xudo exec</code>.</p>"
    ));
    assert!(shows_markdown_backtick("<p>Run `xudo exec`.</p>"));
    assert!(states_passwordless_and_landlock_absent(
        "The passwordless agent path and Landlock are not in this release."
    ));
    assert!(states_passwordless_and_landlock_absent(
        "The passwordless agent path and Landlock confinement are not in this release."
    ));
    assert!(!states_passwordless_and_landlock_absent(
        "Next: M4 enrollment and the passwordless path. Landlock is later."
    ));
    assert!(!states_passwordless_and_landlock_absent(
        "The passwordless agent path is not in this release. Landlock confinement comes after."
    ));
}
