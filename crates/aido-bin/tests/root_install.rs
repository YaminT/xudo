//! `aido install` and `aido install --uninstall`, the real binary, as real root.
//!
//! The unit tests drive the executor against a fake machine and the container
//! harness (`just install-root`) drives the static binary across sudo, sudo-rs
//! and `OpenDoas`. This is the same command in the root lane: the process the
//! packaging scripts run, against the container's real `/etc` and the real
//! `sudo` the lane installs, asserting the two things an operator relies on. The
//! file that lands is `root:root` and `0440`, and an install says out loud that
//! it was not shown to work, with a failing status, until the functional probe
//! exists (it needs the broker client, M2b plan item C1).
//!
//! This package owns the binary, so Cargo builds it fresh for these tests and
//! sets `CARGO_BIN_EXE_aido`: a binary found any other way could be a stale one.
//! See `aido-sys/tests/root_lane.rs` for how the lane works.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use aido_tests::root_lane::root_guard;

use std::fs::{self, File, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use assert_cmd::Command;

const AIDO: &str = env!("CARGO_BIN_EXE_aido");
const SNIPPET: &str = "/etc/sudoers.d/aido";

fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    let _ = fs::remove_file(SNIPPET);
    fs::create_dir_all("/etc/sudoers.d").unwrap();
    true
}

/// Runs `aido` with `args`: its status, and everything it said.
fn aido(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(AIDO).args(args).output().unwrap();
    (
        output.status.code().unwrap(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn install_as_root_writes_the_snippet_and_says_it_was_not_verified() {
    if !begin_root_test("install_as_root_writes_the_snippet_and_says_it_was_not_verified") {
        return;
    }
    let (code, out, err) = aido(&["install"]);

    assert_eq!(code, 19, "an unverified install must fail:\n{out}\n{err}");
    assert!(err.contains("NOT VERIFIED"), "{err}");
    assert!(
        !out.contains("verified     "),
        "the install claimed a probe passed:\n{out}"
    );
    let meta = fs::symlink_metadata(SNIPPET).unwrap();
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777, meta.nlink()),
        (0, 0, 0o440, 1)
    );
    let text = fs::read_to_string(SNIPPET).unwrap();
    assert!(text.contains("PASSWD:"), "{text}");
    assert!(!text.contains("NOPASSWD"), "{text}");
    // The backend was asked whether it reads the rule, on a line of its own. What
    // it answers depends on whether another test has put an account in the
    // group, so either honest answer passes; a warning does not, and neither
    // does an answer that reads as a verification.
    assert!(
        out.contains("not checked") || out.contains("the rule is read"),
        "{out}"
    );
    assert!(!out.contains("NOT in effect"), "{out}");
    let _ = fs::remove_file(SNIPPET);
}

#[test]
fn uninstall_as_root_removes_what_install_wrote_and_nothing_else() {
    if !begin_root_test("uninstall_as_root_removes_what_install_wrote_and_nothing_else") {
        return;
    }
    let neighbour = "/etc/sudoers.d/operators-own";
    File::create(neighbour)
        .unwrap()
        .write_all(b"# the operator's own\n")
        .unwrap();
    fs::set_permissions(neighbour, Permissions::from_mode(0o440)).unwrap();
    assert_eq!(aido(&["install"]).0, 19);

    let (code, out, err) = aido(&["install", "--uninstall"]);

    assert_eq!(code, 0, "{out}\n{err}");
    assert!(fs::symlink_metadata(SNIPPET).is_err(), "the snippet stayed");
    assert_eq!(
        fs::read_to_string(neighbour).unwrap(),
        "# the operator's own\n"
    );
    // A second uninstall has nothing to do and says nothing is wrong.
    assert_eq!(aido(&["install", "--uninstall"]).0, 0);
    fs::remove_file(neighbour).unwrap();
}

#[test]
fn uninstall_refuses_a_file_the_operator_wrote() {
    if !begin_root_test("uninstall_refuses_a_file_the_operator_wrote") {
        return;
    }
    let theirs = "# the operator's own file, under aido's name\n";
    File::create(SNIPPET)
        .unwrap()
        .write_all(theirs.as_bytes())
        .unwrap();
    fs::set_permissions(SNIPPET, Permissions::from_mode(0o440)).unwrap();

    let (code, _, err) = aido(&["install", "--uninstall"]);
    assert_eq!(code, 19, "{err}");
    assert_eq!(fs::read_to_string(SNIPPET).unwrap(), theirs);

    let (code, _, err) = aido(&["install"]);
    assert_eq!(code, 19, "{err}");
    assert_eq!(fs::read_to_string(SNIPPET).unwrap(), theirs);
    let _ = fs::remove_file(SNIPPET);
}
