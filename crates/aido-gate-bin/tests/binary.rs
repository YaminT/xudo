//! The gate, run as a process.
//!
//! The sequence is tested in the `aido-gate` library, step by step, against
//! fakes. What only a process shows is what `sudo` and a hostile user can
//! both see: the exit status, the single line on standard error, and that the
//! binary does what the library says when it is started the way it will be
//! started — under a hardlink's name, with whatever descriptors it was left.
//!
//! These tests run unprivileged, as the hostile user does, so they can only
//! ever show a refusal. What the gate does with an entry minted for it needs a
//! root-owned spool and ruleset, and a process that runs them as root: that is
//! the executing half of the differential matrix (`aido-tests`, M2b step 8).
//!
//! # Where each refusal comes from depends on the host
//!
//! On Linux the gate gets as far as its invocation check, and, for the one
//! name that runs, as far as the ruleset, which a test host does not have.
//! Off Linux `close_range` is refused first, because nothing privileged may
//! happen on a development host. Each test names both.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::{contains, starts_with};

/// The binary Cargo built for this package's tests.
const GATE: &str = env!("CARGO_BIN_EXE_aido-gate");

/// The first step the gate cannot take on this host, for a refusal that comes
/// before the invocation is looked at.
const FIRST_STEP: &str = if cfg!(target_os = "linux") {
    "gate_failed_invocation"
} else {
    "gate_failed_descriptors"
};

/// What the one name that runs reaches on a host with no aido installed: the
/// ruleset on Linux, and `close_range` elsewhere.
const NO_AIDO_HERE: &str = if cfg!(target_os = "linux") {
    "gate_failed_rules"
} else {
    "gate_failed_descriptors"
};

/// A hardlink to the gate under `name`, as the installer makes
/// `aido-gate-auth` — in the workspace's target directory, never `/tmp`.
fn named(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("gate-names");
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join(name);
    match std::fs::hard_link(GATE, &link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("cannot link the gate as {name}: {error}"),
    }
    link
}

fn refusal_line(code: &str, severity: &str) -> String {
    format!("aido-gate: refused ({code}, severity {severity})\n")
}

#[test]
fn a_direct_hostile_invocation_with_no_entry_does_nothing_and_exits_unusable() {
    // Every member of the `aido` group may start the gate through sudo, so
    // starting it with nothing to act on is the ordinary attack. Exit 19,
    // nothing on standard output, one line on standard error.
    Command::new(named("aido-gate-auth"))
        .assert()
        .code(19)
        .stdout("")
        .stderr(starts_with("aido-gate: refused (gate_failed_").and(contains(NO_AIDO_HERE)));
}

#[test]
fn arguments_are_refused() {
    // The sudoers rule grants the gate with no arguments at all.
    let expected = if cfg!(target_os = "linux") {
        refusal_line("gate_failed_invocation", "high")
    } else {
        refusal_line("gate_failed_descriptors", "normal")
    };
    for args in [vec!["--help"], vec!["exec", "/bin/sh"], vec![""]] {
        Command::new(named("aido-gate-auth"))
            .args(&args)
            .assert()
            .code(19)
            .stdout("")
            .stderr(expected.clone());
    }
}

#[test]
fn an_unexpected_argv0_is_refused() {
    // The installed name, the passwordless name that is not shipped until M4,
    // and a name that is neither. Only the `-auth` hardlink runs.
    for name in ["aido-gate", "aido-gate-nopass", "sh"] {
        let output = Command::new(named(name)).output().unwrap();
        assert_eq!(output.status.code(), Some(19), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(FIRST_STEP), "{name}: {stderr}");
        if cfg!(target_os = "linux") {
            assert!(stderr.contains("severity high"), "{name}: {stderr}");
        }
    }
}

#[test]
fn the_refusal_line_carries_a_code_and_nothing_the_caller_supplied() {
    // Nothing the caller controls reaches the line a terminal will print.
    let output = Command::new(named("aido-gate-auth"))
        .arg("\x1b]0;pwned\x07")
        .arg("--secret-token-4711")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    assert!(!stderr.contains("secret-token-4711"), "{stderr:?}");
    assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
}

#[test]
fn closed_standard_streams_do_not_change_what_the_gate_does() {
    // Started with descriptors 0, 1 and 2 closed, as a set-user-ID program's
    // attacker would start it. What fills them here is Rust's runtime, which
    // replaces a closed 0, 1 or 2 with /dev/null before `main` runs, so the
    // gate's own fill (`aido-sys`, `hygiene`) is never reached from a process
    // test, and this test cannot show that it works. It shows what a process
    // can: the gate refuses exactly as it does with them open, and what it
    // opens afterwards is never standard error. The fill itself, and that a
    // filled stream survives the exec that follows, is held on the real
    // descriptors by `aido-sys/tests/std_streams.rs`.
    let link = named("aido-gate-auth");
    let open = Command::new(&link).output().unwrap();
    let closed = Command::new("/bin/sh")
        .args(["-c", r#"exec "$0" <&- >&- 2>&-"#])
        .arg(&link)
        .output()
        .unwrap();
    assert_eq!(open.status.code(), Some(19));
    assert_eq!(closed.status.code(), Some(19));
    // The closed run's diagnostic went to the /dev/null that replaced
    // standard error, not to a file the gate had opened.
    assert!(closed.stdout.is_empty());
    assert!(closed.stderr.is_empty());
}

#[test]
fn a_gate_started_with_a_leaked_descriptor_refuses_without_using_it() {
    // Descriptor 3 left open by the caller, as sudo or a hostile parent may.
    // The gate marks it close-on-exec first and never reads or writes it.
    let link = named("aido-gate-auth");
    let output = Command::new("/bin/sh")
        .args(["-c", r#"exec 3>/dev/null; exec "$0""#])
        .arg(&link)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(19));
    assert!(output.stdout.is_empty());
}

#[test]
fn the_environment_is_never_read() {
    // The gate is reached through sudo, which has already reset the
    // environment, and does not rely on that. Nothing here is an input.
    for (key, value) in [
        ("LD_PRELOAD", ""),
        ("AIDO_RULES", "/tmp/evil"),
        ("PATH", "/tmp/evil"),
        ("CLAUDECODE", "1"),
    ] {
        let output = Command::new(named("aido-gate-auth"))
            .env(key, value)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(19), "{key}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(NO_AIDO_HERE), "{key}: {stderr}");
    }
}
