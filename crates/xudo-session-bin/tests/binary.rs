//! The record helper, run as a process.
//!
//! The logic is tested in `xudod::unit_record` against fakes. What only a
//! process shows is the exit status and the single line on standard error for
//! a caller who is not root and was not started by pid 1: which is every test
//! here, so every test can only show a refusal. A record actually written needs
//! root, a unit under `xudo.slice` and systemd as the parent; that belongs to
//! the systemd lane (H2b).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use predicates::str::{contains, starts_with};

const SESSION: &str = env!("CARGO_BIN_EXE_xudo-session");

fn run(args: &[&str]) -> assert_cmd::assert::Assert {
    Command::new(SESSION).args(args).assert()
}

#[test]
fn a_caller_that_is_not_root_and_not_pid_1s_child_is_refused_and_nothing_is_written() {
    for verb in ["record", "void"] {
        run(&[verb, "codex"])
            .code(1)
            .stderr(starts_with("xudo-session: refused"));
    }
}

#[test]
fn a_command_line_that_is_not_record_or_void_and_a_label_exits_2() {
    run(&[]).code(2).stderr(contains("usage"));
    run(&["record"]).code(2);
    run(&["record", "codex", "extra"]).code(2);
    run(&["start", "codex"]).code(2);
    run(&["record", "Not A Label"]).code(2);
    run(&["record", "../codex"]).code(2);
}

#[cfg(unix)]
#[test]
fn an_argument_that_is_not_utf8_is_a_usage_error_not_a_crash() {
    use std::os::unix::ffi::OsStrExt;
    let hostile = std::ffi::OsStr::from_bytes(b"co\xffdex");
    Command::new(SESSION)
        .arg("record")
        .arg(hostile)
        .assert()
        .code(2)
        .stderr(contains("usage"));
}

#[test]
fn the_environment_cannot_change_the_answer() {
    Command::new(SESSION)
        .args(["record", "codex"])
        .env("XUDO_SESSION_ROOT", "1")
        .env("USER", "root")
        .env("SUDO_UID", "0")
        .assert()
        .code(1);
}
