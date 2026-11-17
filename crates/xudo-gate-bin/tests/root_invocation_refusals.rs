//! Checks invocation refusals after the real gate successfully resets limits.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods
)]

use std::path::{Path, PathBuf};

use xudo_tests::root_lane::root_guard;

const GATE: &str = env!("CARGO_BIN_EXE_xudo-gate");

fn begin_root_test(test: &str) -> bool {
    root_guard(test)
}

fn named(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("root-gate-invocations");
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join(name);
    match std::fs::hard_link(GATE, &link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("cannot link gate as {name}: {error}"),
    }
    link
}

fn assert_invocation_refusal(output: &std::process::Output) {
    assert_eq!(output.status.code(), Some(19));
    assert!(output.stdout.is_empty());
    assert_eq!(
        output.stderr,
        b"xudo-gate: refused (gate_failed_invocation, severity high)\n"
    );
}

#[test]
fn bad_arguments_and_bad_name_are_refused_after_the_root_limit_reset() {
    if !begin_root_test("bad_arguments_and_bad_name_are_refused_after_the_root_limit_reset") {
        return;
    }

    // A caller-state refusal would have a different code. Seeing the
    // invocation refusal proves the gate completed its limit reset first.
    let bad_arguments = std::process::Command::new(named("xudo-gate-auth"))
        .arg("--help")
        .output()
        .unwrap();
    assert_invocation_refusal(&bad_arguments);

    let bad_name = std::process::Command::new(named("sh")).output().unwrap();
    assert_invocation_refusal(&bad_name);
}
