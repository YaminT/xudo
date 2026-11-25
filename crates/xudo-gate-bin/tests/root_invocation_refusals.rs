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

const GATE_DIR: &str = "/usr/libexec/xudo";
const AUTH: &str = "/usr/libexec/xudo/xudo-gate-auth";
const NOPASS: &str = "/usr/libexec/xudo/xudo-gate-nopass";

/// The two gate files as the package ships them: copies of one binary, root's,
/// `0755`, one name each.
fn install_gate_files() {
    use std::os::unix::fs::{PermissionsExt, chown};
    std::fs::create_dir_all(GATE_DIR).unwrap();
    for path in [AUTH, NOPASS] {
        let _ = std::fs::remove_file(path);
        std::fs::copy(GATE, path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        chown(path, Some(0), Some(0)).unwrap();
    }
}

fn remove_gate_files() {
    for path in [AUTH, NOPASS] {
        let _ = std::fs::remove_file(path);
    }
}

fn code_of(output: &std::process::Output) -> String {
    assert_eq!(output.status.code(), Some(19), "{output:?}");
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    stderr
        .split(['(', ','])
        .nth(1)
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn the_mode_comes_from_the_executed_file_not_argv0() {
    if !begin_root_test("the_mode_comes_from_the_executed_file_not_argv0") {
        return;
    }
    install_gate_files();
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("root-gate-modes");
    std::fs::create_dir_all(&dir).unwrap();

    // Each file, run as itself, passes the mode step: what it refuses next is
    // something later than the invocation (no `sudo` above it, no entry).
    for file in [AUTH, NOPASS] {
        let output = std::process::Command::new(file).output().unwrap();
        assert_ne!(code_of(&output), "gate_failed_invocation", "{file}");
    }

    // `argv[0]` naming the other file is the caller's choice and changes
    // nothing: the executed inode says which it is, and the two must agree.
    for (file, claimed) in [(AUTH, "xudo-gate-nopass"), (NOPASS, "xudo-gate-auth")] {
        let output = std::process::Command::new("/bin/bash")
            .args(["-c", &format!("exec -a {claimed} {file}")])
            .output()
            .unwrap();
        assert_eq!(
            code_of(&output),
            "gate_failed_invocation",
            "{file} as {claimed}"
        );
    }

    // A symlink under the other name reaches the same inode, and so refuses.
    let link = dir.join("xudo-gate-nopass");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(AUTH, &link).unwrap();
    let output = std::process::Command::new(&link).output().unwrap();
    assert_eq!(code_of(&output), "gate_failed_invocation");
    std::fs::remove_file(&link).unwrap();
    remove_gate_files();
}

#[test]
fn a_hardlinked_or_replaced_gate_file_is_refused() {
    if !begin_root_test("a_hardlinked_or_replaced_gate_file_is_refused") {
        return;
    }
    install_gate_files();
    // A hardlink needs the same filesystem, so the second name goes beside
    // the gate files.
    let dir = Path::new(GATE_DIR);
    for (file, other) in [(AUTH, "extra-auth"), (NOPASS, "extra-nopass")] {
        let extra = dir.join(other);
        let _ = std::fs::remove_file(&extra);
        std::fs::hard_link(file, &extra).unwrap();
        for run in [AUTH, NOPASS] {
            let output = std::process::Command::new(run).output().unwrap();
            if file == AUTH {
                // A second name for -auth adds no privilege (`sudo` matches
                // by inode and still asks), so it is not refused.
                assert_ne!(
                    code_of(&output),
                    "gate_failed_invocation",
                    "{run} with {file} linked"
                );
            } else {
                // A second name for -nopass makes the executed file ambiguous.
                assert_eq!(
                    code_of(&output),
                    "gate_failed_invocation",
                    "{run} with {file} linked"
                );
            }
        }
        std::fs::remove_file(&extra).unwrap();
        // Replaced by a symlink to the other file: the trust walk refuses it.
        let moved = format!("{file}.real");
        std::fs::rename(file, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, file).unwrap();
        let output = std::process::Command::new(&moved).output().unwrap();
        assert_eq!(
            code_of(&output),
            "gate_failed_invocation",
            "{file} replaced"
        );
        std::fs::remove_file(file).unwrap();
        std::fs::remove_file(&moved).unwrap();
        install_gate_files();
    }
    // One inode under both gate names is refused in either mode.
    std::fs::remove_file(NOPASS).unwrap();
    std::fs::hard_link(AUTH, NOPASS).unwrap();
    for run in [AUTH, NOPASS] {
        let output = std::process::Command::new(run).output().unwrap();
        assert_eq!(
            code_of(&output),
            "gate_failed_invocation",
            "{run} with one inode under both names"
        );
    }
    remove_gate_files();
}
