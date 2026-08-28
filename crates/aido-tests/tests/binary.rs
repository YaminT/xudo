//! The binary, run as a process.
//!
//! Everything else in this crate drives the library directly, which is the
//! right default. These tests exist for the part that only exists in a real
//! process: argument parsing at the entry point, and the exit status a shell
//! actually receives. An exit code asserted only in a unit test is an exit code
//! nobody has watched a shell receive.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

/// A rules directory under the workspace target dir — never `/tmp`.
fn rules_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("10-rules.toml"),
        r#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#,
    )
    .unwrap();
    dir
}

fn aido(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("aido").unwrap();
    cmd.arg("--rules").arg(dir);
    cmd
}

#[test]
fn a_permitted_command_exits_zero() {
    aido(&rules_dir("bin-allow"))
        .args([
            "explain",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ])
        .assert()
        .success()
        .stdout(contains("ALLOW").and(contains("aido.svc.restart")));
}

#[test]
fn a_refused_command_exits_seventeen() {
    // 17, not 1: a shell must be able to tell a policy denial from a crash, and
    // the code sits above the signal range so it cannot be confused with a
    // killed child.
    aido(&rules_dir("bin-deny"))
        .args(["explain", "--", "/usr/bin/systemctl", "restart", "nginx"])
        .assert()
        .code(17)
        .stdout(contains("DENY"));
}

#[test]
fn a_deny_listed_command_exits_seventeen_and_says_not_to_retry() {
    let dir = rules_dir("bin-denylist");
    std::fs::write(
        dir.join("99-oops.toml"),
        r#"
[[action]]
id = "aido.oops"
tier = "diag-read"
exe = "/bin/sh"
args = [{ name = "c", matcher = { literal = "-c" } }]
"#,
    )
    .unwrap();
    aido(&dir)
        .args(["explain", "--action", "aido.oops", "--", "/bin/sh", "-c"])
        .assert()
        .code(17)
        .stdout(contains("deny_listed").and(contains("do not retry")));
}

#[test]
fn an_unusable_ruleset_exits_nineteen() {
    let dir = rules_dir("bin-unusable");
    std::fs::write(dir.join("20-broken.toml"), "[[action]\nid =").unwrap();
    aido(&dir)
        .args(["check"])
        .assert()
        .code(19)
        .stderr(contains("failing closed"));
}

#[test]
fn the_json_envelope_is_parseable_from_a_pipe() {
    // What an agent actually consumes.
    let output = aido(&rules_dir("bin-json"))
        .args([
            "--output",
            "json",
            "explain",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ])
        .output()
        .unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["verdict"], "allow");
}

#[test]
fn doctor_succeeds_and_states_that_nothing_is_executed() {
    aido(&rules_dir("bin-doctor"))
        .args(["doctor"])
        .assert()
        .success()
        .stdout(
            contains("exec path    absent in this build")
                .and(contains("0 trusted"))
                .and(contains("not a")),
        );
}

#[test]
fn check_succeeds_on_the_shipped_ruleset() {
    // The rules that actually ship, run through the real binary.
    let shipped = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("rules");
    Command::cargo_bin("aido")
        .unwrap()
        .args(["--rules", shipped.to_str().unwrap(), "check"])
        .assert()
        .success()
        .stdout(contains("ok:"));
}

#[test]
fn agentdoc_writes_a_block_a_harness_can_splice() {
    aido(&rules_dir("bin-agentdoc"))
        .args(["agentdoc", "--format", "claude"])
        .assert()
        .success()
        .stdout(contains("aido:begin").and(contains("aido:end")));
}

#[test]
fn an_unknown_subcommand_fails_rather_than_defaulting_to_something() {
    Command::cargo_bin("aido")
        .unwrap()
        .arg("frobnicate")
        .assert()
        .failure();
}
