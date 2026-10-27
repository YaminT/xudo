//! `aido audit --log` on the real trail, through the real binary.
//!
//! The trail is written by the real writer (`AuditTrail::system`, as uid 0 in a
//! throwaway container: `just root-test`) and read back by the binary a person
//! would run. It passes on what was written, and it fails on every damage the
//! file itself can show: a cut into the last record, whether one byte of it or
//! half. What it cannot show is pinned too, as assertions that pass: a log that
//! lost only its final newline (nothing of any record is lost, and the writer
//! repairs it on the next append), and whole trailing records dropped cleanly,
//! which leave a log that verifies. The journal copy is the witness for that, and the
//! command's own note says so.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

#[path = "../../aido-tests/tests/support/root_trail.rs"]
mod root_trail;

use aido_audit::record::{Decision, Record};
use aido_sys::{AuditSink as _, AuditTrail};
use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use root_trail::{AUDIT_FILE, Host, root_or_skip};

/// Three records, as the broker and the gate would chain them.
fn write_trail() {
    let mut trail = AuditTrail::system("aido-gate");
    for decision in [Decision::Allowed, Decision::Allowed, Decision::Denied] {
        let build = |previous: Option<&Record>| {
            Record::after(
                previous,
                decision,
                vec![root_trail::PROGRAM.to_owned(), "probe".to_owned()],
                "unattested",
            )
        };
        let _receipt = trail.append(&build).unwrap();
    }
}

fn audit() -> Command {
    let mut command = Command::cargo_bin("aido").unwrap();
    command.args(["audit", "--log", AUDIT_FILE]);
    command
}

#[test]
fn aido_audit_passes_on_the_produced_trail_and_fails_after_truncation() {
    if !root_or_skip("aido_audit_passes_on_the_produced_trail_and_fails_after_truncation") {
        return;
    }
    let host = Host::fresh();
    write_trail();
    let intact = host.log();
    assert_eq!(host.mirrored().len(), 3);

    audit()
        .assert()
        .code(0)
        .stdout(contains("3 record(s)").and(contains("chain intact")));

    // `truncate -s -1` removes only the final newline. Nothing in the record is
    // lost, so by design (`aido_audit::tail`) it is not damage: the verifier
    // reads the record and the writer starts its next one on a new line.
    root_trail::replace_log(&intact[..intact.len() - 1]);
    audit().assert().code(0).stdout(contains("3 record(s)"));

    // `truncate -s -2` cuts into the record itself.
    root_trail::replace_log(&intact[..intact.len() - 2]);
    audit().assert().code(17).stderr(contains("is not intact"));

    // A cut in the middle of the last line.
    let last = intact[..intact.len() - 1]
        .iter()
        .rposition(|b| *b == b'\n')
        .unwrap();
    root_trail::replace_log(&intact[..last + 1 + (intact.len() - last) / 2]);
    audit().assert().code(17).stderr(contains("is not intact"));

    // The limit: the last record, dropped whole and clean, still verifies.
    root_trail::replace_log(&intact[..=last]);
    audit()
        .assert()
        .code(0)
        .stdout(contains("2 record(s)").and(contains("dropped whole from its end")));
}
