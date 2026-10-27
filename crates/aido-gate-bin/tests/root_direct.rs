//! The real gate binary, run directly as root, against the real audit trail.
//!
//! `binary.rs` shows the refusals an unprivileged hostile user sees, and
//! cannot show what the gate leaves behind: it cannot open the trail. Here the
//! binary runs as uid 0 in a throwaway container (`just root-test`), the way
//! `sudo` starts it, with nothing to act on or with a forged argv, and the test
//! reads the trail it wrote:
//!
//! * every refusal leaves one `Denied` record, written by `aido-gate`, chained,
//!   and mirrored to journald as `aido-gate`;
//! * nothing is executed: the refusal is the whole of what happens;
//! * a trail that cannot be written changes the refusal's answer not at all,
//!   and leaves the log as it was.

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

use std::path::{Path, PathBuf};
use std::process::Command;

use aido_audit::record::Decision;
use root_trail::{FAULTS, Host, Mirrored, root_or_skip};

/// The binary Cargo built for this package's tests.
const GATE: &str = env!("CARGO_BIN_EXE_aido-gate");

/// A hardlink to the gate under `name`, as the installer makes
/// `aido-gate-auth`.
fn named(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("gate-names-root");
    std::fs::create_dir_all(&dir).unwrap();
    let link = dir.join(name);
    match std::fs::hard_link(GATE, &link) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => panic!("cannot link the gate as {name}: {error}"),
    }
    link
}

/// What the gate said, and how it ended.
struct Ran {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
}

fn run(name: &str, args: &[&str]) -> Ran {
    let output = Command::new(named(name))
        .args(args)
        .env_clear()
        .output()
        .unwrap();
    Ran {
        status: output.status.code(),
        stdout: output.stdout,
        stderr: String::from_utf8(output.stderr).unwrap(),
    }
}

/// The code in `aido-gate: refused (CODE, severity X)`.
fn code_of(ran: &Ran) -> String {
    ran.stderr
        .strip_prefix("aido-gate: refused (")
        .and_then(|rest| rest.split(',').next())
        .unwrap_or_else(|| panic!("not a refusal line: {:?}", ran.stderr))
        .to_owned()
}

/// Every hostile way to start the gate with nothing to act on.
const HOSTILE: [(&str, &[&str]); 4] = [
    ("aido-gate-auth", &[]),
    ("aido-gate-auth", &["exec", "/bin/sh"]),
    ("aido-gate-auth", &["--help"]),
    ("aido-gate-nopass", &[]),
];

#[test]
fn a_direct_invocation_is_refused_recorded_and_executes_nothing() {
    if !root_or_skip("a_direct_invocation_is_refused_recorded_and_executes_nothing") {
        return;
    }
    let host = Host::fresh();
    for (index, (name, args)) in HOSTILE.iter().enumerate() {
        let ran = run(name, args);
        assert_eq!(ran.status, Some(19), "{name} {args:?}: {}", ran.stderr);
        assert!(ran.stdout.is_empty(), "{name} {args:?}");
        let code = code_of(&ran);

        let chain = host.chain();
        assert_eq!(chain.len(), index + 1, "{name} {args:?}: one record each");
        let record = chain.last().unwrap();
        assert_eq!(record.decision, Decision::Denied);
        assert_eq!(record.denial.as_deref(), Some(code.as_str()));
        assert_eq!(
            host.mirrored(),
            [Mirrored {
                identifier: "aido-gate".to_owned(),
                seq: u64::try_from(index + 1).unwrap(),
                hash: record.hash.clone(),
            }],
            "{name} {args:?}"
        );
    }
    assert!(host.spool().is_empty(), "the gate never writes the spool");
}

#[test]
fn a_refusal_stands_when_the_trail_cannot_be_written() {
    if !root_or_skip("a_refusal_stands_when_the_trail_cannot_be_written") {
        return;
    }
    for fault in FAULTS {
        let host = Host::fresh();
        let first = run("aido-gate-auth", &[]);
        assert_eq!(first.status, Some(19));
        let _ = host.mirrored();

        host.break_trail(fault);
        // Read after the fault: a log that is now a directory has no bytes.
        let before = host.log();
        let ran = run("aido-gate-auth", &[]);
        assert_eq!(ran.status, Some(19), "{fault:?}");
        assert!(ran.stdout.is_empty(), "{fault:?}");
        assert_eq!(code_of(&ran), code_of(&first), "{fault:?}");
        assert_eq!(host.log(), before, "{fault:?}: the log is unchanged");
        assert!(host.mirrored().is_empty(), "{fault:?}");
    }
}
