//! The one gate every root test goes through, shared by `#[path]`-inclusion so
//! the crates that own root tests cannot drift apart on it.
//!
//! A root test changes the machine it runs on: it creates accounts, writes
//! under `/etc`, and binds sockets in `/run`. Run as uid 0 on a developer's
//! host, or on a CI runner, that is damage. So the gate has three outcomes,
//! not two:
//!
//! * not uid 0: the test says `SKIPPED:` and returns, so the suites that
//!   enable every feature (`just test`, `just linux-test`, coverage) can still
//!   build and run it as an ordinary user. `ci/root-test.sh` fails on any
//!   `SKIPPED:` line, so the only place a skip is accepted is one nobody
//!   relies on;
//! * uid 0 and [`SENTINEL`] present: go. `ci/root-test.sh` makes the file, in
//!   the throwaway container, and nothing else does;
//! * uid 0 and no sentinel: **refuse, by panicking**. Never skip: a skip would
//!   be read as a pass by anyone running `cargo test` as root by habit.
//!
//! The sentinel is not a secret and proves nothing about the kernel; it
//! proves that whoever started this run went through the script that
//! throws the filesystem away afterwards.

#![allow(dead_code)]

use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Made by `ci/root-test.sh` inside the container, before any test runs.
pub(crate) const SENTINEL: &str = "/etc/aido-root-lane-sentinel";

/// `true` when the calling test should go on.
///
/// Root is judged by the files this process makes. The standard library has no
/// `geteuid` and `unsafe` is forbidden, and the owner of a file a process
/// creates is the identity every operation in these tests acts as.
///
/// # Panics
///
/// As uid 0 outside the lane, which is the point.
pub(crate) fn root_or_skip(test: &str) -> bool {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("lane-identity-{test}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("probe");
    File::create(&probe).unwrap();
    let uid = fs::metadata(&probe).unwrap().uid();
    let _ = fs::remove_dir_all(&dir);
    decide(test, uid == 0, Path::new(SENTINEL).exists())
}

/// The three outcomes, with the facts as arguments so each is testable.
fn decide(test: &str, is_root: bool, sentinel: bool) -> bool {
    if !is_root {
        eprintln!("SKIPPED: {test} needs uid 0; ci/root-test.sh runs it for real");
        return false;
    }
    assert!(
        sentinel,
        "REFUSED: {test} is running as uid 0 and {SENTINEL} does not exist, so this is not the \
         throwaway container. A root test creates accounts and writes under /etc and /run; \
         run it with `just root-test`, never with `cargo test` as root"
    );
    true
}

#[test]
fn root_without_the_sentinel_is_refused_not_skipped() {
    let refused = std::panic::catch_unwind(|| decide("t", true, false));
    assert!(refused.is_err(), "uid 0 outside the container must panic");
    assert!(decide("t", true, true));
}
