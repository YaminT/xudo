//! What the root lane must be true of itself before any root test can be
//! believed: a run that says it is uid 0 behaves like uid 0.
//!
//! `ci/root-test.sh` (`just root-test`) runs every `tests/root_*.rs` as real
//! root in a throwaway container, on a copy of the checkout. It exists for what
//! only root can observe: a file handed to `root:root` and moded `0440`, a
//! rename inside a directory only root may write. The rest of the workspace is
//! written for an unprivileged user and is not run there: it assumes the
//! opposite (a checkout that is not root's, a mode that refuses the caller), so
//! as root it fails, or passes for the wrong reason.
//!
//! These checks are the lane's tripwire. A lane that quietly ran as someone
//! else (a rootless container whose "root" cannot give a file away, a runner
//! that dropped the capability to override file modes) would turn every root
//! test written after them into a failure with no visible cause, or into a
//! refusal test that passes because the operation was refused for the wrong
//! reason. They fail first, and say what is missing.
//!
//! # Writing a root test
//!
//! * A file `tests/root_<name>.rs` in the crate that owns the code, with
//!   `#![cfg(feature = "root-tests")]`, and the feature declared in that crate's
//!   manifest. The lane selects `root_*` test targets by name and nothing else.
//!   A `[[test]]` entry with `required-features = ["root-tests"]` makes a build
//!   without the feature refuse to run the target instead of running it empty,
//!   as this file's entry does.
//! * Begin each test with `if !root_or_skip("<its name>") { return; }`. Suites
//!   that enable every feature (`just test`, `just linux-test`, coverage) build
//!   this file and run it as an ordinary user, where it must neither fail nor
//!   pretend to have run. The lane reads the output and fails on any `SKIPPED:`
//!   line, so the only place a skip is accepted is the place nobody relies on.
//! * Assert what only root can show. A refusal that depends on a mode proves
//!   nothing here, because root is not refused by one.
//! * Scratch space under the target directory, never `/tmp`, and leave the
//!   container as the next test expects to find it: tests run one at a time.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs::{self, File, OpenOptions, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
use std::path::PathBuf;

/// An owner no account in a container has, so a file given to it can only have
/// got there by root's hand.
const SOMEONE_ELSE: u32 = 12345;

/// A scratch directory under the target directory, empty on return.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("root-lane-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `true` when the calling test should go on. Otherwise says so on standard
/// error, which `ci/root-test.sh` turns into a failure, and the caller returns.
///
/// Root is judged by the files this process makes. The standard library has no
/// `geteuid` and `unsafe` is forbidden, and the owner of a file a process
/// creates is the identity every operation in these tests acts as. The probe is
/// the test's own, because the tests run in parallel outside the lane.
fn root_or_skip(test: &str) -> bool {
    let probe = scratch(&format!("{test}-identity")).join("probe");
    File::create(&probe).unwrap();
    if fs::metadata(&probe).unwrap().uid() == 0 {
        return true;
    }
    eprintln!("SKIPPED: {test} needs uid 0; ci/root-test.sh runs it for real");
    false
}

#[cfg(target_os = "linux")]
#[test]
fn the_lane_is_root_through_and_through() {
    if !root_or_skip("the_lane_is_root_through_and_through") {
        return;
    }
    // Effective alone is not enough: a set-user-ID wrapper leaves the real id
    // someone else's, and code that compares the two sees a different lane.
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for field in ["Uid:", "Gid:"] {
        let ids: Vec<&str> = status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(
            ids,
            ["0", "0", "0", "0"],
            "{field} real, effective, saved, filesystem"
        );
    }
}

#[test]
fn a_mode_that_refuses_everyone_does_not_refuse_root() {
    if !root_or_skip("a_mode_that_refuses_everyone_does_not_refuse_root") {
        return;
    }
    // The reason ci/linux-test.sh never runs as root, held as a fact of this
    // lane: no root test may count on a mode to refuse, and a container that
    // dropped the capability to override one is not the lane it claims to be.
    let dir = scratch("modes");
    let closed = dir.join("closed");
    fs::write(&closed, b"sealed").unwrap();
    fs::set_permissions(&closed, Permissions::from_mode(0o000)).unwrap();
    assert_eq!(fs::read(&closed).unwrap(), b"sealed", "read a 0000 file");

    let read_only = dir.join("read-only");
    fs::write(&read_only, b"").unwrap();
    fs::set_permissions(&read_only, Permissions::from_mode(0o444)).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&read_only)
        .expect("write a 0444 file");
}

#[test]
fn root_gives_a_file_away_and_still_sets_its_mode() {
    if !root_or_skip("root_gives_a_file_away_and_still_sets_its_mode") {
        return;
    }
    // Two capabilities an install depends on and a stripped container may lack:
    // giving a file to another owner (`CAP_CHOWN`), and changing the mode of a
    // file one does not own (`CAP_FOWNER`). An owner no account has shows both
    // at once, and the file is handed back to root, as an install ends with it.
    let file = scratch("owner").join("candidate");
    fs::write(&file, b"x").unwrap();
    chown(&file, Some(SOMEONE_ELSE), Some(SOMEONE_ELSE)).expect("give a file to another owner");
    fs::set_permissions(&file, Permissions::from_mode(0o440))
        .expect("set the mode of a file root does not own");
    let given = fs::metadata(&file).unwrap();
    assert_eq!(
        (given.uid(), given.gid(), given.mode() & 0o7777),
        (SOMEONE_ELSE, SOMEONE_ELSE, 0o440)
    );

    chown(&file, Some(0), Some(0)).expect("take it back");
    let back = fs::metadata(&file).unwrap();
    assert_eq!(
        (back.uid(), back.gid(), back.mode() & 0o7777),
        (0, 0, 0o440)
    );
}
