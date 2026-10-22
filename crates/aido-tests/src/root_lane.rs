//! The one guard every root test begins with.
//!
//! A root test writes to the real `/etc`, replaces the installed gate, deletes
//! the audit log and binds journald's socket. Run as root on a real machine
//! (`sudo just test`, and `--all-features` turns the `root-tests` feature on)
//! that deletes an operator's `/etc/doas.conf` and the host's audit trail. Being
//! uid 0 is therefore not permission to run: the test must also find the
//! sentinel `ci/root-test.sh` puts inside the throwaway container.
//!
//! * Not root: the test skips and says `SKIPPED:`, which `ci/root-test.sh`
//!   turns into a failure, so the only accepted skip is the one nobody relies
//!   on (the suites that enable every feature, run as an ordinary user).
//! * Root, and the sentinel is there and is what the lane writes: it runs.
//! * Root, and anything else: the test **panics**, before it has touched
//!   anything. Never a skip: a skip is a green build on the machine where a
//!   guard mattered.
//!
//! The sentinel is a file because nothing privileged may read the environment
//! to decide what it is allowed to do, and an environment variable is one
//! `export` away from set. A file directly under `/` can only be made by root,
//! and root on a real host has not made it. It must be a regular file (not a
//! link), root's, writable by no one else, and exactly the bytes the lane
//! writes.

// The guard exists to stop a test by panicking; a skip would be a green build
// on the machine where it mattered.
#![allow(clippy::panic)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Where `ci/root-test.sh` creates the sentinel, inside the container only.
pub const SENTINEL: &str = "/aido-root-test-lane";

/// What the sentinel holds. `ci/root-test.sh` writes the same line.
pub const SENTINEL_CONTENT: &str =
    "aido root-test lane: a throwaway container made by ci/root-test.sh\n";

/// What a root test may do.
#[derive(Debug, PartialEq, Eq)]
pub enum Lane {
    /// Root, in the lane: go on.
    Run,
    /// Not root: say so and return.
    Skip,
    /// Root, outside the lane: fail, touching nothing.
    Refuse(String),
}

/// The effective uid of this process.
#[must_use]
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The verdict for a caller with this effective uid and this sentinel path.
#[must_use]
pub fn lane(euid: u32, sentinel: &Path) -> Lane {
    lane_with_root(euid, 0, sentinel)
}

/// [`lane`], with the uid that counts as root named, so the path that runs a
/// test can be exercised by a process that is not root. Production asks with 0.
#[must_use]
pub fn lane_with_root(euid: u32, root: u32, sentinel: &Path) -> Lane {
    if euid != root {
        return Lane::Skip;
    }
    match check_sentinel(sentinel, root) {
        Ok(()) => Lane::Run,
        Err(why) => Lane::Refuse(why),
    }
}

fn check_sentinel(sentinel: &Path, root: u32) -> Result<(), String> {
    let said = |what: &str| format!("the sentinel {} {what}", sentinel.display());
    // Not followed: a link is refused, wherever it points.
    fs::symlink_metadata(sentinel)
        .map_err(|_| said("does not exist"))
        .and_then(|meta| {
            if !meta.file_type().is_file() {
                Err(said("is not a regular file (a link, or something else)"))
            } else if meta.uid() != root {
                Err(said("is not owned by root"))
            } else if meta.mode() & 0o022 != 0 {
                Err(said("is writable by someone other than its owner"))
            } else {
                fs::read(sentinel).map_err(|_| said("cannot be read"))
            }
        })
        .and_then(|bytes| {
            if bytes == SENTINEL_CONTENT.as_bytes() {
                Ok(())
            } else {
                Err(said("does not hold what ci/root-test.sh writes"))
            }
        })
}

/// [`root_guard`] against a caller and a sentinel path of the caller's choosing.
///
/// # Panics
///
/// When `euid` is 0 and the sentinel is not the lane's: the test would run on a
/// real machine.
#[must_use]
pub fn root_guard_at(test: &str, euid: u32, sentinel: &Path) -> bool {
    act_on(test, lane(euid, sentinel))
}

/// What a test does with a verdict.
///
/// # Panics
///
/// For a [`Lane::Refuse`], as [`root_guard_at`] says.
#[must_use]
pub fn act_on(test: &str, verdict: Lane) -> bool {
    match verdict {
        Lane::Run => true,
        Lane::Skip => {
            eprintln!("SKIPPED: {test} needs uid 0; ci/root-test.sh runs it for real");
            false
        }
        Lane::Refuse(why) => panic!(
            "REFUSED: {test} is a root test and this is uid 0, but {why}. It would write to \
             the real /etc, replace /usr/libexec/aido, delete /var/lib/aido/audit.jsonl and \
             bind journald's socket. Run it with `just root-test`, in its container; nothing \
             was touched."
        ),
    }
}

/// `true` when the calling test should go on, `false` when it should return
/// (it said `SKIPPED:`), and a panic when it must not run at all. Every root
/// test calls this as its first statement.
///
/// # Panics
///
/// As [`root_guard_at`], against the lane's sentinel.
#[must_use]
pub fn root_guard(test: &str) -> bool {
    root_guard_at(test, effective_uid(), Path::new(SENTINEL))
}
