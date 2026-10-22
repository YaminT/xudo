//! The root-lane guard (`src/root_lane.rs`), attacked.
//!
//! Each test names a way a root test could end up running as root on a machine
//! that is not the lane's container, and shows the guard stops it. Run as an
//! ordinary user the verdicts are reached with the uid that counts as root
//! named, so the whole of the guard is exercised without being root; the root
//! lane has its own tests of the same guard as real uid 0 in `aido-sys`.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, chown, symlink};
use std::path::{Path, PathBuf};

use aido_tests::root_lane::{
    Lane, SENTINEL_CONTENT, act_on, effective_uid, lane, lane_with_root, root_guard, root_guard_at,
};

fn dir(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("guard-{name}"));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// A well-formed sentinel, owned by whoever runs the test.
fn good(d: &Path) -> PathBuf {
    let p = d.join("sentinel");
    fs::write(&p, SENTINEL_CONTENT).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
    p
}

/// Asserts `got` is a refusal that says `wanted`.
fn refused(got: &Lane, wanted: &str) {
    let text = format!("{got:?}");
    assert!(
        text.starts_with("Refuse(") && text.contains(wanted),
        "{text}"
    );
}

#[test]
fn refuses_as_root_without_the_lane_sentinel() {
    let d = dir("absent");
    refused(&lane(0, &d.join("no-such-sentinel")), "does not exist");
}

#[test]
fn refuses_as_root_with_a_symlinked_sentinel() {
    let d = dir("symlink");
    let real = good(&d);
    let link = d.join("link");
    symlink(&real, &link).unwrap();
    // Even a link to a perfect sentinel.
    let me = effective_uid();
    refused(&lane_with_root(me, me, &link), "not a regular file");
}

#[test]
fn refuses_as_root_with_a_directory_for_a_sentinel() {
    let d = dir("directory");
    let me = effective_uid();
    refused(&lane_with_root(me, me, &d), "not a regular file");
}

#[test]
fn refuses_as_root_with_a_sentinel_root_does_not_own() {
    let d = dir("owner");
    let p = good(&d);
    // Unprivileged, the file is the caller's and so not uid 0's. As root the
    // test would hand it to `nobody` first; this test is not run as root outside
    // the lane (the guard in the lane's own tests covers that).
    let me = effective_uid();
    if me != 0 {
        refused(&lane(0, &p), "not owned by root");
    } else {
        chown(&p, Some(65534), None).unwrap();
        refused(&lane(0, &p), "not owned by root");
    }
}

#[test]
fn refuses_as_root_with_a_sentinel_anyone_can_write() {
    let d = dir("writable");
    let p = good(&d);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
    let me = effective_uid();
    refused(&lane_with_root(me, me, &p), "writable");
}

#[test]
fn refuses_as_root_with_the_wrong_sentinel_content() {
    let d = dir("content");
    let p = good(&d);
    let me = effective_uid();
    for content in ["", "yes\n", &format!("{SENTINEL_CONTENT}more")] {
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&p, content).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        refused(&lane_with_root(me, me, &p), "does not hold");
    }
}

#[test]
fn refuses_a_sentinel_that_cannot_be_read() {
    // Root reads anything, so this shows only to anyone else; the mode refuses.
    let d = dir("unreadable");
    let p = good(&d);
    fs::set_permissions(&p, fs::Permissions::from_mode(0o200)).unwrap();
    let me = effective_uid();
    let got = lane_with_root(me, me, &p);
    if me == 0 {
        refused(&got, "does not hold");
    } else {
        refused(&got, "cannot be read");
    }
}

#[test]
fn a_well_formed_sentinel_is_what_lets_root_run() {
    let d = dir("good");
    let p = good(&d);
    let me = effective_uid();
    assert_eq!(lane_with_root(me, me, &p), Lane::Run);
}

#[test]
fn a_verdict_of_run_lets_the_test_go_on() {
    assert!(act_on("t", Lane::Run));
    assert!(!act_on("t", Lane::Skip));
}

#[test]
fn a_root_test_run_as_root_outside_the_lane_panics() {
    let d = dir("panic");
    let missing = d.join("missing");
    let caught = std::panic::catch_unwind(|| root_guard_at("some_test", 0, &missing));
    assert!(caught.is_err(), "the guard let a root test run");
}

#[test]
fn anyone_but_root_skips_whatever_the_sentinel() {
    let d = dir("skip");
    let p = good(&d);
    assert_eq!(lane(1000, &p), Lane::Skip);
    assert!(!root_guard_at("t", 1000, &p));
}

#[test]
fn the_guard_asks_the_real_process_and_the_lanes_path() {
    // Not root here, so it skips; as root outside the lane it would panic, which
    // the tests above show for a path that is not there.
    if effective_uid() != 0 {
        assert!(!root_guard("a_test_named_for_this_check"));
    }
}
