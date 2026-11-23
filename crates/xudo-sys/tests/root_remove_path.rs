//! Real-kernel `remove-path`. The in-memory fake cannot prove `openat2`.
//!
//! The tree is `/var/lib/xudo-t1-remove-path`. That name is not under the
//! protected prefix `/var/lib/xudo`. The walk still requires `/`, `/var`, and
//! `/var/lib` to be root-owned and closed to group and other writes. A bind
//! mount that the container refuses is a panic, with the command's output.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // mount and umount are run by absolute path; there is no PATH search.
    clippy::disallowed_methods
)]

use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use xudo_sys::{RemoveError, RemoveOwnerPolicy, RemoveReport, RemoveRequest, remove_path_on_host};
use xudo_tests::root_lane::root_guard;

const TREE: &str = "/var/lib/xudo-t1-remove-path";
const SECRET: &str = "/var/lib/xudo-t1-remove-secret";
const BIND_SRC: &str = "/var/lib/xudo-t1-bind-src";

fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    let mounted = format!("{TREE}/box/mnt");
    if Path::new(&mounted).exists() {
        let _ = Command::new("/usr/bin/umount").arg(&mounted).status();
    }
    let _ = fs::remove_dir_all(TREE);
    let _ = fs::remove_file(SECRET);
    let _ = fs::remove_dir_all(BIND_SRC);
    fs::create_dir_all(TREE).unwrap();
    let mut perms = fs::metadata(TREE).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(TREE, perms).unwrap();
    true
}

fn request(relative: &[u8], recursive: bool) -> RemoveRequest {
    RemoveRequest {
        under: TREE.as_bytes().to_vec(),
        relative: relative.to_vec(),
        recursive,
        max_depth: 8,
        max_entries: 100,
        owners: RemoveOwnerPolicy::Only(vec![0]),
        dry_run: false,
    }
}

fn walk(relative: &[u8], recursive: bool) -> Result<RemoveReport, RemoveError> {
    remove_path_on_host(&request(relative, recursive))
}

#[test]
fn a_root_owned_file_under_the_tree_is_unlinked() {
    if !begin_root_test("a_root_owned_file_under_the_tree_is_unlinked") {
        return;
    }
    let file = format!("{TREE}/keep-me");
    fs::write(&file, b"data").unwrap();
    fs::set_permissions(&file, Permissions::from_mode(0o644)).unwrap();
    let report = walk(b"keep-me", false).unwrap();
    assert!(!report.partial, "{report:?}");
    assert!(!Path::new(&file).exists());
    assert!(Path::new(TREE).is_dir());
}

#[test]
fn the_tree_root_is_never_removed() {
    if !begin_root_test("the_tree_root_is_never_removed") {
        return;
    }
    fs::write(format!("{TREE}/stay"), b"x").unwrap();
    let error = walk(b"", false).unwrap_err();
    assert_eq!(error, RemoveError::TreeRoot);
    assert!(Path::new(TREE).is_dir());
    assert!(Path::new(&format!("{TREE}/stay")).is_file());
}

#[test]
fn a_symlink_planted_by_the_agent_is_never_followed() {
    if !begin_root_test("a_symlink_planted_by_the_agent_is_never_followed") {
        return;
    }
    fs::write(SECRET, b"secret").unwrap();
    std::os::unix::fs::symlink(SECRET, format!("{TREE}/link")).unwrap();
    let report = walk(b"link", false).unwrap();
    assert!(!report.partial, "{report:?}");
    assert!(!Path::new(&format!("{TREE}/link")).exists());
    assert_eq!(fs::read(SECRET).unwrap(), b"secret");
    let _ = fs::remove_file(SECRET);
}

#[test]
fn a_hardlink_to_a_root_file_is_unlinked_and_the_file_survives() {
    if !begin_root_test("a_hardlink_to_a_root_file_is_unlinked_and_the_file_survives") {
        return;
    }
    fs::write(SECRET, b"root-file").unwrap();
    fs::hard_link(SECRET, format!("{TREE}/alias")).unwrap();
    let before = fs::metadata(SECRET).unwrap().nlink();
    assert!(before >= 2);
    let report = walk(b"alias", false).unwrap();
    assert!(!report.partial, "{report:?}");
    assert!(!Path::new(&format!("{TREE}/alias")).exists());
    assert_eq!(fs::read(SECRET).unwrap(), b"root-file");
    assert_eq!(
        fs::metadata(SECRET).unwrap().nlink().saturating_add(1),
        before
    );
    let _ = fs::remove_file(SECRET);
}

#[test]
fn a_file_named_dash_rf_is_only_a_name() {
    if !begin_root_test("a_file_named_dash_rf_is_only_a_name") {
        return;
    }
    let name = format!("{TREE}/-rf");
    fs::write(&name, b"name").unwrap();
    fs::write(format!("{TREE}/other"), b"stay").unwrap();
    let report = walk(b"-rf", false).unwrap();
    assert!(!report.partial, "{report:?}");
    assert!(!Path::new(&name).exists());
    assert_eq!(fs::read(format!("{TREE}/other")).unwrap(), b"stay");
}

#[test]
fn a_bind_mount_under_the_tree_is_not_crossed() {
    if !begin_root_test("a_bind_mount_under_the_tree_is_not_crossed") {
        return;
    }
    let box_dir = format!("{TREE}/box");
    let mnt = format!("{box_dir}/mnt");
    fs::create_dir_all(&mnt).unwrap();
    fs::create_dir_all(BIND_SRC).unwrap();
    fs::write(format!("{BIND_SRC}/inside"), b"secret").unwrap();
    fs::write(format!("{box_dir}/a"), b"a").unwrap();
    let output = Command::new("/usr/bin/mount")
        .args(["--bind", BIND_SRC, &mnt])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "mount --bind failed: status {} stdout {} stderr {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = walk(b"box", true).unwrap();
    assert!(report.partial, "{report:?}");
    assert!(Path::new(&mnt).exists());
    assert_eq!(fs::read(format!("{mnt}/inside")).unwrap(), b"secret");
    assert_eq!(fs::read(format!("{BIND_SRC}/inside")).unwrap(), b"secret");
    let umount = Command::new("/usr/bin/umount").arg(&mnt).output().unwrap();
    assert!(
        umount.status.success(),
        "umount failed: {}",
        String::from_utf8_lossy(&umount.stderr)
    );
    let _ = fs::remove_dir_all(BIND_SRC);
}
