//! Real-kernel `remove-path`. The in-memory fake cannot prove `openat2`.
//!
//! The tree is `/var/lib/xudo-t1-remove-path`. That name is not under the
//! protected prefix `/var/lib/xudo`. The walk still requires `/`, `/var`, and
//! `/var/lib` to be root-owned and closed to group and other writes. Docker
//! supplies a tmpfs at the tree root, without granting `SYS_ADMIN`.

#![cfg(all(feature = "root-tests", target_os = "linux"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // chown is run by absolute path; there is no PATH search.
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
const MOVED: &str = "/var/lib/xudo-t1-moved-out";
const MOUNT_TREE: &str = "/var/lib/xudo-t1-remove-mount";

fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    let _ = fs::remove_dir_all(TREE);
    let _ = fs::remove_file(SECRET);
    let _ = fs::remove_dir_all(MOVED);
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
        owners: RemoveOwnerPolicy::Only(vec![65534]),
        dry_run: false,
    }
}

fn walk(relative: &[u8], recursive: bool) -> Result<RemoveReport, RemoveError> {
    remove_path_on_host(&request(relative, recursive))
}

fn chown_unprivileged(path: &str, symlink: bool) {
    let mut command = Command::new("/usr/bin/chown");
    if symlink {
        command.arg("-h");
    }
    let status = command.arg("65534:65534").arg(path).status().unwrap();
    assert!(status.success(), "chown failed for {path}");
}

#[test]
fn a_root_owned_entry_is_never_removed() {
    if !begin_root_test("a_root_owned_entry_is_never_removed") {
        return;
    }
    let file = format!("{TREE}/keep-me");
    fs::write(&file, b"data").unwrap();
    fs::set_permissions(&file, Permissions::from_mode(0o644)).unwrap();
    let report = walk(b"keep-me", false).unwrap();
    assert!(!report.partial, "{report:?}");
    assert!(report.removed.is_empty());
    assert!(Path::new(&file).exists());
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
    let link = format!("{TREE}/link");
    std::os::unix::fs::symlink(SECRET, &link).unwrap();
    chown_unprivileged(&link, true);
    let report = walk(b"link", false).unwrap();
    assert!(!report.partial, "{report:?}");
    assert!(!Path::new(&format!("{TREE}/link")).exists());
    assert_eq!(fs::read(SECRET).unwrap(), b"secret");
    let _ = fs::remove_file(SECRET);
}

#[test]
fn a_hardlink_to_an_unprivileged_file_is_unlinked_and_the_file_survives() {
    if !begin_root_test("a_hardlink_to_an_unprivileged_file_is_unlinked_and_the_file_survives") {
        return;
    }
    fs::write(SECRET, b"root-file").unwrap();
    chown_unprivileged(SECRET, false);
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
    chown_unprivileged(&name, false);
    fs::write(format!("{TREE}/other"), b"stay").unwrap();
    let report = walk(b"-rf", false).unwrap();
    assert!(!report.partial, "{report:?}");
    assert!(!Path::new(&name).exists());
    assert_eq!(fs::read(format!("{TREE}/other")).unwrap(), b"stay");
}

#[test]
fn a_tree_that_is_a_mount_point_is_refused() {
    if !begin_root_test("a_tree_that_is_a_mount_point_is_refused") {
        return;
    }
    fs::write(format!("{TREE}/stay"), b"secret").unwrap();
    let mut mounted = request(b"stay", false);
    mounted.under = MOUNT_TREE.as_bytes().to_vec();
    fs::write(format!("{MOUNT_TREE}/stay"), b"secret").unwrap();
    assert_eq!(
        remove_path_on_host(&mounted).unwrap_err(),
        RemoveError::MountPoint
    );
    assert_eq!(fs::read(format!("{MOUNT_TREE}/stay")).unwrap(), b"secret");
}

#[test]
fn a_directory_renamed_out_of_the_tree_mid_walk_stops_the_walk() {
    if !begin_root_test("a_directory_renamed_out_of_the_tree_mid_walk_stops_the_walk") {
        return;
    }
    let box_dir = format!("{TREE}/box");
    fs::create_dir(&box_dir).unwrap();
    let inside = format!("{box_dir}/inside");
    fs::write(&inside, b"keep after rename").unwrap();
    chown_unprivileged(&inside, false);
    chown_unprivileged(&box_dir, false);
    let mut moved = false;
    let report = xudo_sys::remove::remove_path_on_host_with_before_verify(
        &request(b"box", true),
        move |relative| {
            if relative == b"box" && !moved {
                fs::rename(&box_dir, MOVED).unwrap();
                moved = true;
            }
        },
    )
    .unwrap();
    assert!(report.partial, "{report:?}");
    assert!(Path::new(MOVED).is_dir());
    assert_eq!(
        fs::read(format!("{MOVED}/inside")).unwrap(),
        b"keep after rename"
    );
    assert!(!Path::new(&format!("{TREE}/box")).exists());
    let _ = fs::remove_dir_all(MOVED);
}
