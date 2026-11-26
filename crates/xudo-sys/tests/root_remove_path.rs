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
// Docker mounts a tmpfs at `XDEV_TREE/box/mnt`: a mount inside a walked tree.
// Docker bind-mounts one host directory twice: `BIND_TREE`, and `BIND_TREE/child`
// from a subdirectory of it. Same filesystem, same `st_dev`, still a mount.
const BIND_TREE: &str = "/var/lib/xudo-t1-remove-bind";
const XDEV_TREE: &str = "/var/lib/xudo-t1-remove-xdev";

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

#[test]
fn a_mount_inside_the_walked_tree_is_not_crossed() {
    if !begin_root_test("a_mount_inside_the_walked_tree_is_not_crossed") {
        return;
    }
    let box_dir = format!("{XDEV_TREE}/box");
    let mount = format!("{box_dir}/mnt");
    let inside = format!("{mount}/inside");
    let sibling = format!("{box_dir}/a");
    // The lane's tmpfs must be there; a lane without it proves nothing.
    assert!(Path::new(&mount).is_dir(), "the lane did not mount {mount}");
    assert_ne!(
        fs::metadata(&mount).unwrap().dev(),
        fs::metadata(&box_dir).unwrap().dev()
    );
    fs::write(&inside, b"behind the mount").unwrap();
    fs::write(&sibling, b"outside the mount").unwrap();
    for path in [&inside, &sibling, &mount, &box_dir] {
        chown_unprivileged(path, false);
    }
    let mut request = request(b"box", true);
    request.under = XDEV_TREE.as_bytes().to_vec();
    let outcome = remove_path_on_host(&request);
    // Whatever the walk reports, nothing behind the mount may be deleted.
    assert!(
        outcome.as_ref().map_or(true, |report| report.partial),
        "{outcome:?}"
    );
    assert_eq!(fs::read(&inside).unwrap(), b"behind the mount");
    assert!(Path::new(&mount).is_dir());
    assert!(Path::new(&box_dir).is_dir());
    let _ = fs::remove_file(&sibling);
}

#[test]
fn the_kernel_reports_mount_root_for_a_real_mount() {
    if !begin_root_test("the_kernel_reports_mount_root_for_a_real_mount") {
        return;
    }
    let dir = fs::File::open(MOUNT_TREE).unwrap();
    let x = rustix::fs::statx(
        &dir,
        c"",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::empty(),
    )
    .unwrap();
    // 0x2000 is STATX_ATTR_MOUNT_ROOT: supported here, and set on the tmpfs.
    assert_ne!(x.stx_attributes_mask.bits() & 0x2000, 0);
    assert_ne!(x.stx_attributes.bits() & 0x2000, 0);
}

#[test]
fn a_same_device_bind_mount_as_the_tree_is_refused() {
    if !begin_root_test("a_same_device_bind_mount_as_the_tree_is_refused") {
        return;
    }
    let child = format!("{BIND_TREE}/child");
    assert_eq!(
        fs::metadata(BIND_TREE).unwrap().dev(),
        fs::metadata(&child).unwrap().dev(),
        "the lane's bind mounts are not on one device"
    );
    // The host's temporary directory belongs to whoever ran the lane; the walk
    // wants root-owned ancestors. Make them root's, and give them back after.
    let owner = fs::metadata(BIND_TREE).unwrap();
    for dir in [BIND_TREE, child.as_str()] {
        std::os::unix::fs::chown(dir, Some(0), Some(0)).unwrap();
        fs::set_permissions(dir, Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(format!("{child}/stay"), b"secret").unwrap();
    let mut bound = request(b"stay", false);
    bound.under = child.as_bytes().to_vec();
    assert_eq!(
        remove_path_on_host(&bound).unwrap_err(),
        RemoveError::MountPoint
    );
    assert_eq!(fs::read(format!("{child}/stay")).unwrap(), b"secret");
    fs::remove_file(format!("{child}/stay")).unwrap();
    for dir in [child.as_str(), BIND_TREE] {
        std::os::unix::fs::chown(dir, Some(owner.uid()), Some(owner.gid())).unwrap();
    }
}

#[test]
fn denies_a_real_symlink_planted_as_a_parent_of_the_target() {
    if !begin_root_test("denies_a_real_symlink_planted_as_a_parent_of_the_target") {
        return;
    }
    // Attack: `hop -> MOVED` in the tree, and a removal of `hop/v`. The
    // kernel answers ENOTDIR or ELOOP; either is an escape, nothing goes.
    fs::create_dir_all(MOVED).unwrap();
    let victim = format!("{MOVED}/v");
    fs::write(&victim, b"keep").unwrap();
    chown_unprivileged(&victim, false);
    let link = format!("{TREE}/hop");
    std::os::unix::fs::symlink(MOVED, &link).unwrap();
    chown_unprivileged(&link, true);
    assert_eq!(
        walk(b"hop/v", false).unwrap_err(),
        RemoveError::WalkEscape("a directory on the way to the target is a symbolic link")
    );
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
    assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
    let _ = fs::remove_dir_all(MOVED);
}

#[test]
fn denies_a_real_mount_as_a_parent_or_as_the_target() {
    if !begin_root_test("denies_a_real_mount_as_a_parent_or_as_the_target") {
        return;
    }
    let mount = format!("{XDEV_TREE}/box/mnt");
    assert!(Path::new(&mount).is_dir(), "the lane did not mount {mount}");
    let inside = format!("{mount}/kept");
    fs::write(&inside, b"behind the mount").unwrap();
    chown_unprivileged(&inside, false);
    chown_unprivileged(&mount, false);
    for relative in [&b"box/mnt/kept"[..], b"box/mnt"] {
        let mut request = request(relative, true);
        request.under = XDEV_TREE.as_bytes().to_vec();
        assert_eq!(
            remove_path_on_host(&request).unwrap_err(),
            RemoveError::WalkEscape("the walk would cross a mount"),
            "{}",
            relative.escape_ascii()
        );
    }
    assert_eq!(fs::read(&inside).unwrap(), b"behind the mount");
    let _ = fs::remove_file(&inside);
}
