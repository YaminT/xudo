//! Installing and removing a rule pack against the real `/etc`, as real root.
//!
//! The unit tests prove the checks and the order against a fake machine. What
//! only uid 0 on a real filesystem shows is that the pack lands `root:root`
//! `0644` with xudo's marker by rename, that an operator's file of the same
//! name is neither replaced nor removed, and that `remove` takes back exactly
//! the file it wrote. `ci/root-test.sh` runs this file (see `root_lane.rs`).

#![cfg(feature = "root-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use xudo_policy::pack::digest;
use xudo_sys::{
    HostInstaller, InstallError, InstallProbe, Installer, PackError, PackRequest, ProbeResult,
};
use xudo_tests::root_lane::root_guard;

/// A probe that does not run: packs are files, not the gate.
struct NoProbe;

impl InstallProbe for NoProbe {
    fn verify(&self, _argv: &[String]) -> ProbeResult {
        ProbeResult::Unavailable {
            reason: "not probed here".to_owned(),
        }
    }
}

const DIR: &str = "/etc/xudo/rules.d";
const PATH: &str = "/etc/xudo/rules.d/pack-rootpack.toml";
/// A pack for no harness: it needs no registry, and grants only what sudo's
/// password already would.
const PACK: &str = "[pack]\nname = \"rootpack\"\nversion = \"1\"\n\n[[action]]\nid = \"rootpack.id\"\ntier = \"diag-read\"\nexe = \"/usr/bin/id\"\n\n[[test]]\nargv = [\"/usr/bin/id\"]\nexpect = \"allow\"\naction = \"rootpack.id\"\n";

fn request(text: &str) -> PackRequest {
    PackRequest {
        bytes: text.as_bytes().to_vec(),
        reviewed: digest(text.as_bytes()),
    }
}

/// `true` when the calling test should go on. See `root_lane.rs`.
fn begin_root_test(test: &str) -> bool {
    root_guard(test)
}

#[test]
fn a_pack_lands_root_owned_0644_and_leaves_an_operators_file_alone() {
    if !begin_root_test("a_pack_lands_root_owned_0644_and_leaves_an_operators_file_alone") {
        return;
    }
    fs::create_dir_all(DIR).unwrap();
    fs::set_permissions("/etc/xudo", fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(DIR, fs::Permissions::from_mode(0o755)).unwrap();
    let _ = fs::remove_file(PATH);
    let installer = HostInstaller::new(&NoProbe);

    let report = installer.pack_add(&request(PACK)).unwrap();
    assert_eq!(report.path, PATH);
    let meta = fs::symlink_metadata(PATH).unwrap();
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777),
        (0, 0, 0o644)
    );
    assert_eq!(meta.nlink(), 1);
    let written = fs::read_to_string(PATH).unwrap();
    assert!(written.starts_with("# Managed by xudo."), "{written}");
    assert!(written.ends_with(PACK));
    assert!(!fs::exists(format!("{PATH}.candidate")).unwrap());

    installer.pack_remove("rootpack").unwrap();
    assert!(!fs::exists(PATH).unwrap());

    // An operator's own file under the pack's name is never replaced or removed.
    fs::write(PATH, PACK).unwrap();
    fs::set_permissions(PATH, fs::Permissions::from_mode(0o644)).unwrap();
    let error = installer.pack_add(&request(PACK)).unwrap_err();
    assert!(
        matches!(error, PackError::Install(InstallError::NotOurs { .. })),
        "{error}"
    );
    assert_eq!(
        installer.pack_remove("rootpack").unwrap_err(),
        PackError::NotInstalled("rootpack".to_owned())
    );
    assert_eq!(fs::read_to_string(PATH).unwrap(), PACK);
    fs::remove_file(PATH).unwrap();
}
