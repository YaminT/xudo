//! Installing and removing a rule pack against the real `/etc`, as real root.
//!
//! The unit tests prove the checks and the order against a fake machine. What
//! only uid 0 on a real filesystem shows is that the pack lands `root:root`
//! `0644` with xudo's marker by rename, that an operator's file of the same
//! name is neither replaced nor removed, and that `remove` takes back exactly
//! the file it wrote, under the real lock on the rules directory, and that the
//! real `/proc` walk refuses where it cannot tell where it runs.
//! `ci/root-test.sh` runs this file (see `root_lane.rs`).
//!
//! The lane cannot put a process in a real `xudo.slice`: its container has no
//! systemd and a read-only cgroup filesystem. The `xudo.slice` refusals, of the
//! process and of an ancestor, are tested on a scripted `/proc` in the unit
//! tests; here the real walk meets the container's own cgroup namespace root.

#![cfg(feature = "root-tests")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use xudo_sys::{
    HostInstallOps, HostInstaller, InstallError, InstallProbe, Installer, PackError, PackFileError,
    PackReport, PackRequest, ProbeResult, Whereabouts, add_pack, read_pack_file, remove_pack,
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

/// A human's login session under pid 1, as `/proc` would show it: what the
/// lane's container cannot be.
struct Session;

impl Whereabouts for Session {
    fn read(&self, pid: &str, file: &str) -> std::io::Result<Vec<u8>> {
        Ok(match (pid, file) {
            ("1", "cgroup") => b"0::/init.scope\n".to_vec(),
            (_, "cgroup") => b"0::/user.slice/user-1000.slice/session-1.scope\n".to_vec(),
            ("1", _) => b"PPid:\t0\n".to_vec(),
            _ => b"PPid:\t1\n".to_vec(),
        })
    }

    fn cgroup_ns(&self, _pid: &str) -> std::io::Result<Vec<u8>> {
        Ok(b"cgroup:[1]".to_vec())
    }
}

fn request(text: &str, reviewed: &str) -> PackRequest {
    PackRequest {
        bytes: text.as_bytes().to_vec(),
        reviewed: reviewed.to_owned(),
        allow_waivers: false,
    }
}

/// Root's own token for the change, learnt from its refusal of a wrong one:
/// what the operator's review prints for the same files (the unit tests hold
/// the two equal).
fn token_of(result: Result<PackReport, PackError>) -> String {
    match result {
        Err(PackError::Changed { found, .. }) => found,
        other => panic!("{other:?}"),
    }
}

fn add(text: &str) -> Result<PackReport, PackError> {
    let ops = HostInstallOps::system();
    let token = token_of(add_pack(&request(text, "?"), &Session, &ops, &ops));
    add_pack(&request(text, &token), &Session, &ops, &ops)
}

fn remove(name: &str) -> Result<PackReport, PackError> {
    let ops = HostInstallOps::system();
    match remove_pack(name, "?", &Session, &ops, &ops) {
        Err(PackError::Changed { found, .. }) => remove_pack(name, &found, &Session, &ops, &ops),
        other => other,
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
    let report = add(PACK).unwrap();
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

    remove("rootpack").unwrap();
    assert!(!fs::exists(PATH).unwrap());

    // An operator's own file under the pack's name is never replaced or removed.
    fs::write(PATH, PACK).unwrap();
    fs::set_permissions(PATH, fs::Permissions::from_mode(0o644)).unwrap();
    // The token is checked first, so the refusal comes with the right one.
    let ops = HostInstallOps::system();
    let token = token_of(add_pack(&request(PACK, "?"), &Session, &ops, &ops));
    let error = add_pack(&request(PACK, &token), &Session, &ops, &ops).unwrap_err();
    assert!(
        matches!(error, PackError::Install(InstallError::NotOurs { .. })),
        "{error}"
    );
    assert_eq!(
        remove("rootpack").unwrap_err(),
        PackError::NotInstalled("rootpack".to_owned())
    );
    assert_eq!(fs::read_to_string(PATH).unwrap(), PACK);
    fs::remove_file(PATH).unwrap();
}

#[test]
fn the_real_proc_walk_refuses_where_it_cannot_tell_where_it_runs() {
    if !begin_root_test("the_real_proc_walk_refuses_where_it_cannot_tell_where_it_runs") {
        return;
    }
    fs::create_dir_all(DIR).unwrap();
    let _ = fs::remove_file(PATH);
    let installer = HostInstaller::new(&NoProbe);
    let own = fs::read_to_string("/proc/self/cgroup").unwrap();
    let add = installer.pack_add(&request(PACK, "?"));
    let remove = installer.pack_remove("rootpack", "?");
    if own.lines().any(|line| line.ends_with("::/")) {
        // The container's own cgroup namespace: its root hides where it is.
        assert!(matches!(add, Err(PackError::CgroupUnknown(_))), "{add:?}");
        assert!(
            matches!(remove, Err(PackError::CgroupUnknown(_))),
            "{remove:?}"
        );
    } else {
        // A host cgroup namespace: the walk reached pid 1 outside the box,
        // and the wrong token is what refuses.
        assert!(
            matches!(add, Err(PackError::Changed { .. })),
            "{own}: {add:?}"
        );
    }
    assert!(!fs::exists(PATH).unwrap());
}

#[test]
fn root_never_reads_a_pack_swapped_for_a_symlink_to_shadow() {
    if !begin_root_test("root_never_reads_a_pack_swapped_for_a_symlink_to_shadow") {
        return;
    }
    // The agent's directory, the agent's link to a file only root can read:
    // root refuses the link, and its refusal holds no byte of the target.
    let dir = "/var/tmp/xudo-root-pack-swap";
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).unwrap();
    let secret = format!("{dir}/shadow");
    fs::write(&secret, "root:$y$j9T$secretsecret:20000:0:99999:7:::\n").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    for target in [secret.as_str(), "/etc/shadow"] {
        let link = format!("{dir}/pack.toml");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(target, &link).unwrap();
        let error = read_pack_file(std::path::Path::new(&link)).unwrap_err();
        assert!(matches!(error, PackFileError::Open { .. }), "{error}");
        let text = error.to_string();
        assert!(
            !text.contains("secret") && !text.contains("root:"),
            "{text}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}
