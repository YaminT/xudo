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

use xudo_policy::pack::{Change, review, token_of, without_pack};
use xudo_policy::{HarnessFile, RuleFile, is_rule_file_name};
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
const REGISTRY: &str = "/etc/xudo/harnesses.d";
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

/// The rule files in `/etc/xudo/rules.d` and the registry, as the operator's
/// review reads them.
fn rules_now() -> (Vec<RuleFile>, Result<Vec<HarnessFile>, String>) {
    let mut names: Vec<String> = fs::read_dir(DIR)
        .map(|dir| {
            dir.map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let rules = names
        .into_iter()
        .filter(|name| is_rule_file_name(name.as_bytes()))
        .map(|name| RuleFile {
            bytes: fs::read(format!("{DIR}/{name}")).unwrap(),
            name: name.into_bytes(),
        })
        .collect();
    let mut harnesses: Vec<String> = fs::read_dir(REGISTRY)
        .map(|dir| {
            dir.map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    harnesses.sort();
    let registry = harnesses
        .into_iter()
        .filter(|name| name.as_bytes().ends_with(b".toml"))
        .map(|name| HarnessFile {
            bytes: fs::read(format!("{REGISTRY}/{name}")).unwrap(),
            name: name.into_bytes(),
        })
        .collect();
    (rules, Ok(registry))
}

/// The token the operator's review prints for adding `text` now. Root's
/// refusal of a wrong one no longer carries it.
fn add_token(text: &str) -> String {
    let (before, registry) = rules_now();
    let change = Change::Add {
        pack: text.as_bytes(),
        allow_waivers: false,
    };
    token_of(before, &registry, change).unwrap()
}

fn add(text: &str) -> Result<PackReport, PackError> {
    let ops = HostInstallOps::system();
    assert_eq!(
        add_pack(&request(text, "?"), &Session, &ops, &ops).unwrap_err(),
        PackError::Changed
    );
    add_pack(&request(text, &add_token(text)), &Session, &ops, &ops)
}

fn remove(name: &str) -> Result<PackReport, PackError> {
    let ops = HostInstallOps::system();
    let (before, registry) = rules_now();
    let Some(after) = without_pack(&before, name) else {
        return remove_pack(name, "?", &Session, &ops, &ops);
    };
    let token = review(before, after, &registry, Change::Remove { name })
        .unwrap()
        .token;
    remove_pack(name, &token, &Session, &ops, &ops)
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
    let error = add_pack(&request(PACK, &add_token(PACK)), &Session, &ops, &ops).unwrap_err();
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
        assert_eq!(add, Err(PackError::Changed), "{own}");
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
        assert_eq!(error, PackFileError::Unusable { path: link.clone() });
        let text = error.to_string();
        assert!(
            !text.contains("secret") && !text.contains("root:"),
            "{text}"
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn root_never_follows_a_parent_directory_swapped_for_a_link() {
    if !begin_root_test("root_never_follows_a_parent_directory_swapped_for_a_link") {
        return;
    }
    // The operator reviewed `<dir>/x/<name>`; the agent then made `x` a link
    // to `/dev` (a watchdog starts on open) or to `/etc` (a regular file
    // root alone may read). Root refuses on the link with one text, whether
    // the target exists or not.
    let dir = "/var/tmp/xudo-root-pack-parent";
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).unwrap();
    let link = format!("{dir}/x");
    for (target, name) in [
        ("/dev", "null"),
        ("/dev", "zero"),
        ("/etc", "shadow"),
        ("/etc", "no-such-file"),
    ] {
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(target, &link).unwrap();
        let path = format!("{link}/{name}");
        let error = read_pack_file(std::path::Path::new(&path)).unwrap_err();
        assert_eq!(error, PackFileError::Unusable { path: path.clone() });
        assert!(!error.to_string().contains("root:"), "{error}");
    }
    fs::remove_dir_all(dir).unwrap();
}
