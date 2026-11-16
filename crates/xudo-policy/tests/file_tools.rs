//! File tools are a compiled-in capability class, not a path check.
//!
//! `path-under` is lexical. An agent who can plant a symlink inside the prefix
//! makes `rm` delete a path the rule never named, and `chmod u+s` is a shell
//! on any path. These tests try those attacks. They live here, not in the
//! library, so miri's `--lib` run does not grow.

#![allow(clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use xudo_policy::{
    Arg, Argv, CallerFacts, CapabilityClass, Classification, DenialCode, Matcher, RuleSet, Verdict,
    engine::Settings, evaluate_command, evaluate_deny_list,
};

/// The file-tool names. A copy or a hardlink is denied when it keeps one.
const FILE_TOOLS: &[&str] = &[
    "rm",
    "rmdir",
    "unlink",
    "chmod",
    "chown",
    "chgrp",
    "chattr",
    "setfacl",
    "setfattr",
    "touch",
    "mkdir",
    "mkfifo",
    "rename",
    "prename",
    "link",
    "chcon",
    "restorecon",
    "setfiles",
    "chacl",
    "attr",
    "fallocate",
    "mktemp",
    "file-rename",
];

fn findings(exe: &str, args: &[&str]) -> Vec<CapabilityClass> {
    evaluate_deny_list(exe.as_bytes(), &Argv::new(args.iter().copied()))
        .into_iter()
        .map(|finding| finding.class)
        .collect()
}

fn has(exe: &str, args: &[&str], class: CapabilityClass) -> bool {
    findings(exe, args).contains(&class)
}

const RM_HOME: &str = r#"
[[action]]
id = "xudo.files.rm-home"
tier = "diag-read"
exe = "/bin/rm"
args = [
  { name = "flags", matcher = { literal = "-rf" }, repeat = "optional" },
  { name = "path", matcher = { path-under = { prefix = "/home/agent" } } },
]
"#;

/// The agent planted `workspace/link` -> `/`. The lexical path sits under the
/// prefix, and `rm` follows the symlink to `/etc/shadow`.
#[test]
fn denies_rm_under_a_path_under_rule_via_agent_symlink() {
    let rules = RuleSet::from_toml("rm-home.toml", RM_HOME).unwrap();
    let path = "/home/agent/workspace/link/etc/shadow";
    let matcher = rules
        .actions()
        .iter()
        .flat_map(|action| action.args.iter())
        .find(|spec| spec.name == "path")
        .map(|spec| &spec.matcher)
        .unwrap();
    assert!(
        matcher.accepts(&Arg::from(path)),
        "the lexical matcher must accept the symlink path, or this test no longer shows the hole"
    );
    assert!(matches!(matcher, Matcher::PathUnder { .. }));

    let agent = CallerFacts::new(
        Classification::EnrolledAgent {
            agent_id: "claude-code".into(),
            session_id: "s-1".into(),
            declared_yolo: true,
        },
        1000,
    );
    let argv = Argv::new(["-rf", path]);
    let decision = evaluate_command(
        &rules,
        &agent,
        &Arg::from("/bin/rm"),
        &argv,
        Settings::default(),
    );
    assert_eq!(decision.verdict, Verdict::Deny);
    assert_eq!(decision.denial, Some(DenialCode::DenyListed));
    assert!(
        decision.trace.iter().any(|step| matches!(
            step,
            xudo_policy::decision::TraceStep::ActionMatched { action, .. }
                if action == "xudo.files.rm-home"
        )),
        "the rule matched; the deny-list is what refused it: {:?}",
        decision.trace
    );
    assert!(
        has(
            "/bin/rm",
            &["-rf", path],
            CapabilityClass::ChangesPathMetadataOrExistence
        ),
        "{:?}",
        findings("/bin/rm", &["-rf", path])
    );
    // A copy and a hardlink that keep the name are the same class.
    assert!(has(
        "/tmp/copy/rm",
        &[path],
        CapabilityClass::ChangesPathMetadataOrExistence
    ));
    assert!(has(
        "/opt/hardlink/rm",
        &[],
        CapabilityClass::ChangesPathMetadataOrExistence
    ));
}

#[test]
fn denies_chmod_setuid_on_any_path() {
    let class = CapabilityClass::ChangesPathMetadataOrExistence;
    for args in [
        ["4755", "/tmp/owned"].as_slice(),
        ["6755", "/home/agent/bin/tool"].as_slice(),
        ["u+s", "/var/tmp/nowhere"].as_slice(),
        ["a+s", "./tool"].as_slice(),
        ["777", "/tmp/x"].as_slice(),
        ["--reference=/tmp/mode", "/home/agent/file"].as_slice(),
    ] {
        let found = findings("/bin/chmod", args);
        assert!(found.contains(&class), "{args:?} -> {found:?}");
        assert!(
            !found.contains(&CapabilityClass::SelfModification),
            "a path outside the protected set must be denied for the file tool, not for the path: {args:?} -> {found:?}"
        );
    }
    assert!(has("/tmp/copy/chmod", &["4755", "/tmp/x"], class));
    assert!(has("/opt/hardlink/chmod", &["u+s", "/any/path"], class));
    // No path at all is still the tool.
    assert!(has("/usr/bin/chmod", &[], class));
}

#[test]
fn denies_chown_of_etc_shadow() {
    let found = findings("/bin/chown", &["root:shadow", "/etc/shadow"]);
    assert!(
        found.contains(&CapabilityClass::ChangesPathMetadataOrExistence),
        "{found:?}"
    );
    assert!(
        found.contains(&CapabilityClass::SelfModification),
        "chown of the shadow file is also a write to a protected path: {found:?}"
    );
    assert!(has(
        "/usr/sbin/chown",
        &["0:0", "/etc/shadow"],
        CapabilityClass::ChangesPathMetadataOrExistence
    ));
    assert!(has(
        "/tmp/copy/chown",
        &["root", "/etc/shadow"],
        CapabilityClass::ChangesPathMetadataOrExistence
    ));
    // A path that is not protected is still refused, because the tool is.
    let ordinary = findings("/bin/chown", &["agent", "/home/agent/inbox"]);
    assert_eq!(
        ordinary,
        vec![CapabilityClass::ChangesPathMetadataOrExistence]
    );
}

#[test]
fn denies_rm_via_busybox_applet() {
    let class = CapabilityClass::ChangesPathMetadataOrExistence;
    let applet = findings("/bin/busybox", &["rm", "-rf", "/home/agent/link"]);
    assert!(applet.contains(&class), "{applet:?}");
    assert!(
        applet.contains(&CapabilityClass::SpawnsShell),
        "busybox itself stays a shell: {applet:?}"
    );
    // The applet named as a path, the way a copy of the link is spelled.
    assert!(has("/usr/bin/busybox", &["/bin/rm", "/tmp/x"], class));
    assert!(has(
        "/opt/hardlink/busybox",
        &["chmod", "4755", "/tmp/x"],
        class
    ));
    // No applet argument: still a shell, not a file tool.
    let bare = findings("/bin/busybox", &[]);
    assert!(bare.contains(&CapabilityClass::SpawnsShell), "{bare:?}");
    assert!(!bare.contains(&class), "{bare:?}");
    // A different applet does not borrow the file-tool class from a later word.
    let echo = findings("/bin/busybox", &["echo", "rm"]);
    assert!(!echo.contains(&class), "{echo:?}");
}

#[test]
fn denies_rm_via_coreutils_and_toybox_multicall() {
    let class = CapabilityClass::ChangesPathMetadataOrExistence;
    for exe in ["/usr/bin/coreutils", "/bin/toybox", "/opt/x/coreutils"] {
        assert!(has(exe, &["rm", "-rf", "/tmp/x"], class), "{exe}");
        assert!(has(exe, &["/bin/chmod", "4755", "/tmp/x"], class), "{exe}");
        // No applet, or a flag in its place: the applet is unknown, so refused.
        assert!(has(exe, &[], class), "{exe}");
        assert!(has(exe, &["--help"], class), "{exe}");
        // An applet from another class keeps that class.
        assert!(has(
            exe,
            &["cp", "/a", "/b"],
            CapabilityClass::ArbitraryWrite
        ));
    }
    assert!(has(
        "/usr/bin/coreutils",
        &["--coreutils-prog=rm", "/tmp/x"],
        class
    ));
    assert!(has(
        "/usr/bin/coreutils",
        &["--coreutils-prog=tee", "/tmp/x"],
        CapabilityClass::ArbitraryWrite
    ));
    // A plain applet no list knows is not a file tool.
    assert!(!has("/usr/bin/coreutils", &["true"], class));
    // Only coreutils reads the joined spelling; busybox reads it as a flag.
    assert!(!has("/bin/busybox", &["--coreutils-prog=rm"], class));
    // toybox is a shell-class multicall like busybox.
    assert!(has("/bin/toybox", &["true"], CapabilityClass::SpawnsShell));
}

#[test]
fn denies_writes_via_patch_compressors_alternatives_and_debugfs() {
    for tool in [
        "patch",
        "gzip",
        "xz",
        "zstd",
        "bzip2",
        "update-alternatives",
        "dpkg-divert",
    ] {
        assert!(
            has(
                &format!("/usr/bin/{tool}"),
                &[],
                CapabilityClass::ArbitraryWrite
            ),
            "{tool}"
        );
    }
    assert!(has(
        "/sbin/debugfs",
        &[],
        CapabilityClass::DeviceOrFilesystem
    ));
}

#[test]
fn an_rm_path_under_rule_is_self_denying() {
    let rules = RuleSet::from_toml("rm-home.toml", RM_HOME).unwrap();
    let offenders = rules.self_denying_actions();
    assert_eq!(offenders.len(), 1, "{offenders:?}");
    assert_eq!(
        offenders.first().map(|(id, _)| id.as_str()),
        Some("xudo.files.rm-home")
    );
    assert!(
        offenders.first().is_some_and(
            |(_, classes)| classes.contains(&CapabilityClass::ChangesPathMetadataOrExistence)
        ),
        "{offenders:?}"
    );
}

/// `setcap` was already a privilege tool. `mknod` joins the device class.
/// `mount` and `umount` are not named on the list; a device argument is a
/// separate finding and is not what this check is about.
#[test]
fn setcap_mknod_mount_and_umount_were_checked_against_the_existing_lists() {
    assert!(has(
        "/sbin/setcap",
        &["cap_setuid=ep", "/tmp/x"],
        CapabilityClass::PrivilegeTool
    ));
    assert!(!has(
        "/sbin/setcap",
        &[],
        CapabilityClass::ChangesPathMetadataOrExistence
    ));
    assert!(has(
        "/bin/mknod",
        &["/tmp/node", "c", "1", "3"],
        CapabilityClass::DeviceOrFilesystem
    ));
    assert!(!has(
        "/bin/mknod",
        &[],
        CapabilityClass::ChangesPathMetadataOrExistence
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn appending_a_file_tool_argument_never_allows(
        tool in prop::sample::select(FILE_TOOLS),
        copy in prop::sample::select(&["/bin", "/usr/bin", "/tmp/copy", "/opt/hardlink"][..]),
        arg in "[a-zA-Z0-9._/=-]{0,32}",
        extra in "[a-zA-Z0-9._/=-]{0,24}",
        multicall in prop::sample::select(&["", "busybox", "toybox", "coreutils"][..]),
    ) {
        let (exe, mut args) = if multicall.is_empty() {
            (format!("{copy}/{tool}"), Vec::new())
        } else {
            (format!("/bin/{multicall}"), vec![Arg::from(tool)])
        };
        args.push(Arg::from(arg.as_str()));
        let before = evaluate_deny_list(exe.as_bytes(), &Argv::new(args.clone()));
        prop_assert!(
            before
                .iter()
                .any(|finding| finding.class == CapabilityClass::ChangesPathMetadataOrExistence),
            "allowed {exe} {args:?}"
        );
        args.push(Arg::from(extra.as_str()));
        let after = evaluate_deny_list(exe.as_bytes(), &Argv::new(args));
        prop_assert!(
            after.iter().any(|finding| finding.class == CapabilityClass::ChangesPathMetadataOrExistence)
        );
        for finding in &before {
            prop_assert!(after.iter().any(|later| later.class == finding.class));
        }
    }
}
