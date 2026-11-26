//! Enrolment against described machines. Each refusal has a test that tries to
//! get past it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::*;
use crate::paths_to_root::Answer;
use crate::paths_to_root::MemoryHost;

const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
    agent:x:990:990::/var/lib/agent:/usr/sbin/nologin\n\
    alice:x:1000:1000::/home/alice:/bin/bash\n\
    bob:x:1001:1001::/home/bob:/bin/bash\n";
const SHADOW: &str =
    "root:$6$x:19000:0:99999:7:::\nagent:!:19000::::::\nalice:$6$y:19000:0:99999:7:::\n";
const GROUP: &str = "root:x:0:\nagent:x:990:\nalice:x:1000:\nxudo:x:998:agent\n";

fn request() -> EnrolRequest {
    EnrolRequest {
        label: "codex".to_owned(),
        account: "agent".to_owned(),
        reviewers: vec!["alice".to_owned()],
        argv: vec!["/usr/bin/codex".to_owned(), "exec".to_owned()],
    }
}

fn facts() -> Facts {
    Facts {
        passwd: PASSWD.as_bytes().to_vec(),
        shadow: Some(SHADOW.as_bytes().to_vec()),
        group: GROUP.as_bytes().to_vec(),
        registry: Vec::new(),
        drop_in: DropInState::Absent,
        env_present: false,
        scan: AccountScan {
            uid: 990,
            blockers: Vec::new(),
            doas: false,
        },
    }
}

fn other_harness() -> (String, String) {
    (
        "claude.toml".to_owned(),
        "label = \"claude\"\nway = \"service\"\naccount = \"claude\"\nreviewers = [\"bob\"]\nmax-sessions = 1\n"
            .to_owned(),
    )
}

fn refusal(request: &EnrolRequest, facts: &Facts) -> Refusal {
    plan(request, facts).unwrap_err()
}

#[test]
fn plans_the_registry_entry_the_drop_in_and_the_env_stub() {
    let plan = plan(&request(), &facts()).unwrap();
    assert_eq!(plan.unit, "xudo-agent@codex.service");
    assert_eq!(plan.registry.path, "/etc/xudo/harnesses.d/codex.toml");
    assert_eq!(
        plan.drop_in.path,
        "/etc/systemd/system/xudo-agent@codex.service.d/10-xudo.conf"
    );
    assert_eq!(plan.env.path, "/etc/xudo/agents/codex.env");
    assert_eq!(plan.env.mode, 0o600);
    assert!(plan.registry.contents.starts_with(MANAGED_MARKER));
    assert!(plan.drop_in.contents.contains("User=agent\n"));
    assert!(
        plan.drop_in
            .contents
            .contains("ExecStart=\"/usr/bin/codex\" \"exec\"\n")
    );
    // No file lets anyone but root write it.
    for file in [&plan.registry, &plan.drop_in, &plan.env] {
        assert_eq!(file.mode & 0o133, 0, "{}", file.path);
        assert!(file.contents.starts_with(MANAGED_MARKER));
    }
    let shown = plan.render();
    assert!(shown.contains("--- /etc/xudo/harnesses.d/codex.toml (mode 0644, root, new)"));
    assert!(shown.contains("+ account = \"agent\""));
    assert!(shown.contains("systemctl enable --now xudo-agent@codex.service"));
}

#[test]
fn an_existing_env_file_is_kept_and_not_shown() {
    let mut facts = facts();
    facts.env_present = true;
    let plan = plan(&request(), &facts).unwrap();
    assert!(plan.env.keep);
    let shown = plan.render();
    assert!(shown.contains("/etc/xudo/agents/codex.env (mode 0600, root, already there, kept"));
    assert!(!shown.contains("Credentials for"));
}

#[test]
fn enrol_refuses_malformed_names() {
    let mut bad = request();
    bad.label = "../x".to_owned();
    assert_eq!(
        refusal(&bad, &facts()),
        Refusal::BadLabel("../x".to_owned())
    );
    let mut bad = request();
    bad.account = "Agent".to_owned();
    assert_eq!(
        refusal(&bad, &facts()),
        Refusal::BadAccount("Agent".to_owned())
    );
    let mut bad = request();
    bad.reviewers = vec![];
    assert_eq!(refusal(&bad, &facts()), Refusal::NoReviewer);
    let mut bad = request();
    bad.reviewers = vec!["alice".to_owned(), "a b".to_owned()];
    assert_eq!(
        refusal(&bad, &facts()),
        Refusal::BadReviewer("a b".to_owned())
    );
}

#[test]
fn enrol_refuses_an_account_not_in_passwd() {
    let mut bad = request();
    bad.account = "ghost".to_owned();
    assert_eq!(
        refusal(&bad, &facts()),
        Refusal::AccountUnknown("ghost".to_owned())
    );
}

#[test]
fn enrol_refuses_root_by_uid_or_by_primary_group() {
    let mut facts = facts();
    facts.passwd = b"toor:x:0:990::/root:/bin/sh\nalice:x:1000:1000::/h:/bin/sh\n".to_vec();
    let mut bad = request();
    bad.account = "toor".to_owned();
    assert_eq!(
        refusal(&bad, &facts),
        Refusal::AccountIsRoot("toor".to_owned())
    );
    facts.passwd = b"gid0:x:990:0::/h:/bin/sh\nalice:x:1000:1000::/h:/bin/sh\n".to_vec();
    bad.account = "gid0".to_owned();
    assert_eq!(
        refusal(&bad, &facts),
        Refusal::AccountIsRoot("gid0".to_owned())
    );
}

#[test]
fn enrol_refuses_an_account_whose_name_or_uid_is_ambiguous() {
    let mut facts = facts();
    facts
        .passwd
        .extend_from_slice(b"agent:x:991:991::/h:/bin/sh\n");
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::AccountAmbiguous("agent".to_owned())
    );
    let mut facts = self::facts();
    facts
        .passwd
        .extend_from_slice(b"twin:x:990:990::/h:/bin/sh\n");
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::AccountAmbiguous("agent".to_owned())
    );
}

#[test]
fn enrol_refuses_an_account_that_changed_uid_under_the_scan() {
    let mut facts = facts();
    facts.scan.uid = 991;
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::AccountChanged("agent".to_owned())
    );
}

#[test]
fn enrol_refuses_an_account_with_a_usable_password() {
    let usable = Refusal::PasswordUsable("agent".to_owned());
    for line in [
        "agent:$6$salt$hash:19000::::::\n",
        "agent::19000::::::\n", // empty: a login with no password
        "agent:xx:19000::::::\n",
    ] {
        let mut facts = facts();
        facts.shadow = Some(line.as_bytes().to_vec());
        assert_eq!(refusal(&request(), &facts), usable, "{line}");
    }
    // A hash in /etc/passwd itself, with no shadow file consulted.
    let mut facts = facts();
    facts.passwd = b"agent:$6$h:990:990::/h:/bin/sh\nalice:x:1000:1000::/h:/bin/sh\n".to_vec();
    facts.shadow = None;
    assert_eq!(refusal(&request(), &facts), usable);
    // Locked accounts pass, whichever way they are locked.
    for line in [
        "agent:*:1::::::\n",
        "agent:!!:1::::::\n",
        "agent:!$6$h:1::::::\n",
    ] {
        let mut facts = self::facts();
        facts.shadow = Some(line.as_bytes().to_vec());
        plan(&request(), &facts).unwrap();
    }
}

#[test]
fn enrol_refuses_an_account_whose_password_cannot_be_read() {
    let unknown = Refusal::PasswordUnknown("agent".to_owned());
    let mut facts = facts();
    facts.shadow = None;
    assert_eq!(refusal(&request(), &facts), unknown);
    facts.shadow = Some(b"alice:!:1::::::\nnot a shadow line\n".to_vec());
    assert_eq!(refusal(&request(), &facts), unknown);
}

#[test]
fn enrol_refuses_an_account_in_a_root_equivalent_group() {
    for group in ROOT_EQUIVALENT_GROUPS {
        // A listed member.
        let mut facts = facts();
        facts
            .group
            .extend_from_slice(format!("{group}:x:500:alice,agent\n").as_bytes());
        assert_eq!(
            refusal(&request(), &facts),
            Refusal::RootGroup {
                account: "agent".to_owned(),
                group: group.to_owned()
            },
            "{group}"
        );
        // The primary group.
        let mut facts = self::facts();
        facts
            .group
            .extend_from_slice(format!("{group}:x:990:\n").as_bytes());
        assert!(matches!(
            refusal(&request(), &facts),
            Refusal::RootGroup { .. }
        ));
    }
    // Someone else in the group is not the account; a short line is skipped.
    let mut facts = facts();
    facts
        .group
        .extend_from_slice(b"sudo:x:27:alice\nbroken\ndocker:x:999:agentx\n");
    plan(&request(), &facts).unwrap();
}

#[test]
fn enrol_refuses_an_account_with_any_sudo_rule() {
    let passwd = PASSWD.as_bytes();
    let host = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, passwd)
    .file("/etc/group", 0, 0, 0o644, GROUP.as_bytes())
    .file(
        "/etc/sudoers",
        0,
        0,
        0o440,
        b"agent ALL=(ALL) NOPASSWD: ALL\n",
    );
    let scan = scan_account(&with_pam(host), "agent", &Input::default(), None).unwrap();
    assert_eq!(scan.uid, 990);
    assert!(
        scan.blockers.iter().any(|line| line.contains("NOPASSWD")),
        "{:?}",
        scan.blockers
    );
    let mut facts = facts();
    facts.scan = scan;
    assert!(matches!(
        refusal(&request(), &facts),
        Refusal::OtherPathToRoot { .. }
    ));
    // The same file naming someone else does not stop agent.
    let host = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, passwd)
    .file("/etc/group", 0, 0, 0o644, GROUP.as_bytes())
    .file(
        "/etc/sudoers",
        0,
        0,
        0o440,
        b"alice ALL=(ALL) NOPASSWD: ALL\n",
    );
    let scan = scan_account(&with_pam(host), "agent", &Input::default(), None).unwrap();
    assert_eq!(scan.blockers, Vec::<String>::new());
}

#[test]
fn the_scan_reports_what_it_could_not_read_as_a_blocker() {
    let host = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, PASSWD.as_bytes())
    .unreadable_file("/etc/sudoers", 0, 0, 0o440);
    let scan = scan_account(&host, "agent", &Input::default(), None).unwrap();
    assert!(
        scan.blockers
            .iter()
            .any(|line| line.contains("could not examine /etc/sudoers")),
        "{:?}",
        scan.blockers
    );
}

#[test]
fn the_scan_answers_as_the_account_not_as_the_host_it_runs_on() {
    // Run as root, the report would skip every check. As the account it must
    // not, and every question the report asks passes through to the host.
    let host = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .file("/p", 0, 0, 0o600, b"x")
    .link("/l", "/p");
    let account = AsAccount {
        inner: &host,
        uid: 990,
        gid: 990,
        group: None,
    };
    let joined = AsAccount {
        group: Some(b"xudo:x:1:agent\n".to_vec()),
        ..AsAccount {
            inner: &host,
            uid: 990,
            gid: 990,
            group: None,
        }
    };
    assert_eq!(
        joined.read(Path::new("/etc/group")),
        Lookup::Found(b"xudo:x:1:agent\n".to_vec())
    );
    assert_eq!(joined.read(Path::new("/p")), Lookup::Found(b"x".to_vec()));
    let caller = account.caller();
    assert_eq!((caller.uid, caller.gid), (990, 990));
    assert_eq!(caller.groups, Lookup::Found(vec![]));
    assert!(matches!(account.stat(Path::new("/p")), Lookup::Found(_)));
    assert_eq!(account.read(Path::new("/p")), Lookup::Found(b"x".to_vec()));
    assert!(matches!(account.list(Path::new("/")), Lookup::Found(_)));
    assert_eq!(
        account.read_link(Path::new("/l")),
        Lookup::Found(Path::new("/p").to_path_buf())
    );
    assert!(!account.writable(Path::new("/p")));
    assert_eq!(
        account.ask_sudo("/usr/bin/sudo", "agent"),
        host.ask_sudo("/usr/bin/sudo", "agent")
    );
    assert_eq!(
        account.ask_doas("/usr/bin/doas", Path::new("/etc/doas.conf"), "id"),
        host.ask_doas("/usr/bin/doas", Path::new("/etc/doas.conf"), "id")
    );
}

#[test]
fn the_scan_refuses_an_account_passwd_cannot_name_once() {
    let host = |passwd: &[u8]| {
        MemoryHost::new(Caller {
            uid: 0,
            gid: 0,
            groups: Lookup::Found(vec![0]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/passwd", 0, 0, 0o644, passwd)
    };
    let missing = scan_account(&host(PASSWD.as_bytes()), "ghost", &Input::default(), None);
    assert_eq!(
        missing.unwrap_err(),
        Refusal::AccountUnknown("ghost".to_owned())
    );
    let twice = scan_account(
        &host(b"a:x:5:5::/h:/s\na:x:6:6::/h:/s\n"),
        "a",
        &Input::default(),
        None,
    );
    assert_eq!(
        twice.unwrap_err(),
        Refusal::AccountAmbiguous("a".to_owned())
    );
    let none = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![]),
    });
    assert_eq!(
        scan_account(&none, "a", &Input::default(), None).unwrap_err(),
        Refusal::AccountUnknown("a".to_owned())
    );
}

#[test]
fn enrol_refuses_the_account_as_its_own_reviewer() {
    let mut bad = request();
    bad.reviewers = vec!["alice".to_owned(), "agent".to_owned()];
    assert_eq!(
        refusal(&bad, &facts()),
        Refusal::ReviewerIsAccount("agent".to_owned())
    );
}

#[test]
fn enrol_refuses_a_reviewer_who_does_not_exist() {
    let mut bad = request();
    bad.reviewers = vec!["nobody".to_owned()];
    assert_eq!(
        refusal(&bad, &facts()),
        Refusal::ReviewerUnknown("nobody".to_owned())
    );
}

#[test]
fn enrol_refuses_an_account_used_by_another_label() {
    let mut facts = facts();
    facts.registry = vec![(
        "claude.toml".to_owned(),
        "label = \"claude\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"bob\"]\nmax-sessions = 1\n"
            .to_owned(),
    )];
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::AccountInUse {
            account: "agent".to_owned(),
            label: "claude".to_owned()
        }
    );
    // Listed as a session user of another label is the same thing.
    facts.registry = vec![(
        "dev.toml".to_owned(),
        "label = \"dev\"\nway = \"session\"\nusers = [\"agent\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n"
            .to_owned(),
    )];
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::AccountInUse {
            account: "agent".to_owned(),
            label: "dev".to_owned()
        }
    );
}

#[test]
fn enrol_refuses_a_reviewer_who_is_another_harnesss_account() {
    let mut facts = facts();
    facts.registry = vec![other_harness()];
    facts
        .passwd
        .extend_from_slice(b"claude:x:991:991::/h:/bin/sh\n");
    let mut bad = request();
    bad.reviewers = vec!["claude".to_owned()];
    assert!(matches!(refusal(&bad, &facts), Refusal::Registry(_)));
    // And another harness's reviewer may not be this account.
    let mut other = other_harness();
    other.1 = other.1.replace("bob", "agent");
    facts.registry = vec![other];
    assert!(matches!(refusal(&request(), &facts), Refusal::Registry(_)));
}

#[test]
fn enrol_refuses_a_label_already_enrolled_and_a_registry_that_does_not_load() {
    let mut facts = facts();
    facts.registry = vec![("codex.toml".to_owned(), "x".to_owned())];
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::LabelTaken("codex".to_owned())
    );
    facts.registry = vec![("claude.toml".to_owned(), "not toml {".to_owned())];
    assert!(matches!(refusal(&request(), &facts), Refusal::Registry(_)));
    // An unrelated, valid entry does not stand in the way.
    facts.registry = vec![other_harness()];
    plan(&request(), &facts).unwrap();
}

#[test]
fn enrol_refuses_a_drop_in_directory_that_could_override_user() {
    let mut facts = facts();
    facts.drop_in = DropInState::Occupied;
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::DropInOccupied("codex".to_owned())
    );
    facts.drop_in = DropInState::Untrusted("owned by uid 1000".to_owned());
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::DropInUntrusted("owned by uid 1000".to_owned())
    );
    facts.drop_in = DropInState::Empty;
    plan(&request(), &facts).unwrap();
}

#[test]
fn exec_start_escapes_specifiers() {
    let line = exec_start(&[
        "/usr/bin/x".to_owned(),
        "%i".to_owned(),
        "$HOME".to_owned(),
        "${PATH}".to_owned(),
        "say \"hi\"".to_owned(),
        "back\\slash".to_owned(),
        ";".to_owned(),
        "a b".to_owned(),
        String::new(),
    ])
    .unwrap();
    assert_eq!(
        line,
        r#""/usr/bin/x" "%%i" "$$HOME" "$${PATH}" "say \"hi\"" "back\\slash" ";" "a b" """#
    );
}

#[test]
fn exec_start_refuses_what_a_unit_line_cannot_carry() {
    assert_eq!(exec_start(&[]).unwrap_err(), Refusal::NoProgram);
    assert_eq!(
        exec_start(&["codex".to_owned()]).unwrap_err(),
        Refusal::ProgramNotAbsolute("codex".to_owned())
    );
    for bad in [
        "a\nExecStartPre=/bin/sh",
        "a\rb",
        "a\0b",
        "a\tb",
        "a\u{7f}b",
    ] {
        assert_eq!(
            exec_start(&["/usr/bin/x".to_owned(), bad.to_owned()]).unwrap_err(),
            Refusal::ControlCharacter,
            "{bad:?}"
        );
    }
}

#[test]
fn a_hostile_argument_cannot_leave_its_quotes() {
    // Whatever the argument holds, the rendered word has no `"` that is not
    // escaped and no `%` or `$` that is not doubled: nothing systemd expands.
    for word in [
        "\"; User=root",
        "\\\"",
        "%%",
        "$$",
        "%u$USER\\",
        "\"\"\"",
        "\\\\\"",
    ] {
        let line = exec_start(&["/x".to_owned(), word.to_owned()]).unwrap();
        let body = line
            .strip_prefix("\"/x\" \"")
            .unwrap()
            .strip_suffix('"')
            .unwrap();
        let mut chars = body.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => assert!(matches!(chars.next(), Some('\\' | '"'))),
                '%' => assert_eq!(chars.next(), Some('%')),
                '$' => assert_eq!(chars.next(), Some('$')),
                _ => assert_ne!(c, '"', "{word:?} left its quotes"),
            }
        }
    }
}

#[test]
fn list_shows_service_entries_and_skips_sessions() {
    let files = vec![
        other_harness(),
        (
            "dev.toml".to_owned(),
            "label = \"dev\"\nway = \"session\"\nusers = [\"alice\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n"
                .to_owned(),
        ),
    ];
    assert_eq!(
        listed(&files).unwrap(),
        vec![Listed {
            label: "claude".to_owned(),
            account: "claude".to_owned(),
            reviewers: vec!["bob".to_owned()],
        }]
    );
    assert!(matches!(
        listed(&[("x.toml".to_owned(), "x".to_owned())]).unwrap_err(),
        Refusal::Registry(_)
    ));
}

#[test]
fn every_path_is_under_its_directory() {
    assert_eq!(registry_path("a"), "/etc/xudo/harnesses.d/a.toml");
    assert_eq!(
        drop_in_dir("a"),
        "/etc/systemd/system/xudo-agent@a.service.d"
    );
    assert_eq!(env_path("a"), "/etc/xudo/agents/a.env");
}

#[test]
fn a_passwd_line_that_is_not_an_account_names_no_one() {
    // Short, with a uid or gid that is not a number or not text: skipped, as
    // getpwent skips it, so none of them can name the account.
    let mut facts = facts();
    facts.passwd =
        b"agent\nagent:x\nagent:x:notnum:990\nagent:x:990:notnum\nagent:x:\xff:990\n".to_vec();
    assert_eq!(
        refusal(&request(), &facts),
        Refusal::AccountUnknown("agent".to_owned())
    );
}

fn host_with(group: &str, sudoers: &[u8]) -> MemoryHost {
    let host = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, PASSWD.as_bytes())
    .file("/etc/group", 0, 0, 0o644, group.as_bytes())
    .file("/etc/sudoers", 0, 0, 0o440, sudoers);
    with_pam(host)
}

/// The host with Debian's stock PAM stack for sudo.
fn with_pam(host: MemoryHost) -> MemoryHost {
    host.dir("/etc/pam.d", 0, 0, 0o755)
        .file("/etc/pam.d/sudo", 0, 0, 0o644, DEBIAN_PAM_SUDO.as_bytes())
        .file(
            "/etc/pam.d/common-auth",
            0,
            0,
            0o644,
            DEBIAN_COMMON_AUTH.as_bytes(),
        )
        .file(
            "/etc/pam.d/common-account",
            0,
            0,
            0o644,
            b"account required pam_unix.so\n",
        )
        .file(
            "/etc/pam.d/common-session-noninteractive",
            0,
            0,
            0o644,
            b"session required pam_unix.so\n",
        )
}

/// Debian's own `/etc/pam.d/sudo`, and its `common-auth`, which ends in
/// `pam_permit` after a `requisite` `pam_deny`.
const DEBIAN_PAM_SUDO: &str = "#%PAM-1.0\nsession required pam_env.so readenv=1 user_readenv=0\n@include common-auth\n@include common-account\n@include common-session-noninteractive\n";
const DEBIAN_COMMON_AUTH: &str = "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\nauth optional pam_cap.so\n";

/// What the scan says and what the plan then does, for a described host.
fn through(host: &MemoryHost) -> (AccountScan, Result<EnrolPlan, Refusal>) {
    let scan = scan_account(host, "agent", &Input::default(), None).unwrap();
    let mut facts = facts();
    facts.group = match host.read(Path::new("/etc/group")) {
        Lookup::Found(bytes) => bytes,
        _ => Vec::new(),
    };
    facts.scan = scan.clone();
    (scan, plan(&request(), &facts))
}

fn denied(host: &MemoryHost) -> String {
    let (scan, planned) = through(host);
    assert!(!scan.blockers.is_empty(), "the scan found nothing");
    let Refusal::OtherPathToRoot { blockers, .. } = planned.unwrap_err() else {
        unreachable!("the scan found something, so the plan must say so");
    };
    blockers
}

#[test]
fn a_plain_account_on_a_plain_host_is_clean() {
    let host = host_with(
        GROUP,
        b"root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
    )
    .dir("/etc/sudoers.d", 0, 0, 0o755);
    let (scan, planned) = through(&host);
    assert_eq!(scan.blockers, Vec::<String>::new());
    planned.unwrap();
}

#[test]
fn enrol_refuses_a_gid_alias_of_a_root_equivalent_group() {
    // `dockerish` shares docker's gid and lists the account.
    let group = format!("{GROUP}docker:x:999:\ndockerish:x:999:agent\n");
    let host = host_with(&group, b"");
    let (_, planned) = through(&host);
    assert_eq!(
        planned.unwrap_err(),
        Refusal::RootGroup {
            account: "agent".to_owned(),
            group: "docker".to_owned()
        }
    );
    // As a primary gid too.
    let mut facts = facts();
    facts.passwd = b"agent:x:990:999::/h:/bin/sh\nalice:x:1000:1000::/h:/bin/sh\n".to_vec();
    facts.group = b"docker:x:999:\nagent:x:999:\n".to_vec();
    assert!(matches!(
        refusal(&request(), &facts),
        Refusal::RootGroup { .. }
    ));
    // A root-equivalent group the account is not in stays harmless.
    facts.group = b"docker:x:50:\n".to_vec();
    plan(&request(), &facts).unwrap();
}

#[test]
fn enrol_refuses_a_sudo_rule_that_asks_for_a_password() {
    for sudoers in [
        &b"Defaults:agent rootpw\nagent ALL=(ALL) ALL\n"[..],
        b"#990 ALL=(ALL) ALL\n",
        b"User_Alias A = alice, agent\nA ALL=(ALL) ALL\n",
        b"ALL ALL=(ALL) ALL\n",
        b"@include /etc/elsewhere\n",
        b"#include /etc/elsewhere\n",
        b"@includedir /etc/other.d\n",
        b"#includedir /etc/sudoers.d/extra\n",
    ] {
        let host = host_with(GROUP, sudoers);
        let why = denied(&host);
        assert!(why.contains("/etc/sudoers line"), "{sudoers:?}: {why}");
    }
}

#[test]
fn enrol_refuses_a_rule_in_a_drop_in_or_in_doas() {
    let host = host_with(GROUP, b"")
        .dir("/etc/sudoers.d", 0, 0, 0o755)
        .file(
            "/etc/sudoers.d/90-agent",
            0,
            0,
            0o440,
            b"agent ALL=(ALL) ALL\n",
        );
    assert!(denied(&host).contains("/etc/sudoers.d/90-agent line 1"));
    let host = host_with(GROUP, b"").file("/etc/doas.conf", 0, 0, 0o644, b"# c\npermit agent\n");
    assert!(denied(&host).contains("/etc/doas.conf line 2"));
    let host = host_with(GROUP, b"").dir("/etc/doas.d", 0, 0, 0o755).file(
        "/etc/doas.d/a.conf",
        0,
        0,
        0o644,
        b"permit persist agent as root\n",
    );
    assert!(denied(&host).contains("/etc/doas.d/a.conf line 1"));
}

#[test]
fn a_rule_naming_someone_else_or_a_comment_is_not_the_accounts() {
    let host = host_with(
        GROUP,
        b"# agent was here\nalice ALL=(ALL) ALL\n%xudoers ALL=(ALL) ALL\nDefaults env_reset\nagentx ALL=(ALL) ALL\n",
    );
    let (scan, planned) = through(&host);
    assert_eq!(scan.blockers, Vec::<String>::new());
    planned.unwrap();
}

#[test]
fn enrol_refuses_rule_files_it_cannot_read() {
    let host = host_with(GROUP, b"").unreadable_file("/etc/doas.conf", 0, 0, 0o600);
    assert!(denied(&host).contains("could not examine /etc/doas.conf"));
    let host = host_with(GROUP, b"").unlistable_dir("/etc/sudoers.d", 0, 0, 0o755);
    assert!(denied(&host).contains("could not examine /etc/sudoers.d"));
}

#[test]
fn enrol_refuses_an_account_that_can_write_a_unit_directory() {
    let host = host_with(GROUP, b"").dir("/etc/systemd", 0, 0, 0o755).dir(
        "/etc/systemd/system",
        990,
        990,
        0o755,
    );
    assert!(denied(&host).contains("Writable"));
    // Through a group it holds.
    let group = format!("{GROUP}ops:x:2000:agent\n");
    let host = host_with(&group, b"").dir("/etc/systemd", 0, 0, 0o755).dir(
        "/etc/systemd/system",
        0,
        2000,
        0o775,
    );
    assert!(denied(&host).contains("Writable"));
}

#[test]
fn a_unit_directory_that_only_others_can_write_is_not_the_accounts() {
    let host = host_with(GROUP, b"").dir("/etc/systemd", 0, 0, 0o755).dir(
        "/etc/systemd/system",
        1000,
        1000,
        0o755,
    );
    assert_eq!(through(&host).0.blockers, Vec::<String>::new());
    let host = host_with(GROUP, b"").dir("/etc/systemd", 0, 0, 0o755).dir(
        "/etc/systemd/system",
        0,
        1000,
        0o775,
    );
    assert_eq!(through(&host).0.blockers, Vec::<String>::new());
}

#[test]
fn enrol_refuses_when_the_group_file_cannot_be_read() {
    let host = host_with(GROUP, b"").unreadable_file("/etc/group", 0, 0, 0o600);
    assert!(denied(&host).contains("could not examine /etc/group"));
}

#[test]
fn enrol_refuses_a_world_writable_unit_directory() {
    let host = host_with(GROUP, b"").dir("/etc/systemd", 0, 0, 0o755).dir(
        "/etc/systemd/system",
        0,
        0,
        0o777,
    );
    assert!(denied(&host).contains("Everyone"));
}

// ---- H2d: the agent groups, the managed snippet, the standing re-check ----

use crate::capability::{Capability, CapabilityMatrix};
use crate::{Backend, BackendKind};

fn sudo_backend() -> Backend {
    Backend {
        exe: "/usr/bin/sudo".to_owned(),
        kind: BackendKind::Sudo,
        version: "Sudo version 1.9.17p2".to_owned(),
        capabilities: CapabilityMatrix::from_supported([
            Capability::DisableCredentialCache,
            Capability::AllocatePty,
            Capability::PerCommandDefaults,
            Capability::DropInDirectory,
            Capability::ValidateNamedFile,
        ]),
    }
}

/// The text enrol exempts: what xudo itself would write for the agent path.
fn managed() -> String {
    managed_snippet(Some(&sudo_backend())).unwrap()
}

/// The account is already in both agent groups, as it is once enrolled.
const ENROLLED_GROUP: &str =
    "root:x:0:\nagent:x:990:\nalice:x:1000:\nxudo:x:998:agent\nxudo-agent:x:997:agent\n";

fn sudoers_host(group: &str, xudo_snippet: Option<&str>) -> MemoryHost {
    let host = host_with(
        group,
        b"root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
    )
    .dir("/etc/sudoers.d", 0, 0, 0o755);
    match xudo_snippet {
        Some(text) => host.file("/etc/sudoers.d/xudo", 0, 0, 0o440, text.as_bytes()),
        None => host,
    }
}

fn blockers(host: &MemoryHost, managed: Option<&str>) -> Vec<String> {
    scan_account(host, "agent", &Input::default(), managed)
        .unwrap()
        .blockers
}

#[test]
fn enrol_exempts_only_the_byte_exact_managed_snippet() {
    let text = managed();
    assert!(
        text.contains("NOPASSWD"),
        "the snippet under test has the line"
    );
    let exact = sudoers_host(ENROLLED_GROUP, Some(&text));
    assert_eq!(blockers(&exact, Some(&text)), Vec::<String>::new());

    // One byte more or less, and nothing is exempt.
    for altered in [
        format!("{text}\n"),
        text.replacen("root", "ro0t", 1),
        text.trim_end().to_owned(),
    ] {
        let host = sudoers_host(ENROLLED_GROUP, Some(&altered));
        let found = blockers(&host, Some(&text));
        assert!(
            found.iter().any(|line| line.contains("NOPASSWD")),
            "an altered snippet was exempted: {found:?}"
        );
    }
    // No expected text (a doas machine, no backend): the same exact bytes are a blocker.
    assert!(!blockers(&exact, None).is_empty());
    // The file is absent: there is nothing to exempt, and nothing found.
    let absent = sudoers_host(ENROLLED_GROUP, None);
    assert_eq!(blockers(&absent, Some(&text)), Vec::<String>::new());
    // The plan goes through on the exempt host, and the same host is refused
    // once the file is altered.
    let mut facts = facts();
    facts.group = ENROLLED_GROUP.as_bytes().to_vec();
    facts.scan = scan_account(&exact, "agent", &Input::default(), Some(&text)).unwrap();
    plan(&request(), &facts).unwrap();
}

#[test]
fn a_hand_written_xudo_agent_line_blocks_enrol() {
    let text = managed();
    let hand_written = [
        // Asks for a password, so only a name match can find it.
        "%xudo-agent ALL=(ALL) ALL\n",
        "%xudo-agent ALL=(root) NOPASSWD: ALL\n",
        // By gid.
        "%#997 ALL=(ALL) ALL\n",
        // The passwordless helper by its path, under any user.
        "Cmnd_Alias G = /usr/libexec/xudo/xudo-gate-nopass \"\"\nalice ALL=(root) G\n",
        // The account by name and by uid.
        "agent ALL=(ALL) ALL\n",
        "#990 ALL=(ALL) ALL\n",
    ];
    for line in hand_written {
        // In a file beside the exempt snippet, in the drop-in directory...
        let host = sudoers_host(ENROLLED_GROUP, Some(&text)).file(
            "/etc/sudoers.d/90-local",
            0,
            0,
            0o440,
            line.as_bytes(),
        );
        let found = blockers(&host, Some(&text));
        assert!(
            found.iter().any(|b| b.contains("/etc/sudoers.d/90-local")),
            "{line:?} was not a blocker: {found:?}"
        );
        // ... and with no managed snippet at all.
        let host = sudoers_host(ENROLLED_GROUP, None).file(
            "/etc/sudoers.d/90-local",
            0,
            0,
            0o440,
            line.as_bytes(),
        );
        assert!(!blockers(&host, Some(&text)).is_empty(), "{line:?}");
    }
    // Appended to /etc/sudoers itself.
    let host = host_with(
        ENROLLED_GROUP,
        b"root ALL=(ALL:ALL) ALL\n%xudo-agent ALL=(ALL) ALL\n",
    );
    assert!(!blockers(&host, Some(&text)).is_empty());
    // The refusal reaches the plan.
    let mut facts = facts();
    facts.scan = scan_account(&host, "agent", &Input::default(), Some(&text)).unwrap();
    assert!(matches!(
        refusal(&request(), &facts),
        Refusal::OtherPathToRoot { .. }
    ));
}

#[test]
fn a_line_naming_the_group_is_not_found_by_a_substring_of_another_name() {
    // `%xudo-agents` is some other group's line.
    let host = sudoers_host(ENROLLED_GROUP, None).file(
        "/etc/sudoers.d/90-local",
        0,
        0,
        0o440,
        b"%xudo-agents ALL=(ALL) ALL\n",
    );
    // The whole word is compared: another group's name is not the agent group's.
    assert_eq!(blockers(&host, None), Vec::<String>::new());
}

#[test]
fn the_backend_listing_of_the_managed_helper_is_exempt_for_the_account_only() {
    let text = managed();
    let listing = "(root) NOPASSWD: /usr/libexec/xudo/xudo-gate-nopass \"\"";
    let sudo = Input {
        sudo_exe: Some("/usr/bin/sudo"),
        ..Input::default()
    };
    let group =
        "root:x:0:\nagent:x:990:\nalice:x:1000:\nxudo:x:998:agent,alice\nxudo-agent:x:997:agent\n";
    let run = |user_listing: &[(&str, &str)], managed: Option<&str>| {
        let mut host = sudoers_host(group, Some(&text));
        for (user, listing) in user_listing {
            host = host.sudo_says(user, Answer::Passwordless((*listing).to_owned()));
        }
        scan_account(&host, "agent", &sudo, managed)
            .unwrap()
            .blockers
    };
    // The account's own listing is the helper and nothing else.
    assert_eq!(
        run(&[("agent", listing)], Some(&text)),
        Vec::<String>::new()
    );
    // Anything more in the listing, a blocker.
    let more = format!("{listing}\n(root) NOPASSWD: /bin/sh");
    assert!(!run(&[("agent", &more)], Some(&text)).is_empty());
    assert!(!run(&[("agent", "(ALL) NOPASSWD: ALL")], Some(&text)).is_empty());
    // A human who joined the agent group is not the account: not exempt.
    // The scan asks about the account alone; if a listing for someone else
    // ever reached the filter, it would not be exempt.
    let someone_else = Finding::BackendListing {
        user: "alice".to_owned(),
        listing: listing.to_owned(),
    };
    assert!(!is_managed(&someone_else, "agent", true));
    assert!(is_managed(
        &Finding::BackendListing {
            user: "agent".to_owned(),
            listing: listing.to_owned()
        },
        "agent",
        true
    ));
    // An empty listing is not "only the helper".
    assert!(!is_managed(
        &Finding::BackendListing {
            user: "agent".to_owned(),
            listing: String::new()
        },
        "agent",
        true
    ));
    // Not exempt when the file is not the managed one.
    assert!(!run(&[("agent", listing)], None).is_empty());
}

#[test]
fn the_agent_path_refuses_doas() {
    // Plan level: a doas machine enrols nothing.
    let mut facts = facts();
    facts.scan.doas = true;
    assert_eq!(refusal(&request(), &facts), Refusal::AgentPathNeedsSudo);
    let message = Refusal::AgentPathNeedsSudo.to_string();
    assert!(message.contains("sudo or sudo-rs only") && message.contains("doas"));
    // Scan level: the flag comes from the identified escalator.
    let host = sudoers_host(GROUP, None);
    let doas = Input {
        doas_exe: Some("/usr/bin/doas"),
        ..Input::default()
    };
    assert!(scan_account(&host, "agent", &doas, None).unwrap().doas);
    assert!(
        !scan_account(&host, "agent", &Input::default(), None)
            .unwrap()
            .doas
    );
    // There is no passwordless snippet for doas to exempt.
    let doas_backend = Backend {
        kind: BackendKind::Doas,
        ..sudo_backend()
    };
    assert_eq!(managed_snippet(Some(&doas_backend)), None);
    assert_eq!(managed_snippet(None), None);
}

#[test]
fn enrol_joins_both_agent_groups_and_records_what_it_added() {
    // `xudo` exists with the account in it; `xudo-agent` does not exist.
    let planned = plan(&request(), &facts()).unwrap();
    assert_eq!(
        planned.memberships,
        vec![
            Membership {
                group: "xudo".to_owned(),
                create: false,
                join: false
            },
            Membership {
                group: "xudo-agent".to_owned(),
                create: true,
                join: true
            },
        ]
    );
    // Only the group this run added is recorded as its own.
    assert_eq!(
        joined_groups(&planned.registry.contents),
        vec!["xudo-agent".to_owned()]
    );
    assert!(
        planned
            .render()
            .contains("group xudo-agent: create the group, then add agent")
    );
    assert!(planned.render().contains("group xudo: already a member"));

    // Neither exists, and the account is in neither: both are added.
    let mut bare = facts();
    bare.group = b"root:x:0:\nagent:x:990:\nalice:x:1000:\n".to_vec();
    let planned = plan(&request(), &bare).unwrap();
    assert!(planned.memberships.iter().all(|m| m.create && m.join));
    assert_eq!(
        joined_groups(&planned.registry.contents),
        vec!["xudo".to_owned(), "xudo-agent".to_owned()]
    );
    assert!(
        planned
            .render()
            .contains("group xudo: create the group, then add agent")
    );

    // Existing groups, the account in neither: a member is added, never a redefinition.
    let mut existing = facts();
    existing.group =
        b"root:x:0:\nagent:x:990:\nalice:x:1000:\nxudo:x:998:alice\nxudo-agent:x:997:\n".to_vec();
    let planned = plan(&request(), &existing).unwrap();
    assert!(planned.memberships.iter().all(|m| !m.create && m.join));
    assert!(planned.render().contains("group xudo: add agent"));
    // Already in both: nothing is recorded, so `remove` takes nothing out.
    let mut both = facts();
    both.group = ENROLLED_GROUP.as_bytes().to_vec();
    let planned = plan(&request(), &both).unwrap();
    assert!(planned.memberships.iter().all(|m| !m.create && !m.join));
    assert!(!planned.registry.contents.contains(JOINED_MARKER));
    // The registry still loads with the comment in it.
    check_loads(&plan(&request(), &existing).unwrap(), &existing).unwrap();
}

#[test]
fn an_account_whose_primary_group_is_an_agent_group_is_already_a_member() {
    let mut facts = facts();
    facts.passwd = b"root:x:0:0::/root:/bin/sh\nagent:x:997:997::/h:/sbin/nologin\nalice:x:1000:1000::/h:/bin/sh\n".to_vec();
    facts.scan.uid = 997;
    facts.shadow = Some(b"agent:!:1::::::\n".to_vec());
    facts.group = b"root:x:0:\nagent:x:996:\nxudo:x:998:\nxudo-agent:x:997:\n".to_vec();
    let planned = plan(&request(), &facts).unwrap();
    let agent = planned
        .memberships
        .iter()
        .find(|m| m.group == "xudo-agent")
        .unwrap();
    assert!(!agent.join);
    assert!(is_member(
        &facts.passwd,
        &facts.group,
        "agent",
        "xudo-agent"
    ));
    assert!(!is_member(&facts.passwd, &facts.group, "agent", "xudo"));
    assert!(!is_member(
        &facts.passwd,
        &facts.group,
        "ghost",
        "xudo-agent"
    ));
    // A malformed group line is no group.
    assert!(!is_member(&facts.passwd, b"xudo", "agent", "xudo"));
}

#[test]
fn enrol_refuses_an_agent_group_that_shares_a_privileged_gid() {
    for (group, alias) in [
        ("xudo-agent:x:999:\ndocker:x:999:\n", "docker"),
        ("xudo:x:27:\nsudo:x:27:\n", "sudo"),
        ("xudo-agent:x:0:\n", "root"),
    ] {
        let mut facts = facts();
        facts.group =
            format!("garbage\nroot:x:0:\nagent:x:990:\nalice:x:1000:\n{group}").into_bytes();
        let refusal = refusal(&request(), &facts);
        assert!(
            matches!(&refusal, Refusal::AgentGroupIsRoot { alias: a, .. } if a == alias),
            "{group:?} gave {refusal:?}"
        );
        assert!(refusal.to_string().contains("joining"));
    }
}

#[test]
fn joined_groups_reads_only_the_agent_groups_from_a_root_written_comment() {
    let text =
        format!("{MANAGED_MARKER}\n{JOINED_MARKER} xudo docker xudo-agent root\nlabel = \"x\"\n");
    assert_eq!(
        joined_groups(&text),
        vec!["xudo".to_owned(), "xudo-agent".to_owned()]
    );
    assert_eq!(joined_groups("label = \"x\"\n"), Vec::<String>::new());
}

// ---- the standing re-check, for `doctor` ----

const REGISTRY_TEXT: &str = "# Managed by xudo.\nlabel = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n";
const DROP_IN_TEXT: &str =
    "# Managed by xudo.\n[Service]\nUser=agent\nExecStart=\"/usr/bin/codex\"\n";

fn enrolled_host(group: &str, shadow: Option<&str>) -> MemoryHost {
    sudoers_host(group, Some(&managed()))
        .file(
            "/etc/shadow",
            0,
            0,
            0o640,
            shadow.unwrap_or("agent:!:1::::::\n").as_bytes(),
        )
        .dir("/etc/xudo", 0, 0, 0o755)
        .dir("/etc/xudo/harnesses.d", 0, 0, 0o755)
        .file(
            "/etc/xudo/harnesses.d/codex.toml",
            0,
            0,
            0o644,
            REGISTRY_TEXT.as_bytes(),
        )
        .dir("/etc/systemd", 0, 0, 0o755)
        .dir("/etc/systemd/system", 0, 0, 0o755)
        .dir(
            "/etc/systemd/system/xudo-agent@codex.service.d",
            0,
            0,
            0o755,
        )
        .file(
            "/etc/systemd/system/xudo-agent@codex.service.d/10-xudo.conf",
            0,
            0,
            0o644,
            DROP_IN_TEXT.as_bytes(),
        )
}

fn recheck(host: &MemoryHost) -> Vec<AccountReport> {
    let text = managed();
    recheck_accounts(host, &Input::default(), Some(&text)).unwrap()
}

#[test]
fn recheck_finds_an_enrolled_account_clean_and_reports_nothing_for_an_empty_registry() {
    let rows = recheck(&enrolled_host(ENROLLED_GROUP, None));
    assert_eq!(
        rows,
        vec![AccountReport {
            label: "codex".to_owned(),
            account: "agent".to_owned(),
            problems: Vec::new(),
            unverified: Vec::new(),
        }]
    );
    let none = sudoers_host(GROUP, None);
    assert_eq!(recheck(&none), Vec::new());
}

#[test]
fn recheck_reports_each_way_an_enrolled_account_can_gain_root() {
    let text = managed();
    let problems = |host: &MemoryHost| recheck(host).remove(0).problems.join(" | ");
    // A sudoers line of its own.
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        "/etc/sudoers.d/90-agent",
        0,
        0,
        0o440,
        b"agent ALL=(ALL) NOPASSWD: ALL\n",
    );
    assert!(problems(&host).contains("/etc/sudoers.d/90-agent"));
    // The managed snippet altered by a byte.
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        "/etc/sudoers.d/xudo",
        0,
        0,
        0o440,
        format!("{text}\n").as_bytes(),
    );
    assert!(problems(&host).contains("NOPASSWD"));
    // A root-equivalent group.
    let host = enrolled_host(&format!("{ENROLLED_GROUP}docker:x:999:agent\n"), None);
    assert!(problems(&host).contains("docker"));
    // A password.
    let host = enrolled_host(ENROLLED_GROUP, Some("agent:$6$abc:1::::::\n"));
    assert!(problems(&host).contains("usable password"));
    // Uid 0 behind the same name.
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        "/etc/passwd",
        0,
        0,
        0o644,
        b"agent:x:0:0::/root:/bin/sh\n",
    );
    assert!(problems(&host).contains("is root"));
    // The account vanished from passwd.
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        "/etc/passwd",
        0,
        0,
        0o644,
        b"root:x:0:0::/r:/bin/sh\n",
    );
    assert!(problems(&host).contains("not in /etc/passwd"));
}

#[test]
fn recheck_reports_a_drop_in_that_could_change_who_the_unit_runs_as() {
    let problems = |host: &MemoryHost| recheck(host).remove(0).problems.join(" | ");
    let dir = "/etc/systemd/system/xudo-agent@codex.service.d";
    // A second file.
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        &format!("{dir}/20-user.conf"),
        0,
        0,
        0o644,
        b"[Service]\nUser=root\n",
    );
    assert!(problems(&host).contains("holds more than 10-xudo.conf"));
    // Our file, with another User=.
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        &format!("{dir}/10-xudo.conf"),
        0,
        0,
        0o644,
        b"[Service]\nUser=agent\nUser=root\n",
    );
    assert!(problems(&host).contains("does not run the unit as agent alone"));
    // Not text at all.
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        &format!("{dir}/10-xudo.conf"),
        0,
        0,
        0o644,
        &[0xff, 0xfe],
    );
    assert!(problems(&host).contains("does not run the unit as agent alone"));
    // Not root's alone.
    let host = enrolled_host(ENROLLED_GROUP, None).dir(dir, 990, 990, 0o755);
    assert!(problems(&host).contains("is not root's alone"));
    // Gone.
    let host = enrolled_host(ENROLLED_GROUP, None);
    let missing = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, PASSWD.as_bytes())
    .file("/etc/group", 0, 0, 0o644, ENROLLED_GROUP.as_bytes())
    .file("/etc/shadow", 0, 0, 0o640, SHADOW.as_bytes())
    .dir("/etc/xudo", 0, 0, 0o755)
    .dir("/etc/xudo/harnesses.d", 0, 0, 0o755)
    .file(
        "/etc/xudo/harnesses.d/codex.toml",
        0,
        0,
        0o644,
        REGISTRY_TEXT.as_bytes(),
    );
    let _ = host;
    assert!(problems(&missing).contains("does not exist"));
}

#[test]
fn recheck_says_so_when_the_shadow_file_or_the_registry_cannot_be_read() {
    // Not root: shadow is not readable, and that is "unverified", not "gained root".
    let host = enrolled_host(ENROLLED_GROUP, None).unreadable_file("/etc/shadow", 0, 0, 0o640);
    let row = recheck(&host).remove(0);
    assert!(row.problems.is_empty(), "{:?}", row.problems);
    assert!(row.unverified.iter().any(|gap| gap.contains("/etc/shadow")));
    let text = managed();
    // An unreadable registry directory, file, or one that is not text or does not load.
    let unreadable =
        enrolled_host(ENROLLED_GROUP, None).unlistable_dir("/etc/xudo/harnesses.d", 0, 0, 0o755);
    assert!(
        recheck_accounts(&unreadable, &Input::default(), Some(&text))
            .unwrap_err()
            .contains("cannot be read")
    );
    let file = enrolled_host(ENROLLED_GROUP, None).unreadable_file(
        "/etc/xudo/harnesses.d/codex.toml",
        0,
        0,
        0o644,
    );
    assert!(
        recheck_accounts(&file, &Input::default(), Some(&text))
            .unwrap_err()
            .contains("codex.toml cannot be read")
    );
    let binary = enrolled_host(ENROLLED_GROUP, None).file(
        "/etc/xudo/harnesses.d/codex.toml",
        0,
        0,
        0o644,
        &[0xff],
    );
    assert!(
        recheck_accounts(&binary, &Input::default(), Some(&text))
            .unwrap_err()
            .contains("not UTF-8")
    );
    let broken = enrolled_host(ENROLLED_GROUP, None).file(
        "/etc/xudo/harnesses.d/codex.toml",
        0,
        0,
        0o644,
        b"nope = 1\n",
    );
    assert!(recheck_accounts(&broken, &Input::default(), Some(&text)).is_err());
    // A file that is not a registry file is skipped.
    let other =
        enrolled_host(ENROLLED_GROUP, None).file("/etc/xudo/harnesses.d/README", 0, 0, 0o644, b"x");
    assert_eq!(recheck(&other).len(), 1);
}

#[test]
fn recheck_flags_a_doas_machine_for_an_enrolled_account() {
    let doas = Input {
        doas_exe: Some("/usr/bin/doas"),
        ..Input::default()
    };
    let rows = recheck_accounts(&enrolled_host(ENROLLED_GROUP, None), &doas, None).unwrap();
    assert!(rows[0].problems.iter().any(|p| p.contains("doas")));
}

#[test]
fn recheck_reports_a_drop_in_directory_it_cannot_examine() {
    let host = enrolled_host(ENROLLED_GROUP, None).fault(
        "/etc/systemd/system/xudo-agent@codex.service.d",
        "permission denied",
    );
    let problems = recheck(&host).remove(0).problems.join(" | ");
    assert!(problems.contains("could not examine"), "{problems}");
    assert!(problems.contains("permission denied"), "{problems}");
}

#[test]
fn recheck_skips_a_registry_name_that_vanished_between_the_listing_and_the_read() {
    // A dangling link lists, and reads as missing.
    let host = enrolled_host(ENROLLED_GROUP, None)
        .link("/etc/xudo/harnesses.d/gone.toml", "/etc/xudo/nowhere");
    assert_eq!(recheck(&host).len(), 1);
}

#[test]
fn enrol_refuses_an_agent_group_with_gid_zero_even_with_no_root_group_line() {
    let mut facts = facts();
    facts.group = b"agent:x:990:\nxudo-agent:x:0:\n".to_vec();
    assert!(matches!(
        refusal(&request(), &facts),
        Refusal::AgentGroupIsRoot { gid: 0, .. }
    ));
}

// ---- H2d review: the account is judged as the agent it is about to be ----

/// Neither agent group lists the account yet: it is not a member of either.
const NOT_YET: &str = "root:x:0:\nagent:x:990:\nalice:x:1000:\nxudo:x:998:\nxudo-agent:x:997:\n";

fn not_yet_host(extra: &str) -> MemoryHost {
    sudoers_host(NOT_YET, None).file("/etc/sudoers.d/90-local", 0, 0, 0o440, extra.as_bytes())
}

#[test]
fn denies_enrol_when_a_rule_for_group_xudo_would_hand_the_agent_root() {
    let blocked = blockers(&not_yet_host("%xudo ALL=(ALL) NOPASSWD: ALL\n"), None);
    assert!(
        blocked.iter().any(|line| line.contains("90-local line 1")),
        "{blocked:?}"
    );
}

#[test]
fn denies_enrol_when_a_rule_names_the_xudo_gid_the_agent_will_hold() {
    for rule in [
        "%#998 ALL=(ALL) NOPASSWD: ALL\n",
        "%#997 ALL=(ALL) NOPASSWD: ALL\n",
    ] {
        let blocked = blockers(&not_yet_host(rule), None);
        assert!(!blocked.is_empty(), "{rule}: {blocked:?}");
    }
    // The whole gid, not a prefix of a longer one.
    let other = blockers(&not_yet_host("%#9981 ALL=(ALL) NOPASSWD: ALL\n"), None);
    assert_eq!(other, Vec::<String>::new());
}

#[test]
fn denies_enrol_when_a_root_trusted_directory_is_writable_by_the_group_the_agent_will_join() {
    // The unit directory is writable by group `xudo` (gid 998), which lists
    // nobody yet; the agent holds it the moment enrol adds it.
    for gid in [998, 997] {
        let host = host_with(
            NOT_YET,
            b"root ALL=(ALL:ALL) ALL
",
        )
        .dir("/etc/systemd", 0, 0, 0o755)
        .dir("/etc/systemd/system", 0, gid, 0o775);
        let blocked = blockers(&host, None);
        assert!(
            blocked.iter().any(|line| line.contains("Writable")),
            "gid {gid}: {blocked:?}"
        );
    }
    // A group the account never joins is still not its own.
    let other = "root:x:0:\nagent:x:990:\nxudo:x:998:\nxudo-agent:x:997:\nops:x:2000:\n";
    let host = host_with(other, b"root ALL=(ALL:ALL) ALL\n")
        .dir("/etc/systemd", 0, 0, 0o755)
        .dir("/etc/systemd/system", 0, 2000, 0o775);
    assert_eq!(blockers(&host, None), Vec::<String>::new());
}

#[test]
fn denies_enrol_for_a_user_alias_that_expands_to_the_agent_groups() {
    let blocked = blockers(
        &not_yet_host("User_Alias A = %xudo\nA ALL=(ALL) NOPASSWD: ALL\n"),
        None,
    );
    assert!(!blocked.is_empty(), "{blocked:?}");
}

#[test]
fn enrol_exempts_the_shipped_human_only_snippet_and_nothing_else() {
    let agent_text = managed();
    let human_text = crate::snippet::SudoersSnippet::human_only(&sudo_backend())
        .unwrap()
        .contents;
    // The derivation the scan uses is the shipped text, byte for byte.
    assert_eq!(crate::snippet::human_only_form(&agent_text), human_text);
    assert!(human_text.contains("%xudo ALL=(root) PASSWD"));
    let shipped = sudoers_host(NOT_YET, Some(&human_text));
    assert_eq!(blockers(&shipped, Some(&agent_text)), Vec::<String>::new());
    // One byte more, and the `%xudo` line is a blocker again.
    let altered = sudoers_host(NOT_YET, Some(&format!("{human_text}\n")));
    assert!(!blockers(&altered, Some(&agent_text)).is_empty());
}

#[test]
fn enrol_trusts_the_managed_file_only_when_it_is_root_s_regular_file() {
    let text = managed();
    let base =
        || host_with(NOT_YET, b"root ALL=(ALL:ALL) ALL\n").dir("/etc/sudoers.d", 0, 0, 0o755);
    let good = base().file("/etc/sudoers.d/xudo", 0, 0, 0o440, text.as_bytes());
    assert_eq!(blockers(&good, Some(&text)), Vec::<String>::new());
    for (uid, mode) in [(1000, 0o440), (0, 0o464), (0, 0o442)] {
        let host = base().file("/etc/sudoers.d/xudo", uid, 0, mode, text.as_bytes());
        assert!(
            !blockers(&host, Some(&text)).is_empty(),
            "uid {uid} mode {mode:o}"
        );
    }
    let link = base()
        .file("/elsewhere", 0, 0, 0o440, text.as_bytes())
        .link("/etc/sudoers.d/xudo", "/elsewhere");
    assert!(!blockers(&link, Some(&text)).is_empty());
}

// ---- PAM: the agent will be in `xudo`, so it can reach the password gate ----

fn pam_host(sudo: &str, common_auth: Option<&str>) -> MemoryHost {
    let host = sudoers_host(NOT_YET, None).file("/etc/pam.d/sudo", 0, 0, 0o644, sudo.as_bytes());
    match common_auth {
        Some(text) => host.file("/etc/pam.d/common-auth", 0, 0, 0o644, text.as_bytes()),
        None => host,
    }
}

#[test]
fn denies_enrol_when_pam_can_pass_sudo_without_the_password() {
    for line in [
        "auth sufficient pam_ssh_agent_auth.so file=%h/.ssh/authorized_keys",
        "auth sufficient /lib/security/pam_u2f.so",
        "auth required pam_u2f.so",
        "auth sufficient pam_rhosts.so",
        "auth sufficient pam_permit.so",
        "auth [success=done default=ignore] pam_permit.so",
        "auth sufficient pam_succeed_if.so user = agent",
        "auth sufficient pam_exec.so /usr/bin/true",
        "-auth [success=2 default=ignore] pam_listfile.so item=user sense=allow file=/etc/ok onerr=fail",
        "auth [success=1 default=ignore] pam_ssh_agent_auth.so file=%h/.ssh/authorized_keys",
        "auth [success=1 default=ignore] pam_u2f.so",
        "auth [success=1 default=ignore] pam_permit.so",
        "auth [default=ignore success=done] pam_rssh.so",
        "auth [success=2 default=ignore] pam_rssh.so",
        "auth [default=ignore\tsuccess=1]\tpam_rssh.so",
        "auth sufficient pam_sss.so",
        "auth [success=ok default=ignore] pam_krb5.so",
    ] {
        let sudo = format!("#%PAM-1.0\n{line}\n@include common-auth\n");
        let blocked = blockers(&pam_host(&sudo, Some(DEBIAN_COMMON_AUTH)), None);
        assert!(
            blocked
                .iter()
                .any(|found| found.contains("/etc/pam.d/sudo line 2")),
            "{line}: {blocked:?}"
        );
    }
}

#[test]
fn denies_a_bracket_control_that_skips_the_deny_line() {
    // The `pam-auth-update` shape: the success jumps over `pam_deny`.
    for module in [
        "pam_ssh_agent_auth.so file=%h/.ssh/authorized_keys",
        "pam_u2f.so",
        "pam_permit.so",
    ] {
        let sudo = format!(
            "auth [success=1 default=ignore] {module}\nauth requisite pam_deny.so\nauth required pam_permit.so\n"
        );
        let blocked = blockers(&pam_host(&sudo, None), None);
        assert!(
            blocked.iter().any(|found| found.contains("line 1")),
            "{module}: {blocked:?}"
        );
    }
}

#[test]
fn allows_stock_pam_stacks_that_only_check_a_password() {
    // Debian's `[success=1 default=ignore] pam_unix`, and RHEL's
    // `requisite pam_succeed_if` in system-auth: neither passes anyone.
    for line in [
        "auth [success=1 default=ignore] pam_unix.so nullok",
        "auth requisite pam_succeed_if.so uid >= 1000 quiet_success",
        "auth required pam_exec.so /usr/bin/true",
        "auth required pam_listfile.so item=user sense=deny file=/etc/no onerr=succeed",
        "auth [default=die] pam_succeed_if.so uid >= 1000",
    ] {
        let sudo = format!("auth include common-auth\n{line}\n");
        let blocked = blockers(&pam_host(&sudo, Some(DEBIAN_COMMON_AUTH)), None);
        assert_eq!(blocked, Vec::<String>::new(), "{line}");
    }
}

#[test]
fn refuses_an_auth_line_too_short_to_name_a_module() {
    // libpam rejects the line; xudo cannot tell what the stack then does.
    for line in [
        "auth",
        "auth required",
        "auth [success=1 default=ignore]",
        "auth [success=1",
    ] {
        let sudo = format!("{line}\n");
        let blocked = blockers(&pam_host(&sudo, None), None);
        assert!(
            blocked.iter().any(|found| found.contains("cannot be read")),
            "{line}: {blocked:?}"
        );
    }
    // Blank lines, comments and other types are not auth lines.
    let sudo = "\n# auth\nsession\naccount required pam_permit.so\n";
    assert_eq!(blockers(&pam_host(sudo, None), None), Vec::<String>::new());
}

#[test]
fn denies_pam_shapes_that_libpam_passes_without_a_password() {
    // Each was run through real libpam with no password and passed.
    let probes = [
        // a bracket ends at `]`: no space before the module
        "auth [success=1 default=ignore]pam_permit.so\nauth requisite pam_deny.so\n",
        // a pass falls to `default`
        "auth [default=1] pam_permit.so\nauth requisite pam_deny.so\n",
        "auth [default=1] pam_exec.so /bin/true\n",
        "auth [default=ok] pam_exec.so /bin/true\n",
        "auth [default=done] pam_exec.so /bin/true\n",
        // the words are case-insensitive
        "AUTH sufficient pam_permit.so\n",
        "auth Sufficient pam_permit.so\n",
        "auth [SUCCESS=1 default=ignore] pam_permit.so\n",
        // a trailing backslash joins the next line
        "auth \\\nsufficient pam_permit.so\n",
        "auth sufficient \\\npam_permit.so\n",
        // pam_permit with no `requisite pam_deny` before it
        "auth required pam_permit.so\n",
        "auth required pam_permit.so\nauth requisite pam_deny.so\n",
    ];
    for sudo in probes {
        let blocked = blockers(&pam_host(sudo, None), None);
        assert!(!blocked.is_empty(), "{sudo:?}: {blocked:?}");
    }
    // The joined line is reported at the line it starts on.
    let blocked = blockers(
        &pam_host("#x\nauth \\\nsufficient pam_permit.so\n", None),
        None,
    );
    assert!(
        blocked.iter().any(|line| line.contains("sudo line 2")),
        "{blocked:?}"
    );
    // A comment ending in a backslash does not swallow the next line.
    let blocked = blockers(
        &pam_host("# note \\\nauth sufficient pam_permit.so\n", None),
        None,
    );
    assert!(
        blocked.iter().any(|line| line.contains("sudo line 2")),
        "{blocked:?}"
    );
}

#[test]
fn denies_a_pam_include_spelled_in_another_case() {
    let sudo = "auth Include common-auth\nAuth SUBSTACK common-auth\n";
    let blocked = blockers(&pam_host(sudo, Some("auth sufficient pam_u2f.so\n")), None);
    assert!(
        blocked
            .iter()
            .any(|line| line.contains("common-auth line 1")),
        "{blocked:?}"
    );
}

#[test]
fn allows_pam_permit_after_a_requisite_pam_deny() {
    let sudo = "auth [success=1 default=ignore] pam_unix.so\nauth requisite pam_deny.so\nauth required pam_permit.so\n";
    assert_eq!(blockers(&pam_host(sudo, None), None), Vec::<String>::new());
}

#[test]
fn reads_pam_other_when_the_service_has_no_auth_line() {
    // libpam answers for a service with no `auth` line from `other`.
    let host = pam_host("session required pam_env.so\n", None).file(
        "/etc/pam.d/other",
        0,
        0,
        0o644,
        b"auth sufficient pam_permit.so\n",
    );
    let blocked = blockers(&host, None);
    assert!(
        blocked
            .iter()
            .any(|line| line.contains("/etc/pam.d/other line 1")),
        "{blocked:?}"
    );
    // An unreadable `other` is a blocker; a stock one is not.
    let host = pam_host("auth required pam_unix.so\n", None).unreadable_file(
        "/etc/pam.d/other",
        0,
        0,
        0o600,
    );
    assert!(!blockers(&host, None).is_empty());
    let host = pam_host("auth required pam_unix.so\n", None).file(
        "/etc/pam.d/other",
        0,
        0,
        0o644,
        b"auth required pam_deny.so\n",
    );
    assert_eq!(blockers(&host, None), Vec::<String>::new());
}

#[test]
fn refuses_enrol_when_pam_includes_nest_too_deep_to_read() {
    let mut host = pam_host("auth include p0\n", None);
    for n in 0..12 {
        host = host.file(
            &format!("/etc/pam.d/p{n}"),
            0,
            0,
            0o644,
            format!("auth include p{}\n", n + 1).as_bytes(),
        );
    }
    assert!(
        blockers(&host, None)
            .iter()
            .any(|line| line.contains("nest deeper than 8"))
    );
}

#[test]
fn reads_the_sudo_i_pam_service_too() {
    let host = pam_host("auth include common-auth\n", Some(DEBIAN_COMMON_AUTH)).file(
        "/etc/pam.d/sudo-i",
        0,
        0,
        0o644,
        b"auth sufficient pam_u2f.so\n",
    );
    assert!(
        blockers(&host, None)
            .iter()
            .any(|line| line.contains("/etc/pam.d/sudo-i line 1"))
    );
}

#[test]
fn a_rule_naming_a_gid_enrol_has_yet_to_allocate_blocks() {
    // Neither group exists, so `groupadd --system` picks the gid a leftover
    // `%#996` already names.
    let none = "root:x:0:\nagent:x:990:\nalice:x:1000:\n";
    for rule in [
        "%#996 ALL=(ALL) NOPASSWD: ALL",
        "%996 ALL=(ALL) NOPASSWD: ALL",
        "%:#996 ALL=(ALL) NOPASSWD: ALL",
        "%:996 ALL=(ALL) NOPASSWD: ALL",
    ] {
        let host = sudoers_host(none, None).file(
            "/etc/sudoers.d/90-local",
            0,
            0,
            0o440,
            format!("{rule}\n").as_bytes(),
        );
        assert!(
            blockers(&host, None)
                .iter()
                .any(|line| line.contains("90-local line 1")),
            "{rule}"
        );
    }
    // Both groups allocated: a numeric group is judged by its gid.
    let host = not_yet_host("%#4242 ALL=(ALL) ALL\n");
    assert_eq!(blockers(&host, None), Vec::<String>::new());
}

#[test]
fn denies_enrol_when_an_included_pam_file_hides_the_module() {
    let sudo = "auth include common-auth\n@include common-account\n@include common-session-noninteractive\n";
    let bad = "auth sufficient pam_u2f.so\n";
    let blocked = blockers(&pam_host(sudo, Some(bad)), None);
    assert!(
        blocked
            .iter()
            .any(|line| line.contains("/etc/pam.d/common-auth line 1")),
        "{blocked:?}"
    );
    // By absolute path, and through `substack`; a loop ends.
    let sudo = "auth substack /etc/pam.d/common-auth\nauth include sudo\n";
    let blocked = blockers(&pam_host(sudo, Some(bad)), None);
    assert!(
        blocked
            .iter()
            .any(|line| line.contains("pam_u2f") && line.contains("common-auth")),
        "{blocked:?}"
    );
}

#[test]
fn enrol_refuses_when_sudos_pam_stack_cannot_be_read() {
    let missing = sudoers_host(NOT_YET, None).file("/etc/pam.d/sudo", 0, 0, 0o644, b"");
    assert_eq!(blockers(&missing, None), Vec::<String>::new());
    let host = host_with(NOT_YET, b"").unreadable_file("/etc/pam.d/sudo", 0, 0, 0o600);
    let blocked = blockers(&host, None);
    assert!(
        blocked.iter().any(|l| l.contains("/etc/pam.d/sudo")),
        "{blocked:?}"
    );
    let host = pam_host("@include nowhere\n", None);
    assert!(
        blockers(&host, None)
            .iter()
            .any(|l| l.contains("/etc/pam.d/nowhere: no such file"))
    );
    let binary = pam_host("", None).file("/etc/pam.d/sudo", 0, 0, 0o644, &[0xff, 0xfe]);
    assert!(
        blockers(&binary, None)
            .iter()
            .any(|l| l.contains("not text"))
    );
    // No PAM directory at all: nothing says how sudo authenticates.
    let bare = MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, PASSWD.as_bytes())
    .file("/etc/group", 0, 0, 0o644, NOT_YET.as_bytes());
    assert!(
        blockers(&bare, None)
            .iter()
            .any(|l| l.contains("/etc/pam.d/sudo: no such file"))
    );
}

#[test]
fn debian_s_own_pam_stack_does_not_block_enrol() {
    // `pam_permit` after a `requisite` `pam_deny`, `session` and `account`
    // lines, comments and a commented-out module are all fine.
    let sudo = "# auth sufficient pam_u2f.so\nsession sufficient pam_succeed_if.so quiet\naccount sufficient pam_permit.so\n@include common-auth\n";
    let common = "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\nauth required pam_permit.so\nauth sufficient pam_systemd_home.so\nauth sufficient pam_unix.so\n";
    assert_eq!(
        blockers(&pam_host(sudo, Some(common)), None),
        Vec::<String>::new()
    );
}

#[test]
fn recheck_reports_the_pam_stack_of_an_enrolled_account() {
    let host = enrolled_host(ENROLLED_GROUP, None).file(
        "/etc/pam.d/common-auth",
        0,
        0,
        0o644,
        b"auth sufficient pam_u2f.so\n",
    );
    assert!(
        recheck(&host)
            .remove(0)
            .problems
            .join(" | ")
            .contains("pam_u2f")
    );
}

// ---- the unit's user, as systemd reads the drop-in ----

#[test]
fn recheck_reads_user_the_way_systemd_does() {
    let drop_in = "/etc/systemd/system/xudo-agent@codex.service.d/10-xudo.conf";
    let problems = |body: &str| {
        let host = enrolled_host(ENROLLED_GROUP, None).file(drop_in, 0, 0, 0o644, body.as_bytes());
        recheck(&host).remove(0).problems.join(" | ")
    };
    // Spaces around the key and the value, and the last `User=` wins.
    assert!(problems("[Service]\nUser = root\nExecStart=\"/bin/x\"\n").contains("User="));
    assert!(problems("[Service]\n  User=agent\n User = root \n").contains("Some(\"root\")"));
    assert!(problems("[Service]\nUser=root\n User=agent\nExecStart=\"/bin/x\"\n").is_empty());
    assert!(problems("[Service]\nUser = agent\nExecStart=\"/bin/x\"\n").is_empty());
    // Anything else that changes what the unit keeps or who it runs as.
    for line in [
        "DynamicUser=yes",
        "ExecStart=+/bin/sh",
        "ExecStart=!/bin/sh",
        "ExecStartPost=+/bin/sh",
        "SupplementaryGroups=root",
        "Group=root",
        "[Install]",
        "nonsense",
    ] {
        let found = problems(&format!(
            "[Service]\nUser=agent\nExecStart=\"/bin/x\"\n{line}\n"
        ));
        assert!(!found.is_empty(), "{line}");
    }
    // A comment and a blank line are not settings.
    assert!(problems("# c\n; c\n\n[Service]\nUser=agent\nExecStart=\"/bin/x\"\n").is_empty());
}

fn ancestors(host: MemoryHost) -> MemoryHost {
    [
        "/run",
        "/run/systemd",
        "/run/systemd/system",
        "/usr",
        "/usr/lib",
        "/usr/lib/systemd",
        "/usr/lib/systemd/system",
    ]
    .iter()
    .fold(host, |host, parent| host.dir(parent, 0, 0, 0o755))
}

#[test]
fn recheck_finds_another_unit_source_that_could_change_the_user() {
    let base = || enrolled_host(ENROLLED_GROUP, None);
    for (dir, file) in [
        ("/run/systemd/system/xudo-agent@.service.d", "x.conf"),
        ("/etc/systemd/system/xudo-agent@.service.d", "x.conf"),
        ("/etc/systemd/system/service.d", "x.conf"),
        (
            "/usr/lib/systemd/system/xudo-agent@codex.service.d",
            "x.conf",
        ),
        ("/etc/systemd/system/xudo-agent-.service.d", "x.conf"),
        (
            "/etc/systemd/system.control/xudo-agent@.service.d",
            "x.conf",
        ),
        ("/run/systemd/system.control/service.d", "x.conf"),
        (
            "/run/systemd/transient/xudo-agent@codex.service.d",
            "x.conf",
        ),
        ("/run/systemd/generator.early/service.d", "x.conf"),
        (
            "/run/systemd/generator.late/xudo-agent@.service.d",
            "x.conf",
        ),
    ] {
        let parent = dir.rsplit_once('/').map_or("/", |(parent, _)| parent);
        let host = ancestors(base())
            .dir(parent, 0, 0, 0o755)
            .dir(dir, 0, 0, 0o755)
            .file(
                &format!("{dir}/{file}"),
                0,
                0,
                0o644,
                b"[Service]\nUser=root\n",
            );
        let found = recheck(&host).remove(0).problems.join(" | ");
        assert!(found.contains(dir), "{dir}: {found}");
    }
    // A template file that overrides the packaged one, anywhere but where the
    // package puts it.
    for file in [
        "/etc/systemd/system/xudo-agent@.service",
        "/run/systemd/generator.late/xudo-agent@.service",
    ] {
        let parent = file.rsplit_once('/').map_or("/", |(parent, _)| parent);
        let host = ancestors(base()).dir(parent, 0, 0, 0o755).file(
            file,
            0,
            0,
            0o644,
            b"[Service]\nUser=root\n",
        );
        let found = recheck(&host).remove(0).problems.join(" | ");
        assert!(found.contains(file), "{file}: {found}");
    }
    let packaged = ancestors(base()).file(
        "/usr/lib/systemd/system/xudo-agent@.service",
        0,
        0,
        0o644,
        b"[Service]\n",
    );
    assert_eq!(recheck(&packaged).remove(0).problems, Vec::<String>::new());
    // An empty one adds nothing; a whole unit file by the instance's name does.
    let empty = base().dir("/etc/systemd/system/service.d", 0, 0, 0o755);
    assert_eq!(recheck(&empty).remove(0).problems, Vec::<String>::new());
    let whole = ancestors(base()).file(
        "/run/systemd/system/xudo-agent@codex.service",
        0,
        0,
        0o644,
        b"[Service]\nUser=root\n",
    );
    assert!(
        recheck(&whole)
            .remove(0)
            .problems
            .join(" | ")
            .contains("replace the packaged template")
    );
    let unreadable = ancestors(base()).unlistable_dir("/run/systemd/system/service.d", 0, 0, 0o711);
    assert!(
        recheck(&unreadable)
            .remove(0)
            .problems
            .join(" | ")
            .contains("could not examine /run/systemd/system/service.d")
    );
}

#[test]
fn is_listed_ignores_a_primary_group() {
    let passwd = b"agent:x:990:998::/h:/bin/false\n";
    let group = b"xudo:x:998:\nxudo-agent:x:997:agent,alice\n";
    assert!(is_member(passwd, group, "agent", "xudo"));
    assert!(!is_listed(group, "agent", "xudo"));
    assert!(is_listed(group, "agent", "xudo-agent"));
    assert!(!is_listed(group, "agen", "xudo-agent"));
}

#[test]
fn the_account_is_added_after_an_existing_member_of_an_agent_group() {
    let group = "root:x:0:\nagent:x:990:\nxudo:x:998:alice\nxudo-agent:x:997:\n";
    let host = sudoers_host(group, None).file(
        "/etc/sudoers.d/90-local",
        0,
        0,
        0o440,
        b"%#998 ALL=(ALL) NOPASSWD: ALL\n",
    );
    assert!(!blockers(&host, None).is_empty());
    assert_eq!(
        with_membership(b"xudo:x:998:alice\nother:x:5:bob\n", "agent"),
        b"xudo:x:998:alice,agent\nother:x:5:bob\n".to_vec()
    );
}
