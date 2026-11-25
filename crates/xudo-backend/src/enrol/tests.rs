//! Enrolment against described machines. Each refusal has a test that tries to
//! get past it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use super::*;
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
    let scan = scan_account(&host, "agent", &Input::default()).unwrap();
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
    let scan = scan_account(&host, "agent", &Input::default()).unwrap();
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
    let scan = scan_account(&host, "agent", &Input::default()).unwrap();
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
    };
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
    let missing = scan_account(&host(PASSWD.as_bytes()), "ghost", &Input::default());
    assert_eq!(
        missing.unwrap_err(),
        Refusal::AccountUnknown("ghost".to_owned())
    );
    let twice = scan_account(
        &host(b"a:x:5:5::/h:/s\na:x:6:6::/h:/s\n"),
        "a",
        &Input::default(),
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
        scan_account(&none, "a", &Input::default()).unwrap_err(),
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
    MemoryHost::new(Caller {
        uid: 0,
        gid: 0,
        groups: Lookup::Found(vec![0]),
    })
    .dir("/", 0, 0, 0o755)
    .dir("/etc", 0, 0, 0o755)
    .file("/etc/passwd", 0, 0, 0o644, PASSWD.as_bytes())
    .file("/etc/group", 0, 0, 0o644, group.as_bytes())
    .file("/etc/sudoers", 0, 0, 0o440, sudoers)
}

/// What the scan says and what the plan then does, for a described host.
fn through(host: &MemoryHost) -> (AccountScan, Result<EnrolPlan, Refusal>) {
    let scan = scan_account(host, "agent", &Input::default()).unwrap();
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
        b"# agent was here\nalice ALL=(ALL) ALL\n%xudo ALL=(root) /usr/libexec/xudo/xudo-gate-auth\nDefaults env_reset\nagentx ALL=(ALL) ALL\n",
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
