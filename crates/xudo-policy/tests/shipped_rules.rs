//! The shipped ruleset is tested like code, because it is code.
//!
//! Every rule file under `rules/` is compiled into this test with
//! `include_str!`, so the policy crate stays pure (no I/O) while the files that
//! actually ship are still parsed, validated, and attacked on every run.
//!
//! The checks here are the ones an operator cannot be expected to do by eye:
//! that no shipped rule allowlists something the deny-list refuses, that the
//! rules permit exactly the invocations they claim to, and that the obvious
//! escapes around each one are refused.

#![allow(clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use xudo_policy::{
    Arg, Argv, CallerFacts, CapabilityClass, Classification, DenialCode, Matcher, NameKind,
    Request, RuleSet, Verdict, engine::Settings, evaluate_command,
};

/// Each shipped file, paired with the name it has on disk.
const SHIPPED: &[(&str, &str)] = &[
    (
        "05-probe.toml",
        include_str!("../../../rules/05-probe.toml"),
    ),
    (
        "10-diagnostics.toml",
        include_str!("../../../rules/10-diagnostics.toml"),
    ),
    (
        "20-services.toml",
        include_str!("../../../rules/20-services.toml"),
    ),
    (
        "30-packages.toml",
        include_str!("../../../rules/30-packages.toml"),
    ),
    (
        "40-tunables.toml",
        include_str!("../../../rules/40-tunables.toml"),
    ),
];

/// The lifecycle example is not a shipped rule. The loader only reads names
/// ending in `.toml`, and this file is `*.toml.example`, so `include_str!`
/// is how the build attacks it.
const LIFECYCLE_EXAMPLE: &str =
    include_str!("../../../rules/examples/20-services-lifecycle.toml.example");

/// The hole the tripwires close: a lifecycle rule whose unit position is the
/// generic `unit-name` kind. The shipped rules do not contain this. A test
/// that only calls `evaluate_deny_list` would pass even if matching an action
/// stopped the deny-list from running.
const HOLE_LIFECYCLE: &str = r#"
[[action]]
id = "xudo.svc.lifecycle"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "no-ask", matcher = { literal = "--no-ask-password" } },
  { name = "verb", matcher = { one-of = [
    "start", "stop", "restart", "try-restart", "reload",
    "reload-or-restart", "try-reload-or-restart",
  ] } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;

fn example_lifecycle() -> RuleSet {
    RuleSet::from_toml("20-services-lifecycle.toml", LIFECYCLE_EXAMPLE)
        .unwrap_or_else(|e| panic!("lifecycle example does not load: {e}"))
}

fn hole_lifecycle() -> RuleSet {
    RuleSet::from_toml("hole.toml", HOLE_LIFECYCLE)
        .unwrap_or_else(|e| panic!("hole lifecycle rule does not load: {e}"))
}

fn load_all() -> RuleSet {
    let mut actions = Vec::new();
    for (name, contents) in SHIPPED {
        let set = RuleSet::from_toml(name, contents)
            .unwrap_or_else(|e| panic!("shipped rule file {name} does not load: {e}"));
        actions.extend(set.actions().iter().cloned());
    }
    RuleSet::load(actions).unwrap_or_else(|e| panic!("shipped rules do not combine: {e}"))
}

/// Every shipped file's `[[test]]` tables, and the ruleset they run against.
fn load_all_with_tests() -> (RuleSet, Vec<xudo_policy::RuleTest>) {
    let mut tests = Vec::new();
    for (name, contents) in SHIPPED {
        let (_, file_tests) = RuleSet::from_toml_with_tests(name, contents).unwrap();
        tests.extend(file_tests);
    }
    (load_all(), tests)
}

/// The tests the rule files carry hold, and every action is exercised by one
/// that names it. A failing shipped test fails the build.
#[test]
fn shipped_rule_tests_pass() {
    let (rules, tests) = load_all_with_tests();
    // Pinned exactly: adding or removing a shipped test is edited here, on
    // purpose, so a file that silently lost its tests cannot pass.
    assert_eq!(
        tests.len(),
        31,
        "the shipped test count changed: update this"
    );
    let results = xudo_policy::run_tests(&rules, &tests, &human(), Settings::default());
    let failures: Vec<String> = results
        .iter()
        .filter(|r| !r.outcome.passed())
        .map(|r| format!("{}: {:?} {:?}", r.test.source, r.test.argv, r.outcome))
        .collect();
    assert!(
        failures.is_empty(),
        "shipped rule tests fail:\n{}",
        failures.join("\n")
    );

    for (name, _) in SHIPPED {
        assert!(
            tests.iter().any(|t| &t.source.file == name),
            "{name} carries no tests"
        );
    }

    for action in rules.actions() {
        assert!(
            tests.iter().any(|t| t.action.as_ref() == Some(&action.id)),
            "{} has no test naming it",
            action.id
        );
    }
}

fn human() -> CallerFacts {
    CallerFacts::new(Classification::Human, 1000)
}

fn agent() -> CallerFacts {
    CallerFacts::new(
        Classification::EnrolledAgent {
            agent_id: "claude-code".into(),
            session_id: "s-1".into(),
            declared_yolo: true,
        },
        1000,
    )
}

fn verdict(action: &str, args: &[&str]) -> Verdict {
    let rules = load_all();
    xudo_policy::evaluate(
        &rules,
        &human(),
        &Request::new(action, Argv::new(args.to_vec())),
        Settings::default(),
    )
    .verdict
}

fn denial(action: &str, args: &[&str]) -> Option<DenialCode> {
    let rules = load_all();
    xudo_policy::evaluate(
        &rules,
        &human(),
        &Request::new(action, Argv::new(args.to_vec())),
        Settings::default(),
    )
    .denial
}

/// The shipped install argv, without the package names.
///
/// `--no-remove` sits with the other apt options, before the verb. Apt reads
/// options before the command, and a token after `--` would be a package name.
const INSTALL_PREFIX: &[&str] = &[
    "-y",
    "--no-install-recommends",
    "--no-remove",
    "install",
    "--",
];

fn install_argv<'a>(packages: &[&'a str]) -> Vec<&'a str> {
    let mut args = INSTALL_PREFIX.to_vec();
    args.extend_from_slice(packages);
    args
}

#[test]
fn every_shipped_file_loads_and_reports_real_provenance() {
    for (name, contents) in SHIPPED {
        let set = RuleSet::from_toml(name, contents).unwrap();
        assert!(!set.is_empty(), "{name} defines no actions");
        for action in set.actions() {
            assert_eq!(&action.source.file, name);
            assert!(
                action.source.line > 0,
                "{}: provenance line was not resolved",
                action.id
            );
            // Provenance is derived by the loader, so it must point at the real
            // declaration rather than at whatever the file claimed.
            let line = contents
                .lines()
                .nth((action.source.line as usize).saturating_sub(1))
                .unwrap_or_default();
            assert!(
                line.contains(action.id.as_str()),
                "{}: line {} does not declare it: {line:?}",
                action.id,
                action.source.line
            );
        }
    }
}

#[test]
fn no_shipped_rule_allowlists_a_deny_listed_executable() {
    // The in-process half of the GTFOBins gate. If this ever fails, a rule
    // allowlists something that can be turned into a root shell, and the whole
    // design is void regardless of how narrow the arguments look.
    let rules = load_all();
    let offenders = rules.self_denying_actions();
    assert!(
        offenders.is_empty(),
        "shipped rules allowlist deny-listed executables: {offenders:?}"
    );
}

#[test]
fn no_shipped_action_id_is_duplicated_across_files() {
    // `RuleSet::load` enforces this; combining every file is what makes the
    // check meaningful, since duplicates only collide once the set is merged.
    let set = load_all();
    let mut ids: Vec<&str> = set.actions().iter().map(|a| a.id.as_str()).collect();
    ids.sort_unstable();
    let total = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), total);
}

#[test]
fn an_unknown_key_in_a_rule_file_fails_the_whole_file() {
    // Not a warning. Silently ignoring a security-relevant directive is the
    // footgun this project exists to avoid.
    let err = RuleSet::from_toml(
        "hostile.toml",
        r#"
        [[action]]
        id = "xudo.evil"
        tier = "diag-read"
        exe = "/usr/bin/true"
        nopasswd = true
        "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("nopasswd"), "{err}");
}

#[test]
fn a_rule_file_cannot_declare_its_own_provenance() {
    // Provenance a rule can set is provenance an operator cannot trust, so the
    // key is not part of the schema at all.
    let err = RuleSet::from_toml(
        "hostile.toml",
        r#"
        [[action]]
        id = "xudo.evil"
        tier = "diag-read"
        exe = "/usr/bin/true"
        source = { file = "trustworthy.toml", line = 1 }
        "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("source"), "{err}");
}

#[test]
fn malformed_toml_fails_closed_with_the_file_named() {
    let err = RuleSet::from_toml("broken.toml", "[[action]\nid =").unwrap_err();
    assert!(err.to_string().contains("broken.toml"), "{err}");
}

#[test]
fn an_empty_rule_file_is_valid_and_permits_nothing() {
    let set = RuleSet::from_toml("empty.toml", "# nothing here\n").unwrap();
    assert!(set.is_empty());
}

// --- what the shipped rules actually permit ---------------------------------

/// Verbs the example lists, and the verbs a lifecycle rule is for.
const LIFECYCLE_VERBS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "try-restart",
    "reload",
    "reload-or-restart",
    "try-reload-or-restart",
];

#[test]
fn service_lifecycle_permits_the_verbs_it_lists() {
    // The example, not the shipped rules. The shipped set has no lifecycle
    // action; this is what an operator gets after copying the example and
    // before replacing the placeholder names.
    let rules = example_lifecycle();
    for verb in LIFECYCLE_VERBS {
        let decision = xudo_policy::evaluate(
            &rules,
            &human(),
            &Request::new(
                "xudo.svc.lifecycle",
                Argv::new(vec![
                    "--no-pager",
                    "--no-ask-password",
                    verb,
                    "example.service",
                ]),
            ),
            Settings::default(),
        );
        assert_eq!(
            decision.verdict,
            Verdict::Allow,
            "{verb} was not permitted: {:?}",
            decision.denial
        );
    }
}

#[test]
fn reset_failed_still_accepts_a_plain_service() {
    assert_eq!(
        verdict(
            "xudo.svc.reset-failed",
            &["--no-pager", "reset-failed", "ssh.service"]
        ),
        Verdict::Allow
    );
}

#[test]
fn journal_rules_still_accept_a_target_and_a_template_unit() {
    // Reading a unit's log is the point of the generic unit-name kind.
    // Narrowing it would hide the log of the unit the lifecycle rule refuses.
    for unit in ["poweroff.target", "getty@tty1.service", "a\\x2db.service"] {
        assert_eq!(
            verdict("xudo.svc.logs", &["--no-pager", "-u", unit]),
            Verdict::Allow,
            "{unit}"
        );
    }
}

fn command_verdict(args: &[&str]) -> Verdict {
    let rules = load_all();
    let (program, operands) = args.split_first().unwrap();
    xudo_policy::evaluate_command(
        &rules,
        &human(),
        &xudo_policy::Arg::from(*program),
        &Argv::new(operands.to_vec()),
        Settings::default(),
    )
    .verdict
}

#[test]
fn denies_poweroff_via_systemctl_start_poweroff_target() {
    let args = [
        "/usr/bin/systemctl",
        "--no-pager",
        "--no-ask-password",
        "start",
        "poweroff.target",
    ];
    assert_eq!(command_verdict(&args), Verdict::Deny);
    assert_eq!(
        denial(
            "xudo.svc.reset-failed",
            &["--no-pager", "reset-failed", "poweroff.target"]
        ),
        Some(DenialCode::ArgvRejected)
    );
}

#[test]
fn denies_kernel_module_load_via_modprobe_template_unit() {
    assert_eq!(
        command_verdict(&[
            "/usr/bin/systemctl",
            "--no-pager",
            "--no-ask-password",
            "start",
            "modprobe@dummy.service",
        ]),
        Verdict::Deny
    );
}

#[test]
fn denies_stopping_the_broker_socket() {
    assert_eq!(
        command_verdict(&[
            "/usr/bin/systemctl",
            "--no-pager",
            "--no-ask-password",
            "stop",
            "xudod.socket",
        ]),
        Verdict::Deny
    );
    // A unit-name lifecycle rule would accept this plain service name. The
    // deny-list still refuses the broker's own service.
    let decision = xudo_policy::evaluate(
        &hole_lifecycle(),
        &human(),
        &Request::new(
            "xudo.svc.lifecycle",
            Argv::new(vec![
                "--no-pager",
                "--no-ask-password",
                "stop",
                "xudod.service",
            ]),
        ),
        Settings::default(),
    );
    assert_eq!(decision.denial, Some(DenialCode::DenyListed));
}

#[test]
fn no_lifecycle_verb_reaches_a_special_target() {
    // Every lifecycle verb, plus verbs the deny entry covers even though no
    // shipped rule lists them (`isolate`, `reset-failed`, `status`).
    const VERBS: &[&str] = &[
        "start",
        "stop",
        "restart",
        "try-restart",
        "reload",
        "reload-or-restart",
        "try-reload-or-restart",
        "isolate",
        "kill",
        "reset-failed",
        "status",
        "show",
    ];
    const TARGETS: &[&str] = &[
        "poweroff.target",
        "reboot.target",
        "halt.target",
        "kexec.target",
        "soft-reboot.target",
        "ctrl-alt-del.target",
        "suspend.target",
        "hibernate.target",
        "hybrid-sleep.target",
        "suspend-then-hibernate.target",
        "sleep.target",
        "shutdown.target",
        "rescue.target",
        "emergency.target",
        "exit.target",
        "sysinit.target",
    ];
    for verb in VERBS {
        for target in TARGETS {
            let argv = Argv::new(vec!["--no-pager", "--no-ask-password", verb, target]);
            let findings = xudo_policy::evaluate_deny_list(b"/usr/bin/systemctl", &argv);
            assert!(
                findings
                    .iter()
                    .any(|f| f.class == xudo_policy::CapabilityClass::PowerState),
                "{verb} {target} was not a power state: {findings:?}"
            );
            assert_eq!(
                command_verdict(&[
                    "/usr/bin/systemctl",
                    "--no-pager",
                    "--no-ask-password",
                    verb,
                    target,
                ]),
                Verdict::Deny,
                "{verb} {target}"
            );
        }
    }
}

fn unit_classes(verb: &str, unit: &str) -> Vec<CapabilityClass> {
    let argv = Argv::new(vec![verb, unit]);
    xudo_policy::evaluate_deny_list(b"/usr/bin/systemctl", &argv)
        .into_iter()
        .map(|finding| finding.class)
        .collect()
}

#[test]
fn unit_keyed_deny_entries_cover_templates_security_and_escapes() {
    // The cartesian power-target check is `no_lifecycle_verb_reaches_a_special_target`.
    // This one is the rest of the unit-keyed list, including spellings that
    // only decode to a refused unit. It lives here so miri, which runs the
    // library tests only, does not pay for the matrix.
    for unit in ["modprobe@foo\\x2dbar.service", "mod\\.probe@x.service"] {
        assert!(
            unit_classes("start", unit).contains(&CapabilityClass::KernelModule),
            "{unit}"
        );
    }
    for unit in [
        "systemd-fsck@dev-sda1.service",
        "systemd-growfs@dev-sda1.service",
        "systemd-makefs@dev-sda1.service",
        "mdadm-last-resort@dev-sda1.service",
        "mdadm-grow-continue@dev-md0.service",
        "mdadm@dev-md0.service",
    ] {
        assert!(
            unit_classes("start", unit).contains(&CapabilityClass::DeviceOrFilesystem),
            "{unit}"
        );
    }
    for unit in [
        "xudod.service",
        "xudod",
        "xudod@1.service",
        "xudo-pasban.service",
    ] {
        assert!(
            unit_classes("stop", unit).contains(&CapabilityClass::SelfModification),
            "{unit}"
        );
    }
    assert!(
        !unit_classes("stop", "xudod-extra.service").contains(&CapabilityClass::SelfModification)
    );
    for unit in [
        "apparmor.service",
        "apparmor",
        "apparmor@profile.service",
        "auditd.service",
        "auditd.socket",
    ] {
        assert!(
            unit_classes("stop", unit).contains(&CapabilityClass::SecuritySubsystem),
            "{unit}"
        );
    }
    assert!(unit_classes("stop", "apparmor-helper.service").is_empty());
    for unit in [
        "ctrl\\x2dalt\\x2ddel.target",
        "ctrl\\x2Dalt\\x2ddel.target",
        "reboot\\x2etarget",
        "poweroff\\.target",
        "poweroff.target\\",
    ] {
        assert!(
            unit_classes("start", unit).contains(&CapabilityClass::PowerState),
            "{unit}"
        );
    }
    for unit in [
        "getty@tty\\x2d1.service",
        "getty\\.service",
        "nginx.service",
        "@foo.service",
        "reboot\\x",
        "poweroff\\x2",
        "poweroff\\xz.target",
        "poweroff\\x2g.target",
        "Poweroff.target",
    ] {
        assert!(unit_classes("start", unit).is_empty(), "{unit} was denied");
    }
    let journal = Argv::new(vec!["--no-pager", "-u", "poweroff.target"]);
    assert!(xudo_policy::evaluate_deny_list(b"/usr/bin/journalctl", &journal).is_empty());
    let both = unit_classes("enable", "poweroff.target");
    assert!(both.contains(&CapabilityClass::UnitDefinitionMutation));
    assert!(both.contains(&CapabilityClass::PowerState));
}

#[test]
fn service_lifecycle_refuses_every_unit_mutating_verb() {
    // The example's verb enum is the lifecycle verbs only. `enable` changes
    // a unit definition and is not in that list.
    let rules = example_lifecycle();
    for verb in [
        "enable",
        "disable",
        "mask",
        "unmask",
        "link",
        "revert",
        "edit",
        "set-property",
        "switch-root",
    ] {
        let decision = xudo_policy::evaluate(
            &rules,
            &human(),
            &Request::new(
                "xudo.svc.lifecycle",
                Argv::new(vec![
                    "--no-pager",
                    "--no-ask-password",
                    verb,
                    "example.service",
                ]),
            ),
            Settings::default(),
        );
        assert_eq!(
            decision.denial,
            Some(DenialCode::ArgvRejected),
            "{verb} gave {:?}",
            decision.denial
        );
    }
}

#[test]
fn a_suffixless_unit_name_is_refused() {
    // `systemctl restart example` resolves to example.service, so accepting a
    // bare name would silently widen the operator's list.
    let rules = example_lifecycle();
    let decision = xudo_policy::evaluate(
        &rules,
        &human(),
        &Request::new(
            "xudo.svc.lifecycle",
            Argv::new(vec![
                "--no-pager",
                "--no-ask-password",
                "restart",
                "example",
            ]),
        ),
        Settings::default(),
    );
    assert_eq!(decision.denial, Some(DenialCode::ArgvRejected));
}

#[test]
fn the_shipped_rules_have_no_lifecycle_rule() {
    let rules = load_all();
    assert!(
        rules
            .actions()
            .iter()
            .all(|action| action.id.as_str() != "xudo.svc.lifecycle"),
        "xudo.svc.lifecycle is an example, not a shipped action"
    );
    assert_eq!(
        command_verdict(&[
            "/usr/bin/systemctl",
            "--no-pager",
            "--no-ask-password",
            "restart",
            "nginx.service",
        ]),
        Verdict::Deny
    );
}

#[test]
fn the_lifecycle_example_parses_and_its_tests_pass() {
    let (rules, tests) =
        RuleSet::from_toml_with_tests("20-services-lifecycle.toml", LIFECYCLE_EXAMPLE)
            .unwrap_or_else(|e| panic!("lifecycle example does not load: {e}"));
    assert_eq!(rules.actions().len(), 1);
    assert!(
        rules
            .actions()
            .iter()
            .any(|action| action.id.as_str() == "xudo.svc.lifecycle")
    );
    assert!(
        tests.len() >= 7,
        "the example's [[test]] tables were dropped: {}",
        tests.len()
    );
    let results = xudo_policy::run_tests(&rules, &tests, &human(), Settings::default());
    let failures: Vec<String> = results
        .iter()
        .filter(|result| !result.outcome.passed())
        .map(|result| format!("{:?} {:?}", result.test.argv, result.outcome))
        .collect();
    assert!(
        failures.is_empty(),
        "example tests fail:\n{}",
        failures.join("\n")
    );

    // Near misses the [[test]] tables also pin, asserted here so deleting a
    // table cannot make an unlisted unit look allowed.
    for unit in [
        "nginx.service",
        "systemd-poweroff.service",
        "poweroff.target",
        "example",
        "example.service.extra",
    ] {
        let decision = xudo_policy::evaluate(
            &rules,
            &human(),
            &Request::new(
                "xudo.svc.lifecycle",
                Argv::new(vec!["--no-pager", "--no-ask-password", "restart", unit]),
            ),
            Settings::default(),
        );
        assert_eq!(decision.verdict, Verdict::Deny, "{unit} was permitted");
    }
}

/// Every unit the deny-list keys, with the class that entry uses.
///
/// The cartesian check below is the proof that a `unit-name` lifecycle rule
/// (the hole) still cannot reach one. The class is pinned so a tripwire that
/// moved to the wrong class fails here.
fn listed_units() -> Vec<(&'static str, CapabilityClass)> {
    let mut units = Vec::new();
    let power = [
        "poweroff.target",
        "reboot.target",
        "halt.target",
        "kexec.target",
        "soft-reboot.target",
        "ctrl-alt-del.target",
        "suspend.target",
        "hibernate.target",
        "hybrid-sleep.target",
        "suspend-then-hibernate.target",
        "sleep.target",
        "shutdown.target",
        "rescue.target",
        "emergency.target",
        "exit.target",
        "sysinit.target",
        "runlevel0.target",
        "runlevel1.target",
        "runlevel6.target",
        "systemd-poweroff.service",
        "systemd-reboot.service",
        "systemd-halt.service",
        "systemd-kexec.service",
        "systemd-soft-reboot.service",
        "systemd-suspend.service",
        "systemd-hibernate.service",
        "systemd-hybrid-sleep.service",
        "systemd-suspend-then-hibernate.service",
    ];
    for unit in power {
        units.push((unit, CapabilityClass::PowerState));
    }
    units.push(("debug-shell.service", CapabilityClass::SpawnsShell));
    units.push(("modprobe@dummy.service", CapabilityClass::KernelModule));
    for unit in [
        "systemd-fsck@dev-sda1.service",
        "systemd-growfs@dev-sda1.service",
        "systemd-makefs@dev-sda1.service",
        "mdadm@dev-md0.service",
    ] {
        units.push((unit, CapabilityClass::DeviceOrFilesystem));
    }
    for unit in [
        "xudod.service",
        "xudod.socket",
        "xudo-pasban.service",
        "systemd-journald.service",
        "systemd-journald.socket",
        "systemd-journald-dev-log.socket",
        "rsyslog.service",
    ] {
        units.push((unit, CapabilityClass::SelfModification));
    }
    for unit in [
        "apparmor.service",
        "auditd.service",
        "nftables.service",
        "ufw.service",
        "netfilter-persistent.service",
        "firewalld.service",
        "systemd-timesyncd.service",
        "chrony.service",
        "chronyd.service",
    ] {
        units.push((unit, CapabilityClass::SecuritySubsystem));
    }
    units
}

#[test]
fn no_lifecycle_verb_reaches_a_listed_unit() {
    let rules = hole_lifecycle();
    // The fixture really is a hole for an ordinary service. If this failed,
    // a later DenyListed would only mean "the rule did not match".
    let ordinary = xudo_policy::evaluate(
        &rules,
        &human(),
        &Request::new(
            "xudo.svc.lifecycle",
            Argv::new(vec![
                "--no-pager",
                "--no-ask-password",
                "restart",
                "nginx.service",
            ]),
        ),
        Settings::default(),
    );
    assert_eq!(ordinary.verdict, Verdict::Allow, "{:?}", ordinary.denial);

    for verb in LIFECYCLE_VERBS {
        for (unit, class) in listed_units() {
            let decision = xudo_policy::evaluate(
                &rules,
                &human(),
                &Request::new(
                    "xudo.svc.lifecycle",
                    Argv::new(vec!["--no-pager", "--no-ask-password", verb, unit]),
                ),
                Settings::default(),
            );
            assert_eq!(
                decision.denial,
                Some(DenialCode::DenyListed),
                "{verb} {unit} gave {:?} {:?}",
                decision.verdict,
                decision.denial
            );
            let classes = unit_classes(verb, unit);
            assert!(
                classes.contains(&class),
                "{verb} {unit} was {classes:?}, expected {class:?}"
            );
        }
    }
}

#[test]
fn package_install_permits_names_and_refuses_every_other_source() {
    assert_eq!(
        verdict("xudo.pkg.install", &install_argv(&["ripgrep", "fd-find"])),
        Verdict::Allow
    );

    for bad in [
        "./local.deb",
        "/tmp/x.deb",
        "https://evil.example/x.deb",
        "ripgrep=1.0",
        "ripgrep:amd64",
        "-y",
        "../../etc/passwd",
    ] {
        let d = denial("xudo.pkg.install", &install_argv(&[bad]));
        assert!(d.is_some(), "{bad} was permitted");
    }
}

#[test]
fn denies_package_removal_via_install_trailing_hyphen() {
    // `apt-get install apparmor-` removes apparmor. The install rule must not
    // be that removal: pkg.remove is the removal, and it confirms always.
    for name in ["apparmor-", "auditd-", "xudo-", "sudo-"] {
        let args = install_argv(&[name]);
        assert_eq!(
            denial("xudo.pkg.install", &args),
            Some(DenialCode::ArgvRejected),
            "{name} was not an argument refusal"
        );
        let decision = evaluate_command(
            &load_all(),
            &human(),
            &Arg::from("/usr/bin/apt-get"),
            &Argv::new(args),
            Settings::default(),
        );
        assert_eq!(decision.verdict, Verdict::Deny, "{name} was accepted");
        assert_eq!(decision.denial, Some(DenialCode::ArgvRejected));
    }
}

#[test]
fn install_without_no_remove_is_not_accepted() {
    // The flag is part of the rule, not a default apt adds. Without it an
    // install that must remove a conflicting package would proceed.
    let args = ["-y", "--no-install-recommends", "install", "--", "ripgrep"];
    assert_eq!(
        denial("xudo.pkg.install", &args),
        Some(DenialCode::ArgvRejected)
    );
    let decision = evaluate_command(
        &load_all(),
        &human(),
        &Arg::from("/usr/bin/apt-get"),
        &Argv::new(args.to_vec()),
        Settings::default(),
    );
    assert_eq!(decision.verdict, Verdict::Deny);
    assert_eq!(
        verdict("xudo.pkg.install", &install_argv(&["ripgrep"])),
        Verdict::Allow
    );
}

#[test]
fn legitimate_package_names_with_plus_dot_and_hyphen_are_accepted() {
    // Real names. A trailing `+` stays: `g++` is a package, and `pkg+` on
    // install asks apt to install. An internal `-` or `.` is not a removal.
    for name in [
        "libstdc++6",
        "g++",
        "python3.12",
        "libpng16-16",
        "x11-utils",
    ] {
        for kind in [NameKind::DebName, NameKind::ApkName] {
            assert!(
                Matcher::Name(kind).accepts(&Arg::from(name)),
                "{kind:?} rejected {name}"
            );
        }
        assert_eq!(
            verdict("xudo.pkg.install", &install_argv(&[name])),
            Verdict::Allow,
            "{name} was not an install"
        );
    }
}

#[test]
fn package_install_refuses_a_configuration_redirect() {
    // The motivating case: `-o DPkg::Pre-Invoke::=...` is a root shell reached
    // through a rule that only meant to install a package. The word `sh` never
    // appears as a command.
    let d = denial(
        "xudo.pkg.install",
        &[
            "-y",
            "--no-install-recommends",
            "--no-remove",
            "install",
            "-o",
            "DPkg::Pre-Invoke::=sh -c id",
            "--",
            "ripgrep",
        ],
    );
    assert!(d.is_some(), "a Pre-Invoke injection was permitted");
}

#[test]
fn package_install_caps_the_number_of_names() {
    let mut args = INSTALL_PREFIX.to_vec();
    let many = vec!["ripgrep"; 21];
    args.extend(many.iter().copied());
    assert_eq!(
        denial("xudo.pkg.install", &args),
        Some(DenialCode::ArgvRejected)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    /// A deb-name ending in `-` is a removal. No shipped action accepts one,
    /// in a package slot or through the install, remove, or dry-run shape.
    #[test]
    fn no_deb_name_ending_in_a_hyphen_is_accepted_by_any_shipped_action(
        body in "[a-z0-9+._]{0,48}"
    ) {
        let name = format!("{body}-");
        let arg = Arg::from(name.as_str());
        prop_assert!(!Matcher::Name(NameKind::DebName).accepts(&arg));
        prop_assert!(!Matcher::Name(NameKind::ApkName).accepts(&arg));

        let rules = load_all();
        for action in rules.actions() {
            for spec in &action.args {
                if matches!(
                    spec.matcher,
                    Matcher::Name(NameKind::DebName | NameKind::ApkName)
                ) {
                    let id = action.id.as_str();
                    prop_assert!(!spec.matcher.accepts(&arg), "{id} accepts {name}", id = id, name = name);
                }
            }
        }

        let shapes: &[(&str, &[&str])] = &[
            ("/usr/bin/apt-get", INSTALL_PREFIX),
            ("/usr/bin/apt-get", &["-y", "remove", "--"]),
            ("/usr/bin/apt-get", &["-s", "install", "--"]),
        ];
        for (program, prefix) in shapes {
            let mut argv = prefix.to_vec();
            argv.push(name.as_str());
            let decision = evaluate_command(
                &rules,
                &human(),
                &Arg::from(*program),
                &Argv::new(argv),
                Settings::default(),
            );
            prop_assert_eq!(
                decision.verdict,
                Verdict::Deny,
                "{program} accepted {name}",
                program = program,
                name = name
            );
        }
    }
}

#[test]
fn package_removal_always_confirms_even_for_a_human() {
    // Removals cascade, so this rule sets confirm = "always" rather than
    // relying on the caller being an agent.
    assert_eq!(
        verdict("xudo.pkg.remove", &["-y", "remove", "--", "ripgrep"]),
        Verdict::AllowWithConfirmation
    );
}

fn the_install_probe_permits_only_dash_u(action: &str) {
    assert_eq!(verdict(action, &["-u"]), Verdict::Allow);
    for args in [
        &[][..],
        &["-un"],
        &["-G"],
        &["-u", "root"],
        &["-u", "-u"],
        &["root"],
        &["-u", "--", "root"],
    ] {
        assert_eq!(
            verdict(action, args),
            Verdict::Deny,
            "{action} {args:?} was permitted"
        );
    }
}

#[test]
fn the_install_probe_permits_id_dash_u_and_nothing_wider() {
    the_install_probe_permits_only_dash_u("xudo.probe.id");
}

#[test]
fn the_install_probe_permits_gnuid_dash_u_and_nothing_wider() {
    the_install_probe_permits_only_dash_u("xudo.probe.gnuid");
}

/// A command each shipped action accepts. Every shipped action must have one:
/// an action with no example here fails the tests that walk the ruleset.
fn example(id: &str) -> Vec<&'static str> {
    match id {
        "xudo.svc.status" => vec!["--no-pager", "--full", "status", "nginx.service"],
        "xudo.svc.show" => vec!["--no-pager", "show", "nginx.service"],
        "xudo.svc.logs" => vec!["--no-pager", "-u", "nginx.service"],
        "xudo.svc.reset-failed" => vec!["--no-pager", "reset-failed", "nginx.service"],
        "xudo.svc.reload-units" => vec!["--no-pager", "daemon-reload"],
        "xudo.dmesg" => vec!["--no-pager", "-k"],
        "xudo.probe.id" | "xudo.probe.gnuid" => vec!["-u"],
        "xudo.net.listeners" => vec!["-tulpnH"],
        "xudo.pkg.install" => install_argv(&["ripgrep"]),
        "xudo.pkg.update" => vec!["update"],
        "xudo.pkg.remove" => vec!["-y", "remove", "--", "ripgrep"],
        "xudo.pkg.dry-run-install" => vec!["-s", "install", "--", "ripgrep"],
        "xudo.sysctl.max-map-count" => vec!["-q", "-w", "vm.max_map_count", "262144"],
        "xudo.sysctl.inotify-watches" => {
            vec!["-q", "-w", "fs.inotify.max_user_watches", "524288"]
        }
        "xudo.time.set-ntp" => vec!["set-ntp", "true"],
        other => panic!("shipped action {other} has no example in this test; add one"),
    }
}

#[test]
fn a_yolo_agent_is_confirmed_on_every_shipped_action() {
    // The headline requirement, checked against the real ruleset rather than a
    // fixture: nothing an enrolled agent can run goes through unattended.
    let rules = load_all();
    for action in rules.actions() {
        let argv = example(action.id.as_str());
        let d = xudo_policy::evaluate(
            &rules,
            &agent(),
            &Request::new(action.id.clone(), Argv::new(argv.clone())),
            Settings::default(),
        );
        assert_eq!(
            d.verdict,
            Verdict::AllowWithConfirmation,
            "{} with {argv:?} gave {:?}",
            action.id,
            d.verdict
        );
    }
}

/// Overlaps the shipped ruleset carries on purpose: `(first id, second id,
/// why)`. Empty, because the shipped rules are disjoint. An entry needs a
/// reason an operator could act on, and an entry for a pair that no longer
/// overlaps fails the test, so reasons cannot outlive what they excuse.
const DELIBERATE_OVERLAPS: &[(&str, &str, &str)] = &[];

#[test]
fn the_shipped_rules_overlap_only_where_a_reason_is_written_down() {
    // Overlaps resolve to the strictest, so one is not a hole. But in the
    // rules that ship, every interaction between two rules is a decision
    // somebody has to have made, so an undeclared one fails here. Possible
    // overlaps count: the shipped rules use no pattern, so every pair is
    // decided exactly, and an undecidable one would need a reason too.
    let rules = load_all();
    let found: Vec<(String, String, String)> = rules
        .overlaps()
        .iter()
        .map(|o| {
            (
                o.first.id.to_string(),
                o.second.id.to_string(),
                o.to_string(),
            )
        })
        .collect();

    for (first, second, why) in DELIBERATE_OVERLAPS {
        assert!(
            why.len() >= 80,
            "the reason for {first} / {second} does not argue the case: {why}"
        );
        assert!(
            found.iter().any(|(a, b, _)| a == first && b == second),
            "stale entry: {first} and {second} no longer overlap; remove it"
        );
    }
    let undeclared: Vec<&str> = found
        .iter()
        .filter(|(a, b, _)| {
            !DELIBERATE_OVERLAPS
                .iter()
                .any(|(first, second, _)| a == first && b == second)
        })
        .map(|(_, _, report)| report.as_str())
        .collect();
    assert!(
        undeclared.is_empty(),
        "shipped rules overlap with no written reason; narrow one of them, or add the pair to \
         DELIBERATE_OVERLAPS with the reason:\n{}",
        undeclared.join("\n")
    );
}

#[test]
fn searching_each_shipped_example_finds_its_own_action_and_only_it() {
    // The same command line `xudo explain` and the broker will see, searched
    // across the whole shipped ruleset rather than asked of one action. With
    // disjoint rules, each example is accepted by exactly the action it was
    // written for.
    let rules = load_all();
    for action in rules.actions() {
        let argv = Argv::new(example(action.id.as_str()));
        let d = xudo_policy::evaluate_command(
            &rules,
            &human(),
            &xudo_policy::Arg::from(action.exe.as_str()),
            &argv,
            Settings::default(),
        );
        assert_eq!(d.action.as_ref(), Some(&action.id), "{d:?}");
        let matched = d
            .trace
            .iter()
            .filter(|step| matches!(step, xudo_policy::TraceStep::ActionMatched { .. }))
            .count();
        assert_eq!(
            matched, 1,
            "{} is accepted by more than one action",
            action.id
        );
    }
}

#[test]
fn sysctl_rules_bound_the_value_and_refuse_the_dangerous_keys() {
    assert_eq!(
        verdict(
            "xudo.sysctl.max-map-count",
            &["-q", "-w", "vm.max_map_count", "262144"]
        ),
        Verdict::Allow
    );
    // Below the declared floor.
    assert_eq!(
        denial(
            "xudo.sysctl.max-map-count",
            &["-q", "-w", "vm.max_map_count", "1024"]
        ),
        Some(DenialCode::ArgvRejected)
    );
    // A different key entirely: kernel.core_pattern is a program specification.
    assert!(
        denial(
            "xudo.sysctl.max-map-count",
            &["-q", "-w", "kernel.core_pattern", "|/tmp/x"]
        )
        .is_some()
    );
}

#[test]
fn a_file_driven_sysctl_form_is_refused() {
    for flag in ["-p", "--load", "--system"] {
        assert!(
            denial("xudo.sysctl.max-map-count", &["-q", flag]).is_some(),
            "{flag} was permitted"
        );
    }
}

#[test]
fn the_show_property_is_an_enum_that_cannot_carry_a_path_or_separator() {
    // The joined spelling reaches the matcher exactly as typed: canonicalization
    // does not split on `=`, so the rule lists the joined form and the split
    // form is a different argv.
    for argv in [
        vec![
            "--no-pager",
            "show",
            "nginx.service",
            "--property=ActiveState",
        ],
        vec!["--no-pager", "show", "nginx.service"],
    ] {
        assert_eq!(verdict("xudo.svc.show", &argv), Verdict::Allow, "{argv:?}");
    }

    // The split spelling is a different argv, and the rule lists only the
    // joined one, so it is refused rather than silently unified. Canonicalization
    // does not rewrite argument content, by design.
    assert_eq!(
        denial(
            "xudo.svc.show",
            &[
                "--no-pager",
                "show",
                "nginx.service",
                "--property",
                "ActiveState"
            ]
        ),
        Some(DenialCode::ArgvRejected)
    );

    for bad in [
        "--property=../../etc/shadow",
        "--property=A;id",
        "--property=/etc/passwd",
        "--property=ActiveState,LoadState",
    ] {
        assert_eq!(
            denial(
                "xudo.svc.show",
                &["--no-pager", "show", "nginx.service", bad]
            ),
            Some(DenialCode::ArgvRejected),
            "{bad} was permitted"
        );
    }
}

#[test]
fn a_rule_matches_the_argv_the_kernel_delivers_and_not_a_normalized_form() {
    // The contract after fuzzing removed flag splitting: a rule written against
    // the joined spelling matches the joined spelling, and nothing unifies the
    // two forms behind the author's back. If this ever fails, canonicalization
    // has started rewriting argument content again, and the matcher's view has
    // diverged from the program's.
    let set = RuleSet::from_toml(
        "joined.toml",
        r#"
[[action]]
id = "xudo.joined"
tier = "diag-read"
exe = "/usr/bin/systemctl"
args = [{ name = "prop", matcher = { literal = "--property=ActiveState" } }]
"#,
    )
    .unwrap();
    let joined = xudo_policy::evaluate(
        &set,
        &human(),
        &Request::new("xudo.joined", Argv::new(vec!["--property=ActiveState"])),
        Settings::default(),
    );
    assert_eq!(joined.verdict, Verdict::Allow);

    let split = xudo_policy::evaluate(
        &set,
        &human(),
        &Request::new("xudo.joined", Argv::new(vec!["--property", "ActiveState"])),
        Settings::default(),
    );
    assert_eq!(split.denial, Some(DenialCode::ArgvRejected));
}

#[test]
fn the_fixed_argv_action_accepts_nothing_else() {
    assert_eq!(verdict("xudo.net.listeners", &["-tulpnH"]), Verdict::Allow);
    for bad in [vec![], vec!["-tulpnH", "extra"], vec!["-e"]] {
        assert_eq!(
            denial("xudo.net.listeners", &bad),
            Some(DenialCode::ArgvRejected),
            "{bad:?} was permitted"
        );
    }
}

#[test]
fn dropping_a_pinned_flag_is_refused() {
    // The pinned --no-pager is what keeps journalctl out of the pager class, so
    // an invocation without it must not match.
    assert_eq!(
        denial("xudo.svc.logs", &["-u", "nginx.service"]),
        Some(DenialCode::ArgvRejected)
    );
}

/// The differential fuzz, run against the rules that ship: the overlap analysis
/// misses nothing, no decision depends on canonicalizing first, and appending an
/// argument never turns a refusal into a permission.
#[test]
fn check_fuzz_finds_nothing_in_the_shipped_rules() {
    let rules = load_all();
    let config = xudo_policy::fuzz_check::FuzzConfig {
        budget: 3000,
        ..Default::default()
    };
    let report = xudo_policy::fuzz_check::fuzz(&rules, &rules.overlaps(), config);
    assert_eq!(report.candidates, 3000);
    assert!(
        report.accepted_by_one > 0,
        "the fuzz never reached an accepting action: {report:?}"
    );
    for action in rules.actions() {
        assert!(
            !xudo_policy::fuzz_check::witnesses(&rules, action, 1, 4).is_empty(),
            "no witness for shipped action {}",
            action.id
        );
    }
    let found: Vec<String> = report
        .findings
        .iter()
        .map(|f| format!("{}: {}", f.summary(), f.escaped()))
        .collect();
    assert!(report.clean(), "the fuzz found:\n{}", found.join("\n"));
}
