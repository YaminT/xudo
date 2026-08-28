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

use aido_policy::{
    Argv, CallerFacts, Classification, DenialCode, Request, RuleSet, Verdict, engine::Settings,
};

/// Each shipped file, paired with the name it has on disk.
const SHIPPED: &[(&str, &str)] = &[
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

fn load_all() -> RuleSet {
    let mut actions = Vec::new();
    for (name, contents) in SHIPPED {
        let set = RuleSet::from_toml(name, contents)
            .unwrap_or_else(|e| panic!("shipped rule file {name} does not load: {e}"));
        actions.extend(set.actions().iter().cloned());
    }
    RuleSet::load(actions).unwrap_or_else(|e| panic!("shipped rules do not combine: {e}"))
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
    aido_policy::evaluate(
        &rules,
        &human(),
        &Request::new(action, Argv::new(args.to_vec())),
        Settings::default(),
    )
    .verdict
}

fn denial(action: &str, args: &[&str]) -> Option<DenialCode> {
    let rules = load_all();
    aido_policy::evaluate(
        &rules,
        &human(),
        &Request::new(action, Argv::new(args.to_vec())),
        Settings::default(),
    )
    .denial
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
        id = "aido.evil"
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
        id = "aido.evil"
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

#[test]
fn service_lifecycle_permits_the_verbs_it_lists() {
    for verb in [
        "start",
        "stop",
        "restart",
        "try-restart",
        "reload",
        "reload-or-restart",
        "try-reload-or-restart",
    ] {
        assert_eq!(
            verdict(
                "aido.svc.lifecycle",
                &["--no-pager", "--no-ask-password", verb, "nginx.service"]
            ),
            Verdict::Allow,
            "{verb} was not permitted"
        );
    }
}

#[test]
fn service_lifecycle_refuses_every_unit_mutating_verb() {
    // Refused twice over: the verb is not in the enum, and the deny-list
    // classifies it independently. Either alone would be enough; both is the
    // point.
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
        let d = denial(
            "aido.svc.lifecycle",
            &["--no-pager", "--no-ask-password", verb, "nginx.service"],
        );
        assert!(
            d == Some(DenialCode::ArgvRejected) || d == Some(DenialCode::DenyListed),
            "{verb} gave {d:?}"
        );
    }
}

#[test]
fn a_suffixless_unit_name_is_refused() {
    // `systemctl restart nginx` resolves to nginx.service, so accepting a bare
    // name would silently widen the rule.
    assert_eq!(
        denial(
            "aido.svc.lifecycle",
            &["--no-pager", "--no-ask-password", "restart", "nginx"]
        ),
        Some(DenialCode::ArgvRejected)
    );
}

#[test]
fn package_install_permits_names_and_refuses_every_other_source() {
    assert_eq!(
        verdict(
            "aido.pkg.install",
            &[
                "-y",
                "--no-install-recommends",
                "install",
                "--",
                "ripgrep",
                "fd-find"
            ]
        ),
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
        let d = denial(
            "aido.pkg.install",
            &["-y", "--no-install-recommends", "install", "--", bad],
        );
        assert!(d.is_some(), "{bad} was permitted");
    }
}

#[test]
fn package_install_refuses_a_configuration_redirect() {
    // The motivating case: `-o DPkg::Pre-Invoke::=...` is a root shell reached
    // through a rule that only meant to install a package. The word `sh` never
    // appears as a command.
    let d = denial(
        "aido.pkg.install",
        &[
            "-y",
            "--no-install-recommends",
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
    let mut args = vec!["-y", "--no-install-recommends", "install", "--"];
    let many = vec!["ripgrep"; 21];
    args.extend(many.iter().copied());
    assert_eq!(
        denial("aido.pkg.install", &args),
        Some(DenialCode::ArgvRejected)
    );
}

#[test]
fn package_removal_always_confirms_even_for_a_human() {
    // Removals cascade, so this rule sets confirm = "always" rather than
    // relying on the caller being an agent.
    assert_eq!(
        verdict("aido.pkg.remove", &["-y", "remove", "--", "ripgrep"]),
        Verdict::AllowWithConfirmation
    );
}

#[test]
fn a_yolo_agent_is_confirmed_on_every_shipped_action() {
    // The headline requirement, checked against the real ruleset rather than a
    // fixture: nothing an enrolled agent can run goes through unattended.
    let rules = load_all();
    for action in rules.actions() {
        let argv = match action.id.as_str() {
            "aido.svc.lifecycle" => vec![
                "--no-pager",
                "--no-ask-password",
                "restart",
                "nginx.service",
            ],
            "aido.svc.status" => vec!["--no-pager", "--full", "status", "nginx.service"],
            "aido.svc.show" => vec!["--no-pager", "show", "nginx.service"],
            "aido.svc.logs" => vec!["--no-pager", "-u", "nginx.service"],
            "aido.svc.reset-failed" => vec!["--no-pager", "reset-failed", "nginx.service"],
            "aido.svc.reload-units" => vec!["--no-pager", "daemon-reload"],
            "aido.dmesg" => vec!["--no-pager", "-k"],
            "aido.net.listeners" => vec!["-tulpnH"],
            "aido.pkg.install" => vec!["-y", "--no-install-recommends", "install", "--", "ripgrep"],
            "aido.pkg.update" => vec!["update"],
            "aido.pkg.remove" => vec!["-y", "remove", "--", "ripgrep"],
            "aido.pkg.dry-run-install" => vec!["-s", "install", "--", "ripgrep"],
            "aido.sysctl.max-map-count" => vec!["-q", "-w", "vm.max_map_count", "262144"],
            "aido.sysctl.inotify-watches" => {
                vec!["-q", "-w", "fs.inotify.max_user_watches", "524288"]
            }
            "aido.time.set-ntp" => vec!["set-ntp", "true"],
            other => panic!("shipped action {other} has no coverage in this test; add it"),
        };
        let d = aido_policy::evaluate(
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

#[test]
fn sysctl_rules_bound_the_value_and_refuse_the_dangerous_keys() {
    assert_eq!(
        verdict(
            "aido.sysctl.max-map-count",
            &["-q", "-w", "vm.max_map_count", "262144"]
        ),
        Verdict::Allow
    );
    // Below the declared floor.
    assert_eq!(
        denial(
            "aido.sysctl.max-map-count",
            &["-q", "-w", "vm.max_map_count", "1024"]
        ),
        Some(DenialCode::ArgvRejected)
    );
    // A different key entirely: kernel.core_pattern is a program specification.
    assert!(
        denial(
            "aido.sysctl.max-map-count",
            &["-q", "-w", "kernel.core_pattern", "|/tmp/x"]
        )
        .is_some()
    );
}

#[test]
fn a_file_driven_sysctl_form_is_refused() {
    for flag in ["-p", "--load", "--system"] {
        assert!(
            denial("aido.sysctl.max-map-count", &["-q", flag]).is_some(),
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
        assert_eq!(verdict("aido.svc.show", &argv), Verdict::Allow, "{argv:?}");
    }

    // The split spelling is a different argv, and the rule lists only the
    // joined one, so it is refused rather than silently unified. Canonicalization
    // does not rewrite argument content, by design.
    assert_eq!(
        denial(
            "aido.svc.show",
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
                "aido.svc.show",
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
id = "aido.joined"
tier = "diag-read"
exe = "/usr/bin/systemctl"
args = [{ name = "prop", matcher = { literal = "--property=ActiveState" } }]
"#,
    )
    .unwrap();
    let joined = aido_policy::evaluate(
        &set,
        &human(),
        &Request::new("aido.joined", Argv::new(vec!["--property=ActiveState"])),
        Settings::default(),
    );
    assert_eq!(joined.verdict, Verdict::Allow);

    let split = aido_policy::evaluate(
        &set,
        &human(),
        &Request::new("aido.joined", Argv::new(vec!["--property", "ActiveState"])),
        Settings::default(),
    );
    assert_eq!(split.denial, Some(DenialCode::ArgvRejected));
}

#[test]
fn the_fixed_argv_action_accepts_nothing_else() {
    assert_eq!(verdict("aido.net.listeners", &["-tulpnH"]), Verdict::Allow);
    for bad in [vec![], vec!["-tulpnH", "extra"], vec!["-e"]] {
        assert_eq!(
            denial("aido.net.listeners", &bad),
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
        denial("aido.svc.logs", &["-u", "nginx.service"]),
        Some(DenialCode::ArgvRejected)
    );
}
