//! Overlapping rules resolve to the strictest, through rule files loaded the
//! way every reader loads them.
//!
//! The attack: a ruleset holds a rule that confirms, and a second file — a
//! later edit, a package's drop-in, a paste — accepts the same command without
//! confirming. Until 2026-10-19 the first permitting action in declaration
//! order decided, so whichever file sorted first decided whether a human was
//! asked. Each test here tries one way to make the permissive rule win: sort
//! it first, sort it last, name it, combine it with a setting.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use aido_policy::decision::ConfirmReason;
use aido_policy::{
    ActionId, Arg, Argv, CallerFacts, Classification, Confirm, Decision, DenialCode, Request,
    RuleFile, RuleSet, Verdict, engine::Settings, evaluate, evaluate_command, load_rule_files,
};

/// A narrow rule: removing part of the toolchain always asks a human.
const CONFIRMING: &str = r#"
[[action]]
id = "aido.pkg.remove-toolchain"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { one-of = ["gcc", "make", "build-essential"] } },
]
"#;

/// A broad rule that accepts the same commands, and more, without confirming.
const PERMISSIVE: &str = r#"
[[action]]
id = "aido.pkg.remove-quick"
tier = "pkg-remove"
confirm = "never"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { name = "deb-name" }, repeat = { between = { min = 1, max = 10 } } },
]
"#;

/// The narrow rule again, reserved for a person instead of confirming.
const HUMAN_ONLY: &str = r#"
[[action]]
id = "aido.pkg.remove-by-hand"
tier = "pkg-remove"
agent-allowed = false
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { one-of = ["gcc", "make", "build-essential"] } },
]
"#;

/// The narrow rule as critical, its own `confirm` left at the default.
const CRITICAL: &str = r#"
[[action]]
id = "aido.pkg.remove-critical"
tier = "critical"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { one-of = ["gcc", "make", "build-essential"] } },
]
"#;

/// The critical rule again, also saying `always` — which must not demote it to
/// an ordinary always-confirming rule.
const CRITICAL_ALWAYS: &str = r#"
[[action]]
id = "aido.pkg.remove-critical-always"
tier = "critical"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { one-of = ["gcc", "make", "build-essential"] } },
]
"#;

fn load(files: &[(&str, &str)]) -> RuleSet {
    load_rule_files(
        files
            .iter()
            .map(|(name, contents)| RuleFile {
                name: name.as_bytes().to_vec(),
                bytes: contents.as_bytes().to_vec(),
            })
            .collect(),
    )
    .unwrap()
    .rules
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

fn apt_get() -> Arg {
    Arg::from("/usr/bin/apt-get")
}

fn remove(packages: &[&str]) -> Argv {
    let mut argv = vec!["-y", "remove", "--"];
    argv.extend_from_slice(packages);
    Argv::new(argv)
}

fn searched(rules: &RuleSet, caller: &CallerFacts, packages: &[&str]) -> Decision {
    evaluate_command(
        rules,
        caller,
        &apt_get(),
        &remove(packages),
        Settings::default(),
    )
}

fn named(rules: &RuleSet, caller: &CallerFacts, action: &str, packages: &[&str]) -> Decision {
    evaluate(
        rules,
        caller,
        &Request::for_program(action, apt_get(), remove(packages)),
        Settings::default(),
    )
}

fn always() -> Confirm {
    Confirm::Required {
        reason: ConfirmReason::RuleRequiresConfirmation,
    }
}

#[test]
fn a_critical_rule_outranks_an_ordinary_always_rule_whatever_its_own_confirm_says() {
    // Critical is the strictest requirement there is. A critical rule that
    // also says `always` once ranked as an ordinary always-confirming rule, so
    // an ordinary duplicate tied with it and was cited in its place. Every
    // declaration order, searched or named — including naming the duplicate
    // that never asks — must cite the critical rule with the critical reason.
    let critical = Confirm::Required {
        reason: ConfirmReason::CriticalTier,
    };
    for (critical_rule, critical_id) in [
        (CRITICAL, "aido.pkg.remove-critical"),
        (CRITICAL_ALWAYS, "aido.pkg.remove-critical-always"),
    ] {
        for order in [
            [CONFIRMING, critical_rule, PERMISSIVE],
            [critical_rule, CONFIRMING, PERMISSIVE],
            [PERMISSIVE, CONFIRMING, critical_rule],
            [PERMISSIVE, critical_rule, CONFIRMING],
        ] {
            let rules = load(&[
                ("10-a.toml", order[0]),
                ("20-b.toml", order[1]),
                ("30-c.toml", order[2]),
            ]);
            for caller in [human(), agent()] {
                for d in [
                    searched(&rules, &caller, &["gcc"]),
                    named(&rules, &caller, "aido.pkg.remove-toolchain", &["gcc"]),
                    named(&rules, &caller, "aido.pkg.remove-quick", &["gcc"]),
                ] {
                    assert_eq!(d.verdict, Verdict::AllowWithConfirmation, "{d:?}");
                    assert_eq!(d.confirm, critical, "{d:?}");
                    assert_eq!(d.action, Some(ActionId::new(critical_id)), "{d:?}");
                }
            }
        }
    }
}

#[test]
fn a_later_permissive_duplicate_cannot_weaken_an_earlier_confirming_rule() {
    let rules = load(&[
        ("10-toolchain.toml", CONFIRMING),
        ("90-quick.toml", PERMISSIVE),
    ]);
    let d = searched(&rules, &human(), &["gcc"]);
    assert_eq!(d.verdict, Verdict::AllowWithConfirmation);
    assert_eq!(d.confirm, always());
    assert_eq!(d.action, Some(ActionId::new("aido.pkg.remove-toolchain")));
}

#[test]
fn an_earlier_permissive_duplicate_cannot_weaken_a_later_confirming_rule() {
    // The order first-match got wrong: the permissive file sorts first.
    let rules = load(&[
        ("10-quick.toml", PERMISSIVE),
        ("90-toolchain.toml", CONFIRMING),
    ]);
    let d = searched(&rules, &human(), &["gcc"]);
    assert_eq!(d.verdict, Verdict::AllowWithConfirmation);
    assert_eq!(d.confirm, always());
    assert_eq!(d.action, Some(ActionId::new("aido.pkg.remove-toolchain")));
}

#[test]
fn reordering_rule_files_cannot_drop_a_confirmation() {
    // The same two rules under file names that sort both ways round. The
    // generation differs, because the files do; the answer does not, for the
    // command searched and for the command asked under either name.
    let forward = load(&[("10-a.toml", CONFIRMING), ("20-b.toml", PERMISSIVE)]);
    let backward = load(&[("10-a.toml", PERMISSIVE), ("20-b.toml", CONFIRMING)]);
    for caller in [human(), agent()] {
        let decisions = [
            searched(&forward, &caller, &["make"]),
            searched(&backward, &caller, &["make"]),
            named(&forward, &caller, "aido.pkg.remove-quick", &["make"]),
            named(&backward, &caller, "aido.pkg.remove-quick", &["make"]),
            named(&forward, &caller, "aido.pkg.remove-toolchain", &["make"]),
            named(&backward, &caller, "aido.pkg.remove-toolchain", &["make"]),
        ];
        for d in &decisions {
            assert_eq!(d.verdict, Verdict::AllowWithConfirmation, "{d:?}");
            assert_eq!(d.confirm, always(), "{d:?}");
            assert_eq!(d.action, Some(ActionId::new("aido.pkg.remove-toolchain")));
        }
    }
}

#[test]
fn naming_the_permissive_duplicate_cannot_skip_the_confirmation() {
    // The caller picks the action id. If a requirement bound only the named
    // action, an agent would simply name the one that does not confirm.
    let rules = load(&[
        ("10-toolchain.toml", CONFIRMING),
        ("90-quick.toml", PERMISSIVE),
    ]);
    let d = named(
        &rules,
        &agent(),
        "aido.pkg.remove-quick",
        &["build-essential"],
    );
    assert_eq!(d.verdict, Verdict::AllowWithConfirmation);
    assert_eq!(d.confirm, always());
}

#[test]
fn turning_the_agent_setting_off_does_not_combine_with_a_duplicate_to_skip_an_always_rule() {
    // `confirm_agent_actions = false` lifts the agent-path confirmation and
    // nothing else; the duplicate's `confirm = "never"` lifts nothing for a
    // command another rule always confirms.
    let rules = load(&[
        ("10-quick.toml", PERMISSIVE),
        ("90-toolchain.toml", CONFIRMING),
    ]);
    let off = Settings {
        confirm_agent_actions: false,
        frozen: false,
    };
    let d = evaluate_command(&rules, &agent(), &apt_get(), &remove(&["gcc"]), off);
    assert_eq!(d.confirm, always());
}

#[test]
fn a_permissive_duplicate_cannot_hand_a_human_only_command_to_an_agent() {
    for files in [
        [
            ("10-by-hand.toml", HUMAN_ONLY),
            ("90-quick.toml", PERMISSIVE),
        ],
        [
            ("10-quick.toml", PERMISSIVE),
            ("90-by-hand.toml", HUMAN_ONLY),
        ],
    ] {
        let rules = load(&files);
        assert_eq!(
            searched(&rules, &agent(), &["gcc"]).denial,
            Some(DenialCode::HumanPathOnly)
        );
        assert_eq!(
            named(&rules, &agent(), "aido.pkg.remove-quick", &["gcc"]).denial,
            Some(DenialCode::HumanPathOnly)
        );
        // Withheld from the agent only: a person is served, with nothing to
        // confirm, because neither rule asks for it on the human path.
        assert_eq!(searched(&rules, &human(), &["gcc"]).verdict, Verdict::Allow);
    }
}

#[test]
fn the_strictest_rule_binds_the_commands_it_accepts_and_no_others() {
    // Overlap resolution is per command. The broad rule still grants what the
    // narrow one never accepted — another package, or two at once — because
    // an allowlist is a union and the narrow rule says nothing about those
    // commands. `aido check` reports the overlap, so the operator can narrow
    // the broad rule if two at once was not meant.
    let rules = load(&[
        ("10-toolchain.toml", CONFIRMING),
        ("90-quick.toml", PERMISSIVE),
    ]);
    for packages in [&["ripgrep"][..], &["gcc", "make"][..]] {
        let d = searched(&rules, &human(), packages);
        assert_eq!(d.verdict, Verdict::Allow, "{packages:?}");
        assert_eq!(d.action, Some(ActionId::new("aido.pkg.remove-quick")));
    }
    let overlaps = rules.overlaps();
    assert_eq!(overlaps.len(), 1);
    assert_eq!(overlaps[0].first.id.as_str(), "aido.pkg.remove-toolchain");
}
