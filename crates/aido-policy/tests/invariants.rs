//! The standing invariants, expressed as properties rather than examples.
//!
//! These are the load-bearing security claims of the whole project. Each one is
//! stated in `CLAUDE.md` and must never be deleted: if an invariant here starts
//! failing, the design has been broken, not the test.
//!
//! Example tests check the cases an author thought of. These check the cases
//! nobody thought of, which is where a matcher bypass actually lives.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use aido_policy::{
    Action, ActionId, Arg, Argv, CallerFacts, Classification, Confirm, Decision, DenialCode, Hint,
    HintSource, Matcher, NameKind, Request, RuleFile, RuleSet, Source, Tier, Verdict,
    decision::ConfirmReason,
    engine::Settings,
    evaluate_command, load_rule_files,
    matcher::{AnchoredPattern, ArgSpec, Repeat, match_argv},
    overlap::Extent,
    rule::ConfirmPolicy,
};
use proptest::prelude::*;

/// An argv built from a mixed alphabet: plausible operands, flag shapes,
/// separators, and bytes that are not valid UTF-8.
fn arb_argv() -> impl Strategy<Value = Argv> {
    let token = prop_oneof![
        Just(Arg::from("restart")),
        Just(Arg::from("install")),
        Just(Arg::from("-y")),
        Just(Arg::from("--")),
        Just(Arg::from("--signal=SIGHUP")),
        Just(Arg::from("nginx.service")),
        Just(Arg::from("ripgrep")),
        Just(Arg::from("/etc/sudoers")),
        Just(Arg::from("./local.deb")),
        Just(Arg::from("..")),
        Just(Arg::from("")),
        Just(Arg::new(vec![0xff, 0xfe])),
        "[a-z.=/-]{0,12}".prop_map(|s| Arg::from(s.as_str())),
    ];
    prop::collection::vec(token, 0..8).prop_map(Argv::new)
}

fn arb_specs() -> impl Strategy<Value = Vec<ArgSpec>> {
    let spec = prop_oneof![
        Just(ArgSpec::one("verb", Matcher::Literal("restart".into()))),
        Just(ArgSpec::one("unit", Matcher::Name(NameKind::UnitName))),
        Just(ArgSpec::repeated(
            "pkg",
            Matcher::Name(NameKind::DebName),
            Repeat::Between { min: 1, max: 4 },
        )),
        Just(ArgSpec::repeated(
            "flag",
            Matcher::Literal("-y".into()),
            Repeat::Optional
        )),
        Just(ArgSpec::one(
            "port",
            Matcher::IntRange { lo: 1, hi: 65_535 }
        )),
        Just(ArgSpec::one(
            "path",
            Matcher::PathUnder {
                prefix: "/opt".into()
            }
        )),
    ];
    // Positions must have distinct names for a ruleset to load, so build the
    // list and then de-duplicate by name rather than rejecting samples.
    prop::collection::vec(spec, 0..4).prop_map(|specs| {
        let mut seen: Vec<String> = Vec::new();
        specs
            .into_iter()
            .filter(|s| {
                let fresh = !seen.contains(&s.name);
                if fresh {
                    seen.push(s.name.clone());
                }
                fresh
            })
            .collect()
    })
}

fn arb_exe() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/usr/bin/systemctl".to_owned()),
        Just("/usr/bin/apt-get".to_owned()),
        Just("/usr/bin/journalctl".to_owned()),
        // Deliberately included: an operator's mistake must be caught, not
        // assumed away.
        Just("/bin/sh".to_owned()),
        Just("/usr/bin/tee".to_owned()),
        Just("/usr/bin/python3".to_owned()),
    ]
}

fn arb_tier() -> impl Strategy<Value = Tier> {
    prop_oneof![
        Just(Tier::DiagRead),
        Just(Tier::SvcControl),
        Just(Tier::PkgInstall),
        Just(Tier::PkgRemove),
        Just(Tier::SysTunable),
        Just(Tier::NetFilter),
        Just(Tier::Critical),
    ]
}

fn arb_confirm() -> impl Strategy<Value = ConfirmPolicy> {
    prop_oneof![
        Just(ConfirmPolicy::Default),
        Just(ConfirmPolicy::Always),
        Just(ConfirmPolicy::Never),
    ]
}

prop_compose! {
    fn arb_action(id: &'static str)(
        tier in arb_tier(),
        exe in arb_exe(),
        args in arb_specs(),
        confirm in arb_confirm(),
        agent_allowed in any::<bool>(),
    ) -> Action {
        // A critical tier may not opt out of confirmation; keep the generator
        // inside what `RuleSet::load` accepts so the properties exercise the
        // engine rather than the loader.
        let confirm = if tier == Tier::Critical && confirm == ConfirmPolicy::Never {
            ConfirmPolicy::Always
        } else {
            confirm
        };
        Action {
            id: ActionId::new(id),
            tier,
            exe,
            args,
            confirm,
            agent_allowed,
            env_allow: Vec::new(),
            source: Source::new("generated.toml", 1),
        }
    }
}

fn caller(agent: bool, hints: Vec<Hint>) -> CallerFacts {
    let classification = if agent {
        Classification::EnrolledAgent {
            agent_id: "claude-code".into(),
            session_id: "s-1".into(),
            declared_yolo: true,
        }
    } else {
        Classification::Human
    };
    CallerFacts {
        classification,
        uid: 1000,
        project_root: None,
        hints,
    }
}

fn decide(action: &Action, argv: &Argv, agent: bool, hints: Vec<Hint>) -> Decision {
    let rules = RuleSet::load(vec![action.clone()]).unwrap();
    aido_policy::evaluate(
        &rules,
        &caller(agent, hints),
        &Request::new(action.id.clone(), argv.clone()),
        Settings::default(),
    )
}

/// Decides a request that names `program` as the binary to run.
fn decide_program(action: &Action, program: &str, argv: &Argv) -> Decision {
    let rules = RuleSet::load(vec![action.clone()]).unwrap();
    aido_policy::evaluate(
        &rules,
        &caller(false, Vec::new()),
        &Request::for_program(action.id.clone(), program, argv.clone()),
        Settings::default(),
    )
}

proptest! {
    /// Naming a program can only narrow.
    ///
    /// The program check was added after the argv matcher, so it has to be
    /// provably subtractive: if a request that names a binary is permitted, the
    /// same request without one must have been permitted too. Anything else
    /// would mean naming a binary *unlocked* something, which is the shape of a
    /// bypass rather than a check.
    #[test]
    fn naming_a_program_never_turns_a_deny_into_an_allow(
        action in arb_action("a.b"),
        argv in arb_argv(),
        program in arb_exe(),
    ) {
        let named = decide_program(&action, &program, &argv);
        if named.verdict != Verdict::Allow {
            return Ok(());
        }
        let unnamed = decide(&action, &argv, false, Vec::new());
        prop_assert_eq!(unnamed.verdict, Verdict::Allow);
    }

    /// A program that is not the rule's own is always refused.
    ///
    /// Byte-exact, so no generated path — however plausibly it resolves to the
    /// same file — can pass for the one the rule names.
    #[test]
    fn only_the_rules_own_program_is_ever_accepted(
        action in arb_action("a.b"),
        argv in arb_argv(),
        program in arb_exe(),
    ) {
        if program.as_bytes() == action.exe.as_bytes() {
            return Ok(());
        }
        let decision = decide_program(&action, &program, &argv);
        prop_assert_eq!(decision.verdict, Verdict::Deny);
        prop_assert_eq!(decision.denial, Some(DenialCode::ExeMismatch));
    }

    /// Invariant 5: canonicalization is idempotent.
    ///
    /// If it were not, the tuple the matcher checked could differ from the
    /// tuple the deny-list checked.
    #[test]
    fn canonicalization_is_idempotent(argv in arb_argv()) {
        let once = argv.canonicalize();
        prop_assert_eq!(once.canonicalize(), once);
    }

    /// Canonicalization never loses information about how many operands follow
    /// a separator, which is what stops a rule from seeing a different operand
    /// count than the kernel will.
    #[test]
    fn canonicalization_never_shrinks_below_the_operand_count(argv in arb_argv()) {
        let canonical = argv.canonicalize();
        let operands = argv
            .as_slice()
            .iter()
            .filter(|a| a.as_bytes() != b"--")
            .count();
        prop_assert!(canonical.len() >= operands.saturating_sub(1));
    }

    /// Invariant 2: hints carry zero weight.
    ///
    /// This is the property that makes "agent detection is not a security
    /// boundary" a checkable claim rather than a comment. A forged
    /// `CLAUDECODE=1` must not move a verdict in any direction.
    #[test]
    fn hints_never_change_the_verdict(
        action in arb_action("a.b"),
        argv in arb_argv(),
        agent in any::<bool>(),
    ) {
        let bare = decide(&action, &argv, agent, Vec::new());
        let forged = decide(&action, &argv, agent, vec![
            Hint::new(HintSource::Environment, "CLAUDECODE", "1"),
            Hint::new(HintSource::Environment, "AI_AGENT", "claude"),
            Hint::new(HintSource::Comm, "comm", "claude"),
            Hint::new(HintSource::AncestorExe, "exe", "/usr/bin/claude"),
            Hint::new(HintSource::Cmdline, "cmdline", "claude --dangerously-skip-permissions"),
            Hint::new(HintSource::ControllingTty, "tty", "none"),
        ]);
        prop_assert_eq!(bare.verdict, forged.verdict);
        prop_assert_eq!(bare.confirm, forged.confirm);
        prop_assert_eq!(bare.denial, forged.denial);
    }

    /// Invariant 1: deny always wins.
    ///
    /// Whenever the compiled-in list matches the tuple that would be executed,
    /// the verdict is a denial — no matter what the rule said, what tier it is
    /// in, or who is asking.
    #[test]
    fn deny_list_always_wins(
        action in arb_action("a.b"),
        argv in arb_argv(),
        agent in any::<bool>(),
    ) {
        let canonical = argv.canonicalize();
        let findings = aido_policy::evaluate_deny_list(action.exe.as_bytes(), &canonical);
        let decision = decide(&action, &argv, agent, Vec::new());

        if !findings.is_empty() && decision.verdict != Verdict::Deny {
            // The only way a deny-listed tuple escapes is by never reaching the
            // deny-list, which happens when an earlier check already denied.
            prop_assert_eq!(decision.verdict, Verdict::Deny);
        }
        if decision.verdict.is_permitted() {
            prop_assert!(
                findings.is_empty(),
                "permitted a deny-listed tuple: {:?} {:?}",
                action.exe,
                findings
            );
        }
    }

    /// Invariant 3: appending an argument never widens.
    ///
    /// Extending an argv may turn an allow into a deny; it must never turn a
    /// deny into an allow. The classic argument-injection bug is exactly the
    /// forbidden direction.
    #[test]
    fn appending_an_argument_never_turns_a_deny_into_an_allow(
        action in arb_action("a.b"),
        argv in arb_argv(),
        extra in arb_argv(),
        agent in any::<bool>(),
    ) {
        let before = decide(&action, &argv, agent, Vec::new());
        if before.verdict != Verdict::Deny {
            return Ok(());
        }
        // Appending cannot rescue a denial that was about the deny-list, the
        // caller, or an unknown action. It *can* legitimately change an
        // argv-shape denial into a match, so that one case is excluded.
        if before.denial == Some(DenialCode::ArgvRejected) {
            return Ok(());
        }
        let mut longer: Vec<Arg> = argv.as_slice().to_vec();
        longer.extend(extra.as_slice().iter().cloned());
        let after = decide(&action, &Argv::new(longer), agent, Vec::new());
        prop_assert_eq!(after.verdict, Verdict::Deny);
    }

    /// Invariant 4: rule order cannot rescue a deny.
    ///
    /// Reordering a ruleset may change which rule matched; it must never change
    /// whether the request was denied.
    #[test]
    fn rule_order_does_not_change_a_deny(
        first in arb_action("a.one"),
        second in arb_action("a.two"),
        argv in arb_argv(),
        agent in any::<bool>(),
        ask_for_first in any::<bool>(),
    ) {
        let forward = RuleSet::load(vec![first.clone(), second.clone()]).unwrap();
        let reverse = RuleSet::load(vec![second.clone(), first.clone()]).unwrap();
        let wanted = if ask_for_first { first.id.clone() } else { second.id.clone() };
        let request = Request::new(wanted, argv);
        let facts = caller(agent, Vec::new());

        let a = aido_policy::evaluate(&forward, &facts, &request, Settings::default());
        let b = aido_policy::evaluate(&reverse, &facts, &request, Settings::default());
        prop_assert_eq!(a.verdict, b.verdict);
        prop_assert_eq!(a.denial, b.denial);
    }

    /// The agent path is never broader than the human path.
    ///
    /// For the same rule and argv, anything permitted to an agent is permitted
    /// to a human, and an agent never gets a *weaker* confirmation requirement.
    #[test]
    fn the_agent_path_is_never_broader_than_the_human_path(
        action in arb_action("a.b"),
        argv in arb_argv(),
    ) {
        let as_agent = decide(&action, &argv, true, Vec::new());
        let as_human = decide(&action, &argv, false, Vec::new());

        if as_agent.verdict.is_permitted() {
            prop_assert!(
                as_human.verdict.is_permitted(),
                "an agent was permitted something a human was not: {as_agent:?} vs {as_human:?}"
            );
        }
        if as_human.confirm != as_agent.confirm {
            // The only permitted asymmetry: the agent needs confirmation where
            // the human does not.
            prop_assert!(
                matches!(as_agent.confirm, aido_policy::Confirm::Required { .. })
                    || !as_agent.verdict.is_permitted(),
                "the agent path was laxer: {as_agent:?} vs {as_human:?}"
            );
        }
    }

    /// A yolo declaration never removes a confirmation.
    #[test]
    fn declared_yolo_never_removes_a_confirmation(
        action in arb_action("a.b"),
        argv in arb_argv(),
    ) {
        let rules = RuleSet::load(vec![action.clone()]).unwrap();
        let request = Request::new(action.id.clone(), argv);
        let quiet = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "claude-code".into(),
                session_id: "s".into(),
                declared_yolo: false,
            },
            1000,
        );
        let yolo = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "claude-code".into(),
                session_id: "s".into(),
                declared_yolo: true,
            },
            1000,
        );
        let a = aido_policy::evaluate(&rules, &quiet, &request, Settings::default());
        let b = aido_policy::evaluate(&rules, &yolo, &request, Settings::default());
        prop_assert_eq!(a.confirm, b.confirm);
        prop_assert_eq!(a.verdict, b.verdict);
    }

    /// Every denial carries a code and a next step.
    ///
    /// An agent that cannot tell why it was refused escalates to the human,
    /// which is the failure mode the envelope exists to prevent.
    #[test]
    fn every_denial_is_actionable(
        action in arb_action("a.b"),
        argv in arb_argv(),
        agent in any::<bool>(),
    ) {
        let d = decide(&action, &argv, agent, Vec::new());
        if d.verdict == Verdict::Deny {
            prop_assert!(d.denial.is_some());
            prop_assert!(d.remediation.is_some());
            prop_assert!(!d.trace.is_empty());
        } else {
            prop_assert!(d.denial.is_none());
            prop_assert!(d.remediation.is_none());
        }
    }

    /// The engine never panics, on any input it can be handed.
    ///
    /// A panic in the broker is a denial of service; a panic in the gate is
    /// undefined policy. Neither is acceptable, so this is checked over the
    /// whole generated space rather than argued about.
    #[test]
    fn evaluation_never_panics(
        action in arb_action("a.b"),
        argv in arb_argv(),
        agent in any::<bool>(),
        frozen in any::<bool>(),
        confirm_agent_actions in any::<bool>(),
    ) {
        let rules = RuleSet::load(vec![action.clone()]).unwrap();
        let settings = Settings { confirm_agent_actions, frozen };
        let d = aido_policy::evaluate(
            &rules,
            &caller(agent, Vec::new()),
            &Request::new(action.id.clone(), argv),
            settings,
        );
        // A frozen agent path always denies, whatever else is true.
        if frozen && agent {
            prop_assert_eq!(d.denial, Some(DenialCode::Frozen));
        }
    }

    /// The generation is a function of the files, never of the order a reader
    /// happened to list them in.
    ///
    /// The broker and the gate each list the rules directory themselves. If
    /// order leaked into the generation, a request minted by one would read as
    /// stale to the other for no reason but readdir order; if names and
    /// contents could run together, two different rulesets could share one.
    #[test]
    fn the_generation_depends_on_the_files_not_on_their_read_order(
        files in prop::collection::btree_map("[a-z0-9-]{1,8}", "#[ -~]{0,16}", 0..6),
        rotate in 0usize..6,
    ) {
        let as_files = |pairs: &[(String, String)]| -> Vec<RuleFile> {
            pairs
                .iter()
                .map(|(name, text)| RuleFile {
                    name: format!("{name}.toml").into_bytes(),
                    bytes: text.clone().into_bytes(),
                })
                .collect()
        };
        let mut pairs: Vec<(String, String)> = files.into_iter().collect();
        let sorted = load_rule_files(as_files(&pairs)).unwrap().generation;
        let by = rotate.min(pairs.len());
        pairs.rotate_left(by);
        pairs.reverse();
        prop_assert_eq!(load_rule_files(as_files(&pairs)).unwrap().generation, sorted);
    }
}

// --- overlapping actions -----------------------------------------------------
//
// The generators below draw from a small vocabulary that overlaps itself on
// purpose — literals and enumerations sharing members, ranges sharing values,
// nested prefixes, name kinds, patterns — over two programs, and ask about
// commands sampled from the actions themselves, so that most cases exercise
// two or more actions accepting one command rather than none.

/// Two programs most of the time, and a shell, so the deny-list takes part.
fn arb_shared_exe() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => Just("/usr/bin/systemctl".to_owned()),
        4 => Just("/usr/bin/apt-get".to_owned()),
        1 => Just("/bin/sh".to_owned()),
    ]
}

fn arb_overlapping_matcher() -> impl Strategy<Value = Matcher> {
    prop_oneof![
        Just(Matcher::Literal("restart".into())),
        Just(Matcher::Literal("-y".into())),
        Just(Matcher::Literal("--".into())),
        Just(Matcher::Literal("80".into())),
        Just(Matcher::Literal("a.service".into())),
        Just(Matcher::OneOf(vec!["restart".into(), "stop".into()])),
        Just(Matcher::OneOf(vec!["-y".into(), "--yes".into()])),
        Just(Matcher::IntRange { lo: 1, hi: 100 }),
        Just(Matcher::IntRange { lo: -5, hi: 5 }),
        Just(Matcher::IntRange { lo: 100, hi: 200 }),
        Just(Matcher::PathUnder {
            prefix: "/opt".into()
        }),
        Just(Matcher::PathUnder {
            prefix: "/opt/a".into()
        }),
        Just(Matcher::PathUnder { prefix: "/".into() }),
        Just(Matcher::Name(NameKind::DebName)),
        Just(Matcher::Name(NameKind::UnitName)),
        Just(Matcher::Name(NameKind::Hostname)),
        Just(Matcher::Pattern(AnchoredPattern::new("[a-z]+").unwrap())),
        Just(Matcher::Pattern(AnchoredPattern::new("[0-9]+").unwrap())),
        Just(Matcher::Pattern(
            AnchoredPattern::new("[a-z]+\\.service").unwrap()
        )),
        // Patterns that overlap other matchers without sharing any probe with
        // them, which is exactly where an analysis tempted to call "no probe
        // matched" disjoint would go silent.
        Just(Matcher::Pattern(AnchoredPattern::new("[a-z.]+").unwrap())),
        Just(Matcher::Pattern(AnchoredPattern::new("[a-z0-9]+").unwrap())),
        Just(Matcher::Pattern(AnchoredPattern::new("/opt/.+").unwrap())),
    ]
}

fn arb_overlapping_repeat() -> impl Strategy<Value = Repeat> {
    prop_oneof![
        Just(Repeat::One),
        Just(Repeat::Optional),
        Just(Repeat::Between { min: 0, max: 2 }),
        Just(Repeat::Between { min: 1, max: 3 }),
    ]
}

fn arb_overlapping_specs() -> impl Strategy<Value = Vec<ArgSpec>> {
    prop::collection::vec((arb_overlapping_matcher(), arb_overlapping_repeat()), 0..4).prop_map(
        |specs| {
            specs
                .into_iter()
                .enumerate()
                .map(|(i, (matcher, repeat))| ArgSpec::repeated(format!("p{i}"), matcher, repeat))
                .collect()
        },
    )
}

/// Arguments the vocabulary above accepts, and some it does not.
const TOKENS: &[&str] = &[
    "restart",
    "stop",
    "-y",
    "--yes",
    "--",
    "---",
    "80",
    "5",
    "-3",
    "0",
    "150",
    "/opt/a",
    "/opt/a/b",
    "/opt/b",
    "/etc/x",
    "a.service",
    "nginx.service",
    "ripgrep",
    "a",
    "",
];

fn arb_tokens() -> impl Strategy<Value = Argv> {
    prop::collection::vec(prop::sample::select(TOKENS), 0..6).prop_map(Argv::new)
}

/// An action's program, arguments, and requirements, before it has an id.
type Parts = (String, Vec<ArgSpec>, Tier, ConfirmPolicy, bool);

fn arb_parts() -> impl Strategy<Value = Parts> {
    (
        arb_shared_exe(),
        arb_overlapping_specs(),
        arb_tier(),
        arb_confirm(),
        any::<bool>(),
    )
}

fn assemble(id: &str, (exe, args, tier, confirm, agent_allowed): Parts) -> Action {
    let confirm = if tier == Tier::Critical && confirm == ConfirmPolicy::Never {
        ConfirmPolicy::Always
    } else {
        confirm
    };
    Action {
        id: ActionId::new(id),
        tier,
        exe,
        args,
        confirm,
        agent_allowed,
        env_allow: Vec::new(),
        source: Source::new("generated.toml", 1),
    }
}

/// One to `max` actions with distinct ids, in declaration order.
fn arb_ruleset(max: usize) -> impl Strategy<Value = Vec<Action>> {
    prop::collection::vec(arb_parts(), 1..=max).prop_map(|parts| {
        parts
            .into_iter()
            .enumerate()
            .map(|(i, part)| assemble(&format!("r.{i}"), part))
            .collect()
    })
}

/// Operands `specs` accepts, built from [`TOKENS`] by `choices`: a count within
/// each position's bounds, at most three, and tokens its matcher accepts.
fn sample(specs: &[ArgSpec], choices: &[u8]) -> Argv {
    let mut picks = choices.iter().copied().map(usize::from).cycle();
    let mut argv: Vec<&str> = Vec::new();
    for spec in specs {
        let (min, max) = match spec.repeat {
            Repeat::One => (1, 1),
            Repeat::Optional => (0, 1),
            Repeat::Between { min, max } => (min, max.min(min + 2)),
        };
        let count = min + picks.next().unwrap_or(0) % (max - min + 1);
        let accepted: Vec<&str> = TOKENS
            .iter()
            .copied()
            .filter(|token| spec.matcher.accepts(&Arg::from(*token)))
            .collect();
        if accepted.is_empty() {
            continue;
        }
        for _ in 0..count {
            argv.push(accepted[picks.next().unwrap_or(0) % accepted.len()]);
        }
    }
    Argv::new(argv)
}

/// A command to ask about: one action's program, with operands that action
/// accepts or, when `sampled` is false, arbitrary ones.
fn command_for(
    actions: &[Action],
    pick: usize,
    choices: &[u8],
    random: &Argv,
    sampled: bool,
) -> (Arg, Argv) {
    let action = &actions[pick % actions.len()];
    let argv = if sampled {
        sample(&action.args, choices)
    } else {
        random.clone()
    };
    (Arg::from(action.exe.as_str()), argv)
}

/// How strict a decision is about a command some action accepted, or `None`
/// when no action did, in which case there is no requirement to weaken.
fn severity(decision: &Decision) -> Option<u8> {
    let rank = |reason: ConfirmReason| match reason {
        ConfirmReason::AgentActionsConfirmed => 1,
        ConfirmReason::RuleRequiresConfirmation => 2,
        ConfirmReason::CriticalTier => 3,
    };
    match (decision.verdict, decision.denial, &decision.confirm) {
        (Verdict::Allow, _, _) => Some(0),
        (Verdict::AllowWithConfirmation, _, Confirm::Required { reason }) => {
            Some(1 + rank(*reason))
        }
        (
            Verdict::Deny,
            Some(DenialCode::HumanPathOnly | DenialCode::DenyListed | DenialCode::Frozen),
            _,
        ) => Some(10),
        _ => None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Invariant 6: adding a rule never removes a confirmation.
    ///
    /// Must never be deleted. A rule can grant a command no rule accepted
    /// before; for a command some rule already accepts, adding another can only
    /// make the answer stricter — never drop a confirmation, never lift a
    /// human-only reservation or a deny-list hit. Checked for the command
    /// searched across the ruleset and for the command asked under every name.
    /// The new rule lands anywhere in declaration order, as a new rule file
    /// sorts wherever its name puts it: appended only at the end, it would
    /// never test the first-match failure this property exists for.
    #[test]
    fn adding_a_rule_never_removes_a_confirmation(
        rules in arb_ruleset(4),
        extra in arb_parts(),
        insert_at in any::<usize>(),
        pick in any::<usize>(),
        choices in prop::collection::vec(any::<u8>(), 8),
        random in arb_tokens(),
        sampled in prop::bool::weighted(0.8),
        agent in any::<bool>(),
        confirm_agent_actions in any::<bool>(),
        frozen in prop::bool::weighted(0.1),
    ) {
        let mut grown = rules.clone();
        grown.insert(insert_at % (rules.len() + 1), assemble("r.extra", extra));
        let (program, argv) = command_for(&grown, pick, &choices, &random, sampled);
        let before = RuleSet::load(rules.clone()).unwrap();
        let after = RuleSet::load(grown).unwrap();
        let facts = caller(agent, Vec::new());
        let settings = Settings { confirm_agent_actions, frozen };

        let then = evaluate_command(&before, &facts, &program, &argv, settings);
        let now = evaluate_command(&after, &facts, &program, &argv, settings);
        if then.verdict == Verdict::AllowWithConfirmation {
            prop_assert_ne!(now.verdict, Verdict::Allow, "a confirmation was removed: {:?} then {:?}", then, now);
        }
        if let Some(strictness) = severity(&then) {
            prop_assert!(severity(&now) >= Some(strictness), "weakened: {:?} then {:?}", then, now);
        }

        for action in &rules {
            let request = Request::for_program(action.id.clone(), program.clone(), argv.clone());
            let then = aido_policy::evaluate(&before, &facts, &request, settings);
            let now = aido_policy::evaluate(&after, &facts, &request, settings);
            if let Some(strictness) = severity(&then) {
                prop_assert!(severity(&now) >= Some(strictness), "weakened under {}: {:?} then {:?}", action.id, then, now);
            }
        }
    }

    /// Invariant 6, its twin: rule order never changes whether a confirmation
    /// is demanded.
    ///
    /// Must never be deleted. Reordering may change which of two equally
    /// strict actions a decision cites, and nothing else: not the verdict, not
    /// the denial, not the requirement or its reason.
    #[test]
    fn rule_order_never_changes_whether_a_confirmation_is_demanded(
        (rules, reordered) in arb_ruleset(5).prop_flat_map(|rules| (Just(rules.clone()), Just(rules).prop_shuffle())),
        pick in any::<usize>(),
        choices in prop::collection::vec(any::<u8>(), 8),
        random in arb_tokens(),
        sampled in prop::bool::weighted(0.8),
        agent in any::<bool>(),
        confirm_agent_actions in any::<bool>(),
    ) {
        let (program, argv) = command_for(&rules, pick, &choices, &random, sampled);
        let forward = RuleSet::load(rules.clone()).unwrap();
        let shuffled = RuleSet::load(reordered).unwrap();
        let facts = caller(agent, Vec::new());
        let settings = Settings { confirm_agent_actions, frozen: false };

        let a = evaluate_command(&forward, &facts, &program, &argv, settings);
        let b = evaluate_command(&shuffled, &facts, &program, &argv, settings);
        prop_assert_eq!(a.verdict, b.verdict);
        prop_assert_eq!(&a.confirm, &b.confirm);
        prop_assert_eq!(a.denial, b.denial);

        for action in &rules {
            let request = Request::for_program(action.id.clone(), program.clone(), argv.clone());
            let a = aido_policy::evaluate(&forward, &facts, &request, settings);
            let b = aido_policy::evaluate(&shuffled, &facts, &request, settings);
            prop_assert_eq!(a.verdict, b.verdict);
            prop_assert_eq!(&a.confirm, &b.confirm);
            prop_assert_eq!(a.denial, b.denial);
        }
    }

    /// The caller cannot choose the weakest rule by naming it.
    ///
    /// Whichever action that accepts a command the request names, the
    /// decision is the one the ruleset reaches for the command as a whole.
    #[test]
    fn naming_an_overlapping_action_never_weakens_the_decision(
        rules in arb_ruleset(4),
        pick in any::<usize>(),
        choices in prop::collection::vec(any::<u8>(), 8),
        random in arb_tokens(),
        sampled in prop::bool::weighted(0.8),
        agent in any::<bool>(),
        confirm_agent_actions in any::<bool>(),
        frozen in prop::bool::weighted(0.1),
    ) {
        let (program, argv) = command_for(&rules, pick, &choices, &random, sampled);
        let set = RuleSet::load(rules.clone()).unwrap();
        let facts = caller(agent, Vec::new());
        let settings = Settings { confirm_agent_actions, frozen };
        let whole = evaluate_command(&set, &facts, &program, &argv, settings);

        for action in &rules {
            let named = aido_policy::evaluate(
                &set,
                &facts,
                &Request::for_program(action.id.clone(), program.clone(), argv.clone()),
                settings,
            );
            // Only an action that accepts the command speaks for it.
            if matches!(named.denial, Some(DenialCode::ArgvRejected | DenialCode::ExeMismatch)) {
                continue;
            }
            prop_assert_eq!(named.verdict, whole.verdict, "under {}", action.id);
            prop_assert_eq!(&named.confirm, &whole.confirm, "under {}", action.id);
            prop_assert_eq!(named.denial, whole.denial, "under {}", action.id);
        }
    }

    /// Invariant 1 again, across overlapping actions: whatever accepts a
    /// command, a deny-listed one is never permitted.
    #[test]
    fn deny_list_always_wins_over_every_overlapping_rule(
        rules in arb_ruleset(4),
        pick in any::<usize>(),
        choices in prop::collection::vec(any::<u8>(), 8),
        random in arb_tokens(),
        sampled in prop::bool::weighted(0.8),
        agent in any::<bool>(),
    ) {
        let (program, argv) = command_for(&rules, pick, &choices, &random, sampled);
        let set = RuleSet::load(rules).unwrap();
        let decision = evaluate_command(&set, &caller(agent, Vec::new()), &program, &argv, Settings::default());
        if !aido_policy::evaluate_deny_list(program.as_bytes(), &argv.canonicalize()).is_empty() {
            prop_assert!(!decision.verdict.is_permitted(), "permitted a deny-listed command: {:?}", decision);
        }
    }

    /// `aido check` never misses an overlap, and never invents a witness.
    ///
    /// Whenever both of two actions accept a canonical command, the overlap
    /// report names the pair, certain or possible. Every certain report's
    /// witness is canonical and accepted by both. Silence must mean disjoint.
    #[test]
    fn the_overlap_report_never_misses_a_pair_that_can_accept_one_command(
        first in arb_overlapping_specs(),
        second in arb_overlapping_specs(),
        from_second in any::<bool>(),
        choices in prop::collection::vec(any::<u8>(), 8),
        random in arb_tokens(),
        sampled in prop::bool::weighted(0.8),
    ) {
        let argv = if !sampled {
            random
        } else if from_second {
            sample(&second, &choices)
        } else {
            sample(&first, &choices)
        }
        .canonicalize();
        let accepted_by_both = match_argv(&first, &argv).is_ok() && match_argv(&second, &argv).is_ok();
        let set = RuleSet::load(vec![
            assemble("o.first", ("/usr/bin/x".to_owned(), first, Tier::DiagRead, ConfirmPolicy::Default, true)),
            assemble("o.second", ("/usr/bin/x".to_owned(), second, Tier::DiagRead, ConfirmPolicy::Default, true)),
        ])
        .unwrap();
        let overlaps = set.overlaps();
        if accepted_by_both {
            prop_assert_eq!(overlaps.len(), 1, "missed: both accept {:?}", argv);
        }
        for overlap in &overlaps {
            if let Extent::Certain { witness } = &overlap.extent {
                prop_assert_eq!(&witness.canonicalize(), witness);
                prop_assert!(match_argv(&overlap.first.args, witness).is_ok());
                prop_assert!(match_argv(&overlap.second.args, witness).is_ok());
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// No pair of matchers that can hold one argument is ever called disjoint.
    ///
    /// The overlap analysis rests on deciding, position by position, whether
    /// two matchers share an argument. This asks it directly, one position
    /// each, over every pairing of the vocabulary and arguments drawn from both
    /// the shared token list and arbitrary bytes.
    #[test]
    fn no_two_matchers_that_share_an_argument_are_called_disjoint(
        first in arb_overlapping_matcher(),
        second in arb_overlapping_matcher(),
        token in prop_oneof![
            3 => prop::sample::select(TOKENS).prop_map(Arg::from),
            1 => "[a-z0-9./-]{0,10}".prop_map(|s| Arg::from(s.as_str())),
        ],
    ) {
        if !(first.accepts(&token) && second.accepts(&token)) {
            return Ok(());
        }
        let set = RuleSet::load(vec![
            assemble("m.first", ("/usr/bin/x".to_owned(), vec![ArgSpec::one("a", first)], Tier::DiagRead, ConfirmPolicy::Default, true)),
            assemble("m.second", ("/usr/bin/x".to_owned(), vec![ArgSpec::one("b", second)], Tier::DiagRead, ConfirmPolicy::Default, true)),
        ])
        .unwrap();
        prop_assert_eq!(set.overlaps().len(), 1, "both accept {:?}", token);
    }

    /// The same, with range bounds and path prefixes drawn at random, so the
    /// shapes the exact arms of the analysis argue about — a root prefix, a
    /// doubled or trailing slash, a range at the edge of `i64`, a range that
    /// crosses zero — come up constantly rather than by luck.
    #[test]
    fn no_ranges_or_prefixes_that_share_an_argument_are_called_disjoint(
        first in arb_parametric_matcher(),
        second in arb_parametric_matcher(),
        token in prop_oneof![
            2 => (-30i64..30).prop_map(|v| Arg::new(v.to_string())),
            1 => Just(Arg::from("-0")),
            1 => Just(Arg::new(i64::MAX.to_string())),
            1 => Just(Arg::new((-i64::MAX).to_string())),
            4 => (prop::sample::select(PREFIXES), prop::sample::select(SUFFIXES))
                .prop_map(|(prefix, rest)| Arg::new(format!("{prefix}{rest}"))),
            1 => prop::sample::select(TOKENS).prop_map(Arg::from),
        ],
    ) {
        if !(first.accepts(&token) && second.accepts(&token)) {
            return Ok(());
        }
        let set = RuleSet::load(vec![
            assemble("m.first", ("/usr/bin/x".to_owned(), vec![ArgSpec::one("a", first)], Tier::DiagRead, ConfirmPolicy::Default, true)),
            assemble("m.second", ("/usr/bin/x".to_owned(), vec![ArgSpec::one("b", second)], Tier::DiagRead, ConfirmPolicy::Default, true)),
        ])
        .unwrap();
        prop_assert_eq!(set.overlaps().len(), 1, "both accept {:?}", token);
    }
}

/// Path prefixes in the shapes `path_is_under` treats specially.
const PREFIXES: &[&str] = &[
    "/",
    "//",
    "/opt",
    "/opt/",
    "/opt//",
    "/opt/a",
    "/o",
    "/opt/../x",
    "/opt/a/",
];

/// What can follow a prefix: nothing, a bare or doubled slash, a child.
const SUFFIXES: &[&str] = &["", "/", "//", "/x", "//x", "/a/b", "x", "/..", "/./y"];

/// Integer ranges with random bounds, path prefixes of every awkward shape,
/// and the name kinds, which both of those are argued against.
fn arb_parametric_matcher() -> impl Strategy<Value = Matcher> {
    let bound = prop_oneof![
        8 => -30i64..30,
        1 => Just(i64::MIN),
        1 => Just(i64::MAX),
        1 => Just(-i64::MAX),
    ];
    prop_oneof![
        2 => (bound.clone(), bound).prop_map(|(lo, hi)| Matcher::IntRange { lo, hi }),
        4 => prop::sample::select(PREFIXES).prop_map(|prefix| Matcher::PathUnder {
            prefix: prefix.to_owned()
        }),
        1 => Just(Matcher::Name(NameKind::DebName)),
        1 => Just(Matcher::Name(NameKind::UnitName)),
        1 => Just(Matcher::Name(NameKind::SysctlKey)),
    ]
}
