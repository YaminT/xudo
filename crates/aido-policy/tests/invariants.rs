//! The standing invariants, expressed as properties rather than examples.
//!
//! These are the load-bearing security claims of the whole project. Each one is
//! stated in `CLAUDE.md` and must never be deleted: if an invariant here starts
//! failing, the design has been broken, not the test.
//!
//! Example tests check the cases an author thought of. These check the cases
//! nobody thought of, which is where a matcher bypass actually lives.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use aido_policy::{
    Action, ActionId, Arg, Argv, CallerFacts, Classification, Decision, DenialCode, Hint,
    HintSource, Matcher, NameKind, Request, RuleSet, Source, Tier, Verdict,
    engine::Settings,
    matcher::{ArgSpec, Repeat},
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

proptest! {
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
}
