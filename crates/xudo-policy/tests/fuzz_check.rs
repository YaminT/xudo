//! `xudo check --fuzz` against rulesets of its own: the planted miss, the
//! determinism and the budget, byte-exact reporting, and the standing
//! invariants through a faulty engine. In `tests/` rather than beside the code
//! because Miri runs `--lib` only, and these parse rulesets with patterns and
//! evaluate every candidate several times.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;

use proptest::prelude::*;
use xudo_policy::decision::{Decision, DenialCode, TraceStep, Verdict};
use xudo_policy::engine::{Settings, evaluate_command};
use xudo_policy::fuzz_check::{
    Candidates, Finding, FindingKind, FuzzConfig, MAX_FINDINGS, fuzz, fuzz_with, witnesses,
};
use xudo_policy::matcher::MAX_ARGV_LEN;
use xudo_policy::overlap::Overlap;
use xudo_policy::{ActionId, Arg, Argv, CallerFacts, Classification, RuleSet};

/// Two actions that accept `/usr/bin/foo go`, one that accepts a range, a
/// path and a pattern, and a program of its own.
const RULES: &str = r#"
[[action]]
id = "t.go"
tier = "diag-read"
exe = "/usr/bin/foo"
args = [{ name = "verb", matcher = { literal = "go" } }]

[[action]]
id = "t.verbs"
tier = "diag-read"
exe = "/usr/bin/foo"
args = [{ name = "verb", matcher = { one-of = ["go", "stop"] } }]

[[action]]
id = "t.rest"
tier = "diag-read"
exe = "/usr/bin/bar"
args = [
  { name = "n", matcher = { int-range = { lo = -2, hi = 9 } } },
  { name = "p", matcher = { path-under = { prefix = "/srv/" } }, repeat = "optional" },
  { name = "u", matcher = { name = "unit-name" }, repeat = { between = { min = 0, max = 2 } } },
  { name = "x", matcher = { pattern = "[a-z]+-[0-9]" }, repeat = "optional" },
]

[[action]]
id = "t.never"
tier = "diag-read"
exe = "/usr/bin/baz"
args = [{ name = "x", matcher = { pattern = "[b-c]+" } }]
"#;

fn rules() -> RuleSet {
    RuleSet::from_toml("t.toml", RULES).unwrap()
}

fn small(budget: usize) -> FuzzConfig {
    FuzzConfig {
        budget,
        ..FuzzConfig::default()
    }
}

fn budget() -> usize {
    600
}

#[test]
fn check_fuzz_finds_a_planted_overlap() {
    let rules = rules();
    let honest = rules.overlaps();
    assert_eq!(honest.len(), 1);
    assert!(fuzz(&rules, &honest, small(budget())).clean());

    // A faulty analysis that has lost the pair it found.
    let faulty: Vec<Overlap<'_>> = Vec::new();
    let report = fuzz(&rules, &faulty, small(budget()));
    assert!(!report.clean());
    let finding = report.findings.first().unwrap();
    assert_eq!(
        finding.kind,
        FindingKind::MissedOverlap {
            first: ActionId::new("t.go"),
            second: ActionId::new("t.verbs"),
        }
    );
    assert_eq!(finding.argv, Argv::new(["go"]));
    assert_eq!(finding.exe, Arg::from("/usr/bin/foo"));
    assert_eq!(
        finding.summary(),
        "overlap analysis missed an overlap: t.go and t.verbs both accept it"
    );
    assert_eq!(finding.escaped(), r#""/usr/bin/foo" "go""#);
    assert_eq!(finding.hex(), "0x2f7573722f62696e2f666f6f 0x676f");
    assert!(report.accepted_by_several > 0);
    // One finding per pair, however many candidates show it.
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn check_fuzz_is_deterministic_for_a_seed() {
    let rules = rules();
    let overlaps = rules.overlaps();
    let run = |seed| {
        fuzz(
            &rules,
            &overlaps,
            FuzzConfig {
                seed,
                budget: budget(),
            },
        )
    };
    assert_eq!(run(7), run(7));
    let candidates = |seed| {
        Candidates::new(
            &rules,
            FuzzConfig {
                seed,
                budget: budget(),
            },
        )
        .collect::<Vec<_>>()
    };
    assert_eq!(candidates(7), candidates(7));
    assert_ne!(candidates(7), candidates(8));
}

#[test]
fn check_fuzz_respects_the_budget() {
    let rules = rules();
    for budget in [0, 1, 3, 4, 9] {
        let count = Candidates::new(&rules, small(budget)).count();
        assert_eq!(count, budget);
        let report = fuzz(&rules, &rules.overlaps(), small(budget));
        assert_eq!(report.candidates, budget);
        assert_eq!(
            report.accepted_by_one + report.accepted_by_several + report.accepted_by_none,
            budget
        );
    }
}

#[test]
fn an_empty_ruleset_has_nothing_to_try() {
    let empty = RuleSet::load(Vec::new()).unwrap();
    assert_eq!(Candidates::new(&empty, small(50)).count(), 0);
    assert_eq!(fuzz(&empty, &[], small(50)).candidates, 0);
}

#[test]
fn a_non_utf8_candidate_is_reported_byte_exact() {
    let finding = Finding {
        kind: FindingKind::CanonicalizationUnstable,
        exe: Arg::from("/x"),
        argv: Argv::new([Arg::new(vec![b'a', 0xff, b'"', b'\\', 0x07]), Arg::new("")]),
    };
    assert_eq!(finding.escaped(), r#""/x" "a\xff\"\\\x07" """#);
    assert_eq!(finding.hex(), "0x2f78 0x61ff225c07 0x");

    // And end to end: two actions that accept only the dictionary's invalid
    // UTF-8 token, with an analysis that forgot them.
    let rules = RuleSet::from_toml(
        "t.toml",
        r#"
[[action]]
id = "b.one"
tier = "diag-read"
exe = "/usr/bin/raw"
args = [{ name = "x", matcher = { pattern = '(?-u:\xff\xfe)' } }]

[[action]]
id = "b.two"
tier = "diag-read"
exe = "/usr/bin/raw"
args = [{ name = "x", matcher = { pattern = '(?-u:\xff\xfe)' } }]
"#,
    )
    .unwrap();
    assert_eq!(rules.overlaps().len(), 1);
    let report = fuzz(&rules, &[], small(budget()));
    let [found] = report.findings.as_slice() else {
        panic!("{report:?}");
    };
    assert_eq!(found.argv, Argv::new([Arg::new(vec![0xff, 0xfe])]));
    assert!(found.hex().ends_with("0xfffe"), "{}", found.hex());
    assert!(
        found.escaped().ends_with(r#""\xff\xfe""#),
        "{}",
        found.escaped()
    ); // An overlap the report lists, here only as possible, silences the finding.
    assert!(fuzz(&rules, &rules.overlaps(), small(budget())).clean());
}

#[test]
fn a_decision_that_depends_on_canonicalizing_first_is_a_finding() {
    let rules = rules();
    let human = CallerFacts::new(Classification::Human, 1000);
    // A faulty engine: it permits only when handed the argv uncanonicalized.
    let report = fuzz_with(&rules, &rules.overlaps(), small(budget()), &|exe, argv| {
        let mut decision = evaluate_command(&rules, &human, exe, argv, Settings::default());
        if argv != &argv.canonicalize() {
            decision.verdict = Verdict::Deny;
            decision.denial = Some(DenialCode::DenyListed);
        }
        decision
    });
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::CanonicalizationUnstable)
    );
    let finding = report.findings.first().unwrap();
    assert!(
        finding
            .summary()
            .contains("changes when the argv is canonicalized")
    );
}

#[test]
fn appending_an_argument_that_widens_a_refusal_is_a_finding() {
    let rules = rules();
    // A faulty engine: one argument is refused by the deny-list, two are
    // permitted.
    let report = fuzz_with(&rules, &[], small(budget()), &|_, argv| {
        let mut decision = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        if argv.len() > 1 {
            decision.verdict = Verdict::Allow;
            decision.denial = None;
        }
        decision
    });
    let finding = report
        .findings
        .iter()
        .find(|f| matches!(f.kind, FindingKind::AppendingWidens { .. }))
        .unwrap();
    assert!(finding.summary().starts_with("appending "));
    assert!(
        finding
            .summary()
            .ends_with("turns a refusal into a permission")
    );
    // A refusal of the argument shape is not a refusal to hold: the right
    // argument completes it.
    let shape = fuzz_with(&rules, &[], small(budget()), &|_, argv| {
        let mut decision = Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new());
        if argv.len() > 1 {
            decision.verdict = Verdict::Allow;
        }
        decision
    });
    assert!(
        !shape
            .findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::AppendingWidens { .. }))
    );
}

#[test]
fn findings_are_distinct_and_bounded() {
    let rules = rules();
    // A faulty engine that is lenient about longer commands: every refused
    // short command is a finding of its own.
    let report = fuzz_with(
        &rules,
        &[],
        small(budget().saturating_mul(8)),
        &|_, argv| {
            let mut decision = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
            if argv.len() > 1 {
                decision.verdict = Verdict::Allow;
                decision.denial = None;
            }
            decision
        },
    );
    let keys: BTreeSet<String> = report
        .findings
        .iter()
        .map(|f| format!("{:?}|{}", f.kind, f.hex()))
        .collect();
    assert_eq!(keys.len(), report.findings.len());
    assert!(report.findings.len() <= MAX_FINDINGS);
    assert_eq!(report.findings.len(), MAX_FINDINGS);
    assert!(report.omitted > 0);
    assert!(!report.clean());
}

#[test]
fn the_generator_offers_only_accepted_witnesses() {
    let rules = rules();
    // An action no value fits yields no witness, and an action that can be
    // satisfied yields only verified ones.
    let never = rules.actions().last().unwrap();
    assert!(witnesses(&rules, never, 1, 5).is_empty());
    let rest = rules.get(&ActionId::new("t.rest")).unwrap();
    let found = witnesses(&rules, rest, 1, 40);
    assert_eq!(found.len(), 40);
    assert!(found.iter().any(|argv| argv.len() > 1));
    // The unsatisfiable action still gets candidates: dictionary noise.
    let tried = Candidates::new(&rules, small(8)).filter(|c| c.exe == Arg::from("/usr/bin/baz"));
    assert!(tried.count() > 0);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    #[test]
    fn the_generator_stays_within_the_budget_and_every_witness_is_accepted(
        seed in any::<u64>(),
        budget in 0usize..150,
    ) {
        let rules = rules();
        let config = FuzzConfig { budget, seed };
        prop_assert!(Candidates::new(&rules, config).count() <= budget);
        for candidate in Candidates::new(&rules, config) {
            prop_assert!(candidate.argv.len() <= MAX_ARGV_LEN);
        }
        // Through the engine `xudo explain` asks, not the matcher the
        // generator checked with: every witness is accepted by its action.
        let human = CallerFacts::new(Classification::Human, 1000);
        for action in rules.actions() {
            let found = witnesses(&rules, action, seed, 3);
            prop_assert_eq!(found.is_empty(), action.id.as_str() == "t.never");
            for argv in found {
                let exe = Arg::from(action.exe.as_str());
                let decision =
                    evaluate_command(&rules, &human, &exe, &argv, Settings::default());
                prop_assert!(
                    decision.trace.iter().any(|step| matches!(step, TraceStep::ActionMatched { action: id, .. } if id == action.id.as_str())),
                    "{} does not accept {:?}", action.id.as_str(), argv
                );
            }
        }
    }
}

/// The loader does not reject a rule that allowlists a deny-listed program:
/// `self_denying_actions` reports it, and the compiled-in deny-list refuses
/// every command the rule accepts, so it can never produce an allow. The seed
/// `fuzz/seeds/rules_toml/self-denying-ex.seed` is this ruleset.
#[test]
fn a_self_denying_rule_loads_and_can_never_produce_an_allow() {
    let rules = RuleSet::from_toml(
        "x.toml",
        include_str!("../../../fuzz/seeds/rules_toml/self-denying-ex.seed"),
    )
    .unwrap();
    let offenders = rules.self_denying_actions();
    assert_eq!(offenders.len(), 1);
    let action = rules.actions().first().unwrap();
    assert_eq!(action.exe, "/usr/bin/ex");
    let found = witnesses(&rules, action, 1, 4);
    assert!(!found.is_empty(), "no witness for the self-denying rule");
    let human = CallerFacts::new(Classification::Human, 1000);
    for argv in found {
        let decision = evaluate_command(
            &rules,
            &human,
            &Arg::from(action.exe.as_str()),
            &argv,
            Settings::default(),
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.denial, Some(DenialCode::DenyListed));
    }
}
