//! The overlap report: which actions can accept the same command.
//!
//! The engine resolves an overlap to the strictest action, so an overlap is not
//! a hole — but it is two rules whose interaction nobody wrote down, and `aido
//! check` must say where they are. The claim under test is the one an operator
//! relies on: **silence means disjoint.** A pair the analysis cannot decide is
//! reported as possible, never passed over, and a pair reported as certain
//! comes with a command the engine itself agrees both actions accept.
//!
//! The rendered report is pinned with `insta`. To accept a deliberate change:
//! `INSTA_UPDATE=always cargo test -p aido-policy --test overlaps`, then commit
//! the `.snap` diff.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use aido_policy::overlap::{Extent, STATE_BUDGET, Undecided};
use aido_policy::{
    Arg, Argv, CallerFacts, Classification, RuleSet, TraceStep, engine::Settings, evaluate_command,
    matcher::match_argv,
};

/// One rule file holding every shape the report can take, and pairs that must
/// stay out of it.
const FIXTURE: &str = r#"
# Certain: a narrow rule meant to confirm, inside the broad rule it refines.
[[action]]
id = "aido.pkg.remove"
tier = "pkg-remove"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { name = "deb-name" }, repeat = { between = { min = 1, max = 10 } } },
]

[[action]]
id = "aido.pkg.remove-toolchain"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { one-of = ["gcc", "make"] } },
]

# Disjoint from both: another verb.
[[action]]
id = "aido.pkg.update"
tier = "pkg-install"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]

# Certain, reached only through an optional position.
[[action]]
id = "aido.svc.status"
tier = "diag-read"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "status" } },
  { name = "full", matcher = { literal = "--full" }, repeat = "optional" },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "aido.svc.status-full"
tier = "diag-read"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "status" } },
  { name = "full", matcher = { literal = "--full" } },
  { name = "unit", matcher = { pattern = "[a-z]+\\.service" } },
]

# Not compared: the same arguments for another program.
[[action]]
id = "aido.other.status"
tier = "diag-read"
exe = "/usr/local/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "status" } },
  { name = "full", matcher = { literal = "--full" }, repeat = "optional" },
  { name = "unit", matcher = { name = "unit-name" } },
]

# Certain: two ranges that share one value at their boundary.
[[action]]
id = "aido.sysctl.watches-low"
tier = "sys-tunable"
exe = "/usr/sbin/sysctl"
args = [
  { name = "key", matcher = { literal = "fs.inotify.max_user_watches" } },
  { name = "value", matcher = { int-range = { lo = 8192, hi = 65536 } } },
]

[[action]]
id = "aido.sysctl.watches-high"
tier = "sys-tunable"
exe = "/usr/sbin/sysctl"
args = [
  { name = "key", matcher = { literal = "fs.inotify.max_user_watches" } },
  { name = "value", matcher = { int-range = { lo = 65536, hi = 1048576 } } },
]

# Certain: one directory beneath the other. Disjoint from a third.
[[action]]
id = "aido.dir.claim-srv"
tier = "diag-read"
exe = "/usr/local/bin/claim"
args = [{ name = "dir", matcher = { path-under = { prefix = "/srv" } } }]

[[action]]
id = "aido.dir.claim-app"
tier = "diag-read"
exe = "/usr/local/bin/claim"
args = [{ name = "dir", matcher = { path-under = { prefix = "/srv/app" } } }]

[[action]]
id = "aido.dir.claim-var"
tier = "diag-read"
exe = "/usr/local/bin/claim"
args = [{ name = "dir", matcher = { path-under = { prefix = "/var" } } }]

# Possible: two patterns cannot be intersected here.
[[action]]
id = "aido.net.lookup-internal"
tier = "diag-read"
exe = "/usr/bin/host"
args = [{ name = "host", matcher = { pattern = "[a-z]+\\.internal" } }]

[[action]]
id = "aido.net.lookup-any"
tier = "diag-read"
exe = "/usr/bin/host"
args = [{ name = "target", matcher = { pattern = "[a-z.]+" } }]

# Possible: the only shared argument list ends in a bare `--`, which the
# engine drops before any rule sees it.
[[action]]
id = "aido.sep.one"
tier = "diag-read"
exe = "/usr/local/bin/sep"
args = [
  { name = "verb", matcher = { literal = "run" } },
  { name = "end", matcher = { literal = "--" } },
]

[[action]]
id = "aido.sep.two"
tier = "diag-read"
exe = "/usr/local/bin/sep"
args = [
  { name = "verb", matcher = { one-of = ["run", "walk"] } },
  { name = "end", matcher = { one-of = ["--", "---"] } },
]
"#;

/// Two actions whose argument lists have more pairs of states than the
/// search will visit.
const TOO_LARGE: &str = r#"
[[action]]
id = "aido.big.one"
tier = "diag-read"
exe = "/usr/local/bin/big"
args = [
  { name = "a", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "b", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "c", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "d", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "e", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "f", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "g", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "h", matcher = { literal = "x" }, repeat = { between = { min = 0, max = 64 } } },
]

[[action]]
id = "aido.big.two"
tier = "diag-read"
exe = "/usr/local/bin/big"
args = [
  { name = "a", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "b", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "c", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "d", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "e", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "f", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "g", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
  { name = "h", matcher = { literal = "y" }, repeat = { between = { min = 0, max = 64 } } },
]
"#;

fn fixture() -> RuleSet {
    RuleSet::from_toml("overlaps.toml", FIXTURE).unwrap()
}

/// The reported pairs, as `(first, second)` ids.
fn pairs(rules: &RuleSet) -> Vec<(String, String)> {
    rules
        .overlaps()
        .iter()
        .map(|o| (o.first.id.to_string(), o.second.id.to_string()))
        .collect()
}

fn pair(first: &str, second: &str) -> (String, String) {
    (first.to_owned(), second.to_owned())
}

#[test]
fn the_overlap_report_is_pinned() {
    let rules = fixture();
    let report: Vec<String> = rules.overlaps().iter().map(ToString::to_string).collect();
    insta::assert_snapshot!("overlap_report", report.join("\n"));
}

#[test]
fn exactly_the_overlapping_pairs_are_reported() {
    // Every pair in the fixture that can share a command, and none that
    // cannot: another verb, another directory, another program.
    assert_eq!(
        pairs(&fixture()),
        [
            pair("aido.pkg.remove", "aido.pkg.remove-toolchain"),
            pair("aido.svc.status", "aido.svc.status-full"),
            pair("aido.sysctl.watches-low", "aido.sysctl.watches-high"),
            pair("aido.dir.claim-srv", "aido.dir.claim-app"),
            pair("aido.net.lookup-internal", "aido.net.lookup-any"),
            pair("aido.sep.one", "aido.sep.two"),
        ]
    );
}

#[test]
fn a_narrow_confirming_rule_inside_a_broad_one_is_reported_with_a_command_both_accept() {
    // The shape that matters most: an operator adds a narrow rule meant to
    // confirm, and the broad rule already accepts the same command. The engine
    // resolves it to the confirmation; the report makes the interaction
    // visible, with a command to try in `aido explain`.
    let rules = fixture();
    let found = rules.overlaps();
    let overlap = found
        .iter()
        .find(|o| o.second.id.as_str() == "aido.pkg.remove-toolchain")
        .unwrap();
    assert_eq!(
        overlap.extent,
        Extent::Certain {
            witness: Argv::new(["-y", "remove", "--", "gcc"])
        }
    );
}

#[test]
fn every_certain_witness_is_accepted_by_both_actions_through_the_engine() {
    // Not inferred from the analysis: the engine is asked, with both actions
    // in the ruleset, and both must appear as matched.
    let rules = fixture();
    let human = CallerFacts::new(Classification::Human, 1000);
    let mut certain = 0usize;
    for overlap in rules.overlaps() {
        let Extent::Certain { witness } = &overlap.extent else {
            continue;
        };
        certain += 1;
        assert_eq!(witness.canonicalize(), *witness);
        assert!(match_argv(&overlap.first.args, witness).is_ok());
        assert!(match_argv(&overlap.second.args, witness).is_ok());
        let decision = evaluate_command(
            &rules,
            &human,
            &Arg::from(overlap.first.exe.as_str()),
            witness,
            Settings::default(),
        );
        for id in [&overlap.first.id, &overlap.second.id] {
            let matched = decision.trace.iter().any(
                |step| matches!(step, TraceStep::ActionMatched { action, .. } if action == id.as_str()),
            );
            assert!(
                matched,
                "{id} did not accept {witness:?}: {:?}",
                decision.trace
            );
        }
    }
    assert_eq!(certain, 4, "the fixture has four certain overlaps");
}

#[test]
fn an_overlap_reached_only_through_an_optional_position_is_reported() {
    // A matcher that lines positions up one-to-one would compare `--full`
    // with a unit name and call these disjoint.
    let rules = fixture();
    let found = rules.overlaps();
    let overlap = found
        .iter()
        .find(|o| o.first.id.as_str() == "aido.svc.status")
        .unwrap();
    assert_eq!(
        overlap.extent,
        Extent::Certain {
            witness: Argv::new(["status", "--full", "a.service"])
        }
    );
}

#[test]
fn an_off_by_one_range_boundary_is_reported() {
    let rules = fixture();
    let found = rules.overlaps();
    let overlap = found
        .iter()
        .find(|o| o.first.id.as_str() == "aido.sysctl.watches-low")
        .unwrap();
    assert_eq!(
        overlap.extent,
        Extent::Certain {
            witness: Argv::new(["fs.inotify.max_user_watches", "65536"])
        }
    );
}

#[test]
fn two_patterns_are_reported_as_a_possible_overlap_rather_than_passed_over() {
    let rules = fixture();
    let found = rules.overlaps();
    let overlap = found
        .iter()
        .find(|o| o.first.id.as_str() == "aido.net.lookup-internal")
        .unwrap();
    assert_eq!(
        overlap.extent,
        Extent::Possible {
            reason: Undecided::Positions(vec![(
                "`host` (pattern \"[a-z]+\\\\.internal\")".to_owned(),
                "`target` (pattern \"[a-z.]+\")".to_owned()
            )])
        }
    );
}

#[test]
fn argument_lists_too_large_to_search_are_reported_rather_than_passed_over() {
    // Disjoint in fact — `x` and `y` never meet — but proving it would take
    // more than the budget, and a bound that gave up silently would be a
    // bound an attacker sizes a rule file to.
    let rules = RuleSet::from_toml("big.toml", TOO_LARGE).unwrap();
    let found = rules.overlaps();
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].extent,
        Extent::Possible {
            reason: Undecided::TooLarge
        }
    );
    assert!(
        found[0]
            .to_string()
            .ends_with("the argument lists are too large to compare exactly"),
        "{}",
        found[0]
    );
    // Eight positions of up to 64 arguments: 1 + 8 * 65 states a side.
    const {
        assert!(
            STATE_BUDGET < 521 * 521,
            "the fixture must exceed the budget"
        );
    };
}

#[test]
fn a_pair_sharing_only_a_trailing_separator_is_reported_as_possible() {
    // `run --` is accepted by both position by position, but canonicalization
    // drops a trailing `--`, so no request reaches either rule with it. Not
    // certain, then, and not disjoint either: reported as possible.
    let rules = fixture();
    let found = rules.overlaps();
    let overlap = found
        .iter()
        .find(|o| o.first.id.as_str() == "aido.sep.one")
        .unwrap();
    assert_eq!(
        overlap.extent,
        Extent::Possible {
            reason: Undecided::Unconfirmed(Argv::new(["run", "--"]))
        }
    );
}

#[test]
fn the_same_arguments_for_another_program_are_not_an_overlap() {
    // The engine compares the program byte for byte, so two rules for two
    // spellings of a path never accept one request. That the two spellings
    // may be one file is a filesystem question this crate cannot ask.
    let pairs = pairs(&fixture());
    assert!(
        !pairs
            .iter()
            .any(|(a, b)| a == "aido.other.status" || b == "aido.other.status")
    );
}

#[test]
fn a_ruleset_without_overlaps_reports_nothing() {
    let rules = RuleSet::from_toml(
        "disjoint.toml",
        r#"
[[action]]
id = "aido.svc.start"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [{ name = "verb", matcher = { literal = "start" } }]

[[action]]
id = "aido.svc.stop"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [{ name = "verb", matcher = { literal = "stop" } }]
"#,
    )
    .unwrap();
    assert!(rules.overlaps().is_empty());
    assert!(RuleSet::default().overlaps().is_empty());
}
