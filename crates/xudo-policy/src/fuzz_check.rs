//! A bounded, deterministic differential fuzz of one ruleset.
//!
//! [`crate::overlap`] decides *symbolically* which actions can accept the same
//! command. This module cross-examines that answer *concretely*: it derives
//! candidate commands from the rules themselves, asks the engine `xudo explain`
//! asks which actions accept each, and reports what the symbolic answer got
//! wrong, plus any breach of a standing invariant on the operator's own rules.
//!
//! # What is checked
//!
//! For every candidate, evaluated as an unattested human with default settings:
//!
//! * **A missed overlap.** Two actions accept it and the overlap report does
//!   not list that pair, certain or possible. The report promises silence means
//!   disjoint, so this is a soundness hole in the analysis, never a rule problem.
//! * **Canonicalization stability.** Deciding the canonical form of the argv
//!   must give the same decision as deciding the argv.
//! * **Appending never widens.** A candidate refused for a reason other than its
//!   argument shape stays refused when an argument is appended.
//!
//! Candidates accepted by one action, by several actions the report predicts,
//! or by none are only counted.
//!
//! # Where candidates come from
//!
//! * **Witnesses.** For each action, an argument list that action accepts: every
//!   position gets a value its matcher accepts, drawn from the matcher's own
//!   samples (a literal, each member of a set, an integer range's bounds, a
//!   path's prefix with trailing components) and from a dictionary of every
//!   sample in the whole ruleset, so one action's witness can land in another.
//!   Every witness is verified against the action's matcher before use.
//! * **Mutations.** Appending, dropping, swapping and duplicating arguments,
//!   changing one byte, a `--` separator, an empty argument, a very long
//!   argument, a non-UTF-8 argument, and replacing an argument with a token of
//!   another matcher.
//!
//! Everything is byte exact and nothing is run. The only entropy is a small
//! seeded generator in this file: the same ruleset and seed give the same
//! report, and the work is bounded by the candidate budget.

use core::fmt::Write as _;
use std::collections::BTreeSet;

use crate::argv::{Arg, Argv};
use crate::caller::{CallerFacts, Classification};
use crate::decision::{Decision, DenialCode, TraceStep, Verdict};
use crate::engine::{Settings, evaluate_command};
use crate::matcher::{MAX_ARGV_LEN, Matcher, match_argv};
use crate::overlap::Overlap;
use crate::rule::{Action, ActionId, RuleSet};

/// Candidates tried when the caller does not say.
pub const DEFAULT_BUDGET: usize = 20_000;

/// The most candidates one run may try.
pub const MAX_BUDGET: usize = 1_000_000;

/// The seed used when the caller does not give one.
pub const DEFAULT_SEED: u64 = 0x7875_646f_6675_7a7a;

/// The most findings a report lists; the rest are counted in
/// [`FuzzReport::omitted`].
pub const MAX_FINDINGS: usize = 32;

/// Length of the long argument: far over any name, far under the matcher's
/// work bound.
const LONG_ARG: usize = if cfg!(miri) { 64 } else { 1024 };

/// How many mutation kinds [`mutate`] knows.
const KINDS: usize = 10;

/// What one run is asked to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuzzConfig {
    /// How many candidates to try, at most.
    pub budget: usize,
    /// The seed of the candidate generator.
    pub seed: u64,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            budget: DEFAULT_BUDGET,
            seed: DEFAULT_SEED,
        }
    }
}

/// What a finding says went wrong.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// Two actions accept the command and the overlap report lists neither as
    /// overlapping with the other.
    MissedOverlap {
        /// The action declared first.
        first: ActionId,
        /// The action declared after it.
        second: ActionId,
    },
    /// Deciding the canonical form gave a different decision.
    CanonicalizationUnstable,
    /// The command was refused for a reason other than its shape, and is
    /// permitted once this argument is appended.
    AppendingWidens {
        /// The appended argument.
        appended: Arg,
    },
}

/// One thing the run found, with the command that shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// What went wrong.
    pub kind: FindingKind,
    /// The program.
    pub exe: Arg,
    /// The operands, byte for byte.
    pub argv: Argv,
}

impl Finding {
    /// The finding in words, without the command.
    pub fn summary(&self) -> String {
        match &self.kind {
            FindingKind::MissedOverlap { first, second } => format!(
                "overlap analysis missed an overlap: {} and {} both accept it",
                first.as_str(),
                second.as_str()
            ),
            FindingKind::CanonicalizationUnstable => {
                "the decision changes when the argv is canonicalized first".to_owned()
            }
            FindingKind::AppendingWidens { appended } => format!(
                "appending {} turns a refusal into a permission",
                escape(appended.as_bytes())
            ),
        }
    }

    /// The command with every byte outside printable ASCII escaped as `\xNN`,
    /// so it is safe to print and loses nothing.
    pub fn escaped(&self) -> String {
        words(&self.exe, &self.argv, |arg| {
            format!("\"{}\"", escape(arg.as_bytes()))
        })
    }

    /// The command as hexadecimal, one `0x` word per argument.
    pub fn hex(&self) -> String {
        words(&self.exe, &self.argv, |arg| {
            let mut hex = String::from("0x");
            for byte in arg.as_bytes() {
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        })
    }

    /// What makes two findings the same one: a missed overlap is one per pair,
    /// whatever command shows it; any other is one per command.
    fn key(&self) -> String {
        match &self.kind {
            kind @ FindingKind::MissedOverlap { .. } => format!("{kind:?}"),
            kind => format!("{kind:?}|{}", self.hex()),
        }
    }
}

fn words(exe: &Arg, argv: &Argv, render: impl Fn(&Arg) -> String) -> String {
    std::iter::once(exe)
        .chain(argv.as_slice())
        .map(render)
        .collect::<Vec<_>>()
        .join(" ")
}

fn escape(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| match byte {
            b'\\' => "\\\\".to_owned(),
            b'"' => "\\\"".to_owned(),
            0x20..=0x7e => char::from(*byte).to_string(),
            other => format!("\\x{other:02x}"),
        })
        .collect()
}

/// What a run tried and found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzReport {
    /// The seed it ran with.
    pub seed: u64,
    /// The budget it ran with.
    pub budget: usize,
    /// Candidates evaluated.
    pub candidates: usize,
    /// Candidates exactly one action accepts.
    pub accepted_by_one: usize,
    /// Candidates several actions accept, all pairs listed by the overlap
    /// report.
    pub accepted_by_several: usize,
    /// Candidates no action accepts.
    pub accepted_by_none: usize,
    /// The findings, at most [`MAX_FINDINGS`], each distinct.
    pub findings: Vec<Finding>,
    /// Distinct findings beyond [`MAX_FINDINGS`], not listed.
    pub omitted: usize,
}

impl FuzzReport {
    /// Whether anything was found.
    pub fn clean(&self) -> bool {
        self.findings.is_empty() && self.omitted == 0
    }
}

/// A small seeded generator (splitmix64). Never seeded from the machine.
#[derive(Clone, Debug)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `bound`, or zero when `bound` is.
    fn below(&mut self, bound: usize) -> usize {
        let draw = self.next();
        u64::try_from(bound)
            .ok()
            .and_then(|bound| draw.checked_rem(bound))
            .and_then(|drawn| usize::try_from(drawn).ok())
            .unwrap_or(0)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        items.get(self.below(items.len()))
    }
}

/// One command to evaluate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The program.
    pub exe: Arg,
    /// The operands.
    pub argv: Argv,
    /// The argument the append check adds.
    pub extra: Arg,
}

/// Arguments that show a matcher's edges, accepted or not.
fn samples(matcher: &Matcher) -> Vec<Arg> {
    match matcher {
        Matcher::Literal(want) => vec![Arg::from(want.as_str())],
        Matcher::OneOf(options) => options.iter().map(|o| Arg::from(o.as_str())).collect(),
        Matcher::IntRange { lo, hi } => {
            let (lo, hi) = (i128::from(*lo), i128::from(*hi));
            let mid = lo.saturating_add(hi) >> 1;
            [lo, hi, mid, lo.saturating_sub(1), hi.saturating_add(1), 0]
                .into_iter()
                .map(|value| Arg::new(value.to_string()))
                .collect()
        }
        Matcher::PathUnder { prefix } => {
            let base = prefix.strip_suffix('/').unwrap_or(prefix);
            [
                "", "/", "/x", "/x/y", "/x/", "/../x", "/./x", "//x", "/x/..", "x",
            ]
            .iter()
            .map(|tail| Arg::new(format!("{base}{tail}")))
            .collect()
        }
        Matcher::Name(_) => [
            "a",
            "ripgrep",
            "Foo_Bar",
            "foo.service",
            "foo@bar.timer",
            "example.com",
            "net.ipv4.ip_forward",
            "-a",
            "a/b",
            "a=b",
            "a:b",
            "..",
        ]
        .iter()
        .map(|name| Arg::from(*name))
        .collect(),
        Matcher::Pattern(pattern) => {
            let plain: String = pattern
                .source()
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
                .collect();
            vec![Arg::new(plain), Arg::from("a"), Arg::from("0")]
        }
    }
}

/// Every token worth putting in a command: each matcher's samples across the
/// whole ruleset, and the awkward ones no matcher mentions.
fn dictionary(rules: &RuleSet) -> Vec<Arg> {
    let mut tokens: BTreeSet<Arg> = rules
        .actions()
        .iter()
        .flat_map(|action| action.args.iter())
        .flat_map(|spec| samples(&spec.matcher))
        .collect();
    tokens.extend([
        Arg::from("--"),
        Arg::from("-"),
        Arg::from("-x"),
        Arg::from("--help"),
        Arg::from("../x"),
        Arg::new(Vec::new()),
        Arg::new(vec![0xff, 0xfe]),
        Arg::new(vec![b'a', 0xc3, 0x28]),
        Arg::new(vec![b'a'; LONG_ARG]),
    ]);
    tokens.into_iter().collect()
}

/// Per position of `action`, the dictionary tokens that position accepts.
fn values(action: &Action, dictionary: &[Arg]) -> Vec<Vec<Arg>> {
    action
        .args
        .iter()
        .map(|spec| {
            dictionary
                .iter()
                .filter(|token| spec.matcher.accepts(token))
                .cloned()
                .collect()
        })
        .collect()
}

/// An argument list `action` accepts, or `None` when a required position has no
/// value to offer. Verified against the action's own matchers.
fn witness(action: &Action, values: &[Vec<Arg>], rng: &mut Rng) -> Option<Argv> {
    let mut args = Vec::new();
    for (spec, choices) in action.args.iter().zip(values) {
        let (min, max) = spec.repeat.bounds();
        let count = if choices.is_empty() {
            min
        } else {
            min.saturating_add(rng.below(max.saturating_sub(min).min(3).saturating_add(1)))
        };
        for _ in 0..count {
            args.push(rng.pick(choices)?.clone());
        }
    }
    let made = Argv::new(args);
    match_argv(&action.args, &made.canonicalize())
        .is_ok()
        .then_some(made)
}

/// Changes `args` one way. `kind` is taken modulo the number of kinds.
fn mutate(args: &mut Vec<Arg>, kind: usize, rng: &mut Rng, dictionary: &[Arg]) {
    let room = args.len() < MAX_ARGV_LEN;
    let at = rng.below(args.len());
    let token = rng
        .pick(dictionary)
        .cloned()
        .unwrap_or(Arg::new(Vec::new()));
    match kind % KINDS {
        0 if room => args.push(token),
        1 if at < args.len() => {
            args.remove(at);
        }
        2 if !args.is_empty() => {
            let other = rng.below(args.len());
            args.swap(at, other);
        }
        3 if room => {
            if let Some(arg) = args.get(at).cloned() {
                args.insert(at, arg);
            }
        }
        4 => {
            let mut bytes = args
                .get(at)
                .map_or_else(Vec::new, |a| a.as_bytes().to_vec());
            let place = rng.below(bytes.len().saturating_add(1));
            let byte = u8::try_from(rng.below(256)).unwrap_or(0);
            match bytes.get_mut(place) {
                Some(slot) => *slot = byte,
                None => bytes.push(byte),
            }
            match args.get_mut(at) {
                Some(slot) => *slot = Arg::new(bytes),
                None => args.push(Arg::new(bytes)),
            }
        }
        5 if room => args.insert(at, Arg::from("--")),
        6 if room => args.push(Arg::new(Vec::new())),
        7 if room => args.push(Arg::new(vec![b'a'; LONG_ARG])),
        8 if room => args.push(Arg::new(vec![0xff, b'x', 0x80])),
        _ => {
            if let Some(slot) = args.get_mut(at) {
                *slot = token;
            }
        }
    }
}

/// One action and the values each of its positions can take.
type Plan<'r> = (&'r Action, Vec<Vec<Arg>>);

/// The candidates of one run, lazily, at most `budget` of them.
#[derive(Clone, Debug)]
pub struct Candidates<'r> {
    plans: Vec<Plan<'r>>,
    cycle: usize,
    dictionary: Vec<Arg>,
    rng: Rng,
    next: usize,
    budget: usize,
}

impl<'r> Candidates<'r> {
    /// A generator over `rules` for `config`.
    pub fn new(rules: &'r RuleSet, config: FuzzConfig) -> Self {
        let dictionary = dictionary(rules);
        Self {
            plans: rules
                .actions()
                .iter()
                .map(|action| (action, values(action, &dictionary)))
                .collect(),
            cycle: 0,
            dictionary,
            rng: Rng(config.seed),
            next: 0,
            budget: config.budget.min(MAX_BUDGET),
        }
    }
}

impl Iterator for Candidates<'_> {
    type Item = Candidate;

    fn next(&mut self) -> Option<Candidate> {
        if self.next >= self.budget {
            return None;
        }
        // Every action in turn, round and round.
        let (action, values) = self.plans.get(self.cycle)?;
        self.cycle = self.cycle.saturating_add(1);
        if self.cycle >= self.plans.len() {
            self.cycle = 0;
        }
        let first_pass = self.next < self.plans.len();
        self.next = self.next.saturating_add(1);

        let mut args: Vec<Arg> = match witness(action, values, &mut self.rng) {
            Some(argv) => argv.as_slice().to_vec(),
            None => (0..self.rng.below(3))
                .filter_map(|_| self.rng.pick(&self.dictionary).cloned())
                .collect(),
        };
        // The first pass, and one candidate in four after it, stays as derived.
        if !first_pass && self.rng.below(4) > 0 {
            for _ in 0..self.rng.below(3).saturating_add(1) {
                let kind = self.rng.below(KINDS);
                mutate(&mut args, kind, &mut self.rng, &self.dictionary);
            }
        }
        let extra = (self.rng.pick(&self.dictionary).cloned()).unwrap_or(Arg::new(Vec::new()));
        Some(Candidate {
            exe: Arg::from(action.exe.as_str()),
            argv: Argv::new(args),
            extra,
        })
    }
}

/// Up to `count` argument lists `action` accepts, each verified. For a test and
/// for self-checking: every one is accepted by `action`.
pub fn witnesses(rules: &RuleSet, action: &Action, seed: u64, count: usize) -> Vec<Argv> {
    let dictionary = dictionary(rules);
    let values = values(action, &dictionary);
    let mut rng = Rng(seed);
    (0..count)
        .filter_map(|_| witness(action, &values, &mut rng))
        .collect()
}

/// The ids of the actions the decision's trace shows accepting the command, in
/// declaration order.
fn accepted_by(decision: &Decision) -> Vec<&str> {
    decision
        .trace
        .iter()
        .filter_map(|step| match step {
            TraceStep::ActionMatched { action, .. } => Some(action.as_str()),
            _ => None,
        })
        .collect()
}

/// The same decision, as far as what the command is allowed to do.
fn same(a: &Decision, b: &Decision) -> bool {
    (&a.verdict, &a.denial, &a.action, &a.confirm, accepted_by(a))
        == (&b.verdict, &b.denial, &b.action, &b.confirm, accepted_by(b))
}

/// Runs the fuzz against the engine, with the overlap report to cross-examine.
///
/// `overlaps` is what [`RuleSet::overlaps`] returned for `rules`, taken as a
/// parameter so a test can hand in a faulty one.
pub fn fuzz(rules: &RuleSet, overlaps: &[Overlap<'_>], config: FuzzConfig) -> FuzzReport {
    let human = CallerFacts::new(Classification::Human, 1000);
    fuzz_with(rules, overlaps, config, &|exe, argv| {
        evaluate_command(rules, &human, exe, argv, Settings::default())
    })
}

/// [`fuzz`] against any decision function, so a test can hand in a faulty one.
pub fn fuzz_with(
    rules: &RuleSet,
    overlaps: &[Overlap<'_>],
    config: FuzzConfig,
    decide: &dyn Fn(&Arg, &Argv) -> Decision,
) -> FuzzReport {
    let known: BTreeSet<(&str, &str)> = overlaps
        .iter()
        .flat_map(|o| {
            let (a, b) = (o.first.id.as_str(), o.second.id.as_str());
            [(a, b), (b, a)]
        })
        .collect();
    let mut report = FuzzReport {
        seed: config.seed,
        budget: config.budget,
        candidates: 0,
        accepted_by_one: 0,
        accepted_by_several: 0,
        accepted_by_none: 0,
        findings: Vec::new(),
        omitted: 0,
    };
    let mut seen = BTreeSet::new();
    let mut record = |report: &mut FuzzReport, finding: Finding| {
        if !seen.insert(finding.key()) {
            return;
        }
        if report.findings.len() < MAX_FINDINGS {
            report.findings.push(finding);
        } else {
            report.omitted = report.omitted.saturating_add(1);
        }
    };

    for candidate in Candidates::new(rules, config) {
        report.candidates = report.candidates.saturating_add(1);
        let Candidate { exe, argv, extra } = candidate;
        let decision = decide(&exe, &argv);
        let accepted = accepted_by(&decision);
        match accepted.len() {
            0 => report.accepted_by_none = report.accepted_by_none.saturating_add(1),
            1 => report.accepted_by_one = report.accepted_by_one.saturating_add(1),
            _ => report.accepted_by_several = report.accepted_by_several.saturating_add(1),
        }
        let missed: Vec<(ActionId, ActionId)> = accepted
            .iter()
            .enumerate()
            .flat_map(|(at, first)| {
                accepted
                    .iter()
                    .skip(at.saturating_add(1))
                    .map(move |second| (*first, *second))
            })
            .filter(|pair| !known.contains(pair))
            .map(|(first, second)| (ActionId::new(first), ActionId::new(second)))
            .collect();
        for (first, second) in missed {
            let kind = FindingKind::MissedOverlap { first, second };
            let (exe, argv) = (exe.clone(), argv.clone());
            record(&mut report, Finding { kind, exe, argv });
        }

        if !same(&decision, &decide(&exe, &argv.canonicalize())) {
            let (exe, argv) = (exe.clone(), argv.clone());
            let kind = FindingKind::CanonicalizationUnstable;
            record(&mut report, Finding { kind, exe, argv });
        }

        let shape = matches!(decision.denial, Some(DenialCode::ArgvRejected));
        if decision.verdict == Verdict::Deny && !shape {
            let mut longer = argv.as_slice().to_vec();
            longer.push(extra.clone());
            if decide(&exe, &Argv::new(longer)).verdict != Verdict::Deny {
                let kind = FindingKind::AppendingWidens { appended: extra };
                record(&mut report, Finding { kind, exe, argv });
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;

    fn bare() -> Vec<Arg> {
        dictionary(&RuleSet::load(Vec::new()).unwrap())
    }

    #[test]
    fn every_mutation_kind_changes_an_argv_without_panicking() {
        let dictionary = bare();
        for kind in 0..KINDS.saturating_mul(2) {
            for start in [
                Vec::new(),
                vec![Arg::from("a")],
                vec![Arg::from("a"), Arg::from("b"), Arg::from("c")],
                vec![Arg::from("a"); MAX_ARGV_LEN],
            ] {
                for seed in 0..4 {
                    let mut args = start.clone();
                    mutate(&mut args, kind, &mut Rng(seed), &dictionary);
                    assert!(
                        args.len() <= MAX_ARGV_LEN,
                        "kind {kind} grew past the bound"
                    );
                }
            }
        }
        // The kinds that must act on a small argv, do.
        let one = vec![Arg::from("a")];
        let after = |kind| {
            let mut args = one.clone();
            mutate(&mut args, kind, &mut Rng(1), &dictionary);
            args
        };
        assert_eq!(after(1), Vec::<Arg>::new());
        assert_eq!(after(3), vec![Arg::from("a"), Arg::from("a")]);
        assert_eq!(after(5), vec![Arg::from("--"), Arg::from("a")]);
        assert_eq!(after(6), vec![Arg::from("a"), Arg::new("")]);
        assert_eq!(after(7).get(1).map(Arg::len), Some(LONG_ARG));
        assert_eq!(
            after(8).get(1).map(Arg::as_bytes),
            Some(&[0xff, b'x', 0x80][..])
        );
        assert_eq!(after(0).len(), 2);
        assert_ne!(after(4), one);
    }

    #[test]
    fn samples_show_each_matchers_edges() {
        let range = Matcher::IntRange { lo: -2, hi: 9 };
        let edges: BTreeSet<Vec<u8>> = samples(&range)
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect();
        for want in ["-2", "9", "3", "-3", "10", "0"] {
            assert!(edges.contains(want.as_bytes()), "{want}");
        }
        let path = Matcher::PathUnder {
            prefix: "/srv/".to_owned(),
        };
        let paths: Vec<String> = samples(&path).iter().map(Arg::display).collect();
        assert!(paths.contains(&"/srv/../x".to_owned()));
        assert!(paths.contains(&"/srv/x/y".to_owned()));
    }

    #[test]
    fn the_budget_is_capped_and_an_empty_ruleset_has_nothing_to_try() {
        let empty = RuleSet::load(Vec::new()).unwrap();
        let config = FuzzConfig {
            budget: usize::MAX,
            seed: 1,
        };
        assert_eq!(Candidates::new(&empty, config).budget, MAX_BUDGET);
        assert_eq!(Candidates::new(&empty, config).count(), 0);
        assert_eq!(fuzz(&empty, &[], config).candidates, 0);
    }

    #[test]
    fn the_generator_is_a_function_of_the_seed() {
        let mut one = Rng(3);
        let mut two = Rng(3);
        assert_eq!(one.next(), two.next());
        assert_ne!(one.next(), Rng(4).next());
        assert_eq!(Rng(1).below(0), 0);
        assert!(Rng(1).pick::<u8>(&[]).is_none());
    }
}
