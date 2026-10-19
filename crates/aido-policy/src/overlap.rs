//! Which actions can accept the same command.
//!
//! Overlapping actions are resolved safely: every action that accepts a command
//! contributes its requirement, and the strictest applies (see
//! [`crate::engine`]). An operator still needs to know where two rules
//! interact, because an overlap is two rules whose interaction nobody wrote
//! down, and it is how a rule meant as a narrow exception ends up governed by
//! the broad rule it was meant to refine. `aido check` prints this report.
//!
//! # Silence means disjoint
//!
//! Two actions overlap when they name the same program, byte for byte, and
//! some argument list satisfies both argument lists. Each position is a typed
//! matcher, and whether two positions can hold the same argument is decided
//! exactly for most pairs of types and cannot be decided here for some — a
//! pattern against a pattern. Where it cannot be decided, and where the search
//! would be too large to finish, the pair is reported as a *possible* overlap
//! rather than passed over. A pair is left out of the report only when no
//! command can satisfy both.
//!
//! A *certain* overlap carries a witness: the operands of a command both
//! actions accept, checked against both with the engine's own matcher, in
//! canonical form, before it is reported.
//!
//! # How
//!
//! An argument list is a small automaton whose state is the position that
//! comes next and how many arguments that position has consumed. The two lists
//! are run in step over one shared argument list, consuming an argument only
//! where both current positions can hold the same one, and the question is
//! whether both can finish together. That is a breadth-first search over pairs
//! of states, so a witness is as short as the two lists allow.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use bstr::ByteSlice;

use crate::argv::{Arg, Argv};
use crate::matcher::{ArgSpec, Meet, match_argv, meet};
use crate::rule::{Action, RuleSet};

/// The most pairs of automaton states one pair of actions may need.
///
/// Above it the pair is reported as a possible overlap. Real rules need a few
/// hundred; the bound exists so a pathological rule file cannot stall `aido
/// check`, and it errs towards reporting.
pub const STATE_BUDGET: usize = 1 << 18;

/// Two actions that can accept the same command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Overlap<'r> {
    /// The action declared first.
    pub first: &'r Action,
    /// The action declared after it.
    pub second: &'r Action,
    /// How certain the report is.
    pub extent: Extent,
}

/// How certain an overlap report is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extent {
    /// Both actions accept a command with these operands.
    Certain {
        /// The operands, checked against both argument lists.
        witness: Argv,
    },
    /// The analysis could not rule an overlap out.
    Possible {
        /// Why it could not decide.
        reason: Undecided,
    },
}

/// Why an overlap could be neither confirmed nor ruled out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Undecided {
    /// Pairs of positions, one from each action, whose matchers cannot be
    /// compared exactly.
    Positions(Vec<(String, String)>),
    /// The two argument lists have more pairs of states than
    /// [`STATE_BUDGET`].
    TooLarge,
    /// Both argument lists accept these operands position by position, but the
    /// engine never matches them as written: they are not in canonical form.
    Unconfirmed(Argv),
}

impl RuleSet {
    /// Every pair of actions that can accept the same command, in declaration
    /// order.
    ///
    /// Never misses a pair that can: see the [`overlap`](crate::overlap)
    /// module documentation for how a pair is decided and what *possible*
    /// means.
    pub fn overlaps(&self) -> Vec<Overlap<'_>> {
        let actions = self.actions();
        let mut found = Vec::new();
        for (index, first) in actions.iter().enumerate() {
            // Only the same program, compared the way the engine compares it.
            for second in actions
                .iter()
                .skip(index.saturating_add(1))
                .filter(|second| second.exe.as_bytes() == first.exe.as_bytes())
            {
                if let Some(extent) = compare(&first.args, &second.args) {
                    found.push(Overlap {
                        first,
                        second,
                        extent,
                    });
                }
            }
        }
        found
    }
}

/// Whether two argument lists can accept the same operands, and how certainly.
///
/// `None` only when no argument list satisfies both.
fn compare(first: &[ArgSpec], second: &[ArgSpec]) -> Option<Extent> {
    if states(first).saturating_mul(states(second)) > STATE_BUDGET {
        return Some(Extent::Possible {
            reason: Undecided::TooLarge,
        });
    }
    let product = Product::new(first, second);

    if let Some(path) = product.search(false) {
        let witness: Argv = path.iter().filter_map(Step::argument).cloned().collect();
        let confirmed = witness.canonicalize() == witness
            && match_argv(first, &witness).is_ok()
            && match_argv(second, &witness).is_ok();
        return Some(if confirmed {
            Extent::Certain { witness }
        } else {
            Extent::Possible {
                reason: Undecided::Unconfirmed(witness),
            }
        });
    }

    product.search(true).map(|path| Extent::Possible {
        reason: Undecided::Positions(undecided_on(&path)),
    })
}

/// How many automaton states an argument list has: each position counts every
/// number of arguments it can have consumed, and the finished state counts one.
fn states(specs: &[ArgSpec]) -> usize {
    specs.iter().fold(1usize, |total, spec| {
        total.saturating_add(spec.repeat.bounds().1.saturating_add(1))
    })
}

/// The positions on a path whose matchers could not be compared, each pair
/// once, described for an operator.
fn undecided_on(path: &[Step<'_>]) -> Vec<(String, String)> {
    let pairs: BTreeSet<(String, String)> = path
        .iter()
        .filter_map(|step| match step {
            Step::Undecided(first, second) => Some((position(first), position(second))),
            Step::Advance | Step::Consume(_) => None,
        })
        .collect();
    pairs.into_iter().collect()
}

/// One position, as the report names it.
fn position(spec: &ArgSpec) -> String {
    format!("`{}` ({})", spec.name, spec.matcher.describe())
}

/// The state of one argument list's automaton: the position that comes next,
/// and how many arguments it has consumed. A list is finished at
/// `(len, 0)`.
type Side = (usize, usize);

/// A state of both automata at once.
type State = (Side, Side);

/// The answer when a pair of positions was somehow never compared: undecided,
/// which reports, rather than disjoint, which would stay silent.
static NEVER_COMPARED: Meet = Meet::Undecided;

/// One edge of a path through the product.
#[derive(Clone, Copy, Debug)]
enum Step<'p> {
    /// One list moved past a position without consuming an argument.
    Advance,
    /// Both lists consumed this argument.
    Consume(&'p Arg),
    /// Both lists consumed an argument at these positions, whose matchers
    /// could not be compared exactly.
    Undecided(&'p ArgSpec, &'p ArgSpec),
}

impl<'p> Step<'p> {
    /// The argument this step consumed, if it consumed a known one.
    fn argument(&self) -> Option<&'p Arg> {
        match self {
            Self::Consume(argument) => Some(argument),
            Self::Advance | Self::Undecided(..) => None,
        }
    }
}

/// Two argument lists run in step.
struct Product<'s> {
    first: &'s [ArgSpec],
    second: &'s [ArgSpec],
    /// What each pair of positions has in common, computed once.
    meets: BTreeMap<(usize, usize), Meet>,
}

impl<'s> Product<'s> {
    fn new(first: &'s [ArgSpec], second: &'s [ArgSpec]) -> Self {
        let mut meets = BTreeMap::new();
        for (at_first, spec_first) in first.iter().enumerate() {
            for (at_second, spec_second) in second.iter().enumerate() {
                meets.insert(
                    (at_first, at_second),
                    meet(&spec_first.matcher, &spec_second.matcher),
                );
            }
        }
        Self {
            first,
            second,
            meets,
        }
    }

    /// A shortest path from the start to where both lists finish together.
    ///
    /// Consumes an argument only where both positions are known to share one,
    /// and, with `undecided`, also where that could not be decided.
    fn search(&self, undecided: bool) -> Option<Vec<Step<'_>>> {
        let start: State = ((0, 0), (0, 0));
        let finish: State = ((self.first.len(), 0), (self.second.len(), 0));
        let mut reached_by: BTreeMap<State, (State, Step<'_>)> = BTreeMap::new();
        let mut seen = BTreeSet::from([start]);
        let mut queue = VecDeque::from([start]);

        while let Some(state) = queue.pop_front() {
            if state == finish {
                let mut path = Vec::new();
                let mut at = state;
                while let Some((previous, step)) = reached_by.get(&at) {
                    path.push(*step);
                    at = *previous;
                }
                path.reverse();
                return Some(path);
            }
            for (next, step) in self.successors(state, undecided) {
                if seen.insert(next) {
                    reached_by.insert(next, (state, step));
                    queue.push_back(next);
                }
            }
        }
        None
    }

    /// The states one step from `state`.
    fn successors(&self, state: State, undecided: bool) -> Vec<(State, Step<'_>)> {
        let ((at_first, used_first), (at_second, used_second)) = state;
        let first = self.first.get(at_first);
        let second = self.second.get(at_second);
        let mut next = Vec::new();

        if let Some(spec) = first
            && used_first >= spec.repeat.bounds().0
        {
            let moved = (at_first.saturating_add(1), 0);
            next.push(((moved, (at_second, used_second)), Step::Advance));
        }
        if let Some(spec) = second
            && used_second >= spec.repeat.bounds().0
        {
            let moved = (at_second.saturating_add(1), 0);
            next.push((((at_first, used_first), moved), Step::Advance));
        }
        if let (Some(spec_first), Some(spec_second)) = (first, second)
            && used_first < spec_first.repeat.bounds().1
            && used_second < spec_second.repeat.bounds().1
        {
            let consumed = (
                (at_first, used_first.saturating_add(1)),
                (at_second, used_second.saturating_add(1)),
            );
            match self
                .meets
                .get(&(at_first, at_second))
                .unwrap_or(&NEVER_COMPARED)
            {
                Meet::Common(argument) => next.push((consumed, Step::Consume(argument))),
                Meet::Undecided if undecided => {
                    next.push((consumed, Step::Undecided(spec_first, spec_second)));
                }
                Meet::Undecided | Meet::Disjoint => {}
            }
        }
        next
    }
}

impl fmt::Display for Overlap<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (first, second) = (self.first, self.second);
        match &self.extent {
            Extent::Certain { witness } => write!(
                f,
                "overlap: {} ({}) and {} ({}) both accept {}",
                first.id,
                first.source,
                second.id,
                second.source,
                command(&first.exe, witness)
            ),
            Extent::Possible { reason } => write!(
                f,
                "possible overlap: {} ({}) and {} ({}): {reason}",
                first.id, first.source, second.id, second.source
            ),
        }
    }
}

impl fmt::Display for Undecided {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Positions(pairs) => {
                let pairs: Vec<String> = pairs
                    .iter()
                    .map(|(first, second)| format!("{first} against {second}"))
                    .collect();
                write!(f, "cannot compare {} exactly", pairs.join("; "))
            }
            Self::TooLarge => f.write_str("the argument lists are too large to compare exactly"),
            Self::Unconfirmed(operands) => write!(
                f,
                "both accept `{}` position by position, but not as a canonical argument list, \
                 which is all the engine matches",
                operands
                    .as_slice()
                    .iter()
                    .map(shown)
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        }
    }
}

/// A command as an operator would type it: the program, then the operands.
fn command(exe: &str, operands: &Argv) -> String {
    std::iter::once(Arg::from(exe))
        .chain(operands.as_slice().iter().cloned())
        .map(|argument| shown(&argument))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One argument, bare when that is unambiguous and quoted with escapes
/// otherwise, so an empty argument or one with a space in it cannot be misread.
///
/// For a human only; never compared and never parsed back.
fn shown(argument: &Arg) -> String {
    let bytes = argument.as_bytes();
    let bare = !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./=+:@,%".contains(b));
    if bare {
        argument.display()
    } else {
        format!("{:?}", bytes.as_bstr())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::matcher::{AnchoredPattern, Matcher, NameKind, Repeat};

    fn lit(name: &str, value: &str) -> ArgSpec {
        ArgSpec::one(name, Matcher::Literal(value.into()))
    }

    #[test]
    fn a_state_count_saturates_rather_than_wrapping() {
        let huge = ArgSpec::repeated(
            "x",
            Matcher::Literal("x".into()),
            Repeat::Between {
                min: 0,
                max: usize::MAX,
            },
        );
        // Clamped to MAX_REPEAT by `bounds`, so the count stays small.
        assert_eq!(states(&[huge]), 66);
        assert_eq!(states(&[]), 1);
    }

    #[test]
    fn identical_lists_overlap_on_their_own_shortest_argument_list() {
        let specs = [
            lit("verb", "status"),
            ArgSpec::repeated("full", Matcher::Literal("--full".into()), Repeat::Optional),
        ];
        assert_eq!(
            compare(&specs, &specs),
            Some(Extent::Certain {
                witness: Argv::new(["status"])
            })
        );
    }

    #[test]
    fn a_search_finds_the_empty_argument_list_or_nothing_at_all() {
        let product = Product::new(&[], &[]);
        // Start and finish coincide for two empty lists: the empty argv.
        assert_eq!(product.search(false).map(|path| path.len()), Some(0));
        let one = [lit("a", "a")];
        let other = [lit("b", "b")];
        assert!(Product::new(&one, &other).search(true).is_none());
    }

    #[test]
    fn steps_report_only_the_arguments_they_consumed() {
        let argument = Arg::from("x");
        let spec = lit("a", "a");
        assert_eq!(Step::Consume(&argument).argument(), Some(&argument));
        assert_eq!(Step::Advance.argument(), None);
        assert_eq!(Step::Undecided(&spec, &spec).argument(), None);
        assert!(format!("{:?}", Step::Advance).contains("Advance"));
    }

    #[test]
    fn undecided_positions_are_named_once_each() {
        let pattern = ArgSpec::one(
            "word",
            Matcher::Pattern(AnchoredPattern::new("[a-z]+").unwrap()),
        );
        let name = ArgSpec::repeated(
            "pkg",
            Matcher::Name(NameKind::DebName),
            Repeat::Between { min: 1, max: 3 },
        );
        let path = [
            Step::Undecided(&pattern, &name),
            Step::Advance,
            Step::Undecided(&pattern, &name),
        ];
        assert_eq!(
            undecided_on(&path),
            vec![(
                "`word` (pattern \"[a-z]+\")".to_owned(),
                "`pkg` (DebName)".to_owned()
            )]
        );
    }

    #[test]
    fn arguments_are_shown_bare_only_when_that_cannot_be_misread() {
        assert_eq!(shown(&Arg::from("nginx.service")), "nginx.service");
        assert_eq!(shown(&Arg::from("--property=A,B")), "--property=A,B");
        assert_eq!(shown(&Arg::from("")), "\"\"");
        assert_eq!(shown(&Arg::from("a b")), "\"a b\"");
        assert_eq!(shown(&Arg::new(vec![0xff])), "\"\\xff\"");
        assert_eq!(
            command("/usr/bin/x", &Argv::new(["a", ""])),
            "/usr/bin/x a \"\""
        );
    }
}
