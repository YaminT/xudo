//! Rule packs: a rule file with a `[pack]` header, and what installing or
//! removing one changes.
//!
//! A pack is today's rule file plus a header:
//!
//! ```toml
//! [pack]
//! name = "nginx-ops"
//! version = "1.0.0"
//! for = ["codex"]
//! ```
//!
//! `for` fills the `harness` of every action and operation that does not name
//! one, and an action that does name one may only narrow it: a label outside
//! `for` is a load error. A pack with no `for` applies to no harness, so any
//! action in it that lists a harness fails to load. The header's name and
//! version enter the ruleset generation.
//!
//! [`review`] is the one judgement `xudo rules add` and `xudo rules remove`
//! make, on the operator's side and again as root before the rename: the
//! changed ruleset must load, pass every `[[test]]`, carry a near-miss test
//! for every harness action, name only registered harnesses, and have no lint
//! error. It also says what changes, per harness and on the password path:
//! every setting of a rule that widens access is in its line, a `[[deny]]`
//! rule that goes is a gain for everyone, a lost rule that still overlaps
//! another says the other now applies, and the engine itself is asked about
//! every `[[test]]` command and a few each action accepts, before and after.
//!
//! The review prints a token that binds the change (the pack's bytes or the
//! name removed, and `--allow-waivers`) to the generation of the rules it was
//! judged against, which covers the harness registry. The root side recomputes
//! it from its own reading and refuses on any difference, so nothing installs
//! an effect nobody saw.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::argv::{Arg, Argv};
use crate::caller::{CallerFacts, Classification};
use crate::decision::{Decision, DenialCode, Verdict};
use crate::deny_rule::DenyRule;
use crate::engine::{Settings, evaluate_command};
use crate::files::{
    Generation, HarnessFile, LoadedRuleSet, RuleFile, RuleFilesError, load_policy_with_registry,
};
use crate::fuzz_check::{dictionary, witnesses_from};
use crate::harness::valid_harness_label;
use crate::matcher::{ArgSpec, Matcher, Repeat};
use crate::operation::Operation;
use crate::rule::{Action, ConfirmPolicy, Outcome, RuleSet};
use crate::rule_test::run_tests;

/// The audience of a capability every caller has after sudo's password.
pub const PASSWORD_PATH: &str = "password path";

/// The `[pack]` table of a rule file.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackHeader {
    /// The pack's name, `[a-z][a-z0-9-]{0,31}`: the installed file is
    /// `pack-<name>.toml`.
    pub name: String,
    /// The author's version, `[0-9A-Za-z.+_-]{1,32}`.
    pub version: String,
    /// The harnesses the pack is for. Empty: none.
    #[serde(default, rename = "for")]
    pub harnesses: Vec<String>,
}

impl PackHeader {
    /// Why the header is not one, if it is not.
    ///
    /// # Errors
    ///
    /// A bad name, version or label, or a label listed twice.
    pub fn validate(&self) -> Result<(), String> {
        if !valid_harness_label(&self.name) {
            return Err(format!(
                "pack name {:?} is not [a-z][a-z0-9-]{{0,31}}",
                self.name
            ));
        }
        let version_ok = !self.version.is_empty()
            && self.version.len() <= 32
            && self
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'_' | b'-'));
        if !version_ok {
            return Err(format!(
                "pack version {:?} is not [0-9A-Za-z.+_-]{{1,32}}",
                self.version
            ));
        }
        let mut seen = BTreeSet::new();
        for label in &self.harnesses {
            if !valid_harness_label(label) || !seen.insert(label.as_str()) {
                return Err(format!(
                    "pack for lists {label:?}, which is not a label or is listed twice"
                ));
            }
        }
        Ok(())
    }

    /// The file `xudo rules add` installs this pack as.
    pub fn file_name(&self) -> String {
        file_name(&self.name)
    }
}

/// The file a pack named `name` is installed as.
pub fn file_name(name: &str) -> String {
    format!("pack-{name}.toml")
}

/// Fills an empty `harness` list from the pack's `for`; refuses a label `for`
/// does not list. Returns the first such label.
pub(crate) fn narrow(harness: &mut Vec<String>, pack_for: &[String]) -> Result<(), String> {
    if harness.is_empty() {
        *harness = pack_for.to_vec();
        return Ok(());
    }
    harness
        .iter()
        .find(|label| !pack_for.contains(label))
        .map_or(Ok(()), |label| Err(label.clone()))
}

/// The SHA-256 of a candidate, as 64 lowercase hex characters: what the
/// operator reviewed, and what the root side must be handed again.
pub fn digest(bytes: &[u8]) -> String {
    Generation::from_digest(Sha256::digest(bytes).into()).hex()
}

/// Why a pack cannot be read, or cannot be installed or removed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackRefusal {
    /// The candidate is not UTF-8.
    #[error("the pack is not UTF-8 text")]
    NotUtf8,
    /// The candidate is not a rule file.
    #[error("{0}")]
    Parse(crate::rule::RuleSetError),
    /// The candidate has no `[pack]` header.
    #[error("the file has no [pack] header, so it is not a rule pack")]
    NotAPack,
    /// The rules as they are do not load.
    #[error("the installed rules do not load, so no change can be judged: {0}")]
    Current(RuleFilesError),
    /// The rules after the change do not load.
    #[error("after the change the rules would not load: {0}")]
    Load(RuleFilesError),
    /// The rules after the change load and fail a check.
    #[error("after the change the rules fail {} check(s): {}", .0.len(), .0.join("; "))]
    Problems(Vec<String>),
    /// The review would cost too much to make, here and again as root under
    /// the lock on the rules directory.
    #[error("the pack is too large to review: {0}; split it into smaller packs")]
    TooLarge(String),
    /// The pack waives a `GTFOBins` refusal and the operator did not allow it.
    #[error(
        "the pack waives {} GTFOBins refusal(s) ({}); read each and pass --allow-waivers to both \
         `xudo rules add` and the sudo step to install it",
        .0.len(), .0.join("; ")
    )]
    Waivers(Vec<String>),
}

/// The header of a candidate pack.
///
/// # Errors
///
/// [`PackRefusal::NotUtf8`], [`PackRefusal::Parse`] for anything the loader
/// refuses in the file on its own, and [`PackRefusal::NotAPack`].
pub fn header_of(bytes: &[u8]) -> Result<PackHeader, PackRefusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| PackRefusal::NotUtf8)?;
    RuleSet::parse_file("pack.toml", text)
        .map_err(PackRefusal::Parse)?
        .pack
        .ok_or(PackRefusal::NotAPack)
}

/// How an audience may run what a [`Capability`] names.
pub const NO_PASSWORD: &str = "no password";
/// An `ask-human` rule: the harness's request waits for a human.
pub const ASKS_A_HUMAN: &str = "asks a human";
/// The password path: sudo's password, then the rule.
pub const PASSWORD: &str = "password";
/// A `[[deny]]` rule: a refusal every caller has. Losing one widens.
pub const REFUSED: &str = "refused";
/// The audience of a `[[deny]]` rule.
pub const EVERYONE: &str = "everyone";

/// One thing one audience can do, or, for [`REFUSED`], is kept from doing.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Capability {
    /// A harness label, [`PASSWORD_PATH`], or [`EVERYONE`].
    pub audience: String,
    /// [`NO_PASSWORD`], [`ASKS_A_HUMAN`], [`PASSWORD`] or [`REFUSED`].
    pub how: &'static str,
    /// The rule id and everything in the rule that decides what it allows.
    pub what: String,
    /// The program an action runs, empty for anything else: what tells
    /// whether another action overlaps it.
    pub program: String,
}

impl Capability {
    /// Whether having it keeps someone from something: losing it widens.
    pub fn restricts(&self) -> bool {
        self.how == REFUSED
    }
}

/// A matcher, as a reader of a diff sees it.
fn shape(spec: &ArgSpec) -> String {
    let one = match &spec.matcher {
        Matcher::Literal(value) => value.clone(),
        other => format!("<{}>", other.describe()),
    };
    match spec.repeat {
        Repeat::One => one,
        Repeat::Optional => format!("[{one}]"),
        Repeat::Between { min, max } => format!("{one}{{{min},{max}}}"),
    }
}

/// An action as the diff shows it: the command shape, then every setting that
/// changes what it allows, so changing any of them is a loss and a gain.
///
/// Every field is named, so a field added to [`Action`] does not compile here
/// until someone decides whether it changes what the action allows.
fn action_text(action: &Action) -> String {
    let Action {
        id,
        tier,
        exe,
        args,
        confirm,
        agent_allowed,
        env_allow,
        // The audience and the how of the capability, not its text.
        harness: _,
        outcome: _,
        // Allows nothing: a reason, shown with the waivers.
        gtfobins_waiver: _,
        // Where, not what.
        source: _,
    } = action;
    let mut text = std::iter::once(exe.clone())
        .chain(args.iter().map(shape))
        .collect::<Vec<_>>()
        .join(" ");
    if !env_allow.is_empty() {
        let _ = write!(text, "; env-allow {env_allow:?}");
    }
    match confirm {
        ConfirmPolicy::Default => {}
        ConfirmPolicy::Always => text.push_str("; confirm always"),
        ConfirmPolicy::Never => text.push_str("; confirm never"),
    }
    if !agent_allowed {
        text.push_str("; agent-allowed false");
    }
    // No other tier changes a decision.
    if tier.always_confirms() {
        text.push_str("; tier critical");
    }
    format!("{id}: {text}")
}

fn operation_text(op: &Operation) -> String {
    let owners = op
        .owners
        .as_ref()
        .map_or_else(|| "any but root".to_owned(), |owners| format!("{owners:?}"));
    format!(
        "{}: remove-path under {}; recursive {}; max-depth {}; max-entries {}; owners {owners}",
        op.id, op.under, op.recursive, op.max_depth, op.max_entries
    )
}

fn deny_text(rule: &DenyRule) -> String {
    let when: String = rule
        .all
        .iter()
        .map(|clause| match (&clause.any_arg, &clause.any_deb_name) {
            (Some(values), _) => format!(" when an argument is one of {values:?}"),
            (None, values) => format!(
                " when a package is one of {:?}",
                values.as_deref().unwrap_or_default()
            ),
        })
        .collect();
    format!("{}: {}{when}", rule.id, rule.program.join(", "))
}

fn how(outcome: Outcome) -> &'static str {
    if outcome == Outcome::Allow {
        NO_PASSWORD
    } else {
        ASKS_A_HUMAN
    }
}

/// Everything `rules` lets each audience do, and every refusal it adds, by
/// rule text.
///
/// The engine applies the strictest of every action that accepts a command, so
/// an overlapping stricter rule can withhold what a line here names; removing
/// that rule then widens. [`review`] says so, and asks the engine.
pub fn capabilities(rules: &RuleSet) -> BTreeSet<Capability> {
    let actions = rules.actions().iter().map(|action| {
        (
            action_text(action),
            &action.harness,
            action.outcome,
            action.exe.clone(),
        )
    });
    let operations = rules
        .operations()
        .iter()
        .map(|op| (operation_text(op), &op.harness, op.outcome, String::new()));
    let mut found = BTreeSet::new();
    for (what, harness, outcome, program) in actions.chain(operations) {
        for label in harness {
            found.insert(Capability {
                audience: label.clone(),
                how: how(outcome),
                what: what.clone(),
                program: program.clone(),
            });
        }
        found.insert(Capability {
            audience: PASSWORD_PATH.to_owned(),
            how: PASSWORD,
            what,
            program,
        });
    }
    found.extend(rules.deny_rules().iter().map(|rule| Capability {
        audience: EVERYONE.to_owned(),
        how: REFUSED,
        what: deny_text(rule),
        program: String::new(),
    }));
    found
}

/// What the engine decides for one command, before and after a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effect {
    /// A harness label or [`PASSWORD_PATH`].
    pub audience: String,
    /// The command, for display.
    pub command: String,
    /// The decision before.
    pub before: &'static str,
    /// The decision after.
    pub after: &'static str,
    /// Whether the change lets the audience do more.
    pub widens: bool,
}

/// One decision in a word, ranked by how much it lets the caller do.
fn decided(decision: &Decision, agent: bool) -> (&'static str, u8) {
    match decision.verdict {
        Verdict::Allow if agent => (NO_PASSWORD, 4),
        Verdict::Allow => (PASSWORD, 3),
        Verdict::AllowWithConfirmation => ("confirmed by a human", 2),
        Verdict::Deny if decision.denial == Some(DenialCode::AskHuman) => ("queued for a human", 1),
        Verdict::Deny => (REFUSED, 0),
    }
}

/// How many example commands each action gives the engine probe.
const WITNESSES_PER_ACTION: usize = 3;

// A review runs twice, the second time as root holding the lock on the rules
// directory, so its cost is bounded. Miri interprets the review some thousand
// times slower, so under it the bounds are small; the tests state them
// through these constants, never as literals.

/// The most actions, operations and `[[deny]]` rules one pack may hold.
pub const MAX_PACK_RULES: usize = if cfg!(miri) { 4 } else { 256 };
/// The most distinct tokens one side's example commands are drawn from.
pub const MAX_PROBE_TOKENS: usize = if cfg!(miri) { 64 } else { 4096 };
/// The most commands the engine is asked about.
// Under miri, below what the loader lets the files' tests reach.
pub const MAX_PROBES: usize = if cfg!(miri) { 16 } else { 4096 };
/// The most engine work a review may cost, in matcher steps: for every
/// command asked about, every argument position of every action on its
/// program, times the square of the command's length plus one, the bound of
/// the argv matcher's table, for each audience and the test run. Measured on
/// rules built to be slow, a few seconds in a release build.
pub const MAX_REVIEW_WORK: usize = if cfg!(miri) { 1 << 16 } else { 1 << 28 };
/// The most engine lines a review prints; the rest are counted.
pub const MAX_EFFECT_LINES: usize = if cfg!(miri) { 2 } else { 64 };

/// A command the engine is asked about: the program and its operands.
type Probe = (Arg, Vec<Arg>);

/// Every command worth asking the engine about: each `[[test]]` argv, and a
/// few each action of either side accepts, drawn from one dictionary per side.
/// Refused when asking the engine about them all, for `audiences` callers and
/// the test run, would cost more than [`MAX_REVIEW_WORK`].
fn probes(sides: [&LoadedRuleSet; 2], audiences: usize) -> Result<BTreeSet<Probe>, PackRefusal> {
    let mut found = BTreeSet::new();
    for side in sides {
        found.extend(side.tests.iter().filter_map(|test| {
            test.argv.split_first().map(|(program, operands)| {
                (
                    Arg::from(program.as_str()),
                    operands.iter().map(|arg| Arg::from(arg.as_str())).collect(),
                )
            })
        }));
        let tokens = dictionary(&side.rules);
        if tokens.len() > MAX_PROBE_TOKENS {
            return Err(PackRefusal::TooLarge(format!(
                "the rules' matchers give {} example arguments, more than {MAX_PROBE_TOKENS}",
                tokens.len()
            )));
        }
        for action in side.rules.actions() {
            found.extend(
                witnesses_from(&tokens, action, 1, WITNESSES_PER_ACTION)
                    .into_iter()
                    .map(|argv| (Arg::from(action.exe.as_str()), argv.as_slice().to_vec())),
            );
        }
    }
    if found.len() > MAX_PROBES {
        return Err(PackRefusal::TooLarge(format!(
            "the engine would be asked about {} commands, more than {MAX_PROBES}",
            found.len()
        )));
    }
    let work = work(sides, &found).saturating_mul(audiences.saturating_add(1));
    if work > MAX_REVIEW_WORK {
        return Err(PackRefusal::TooLarge(format!(
            "asking the engine about every command would take {work} matcher steps, more than \
             {MAX_REVIEW_WORK}"
        )));
    }
    Ok(found)
}

/// What asking both sides about every probe once costs, in matcher steps.
fn work(sides: [&LoadedRuleSet; 2], probes: &BTreeSet<Probe>) -> usize {
    let mut positions: BTreeMap<&[u8], usize> = BTreeMap::new();
    for action in sides.iter().flat_map(|side| side.rules.actions()) {
        let count = positions.entry(action.exe.as_bytes()).or_default();
        *count = count.saturating_add(action.args.len().saturating_add(1));
    }
    probes
        .iter()
        .map(|(program, operands)| {
            let length = operands.len().saturating_add(1);
            positions
                .get(program.as_bytes())
                .copied()
                .unwrap_or_default()
                .saturating_mul(length.saturating_mul(length))
        })
        .fold(0, usize::saturating_add)
}

/// Who the engine is asked as: every harness either side names, and the
/// password path.
fn callers(old: &LoadedRuleSet, new: &LoadedRuleSet) -> Vec<(String, CallerFacts)> {
    let labels: BTreeSet<&String> = [&old.rules, &new.rules]
        .into_iter()
        .flat_map(|rules| {
            let actions = rules.actions().iter().flat_map(|a| &a.harness);
            actions.chain(rules.operations().iter().flat_map(|op| &op.harness))
        })
        .collect();
    labels
        .into_iter()
        .map(|label| {
            let agent = Classification::EnrolledAgent {
                agent_id: label.clone(),
                session_id: "review".to_owned(),
                declared_yolo: false,
            };
            (label.clone(), CallerFacts::new(agent, 1000))
        })
        .chain(std::iter::once((
            PASSWORD_PATH.to_owned(),
            CallerFacts::new(Classification::Human, 1000),
        )))
        .collect()
}

/// What the engine decides differently after the change, per audience, for
/// every probe command: the real effect of the change, overlaps included.
fn effects(
    [old, new]: [&LoadedRuleSet; 2],
    callers: &[(String, CallerFacts)],
    probes: BTreeSet<Probe>,
) -> Vec<Effect> {
    let mut found = Vec::new();
    for (program, operands) in probes {
        let argv = Argv::new(operands);
        for (audience, caller) in callers {
            let agent = caller.classification.is_enrolled_agent();
            let ask = |rules: &RuleSet| {
                decided(
                    &evaluate_command(rules, caller, &program, &argv, Settings::default()),
                    agent,
                )
            };
            let ((before, was), (after, now)) = (ask(&old.rules), ask(&new.rules));
            if before != after {
                found.push(Effect {
                    audience: audience.clone(),
                    command: format!("{} {}", program.display(), argv.display()),
                    before,
                    after,
                    widens: now > was,
                });
            }
        }
    }
    found
}

/// What a review is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change<'a> {
    /// Installing a pack, these bytes exactly.
    Add {
        /// The pack, as reviewed.
        pack: &'a [u8],
        /// Whether the operator allowed `gtfobins-waiver` keys in it.
        allow_waivers: bool,
    },
    /// Removing the pack of this name.
    Remove {
        /// The pack's name.
        name: &'a str,
    },
}

/// The token a review prints and the root side must be handed back: the
/// change, the flag, and the generation of the rules it was judged against,
/// which also covers the harness registry. Root recomputes it from its own
/// reading, so a pack, a rule file or a registry entry that changed since the
/// review refuses.
fn token(change: Change<'_>, before: &Generation) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"xudo rules review v1\0");
    match change {
        Change::Add {
            pack,
            allow_waivers,
        } => {
            hasher.update(b"add\0");
            hasher.update(Sha256::digest(pack));
            hasher.update(if allow_waivers { b"\x01" } else { b"\x00" });
        }
        Change::Remove { name } => {
            hasher.update(b"remove\0");
            hasher.update(name.as_bytes());
            hasher.update(b"\0");
        }
    }
    hasher.update(before.hex().as_bytes());
    Generation::from_digest(hasher.finalize().into()).hex()
}

/// The token of `change` onto the rules `before`, made without reading the
/// pack at all: only its digest enters it. The root side checks this before
/// it parses a byte of the pack, so a file swapped after the review is
/// refused unparsed, and no parse error can show a line of what it now is.
///
/// # Errors
///
/// [`PackRefusal::Current`] when `before` does not load.
pub fn token_of(
    before: Vec<RuleFile>,
    registry: &Result<Vec<HarnessFile>, String>,
    change: Change<'_>,
) -> Result<String, PackRefusal> {
    let old = load_policy_with_registry(before, registry.as_deref().map_err(Clone::clone))
        .map_err(PackRefusal::Current)?;
    Ok(token(change, &old.generation))
}

/// What a change does, and the generation it leads to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    /// What some audience can do after and not before, and every refusal that
    /// goes away.
    pub gains: Vec<Capability>,
    /// What some audience could do before and not after, and every refusal
    /// that is added.
    pub losses: Vec<Capability>,
    /// For a loss, the actions still on the same program for that audience:
    /// the loss may widen, because the strictest of them now applies.
    pub overlaps: Vec<(Capability, Vec<String>)>,
    /// For a lost action, each harness with an action on the same program
    /// that did not lose it itself, and those actions: the lost one applied to
    /// that harness's commands too, being the strictest, so it may widen.
    pub spills: Vec<(String, Capability, Vec<String>)>,
    /// What the engine decides differently, for every probe command.
    pub effects: Vec<Effect>,
    /// Each `gtfobins-waiver` the added pack carries, as `id: waiver`.
    pub waivers: Vec<String>,
    /// The generation of the rules after the change.
    pub generation: Generation,
    /// What the operator hands back to the root side.
    pub token: String,
}

impl Review {
    /// One line per gain, then one per loss, by rule text.
    pub fn lines(&self) -> Vec<String> {
        let gain = |c: &Capability| {
            if c.restricts() {
                format!("{} gains, a refusal goes: {}", c.audience, c.what)
            } else {
                format!("{} gains ({}): {}", c.audience, c.how, c.what)
            }
        };
        let loss = |c: &Capability| {
            let line = if c.restricts() {
                format!("{} loses, a new refusal: {}", c.audience, c.what)
            } else {
                format!("{} loses ({}): {}", c.audience, c.how, c.what)
            };
            match self.overlaps.iter().find(|(lost, _)| lost == c) {
                Some((_, now)) => format!("{line}; may widen: now {} applies", now.join(", ")),
                None => line,
            }
        };
        let spill = |(label, lost, now): &(String, Capability, Vec<String>)| {
            format!(
                "{label} may widen: {} goes, which also bound {label}'s own rules on that \
                 program; now {} applies",
                lost.what,
                now.join(", ")
            )
        };
        self.gains
            .iter()
            .map(gain)
            .chain(self.losses.iter().map(loss))
            .chain(self.spills.iter().map(spill))
            .collect()
    }

    /// One line per command the engine decides differently, gains first, at
    /// most [`MAX_EFFECT_LINES`] of them and then how many more there are.
    pub fn effect_lines(&self) -> Vec<String> {
        let line = |e: &Effect| {
            format!(
                "{} {}: {} was {}, now {}",
                e.audience,
                if e.widens { "gains" } else { "loses" },
                e.command,
                e.before,
                e.after
            )
        };
        let (wider, narrower): (Vec<&Effect>, Vec<&Effect>) =
            self.effects.iter().partition(|e| e.widens);
        let more = self.effects.len().saturating_sub(MAX_EFFECT_LINES);
        let hidden = wider.len().saturating_sub(MAX_EFFECT_LINES);
        let mut lines: Vec<String> = wider
            .into_iter()
            .chain(narrower)
            .take(MAX_EFFECT_LINES)
            .map(line)
            .collect();
        if more > 0 {
            lines.push(format!(
                "and {more} more commands decided differently, {hidden} of them gains"
            ));
        }
        lines
    }
}

/// Every check the rules after a change must pass, as one sentence each.
fn problems(loaded: &LoadedRuleSet) -> Vec<String> {
    let rules = &loaded.rules;
    let human = CallerFacts::new(Classification::Human, 1000);
    let failed = run_tests(rules, &loaded.tests, &human, Settings::default())
        .into_iter()
        .filter(|result| !result.outcome.passed())
        .map(|result| {
            format!(
                "the [[test]] at {} does not hold: {:?}",
                result.test.source, result.outcome
            )
        });
    let near_miss = rules
        .harness_lints(&loaded.tests)
        .into_iter()
        .map(|lint| lint.message);
    let unregistered = loaded.unregistered_labels().into_iter().map(|rule| {
        format!(
            "{} {} at {} names harness {:?}, which is not in the registry",
            rule.kind, rule.id, rule.at, rule.label
        )
    });
    let fault = loaded
        .registry_fault
        .iter()
        .map(|why| format!("the harness registry failed to load: {why}"));
    let denied = rules
        .self_denying_actions()
        .into_iter()
        .map(|(id, _)| format!("{id} allowlists an executable the deny-list refuses"));
    let open = rules
        .open_unit_actions()
        .into_iter()
        .map(|lint| lint.message());
    let multicall = rules
        .unpinned_multicall_actions()
        .into_iter()
        .map(|action| format!("{}: a multicall rule must pin its applet", action.id));
    failed
        .chain(near_miss)
        .chain(unregistered)
        .chain(fault)
        .chain(denied)
        .chain(open)
        .chain(multicall)
        .collect()
}

/// The file an added pack is installed as; nothing for a removal.
fn pack_file(change: Change<'_>) -> Option<String> {
    match change {
        Change::Add { pack, .. } => header_of(pack).ok().map(|header| header.file_name()),
        Change::Remove { .. } => None,
    }
}

/// Refuses an added pack with more rules than a review may judge.
fn small_enough(change: Change<'_>, new: &RuleSet) -> Result<(), PackRefusal> {
    let file = pack_file(change);
    let ours = |source: &crate::rule::Source| file.as_deref() == Some(source.file.as_str());
    let count = new
        .actions()
        .iter()
        .map(|a| &a.source)
        .chain(new.operations().iter().map(|op| &op.source))
        .chain(new.deny_rules().iter().map(|d| &d.source))
        .filter(|source| ours(source))
        .count();
    if count > MAX_PACK_RULES {
        return Err(PackRefusal::TooLarge(format!(
            "it holds {count} actions, operations and deny rules, more than {MAX_PACK_RULES}"
        )));
    }
    Ok(())
}

/// The waivers of the actions the added pack defines.
fn waivers(change: Change<'_>, new: &LoadedRuleSet) -> Vec<String> {
    let file = pack_file(change);
    new.rules
        .actions()
        .iter()
        .filter(|action| file.as_deref() == Some(action.source.file.as_str()))
        .filter_map(|action| {
            action
                .gtfobins_waiver
                .as_ref()
                .map(|waiver| format!("{}: {waiver}", action.id))
        })
        .collect()
}

/// For each lost action, the harnesses that keep an action on its program
/// without having lost the action themselves: the engine applies the
/// strictest of every action that accepts a command, whoever it names, so
/// the lost one may have held those harnesses back too.
fn spills(losses: &[Capability], new: &RuleSet) -> Vec<(String, Capability, Vec<String>)> {
    let mut found = Vec::new();
    // Every action has a password-path line, so this visits each lost one once.
    for lost in losses.iter().filter(|c| c.audience == PASSWORD_PATH) {
        let on_program: Vec<&Action> = new
            .actions()
            .iter()
            .filter(|action| action.exe == lost.program)
            .collect();
        let labels: BTreeSet<&String> = on_program.iter().flat_map(|a| &a.harness).collect();
        for label in labels {
            let own = losses
                .iter()
                .any(|c| &c.audience == label && c.what == lost.what);
            if own {
                continue;
            }
            let now = on_program
                .iter()
                .filter(|action| action.harness.contains(label))
                .map(|action| action.id.to_string())
                .collect();
            found.push((label.clone(), lost.clone(), now));
        }
    }
    found
}

/// Judges `change`, from the rule files `before` to the rule files `after`.
///
/// # Errors
///
/// [`PackRefusal::Current`] when `before` does not load,
/// [`PackRefusal::Load`] when `after` does not, [`PackRefusal::Problems`]
/// for every check `after` fails, and [`PackRefusal::Waivers`] for an added
/// pack that waives a `GTFOBins` refusal without `allow_waivers`.
pub fn review(
    before: Vec<RuleFile>,
    after: Vec<RuleFile>,
    registry: &Result<Vec<HarnessFile>, String>,
    change: Change<'_>,
) -> Result<Review, PackRefusal> {
    let registry = || registry.as_deref().map_err(Clone::clone);
    let old = load_policy_with_registry(before, registry()).map_err(PackRefusal::Current)?;
    let new = load_policy_with_registry(after, registry()).map_err(PackRefusal::Load)?;
    small_enough(change, &new.rules)?;
    // Bounded before anything is asked of the engine, the tests included.
    let callers = callers(&old, &new);
    let probes = probes([&old, &new], callers.len())?;
    let found = problems(&new);
    if !found.is_empty() {
        return Err(PackRefusal::Problems(found));
    }
    let waivers = waivers(change, &new);
    let allowed = match change {
        Change::Add { allow_waivers, .. } => allow_waivers,
        Change::Remove { .. } => true,
    };
    if !allowed && !waivers.is_empty() {
        return Err(PackRefusal::Waivers(waivers));
    }
    let (old_caps, new_caps) = (capabilities(&old.rules), capabilities(&new.rules));
    let (mut gains, mut losses) = (Vec::new(), Vec::new());
    // A grant that appears is a gain; a refusal that appears is a loss.
    for added in new_caps.difference(&old_caps).cloned() {
        if added.restricts() {
            losses.push(added);
        } else {
            gains.push(added);
        }
    }
    for removed in old_caps.difference(&new_caps).cloned() {
        if removed.restricts() {
            gains.push(removed);
        } else {
            losses.push(removed);
        }
    }
    let overlaps = losses
        .iter()
        .filter_map(|lost| {
            let now: Vec<String> = new
                .rules
                .actions()
                .iter()
                .filter(|action| {
                    !lost.program.is_empty()
                        && action.exe == lost.program
                        && (lost.audience == PASSWORD_PATH
                            || action.harness.contains(&lost.audience))
                })
                .map(|action| action.id.to_string())
                .collect();
            (!now.is_empty()).then(|| (lost.clone(), now))
        })
        .collect();
    let spills = spills(&losses, &new.rules);
    let effects = effects([&old, &new], &callers, probes);
    Ok(Review {
        gains,
        losses,
        overlaps,
        spills,
        effects,
        waivers,
        generation: new.generation,
        token: token(change, &old.generation),
    })
}

/// The marker line every pack `xudo rules add` installs begins with. It
/// begins with the marker every file xudo writes carries, so the install's
/// file operations accept it, and goes on so a sudoers drop-in or any other
/// file of xudo's is never taken for a pack.
pub const PACK_MARKER: &str = "# Managed by xudo. Rule pack:";

/// A pack's bytes as installed: the marker line, then the pack unchanged.
pub fn installed_bytes(pack: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{PACK_MARKER} installed by `xudo rules add`; remove it with `xudo rules remove`.\n"
    )
    .into_bytes();
    bytes.extend_from_slice(pack);
    bytes
}

/// Whether a rule file is a pack `xudo rules add` installed.
pub fn installed_by_xudo(bytes: &[u8]) -> bool {
    bytes.starts_with(PACK_MARKER.as_bytes())
}

/// The rule files with `pack` installed as `xudo rules add` writes it: the
/// file of its name replaced or added. The operator's review and root's both
/// build the change this way, so they judge the same files.
pub fn with_pack(before: &[RuleFile], header: &PackHeader, pack: &[u8]) -> Vec<RuleFile> {
    let name = header.file_name().into_bytes();
    before
        .iter()
        .filter(|found| found.name != name)
        .cloned()
        .chain(std::iter::once(RuleFile {
            name: name.clone(),
            bytes: installed_bytes(pack),
        }))
        .collect()
}

/// The rule files without the pack `name`, when `before` holds it as a file
/// `xudo rules add` installed; `None` otherwise, a name that is not a pack
/// name included.
pub fn without_pack(before: &[RuleFile], name: &str) -> Option<Vec<RuleFile>> {
    let file = file_name(name);
    let ours = valid_harness_label(name)
        && before
            .iter()
            .any(|found| found.name == file.as_bytes() && installed_by_xudo(&found.bytes));
    ours.then(|| {
        before
            .iter()
            .filter(|found| found.name != file.as_bytes())
            .cloned()
            .collect()
    })
}

#[cfg(test)]
mod tests;
