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
//! error. It also says what changes, per harness and on the password path.

use std::collections::BTreeSet;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::caller::{CallerFacts, Classification};
use crate::engine::Settings;
use crate::files::{Generation, HarnessFile, RuleFile, RuleFilesError, load_policy_with_registry};
use crate::harness::valid_harness_label;
use crate::matcher::{ArgSpec, Matcher, Repeat};
use crate::rule::{Action, Outcome, RuleSet};
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

/// One thing one audience can do.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Capability {
    /// A harness label, or [`PASSWORD_PATH`].
    pub audience: String,
    /// How: `no password`, `asks a human`, or `password`.
    pub how: &'static str,
    /// The rule id and the command shape it accepts.
    pub what: String,
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

fn action_shape(action: &Action) -> String {
    std::iter::once(action.exe.clone())
        .chain(action.args.iter().map(shape))
        .collect::<Vec<_>>()
        .join(" ")
}

fn how(outcome: Outcome) -> &'static str {
    if outcome == Outcome::Allow {
        "no password"
    } else {
        "asks a human"
    }
}

/// Everything `rules` lets each audience do, by rule text.
///
/// The engine still applies the strictest of every action that accepts a
/// command, so an overlapping stricter rule can withhold what a line here
/// names; it never adds to it.
pub fn capabilities(rules: &RuleSet) -> BTreeSet<Capability> {
    let actions = rules.actions().iter().map(|action| {
        (
            format!("{}: {}", action.id, action_shape(action)),
            &action.harness,
            action.outcome,
        )
    });
    let operations = rules.operations().iter().map(|op| {
        (
            format!("{}: remove-path under {}", op.id, op.under),
            &op.harness,
            op.outcome,
        )
    });
    let mut found = BTreeSet::new();
    for (what, harness, outcome) in actions.chain(operations) {
        for label in harness {
            found.insert(Capability {
                audience: label.clone(),
                how: how(outcome),
                what: what.clone(),
            });
        }
        found.insert(Capability {
            audience: PASSWORD_PATH.to_owned(),
            how: "password",
            what,
        });
    }
    found
}

/// What a change does, and the generation it leads to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Review {
    /// What some audience can do after and not before.
    pub gains: Vec<Capability>,
    /// What some audience could do before and not after.
    pub losses: Vec<Capability>,
    /// The generation of the rules after the change.
    pub generation: Generation,
}

impl Review {
    /// One line per gain, then one per loss.
    pub fn lines(&self) -> Vec<String> {
        let line =
            |verb: &str, c: &Capability| format!("{} {verb} ({}): {}", c.audience, c.how, c.what);
        self.gains
            .iter()
            .map(|c| line("gains", c))
            .chain(self.losses.iter().map(|c| line("loses", c)))
            .collect()
    }
}

/// Every check the rules after a change must pass, as one sentence each.
fn problems(loaded: &crate::files::LoadedRuleSet) -> Vec<String> {
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

/// Judges a change from the rule files `before` to the rule files `after`.
///
/// # Errors
///
/// [`PackRefusal::Current`] when `before` does not load,
/// [`PackRefusal::Load`] when `after` does not, and [`PackRefusal::Problems`]
/// for every check `after` fails.
pub fn review(
    before: Vec<RuleFile>,
    after: Vec<RuleFile>,
    registry: &Result<Vec<HarnessFile>, String>,
) -> Result<Review, PackRefusal> {
    let registry = || registry.as_deref().map_err(Clone::clone);
    let old = load_policy_with_registry(before, registry()).map_err(PackRefusal::Current)?;
    let new = load_policy_with_registry(after, registry()).map_err(PackRefusal::Load)?;
    let found = problems(&new);
    if !found.is_empty() {
        return Err(PackRefusal::Problems(found));
    }
    let (old_caps, new_caps) = (capabilities(&old.rules), capabilities(&new.rules));
    Ok(Review {
        gains: new_caps.difference(&old_caps).cloned().collect(),
        losses: old_caps.difference(&new_caps).cloned().collect(),
        generation: new.generation,
    })
}

#[cfg(test)]
mod tests;
