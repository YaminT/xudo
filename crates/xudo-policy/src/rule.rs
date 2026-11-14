//! The rule model: named actions with typed argument lists.
//!
//! # Named actions, not command strings
//!
//! A rule does not allowlist a command line. It allowlists an *action id* whose
//! executable is fixed by the rule and whose arguments are constrained
//! position-by-position. The front-end expands a verb into an action id plus
//! operands; no caller-supplied token ever lands in a position the rule did not
//! declare, so a token cannot reach a `--mount`, `--exec`, `-o`, or hook flag.
//!
//! Two independent designs converged on this shape — polkit's action ids and
//! Gemini CLI's `ShellTool(git status)` — which is some evidence it is the
//! right one.
//!
//! # Validation is a security control, not hygiene
//!
//! [`RuleSet::load`] rejects a ruleset rather than repairing it. An
//! unrecognised key is a hard failure (`deny_unknown_fields` everywhere),
//! because silently ignoring a security-relevant directive is exactly how an
//! operator ends up believing a constraint is in force when it is not.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::argv::Arg;
use crate::deny::{LIFECYCLE_OR_POWER_VERBS, evaluate_deny_list, exe_is_systemctl};
use crate::matcher::{ArgSpec, Matcher};
use crate::rule_test::RuleTest;

/// An action's stable identifier, e.g. `xudo.svc.restart`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionId(String);

impl ActionId {
    /// Wraps a string as an action id.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrows the id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ActionId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl fmt::Debug for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActionId({:?})", self.0)
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a rule is defined, so a decision can cite `file:line`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// The rule file's path.
    pub file: String,
    /// The 1-based line the action begins on.
    pub line: u32,
}

impl Default for Source {
    /// A provenance that names nothing, for a rule built in memory.
    ///
    /// `RuleSet::from_toml` overwrites this with the real file and line; a rule
    /// file cannot set it, so it cannot lie about where it came from.
    fn default() -> Self {
        Self {
            file: "<in-memory>".to_owned(),
            line: 0,
        }
    }
}

impl Source {
    /// Records a rule's origin.
    pub fn new(file: impl Into<String>, line: u32) -> Self {
        Self {
            file: file.into(),
            line,
        }
    }
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.file, self.line)
    }
}

/// The risk tier an action belongs to.
///
/// Tiers exist so an operator can reason about a whole class at once, and so
/// `Critical` can carry a mandatory confirmation that no rule-level setting can
/// remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// Reads system state, changes nothing.
    DiagRead,
    /// Changes running state but not unit definitions.
    SvcControl,
    /// Installs from a configured, root-owned repository.
    PkgInstall,
    /// Removes or upgrades packages; cascades.
    PkgRemove,
    /// Writes kernel or system tunables.
    SysTunable,
    /// Writes packet-filter state.
    NetFilter,
    /// Anything whose mistake is unrecoverable or whose scope cannot be bounded.
    Critical,
}

impl Tier {
    /// Whether this tier always demands human confirmation.
    pub fn always_confirms(self) -> bool {
        matches!(self, Self::Critical)
    }
}

/// When a human must approve an action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmPolicy {
    /// Follow the global `confirm_agent_actions` setting. The default.
    #[default]
    Default,
    /// Always confirm, for every caller, regardless of settings.
    Always,
    /// Never confirm.
    ///
    /// Honoured only in combination with a root-authored `trust.d` record and a
    /// per-invocation `--unattended` flag, both enforced by the broker. On its
    /// own this is a request, not a grant — which is why there is no global
    /// boolean that turns confirmation off.
    Never,
}

/// A single allowlisted action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// Keys are kebab-case, the vocabulary every other rule-file construct uses
// (`one-of`, `int-range`, `path-under`). `rename_all` rather than a `rename` per
// field so a field added later cannot reintroduce a snake_case key.
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Action {
    /// The action's stable id.
    pub id: ActionId,
    /// The risk tier.
    pub tier: Tier,
    /// Absolute path to the executable. Never resolved through `PATH`.
    pub exe: String,
    /// The argument list, position by position.
    ///
    /// An empty list permits an argv of length zero and nothing else.
    #[serde(default)]
    pub args: Vec<ArgSpec>,
    /// When to confirm.
    #[serde(default)]
    pub confirm: ConfirmPolicy,
    /// Whether an enrolled agent may run this at all.
    ///
    /// Defaults to `true`; setting it to `false` makes the action human-only.
    #[serde(default = "default_true")]
    pub agent_allowed: bool,
    /// Environment variables to pass through, by exact name.
    ///
    /// An allowlist, never a denylist. The child environment is built from
    /// scratch, so a variable absent from every list simply does not exist for
    /// the child.
    #[serde(default)]
    pub env_allow: Vec<String>,
    /// Where this action was defined.
    ///
    /// Assigned by the loader, never by the rule file: provenance a rule can
    /// declare is provenance an operator cannot trust.
    #[serde(skip)]
    pub source: Source,
}

/// One rule file's contents.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    action: Vec<Action>,
    /// Executable tests. Kept apart from `action` on purpose: a test is not
    /// policy and never reaches the compiled ruleset.
    #[serde(default)]
    test: Vec<toml::Spanned<RuleTest>>,
}

/// The most `[[test]]` tables one rule file may carry.
///
/// The broker and the gate parse every test of every file on every request, so
/// a generated suite must not become a per-request cost. A file over the bound
/// fails to load, for every reader alike.
///
/// Miri interprets the parser some thousand times slower, so under it the bound
/// is small: the check it guards is the same comparison, and the tests state
/// the bound through this constant, never as a literal.
pub const MAX_TESTS_PER_FILE: usize = if cfg!(miri) { 8 } else { 4096 };

/// The byte offset at which each line of `text` begins.
fn line_starts(text: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(text.match_indices('\n').map(|(at, _)| at.saturating_add(1)))
        .collect()
}

/// The 1-based line holding byte offset `at`.
fn line_at(starts: &[usize], at: usize) -> u32 {
    u32::try_from(starts.partition_point(|start| *start <= at)).unwrap_or(u32::MAX)
}

fn default_true() -> bool {
    true
}

/// Finds the 1-based line on which `id` is declared.
///
/// Returns 0 when the id cannot be located, which only happens if the id was
/// produced by something other than this file's text.
fn line_of_id(contents: &str, id: &str) -> u32 {
    let needle = format!("\"{id}\"");
    contents
        .lines()
        .enumerate()
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            trimmed.starts_with("id") && trimmed.contains(&needle)
        })
        .map_or(0, |(index, _)| {
            u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
        })
}

/// Why a ruleset was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuleSetError {
    /// Two actions share an id.
    #[error("duplicate action id {id} at {second} (first defined at {first})")]
    DuplicateId {
        /// The repeated id.
        id: String,
        /// Where it was first defined.
        first: Source,
        /// Where it was defined again.
        second: Source,
    },
    /// An action's executable is not an absolute path.
    #[error("action {id} at {at}: exe {exe:?} is not an absolute path")]
    RelativeExe {
        /// The offending action.
        id: String,
        /// Its declared executable.
        exe: String,
        /// Where it is defined.
        at: Source,
    },
    /// An action's executable path is not lexically clean.
    #[error("action {id} at {at}: exe {exe:?} contains a traversal or empty component")]
    UncleanExe {
        /// The offending action.
        id: String,
        /// Its declared executable.
        exe: String,
        /// Where it is defined.
        at: Source,
    },
    /// Two argument positions share a name, making a trace ambiguous.
    #[error("action {id} at {at}: duplicate argument position name {name:?}")]
    DuplicateArgName {
        /// The offending action.
        id: String,
        /// The repeated position name.
        name: String,
        /// Where it is defined.
        at: Source,
    },
    /// A rule file could not be parsed.
    #[error("rule file {file}: {reason}")]
    Parse {
        /// The file that failed.
        file: String,
        /// The parser's account of why.
        reason: String,
    },
    /// A rule file carries more `[[test]]` tables than the bound allows.
    #[error("rule file {file}: more than {limit} [[test]] tables")]
    TooManyTests {
        /// The file that failed.
        file: String,
        /// The bound.
        limit: usize,
    },
    /// A critical-tier action declares that it never confirms.
    #[error("action {id} at {at}: a critical-tier action cannot set confirm = \"never\"")]
    CriticalWithoutConfirm {
        /// The offending action.
        id: String,
        /// Where it is defined.
        at: Source,
    },
}

/// A validated set of allowlisted actions.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RuleSet {
    actions: Vec<Action>,
}

/// A systemctl action whose unit position can name any unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenUnitLint<'a> {
    /// The action id.
    pub id: &'a ActionId,
    /// The file and line of that action.
    pub source: &'a Source,
}

impl OpenUnitLint<'_> {
    /// The sentence `xudo check` and `xudo doctor` print.
    pub fn message(&self) -> String {
        format!(
            "{} at {}: this rule can start or stop any unit: replace the unit matcher with a one-of list of your units",
            self.id, self.source
        )
    }
}

/// A literal or a `one-of` whose options are literals.
fn matcher_is_closed_literals(matcher: &Matcher) -> bool {
    match matcher {
        Matcher::Literal(_) | Matcher::OneOf(_) => true,
        Matcher::IntRange { .. }
        | Matcher::PathUnder { .. }
        | Matcher::Name(_)
        | Matcher::Pattern(_) => false,
    }
}

/// Whether this position can accept a lifecycle or power verb.
///
/// Every matcher kind is asked. A `pattern` or a `name` that accepts `restart`
/// is a verb position, the same as a literal. A kind that accepts none of the
/// verbs is not.
fn matcher_accepts_lifecycle_or_power_verb(matcher: &Matcher) -> bool {
    LIFECYCLE_OR_POWER_VERBS
        .iter()
        .copied()
        .any(|verb| matcher.accepts(&Arg::new(verb.to_vec())))
}

impl RuleSet {
    /// Validates and takes ownership of a list of actions.
    ///
    /// # Errors
    ///
    /// Returns the first [`RuleSetError`] found. Loading is all-or-nothing: a
    /// partially-loaded ruleset is a ruleset whose contents nobody reviewed.
    pub fn load(actions: Vec<Action>) -> Result<Self, RuleSetError> {
        for (index, action) in actions.iter().enumerate() {
            if let Some(prior) = actions
                .iter()
                .take(index)
                .find(|other| other.id == action.id)
            {
                return Err(RuleSetError::DuplicateId {
                    id: action.id.as_str().to_owned(),
                    first: prior.source.clone(),
                    second: action.source.clone(),
                });
            }

            if !action.exe.starts_with('/') {
                return Err(RuleSetError::RelativeExe {
                    id: action.id.as_str().to_owned(),
                    exe: action.exe.clone(),
                    at: action.source.clone(),
                });
            }

            if action
                .exe
                .split('/')
                .skip(1)
                .any(|c| c.is_empty() || c == "." || c == "..")
            {
                return Err(RuleSetError::UncleanExe {
                    id: action.id.as_str().to_owned(),
                    exe: action.exe.clone(),
                    at: action.source.clone(),
                });
            }

            for (i, spec) in action.args.iter().enumerate() {
                if action
                    .args
                    .iter()
                    .take(i)
                    .any(|other| other.name == spec.name)
                {
                    return Err(RuleSetError::DuplicateArgName {
                        id: action.id.as_str().to_owned(),
                        name: spec.name.clone(),
                        at: action.source.clone(),
                    });
                }
            }

            if action.tier.always_confirms() && action.confirm == ConfirmPolicy::Never {
                return Err(RuleSetError::CriticalWithoutConfirm {
                    id: action.id.as_str().to_owned(),
                    at: action.source.clone(),
                });
            }
        }

        Ok(Self { actions })
    }

    /// Parses one rule file and validates it.
    ///
    /// Pure: the caller does the reading, this does the parsing. `file` is used
    /// only to build each action's [`Source`], which is derived here rather
    /// than read from the file so a rule cannot misreport its own origin.
    ///
    /// # Errors
    ///
    /// Returns [`RuleSetError::Parse`] when the TOML is invalid or contains an
    /// unrecognised key, and any validation error from [`RuleSet::load`].
    pub fn from_toml(file: &str, contents: &str) -> Result<Self, RuleSetError> {
        Self::from_toml_with_tests(file, contents).map(|(rules, _)| rules)
    }

    /// [`Self::from_toml`], and the file's `[[test]]` tables beside the ruleset.
    ///
    /// The tests are validated like everything else in the file (an unknown key
    /// is a hard failure) and returned separately: a test can never become part
    /// of the ruleset the engine reads. Each carries the file and line it was
    /// declared on, assigned here.
    ///
    /// # Errors
    ///
    /// As [`Self::from_toml`].
    pub fn from_toml_with_tests(
        file: &str,
        contents: &str,
    ) -> Result<(Self, Vec<RuleTest>), RuleSetError> {
        let parsed: RuleFile = toml::from_str(contents).map_err(|e| RuleSetError::Parse {
            file: file.to_owned(),
            reason: e.to_string(),
        })?;
        let actions = parsed
            .action
            .into_iter()
            .map(|mut action| {
                action.source = Source::new(file, line_of_id(contents, action.id.as_str()));
                action
            })
            .collect();
        if parsed.test.len() > MAX_TESTS_PER_FILE {
            return Err(RuleSetError::TooManyTests {
                file: file.to_owned(),
                limit: MAX_TESTS_PER_FILE,
            });
        }
        // The parser's own span for each table, turned into a line with one
        // pass over the file: no second reading of the text, and `[[ test ]]`
        // or a header-looking line inside a string cannot mislead it.
        let line_starts = line_starts(contents);
        let tests = parsed
            .test
            .into_iter()
            .map(|spanned| {
                let at = spanned.span().start;
                let mut test = spanned.into_inner();
                test.source = Source::new(file, line_at(&line_starts, at));
                test
            })
            .collect();
        Ok((Self::load(actions)?, tests))
    }

    /// Looks up an action by id.
    pub fn get(&self, id: &ActionId) -> Option<&Action> {
        self.actions.iter().find(|a| &a.id == id)
    }

    /// Every action, in declaration order.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// Every allowlisted executable that the compiled-in deny-list refuses.
    ///
    /// A non-empty result means a rule allowlists something that can be turned
    /// into a root shell, which defeats the design. This is the in-process half
    /// of the `GTFOBins` gate, and it runs against the shipped ruleset in the
    /// test suite so the check cannot be forgotten.
    pub fn self_denying_actions(&self) -> Vec<(&ActionId, Vec<crate::deny::CapabilityClass>)> {
        self.actions
            .iter()
            .filter_map(|action| {
                let classes: Vec<_> =
                    evaluate_deny_list(action.exe.as_bytes(), &crate::Argv::default())
                        .into_iter()
                        .map(|f| f.class)
                        .collect();
                if classes.is_empty() {
                    None
                } else {
                    Some((&action.id, classes))
                }
            })
            .collect()
    }

    /// Systemctl actions that can start or stop a unit they do not name.
    ///
    /// A position can be the verb when its matcher accepts any lifecycle or
    /// power verb, whatever the matcher kind. A later position that is not a
    /// literal or a finite `one-of` of literals is the finding. `unit-name`,
    /// `service-unit-name`, a pattern, a path, and an open repeat of any of
    /// those are that later position. A finite list is the operator's own
    /// units, and it is not an error. The check is the rule text, not an
    /// execution.
    pub fn open_unit_actions(&self) -> Vec<OpenUnitLint<'_>> {
        self.actions
            .iter()
            .filter_map(|action| {
                if !exe_is_systemctl(action.exe.as_bytes()) {
                    return None;
                }
                let verb_at = action
                    .args
                    .iter()
                    .position(|spec| matcher_accepts_lifecycle_or_power_verb(&spec.matcher))?;
                let open_unit = action
                    .args
                    .iter()
                    .skip(verb_at.saturating_add(1))
                    .any(|spec| !matcher_is_closed_literals(&spec.matcher));
                if !open_unit {
                    return None;
                }
                Some(OpenUnitLint {
                    id: &action.id,
                    source: &action.source,
                })
            })
            .collect()
    }

    /// Whether any action is `systemctl` with a lifecycle or power verb.
    ///
    /// The id is not consulted. A pattern or a name that accepts the verb
    /// counts, the same as a literal. An operator who copied the example and
    /// renamed it still has a lifecycle rule.
    pub fn has_systemctl_lifecycle_or_power(&self) -> bool {
        self.actions.iter().any(|action| {
            exe_is_systemctl(action.exe.as_bytes())
                && action
                    .args
                    .iter()
                    .any(|spec| matcher_accepts_lifecycle_or_power_verb(&spec.matcher))
        })
    }

    /// How many actions the set contains.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::matcher::{AnchoredPattern, Matcher, NameKind};

    fn action(id: &str) -> Action {
        Action {
            id: ActionId::new(id),
            tier: Tier::SvcControl,
            exe: "/usr/bin/systemctl".into(),
            args: vec![ArgSpec::one("unit", Matcher::Name(NameKind::UnitName))],
            confirm: ConfirmPolicy::Default,
            agent_allowed: true,
            env_allow: Vec::new(),
            source: Source::new("20-services.toml", 3),
        }
    }

    #[test]
    fn action_ids_render_for_display_and_debug() {
        let id = ActionId::from("xudo.svc.restart");
        assert_eq!(id.as_str(), "xudo.svc.restart");
        assert_eq!(id.to_string(), "xudo.svc.restart");
        assert_eq!(format!("{id:?}"), "ActionId(\"xudo.svc.restart\")");
    }

    #[test]
    fn sources_render_as_file_and_line() {
        let s = Source::new("20-services.toml", 12);
        assert_eq!(s.to_string(), "20-services.toml:12");
        assert_eq!(format!("{s:?}"), "20-services.toml:12");
        assert_eq!(s.line, 12);
    }

    #[test]
    fn only_the_critical_tier_always_confirms() {
        assert!(Tier::Critical.always_confirms());
        for tier in [
            Tier::DiagRead,
            Tier::SvcControl,
            Tier::PkgInstall,
            Tier::PkgRemove,
            Tier::SysTunable,
            Tier::NetFilter,
        ] {
            assert!(!tier.always_confirms(), "{tier:?}");
        }
    }

    #[test]
    fn tiers_are_ordered_and_serializable() {
        assert!(Tier::DiagRead < Tier::Critical);
        let json = serde_json::to_string(&Tier::PkgInstall).unwrap();
        assert_eq!(json, "\"pkg-install\"");
        assert_eq!(
            serde_json::from_str::<Tier>(&json).unwrap(),
            Tier::PkgInstall
        );
    }

    #[test]
    fn confirm_policy_defaults_to_the_global_setting() {
        assert_eq!(ConfirmPolicy::default(), ConfirmPolicy::Default);
        for p in [
            ConfirmPolicy::Default,
            ConfirmPolicy::Always,
            ConfirmPolicy::Never,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(serde_json::from_str::<ConfirmPolicy>(&json).unwrap(), p);
            assert!(format!("{p:?}").len() > 3);
        }
    }

    #[test]
    fn a_valid_set_loads_and_is_queryable() {
        let set = RuleSet::load(vec![action("a"), action("b")]).unwrap();
        assert_eq!(set.len(), 2);
        assert!(!set.is_empty());
        assert_eq!(set.actions().len(), 2);
        assert!(set.get(&ActionId::new("a")).is_some());
        assert!(set.get(&ActionId::new("nope")).is_none());
        assert!(RuleSet::default().is_empty());
        assert!(format!("{set:?}").contains('a'));
    }

    #[test]
    fn duplicate_ids_are_refused_with_both_locations() {
        let mut second = action("a");
        second.source = Source::new("30-more.toml", 9);
        let err = RuleSet::load(vec![action("a"), second]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("20-services.toml:3"), "{msg}");
        assert!(msg.contains("30-more.toml:9"), "{msg}");
    }

    #[test]
    fn a_relative_exe_is_refused() {
        // PATH resolution is never used, so a relative exe has no meaning and
        // must not be silently anchored to something.
        let mut a = action("a");
        a.exe = "systemctl".into();
        let err = RuleSet::load(vec![a]).unwrap_err();
        assert!(err.to_string().contains("is not an absolute path"), "{err}");
    }

    #[test]
    fn an_unclean_exe_path_is_refused() {
        for exe in ["/usr/bin/../bin/sh", "/usr/./bin/systemctl", "/usr//bin/sh"] {
            let mut a = action("a");
            a.exe = exe.into();
            let err = RuleSet::load(vec![a]).unwrap_err();
            assert!(err.to_string().contains("traversal"), "{exe} gave {err}");
        }
    }

    #[test]
    fn a_root_exe_is_clean_enough_to_load() {
        // "/" splits into one empty component that must not be mistaken for a
        // traversal.
        let mut a = action("a");
        a.exe = "/systemctl".into();
        assert!(RuleSet::load(vec![a]).is_ok());
    }

    #[test]
    fn duplicate_argument_names_are_refused() {
        let mut a = action("a");
        a.args = vec![
            ArgSpec::one("unit", Matcher::Name(NameKind::UnitName)),
            ArgSpec::one("unit", Matcher::Name(NameKind::UnitName)),
        ];
        let err = RuleSet::load(vec![a]).unwrap_err();
        assert!(
            err.to_string().contains("duplicate argument position name"),
            "{err}"
        );
        assert!(err.to_string().contains("\"unit\""));
    }

    #[test]
    fn a_critical_action_cannot_opt_out_of_confirmation() {
        let mut a = action("a");
        a.tier = Tier::Critical;
        a.confirm = ConfirmPolicy::Never;
        let err = RuleSet::load(vec![a]).unwrap_err();
        assert!(err.to_string().contains("critical-tier"), "{err}");
    }

    #[test]
    fn a_critical_action_may_confirm_always() {
        let mut a = action("a");
        a.tier = Tier::Critical;
        a.confirm = ConfirmPolicy::Always;
        assert!(RuleSet::load(vec![a]).is_ok());
    }

    #[test]
    fn denies_the_snake_case_spelling_of_a_human_only_rule() {
        // The keys are kebab-case; `deny_unknown_fields` makes the old spelling
        // a hard parse failure rather than a silently ignored directive. That is
        // the point: `agent_allowed = false` quietly dropped would publish a
        // human-only action to agents.
        let snake = toml::from_str::<Action>(
            r#"
            id = "xudo.svc.stop"
            tier = "svc-control"
            exe = "/usr/bin/systemctl"
            agent_allowed = false
            "#,
        );
        assert!(snake.is_err(), "a snake_case key must not parse");

        let kebab = toml::from_str::<Action>(
            r#"
            id = "xudo.svc.stop"
            tier = "svc-control"
            exe = "/usr/bin/systemctl"
            agent-allowed = false
            env-allow = ["TERM"]
            "#,
        )
        .unwrap();
        assert!(!kebab.agent_allowed);
        assert_eq!(kebab.env_allow, ["TERM"]);
    }

    #[test]
    fn actions_load_from_toml_with_defaults() {
        let parsed: Action = toml::from_str(
            r#"
            id = "xudo.svc.restart"
            tier = "svc-control"
            exe = "/usr/bin/systemctl"

            [[args]]
            name = "verb"
            matcher = { literal = "restart" }
            "#,
        )
        .unwrap();
        assert_eq!(parsed.confirm, ConfirmPolicy::Default);
        assert!(parsed.agent_allowed, "agent-allowed must default to true");
        assert!(parsed.env_allow.is_empty());
        assert_eq!(parsed.args.len(), 1);
        // Provenance is the loader's to assign, so a bare Action carries the
        // in-memory placeholder rather than anything the file could set.
        assert_eq!(parsed.source, Source::default());
    }

    #[test]
    fn an_action_with_no_args_key_permits_zero_arguments() {
        let parsed: Action = toml::from_str(
            r#"
            id = "xudo.svc.daemon-reload"
            tier = "svc-control"
            exe = "/usr/bin/systemctl"
            "#,
        )
        .unwrap();
        assert!(parsed.args.is_empty());
    }

    #[test]
    fn an_unknown_action_key_is_a_hard_error() {
        let err = toml::from_str::<Action>(
            r#"
            id = "x"
            tier = "diag-read"
            exe = "/bin/true"
            nopasswd = true
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("nopasswd"), "{err}");
    }

    #[test]
    fn provenance_does_not_survive_serialization() {
        // Deliberate: an Action that travelled over the wire has no trustworthy
        // origin, so it comes back with the placeholder and the receiver must
        // assign provenance itself.
        let a = action("a");
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("20-services.toml"), "{json}");
        let back = serde_json::from_str::<Action>(&json).unwrap();
        assert_eq!(back.source, Source::default());
        assert_eq!(back.id, a.id);
        assert_eq!(back.args, a.args);
    }

    #[test]
    fn from_toml_assigns_provenance_from_the_file_it_parsed() {
        let set = RuleSet::from_toml(
            "50-example.toml",
            r#"
[[action]]
id = "xudo.example"
tier = "diag-read"
exe = "/usr/bin/true"
"#,
        )
        .unwrap();
        let action = set.get(&ActionId::new("xudo.example")).unwrap();
        assert_eq!(action.source.file, "50-example.toml");
        assert_eq!(action.source.line, 3);
    }

    #[test]
    fn from_toml_reports_a_parse_failure_with_the_file_named() {
        let err = RuleSet::from_toml("broken.toml", "[[action]\n").unwrap_err();
        assert!(err.to_string().contains("broken.toml"), "{err}");
    }

    #[test]
    fn from_toml_propagates_validation_errors() {
        let err = RuleSet::from_toml(
            "bad.toml",
            r#"
[[action]]
id = "xudo.relative"
tier = "diag-read"
exe = "true"
"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("is not an absolute path"), "{err}");
    }

    #[test]
    fn an_unlocatable_id_reports_line_zero_rather_than_guessing() {
        // Only reachable if an id was not produced by the file's own text.
        assert_eq!(line_of_id("id = \"other\"\n", "missing"), 0);
        assert_eq!(line_of_id("\nid = \"here\"\n", "here"), 2);
    }

    #[test]
    fn self_denying_actions_flags_a_rule_that_allowlists_a_shell() {
        let mut shell = action("a");
        shell.exe = "/bin/sh".into();
        let clean = action("b");
        let set = RuleSet::load(vec![shell, clean]).unwrap();
        let offenders = set.self_denying_actions();
        assert_eq!(offenders.len(), 1);
        assert_eq!(offenders.first().map(|(id, _)| id.as_str()), Some("a"));
        assert!(offenders.first().is_some_and(|(_, classes)| {
            classes.contains(&crate::deny::CapabilityClass::SpawnsShell)
        }));
    }

    fn with_args(id: &str, args: Vec<ArgSpec>) -> Action {
        let mut found = action(id);
        found.args = args;
        found
    }

    fn spec(name: &str, matcher: Matcher) -> ArgSpec {
        ArgSpec::one(name, matcher)
    }

    /// Actions that together reach every arm of the open-unit lint.
    ///
    /// The pattern fixtures each compile a regex and match it against every
    /// lifecycle verb. That matrix runs natively in
    /// `crates/xudo-policy/tests/open_unit.rs`. This builds one pattern: as
    /// the verb, so `accepts` matches `start` on the first verb, and after a
    /// literal verb, so the closed-literal check sees a pattern without
    /// walking the verb list.
    /// Matchers that do not accept `start`, then the literal that does, then
    /// an open unit. Each kind is asked `accepts` before the verb is found.
    fn walked_before_the_verb(start: &Matcher, unit: &Matcher, service: &Matcher) -> Action {
        with_args(
            "walk",
            vec![
                spec("num", Matcher::IntRange { lo: 1, hi: 2 }),
                spec(
                    "path",
                    Matcher::PathUnder {
                        prefix: "/tmp".into(),
                    },
                ),
                spec("unit", unit.clone()),
                spec("service", service.clone()),
                spec(
                    "closed",
                    Matcher::OneOf(vec!["status".into(), "show".into()]),
                ),
                spec("empty", Matcher::OneOf(vec![])),
                spec("harmless", Matcher::Literal("daemon-reload".into())),
                spec("verb", start.clone()),
                spec("open", unit.clone()),
            ],
        )
    }

    fn open_unit_witness_actions() -> Vec<Action> {
        let pattern = Matcher::Pattern(AnchoredPattern::new("start").unwrap());
        let start = Matcher::Literal("start".into());
        let unit = Matcher::Name(NameKind::UnitName);
        let service = Matcher::Name(NameKind::ServiceUnitName);
        let walked = walked_before_the_verb(&start, &unit, &service);
        let by_name = with_args(
            "by-name",
            vec![
                spec("verb", Matcher::Name(NameKind::Hostname)),
                spec("unit", service),
            ],
        );
        let by_one = with_args(
            "by-one",
            vec![
                spec("verb", Matcher::OneOf(vec!["stop".into()])),
                spec("unit", unit.clone()),
            ],
        );
        let pattern_verb = with_args(
            "pattern-verb",
            vec![spec("verb", pattern.clone()), spec("unit", unit.clone())],
        );
        let range = with_args(
            "range",
            vec![
                spec("verb", start.clone()),
                spec("n", Matcher::IntRange { lo: 1, hi: 2 }),
            ],
        );
        let path = with_args(
            "path",
            vec![
                spec("verb", start.clone()),
                spec(
                    "p",
                    Matcher::PathUnder {
                        prefix: "/srv".into(),
                    },
                ),
            ],
        );
        let pattern_unit = with_args(
            "pattern-unit",
            vec![spec("verb", start.clone()), spec("unit", pattern)],
        );
        let finite = with_args(
            "finite",
            vec![
                spec("verb", start.clone()),
                spec("flag", Matcher::Literal("--no-block".into())),
                spec(
                    "unit",
                    Matcher::OneOf(vec!["nginx.service".into(), "example.service".into()]),
                ),
            ],
        );
        let mut other = action("other");
        other.exe = "/usr/bin/systemctl-helper".into();
        let verb_only = with_args(
            "verb-only",
            vec![spec("verb", Matcher::Literal("reboot".into()))],
        );
        let mut harmless = action("harmless");
        harmless.args = vec![
            spec("verb", Matcher::Literal("daemon-reload".into())),
            spec("unit", unit),
        ];
        let mut helper = action("helper");
        helper.exe = "/bin/systemctl-helper".into();
        vec![
            walked,
            finite,
            by_name,
            by_one,
            pattern_verb,
            range,
            path,
            pattern_unit,
            other,
            verb_only,
            harmless,
            helper,
        ]
    }

    fn assert_no_open_unit(set: &RuleSet, has_lifecycle: bool) {
        assert!(set.open_unit_actions().is_empty());
        assert_eq!(set.has_systemctl_lifecycle_or_power(), has_lifecycle);
    }

    #[test]
    fn open_unit_lint_witnesses_each_matcher_kind() {
        let actions = open_unit_witness_actions();
        let finite = actions
            .iter()
            .find(|item| item.id.as_str() == "finite")
            .unwrap();
        let verb_only = actions
            .iter()
            .find(|item| item.id.as_str() == "verb-only")
            .unwrap();
        let harmless = actions
            .iter()
            .find(|item| item.id.as_str() == "harmless")
            .unwrap();
        let helper = actions
            .iter()
            .find(|item| item.id.as_str() == "helper")
            .unwrap();
        assert_no_open_unit(&RuleSet::load(vec![finite.clone()]).unwrap(), true);
        assert_no_open_unit(&RuleSet::load(vec![verb_only.clone()]).unwrap(), true);
        assert_no_open_unit(&RuleSet::load(vec![harmless.clone()]).unwrap(), false);
        assert_no_open_unit(&RuleSet::load(vec![helper.clone()]).unwrap(), false);
        assert_no_open_unit(&RuleSet::load(vec![]).unwrap(), false);

        let set = RuleSet::load(actions).unwrap();
        let lints = set.open_unit_actions();
        let ids: Vec<_> = lints.iter().map(|lint| lint.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "walk",
                "by-name",
                "by-one",
                "pattern-verb",
                "range",
                "path",
                "pattern-unit",
            ]
        );
        assert!(set.has_systemctl_lifecycle_or_power());
        let lint = lints.first().unwrap();
        assert_eq!(lint.source.file, "20-services.toml");
        assert_eq!(lint.source.line, 3);
        assert_eq!(
            lint.message(),
            "walk at 20-services.toml:3: this rule can start or stop any unit: replace the unit matcher with a one-of list of your units"
        );
        assert!(format!("{lint:?}").contains("walk"));
    }
}
