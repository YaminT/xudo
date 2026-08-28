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

use crate::deny::evaluate_deny_list;
use crate::matcher::ArgSpec;

/// An action's stable identifier, e.g. `aido.svc.restart`.
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
#[serde(deny_unknown_fields)]
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
        Self::load(actions)
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
    use crate::matcher::{Matcher, NameKind};

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
        let id = ActionId::from("aido.svc.restart");
        assert_eq!(id.as_str(), "aido.svc.restart");
        assert_eq!(id.to_string(), "aido.svc.restart");
        assert_eq!(format!("{id:?}"), "ActionId(\"aido.svc.restart\")");
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
    fn actions_load_from_toml_with_defaults() {
        let parsed: Action = toml::from_str(
            r#"
            id = "aido.svc.restart"
            tier = "svc-control"
            exe = "/usr/bin/systemctl"

            [[args]]
            name = "verb"
            matcher = { literal = "restart" }
            "#,
        )
        .unwrap();
        assert_eq!(parsed.confirm, ConfirmPolicy::Default);
        assert!(parsed.agent_allowed, "agent_allowed must default to true");
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
            id = "aido.svc.daemon-reload"
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
id = "aido.example"
tier = "diag-read"
exe = "/usr/bin/true"
"#,
        )
        .unwrap();
        let action = set.get(&ActionId::new("aido.example")).unwrap();
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
id = "aido.relative"
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
}
