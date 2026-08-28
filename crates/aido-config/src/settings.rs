//! The settings, and the two rules that keep the lower layers honest.
//!
//! # Security-relevant settings are not settable from the environment
//!
//! The caller controls the environment. A safety default readable from an
//! environment variable is a safety default one `export` away from off — and in
//! the case this project exists for, the *agent* controls the export. So the
//! refusal is a property of the setting, checked at merge time, rather than a
//! convention that a future contributor might not know about.
//!
//! # A project layer may only narrow
//!
//! A checked-in file is writable by anyone who can open a pull request. It may
//! tighten a limit, shorten a timeout, or add a confirmation requirement. It may
//! never remove one. Enforced per setting by [`Setting::narrows`], because
//! "narrower" means different things for a boolean and for a duration and there
//! is no generic answer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::layer::{Layer, Origin, Tracked};

/// Which setting a value belongs to.
///
/// An enum rather than string keys, so a typo in a merge is a compile error and
/// the schema can be enumerated exhaustively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Setting {
    /// Whether an enrolled agent's actions are confirmed by a human.
    ///
    /// Defaults to `true`, and there is deliberately no global off switch:
    /// narrowing the confirmation requirement takes a root-authored `trust.d`
    /// record plus a per-invocation flag, both enforced by the broker.
    ConfirmAgentActions,
    /// How long a pending confirmation waits before it is denied.
    ConfirmationTimeoutSecs,
    /// Whether the agent path is frozen.
    Frozen,
    /// Where audit records go.
    AuditSink,
    /// Whether output is coloured.
    ///
    /// The one presentation setting, and the only one the environment may set.
    Color,
    /// A fresh pty is always allocated for a privileged child.
    ///
    /// Compiled in. Present in the schema so a reader can see that it is not
    /// theirs to change, rather than set it and wonder why nothing happened.
    UsePty,
}

impl Setting {
    /// Every setting, for exhaustive reporting and schema export.
    pub const ALL: [Self; 6] = [
        Self::ConfirmAgentActions,
        Self::ConfirmationTimeoutSecs,
        Self::Frozen,
        Self::AuditSink,
        Self::Color,
        Self::UsePty,
    ];

    /// The key as it appears in a configuration file.
    pub fn key(self) -> &'static str {
        match self {
            Self::ConfirmAgentActions => "confirm_agent_actions",
            Self::ConfirmationTimeoutSecs => "confirmation_timeout_secs",
            Self::Frozen => "frozen",
            Self::AuditSink => "audit_sink",
            Self::Color => "color",
            Self::UsePty => "use_pty",
        }
    }

    /// Whether changing this setting changes what is permitted or observed.
    ///
    /// Everything except presentation. The environment may not set these.
    pub fn is_security_relevant(self) -> bool {
        !matches!(self, Self::Color)
    }

    /// Whether this setting can be configured at all.
    pub fn is_configurable(self) -> bool {
        !matches!(self, Self::UsePty)
    }

    /// Whether `candidate` is no wider than `current` for this setting.
    ///
    /// "Narrower" has no generic definition, so each setting says what it means:
    ///
    /// * A confirmation requirement narrows by turning **on**.
    /// * A freeze narrows by turning **on**.
    /// * A timeout narrows by getting **shorter**, because a shorter wait denies
    ///   sooner.
    /// * A sink and a colour choice have no ordering, so a project layer may not
    ///   change them at all.
    pub fn narrows(self, current: &Value, candidate: &Value) -> bool {
        match (self, current, candidate) {
            (
                Self::ConfirmAgentActions | Self::Frozen,
                Value::Bool(current),
                Value::Bool(candidate),
            ) => *candidate || !*current,
            (Self::ConfirmationTimeoutSecs, Value::Integer(current), Value::Integer(candidate)) => {
                candidate <= current
            }
            // No ordering, so no narrowing: equal is the only acceptable
            // "change". Also the fallback for a type mismatch, which a lower
            // layer must not be able to use as an escape hatch.
            _ => current == candidate,
        }
    }
}

/// A configured value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    /// A boolean.
    Bool(bool),
    /// A non-negative integer.
    Integer(u64),
    /// A string, from a closed set the caller validates.
    Text(String),
}

impl Value {
    /// The type name, for a schema and for an error message.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bool(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::Text(_) => "string",
        }
    }

    /// Renders the value for `config list`.
    pub fn render(&self) -> String {
        match self {
            Self::Bool(v) => v.to_string(),
            Self::Integer(v) => v.to_string(),
            Self::Text(v) => v.clone(),
        }
    }
}

/// Why a value was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MergeError {
    /// A security-relevant setting was set from the environment.
    #[error(
        "{key} cannot be set from the environment: the caller controls the environment, so a \
         safety setting readable from it is one `export` away from off"
    )]
    EnvironmentForbidden {
        /// The setting's key.
        key: String,
    },
    /// A narrowing-only layer tried to widen a setting.
    #[error(
        "{layer} may only narrow {key}: it tried to change {current} to {candidate}, which \
         permits more than the layer above it allowed"
    )]
    WouldWiden {
        /// The offending layer.
        layer: Layer,
        /// The setting's key.
        key: String,
        /// The value in force.
        current: String,
        /// What was asked for.
        candidate: String,
    },
    /// A value had the wrong type.
    #[error("{key} expects a {expected}, got a {actual}")]
    TypeMismatch {
        /// The setting's key.
        key: String,
        /// The expected type.
        expected: String,
        /// What was supplied.
        actual: String,
    },
    /// A setting that is compiled in was set.
    #[error("{key} is compiled in and cannot be configured; remove it")]
    NotConfigurable {
        /// The setting's key.
        key: String,
    },
}

/// The resolved configuration, with an origin for every setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    values: BTreeMap<Setting, Tracked<Value>>,
}

impl Default for Settings {
    /// The built-in defaults.
    ///
    /// `confirm_agent_actions` starts `true`. That is the project's headline
    /// promise, so it is the default rather than something an installer sets.
    fn default() -> Self {
        let mut values = BTreeMap::new();
        values.insert(
            Setting::ConfirmAgentActions,
            Tracked::default_value(Value::Bool(true)),
        );
        values.insert(
            Setting::ConfirmationTimeoutSecs,
            Tracked::default_value(Value::Integer(60)),
        );
        values.insert(Setting::Frozen, Tracked::default_value(Value::Bool(false)));
        values.insert(
            Setting::AuditSink,
            Tracked::default_value(Value::Text("journald".to_owned())),
        );
        values.insert(Setting::Color, Tracked::default_value(Value::Bool(true)));
        // Not configurable, and shown as such rather than omitted.
        values.insert(Setting::UsePty, Tracked::compiled(Value::Bool(true)));
        Self { values }
    }
}

impl Settings {
    /// The value in force for `setting`.
    ///
    /// Every setting always has one, because every setting has a default, so
    /// there is no `Option` for a caller to mishandle.
    pub fn get(&self, setting: Setting) -> &Tracked<Value> {
        self.values
            .get(&setting)
            .unwrap_or_else(|| Self::fallback(setting))
    }

    /// The compiled-in fallback, for a setting somehow absent from the map.
    ///
    /// Unreachable through the public API — [`Self::default`] populates every
    /// variant and nothing removes entries — and it returns the *safe* value
    /// rather than panicking, because a panic in a decision path is undefined
    /// policy.
    fn fallback(setting: Setting) -> &'static Tracked<Value> {
        static SAFE_TRUE: std::sync::LazyLock<Tracked<Value>> =
            std::sync::LazyLock::new(|| Tracked::compiled(Value::Bool(true)));
        let _ = setting;
        &SAFE_TRUE
    }

    /// Applies one value from one layer.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError::NotConfigurable`] for a compiled-in setting,
    /// [`MergeError::EnvironmentForbidden`] for a security-relevant setting from
    /// the environment, [`MergeError::TypeMismatch`] for the wrong type, and
    /// [`MergeError::WouldWiden`] when a narrowing-only layer tries to permit
    /// more.
    pub fn apply(
        &mut self,
        setting: Setting,
        value: Value,
        origin: Origin,
    ) -> Result<(), MergeError> {
        if !setting.is_configurable() {
            return Err(MergeError::NotConfigurable {
                key: setting.key().to_owned(),
            });
        }
        if origin.layer == Layer::Environment && setting.is_security_relevant() {
            return Err(MergeError::EnvironmentForbidden {
                key: setting.key().to_owned(),
            });
        }

        let current = self.get(setting).clone();
        if current.value.type_name() != value.type_name() {
            return Err(MergeError::TypeMismatch {
                key: setting.key().to_owned(),
                expected: current.value.type_name().to_owned(),
                actual: value.type_name().to_owned(),
            });
        }
        if origin.layer.is_narrowing_only() && !setting.narrows(&current.value, &value) {
            return Err(MergeError::WouldWiden {
                layer: origin.layer,
                key: setting.key().to_owned(),
                current: current.value.render(),
                candidate: value.render(),
            });
        }
        // A lower-precedence layer never displaces a higher one. Callers apply
        // in ascending order, and this makes an out-of-order call inert rather
        // than surprising.
        if origin.layer < current.origin.layer {
            return Ok(());
        }

        self.values.insert(setting, Tracked::from(value, origin));
        Ok(())
    }

    /// Every setting, with its value and origin, in key order.
    pub fn report(&self) -> Vec<(Setting, String, String)> {
        Setting::ALL
            .into_iter()
            .map(|setting| {
                let tracked = self.get(setting);
                (setting, tracked.value.render(), tracked.origin.to_string())
            })
            .collect()
    }

    /// The machine-readable schema, so an editor, `aido check`, and an agent all
    /// validate against one definition instead of three drifting ones.
    pub fn schema() -> Vec<SchemaEntry> {
        let defaults = Self::default();
        Setting::ALL
            .into_iter()
            .map(|setting| SchemaEntry {
                key: setting.key().to_owned(),
                value_type: defaults.get(setting).value.type_name().to_owned(),
                default: defaults.get(setting).value.render(),
                configurable: setting.is_configurable(),
                security_relevant: setting.is_security_relevant(),
                settable_from_environment: setting.is_configurable()
                    && !setting.is_security_relevant(),
            })
            .collect()
    }
}

/// One setting, described for a machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaEntry {
    /// The key as written in a file.
    pub key: String,
    /// Its type.
    pub value_type: String,
    /// Its built-in default, rendered.
    pub default: String,
    /// Whether it can be configured at all.
    pub configurable: bool,
    /// Whether changing it changes what is permitted or observed.
    pub security_relevant: bool,
    /// Whether the environment may set it.
    pub settable_from_environment: bool,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    fn system(line: u32) -> Origin {
        Origin::file(Layer::System, "/etc/aido/config.toml", line)
    }

    fn project(line: u32) -> Origin {
        Origin::file(Layer::Project, ".aido/policy.toml", line)
    }

    #[test]
    fn confirmation_is_on_by_default_and_says_it_is_a_default() {
        // The project's headline promise, so it is the default rather than
        // something an installer has to remember to set.
        let settings = Settings::default();
        let confirm = settings.get(Setting::ConfirmAgentActions);
        assert_eq!(confirm.value, Value::Bool(true));
        assert_eq!(confirm.origin.layer, Layer::BuiltInDefault);
        assert_eq!(confirm.origin.to_string(), "<default>");
    }

    #[test]
    fn a_system_layer_wins_over_a_default_and_reports_its_file_and_line() {
        let mut settings = Settings::default();
        settings
            .apply(
                Setting::ConfirmationTimeoutSecs,
                Value::Integer(30),
                system(12),
            )
            .unwrap();
        let timeout = settings.get(Setting::ConfirmationTimeoutSecs);
        assert_eq!(timeout.value, Value::Integer(30));
        assert_eq!(
            timeout.origin.to_string(),
            "system (/etc/aido/config.toml:12)"
        );
    }

    #[test]
    fn the_environment_cannot_touch_a_security_setting() {
        // The rule that matters most here. An agent controls the environment of
        // the process it spawns, so a safety default readable from it is not a
        // default at all.
        let mut settings = Settings::default();
        for setting in [
            Setting::ConfirmAgentActions,
            Setting::Frozen,
            Setting::ConfirmationTimeoutSecs,
            Setting::AuditSink,
        ] {
            let value = settings.get(setting).value.clone();
            let err = settings
                .apply(setting, value, Origin::layer(Layer::Environment))
                .unwrap_err();
            assert!(
                err.to_string()
                    .contains("cannot be set from the environment"),
                "{setting:?} was settable from the environment: {err}"
            );
            assert!(err.to_string().contains("one `export` away"), "{err}");
        }
    }

    #[test]
    fn the_environment_may_set_a_presentation_setting() {
        let mut settings = Settings::default();
        settings
            .apply(
                Setting::Color,
                Value::Bool(false),
                Origin::layer(Layer::Environment),
            )
            .unwrap();
        assert_eq!(settings.get(Setting::Color).value, Value::Bool(false));
        assert_eq!(
            settings.get(Setting::Color).origin.layer,
            Layer::Environment
        );
    }

    #[test]
    fn a_project_layer_may_turn_a_confirmation_on_but_never_off() {
        // Narrowing means "permits less". For a confirmation requirement that
        // is turning it on.
        let mut settings = Settings::default();
        // Start from a system layer that turned it off.
        settings
            .apply(Setting::ConfirmAgentActions, Value::Bool(false), system(4))
            .unwrap();
        // The project layer may turn it back on.
        settings
            .apply(Setting::ConfirmAgentActions, Value::Bool(true), project(1))
            .unwrap();
        assert_eq!(
            settings.get(Setting::ConfirmAgentActions).value,
            Value::Bool(true)
        );

        // And now it may not turn it off again.
        let err = settings
            .apply(Setting::ConfirmAgentActions, Value::Bool(false), project(2))
            .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("may only narrow"), "{message}");
        assert!(message.contains("permits more"), "{message}");
    }

    #[test]
    fn a_project_layer_may_shorten_a_timeout_but_never_lengthen_it() {
        // A shorter wait denies sooner, so shorter is narrower.
        let mut settings = Settings::default();
        settings
            .apply(
                Setting::ConfirmationTimeoutSecs,
                Value::Integer(30),
                project(1),
            )
            .unwrap();
        assert_eq!(
            settings.get(Setting::ConfirmationTimeoutSecs).value,
            Value::Integer(30)
        );

        let err = settings
            .apply(
                Setting::ConfirmationTimeoutSecs,
                Value::Integer(600),
                project(2),
            )
            .unwrap_err();
        assert!(err.to_string().contains("may only narrow"), "{err}");
        assert!(err.to_string().contains("30"), "{err}");
        assert!(err.to_string().contains("600"), "{err}");
    }

    #[test]
    fn a_project_layer_may_freeze_but_never_thaw() {
        let mut settings = Settings::default();
        settings
            .apply(Setting::Frozen, Value::Bool(true), project(1))
            .unwrap();
        assert_eq!(settings.get(Setting::Frozen).value, Value::Bool(true));
        assert!(
            settings
                .apply(Setting::Frozen, Value::Bool(false), project(2))
                .is_err()
        );
    }

    #[test]
    fn a_project_layer_cannot_change_a_setting_with_no_ordering() {
        // "Narrower" is meaningless for a sink, so the answer is "not at all"
        // rather than a guess.
        let mut settings = Settings::default();
        let err = settings
            .apply(
                Setting::AuditSink,
                Value::Text("none".to_owned()),
                project(1),
            )
            .unwrap_err();
        assert!(err.to_string().contains("may only narrow"), "{err}");
        // Setting it to the value already in force is permitted, because it
        // changes nothing.
        settings
            .apply(
                Setting::AuditSink,
                Value::Text("journald".to_owned()),
                project(2),
            )
            .unwrap();
    }

    #[test]
    fn a_narrowing_layer_cannot_use_a_type_mismatch_as_an_escape_hatch() {
        // The `_` arm of `narrows` compares for equality, so a mismatched type
        // is refused rather than treated as narrower. The type check catches it
        // first; this asserts both refuse.
        let mut settings = Settings::default();
        let err = settings
            .apply(Setting::ConfirmAgentActions, Value::Integer(0), project(1))
            .unwrap_err();
        assert!(err.to_string().contains("expects a boolean"), "{err}");

        // And directly: an integer is not a narrowing of a boolean.
        assert!(!Setting::ConfirmAgentActions.narrows(&Value::Bool(true), &Value::Integer(0)));
    }

    #[test]
    fn a_compiled_in_setting_cannot_be_configured_from_any_layer() {
        let mut settings = Settings::default();
        for layer in Layer::ALL {
            let err = settings
                .apply(Setting::UsePty, Value::Bool(false), Origin::layer(layer))
                .unwrap_err();
            assert!(err.to_string().contains("compiled in"), "{layer:?}: {err}");
        }
        // And it is still reported, so a reader sees it is not theirs to change.
        assert_eq!(settings.get(Setting::UsePty).origin.layer, Layer::Compiled);
    }

    #[test]
    fn a_lower_layer_applied_out_of_order_is_inert_rather_than_surprising() {
        let mut settings = Settings::default();
        settings
            .apply(
                Setting::Color,
                Value::Bool(false),
                Origin::layer(Layer::CliFlag),
            )
            .unwrap();
        // A system value arriving afterwards does not displace the flag.
        settings
            .apply(Setting::Color, Value::Bool(true), system(1))
            .unwrap();
        assert_eq!(settings.get(Setting::Color).value, Value::Bool(false));
        assert_eq!(settings.get(Setting::Color).origin.layer, Layer::CliFlag);
    }

    #[test]
    fn an_equal_precedence_layer_replaces_so_later_files_win() {
        // Two system drop-ins: the later one wins, which is the systemd
        // convention operators already expect.
        let mut settings = Settings::default();
        settings
            .apply(
                Setting::AuditSink,
                Value::Text("syslog".to_owned()),
                system(1),
            )
            .unwrap();
        settings
            .apply(
                Setting::AuditSink,
                Value::Text("journald".to_owned()),
                Origin::file(Layer::System, "/etc/aido/conf.d/99-late.toml", 2),
            )
            .unwrap();
        assert_eq!(settings.get(Setting::AuditSink).value.render(), "journald");
        assert!(
            settings
                .get(Setting::AuditSink)
                .origin
                .to_string()
                .contains("99-late")
        );
    }

    #[test]
    fn the_report_names_every_setting_and_where_it_came_from() {
        let mut settings = Settings::default();
        settings
            .apply(Setting::Frozen, Value::Bool(true), system(7))
            .unwrap();
        let report = settings.report();
        assert_eq!(report.len(), Setting::ALL.len());
        let frozen = report
            .iter()
            .find(|(s, _, _)| *s == Setting::Frozen)
            .unwrap();
        assert_eq!(frozen.1, "true");
        assert!(frozen.2.contains("config.toml:7"));
        // Compiled-in values appear, marked.
        let pty = report
            .iter()
            .find(|(s, _, _)| *s == Setting::UsePty)
            .unwrap();
        assert_eq!(pty.2, "<compiled-in>");
    }

    #[test]
    fn the_schema_states_which_settings_the_environment_may_set() {
        let schema = Settings::schema();
        assert_eq!(schema.len(), Setting::ALL.len());
        for entry in &schema {
            // Exactly one rule, stated once: the environment may set a setting
            // only if it is configurable and not security-relevant.
            assert_eq!(
                entry.settable_from_environment,
                entry.configurable && !entry.security_relevant,
                "{}",
                entry.key
            );
        }
        let color = schema.iter().find(|e| e.key == "color").unwrap();
        assert!(color.settable_from_environment);
        let confirm = schema
            .iter()
            .find(|e| e.key == "confirm_agent_actions")
            .unwrap();
        assert!(!confirm.settable_from_environment);
        assert_eq!(confirm.default, "true");
        let pty = schema.iter().find(|e| e.key == "use_pty").unwrap();
        assert!(!pty.configurable);
    }

    #[test]
    fn the_schema_round_trips_for_an_editor_or_an_agent() {
        let schema = Settings::schema();
        let json = serde_json::to_string(&schema).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<SchemaEntry>>(&json).unwrap(),
            schema
        );
        assert!(json.contains("confirm_agent_actions"));
    }

    #[test]
    fn every_setting_has_a_distinct_key_and_a_stated_posture() {
        let mut keys: Vec<&str> = Setting::ALL.into_iter().map(Setting::key).collect();
        let count = keys.len();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), count);
        // Only presentation is not security-relevant.
        let relaxed: Vec<Setting> = Setting::ALL
            .into_iter()
            .filter(|s| !s.is_security_relevant())
            .collect();
        assert_eq!(relaxed, vec![Setting::Color]);
        for setting in Setting::ALL {
            assert!(format!("{setting:?}").len() > 3);
        }
    }

    #[test]
    fn values_report_their_type_and_render_themselves() {
        assert_eq!(Value::Bool(true).type_name(), "boolean");
        assert_eq!(Value::Integer(1).type_name(), "integer");
        assert_eq!(Value::Text("x".to_owned()).type_name(), "string");
        assert_eq!(Value::Bool(false).render(), "false");
        assert_eq!(Value::Integer(60).render(), "60");
        assert_eq!(Value::Text("journald".to_owned()).render(), "journald");
        let json = serde_json::to_string(&Value::Integer(3)).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&json).unwrap(),
            Value::Integer(3)
        );
    }

    #[test]
    fn a_missing_entry_falls_back_to_a_safe_compiled_value_rather_than_panicking() {
        // Unreachable through the public API, since `default` populates every
        // variant and nothing removes entries. It returns the safe value
        // because a panic in a decision path is undefined policy.
        let empty = Settings {
            values: BTreeMap::new(),
        };
        let fallback = empty.get(Setting::ConfirmAgentActions);
        assert_eq!(fallback.value, Value::Bool(true));
        assert_eq!(fallback.origin.layer, Layer::Compiled);
    }

    #[test]
    fn settings_compare_and_debug_for_tests() {
        let a = Settings::default();
        let mut b = Settings::default();
        assert_eq!(a, b);
        b.apply(Setting::Color, Value::Bool(false), system(1))
            .unwrap();
        assert_ne!(a, b);
        assert!(format!("{a:?}").contains("ConfirmAgentActions"));
    }
}
