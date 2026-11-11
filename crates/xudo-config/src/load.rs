//! Turning one configuration file's text into layered values.
//!
//! Pure: text in, values out. The caller does the reading, so this is testable
//! against a hostile file without one existing on disk.
//!
//! # An unrecognised key fails the whole file
//!
//! Not a warning. Silently ignoring a security-relevant directive is exactly the
//! sudo-rs-on-Ubuntu footgun this project exists to avoid, and a typo in
//! `confirm_agent_actions` that reads as "no such setting, carry on" is the same
//! failure with a friendlier face.
//!
//! # Line numbers are derived, not declared
//!
//! A file cannot state its own provenance. The line for each key is the offset the
//! TOML parser reported for it, so an origin points at the real declaration rather than at
//! whatever the file claimed.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::layer::{Layer, Origin};
use crate::settings::{MergeError, Setting, Settings, Value};

/// Why a file could not be applied.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// The text is not valid TOML, or contains a key that is not a setting.
    #[error("{file}: {reason}")]
    Parse {
        /// The file.
        file: String,
        /// The parser's account of why.
        reason: String,
    },
    /// A value was refused by the merge rules.
    #[error("{file}:{line}: {source}")]
    Rejected {
        /// The file.
        file: String,
        /// The line the offending key is on.
        line: u32,
        /// What the merge refused, and why.
        source: MergeError,
    },
}

/// One file's worth of settings.
///
/// Every field is optional, because a file sets what it wants to set. Unknown
/// fields are a hard error.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    confirm_agent_actions: Option<bool>,
    confirm_human_path: Option<bool>,
    confirmation_timeout_secs: Option<u64>,
    frozen: Option<bool>,
    audit_sink: Option<String>,
    color: Option<bool>,
    /// Present only so that setting it produces the *right* error — "compiled
    /// in and cannot be configured" — rather than "unknown key".
    use_pty: Option<bool>,
}

/// Applies one file's contents to `settings` as `layer`.
///
/// # Errors
///
/// Returns [`LoadError::Parse`] for invalid TOML or an unrecognised key, and
/// [`LoadError::Rejected`] when a value is refused by the merge rules — a
/// security setting from the environment, a widening from a project layer, or a
/// compiled-in setting.
pub fn apply_file(
    settings: &mut Settings,
    layer: Layer,
    file: &str,
    contents: &str,
) -> Result<(), LoadError> {
    apply_file_scoped(settings, layer, file, contents, &Setting::ALL)
}

/// Like [`apply_file`], for a program that owns only some of the settings.
///
/// A key that is a setting of another program fails the whole file, exactly as
/// an unknown key does: `ido` must not accept `frozen = true` and then ignore
/// it, because a file that does not mean what it says is the failure this
/// project refuses to paper over.
///
/// # Errors
///
/// As [`apply_file`], plus [`LoadError::Parse`] for a key outside `owned`.
pub fn apply_file_scoped(
    settings: &mut Settings,
    layer: Layer,
    file: &str,
    contents: &str,
    owned: &[Setting],
) -> Result<(), LoadError> {
    let document = toml::de::DeTable::parse(contents).map_err(|e| LoadError::Parse {
        file: file.to_owned(),
        reason: e.to_string(),
    })?;
    let lines = key_lines(contents, document.get_ref());
    let parsed: File = toml::from_str(contents).map_err(|e| LoadError::Parse {
        file: file.to_owned(),
        reason: e.to_string(),
    })?;

    if let Some(foreign) = lines
        .keys()
        .find(|key| !Setting::from_key(key).is_some_and(|s| owned.contains(&s)))
    {
        return Err(LoadError::Parse {
            file: file.to_owned(),
            reason: format!("{foreign} is not a setting of this program"),
        });
    }

    if parsed
        .audit_sink
        .as_deref()
        .is_some_and(|sink| sink != "journald")
    {
        return Err(LoadError::Parse {
            file: file.to_owned(),
            reason: "audit_sink only accepts \"journald\"".to_owned(),
        });
    }

    // Ordered so a file's errors are reported in a stable order regardless of
    // how the keys were written.
    let entries: [(Setting, Option<Value>); 7] = [
        (
            Setting::ConfirmAgentActions,
            parsed.confirm_agent_actions.map(Value::Bool),
        ),
        (
            Setting::ConfirmHumanPath,
            parsed.confirm_human_path.map(Value::Bool),
        ),
        (
            Setting::ConfirmationTimeoutSecs,
            parsed.confirmation_timeout_secs.map(Value::Integer),
        ),
        (Setting::Frozen, parsed.frozen.map(Value::Bool)),
        (Setting::AuditSink, parsed.audit_sink.map(Value::Text)),
        (Setting::Color, parsed.color.map(Value::Bool)),
        (Setting::UsePty, parsed.use_pty.map(Value::Bool)),
    ];

    for (setting, value) in entries {
        let Some(value) = value else {
            continue;
        };
        let line = lines.get(setting.key()).copied().unwrap_or_default();
        settings
            .apply(setting, value, Origin::file(layer, file, line))
            .map_err(|source| LoadError::Rejected {
                file: file.to_owned(),
                line,
                source,
            })?;
    }

    Ok(())
}

/// Maps each top-level key to the 1-based line the parser found it on.
///
/// The offset comes from the TOML parse itself, so a quoted key resolves and a
/// lookalike inside a string does not.
fn key_lines<'a>(contents: &str, table: &'a toml::de::DeTable<'_>) -> BTreeMap<&'a str, u32> {
    table
        .iter()
        .map(|(key, _)| {
            let newlines = contents
                .as_bytes()
                .iter()
                .take(key.span().start)
                .filter(|byte| **byte == b'\n')
                .count();
            let line = u32::try_from(newlines.saturating_add(1)).unwrap_or(u32::MAX);
            (key.get_ref().as_ref(), line)
        })
        .collect()
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

    #[test]
    fn a_scoped_file_refuses_another_programs_setting() {
        // `ido` must not accept `frozen = true` and then ignore it.
        let mut settings = Settings::default();
        let err = apply_file_scoped(
            &mut settings,
            Layer::User,
            "config.toml",
            "color = false\nfrozen = true\n",
            &[Setting::Color],
        )
        .unwrap_err();
        assert!(err.to_string().contains("frozen is not a setting"), "{err}");
        assert_eq!(settings, Settings::default());
        apply_file_scoped(
            &mut settings,
            Layer::User,
            "config.toml",
            "color = false\n",
            &[Setting::Color],
        )
        .unwrap();
        assert_eq!(settings.get(Setting::Color).value, Value::Bool(false));
    }

    #[test]
    fn a_file_sets_what_it_names_and_leaves_the_rest_alone() {
        let mut settings = Settings::default();
        apply_file(
            &mut settings,
            Layer::System,
            "config.toml",
            "confirmation_timeout_secs = 30\n",
        )
        .unwrap();
        assert_eq!(
            settings.get(Setting::ConfirmationTimeoutSecs).value,
            Value::Integer(30)
        );
        // Untouched, and still reporting itself as a default.
        assert_eq!(
            settings.get(Setting::Frozen).origin.layer,
            Layer::BuiltInDefault
        );
    }

    #[test]
    fn origin_line_survives_a_quoted_key() {
        let mut settings = Settings::default();
        let contents = "# c\n\"frozen\" = true\n'color' = false\n";
        apply_file(&mut settings, Layer::System, "c.toml", contents).unwrap();
        assert_eq!(
            settings.get(Setting::Frozen).origin.to_string(),
            "system (c.toml:2)"
        );
        assert_eq!(
            settings.get(Setting::Color).origin.to_string(),
            "system (c.toml:3)"
        );
    }

    #[test]
    fn origin_line_ignores_a_lookalike_inside_a_multiline_string() {
        let contents = "note = \"\"\"\nfrozen = false\n\"\"\"\nfrozen = true\n";
        let document = toml::de::DeTable::parse(contents).unwrap();
        let lines = key_lines(contents, document.get_ref());
        assert_eq!(lines.get("frozen"), Some(&4));
        assert_eq!(lines.get("note"), Some(&1));
    }

    #[test]
    fn origin_line_for_a_dotted_or_table_key() {
        // A dotted or table key is not a setting: refused, never mis-pointed.
        let mut settings = Settings::default();
        for contents in ["frozen.x = true\n", "[frozen]\nx = 1\n"] {
            let err = apply_file(&mut settings, Layer::System, "c.toml", contents).unwrap_err();
            assert!(err.to_string().starts_with("c.toml: "), "{err}");
        }
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn the_origin_points_at_the_real_line_the_key_is_on() {
        // Derived from the parse, because a file cannot state its own provenance.
        let mut settings = Settings::default();
        let contents = "# a comment\n\nfrozen = true\ncolor = false\n";
        apply_file(&mut settings, Layer::System, "config.toml", contents).unwrap();
        assert_eq!(
            settings.get(Setting::Frozen).origin.to_string(),
            "system (config.toml:3)"
        );
        assert_eq!(
            settings.get(Setting::Color).origin.to_string(),
            "system (config.toml:4)"
        );
    }

    #[test]
    fn a_key_with_padding_around_the_equals_is_still_located() {
        let mut settings = Settings::default();
        apply_file(
            &mut settings,
            Layer::System,
            "c.toml",
            "  frozen   =  true\n",
        )
        .unwrap();
        assert!(
            settings
                .get(Setting::Frozen)
                .origin
                .to_string()
                .contains("c.toml:1")
        );
    }

    #[test]
    fn an_unknown_key_fails_the_whole_file() {
        // A typo that reads as "no such setting, carry on" is the same failure
        // as silently ignoring a directive, with a friendlier face.
        let mut settings = Settings::default();
        let err = apply_file(
            &mut settings,
            Layer::System,
            "config.toml",
            "confirm_agent_action = false\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("confirm_agent_action"), "{err}");
        // And nothing was applied.
        assert_eq!(
            settings.get(Setting::ConfirmAgentActions).value,
            Value::Bool(true)
        );
    }

    #[test]
    fn invalid_toml_fails_with_the_file_named() {
        let mut settings = Settings::default();
        let err = apply_file(&mut settings, Layer::System, "broken.toml", "frozen =").unwrap_err();
        assert!(err.to_string().starts_with("broken.toml:"), "{err}");
        // A parse failure, not a merge rejection: the message carries no line
        // prefix of its own beyond the file.
        assert!(!err.to_string().starts_with("broken.toml:0:"), "{err}");
    }

    #[test]
    fn a_wrong_type_is_refused_rather_than_coerced() {
        let mut settings = Settings::default();
        let err = apply_file(
            &mut settings,
            Layer::System,
            "config.toml",
            "frozen = \"yes\"\n",
        )
        .unwrap_err();
        // TOML itself catches this, and the message still names the key.
        assert!(err.to_string().contains("frozen"), "{err}");
    }

    #[test]
    fn a_project_file_that_would_widen_is_refused_with_its_line() {
        // The rule that keeps a checked-in file honest, reported with enough
        // detail to fix it.
        let mut settings = Settings::default();
        let err = apply_file(
            &mut settings,
            Layer::Project,
            ".xudo/policy.toml",
            "# our project\nconfirm_agent_actions = false\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.starts_with(".xudo/policy.toml:2:"), "{message}");
        assert!(message.contains("may only narrow"), "{message}");
        // Asserted on the rendered message rather than by pattern, so there is
        // no arm for a variant this assertion never sees.
        assert!(
            message.contains("permits more than the layer above"),
            "{message}"
        );
    }

    #[test]
    fn a_project_file_that_narrows_is_accepted() {
        let mut settings = Settings::default();
        apply_file(
            &mut settings,
            Layer::Project,
            ".xudo/policy.toml",
            "confirmation_timeout_secs = 0\nfrozen = true\n",
        )
        .unwrap();
        assert_eq!(
            settings.get(Setting::ConfirmationTimeoutSecs).value,
            Value::Integer(0)
        );
        assert_eq!(settings.get(Setting::Frozen).value, Value::Bool(true));
    }

    #[test]
    fn setting_a_compiled_in_key_says_so_rather_than_calling_it_unknown() {
        // The reason `use_pty` is in the schema at all: an operator who sets it
        // deserves "this is compiled in", not "no such key".
        let mut settings = Settings::default();
        let err = apply_file(
            &mut settings,
            Layer::System,
            "config.toml",
            "use_pty = false\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("compiled in"), "{err}");
        assert!(err.to_string().contains("remove it"), "{err}");
        assert!(err.to_string().contains("config.toml:1"), "{err}");
    }

    #[test]
    fn an_empty_file_is_valid_and_changes_nothing() {
        let mut settings = Settings::default();
        let before = settings.clone();
        apply_file(&mut settings, Layer::System, "c.toml", "# nothing\n").unwrap();
        assert_eq!(settings, before);
    }

    #[test]
    fn two_files_at_the_same_layer_apply_in_the_order_they_are_given() {
        // The systemd convention: a later drop-in wins.
        let mut settings = Settings::default();
        apply_file(&mut settings, Layer::System, "10-a.toml", "frozen = true\n").unwrap();
        apply_file(
            &mut settings,
            Layer::System,
            "99-z.toml",
            "frozen = false\n",
        )
        .unwrap();
        assert_eq!(settings.get(Setting::Frozen).value, Value::Bool(false));
        assert!(
            settings
                .get(Setting::Frozen)
                .origin
                .to_string()
                .contains("99-z.toml")
        );
    }

    #[test]
    fn every_setting_can_actually_be_set_from_a_file() {
        // Guards against a setting being added to the enum and never wired into
        // the file struct, which would make it silently unconfigurable.
        let cases = [
            ("confirm_agent_actions = true", Setting::ConfirmAgentActions),
            ("confirm_human_path = true", Setting::ConfirmHumanPath),
            (
                "confirmation_timeout_secs = 45",
                Setting::ConfirmationTimeoutSecs,
            ),
            ("frozen = true", Setting::Frozen),
            ("audit_sink = \"journald\"", Setting::AuditSink),
            ("color = false", Setting::Color),
        ];
        for (line, setting) in cases {
            let mut settings = Settings::default();
            apply_file(&mut settings, Layer::System, "c.toml", line).unwrap();
            assert_eq!(
                settings.get(setting).origin.layer,
                Layer::System,
                "{line} did not take effect"
            );
        }
        // And every configurable setting is covered by the list above.
        let covered = cases.len();
        let configurable = Setting::ALL
            .into_iter()
            .filter(|s| s.is_configurable())
            .count();
        assert_eq!(covered, configurable, "a configurable setting is untested");
    }

    #[test]
    fn audit_sink_other_than_journald_is_refused() {
        let mut settings = Settings::default();
        let error = apply_file(
            &mut settings,
            Layer::System,
            "xudo.toml",
            "audit_sink = \"syslog\"\n",
        )
        .expect_err("unsupported audit sink must fail parsing");
        assert!(error.to_string().contains("only accepts \"journald\""));
    }

    #[test]
    fn a_comment_or_a_longer_key_is_not_the_setting() {
        let contents = "# frozen is nice\nfrozen_solid = true\nfrozen = true\n";
        let document = toml::de::DeTable::parse(contents).unwrap();
        let lines = key_lines(contents, document.get_ref());
        assert_eq!(lines.get("frozen"), Some(&3));
        assert_eq!(lines.get("frozen_solid"), Some(&2));
        assert_eq!(lines.get("other"), None);
    }
}
