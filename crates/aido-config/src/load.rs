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
//! A file cannot state its own provenance. The line for each key is found by
//! scanning the text, so an origin points at the real declaration rather than at
//! whatever the file claimed.

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
    let parsed: File = toml::from_str(contents).map_err(|e| LoadError::Parse {
        file: file.to_owned(),
        reason: e.to_string(),
    })?;

    // Ordered so a file's errors are reported in a stable order regardless of
    // how the keys were written.
    let entries: [(Setting, Option<Value>); 6] = [
        (
            Setting::ConfirmAgentActions,
            parsed.confirm_agent_actions.map(Value::Bool),
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
        let line = line_of_key(contents, setting.key());
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

/// Finds the 1-based line on which `key` is assigned.
///
/// Returns 0 when it cannot be located, which happens only if the key reached
/// the parser by some route other than this text.
fn line_of_key(contents: &str, key: &str) -> u32 {
    contents
        .lines()
        .enumerate()
        .find(|(_, line)| {
            let trimmed = line.trim_start();
            trimmed.starts_with(key)
                && trimmed
                    .get(key.len()..)
                    .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .map_or(0, |(index, _)| {
            u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX)
        })
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
    fn the_origin_points_at_the_real_line_the_key_is_on() {
        // Derived by scanning, because a file cannot state its own provenance.
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
            ".aido/policy.toml",
            "# our project\nconfirm_agent_actions = false\n",
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.starts_with(".aido/policy.toml:2:"), "{message}");
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
            ".aido/policy.toml",
            "confirmation_timeout_secs = 15\nfrozen = true\n",
        )
        .unwrap();
        assert_eq!(
            settings.get(Setting::ConfirmationTimeoutSecs).value,
            Value::Integer(15)
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
            (
                "confirmation_timeout_secs = 45",
                Setting::ConfirmationTimeoutSecs,
            ),
            ("frozen = true", Setting::Frozen),
            ("audit_sink = \"syslog\"", Setting::AuditSink),
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
    fn a_key_that_cannot_be_located_reports_line_zero_rather_than_guessing() {
        assert_eq!(line_of_key("other = 1\n", "frozen"), 0);
        assert_eq!(line_of_key("\nfrozen = true\n", "frozen"), 2);
        // A key mentioned in a comment is not an assignment.
        assert_eq!(
            line_of_key("# frozen is nice\nfrozen = true\n", "frozen"),
            2
        );
        // A longer key that merely starts with the same text is not a match.
        assert_eq!(line_of_key("frozen_solid = true\n", "frozen"), 0);
    }
}
