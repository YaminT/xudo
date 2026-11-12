//! The root-owned rules and settings the gate rechecks.

use std::path::Path;

use xudo_config::{Layer, LoadError, Setting, Settings as ConfigSettings, Value};
use xudo_policy::{LoadedRuleSet, engine::Settings};
use xudo_sys::{TrustError, TrustedRulesError, load_trusted_rules, read_trusted_file};

/// The largest settings file the gate reads.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// The freeze marker is small and never controls an allocation.
pub const MAX_FREEZE_BYTES: usize = 2048;
/// The broker-owned freeze marker.
pub const FREEZE_FILE: &str = "/var/lib/xudo/frozen";
/// The state directory the freeze markers live in.
pub const FREEZE_DIR: &str = "/var/lib/xudo";

/// The marker one uid's freeze is published under: root's is the global
/// `frozen`, anyone else's covers that uid's agents only. The name is built
/// from a number, never from anything the caller wrote.
#[must_use]
pub fn freeze_marker_name(uid: u32) -> String {
    if uid == 0 {
        "frozen".to_owned()
    } else {
        format!("frozen-{uid}")
    }
}

/// Whether `name` is a freeze marker's name: `frozen` or `frozen-<digits>`.
#[must_use]
pub fn is_freeze_marker_name(name: &[u8]) -> bool {
    match name.strip_prefix(b"frozen") {
        Some(b"") => true,
        Some(rest) => rest
            .strip_prefix(b"-")
            .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit)),
        None => false,
    }
}

/// A reader of one trusted file, as the marker check is handed it.
pub type MarkerRead<'a> = dyn Fn(&Path, usize) -> Result<Option<Vec<u8>>, TrustError> + 'a;

/// Whether `uid`'s own freeze marker stands. Anything but a clean absence
/// counts as frozen: a marker that is unreadable or malformed freezes.
pub fn user_frozen(uid: u32, read: &MarkerRead<'_>) -> bool {
    let path = format!("{FREEZE_DIR}/{}", freeze_marker_name(uid));
    freeze_state(read(Path::new(&path), MAX_FREEZE_BYTES))
}

#[cfg(feature = "fuzzing")]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// The root-owned freeze marker's data.
pub struct FreezeRecord {
    reason: String,
    uid: u32,
    time: u64,
}

#[cfg(not(feature = "fuzzing"))]
#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// The root-owned freeze marker's data.
pub(crate) struct FreezeRecord {
    reason: String,
    uid: u32,
    time: u64,
}

/// The rules and settings in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedPolicy {
    /// The trusted rules.
    pub rules: LoadedRuleSet,
    /// Settings derived from the trusted config bytes.
    pub settings: Settings,
}

/// Why settings bytes could not be interpreted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SettingsError {
    /// The settings bytes were not UTF-8.
    #[error("{file} is not UTF-8")]
    NotUtf8 {
        /// The settings file path.
        file: String,
    },
    /// The settings text was invalid.
    #[error(transparent)]
    Invalid(LoadError),
}

/// Why the gate could not load root's policy.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The rules failed the trust walk or parse.
    #[error("the ruleset cannot be loaded: {0}")]
    Rules(TrustedRulesError),
    /// The settings file or an ancestor failed the trust walk.
    #[error("the settings file cannot be read: {0}")]
    ConfigUntrusted(TrustError),
    /// The settings bytes could not be interpreted.
    #[error(transparent)]
    Config(SettingsError),
}

/// Reads the rules and optional settings through the privileged trust walk.
///
/// # Errors
///
/// Returns [`PolicyError`] if either input fails the trust walk or parsing.
pub fn load(rules_dir: &Path, config_file: &Path) -> Result<LoadedPolicy, PolicyError> {
    load_with(
        rules_dir,
        config_file,
        &load_trusted_rules,
        &read_trusted_file,
        &read_trusted_file,
    )
}

type RulesRead = dyn Fn(&Path) -> Result<LoadedRuleSet, TrustedRulesError>;
type ConfigRead = dyn Fn(&Path, usize) -> Result<Option<Vec<u8>>, TrustError>;

#[cfg(test)]
type FreezeReadFn = fn(&Path, usize) -> Result<Option<Vec<u8>>, TrustError>;
#[cfg(test)]
const ABSENT_FREEZE: FreezeReadFn = |_, _| Ok(None);

fn load_with(
    rules_dir: &Path,
    config_file: &Path,
    rules_read: &RulesRead,
    config_read: &ConfigRead,
    freeze_read: &ConfigRead,
) -> Result<LoadedPolicy, PolicyError> {
    let rules = rules_read(rules_dir).map_err(PolicyError::Rules)?;
    let config =
        config_read(config_file, MAX_CONFIG_BYTES).map_err(PolicyError::ConfigUntrusted)?;
    let mut settings =
        settings_from(config.as_deref(), config_file).map_err(PolicyError::Config)?;
    settings.frozen |= freeze_state(freeze_read(Path::new(FREEZE_FILE), MAX_FREEZE_BYTES));
    Ok(LoadedPolicy { rules, settings })
}

fn freeze_state(read: Result<Option<Vec<u8>>, TrustError>) -> bool {
    match read {
        Ok(None) => false,
        Ok(Some(bytes)) => match parse_freeze_record(&bytes) {
            Ok(record) => {
                let _ = (record.reason, record.uid, record.time);
                true
            }
            Err(_) => true,
        },
        Err(_) => true,
    }
}

/// Parses one freeze marker, refusing non-object and duplicate-key forms.
///
/// # Errors
///
/// Returns the serde error for invalid JSON, an invalid shape, or duplicate keys.
fn parse_freeze_record_inner(bytes: &[u8]) -> Result<FreezeRecord, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if !value.is_object() {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "freeze record must be an object",
        ));
    }
    serde_json::from_slice(bytes)
}

#[cfg(feature = "fuzzing")]
/// Parses one freeze marker, refusing non-object and duplicate-key forms.
///
/// # Errors
///
/// Returns the serde error for invalid JSON, an invalid shape, or duplicate keys.
pub fn parse_freeze_record(bytes: &[u8]) -> Result<FreezeRecord, serde_json::Error> {
    parse_freeze_record_inner(bytes)
}

#[cfg(not(feature = "fuzzing"))]
pub(crate) fn parse_freeze_record(bytes: &[u8]) -> Result<FreezeRecord, serde_json::Error> {
    parse_freeze_record_inner(bytes)
}

/// Derives engine settings from the bytes shared by the gate and broker.
///
/// # Errors
///
/// Returns [`SettingsError`] for invalid UTF-8, malformed TOML or an unknown key.
pub fn settings_from(contents: Option<&[u8]>, file: &Path) -> Result<Settings, SettingsError> {
    let mut config = ConfigSettings::default();
    if let Some(bytes) = contents {
        let name = file.display().to_string();
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Err(SettingsError::NotUtf8 { file: name });
        };
        xudo_config::apply_file(&mut config, Layer::System, &name, text)
            .map_err(SettingsError::Invalid)?;
    }
    Ok(Settings {
        confirm_agent_actions: config.get(Setting::ConfirmAgentActions).value == Value::Bool(true),
        confirm_human_path: config.get(Setting::ConfirmHumanPath).value == Value::Bool(true),
        frozen: config.get(Setting::Frozen).value == Value::Bool(true),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[allow(clippy::unnecessary_wraps)]
    fn empty_rules(_: &Path) -> Result<LoadedRuleSet, TrustedRulesError> {
        Ok(xudo_policy::load_rule_files(Vec::new()).unwrap())
    }

    #[test]
    fn missing_config_uses_defaults_after_the_parent_is_verified() {
        let loaded = load_with(
            Path::new("/etc/xudo/rules.d"),
            Path::new("/etc/xudo/config.toml"),
            &empty_rules,
            &|_, limit| {
                assert_eq!(limit, MAX_CONFIG_BYTES);
                Ok(None)
            },
            &ABSENT_FREEZE,
        )
        .unwrap();
        assert_eq!(loaded.settings, Settings::default());
    }

    #[test]
    fn broken_and_unknown_settings_refuse_instead_of_using_defaults() {
        let error = settings_from(Some(b"confirm_human_path = \xff"), Path::new("config.toml"))
            .unwrap_err();
        assert!(error.to_string().contains("not UTF-8"), "{error}");
        let error = settings_from(Some(b"unknown = true"), Path::new("config.toml")).unwrap_err();
        assert!(error.to_string().contains("unknown"), "{error}");
        assert!(settings_from(Some(b"frozen ="), Path::new("config.toml")).is_err());
        let error = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(Some(b"unknown = true".to_vec())),
            &ABSENT_FREEZE,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown"), "{error}");
    }

    #[test]
    fn a_settings_read_that_fails_the_trust_walk_refuses() {
        let error = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| {
                Err(TrustError::NotRootOwned {
                    at: "config.toml".to_owned(),
                    uid: 1000,
                })
            },
            &ABSENT_FREEZE,
        )
        .unwrap_err();
        assert!(error.to_string().contains("not root"), "{error}");
    }

    #[test]
    fn an_unreadable_freeze_file_means_frozen() {
        assert!(freeze_state(Err(TrustError::NotRootOwned {
            at: FREEZE_FILE.to_owned(),
            uid: 1000,
        })));
    }

    #[test]
    fn a_freeze_file_failing_the_trust_walk_means_frozen() {
        let loaded = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(None),
            &|path, _| {
                assert_eq!(path, Path::new(FREEZE_FILE));
                Err(TrustError::Writable {
                    at: FREEZE_FILE.to_owned(),
                    mode: 0o777,
                })
            },
        )
        .unwrap();
        assert!(loaded.settings.frozen);
    }

    #[test]
    fn marker_names_are_numbers_never_caller_text() {
        assert_eq!(freeze_marker_name(0), "frozen");
        assert_eq!(freeze_marker_name(1000), "frozen-1000");
        for name in [&b"frozen"[..], b"frozen-0", b"frozen-1000"] {
            assert!(is_freeze_marker_name(name));
        }
        for name in [
            &b"frozen-"[..],
            b"frozen-1x",
            b"frozen-../x",
            b"frozen1",
            b"audit.jsonl",
            b"xfrozen",
            b"",
        ] {
            assert!(!is_freeze_marker_name(name), "{name:?}");
        }
    }

    #[test]
    fn a_users_marker_that_is_malformed_or_unreadable_still_freezes_that_user() {
        let seen = std::cell::RefCell::new(Vec::new());
        let read = |path: &Path, limit: usize| {
            seen.borrow_mut().push((path.to_path_buf(), limit));
            Ok(Some(b"garbage".to_vec()))
        };
        assert!(user_frozen(1000, &read));
        assert_eq!(
            seen.borrow().as_slice(),
            [(
                Path::new("/var/lib/xudo/frozen-1000").to_path_buf(),
                MAX_FREEZE_BYTES
            )]
        );
        assert!(!user_frozen(1000, &|_, _| Ok(None)));
        assert!(user_frozen(1000, &|_, _| Err(TrustError::NotRootOwned {
            at: "/var/lib/xudo".to_owned(),
            uid: 1000
        })));
    }

    #[test]
    fn an_existing_freeze_file_fails_closed_and_absence_does_not() {
        assert!(freeze_state(Ok(Some(b"not json".to_vec()))));
        assert!(!freeze_state(Ok(None)));
        assert!(freeze_state(Ok(Some(
            br#"{"reason":"maintenance","uid":0,"time":1}"#.to_vec()
        ))));
    }

    #[test]
    fn array_and_duplicate_key_freeze_records_are_rejected() {
        assert!(parse_freeze_record(br#"["maintenance",0,1]"#).is_err());
        assert!(
            parse_freeze_record(br#"{"reason":"one","reason":"two","uid":0,"time":1}"#).is_err()
        );
    }
}
