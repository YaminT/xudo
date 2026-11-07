//! The root-owned rules and settings the gate rechecks.

use std::path::Path;

use xudo_config::{Layer, LoadError, Setting, Settings as ConfigSettings, Value};
use xudo_policy::{LoadedRuleSet, engine::Settings};
use xudo_sys::{TrustError, TrustedRulesError, load_trusted_rules, read_trusted_file};

/// The largest settings file the gate reads.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

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
    )
}

type RulesRead = dyn Fn(&Path) -> Result<LoadedRuleSet, TrustedRulesError>;
type ConfigRead = dyn Fn(&Path, usize) -> Result<Option<Vec<u8>>, TrustError>;

fn load_with(
    rules_dir: &Path,
    config_file: &Path,
    rules_read: &RulesRead,
    config_read: &ConfigRead,
) -> Result<LoadedPolicy, PolicyError> {
    let rules = rules_read(rules_dir).map_err(PolicyError::Rules)?;
    let config =
        config_read(config_file, MAX_CONFIG_BYTES).map_err(PolicyError::ConfigUntrusted)?;
    let settings = settings_from(config.as_deref(), config_file).map_err(PolicyError::Config)?;
    Ok(LoadedPolicy { rules, settings })
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
        )
        .unwrap_err();
        assert!(error.to_string().contains("not root"), "{error}");
    }
}
