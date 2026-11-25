//! The root-owned rules and settings the gate rechecks.

use std::path::Path;

use xudo_config::{Layer, LoadError, Setting, Settings as ConfigSettings, Value};
use xudo_policy::{LoadedRuleSet, engine::Settings};
use xudo_sys::{TrustError, TrustedRulesError, load_trusted_policy, read_trusted_file};

/// The largest settings file the gate reads.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// The freeze marker is small and never controls an allocation.
pub const MAX_FREEZE_BYTES: usize = 2048;
/// The host account database used to bind registry names to peer uids.
pub const MAX_PASSWD_BYTES: usize = 1 << 20;
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

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// The root-owned freeze marker's data.
pub struct FreezeRecord {
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
    /// Maximum lifetime, in seconds, of a root-held ask-human entry.
    pub queue_ttl_secs: u64,
    /// Root-owned account records used to match harness accounts to uids.
    pub passwd: String,
    /// What is wrong with those records, if anything: lines that cannot
    /// resolve an account, and lines read lossily. A report, not a decision.
    pub passwd_fault: Option<String>,
}

impl LoadedPolicy {
    /// The registry and account-database faults, as audit evidence lines.
    ///
    /// Every audit record made under a policy with a fault carries them, so a
    /// reviewer can tell "no harness was armed" from "no harness asked".
    #[must_use]
    pub fn fault_evidence(&self) -> Vec<String> {
        [
            ("registry_fault", self.rules.registry_fault.as_deref()),
            ("passwd_fault", self.passwd_fault.as_deref()),
        ]
        .into_iter()
        .filter_map(|(key, fault)| Some(format!("{key}={}", one_line(fault?))))
        .collect()
    }
}

/// `text` with every control character, newlines included, as a space: a
/// fault carries parser output that root wrote, and evidence is one line.
fn one_line(text: &str) -> String {
    let mut out: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if out.len() > FAULT_EVIDENCE_MAX {
        // Byte 0 is always a boundary, so the search never comes up empty.
        let end = (0..=FAULT_EVIDENCE_MAX)
            .rev()
            .find(|at| out.is_char_boundary(*at))
            .unwrap_or_default();
        out.truncate(end);
        out.push('…');
    }
    out
}

/// Longest fault text one evidence line keeps. A parser error can echo a whole
/// offending line, and a record over the audit limit is refused outright.
const FAULT_EVIDENCE_MAX: usize = 512;

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
    /// `/etc/passwd` is missing or empty. Without it no enrolled agent can be
    /// told from a human, so the policy does not load.
    #[error("the account database is missing or empty")]
    PasswdUnusable,
}

impl From<SettingsError> for PolicyError {
    fn from(error: SettingsError) -> Self {
        Self::Config(error)
    }
}

/// Reads the rules and optional settings through the privileged trust walk.
///
/// # Errors
///
/// Returns [`PolicyError`] if either input fails the trust walk or parsing.
pub fn load(rules_dir: &Path, config_file: &Path) -> Result<LoadedPolicy, PolicyError> {
    // Read passwd through the trust walk even when the rules path later fails;
    // defer propagating its error to preserve rules/config error precedence.
    let passwd = read_trusted_file(Path::new("/etc/passwd"), MAX_PASSWD_BYTES)
        .map_err(PolicyError::ConfigUntrusted);
    let loaded = load_with(
        rules_dir,
        config_file,
        &load_trusted_policy,
        &read_trusted_file,
        &read_trusted_file,
    );
    attach_passwd(loaded, passwd)
}

fn attach_passwd(
    loaded: Result<LoadedPolicy, PolicyError>,
    passwd: Result<Option<Vec<u8>>, PolicyError>,
) -> Result<LoadedPolicy, PolicyError> {
    let mut loaded = loaded?;
    // Lossy on purpose. Any user may put a stray byte in their own GECOS
    // (`chfn`), and a strict decode would let one user stop every request. The
    // name and uid fields are ASCII (`valid_account_name`) and only root edits
    // uids, so a replacement character, which is neither a newline nor a
    // colon, cannot change who resolves to which uid. Skipping a bad line
    // instead would let a harness user hide their own uid, so never do that.
    let bytes = passwd?
        .filter(|bytes| !bytes.is_empty())
        .ok_or(PolicyError::PasswdUnusable)?;
    loaded.passwd_fault = xudo_policy::passwd_fault(&bytes);
    loaded.passwd = String::from_utf8_lossy(&bytes).into_owned();
    Ok(loaded)
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
    let parsed = parse_config(config.as_deref(), config_file)?;
    let mut settings = settings_of(&parsed);
    let queue_ttl_secs = queue_ttl_seconds(&parsed.get(Setting::QueueTtlSecs).value);
    settings.frozen |= freeze_state(freeze_read(Path::new(FREEZE_FILE), MAX_FREEZE_BYTES));
    Ok(LoadedPolicy {
        rules,
        settings,
        queue_ttl_secs,
        passwd: String::new(),
        passwd_fault: None,
    })
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

/// Parses one freeze marker, refusing non-object and duplicate-key forms.
///
/// # Errors
///
/// Returns the serde error for invalid JSON, an invalid shape, or duplicate keys.
pub fn parse_freeze_record(bytes: &[u8]) -> Result<FreezeRecord, serde_json::Error> {
    parse_freeze_record_inner(bytes)
}

/// Derives engine settings from the bytes shared by the gate and broker.
///
/// # Errors
///
/// Returns [`SettingsError`] for invalid UTF-8, malformed TOML or an unknown key.
pub fn settings_from(contents: Option<&[u8]>, file: &Path) -> Result<Settings, SettingsError> {
    Ok(settings_of(&parse_config(contents, file)?))
}

fn parse_config(contents: Option<&[u8]>, file: &Path) -> Result<ConfigSettings, SettingsError> {
    let mut config = ConfigSettings::default();
    if let Some(bytes) = contents {
        let name = file.display().to_string();
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Err(SettingsError::NotUtf8 { file: name });
        };
        xudo_config::apply_file(&mut config, Layer::System, &name, text)
            .map_err(SettingsError::Invalid)?;
    }
    Ok(config)
}

fn settings_of(config: &ConfigSettings) -> Settings {
    Settings {
        confirm_human_path: config.get(Setting::ConfirmHumanPath).value == Value::Bool(true),
        frozen: config.get(Setting::Frozen).value == Value::Bool(true),
    }
}

#[inline(never)]
fn queue_ttl_seconds(value: &Value) -> u64 {
    match value {
        Value::Integer(seconds) => *seconds,
        // A value that is not an integer never reaches this through the TOML
        // parser. If it does, the shortest lifetime expires every entry.
        _ => 0,
    }
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
        assert_eq!(loaded.queue_ttl_secs, 24 * 60 * 60);
    }

    #[test]
    fn the_root_queue_lifetime_is_loaded_from_the_trusted_config() {
        let loaded = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(Some(b"queue_ttl_secs = 300\n".to_vec())),
            &ABSENT_FREEZE,
        )
        .unwrap();
        assert_eq!(loaded.queue_ttl_secs, 300);
    }

    #[test]
    fn queue_lifetime_rejects_non_utf8_and_invalid_config() {
        let non_utf8 = parse_config(Some(&[0xff]), Path::new("config.toml"));
        assert_eq!(
            non_utf8.unwrap_err().to_string(),
            "config.toml is not UTF-8"
        );

        let invalid = parse_config(
            Some(b"queue_ttl_secs = \"slow\"\n"),
            Path::new("config.toml"),
        );
        assert!(invalid.unwrap_err().to_string().contains("queue_ttl_secs"));
        let error = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(Some(b"queue_ttl_secs = \"slow\"\n".to_vec())),
            &ABSENT_FREEZE,
        )
        .unwrap_err();
        assert!(error.to_string().contains("queue_ttl_secs"));
    }

    #[test]
    fn a_wrong_typed_queue_lifetime_fails_closed_to_the_shortest_ttl() {
        assert_eq!(queue_ttl_seconds(&Value::Bool(false)), 0);
        assert_eq!(queue_ttl_seconds(&Value::Text("slow".to_owned())), 0);
        assert_eq!(queue_ttl_seconds(&Value::Integer(300)), 300);
    }

    #[test]
    fn public_loader_reaches_passwd_read_before_a_missing_rules_error() {
        let error = load(
            Path::new("/xudo-test-missing-rules"),
            Path::new("/xudo-test-missing-config"),
        )
        .unwrap_err();
        assert_eq!(format!("{error:?}").split('(').next(), Some("Rules"));
    }

    #[test]
    fn passwd_attachment_accepts_a_loaded_policy_and_absent_passwd() {
        let loaded = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(None),
            &ABSENT_FREEZE,
        )
        .unwrap();
        let error = attach_passwd(Ok(loaded), Ok(None)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the account database is missing or empty"
        );
    }

    #[test]
    fn an_empty_passwd_still_fails_the_load_closed() {
        let error = attach_passwd(Ok(loaded_policy()), Ok(Some(Vec::new()))).unwrap_err();
        assert_eq!(
            error.to_string(),
            "the account database is missing or empty"
        );
    }

    fn loaded_policy() -> LoadedPolicy {
        load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(None),
            &ABSENT_FREEZE,
        )
        .unwrap()
    }

    #[test]
    fn a_non_utf8_gecos_does_not_stop_the_policy_load() {
        // `chfn -r $'\xff'`: any user can do this to their own line.
        let bytes =
            b"root:x:0:0:root:/root:/bin/sh\nmallory:x:1001:1001:\xff\xfe:/home/m:/bin/sh\n";
        let attached = attach_passwd(Ok(loaded_policy()), Ok(Some(bytes.to_vec()))).unwrap();
        assert!(attached.passwd.contains("mallory:x:1001:1001:\u{fffd}"));
    }

    #[test]
    fn a_non_utf8_byte_cannot_change_a_name_or_uid_field() {
        let bytes = b"agent:x:1000:1000:\xff\n:x:0:0:evil:/:/bin/sh\nbob\xff:x:0:0::/:/bin/sh\nroot:x:0:0:\xff:/root:/bin/sh\n";
        let attached = attach_passwd(Ok(loaded_policy()), Ok(Some(bytes.to_vec()))).unwrap();
        let text = &attached.passwd;
        assert_eq!(xudo_policy::passwd_uid(text, "agent"), Some(1000));
        assert_eq!(xudo_policy::passwd_uid(text, "root"), Some(0));
        // A damaged name does not become a clean one, and no new name appears.
        assert_eq!(xudo_policy::passwd_uid(text, "bob"), None);
        assert_eq!(xudo_policy::passwd_uid(text, "evil"), None);
        assert_eq!(
            text.lines().count(),
            bytes.split(|b| *b == b'\n').count() - 1
        );
    }

    #[test]
    fn a_non_utf8_passwd_line_is_reported_not_silent() {
        let bytes = b"root:x:0:0:root:/root:/bin/sh\nmallory:x:1001:1001:\xff:/home/m:/bin/sh\nbad:x:nope:1\n";
        let attached = attach_passwd(Ok(loaded_policy()), Ok(Some(bytes.to_vec()))).unwrap();
        assert_eq!(
            attached.passwd_fault.as_deref(),
            Some("1 unusable and 1 non-UTF-8 line(s) in the account database")
        );
        let clean = attach_passwd(
            Ok(loaded_policy()),
            Ok(Some(b"root:x:0:0::/:/bin/sh\n".to_vec())),
        )
        .unwrap();
        assert_eq!(clean.passwd_fault, None);
        assert!(clean.fault_evidence().is_empty());
    }

    #[test]
    fn faults_become_one_line_evidence_each() {
        let mut loaded = loaded_policy();
        loaded.rules = xudo_policy::load_policy_with_registry(
            Vec::new(),
            Err("line one\nline two\x1b[31m".to_owned()),
        )
        .unwrap();
        loaded.passwd_fault = Some("3 unusable".to_owned());
        assert_eq!(
            loaded.fault_evidence(),
            [
                "registry_fault=line one line two [31m".to_owned(),
                "passwd_fault=3 unusable".to_owned()
            ]
        );
    }

    #[test]
    fn an_oversized_fault_is_capped_so_a_record_stays_writable() {
        let mut loaded = loaded_policy();
        let huge = format!("é{}", "x".repeat(200 * 1024));
        loaded.rules =
            xudo_policy::load_policy_with_registry(Vec::new(), Err(huge.clone())).unwrap();
        // One ASCII byte first, so byte 512 falls inside a two-byte char.
        loaded.passwd_fault = Some(format!("a{}", "é".repeat(100 * 1024)));
        let evidence = loaded.fault_evidence();
        assert!(evidence.iter().all(|line| line.len() <= 530));
        assert!(evidence.iter().all(|line| line.ends_with('…')));
        let record: usize = evidence.iter().map(String::len).sum();
        assert!(record < 64 * 1024);
    }

    #[test]
    fn passwd_attachment_accepts_present_passwd_bytes() {
        let loaded = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(None),
            &ABSENT_FREEZE,
        )
        .unwrap();
        let bytes = b"agent:x:1000:1000::/:/bin/sh\n".to_vec();
        let attached = attach_passwd(Ok(loaded), Ok(Some(bytes.clone()))).unwrap();
        assert_eq!(attached.passwd.as_bytes(), bytes);
    }

    #[test]
    fn passwd_attachment_propagates_a_passwd_error() {
        let loaded = load_with(
            Path::new("rules"),
            Path::new("config.toml"),
            &empty_rules,
            &|_, _| Ok(None),
            &ABSENT_FREEZE,
        )
        .unwrap();
        let error = settings_from(Some(b"invalid = ["), Path::new("config.toml")).unwrap_err();
        assert!(attach_passwd(Ok(loaded), Err(PolicyError::Config(error))).is_err());
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
