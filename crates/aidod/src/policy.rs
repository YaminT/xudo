//! Root's policy, read the way a privileged reader must, and the one decision
//! the broker and `aido explain` both make.
//!
//! The ruleset is loaded only through [`aido_sys::load_trusted_rules`]: every
//! directory from `/` down and every rule file checked on the descriptor it is
//! read through, then handed to the same `aido_policy::load_rule_files` the
//! front-end and the gate use. So the generation the broker mints with is the
//! generation the gate will compute from the same bytes.
//!
//! The decision is [`aido_policy::evaluate_command`] — the function behind
//! `aido explain` — so the broker never mints for a command `explain` refuses,
//! nor refuses one it allows. The broker does not search the actions itself:
//! the engine gathers every action that accepts the command and resolves them
//! to the strictest, and a second search here would be a second chance to get
//! that wrong.

use std::path::{Path, PathBuf};

use aido_config::{Layer, LoadError, Setting, Settings as ConfigSettings, SystemPaths, Value};
use aido_policy::engine::Settings;
use aido_policy::{
    Arg, Argv, CallerFacts, Classification, Decision, LoadedRuleSet, evaluate_command,
};
use aido_sys::{TrustError, TrustedRulesError, load_trusted_rules, read_trusted_file};
use aido_wire::BrokerRequest;

use crate::identify::PeerIdentity;

/// The largest settings file the broker reads, in bytes.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// The ruleset and settings in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedPolicy {
    /// The validated ruleset and its generation.
    pub rules: LoadedRuleSet,
    /// The settings the engine decides with.
    pub settings: Settings,
}

/// Why root's policy could not be loaded. Every variant fails closed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The ruleset failed the trust walk or is not a ruleset.
    #[error("the ruleset cannot be loaded: {0}")]
    Rules(TrustedRulesError),
    /// The settings file, or a directory above it, failed the trust walk.
    #[error("the settings file cannot be read: {0}")]
    ConfigUntrusted(TrustError),
    /// The settings file is not UTF-8.
    #[error("{file} is not UTF-8")]
    ConfigNotUtf8 {
        /// The file.
        file: String,
    },
    /// The settings file is not valid configuration.
    #[error(transparent)]
    ConfigInvalid(LoadError),
}

/// Where root's policy comes from, as a seam.
pub trait PolicySource {
    /// Loads the ruleset and settings in force now.
    ///
    /// # Errors
    ///
    /// A [`PolicyError`] for anything that cannot be loaded; there is no
    /// partial policy.
    fn load(&self) -> Result<LoadedPolicy, PolicyError>;
}

/// Root's policy on this host: the ruleset directory and the settings file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPolicy {
    rules_dir: PathBuf,
    config_file: PathBuf,
}

impl HostPolicy {
    /// `/etc/aido/rules.d` and `/etc/aido/config.toml`.
    pub fn system() -> Self {
        let paths = SystemPaths::default();
        Self::new(paths.rules_dir(), paths.config())
    }

    /// The policy in `rules_dir` and `config_file`.
    pub fn new(rules_dir: impl Into<PathBuf>, config_file: impl Into<PathBuf>) -> Self {
        Self {
            rules_dir: rules_dir.into(),
            config_file: config_file.into(),
        }
    }
}

impl PolicySource for HostPolicy {
    fn load(&self) -> Result<LoadedPolicy, PolicyError> {
        self.load_with(&load_trusted_rules, &read_trusted_file)
    }
}

/// The trusted read of the ruleset directory.
type RulesRead = dyn Fn(&Path) -> Result<LoadedRuleSet, TrustedRulesError>;

/// The trusted read of the settings file, to at most the given bytes.
type ConfigRead = dyn Fn(&Path, usize) -> Result<Option<Vec<u8>>, TrustError>;

impl HostPolicy {
    /// [`PolicySource::load`], with the two trusted reads as parameters, so the
    /// composition is tested on a host whose mount table cannot be read.
    ///
    /// Trait objects, not generics: one body, so the host's own reads and the
    /// test's are the same code and the same coverage.
    fn load_with(
        &self,
        rules: &RulesRead,
        config: &ConfigRead,
    ) -> Result<LoadedPolicy, PolicyError> {
        let rules = rules(&self.rules_dir).map_err(PolicyError::Rules)?;
        let config =
            config(&self.config_file, MAX_CONFIG_BYTES).map_err(PolicyError::ConfigUntrusted)?;
        // Mapped rather than `?`: a root-owned settings file that is broken
        // cannot be planted on a development host, and every way
        // `settings_from` refuses is pinned by its own tests below.
        settings_from(config.as_deref(), &self.config_file)
            .map(|settings| LoadedPolicy { rules, settings })
    }
}

/// The engine's settings from the settings file's contents, or the documented
/// defaults when there is no file.
///
/// The same derivation `aido explain` makes, from the same `aido-config`
/// loader, so a key the front-end honours the broker honours too. A file that
/// is present and broken is a refusal, never a quiet fall back to defaults: a
/// settings file that does not mean what it says is exactly what this project
/// refuses to paper over.
///
/// # Errors
///
/// [`PolicyError::ConfigNotUtf8`] or [`PolicyError::ConfigInvalid`].
pub fn settings_from(contents: Option<&[u8]>, file: &Path) -> Result<Settings, PolicyError> {
    let mut config = ConfigSettings::default();
    if let Some(bytes) = contents {
        let name = file.display().to_string();
        let Ok(text) = std::str::from_utf8(bytes) else {
            return Err(PolicyError::ConfigNotUtf8 { file: name });
        };
        aido_config::apply_file(&mut config, Layer::System, &name, text)
            .map_err(PolicyError::ConfigInvalid)?;
    }
    Ok(Settings {
        confirm_agent_actions: config.get(Setting::ConfirmAgentActions).value == Value::Bool(true),
        frozen: config.get(Setting::Frozen).value == Value::Bool(true),
    })
}

/// How the broker classifies the peer: `Unattested`, always, in M2b.
///
/// There is no cgroup classification until M4, so no caller can be an
/// enrolled agent, and unattested routes to the human path with a password —
/// misclassification here can only withhold capability. The reason records
/// how the peer was identified, for the audit trail.
pub fn classify(identity: &PeerIdentity) -> CallerFacts {
    let pin = if identity.pinned {
        "pinned by pidfd"
    } else {
        "unpinned"
    };
    CallerFacts::new(
        Classification::Unattested {
            reason: format!(
                "no cgroup classification until M4; identified via {} as pid {} started at {} \
                 ({pin})",
                identity.rung.mechanism(),
                identity.pid,
                identity.starttime,
            ),
        },
        identity.uid,
    )
}

/// The decision for a request, made exactly as `aido explain` makes it: the
/// command, with no action named, through [`evaluate_command`].
pub fn decide(policy: &LoadedPolicy, caller: &CallerFacts, request: &BrokerRequest) -> Decision {
    evaluate_command(
        &policy.rules.rules,
        caller,
        &Arg::from(request.program.as_str()),
        &Argv::new(request.argv.iter().map(String::as_str)),
        policy.settings,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use aido_policy::{DenialCode, RuleFile, Verdict, load_rule_files};
    use aido_sys::Attestation;

    use super::*;
    use crate::identify::EuidSource;

    fn policy_of(toml: &str) -> LoadedPolicy {
        LoadedPolicy {
            rules: load_rule_files(vec![RuleFile {
                name: b"10-test.toml".to_vec(),
                bytes: toml.as_bytes().to_vec(),
            }])
            .unwrap(),
            settings: Settings::default(),
        }
    }

    const RULES: &str = r#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;

    fn identity(pinned: bool) -> PeerIdentity {
        PeerIdentity {
            rung: Attestation::PeerPidfdInfo,
            pid: 4242,
            uid: 1000,
            gid: 100,
            starttime: 998_877,
            pinned,
            cgroup_id: None,
            euid_source: EuidSource::PidfdInfo,
        }
    }

    fn ask(program: &str, argv: &[&str]) -> BrokerRequest {
        BrokerRequest::new(
            program,
            argv.iter().map(|a| (*a).to_owned()).collect(),
            "enrolled-agent",
        )
    }

    #[test]
    fn every_peer_is_unattested_in_m2b_and_keeps_its_connect_time_uid() {
        for pinned in [true, false] {
            let facts = classify(&identity(pinned));
            assert_eq!(facts.classification.label(), "unattested");
            assert!(facts.classification.requires_password());
            assert_eq!(facts.uid, 1000);
            let reason = format!("{:?}", facts.classification);
            assert!(reason.contains("SO_PEERPIDFD + PIDFD_GET_INFO"), "{reason}");
            assert!(reason.contains("pid 4242 started at 998877"), "{reason}");
            assert!(
                reason.contains(if pinned {
                    "pinned by pidfd"
                } else {
                    "unpinned"
                }),
                "{reason}"
            );
        }
    }

    #[test]
    fn the_brokers_decision_is_the_one_explain_makes() {
        // Same function, same inputs: the decision is identical to what the
        // front-end prints, field for field.
        let policy = policy_of(RULES);
        let caller = classify(&identity(true));
        let request = ask("/usr/bin/systemctl", &["restart", "nginx.service"]);
        let ours = decide(&policy, &caller, &request);
        let explain = evaluate_command(
            &policy.rules.rules,
            &caller,
            &Arg::from("/usr/bin/systemctl"),
            &Argv::new(["restart", "nginx.service"]),
            Settings::default(),
        );
        assert_eq!(ours, explain);
        assert_eq!(ours.verdict, Verdict::Allow);
    }

    #[test]
    fn the_claimed_classification_moves_nothing() {
        // Invariant 1 at the broker: the request may claim anything.
        let policy = policy_of(RULES);
        let caller = classify(&identity(true));
        let mut honest = ask("/usr/bin/systemctl", &["restart", "nginx.service"]);
        honest.claimed_classification = "human".to_owned();
        let mut lying = honest.clone();
        lying.claimed_classification = "enrolled-agent-yolo".to_owned();
        assert_eq!(
            decide(&policy, &caller, &honest),
            decide(&policy, &caller, &lying)
        );
    }

    #[test]
    fn settings_cannot_move_an_unattested_verdict() {
        // Why M2b's broker may run on the documented defaults when no
        // settings file exists: both settings apply to the agent path only,
        // and nobody reaches it until M4. If this ever fails, a setting has
        // started to affect the human path and must be loaded with care.
        let caller = classify(&identity(true));
        let request = ask("/usr/bin/systemctl", &["restart", "nginx.service"]);
        let mut policy = policy_of(RULES);
        let baseline = decide(&policy, &caller, &request);
        for (confirm_agent_actions, frozen) in [(true, true), (false, false), (false, true)] {
            policy.settings = Settings {
                confirm_agent_actions,
                frozen,
            };
            assert_eq!(decide(&policy, &caller, &request), baseline);
        }
    }

    #[test]
    fn a_command_no_rule_names_is_an_unknown_action_about_that_program() {
        let policy = policy_of(RULES);
        let caller = classify(&identity(true));
        let decision = decide(&policy, &caller, &ask("/bin/sh", &["-c", "id", "--"]));
        assert_eq!(decision.denial, Some(DenialCode::UnknownAction));
        assert_eq!(decision.resolved_exe.as_deref(), Some("/bin/sh"));
        assert_eq!(decision.resolved_argv, ["-c", "id"]);
    }

    #[test]
    fn a_missing_settings_file_means_the_documented_defaults() {
        let settings = settings_from(None, Path::new("/etc/aido/config.toml")).unwrap();
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn a_settings_file_is_honoured_as_the_front_end_honours_it() {
        let settings = settings_from(
            Some(b"confirm_agent_actions = false\nfrozen = true\n"),
            Path::new("/etc/aido/config.toml"),
        )
        .unwrap();
        assert_eq!(
            settings,
            Settings {
                confirm_agent_actions: false,
                frozen: true
            }
        );
    }

    #[test]
    fn a_broken_settings_file_is_a_refusal_not_a_fallback() {
        let file = Path::new("/etc/aido/config.toml");
        let err = settings_from(Some(b"confirm_agent_actions = \xff"), file).unwrap_err();
        assert_eq!(
            err,
            PolicyError::ConfigNotUtf8 {
                file: "/etc/aido/config.toml".to_owned()
            }
        );
        let err = settings_from(Some(b"skip_confirmation = true"), file).unwrap_err();
        assert!(err.to_string().contains("/etc/aido/config.toml"), "{err}");
    }

    // Handed to a parameter that must return a `Result`.
    #[allow(clippy::unnecessary_wraps)]
    fn no_rules(_: &Path) -> Result<LoadedRuleSet, TrustedRulesError> {
        Ok(aido_policy::load_rule_files(Vec::new()).unwrap())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn no_config(_: &Path, _: usize) -> Result<Option<Vec<u8>>, TrustError> {
        Ok(None)
    }

    fn untrusted() -> TrustError {
        TrustError::NotAbsolute { at: "x".to_owned() }
    }

    #[test]
    fn the_host_policy_is_the_trusted_ruleset_and_the_trusted_settings() {
        // On every platform: the composition, with the trusted reads handed in.
        let host = HostPolicy::new("/etc/aido/rules.d", "/etc/aido/config.toml");
        let loaded = host.load_with(&no_rules, &no_config).unwrap();
        assert!(loaded.rules.rules.is_empty());
        assert_eq!(loaded.settings, Settings::default());

        let loaded = host
            .load_with(&no_rules, &|file, limit| {
                assert_eq!(file, Path::new("/etc/aido/config.toml"));
                assert_eq!(limit, MAX_CONFIG_BYTES);
                Ok(Some(b"frozen = true\n".to_vec()))
            })
            .unwrap();
        assert!(loaded.settings.frozen);
    }

    #[test]
    fn the_host_policy_refuses_whatever_either_trusted_read_refuses() {
        let host = HostPolicy::new("/etc/aido/rules.d", "/etc/aido/config.toml");
        let err = host
            .load_with(
                &|dir| {
                    assert_eq!(dir, Path::new("/etc/aido/rules.d"));
                    Err(TrustedRulesError::Trust(untrusted()))
                },
                &no_config,
            )
            .unwrap_err();
        assert_eq!(
            err,
            PolicyError::Rules(TrustedRulesError::Trust(untrusted()))
        );
        let err = host
            .load_with(&no_rules, &|_, _| Err(untrusted()))
            .unwrap_err();
        assert_eq!(err, PolicyError::ConfigUntrusted(untrusted()));
        let err = host
            .load_with(&no_rules, &|_, _| Ok(Some(b"\xff".to_vec())))
            .unwrap_err();
        assert_eq!(
            err,
            PolicyError::ConfigNotUtf8 {
                file: "/etc/aido/config.toml".to_owned()
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_host_policy_loads_through_the_trust_walk() {
        // /usr/bin is root's on every host and holds no rule files, so it
        // loads as an empty ruleset; an absent settings file in it is the
        // defaults.
        let loaded = HostPolicy::new("/usr/bin", "/usr/bin/aido-surely-absent.toml")
            .load()
            .unwrap();
        assert!(loaded.rules.rules.is_empty());
        assert_eq!(loaded.settings, Settings::default());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_host_policy_refuses_a_ruleset_or_settings_that_are_not_roots() {
        let checkout = env!("CARGO_MANIFEST_DIR");
        let err = HostPolicy::new(checkout, "/usr/bin/absent.toml")
            .load()
            .unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");

        let err = HostPolicy::new("/usr/bin", "/dev/null").load().unwrap_err();
        assert!(
            err.to_string()
                .starts_with("the settings file cannot be read"),
            "{err}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_the_host_policy_is_never_loaded_because_no_mount_can_be_judged() {
        let err = HostPolicy::new("/usr/bin", "/usr/bin/absent.toml")
            .load()
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("the mount table cannot be checked"),
            "{err}"
        );
    }

    #[test]
    fn the_real_paths_are_absent_or_not_roots_on_a_development_host_and_refused_either_way() {
        let system = HostPolicy::system();
        assert_eq!(
            system,
            HostPolicy::new("/etc/aido/rules.d", "/etc/aido/config.toml")
        );
        assert!(system.load().is_err());
    }

    #[test]
    fn every_policy_refusal_names_the_problem() {
        for err in [
            PolicyError::Rules(TrustedRulesError::Trust(TrustError::NotAbsolute {
                at: "x".to_owned(),
            })),
            PolicyError::ConfigUntrusted(TrustError::NotAbsolute { at: "x".to_owned() }),
            PolicyError::ConfigNotUtf8 {
                file: "x".to_owned(),
            },
        ] {
            assert!(err.to_string().len() > 10, "{err:?}");
        }
    }
}
