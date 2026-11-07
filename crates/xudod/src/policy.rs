//! Root's policy, read the way a privileged reader must, and the one decision
//! the broker and `xudo explain` both make.
//!
//! Settings and trusted policy loading come from `xudo-gate::policy`, so the
//! broker and gate necessarily interpret the same trusted bytes identically.
//! The decision is `xudo_policy::evaluate_command`, the function behind
//! `xudo explain`.

use std::path::PathBuf;

use xudo_policy::{Arg, Argv, CallerFacts, Classification, Decision, evaluate_command};
use xudo_wire::BrokerRequest;

use crate::identify::PeerIdentity;

pub use xudo_gate::policy::{LoadedPolicy, PolicyError};
/// The largest settings file the broker will accept, in bytes.
pub const MAX_CONFIG_BYTES: usize = xudo_gate::MAX_CONFIG_BYTES;

/// Where the broker's policy comes from.
pub trait PolicySource {
    /// Loads the ruleset and settings in force now.
    ///
    /// # Errors
    ///
    /// Returns the shared policy error if trusted loading or parsing fails.
    fn load(&self) -> Result<LoadedPolicy, PolicyError>;
}

/// Root's policy on this host: the ruleset directory and settings file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostPolicy {
    rules_dir: PathBuf,
    config_file: PathBuf,
}

impl HostPolicy {
    /// `/etc/xudo/rules.d` and `/etc/xudo/config.toml`.
    pub fn system() -> Self {
        let paths = xudo_config::SystemPaths::default();
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
        xudo_gate::policy::load(&self.rules_dir, &self.config_file)
    }
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

/// The decision for a request, made exactly as `xudo explain` makes it.
pub fn decide(policy: &LoadedPolicy, caller: &CallerFacts, request: &BrokerRequest) -> Decision {
    let Some((program, argv, _)) = request.run_fields() else {
        return Decision::deny(
            xudo_policy::DenialCode::ArgvRejected,
            Vec::new(),
            Vec::new(),
        );
    };
    evaluate_command(
        &policy.rules.rules,
        caller,
        &Arg::from(program),
        &Argv::new(argv.iter().map(String::as_str)),
        policy.settings,
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use proptest::prelude::*;
    use std::path::Path;
    use xudo_policy::{DenialCode, RuleFile, Verdict, engine::Settings, load_rule_files};
    use xudo_sys::{Attestation, TrustError, TrustedRulesError};

    use super::*;
    use crate::identify::EuidSource;

    proptest! {
        #[test]
        fn shared_loader_handles_absent_and_present_settings(
            agent in proptest::option::of(any::<bool>()),
            human in proptest::option::of(any::<bool>()),
            frozen in proptest::option::of(any::<bool>()),
        ) {
            let mut rows = Vec::new();
            if let Some(value) = agent { rows.push(format!("confirm_agent_actions = {value}")); }
            if let Some(value) = human { rows.push(format!("confirm_human_path = {value}")); }
            if let Some(value) = frozen { rows.push(format!("frozen = {value}")); }
            let bytes = rows.join("\n");
            let loaded = xudo_gate::settings_from(
                (!rows.is_empty()).then_some(bytes.as_bytes()),
                Path::new("/etc/xudo/config.toml"),
            ).unwrap();
            prop_assert_eq!(loaded.confirm_agent_actions, agent.unwrap_or(Settings::default().confirm_agent_actions));
            prop_assert_eq!(loaded.confirm_human_path, human.unwrap_or(Settings::default().confirm_human_path));
            prop_assert_eq!(loaded.frozen, frozen.unwrap_or(Settings::default().frozen));
        }
    }

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
id = "xudo.svc.restart"
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
            sid: 1,
            tty: 0,
            diverged: false,
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
        honest.question = xudo_wire::Question::Run {
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
            claimed_classification: "human".to_owned(),
        };
        let mut lying = honest.clone();
        lying.question = xudo_wire::Question::Run {
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
            claimed_classification: "enrolled-agent-yolo".to_owned(),
        };
        assert_eq!(
            decide(&policy, &caller, &honest),
            decide(&policy, &caller, &lying)
        );
    }

    #[test]
    fn decide_refuses_a_non_run_question_closed() {
        let loaded = policy_of(RULES);
        let caller = classify(&identity(true));
        let mut request = ask("/usr/bin/systemctl", &["restart", "nginx.service"]);
        request.question = xudo_wire::Question::Watch;
        assert_eq!(
            decide(&loaded, &caller, &request).denial,
            Some(DenialCode::ArgvRejected)
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
                ..Settings::default()
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
        let settings = xudo_gate::settings_from(None, Path::new("/etc/xudo/config.toml")).unwrap();
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn a_settings_file_is_honoured_as_the_front_end_honours_it() {
        let settings = xudo_gate::settings_from(
            Some(b"confirm_agent_actions = false\nfrozen = true\n"),
            Path::new("/etc/xudo/config.toml"),
        )
        .unwrap();
        assert_eq!(
            settings,
            Settings {
                confirm_agent_actions: false,
                confirm_human_path: false,
                frozen: true,
            }
        );
    }

    #[test]
    fn a_broken_settings_file_is_a_refusal_not_a_fallback() {
        let file = Path::new("/etc/xudo/config.toml");
        let err =
            xudo_gate::settings_from(Some(b"confirm_agent_actions = \xff"), file).unwrap_err();
        assert_eq!(
            err,
            xudo_gate::SettingsError::NotUtf8 {
                file: "/etc/xudo/config.toml".to_owned()
            }
        );
        let err = xudo_gate::settings_from(Some(b"skip_confirmation = true"), file).unwrap_err();
        assert!(err.to_string().contains("/etc/xudo/config.toml"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_host_policy_loads_through_the_trust_walk() {
        // /usr/bin is root's on every host and holds no rule files, so it
        // loads as an empty ruleset; an absent settings file in it is the
        // defaults.
        let loaded = HostPolicy::new("/usr/bin", "/usr/bin/xudo-surely-absent.toml")
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
            HostPolicy::new("/etc/xudo/rules.d", "/etc/xudo/config.toml")
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
            PolicyError::Config(xudo_gate::SettingsError::NotUtf8 {
                file: "x".to_owned(),
            }),
        ] {
            assert!(err.to_string().len() > 10, "{err:?}");
        }
    }
}
