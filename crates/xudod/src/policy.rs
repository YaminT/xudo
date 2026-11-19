//! Root's policy, read the way a privileged reader must, and the one decision
//! the broker and `xudo explain` both make.
//!
//! Settings and trusted policy loading come from `xudo-gate::policy`, so the
//! broker and gate necessarily interpret the same trusted bytes identically.
//! The decision is `xudo_policy::evaluate_command`, the function behind
//! `xudo explain`.

use std::path::PathBuf;

use xudo_policy::{
    Arg, Argv, CallerFacts, Classification, Decision, HarnessRegistry, evaluate_command, passwd_uid,
};
use xudo_wire::BrokerRequest;

use crate::identify::{CgroupAttestation, PeerIdentity};

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

/// Classifies the peer from the cgroup result derived while its kernel pidfd
/// was held. Process names and caller-controlled environment are audit hints
/// only and are never inputs here.
pub fn classify(identity: &PeerIdentity) -> CallerFacts {
    classify_with_registry(identity, &HarnessRegistry::empty(), "")
}

/// Classifies an identity only when its live root record still matches the
/// current root registry and the account database maps its configured name to
/// the peer uid.
pub fn classify_with_registry(
    identity: &PeerIdentity,
    registry: &HarnessRegistry,
    passwd: &str,
) -> CallerFacts {
    let classification = if identity.diverged {
        xudo_policy::Classification::Unattested {
            reason: "the peer's identity namespace diverges from the broker's".to_owned(),
        }
    } else {
        match &identity.cgroup_attestation {
            CgroupAttestation::AgentScope(scope) => {
                let registered = serde_json::from_slice::<xudo_gate::SessionRecord>(&scope.record)
                    .is_ok_and(|record| {
                        let resolve = |name: &str| passwd_uid(passwd, name);
                        registry.attests(
                            &record.label,
                            record.way,
                            &record.registry_entry_hash,
                            identity.uid,
                            &resolve,
                        )
                    });
                match (identity.cgroup_id, registered) {
                    (Some(scope_id), true) => xudo_policy::Classification::EnrolledAgent {
                        agent_id: format!("scope-{scope_id}"),
                        session_id: scope.name.clone(),
                        declared_yolo: false,
                    },
                    _ => xudo_policy::Classification::Unattested {
                        reason: "agent scope record does not match the current harness registry"
                            .to_owned(),
                    },
                }
            }
            CgroupAttestation::Outside | CgroupAttestation::OtherScope(_) => {
                xudo_policy::Classification::Human
            }
            CgroupAttestation::Recordless
            | CgroupAttestation::Unattested
            | CgroupAttestation::NotChecked => xudo_policy::Classification::Unattested {
                reason: format!(
                    "cgroup facts were not sufficient at {}",
                    identity.rung.mechanism()
                ),
            },
        }
    };
    CallerFacts::new(classification, identity.uid)
}

/// The requester's facts as the broker stored them at mint, from kernel
/// attestation: the class and the requester's uid, nothing the answering
/// watcher or freezer is, and nothing the requester claimed. The registry
/// names are placeholders; they never decide anything.
pub fn stored_caller(entry: &xudo_gate::request::PendingRequest) -> CallerFacts {
    use xudo_gate::request::AttestedClass;
    let classification = match &entry.attested_class {
        AttestedClass::Unattested => Classification::Unattested {
            reason: "stored class at mint".to_owned(),
        },
        AttestedClass::Human => Classification::Human,
        AttestedClass::EnrolledAgent { scope_id } => Classification::EnrolledAgent {
            agent_id: format!("scope-{scope_id}"),
            session_id: "stored".to_owned(),
            declared_yolo: false,
        },
    };
    CallerFacts::new(classification, entry.caller_uid)
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
    #[cfg(target_os = "linux")]
    use xudo_sys::load_trusted_rules;
    use xudo_sys::{Attestation, TrustError, TrustedRulesError};

    use super::*;
    use crate::identify::EuidSource;

    proptest! {
        #[test]
        fn shared_loader_handles_absent_and_present_settings(
            human in proptest::option::of(any::<bool>()),
            frozen in proptest::option::of(any::<bool>()),
        ) {
            let mut rows = Vec::new();
            if let Some(value) = human { rows.push(format!("confirm_human_path = {value}")); }
            if let Some(value) = frozen { rows.push(format!("frozen = {value}")); }
            let bytes = rows.join("\n");
            let loaded = xudo_gate::settings_from(
                (!rows.is_empty()).then_some(bytes.as_bytes()),
                Path::new("/etc/xudo/config.toml"),
            ).unwrap();
            prop_assert!(loaded.confirm_agent_actions);
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
            passwd: Vec::new(),
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
            cgroup_attestation: CgroupAttestation::NotChecked,
            cgroup_rung: None,
            euid_source: EuidSource::PidfdInfo,
        }
    }

    fn test_registry() -> xudo_policy::HarnessRegistry {
        xudo_policy::HarnessRegistry::from_files([(
            "codex.toml",
            "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 4\n",
        )])
        .unwrap()
    }

    fn test_record(registry: &xudo_policy::HarnessRegistry, label: &str) -> Vec<u8> {
        let hash = registry.get("codex").unwrap().hash_hex();
        format!(
            r#"{{"uid":1000,"label":"{label}","way":"service","registry_entry_hash":"{hash}","boot_id":"abcdef01-2345-6789-abcd-ef0123456789","created_at_boottime_ms":20,"deadline":200,"pid":4242,"starttime":998877,"cgroup_id":77}}"#
        )
        .into_bytes()
    }

    fn ask(program: &str, argv: &[&str]) -> BrokerRequest {
        BrokerRequest::new(
            program,
            argv.iter().map(|a| (*a).to_owned()).collect(),
            "enrolled-agent",
        )
    }

    #[test]
    fn claudecode_env_and_agent_comm_without_a_scope_is_human() {
        let mut peer = identity(true);
        peer.cgroup_attestation = CgroupAttestation::Outside;
        let facts = classify(&peer);
        assert_eq!(facts.classification.label(), "human");
        assert!(facts.classification.requires_password());
        assert_eq!(facts.uid, 1000);
    }

    #[test]
    fn a_broker_agent_uses_the_attested_scope_name_as_its_session_id() {
        let registry = test_registry();
        let mut peer = identity(true);
        peer.cgroup_id = Some(77);
        peer.cgroup_attestation = CgroupAttestation::AgentScope(xudo_sys::Scope {
            kind: xudo_sys::ScopeKind::Agent,
            name: "agent-0123456789abcdef0123456789abcdef.scope".to_owned(),
            record: test_record(&registry, "codex"),
        });

        let facts = classify_with_registry(
            &peer,
            &registry,
            "agent:x:1000:1000:agent:/home/agent:/bin/sh\n",
        );

        assert!(matches!(
            facts.classification,
            xudo_policy::Classification::EnrolledAgent { session_id, .. }
                if session_id == "agent-0123456789abcdef0123456789abcdef.scope"
        ));
    }

    #[test]
    fn an_unregistered_same_uid_process_is_not_a_harness() {
        let registry = test_registry();
        let mut peer = identity(true);
        peer.cgroup_id = Some(77);
        peer.cgroup_attestation = CgroupAttestation::AgentScope(xudo_sys::Scope {
            kind: xudo_sys::ScopeKind::Agent,
            name: "agent-0123456789abcdef0123456789abcdef.scope".to_owned(),
            record: test_record(&registry, "removed"),
        });
        let facts = classify_with_registry(
            &peer,
            &registry,
            "agent:x:1000:1000:agent:/home/agent:/bin/sh\n",
        );
        assert!(!facts.classification.is_enrolled_agent());
        assert!(facts.classification.requires_password());
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
    fn a_settings_file_keeps_agent_actions_on_the_human_path() {
        let settings = xudo_gate::settings_from(
            Some(b"confirm_human_path = false\nfrozen = true\n"),
            Path::new("/etc/xudo/config.toml"),
        )
        .unwrap();
        assert_eq!(
            settings,
            Settings {
                confirm_agent_actions: true,
                confirm_human_path: false,
                frozen: true,
            }
        );
    }

    #[test]
    fn settings_refuse_an_audit_sink_other_than_journald() {
        let error = xudo_gate::settings_from(
            Some(b"audit_sink = \"syslog\"\n"),
            Path::new("/etc/xudo/config.toml"),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("audit_sink only accepts \"journald\"")
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
    fn on_linux_the_host_policy_loads_an_absent_registry_as_empty() {
        // `/usr/bin` is root-owned and contains no rule files. With no
        // adjacent registry, there are no root-registered harnesses.
        assert!(load_trusted_rules(Path::new("/usr/bin")).is_ok());
        let loaded = HostPolicy::new("/usr/bin", "/usr/bin/xudo-surely-absent.toml")
            .load()
            .unwrap();
        assert!(loaded.rules.rules.is_empty());
        assert!(loaded.rules.harnesses.is_empty());
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
        assert!(err.to_string().contains("/dev/null"), "{err}");
        assert!(
            err.to_string()
                .contains("not a directory or a regular file"),
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
