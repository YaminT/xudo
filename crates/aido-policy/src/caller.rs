//! Who is asking, and how much that is worth.
//!
//! # The inverted trust model
//!
//! `aido`'s premise — agents run without a password, humans are prompted —
//! makes the *absence* of proof-of-humanity the thing that grants a privilege.
//! Every cheap signal that a caller is an agent is produced by the caller:
//! `CLAUDECODE=1` is an environment variable anyone can export, `argv[0]` is
//! chosen by the exec'ing process, `comm` is 16 bytes of anything, and
//! `/proc/<pid>/exe` points at a file in a user-writable, self-updating `$HOME`.
//!
//! So this module draws a hard line. [`Classification`] is derived by the root
//! broker from *kernel-attested* facts and is the only input with authorization
//! weight. Everything else is a [`Hint`]: recorded in the audit trail so an
//! investigator can see what the caller claimed, and structurally unable to
//! change a verdict.
//!
//! Even a perfect classification is not a security boundary, and the design
//! says so out loud. A human can ask a genuinely-enrolled agent to run the
//! command, which is indistinguishable at the syscall layer. A successful
//! impersonation therefore buys exactly one thing — skipping the password on an
//! action that is *already allowlisted* — and buys no new capability. The
//! allowlist must be sized on that assumption.

use serde::{Deserialize, Serialize};

/// How the broker classified the caller, from kernel-attested facts only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Classification {
    /// The caller's cgroup id matches a live, root-created transient scope
    /// under `aido.slice`.
    ///
    /// This is the one signal that cannot be forged by a same-uid process:
    /// writing a pid into that cgroup requires write access to both the
    /// destination and the common-ancestor `cgroup.procs`, and `aido.slice`
    /// sits outside systemd's delegated user subtree, so the attempt fails
    /// `EACCES`.
    EnrolledAgent {
        /// The registry id of the enrolled agent.
        agent_id: String,
        /// The broker's session record id.
        session_id: String,
        /// Whether the agent declared an auto-approve ("yolo") mode over the
        /// authenticated channel.
        ///
        /// Never inferred from ancestor argv: an attacker who wants the prompt
        /// skipped simply omits the flag, and an in-session toggle never
        /// appears in argv at all. This affects logging and prompt wording
        /// only, never authorization.
        declared_yolo: bool,
    },
    /// An authenticated human on the interactive path.
    Human,
    /// The broker could not attest the caller.
    ///
    /// Routes identically to [`Classification::Human`], and that direction is
    /// deliberate: misclassification may only withhold capability, never grant
    /// it. There is no path from "cannot attest" to "passwordless".
    Unattested {
        /// Why attestation failed, for the audit record.
        reason: String,
    },
}

impl Classification {
    /// Returns `true` only for an attested, enrolled agent session.
    pub fn is_enrolled_agent(&self) -> bool {
        matches!(self, Self::EnrolledAgent { .. })
    }

    /// Returns `true` when this caller must authenticate with a password.
    ///
    /// Note the asymmetry: everything that is not a proven agent authenticates.
    pub fn requires_password(&self) -> bool {
        !self.is_enrolled_agent()
    }

    /// Returns the agent's declared auto-approve state, if any.
    pub fn declared_yolo(&self) -> bool {
        matches!(
            self,
            Self::EnrolledAgent {
                declared_yolo: true,
                ..
            }
        )
    }

    /// A short label for audit records and traces.
    pub fn label(&self) -> &'static str {
        match self {
            Self::EnrolledAgent { .. } => "enrolled-agent",
            Self::Human => "human",
            Self::Unattested { .. } => "unattested",
        }
    }
}

/// Where an unauthenticated hint came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum HintSource {
    /// An environment variable, e.g. `CLAUDECODE`.
    Environment,
    /// `/proc/<pid>/comm` of the caller or an ancestor.
    Comm,
    /// `/proc/<pid>/cmdline` of the caller or an ancestor.
    Cmdline,
    /// The resolved `/proc/<pid>/exe` of an ancestor.
    AncestorExe,
    /// Presence or absence of a controlling terminal.
    ControllingTty,
}

/// An unauthenticated claim about the caller.
///
/// Hints exist to be written down, never to be believed. See the
/// `hints_never_change_the_verdict` property test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hint {
    /// Where the claim came from.
    pub source: HintSource,
    /// The claim's key, e.g. the variable or field name.
    pub key: String,
    /// The claim's value, rendered for display.
    pub value: String,
}

impl Hint {
    /// Records a hint.
    pub fn new(source: HintSource, key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            source,
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Everything the engine knows about a caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerFacts {
    /// The broker's classification. The only field with authorization weight.
    pub classification: Classification,
    /// The caller's real uid, from `SO_PEERCRED`/`PIDFD_GET_INFO`.
    pub uid: u32,
    /// The project root the request is scoped to, if any.
    pub project_root: Option<String>,
    /// Unauthenticated claims, for the audit record only.
    #[serde(default)]
    pub hints: Vec<Hint>,
}

impl CallerFacts {
    /// Builds facts for a caller with no hints recorded.
    pub fn new(classification: Classification, uid: u32) -> Self {
        Self {
            classification,
            uid,
            project_root: None,
            hints: Vec::new(),
        }
    }

    /// Attaches an unauthenticated hint.
    #[must_use]
    pub fn with_hint(mut self, hint: Hint) -> Self {
        self.hints.push(hint);
        self
    }

    /// Scopes the request to a project root.
    #[must_use]
    pub fn with_project_root(mut self, root: impl Into<String>) -> Self {
        self.project_root = Some(root.into());
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn agent(yolo: bool) -> Classification {
        Classification::EnrolledAgent {
            agent_id: "claude-code".into(),
            session_id: "s-1".into(),
            declared_yolo: yolo,
        }
    }

    #[test]
    fn only_an_enrolled_agent_skips_the_password() {
        assert!(agent(false).is_enrolled_agent());
        assert!(!agent(false).requires_password());
        assert!(Classification::Human.requires_password());
    }

    #[test]
    fn unattested_authenticates_like_a_human() {
        // The direction that matters: failing to attest must never be a
        // shortcut to the passwordless path.
        let unattested = Classification::Unattested {
            reason: "namespace divergence".into(),
        };
        assert!(unattested.requires_password());
        assert!(!unattested.is_enrolled_agent());
    }

    #[test]
    fn declared_yolo_is_only_ever_read_from_an_attested_session() {
        assert!(agent(true).declared_yolo());
        assert!(!agent(false).declared_yolo());
        assert!(!Classification::Human.declared_yolo());
        assert!(
            !Classification::Unattested {
                reason: String::new()
            }
            .declared_yolo()
        );
    }

    #[test]
    fn labels_are_stable_for_audit_records() {
        assert_eq!(agent(false).label(), "enrolled-agent");
        assert_eq!(Classification::Human.label(), "human");
        assert_eq!(
            Classification::Unattested {
                reason: String::new()
            }
            .label(),
            "unattested"
        );
    }

    #[test]
    fn facts_builders_compose() {
        let facts = CallerFacts::new(Classification::Human, 1000)
            .with_project_root("/srv/app")
            .with_hint(Hint::new(HintSource::Environment, "CLAUDECODE", "1"));
        assert_eq!(facts.uid, 1000);
        assert_eq!(facts.project_root.as_deref(), Some("/srv/app"));
        assert_eq!(facts.hints.len(), 1);
        assert_eq!(
            facts.hints.first().map(|h| h.source),
            Some(HintSource::Environment)
        );
    }

    #[test]
    fn every_hint_source_is_representable_and_serializable() {
        for source in [
            HintSource::Environment,
            HintSource::Comm,
            HintSource::Cmdline,
            HintSource::AncestorExe,
            HintSource::ControllingTty,
        ] {
            let hint = Hint::new(source, "k", "v");
            let json = serde_json::to_string(&hint).unwrap();
            let back: Hint = serde_json::from_str(&json).unwrap();
            assert_eq!(hint, back);
            assert!(format!("{hint:?}").contains('k'));
        }
    }

    #[test]
    fn facts_round_trip_and_reject_unknown_keys() {
        let facts = CallerFacts::new(agent(true), 0);
        let json = serde_json::to_string(&facts).unwrap();
        assert_eq!(serde_json::from_str::<CallerFacts>(&json).unwrap(), facts);
        assert!(format!("{facts:?}").contains("claude-code"));

        let err = serde_json::from_str::<CallerFacts>(
            r#"{"classification":"human","uid":0,"project_root":null,"trusted":true}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("trusted"), "{err}");
    }

    #[test]
    fn hints_default_to_empty_when_absent() {
        let facts: CallerFacts =
            serde_json::from_str(r#"{"classification":"human","uid":7,"project_root":null}"#)
                .unwrap();
        assert!(facts.hints.is_empty());
    }
}
