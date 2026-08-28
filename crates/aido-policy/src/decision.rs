//! The verdict, its machine-readable envelope, and the denial taxonomy.
//!
//! # Why the taxonomy is append-only
//!
//! The primary consumer of `aido` is a language model, and `exit 1` with a
//! prose message is the worst possible interface for one: the model guesses,
//! retries with a mangled command, or gives up and asks the human to run raw
//! `sudo` — defeating the tool. A stable code plus a concrete remediation lets
//! an agent branch correctly: needs a grant, so request one; permanently
//! denied, so stop asking; needs confirmation, so surface it and wait.
//!
//! Codes are therefore **append-only**. Renumbering one silently changes the
//! behaviour of every deployed agent that learned the old number.

use serde::{Deserialize, Serialize};

use crate::rule::{ActionId, Source};

/// Schema version of the decision envelope.
///
/// Bump on any change to the serialized shape so a consumer can refuse an
/// envelope it does not understand rather than misread one.
pub const ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// What the engine decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// May run now.
    Allow,
    /// May run once a human approves, out of band.
    AllowWithConfirmation,
    /// Must not run.
    ///
    /// There is deliberately no `Default` impl on this enum: a verdict that
    /// appears by default is a verdict nobody decided.
    Deny,
}

impl Verdict {
    /// Returns `true` when the request may proceed, with or without approval.
    pub fn is_permitted(self) -> bool {
        matches!(self, Self::Allow | Self::AllowWithConfirmation)
    }
}

/// Whether, and why, a human must approve before execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Confirm {
    /// No approval required.
    NotRequired,
    /// Approval required, with the reason to show the human.
    Required {
        /// Why this request is being surfaced.
        reason: ConfirmReason,
    },
}

/// Why a confirmation was demanded.
///
/// Always stated in both the prompt and the audit record. An unexplained "this
/// looked unusual" prompt trains people to click through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmReason {
    /// The default-on safety setting for the agent path.
    AgentActionsConfirmed,
    /// The matched rule declares confirmation regardless of caller.
    RuleRequiresConfirmation,
    /// The rule's tier is critical.
    CriticalTier,
}

impl ConfirmReason {
    /// The sentence shown to the approving human.
    pub fn explain(self) -> &'static str {
        match self {
            Self::AgentActionsConfirmed => {
                "an enrolled agent requested a privileged action and confirm_agent_actions is on"
            }
            Self::RuleRequiresConfirmation => "the matched rule always requires confirmation",
            Self::CriticalTier => "the matched rule is in a critical tier",
        }
    }
}

/// A stable, append-only denial code.
///
/// The numeric values are a wire contract. Never renumber, never reuse, and
/// only ever append.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialCode {
    /// No action in the ruleset has the requested id.
    UnknownAction,
    /// The action exists but the argv does not fit its argument list.
    ArgvRejected,
    /// A compiled-in deny-list capability class matched.
    DenyListed,
    /// The ruleset failed to load or parse.
    PolicyUnloadable,
    /// The broker is frozen: every agent-path request is denied.
    Frozen,
    /// No out-of-band confirmation channel is live, so the request cannot be
    /// confirmed and therefore cannot proceed.
    NoConfirmationChannel,
    /// The action is allowed for humans but never on the agent path.
    HumanPathOnly,
}

impl DenialCode {
    /// The stable numeric code. Append-only.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::UnknownAction => 1,
            Self::ArgvRejected => 2,
            Self::DenyListed => 3,
            Self::PolicyUnloadable => 4,
            Self::Frozen => 5,
            Self::NoConfirmationChannel => 6,
            Self::HumanPathOnly => 7,
        }
    }

    /// The stable string code, used in the JSON envelope.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownAction => "unknown_action",
            Self::ArgvRejected => "argv_rejected",
            Self::DenyListed => "deny_listed",
            Self::PolicyUnloadable => "policy_unloadable",
            Self::Frozen => "frozen",
            Self::NoConfirmationChannel => "no_confirmation_channel",
            Self::HumanPathOnly => "human_path_only",
        }
    }

    /// The concrete next step for the caller.
    ///
    /// This field is the difference between an agent that recovers and an agent
    /// that escalates to the human, so every code must name an action rather
    /// than restate the problem.
    pub fn remediation(self) -> &'static str {
        match self {
            Self::UnknownAction => {
                "no rule defines this action; run `aido list` to see what is permitted, \
                 or ask an administrator to add a rule"
            }
            Self::ArgvRejected => {
                "the action exists but these arguments are not permitted; run \
                 `aido explain -- <argv>` to see which position was rejected"
            }
            Self::DenyListed => {
                "this is permanently denied by a compiled-in rule and no configuration can \
                 allow it; do not retry, and do not look for a variant that slips past"
            }
            Self::PolicyUnloadable => {
                "the ruleset is invalid and aido is failing closed; an administrator must run \
                 `aido check` and repair it"
            }
            Self::Frozen => {
                "an administrator froze the agent path; the human path still works, so hand \
                 this action to a person"
            }
            Self::NoConfirmationChannel => {
                "this action needs human approval and no channel is live; ask the operator to \
                 run `aido watch` in a terminal they control"
            }
            Self::HumanPathOnly => {
                "this action is never available to an agent; hand it to a person"
            }
        }
    }
}

/// Process exit status.
///
/// Distinct from the denial code so a shell script can branch on the class of
/// failure while an agent branches on the precise code. Append-only, same
/// contract as [`DenialCode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitCode {
    /// The action ran; `aido` propagates the child's status instead.
    Delegated,
    /// Denied by policy.
    Denied,
    /// Awaiting or refused confirmation.
    NotConfirmed,
    /// aido itself could not operate and failed closed.
    Unusable,
}

impl ExitCode {
    /// The numeric exit status.
    ///
    /// `17`, `18`, and `19` sit above the range shells use for signals so they
    /// cannot be confused with a killed child.
    pub fn as_i32(self) -> i32 {
        match self {
            Self::Delegated => 0,
            Self::Denied => 17,
            Self::NotConfirmed => 18,
            Self::Unusable => 19,
        }
    }
}

/// One step of the evaluation, for `aido explain`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum TraceStep {
    /// The argv was canonicalized.
    Canonicalized {
        /// The argv as supplied.
        before: String,
        /// The argv after canonicalization.
        after: String,
    },
    /// A candidate action was considered and rejected.
    ActionRejected {
        /// The action's id.
        action: String,
        /// Why it did not apply.
        reason: String,
    },
    /// A candidate action matched.
    ActionMatched {
        /// The action's id.
        action: String,
        /// Where the rule is defined.
        source: String,
    },
    /// The deny-list was evaluated.
    DenyListEvaluated {
        /// Version of the compiled-in list.
        version: u32,
        /// Which capability classes matched, if any.
        matched: Vec<String>,
    },
    /// The confirmation requirement was decided.
    ConfirmationDecided {
        /// The requirement.
        required: bool,
        /// Why.
        reason: String,
    },
}

/// The complete result of an evaluation.
///
/// Serializes to the machine-readable envelope. Every field is present in
/// every verdict so a consumer never has to branch on absence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// Envelope schema version.
    pub schema_version: u32,
    /// The verdict.
    pub verdict: Verdict,
    /// The denial code, when the verdict is not [`Verdict::Allow`].
    pub denial: Option<DenialCode>,
    /// The concrete next step, when denied.
    pub remediation: Option<String>,
    /// Which action matched, if any.
    pub action: Option<ActionId>,
    /// Where the matching rule is defined, for `file:line` reporting.
    pub rule_source: Option<Source>,
    /// The canonicalized argv the decision was made about.
    pub resolved_argv: Vec<String>,
    /// Whether a human must approve.
    pub confirm: Confirm,
    /// The evaluation trace.
    pub trace: Vec<TraceStep>,
}

impl Decision {
    /// Builds a denial.
    pub fn deny(code: DenialCode, resolved_argv: Vec<String>, trace: Vec<TraceStep>) -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            verdict: Verdict::Deny,
            denial: Some(code),
            remediation: Some(code.remediation().to_owned()),
            action: None,
            rule_source: None,
            resolved_argv,
            confirm: Confirm::NotRequired,
            trace,
        }
    }

    /// The process exit status for this decision.
    pub fn exit_code(&self) -> ExitCode {
        match (self.verdict, self.denial) {
            (Verdict::Allow, _) => ExitCode::Delegated,
            // Awaiting approval and refused-for-lack-of-a-channel are the same
            // status on purpose: from a caller's side both mean "nobody has
            // approved this", and both are retryable once a channel is live.
            (Verdict::AllowWithConfirmation, _)
            | (Verdict::Deny, Some(DenialCode::NoConfirmationChannel)) => ExitCode::NotConfirmed,
            (Verdict::Deny, Some(DenialCode::PolicyUnloadable)) => ExitCode::Unusable,
            (Verdict::Deny, _) => ExitCode::Denied,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    const ALL_CODES: [DenialCode; 7] = [
        DenialCode::UnknownAction,
        DenialCode::ArgvRejected,
        DenialCode::DenyListed,
        DenialCode::PolicyUnloadable,
        DenialCode::Frozen,
        DenialCode::NoConfirmationChannel,
        DenialCode::HumanPathOnly,
    ];

    #[test]
    fn verdict_permits_only_allow_and_confirm() {
        assert!(Verdict::Allow.is_permitted());
        assert!(Verdict::AllowWithConfirmation.is_permitted());
        assert!(!Verdict::Deny.is_permitted());
    }

    #[test]
    fn denial_codes_are_unique_and_stable() {
        // The wire contract. If this test needs editing, a deployed agent's
        // error handling has just silently changed meaning.
        let numeric: Vec<u32> = ALL_CODES.iter().map(|c| c.as_u32()).collect();
        assert_eq!(numeric, vec![1, 2, 3, 4, 5, 6, 7]);

        let mut names: Vec<&str> = ALL_CODES.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate denial code string");
    }

    #[test]
    fn every_denial_code_names_a_next_step() {
        for code in ALL_CODES {
            let r = code.remediation();
            assert!(r.len() > 20, "{code:?} remediation is too thin: {r}");
            assert!(
                r.contains("aido")
                    || r.contains("administrator")
                    || r.contains("person")
                    || r.contains("do not retry"),
                "{code:?} remediation names no actor or action: {r}"
            );
        }
    }

    #[test]
    fn denial_codes_round_trip_through_json() {
        for code in ALL_CODES {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(serde_json::from_str::<DenialCode>(&json).unwrap(), code);
            assert!(json.contains(code.as_str()));
            assert!(format!("{code:?}").len() > 3);
        }
    }

    #[test]
    fn exit_codes_sit_above_the_signal_range() {
        assert_eq!(ExitCode::Delegated.as_i32(), 0);
        for code in [ExitCode::Denied, ExitCode::NotConfirmed, ExitCode::Unusable] {
            assert!(
                code.as_i32() > 16,
                "{code:?} could be mistaken for a signal"
            );
        }
        let json = serde_json::to_string(&ExitCode::Denied).unwrap();
        assert_eq!(
            serde_json::from_str::<ExitCode>(&json).unwrap(),
            ExitCode::Denied
        );
        assert!(format!("{:?}", ExitCode::Unusable).contains("Unusable"));
    }

    #[test]
    fn exit_code_distinguishes_unusable_from_denied() {
        let unusable = Decision::deny(DenialCode::PolicyUnloadable, Vec::new(), Vec::new());
        assert_eq!(unusable.exit_code(), ExitCode::Unusable);

        let denied = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        assert_eq!(denied.exit_code(), ExitCode::Denied);

        let unconfirmed = Decision::deny(DenialCode::NoConfirmationChannel, Vec::new(), Vec::new());
        assert_eq!(unconfirmed.exit_code(), ExitCode::NotConfirmed);
    }

    #[test]
    fn exit_code_covers_permitted_verdicts() {
        let mut d = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        d.verdict = Verdict::Allow;
        assert_eq!(d.exit_code(), ExitCode::Delegated);
        d.verdict = Verdict::AllowWithConfirmation;
        assert_eq!(d.exit_code(), ExitCode::NotConfirmed);
    }

    #[test]
    fn exit_code_handles_a_denial_with_no_code() {
        // Should not be constructible through the public API, but the match arm
        // must still fail closed rather than report success.
        let mut d = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        d.denial = None;
        assert_eq!(d.exit_code(), ExitCode::Denied);
    }

    #[test]
    fn deny_constructor_fills_the_whole_envelope() {
        let d = Decision::deny(
            DenialCode::ArgvRejected,
            vec!["install".into()],
            vec![TraceStep::Canonicalized {
                before: "a".into(),
                after: "a".into(),
            }],
        );
        assert_eq!(d.schema_version, ENVELOPE_SCHEMA_VERSION);
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.denial, Some(DenialCode::ArgvRejected));
        assert_eq!(
            d.remediation.as_deref(),
            Some(DenialCode::ArgvRejected.remediation())
        );
        assert!(d.action.is_none());
        assert!(d.rule_source.is_none());
        assert_eq!(d.confirm, Confirm::NotRequired);
        assert_eq!(d.trace.len(), 1);
    }

    #[test]
    fn decision_round_trips_and_rejects_unknown_keys() {
        let d = Decision::deny(DenialCode::Frozen, vec!["x".into()], Vec::new());
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Decision>(&json).unwrap(), d);
        assert!(format!("{d:?}").contains("Frozen"));

        let tampered = json.replace(r#""verdict""#, r#""allow_everything":true,"verdict""#);
        assert!(serde_json::from_str::<Decision>(&tampered).is_err());
    }

    #[test]
    fn confirm_reasons_each_explain_themselves() {
        for reason in [
            ConfirmReason::AgentActionsConfirmed,
            ConfirmReason::RuleRequiresConfirmation,
            ConfirmReason::CriticalTier,
        ] {
            assert!(reason.explain().len() > 20, "{reason:?}");
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(
                serde_json::from_str::<ConfirmReason>(&json).unwrap(),
                reason
            );
            assert!(format!("{reason:?}").len() > 3);
        }
    }

    #[test]
    fn confirm_round_trips_in_both_states() {
        for c in [
            Confirm::NotRequired,
            Confirm::Required {
                reason: ConfirmReason::CriticalTier,
            },
        ] {
            let json = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<Confirm>(&json).unwrap(), c);
            assert!(format!("{c:?}").len() > 3);
        }
    }

    #[test]
    fn every_trace_step_variant_serializes() {
        let steps = vec![
            TraceStep::Canonicalized {
                before: "a".into(),
                after: "b".into(),
            },
            TraceStep::ActionRejected {
                action: "x".into(),
                reason: "y".into(),
            },
            TraceStep::ActionMatched {
                action: "x".into(),
                source: "f:1".into(),
            },
            TraceStep::DenyListEvaluated {
                version: 1,
                matched: vec!["SpawnsShell".into()],
            },
            TraceStep::ConfirmationDecided {
                required: true,
                reason: "r".into(),
            },
        ];
        let json = serde_json::to_string(&steps).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<TraceStep>>(&json).unwrap(),
            steps
        );
        for s in &steps {
            assert!(format!("{s:?}").len() > 5);
        }
    }
}
