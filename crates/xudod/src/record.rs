//! The audit record of every answer the broker gives.
//!
//! Each builder takes the chain's last record, so the sink can chain it. A
//! record carries what the response does not: how the peer was identified, its
//! pin, the generation decided under, the nonce minted, a refusal's detail, and
//! the caller's own claim beside the classification the broker made.

use xudo_audit::record::{Decision as AuditDecision, Outcome, Record};
use xudo_gate::request::PendingRequest;
use xudo_policy::{CallerFacts, Decision, Generation, Verdict, deny_list_version};
use xudo_wire::BrokerRequest;

use crate::identify::PeerIdentity;
use crate::mint::Grant;
use crate::refusal::Refusal;

/// The classification label for a refusal made before anyone was classified.
///
/// The broker classifies every caller `Unattested` in M2b anyway, so this is
/// the label a classified caller would have carried too.
const UNATTESTED: &str = "unattested";

/// The record of a decision, and of the entry minted for it if there is one.
pub fn decided(
    previous: Option<&Record>,
    decision: &Decision,
    caller: &CallerFacts,
    identity: &PeerIdentity,
    request: &BrokerRequest,
    generation: &Generation,
    minted: Option<&PendingRequest>,
) -> Record {
    let mut evidence = vec!["broker=xudod".to_owned()];
    evidence.extend(identity_evidence(identity));
    if let Some((_, _, claimed)) = request.run_fields() {
        evidence.push(format!("claimed_classification={claimed}"));
    }
    evidence.push(format!("generation={}", generation.hex()));
    if let Some(entry) = minted {
        evidence.push(format!("nonce={}", entry.nonce));
        evidence.push(format!("deadline_ms={}", entry.deadline.0));
    }

    // A minted entry is recorded as the gate will read it, which is what
    // `authorize` checks the record against.
    let command = minted.map_or_else(|| decision.resolved_command(), Grant::command_of);
    let mut record = Record::after(
        previous,
        audit_decision(decision.verdict),
        command,
        caller.classification.label(),
    )
    .with_evidence(evidence)
    .with_deny_list_version(deny_list_version())
    .with_outcome(Outcome::NotExecuted);
    if let Some(code) = decision.denial {
        record = record.with_denial(code.as_str());
    }
    if let (Some(action), Some(source)) = (&decision.action, &decision.rule_source) {
        record = record.with_rule(action.as_str(), source.to_string());
    }
    record
}

/// The record of a refusal.
pub fn refused(
    previous: Option<&Record>,
    refusal: &Refusal,
    identity: Option<&PeerIdentity>,
    request: Option<&BrokerRequest>,
) -> Record {
    let mut evidence = vec![
        "broker=xudod".to_owned(),
        format!("fault={}", refusal.fault.label()),
        format!("detail={}", refusal.detail),
    ];
    if let Some(identity) = identity {
        evidence.extend(identity_evidence(identity));
    }
    if let Some(request) = request {
        evidence.push(format!("question={}", question_kind(&request.question)));
        if let Some((_, _, claimed)) = request.run_fields() {
            evidence.push(format!("claimed_classification={claimed}"));
        }
    }
    Record::after(
        previous,
        AuditDecision::Denied,
        request.map(command_of).unwrap_or_default(),
        UNATTESTED,
    )
    .with_denial(refusal.code.as_str())
    .with_evidence(evidence)
    .with_outcome(Outcome::NotExecuted)
}

fn question_kind(question: &xudo_wire::Question) -> &'static str {
    match question {
        xudo_wire::Question::Run { .. } => "run",
        xudo_wire::Question::Status { .. } => "status",
        xudo_wire::Question::Watch => "watch",
        xudo_wire::Question::Pending => "pending",
        xudo_wire::Question::Answer { .. } => "answer",
        xudo_wire::Question::Freeze { .. } => "freeze",
        xudo_wire::Question::Thaw => "thaw",
    }
}

/// The evidence for how the peer was identified.
fn identity_evidence(identity: &PeerIdentity) -> Vec<String> {
    let mut evidence = vec![
        format!("rung={}", identity.rung.mechanism()),
        format!("peer_pid={}", identity.pid),
        format!("peer_starttime={}", identity.starttime),
        format!("peer_sid={}", identity.sid),
        format!("peer_tty={}", identity.tty),
        format!("diverged={}", identity.diverged),
        format!("peer_uid={}", identity.uid),
        format!("peer_gid={}", identity.gid),
        format!("pinned={}", identity.pinned),
        format!("euid_from={}", identity.euid_source.label()),
    ];
    if let Some(id) = identity.cgroup_id {
        evidence.push(format!("cgroup_id={id}"));
    }
    evidence
}

/// The request's command as one argv, program first, exactly as asked.
fn command_of(request: &BrokerRequest) -> Vec<String> {
    request
        .run_fields()
        .map_or_else(Vec::new, |(program, argv, _)| {
            let mut command = vec![program.to_owned()];
            command.extend(argv.iter().cloned());
            command
        })
}

/// The audit trail's word for a verdict.
fn audit_decision(verdict: Verdict) -> AuditDecision {
    match verdict {
        Verdict::Allow => AuditDecision::Allowed,
        Verdict::AllowWithConfirmation => AuditDecision::AwaitingConfirmation,
        Verdict::Deny => AuditDecision::Denied,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use xudo_policy::{ActionId, Classification, DenialCode, Source};
    use xudo_sys::Attestation;
    use xudo_wire::RefusalCode;

    use super::*;
    use crate::identify::EuidSource;

    fn identity(cgroup_id: Option<u64>) -> PeerIdentity {
        PeerIdentity {
            rung: Attestation::PeerPidfdInfo,
            pid: 4242,
            uid: 1000,
            gid: 100,
            starttime: 998_877,
            sid: 1,
            tty: 0,
            diverged: false,
            pinned: true,
            cgroup_id,
            euid_source: EuidSource::PidfdInfo,
        }
    }

    fn caller() -> CallerFacts {
        CallerFacts::new(
            Classification::Unattested {
                reason: "M2b".to_owned(),
            },
            1000,
        )
    }

    fn request() -> BrokerRequest {
        BrokerRequest::new(
            "/usr/bin/systemctl",
            vec!["restart".to_owned(), "nginx.service".to_owned()],
            "enrolled-agent-yolo",
        )
    }

    #[test]
    fn refusal_records_name_every_question_kind_without_its_secret_fields() {
        let refusal = Refusal::client(RefusalCode::RequestUnknown, "private detail");
        for (question, kind) in [
            (
                xudo_wire::Question::Run {
                    program: "/bin/id".to_owned(),
                    argv: Vec::new(),
                    claimed_classification: "x".to_owned(),
                },
                "run",
            ),
            (xudo_wire::Question::Status { id: "a".repeat(64) }, "status"),
            (xudo_wire::Question::Watch, "watch"),
            (xudo_wire::Question::Pending, "pending"),
            (
                xudo_wire::Question::Answer {
                    id: "a".repeat(64),
                    token: "secret-token".to_owned(),
                    approve: true,
                },
                "answer",
            ),
            (
                xudo_wire::Question::Freeze {
                    reason: "secret-reason".to_owned(),
                },
                "freeze",
            ),
            (xudo_wire::Question::Thaw, "thaw"),
        ] {
            let request = BrokerRequest {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                question,
            };
            let record = refused(None, &refusal, None, Some(&request));
            assert!(record.evidence.contains(&format!("question={kind}")));
            let evidence = record.evidence.join(" ");
            assert!(!evidence.contains("secret-token"));
            assert!(!evidence.contains("secret-reason"));
        }
    }

    fn generation() -> Generation {
        xudo_policy::load_rule_files(Vec::new()).unwrap().generation
    }

    fn permitted(verdict: Verdict) -> Decision {
        let mut decision = Decision::deny(
            DenialCode::DenyListed,
            vec!["restart".to_owned(), "nginx.service".to_owned()],
            Vec::new(),
        )
        .about_program("/usr/bin/systemctl");
        decision.verdict = verdict;
        decision.denial = None;
        decision.action = Some(ActionId::new("xudo.svc.restart"));
        decision.rule_source = Some(Source::new("20-services.toml", 3));
        decision
    }

    #[test]
    fn a_non_run_decision_record_does_not_invent_a_command_or_claim() {
        let request = BrokerRequest {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Watch,
        };
        let decision = Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new());
        let record = decided(
            None,
            &decision,
            &caller(),
            &identity(None),
            &request,
            &generation(),
            None,
        );
        assert!(record.argv.is_empty());
        assert!(
            !record
                .evidence
                .iter()
                .any(|item| item.starts_with("claimed_classification="))
        );
    }

    #[test]
    fn a_minted_decision_records_the_pin_the_rule_the_nonce_and_the_unheeded_claim() {
        let entry = PendingRequest {
            schema_version: xudo_gate::request::REQUEST_SCHEMA_VERSION,
            nonce: "ab".repeat(32),
            caller_pid: 4242,
            caller_starttime: 998_877,
            action: "xudo.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
            generation: 7,
            deadline: xudo_gate::request::BoottimeMillis(1_900),
            confirmed: false,
            confirmed_by: None,
            state: xudo_gate::request::ConfirmationState::Pending,
            caller_uid: 1000,
            caller_sid: 10,
            caller_tty: 20,
            needs_watch: false,
            shown_at_ms: None,
            shown_to: None,
            fingerprint: "0".repeat(64),
            claimed_classification: "enrolled-agent-yolo".to_owned(),
        };
        let record = decided(
            None,
            &permitted(Verdict::Allow),
            &caller(),
            &identity(Some(77)),
            &request(),
            &generation(),
            Some(&entry),
        );
        assert_eq!(record.decision, AuditDecision::Allowed);
        assert_eq!(record.action.as_deref(), Some("xudo.svc.restart"));
        assert_eq!(record.rule_source.as_deref(), Some("20-services.toml:3"));
        assert_eq!(record.denial, None);
        assert_eq!(record.classification, "unattested");
        assert_eq!(
            record.argv,
            ["/usr/bin/systemctl", "restart", "nginx.service"]
        );
        for expected in [
            "broker=xudod".to_owned(),
            "rung=SO_PEERPIDFD + PIDFD_GET_INFO".to_owned(),
            "peer_pid=4242".to_owned(),
            "peer_starttime=998877".to_owned(),
            "peer_uid=1000".to_owned(),
            "pinned=true".to_owned(),
            "euid_from=PIDFD_GET_INFO".to_owned(),
            "cgroup_id=77".to_owned(),
            "claimed_classification=enrolled-agent-yolo".to_owned(),
            format!("generation={}", generation().hex()),
            format!("nonce={}", "ab".repeat(32)),
            "deadline_ms=1900".to_owned(),
        ] {
            assert!(
                record.evidence.contains(&expected),
                "missing {expected}: {:?}",
                record.evidence
            );
        }
        assert_eq!(record.deny_list_version, deny_list_version());
        assert_eq!(record.outcome, Outcome::NotExecuted);
        assert!(record.is_sealed());
    }

    #[test]
    fn a_confirming_decision_is_recorded_as_awaiting_confirmation() {
        // On the password path the confirmation is the password sudo asks
        // for; the record says one is still owed.
        let record = decided(
            None,
            &permitted(Verdict::AllowWithConfirmation),
            &caller(),
            &identity(None),
            &request(),
            &generation(),
            None,
        );
        assert_eq!(record.decision, AuditDecision::AwaitingConfirmation);
        assert!(!record.evidence.iter().any(|e| e.starts_with("nonce=")));
        assert!(!record.evidence.iter().any(|e| e.starts_with("cgroup_id=")));
    }

    #[test]
    fn a_denial_records_its_code_and_no_rule() {
        let denial = Decision::deny(DenialCode::ArgvRejected, vec!["x".to_owned()], Vec::new());
        let record = decided(
            None,
            &denial,
            &caller(),
            &identity(None),
            &request(),
            &generation(),
            None,
        );
        assert_eq!(record.decision, AuditDecision::Denied);
        assert_eq!(record.denial.as_deref(), Some("argv_rejected"));
        assert_eq!(record.action, None);
    }

    #[test]
    fn a_refusal_records_the_detail_the_client_never_sees() {
        let refusal = Refusal::broker(
            RefusalCode::SpoolUnusable,
            "/run/xudo cannot be inspected: No such file or directory",
        );
        let record = refused(None, &refusal, Some(&identity(None)), Some(&request()));
        assert_eq!(record.decision, AuditDecision::Denied);
        assert_eq!(record.denial.as_deref(), Some("spool_unusable"));
        assert_eq!(
            record.argv,
            ["/usr/bin/systemctl", "restart", "nginx.service"]
        );
        assert!(record.evidence.contains(&"fault=broker".to_owned()));
        assert!(record.evidence.contains(
            &"detail=/run/xudo cannot be inspected: No such file or directory".to_owned()
        ));
        assert!(record.evidence.contains(&"peer_pid=4242".to_owned()));
        assert!(
            record
                .evidence
                .contains(&"claimed_classification=enrolled-agent-yolo".to_owned())
        );
        assert!(record.is_sealed());
    }

    #[test]
    fn a_refusal_before_anything_was_known_still_leaves_a_record() {
        let refusal = Refusal::client(RefusalCode::RequestMalformed, "not JSON");
        let record = refused(None, &refusal, None, None);
        assert!(record.argv.is_empty());
        assert_eq!(record.classification, "unattested");
        assert_eq!(
            record.evidence,
            ["broker=xudod", "fault=client", "detail=not JSON"]
        );
    }
}
