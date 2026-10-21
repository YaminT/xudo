//! The audit record of every answer the broker gives.
//!
//! One `aido_audit::Record` per connection, as one JSON line on standard
//! error, which the unit hands to the journal. The hash-chained trail
//! (`aido_sys::audit`, M2b step 6) exists, but the broker does not write
//! through it until plan item D1; until then each record is the first of a
//! chain of one, and the journal is the trail.
//!
//! A record carries what the response does not: how the peer was identified
//! and on which rung, its pinned identity, the generation decided under, the
//! nonce minted, and, for a refusal, the full detail. The caller's own claim
//! about what it is goes in too, beside the classification the broker made,
//! because "it claimed to be an agent and the claim changed nothing" is the
//! sentence an investigator needs.

use std::io::Write;

use aido_audit::record::{Decision as AuditDecision, Outcome, Record};
use aido_gate::request::PendingRequest;
use aido_policy::{CallerFacts, Decision, Generation, Verdict, deny_list_version};
use aido_wire::BrokerRequest;

use crate::identify::PeerIdentity;
use crate::refusal::Refusal;

/// The classification label for a refusal made before anyone was classified.
///
/// The broker classifies every caller `Unattested` in M2b anyway, so this is
/// the label a classified caller would have carried too.
const UNATTESTED: &str = "unattested";

/// The record of a decision, and of the entry minted for it if there is one.
pub fn decided(
    decision: &Decision,
    caller: &CallerFacts,
    identity: &PeerIdentity,
    request: &BrokerRequest,
    generation: &Generation,
    minted: Option<&PendingRequest>,
) -> Record {
    let mut evidence = vec!["broker=aidod".to_owned()];
    evidence.extend(identity_evidence(identity));
    evidence.push(format!(
        "claimed_classification={}",
        request.claimed_classification
    ));
    evidence.push(format!("generation={}", generation.hex()));
    if let Some(entry) = minted {
        evidence.push(format!("nonce={}", entry.nonce));
        evidence.push(format!("deadline={}", entry.deadline.0));
    }

    let mut record = Record::first(
        audit_decision(decision.verdict),
        decision.resolved_command(),
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
    refusal: &Refusal,
    identity: Option<&PeerIdentity>,
    request: Option<&BrokerRequest>,
) -> Record {
    let mut evidence = vec![
        "broker=aidod".to_owned(),
        format!("fault={}", refusal.fault.label()),
        format!("detail={}", refusal.detail),
    ];
    if let Some(identity) = identity {
        evidence.extend(identity_evidence(identity));
    }
    if let Some(request) = request {
        evidence.push(format!(
            "claimed_classification={}",
            request.claimed_classification
        ));
    }
    Record::first(
        AuditDecision::Denied,
        request.map(command_of).unwrap_or_default(),
        UNATTESTED,
    )
    .with_denial(refusal.code.as_str())
    .with_evidence(evidence)
    .with_outcome(Outcome::NotExecuted)
}

/// Writes one record as one line.
///
/// # Errors
///
/// Whatever the writer refuses with. The broker mints nothing whose record
/// could not be written.
pub fn emit(record: &Record, log: &mut dyn Write) -> std::io::Result<()> {
    writeln!(log, "{}", record.to_jsonl())
}

/// The evidence for how the peer was identified.
fn identity_evidence(identity: &PeerIdentity) -> Vec<String> {
    let mut evidence = vec![
        format!("rung={}", identity.rung.mechanism()),
        format!("peer_pid={}", identity.pid),
        format!("peer_starttime={}", identity.starttime),
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
    let mut command = vec![request.program.clone()];
    command.extend(request.argv.iter().cloned());
    command
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

    use aido_policy::{ActionId, Classification, DenialCode, Source};
    use aido_sys::Attestation;
    use aido_wire::RefusalCode;

    use super::*;
    use crate::identify::EuidSource;

    fn identity(cgroup_id: Option<u64>) -> PeerIdentity {
        PeerIdentity {
            rung: Attestation::PeerPidfdInfo,
            pid: 4242,
            uid: 1000,
            gid: 100,
            starttime: 998_877,
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

    fn generation() -> Generation {
        aido_policy::load_rule_files(Vec::new()).unwrap().generation
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
        decision.action = Some(ActionId::new("aido.svc.restart"));
        decision.rule_source = Some(Source::new("20-services.toml", 3));
        decision
    }

    #[test]
    fn a_minted_decision_records_the_pin_the_rule_the_nonce_and_the_unheeded_claim() {
        let entry = PendingRequest {
            schema_version: aido_gate::request::REQUEST_SCHEMA_VERSION,
            nonce: "ab".repeat(32),
            caller_pid: 4242,
            caller_starttime: 998_877,
            action: "aido.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: Vec::new(),
            generation: 7,
            deadline: aido_gate::request::MonotonicSecs(1_900),
            confirmed: false,
            confirmed_by: None,
            claimed_classification: "enrolled-agent-yolo".to_owned(),
        };
        let record = decided(
            &permitted(Verdict::Allow),
            &caller(),
            &identity(Some(77)),
            &request(),
            &generation(),
            Some(&entry),
        );
        assert_eq!(record.decision, AuditDecision::Allowed);
        assert_eq!(record.action.as_deref(), Some("aido.svc.restart"));
        assert_eq!(record.rule_source.as_deref(), Some("20-services.toml:3"));
        assert_eq!(record.denial, None);
        assert_eq!(record.classification, "unattested");
        assert_eq!(
            record.argv,
            ["/usr/bin/systemctl", "restart", "nginx.service"]
        );
        for expected in [
            "broker=aidod".to_owned(),
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
            "deadline=1900".to_owned(),
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
            "/run/aido cannot be inspected: No such file or directory",
        );
        let record = refused(&refusal, Some(&identity(None)), Some(&request()));
        assert_eq!(record.decision, AuditDecision::Denied);
        assert_eq!(record.denial.as_deref(), Some("spool_unusable"));
        assert_eq!(
            record.argv,
            ["/usr/bin/systemctl", "restart", "nginx.service"]
        );
        assert!(record.evidence.contains(&"fault=broker".to_owned()));
        assert!(record.evidence.contains(
            &"detail=/run/aido cannot be inspected: No such file or directory".to_owned()
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
        let record = refused(&refusal, None, None);
        assert!(record.argv.is_empty());
        assert_eq!(record.classification, "unattested");
        assert_eq!(
            record.evidence,
            ["broker=aidod", "fault=client", "detail=not JSON"]
        );
    }

    #[test]
    fn a_record_is_one_json_line() {
        let refusal = Refusal::client(RefusalCode::RequestMalformed, "line\nbreak");
        let mut log = Vec::new();
        emit(&refused(&refusal, None, None), &mut log).unwrap();
        let text = String::from_utf8(log).unwrap();
        assert_eq!(text.matches('\n').count(), 1, "{text}");
        assert!(text.ends_with('\n'));
        let parsed: aido_audit::record::Record = serde_json::from_str(text.trim_end()).unwrap();
        assert!(parsed.is_sealed());
    }
}
