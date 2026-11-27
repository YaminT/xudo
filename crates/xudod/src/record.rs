//! The audit record of every answer the broker gives.
//!
//! Each builder takes the chain's last record, so the sink can chain it. A
//! record carries what the response does not: how the peer was identified, its
//! pin, the generation decided under, the nonce minted, a refusal's detail, and
//! the caller's own claim beside the classification the broker made.

use xudo_audit::record::{Decision as AuditDecision, Outcome, Record};
use xudo_gate::policy::LoadedPolicy;
use xudo_gate::request::PendingRequest;
use xudo_policy::{CallerFacts, Decision, Generation, Verdict, deny_list_version};
use xudo_wire::BrokerRequest;

use crate::identify::Identified;
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
    identity: &Identified,
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
    if let Some(label) = caller.classification.enrolled_agent_id() {
        evidence.push(format!("agent_id={label}"));
    }
    if let Some(entry) = minted {
        evidence.push(format!("nonce={}", entry.nonce));
        evidence.push(format!("deadline_ms={}", entry.deadline.0));
        evidence.push(format!("via={}", entry.via.label()));
        if let Some(id) = &entry.queue_id {
            evidence.push(format!("queue_id={id}"));
        }
    }
    if let Some(id) = deciding_deny_rule_id(decision) {
        evidence.push(format!("deny_rule_id={id}"));
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

/// [`decided`] under `policy`: its generation, and any registry or passwd
/// fault in force, which every decision record carries as evidence.
pub fn decided_under(
    previous: Option<&Record>,
    decision: &Decision,
    caller: &CallerFacts,
    identity: &Identified,
    request: &BrokerRequest,
    policy: &LoadedPolicy,
    minted: Option<&PendingRequest>,
) -> Record {
    let record = decided(
        previous,
        decision,
        caller,
        identity,
        request,
        &policy.rules.generation,
        minted,
    );
    let mut evidence = record.evidence.clone();
    evidence.extend(policy.fault_evidence());
    record.with_evidence(evidence)
}

/// Adds the queue id to a decision record and reseals it.
///
/// The admission audit is written before the entry is published, so the id
/// has to be attached here rather than read back from the store.
#[must_use]
pub fn with_queue_id(record: Record, queue_id: &str) -> Record {
    let mut evidence = record.evidence.clone();
    evidence.push(format!("queue_id={queue_id}"));
    record.with_evidence(evidence)
}

fn deciding_deny_rule_id(decision: &Decision) -> Option<&str> {
    decision.trace.iter().find_map(|step| match step {
        xudo_policy::TraceStep::DenyRulesEvaluated { matched } => {
            matched.first().map(|rule| rule.id.as_str())
        }
        _ => None,
    })
}

/// The record of a refusal.
pub fn refused(
    previous: Option<&Record>,
    refusal: &Refusal,
    identity: Option<&Identified>,
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
        let claimed = request
            .run_fields()
            .map(|(_, _, claimed)| claimed)
            .or_else(|| request.remove_fields().map(|(_, _, claimed)| claimed));
        if let Some(claimed) = claimed {
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
        xudo_wire::Question::QueueList => "queue_list",
        xudo_wire::Question::QueueClaim { .. } => "queue_claim",
        xudo_wire::Question::QueueComplete { .. } => "queue_complete",
        xudo_wire::Question::QueueRelease { .. } => "queue_release",
        xudo_wire::Question::QueueListPage { .. } => "queue_list_page",
        xudo_wire::Question::RemovePath { .. } => "remove_path",
    }
}

/// The evidence for how the peer was identified, and what it showed.
fn identity_evidence(peer: &Identified) -> Vec<String> {
    let identity = &peer.identity;
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
        // A hint, never a fact: escaped and quoted like the others, so any
        // byte the peer named itself with reads as itself and cannot pose as
        // another field or as the bare word `unavailable`.
        format!("hint_comm=\"{}\"", identity.comm.escape_ascii()),
    ];
    evidence.extend(peer.hints.evidence());
    if let Some(id) = identity.cgroup_id {
        evidence.push(format!("cgroup_id={id}"));
    }
    evidence
}

/// The request's command as one argv, program first, exactly as asked.
fn command_of(request: &BrokerRequest) -> Vec<String> {
    if let Some((target, _, _)) = request.remove_fields() {
        return vec![
            xudo_wire::OPERATION_PROGRAM.to_owned(),
            target.escape_ascii().to_string(),
        ];
    }
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

    fn identity(cgroup_id: Option<u64>) -> Identified {
        crate::identify::PeerIdentity {
            rung: Attestation::PeerPidfdInfo,
            pid: 4242,
            uid: 1000,
            gid: 100,
            starttime: 998_877,
            sid: 1,
            tty: 0,
            comm: b"xudo".to_vec(),
            diverged: false,
            pinned: true,
            cgroup_id,
            cgroup_attestation: crate::identify::CgroupAttestation::NotChecked,
            cgroup_rung: None,
            euid_source: EuidSource::PidfdInfo,
        }
        .into()
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
                    cwd: Vec::new(),
                    claimed_classification: "x".to_owned(),
                },
                "run",
            ),
            (xudo_wire::Question::Status { id: "a".repeat(64) }, "status"),
            (xudo_wire::Question::Watch, "watch"),
            (xudo_wire::Question::Pending, "pending"),
            (xudo_wire::Question::QueueList, "queue_list"),
            (
                xudo_wire::Question::QueueClaim { id: "b".repeat(64) },
                "queue_claim",
            ),
            (
                xudo_wire::Question::QueueComplete {
                    id: "c".repeat(64),
                    audit_seq: 0,
                    claim_token: String::new(),
                },
                "queue_complete",
            ),
            (
                xudo_wire::Question::QueueRelease {
                    id: "d".repeat(64),
                    claim_token: String::new(),
                },
                "queue_release",
            ),
            (
                xudo_wire::Question::QueueListPage {
                    after: String::new(),
                },
                "queue_list_page",
            ),
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
            (
                xudo_wire::Question::RemovePath {
                    target: b"/srv/app/build/cache".to_vec(),
                    dry_run: false,
                    claimed_classification: "unattested".to_owned(),
                },
                "remove_path",
            ),
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
    fn a_decision_record_carries_the_registry_and_passwd_faults() {
        let mut policy = LoadedPolicy {
            rules: xudo_policy::load_policy_with_registry(Vec::new(), Err("bad\nfile".to_owned()))
                .unwrap(),
            settings: xudo_policy::engine::Settings::default(),
            queue_ttl_secs: 60,
            passwd: String::new(),
            passwd_fault: Some("2 unusable".to_owned()),
        };
        let build = |policy: &LoadedPolicy| {
            decided_under(
                None,
                &permitted(Verdict::Deny),
                &caller(),
                &identity(None),
                &request(),
                policy,
                None,
            )
        };
        let record = build(&policy);
        assert!(
            record
                .evidence
                .contains(&"registry_fault=bad file".to_owned())
        );
        assert!(
            record
                .evidence
                .contains(&"passwd_fault=2 unusable".to_owned())
        );
        policy.rules.registry_fault = None;
        policy.passwd_fault = None;
        assert!(
            !build(&policy)
                .evidence
                .iter()
                .any(|line| line.contains("_fault="))
        );
    }

    #[test]
    fn an_enrolled_decision_records_the_registry_label_as_agent_id() {
        let enrolled = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "codex".to_owned(),
                session_id: "agent.scope".to_owned(),
                declared_yolo: false,
            },
            1000,
        );
        let enrolled_record = decided(
            None,
            &permitted(Verdict::Deny),
            &enrolled,
            &identity(Some(44)),
            &request(),
            &generation(),
            None,
        );
        assert!(
            enrolled_record
                .evidence
                .contains(&"agent_id=codex".to_owned())
        );
        let unattested = decided(
            None,
            &permitted(Verdict::Deny),
            &caller(),
            &identity(None),
            &request(),
            &generation(),
            None,
        );
        assert!(
            !unattested
                .evidence
                .iter()
                .any(|item| item.starts_with("agent_id="))
        );
    }

    #[test]
    fn with_queue_id_seals_the_entry_id_into_the_admission_record() {
        let record = decided(
            None,
            &permitted(Verdict::Deny),
            &caller(),
            &identity(None),
            &request(),
            &generation(),
            None,
        );
        let linked = with_queue_id(record, &"ab".repeat(32));
        assert!(
            linked
                .evidence
                .contains(&format!("queue_id={}", "ab".repeat(32)))
        );
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
    fn the_peers_comm_is_recorded_as_a_hint() {
        let decision = Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new());
        let record = decided(
            None,
            &decision,
            &caller(),
            &identity(None),
            &request(),
            &generation(),
            None,
        );
        assert!(record.evidence.contains(&"hint_comm=\"xudo\"".to_owned()));
    }

    #[test]
    fn a_comm_posing_as_another_field_is_recorded_escaped_under_its_prefix() {
        let mut peer = identity(None);
        peer.identity.comm = b"via=harness\x1b[2J\n\xff".to_vec();
        let evidence = identity_evidence(&peer);
        assert!(
            evidence.contains(&"hint_comm=\"via=harness\\x1b[2J\\n\\xff\"".to_owned()),
            "{evidence:?}"
        );
        assert!(!evidence.iter().any(|line| line.starts_with("via=")));
    }

    #[test]
    fn a_process_named_unavailable_is_not_read_as_the_sentinel() {
        let mut peer = identity(None);
        peer.identity.comm = b"unavailable".to_vec();
        let evidence = identity_evidence(&peer);
        assert!(evidence.contains(&"hint_comm=\"unavailable\"".to_owned()));
        assert!(!evidence.contains(&"hint_comm=unavailable".to_owned()));
    }

    #[test]
    fn the_peers_exe_argv0_and_claudecode_are_recorded_as_hints_on_decisions_and_refusals() {
        let mut peer = identity(None);
        peer.hints = xudo_sys::CallerHints::from_reads(
            Some(b"/usr/bin/claude"),
            Some(b"claude\0-p\0--password=hunter2\0"),
            Some(b"PATH=/bin\0CLAUDECODE=1\0"),
        );
        let decision = Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new());
        let decided = decided(
            None,
            &decision,
            &caller(),
            &peer,
            &request(),
            &generation(),
            None,
        );
        let refusal = Refusal::client(RefusalCode::RequestUnknown, "x");
        let refused = refused(None, &refusal, Some(&peer), None);
        for record in [decided, refused] {
            for line in peer.hints.evidence() {
                assert!(record.evidence.contains(&line), "{line}");
            }
            assert!(
                record
                    .evidence
                    .contains(&"hint_claudecode=set:\"1\"".to_owned()),
                "{:?}",
                record.evidence
            );
            let all = record.evidence.join(" ");
            assert!(!all.contains("PATH="), "{all}");
            assert!(!all.contains("hunter2"), "{all}");
        }
    }

    /// The largest hints a peer can make: every byte the worst kind (escaped
    /// to four, then JSON-escaped to five), far past every cap.
    fn hostile_peer() -> Identified {
        let junk = vec![0xff_u8; 1 << 20];
        let mut environ = b"CLAUDECODE=".to_vec();
        environ.extend(&junk);
        let mut peer = identity(Some(77));
        peer.identity.comm = vec![0xff; 15];
        peer.hints = xudo_sys::CallerHints::from_reads(Some(&junk), Some(&junk), Some(&environ));
        peer
    }

    #[test]
    fn a_hostile_peers_hints_cannot_swell_any_record_toward_the_limit() {
        // A decision, a mint and a refusal, each with the largest hints: they
        // add under 8 KiB, an eighth of what a record may hold.
        let entry = minted_entry();
        let decision = Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new());
        let refusal = Refusal::client(RefusalCode::RequestUnknown, "x");
        let records = |peer: &Identified| {
            [
                decided(
                    None,
                    &decision,
                    &caller(),
                    peer,
                    &request(),
                    &generation(),
                    None,
                ),
                decided(
                    None,
                    &permitted(Verdict::Allow),
                    &caller(),
                    peer,
                    &request(),
                    &generation(),
                    Some(&entry),
                ),
                refused(None, &refusal, Some(peer), Some(&request())),
            ]
            .map(|record| record.to_jsonl().len())
        };
        let plain = records(&identity(Some(77)));
        let hostile = records(&hostile_peer());
        for (plain, hostile) in plain.into_iter().zip(hostile) {
            assert!(hostile > plain + 4096, "{plain} -> {hostile}");
            assert!(hostile - plain < 8 * 1024, "{plain} -> {hostile}");
            assert!(hostile < xudo_audit::MAX_RECORD_BYTES);
        }
    }

    fn minted_entry() -> PendingRequest {
        PendingRequest {
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
            attested_class: xudo_gate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
            attested_harness: None,
            via: xudo_gate::request::Via::Auth,
            queue_id: None,
            operation: None,
        }
    }

    #[test]
    fn a_minted_decision_records_the_pin_the_rule_the_nonce_and_the_unheeded_claim() {
        let entry = minted_entry();
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
        let mut linked = entry.clone();
        linked.queue_id = Some("cd".repeat(32));
        let linked_record = decided(
            None,
            &permitted(Verdict::Allow),
            &caller(),
            &identity(Some(77)),
            &request(),
            &generation(),
            Some(&linked),
        );
        assert!(
            linked_record
                .evidence
                .contains(&format!("queue_id={}", "cd".repeat(32)))
        );
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
    fn a_deny_rule_denial_records_the_deciding_rule_id() {
        let mut denial = Decision::deny(DenialCode::DenyRule, vec!["x".to_owned()], Vec::new());
        denial
            .trace
            .push(xudo_policy::TraceStep::DenyRulesEvaluated {
                matched: vec![xudo_policy::DenyRuleMatch {
                    id: ActionId::from("xudo.protect.pkg-remove"),
                    source: Source::new("00-protect.toml", 6),
                    reason: "protected package".to_owned(),
                }],
            });
        let record = decided(
            None,
            &denial,
            &caller(),
            &identity(None),
            &request(),
            &generation(),
            None,
        );
        assert!(
            record
                .evidence
                .contains(&"deny_rule_id=xudo.protect.pkg-remove".to_owned())
        );
        assert!(record.is_sealed());
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
