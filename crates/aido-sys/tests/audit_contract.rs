//! The audit contract as the broker and the gate will use it.
//!
//! Neither binary is wired to a sink yet (M2b steps 2 and 4). These tests are
//! written the way both are expected to call the API, with the record builders
//! `aido-gate` already has, so a change that breaks the shape they depend on
//! fails here first.

#![cfg(feature = "fake")]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use aido_audit::journal::{HIGH_SEVERITY, fields};
use aido_audit::{Decision, verify};
use aido_gate::request::CallerPin;
use aido_gate::{
    Approved, GateCaller, Refusal, RequestError, Severity, authorization_record, refusal_record,
};
use aido_sys::{AuditError, AuditSink, CallerFacts, Classification, FakeAuditSink, authorize};

fn caller() -> GateCaller {
    GateCaller {
        pin: CallerPin::new(77, 555),
        facts: CallerFacts::new(Classification::Human, 1000),
    }
}

fn approved() -> Approved {
    Approved {
        program: "/usr/bin/systemctl".to_owned(),
        argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
        environment: Vec::new(),
        action: "aido.svc.restart".to_owned(),
        rule_source: "20-services.toml:15".to_owned(),
        requested_action: "aido.svc.restart".to_owned(),
        requested_rule_source: "20-services.toml:15".to_owned(),
        nonce: "ab".repeat(32),
    }
}

/// What the gate's execute step will look like: it takes the authorization,
/// so it cannot be called with an approval that was never recorded.
fn execute(authorized: aido_sys::Authorized<Approved>) -> (String, u64) {
    let (approved, receipt) = authorized.into_parts();
    (approved.program, receipt.seq().get())
}

#[test]
fn a_gate_that_cannot_record_its_authorization_has_nothing_to_execute() {
    // A full disk, a missing journal: the approval goes into `authorize` and
    // does not come back, so there is no value left to hand to `execute`.
    let caller = caller();
    let mut trail = FakeAuditSink::failing("disk full");
    let outcome = authorize(&mut trail, approved(), &|previous, approval| {
        authorization_record(previous, approval, &caller, None)
    });
    assert_eq!(
        outcome.unwrap_err(),
        AuditError::Unavailable {
            reason: "disk full".to_owned()
        }
    );
    // The refusal that follows is written best-effort; it stands either way.
    let refusal = Refusal::NoPendingRequest {
        pid: caller.pin.pid,
    };
    assert!(
        trail
            .append(&|previous| refusal_record(previous, &refusal, &caller, None))
            .is_err()
    );
}

#[test]
fn the_broker_and_the_gate_write_one_chain_and_the_receipt_names_the_record() {
    let caller = caller();
    let mut trail = FakeAuditSink::new();

    // The broker refused one request, then the gate authorized another.
    let refusal = Refusal::NoPendingRequest { pid: 12 };
    let _ = trail
        .append(&|previous| refusal_record(previous, &refusal, &caller, None))
        .unwrap();
    let authorized = authorize(&mut trail, approved(), &|previous, approval| {
        authorization_record(previous, approval, &caller, None)
    })
    .unwrap();
    assert_eq!(authorized.receipt().decision(), Decision::Allowed);

    let (program, seq) = execute(authorized);
    assert_eq!((program.as_str(), seq), ("/usr/bin/systemctl", 2));
    verify(trail.records()).unwrap();
    assert_eq!(
        trail.records()[1].action.as_deref(),
        Some("aido.svc.restart")
    );
}

#[test]
fn a_gate_record_built_for_another_approval_authorizes_nothing() {
    // A builder handed one approval while `authorize` holds another — a stale
    // copy, two requests mixed up — would leave a receipt for a command other
    // than the one about to run. The gate's own builder, given the wrong
    // approval, is refused before anything is written.
    let caller = caller();
    let mut trail = FakeAuditSink::new();
    let mut other = approved();
    other.argv = vec!["stop".to_owned(), "nginx.service".to_owned()];
    let err = authorize(&mut trail, approved(), &|previous, _| {
        authorization_record(previous, &other, &caller, None)
    })
    .unwrap_err();
    assert_eq!(err, AuditError::Misrecorded { field: "argv" });
    let mut renamed = approved();
    renamed.action = "aido.svc.restart.quiet".to_owned();
    let err = authorize(&mut trail, approved(), &|previous, _| {
        authorization_record(previous, &renamed, &caller, None)
    })
    .unwrap_err();
    assert_eq!(err, AuditError::Misrecorded { field: "action" });
    assert!(trail.records().is_empty());
}

#[test]
fn a_hostile_direct_invocation_reaches_the_journal_as_an_alert() {
    // The gate marks a refusal that only an attempt produces with its
    // high-severity label; the journal entry must carry it as an alert, or
    // nobody's alert rule ever fires on it.
    let refusal = Refusal::NoPendingRequest { pid: 77 };
    assert_eq!(refusal.severity(), Severity::High);
    let record = refusal_record(None, &refusal, &caller(), None);
    assert!(record.evidence.contains(&HIGH_SEVERITY.to_owned()));
    assert!(fields(&record, "aido-gate").contains(&("PRIORITY", "1".to_owned())));

    // A request that expired is a slow human, not an attack: a warning.
    let slow = Refusal::Request(RequestError::Expired {
        deadline: 1,
        now: 2,
    });
    assert_eq!(slow.severity(), Severity::Normal);
    let record = refusal_record(None, &slow, &caller(), None);
    assert!(fields(&record, "aido-gate").contains(&("PRIORITY", "4".to_owned())));
}
