//! Pins what the broker writes to the audit trail and what an operator reads
//! in a refusal: every record shape, and the sentence of every mint refusal.
//!
//! A record is evidence. A change to its fields, their order, or their words
//! is a change to what an investigator can rely on, and must be reviewed as
//! one. Records here carry no time and no randomness, so the whole line,
//! hash included, is pinned.
//!
//! Accept a deliberate change with `cargo insta review` or
//! `INSTA_UPDATE=always cargo test`, and commit the `.snap` diff.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;

use aido_audit::record::Record;
use aido_gate::request::{MonotonicSecs, PendingRequest, REQUEST_SCHEMA_VERSION};
use aido_policy::{ActionId, CallerFacts, Classification, Decision, DenialCode, Source, Verdict};
use aido_sys::{Attestation, SpoolError};
use aido_wire::{BrokerRequest, RefusalCode};
use aidod::identify::{EuidSource, PeerIdentity};
use aidod::mint::MintError;
use aidod::record::{decided, refused};
use aidod::refusal::Refusal;

fn identity() -> PeerIdentity {
    PeerIdentity {
        rung: Attestation::PeerPidfdInfo,
        pid: 4242,
        uid: 1000,
        gid: 100,
        starttime: 998_877,
        pinned: true,
        cgroup_id: Some(77),
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

fn entry() -> PendingRequest {
    PendingRequest {
        schema_version: REQUEST_SCHEMA_VERSION,
        nonce: "ab".repeat(32),
        caller_pid: 4242,
        caller_starttime: 998_877,
        action: "aido.svc.restart".to_owned(),
        program: "/usr/bin/systemctl".to_owned(),
        argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
        generation: 7,
        deadline: MonotonicSecs(1_900),
        confirmed: false,
        confirmed_by: None,
        claimed_classification: "enrolled-agent-yolo".to_owned(),
    }
}

/// One record as pretty JSON, so a diff names the field that moved.
fn rendered(record: &Record) -> String {
    let value: serde_json::Value = serde_json::from_str(&record.to_jsonl()).unwrap();
    serde_json::to_string_pretty(&value).unwrap()
}

#[test]
fn the_records_of_a_decision_are_pinned() {
    let generation = aido_policy::load_rule_files(Vec::new()).unwrap().generation;
    let mut text = String::new();
    let minted = decided(
        &permitted(Verdict::Allow),
        &caller(),
        &identity(),
        &request(),
        &generation,
        Some(&entry()),
    );
    let awaiting = decided(
        &permitted(Verdict::AllowWithConfirmation),
        &caller(),
        &identity(),
        &request(),
        &generation,
        None,
    );
    let denied = decided(
        &Decision::deny(DenialCode::ArgvRejected, vec!["x".to_owned()], Vec::new()),
        &caller(),
        &identity(),
        &request(),
        &generation,
        None,
    );
    for (name, record) in [
        ("minted", minted),
        ("awaiting confirmation", awaiting),
        ("denied", denied),
    ] {
        let _ = writeln!(text, "## {name}\n{}\n", rendered(&record));
    }
    insta::assert_snapshot!("decision_records", text);
}

#[test]
fn the_record_of_every_refusal_code_is_pinned() {
    let mut text = String::new();
    for code in RefusalCode::ALL {
        let refusal = if code.as_u32() <= 8 {
            Refusal::client(code, "detail of the client's fault")
        } else {
            Refusal::broker(code, "detail of the broker's fault")
        };
        let _ = writeln!(
            text,
            "## {} with a request and a peer\n{}\n",
            code.as_str(),
            rendered(&refused(&refusal, Some(&identity()), Some(&request())))
        );
    }
    let nothing_known = Refusal::client(RefusalCode::RequestMalformed, "not JSON");
    let _ = writeln!(
        text,
        "## before anything was known\n{}",
        rendered(&refused(&nothing_known, None, None))
    );
    insta::assert_snapshot!("refusal_records", text);
}

#[test]
fn every_mint_refusal_is_pinned_with_its_code_and_whose_fault_it_is() {
    let mut text = String::new();
    for failure in [
        MintError::NoAction,
        MintError::Spool(SpoolError::Exists {
            name: "a-name".to_owned(),
        }),
        MintError::Full {
            entries: 64,
            bytes: 4096,
        },
        MintError::UidFull {
            uid: 1000,
            entries: 8,
        },
        MintError::Collision {
            nonce: "ab".repeat(32),
        },
    ] {
        let refusal = Refusal::from(&failure);
        let _ = writeln!(
            text,
            "{} ({:?})\n    {}",
            refusal.code.as_str(),
            refusal.fault,
            refusal.detail
        );
    }
    insta::assert_snapshot!("mint_refusals", text);
}
