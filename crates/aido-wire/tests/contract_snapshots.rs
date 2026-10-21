//! Pins the refusal-code wire contract: every code's number, name, rendered
//! response, and the remediation sentence a human is shown.
//!
//! A front-end deployed months ago branches on the name and a person acts on
//! the sentence, so a diff in either is a contract change and must be reviewed
//! as one. `serde_json` and `as_str` agree by construction, so a test that
//! compares only the two to each other still passes when a variant is renamed;
//! the snapshot, and the literal list below, are what fail.
//!
//! Accept a deliberate change with `cargo insta review` or
//! `INSTA_UPDATE=always cargo test`, and commit the `.snap` diff.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;

use aido_wire::{BrokerResponse, RefusalCode};

/// Compile-time exhaustiveness for [`RefusalCode::ALL`] and the snapshot: no
/// wildcard arm, so a new variant is a build failure here, where the snapshot
/// and the literal list need a row for it.
fn lists_every_refusal_code(code: RefusalCode) -> &'static str {
    match code {
        RefusalCode::RequestTooLarge => "request_too_large",
        RefusalCode::RequestTimedOut => "request_timed_out",
        RefusalCode::RequestUnreadable => "request_unreadable",
        RefusalCode::RequestNotUtf8 => "request_not_utf8",
        RefusalCode::RequestMalformed => "request_malformed",
        RefusalCode::RequestWrongSchema => "request_wrong_schema",
        RefusalCode::ProgramNotAbsolute => "program_not_absolute",
        RefusalCode::InteriorNul => "interior_nul",
        RefusalCode::PeerUnidentified => "peer_unidentified",
        RefusalCode::SpoolUnusable => "spool_unusable",
        RefusalCode::SpoolFull => "spool_full",
        RefusalCode::PolicyUnloadable => "policy_unloadable",
        RefusalCode::NonceCollision => "nonce_collision",
        RefusalCode::BrokerUnusable => "broker_unusable",
    }
}

#[test]
fn renaming_a_refusal_code_breaks_the_wire_contract_and_this_test() {
    // The names, written out. Not derived from the type under test.
    let pinned = [
        "request_too_large",
        "request_timed_out",
        "request_unreadable",
        "request_not_utf8",
        "request_malformed",
        "request_wrong_schema",
        "program_not_absolute",
        "interior_nul",
        "peer_unidentified",
        "spool_unusable",
        "spool_full",
        "policy_unloadable",
        "nonce_collision",
        "broker_unusable",
    ];
    assert_eq!(RefusalCode::ALL.len(), pinned.len());
    for (code, name) in RefusalCode::ALL.iter().zip(pinned) {
        assert_eq!(code.as_str(), name);
        assert_eq!(lists_every_refusal_code(*code), name);
        // The name a deployed front-end reads off the wire.
        assert_eq!(serde_json::to_string(code).unwrap(), format!("\"{name}\""));
        assert_eq!(
            serde_json::from_str::<RefusalCode>(&format!("\"{name}\"")).unwrap(),
            *code
        );
    }
}

#[test]
fn the_refusal_code_wire_contract_is_pinned() {
    let mut table = String::new();
    for code in RefusalCode::ALL {
        let _ = writeln!(table, "{:>2}  {}", code.as_u32(), code.as_str());
        let _ = writeln!(table, "    {}", code.remediation());
    }
    insta::assert_snapshot!("refusal_code_wire_contract", table);
}

#[test]
fn every_refusal_is_sent_as_this_exact_response() {
    let mut table = String::new();
    for code in RefusalCode::ALL {
        let _ = writeln!(table, "{}", BrokerResponse::refused(code).to_json());
    }
    insta::assert_snapshot!("refusal_responses", table);
}
