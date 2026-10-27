//! The real broker binary, as uid 0, against the real audit trail.
//!
//! `broker.rs` runs this binary as an ordinary user, where the trail cannot be
//! opened and so nothing is ever minted. These tests are the other half: the
//! binary as root in a throwaway container (`just root-test`), with a real
//! `/var/lib/aido`, a real spool, a real ruleset, and a datagram socket where
//! journald would be. They prove what the unit's sandbox exists to allow and
//! what the trail exists to require:
//!
//! * a permitted request is recorded, chained, mirrored, and only then minted;
//! * a refusal and a denial are recorded on the same chain;
//! * a trail that cannot be written mints nothing, whichever way it fails, and
//!   a denial is answered all the same.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

#[path = "../../aido-tests/tests/support/root_trail.rs"]
mod root_trail;

use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use aido_audit::record::Decision;
use aido_wire::{Answer, BrokerRequest, BrokerResponse, RefusalCode};
use root_trail::{ACTION, AUDIT_FILE, FAULTS, Host, Mirrored, PROGRAM, root_or_skip};

/// The binary under test, by the absolute path Cargo built it at.
const AIDOD: &str = env!("CARGO_BIN_EXE_aidod");

/// `aido`'s "unusable": the broker or its host is broken.
const UNUSABLE: i32 = 19;

/// Runs the broker on one end of a socket pair with `request` sent on the
/// other, and returns what it answered and how it exited.
fn exchange(request: &BrokerRequest) -> (BrokerResponse, Option<i32>) {
    let (served, mut client) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let child = Command::new(AIDOD)
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(served)))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    client.write_all(request.to_json().as_bytes()).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("\"prev_hash\""),
        "a record on standard error: {stderr}"
    );
    (BrokerResponse::parse(&answer).unwrap(), output.status.code())
}

fn permitted() -> BrokerRequest {
    BrokerRequest::new(PROGRAM, vec!["probe".to_owned()], "unattested")
}

fn shell() -> BrokerRequest {
    BrokerRequest::new(
        "/bin/sh",
        vec!["-c".to_owned(), "id".to_owned()],
        "unattested",
    )
}

fn refusal_of(response: &BrokerResponse) -> Option<RefusalCode> {
    match &response.answer {
        Answer::Refused { code, .. } => Some(*code),
        Answer::Decided { .. } => None,
    }
}

#[test]
fn a_permitted_request_is_recorded_chained_and_mirrored_and_then_minted() {
    if !root_or_skip("a_permitted_request_is_recorded_chained_and_mirrored_and_then_minted") {
        return;
    }
    let host = Host::fresh();

    let (response, status) = exchange(&permitted());
    assert_eq!(status, Some(0));
    let Answer::Decided { minted, .. } = &response.answer else {
        panic!("not decided: {response:?}");
    };
    let nonce = minted.as_ref().expect("a minted entry").nonce.clone();

    // The trail: one record, on disk, in the right hands, naming the nonce.
    let meta = std::fs::metadata(AUDIT_FILE).unwrap();
    assert_eq!((meta.uid(), meta.mode() & 0o777), (0, 0o600));
    let chain = host.chain();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].decision, Decision::Allowed);
    assert_eq!(chain[0].action.as_deref(), Some(ACTION));
    assert!(chain[0].evidence.contains(&format!("nonce={nonce}")));
    // The same record, in the journal, as the broker.
    assert_eq!(
        host.mirrored(),
        [Mirrored {
            identifier: "aidod".to_owned(),
            seq: 1,
            hash: chain[0].hash.clone(),
        }]
    );
    // And the entry the record authorized is in the spool, and only it.
    assert_eq!(host.spool(), [nonce]);

    // A second broker process chains onto the first one's record.
    let (denied, status) = exchange(&shell());
    assert_eq!(status, Some(0));
    assert_eq!(refusal_of(&denied), None);
    let chain = host.chain();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].decision, Decision::Denied);
    assert_eq!(chain[1].prev_hash, chain[0].hash);
    let mirrored = host.mirrored();
    assert_eq!((mirrored.len(), mirrored[0].seq), (1, 2));
    assert_eq!(mirrored[0].hash, chain[1].hash);
    assert_eq!(host.spool().len(), 1, "a denial mints nothing");
}

#[test]
fn a_refusal_is_recorded_on_the_same_chain() {
    if !root_or_skip("a_refusal_is_recorded_on_the_same_chain") {
        return;
    }
    let host = Host::fresh();
    let (_, status) = exchange(&permitted());
    assert_eq!(status, Some(0));

    // A client's malformed request: refused, answered, exit 0, and recorded.
    let (client, mut stream) = UnixStream::pair().unwrap();
    let child = Command::new(AIDOD)
        .env_clear()
        .stdin(Stdio::from(OwnedFd::from(client)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    stream.write_all(b"{\"skip_confirmation\":true}").unwrap();
    stream.shutdown(Shutdown::Write).unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).unwrap();
    assert_eq!(child.wait_with_output().unwrap().status.code(), Some(0));
    assert_eq!(
        refusal_of(&BrokerResponse::parse(&answer).unwrap()),
        Some(RefusalCode::RequestMalformed)
    );

    let chain = host.chain();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[1].denial.as_deref(), Some("request_malformed"));
    assert_eq!(chain[1].prev_hash, chain[0].hash);
}

#[test]
fn a_trail_that_cannot_be_written_mints_nothing_however_it_fails() {
    if !root_or_skip("a_trail_that_cannot_be_written_mints_nothing_however_it_fails") {
        return;
    }
    for fault in FAULTS {
        let host = Host::fresh();
        // One good record first, so "unchanged" means a chain is still there.
        let (_, status) = exchange(&permitted());
        assert_eq!(status, Some(0), "{fault:?}");
        let _ = host.mirrored();
        let entry = host.spool();

        host.break_trail(fault);
        // Read after the fault: a log that is now a directory has no bytes.
        let before = host.log();
        let (response, status) = exchange(&permitted());
        assert_eq!(
            refusal_of(&response),
            Some(RefusalCode::AuditUnavailable),
            "{fault:?}: {response:?}"
        );
        assert_eq!(status, Some(UNUSABLE), "{fault:?}");
        assert_eq!(host.spool(), entry, "{fault:?}: nothing new minted");
        assert!(host.mirrored().is_empty(), "{fault:?}: nothing mirrored");
        assert_eq!(host.log(), before, "{fault:?}: the log is unchanged");

        // A denial is answered, whatever state the trail is in.
        let (denied, status) = exchange(&shell());
        assert_eq!(refusal_of(&denied), None, "{fault:?}");
        assert_eq!(status, Some(0), "{fault:?}");
        assert_eq!(host.log(), before, "{fault:?}: still unchanged");
    }
}
