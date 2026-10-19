//! Pins the bytes journald receives for an audit record.
//!
//! The journal is where an operator queries the trail and where an alert rule
//! matches on it, so a change to a field name, a priority, or the framing is a
//! change to what every such rule sees. A snapshot makes that diff impossible
//! to land silently: accept a deliberate change with `cargo insta review` or
//! `INSTA_UPDATE=always cargo test`, and commit the `.snap` diff.
//!
//! The decoder below is written from systemd's protocol description rather than
//! from the encoder, so the round trip checks the framing independently of the
//! snapshot.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fmt::Write as _;

use aido_audit::journal::{datagram, fields, query};
use aido_audit::{Decision, Outcome, Record};

/// One decoded field: its name, its value, and the exact bytes that framed it.
struct Field<'a> {
    name: String,
    value: Vec<u8>,
    raw: &'a [u8],
}

/// Splits a native-protocol payload back into fields.
fn decode(payload: &[u8]) -> Vec<Field<'_>> {
    let mut fields = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        let rest = &payload[at..];
        let end = rest.iter().position(|b| *b == b'\n').unwrap();
        let head = &rest[..end];
        let (name, value, used) = if let Some(eq) = head.iter().position(|b| *b == b'=') {
            (&head[..eq], head[eq + 1..].to_vec(), end + 1)
        } else {
            let body = &rest[end + 1..];
            let len = usize::try_from(u64::from_le_bytes(body[..8].try_into().unwrap())).unwrap();
            assert_eq!(body[8 + len], b'\n', "a binary field ends in a newline");
            (head, body[8..8 + len].to_vec(), end + 1 + 8 + len + 1)
        };
        fields.push(Field {
            name: String::from_utf8(name.to_vec()).unwrap(),
            value,
            raw: &rest[..used],
        });
        at += used;
    }
    fields
}

/// The payload, escaped exactly, one field per line.
///
/// Lines break between fields only, so a newline inside a length-framed value
/// stays visibly inside it rather than looking like a field of its own.
fn render(payload: &[u8]) -> String {
    let mut out = String::new();
    for field in decode(payload) {
        let _ = writeln!(out, "{}", field.raw.escape_ascii());
    }
    out
}

fn authorization() -> Record {
    let first = Record::first(
        Decision::Denied,
        vec!["/bin/sh".to_owned(), "-c".to_owned(), "id".to_owned()],
        "unattested",
    )
    .with_denial("deny_listed")
    .with_deny_list_version(1);
    Record::after(
        Some(&first),
        Decision::Allowed,
        vec![
            "/usr/bin/systemctl".to_owned(),
            "restart".to_owned(),
            "nginx.service".to_owned(),
        ],
        "human",
    )
    .with_rule("aido.svc.restart", "20-services.toml:15")
    .with_evidence(vec!["gate_caller_pid=4242".to_owned()])
    .with_deny_list_version(1)
}

fn hostile_refusal() -> Record {
    Record::first(Decision::Denied, Vec::new(), "unattested")
        .with_denial("gate_no_pending_request")
        .with_evidence(vec![
            "severity=high".to_owned(),
            "gate_caller_pid=77".to_owned(),
        ])
}

#[test]
fn an_authorization_as_journald_receives_it() {
    insta::assert_snapshot!(
        "authorization",
        render(&datagram(&authorization(), "aidod").unwrap())
    );
}

#[test]
fn a_hostile_direct_invocation_as_journald_receives_it() {
    insta::assert_snapshot!(
        "hostile_refusal",
        render(&datagram(&hostile_refusal(), "aido-gate").unwrap())
    );
}

#[test]
fn the_query_every_alert_rule_starts_from() {
    // An unprivileged sender can forge every field above; only `_UID=0`
    // keeps its entries out. A diff here changes what every alert rule and
    // every comparison with the file counts.
    insta::assert_snapshot!(
        "trusted_query",
        format!(
            "{}\n{}\n",
            query(&[]),
            query(&["AIDO_DECISION=denied", "PRIORITY=1"])
        )
    );
}

#[test]
fn a_value_holding_a_newline_is_framed_by_length() {
    // A rule file name is root's, but the encoder does not get to assume it
    // is one line: the binary framing is what keeps a newline from being read
    // as the start of a forged field.
    let record = Record::first(Decision::Allowed, vec!["/usr/bin/true".to_owned()], "human")
        .with_rule("aido.x", "evil.toml:1\nPRIORITY=7")
        .with_outcome(Outcome::Exited { code: 0 });
    let payload = datagram(&record, "aidod").unwrap();
    insta::assert_snapshot!("newline_in_value", render(&payload));
    let decoded = decode(&payload);
    let priorities: Vec<&[u8]> = decoded
        .iter()
        .filter(|field| field.name == "PRIORITY")
        .map(|field| field.value.as_slice())
        .collect();
    assert_eq!(
        priorities,
        [b"5".as_slice()],
        "a value forged a second field"
    );
}

#[test]
fn every_field_decodes_back_to_what_was_encoded() {
    for record in [authorization(), hostile_refusal()] {
        let expected: Vec<(String, Vec<u8>)> = fields(&record, "aidod")
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.into_bytes()))
            .collect();
        let payload = datagram(&record, "aidod").unwrap();
        let decoded: Vec<(String, Vec<u8>)> = decode(&payload)
            .into_iter()
            .map(|field| (field.name, field.value))
            .collect();
        assert_eq!(decoded, expected);
    }
}
