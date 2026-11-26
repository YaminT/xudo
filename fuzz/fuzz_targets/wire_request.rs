//! Fuzz the broker request parser.
//! Asserts: no panic on any bytes; a parsed request has the current schema, fits the size limit, and re-parses equal after rendering.
//! And nothing a caller sends can name a gate, a `via`, or a grant: those are the broker's to decide,
//! so no key with such a name survives parsing, and the claimed classification is only ever a string.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_wire::{BrokerRequest, Question, MAX_REQUEST_BYTES, WIRE_SCHEMA_VERSION};

/// Keys that decide which gate runs. None may appear anywhere in a request.
const BROKER_ONLY: [&str; 5] = ["via", "gate", "harness_grant", "attested_class", "attested_harness"];

fn no_broker_only_key(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => map
            .iter()
            .all(|(key, inner)| !BROKER_ONLY.contains(&key.as_str()) && no_broker_only_key(inner)),
        serde_json::Value::Array(items) => items.iter().all(no_broker_only_key),
        _ => true,
    }
}

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input, valid or not.
    let Ok(request) = BrokerRequest::parse(data) else {
        return;
    };

    assert_eq!(request.schema_version, WIRE_SCHEMA_VERSION);
    match &request.question {
        Question::Run { .. }
        | Question::Status { .. }
        | Question::Watch
        | Question::Answer { .. }
        | Question::Freeze { .. }
        | Question::Thaw
        | Question::Pending => {}
        Question::QueueList
        | Question::QueueClaim { .. }
        | Question::QueueComplete { .. }
        | Question::QueueRelease { .. }
        | Question::QueueListPage { .. }
        | Question::RemovePath { .. } => {}
    }
    assert!(data.len() <= MAX_REQUEST_BYTES);

    // What was accepted carries no broker-only key, in what was sent or in
    // what the parser kept.
    let sent: serde_json::Value =
        serde_json::from_slice(data).expect("a parsed request is JSON");
    assert!(no_broker_only_key(&sent), "a request named a gate or a grant");
    let rendered = request.to_json();
    let kept: serde_json::Value =
        serde_json::from_str(&rendered).expect("a rendered request is JSON");
    assert!(no_broker_only_key(&kept));

    let again = BrokerRequest::parse(rendered.as_bytes())
        .expect("a parsed request must parse again after rendering");
    assert_eq!(again, request, "round trip changed the request");
});
