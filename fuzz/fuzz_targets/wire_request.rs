//! Fuzz the broker request parser.
//! Asserts: no panic on any bytes; a parsed request has the current schema, fits the size limit, and re-parses equal after rendering.

#![no_main]

use xudo_wire::{BrokerRequest, MAX_REQUEST_BYTES, Question, WIRE_SCHEMA_VERSION};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input, valid or not.
    let Ok(request) = BrokerRequest::parse(data) else {
        return;
    };

    assert_eq!(request.schema_version, WIRE_SCHEMA_VERSION);
    match &request.question {
        Question::Run { .. } | Question::Status { .. } | Question::Watch
        | Question::Answer { .. } | Question::Freeze { .. } | Question::Thaw
        | Question::Pending => {}
    }
    assert!(data.len() <= MAX_REQUEST_BYTES);

    let again = BrokerRequest::parse(request.to_json().as_bytes())
        .expect("a parsed request must parse again after rendering");
    assert_eq!(again, request, "round trip changed the request");
});
