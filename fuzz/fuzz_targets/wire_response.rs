//! Fuzz the broker response parser.
//! Asserts: no panic on any bytes; a parsed response has the current schema, fits the size limit, and re-parses equal after rendering.

#![no_main]

use xudo_wire::{BrokerResponse, MAX_RESPONSE_BYTES, WIRE_SCHEMA_VERSION};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must not panic on any input, valid or not.
    let Ok(response) = BrokerResponse::parse(data) else {
        return;
    };

    assert_eq!(response.schema_version, WIRE_SCHEMA_VERSION);
    assert!(data.len() <= MAX_RESPONSE_BYTES);

    let again = BrokerResponse::parse(response.to_json().as_bytes())
        .expect("a parsed response must parse again after rendering");
    assert_eq!(again, response, "round trip changed the response");
});
