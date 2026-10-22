//! Fuzz the front-end's response parser.
//!
//! The front-end reads these bytes from a socket, and what it renders to the
//! human comes from them. A panic is a crash in the tool the operator uses to
//! see a denial; a partial accept is a verdict read out of a message the broker
//! did not send. Beyond "never panics" the target checks the same properties
//! as `wire_request`: a parsed response survives the crate's own encoder,
//! trailing bytes are refused except documented JSON whitespace, and the size
//! limit is exact. "Bounded" is asserted by behaviour, as there.
//!
//! The round trip asserts equal *values*, not equal bytes: the decision inside
//! a response carries `serde(default)` fields, so input bytes that omit one
//! re-encode to bytes that spell it out. A byte fixed point holds only from the
//! first encode on.

#![no_main]

use aido_wire::{BrokerResponse, FALLBACK_RESPONSE, MAX_RESPONSE_BYTES, ResponseError};
use libfuzzer_sys::fuzz_target;

/// Bytes that must never turn a valid message into a different valid one.
const TRAILERS: [u8; 9] = [b'x', b'}', b'{', b']', b'0', b'"', b',', 0, 0xff];

fuzz_target!(|data: &[u8]| {
    // The fallback is what a front-end is handed when rendering fails: it must
    // always parse, and render to itself.
    let fallback = BrokerResponse::parse(FALLBACK_RESPONSE.as_bytes());
    assert_eq!(
        fallback.map(|r| r.to_json()),
        Ok(FALLBACK_RESPONSE.to_owned()),
        "the fallback response does not round trip"
    );

    let parsed = BrokerResponse::parse(data);

    if data.len() > MAX_RESPONSE_BYTES {
        assert_eq!(
            parsed,
            Err(ResponseError::TooLarge {
                limit: MAX_RESPONSE_BYTES
            }),
            "an oversized response was not refused for its size"
        );
        return;
    }
    let Ok(response) = parsed else { return };

    let encoded = response.to_json();
    let again = BrokerResponse::parse(encoded.as_bytes());
    assert_eq!(
        again.as_ref(),
        Ok(&response),
        "round trip changed the value"
    );
    assert_eq!(
        again.map(|r| r.to_json()),
        Ok(encoded),
        "re-encoding is not a fixed point"
    );

    // No partial accept.
    let mut probe = Vec::with_capacity(MAX_RESPONSE_BYTES + 1);
    for trailer in TRAILERS {
        probe.clear();
        probe.extend_from_slice(data);
        probe.push(trailer);
        if probe.len() <= MAX_RESPONSE_BYTES {
            assert!(
                BrokerResponse::parse(&probe).is_err(),
                "trailing byte {trailer:#04x} was accepted after a valid message"
            );
        }
    }
    probe.clear();
    probe.extend_from_slice(data);
    probe.extend_from_slice(b" \n\t\r");
    if probe.len() <= MAX_RESPONSE_BYTES {
        assert_eq!(
            BrokerResponse::parse(&probe).as_ref(),
            Ok(&response),
            "trailing whitespace changed the message"
        );
    }

    // Bounded: exact at the limit, refused one byte over.
    probe.clear();
    probe.extend_from_slice(data);
    probe.resize(MAX_RESPONSE_BYTES, b' ');
    assert_eq!(
        BrokerResponse::parse(&probe).as_ref(),
        Ok(&response),
        "a response of exactly the limit was refused"
    );
    probe.push(b' ');
    assert_eq!(
        BrokerResponse::parse(&probe),
        Err(ResponseError::TooLarge {
            limit: MAX_RESPONSE_BYTES
        }),
        "a response one byte over the limit was not refused for its size"
    );
});
