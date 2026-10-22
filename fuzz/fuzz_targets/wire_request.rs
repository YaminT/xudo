//! Fuzz the broker's request parser.
//!
//! Root parses these bytes, and an unprivileged peer chose every one of them.
//! A panic is a broker denial of service; a partial accept means the broker
//! acts on a message the caller did not send; an unbounded read lets any group
//! member make root allocate. Beyond "never panics" the target checks that a
//! parsed request survives the crate's own encoder, that trailing bytes are
//! refused except the JSON whitespace the crate documents, and that the size
//! limit is exact.
//!
//! "Bounded" is asserted by behaviour: the unsafe budget forbids the counting
//! allocator that would measure it. The length gate runs before any parse work,
//! so refusing valid content at one byte over the limit shows nothing
//! proportional to the input was handed to serde.

#![no_main]

use aido_wire::{BrokerRequest, MAX_REQUEST_BYTES, RequestError};
use libfuzzer_sys::fuzz_target;

/// Bytes that must never turn a valid message into a different valid one.
const TRAILERS: [u8; 9] = [b'x', b'}', b'{', b']', b'0', b'"', b',', 0, 0xff];

fuzz_target!(|data: &[u8]| {
    let parsed = BrokerRequest::parse(data);

    if data.len() > MAX_REQUEST_BYTES {
        assert_eq!(
            parsed,
            Err(RequestError::TooLarge {
                limit: MAX_REQUEST_BYTES
            }),
            "an oversized request was not refused for its size"
        );
        return;
    }
    let Ok(request) = parsed else { return };

    // Round trip: what the broker accepts, the front-end can send, and it
    // reads back as the same value.
    let encoded = request.to_json();
    assert!(
        encoded.len() <= MAX_REQUEST_BYTES,
        "an accepted request re-encodes past the limit"
    );
    let again = BrokerRequest::parse(encoded.as_bytes());
    assert_eq!(again.as_ref(), Ok(&request), "round trip changed the value");
    assert_eq!(
        again.map(|r| r.to_json()),
        Ok(encoded),
        "re-encoding is not a fixed point"
    );

    // No partial accept: anything after a complete message is refused, except
    // JSON whitespace, which the crate's own boundary test relies on.
    let mut probe = Vec::with_capacity(MAX_REQUEST_BYTES + 1);
    for trailer in TRAILERS {
        probe.clear();
        probe.extend_from_slice(data);
        probe.push(trailer);
        if probe.len() <= MAX_REQUEST_BYTES {
            assert!(
                BrokerRequest::parse(&probe).is_err(),
                "trailing byte {trailer:#04x} was accepted after a valid message"
            );
        }
    }
    probe.clear();
    probe.extend_from_slice(data);
    probe.extend_from_slice(b" \n\t\r");
    if probe.len() <= MAX_REQUEST_BYTES {
        assert_eq!(
            BrokerRequest::parse(&probe).as_ref(),
            Ok(&request),
            "trailing whitespace changed the message"
        );
    }

    // Bounded: exact at the limit, refused one byte over.
    probe.clear();
    probe.extend_from_slice(data);
    probe.resize(MAX_REQUEST_BYTES, b' ');
    assert_eq!(
        BrokerRequest::parse(&probe).as_ref(),
        Ok(&request),
        "a request of exactly the limit was refused"
    );
    probe.push(b' ');
    assert_eq!(
        BrokerRequest::parse(&probe),
        Err(RequestError::TooLarge {
            limit: MAX_REQUEST_BYTES
        }),
        "a request one byte over the limit was not refused for its size"
    );
});
