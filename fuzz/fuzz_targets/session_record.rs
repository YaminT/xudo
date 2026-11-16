//! Fuzz the strict committed-session record parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_gate::session::parse_session_record;

fuzz_target!(|data: &[u8]| {
    let _ = parse_session_record(
        data,
        "agent-0123456789abcdef0123456789abcdef",
        1000,
        "01234567-89ab-cdef-0123-456789abcdef",
        20,
    );
});
