//! Fuzz the broker's freeze marker parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_gate::policy::parse_freeze_record;

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = parse_freeze_record(data) else { return };
    assert!(serde_json::from_slice::<serde_json::Value>(data)
        .expect("successful parse is JSON")
        .is_object());
    let canonical = serde_json::to_vec(&parsed).expect("freeze record serializes");
    assert!(serde_json::from_slice::<serde_json::Value>(&canonical)
        .expect("canonical record is JSON")
        .is_object());
    assert_eq!(parse_freeze_record(&canonical).expect("canonical form parses"), parsed);
});
