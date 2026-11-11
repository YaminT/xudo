//! Fuzz compact confirmation state, including its strict object shapes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xudod::serve::parse_confirm_data;

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = parse_confirm_data(data) else { return };
    assert!(serde_json::from_slice::<serde_json::Value>(data)
        .expect("successful parse is JSON")
        .is_object());
    let canonical = serde_json::to_vec(&parsed).expect("confirmation record serializes");
    assert!(serde_json::from_slice::<serde_json::Value>(&canonical)
        .expect("canonical record is JSON")
        .is_object());
    assert_eq!(parse_confirm_data(&canonical).expect("canonical form parses"), parsed);
});
