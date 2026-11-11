//! Fuzz the root-owned pending request parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_gate::request::PendingRequest;

fuzz_target!(|data: &[u8]| {
    let Ok(entry) = std::str::from_utf8(data).ok().and_then(|text| PendingRequest::parse(text).ok()).ok_or(()) else {
        return;
    };
    assert!(serde_json::from_slice::<serde_json::Value>(data)
        .expect("successful parse is JSON")
        .is_object());
    let value: serde_json::Value = serde_json::from_str(&entry.to_json()).expect("serialized entry is JSON");
    assert!(value.is_object());
    let canonical = entry.to_json();
    assert_eq!(PendingRequest::parse(&canonical).expect("canonical entry parses"), entry);
});
