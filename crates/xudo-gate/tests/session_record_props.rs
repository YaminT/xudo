//! The record parser's standing properties: a record missing a field or
//! carrying an unknown key is never accepted.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use xudo_gate::parse_session_record;

const NAME: &str = "agent-0123456789abcdef0123456789abcdef";
const FIELDS: [&str; 9] = [
    "\"kind\":\"agent\"",
    "\"uid\":1000",
    "\"label\":\"codex\"",
    "\"boot_id\":\"boot-a\"",
    "\"created_at_boottime_ms\":20",
    "\"deadline\":200",
    "\"pid\":42",
    "\"starttime\":71",
    "\"cgroup_id\":9001",
];
const KNOWN: [&str; 9] = [
    "kind",
    "uid",
    "label",
    "boot_id",
    "created_at_boottime_ms",
    "deadline",
    "pid",
    "starttime",
    "cgroup_id",
];

fn record(fields: &[&str]) -> String {
    format!("{{{}}}", fields.join(","))
}

#[test]
fn the_full_record_is_accepted() {
    let full = record(&FIELDS);
    assert!(parse_session_record(full.as_bytes(), NAME, 1000, "boot-a", 100).is_some());
}

proptest! {
    #[test]
    fn a_record_missing_any_field_is_refused(skip in 0..FIELDS.len()) {
        let kept: Vec<&str> = FIELDS
            .iter()
            .enumerate()
            .filter_map(|(index, field)| (index != skip).then_some(*field))
            .collect();
        let text = record(&kept);
        prop_assert!(parse_session_record(text.as_bytes(), NAME, 1000, "boot-a", 100).is_none());
    }

    #[test]
    fn a_record_with_an_unknown_key_is_refused(key in "[a-z_]{1,16}", at in 0..=FIELDS.len()) {
        prop_assume!(!KNOWN.contains(&key.as_str()));
        let extra = format!("\"{key}\":1");
        let mut fields = FIELDS.to_vec();
        fields.insert(at, extra.as_str());
        let text = record(&fields);
        prop_assert!(parse_session_record(text.as_bytes(), NAME, 1000, "boot-a", 100).is_none());
    }
}
