//! Fuzz compact confirmation state: successful parses must have unique keys
//! and preserve the complete JSON tree when reserialized.
#![no_main]

use libfuzzer_sys::fuzz_target;
use xudod::fuzzing::parse_confirm_data;

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = parse_confirm_data(data) else { return };
    assert!(has_no_duplicate_keys(data), "successful parse accepted duplicate keys");
    let mut input: serde_json::Value = serde_json::from_slice(data).expect("successful parse is JSON");
    let mut parsed_tree = serde_json::to_value(&parsed).expect("confirmation record becomes JSON");
    normalize_omitted_options(&mut input);
    normalize_omitted_options(&mut parsed_tree);
    assert_eq!(input, parsed_tree, "successful parse changed the JSON tree");
    let canonical = serde_json::to_vec(&parsed).expect("confirmation record serializes");
    assert!(serde_json::from_slice::<serde_json::Value>(&canonical)
        .expect("canonical record is JSON")
        .is_object());
    assert_eq!(parse_confirm_data(&canonical).expect("canonical form parses"), parsed);
});

use std::collections::HashSet;

/// Checks duplicate object keys recursively in already-valid JSON bytes.
pub fn has_no_duplicate_keys(bytes: &[u8]) -> bool {
    struct Scanner<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Scanner<'_> {
        fn ws(&mut self) {
            while self.bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
                self.at += 1;
            }
        }

        fn string(&mut self) -> bool {
            let start = self.at;
            if self.bytes.get(self.at) != Some(&b'"') { return false; }
            self.at += 1;
            while let Some(byte) = self.bytes.get(self.at) {
                self.at += 1;
                match byte {
                    b'\\' => self.at = self.at.saturating_add(1),
                    b'"' => return serde_json::from_slice::<String>(&self.bytes[start..self.at]).is_ok(),
                    _ => {}
                }
            }
            false
        }

        fn value(&mut self) -> bool {
            self.ws();
            match self.bytes.get(self.at) {
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => self.string(),
                Some(_) => {
                    let start = self.at;
                    while self.bytes.get(self.at).is_some_and(|b| !b",]} \t\r\n".contains(b)) { self.at += 1; }
                    self.at > start
                }
                None => false,
            }
        }

        fn object(&mut self) -> bool {
            self.at += 1;
            self.ws();
            if self.bytes.get(self.at) == Some(&b'}') { self.at += 1; return true; }
            let mut keys = HashSet::new();
            loop {
                self.ws();
                let start = self.at;
                if !self.string() { return false; }
                let Ok(key) = serde_json::from_slice::<String>(&self.bytes[start..self.at]) else { return false };
                if !keys.insert(key) { return false; }
                self.ws();
                if self.bytes.get(self.at) != Some(&b':') { return false; }
                self.at += 1;
                if !self.value() { return false; }
                self.ws();
                match self.bytes.get(self.at) {
                    Some(b',') => self.at += 1,
                    Some(b'}') => { self.at += 1; return true; }
                    _ => return false,
                }
            }
        }

        fn array(&mut self) -> bool {
            self.at += 1;
            self.ws();
            if self.bytes.get(self.at) == Some(&b']') { self.at += 1; return true; }
            loop {
                if !self.value() { return false; }
                self.ws();
                match self.bytes.get(self.at) {
                    Some(b',') => self.at += 1,
                    Some(b']') => { self.at += 1; return true; }
                    _ => return false,
                }
            }
        }
    }

    let mut scanner = Scanner { bytes, at: 0 };
    scanner.ws();
    let valid = scanner.value();
    scanner.ws();
    valid && scanner.at == bytes.len()
}

/// Treat absent optional fields and explicit nulls as the same tree shape.
pub fn normalize_omitted_options(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            object.retain(|_, value| !value.is_null());
            for value in object.values_mut() { normalize_omitted_options(value); }
        }
        serde_json::Value::Array(items) => {
            for value in items { normalize_omitted_options(value); }
        }
        _ => {}
    }
}
