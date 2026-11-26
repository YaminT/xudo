//! Fuzz the rule-pack header and the review `xudo rules add` makes.
//!
//! A pack is a file an operator got from somewhere else, so its parser is a
//! trust boundary. Must never panic, and must never let a pack reach a harness
//! its `for` does not name: every capability a loaded pack gives a harness is
//! for a label in `for`, and a pack with no `for` gives no harness anything.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_policy::pack::{capabilities, digest, header_of, review, PASSWORD_PATH};
use xudo_policy::{HarnessFile, RuleFile, RuleSet};

fuzz_target!(|data: &[u8]| {
    let _ = digest(data);
    let header = header_of(data);
    let Ok(text) = std::str::from_utf8(data) else {
        assert!(header.is_err(), "a pack that is not UTF-8 was read");
        return;
    };
    let Ok(parsed) = RuleSet::parse_file("fuzz.toml", text) else {
        assert!(header.is_err(), "a header was read from a file that does not load");
        return;
    };
    let Some(pack) = parsed.pack else {
        return;
    };
    assert_eq!(header.as_ref().ok(), Some(&pack));
    assert!(pack.validate().is_ok(), "an invalid header loaded");

    for capability in capabilities(&parsed.rules) {
        assert!(
            capability.audience == PASSWORD_PATH || pack.harnesses.contains(&capability.audience),
            "a pack reached harness {} outside its for",
            capability.audience
        );
    }

    // The review never panics, and refuses or says what changes.
    let registry: Result<Vec<HarnessFile>, String> = Ok(Vec::new());
    let file = RuleFile {
        name: pack.file_name().into_bytes(),
        bytes: data.to_vec(),
    };
    if let Ok(change) = review(Vec::new(), vec![file], &registry) {
        assert!(change.losses.is_empty(), "adding to nothing took something away");
        // With an empty registry no harness can be named, so nothing is granted.
        assert!(change.gains.iter().all(|c| c.audience == PASSWORD_PATH));
    }
});
