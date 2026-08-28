//! Fuzz the rule-file parser.
//!
//! A root-owned rule file is attacker-adjacent in one specific way: an operator
//! pastes a snippet from somewhere. The parser must therefore never panic and
//! never accept something the validator would have rejected. Both are asserted
//! here, so a crash and a validation bypass are both findings.

#![no_main]

use aido_policy::RuleSet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Must not panic on any input, valid or not.
    let Ok(set) = RuleSet::from_toml("fuzz.toml", text) else {
        return;
    };

    // Anything that loaded must satisfy every invariant the validator claims.
    for action in set.actions() {
        assert!(
            action.exe.starts_with('/'),
            "loaded a relative exe: {:?}",
            action.exe
        );
        assert!(
            !action.exe.split('/').skip(1).any(|c| c.is_empty() || c == "." || c == ".."),
            "loaded an unclean exe: {:?}",
            action.exe
        );
        assert_eq!(
            action.source.file, "fuzz.toml",
            "a rule file set its own provenance"
        );
    }

    // A loaded ruleset must never allowlist a deny-listed executable.
    assert!(
        set.self_denying_actions().is_empty(),
        "loaded a ruleset that allowlists a deny-listed executable"
    );
});
