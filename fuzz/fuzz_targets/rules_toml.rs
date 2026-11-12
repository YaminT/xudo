//! Fuzz the rule-file parser.
//!
//! A root-owned rule file is attacker-adjacent in one specific way: an operator
//! pastes a snippet from somewhere. The parser must therefore never panic and
//! never accept something the validator would have rejected. Both are asserted
//! here, so a crash and a validation bypass are both findings.

#![no_main]

use xudo_policy::{CallerFacts, Classification, RuleSet, engine::Settings, run_tests};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Must not panic on any input, valid or not.
    let Ok((set, tests)) = RuleSet::from_toml_with_tests("fuzz.toml", text) else {
        return;
    };

    // `from_toml` is what the gate and the broker call; a test block must not
    // make the two disagree about whether the file loads, or about its actions.
    let plain = RuleSet::from_toml("fuzz.toml", text).expect("from_toml refused what the tests loader took");
    assert_eq!(plain, set, "a [[test]] block changed the compiled ruleset");

    // Running whatever tests loaded must never panic, and a test cannot set
    // its own provenance.
    let human = CallerFacts::new(Classification::Human, 1000);
    let results = run_tests(&set, &tests, &human, Settings::default());
    assert_eq!(results.len(), tests.len());
    for test in &tests {
        assert_eq!(test.source.file, "fuzz.toml", "a test set its own provenance");
    }

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
