//! Fuzz the rule-file parser.
//!
//! A root-owned rule file is attacker-adjacent in one specific way: an operator
//! pastes a snippet from somewhere. The parser must therefore never panic and
//! never accept something the validator would have rejected. Both are asserted
//! here, so a crash and a validation bypass are both findings.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_policy::{
    engine::Settings, evaluate_command, fuzz_check::witnesses, load_rule_files, run_tests, Arg,
    CallerFacts, Classification, DenialCode, RuleFile, RuleSet, Verdict,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // Must not panic on any input, valid or not.
    let Ok((set, tests)) = RuleSet::from_toml_with_tests("fuzz.toml", text) else {
        return;
    };

    // The gate and the broker load through `load_rule_files`. A `[[test]]`
    // table must change neither whether a file loads nor the generation: strip
    // the tables the way the parser sees them and compare.
    if let Ok(mut table) = text.parse::<toml::Table>() {
        table.remove("test");
        if let Ok(stripped) = toml::to_string(&table) {
            let file = |bytes: &[u8]| RuleFile {
                name: b"fuzz.toml".to_vec(),
                bytes: bytes.to_vec(),
            };
            let with = load_rule_files(vec![file(text.as_bytes())]);
            let without = load_rule_files(vec![file(stripped.as_bytes())]);
            if let Ok(with) = with {
                let without = without.expect("stripping the tests made a loadable file unloadable");
                assert_eq!(
                    with.generation, without.generation,
                    "a [[test]] table moved the generation"
                );
            }
        }
    }

    // Running whatever tests loaded must never panic, and a test cannot set
    // its own provenance.
    let human = CallerFacts::new(Classification::Human, 1000);
    let results = run_tests(&set, &tests, &human, Settings::default());
    assert_eq!(results.len(), tests.len());
    for test in &tests {
        assert_eq!(
            test.source.file, "fuzz.toml",
            "a test set its own provenance"
        );
    }

    // Anything that loaded must satisfy every invariant the validator claims.
    for action in set.actions() {
        assert!(
            action.exe.starts_with('/'),
            "loaded a relative exe: {:?}",
            action.exe
        );
        assert!(
            !action
                .exe
                .split('/')
                .skip(1)
                .any(|c| c.is_empty() || c == "." || c == ".."),
            "loaded an unclean exe: {:?}",
            action.exe
        );
        assert_eq!(
            action.source.file, "fuzz.toml",
            "a rule file set its own provenance"
        );
    }

    // The loader does not reject a rule that allowlists a deny-listed
    // executable: `self_denying_actions` is a lint (`xudo check`, exit 21) and a
    // check on the shipped rules. The invariant is that such a rule can never
    // produce an allow, because the compiled-in deny-list refuses at decision
    // time and no file can override it. Prove it with a witness per offender.
    for (id, _) in set.self_denying_actions() {
        let Some(action) = set.actions().iter().find(|a| &a.id == id) else {
            continue;
        };
        for argv in witnesses(&set, action, 1, 4) {
            let program = Arg::from(action.exe.as_str());
            let decision = evaluate_command(&set, &human, &program, &argv, Settings::default());
            assert_eq!(
                decision.verdict,
                Verdict::Deny,
                "a self-denying rule produced an allow"
            );
            assert_eq!(decision.denial, Some(DenialCode::DenyListed));
        }
    }
});
