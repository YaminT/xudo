//! Fuzz the remove-path target grammar.
//!
//! The input is a candidate target, raw bytes. The fixed rule is not attacker
//! controlled. The parser and the judge must not panic, and a target that is
//! not a clean relative path under the tree must not come back allowed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_policy::{
    CallerFacts, Classification, DenialCode, RuleSet, Verdict, engine::Settings,
    evaluate_remove_path, target_under,
};

const RULES: &str = r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 8
max-entries = 100
"#;

fuzz_target!(|data: &[u8]| {
    let depth = u32::from(data.first().copied().unwrap_or(0)).saturating_add(1);
    let _ = target_under(b"/srv/app/build", data, depth.min(32));
    let relative = target_under(b"/srv/app/build", data, 8);

    let set = RuleSet::from_toml("fuzz.toml", RULES).expect("fixed ruleset");
    let caller = CallerFacts::new(Classification::Human, 1000);
    let decision = evaluate_remove_path(
        &set,
        &caller,
        data,
        Settings::default(),
        "root:x:0:0:root:/root:/bin/sh\n",
    );
    if relative.is_err() {
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.denial, Some(DenialCode::OperationRefused));
    }
    if let Ok(relative) = relative {
        assert!(decision.verdict.is_permitted());
        assert!(!relative.is_empty());
        assert!(!relative.split(|byte| *byte == b'/').any(|part| {
            part.is_empty() || part == b"." || part == b".."
        }));
    }
});
