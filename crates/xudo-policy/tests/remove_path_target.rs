//! Properties of the remove-path target grammar.
//!
//! These live outside the policy library. `cargo miri` runs `xudo-policy --lib`,
//! and this file is an integration test.

#![allow(clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use xudo_policy::{
    CallerFacts, Classification, DenialCode, RuleSet, Verdict, engine::Settings,
    evaluate_remove_path, target_under,
};

const UNDER: &[u8] = b"/srv/app/build";

fn ruleset() -> RuleSet {
    RuleSet::from_toml(
        "op.toml",
        r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 8
max-entries = 100
"#,
    )
    .unwrap()
}

fn human() -> CallerFacts {
    CallerFacts::new(Classification::Human, 1000)
}

fn decide(target: &[u8]) -> xudo_policy::Decision {
    evaluate_remove_path(&ruleset(), &human(), target, Settings::default(), "")
}

#[test]
fn the_example_rule_loads_and_refuses_the_tree_and_a_shared_prefix() {
    let example = include_str!("../../../rules/examples/50-remove-path.toml.example");
    let set = RuleSet::from_toml("50-remove-path.toml", example).unwrap();
    let operation = set.operations().first().unwrap();
    assert_eq!(operation.op.as_str(), "remove-path");
    let allowed = evaluate_remove_path(
        &set,
        &human(),
        b"/srv/app/build/cache",
        Settings::default(),
        "",
    );
    assert!(allowed.verdict.is_permitted(), "{allowed:?}");
    assert_eq!(
        evaluate_remove_path(&set, &human(), b"/srv/app/build", Settings::default(), "").denial,
        Some(DenialCode::OperationRefused)
    );
}

#[test]
fn empty_absolute_and_parent_components_are_refused() {
    assert_eq!(
        target_under(UNDER, UNDER, 8).unwrap_err(),
        "the tree root is never removed"
    );
    assert_eq!(
        target_under(UNDER, b"/srv/other", 8).unwrap_err(),
        "target is outside the tree"
    );
    assert_eq!(
        target_under(UNDER, b"/srv/app/build-evil", 8).unwrap_err(),
        "target is outside the tree"
    );
    assert_eq!(
        target_under(UNDER, b"/srv/app/build-evil/cache", 8).unwrap_err(),
        "target is outside the tree"
    );
    assert_eq!(
        target_under(UNDER, b"/srv/app/build//cache", 8).unwrap_err(),
        "target is not a clean absolute path"
    );
    assert_eq!(
        target_under(UNDER, b"/srv/app/build/./cache", 8).unwrap_err(),
        "target is not a clean absolute path"
    );
    assert_eq!(
        target_under(UNDER, b"/srv/app/build/cache/..", 8).unwrap_err(),
        "target is not a clean absolute path"
    );
    assert_eq!(
        target_under(UNDER, b"//srv/app/build/cache", 8).unwrap_err(),
        "target is not a clean absolute path"
    );
    assert_eq!(decide(UNDER).denial, Some(DenialCode::OperationRefused));
    assert_eq!(
        decide(b"/etc/passwd").denial,
        Some(DenialCode::OperationRefused)
    );
    assert_eq!(decide(b"/srv/app/build/cache").verdict, Verdict::Allow);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn a_clean_relative_target_is_under_the_tree_and_dotdot_is_not(
        parts in prop::collection::vec("[a-z][a-z0-9]{0,7}", 1..=4)
    ) {
        let relative = parts.join("/");
        let mut target = UNDER.to_vec();
        target.push(b'/');
        target.extend(relative.as_bytes());
        let got = target_under(UNDER, &target, 8).unwrap();
        assert_eq!(got, relative.as_bytes());
        assert!(!got.split(|byte| *byte == b'/').any(|part| {
            part.is_empty() || part == b"." || part == b".."
        }));
        let decision = decide(&target);
        assert!(decision.verdict.is_permitted(), "{decision:?}");

        let mut escaped = target.clone();
        escaped.extend_from_slice(b"/..");
        assert_eq!(
            target_under(UNDER, &escaped, 8).unwrap_err(),
            "target is not a clean absolute path"
        );
        assert_eq!(decide(&escaped).denial, Some(DenialCode::OperationRefused));
        assert_eq!(decide(&escaped).verdict, Verdict::Deny);
    }
}
