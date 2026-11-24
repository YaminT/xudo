//! Fuzz configured deny rules and their monotone, order-independent matcher.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_policy::{Arg, Argv, RuleSet, evaluate_deny_rules};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return; };
    let Ok(rules) = RuleSet::from_toml("fuzz.toml", text) else { return; };
    let deny_rules = rules.deny_rules();
    if deny_rules.is_empty() { return; }

    let argv = Argv::new(data.chunks(16).map(Arg::new).collect::<Vec<_>>());
    let exe = deny_rules[0].program.first().map_or(b"/bin/unknown".as_slice(), |p| p.as_bytes());
    let matched = evaluate_deny_rules(deny_rules, exe, &argv);
    let appended = Argv::new(argv.as_slice().iter().cloned().chain([Arg::new(data)]).collect::<Vec<_>>());
    let appended_matched = evaluate_deny_rules(deny_rules, exe, &appended);
    for rule in &matched {
        assert!(appended_matched.iter().any(|candidate| candidate.id == rule.id), "appending argv removed a deny");
    }

    let mut reversed = deny_rules.to_vec();
    reversed.reverse();
    let mut before: Vec<_> = matched.iter().map(|rule| rule.id.as_str()).collect();
    let mut after: Vec<_> = evaluate_deny_rules(&reversed, exe, &argv).iter().map(|rule| rule.id.as_str()).collect();
    before.sort_unstable();
    after.sort_unstable();
    assert_eq!(before, after, "deny declaration order changed the matched set");
});
