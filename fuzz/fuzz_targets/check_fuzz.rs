//! Fuzz `xudo check --fuzz`: the differential fuzz run over an arbitrary rule
//! file.
//!
//! Input layout: eight bytes of seed, one byte of budget, then the rule file.
//! The budget is capped small so one execution is bounded; what is asserted is
//! that the run never panics, stays within its budget, and that the overlap
//! analysis and the invariants hold for whatever ruleset the parser accepted.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xudo_policy::{RuleSet, fuzz_check};

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_at_checked(9) else {
        return;
    };
    let (seed, budget) = head.split_at(8);
    let seed = u64::from_le_bytes(seed.try_into().expect("eight bytes"));
    let budget = usize::from(budget.first().copied().unwrap_or(0)).max(1);
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let Ok(set) = RuleSet::from_toml("fuzz.toml", text) else {
        return;
    };

    let config = fuzz_check::FuzzConfig { budget, seed };
    let report = fuzz_check::fuzz(&set, &set.overlaps(), config);
    assert!(report.candidates <= budget, "the fuzz ran over its budget");
    assert_eq!(
        report.candidates,
        report.accepted_by_one + report.accepted_by_several + report.accepted_by_none
    );
    assert_eq!(report, fuzz_check::fuzz(&set, &set.overlaps(), config), "not deterministic");
    let found: Vec<String> = report
        .findings
        .iter()
        .map(|f| format!("{}: {}", f.summary(), f.escaped()))
        .collect();
    assert!(report.clean(), "the fuzz found:\n{}", found.join("\n"));
});
