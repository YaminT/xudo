//! Fuzz the deny-list evaluator.
//!
//! The deny-list is the backstop for a mistaken allow rule, so it must never
//! panic and must never *miss* a spelling of something it already refuses. The
//! second property is the interesting one: appending arguments can only ever add
//! findings, never remove them.

#![no_main]

use aido_policy::{Arg, Argv, evaluate_deny_list};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|b| *b == 0);
    let exe = parts.next().unwrap_or_default();
    let argv: Argv = parts.take(512).map(|c| Arg::new(c.to_vec())).collect();

    let findings = evaluate_deny_list(exe, &argv);

    // Monotonic: extending the argv never un-denies anything.
    let mut longer: Vec<Arg> = argv.as_slice().to_vec();
    longer.push(Arg::from("--extra"));
    let extended = evaluate_deny_list(exe, &Argv::new(longer));
    for finding in &findings {
        assert!(
            extended.iter().any(|f| f.class == finding.class),
            "appending an argument removed a {:?} finding",
            finding.class
        );
    }

    // Findings are sorted and deduplicated, so an audit record is stable.
    for pair in findings.windows(2) {
        if let [a, b] = pair {
            assert!(
                (a.class, a.evidence.as_str()) <= (b.class, b.evidence.as_str()),
                "findings are not sorted"
            );
        }
    }
});
