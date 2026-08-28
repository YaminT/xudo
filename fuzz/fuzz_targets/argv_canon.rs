//! Fuzz argv canonicalization.
//!
//! Canonicalization is the one transformation applied before matching, so a bug
//! here means the matcher and the kernel see different argvs — the divergence
//! CVE-2021-3156 exploited. The properties checked are the two the rest of the
//! engine depends on: idempotence, and never losing an operand.

#![no_main]

use aido_policy::{Arg, Argv};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split on NUL, exactly as the kernel delimits a real argv.
    let argv: Argv = data
        .split(|b| *b == 0)
        .take(512)
        .map(|chunk| Arg::new(chunk.to_vec()))
        .collect();

    let once = argv.canonicalize();
    let twice = once.canonicalize();
    assert_eq!(once, twice, "canonicalization is not idempotent");

    // Only a separator may ever be dropped, and at most one of them.
    let separators = argv
        .as_slice()
        .iter()
        .filter(|a| a.as_bytes() == b"--")
        .count();
    if separators == 0 {
        assert!(
            once.len() >= argv.len(),
            "an argument was lost with no separator present"
        );
    }
});
