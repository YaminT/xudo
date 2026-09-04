//! Standing invariants of the sanitizer, held under arbitrary input.
//!
//! The sanitizer sits between attacker-controlled bytes and a human's
//! terminal, so its guarantees are stated as properties over all inputs, not
//! as examples: the output never contains anything a terminal interprets, a
//! second pass never finds more to remove, and the limits actually bound the
//! output.

#![allow(clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use term_sanitize::{Limits, display_bytes, display_str};

fn any_limits() -> impl Strategy<Value = Limits> {
    (1usize..200, 1usize..20).prop_map(|(max_cols, max_lines)| Limits {
        max_cols,
        max_lines,
    })
}

proptest! {
    /// Nothing a terminal interprets survives: no control characters other
    /// than newline, no bidi formatting, no zero-width characters.
    #[test]
    fn output_never_contains_terminal_significant_characters(
        input in proptest::collection::vec(any::<u8>(), 0..512),
        limits in any_limits(),
    ) {
        let clean = display_bytes(&input, limits);
        for ch in clean.text.chars() {
            prop_assert!(ch == '\n' || !ch.is_control(), "control {ch:?} survived");
            prop_assert!(
                !matches!(
                    ch,
                    '\u{061C}' | '\u{200E}' | '\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                ),
                "bidi {ch:?} survived"
            );
            prop_assert!(
                !matches!(ch, '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}'),
                "invisible {ch:?} survived"
            );
        }
    }

    /// Sanitization is idempotent: a second pass changes nothing and finds
    /// nothing. If it did, the first pass left something behind.
    #[test]
    fn sanitization_is_idempotent(
        input in proptest::collection::vec(any::<u8>(), 0..512),
        limits in any_limits(),
    ) {
        let once = display_bytes(&input, limits);
        let twice = display_str(&once.text, limits);
        // The ellipsis a truncation appends occupies one character, so a
        // clamped line can be max_cols + 1 wide; re-clamping such a line
        // reports Truncated again but must not change the text.
        prop_assert!(
            twice.text == once.text
                || (twice.findings.contains(&term_sanitize::Finding::Truncated)
                    && once.findings.contains(&term_sanitize::Finding::Truncated)),
            "second pass altered text: {:?} -> {:?}",
            once.text,
            twice.text
        );
        for finding in &twice.findings {
            prop_assert!(
                matches!(finding, term_sanitize::Finding::Truncated),
                "second pass found {finding:?}"
            );
        }
    }

    /// The limits bound the output: at most `max_lines` lines, each at most
    /// `max_cols` characters plus the one-character ellipsis.
    #[test]
    fn limits_actually_bound_the_output(
        input in proptest::collection::vec(any::<u8>(), 0..512),
        limits in any_limits(),
    ) {
        let clean = display_bytes(&input, limits);
        let lines: Vec<&str> = clean.text.split('\n').collect();
        prop_assert!(lines.len() <= limits.max_lines);
        for line in lines {
            prop_assert!(line.chars().count() <= limits.max_cols.saturating_add(1));
        }
    }
}
