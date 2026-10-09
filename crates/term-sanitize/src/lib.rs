//! Sanitizes untrusted text on its way to a terminal.
//!
//! Both `ido`'s picker and `aido`'s confirmation prompt render text an agent
//! wrote — a queued command, a reason string, a working directory — to a human
//! who will act on what they see. That text is therefore attacker-controlled
//! input destined for a terminal, and a terminal is an interpreter: escape
//! sequences redraw the screen, bidirectional overrides reorder what is
//! displayed without changing the bytes (the Trojan Source class), and a
//! homoglyph makes `аws` read as `aws` while naming a different binary.
//!
//! One crate, shared, so the two surfaces cannot drift apart.
//!
//! # Display only
//!
//! The output of this crate is for human eyes. It must never be compared
//! against anything, matched against a rule, or executed — sanitization is
//! *lossy by design*, so two different inputs can render identically. The
//! bytes that get executed are the bytes that were stored, untouched; the
//! [`Finding`]s tell the renderer to warn the human that what they see is not
//! everything that is there.
//!
//! # What is removed, what is flagged
//!
//! Removed (each removal recorded as a [`Finding`]):
//! * C0 controls (except `\n`, which [`Limits::max_lines`] governs) and C1
//!   controls, including a lone `ESC` and raw 8-bit CSI/OSC introducers.
//! * Complete ANSI escape sequences — CSI, OSC (BEL- and ST-terminated), and
//!   two-character `ESC`-prefixed sequences — so their parameter bytes do not
//!   leak into the rendered text.
//! * Bidirectional formatting characters: U+061C, U+200E, U+200F,
//!   U+202A–U+202E, U+2066–U+2069.
//! * Invisible or zero-width characters that enable spoofing: U+200B–U+200D,
//!   U+2060, U+FEFF, U+00AD.
//!
//! Flagged but kept: non-ASCII characters that resemble ASCII (a curated
//! confusables table names what each resembles), and every other non-ASCII
//! character in a *command position*, because a complete confusables table
//! does not exist and a binary name is where the lie pays off.

#![forbid(unsafe_code)]

use std::fmt;

/// Bounds on rendered size, so one entry cannot push the rest off screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum characters per line. Longer lines are truncated with `…`.
    pub max_cols: usize,
    /// Maximum lines. Further lines are dropped, recorded as a finding.
    pub max_lines: usize,
}

impl Limits {
    /// A single display line, the shape list rows use.
    #[must_use]
    pub fn single_line(max_cols: usize) -> Self {
        Self {
            max_cols,
            max_lines: 1,
        }
    }
}

/// Something the sanitizer removed, altered, or wants the human warned about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// ANSI escape sequences were removed.
    AnsiEscapes {
        /// How many sequences.
        count: usize,
    },
    /// C0/C1 control characters were removed (outside escape sequences).
    ControlChars {
        /// How many characters.
        count: usize,
    },
    /// Bidirectional formatting characters were removed.
    BidiOverrides {
        /// How many characters.
        count: usize,
    },
    /// Invisible or zero-width characters were removed.
    Invisibles {
        /// How many characters.
        count: usize,
    },
    /// A non-ASCII character that resembles an ASCII one was kept and flagged.
    Confusable {
        /// The character found.
        found: char,
        /// The ASCII character it resembles.
        resembles: char,
    },
    /// A non-ASCII character with no table entry, flagged in command position.
    NonAscii {
        /// The character found.
        found: char,
    },
    /// The text was longer than the limits and was truncated.
    Truncated,
    /// The bytes were not valid UTF-8; invalid sequences render as U+FFFD.
    InvalidUtf8,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnsiEscapes { count } => {
                write!(f, "{count} terminal escape sequence(s) removed")
            }
            Self::ControlChars { count } => write!(f, "{count} control character(s) removed"),
            Self::BidiOverrides { count } => write!(
                f,
                "{count} bidirectional override(s) removed — displayed order may have been \
                 forged"
            ),
            Self::Invisibles { count } => write!(f, "{count} invisible character(s) removed"),
            Self::Confusable { found, resembles } => write!(
                f,
                "'{found}' (U+{:04X}) looks like '{resembles}' but is a different character",
                u32::from(*found)
            ),
            Self::NonAscii { found } => write!(
                f,
                "'{found}' (U+{:04X}) is a non-ASCII character in a command name",
                u32::from(*found)
            ),
            Self::Truncated => write!(f, "text truncated to fit"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 replaced with \u{FFFD}"),
        }
    }
}

/// Sanitized display text, with everything the human should be warned about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clean {
    /// The text, safe to write to a terminal.
    pub text: String,
    /// What was removed or flagged. Empty means the input was already clean.
    pub findings: Vec<Finding>,
}

impl Clean {
    /// Whether anything at all was removed, altered, or flagged.
    #[must_use]
    pub fn is_suspect(&self) -> bool {
        !self.findings.is_empty()
    }
}

/// Sanitizes arbitrary untrusted bytes for display.
///
/// Invalid UTF-8 is replaced with U+FFFD (and recorded), escape sequences and
/// control characters are stripped, bidi and invisible characters are removed,
/// and the result is clamped to `limits`.
#[must_use]
pub fn display_bytes(input: &[u8], limits: Limits) -> Clean {
    let (text, valid) = decode(input);
    let mut clean = display_str(&text, limits);
    if !valid {
        clean.findings.push(Finding::InvalidUtf8);
    }
    clean
}

/// Sanitizes an untrusted string for display. See [`display_bytes`].
#[must_use]
pub fn display_str(input: &str, limits: Limits) -> Clean {
    let stripped = strip(input);
    let (text, truncated) = clamp(&stripped.text, limits);
    let mut findings = stripped.findings;
    if truncated {
        findings.push(Finding::Truncated);
    }
    Clean { text, findings }
}

/// Flags confusable and non-ASCII characters in a command name.
///
/// Everything non-ASCII is flagged: the curated table adds *what a character
/// resembles*, and the catch-all exists because no confusables table is
/// complete, and a command name is exactly where an unlisted lookalike pays
/// off. ASCII-only input returns no findings.
#[must_use]
pub fn flag_command_name(name: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for ch in name.chars() {
        if ch.is_ascii() {
            continue;
        }
        match confusable_target(ch) {
            Some(resembles) => findings.push(Finding::Confusable {
                found: ch,
                resembles,
            }),
            None => findings.push(Finding::NonAscii { found: ch }),
        }
    }
    findings
}

/// Lossy UTF-8 decode that reports whether the input was valid.
fn decode(input: &[u8]) -> (String, bool) {
    match std::str::from_utf8(input) {
        Ok(s) => (s.to_owned(), true),
        Err(_) => (String::from_utf8_lossy(input).into_owned(), false),
    }
}

/// Intermediate result of the stripping pass.
struct Stripped {
    text: String,
    findings: Vec<Finding>,
}

/// One pass over the characters: parse and drop escape sequences, drop
/// controls, bidi, and invisibles, keep everything else.
fn strip(input: &str) -> Stripped {
    let mut out = String::with_capacity(input.len());
    let mut ansi: usize = 0;
    let mut controls: usize = 0;
    let mut bidi: usize = 0;
    let mut invisibles: usize = 0;

    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            // ESC starts a 7-bit sequence; a lone trailing ESC is a control.
            '\u{1B}' => {
                if consume_escape_body(&mut chars) {
                    ansi = ansi.saturating_add(1);
                } else {
                    controls = controls.saturating_add(1);
                }
            }
            // Raw 8-bit CSI and OSC introducers carry a body too.
            '\u{9B}' => {
                consume_csi_body(&mut chars);
                ansi = ansi.saturating_add(1);
            }
            '\u{9D}' => {
                consume_osc_body(&mut chars);
                ansi = ansi.saturating_add(1);
            }
            '\n' => out.push('\n'),
            c if c.is_control() => controls = controls.saturating_add(1),
            c if is_bidi_control(c) => bidi = bidi.saturating_add(1),
            c if is_invisible(c) => invisibles = invisibles.saturating_add(1),
            c => out.push(c),
        }
    }

    let mut findings = Vec::new();
    if ansi > 0 {
        findings.push(Finding::AnsiEscapes { count: ansi });
    }
    if controls > 0 {
        findings.push(Finding::ControlChars { count: controls });
    }
    if bidi > 0 {
        findings.push(Finding::BidiOverrides { count: bidi });
    }
    if invisibles > 0 {
        findings.push(Finding::Invisibles { count: invisibles });
    }
    Stripped {
        text: out,
        findings,
    }
}

/// Consumes the body of a 7-bit escape sequence after the ESC.
///
/// Returns `true` when a sequence body was consumed, `false` for a lone
/// trailing ESC. CSI (`ESC [`) runs to its final byte, OSC (`ESC ]`) to BEL or
/// ST, an intermediate byte (`0x20..=0x2F`) runs through further intermediates
/// to one final byte (ECMA-48 — charset selection like `ESC ( B`), and any
/// other single character is a two-character sequence.
fn consume_escape_body(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    match chars.next() {
        None => false,
        Some('[') => {
            consume_csi_body(chars);
            true
        }
        Some(']') => {
            consume_osc_body(chars);
            true
        }
        Some(c) if ('\u{20}'..='\u{2F}').contains(&c) => {
            while let Some(&next) = chars.peek() {
                if ('\u{20}'..='\u{2F}').contains(&next) {
                    let _ = chars.next();
                } else if ('\u{30}'..='\u{7E}').contains(&next) {
                    let _ = chars.next();
                    break;
                } else {
                    break;
                }
            }
            true
        }
        Some(_) => true,
    }
}

/// Consumes CSI parameter and intermediate bytes up to and including the final
/// byte (`0x40..=0x7E`). Anything out of range ends the sequence unconsumed —
/// the character is left for the caller's loop, which strips or keeps it on
/// its own merits rather than trusting a malformed sequence to end itself.
fn consume_csi_body(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&next) = chars.peek() {
        if ('\u{20}'..='\u{3F}').contains(&next) {
            let _ = chars.next();
        } else if ('\u{40}'..='\u{7E}').contains(&next) {
            let _ = chars.next();
            return;
        } else {
            return;
        }
    }
}

/// Consumes an OSC body up to and including BEL, or ST (`ESC \`), or 8-bit ST.
fn consume_osc_body(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(next) = chars.next() {
        match next {
            '\u{07}' | '\u{9C}' => return,
            '\u{1B}' => {
                // ST is ESC \. Any other character after ESC still ends the
                // OSC: a nested escape means the sequence was malformed.
                let _ = chars.next();
                return;
            }
            _ => {}
        }
    }
}

/// Bidirectional formatting characters — the Trojan Source set.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Invisible or zero-width characters that enable visual spoofing.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}'
    )
}

/// Clamps to at most `max_lines` lines of at most `max_cols` characters.
fn clamp(input: &str, limits: Limits) -> (String, bool) {
    let mut out = String::with_capacity(input.len().min(4096));
    let mut truncated = false;
    for (i, line) in input.split('\n').enumerate() {
        if i >= limits.max_lines {
            truncated = true;
            break;
        }
        if i > 0 {
            out.push('\n');
        }
        let mut count: usize = 0;
        for ch in line.chars() {
            if count >= limits.max_cols {
                truncated = true;
                out.push('…');
                break;
            }
            out.push(ch);
            count = count.saturating_add(1);
        }
    }
    (out, truncated)
}

/// What a non-ASCII character resembles, for the curated lookalikes.
///
/// Deliberately small: the common Cyrillic and Greek letters that render
/// near-identically to ASCII in monospace fonts. Completeness is not the goal
/// — [`flag_command_name`] flags every non-ASCII character regardless; this
/// table only upgrades the message from "non-ASCII" to "looks like 'a'".
fn confusable_target(c: char) -> Option<char> {
    // Grouped by what the character resembles: Cyrillic and Greek lookalikes
    // for one ASCII letter share an arm.
    let resembles = match c {
        '\u{0430}' => 'a',              // а
        '\u{0435}' => 'e',              // е
        '\u{043E}' | '\u{03BF}' => 'o', // о ο
        '\u{0440}' => 'p',              // р
        '\u{0441}' => 'c',              // с
        '\u{0443}' => 'y',              // у
        '\u{0445}' => 'x',              // х
        '\u{0455}' => 's',              // ѕ
        '\u{0456}' => 'i',              // і
        '\u{0458}' => 'j',              // ј
        '\u{04BB}' => 'h',              // һ
        '\u{0501}' => 'd',              // ԁ
        '\u{051B}' => 'q',              // ԛ
        '\u{051D}' => 'w',              // ԝ
        '\u{03BD}' => 'v',              // ν
        '\u{0410}' | '\u{0391}' => 'A',
        '\u{0412}' | '\u{0392}' => 'B',
        '\u{0421}' => 'C',
        '\u{0415}' | '\u{0395}' => 'E',
        '\u{041D}' | '\u{0397}' => 'H',
        '\u{0399}' => 'I',
        '\u{041A}' | '\u{039A}' => 'K',
        '\u{041C}' | '\u{039C}' => 'M',
        '\u{039D}' => 'N',
        '\u{041E}' | '\u{039F}' => 'O',
        '\u{0420}' | '\u{03A1}' => 'P',
        '\u{0422}' | '\u{03A4}' => 'T',
        '\u{0425}' | '\u{03A7}' => 'X',
        '\u{03A5}' => 'Y',
        '\u{0396}' => 'Z',
        _ => return None,
    };
    Some(resembles)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;

    fn wide() -> Limits {
        Limits {
            max_cols: 1000,
            max_lines: 100,
        }
    }

    #[test]
    fn ansi_escapes_in_a_reason_cannot_redraw_the_screen() {
        // Clear screen, cursor home, red text, then a fake prompt line.
        let hostile = "\u{1B}[2J\u{1B}[H\u{1B}[31mrun me\u{1B}[0m$ sudo rm -rf /";
        let clean = display_str(hostile, wide());
        assert_eq!(clean.text, "run me$ sudo rm -rf /");
        assert!(
            clean.findings.contains(&Finding::AnsiEscapes { count: 4 }),
            "{:?}",
            clean.findings
        );
    }

    #[test]
    fn osc_sequences_are_removed_whole_with_both_terminators() {
        // OSC bodies (window title, hyperlinks) must not leak their payload.
        let bel = "a\u{1B}]0;evil title\u{07}b";
        assert_eq!(display_str(bel, wide()).text, "ab");
        let st = "a\u{1B}]8;;https://evil\u{1B}\\b";
        assert_eq!(display_str(st, wide()).text, "ab");
    }

    #[test]
    fn eight_bit_csi_and_osc_introducers_are_stripped_with_their_bodies() {
        let csi = "a\u{9B}31mb";
        assert_eq!(display_str(csi, wide()).text, "ab");
        let osc = "a\u{9D}0;title\u{07}b";
        assert_eq!(display_str(osc, wide()).text, "ab");
        let osc_8bit_st = "a\u{9D}0;title\u{9C}b";
        assert_eq!(display_str(osc_8bit_st, wide()).text, "ab");
    }

    #[test]
    fn a_lone_trailing_escape_is_a_control_character_not_a_sequence() {
        let clean = display_str("abc\u{1B}", wide());
        assert_eq!(clean.text, "abc");
        assert_eq!(clean.findings, vec![Finding::ControlChars { count: 1 }]);
    }

    #[test]
    fn a_charset_escape_sequence_is_consumed_through_its_final_byte() {
        // ESC ( B — charset selection. Neither '(' nor 'B' may survive as text.
        let clean = display_str("a\u{1B}(Bb", wide());
        assert_eq!(clean.text, "ab");
        assert_eq!(clean.findings, vec![Finding::AnsiEscapes { count: 1 }]);
        // A two-character sequence: ESC 7 (save cursor).
        let clean = display_str("a\u{1B}7b", wide());
        assert_eq!(clean.text, "ab");
        // An unterminated intermediate at end of input ends cleanly.
        let clean = display_str("a\u{1B}(", wide());
        assert_eq!(clean.text, "a");
    }

    #[test]
    fn a_multibyte_charset_escape_is_consumed_through_every_intermediate() {
        // ESC $ ( B — two intermediates before the final byte. Stopping after
        // the first would leave "(B" on screen.
        let clean = display_str("a\u{1B}$(Bb", wide());
        assert_eq!(clean.text, "ab");
        assert_eq!(clean.findings, vec![Finding::AnsiEscapes { count: 1 }]);
    }

    #[test]
    fn a_malformed_intermediate_escape_does_not_swallow_the_next_character() {
        // 'é' is not a valid final byte, so the sequence ends before it and it
        // is judged on its own merits.
        let clean = display_str("a\u{1B}(éb", wide());
        assert_eq!(clean.text, "aéb");
    }

    #[test]
    fn a_carriage_return_cannot_overwrite_what_was_shown() {
        // "rm -rf /\rls" renders as "ls" on a raw terminal.
        let clean = display_str("rm -rf /\rls", wide());
        assert_eq!(clean.text, "rm -rf /ls");
        assert_eq!(clean.findings, vec![Finding::ControlChars { count: 1 }]);
    }

    #[test]
    fn a_malformed_csi_does_not_swallow_the_rest_of_the_line() {
        // A CSI whose "parameters" include a byte outside the CSI grammar must
        // stop consuming there, not eat to end of string.
        let clean = display_str("a\u{1B}[1;é31mb", wide());
        assert!(clean.text.contains('b'), "{:?}", clean.text);
        assert!(clean.text.contains('é'), "{:?}", clean.text);
    }

    #[test]
    fn an_unterminated_csi_at_end_of_input_ends_cleanly() {
        let clean = display_str("a\u{1B}[31", wide());
        assert_eq!(clean.text, "a");
    }

    #[test]
    fn an_unterminated_osc_at_end_of_input_ends_cleanly() {
        let clean = display_str("a\u{1B}]0;title", wide());
        assert_eq!(clean.text, "a");
    }

    #[test]
    fn bidi_overrides_in_a_command_cannot_reorder_the_display() {
        // The Trojan Source shape: RLO makes "gpg.exe" render reversed.
        let hostile = "run \u{202E}exe.gpg\u{202C} now";
        let clean = display_str(hostile, wide());
        assert_eq!(clean.text, "run exe.gpg now");
        assert_eq!(
            clean.findings,
            vec![Finding::BidiOverrides { count: 2 }],
            "rendered order must equal byte order"
        );
        // The isolate set is stripped too.
        let isolates = "a\u{2066}b\u{2067}c\u{2068}d\u{2069}e\u{061C}f\u{200E}g\u{200F}h";
        assert_eq!(display_str(isolates, wide()).text, "abcdefgh");
    }

    #[test]
    fn zero_width_characters_cannot_hide_in_a_command() {
        let hostile = "a\u{200B}b\u{200C}c\u{200D}d\u{2060}e\u{FEFF}f\u{00AD}g";
        let clean = display_str(hostile, wide());
        assert_eq!(clean.text, "abcdefg");
        assert_eq!(clean.findings, vec![Finding::Invisibles { count: 6 }]);
    }

    #[test]
    fn a_homoglyph_binary_name_is_flagged() {
        // Cyrillic а in аws is a different binary.
        let findings = flag_command_name("\u{0430}ws");
        assert_eq!(
            findings,
            vec![Finding::Confusable {
                found: '\u{0430}',
                resembles: 'a'
            }]
        );
        let rendered = findings[0].to_string();
        assert!(rendered.contains("U+0430"), "{rendered}");
        assert!(rendered.contains("looks like 'a'"), "{rendered}");
    }

    #[test]
    fn an_unlisted_non_ascii_character_in_a_command_is_still_flagged() {
        // No table can be complete; the catch-all is the guarantee.
        let findings = flag_command_name("ls\u{1D5C5}");
        assert_eq!(findings, vec![Finding::NonAscii { found: '\u{1D5C5}' }]);
        assert!(findings[0].to_string().contains("non-ASCII"));
    }

    #[test]
    fn an_ascii_command_name_raises_nothing() {
        assert!(flag_command_name("/usr/bin/systemctl").is_empty());
    }

    #[test]
    fn every_curated_confusable_maps_to_ascii() {
        // The table's whole claim is "this resembles ASCII"; hold it to that.
        // Codepoints written as escapes, not glyphs: the first version of this
        // test typed an ASCII 'x' where Cyrillic х was meant, and the arm for
        // х went unexercised — the exact confusion this crate exists to catch,
        // committed by its own test.
        let curated: [char; 41] = [
            '\u{0430}', '\u{0435}', '\u{043E}', '\u{0440}', '\u{0441}', '\u{0443}', '\u{0445}',
            '\u{0455}', '\u{0456}', '\u{0458}', '\u{04BB}', '\u{0501}', '\u{051B}', '\u{051D}',
            '\u{03BD}', '\u{03BF}', '\u{0410}', '\u{0412}', '\u{0415}', '\u{041A}', '\u{041C}',
            '\u{041D}', '\u{041E}', '\u{0420}', '\u{0421}', '\u{0422}', '\u{0425}', '\u{0391}',
            '\u{0392}', '\u{0395}', '\u{0396}', '\u{0397}', '\u{0399}', '\u{039A}', '\u{039C}',
            '\u{039D}', '\u{039F}', '\u{03A1}', '\u{03A4}', '\u{03A5}', '\u{03A7}',
        ];
        let targets: Vec<Option<char>> = curated.iter().map(|&c| confusable_target(c)).collect();
        let all_ascii = targets.iter().all(|t| t.is_some_and(|c| c.is_ascii()));
        assert!(all_ascii, "{targets:?}");
        // ASCII itself and an uncurated non-ASCII character have no entry.
        assert_eq!(confusable_target('x'), None);
        assert_eq!(confusable_target('\u{4E00}'), None);
    }

    #[test]
    fn width_is_clamped_with_a_visible_ellipsis() {
        let clean = display_str("abcdefgh", Limits::single_line(4));
        assert_eq!(clean.text, "abcd…");
        assert!(clean.findings.contains(&Finding::Truncated));
    }

    #[test]
    fn line_count_is_clamped() {
        let clean = display_str(
            "one\ntwo\nthree",
            Limits {
                max_cols: 80,
                max_lines: 2,
            },
        );
        assert_eq!(clean.text, "one\ntwo");
        assert!(clean.findings.contains(&Finding::Truncated));
    }

    #[test]
    fn invalid_utf8_is_replaced_and_reported() {
        let clean = display_bytes(b"ok\xFF\xFEok", wide());
        assert!(clean.text.contains('\u{FFFD}'));
        assert!(clean.findings.contains(&Finding::InvalidUtf8));
    }

    #[test]
    fn valid_bytes_report_no_utf8_finding() {
        let clean = display_bytes("plain".as_bytes(), wide());
        assert_eq!(clean.text, "plain");
        assert!(!clean.is_suspect());
    }

    #[test]
    fn clean_input_is_untouched_and_unsuspicious() {
        let input = "apt-get install -y ripgrep";
        let clean = display_str(input, wide());
        assert_eq!(clean.text, input);
        assert!(!clean.is_suspect());
    }

    #[test]
    fn every_finding_renders_a_sentence() {
        let findings = [
            Finding::AnsiEscapes { count: 1 },
            Finding::ControlChars { count: 2 },
            Finding::BidiOverrides { count: 3 },
            Finding::Invisibles { count: 4 },
            Finding::Confusable {
                found: '\u{0430}',
                resembles: 'a',
            },
            Finding::NonAscii { found: 'é' },
            Finding::Truncated,
            Finding::InvalidUtf8,
        ];
        for finding in &findings {
            assert!(finding.to_string().len() > 10, "{finding:?}");
        }
    }
}
