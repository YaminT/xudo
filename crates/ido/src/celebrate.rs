//! The acceptance celebration. Abstract only — no people in it.
//!
//! Ships as `ido celebrate`, and the same binary installed under the second
//! name `willyoumarryme` runs it too, so the literal command from the brief
//! works as a queued entry with one code path behind it. Ends by printing
//! exactly `ido works.` and exiting 0.

use std::io::Write;
use std::time::Duration;

/// How the celebration should behave on this terminal.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    /// Play the animation. Off when stdout is not a tty, `--no-animation`
    /// was passed, or `IDO_NO_ANIMATION` is set.
    pub animate: bool,
    /// Use color. Off under `NO_COLOR` or without a tty.
    pub color: bool,
    /// Delay between frames. Zero in tests; the whole run stays well under
    /// two seconds in any case.
    pub frame_delay: Duration,
}

/// Abstract confetti: glyphs, rings, a bell. Nothing and nobody else.
const FRAMES: [&str; 8] = [
    "  ·  ✦  ·  ◌  ·  ",
    "  ✦  ·  ◌  ·  ✦  ",
    "  ·  ◌  ·  ✦  ·  ",
    "  ◌  ·  ✦  ·  ◌  ",
    "  ✶  ◌  ·  ◌  ✶  ",
    "  ·  ✶  ◎  ✶  ·  ",
    "  ✦  ·  ◉  ·  ✦  ",
    "  ·  ✧  ◉  ✧  ·  ",
];

/// The last line, exactly. Asserted byte-for-byte by the acceptance test.
const FINALE: &str = "ido works.";

/// Plays the celebration and prints the finale.
///
/// # Errors
///
/// Only when the writer fails.
pub fn celebrate(out: &mut dyn Write, style: Style) -> std::io::Result<()> {
    let mut ending = String::new();
    if style.animate {
        for frame in FRAMES {
            let drawn = if style.color {
                format!("\r\u{1B}[36m{frame}\u{1B}[0m")
            } else {
                format!("\r{frame}")
            };
            out.write_all(drawn.as_bytes())?;
            out.flush()?;
            std::thread::sleep(style.frame_delay);
        }
        // Clear the frame line so the finale stands alone.
        ending.push('\r');
        ending.push_str(&" ".repeat(20));
        ending.push('\r');
    }
    ending.push_str(FINALE);
    ending.push('\n');
    out.write_all(ending.as_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn text(style: Style) -> String {
        let mut buffer = Vec::new();
        celebrate(&mut buffer, style).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn the_finale_is_exact_and_final() {
        let plain = text(Style {
            animate: false,
            color: false,
            frame_delay: Duration::ZERO,
        });
        assert_eq!(plain, "ido works.\n");
    }

    #[test]
    fn the_animation_ends_with_the_same_finale_and_stays_abstract() {
        let animated = text(Style {
            animate: true,
            color: true,
            frame_delay: Duration::ZERO,
        });
        assert!(animated.ends_with("ido works.\n"), "{animated}");
        // Abstract only: every frame draws from a fixed glyph alphabet, so no
        // person, name, or pronoun can appear without failing here.
        let alphabet = [' ', '·', '✦', '✧', '✶', '◌', '◎', '◉'];
        for frame in FRAMES {
            for ch in frame.chars() {
                assert!(
                    alphabet.contains(&ch),
                    "unexpected glyph {ch:?} in {frame:?}"
                );
            }
        }
    }

    #[test]
    fn without_color_no_escape_sequence_is_written() {
        let animated = text(Style {
            animate: true,
            color: false,
            frame_delay: Duration::ZERO,
        });
        assert!(!animated.contains('\u{1B}'), "{animated:?}");
    }

    /// Accepts `writes` whole writes, then fails; `flush` fails on request.
    struct Failing {
        writes: usize,
        flush_fails: bool,
    }

    impl Write for Failing {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.writes == 0 {
                return Err(std::io::Error::other("full"));
            }
            self.writes = self.writes.saturating_sub(1);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.flush_fails {
                return Err(std::io::Error::other("flush"));
            }
            Ok(())
        }
    }

    #[test]
    fn a_failing_writer_surfaces_the_error_wherever_it_fails() {
        let style = |animate, color| Style {
            animate,
            color,
            frame_delay: Duration::ZERO,
        };
        let fail = |writes, flush_fails, style| {
            celebrate(
                &mut Failing {
                    writes,
                    flush_fails,
                },
                style,
            )
            .unwrap_err()
            .to_string()
        };
        assert_eq!(fail(0, false, style(false, false)), "full", "the finale");
        assert_eq!(
            fail(0, false, style(true, true)),
            "full",
            "a coloured frame"
        );
        assert_eq!(fail(0, false, style(true, false)), "full", "a plain frame");
        assert_eq!(fail(1, true, style(true, false)), "flush");
        assert_eq!(
            fail(FRAMES.len(), false, style(true, false)),
            "full",
            "the end"
        );
    }
}
