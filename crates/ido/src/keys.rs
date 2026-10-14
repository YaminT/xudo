//! Decoding raw terminal input into keys.
//!
//! The binary puts the terminal in raw mode and hands this module whatever
//! bytes one `read` returned. Escape sequences arrive whole in practice; a
//! sequence this module does not know is consumed and reported as
//! [`Key::Unknown`], never replayed as the printable characters inside it —
//! otherwise an arrow key on an unusual terminal would type `[A` into a
//! confirmation prompt.

/// One key press.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Cursor up.
    Up,
    /// Cursor down.
    Down,
    /// The space bar.
    Space,
    /// Return or enter.
    Enter,
    /// Escape on its own.
    Esc,
    /// Backspace or delete-left.
    Backspace,
    /// Control-C. Raw mode delivers it as a byte instead of a signal.
    CtrlC,
    /// A printable character.
    Char(char),
    /// Anything else: an unknown escape sequence or control byte.
    Unknown,
}

/// Decodes one read's worth of bytes.
#[must_use]
pub fn decode(bytes: &[u8]) -> Vec<Key> {
    let text = String::from_utf8_lossy(bytes);
    let mut keys = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        let key = match c {
            '\u{1B}' => match chars.peek() {
                Some('[' | 'O') => {
                    chars.next();
                    escape_sequence(&mut chars)
                }
                _ => Key::Esc,
            },
            '\r' | '\n' => Key::Enter,
            ' ' => Key::Space,
            '\u{7F}' | '\u{8}' => Key::Backspace,
            '\u{3}' => Key::CtrlC,
            c if c.is_control() => Key::Unknown,
            c => Key::Char(c),
        };
        keys.push(key);
    }
    keys
}

/// Consumes the rest of a CSI or SS3 sequence: parameter bytes, then one final
/// byte in `@`..=`~`.
fn escape_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Key {
    for c in chars.by_ref() {
        match c {
            'A' => return Key::Up,
            'B' => return Key::Down,
            '@'..='~' => return Key::Unknown,
            _ => {}
        }
    }
    // Truncated mid-sequence: nothing to act on.
    Key::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrows_decode_in_both_cursor_modes() {
        assert_eq!(decode(b"\x1b[A\x1b[B"), vec![Key::Up, Key::Down]);
        assert_eq!(decode(b"\x1bOA\x1bOB"), vec![Key::Up, Key::Down]);
    }

    #[test]
    fn an_unknown_sequence_is_consumed_whole_not_typed() {
        // Page Down, then `x`: the `6~` must not leak in as characters.
        assert_eq!(decode(b"\x1b[6~x"), vec![Key::Unknown, Key::Char('x')]);
        assert_eq!(decode(b"\x1b[1;5C"), vec![Key::Unknown]);
        assert_eq!(decode(b"\x1b["), vec![Key::Unknown], "truncated");
    }

    #[test]
    fn plain_keys_decode() {
        assert_eq!(
            decode(b" \r\n\x7f\x08\x03\x1bq\x01"),
            vec![
                Key::Space,
                Key::Enter,
                Key::Enter,
                Key::Backspace,
                Key::Backspace,
                Key::CtrlC,
                Key::Esc,
                Key::Char('q'),
                Key::Unknown,
            ]
        );
    }

    #[test]
    fn a_lone_escape_at_the_end_is_escape() {
        assert_eq!(decode(b"\x1b"), vec![Key::Esc]);
    }

    #[test]
    fn non_ascii_input_is_a_character() {
        assert_eq!(decode("é".as_bytes()), vec![Key::Char('é')]);
    }
}
