//! The hints about a caller that go in the audit trail and nowhere else.
//!
//! A caller's executable path, its command line and whether it exported
//! `CLAUDECODE` are all its own to choose (invariant 1). They are recorded so
//! an operator reading the trail can see who claimed to be what, and nothing
//! may decide on them: [`CallerHints`] has no accessor, only
//! [`CallerHints::evidence`], which renders the audit lines.
//!
//! Every value is escaped (`escape_ascii`, so control characters and non-ASCII
//! bytes become `\xNN`) and capped, so a hostile caller can neither forge
//! another field nor fill the audit record. A value read is quoted, and a cut
//! value ends in `…` after the closing quote: escaped text is pure ASCII, so
//! neither the quotes nor the marker can come from the caller's bytes. A value
//! that could not be read, or was read from a process the pin no longer names,
//! is the bare word `unavailable`.

use bstr::ByteSlice;

use crate::proc::parse_stat;
use crate::source::ProcSource;

/// How much of the executable's path is recorded, before escaping. Short of
/// `PATH_MAX` on purpose: escaped and then JSON-encoded, each byte can take
/// five, and the three hints together stay under 8 KiB of the 64 KiB record.
pub const HINT_EXE_MAX: usize = 1024;
/// How much of the command line is recorded, before escaping.
pub const HINT_CMDLINE_MAX: usize = 512;
/// How much of `CLAUDECODE`'s value is recorded. Never more of the environment.
pub const HINT_CLAUDECODE_MAX: usize = 32;

/// What a value that could not be read records.
const UNAVAILABLE: &str = "unavailable";

/// The rendered hints for one process. Built only from what was read; read
/// only by [`Self::evidence`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerHints {
    exe: String,
    cmdline: String,
    claudecode: String,
}

impl CallerHints {
    /// Hints for a process that could not be read, or was not pinned.
    pub fn unavailable() -> Self {
        Self {
            exe: UNAVAILABLE.to_owned(),
            cmdline: UNAVAILABLE.to_owned(),
            claudecode: UNAVAILABLE.to_owned(),
        }
    }

    /// Renders the three reads: the target of `exe`, the bytes of `cmdline`,
    /// and the bytes of `environ`. A read that failed is `unavailable`, never a
    /// failure of anything else.
    pub fn from_reads(exe: Option<&[u8]>, cmdline: Option<&[u8]>, environ: Option<&[u8]>) -> Self {
        Self {
            exe: exe.map_or_else(|| UNAVAILABLE.to_owned(), |link| quoted(link, HINT_EXE_MAX)),
            cmdline: cmdline.map_or_else(
                || UNAVAILABLE.to_owned(),
                |bytes| quoted(bytes.strip_suffix(b"\0").unwrap_or(bytes), HINT_CMDLINE_MAX),
            ),
            claudecode: environ.map_or_else(|| UNAVAILABLE.to_owned(), claudecode),
        }
    }

    /// The audit lines, in a fixed order.
    pub fn evidence(&self) -> [String; 3] {
        [
            format!("hint_exe={}", self.exe),
            format!("hint_cmdline={}", self.cmdline),
            format!("hint_claudecode={}", self.claudecode),
        ]
    }
}

/// `"<escaped>"`, cut to `max` bytes first, with `…` after a cut.
fn quoted(bytes: &[u8], max: usize) -> String {
    let (kept, cut) = bytes.split_at_checked(max).unwrap_or((bytes, &[]));
    let marker = if cut.is_empty() { "" } else { "\u{2026}" };
    format!("\"{}\"{marker}", kept.escape_ascii())
}

/// Whether `environ` sets `CLAUDECODE`, and the start of its value. Nothing
/// else of the environment is kept.
fn claudecode(environ: &[u8]) -> String {
    environ
        .split_str("\0")
        .find_map(|entry| entry.strip_prefix(b"CLAUDECODE="))
        .map_or_else(
            || "unset".to_owned(),
            |value| quoted(value, HINT_CLAUDECODE_MAX),
        )
}

/// The hints of the process pinned as `(pid, starttime)`, read through
/// `source`.
///
/// The three files are read by number, then `stat` is read again: unless it
/// still names `pid` with the pinned start time, the reads may have come from
/// another process that took the number, and every hint is `unavailable`.
pub fn pinned_hints(source: &dyn ProcSource, pid: u32, starttime: u64) -> CallerHints {
    let exe = source.read_link(&format!("{pid}/exe")).ok();
    let cmdline = source.read(&format!("{pid}/cmdline")).ok();
    let environ = source.read(&format!("{pid}/environ")).ok();
    let path = format!("{pid}/stat");
    let still_pinned = source
        .read(&path)
        .and_then(|bytes| parse_stat(&path, &bytes))
        .is_ok_and(|stat| stat.pid == pid && stat.starttime == starttime);
    if still_pinned {
        CallerHints::from_reads(exe.as_deref(), cmdline.as_deref(), environ.as_deref())
    } else {
        CallerHints::unavailable()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use proptest::prelude::*;

    use super::*;
    use crate::source::MapSource;

    fn stat(pid: u32, starttime: u64) -> String {
        let mut tail: Vec<String> = vec!["S".into(), "1".into()];
        for _ in 0..17 {
            tail.push("0".to_owned());
        }
        tail.push(starttime.to_string());
        format!("{pid} (claude) {}", tail.join(" "))
    }

    fn lines(hints: &CallerHints) -> Vec<String> {
        hints.evidence().to_vec()
    }

    #[test]
    fn a_read_peer_records_its_exe_cmdline_and_claudecode() {
        let hints = CallerHints::from_reads(
            Some(b"/usr/bin/claude"),
            Some(b"claude\0--print\0"),
            Some(b"HOME=/root\0CLAUDECODE=1\0SECRET=hunter2\0"),
        );
        assert_eq!(
            lines(&hints),
            [
                "hint_exe=\"/usr/bin/claude\"",
                "hint_cmdline=\"claude\\x00--print\"",
                "hint_claudecode=\"1\"",
            ]
        );
    }

    #[test]
    fn nothing_of_the_environment_but_claudecode_is_recorded() {
        let hints = CallerHints::from_reads(
            None,
            None,
            Some(b"AWS_SECRET_ACCESS_KEY=hunter2\0NOTCLAUDECODE=2\0"),
        );
        let rendered = lines(&hints).join(" ");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("hint_claudecode=unset"), "{rendered}");
    }

    #[test]
    fn a_long_claudecode_value_keeps_only_its_first_32_bytes() {
        let value = format!("CLAUDECODE={}TAIL", "a".repeat(HINT_CLAUDECODE_MAX));
        let hints = CallerHints::from_reads(None, None, Some(value.as_bytes()));
        assert_eq!(
            lines(&hints)[2],
            format!("hint_claudecode=\"{}\"\u{2026}", "a".repeat(32))
        );
    }

    #[test]
    fn a_huge_cmdline_is_cut_and_marked() {
        let argv = vec![b'x'; 1 << 20];
        let hints = CallerHints::from_reads(Some(&argv), Some(&argv), Some(&argv));
        let [exe, cmdline, _] = hints.evidence();
        assert_eq!(
            cmdline,
            format!("hint_cmdline=\"{}\"\u{2026}", "x".repeat(512))
        );
        assert_eq!(exe.len(), "hint_exe=\"\"\u{2026}".len() + HINT_EXE_MAX);
    }

    #[test]
    fn a_cmdline_ending_in_dots_is_not_mistaken_for_a_cut() {
        let hints = CallerHints::from_reads(None, Some(b"claude..."), None);
        assert_eq!(lines(&hints)[1], "hint_cmdline=\"claude...\"");
    }

    #[test]
    fn a_cmdline_posing_as_another_field_is_escaped_inside_its_quotes() {
        let hints = CallerHints::from_reads(
            Some(b"/x\" via=harness\n"),
            Some(b"unavailable\"\x1b[2J\xff"),
            None,
        );
        let [exe, cmdline, claudecode] = hints.evidence();
        assert_eq!(exe, "hint_exe=\"/x\\\" via=harness\\n\"");
        assert_eq!(cmdline, "hint_cmdline=\"unavailable\\\"\\x1b[2J\\xff\"");
        assert_eq!(claudecode, "hint_claudecode=unavailable");
    }

    #[test]
    fn an_unreadable_peer_records_unavailable() {
        assert_eq!(
            lines(&CallerHints::unavailable()),
            [
                "hint_exe=unavailable",
                "hint_cmdline=unavailable",
                "hint_claudecode=unavailable",
            ]
        );
        assert_eq!(
            CallerHints::from_reads(None, None, None),
            CallerHints::unavailable()
        );
    }

    fn peer(starttime_after: u64) -> MapSource {
        MapSource::new()
            .with_link("7/exe", "/usr/bin/claude")
            .with("7/cmdline", "claude\0")
            .with("7/environ", "CLAUDECODE=1\0")
            .with("7/stat", stat(7, starttime_after))
    }

    #[test]
    fn a_pinned_peer_records_what_was_read() {
        assert_eq!(
            lines(&pinned_hints(&peer(500), 7, 500)),
            [
                "hint_exe=\"/usr/bin/claude\"",
                "hint_cmdline=\"claude\"",
                "hint_claudecode=\"1\"",
            ]
        );
    }

    #[test]
    fn a_recycled_pid_gives_no_hints_of_the_process_that_took_the_number() {
        // The number now names a process that started later: what was read
        // is someone else's.
        assert_eq!(pinned_hints(&peer(501), 7, 500), CallerHints::unavailable());
    }

    #[test]
    fn a_vanished_peer_records_unavailable() {
        let gone = MapSource::new().with_link("7/exe", "/usr/bin/claude");
        assert_eq!(pinned_hints(&gone, 7, 500), CallerHints::unavailable());
        let wrong_pid = peer(500).with("7/stat", stat(8, 500));
        assert_eq!(pinned_hints(&wrong_pid, 7, 500), CallerHints::unavailable());
    }

    proptest! {
        #[test]
        fn hint_lines_stay_bounded_and_ascii_for_any_bytes(
            exe in proptest::collection::vec(any::<u8>(), 0..6000),
            cmdline in proptest::collection::vec(any::<u8>(), 0..2000),
            value in proptest::collection::vec(any::<u8>(), 0..200),
        ) {
            let mut environ = b"CLAUDECODE=".to_vec();
            environ.extend(value.iter().filter(|b| **b != 0));
            let hints = CallerHints::from_reads(Some(&exe), Some(&cmdline), Some(&environ));
            let total: usize = hints.evidence().iter().map(String::len).sum();
            // Four bytes per escaped byte, plus prefixes, quotes and markers.
            prop_assert!(total < 4 * (HINT_EXE_MAX + HINT_CMDLINE_MAX + HINT_CLAUDECODE_MAX) + 128);
            for line in hints.evidence() {
                let body = line.trim_end_matches('\u{2026}');
                prop_assert!(body.is_ascii(), "{line}");
                prop_assert!(!body.contains('\n'), "{line}");
            }
        }
    }
}
