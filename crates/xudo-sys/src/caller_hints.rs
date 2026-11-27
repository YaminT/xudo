//! The hints about a caller that go in the audit trail and nowhere else.
//!
//! A caller's `comm`, its executable path, its command line and whether it
//! exported `CLAUDECODE` are all its own to choose (invariant 1). They are recorded so
//! an operator reading the trail can see who claimed to be what, and nothing
//! may decide on them: [`CallerHints`] has no accessor and its `Debug` prints
//! no value, only [`CallerHints::evidence`] renders the audit lines.
//!
//! What is kept is little on purpose. Of the command line, `argv[0]`, the
//! argument count and the length, and no digest: a digest of a short secret
//! confirms a guess offline, and a password typed on a command line must not
//! reach the audit trail or the journal. `argv[0]` is the caller's own, and
//! bounded: a process that rewrote its title as one string with no
//! terminator shows that whole string as `argv[0]`. Of the environment, only
//! whether `CLAUDECODE` is set, and whether to exactly `1`. Both files are looked at in their first
//! [`HINT_READ_MAX`] bytes only, and the broker reads no more than that.
//!
//! Every text is escaped (`escape_ascii`, so control characters and non-ASCII
//! bytes become `\xNN`) and capped, so a hostile caller can neither forge
//! another field nor fill the audit record. A text read is quoted, and a cut
//! text ends in `…` after the closing quote: escaped text is pure ASCII, so
//! neither the quotes nor the marker can come from the caller's bytes. A file
//! that could not be read, or was read from a process the pin no longer
//! names, is the bare word `unavailable`.

use std::fmt;

use bstr::ByteSlice;

use crate::peer::{PeerCalls, ProcFile};
use crate::proc::parse_stat;
use crate::source::ProcSource;

/// How much of the executable's path is recorded, before escaping. Short of
/// `PATH_MAX` on purpose: escaped and then JSON-encoded, each byte can take
/// five, and the hints together stay under 8 KiB of the 64 KiB record.
pub const HINT_EXE_MAX: usize = 1024;
/// How much of `argv[0]` is recorded, before escaping.
pub const HINT_ARGV0_MAX: usize = 256;
/// How much of `comm` is recorded, before escaping. The kernel keeps 15
/// bytes; this only bounds what a seam could hand over.
pub const HINT_COMM_MAX: usize = 64;
/// How much of `cmdline` and of `environ` is looked at. The broker reads one
/// byte more, to tell a file of exactly this size from a longer one.
pub const HINT_READ_MAX: usize = 64 * 1024;

/// What a value that could not be read records.
const UNAVAILABLE: &str = "unavailable";

/// The rendered hints for one process. Built only from what was read; read
/// only by [`Self::evidence`].
#[derive(Clone, PartialEq, Eq)]
pub struct CallerHints {
    exe: String,
    cmdline: String,
    claudecode: String,
    comm: Option<String>,
}

impl fmt::Debug for CallerHints {
    // No value: a decision that formats what it holds learns nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallerHints { .. }")
    }
}

impl CallerHints {
    /// Hints for a process that could not be read, or was not pinned.
    pub fn unavailable() -> Self {
        Self {
            exe: UNAVAILABLE.to_owned(),
            cmdline: UNAVAILABLE.to_owned(),
            claudecode: UNAVAILABLE.to_owned(),
            comm: None,
        }
    }

    /// Renders the three reads: the target of `exe`, the bytes of `cmdline`,
    /// and the bytes of `environ`. A read that failed is `unavailable`, never a
    /// failure of anything else.
    pub fn from_reads(exe: Option<&[u8]>, cmdline: Option<&[u8]>, environ: Option<&[u8]>) -> Self {
        Self {
            exe: exe.map_or_else(|| UNAVAILABLE.to_owned(), |link| quoted(link, HINT_EXE_MAX)),
            cmdline: cmdline.map_or_else(|| UNAVAILABLE.to_owned(), command_line),
            claudecode: environ.map_or_else(|| UNAVAILABLE.to_owned(), claudecode),
            comm: None,
        }
    }

    /// The same hints with the `comm` the broker read from `stat`, recorded
    /// as `hint_comm`. The gate records none.
    #[must_use]
    pub fn with_comm(mut self, comm: &[u8]) -> Self {
        self.comm = Some(quoted(comm, HINT_COMM_MAX));
        self
    }

    /// The audit lines, in a fixed order: `hint_comm` first when there is
    /// one.
    pub fn evidence(&self) -> Vec<String> {
        let comm = self.comm.as_ref().map(|comm| format!("hint_comm={comm}"));
        comm.into_iter()
            .chain([
                format!("hint_exe={}", self.exe),
                format!("hint_cmdline={}", self.cmdline),
                format!("hint_claudecode={}", self.claudecode),
            ])
            .collect()
    }
}

/// The first `max` bytes, and whether anything was left over.
fn cut(bytes: &[u8], max: usize) -> (&[u8], bool) {
    let (kept, rest) = bytes.split_at_checked(max).unwrap_or((bytes, &[]));
    (kept, !rest.is_empty())
}

/// `"<escaped>"`, cut to `max` bytes first, with `…` after a cut.
fn quoted(bytes: &[u8], max: usize) -> String {
    let (kept, was_cut) = cut(bytes, max);
    let marker = if was_cut { "\u{2026}" } else { "" };
    format!("\"{}\"{marker}", kept.escape_ascii())
}

/// `argv0:"<argv[0]>" argc:N len:N` of the first [`HINT_READ_MAX`] bytes,
/// with `+` after the count and the length when the file was longer. Nothing
/// past the first terminator: no argument's text and no digest of one.
fn command_line(bytes: &[u8]) -> String {
    let (window, was_cut) = cut(bytes, HINT_READ_MAX);
    let argv = window.strip_suffix(b"\0").unwrap_or(window);
    let argv0 = argv.split_once_str("\0").map_or(argv, |(first, _)| first);
    let count = if window.is_empty() {
        0
    } else {
        argv.find_iter("\0").count().saturating_add(1)
    };
    let more = if was_cut { "+" } else { "" };
    format!(
        "argv0:{} argc:{count}{more} len:{}{more}",
        quoted(argv0, HINT_ARGV0_MAX),
        window.len()
    )
}

/// Whether `environ` sets `CLAUDECODE`: `unset`, `set:"1"` for exactly `1`,
/// else `set:other(len=N)`. No value but `1` is ever recorded. An entry the
/// window cuts short has `+` after its length.
fn claudecode(environ: &[u8]) -> String {
    let (window, was_cut) = cut(environ, HINT_READ_MAX);
    let open_tail = was_cut && !window.ends_with(b"\0");
    let entries: Vec<&[u8]> = window.split_str("\0").collect();
    let last = entries.len().saturating_sub(1);
    entries
        .iter()
        .enumerate()
        .find_map(|(at, entry)| {
            entry
                .strip_prefix(b"CLAUDECODE=")
                .map(|value| (value, open_tail && at == last))
        })
        .map_or_else(
            || "unset".to_owned(),
            |found| match found {
                (b"1", false) => "set:\"1\"".to_owned(),
                (value, partial) => {
                    let more = if partial { "+" } else { "" };
                    format!("set:other(len={}{more})", value.len())
                }
            },
        )
}

/// The hints of the broker's peer `pid`, read through the seam while its
/// pidfd holds it. The caller re-checks the pidfd afterwards. A file that
/// cannot be read is `unavailable` and never fails anything: nothing decides
/// on a hint. The seam reads `cmdline` and `environ` only to a bound.
pub fn peer_hints(peers: &dyn PeerCalls, pid: u32) -> CallerHints {
    let exe = peers.read_proc(pid, ProcFile::Exe).ok();
    let cmdline = peers.read_proc(pid, ProcFile::Cmdline).ok();
    let environ = peers.read_proc(pid, ProcFile::Environ).ok();
    CallerHints::from_reads(exe.as_deref(), cmdline.as_deref(), environ.as_deref())
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
        hints.evidence()
    }

    fn three(hints: &CallerHints) -> [String; 3] {
        hints.evidence().try_into().unwrap()
    }

    #[test]
    fn a_read_peer_records_its_exe_argv0_and_claudecode() {
        let hints = CallerHints::from_reads(
            Some(b"/usr/bin/claude"),
            Some(b"claude\0--print\0"),
            Some(b"HOME=/root\0CLAUDECODE=1\0SECRET=hunter2\0"),
        );
        assert_eq!(
            lines(&hints),
            [
                "hint_exe=\"/usr/bin/claude\"".to_owned(),
                "hint_cmdline=argv0:\"claude\" argc:2 len:15".to_owned(),
                "hint_claudecode=set:\"1\"".to_owned(),
            ]
        );
    }

    #[test]
    fn a_password_on_the_command_line_is_never_recorded() {
        let cmdline = b"/usr/bin/mysql\0-uroot\0--password=hunter2\0";
        let hints = CallerHints::from_reads(None, Some(cmdline), None);
        let rendered = lines(&hints).join(" ");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("root\""), "{rendered}");
        assert_eq!(
            lines(&hints)[1],
            format!(
                "hint_cmdline=argv0:\"/usr/bin/mysql\" argc:3 len:{}",
                cmdline.len()
            )
        );
    }

    #[test]
    fn a_guessed_password_cannot_be_confirmed_from_the_record() {
        // With a digest, a journal reader who knows argv[0], the count and
        // the length could test guesses offline. Two command lines that differ
        // only in a secret of the same length must render the same.
        let right = CallerHints::from_reads(None, Some(b"mysql\0--password=hunter2\0"), None);
        let guess = CallerHints::from_reads(None, Some(b"mysql\0--password=letmein\0"), None);
        assert_eq!(right, guess);
        assert_eq!(
            lines(&right)[1],
            "hint_cmdline=argv0:\"mysql\" argc:2 len:25"
        );
    }

    #[test]
    fn an_empty_or_unterminated_cmdline_is_counted_as_it_is() {
        // A kernel thread or a zombie shows nothing; a process that rewrote
        // its title may show one string with no terminator, and that string,
        // arguments and all, is its argv[0]: its own choice, and bounded.
        let empty = CallerHints::from_reads(None, Some(b""), None);
        assert_eq!(lines(&empty)[1], "hint_cmdline=argv0:\"\" argc:0 len:0");
        let title = CallerHints::from_reads(None, Some(b"sshd: alice"), None);
        assert_eq!(
            lines(&title)[1],
            "hint_cmdline=argv0:\"sshd: alice\" argc:1 len:11"
        );
        let blank = CallerHints::from_reads(None, Some(b"\0"), None);
        assert_eq!(lines(&blank)[1], "hint_cmdline=argv0:\"\" argc:1 len:1");
    }

    #[test]
    fn nothing_of_the_environment_but_claudecodes_presence_is_recorded() {
        let hints = CallerHints::from_reads(
            None,
            None,
            Some(b"AWS_SECRET_ACCESS_KEY=hunter2\0NOTCLAUDECODE=1\0"),
        );
        let rendered = lines(&hints).join(" ");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("hint_claudecode=unset"), "{rendered}");
    }

    #[test]
    fn a_claudecode_other_than_one_records_only_its_length() {
        for (environ, want) in [
            (&b"CLAUDECODE=hunter2\0"[..], "set:other(len=7)"),
            (b"CLAUDECODE=\0", "set:other(len=0)"),
            (b"CLAUDECODE=11", "set:other(len=2)"),
            (b"CLAUDECODE=1\0CLAUDECODE=2\0", "set:\"1\""),
            (b"CLAUDECODE=0\0CLAUDECODE=1\0", "set:other(len=1)"),
        ] {
            let hints = CallerHints::from_reads(None, None, Some(environ));
            assert_eq!(lines(&hints)[2], format!("hint_claudecode={want}"));
        }
    }

    #[test]
    fn only_the_first_window_of_the_environment_is_looked_at() {
        let mut environ = vec![b'x'; HINT_READ_MAX];
        environ.extend(b"\0CLAUDECODE=1\0");
        let hints = CallerHints::from_reads(None, None, Some(&environ));
        assert_eq!(lines(&hints)[2], "hint_claudecode=unset");
        // An entry the window cuts short is a length, and a lower bound.
        let mut tail = vec![b'x'; HINT_READ_MAX - 12];
        tail.extend(b"\0CLAUDECODE=1234");
        let hints = CallerHints::from_reads(None, None, Some(&tail));
        assert_eq!(lines(&hints)[2], "hint_claudecode=set:other(len=0+)");
        // A window that ends on a terminator holds whole entries.
        let mut whole = vec![b'x'; HINT_READ_MAX - 14];
        whole.extend(b"\0CLAUDECODE=1\0tail");
        let hints = CallerHints::from_reads(None, None, Some(&whole));
        assert_eq!(lines(&hints)[2], "hint_claudecode=set:\"1\"");
    }

    #[test]
    fn a_huge_cmdline_is_summarized_from_its_first_window() {
        let mut argv = vec![b'x'; 300];
        argv.push(0);
        argv.extend(std::iter::repeat_n(b"a\0".as_slice(), 1 << 16).flatten());
        let path = vec![b'x'; 5000];
        let hints = CallerHints::from_reads(Some(&path), Some(&argv), Some(&argv));
        let [exe, cmdline, claudecode] = three(&hints);
        let window = argv.get(..HINT_READ_MAX).unwrap();
        assert_eq!(
            cmdline,
            format!(
                "hint_cmdline=argv0:\"{}\"\u{2026} argc:{}+ len:{HINT_READ_MAX}+",
                "x".repeat(HINT_ARGV0_MAX),
                window.find_iter("\0").count() + 1
            )
        );
        assert_eq!(exe.len(), "hint_exe=\"\"\u{2026}".len() + HINT_EXE_MAX);
        assert_eq!(claudecode, "hint_claudecode=unset");
    }

    #[test]
    fn an_exe_ending_in_dots_is_not_mistaken_for_a_cut() {
        let hints = CallerHints::from_reads(Some(b"/opt/claude..."), None, None);
        assert_eq!(lines(&hints)[0], "hint_exe=\"/opt/claude...\"");
    }

    #[test]
    fn a_hint_posing_as_another_field_is_escaped_inside_its_quotes() {
        let hints = CallerHints::from_reads(
            Some(b"/x\" via=harness\n"),
            Some(b"unavailable\" argc:0\x1b[2J\xff\0-p\0"),
            None,
        );
        let [exe, cmdline, claudecode] = three(&hints);
        assert_eq!(exe, "hint_exe=\"/x\\\" via=harness\\n\"");
        assert!(
            cmdline.starts_with(
                "hint_cmdline=argv0:\"unavailable\\\" argc:0\\x1b[2J\\xff\" argc:2 len:"
            ),
            "{cmdline}"
        );
        assert_eq!(claudecode, "hint_claudecode=unavailable");
    }

    #[test]
    fn a_comm_is_quoted_capped_and_first_and_the_gate_records_none() {
        let hints = CallerHints::from_reads(Some(b"/usr/bin/xudo"), None, None);
        assert_eq!(lines(&hints).len(), 3);
        let named = hints.clone().with_comm(b"unavailable\" via=harness\n");
        assert_eq!(
            lines(&named),
            [
                "hint_comm=\"unavailable\\\" via=harness\\n\"",
                "hint_exe=\"/usr/bin/xudo\"",
                "hint_cmdline=unavailable",
                "hint_claudecode=unavailable",
            ]
        );
        let long = CallerHints::unavailable().with_comm(&[b'c'; HINT_COMM_MAX + 1]);
        assert_eq!(
            lines(&long)[0],
            format!("hint_comm=\"{}\"\u{2026}", "c".repeat(HINT_COMM_MAX))
        );
        assert_eq!(
            format!("{named:?}"),
            "CallerHints { .. }",
            "the comm shows in Debug no more than the rest"
        );
    }

    #[test]
    fn the_debug_form_shows_no_hint() {
        let hints = CallerHints::from_reads(
            Some(b"/usr/bin/claude"),
            Some(b"claude\0"),
            Some(b"CLAUDECODE=1\0"),
        );
        let shown = format!("{hints:?} {:?}", CallerHints::unavailable());
        assert_eq!(shown, "CallerHints { .. } CallerHints { .. }");
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

    #[test]
    fn a_broker_peer_is_read_through_the_seam_and_a_missing_file_is_unavailable() {
        let peers =
            crate::peer::FakePeer::new().with_proc(7, ProcFile::Exe, b"/usr/bin/claude".to_vec());
        assert_eq!(
            lines(&peer_hints(&peers, 7)),
            [
                "hint_exe=\"/usr/bin/claude\"",
                "hint_cmdline=unavailable",
                "hint_claudecode=unavailable",
            ]
        );
        assert_eq!(peer_hints(&peers, 8), CallerHints::unavailable());
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
                "hint_exe=\"/usr/bin/claude\"".to_owned(),
                "hint_cmdline=argv0:\"claude\" argc:1 len:7".to_owned(),
                "hint_claudecode=set:\"1\"".to_owned(),
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
            let named = hints.clone().with_comm(&exe);
            let total: usize = named.evidence().iter().map(String::len).sum();
            // Four bytes per escaped byte, plus prefixes, counts and markers.
            prop_assert!(total < 4 * (HINT_EXE_MAX + HINT_ARGV0_MAX + HINT_COMM_MAX) + 256);
            for line in named.evidence() {
                prop_assert!(line.replace('\u{2026}', "").is_ascii(), "{line}");
                prop_assert!(!line.contains('\n'), "{line}");
            }
            // No argument after the first, and no value but `1`, survives.
            let [_, rendered_cmdline, rendered_env] = three(&hints);
            // After argv[0], only the count and the length: no digest.
            let tail = rendered_cmdline.rsplit_once(" argc:").map_or("", |(_, tail)| tail);
            let numbers: Vec<&str> = tail.split(" len:").collect();
            prop_assert_eq!(numbers.len(), 2, "{}", rendered_cmdline);
            for number in numbers {
                let digits = number.strip_suffix('+').unwrap_or(number);
                prop_assert!(
                    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
                    "{}",
                    rendered_cmdline
                );
            }
            prop_assert!(
                rendered_env == "hint_claudecode=set:\"1\""
                    || rendered_env.starts_with("hint_claudecode=set:other(len="),
                "{rendered_env}"
            );
        }
    }
}
