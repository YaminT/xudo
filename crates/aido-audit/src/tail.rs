//! Where a writer picks a chain up.
//!
//! A privileged writer appends to a log it has not read in full: reading every
//! record on every request would make each decision cost the whole history of
//! the machine. So it reads the end of the log, finds the last record, and
//! builds the next one after it. This module is that step, pure, so every shape
//! a damaged log can end in is a test case rather than a disk image.
//!
//! # What a writer refuses, and why it never starts over
//!
//! A log whose end is not a record a writer can continue from is **damage**:
//! a write that did not finish (a crash, a full disk), a last line someone
//! edited, bytes that are not a record at all, or an end so long without a
//! complete line that the record before it is out of the window. A writer
//! stops there. It does not append after the damage, because the new record
//! would follow a predecessor nobody can read; and it does not start a new
//! chain, because a fresh `seq 1` after the damage would make everything before
//! it unverifiable while looking like an ordinary log. The repair is a
//! person's: move the log aside, which starts a new chain *deliberately* and
//! keeps the damaged one as evidence.
//!
//! The verifier agrees by construction. [`crate::verify_log`] — what
//! `aido audit` runs — checks every record and then asks [`continuation_of`]
//! about the end of the log, which reads the same window through the same
//! function a writer does. So every ending a writer refuses, the verifier
//! reports: as the line, when the damage is a line, and as the writer's own
//! refusal when it is not. A writer reads only the end; damage further back is
//! the verifier's alone to find.
//!
//! One shape is not damage: a complete, sealed last record missing only its
//! newline. Nothing in it is lost, the verifier reads it, and the writer begins
//! its own record on a new line rather than refusing every request over one
//! missing byte.
//!
//! # What it cannot see
//!
//! A log cut back at a record boundary ends in a perfectly good record, and a
//! log cut back to nothing — or to blank lines — holds no record at all.
//! Nothing in the file can tell the first from a log that simply stopped there,
//! or the second from a new one, so a writer continues the first and starts a
//! fresh chain at `seq 1` in the second, silently. Both need root or a disk
//! fault. Only a comparison with the journal entries root sent, which carry
//! each record's `seq` and hash, could show either, and no tool makes it yet.

use crate::chain::is_blank;
use crate::record::{RECORD_SCHEMA_VERSION, Record};

/// The longest line a writer appends.
///
/// A bound rather than a convenience: it is what lets a writer find the last
/// record by reading a fixed window from the end, and what keeps the journal
/// copy of a record inside one datagram. A request whose record would be
/// longer is refused by the writer, before anything is written.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// How much of the end of a log a writer reads to find its last record.
///
/// Twice the longest record, so the newline before the last record always
/// falls inside the window and the record is read whole.
pub const TAIL_WINDOW: usize = 128 * 1024;

// The arithmetic a writer relies on, checked when the crate compiles: the
// longest record, its own newline, and the newline ending the record before
// it all fit in the window.
const _: () = assert!(TAIL_WINDOW >= MAX_RECORD_BYTES.saturating_mul(2));

/// What a writer continues from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Continuation {
    /// The last record in the log, or `None` for a log with none yet.
    pub last: Option<Record>,
    /// Whether the log's last byte is not a newline, so the next record must
    /// begin with one.
    pub needs_newline: bool,
}

/// Why the end of a log is not something a writer may continue from.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TailError {
    /// No complete line in the window: the last line is longer than any record
    /// a writer puts down, or the end of the log is that much blank space.
    #[error(
        "the last {window} bytes hold no complete record line — one line longer than any record \
         a writer puts down, or that much blank space — so the record to follow is out of a \
         writer's sight"
    )]
    Overlong {
        /// The size of the window that was read.
        window: usize,
    },
    /// The last line is not a record.
    #[error(
        "the last line is not an audit record ({reason}): the write that produced it did not \
         finish, or it was changed afterwards"
    )]
    NotARecord {
        /// Why it did not parse.
        reason: String,
    },
    /// The last record is from a schema this build does not write.
    #[error(
        "the last record, {seq}, uses schema version {found}; this build continues version \
         {supported} only"
    )]
    UnknownSchema {
        /// Its position.
        seq: u64,
        /// Its version.
        found: u32,
        /// The version this build writes.
        supported: u32,
    },
    /// The last record's hash no longer covers its contents.
    #[error("the last record, {seq}, was edited: its hash no longer covers its contents")]
    Edited {
        /// Its position.
        seq: u64,
    },
}

/// Where the window a writer reads begins, in a log `len` bytes long: the last
/// [`TAIL_WINDOW`] bytes, or all of it when it is shorter.
///
/// One function for the writer reading a file and for [`continuation_of`], so
/// the two cannot read different windows.
pub fn window_start(len: u64) -> u64 {
    len.saturating_sub(u64::try_from(TAIL_WINDOW).unwrap_or(u64::MAX))
}

/// What a writer finds at the end of `log`, a whole log held in memory:
/// [`continuation`] over the window a writer reads from the file.
///
/// The verifier's half of the agreement described in the module docs.
///
/// # Errors
///
/// As [`continuation`].
pub fn continuation_of(log: &[u8]) -> Result<Continuation, TailError> {
    let len = u64::try_from(log.len()).unwrap_or(u64::MAX);
    let start = usize::try_from(window_start(len)).unwrap_or(0);
    continuation(log.get(start..).unwrap_or_default(), start == 0)
}

/// Finds the record a writer continues from in `window`, the last bytes of a
/// log.
///
/// `whole` says whether `window` is the entire log. When it is not, the first
/// line in the window may be the tail end of a longer one, so it is never taken
/// for a record.
///
/// # Errors
///
/// A [`TailError`] for every ending that is damage; see the module docs.
pub fn continuation(window: &[u8], whole: bool) -> Result<Continuation, TailError> {
    let needs_newline = window.last().is_some_and(|byte| *byte != b'\n');
    let lines: Vec<&[u8]> = window.split(|byte| *byte == b'\n').collect();

    for (index, line) in lines.iter().enumerate().rev() {
        if std::str::from_utf8(line).is_ok_and(is_blank) {
            continue;
        }
        if index == 0 && !whole {
            return Err(TailError::Overlong {
                window: window.len(),
            });
        }
        return last_record(line).map(|record| Continuation {
            last: Some(record),
            needs_newline,
        });
    }

    if whole {
        Ok(Continuation {
            last: None,
            needs_newline,
        })
    } else {
        Err(TailError::Overlong {
            window: window.len(),
        })
    }
}

/// Parses the last line, and refuses a record a writer must not follow.
fn last_record(line: &[u8]) -> Result<Record, TailError> {
    let record: Record = serde_json::from_slice(line).map_err(|source| TailError::NotARecord {
        reason: source.to_string(),
    })?;
    if record.schema_version != RECORD_SCHEMA_VERSION {
        return Err(TailError::UnknownSchema {
            seq: record.seq.get(),
            found: record.schema_version,
            supported: RECORD_SCHEMA_VERSION,
        });
    }
    if !record.is_sealed() {
        return Err(TailError::Edited {
            seq: record.seq.get(),
        });
    }
    Ok(record)
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

    use super::*;
    use crate::chain::Chain;
    use crate::record::Decision;

    fn log_of(n: usize) -> (Chain, String) {
        let mut chain = Chain::new();
        for i in 0..n {
            chain.append(Decision::Allowed, vec![format!("cmd{i}")], "human");
        }
        let text = chain.to_jsonl();
        (chain, text)
    }

    #[test]
    fn an_empty_log_starts_a_chain() {
        // A fresh install, or a log an operator moved aside on purpose.
        let found = continuation(b"", true).unwrap();
        assert_eq!(
            found,
            Continuation {
                last: None,
                needs_newline: false
            }
        );
    }

    #[test]
    fn a_writer_continues_from_the_last_record() {
        let (chain, text) = log_of(3);
        let found = continuation(text.as_bytes(), true).unwrap();
        assert_eq!(found.last.as_ref(), chain.records().last());
        assert!(!found.needs_newline);
    }

    #[test]
    fn the_last_record_is_found_in_a_window_that_starts_mid_line() {
        // The writer reads the end of a long log; the first line of the window
        // is the tail of some earlier record and must never be parsed.
        let (chain, text) = log_of(4);
        let window = &text.as_bytes()[10..];
        let found = continuation(window, false).unwrap();
        assert_eq!(found.last.as_ref(), chain.records().last());
    }

    #[test]
    fn a_line_longer_than_the_window_is_refused_rather_than_read_in_part() {
        // A window holding only the end of one line: whatever it parses as,
        // it is not the record the line began with.
        let (_, text) = log_of(1);
        let window = &text.as_bytes()[5..];
        assert_eq!(
            continuation(window, false),
            Err(TailError::Overlong {
                window: window.len()
            })
        );
        // And a window of nothing but blank lines from the middle of a log.
        assert_eq!(
            continuation(b"\n\n  \n", false),
            Err(TailError::Overlong { window: 5 })
        );
    }

    #[test]
    fn a_torn_last_record_is_refused_rather_than_continued_or_restarted() {
        // A crash or a full disk mid-write. Appending after it would chain a
        // new record onto a predecessor nobody can read; starting a new chain
        // would make the history before it unverifiable.
        let (_, text) = log_of(3);
        let torn = &text.as_bytes()[..text.len().saturating_sub(30)];
        let err = continuation(torn, true).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("the last line is not an audit record"),
            "{err}"
        );
        // The verifier names the same damage.
        assert!(Chain::from_jsonl(std::str::from_utf8(torn).unwrap()).is_err());
    }

    #[test]
    fn bytes_that_are_not_text_are_damage_not_a_blank_line() {
        // What a filesystem leaves in a file whose size reached the disk before
        // its data did.
        // Asserted on the message rather than through `matches!`, which would
        // leave an arm in this file that only a failing test could reach.
        let (_, mut text) = log_of(2);
        text.push_str("\0\0\0\0");
        let zeroes = continuation(text.as_bytes(), true).unwrap_err();
        assert!(
            zeroes.to_string().contains("not an audit record"),
            "{zeroes}"
        );
        let mut invalid = log_of(1).1.into_bytes();
        invalid.extend_from_slice(&[0xff, 0xfe, b'\n']);
        let binary = continuation(&invalid, true).unwrap_err();
        assert!(
            binary.to_string().contains("not an audit record"),
            "{binary}"
        );
    }

    #[test]
    fn a_complete_record_missing_only_its_newline_is_continued_on_a_new_line() {
        // Nothing is lost and the verifier reads it, so refusing every request
        // over one byte would be a denial of service with no evidence behind it.
        let (chain, text) = log_of(2);
        let found = continuation(text.trim_end().as_bytes(), true).unwrap();
        assert_eq!(found.last.as_ref(), chain.records().last());
        assert!(found.needs_newline);
    }

    #[test]
    fn trailing_blank_lines_are_skipped_as_the_verifier_skips_them() {
        let (chain, text) = log_of(2);
        let padded = format!("{text}\n  \n\n");
        let found = continuation(padded.as_bytes(), true).unwrap();
        assert_eq!(found.last.as_ref(), chain.records().last());
        assert!(!found.needs_newline);
        assert_eq!(Chain::from_jsonl(&padded).unwrap().len(), 2);
        // A log of nothing but blank lines holds no records, for both readers.
        assert_eq!(continuation(b"\n \n", true).unwrap().last, None);
        assert!(continuation(b" ", true).unwrap().needs_newline);
    }

    #[test]
    fn an_edited_last_record_is_refused() {
        let (chain, _) = log_of(2);
        let mut records = chain.records().to_vec();
        records[1].argv.push("smuggled".to_owned());
        let text = format!("{}\n{}\n", records[0].to_jsonl(), records[1].to_jsonl());
        assert_eq!(
            continuation(text.as_bytes(), true),
            Err(TailError::Edited { seq: 2 })
        );
    }

    #[test]
    fn a_last_record_from_another_schema_is_refused_rather_than_misread() {
        let (chain, _) = log_of(1);
        let mut record = chain.records()[0].clone();
        record.schema_version = 99;
        let err = continuation(format!("{}\n", record.to_jsonl()).as_bytes(), true).unwrap_err();
        assert_eq!(
            err,
            TailError::UnknownSchema {
                seq: 1,
                found: 99,
                supported: RECORD_SCHEMA_VERSION
            }
        );
        assert!(err.to_string().contains("continues version 1 only"));
    }

    /// A record whose line is `len` bytes or a little more.
    fn record_of_length(previous: Option<&crate::Record>, len: usize) -> crate::Record {
        crate::Record::after(previous, Decision::Denied, vec!["z".repeat(len)], "human")
    }

    #[test]
    fn the_writer_and_the_verifier_agree_on_every_ending() {
        // A writer that refuses a log the verifier calls intact sends an
        // operator to a tool that says nothing is wrong; one that accepts a log
        // the verifier rejects vouches for damage. `verify_log` asks the
        // writer's own question about the end, so the two answer alike.
        let (chain, text) = log_of(2);
        let mut edited = chain.records().to_vec();
        edited[1].argv.push("smuggled".to_owned());
        let mut foreign = chain.records()[1].clone();
        foreign.schema_version = 99;
        let last = chain.records().last();
        let long_ok = record_of_length(last, MAX_RECORD_BYTES + 1000).to_jsonl();
        let too_long = record_of_length(last, TAIL_WINDOW + 10).to_jsonl();

        let endings: Vec<(&str, Vec<u8>, bool)> = vec![
            ("empty", Vec::new(), true),
            ("intact", text.clone().into_bytes(), true),
            (
                "blank lines after",
                format!("{text}\n \n").into_bytes(),
                true,
            ),
            (
                "no final newline",
                text.trim_end().as_bytes().to_vec(),
                true,
            ),
            (
                "a line over the record bound, inside the window",
                format!("{text}{long_ok}\n").into_bytes(),
                true,
            ),
            ("torn", text.as_bytes()[..text.len() - 30].to_vec(), false),
            (
                "edited",
                format!("{}\n{}\n", edited[0].to_jsonl(), edited[1].to_jsonl()).into_bytes(),
                false,
            ),
            (
                "foreign schema",
                format!(
                    "{}\n{}\n",
                    chain.records()[0].to_jsonl(),
                    foreign.to_jsonl()
                )
                .into_bytes(),
                false,
            ),
            ("not text", [text.as_bytes(), b"\xff\xfe\n"].concat(), false),
            (
                "blank space past the window",
                [text.as_bytes(), &vec![b' '; TAIL_WINDOW + 10], b"\n"].concat(),
                false,
            ),
            (
                "a line past the window",
                format!("{text}{too_long}\n").into_bytes(),
                false,
            ),
        ];
        for (name, log, continuable) in endings {
            let writer = continuation_of(&log);
            let verifier = crate::verify_log(&log);
            assert_eq!(writer.is_ok(), continuable, "writer, {name}: {writer:?}");
            assert_eq!(verifier.is_ok(), continuable, "verifier, {name}");
        }
    }

    #[test]
    fn an_end_with_no_line_in_sight_is_reported_by_the_verifier_as_the_writer_refuses_it() {
        // Every record verifies, so only the writer's question can catch it:
        // the verifier now asks it and gives the writer's answer.
        let (_, text) = log_of(2);
        let log = [text.as_bytes(), &vec![b' '; TAIL_WINDOW + 10], b"\n"].concat();
        let refusal = TailError::Overlong {
            window: TAIL_WINDOW,
        };
        assert_eq!(continuation_of(&log), Err(refusal.clone()));
        assert_eq!(crate::verify_log(&log), Err(crate::LogError::End(refusal)));
        assert!(Chain::from_jsonl_bytes(&log).is_ok());
    }

    #[test]
    fn the_window_is_the_last_bytes_of_the_log_or_all_of_it() {
        let window = TAIL_WINDOW as u64;
        assert_eq!(window_start(0), 0);
        assert_eq!(window_start(window), 0);
        assert_eq!(window_start(window + 7), 7);
    }

    #[test]
    fn every_refusal_says_what_was_found() {
        for err in [
            TailError::Overlong { window: 9 },
            TailError::NotARecord {
                reason: "EOF".to_owned(),
            },
            TailError::UnknownSchema {
                seq: 1,
                found: 2,
                supported: 1,
            },
            TailError::Edited { seq: 4 },
        ] {
            assert!(err.to_string().len() > 30, "{err}");
            assert_eq!(err.clone(), err);
        }
    }
}
