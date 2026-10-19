//! Verifying that a log has not been edited.
//!
//! `aido audit` runs [`verify_log`]. It answers one question — has anything
//! in this log changed since it was written — and it answers it precisely,
//! naming the position where the chain first stops matching rather than saying
//! "invalid".

use crate::record::{Record, Sequence};
use crate::tail::{TailError, continuation_of};

/// Where and how a chain stopped being consistent.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainError {
    /// A record's hash no longer covers its own contents.
    #[error("record {seq} was edited: its hash no longer covers its contents")]
    Edited {
        /// The position.
        seq: u64,
    },
    /// A record does not follow the one before it.
    ///
    /// The signature of a **deletion**: remove a record and the next one's
    /// `prev_hash` points at something no longer there.
    #[error(
        "record {seq} does not follow record {expected_seq}: its prev_hash points at \
         {found_prev}, but that record hashes to {expected_prev}. A record was removed \
         or reordered"
    )]
    Broken {
        /// The position that does not follow.
        seq: u64,
        /// The position before it.
        expected_seq: u64,
        /// What the record claims its predecessor hashed to.
        found_prev: String,
        /// What the predecessor actually hashes to.
        expected_prev: String,
    },
    /// Positions are not consecutive.
    #[error("record {seq} follows record {previous}: the sequence skips or repeats")]
    OutOfOrder {
        /// The position found.
        seq: u64,
        /// The position before it.
        previous: u64,
    },
    /// The first record claims a predecessor.
    #[error(
        "the first record claims a predecessor hashing to {prev_hash}; the log has been \
         truncated from the front"
    )]
    TruncatedFront {
        /// What it claims.
        prev_hash: String,
    },
    /// A record uses a schema this build cannot read.
    #[error("record {seq} uses schema version {found}; this build reads version {supported}")]
    UnknownSchema {
        /// The position.
        seq: u64,
        /// Its version.
        found: u32,
        /// What this build supports.
        supported: u32,
    },
}

/// A verified chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    records: Vec<Record>,
}

impl Chain {
    /// Starts an empty chain.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Appends a record built to follow the current tail.
    ///
    /// Takes the decision fields rather than a finished record, so a caller
    /// cannot append one whose `prev_hash` points somewhere else.
    /// Returns the position it was given. Read the record itself back with
    /// [`Self::records`] if you need it — returning a reference here would mean
    /// re-fetching a tail that was just pushed, and the "what if it is missing"
    /// branch that comes with it can never be exercised.
    pub fn append(
        &mut self,
        decision: crate::record::Decision,
        argv: Vec<String>,
        classification: impl Into<String>,
    ) -> Sequence {
        let record = Record::after(self.records.last(), decision, argv, classification);
        let seq = record.seq;
        self.records.push(record);
        seq
    }

    /// The records, in order.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// How many records the chain holds.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Renders the whole chain as JSON lines.
    ///
    /// Infallible, for the same reason [`Record::to_jsonl`] is.
    pub fn to_jsonl(&self) -> String {
        let mut out = String::new();
        for record in &self.records {
            out.push_str(&record.to_jsonl());
            out.push('\n');
        }
        out
    }

    /// Parses and verifies a log.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] naming the first position that does not hold, or a
    /// `serde_json` error for a line that is not a record.
    pub fn from_jsonl(text: &str) -> Result<Self, ChainReadError> {
        Self::from_jsonl_bytes(text.as_bytes())
    }

    /// [`Self::from_jsonl`] for a log read as bytes, as a file is.
    ///
    /// A line that is not UTF-8 is a line that is not a record, reported by
    /// its number — not a file that cannot be read. Lines split at `\n`, as a
    /// writer finds them; a `\r` before it is blank space to the parser, as it
    /// is to [`str::lines`].
    ///
    /// # Errors
    ///
    /// As [`Self::from_jsonl`].
    pub fn from_jsonl_bytes(log: &[u8]) -> Result<Self, ChainReadError> {
        let mut records = Vec::new();
        for (index, line) in log.split(|byte| *byte == b'\n').enumerate() {
            if std::str::from_utf8(line).is_ok_and(is_blank) {
                continue;
            }
            let record: Record =
                serde_json::from_slice(line).map_err(|source| ChainReadError::Malformed {
                    line: index.saturating_add(1),
                    reason: source.to_string(),
                })?;
            records.push(record);
        }
        verify(&records).map_err(ChainReadError::Inconsistent)?;
        Ok(Self { records })
    }
}

/// Verifies a whole log the way `aido audit` does: every record, in order,
/// then the end of the log as a privileged writer reads it.
///
/// The second half is what keeps the verifier and the writer from
/// disagreeing. A writer reads only the end of the log; every ending it
/// refuses, this reports — through the records when the damage is a record,
/// and through [`continuation_of`], the writer's own function on the writer's
/// own window, when it is not: a log that ends in more than
/// [`crate::TAIL_WINDOW`] bytes without a complete line verifies record by
/// record, and is still a log no privileged writer will continue.
///
/// # Errors
///
/// [`LogError::Chain`] for the first record that does not parse or does not
/// follow; [`LogError::End`] when every record does and the end is one a
/// writer refuses.
pub fn verify_log(log: &[u8]) -> Result<Chain, LogError> {
    let chain = Chain::from_jsonl_bytes(log)?;
    continuation_of(log)?;
    Ok(chain)
}

/// Why a log does not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// A record does not parse, or the chain does not hold.
    #[error(transparent)]
    Chain(#[from] ChainReadError),
    /// Every record verifies, and the end of the log is one a privileged
    /// writer refuses to continue from.
    #[error(
        "every record verifies, but a privileged writer refuses to continue from the end of the \
         log: {0}"
    )]
    End(#[from] TailError),
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

/// A log that could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChainReadError {
    /// A line was not a record.
    #[error("line {line} is not an audit record: {reason}")]
    Malformed {
        /// The 1-based line.
        line: usize,
        /// Why.
        reason: String,
    },
    /// The records parsed but the chain does not hold.
    #[error(transparent)]
    Inconsistent(#[from] ChainError),
}

/// Verifies that `records` form an unbroken chain.
///
/// An empty log is valid: nothing has happened yet, which is different from
/// something having been removed.
///
/// # Errors
///
/// Returns the **first** inconsistency, because that is where the tampering
/// starts; everything after it is a consequence rather than independent
/// evidence.
pub fn verify(records: &[Record]) -> Result<(), ChainError> {
    let mut previous: Option<&Record> = None;

    for record in records {
        follows(previous, record)?;
        previous = Some(record);
    }

    Ok(())
}

/// Whether `record` may stand where it does: directly after `previous`, or
/// first in a log when `previous` is `None`.
///
/// The one check behind [`verify`] and behind a writer about to append, so a
/// writer can never put down a record the verifier would reject at that
/// position: the two share this function rather than two copies of the rule.
///
/// # Errors
///
/// The same [`ChainError`] that [`verify`] reports for this position.
pub fn follows(previous: Option<&Record>, record: &Record) -> Result<(), ChainError> {
    if record.schema_version != crate::record::RECORD_SCHEMA_VERSION {
        return Err(ChainError::UnknownSchema {
            seq: record.seq.get(),
            found: record.schema_version,
            supported: crate::record::RECORD_SCHEMA_VERSION,
        });
    }
    if !record.is_sealed() {
        return Err(ChainError::Edited {
            seq: record.seq.get(),
        });
    }

    match previous {
        None => {
            if !record.prev_hash.is_empty() {
                return Err(ChainError::TruncatedFront {
                    prev_hash: record.prev_hash.clone(),
                });
            }
            if record.seq != Sequence::first() {
                return Err(ChainError::OutOfOrder {
                    seq: record.seq.get(),
                    previous: 0,
                });
            }
        }
        Some(prior) => {
            if record.seq != prior.seq.next() {
                return Err(ChainError::OutOfOrder {
                    seq: record.seq.get(),
                    previous: prior.seq.get(),
                });
            }
            if record.prev_hash != prior.hash {
                return Err(ChainError::Broken {
                    seq: record.seq.get(),
                    expected_seq: prior.seq.get(),
                    found_prev: record.prev_hash.clone(),
                    expected_prev: prior.hash.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Whether a line of a log is blank.
///
/// Every reader skips blank lines — [`Chain::from_jsonl`] and a writer looking
/// for the record to continue from — and they share this predicate so a stray
/// newline is never damage to one and a record boundary to the other.
pub(crate) fn is_blank(line: &str) -> bool {
    line.trim().is_empty()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::record::{Decision, Outcome};

    fn chain_of(n: usize) -> Chain {
        let mut chain = Chain::new();
        for i in 0..n {
            chain.append(Decision::Allowed, vec![format!("cmd{i}")], "unattested");
        }
        chain
    }

    #[test]
    fn an_empty_log_is_valid_because_nothing_has_happened() {
        // Different from something having been removed, and the distinction
        // matters: a fresh install must not look tampered with.
        let chain = Chain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(verify(chain.records()).is_ok());
        assert_eq!(chain.to_jsonl(), "");
        assert_eq!(Chain::default(), Chain::new());
    }

    #[test]
    fn a_chain_links_each_record_to_the_one_before() {
        let chain = chain_of(4);
        assert_eq!(chain.len(), 4);
        verify(chain.records()).unwrap();
        for pair in chain.records().windows(2) {
            assert_eq!(pair[1].prev_hash, pair[0].hash);
            assert_eq!(pair[1].seq.get(), pair[0].seq.get() + 1);
        }
        assert!(format!("{chain:?}").contains("cmd0"));
    }

    #[test]
    fn appending_always_follows_the_current_tail() {
        // The reason `append` takes fields rather than a finished record: a
        // caller cannot hand over one whose prev_hash points elsewhere.
        let mut chain = chain_of(2);
        let seq = chain.append(Decision::Denied, vec!["x".to_owned()], "human");
        assert_eq!(seq.get(), 3);
        let appended = chain.records().last().unwrap();
        assert_eq!(appended.prev_hash, chain.records()[1].hash);
        verify(chain.records()).unwrap();
    }

    #[test]
    fn an_outcome_is_a_record_of_its_own_and_filling_one_in_is_tampering() {
        // The log is append-only. The child's exit status, learnt after the
        // authorization was written, is a new record after it; written into
        // the authorization instead, it is an edit, and the verifier says so.
        // That is why `Chain` has no way to replace its tail.
        let chain = chain_of(2);
        let mut records = chain.records().to_vec();
        let outcome = Record::after(
            records.last(),
            Decision::Allowed,
            records[1].argv.clone(),
            "unattested",
        )
        .with_outcome(Outcome::Exited { code: 0 });
        records.push(outcome);
        verify(&records).unwrap();

        let mut filled_in = chain.records().to_vec();
        filled_in[1].outcome = Outcome::Exited { code: 0 };
        assert_eq!(verify(&filled_in), Err(ChainError::Edited { seq: 2 }));
    }

    #[test]
    fn editing_a_record_in_the_middle_is_detected_at_that_record() {
        // The whole claim of the crate.
        let mut records = chain_of(5).records().to_vec();
        records[2].argv.push("smuggled".to_owned());
        assert_eq!(verify(&records), Err(ChainError::Edited { seq: 3 }));
        assert!(
            verify(&records)
                .unwrap_err()
                .to_string()
                .contains("no longer covers its contents")
        );
    }

    #[test]
    fn resealing_an_edited_record_still_breaks_the_chain_after_it() {
        // The more careful attack: edit a record *and* fix its own hash. The
        // next record's prev_hash no longer matches, so the break simply moves
        // one position later.
        let mut records = chain_of(5).records().to_vec();
        records[2].argv.push("smuggled".to_owned());
        records[2] = records[2].clone().with_evidence(Vec::new()); // reseals
        assert!(records[2].is_sealed());
        // Asserted on the message, so there is no arm for a variant this
        // assertion never sees.
        let message = verify(&records).unwrap_err().to_string();
        assert!(
            message.starts_with("record 4 does not follow record 3"),
            "{message}"
        );
        assert!(message.contains("removed or reordered"), "{message}");
    }

    #[test]
    fn deleting_a_record_is_detected_as_a_broken_link() {
        // A deletion leaves no gap in the file, only in the chain.
        let mut records = chain_of(5).records().to_vec();
        records.remove(2);
        let err = verify(&records).unwrap_err();
        // The sequence jump is noticed first, which is the more specific
        // complaint.
        assert_eq!(
            err,
            ChainError::OutOfOrder {
                seq: 4,
                previous: 2
            }
        );
        assert!(err.to_string().contains("skips or repeats"), "{err}");
    }

    #[test]
    fn reordering_two_records_is_detected() {
        let mut records = chain_of(4).records().to_vec();
        records.swap(1, 2);
        assert!(verify(&records).is_err());
    }

    #[test]
    fn truncating_the_front_is_detected_rather_than_looking_like_a_fresh_log() {
        // Without this check, dropping the first N records would produce a log
        // that verifies cleanly and hides everything before it.
        let mut records = chain_of(4).records().to_vec();
        records.remove(0);
        let err = verify(&records).unwrap_err();
        assert!(
            err.to_string().contains("truncated from the front"),
            "{err}"
        );
    }

    #[test]
    fn a_first_record_with_the_wrong_sequence_is_rejected() {
        let mut records = chain_of(2).records().to_vec();
        records.remove(0);
        records[0].prev_hash = String::new();
        let resealed = records[0].clone().with_evidence(Vec::new());
        records[0] = resealed;
        assert_eq!(
            verify(&records),
            Err(ChainError::OutOfOrder {
                seq: 2,
                previous: 0
            })
        );
    }

    #[test]
    fn a_record_from_a_future_schema_is_refused_rather_than_misread() {
        let mut records = chain_of(2).records().to_vec();
        records[0].schema_version = 99;
        let err = verify(&records).unwrap_err();
        assert_eq!(
            err,
            ChainError::UnknownSchema {
                seq: 1,
                found: 99,
                supported: crate::record::RECORD_SCHEMA_VERSION,
            }
        );
        assert!(err.to_string().contains("this build reads version"));
    }

    #[test]
    fn a_log_round_trips_through_json_lines() {
        let chain = chain_of(3);
        let text = chain.to_jsonl();
        assert_eq!(text.lines().count(), 3);
        let parsed = Chain::from_jsonl(&text).unwrap();
        assert_eq!(parsed, chain);
    }

    #[test]
    fn blank_lines_in_a_log_are_tolerated() {
        // A partially-flushed write or a hand-edited file should not be
        // unreadable for a reason as trivial as whitespace.
        let chain = chain_of(2);
        let text = format!("\n{}\n\n", chain.to_jsonl());
        assert_eq!(Chain::from_jsonl(&text).unwrap().len(), 2);
    }

    #[test]
    fn a_line_that_is_not_a_record_names_its_line_number() {
        let chain = chain_of(2);
        let text = format!("{}not a record\n", chain.to_jsonl());
        let err = Chain::from_jsonl(&text).unwrap_err();
        assert!(
            err.to_string().starts_with("line 3 is not an audit record"),
            "{err}"
        );
    }

    #[test]
    fn a_writer_checks_one_link_with_the_rule_the_verifier_uses() {
        // `follows` is `verify` for one position: a record built after the
        // tail passes, and one that ignores the tail fails exactly as the
        // verifier would fail it there.
        let chain = chain_of(2);
        let tail = chain.records().last();
        let next = Record::after(tail, Decision::Denied, vec!["x".to_owned()], "human");
        assert_eq!(follows(tail, &next), Ok(()));
        assert_eq!(follows(None, &chain.records()[0]), Ok(()));

        let restart = Record::first(Decision::Allowed, vec!["x".to_owned()], "human");
        assert_eq!(
            follows(tail, &restart),
            Err(ChainError::OutOfOrder {
                seq: 1,
                previous: 2
            })
        );
        let mut both = chain.records().to_vec();
        both.push(restart);
        assert_eq!(
            verify(&both).unwrap_err(),
            follows(tail, &both[2]).unwrap_err()
        );
    }

    #[test]
    fn a_torn_final_record_is_reported_by_the_verifier_at_its_line() {
        // What a crash mid-write leaves. `aido audit` runs this function,
        // through `verify_log`, so the damage a privileged writer refuses to
        // continue past is damage the verifier names.
        let text = chain_of(3).to_jsonl();
        let torn = &text[..text.len().saturating_sub(20)];
        let err = Chain::from_jsonl(torn).unwrap_err();
        assert!(
            err.to_string().starts_with("line 3 is not an audit record"),
            "{err}"
        );
        // A complete last record missing only its newline is not damage.
        assert_eq!(Chain::from_jsonl(text.trim_end()).unwrap().len(), 3);
    }

    #[test]
    fn a_line_that_is_not_text_is_named_by_its_number_not_hidden_as_an_unreadable_file() {
        // What a filesystem leaves behind a crash, or what someone with the
        // file wrote. Read as text, the whole log was "unreadable" and the
        // damage had no position; read as bytes, it is a line like any other.
        let mut log = chain_of(2).to_jsonl().into_bytes();
        log.extend_from_slice(b"\xff\xfe{}\n");
        let err = Chain::from_jsonl_bytes(&log).unwrap_err();
        assert!(
            err.to_string().starts_with("line 3 is not an audit record"),
            "{err}"
        );
        assert!(verify_log(&log).is_err());
    }

    #[test]
    fn reading_bytes_and_reading_text_find_the_same_chain() {
        // Including the line endings `str::lines` forgives.
        let crlf = chain_of(3).to_jsonl().replace('\n', "\r\n");
        let from_text = Chain::from_jsonl(&crlf).unwrap();
        assert_eq!(from_text.len(), 3);
        assert_eq!(Chain::from_jsonl_bytes(crlf.as_bytes()).unwrap(), from_text);
        assert_eq!(verify_log(crlf.as_bytes()).unwrap(), from_text);
    }

    #[test]
    fn the_verifier_reports_the_first_bad_record_before_the_end_of_the_log() {
        let mut records = chain_of(3).records().to_vec();
        records[0].argv.push("smuggled".to_owned());
        let mut text = String::new();
        for record in &records {
            text.push_str(&record.to_jsonl());
            text.push('\n');
        }
        let err = verify_log(text.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            LogError::Chain(ChainReadError::Inconsistent(ChainError::Edited { seq: 1 }))
        );
        assert!(err.to_string().starts_with("record 1 was edited"), "{err}");
        let end = LogError::End(TailError::Edited { seq: 2 });
        assert!(
            end.to_string()
                .starts_with("every record verifies, but a privileged writer refuses"),
            "{end}"
        );
        assert_eq!(end.clone(), end);
    }

    #[test]
    fn reading_a_tampered_log_reports_the_inconsistency() {
        let mut records = chain_of(3).records().to_vec();
        records[1].classification = "enrolled-agent".to_owned();
        let text = records
            .iter()
            .map(Record::to_jsonl)
            .collect::<Vec<_>>()
            .join("\n");
        let message = Chain::from_jsonl(&text).unwrap_err().to_string();
        assert!(message.starts_with("record 2 was edited"), "{message}");
    }
}
