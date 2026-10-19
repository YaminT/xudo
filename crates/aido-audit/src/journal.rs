//! A record, as journald's native protocol carries it.
//!
//! The journal is the trail's mirror, never its authority. The chain lives in
//! the file, because only a file has a last record to continue from; what the
//! journal adds is a second copy, outside the file, queryable by field:
//!
//! ```text
//! journalctl _UID=0 MESSAGE_ID=a06b36c755dd4b85815d6af790559b5e AIDO_DECISION=denied
//! ```
//!
//! # Only entries root sent count
//!
//! Every field a client sends is the client's to choose, and any local user can
//! send a datagram to journald's socket. So anyone can put an entry in the
//! journal carrying aido's [`MESSAGE_ID`], `PRIORITY=1`, and every `AIDO_*`
//! field — enough to fire an alert, bury one, or offer a second chain to
//! whatever compares the journal with the file. What a client cannot choose is
//! `_UID`: journald takes it from the credentials the kernel attaches to the
//! datagram (`SCM_CREDENTIALS`), and no unprivileged process can claim uid 0.
//! So every query, alert rule, and cross-check starts from [`query`], which
//! matches on [`TRUSTED_SENDER`], and an entry that does not pass it is not an
//! aido audit entry, whatever it says.
//!
//! `_EXE`, `_COMM`, and `_SYSTEMD_UNIT` cannot narrow it further. journald
//! reads them from `/proc` after the datagram arrives, not from the kernel when
//! it was sent, and the gate exits as soon as it has refused and will exec as
//! soon as it has recorded. Measured against systemd 257's journald, from root:
//! of 300 entries whose sender exited at once, 299 had no `_EXE`; of 300 whose
//! sender exec'd another program at once, 86 named that program. A query
//! filtered on them would lose the gate's alerts, the entries it most needs.
//! What `_UID=0` leaves in is root, which can rewrite the file as easily as it
//! can send an entry: the journal is a copy to compare against, never proof.
//!
//! Pure, like the rest of this crate: it builds the bytes. Sending them is
//! `aido-sys`'s job.
//!
//! # The wire format
//!
//! systemd's native protocol (`systemd.io/JOURNAL_NATIVE_PROTOCOL`): one
//! datagram carries every field of one entry. A field whose value holds no
//! newline is `NAME=value\n`; one whose value does is `NAME\n`, the value's
//! length as a little-endian `u64`, the value, and `\n`. Names are upper-case
//! ASCII letters, digits, and underscores, begin with a letter, and never with
//! `_`, which is reserved for the fields journald attests itself (`_PID`,
//! `_UID`, `_COMM`), so a sender cannot forge who sent it.
//!
//! # What an entry holds
//!
//! * `MESSAGE` — one line for a person. It quotes agent-influenced text, so it
//!   goes through `term-sanitize`: no escape sequences, no bidirectional
//!   overrides, no control characters, bounded width. Display only; nothing
//!   compares it.
//! * `PRIORITY` — 5 (notice) for an authorization, 4 (warning) for a refusal,
//!   and 1 (alert) for a refusal recorded with [`HIGH_SEVERITY`] evidence: the
//!   gate's mark for a refusal that only happens when someone is trying
//!   something. sudo makes the same split, logging a permitted command at notice
//!   and a refused one at alert. An alert rule matches `PRIORITY=1` inside
//!   [`query`], never `PRIORITY` and `MESSAGE_ID` alone: anyone can send those.
//! * `SYSLOG_FACILITY=10` (authpriv), `SYSLOG_IDENTIFIER` (the binary that
//!   wrote it), and [`MESSAGE_ID`], shared by every aido audit entry. All three
//!   are the sender's claims.
//! * `AIDO_*` index fields for queries, and `AIDO_RECORD`: the record's JSON line
//!   exactly as the file holds it, so the entries [`query`] finds can be
//!   checked against the file record by record — as long as journald kept each
//!   one, since it drops what exceeds its rate limit without telling the
//!   sender. No tool makes that comparison yet.
//!
//! An index value longer than [`INDEX_FIELD_MAX`] is left out — the record
//! carries it whole. That is what keeps an entry inside one datagram: the
//! record is bounded by [`crate::tail::MAX_RECORD_BYTES`] and everything else
//! here is bounded by construction, so the encoder never needs journald's
//! out-of-band `memfd` path.

use term_sanitize::{Limits, display_str};

use crate::record::{Decision, Outcome, Record};

/// The `MESSAGE_ID` of every aido audit entry.
///
/// A fixed 128-bit identifier, as journald's catalog convention asks, so one
/// query finds every entry from every aido binary and nothing else.
pub const MESSAGE_ID: &str = "a06b36c755dd4b85815d6af790559b5e";

/// The match an entry must pass to count as an aido audit entry: sent by
/// uid 0.
///
/// The one field of an entry the sender cannot choose and journald does not
/// guess at later: it comes from the kernel's credentials on the datagram. See
/// the module docs for why nothing narrower can be relied on.
pub const TRUSTED_SENDER: &str = "_UID=0";

/// The `journalctl` command that finds aido's audit entries, narrowed by
/// `extra` matches such as `AIDO_DECISION=denied` or `PRIORITY=1`.
///
/// Every query, alert rule, and comparison with the file starts here, so none
/// of them counts an entry an unprivileged user sent.
pub fn query(extra: &[&str]) -> String {
    let message_id = format!("MESSAGE_ID={MESSAGE_ID}");
    let mut words = vec!["journalctl", TRUSTED_SENDER, message_id.as_str()];
    words.extend_from_slice(extra);
    words.join(" ")
}

/// The evidence entry that marks a refusal worth waking someone for.
///
/// Written by the gate as `severity=<label>`; the label is `aido-gate`'s
/// `Severity::High`, and a test in `aido-sys` checks the two still meet.
pub const HIGH_SEVERITY: &str = "severity=high";

/// The longest value an `AIDO_*` index field carries.
pub const INDEX_FIELD_MAX: usize = 512;

/// The most bytes one entry is allowed to take.
///
/// Below the smallest datagram a stock Linux host accepts on a Unix socket
/// (the default socket send buffer, about 208 KiB), with room to spare. The
/// largest entry a bounded record produces is around 70 KiB.
pub const PAYLOAD_MAX: usize = 96 * 1024;

/// Width of the `MESSAGE` line, in characters.
const MESSAGE_COLUMNS: usize = 1024;

/// syslog's authpriv facility: security and authorization messages.
const FACILITY_AUTHPRIV: &str = "10";

/// Why a record cannot become one journal entry.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JournalError {
    /// The entry would not fit in one datagram.
    #[error("the journal entry would be {size} bytes; one datagram carries at most {max}")]
    TooLarge {
        /// What it would have been.
        size: usize,
        /// The bound.
        max: usize,
    },
}

/// The datagram journald receives for `record`, written by `identifier`.
///
/// # Errors
///
/// [`JournalError::TooLarge`] for a record too big for one datagram. A writer
/// never produces one — it refuses a record over the line limit before writing
/// anything — but this function is public and says so rather than truncate.
pub fn datagram(record: &Record, identifier: &str) -> Result<Vec<u8>, JournalError> {
    let mut payload = Vec::new();
    for (name, value) in fields(record, identifier) {
        push_field(&mut payload, name, value.as_bytes());
    }
    if payload.len() > PAYLOAD_MAX {
        return Err(JournalError::TooLarge {
            size: payload.len(),
            max: PAYLOAD_MAX,
        });
    }
    Ok(payload)
}

/// The fields of the journal entry for `record`, in the order they are sent.
pub fn fields(record: &Record, identifier: &str) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("MESSAGE", summary(record)),
        ("PRIORITY", priority(record).to_owned()),
        ("SYSLOG_FACILITY", FACILITY_AUTHPRIV.to_owned()),
        ("SYSLOG_IDENTIFIER", identifier.to_owned()),
        ("MESSAGE_ID", MESSAGE_ID.to_owned()),
        ("AIDO_SCHEMA_VERSION", record.schema_version.to_string()),
        ("AIDO_SEQ", record.seq.get().to_string()),
        ("AIDO_HASH", record.hash.clone()),
        ("AIDO_PREV_HASH", record.prev_hash.clone()),
        ("AIDO_DECISION", record.decision.as_str().to_owned()),
        ("AIDO_OUTCOME", record.outcome.kind().to_owned()),
    ];
    let indexed = [
        ("AIDO_CLASSIFICATION", Some(record.classification.as_str())),
        ("AIDO_DENIAL", record.denial.as_deref()),
        ("AIDO_ACTION", record.action.as_deref()),
        ("AIDO_RULE_SOURCE", record.rule_source.as_deref()),
        ("AIDO_PROGRAM", record.argv.first().map(String::as_str)),
    ];
    for (name, value) in indexed {
        if let Some(value) = value.filter(|value| value.len() <= INDEX_FIELD_MAX) {
            fields.push((name, value.to_owned()));
        }
    }
    fields.push(("AIDO_RECORD", record.to_jsonl()));
    fields
}

/// The syslog priority of a record.
fn priority(record: &Record) -> &'static str {
    match record.decision {
        Decision::Denied if record.evidence.iter().any(|item| item == HIGH_SEVERITY) => "1",
        Decision::Denied => "4",
        Decision::Allowed | Decision::AwaitingConfirmation => "5",
    }
}

/// The one line a person reads.
///
/// The argv is rendered as a JSON array and every other value with Rust's
/// debug escapes, so argument boundaries stay visible and a newline anywhere
/// shows as `\n` instead of starting a second log line or cutting this one
/// short. Then the whole line goes through `term-sanitize`, which removes what
/// those escapes leave alone (C1 controls, bidirectional overrides, invisible
/// characters) and bounds the width. When it had to change anything, the line
/// says so, and says where the exact text is.
fn summary(record: &Record) -> String {
    let argv = serde_json::to_string(&record.argv).unwrap_or_default();
    let mut context = vec![format!("caller {}", shown(&record.classification))];
    context.extend(
        record
            .action
            .as_deref()
            .map(|action| format!("action {}", shown(action))),
    );
    context.extend(
        record
            .rule_source
            .as_deref()
            .map(|source| format!("rule {}", shown(source))),
    );
    context.extend(
        record
            .denial
            .as_deref()
            .map(|code| format!("refused {}", shown(code))),
    );
    context.extend(outcome_phrase(&record.outcome));
    context.push(format!("audit seq {}", record.seq.get()));

    let line = format!(
        "{}: {argv} ({})",
        record.decision.as_str(),
        context.join(", ")
    );
    let clean = display_str(&line, Limits::single_line(MESSAGE_COLUMNS));
    if clean.is_suspect() {
        format!("{} [display sanitized; AIDO_RECORD is exact]", clean.text)
    } else {
        clean.text
    }
}

/// A value quoted in the summary, with newlines and control characters
/// escaped rather than acted on.
fn shown(value: &str) -> String {
    value.escape_debug().to_string()
}

/// What happened, for a record written after the fact.
fn outcome_phrase(outcome: &Outcome) -> Option<String> {
    match outcome {
        Outcome::NotExecuted => None,
        Outcome::Exited { code } => Some(format!("exited {code}")),
        Outcome::Signalled { signal } => Some(format!("killed by signal {signal}")),
        Outcome::Failed { reason } => Some(format!("failed to start: {}", shown(reason))),
    }
}

/// Appends one field in the native protocol's framing.
fn push_field(payload: &mut Vec<u8>, name: &str, value: &[u8]) {
    payload.extend_from_slice(name.as_bytes());
    if value.contains(&b'\n') {
        payload.push(b'\n');
        let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
        payload.extend_from_slice(&length.to_le_bytes());
    } else {
        payload.push(b'=');
    }
    payload.extend_from_slice(value);
    payload.push(b'\n');
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
    use crate::record::Decision;

    fn allowed() -> Record {
        Record::first(
            Decision::Allowed,
            vec![
                "/usr/bin/systemctl".to_owned(),
                "restart".to_owned(),
                "nginx.service".to_owned(),
            ],
            "human",
        )
        .with_rule("aido.svc.restart", "20-services.toml:15")
    }

    fn value_of(fields: &[(&'static str, String)], name: &str) -> Option<String> {
        fields
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn a_forged_entry_from_an_unprivileged_sender_fails_every_documented_query() {
        // Any local user can send an entry with aido's MESSAGE_ID, PRIORITY=1,
        // and every AIDO_* field: a real journald stored one from uid 1000 and
        // the query without `_UID=0` returned it. So the query an operator is
        // told to run, and every alert rule built on it, matches on the one
        // field journald takes from the kernel.
        assert_eq!(
            query(&["AIDO_DECISION=denied"]),
            "journalctl _UID=0 MESSAGE_ID=a06b36c755dd4b85815d6af790559b5e AIDO_DECISION=denied"
        );
        assert_eq!(
            query(&[]),
            "journalctl _UID=0 MESSAGE_ID=a06b36c755dd4b85815d6af790559b5e"
        );
        // A client cannot send the field the query trusts: journald drops a
        // client field whose name starts with `_`, and the encoder sends none.
        assert!(TRUSTED_SENDER.starts_with("_UID="));
        let record = allowed();
        assert!(
            fields(&record, "aidod")
                .iter()
                .all(|(name, _)| !name.starts_with('_'))
        );
    }

    #[test]
    fn the_query_in_the_module_docs_is_the_one_the_code_renders() {
        // A query copied from the docs is the one people run; it must not
        // drift from the one the tests pin.
        let source = include_str!("journal.rs");
        let documented = format!("//! {}\n", query(&["AIDO_DECISION=denied"]));
        assert!(source.contains(&documented), "{documented}");
    }

    #[test]
    fn every_field_name_is_one_journald_accepts_from_a_client() {
        // Upper-case letters, digits, and underscores, starting with a letter,
        // at most 64 bytes. A leading `_` is a field journald attests itself,
        // and it drops a client's attempt to send one.
        let record = allowed()
            .with_denial("deny_listed")
            .with_outcome(Outcome::Exited { code: 0 });
        for (name, _) in fields(&record, "aidod") {
            assert!(name.len() <= 64, "{name}");
            assert!(name.as_bytes()[0].is_ascii_uppercase(), "{name}");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{name}"
            );
        }
    }

    #[test]
    fn the_journal_copy_carries_the_file_line_byte_for_byte() {
        // So the journal alone can reproduce the chain, and a cut-back file
        // can be caught against it.
        let record = allowed();
        let fields = fields(&record, "aidod");
        assert_eq!(value_of(&fields, "AIDO_RECORD"), Some(record.to_jsonl()));
        assert_eq!(value_of(&fields, "AIDO_SEQ").as_deref(), Some("1"));
        assert_eq!(value_of(&fields, "AIDO_HASH"), Some(record.hash.clone()));
        assert_eq!(value_of(&fields, "AIDO_PREV_HASH").as_deref(), Some(""));
        assert_eq!(
            value_of(&fields, "SYSLOG_IDENTIFIER").as_deref(),
            Some("aidod")
        );
        assert_eq!(value_of(&fields, "MESSAGE_ID").as_deref(), Some(MESSAGE_ID));
        assert_eq!(
            value_of(&fields, "AIDO_PROGRAM").as_deref(),
            Some("/usr/bin/systemctl")
        );
        // A field the record does not have is absent, not empty.
        assert_eq!(value_of(&fields, "AIDO_DENIAL"), None);
    }

    #[test]
    fn a_refusal_that_means_an_attempt_is_an_alert_and_an_ordinary_one_a_warning() {
        let refused = Record::first(Decision::Denied, Vec::new(), "unattested")
            .with_denial("gate_no_pending_request");
        assert_eq!(priority(&refused), "4");
        let ordinary = refused
            .clone()
            .with_evidence(vec!["severity=normal".to_owned()]);
        assert_eq!(priority(&ordinary), "4");
        let attempt = refused.with_evidence(vec![
            "gate_caller_pid=7".to_owned(),
            HIGH_SEVERITY.to_owned(),
        ]);
        assert_eq!(priority(&attempt), "1");
        assert_eq!(priority(&allowed()), "5");
        let confirmed = Record::first(Decision::AwaitingConfirmation, Vec::new(), "human");
        assert_eq!(priority(&confirmed), "5");
    }

    #[test]
    fn the_summary_names_the_verdict_the_argv_and_why() {
        let line = summary(&allowed());
        assert_eq!(
            line,
            "allowed: [\"/usr/bin/systemctl\",\"restart\",\"nginx.service\"] (caller human, \
             action aido.svc.restart, rule 20-services.toml:15, audit seq 1)"
        );
        let refused = summary(
            &Record::first(Decision::Denied, vec!["/bin/sh".to_owned()], "unattested")
                .with_denial("deny_listed"),
        );
        assert!(refused.contains("refused deny_listed"), "{refused}");
    }

    #[test]
    fn every_outcome_reads_as_what_happened() {
        assert_eq!(outcome_phrase(&Outcome::NotExecuted), None);
        let ran = summary(&allowed().with_outcome(Outcome::Exited { code: 3 }));
        assert!(ran.contains("exited 3"), "{ran}");
        let killed = summary(&allowed().with_outcome(Outcome::Signalled { signal: 9 }));
        assert!(killed.contains("killed by signal 9"), "{killed}");
        let failed = summary(&allowed().with_outcome(Outcome::Failed {
            reason: "ENOEXEC".to_owned(),
        }));
        assert!(failed.contains("failed to start: ENOEXEC"), "{failed}");
    }

    #[test]
    fn an_argv_cannot_forge_a_log_line_or_drive_the_terminal_through_the_message() {
        // A newline would start a second log line in every text view of the
        // journal; an escape sequence or a bidi override would rewrite what
        // the operator sees. The record keeps the bytes; the message does not.
        let hostile = Record::first(
            Decision::Denied,
            vec![
                "/usr/bin/systemctl".to_owned(),
                "nginx\nFAKE: allowed everything".to_owned(),
                "\u{1b}[2J\u{202e}gnp.exe".to_owned(),
                "\u{9b}31m".to_owned(),
            ],
            "unattested",
        );
        let message = summary(&hostile);
        assert!(!message.contains('\n'), "{message}");
        assert!(!message.contains('\u{1b}'), "{message}");
        assert!(!message.contains('\u{202e}'), "{message}");
        assert!(!message.contains('\u{9b}'), "{message}");
        assert!(message.ends_with("[display sanitized; AIDO_RECORD is exact]"));
        // The exact argv is still in the entry, inside the record.
        let fields = fields(&hostile, "aido-gate");
        assert!(
            value_of(&fields, "AIDO_RECORD")
                .unwrap()
                .contains("FAKE: allowed everything")
        );
    }

    #[test]
    fn a_newline_in_any_quoted_value_is_shown_not_obeyed() {
        // Found by the snapshot: a newline in the rule source used to end the
        // line there, dropping every word after it — including the outcome.
        let record = allowed()
            .with_rule("aido.x", "evil.toml:1\nPRIORITY=7")
            .with_outcome(Outcome::Failed {
                reason: "no\nsuch file".to_owned(),
            });
        let message = summary(&record);
        assert!(!message.contains('\n'), "{message}");
        assert!(
            message.contains("rule evil.toml:1\\nPRIORITY=7"),
            "{message}"
        );
        assert!(
            message.contains("failed to start: no\\nsuch file"),
            "{message}"
        );
        assert!(message.ends_with("audit seq 1)"), "{message}");
    }

    #[test]
    fn the_message_is_bounded_however_long_the_argv() {
        let long = Record::first(Decision::Denied, vec!["x".repeat(20_000)], "unattested");
        let message = summary(&long);
        let columns = message.chars().count();
        assert!(columns < MESSAGE_COLUMNS.saturating_add(64), "{columns}");
    }

    #[test]
    fn an_index_value_too_long_for_a_query_is_left_to_the_record() {
        let action = "a".repeat(INDEX_FIELD_MAX.saturating_add(1));
        let record = allowed().with_rule(&action, "r.toml:1");
        let fields = fields(&record, "aidod");
        assert_eq!(value_of(&fields, "AIDO_ACTION"), None);
        assert!(value_of(&fields, "AIDO_RECORD").unwrap().contains(&action));
        let just_fits = allowed().with_rule("b".repeat(INDEX_FIELD_MAX), "r.toml:1");
        assert!(value_of(&super::fields(&just_fits, "aidod"), "AIDO_ACTION").is_some());
    }

    #[test]
    fn a_value_with_a_newline_is_length_prefixed_and_one_without_is_not() {
        let mut payload = Vec::new();
        push_field(&mut payload, "A", b"one line");
        assert_eq!(payload, b"A=one line\n");

        let mut payload = Vec::new();
        push_field(&mut payload, "B", b"two\nlines");
        let mut expected = b"B\n".to_vec();
        expected.extend_from_slice(&9u64.to_le_bytes());
        expected.extend_from_slice(b"two\nlines\n");
        assert_eq!(payload, expected);
    }

    #[test]
    fn a_record_too_large_for_one_datagram_is_refused_not_truncated() {
        let huge = Record::first(
            Decision::Denied,
            vec!["x".repeat(PAYLOAD_MAX)],
            "unattested",
        );
        let err = datagram(&huge, "aidod").unwrap_err();
        assert!(
            err.to_string().contains("one datagram carries at most"),
            "{err}"
        );
        assert_eq!(err.clone(), err);
        // A record of the largest size a writer accepts still fits.
        let largest = Record::first(
            Decision::Denied,
            vec!["y".repeat(crate::tail::MAX_RECORD_BYTES.saturating_sub(1024))],
            "unattested",
        );
        assert!(largest.to_jsonl().len() <= crate::tail::MAX_RECORD_BYTES);
        assert!(datagram(&largest, "aidod").unwrap().len() <= PAYLOAD_MAX);
    }
}
