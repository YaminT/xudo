//! The audit trail: a privileged decision is written down before it takes
//! effect, or it does not take effect.
//!
//! # The contract
//!
//! [`AuditSink`] is what the broker and the gate write through, and its shape
//! carries the rule rather than a comment beside it:
//!
//! * [`AuditSink::append`] takes a function that builds the record **from the
//!   chain's last record**, called while the sink holds the log, so the record
//!   always follows what is really there. The sink checks that it does.
//! * It returns an [`AuditReceipt`], which only a sink in this crate can make,
//!   and only once every part of the trail holds the record and the log's data
//!   is on disk (`fdatasync`).
//! * [`authorize`] hands an approval back inside [`Authorized`] only with that
//!   receipt, and only for a record that describes the approval — the same
//!   command and the same governing action ([`Approval`]), checked before
//!   anything is written. When the record cannot be written, or describes
//!   something else, `authorize` returns the error and drops the approval it
//!   was given.
//! * That drop is not the guarantee: `aido_gate::Approved` is `Clone`, with
//!   public fields, so a caller can keep a copy. The guarantee is the other
//!   half — each privileged action, the broker minting a spool entry and the
//!   gate executing, is to take an `Authorized<_>`, which only `authorize`
//!   makes, so that acting on an approval nobody recorded does not compile.
//!   Neither takes one yet (M2b steps 2 and 4).
//!
//! A refusal needs no receipt: it stands whether or not its record lands.
//! Write it with [`AuditSink::append`] anyway; a failure there changes nothing
//! about the answer, only what the caller can say about the trail.
//!
//! # How the broker and the gate call it
//!
//! Neither is wired yet (M2b steps 2 and 4). This is the shape both are
//! expected to take, with the record builders `aido-gate` already has:
//!
//! ```text
//! let mut trail = AuditTrail::system("aido-gate");          // "aidod" in the broker
//! match decide(&rules, &caller, pending.as_ref(), context) {
//!     Err(refusal) => {
//!         let _ = trail.append(&|prev| refusal_record(prev, &refusal, &caller, pending.as_ref()));
//!         exit(refusal.exit_code())
//!     }
//!     Ok(approved) => {
//!         let build = |prev: Option<&Record>, a: &Approved| authorization_record(prev, a, &caller, None);
//!         match authorize(&mut trail, approved, &build) {
//!             Ok(authorized) => execute(authorized),       // takes Authorized<Approved>
//!             Err(_unrecorded) => refuse_audit_unavailable(&mut trail),
//!         }
//!     }
//! }
//! ```
//!
//! The file is append-only, so an outcome learnt after the child exits is a new
//! record that names the one it completes, never an edit of it.
//!
//! # What the trail is made of
//!
//! [`AuditTrail`] writes the hash-chained log ([`JsonlLog`], the chain's
//! authority, at [`AUDIT_DIR`]`/`[`AUDIT_FILE_NAME`]) and then sends the record
//! to every mirror ([`JournaldSink`]) while it still holds the log's lock. An
//! append lands on the whole trail or on none of it: if the record does not
//! reach the disk, or a mirror refuses it, the log is cut back to where it
//! ended before the lock is released, so no other writer ever chains onto a
//! record nobody was given a receipt for. The receipt exists only if
//! everything took the record. A host without journald therefore records
//! nothing at all, refusals included, and refuses every decision that needs a
//! record.

mod file;
mod journal;

pub use file::{AUDIT_DIR, AUDIT_FILE_NAME, JsonlLog};
pub use journal::{JOURNAL_SOCKET, JournaldSink};

pub use aido_audit::Approval;
use aido_audit::{ChainError, Decision, MAX_RECORD_BYTES, Record, Sequence, TailError};

use crate::trust::TrustError;

/// Somewhere a privileged decision is written before it takes effect.
pub trait AuditSink {
    /// Appends the record `build` makes from the chain's last record, and
    /// returns proof that it was written.
    ///
    /// `build` is called once, while the sink holds the log, with the record
    /// the new one must follow — `None` when the chain is empty. The record it
    /// returns is checked to follow that one before anything is written.
    ///
    /// # Errors
    ///
    /// An [`AuditError`] whenever the record is not on every part of the
    /// trail. The caller must treat that as "not recorded" and refuse.
    fn append(
        &mut self,
        build: &dyn Fn(Option<&Record>) -> Record,
    ) -> Result<AuditReceipt, AuditError> {
        self.append_checked(build, &|_| Ok(()))
    }

    /// As [`Self::append`], and `check` must accept the record — after it is
    /// built and found to follow the chain, before anything is written.
    /// [`authorize`] checks with it that the record describes the approval.
    ///
    /// # Errors
    ///
    /// As [`Self::append`], and whatever `check` returns.
    fn append_checked(
        &mut self,
        build: &dyn Fn(Option<&Record>) -> Record,
        check: &dyn Fn(&Record) -> Result<(), AuditError>,
    ) -> Result<AuditReceipt, AuditError>;
}

/// A copy of each record, sent once the log holds it on disk and before the
/// log's lock is released.
pub trait AuditMirror: std::fmt::Debug {
    /// Sends `record`.
    ///
    /// # Errors
    ///
    /// An [`AuditError`] when the record did not reach the mirror. The trail
    /// fails the append on it and cuts the record back out of the log: a
    /// mirror that is configured is required.
    fn mirror(&mut self, record: &Record) -> Result<(), AuditError>;
}

/// Proof that a record is on the trail.
///
/// Made only by the sinks in this crate, after the record is written and
/// synced, so holding one means the write happened.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a receipt is the only evidence the record was written"]
pub struct AuditReceipt {
    seq: Sequence,
    hash: String,
    decision: Decision,
}

impl AuditReceipt {
    /// The receipt for a record that was just written.
    fn of(record: &Record) -> Self {
        Self {
            seq: record.seq,
            hash: record.hash.clone(),
            decision: record.decision,
        }
    }

    /// The record's position in the chain: the audit id a spool entry or a
    /// decision envelope can cite.
    pub fn seq(&self) -> Sequence {
        self.seq
    }

    /// The record's hash.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// What the record says was decided.
    pub fn decision(&self) -> Decision {
        self.decision
    }
}

/// An approval whose authorization is on the audit trail.
///
/// The only way to get one is [`authorize`]. Take one in every function that
/// acts with privilege, so that acting without a record is a type error.
#[derive(Debug)]
#[must_use = "an authorization that is not acted on authorizes nothing"]
pub struct Authorized<T> {
    approval: T,
    receipt: AuditReceipt,
}

impl<T> Authorized<T> {
    /// The approval.
    pub fn approval(&self) -> &T {
        &self.approval
    }

    /// The receipt for its record.
    pub fn receipt(&self) -> &AuditReceipt {
        &self.receipt
    }

    /// Both halves, for the function that finally acts.
    pub fn into_parts(self) -> (T, AuditReceipt) {
        (self.approval, self.receipt)
    }
}

/// Records the authorization of `approval`, and hands it back only once the
/// record is on the trail.
///
/// `build` makes the record from the chain's last record and the approval.
/// Before anything is written, the record must describe the approval: carry
/// its command as `argv` and its governing action as `action`. A builder that
/// records another command or action gets nothing written and no approval
/// back.
///
/// # Errors
///
/// Whatever the sink reports; [`AuditError::Misrecorded`] when the record does
/// not describe the approval; and [`AuditError::RecordedAsRefusal`] when the
/// record says the request was denied. In every error case the approval given
/// is dropped — see the module docs for why that alone is not the guarantee.
pub fn authorize<T: Approval>(
    sink: &mut dyn AuditSink,
    approval: T,
    build: &dyn Fn(Option<&Record>, &T) -> Record,
) -> Result<Authorized<T>, AuditError> {
    let receipt = sink.append_checked(&|previous| build(previous, &approval), &|record| {
        record
            .describes(&approval)
            .map_err(|field| AuditError::Misrecorded { field })
    })?;
    match receipt.decision() {
        Decision::Denied => Err(AuditError::RecordedAsRefusal {
            seq: receipt.seq().get(),
        }),
        Decision::Allowed | Decision::AwaitingConfirmation => Ok(Authorized { approval, receipt }),
    }
}

/// The trail a privileged binary writes: the chained log, then each mirror.
#[derive(Debug)]
pub struct AuditTrail {
    log: JsonlLog,
    mirrors: Vec<Box<dyn AuditMirror>>,
}

impl AuditTrail {
    /// A trail of the log alone.
    pub fn new(log: JsonlLog) -> Self {
        Self {
            log,
            mirrors: Vec::new(),
        }
    }

    /// Adds a mirror every record must also reach.
    ///
    /// Mirrors are sent to in the order they were added. With more than one,
    /// an earlier mirror can hold a record a later one refused, which the log
    /// then cut back — and whose `seq` the next record reuses. The system
    /// trail has one.
    #[must_use]
    pub fn with_mirror(mut self, mirror: impl AuditMirror + 'static) -> Self {
        self.mirrors.push(Box::new(mirror));
        self
    }

    /// The trail the broker and the gate write: the chain at
    /// `/var/lib/aido/audit.jsonl`, mirrored to journald, written by
    /// `identifier`.
    ///
    /// On a host without journald every append fails and leaves the log as it
    /// was, and so every decision that needs a record is refused: a
    /// configured sink is a required one.
    /// Leaving journald out is an operator's decision, for when the
    /// `audit_sink` setting exists — never a fallback taken quietly.
    pub fn system(identifier: &'static str) -> Self {
        Self::new(JsonlLog::system()).with_mirror(JournaldSink::system(identifier))
    }
}

impl AuditSink for AuditTrail {
    fn append_checked(
        &mut self,
        build: &dyn Fn(Option<&Record>) -> Record,
        check: &dyn Fn(&Record) -> Result<(), AuditError>,
    ) -> Result<AuditReceipt, AuditError> {
        // The mirrors run inside the log's write, under its lock, so one that
        // refuses gets the record cut back before any other writer can chain
        // onto it.
        let mirrors = &mut self.mirrors;
        let mut publish = |record: &Record| {
            mirrors
                .iter_mut()
                .try_for_each(|mirror| mirror.mirror(record))
        };
        self.log
            .write(build, check, &mut publish)
            .map(|record| AuditReceipt::of(&record))
    }
}

impl AuditSink for JsonlLog {
    fn append_checked(
        &mut self,
        build: &dyn Fn(Option<&Record>) -> Record,
        check: &dyn Fn(&Record) -> Result<(), AuditError>,
    ) -> Result<AuditReceipt, AuditError> {
        self.write(build, check, &mut |_| Ok(()))
            .map(|record| AuditReceipt::of(&record))
    }
}

/// An in-memory sink, for the tests of code that must record before it acts.
///
/// Behind the `fake` feature, which only test builds enable: a sink that makes
/// receipts without writing anything must not be linkable into a shipped
/// binary. It checks every record follows the last one, as the real log does,
/// so a builder that ignores the chain fails here too.
#[cfg(any(test, feature = "fake"))]
#[derive(Debug, Default)]
pub struct FakeAuditSink {
    records: Vec<Record>,
    failure: Option<String>,
}

#[cfg(any(test, feature = "fake"))]
impl FakeAuditSink {
    /// A sink that accepts every record that follows the chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink that accepts nothing: a full disk, a missing journal.
    pub fn failing(reason: impl Into<String>) -> Self {
        Self {
            records: Vec::new(),
            failure: Some(reason.into()),
        }
    }

    /// The records accepted so far, in order.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
}

#[cfg(any(test, feature = "fake"))]
impl AuditSink for FakeAuditSink {
    fn append_checked(
        &mut self,
        build: &dyn Fn(Option<&Record>) -> Record,
        check: &dyn Fn(&Record) -> Result<(), AuditError>,
    ) -> Result<AuditReceipt, AuditError> {
        if let Some(reason) = &self.failure {
            return Err(AuditError::Unavailable {
                reason: reason.clone(),
            });
        }
        let (record, _line) = next_record(self.records.last(), build, check)?;
        let receipt = AuditReceipt::of(&record);
        self.records.push(record);
        Ok(receipt)
    }
}

/// The record `build` makes to follow `previous`, checked, and the line it is
/// written as.
///
/// What every sink does before it writes, in one function, so the fake refuses
/// exactly what the log refuses: a record that does not follow the chain, one
/// `check` rejects, and one longer than a log line may be. A builder that
/// passes a consumer's tests against the fake cannot then fail first in
/// production.
fn next_record(
    previous: Option<&Record>,
    build: &dyn Fn(Option<&Record>) -> Record,
    check: &dyn Fn(&Record) -> Result<(), AuditError>,
) -> Result<(Record, String), AuditError> {
    let record = build(previous);
    aido_audit::follows(previous, &record).map_err(AuditError::NotChained)?;
    check(&record)?;
    let line = record.to_jsonl();
    if line.len() > MAX_RECORD_BYTES {
        return Err(AuditError::TooLarge {
            size: line.len(),
            max: MAX_RECORD_BYTES,
        });
    }
    Ok((record, line))
}

/// Why a record is not on the trail. Every variant means: refuse.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// The log's directory, or one above it, failed the trust walk.
    #[error("the audit log's directory cannot be trusted: {0}")]
    Untrusted(TrustError),
    /// The log file is not one a privileged writer may append to.
    #[error("{path} is not an audit log aido will write to: {reason}")]
    Refused {
        /// The log.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
    /// An operation on the log failed.
    #[error("cannot {op} the audit log {path}: {reason}")]
    Io {
        /// What was attempted.
        op: &'static str,
        /// The log.
        path: String,
        /// The operating system's account.
        reason: String,
    },
    /// Another writer held the log longer than the writer waits.
    #[error(
        "the audit log {path} stayed locked for {waited_ms} ms ({reason}); refusing rather than \
         writing out of turn"
    )]
    Busy {
        /// The log.
        path: String,
        /// How long the writer waited.
        waited_ms: u128,
        /// The last answer from `flock`.
        reason: String,
    },
    /// The log does not end in a record a writer can continue from.
    #[error(
        "the audit log {path} ends in damage, and a privileged writer neither continues past \
         damage nor starts a new chain: {reason}. `aido audit --log {path}`, run as root, reports \
         it, or the first damage before it; moving the log aside starts a new chain deliberately \
         and keeps this one as evidence"
    )]
    DamagedTail {
        /// The log.
        path: String,
        /// What the end of it holds.
        reason: TailError,
    },
    /// The record built does not follow the chain's last record.
    #[error("the record does not follow the chain's last record: {0}")]
    NotChained(ChainError),
    /// The record is longer than a log line may be.
    #[error(
        "the audit record is {size} bytes and a log line holds at most {max}; a request that \
         cannot be recorded is not carried out"
    )]
    TooLarge {
        /// The record's length.
        size: usize,
        /// The bound.
        max: usize,
    },
    /// journald did not take the record, or there is no journald.
    #[error("journald at {socket} did not take the record: {reason}")]
    Journal {
        /// The socket the record was sent to.
        socket: String,
        /// Why not.
        reason: String,
    },
    /// The record made for an authorization says the request was refused.
    #[error("record {seq} says the request was refused, and a refusal authorizes nothing")]
    RecordedAsRefusal {
        /// Its position.
        seq: u64,
    },
    /// The record made for an authorization does not describe the approval.
    #[error(
        "the record built for this approval carries another {field}, so it was not written: a \
         record of some other command or action authorizes nothing"
    )]
    Misrecorded {
        /// The field that differs, `argv` or `action`.
        field: &'static str,
    },
    /// The sink is unavailable. Produced by [`FakeAuditSink`] on request.
    #[error("the audit trail is unavailable: {reason}")]
    Unavailable {
        /// Why.
        reason: String,
    },
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

    use std::path::{Path, PathBuf};

    use aido_audit::{Outcome, verify};

    use super::*;

    /// What a gate approves, for these tests: a program run under
    /// `aido.test`.
    #[derive(Debug, PartialEq, Eq)]
    struct Grant(&'static str);

    impl Approval for Grant {
        fn command(&self) -> Vec<String> {
            vec![self.0.to_owned()]
        }

        fn action(&self) -> &'static str {
            "aido.test"
        }
    }

    fn authorization(previous: Option<&Record>, approval: &Grant) -> Record {
        Record::after(previous, Decision::Allowed, approval.command(), "human")
            .with_rule(approval.action(), "t.toml:1")
    }

    fn refusal(previous: Option<&Record>) -> Record {
        Record::after(previous, Decision::Denied, Vec::new(), "unattested")
            .with_denial("gate_no_pending_request")
    }

    #[test]
    fn an_approval_comes_back_only_with_the_receipt_for_its_record() {
        let mut sink = FakeAuditSink::new();
        let authorized = authorize(&mut sink, Grant("/usr/bin/true"), &authorization).unwrap();
        assert_eq!(authorized.approval(), &Grant("/usr/bin/true"));
        assert_eq!(authorized.receipt().seq(), Sequence::first());
        assert_eq!(authorized.receipt().decision(), Decision::Allowed);
        assert_eq!(authorized.receipt().hash(), sink.records()[0].hash);
        let (approval, receipt) = authorized.into_parts();
        assert_eq!(approval, Grant("/usr/bin/true"));
        assert_eq!(receipt.seq().get(), 1);
    }

    #[test]
    fn an_approval_that_cannot_be_recorded_leaves_nothing_to_act_on() {
        // The approval moves into `authorize` and is dropped on failure: the
        // caller has no value left to execute, so refusing is all it can do.
        let mut sink = FakeAuditSink::failing("disk full");
        let err = authorize(&mut sink, Grant("/usr/bin/true"), &authorization).unwrap_err();
        assert_eq!(
            err,
            AuditError::Unavailable {
                reason: "disk full".to_owned()
            }
        );
        assert!(sink.records().is_empty());
    }

    #[test]
    fn a_record_that_says_denied_authorizes_nothing() {
        // A builder that writes the wrong record must not mint an approval:
        // the trail would say refused while the action went ahead.
        let mut sink = FakeAuditSink::new();
        let denied = |previous: Option<&Record>, approval: &Grant| {
            Record::after(previous, Decision::Denied, approval.command(), "human")
                .with_rule(approval.action(), "t.toml:1")
                .with_denial("gate_no_pending_request")
        };
        let err = authorize(&mut sink, Grant("x"), &denied).unwrap_err();
        assert_eq!(err, AuditError::RecordedAsRefusal { seq: 1 });
        // The refusal is on the trail, which is what it says.
        assert_eq!(sink.records().len(), 1);
    }

    #[test]
    fn an_authorization_recorded_for_another_command_authorizes_nothing() {
        // The receipt would cover a record of `/bin/sh` while the approval
        // that came back ran `/usr/bin/true`: an audit trail that lies about
        // what root ran. Refused before anything is written.
        let mut sink = FakeAuditSink::new();
        let other_command = |previous: Option<&Record>, approval: &Grant| {
            Record::after(
                previous,
                Decision::Allowed,
                vec!["/bin/sh".to_owned()],
                "human",
            )
            .with_rule(approval.action(), "t.toml:1")
        };
        let err = authorize(&mut sink, Grant("/usr/bin/true"), &other_command).unwrap_err();
        assert_eq!(err, AuditError::Misrecorded { field: "argv" });
        assert!(sink.records().is_empty(), "the false record was written");
    }

    #[test]
    fn an_authorization_recorded_under_another_action_authorizes_nothing() {
        // The record would cite a rule that did not govern the decision — a
        // quieter duplicate, say — so the trail would explain the approval
        // with the wrong reason.
        let mut sink = FakeAuditSink::new();
        let other_action = |previous: Option<&Record>, approval: &Grant| {
            Record::after(previous, Decision::Allowed, approval.command(), "human")
                .with_rule("aido.test.quiet", "t.toml:9")
        };
        let err = authorize(&mut sink, Grant("/usr/bin/true"), &other_action).unwrap_err();
        assert_eq!(err, AuditError::Misrecorded { field: "action" });
        assert!(sink.records().is_empty());
    }

    #[test]
    fn a_misrecorded_authorization_never_reaches_the_log_or_a_mirror() {
        // The same check on the real trail: refused after the record is built
        // and found to chain, before the write.
        let dir = scratch("misrecorded");
        let mirror = Mirror::default();
        let seen = mirror.seen.clone();
        let mut trail = AuditTrail::new(JsonlLog::opened_for_test(&dir)).with_mirror(mirror);
        let other_command = |previous: Option<&Record>, approval: &Grant| {
            Record::after(
                previous,
                Decision::Allowed,
                vec!["/bin/sh".to_owned()],
                "human",
            )
            .with_rule(approval.action(), "t.toml:1")
        };
        let err = authorize(&mut trail, Grant("/usr/bin/true"), &other_command).unwrap_err();
        assert!(err.to_string().contains("carries another argv"), "{err}");
        assert!(read_log(&dir).is_empty());
        assert!(seen.borrow().is_empty());
    }

    #[test]
    fn a_confirmed_authorization_is_an_authorization() {
        let mut sink = FakeAuditSink::new();
        let confirmed = |previous: Option<&Record>, approval: &Grant| {
            Record::after(
                previous,
                Decision::AwaitingConfirmation,
                approval.command(),
                "human",
            )
            .with_rule(approval.action(), "t.toml:1")
        };
        assert!(authorize(&mut sink, Grant("x"), &confirmed).is_ok());
    }

    #[test]
    fn the_fake_refuses_a_record_that_ignores_the_chain() {
        // The same check the real log makes, so a builder that restarts the
        // chain fails in a consumer's tests, not first in production.
        let mut sink = FakeAuditSink::new();
        let _ = sink.append(&refusal).unwrap();
        let err = sink.append(&|_| refusal(None)).unwrap_err();
        assert_eq!(
            err,
            AuditError::NotChained(ChainError::OutOfOrder {
                seq: 1,
                previous: 1
            })
        );
        assert_eq!(sink.records().len(), 1);
    }

    /// A mirror that remembers what it saw, or refuses everything.
    #[derive(Debug, Default)]
    struct Mirror {
        seen: std::rc::Rc<std::cell::RefCell<Vec<u64>>>,
        refuse: bool,
    }

    impl AuditMirror for Mirror {
        fn mirror(&mut self, record: &Record) -> Result<(), AuditError> {
            self.seen.borrow_mut().push(record.seq.get());
            if self.refuse {
                Err(AuditError::Journal {
                    socket: "test".to_owned(),
                    reason: "no listener".to_owned(),
                })
            } else {
                Ok(())
            }
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("audit-trail-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    fn read_log(dir: &Path) -> Vec<Record> {
        let text = std::fs::read_to_string(dir.join(AUDIT_FILE_NAME)).unwrap();
        aido_audit::Chain::from_jsonl(&text)
            .unwrap()
            .records()
            .to_vec()
    }

    #[test]
    fn the_trail_writes_the_log_then_every_mirror() {
        let dir = scratch("mirrors");
        let first = Mirror::default();
        let second = Mirror::default();
        let (seen_first, seen_second) = (first.seen.clone(), second.seen.clone());
        let mut trail = AuditTrail::new(JsonlLog::opened_for_test(&dir))
            .with_mirror(first)
            .with_mirror(second);
        let receipt = trail.append(&refusal).unwrap();
        let receipt_two = trail.append(&refusal).unwrap();
        assert_eq!((receipt.seq().get(), receipt_two.seq().get()), (1, 2));
        assert_eq!(*seen_first.borrow(), [1, 2]);
        assert_eq!(*seen_second.borrow(), [1, 2]);
        let log = read_log(&dir);
        assert_eq!(log.len(), 2);
        verify(&log).unwrap();
        assert!(format!("{trail:?}").contains("mirrors"));
    }

    #[test]
    fn a_mirror_that_refuses_leaves_no_record_for_the_next_writer_to_chain_onto() {
        // Required means required: no receipt. Left in the log, an "allowed"
        // record nothing ran for would read exactly like one that did, and the
        // next writer would chain onto it; it is cut back under the lock
        // instead, so the next record takes its place.
        let dir = scratch("mirror-refuses");
        let refusing = Mirror {
            refuse: true,
            ..Mirror::default()
        };
        let seen = refusing.seen.clone();
        let mut trail = AuditTrail::new(JsonlLog::opened_for_test(&dir)).with_mirror(refusing);
        let err = authorize(&mut trail, Grant("/usr/bin/true"), &authorization).unwrap_err();
        assert!(err.to_string().contains("did not take the record"), "{err}");
        assert_eq!(*seen.borrow(), [1], "the mirror was offered the record");
        assert!(read_log(&dir).is_empty(), "the record was not cut back");

        let mut next =
            AuditTrail::new(JsonlLog::opened_for_test(&dir)).with_mirror(Mirror::default());
        let receipt = next.append(&refusal).unwrap();
        assert_eq!(receipt.seq(), Sequence::first());
        assert_eq!(read_log(&dir)[0].outcome, Outcome::NotExecuted);
    }

    #[test]
    fn a_log_that_refuses_reaches_no_mirror() {
        // The record is built from the log's tail, so a log that cannot be
        // opened leaves nothing to mirror: the journal never holds a record
        // the chain does not.
        let mirror = Mirror::default();
        let seen = mirror.seen.clone();
        let mut trail =
            AuditTrail::new(JsonlLog::in_dir(env!("CARGO_MANIFEST_DIR"))).with_mirror(mirror);
        let err = trail.append(&refusal).unwrap_err();
        assert!(err.to_string().contains("cannot be trusted"), "{err}");
        assert!(seen.borrow().is_empty());
    }

    #[test]
    fn a_trail_whose_journal_is_gone_records_nothing_and_authorizes_nothing() {
        // The real mirror, not a stand-in: with nothing at the socket (every
        // container, and every macOS host), the authorization comes back
        // unrecorded, the approval is gone with it, and the log is as it was.
        let dir = scratch("journal-gone");
        let mut trail = AuditTrail::new(JsonlLog::opened_for_test(&dir))
            .with_mirror(JournaldSink::at(dir.join("absent.sock"), "aido-test"));
        let err = authorize(&mut trail, Grant("/usr/bin/id"), &authorization).unwrap_err();
        assert!(err.to_string().contains("did not take the record"), "{err}");
        assert!(read_log(&dir).is_empty());
        assert_eq!(
            std::fs::metadata(dir.join(AUDIT_FILE_NAME)).unwrap().len(),
            0,
            "the cut left bytes behind"
        );
    }

    /// The real sinks together, against a datagram socket the test binds
    /// under `target/`: a container has no journald to send to.
    #[cfg(target_os = "linux")]
    mod linux {
        use std::os::unix::net::UnixDatagram;
        use std::time::Duration;

        use super::*;

        #[test]
        fn the_journal_receives_the_line_the_log_holds_byte_for_byte() {
            let dir = scratch("jn");
            let socket = dir.join("j.sock");
            let receiver = UnixDatagram::bind(&socket).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut trail = AuditTrail::new(JsonlLog::opened_for_test(&dir))
                .with_mirror(JournaldSink::at(&socket, "aido-test"));
            let authorized = authorize(&mut trail, Grant("/usr/bin/id"), &authorization).unwrap();

            let mut buf = vec![0; 256 * 1024];
            let count = receiver.recv(&mut buf).unwrap();
            let datagram = &buf[..count];
            let line = std::fs::read_to_string(dir.join(AUDIT_FILE_NAME)).unwrap();
            assert!(
                datagram.ends_with(format!("AIDO_RECORD={line}").as_bytes()),
                "the journal's copy is not the file's line"
            );
            let hash = format!("\nAIDO_HASH={}\n", authorized.receipt().hash());
            assert!(datagram.windows(hash.len()).any(|w| w == hash.as_bytes()));
        }
    }

    #[test]
    fn the_log_alone_is_a_sink() {
        let dir = scratch("log-alone");
        let mut log = JsonlLog::opened_for_test(&dir);
        let receipt = authorize(&mut log, Grant("/usr/bin/id"), &authorization).unwrap();
        assert_eq!(receipt.receipt().seq(), Sequence::first());
        assert_eq!(read_log(&dir)[0].argv, ["/usr/bin/id"]);
    }

    #[test]
    fn the_system_trail_is_the_chain_under_var_lib_mirrored_to_journald() {
        // Inspected, not appended to: a suite run as root on a machine with
        // aido installed must not write a test record into the real chain.
        // The walk that refuses an untrusted directory is tested in `file`.
        let rendered = format!("{:?}", AuditTrail::system("aido-test"));
        assert!(rendered.contains("\"/var/lib/aido\""), "{rendered}");
        assert!(rendered.contains(JOURNAL_SOCKET), "{rendered}");
        assert!(rendered.contains("aido-test"), "{rendered}");
    }

    #[test]
    fn every_refusal_tells_the_operator_what_to_look_at() {
        let errors = [
            AuditError::Untrusted(TrustError::NotAbsolute { at: "x".to_owned() }),
            AuditError::Refused {
                path: "/var/lib/aido/audit.jsonl".to_owned(),
                reason: "it is a symbolic link".to_owned(),
            },
            AuditError::Io {
                op: "open",
                path: "/var/lib/aido/audit.jsonl".to_owned(),
                reason: "Permission denied".to_owned(),
            },
            AuditError::Busy {
                path: "/var/lib/aido/audit.jsonl".to_owned(),
                waited_ms: 5000,
                reason: "Resource temporarily unavailable".to_owned(),
            },
            AuditError::DamagedTail {
                path: "/var/lib/aido/audit.jsonl".to_owned(),
                reason: TailError::Edited { seq: 9 },
            },
            AuditError::NotChained(ChainError::Edited { seq: 2 }),
            AuditError::TooLarge {
                size: 70_000,
                max: 65_536,
            },
            AuditError::Journal {
                socket: JOURNAL_SOCKET.to_owned(),
                reason: "No such file or directory".to_owned(),
            },
            AuditError::RecordedAsRefusal { seq: 3 },
            AuditError::Unavailable {
                reason: "disk full".to_owned(),
            },
            AuditError::Misrecorded { field: "argv" },
        ];
        for err in &errors {
            assert!(err.to_string().len() > 40, "{err}");
            assert_eq!(err.clone(), *err);
        }
        // The command it names is one the front-end really has: `aido audit`,
        // whose `--log` takes the path.
        assert!(
            errors[4]
                .to_string()
                .contains("`aido audit --log /var/lib/aido/audit.jsonl`, run as root")
        );
        assert!(errors[4].to_string().contains("moving the log aside"));
    }
}
