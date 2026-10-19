//! Tamper-evident audit records.
//!
//! A gate that executes before there is a record of what it executed is a gate
//! whose first incident is unreconstructable. So this crate exists before the
//! gate does, and the gate will not ship without it.
//!
//! Pure: it builds records, chains them, and verifies a chain; it decides
//! where a writer picks a chain up ([`tail`]) and what bytes journald receives
//! for a record ([`journal`]). It does not open a file, send a datagram, or
//! decide where anything goes — that is `aido-sys`'s job, and keeping it out of
//! here is what makes the chaining logic testable without a filesystem.
//!
//! # What the chain does and does not give you
//!
//! Each record carries the hash of its predecessor, so **an edit or a deletion
//! in the middle of the log is detectable**: every subsequent link stops
//! matching. That is the whole claim, and it is worth being precise about the
//! limits:
//!
//! * It is **not** a signature. An attacker with write access to the log can
//!   truncate it and rebuild a consistent chain from any point, because the hash
//!   input is entirely in the log. Detecting *that* needs an off-box copy or a
//!   signing key the attacker does not hold — both are later work, and both are
//!   listed in the enhancement backlog.
//! * It says nothing about records that were never written. A gate killed
//!   before it logged leaves no gap to find, which is why the design writes the
//!   record and `fdatasync`s it **before** returning the child's result rather
//!   than after.
//!
//! Stating those here rather than letting someone infer a stronger guarantee is
//! the point: an audit log people over-trust is worse than one whose limits are
//! written down.

#![forbid(unsafe_code)]

pub mod chain;
pub mod journal;
pub mod record;
pub mod tail;

pub use chain::{Chain, ChainError, ChainReadError, LogError, follows, verify, verify_log};
pub use record::{Approval, Decision, Outcome, Record, Sequence};
pub use tail::{
    Continuation, MAX_RECORD_BYTES, TAIL_WINDOW, TailError, continuation, continuation_of,
    window_start,
};
