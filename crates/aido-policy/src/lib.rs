//! The pure policy engine for `aido`.
//!
//! This crate answers exactly one question, and performs no I/O to do it:
//!
//! ```text
//! (ruleset, caller facts, request) -> Decision
//! ```
//!
//! # Why this crate has no syscalls
//!
//! Everything security-relevant in `aido` is parsing and matching, which is
//! precisely the code shape that produced sudo's memory-safety and
//! argument-injection CVE record. Isolating it here makes it a pure function:
//! fuzzable, property-testable, and buildable on a macOS development host with
//! no Linux in the loop. Anything that needs the filesystem, `/proc`, or a
//! process belongs in `aido-sys` behind a trait.
//!
//! # What this crate deliberately cannot do
//!
//! * It cannot resolve a path. [`Matcher::PathUnder`] is a *syntactic*
//!   pre-filter only; symlink-resistant resolution via `openat2` is enforced in
//!   `aido-sys`, and a decision from this crate is never sufficient authority
//!   to open a file.
//! * It cannot classify a caller. It consumes a [`Classification`] that the
//!   root broker derived from kernel-attested facts.
//! * It cannot be widened by configuration. The deny-list is compiled in.
//!
//! # The invariants
//!
//! These hold for every input and are asserted as property tests:
//!
//! 1. **Deny always wins.** If any deny-list class matches, the verdict is
//!    [`Verdict::Deny`] regardless of how many allow rules matched.
//! 2. **Hints carry zero weight.** Mutating [`CallerFacts::hints`] can never
//!    change a verdict. Hints exist to be written to the audit record.
//! 3. **Appending an argument never widens.** Extending an argv can turn an
//!    allow into a deny, never a deny into an allow.
//! 4. **Rule order cannot rescue a deny.** Reordering the ruleset can change
//!    which rule matched, never whether the deny-list fired.
//! 5. **Canonicalization is idempotent.**
//!
//! # Failure posture
//!
//! Every error path denies. There is no verdict whose [`Default`] means allow,
//! and no code path that logs a parse failure and continues.

#![forbid(unsafe_code)]

pub mod argv;
pub mod caller;
pub mod decision;
pub mod deny;
pub mod engine;
pub mod matcher;
pub mod rule;

pub use argv::{Arg, Argv};
pub use caller::{CallerFacts, Classification, Hint, HintSource};
pub use decision::{Confirm, Decision, DenialCode, ExitCode, TraceStep, Verdict};
pub use deny::{CapabilityClass, DenyFinding, deny_list_version, evaluate_deny_list};
pub use engine::{Request, evaluate};
pub use matcher::{ArgSpec, MatchError, Matcher, NameKind, Repeat};
pub use rule::{Action, ActionId, RuleSet, RuleSetError, Source, Tier};
