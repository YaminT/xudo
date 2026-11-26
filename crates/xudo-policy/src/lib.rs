//! The pure policy engine for `xudo`.
//!
//! This crate answers exactly one question, and performs no I/O to do it:
//!
//! ```text
//! (ruleset, caller facts, request) -> Decision
//! ```
//!
//! # Why this crate has no syscalls
//!
//! Everything security-relevant in `xudo` is parsing and matching, which is
//! precisely the code shape that produced sudo's memory-safety and
//! argument-injection CVE record. Isolating it here makes it a pure function:
//! fuzzable, property-testable, and buildable on a macOS development host with
//! no Linux in the loop. Anything that needs the filesystem, `/proc`, or a
//! process belongs in `xudo-sys` behind a trait.
//!
//! # What this crate deliberately cannot do
//!
//! * It cannot resolve a path. [`Matcher::PathUnder`] is lexical only.
//!   Nothing in xudo enforces containment for argument paths. Never use it
//!   for a program that opens the path as root. A decision from this crate
//!   is never sufficient authority to open a file.
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
//! 6. **Adding a rule never removes a confirmation**, and rule order never
//!    changes whether one is demanded. Every action that accepts a command
//!    contributes its requirement and the strictest applies, so a permissive
//!    duplicate, wherever it sorts and whichever name a caller asks under,
//!    cannot weaken a confirming rule. See [`engine`] and [`overlap`].
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
pub mod deny_rule;
pub mod engine;
pub mod files;
pub mod fuzz_check;
pub mod harness;
pub mod matcher;
pub mod operation;
pub mod overlap;
pub mod pack;
pub mod rule;
pub mod rule_test;

pub use argv::{Arg, Argv};
pub use caller::{CallerFacts, Classification, Hint, HintSource};
pub use decision::{Confirm, ConfirmReason, Decision, DenialCode, ExitCode, TraceStep, Verdict};
pub use deny::{CapabilityClass, DenyFinding, deny_list_version, evaluate_deny_list};
pub use deny_rule::{DenyClause, DenyRule, DenyRuleMatch, MAX_DENY_RULES, evaluate_deny_rules};
pub use engine::{Request, evaluate, evaluate_command};
pub use files::{
    Generation, HarnessFile, LoadedPack, LoadedRuleSet, RULE_FILE_SUFFIX, RuleFile, RuleFilesError,
    UnregisteredLabel, is_rule_file_name, load_policy, load_policy_with_registry, load_rule_files,
};
pub use harness::{
    HarnessEntry, HarnessError, HarnessRegistry, HarnessWay, passwd_fault, passwd_uid,
    uid_from_passwd_read, valid_account_name, valid_harness_label,
};
pub use matcher::{ArgSpec, MatchError, Matcher, NameKind, Repeat};
pub use operation::{
    MAX_COMPONENT_BYTES, MAX_DEPTH_LIMIT, MAX_ENTRIES_LIMIT, MAX_PATH_BYTES, OpKind, Operation,
    OwnerPolicy, RemoveGrant, evaluate_remove_path, judge_remove_path, target_under,
};
pub use overlap::Overlap;
pub use pack::{Capability, PackHeader, PackRefusal, Review};
pub use rule::{
    Action, ActionId, HarnessLint, OpenUnitLint, Outcome, ParsedFile, RuleSet, RuleSetError,
    Source, Tier, harness_near_miss,
};
pub use rule_test::{Expectation, RuleTest, TestError, TestOutcome, TestResult, run_tests};
