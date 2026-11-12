//! Pins every contract string a caller acts on: the denial-code wire contract
//! and every confirmation-prompt sentence.
//!
//! An agent branches on the code and a human decides on the sentence, so a
//! diff in either is a policy or UX change and must be reviewed as one. A
//! snapshot makes that diff impossible to land silently: `cargo test` fails
//! until the new text is accepted (`INSTA_UPDATE=always cargo test`, or
//! `cargo insta review`) and the changed `.snap` file reaches review.
//!
//! Writing the first snapshot here found a real defect: the `exe_mismatch`
//! remediation carried an eighteen-space run from a mis-wrapped string
//! literal, which every earlier test missed because each asserted only that a
//! substring was present.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fmt::Write as _;

use xudo_policy::decision::ConfirmReason;
use xudo_policy::{DenialCode, ExitCode};

/// Every denial code. [`lists_every_denial_code`] stops compiling when a
/// variant is added, and the build error lands here, where this array needs
/// the new code so the snapshot gains its row.
const ALL_CODES: [DenialCode; 11] = [
    DenialCode::UnknownAction,
    DenialCode::ArgvRejected,
    DenialCode::DenyListed,
    DenialCode::PolicyUnloadable,
    DenialCode::Frozen,
    DenialCode::NoConfirmationChannel,
    DenialCode::HumanPathOnly,
    DenialCode::ExeMismatch,
    DenialCode::ConfirmationRefused,
    DenialCode::ConfirmationExpired,
    DenialCode::ConfirmationThrottled,
];

/// Compile-time exhaustiveness for [`ALL_CODES`]: no wildcard arm, so a new
/// variant is a build failure, never a silently missing snapshot row.
fn lists_every_denial_code(code: DenialCode) {
    match code {
        DenialCode::UnknownAction
        | DenialCode::ArgvRejected
        | DenialCode::DenyListed
        | DenialCode::PolicyUnloadable
        | DenialCode::Frozen
        | DenialCode::NoConfirmationChannel
        | DenialCode::HumanPathOnly
        | DenialCode::ExeMismatch
        | DenialCode::ConfirmationRefused
        | DenialCode::ConfirmationExpired
        | DenialCode::ConfirmationThrottled => {}
    }
}

/// Every confirmation reason, with the same exhaustiveness arrangement.
const ALL_REASONS: [ConfirmReason; 3] = [
    ConfirmReason::AgentActionsConfirmed,
    ConfirmReason::RuleRequiresConfirmation,
    ConfirmReason::CriticalTier,
];

/// Compile-time exhaustiveness for [`ALL_REASONS`].
fn lists_every_confirm_reason(reason: ConfirmReason) {
    match reason {
        ConfirmReason::AgentActionsConfirmed
        | ConfirmReason::RuleRequiresConfirmation
        | ConfirmReason::CriticalTier => {}
    }
}

#[test]
fn the_denial_code_wire_contract_is_pinned() {
    let mut table = String::new();
    for code in ALL_CODES {
        lists_every_denial_code(code);
        let _ = writeln!(table, "{:>2}  {}", code.as_u32(), code.as_str());
        let _ = writeln!(table, "    {}", code.remediation());
    }
    // Numeric codes are contiguous from 1, so the largest equals the count —
    // unless a variant exists that this array (and therefore the snapshot)
    // does not carry.
    let largest = ALL_CODES.iter().map(|c| c.as_u32()).max().unwrap();
    assert_eq!(u32::try_from(ALL_CODES.len()).unwrap(), largest);
    insta::assert_snapshot!("denial_code_wire_contract", table);
}

#[test]
fn every_confirmation_prompt_string_is_pinned() {
    let mut prompts = String::new();
    for reason in ALL_REASONS {
        lists_every_confirm_reason(reason);
        let _ = writeln!(prompts, "{reason:?}");
        let _ = writeln!(prompts, "    {}", reason.explain());
    }
    insta::assert_snapshot!("confirmation_prompt_strings", prompts);
}

/// Every process exit status `xudo` itself reports, with the same
/// exhaustiveness arrangement as [`ALL_CODES`].
const ALL_EXIT_CODES: [ExitCode; 7] = [
    ExitCode::Delegated,
    ExitCode::Denied,
    ExitCode::NotConfirmed,
    ExitCode::Unusable,
    ExitCode::LintWarning,
    ExitCode::LintError,
    ExitCode::TestFailure,
];

/// Compile-time exhaustiveness for [`ALL_EXIT_CODES`].
fn lists_every_exit_code(code: ExitCode) {
    match code {
        ExitCode::Delegated
        | ExitCode::Denied
        | ExitCode::NotConfirmed
        | ExitCode::Unusable
        | ExitCode::LintWarning
        | ExitCode::LintError
        | ExitCode::TestFailure => {}
    }
}

#[test]
fn the_exit_status_contract_is_pinned() {
    // A pipeline gates on these numbers, so a renumbering is a breaking change.
    let mut table = String::new();
    for code in ALL_EXIT_CODES {
        lists_every_exit_code(code);
        let _ = writeln!(table, "{:>2}  {code:?}", code.as_i32());
    }
    insta::assert_snapshot!("exit_status_contract", table);
}

#[test]
fn the_check_codes_rank_by_severity_and_never_collide_with_a_refusal() {
    use ExitCode::{Denied, LintError, LintWarning, NotConfirmed, TestFailure, Unusable};
    assert!(LintWarning.as_i32() < LintError.as_i32());
    assert!(LintError.as_i32() < TestFailure.as_i32());
    for check in [LintWarning, LintError, TestFailure] {
        for other in [Denied, NotConfirmed, Unusable] {
            assert_ne!(check.as_i32(), other.as_i32());
        }
        assert!(check.as_i32() < 128, "{check:?} could read as a signal");
    }
}
