//! Reporting the child's fate without softening it.
//!
//! When the gate execs a privileged child, the caller's exit status must be the
//! child's exit status. This sounds like a detail and is not: a wrapper that
//! collapses every failure to `1` breaks `set -e` scripts, hides the difference
//! between "the package was already installed" (`apt-get` exit 0) and "the
//! archive is corrupt" (exit 100), and — worse for this project — makes a
//! *denial* indistinguishable from a command that ran and failed. `aido` reserves
//! its own exit codes for its own refusals and passes everything else through.
//!
//! # The shell convention, and why signals are not exit codes
//!
//! A child killed by a signal has no exit code. Unix's answer, which every shell
//! implements and `sudo` follows, is to report `128 + signal`. It is a
//! convention, not a kernel fact, and it is lossy — exit code 137 and "killed by
//! SIGKILL" are the same number — so [`Termination`] keeps the distinction
//! internally and flattens it only at the process boundary, where it must. The
//! audit record gets the unflattened form via [`Termination::outcome`].
//!
//! # Decoding, done here rather than with libc macros
//!
//! `WIFEXITED` and friends are C macros, unavailable through a Rust FFI
//! declaration, and each libc binding reimplements them anyway. Reimplementing
//! them here — in a pure module, with a test per branch — is both the honest and
//! the testable option: this crate takes no `unsafe`, and a fabricated status
//! word exercises every arm without spawning a process.

/// The low seven bits, which hold the signal number when there is one.
const SIGNAL_MASK: u32 = 0x7f;

/// The value in [`SIGNAL_MASK`] that means "stopped or continued, not dead".
const STOPPED: u32 = 0x7f;

/// The bit that means the kernel wrote a core file.
const CORE_DUMPED: u32 = 0x80;

/// The offset shells add to a signal number to report it as an exit status.
const SIGNAL_EXIT_BASE: i32 = 128;

/// How a child process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termination {
    /// It called `exit`.
    Exited {
        /// The status it passed. Truncated to 8 bits by the kernel, not by us.
        code: u8,
    },
    /// It was killed.
    Signalled {
        /// The signal that killed it.
        signal: u8,
        /// Whether a core file was written.
        core_dumped: bool,
    },
}

impl Termination {
    /// Decodes a `wait` status word.
    ///
    /// Returns `None` for a status that is not a termination — a stop, or a
    /// continue — because those are events about a *living* child and treating
    /// them as an exit would report a process as finished while it is still
    /// running. The gate does not use `WUNTRACED`, so it should never see one;
    /// the case is handled rather than assumed away.
    ///
    /// Takes `u32` rather than the `c_int` `waitpid` produces: `waitpid` never
    /// yields a negative status word, and requiring the conversion at the
    /// syscall boundary keeps the sign question out of a module whose whole job
    /// is bit arithmetic.
    pub fn from_wait_status(raw: u32) -> Option<Self> {
        let low = raw & SIGNAL_MASK;
        if low == 0 {
            let code = raw.checked_shr(8).unwrap_or(0) & 0xff;
            return Some(Self::Exited {
                code: u8::try_from(code).unwrap_or(u8::MAX),
            });
        }
        if low == STOPPED {
            return None;
        }
        Some(Self::Signalled {
            signal: u8::try_from(low).unwrap_or(u8::MAX),
            core_dumped: raw & CORE_DUMPED != 0,
        })
    }

    /// The exit status the gate itself should exit with.
    ///
    /// `128 + signal` for a signalled child, matching every shell and `sudo`.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Exited { code } => i32::from(code),
            Self::Signalled { signal, .. } => SIGNAL_EXIT_BASE.saturating_add(i32::from(signal)),
        }
    }

    /// The audit outcome, with the signal kept distinct from an exit code.
    pub fn outcome(self) -> aido_audit::record::Outcome {
        match self {
            Self::Exited { code } => aido_audit::record::Outcome::Exited {
                code: i32::from(code),
            },
            Self::Signalled { signal, .. } => aido_audit::record::Outcome::Signalled {
                signal: i32::from(signal),
            },
        }
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

    use super::*;

    /// The status word the kernel produces for `exit(code)`.
    fn exited(code: u32) -> u32 {
        code << 8
    }

    #[test]
    fn a_clean_exit_is_reported_as_zero_and_not_as_success() {
        let end = Termination::from_wait_status(exited(0)).unwrap();
        assert_eq!(end, Termination::Exited { code: 0 });
        assert_eq!(end.exit_code(), 0);
    }

    #[test]
    fn an_exit_status_is_passed_through_unchanged() {
        // apt-get's 100 is the case that matters: a wrapper that reported 1
        // here would tell a script "unknown failure" instead of "package
        // manager error".
        for code in [1_u32, 2, 100, 127, 255] {
            let end = Termination::from_wait_status(exited(code)).unwrap();
            assert_eq!(end.exit_code(), i32::try_from(code).unwrap(), "code {code}");
        }
    }

    #[test]
    fn a_killed_child_is_reported_as_one_hundred_twenty_eight_plus_the_signal() {
        let killed = Termination::from_wait_status(9).unwrap();
        assert_eq!(
            killed,
            Termination::Signalled {
                signal: 9,
                core_dumped: false
            }
        );
        assert_eq!(killed.exit_code(), 137);
    }

    #[test]
    fn a_core_dump_is_recorded_and_does_not_change_the_exit_code() {
        let dumped = Termination::from_wait_status(0x0b | CORE_DUMPED).unwrap();
        assert_eq!(
            dumped,
            Termination::Signalled {
                signal: 11,
                core_dumped: true
            }
        );
        assert_eq!(dumped.exit_code(), 139);
    }

    #[test]
    fn a_stopped_child_is_not_a_termination() {
        // 0x137f is SIGSTOP-stopped. Reporting it as an exit would say a
        // running process had finished.
        assert_eq!(Termination::from_wait_status(0x137f), None);
        assert_eq!(Termination::from_wait_status(0xffff), None);
    }

    #[test]
    fn the_audit_outcome_keeps_a_signal_distinct_from_an_exit_code() {
        // 137-as-exit and killed-by-9 must not read alike in the log, even
        // though the process exit status cannot tell them apart.
        let signalled = Termination::from_wait_status(9).unwrap().outcome();
        let exited_137 = Termination::from_wait_status(exited(137))
            .unwrap()
            .outcome();
        assert_eq!(
            signalled,
            aido_audit::record::Outcome::Signalled { signal: 9 }
        );
        assert_eq!(
            exited_137,
            aido_audit::record::Outcome::Exited { code: 137 }
        );
        assert_ne!(signalled, exited_137);
        assert!(signalled.executed() && exited_137.executed());
    }

    #[test]
    fn a_status_word_wider_than_the_kernel_produces_still_decodes() {
        // Not reachable from waitpid, but the function is public and takes a
        // u32, so the saturating conversions must be exercised rather than
        // assumed unreachable.
        let end = Termination::from_wait_status(0xffff_ff00).unwrap();
        assert_eq!(end, Termination::Exited { code: 0xff });
    }
}
