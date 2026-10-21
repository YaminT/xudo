//! The one clock request deadlines are measured on.
//!
//! The broker stamps every spool entry with a deadline and the gate refuses an
//! entry past it, so the two must read the **same** clock. That clock is
//! `CLOCK_MONOTONIC`, read here, in whole seconds: an operator fixing the
//! timezone cannot move it, and neither can anything that sets the wall clock
//! back. Both binaries read it through [`HostClock`], so there is one
//! definition of "now" for a deadline, not two that could drift.

/// A source of monotonic seconds.
pub trait Clock {
    /// Whole seconds of `CLOCK_MONOTONIC`.
    fn monotonic_secs(&self) -> u64;
}

/// The running kernel's `CLOCK_MONOTONIC`.
#[derive(Clone, Copy, Debug)]
pub struct HostClock;

impl Clock for HostClock {
    fn monotonic_secs(&self) -> u64 {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        // Never negative on a real kernel. If it ever were, zero is the
        // fail-closed reading: a deadline minted at zero has already passed by
        // the time any later reading compares it.
        u64::try_from(now.tv_sec).unwrap_or(0)
    }
}

/// A clock that always reads the same second, for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn monotonic_secs(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_host_clock_never_runs_backwards() {
        let first = HostClock.monotonic_secs();
        let second = HostClock.monotonic_secs();
        assert!(second >= first, "{second} < {first}");
        assert!(format!("{HostClock:?}").contains("HostClock"));
    }

    #[test]
    fn a_fixed_clock_reads_what_it_was_given() {
        assert_eq!(FixedClock(1_234).monotonic_secs(), 1_234);
        assert_eq!(FixedClock(7), FixedClock(7));
    }
}
