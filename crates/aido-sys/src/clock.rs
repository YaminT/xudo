//! The monotonic clock, as a seam.
//!
//! A deadline in this project is a reading of `CLOCK_MONOTONIC`: the broker
//! mints a request with one, and the gate refuses the request once the same
//! clock has passed it. The wall clock is never used for either, because a
//! deadline anchored to it is one an operator extends by correcting the time
//! and an attacker extends by anything that moves it backwards.
//!
//! The reading is whole seconds, rounded down. A request is therefore live for
//! at most the seconds it was minted for, and the gate's `now >= deadline`
//! comparison errs towards refusing.
//!
//! [`HostClock`] is the real clock and cannot fail: `clock_gettime` on
//! `CLOCK_MONOTONIC` has no failure the kernel reports. [`Clock`] returns a
//! `Result` anyway, so a gate that cannot read the time is a gate with a
//! refusal path a test can reach through [`FakeClock`], not an `unwrap`.

use crate::error::SysError;

/// Somewhere to read the monotonic clock.
pub trait Clock {
    /// Whole seconds of `CLOCK_MONOTONIC`, from an unspecified epoch.
    ///
    /// # Errors
    ///
    /// [`SysError`] when no reading can be had. The caller must treat that as
    /// "the deadline cannot be checked" and refuse.
    fn monotonic_secs(&self) -> Result<u64, SysError>;
}

/// The running system's `CLOCK_MONOTONIC`.
#[derive(Clone, Copy, Debug)]
pub struct HostClock;

impl Clock for HostClock {
    fn monotonic_secs(&self) -> Result<u64, SysError> {
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        // `unsigned_abs`, not a checked conversion with a fallback: a fallback
        // to 0 would read every deadline as still in the future. The monotonic
        // clock is never negative, so the absolute value is the value.
        Ok(now.tv_sec.unsigned_abs())
    }
}

/// A clock a test sets, which can also be made to fail.
#[derive(Clone, Debug)]
pub struct FakeClock {
    reading: Result<u64, SysError>,
}

impl FakeClock {
    /// A clock that reads `secs`.
    pub fn at(secs: u64) -> Self {
        Self { reading: Ok(secs) }
    }

    /// A clock that cannot be read.
    pub fn broken(reason: impl Into<String>) -> Self {
        Self {
            reading: Err(SysError::Os {
                operation: "clock_gettime".to_owned(),
                code: None,
                reason: reason.into(),
            }),
        }
    }
}

impl Clock for FakeClock {
    fn monotonic_secs(&self) -> Result<u64, SysError> {
        self.reading.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_host_clock_moves_forward_and_is_not_the_wall_clock() {
        let first = HostClock.monotonic_secs().unwrap();
        let second = HostClock.monotonic_secs().unwrap();
        assert!(second >= first);
        // Seconds since boot, not since 1970: a deadline anchored to the wall
        // clock would be about 1.7 billion. This is a property of the clock
        // chosen, so a swap to the realtime clock fails here.
        assert!(first < 1_000_000_000, "{first} looks like wall-clock time");
        assert!(format!("{HostClock:?}").contains("HostClock"));
    }

    #[test]
    fn a_fake_clock_reads_what_it_was_set_to_and_a_broken_one_refuses() {
        assert_eq!(FakeClock::at(41).monotonic_secs().unwrap(), 41);
        let err = FakeClock::broken("no clock").monotonic_secs().unwrap_err();
        assert!(err.to_string().contains("no clock"), "{err}");
        assert!(format!("{:?}", FakeClock::at(1)).contains("FakeClock"));
    }
}
