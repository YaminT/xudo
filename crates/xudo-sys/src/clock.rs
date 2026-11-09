//! The one clock request deadlines are measured on.
//!
//! The broker stamps every spool entry with a deadline and the gate refuses an
//! entry past it, so the two must read the **same** clock. That clock is
//! `CLOCK_BOOTTIME`, read here, in milliseconds: unlike monotonic time it
//! includes suspend. Both binaries read it through [`HostClock`], so there is one
//! definition of "now" for a deadline, not two that could drift.

use rustix::time::ClockId;

/// Clock used to stamp and judge request deadlines.
pub const DEADLINE_CLOCK: ClockId = ClockId::Boottime;

/// A source of boottime milliseconds.
pub trait Clock {
    /// Milliseconds of `CLOCK_BOOTTIME`.
    fn boottime_millis(&self) -> u64;

    /// Milliseconds since the Unix epoch. For records read by people, never
    /// for a deadline.
    fn wall_millis(&self) -> u64;
}

/// The running kernel's `CLOCK_BOOTTIME`.
#[derive(Clone, Copy, Debug)]
pub struct HostClock;

impl Clock for HostClock {
    fn wall_millis(&self) -> u64 {
        let since = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    }

    fn boottime_millis(&self) -> u64 {
        let now = rustix::time::clock_gettime(DEADLINE_CLOCK);
        let secs = u64::try_from(now.tv_sec).unwrap_or(0);
        let nanos = u32::try_from(now.tv_nsec).unwrap_or(0);
        u64::try_from(std::time::Duration::new(secs, nanos).as_millis()).unwrap_or(0)
    }
}

/// A clock that always reads the same second, for tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn wall_millis(&self) -> u64 {
        self.0.saturating_add(1_700_000_000_000)
    }

    fn boottime_millis(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_host_clock_never_runs_backwards() {
        let first = HostClock.boottime_millis();
        let second = HostClock.boottime_millis();
        assert!(second >= first, "{second} < {first}");
        assert!(format!("{HostClock:?}").contains("HostClock"));
    }

    #[test]
    fn the_host_clock_is_milliseconds_since_boot_and_not_the_wall_clock() {
        // A deadline anchored to the wall clock is one an operator extends by
        // correcting the time and an attacker extends by anything that moves
        // it backwards. The wall clock reads about 1.8 billion; boottime is
        // milliseconds since boot, and no host runs for thirty-one years.
        // A swap to `ClockId::Realtime` fails here and nowhere else.
        let now = HostClock.boottime_millis();
        assert!(now < 1_000_000_000_000, "{now} looks like wall-clock time");
    }

    #[test]
    fn the_wall_clock_is_milliseconds_since_the_epoch() {
        assert!(HostClock.wall_millis() > 1_700_000_000_000);
        assert_eq!(FixedClock(5).wall_millis(), 1_700_000_000_005);
    }

    #[test]
    fn a_fixed_clock_reads_what_it_was_given() {
        assert_eq!(FixedClock(1_234).boottime_millis(), 1_234);
        assert_eq!(FixedClock(7), FixedClock(7));
    }

    #[test]
    fn deadlines_use_boottime_because_ci_hosts_do_not_suspend() {
        assert_eq!(DEADLINE_CLOCK, ClockId::Boottime);
    }
}
