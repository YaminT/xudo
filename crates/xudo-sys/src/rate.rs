//! The `-nopass` gate's rate ledger: a ceiling on how often one account may
//! reach the passwordless door, counted by the gate because the gate is what
//! runs.
//!
//! One file per key under `/run/xudo/rate`, named `<uid>-<label>` for an
//! attested harness and `<uid>` alone for a caller the gate could not attest.
//! Every `-nopass` invocation counts, a refusal as much as a run: with a
//! `NOPASSWD` line an agent can start the gate as often as it likes, and each
//! refusal is an audit append, so a log the agent can fill is a log that
//! refuses humans too.
//!
//! * **Ceiling.** Up to [`MAX_STAMPS`] boottime-millisecond stamps. Stamps an
//!   hour old are dropped. At [`MINUTE_CEILING`] stamps in the last minute, or
//!   [`MAX_STAMPS`] kept, the call is refused and nothing is appended.
//! * **Coalescing.** A refusal over the ceiling counts as suppressed. At most
//!   once per [`REPORT_INTERVAL_MS`] the answer carries the number to write
//!   as one audit record; every other refusal writes nothing.
//! * **Atomic.** Written as a temporary file and renamed, under the key's
//!   own `flock` (on `<key>.lock`, which no ledger name can equal), so a gate killed at any instant leaves either the
//!   old ledger or the new one. A temporary file a killed gate left is
//!   removed under the lock: no write can be in progress while it is held.
//! * **Per key.** One lock per key: a gate stopped while it holds its lock
//!   blocks that key's next calls and no other key's.
//! * **Bounded wait.** The lock is taken without blocking and retried for at
//!   most [`LOCK_ATTEMPTS`] times [`LOCK_STEP`]: `sudo` relays `SIGTSTP` and
//!   `SIGTERM` to the gate, and a gate stopped inside a blocking `flock` while
//!   it holds the lock would hold every other gate behind it. A lock that is
//!   never won is a refusal.
//! * **Fail closed.** A ledger that cannot be read, is oversized, is not
//!   private to root, or does not parse is a refusal, never a free pass.

use std::time::Duration;

use crate::spool::{Spool, SpoolDir, SpoolError, TEMP_PREFIX};

/// Where the ledgers live.
pub const RATE_DIR: &str = "/run/xudo/rate";

/// The most stamps one ledger keeps.
pub const MAX_STAMPS: usize = 600;
/// The most runs in the last minute.
pub const MINUTE_CEILING: usize = 60;
/// One minute, in the clock's unit.
pub const MINUTE_MS: u64 = 60_000;
/// One hour, in the clock's unit.
pub const HOUR_MS: u64 = 3_600_000;
/// The least time between two audit records for refusals over the ceiling.
pub const REPORT_INTERVAL_MS: u64 = 60_000;
/// How many times the lock is tried before the call is refused.
pub const LOCK_ATTEMPTS: u32 = 100;
/// The pause between two tries.
pub const LOCK_STEP: Duration = Duration::from_millis(20);
/// The most bytes of a ledger read: 600 stamps of at most 20 digits and the
/// two header lines fit with room to spare.
const MAX_LEDGER_BYTES: usize = 16 * 1024;
/// The first line of every ledger.
const HEADER: &str = "xudo-rate 1";
/// The longest label a ledger name carries.
const MAX_LABEL_BYTES: usize = 64;

/// Whose invocations a ledger counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerKey {
    /// The live uid, read from the caller's own `status`; the entry's claim
    /// is never used.
    pub uid: u32,
    /// The live harness label, or `None` for a caller that is not attested.
    pub label: Option<String>,
}

impl LedgerKey {
    /// The file the key's ledger is kept in.
    ///
    /// # Errors
    ///
    /// [`RateError::Key`] for a label that is empty, long, or holds anything
    /// but ASCII letters, digits, `_` and `-`: the name is built from it and
    /// must stay one plain component.
    pub fn file_name(&self) -> Result<String, RateError> {
        match &self.label {
            None => Ok(self.uid.to_string()),
            Some(label) => {
                let plain = !label.is_empty()
                    && label.len() <= MAX_LABEL_BYTES
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
                if plain {
                    Ok(format!("{}-{label}", self.uid))
                } else {
                    Err(RateError::Key)
                }
            }
        }
    }
}

/// What a ledger said about one more invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Under the ceiling: this invocation is counted.
    Admitted {
        /// Invocations in the last minute, this one included.
        minute: usize,
        /// Invocations in the last hour, this one included.
        hour: usize,
        /// Refusals over the ceiling that no audit record has counted yet:
        /// they ride on this invocation's record as evidence.
        carried: u64,
    },
    /// Over the ceiling: nothing was appended.
    OverCeiling {
        /// Invocations in the last minute.
        minute: usize,
        /// Invocations in the last hour.
        hour: usize,
        /// `Some(n)` when this refusal is the one to write an audit record
        /// for, and `n` refusals since the last record (this one included) are
        /// what it stands for. `None`: write nothing.
        report: Option<u64>,
    },
}

/// Why the ledger could not be consulted. Every one is a refusal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RateError {
    /// The key cannot be made into one plain file name.
    #[error("the ledger key is not a plain name")]
    Key,
    /// The lock was not won within the bounded wait.
    #[error("the ledger lock was busy for {LOCK_ATTEMPTS} tries")]
    Busy,
    /// The ledger directory or a ledger file failed.
    #[error("the ledger: {0}")]
    Spool(SpoolError),
    /// A ledger file is not one this code wrote.
    #[error("the ledger is not valid: {0}")]
    Corrupt(&'static str),
}

/// The ledger directory: a [`Spool`] that can also be locked without
/// blocking.
pub trait RateDir: Spool {
    /// Tries the exclusive lock of the key named `name` once, creating its
    /// lock file if need be. The lock is held until [`Self::release`].
    ///
    /// # Errors
    ///
    /// [`SpoolError::Io`] when the lock fails for any reason but being held,
    /// and [`SpoolError::Unreadable`] when the lock file is not a private
    /// regular file of root's.
    fn try_lock(&self, name: &str) -> Result<bool, SpoolError>;

    /// Gives up the lock [`Self::try_lock`] won.
    fn release(&self);
}

/// The ledger of one account, taken from the host.
pub trait RateLedger {
    /// Counts one invocation of `key` at boottime `now_ms`, or refuses it.
    ///
    /// # Errors
    ///
    /// [`RateError`]; the caller refuses.
    fn admit(&self, key: &LedgerKey, now_ms: u64) -> Result<Admission, RateError>;
}

/// The real ledger: `/run/xudo/rate`, opened through the trust walk.
#[derive(Clone, Copy, Debug)]
pub struct HostRateLedger;

impl RateLedger for HostRateLedger {
    fn admit(&self, key: &LedgerKey, now_ms: u64) -> Result<Admission, RateError> {
        admit_opened(SpoolDir::open(std::path::Path::new(RATE_DIR)), key, now_ms)
    }
}

/// [`admit`] on a directory that may not have opened, pausing with the real
/// clock: a directory that failed the trust walk is a refusal.
fn admit_opened(
    opened: Result<SpoolDir, SpoolError>,
    key: &LedgerKey,
    now_ms: u64,
) -> Result<Admission, RateError> {
    match opened {
        Ok(dir) => admit(&dir, key, now_ms, &std::thread::sleep),
        Err(error) => Err(RateError::Spool(error)),
    }
}

/// What one ledger holds.
#[derive(Debug, PartialEq, Eq)]
struct State {
    /// The boottime stamp of the last audit record for over-ceiling refusals.
    last_report_ms: u64,
    /// Refusals since then, not yet written.
    suppressed: u64,
    /// Invocations, oldest first.
    stamps: Vec<u64>,
}

impl State {
    fn fresh() -> Self {
        Self {
            last_report_ms: 0,
            suppressed: 0,
            stamps: Vec::new(),
        }
    }

    fn render(&self) -> String {
        let mut text = format!("{HEADER}\n{} {}\n", self.last_report_ms, self.suppressed);
        for stamp in &self.stamps {
            text.push_str(&stamp.to_string());
            text.push('\n');
        }
        text
    }

    fn parse(bytes: &[u8]) -> Result<Self, RateError> {
        let text = std::str::from_utf8(bytes).map_err(|_| RateError::Corrupt("not text"))?;
        let mut lines = text.split('\n');
        if lines.next() != Some(HEADER) {
            return Err(RateError::Corrupt("no header"));
        }
        let counters = lines.next().ok_or(RateError::Corrupt("no counters"))?;
        let (last, suppressed) = counters
            .split_once(' ')
            .ok_or(RateError::Corrupt("bad counters"))?;
        let mut state = Self {
            last_report_ms: number(last)?,
            suppressed: number(suppressed)?,
            stamps: Vec::new(),
        };
        let mut rest: Vec<&str> = lines.collect();
        // The text ends with a newline, so the last piece is empty.
        if rest.pop() != Some("") {
            return Err(RateError::Corrupt("no final newline"));
        }
        if rest.len() > MAX_STAMPS {
            return Err(RateError::Corrupt("more stamps than the ledger keeps"));
        }
        for line in rest {
            state.stamps.push(number(line)?);
        }
        Ok(state)
    }
}

/// A canonical decimal: what `to_string` writes and nothing else, so a ledger
/// has one spelling.
fn number(text: &str) -> Result<u64, RateError> {
    match text.parse::<u64>() {
        Ok(value) if value.to_string() == text => Ok(value),
        _ => Err(RateError::Corrupt("not a number")),
    }
}

/// The body of [`RateLedger::admit`], on any directory, with the pause as a
/// parameter so a test can count it.
///
/// # Errors
///
/// [`RateError`]; the caller refuses.
pub fn admit(
    dir: &dyn RateDir,
    key: &LedgerKey,
    now_ms: u64,
    sleep: &dyn Fn(Duration),
) -> Result<Admission, RateError> {
    let name = key.file_name()?;
    lock_within_bound(dir, &name, sleep)?;
    let result = admit_locked(dir, &name, now_ms);
    dir.release();
    result
}

/// Tries the lock up to [`LOCK_ATTEMPTS`] times, pausing between tries.
fn lock_within_bound(
    dir: &dyn RateDir,
    name: &str,
    sleep: &dyn Fn(Duration),
) -> Result<(), RateError> {
    for attempt in 0..LOCK_ATTEMPTS {
        if dir.try_lock(name).map_err(RateError::Spool)? {
            return Ok(());
        }
        if attempt.saturating_add(1) < LOCK_ATTEMPTS {
            sleep(LOCK_STEP);
        }
    }
    Err(RateError::Busy)
}

/// What is left of the previous ledger once the lock is held.
enum Previous {
    /// A ledger file, and the bytes it held.
    Present(Vec<u8>, State),
    /// No file yet.
    Absent,
}

fn admit_locked(dir: &dyn RateDir, name: &str, now_ms: u64) -> Result<Admission, RateError> {
    // The lock is held, so no write is in progress: a temporary file is a
    // gate that was killed between creating it and renaming it.
    for stale in [
        format!("{TEMP_PREFIX}{name}"),
        format!("{TEMP_PREFIX}replace-{name}"),
    ] {
        dir.remove(stale.as_bytes()).map_err(RateError::Spool)?;
    }
    let previous = match dir.read(name.as_bytes(), MAX_LEDGER_BYTES) {
        Ok(bytes) => {
            let state = State::parse(&bytes)?;
            Previous::Present(bytes, state)
        }
        // Nothing readable is either no file or a file that is wrong. The
        // exclusive create below tells them apart: it never replaces one.
        Err(SpoolError::Unreadable { .. }) => Previous::Absent,
        Err(other) => return Err(RateError::Spool(other)),
    };
    let (mut state, bytes) = match previous {
        Previous::Present(bytes, state) => (state, Some(bytes)),
        Previous::Absent => (State::fresh(), None),
    };
    state
        .stamps
        .retain(|stamp| *stamp > now_ms.saturating_sub(HOUR_MS));
    let in_minute = |state: &State| {
        state
            .stamps
            .iter()
            .filter(|stamp| **stamp > now_ms.saturating_sub(MINUTE_MS))
            .count()
    };
    let minute = in_minute(&state);
    let over = minute >= MINUTE_CEILING || state.stamps.len() >= MAX_STAMPS;
    let admission = if over {
        state.suppressed = state.suppressed.saturating_add(1);
        let due = state.last_report_ms == 0
            || now_ms.saturating_sub(state.last_report_ms) >= REPORT_INTERVAL_MS;
        let report = due.then_some(state.suppressed);
        if due {
            state.last_report_ms = now_ms;
            state.suppressed = 0;
        }
        Admission::OverCeiling {
            minute,
            hour: state.stamps.len(),
            report,
        }
    } else {
        state.stamps.push(now_ms);
        // A flood that stopped before its next report is written here, once.
        let carried = std::mem::take(&mut state.suppressed);
        Admission::Admitted {
            minute: minute.saturating_add(1),
            hour: state.stamps.len(),
            carried,
        }
    };
    store(dir, name, bytes.as_deref(), &state)?;
    Ok(admission)
}

/// Writes the ledger: a temporary file renamed into place, never a write in
/// place.
fn store(
    dir: &dyn RateDir,
    name: &str,
    previous: Option<&[u8]>,
    state: &State,
) -> Result<(), RateError> {
    let text = state.render();
    let written = match previous {
        Some(old) => dir.replace(name.as_bytes(), old, text.as_bytes()),
        None => dir.publish(name, text.as_bytes()),
    };
    written.map_err(RateError::Spool)
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

    use std::cell::Cell;

    use super::*;
    use crate::spool::{FakeSpool, SpoolCall};

    const T0: u64 = 10_000_000;

    fn key() -> LedgerKey {
        LedgerKey {
            uid: 1001,
            label: Some("codex".to_owned()),
        }
    }

    fn no_sleep(_: Duration) {}

    fn admitted(answer: &Admission) -> bool {
        match answer {
            Admission::Admitted { .. } => true,
            Admission::OverCeiling { .. } => false,
        }
    }

    fn report_of(answer: &Admission) -> Option<u64> {
        match answer {
            Admission::OverCeiling { report, .. } => *report,
            Admission::Admitted { .. } => None,
        }
    }

    fn refusal_text(result: Result<Admission, RateError>) -> String {
        result.unwrap_err().to_string()
    }

    fn run(dir: &FakeSpool, now: u64) -> Admission {
        admit(dir, &key(), now, &no_sleep).unwrap()
    }

    #[test]
    fn a_key_names_one_plain_file() {
        assert_eq!(key().file_name().unwrap(), "1001-codex");
        let unattested = LedgerKey {
            uid: 1001,
            label: None,
        };
        assert_eq!(unattested.file_name().unwrap(), "1001");
        let long = "x".repeat(65);
        for bad in ["", "a/b", "..", "a b", "é", long.as_str(), "a\0b", "a.b"] {
            let hostile = LedgerKey {
                uid: 1,
                label: Some(bad.to_owned()),
            };
            assert_eq!(hostile.file_name(), Err(RateError::Key), "{bad:?}");
        }
    }

    #[test]
    fn the_first_invocation_creates_the_ledger_and_is_counted() {
        let dir = FakeSpool::new();
        assert_eq!(
            run(&dir, T0),
            Admission::Admitted {
                minute: 1,
                hour: 1,
                carried: 0
            }
        );
        let files = dir.files();
        let text = String::from_utf8(files[b"1001-codex".as_slice()].clone()).unwrap();
        assert_eq!(text, format!("xudo-rate 1\n0 0\n{T0}\n"));
        assert_eq!(dir.calls().last(), Some(&SpoolCall::Release));
    }

    #[test]
    fn the_sixty_first_run_in_a_minute_is_refused() {
        let dir = FakeSpool::new();
        for step in 0..60u64 {
            assert!(admitted(&run(&dir, T0 + step)));
        }
        let over = run(&dir, T0 + 60);
        assert_eq!(
            over,
            Admission::OverCeiling {
                minute: 60,
                hour: 60,
                report: Some(1)
            }
        );
        // Nothing was appended: the ledger still holds sixty stamps.
        let text = String::from_utf8(dir.files()[b"1001-codex".as_slice()].clone()).unwrap();
        assert_eq!(text.lines().count(), 2 + 60);
    }

    #[test]
    fn refusals_over_the_ceiling_report_once_a_minute_with_the_count() {
        // Sixty stamps in the last minute and a report written a second ago.
        let state = State {
            last_report_ms: T0 + 1,
            suppressed: 0,
            stamps: (0..60).map(|step| T0 + 40_000 + step).collect(),
        };
        let dir = FakeSpool::new().with_file("1001-codex", state.render());
        // A flood inside the minute: refused every time, reported never.
        for step in 0..500u64 {
            let over = run(&dir, T0 + 50_000 + step);
            assert!(!admitted(&over));
            assert_eq!(report_of(&over), None);
        }
        // The report interval passes while the stamps are still in the minute:
        // one record, carrying every refusal since the last.
        assert_eq!(report_of(&run(&dir, T0 + 61_000)), Some(501));
        // And the count starts again.
        let after = run(&dir, T0 + 61_001);
        assert!(!admitted(&after));
        assert_eq!(report_of(&after), None);
    }

    #[test]
    fn a_full_hour_ledger_refuses_until_stamps_age_out() {
        // Fifty-nine a minute for twelve minutes: 600 kept, none over the
        // minute ceiling.
        let dir = FakeSpool::new();
        let mut now = T0;
        let mut kept = 0usize;
        for _minute in 0..12 {
            for _ in 0..50 {
                kept += usize::from(admitted(&run(&dir, now)));
                now += 1_000;
            }
            now += 10_000;
        }
        assert_eq!(kept, MAX_STAMPS);
        let refused = run(&dir, now);
        assert!(!admitted(&refused));
        // An hour on, the oldest stamps are gone and the door reopens.
        let reopened = run(&dir, T0 + HOUR_MS + 1_000_000);
        assert!(admitted(&reopened));
        assert_eq!(report_of(&reopened), None);
    }

    #[test]
    fn stamps_an_hour_old_are_dropped() {
        let dir = FakeSpool::new();
        run(&dir, T0);
        let later = run(&dir, T0 + HOUR_MS + 5);
        assert_eq!(
            later,
            Admission::Admitted {
                minute: 1,
                hour: 1,
                carried: 0
            }
        );
    }

    #[test]
    fn a_held_lock_for_one_key_does_not_block_another_key() {
        let dir = FakeSpool::new().busy_key("1001-codex");
        assert_eq!(admit(&dir, &key(), T0, &no_sleep), Err(RateError::Busy));
        let other = LedgerKey {
            uid: 1002,
            label: Some("codex".to_owned()),
        };
        assert_eq!(
            admit(&dir, &other, T0, &no_sleep),
            Ok(Admission::Admitted {
                minute: 1,
                hour: 1,
                carried: 0
            })
        );
        assert!(dir.files().contains_key(b"1002-codex".as_slice()));
        assert!(!dir.files().contains_key(b"1001-codex".as_slice()));
    }

    #[test]
    fn a_stale_temporary_is_cleared_for_its_own_key_only() {
        let dir = FakeSpool::new().with_file(".tmp.1002-codex", "another key's write");
        run(&dir, T0);
        assert!(dir.files().contains_key(b".tmp.1002-codex".as_slice()));
    }

    // Exactly on the edge of each window: 1 ms either side flips the answer.
    #[test]
    fn a_stamp_exactly_a_minute_old_is_out_of_the_minute_and_one_ms_younger_is_in() {
        let sixty = |age: u64| State {
            last_report_ms: 0,
            suppressed: 0,
            stamps: vec![T0 - age; 60],
        };
        let at_edge = FakeSpool::new().with_file("1001-codex", sixty(MINUTE_MS).render());
        assert!(admitted(&run(&at_edge, T0)));
        let inside = FakeSpool::new().with_file("1001-codex", sixty(MINUTE_MS - 1).render());
        assert!(!admitted(&run(&inside, T0)));
    }

    #[test]
    fn a_stamp_exactly_an_hour_old_is_dropped_and_one_ms_younger_is_kept() {
        let full = |age: u64| State {
            last_report_ms: 0,
            suppressed: 0,
            stamps: vec![T0 - age; MAX_STAMPS],
        };
        let at_edge = FakeSpool::new().with_file("1001-codex", full(HOUR_MS).render());
        assert_eq!(
            run(&at_edge, T0),
            Admission::Admitted {
                minute: 1,
                hour: 1,
                carried: 0
            }
        );
        let inside = FakeSpool::new().with_file("1001-codex", full(HOUR_MS - 1).render());
        assert!(!admitted(&run(&inside, T0)));
    }

    #[test]
    fn the_report_is_due_exactly_one_interval_after_the_last() {
        let flooded = |last: u64| {
            let state = State {
                last_report_ms: last,
                suppressed: 4,
                stamps: vec![T0 - 1; 60],
            };
            FakeSpool::new().with_file("1001-codex", state.render())
        };
        let on_time = flooded(T0 - REPORT_INTERVAL_MS);
        assert_eq!(report_of(&run(&on_time, T0)), Some(5));
        let early = flooded(T0 - REPORT_INTERVAL_MS + 1);
        assert_eq!(report_of(&run(&early, T0)), None);
    }

    #[test]
    fn refusals_not_yet_reported_ride_on_the_next_admitted_record() {
        // A flood that stopped before its minute was up: three refusals are
        // owed to the trail, and the next run that is let through carries them.
        let state = State {
            last_report_ms: T0 - 1,
            suppressed: 3,
            stamps: vec![],
        };
        let dir = FakeSpool::new().with_file("1001-codex", state.render());
        assert_eq!(
            run(&dir, T0),
            Admission::Admitted {
                minute: 1,
                hour: 1,
                carried: 3
            }
        );
        // Said once: the next one carries nothing.
        assert_eq!(
            run(&dir, T0 + 1),
            Admission::Admitted {
                minute: 2,
                hour: 2,
                carried: 0
            }
        );
    }

    #[test]
    fn two_keys_have_two_ledgers() {
        let dir = FakeSpool::new();
        for step in 0..60u64 {
            run(&dir, T0 + step);
        }
        let other = LedgerKey {
            uid: 1002,
            label: Some("codex".to_owned()),
        };
        assert_eq!(
            admit(&dir, &other, T0 + 61, &no_sleep).unwrap(),
            Admission::Admitted {
                minute: 1,
                hour: 1,
                carried: 0
            }
        );
    }

    #[test]
    fn an_unreadable_ledger_refuses() {
        for garbage in [
            String::new(),
            "not a ledger\n".to_owned(),
            "xudo-rate 1\n".to_owned(),
            "xudo-rate 1\n0\n".to_owned(),
            "xudo-rate 1".to_owned(),
            "xudo-rate 1\n0 x\n".to_owned(),
            "xudo-rate 1\n0 0\n5".to_owned(),
            "xudo-rate 1\n0 0\n+5\n".to_owned(),
            "xudo-rate 1\n0 0\n05\n".to_owned(),
            "xudo-rate 1\n0 0\n-5\n".to_owned(),
            "xudo-rate 1\n0 0\nfive\n".to_owned(),
            "xudo-rate 1\nx 0\n".to_owned(),
            "xudo-rate 1\n0 0\n99999999999999999999999\n".to_owned(),
            format!("xudo-rate 1\n0 0\n{}", "7\n".repeat(MAX_STAMPS + 1)),
        ] {
            let dir = FakeSpool::new().with_file("1001-codex", garbage.clone());
            let refused = admit(&dir, &key(), T0, &no_sleep);
            assert!(refusal_text(refused).contains("not valid"), "{garbage:?}");
            assert_eq!(dir.calls().last(), Some(&SpoolCall::Release));
        }
        let dir = FakeSpool::new().with_file("1001-codex", vec![0xff, 0xfe]);
        assert_eq!(
            admit(&dir, &key(), T0, &no_sleep),
            Err(RateError::Corrupt("not text"))
        );
    }

    #[test]
    fn an_oversized_or_failing_ledger_read_refuses() {
        let big = "x".repeat(MAX_LEDGER_BYTES + 1);
        let dir = FakeSpool::new().with_file("1001-codex", big);
        let text = refusal_text(admit(&dir, &key(), T0, &no_sleep));
        assert!(text.starts_with("the ledger:"), "{text}");
        let bad_key = LedgerKey {
            uid: 1,
            label: Some("a/b".to_owned()),
        };
        assert_eq!(admit(&dir, &bad_key, T0, &no_sleep), Err(RateError::Key));
    }

    #[test]
    fn a_ledger_that_exists_but_cannot_be_read_is_never_replaced() {
        // The fake reports the file as unreadable, as the real directory does
        // for a link, a loose mode or another owner. The exclusive create finds
        // the name taken, and nothing is written over it.
        let dir = FakeSpool::new()
            .with_file("1001-codex", "xudo-rate 1\n0 0\n")
            .failing_read("1001-codex");
        let refused = admit(&dir, &key(), T0, &no_sleep);
        assert_eq!(
            refusal_text(refused),
            "the ledger: 1001-codex already exists in the spool"
        );
        assert_eq!(
            dir.files()[b"1001-codex".as_slice()],
            b"xudo-rate 1\n0 0\n".to_vec()
        );
    }

    #[test]
    fn a_failed_write_refuses_and_keeps_the_old_ledger() {
        let dir = FakeSpool::new();
        run(&dir, T0);
        let before = dir.files();
        let failing = FakeSpool::new()
            .with_file("1001-codex", before[b"1001-codex".as_slice()].clone())
            .failing_replace(SpoolError::Io {
                operation: "write".to_owned(),
                at: "x".to_owned(),
                code: Some(28),
                reason: "scripted".to_owned(),
            });
        let text = refusal_text(admit(&failing, &key(), T0 + 1, &no_sleep));
        assert!(text.contains("scripted"), "{text}");
        assert_eq!(failing.files(), before);
        let failing_create = FakeSpool::new().failing_publish(SpoolError::Io {
            operation: "write".to_owned(),
            at: "x".to_owned(),
            code: Some(28),
            reason: "scripted".to_owned(),
        });
        assert!(admit(&failing_create, &key(), T0, &no_sleep).is_err());
        assert!(failing_create.files().is_empty());
    }

    #[test]
    fn a_failing_removal_of_a_stale_temporary_refuses() {
        let dir = FakeSpool::new().failing_remove(SpoolError::Io {
            operation: "unlink".to_owned(),
            at: "x".to_owned(),
            code: Some(13),
            reason: "scripted".to_owned(),
        });
        let text = refusal_text(admit(&dir, &key(), T0, &no_sleep));
        assert!(text.contains("scripted"), "{text}");
        assert_eq!(dir.calls().last(), Some(&SpoolCall::Release));
    }

    #[test]
    fn a_stale_temporary_left_by_a_killed_gate_is_cleared_and_counting_goes_on() {
        let dir = FakeSpool::new()
            .with_file(".tmp.1001-codex", "xudo-rate 1\n0 0\n1\n2")
            .with_file(".tmp.replace-1001-codex", "half a ledg");
        run(&dir, T0);
        let files = dir.files();
        assert!(!files.contains_key(b".tmp.1001-codex".as_slice()));
        assert!(!files.contains_key(b".tmp.replace-1001-codex".as_slice()));
        assert_eq!(
            run(&dir, T0 + 1),
            Admission::Admitted {
                minute: 2,
                hour: 2,
                carried: 0
            }
        );
    }

    #[test]
    fn a_lock_that_stays_busy_is_tried_a_bounded_number_of_times_then_refused() {
        let dir = FakeSpool::new().busy_locks(usize::MAX);
        let pauses = Cell::new(0u32);
        let refused = admit(&dir, &key(), T0, &|step| {
            assert_eq!(step, LOCK_STEP);
            pauses.set(pauses.get() + 1);
        });
        assert_eq!(refused, Err(RateError::Busy));
        assert_eq!(pauses.get(), LOCK_ATTEMPTS - 1);
        let tries = dir
            .calls()
            .iter()
            .filter(|call| matches!(call, SpoolCall::TryLock(name) if name == "1001-codex"))
            .count();
        assert_eq!(tries, LOCK_ATTEMPTS as usize);
        // Never held, so never released, and nothing read or written.
        assert!(!dir.calls().contains(&SpoolCall::Release));
        assert!(dir.files().is_empty());
    }

    #[test]
    fn a_lock_won_after_a_short_wait_counts() {
        let dir = FakeSpool::new().busy_locks(3);
        let pauses = Cell::new(0u32);
        let admitted = admit(&dir, &key(), T0, &|_| pauses.set(pauses.get() + 1));
        assert_eq!(
            admitted,
            Ok(Admission::Admitted {
                minute: 1,
                hour: 1,
                carried: 0
            })
        );
        assert_eq!(pauses.get(), 3);
    }

    #[test]
    fn a_lock_that_fails_for_another_reason_refuses_at_once() {
        let dir = FakeSpool::new().failing_lock(SpoolError::Io {
            operation: "flock".to_owned(),
            at: "x".to_owned(),
            code: Some(9),
            reason: "scripted".to_owned(),
        });
        let refused = admit(&dir, &key(), T0, &no_sleep);
        assert!(refusal_text(refused).contains("scripted"));
        assert_eq!(
            dir.calls(),
            vec![SpoolCall::TryLock("1001-codex".to_owned())]
        );
    }

    #[test]
    fn every_error_renders_a_sentence() {
        for error in [
            RateError::Key,
            RateError::Busy,
            RateError::Corrupt("x"),
            RateError::Spool(SpoolError::Gone {
                name: "n".to_owned(),
            }),
        ] {
            assert!(error.to_string().len() > 10, "{error:?}");
        }
    }

    #[test]
    fn the_host_ledger_on_a_machine_without_the_directory_refuses() {
        // Off a lane the directory is absent or not root's: either way the
        // real ledger is a refusal, never an admission.
        let _ = HostRateLedger.admit(&key(), T0);
        let absent = SpoolDir::open(std::path::Path::new("/nonexistent/xudo-rate"));
        assert!(refusal_text(admit_opened(absent, &key(), T0)).starts_with("the ledger:"));
        no_sleep(LOCK_STEP);
    }

    #[cfg(feature = "fake")]
    mod on_a_real_directory {
        use std::os::unix::fs::PermissionsExt;
        use std::path::PathBuf;

        use super::*;

        fn private(name: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!("xudo-rate-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            dir
        }

        #[test]
        fn an_opened_directory_counts_and_one_that_did_not_open_refuses() {
            let path = private("opened");
            let opened = SpoolDir::open_test_directory(&path);
            assert_eq!(
                admit_opened(opened, &key(), T0),
                Ok(Admission::Admitted {
                    minute: 1,
                    hour: 1,
                    carried: 0
                })
            );
            let refused = admit_opened(
                Err(SpoolError::Gone {
                    name: "x".to_owned(),
                }),
                &key(),
                T0,
            );
            assert!(refusal_text(refused).starts_with("the ledger:"));
            let _ = std::fs::remove_dir_all(path);
        }

        #[test]
        fn a_lock_that_fails_for_another_reason_is_an_error_not_busy() {
            let path = private("flockerr");
            let dir = SpoolDir::open_test_directory(&path).unwrap();
            assert_eq!(dir.lock_outcome(Ok(())), Ok(true));
            assert_eq!(
                dir.lock_outcome(Err(rustix::io::Errno::WOULDBLOCK)),
                Ok(false)
            );
            let failed = dir.lock_outcome(Err(rustix::io::Errno::BADF));
            assert!(failed.unwrap_err().to_string().contains("flock"));
            let _ = std::fs::remove_dir_all(path);
        }

        #[test]
        fn a_stopped_gate_holding_one_key_blocks_that_key_and_no_other() {
            let path = private("lock");
            let stopped = SpoolDir::open_test_directory(&path).unwrap();
            let other = SpoolDir::open_test_directory(&path).unwrap();
            // A gate stopped while it holds the lock of the key's ledger.
            assert_eq!(stopped.try_lock("1001-codex"), Ok(true));
            assert_eq!(admit(&other, &key(), T0, &no_sleep), Err(RateError::Busy));
            let neighbour = LedgerKey {
                uid: 1002,
                label: Some("codex".to_owned()),
            };
            assert_eq!(
                admit(&other, &neighbour, T0, &no_sleep),
                Ok(Admission::Admitted {
                    minute: 1,
                    hour: 1,
                    carried: 0
                })
            );
            stopped.release();
            assert!(admit(&other, &key(), T0 + 1, &no_sleep).is_ok());
            let _ = std::fs::remove_dir_all(path);
        }

        // The replacing write exchanges two names, which only Linux can do.
        #[cfg(target_os = "linux")]
        #[test]
        fn a_gate_killed_mid_ledger_write_leaves_a_valid_ledger() {
            let path = private("killed");
            let dir = SpoolDir::open_test_directory(&path).unwrap();
            for step in 0..5u64 {
                admit(&dir, &key(), T0 + step, &no_sleep).unwrap();
            }
            let valid = std::fs::read(path.join("1001-codex")).unwrap();
            // What a gate killed between "create the temporary" and "rename it"
            // leaves: a torn temporary beside the untouched ledger, for both
            // spellings the writers use.
            std::fs::write(path.join(".tmp.1001-codex"), b"xudo-rate 1\n0 0\n12").unwrap();
            std::fs::write(path.join(".tmp.replace-1001-codex"), b"xudo-ra").unwrap();
            // The ledger a reader sees is still the last whole one.
            assert_eq!(std::fs::read(path.join("1001-codex")).unwrap(), valid);
            assert!(State::parse(&valid).is_ok());
            // And the next gate clears the debris and counts on from it.
            assert_eq!(
                admit(&dir, &key(), T0 + 10, &no_sleep).unwrap(),
                Admission::Admitted {
                    minute: 6,
                    hour: 6,
                    carried: 0
                }
            );
            assert!(!path.join(".tmp.1001-codex").exists());
            assert!(!path.join(".tmp.replace-1001-codex").exists());
            let _ = std::fs::remove_dir_all(path);
        }

        #[test]
        fn a_ledger_that_is_a_link_or_loose_is_refused_not_followed() {
            let path = private("hostile");
            let dir = SpoolDir::open_test_directory(&path).unwrap();
            std::fs::write(path.join("target"), "xudo-rate 1\n0 0\n").unwrap();
            std::os::unix::fs::symlink(path.join("target"), path.join("1001-codex")).unwrap();
            assert!(admit(&dir, &key(), T0, &no_sleep).is_err());
            std::fs::remove_file(path.join("1001-codex")).unwrap();
            std::fs::write(path.join("1001-codex"), "xudo-rate 1\n0 0\n").unwrap();
            std::fs::set_permissions(
                path.join("1001-codex"),
                std::fs::Permissions::from_mode(0o666),
            )
            .unwrap();
            assert!(admit(&dir, &key(), T0, &no_sleep).is_err());
            let _ = std::fs::remove_dir_all(path);
        }
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn the_ledger_never_admits_more_than_the_ceiling_in_a_minute(
            gaps in proptest::collection::vec(0u64..2_000, 1..300)
        ) {
            let dir = FakeSpool::new();
            let mut now = T0;
            let mut stamps: Vec<u64> = Vec::new();
            for gap in gaps {
                now += gap;
                if admitted(&admit(&dir, &key(), now, &no_sleep).unwrap()) {
                    stamps.push(now);
                }
                let in_minute = stamps.iter().filter(|at| **at + MINUTE_MS > now).count();
                prop_assert!(in_minute <= MINUTE_CEILING);
                let in_hour = stamps.iter().filter(|at| **at + HOUR_MS > now).count();
                prop_assert!(in_hour <= MAX_STAMPS);
            }
        }

        #[test]
        fn a_ledger_round_trips_through_its_text(
            stamps in proptest::collection::vec(any::<u64>(), 0..=MAX_STAMPS),
            last in any::<u64>(),
            suppressed in any::<u64>(),
        ) {
            let state = State { last_report_ms: last, suppressed, stamps };
            prop_assert_eq!(State::parse(state.render().as_bytes()).unwrap(), state);
        }

        #[test]
        fn no_bytes_parse_to_a_ledger_that_renders_differently(
            bytes in proptest::collection::vec(any::<u8>(), 0..200)
        ) {
            if let Ok(state) = State::parse(&bytes) {
                prop_assert_eq!(state.render().into_bytes(), bytes);
            }
        }
    }
}
