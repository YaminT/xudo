//! The journald mirror: each record, sent to journald's native socket.
//!
//! One datagram per record, built by [`xudo_audit::journal::datagram`] and sent
//! with `sendto` on an `AF_UNIX` datagram socket through rustix's safe API — no
//! client library, no new dependency. A send that does not complete within a
//! bound fails, so a stalled journald refuses a decision rather than hanging
//! it. With `SO_SNDTIMEO` set, the kernel does not restart `sendto` after a
//! signal: `EINTR` means nothing was sent. That is not a refusal. The send is
//! tried again with only the time still left on the original monotonic
//! deadline, and a signal that keeps arriving refuses when that deadline
//! passes rather than stretching it or hanging the decision.
//!
//! # Where there is no journald
//!
//! The send fails — no socket, nobody listening — and the trail fails the
//! append, so the decision is refused. A mirror that is configured is
//! required; one that is missing is never skipped quietly. On a platform with
//! no journald at all (macOS, the development host) every send fails the same
//! way.
//!
//! # Size
//!
//! An entry is bounded below one datagram (see [`xudo_audit::journal`]), so the
//! protocol's `memfd` path for oversized entries is not built: a writer refuses
//! a record too long for the log before it reaches this point. A host whose
//! socket send buffer is tuned below the bound gets `EMSGSIZE`, which fails
//! closed like any other refusal.
//!
//! # What journald may still drop
//!
//! journald rate-limits per service and drops what exceeds the limit without
//! telling the sender. The file is the authority for that reason; the journal
//! is the copy that cannot be cut back from the file's side.
//!
//! # Reading it back
//!
//! Every field this sink sends, any local user can send too. Read the entries
//! back only through [`xudo_audit::journal::query`], which matches `_UID=0` —
//! the one field journald takes from the kernel rather than the sender.

use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(any(test, target_os = "linux"))]
use std::time::Instant;

use xudo_audit::Record;

use super::{AuditError, AuditMirror};

/// journald's native-protocol socket.
pub const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// How long a send may block on a full journald queue before it fails.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// What a send says when the monotonic deadline passes, including when a
/// signal keeps interrupting it until nothing is left.
#[cfg(any(test, target_os = "linux"))]
const SEND_DEADLINE: &str = "the send deadline passed before journald took the record";

/// Sends every record to journald.
#[derive(Clone, Debug)]
pub struct JournaldSink {
    socket: PathBuf,
    identifier: &'static str,
    timeout: Duration,
}

impl JournaldSink {
    /// The system journal, with entries attributed to `identifier` — the
    /// binary writing them, `xudod` or `xudo-gate`.
    pub fn system(identifier: &'static str) -> Self {
        Self::at(JOURNAL_SOCKET, identifier)
    }

    /// A journal listening on `socket`.
    pub fn at(socket: impl Into<PathBuf>, identifier: &'static str) -> Self {
        Self {
            socket: socket.into(),
            identifier,
            timeout: SEND_TIMEOUT,
        }
    }

    /// Changes how long a send may block.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The refusal for a record journald did not take.
    fn refused(&self, reason: String) -> AuditError {
        AuditError::Journal {
            socket: self.socket.display().to_string(),
            reason,
        }
    }
}

impl AuditMirror for JournaldSink {
    fn mirror(&mut self, record: &Record) -> Result<(), AuditError> {
        let payload = xudo_audit::journal::datagram(record, self.identifier)
            .map_err(|error| self.refused(error.to_string()))?;
        send(&self.socket, &payload, self.timeout).map_err(|reason| self.refused(reason))
    }
}

/// Sends `payload` as one datagram to the socket at `path`.
#[cfg(target_os = "linux")]
fn send(path: &Path, payload: &[u8], timeout: Duration) -> Result<(), String> {
    use rustix::net::sockopt::{Timeout, set_socket_timeout};
    use rustix::net::{
        AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType, sendto, socket_with,
    };

    let opened = SocketAddrUnix::new(path).and_then(|address| {
        socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map(|fd| (fd, address))
    });
    let (fd, address) = match opened {
        Ok(opened) => opened,
        Err(errno) => return Err(errno.to_string()),
    };
    // One function body, not a copy per caller. Coverage merges generic
    // instantiations by the copy with the most regions, so a copy that never
    // sees `EINTR` would hide the copy that does.
    let mut now = Instant::now;
    send_until(payload.len(), timeout, &mut now, &mut |remaining| {
        transmit(remaining, &mut |bounded| {
            set_socket_timeout(&fd, Timeout::Send, Some(bounded))
                .and_then(|()| sendto(&fd, payload, SendFlags::NOSIGNAL, &address))
        })
    })
}

/// One `sendto`. Only [`Attempt::Interrupted`] is tried again, and only while
/// the original deadline still has time left.
#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Debug, PartialEq, Eq)]
enum Attempt {
    /// The kernel accepted `count` bytes.
    Sent(usize),
    /// `EINTR`: nothing was sent. The deadline is unchanged.
    Interrupted,
    /// Any other failure, including the kernel's send timeout.
    Failed(String),
}

/// The time still inside `timeout`, measured from `started`.
///
/// `None` when the deadline has passed or the clock moved backwards. A
/// backwards step is not "no time has elapsed": that reading would hand the
/// next attempt a fresh full timeout and extend the deadline.
#[cfg(any(test, target_os = "linux"))]
fn time_left(started: Instant, now: Instant, timeout: Duration) -> Option<Duration> {
    now.checked_duration_since(started)
        .and_then(|elapsed| timeout.checked_sub(elapsed))
        .filter(|left| !left.is_zero())
}

/// Calls `attempt` until the datagram is accepted, some other error refuses
/// it, or `timeout` has passed on `now`.
///
/// `now` is a monotonic clock. Each attempt is told only the time still left,
/// so a retry cannot restart the full timeout.
#[cfg(any(test, target_os = "linux"))]
fn send_until(
    len: usize,
    timeout: Duration,
    now: &mut dyn FnMut() -> Instant,
    attempt: &mut dyn FnMut(Duration) -> Attempt,
) -> Result<(), String> {
    let started = now();
    loop {
        let Some(remaining) = time_left(started, now(), timeout) else {
            return Err(SEND_DEADLINE.to_owned());
        };
        match attempt(remaining) {
            Attempt::Sent(count) => return whole(count, len),
            Attempt::Interrupted => {}
            Attempt::Failed(reason) => return Err(reason),
        }
    }
}

/// Reads one `sendto` result. `EINTR` is the only errno that is not a refusal.
#[cfg(any(test, target_os = "linux"))]
fn classify_send(result: Result<usize, rustix::io::Errno>) -> Attempt {
    match result {
        Ok(count) => Attempt::Sent(count),
        Err(rustix::io::Errno::INTR) => Attempt::Interrupted,
        Err(errno) => Attempt::Failed(errno.to_string()),
    }
}

/// A socket timeout that cannot outlast `remaining`.
///
/// `SO_SNDTIMEO` is a timeval. rustix rounds it up to the next microsecond,
/// and a zero timeval means block forever, so one microsecond is held back.
/// What cannot spare that microsecond is already the deadline.
#[cfg(any(test, target_os = "linux"))]
fn kernel_timeout(remaining: Duration) -> Option<Duration> {
    remaining
        .checked_sub(Duration::from_micros(1))
        .filter(|adjusted| !adjusted.is_zero())
}

/// One attempt, bounded so the kernel wait cannot pass `remaining`.
#[cfg(any(test, target_os = "linux"))]
fn transmit(
    remaining: Duration,
    send: &mut dyn FnMut(Duration) -> Result<usize, rustix::io::Errno>,
) -> Attempt {
    match kernel_timeout(remaining) {
        None => Attempt::Failed(SEND_DEADLINE.to_owned()),
        Some(bounded) => classify_send(send(bounded)),
    }
}

/// A datagram is delivered whole or not at all, and anything in between is
/// not a delivery.
#[cfg(any(test, target_os = "linux"))]
fn whole(sent: usize, len: usize) -> Result<(), String> {
    if sent == len {
        Ok(())
    } else {
        Err(format!("only {sent} of {len} bytes were sent"))
    }
}

/// There is no journald off Linux, so there is nothing to send to.
#[cfg(not(target_os = "linux"))]
fn send(_path: &Path, _payload: &[u8], _timeout: Duration) -> Result<(), String> {
    Err("journald exists only on Linux; this platform has no journal to mirror to".to_owned())
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

    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use rustix::io::Errno;
    use xudo_audit::Decision;

    use super::*;

    fn sample() -> Record {
        Record::first(Decision::Denied, vec!["/bin/sh".to_owned()], "unattested")
            .with_denial("deny_listed")
            .with_evidence(vec!["test=xudo-sys journald sink".to_owned()])
    }

    #[test]
    fn the_system_sink_reaches_journald_exactly_when_the_host_has_one() {
        // No branch on the answer: it is predicted from whether the socket
        // exists, so the same assertion holds on a systemd host (a CI runner),
        // in a container with no journald (`just linux-test`), and on macOS.
        // Where a journald is listening, this leaves one `xudo-test` entry.
        let present = Path::new(JOURNAL_SOCKET).exists();
        let delivered = JournaldSink::system("xudo-test").mirror(&sample());
        assert_eq!(delivered.is_ok(), present, "{delivered:?}");
    }

    /// Runs `script` against a clock whose readings are `offsets` after one
    /// instant, and returns the outcome plus the budget each attempt was given.
    ///
    /// The clock and the script both end. A send that ignores its deadline asks
    /// for another reading or another attempt and the test panics, instead of
    /// hanging on a loop that never checks the time.
    fn scripted_send(
        len: usize,
        timeout: Duration,
        offsets: &[Duration],
        script: &[Attempt],
    ) -> (Result<(), String>, Vec<Duration>) {
        let base = Instant::now();
        let readings = RefCell::new(VecDeque::from_iter(offsets.iter().map(|offset| {
            base.checked_add(*offset)
                .expect("scripted clock overflowed")
        })));
        let planned = RefCell::new(VecDeque::from(script.to_vec()));
        let seen = RefCell::new(Vec::new());
        let result = send_until(
            len,
            timeout,
            &mut || {
                readings.borrow_mut().pop_front().expect(
                    "the send kept reading the clock after the script ended; it did not stop at \
                     the deadline",
                )
            },
            &mut |remaining| {
                seen.borrow_mut().push(remaining);
                planned.borrow_mut().pop_front().expect(
                    "the send kept trying after the script ended; it did not stop at the deadline",
                )
            },
        );
        (result, seen.into_inner())
    }

    #[test]
    fn an_interrupted_journald_send_still_delivers_the_record() {
        // One EINTR is a signal arriving before the datagram is queued. The
        // record still has to land, and the retry must be handed only the time
        // that was left, not a fresh full timeout.
        let timeout = Duration::from_millis(100);
        let (result, seen) = scripted_send(
            4,
            timeout,
            &[Duration::ZERO, Duration::ZERO, Duration::from_millis(40)],
            &[Attempt::Interrupted, Attempt::Sent(4)],
        );
        assert_eq!(result, Ok(()));
        assert_eq!(seen, vec![timeout, Duration::from_millis(60)]);
    }

    #[test]
    fn a_run_of_interrupts_still_delivers_without_stretching_the_deadline() {
        let timeout = Duration::from_millis(100);
        let mut offsets = vec![Duration::ZERO, Duration::ZERO];
        let mut script = Vec::new();
        for step in 1..=20 {
            script.push(Attempt::Interrupted);
            offsets.push(Duration::from_millis(step));
        }
        script.push(Attempt::Sent(4));
        let (result, seen) = scripted_send(4, timeout, &offsets, &script);
        assert_eq!(result, Ok(()));
        assert_eq!(seen.len(), 21);
        assert_eq!(seen.first().copied(), Some(timeout));
        assert_eq!(seen.last().copied(), Some(Duration::from_millis(80)));
        assert!(seen.iter().all(|left| *left <= timeout));
        assert!(seen.windows(2).all(|pair| pair[0] > pair[1]));
    }

    #[test]
    fn a_signal_storm_refuses_the_journald_send_at_the_deadline_instead_of_hanging() {
        let timeout = Duration::from_millis(50);
        let base = Instant::now();
        let readings = RefCell::new(VecDeque::from([
            base,
            base,
            base.checked_add(timeout).expect("deadline"),
        ]));
        let calls = Cell::new(0_u32);
        let err = send_until(
            4,
            timeout,
            &mut || {
                readings
                    .borrow_mut()
                    .pop_front()
                    .expect("the send kept reading the clock after the deadline; it did not stop")
            },
            &mut |remaining| {
                let call = calls.get().saturating_add(1);
                calls.set(call);
                assert!(call < 3, "kept sending after the deadline");
                assert_eq!(remaining, timeout);
                Attempt::Interrupted
            },
        )
        .unwrap_err();
        assert_eq!(err, SEND_DEADLINE);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_backwards_clock_cannot_stretch_the_journald_send_deadline() {
        // A clock that steps backwards must not be read as "nothing has
        // elapsed": that would arm the next send with the original timeout
        // and extend the wait an attacker, or a bad clock, was trying to
        // stretch.
        let timeout = Duration::from_millis(100);
        let base = Instant::now();
        let readings = RefCell::new(VecDeque::from([
            base.checked_add(Duration::from_millis(80)).expect("start"),
            base,
        ]));
        let mut late = attempt_after_the_deadline;
        let err = send_until(
            4,
            timeout,
            &mut || readings.borrow_mut().pop_front().expect("clock"),
            &mut late,
        )
        .unwrap_err();
        assert_eq!(err, SEND_DEADLINE);
    }

    #[test]
    fn a_clock_past_the_deadline_refuses_before_another_journald_send() {
        let timeout = Duration::from_millis(10);
        let (result, seen) = scripted_send(
            4,
            timeout,
            &[
                Duration::ZERO,
                timeout.saturating_add(Duration::from_millis(5)),
            ],
            &[],
        );
        assert_eq!(result, Err(SEND_DEADLINE.to_owned()));
        assert!(seen.is_empty());
    }

    #[test]
    fn a_zero_send_timeout_refuses_before_journald_is_asked() {
        // A zero `SO_SNDTIMEO` means "block forever" to the kernel. The
        // deadline is already due, so nothing is sent.
        let (result, seen) =
            scripted_send(4, Duration::ZERO, &[Duration::ZERO, Duration::ZERO], &[]);
        assert_eq!(result, Err(SEND_DEADLINE.to_owned()));
        assert!(seen.is_empty());
    }

    #[test]
    fn a_journald_send_error_other_than_an_interrupt_is_refused_at_once() {
        let reason = "Resource temporarily unavailable (os error 11)";
        let (result, seen) = scripted_send(
            4,
            Duration::from_secs(2),
            &[Duration::ZERO, Duration::ZERO, Duration::from_millis(1)],
            &[Attempt::Failed(reason.to_owned())],
        );
        assert_eq!(result, Err(reason.to_owned()));
        assert_eq!(seen, vec![Duration::from_secs(2)]);
    }

    #[test]
    fn a_short_send_is_not_delivered_by_retrying_it() {
        let (result, seen) = scripted_send(
            4,
            Duration::from_millis(100),
            &[Duration::ZERO, Duration::ZERO, Duration::from_millis(1)],
            &[Attempt::Interrupted, Attempt::Sent(3)],
        );
        assert_eq!(result, Err("only 3 of 4 bytes were sent".to_owned()));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn only_an_interrupt_is_retried_and_every_other_errno_refuses() {
        assert_eq!(classify_send(Ok(4)), Attempt::Sent(4));
        assert_eq!(classify_send(Err(Errno::INTR)), Attempt::Interrupted);
        let refused = classify_send(Err(Errno::AGAIN));
        assert!(
            matches!(refused, Attempt::Failed(ref reason) if reason.contains("Resource temporarily unavailable")),
            "{refused:?}"
        );
        let mut late = kernel_send_after_the_deadline;
        let early = transmit(Duration::from_nanos(1), &mut late);
        assert_eq!(early, Attempt::Failed(SEND_DEADLINE.to_owned()));
        let sent = transmit(Duration::from_millis(20), &mut |bounded| {
            assert!(bounded < Duration::from_millis(20));
            assert!(!bounded.is_zero());
            Ok(4)
        });
        assert_eq!(sent, Attempt::Sent(4));
        assert_eq!(
            transmit(Duration::from_millis(20), &mut |_| Err(Errno::INTR)),
            Attempt::Interrupted
        );
        let refused = transmit(Duration::from_millis(20), &mut |_| Err(Errno::CONNREFUSED));
        assert!(
            matches!(refused, Attempt::Failed(ref reason) if reason.contains("Connection refused")),
            "{refused:?}"
        );
    }

    #[test]
    fn the_socket_timeout_cannot_outlast_the_monotonic_deadline() {
        // rustix rounds a timeval up to the next microsecond and turns a zero
        // value into one microsecond. The duration we would ask the kernel to
        // wait must still come out no later than `remaining`.
        for nanos in [
            0_u64,
            1,
            999,
            1_000,
            1_001,
            1_500,
            20_000_000,
            1_000_000_001,
        ] {
            let remaining = Duration::from_nanos(nanos);
            match kernel_timeout(remaining) {
                None => assert!(
                    remaining <= Duration::from_micros(1),
                    "{remaining:?} was treated as already due"
                ),
                Some(asked) => {
                    assert!(!asked.is_zero());
                    assert!(asked < remaining);
                    let rounded = timeval_rounded_up(asked);
                    assert!(
                        rounded <= remaining,
                        "kernel would wait {rounded:?}, past {remaining:?}"
                    );
                }
            }
        }
        // A zero timeval means block forever, which is the case the hold-back
        // exists to avoid. An exact second does not round up.
        assert_eq!(timeval_rounded_up(Duration::ZERO), Duration::from_micros(1));
        assert_eq!(
            timeval_rounded_up(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
        assert_eq!(
            timeval_rounded_up(Duration::from_secs(1) + Duration::from_nanos(1)),
            Duration::from_secs(1) + Duration::from_micros(1)
        );
    }

    /// The closure a deadline guard is given. Calling it is the bug: the
    /// guard must have refused before asking journald.
    fn attempt_after_the_deadline(_remaining: Duration) -> Attempt {
        panic!("journald was asked after the send deadline");
    }

    fn kernel_send_after_the_deadline(_remaining: Duration) -> Result<usize, Errno> {
        panic!("journald was asked after the send deadline");
    }

    #[test]
    fn asking_journald_after_the_send_deadline_is_the_bug() {
        let attempt = std::panic::catch_unwind(|| {
            let _ = attempt_after_the_deadline(Duration::ZERO);
        });
        let kernel = std::panic::catch_unwind(|| {
            let _ = kernel_send_after_the_deadline(Duration::ZERO);
        });
        assert!(attempt.is_err(), "a late attempt did not panic");
        assert!(kernel.is_err(), "a late kernel send did not panic");
    }

    /// A full journal queue refuses with the kernel send timeout. A signal
    /// that uses up the rest of the deadline refuses with that deadline.
    /// `EINTR` itself is neither: reporting it would deny a decision the
    /// kernel had not finished.
    fn refusal_is_a_bounded_send(text: &str) -> bool {
        text.contains("Resource temporarily unavailable") || text.contains(SEND_DEADLINE)
    }

    #[test]
    fn a_stalled_journald_refusal_is_the_timeout_or_the_deadline_never_an_interrupt() {
        assert!(refusal_is_a_bounded_send(
            "Resource temporarily unavailable (os error 11)"
        ));
        assert!(refusal_is_a_bounded_send(SEND_DEADLINE));
        assert!(!refusal_is_a_bounded_send(
            "Interrupted system call (os error 4)"
        ));
        assert!(!refusal_is_a_bounded_send(
            "Connection refused (os error 111)"
        ));
    }

    /// rustix's `SO_SNDTIMEO` conversion: round the subsecond part up to the
    /// next microsecond, and never hand the kernel a zero timeval.
    #[allow(clippy::integer_division)]
    fn timeval_rounded_up(timeout: Duration) -> Duration {
        let secs = timeout.as_secs();
        let usec = u64::from(timeout.subsec_nanos().saturating_add(999) / 1_000);
        if secs == 0 && usec == 0 {
            Duration::from_micros(1)
        } else {
            Duration::from_secs(secs).saturating_add(Duration::from_micros(usec))
        }
    }

    #[test]
    fn a_missing_journald_fails_closed_naming_the_socket() {
        let mut sink = JournaldSink::at("/nonexistent/xudo-test/journal.sock", "xudo-test")
            .with_timeout(Duration::from_millis(50));
        let err = sink.mirror(&sample()).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("journald at /nonexistent/xudo-test/journal.sock did not take"),
            "{err}"
        );
        assert!(format!("{sink:?}").contains("xudo-test"));
    }

    #[test]
    fn a_record_too_large_for_one_datagram_is_refused_before_anything_is_sent() {
        let huge = Record::first(
            Decision::Denied,
            vec!["x".repeat(xudo_audit::journal::PAYLOAD_MAX)],
            "unattested",
        );
        let err = JournaldSink::at("/nonexistent/xudo-test/journal.sock", "xudo-test")
            .mirror(&huge)
            .unwrap_err();
        assert!(
            err.to_string().contains("one datagram carries at most"),
            "{err}"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn there_is_no_journal_to_mirror_to_off_linux() {
        let err = JournaldSink::system("xudo-test")
            .mirror(&sample())
            .unwrap_err();
        assert!(err.to_string().contains("only on Linux"), "{err}");
    }

    /// The transport against a socket the test binds itself, under the
    /// workspace `target/`: real datagrams, no host journal involved.
    #[cfg(target_os = "linux")]
    mod linux {
        use std::os::unix::net::UnixDatagram;
        use std::time::Instant;

        use super::*;

        fn socket_dir(name: &str) -> PathBuf {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("target")
                .join("test-tmp")
                .join(format!("jn-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::canonicalize(&dir).unwrap()
        }

        #[test]
        fn a_record_arrives_as_one_native_protocol_datagram() {
            let path = socket_dir("deliver").join("j.sock");
            let receiver = UnixDatagram::bind(&path).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let record = sample();
            JournaldSink::at(&path, "xudo-test")
                .mirror(&record)
                .unwrap();
            let mut buf = vec![0; 256 * 1024];
            let count = receiver.recv(&mut buf).unwrap();
            assert_eq!(
                &buf[..count],
                xudo_audit::journal::datagram(&record, "xudo-test")
                    .unwrap()
                    .as_slice()
            );
        }

        #[test]
        fn the_largest_record_a_writer_accepts_fits_one_datagram() {
            // The reason there is no memfd path: on a stock kernel the bound
            // holds with room to spare.
            let path = socket_dir("largest").join("j.sock");
            let receiver = UnixDatagram::bind(&path).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let largest = Record::first(
                Decision::Denied,
                vec!["y".repeat(xudo_audit::MAX_RECORD_BYTES - 1024)],
                "unattested",
            );
            JournaldSink::at(&path, "xudo-test")
                .mirror(&largest)
                .unwrap();
            let mut buf = vec![0; 256 * 1024];
            let count = receiver.recv(&mut buf).unwrap();
            assert!(count > xudo_audit::MAX_RECORD_BYTES - 1024, "{count}");
        }

        #[test]
        fn a_journald_nobody_is_reading_fails_closed() {
            // The socket file is there; its owner is gone.
            let path = socket_dir("refused").join("j.sock");
            drop(UnixDatagram::bind(&path).unwrap());
            assert!(path.exists());
            let err = JournaldSink::at(&path, "xudo-test")
                .mirror(&sample())
                .unwrap_err();
            assert!(err.to_string().contains("Connection refused"), "{err}");
        }

        #[test]
        fn a_stalled_journald_refuses_within_the_timeout_instead_of_hanging() {
            // A journald that stops reading fills its queue; every send after
            // that would block forever without the timeout, and the decision
            // waiting on it would never be made.
            let path = socket_dir("stalled").join("j.sock");
            let _receiver = UnixDatagram::bind(&path).unwrap();
            let mut sink =
                JournaldSink::at(&path, "xudo-test").with_timeout(Duration::from_millis(20));
            let started = Instant::now();
            let mut delivered = 0_u32;
            let mut refusal = None;
            for _ in 0..10_000 {
                match sink.mirror(&sample()) {
                    Ok(()) => delivered = delivered.saturating_add(1),
                    Err(err) => {
                        refusal = Some(err);
                        break;
                    }
                }
            }
            let err = refusal.expect("the queue never filled");
            assert!(started.elapsed() < Duration::from_secs(30), "{err}");
            // The queue starts empty, so a healthy send lands before the
            // timeout. An interrupt during a later blocked send is retried
            // inside that deadline; it must not be the refusal itself.
            assert!(delivered > 0, "the first send was refused: {err}");
            let text = err.to_string();
            assert!(super::refusal_is_a_bounded_send(&text), "{text}");
            assert!(!text.contains("Interrupted system call"), "{text}");
        }

        #[test]
        fn a_short_send_is_not_a_delivery() {
            assert_eq!(whole(4, 4), Ok(()));
            assert_eq!(whole(3, 4), Err("only 3 of 4 bytes were sent".to_owned()));
        }

        #[test]
        fn a_socket_path_too_long_for_the_kernel_fails_closed() {
            let long = PathBuf::from("/").join("x".repeat(200));
            let err = JournaldSink::at(long, "xudo-test")
                .mirror(&sample())
                .unwrap_err();
            assert!(err.to_string().contains("did not take the record"), "{err}");
        }
    }
}
