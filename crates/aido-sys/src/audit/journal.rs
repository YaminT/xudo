//! The journald mirror: each record, sent to journald's native socket.
//!
//! One datagram per record, built by [`aido_audit::journal::datagram`] and sent
//! with `sendto` on an `AF_UNIX` datagram socket through rustix's safe API — no
//! client library, no new dependency. A send that does not complete within a
//! bound fails, so a stalled journald refuses a decision rather than hanging
//! it.
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
//! An entry is bounded below one datagram (see [`aido_audit::journal`]), so the
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
//! back only through [`aido_audit::journal::query`], which matches `_UID=0` —
//! the one field journald takes from the kernel rather than the sender.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aido_audit::Record;

use super::{AuditError, AuditMirror};

/// journald's native-protocol socket.
pub const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// How long a send may block on a full journald queue before it fails.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Sends every record to journald.
#[derive(Clone, Debug)]
pub struct JournaldSink {
    socket: PathBuf,
    identifier: &'static str,
    timeout: Duration,
}

impl JournaldSink {
    /// The system journal, with entries attributed to `identifier` — the
    /// binary writing them, `aidod` or `aido-gate`.
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
        let payload = aido_audit::journal::datagram(record, self.identifier)
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

    let sent = SocketAddrUnix::new(path).and_then(|address| {
        socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .and_then(|fd| set_socket_timeout(&fd, Timeout::Send, Some(timeout)).map(|()| fd))
        .and_then(|fd| sendto(&fd, payload, SendFlags::NOSIGNAL, &address))
    });
    match sent {
        Ok(count) => whole(count, payload.len()),
        Err(errno) => Err(errno.to_string()),
    }
}

/// A datagram is delivered whole or not at all, and anything in between is
/// not a delivery.
#[cfg(target_os = "linux")]
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

    use aido_audit::Decision;

    use super::*;

    fn sample() -> Record {
        Record::first(Decision::Denied, vec!["/bin/sh".to_owned()], "unattested")
            .with_denial("deny_listed")
            .with_evidence(vec!["test=aido-sys journald sink".to_owned()])
    }

    #[test]
    fn the_system_sink_reaches_journald_exactly_when_the_host_has_one() {
        // No branch on the answer: it is predicted from whether the socket
        // exists, so the same assertion holds on a systemd host (a CI runner),
        // in a container with no journald (`just linux-test`), and on macOS.
        // Where a journald is listening, this leaves one `aido-test` entry.
        let present = Path::new(JOURNAL_SOCKET).exists();
        let delivered = JournaldSink::system("aido-test").mirror(&sample());
        assert_eq!(delivered.is_ok(), present, "{delivered:?}");
    }

    #[test]
    fn a_missing_journald_fails_closed_naming_the_socket() {
        let mut sink = JournaldSink::at("/nonexistent/aido-test/journal.sock", "aido-test")
            .with_timeout(Duration::from_millis(50));
        let err = sink.mirror(&sample()).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("journald at /nonexistent/aido-test/journal.sock did not take"),
            "{err}"
        );
        assert!(format!("{sink:?}").contains("aido-test"));
    }

    #[test]
    fn a_record_too_large_for_one_datagram_is_refused_before_anything_is_sent() {
        let huge = Record::first(
            Decision::Denied,
            vec!["x".repeat(aido_audit::journal::PAYLOAD_MAX)],
            "unattested",
        );
        let err = JournaldSink::at("/nonexistent/aido-test/journal.sock", "aido-test")
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
        let err = JournaldSink::system("aido-test")
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
            JournaldSink::at(&path, "aido-test")
                .mirror(&record)
                .unwrap();
            let mut buf = vec![0; 256 * 1024];
            let count = receiver.recv(&mut buf).unwrap();
            assert_eq!(
                &buf[..count],
                aido_audit::journal::datagram(&record, "aido-test")
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
                vec!["y".repeat(aido_audit::MAX_RECORD_BYTES - 1024)],
                "unattested",
            );
            JournaldSink::at(&path, "aido-test")
                .mirror(&largest)
                .unwrap();
            let mut buf = vec![0; 256 * 1024];
            let count = receiver.recv(&mut buf).unwrap();
            assert!(count > aido_audit::MAX_RECORD_BYTES - 1024, "{count}");
        }

        #[test]
        fn a_journald_nobody_is_reading_fails_closed() {
            // The socket file is there; its owner is gone.
            let path = socket_dir("refused").join("j.sock");
            drop(UnixDatagram::bind(&path).unwrap());
            assert!(path.exists());
            let err = JournaldSink::at(&path, "aido-test")
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
                JournaldSink::at(&path, "aido-test").with_timeout(Duration::from_millis(20));
            let started = Instant::now();
            let refused = (0..10_000).find_map(|_| sink.mirror(&sample()).err());
            let err = refused.expect("the queue never filled");
            assert!(started.elapsed() < Duration::from_secs(30));
            assert!(
                err.to_string().contains("Resource temporarily unavailable"),
                "{err}"
            );
        }

        #[test]
        fn a_short_send_is_not_a_delivery() {
            assert_eq!(whole(4, 4), Ok(()));
            assert_eq!(whole(3, 4), Err("only 3 of 4 bytes were sent".to_owned()));
        }

        #[test]
        fn a_socket_path_too_long_for_the_kernel_fails_closed() {
            let long = PathBuf::from("/").join("x".repeat(200));
            let err = JournaldSink::at(long, "aido-test")
                .mirror(&sample())
                .unwrap_err();
            assert!(err.to_string().contains("did not take the record"), "{err}");
        }
    }
}
