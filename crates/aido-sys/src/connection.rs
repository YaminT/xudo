//! The broker's one connection: adopted from descriptor 0, read once, written
//! once.
//!
//! systemd accepts the connection (`Accept=yes`) and starts one broker per
//! connection with the accepted socket as its standard input
//! (`StandardInput=socket`). So the broker never listens and never parses
//! `LISTEN_FDS` from an environment it must not read: the connection is
//! descriptor 0, borrowed from `std::io::stdin()`, and [`UnixConnection::adopt`]
//! refuses it unless it really is what systemd promises — a connected
//! `AF_UNIX` stream socket.
//!
//! Every read and write is bounded in time, because a client that connects and
//! says nothing must not be able to hold a root process open: the receive
//! timeout ends it, and the unit's `RuntimeMaxSec=` ends whatever the timeout
//! does not.

use std::cell::RefCell;
use std::io::{ErrorKind, Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::error::SysError;

/// Why a descriptor cannot be served as the broker's connection.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdoptError {
    /// It is not a socket at all.
    #[error("the connection is not a socket: aidod runs with an accepted connection on fd 0")]
    NotASocket,
    /// It is a socket, but not a stream.
    #[error("the connection is not a stream socket")]
    NotAStream,
    /// It is a stream socket, but not a Unix one.
    #[error("the connection is not an AF_UNIX socket, so the kernel cannot say who is on it")]
    NotUnix,
    /// It is a Unix stream socket with no peer: a listener, or never
    /// connected.
    #[error("the socket is not connected to anyone")]
    NotConnected,
    /// It could not be adopted.
    #[error(transparent)]
    Os(SysError),
}

/// Why a request could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadFailure {
    /// More than the limit arrived before end of file.
    #[error("the request is longer than {limit} bytes")]
    TooLarge {
        /// The limit it exceeded.
        limit: usize,
    },
    /// End of file did not arrive before the receive timeout.
    #[error("no complete request arrived before the receive timeout")]
    TimedOut,
    /// The read itself failed.
    #[error(transparent)]
    Os(SysError),
}

/// One request-response exchange, as a seam.
pub trait Connection {
    /// The socket, for the calls that ask the kernel who is on it.
    fn socket(&self) -> BorrowedFd<'_>;

    /// Reads the request: everything until the peer shuts down its writing
    /// half, and never more than `limit` bytes.
    ///
    /// # Errors
    ///
    /// [`ReadFailure::TooLarge`] past the limit, [`ReadFailure::TimedOut`]
    /// when the receive timeout fires first, and [`ReadFailure::Os`] for any
    /// other failure.
    fn read_request(&self, limit: usize) -> Result<Vec<u8>, ReadFailure>;

    /// Writes the whole response.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] if it cannot be written, including when the peer has
    /// gone or the send timeout fires.
    fn write_response(&self, bytes: &[u8]) -> Result<(), SysError>;
}

/// A connected Unix stream socket, with both timeouts set.
#[derive(Debug)]
pub struct UnixConnection {
    stream: UnixStream,
}

impl UnixConnection {
    /// Adopts `fd` as the connection, after checking it is a connected
    /// `AF_UNIX` stream socket, with `timeout` on every read and write.
    ///
    /// The descriptor is duplicated, not taken: it belongs to whoever lent it
    /// (standard input, in the broker), and adopting it must not close it out
    /// from under them.
    ///
    /// # Errors
    ///
    /// The first property that does not hold, as the matching [`AdoptError`];
    /// [`AdoptError::Os`] if it cannot be duplicated or a timeout cannot be
    /// set, which a zero `timeout` causes.
    pub fn adopt(fd: BorrowedFd<'_>, timeout: Duration) -> Result<Self, AdoptError> {
        check_socket(fd)?;
        connection_from(fd.try_clone_to_owned().map(UnixStream::from), timeout)
    }
}

/// Whether `fd` is a connected `AF_UNIX` stream socket: what systemd hands a
/// service as the connection, and what it hands as standard error when it
/// connects that to the journal.
///
/// # Errors
///
/// The first property that does not hold, as the matching [`AdoptError`].
pub fn connected_unix_stream(fd: BorrowedFd<'_>) -> Result<(), AdoptError> {
    check_socket(fd)
}

/// Checks the four properties systemd promises, each on the descriptor.
///
/// Each check folds "the call failed" into "the property does not hold": on a
/// descriptor that is open, as this one is, these calls fail only when the
/// property is absent, and a refusal is the right answer either way.
fn check_socket(fd: BorrowedFd<'_>) -> Result<(), AdoptError> {
    match rustix::fs::fstat(fd) {
        Ok(stat) if rustix::fs::FileType::from_raw_mode(stat.st_mode).is_socket() => {}
        _ => return Err(AdoptError::NotASocket),
    }
    match rustix::net::sockopt::socket_type(fd) {
        Ok(kind) if kind == rustix::net::SocketType::STREAM => {}
        _ => return Err(AdoptError::NotAStream),
    }
    match rustix::net::getsockname(fd) {
        Ok(name) if name.address_family() == rustix::net::AddressFamily::UNIX => {}
        _ => return Err(AdoptError::NotUnix),
    }
    match rustix::net::getpeername(fd) {
        Ok(_) => Ok(()),
        Err(_) => Err(AdoptError::NotConnected),
    }
}

/// Finishes adoption: the duplicated stream, with its timeouts.
fn connection_from(
    stream: std::io::Result<UnixStream>,
    timeout: Duration,
) -> Result<UnixConnection, AdoptError> {
    match stream.and_then(|stream| with_timeouts(stream, timeout)) {
        Ok(stream) => Ok(UnixConnection { stream }),
        Err(error) => Err(AdoptError::Os(SysError::os("adopt the connection", &error))),
    }
}

/// Sets both timeouts — `SO_RCVTIMEO` and `SO_SNDTIMEO` — or fails.
///
/// A zero timeout means "block forever" to the kernel, so rustix refuses to
/// set one with `EINVAL`, and so does this.
fn with_timeouts(stream: UnixStream, timeout: Duration) -> std::io::Result<UnixStream> {
    use rustix::net::sockopt::{Timeout, set_socket_timeout};

    set_socket_timeout(&stream, Timeout::Recv, Some(timeout))
        .and(set_socket_timeout(&stream, Timeout::Send, Some(timeout)))
        .map(|()| stream)
        .map_err(std::io::Error::from)
}

impl Connection for UnixConnection {
    fn socket(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }

    fn read_request(&self, limit: usize) -> Result<Vec<u8>, ReadFailure> {
        let mut bytes = Vec::new();
        let ceiling = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        let read = (&self.stream).take(ceiling).read_to_end(&mut bytes);
        request_from(read, bytes, limit)
    }

    fn write_response(&self, bytes: &[u8]) -> Result<(), SysError> {
        match (&self.stream).write_all(bytes) {
            Ok(()) => Ok(()),
            Err(error) => Err(SysError::os("write the response", &error)),
        }
    }
}

/// Reads the outcome of a bounded read as a request, or why there is none.
///
/// One byte past the limit is read on purpose: it is the only way to tell a
/// request of exactly the limit from a longer one. A timeout surfaces as
/// `WouldBlock` from a socket with a receive timeout set. Split out so every
/// arm is reachable from a test with a real error.
fn request_from(
    read: std::io::Result<usize>,
    bytes: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, ReadFailure> {
    match read {
        Ok(_) if bytes.len() > limit => Err(ReadFailure::TooLarge { limit }),
        Ok(_) => Ok(bytes),
        Err(error) if is_timeout(error.kind()) => Err(ReadFailure::TimedOut),
        Err(error) => Err(ReadFailure::Os(SysError::os("read the request", &error))),
    }
}

/// Whether a read failed because its timeout fired.
fn is_timeout(kind: ErrorKind) -> bool {
    kind == ErrorKind::WouldBlock || kind == ErrorKind::TimedOut
}

/// A scripted connection, for tests.
///
/// Holds a real descriptor — anything — only so that the peer-identification
/// fakes have something to be handed; they never look at it. Records every
/// byte written.
#[derive(Debug)]
pub struct FakeConnection {
    socket: OwnedFd,
    request: Result<Vec<u8>, ReadFailure>,
    write: Result<(), SysError>,
    written: RefCell<Vec<u8>>,
}

impl FakeConnection {
    /// A connection whose request read returns `request`.
    ///
    /// A scripted request longer than the limit the caller passes is reported
    /// as [`ReadFailure::TooLarge`], as the real connection would.
    pub fn new(socket: OwnedFd, request: Result<Vec<u8>, ReadFailure>) -> Self {
        Self {
            socket,
            request,
            write: Ok(()),
            written: RefCell::new(Vec::new()),
        }
    }

    /// Makes every write fail with `error`, after recording what was sent.
    #[must_use]
    pub fn with_write_error(mut self, error: SysError) -> Self {
        self.write = Err(error);
        self
    }

    /// Everything written so far.
    pub fn written(&self) -> Vec<u8> {
        self.written.borrow().clone()
    }
}

impl Connection for FakeConnection {
    fn socket(&self) -> BorrowedFd<'_> {
        self.socket.as_fd()
    }

    fn read_request(&self, limit: usize) -> Result<Vec<u8>, ReadFailure> {
        match &self.request {
            Ok(bytes) if bytes.len() > limit => Err(ReadFailure::TooLarge { limit }),
            scripted => scripted.clone(),
        }
    }

    fn write_response(&self, bytes: &[u8]) -> Result<(), SysError> {
        self.written.borrow_mut().extend_from_slice(bytes);
        self.write.clone()
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

    use std::net::Shutdown;
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::path::{Path, PathBuf};

    use super::*;

    const SHORT: Duration = Duration::from_millis(50);

    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-tmp")
            .join(format!("conn-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_connected_unix_stream_is_adopted_and_carries_one_exchange() {
        let (broker, mut client) = UnixStream::pair().unwrap();
        client.write_all(b"{\"question\":1}").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let conn = UnixConnection::adopt(broker.as_fd(), SHORT).unwrap();
        assert_eq!(conn.read_request(64).unwrap(), b"{\"question\":1}");
        conn.write_response(b"answer").unwrap();
        drop(conn);
        drop(broker);

        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        assert_eq!(answer, b"answer");
    }

    #[test]
    fn adoption_borrows_the_descriptor_rather_than_taking_it() {
        // The broker lends fd 0 from stdin; adopting it must leave it open.
        let (broker, _client) = UnixStream::pair().unwrap();
        let conn = UnixConnection::adopt(broker.as_fd(), SHORT).unwrap();
        assert_ne!(
            std::os::fd::AsRawFd::as_raw_fd(&conn.socket()),
            std::os::fd::AsRawFd::as_raw_fd(&broker)
        );
        drop(conn);
        assert!(rustix::fs::fstat(&broker).is_ok());
    }

    #[test]
    fn a_regular_file_on_fd_zero_is_refused() {
        let file = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
        assert_eq!(
            UnixConnection::adopt(file.as_fd(), SHORT).unwrap_err(),
            AdoptError::NotASocket
        );
        let null = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            UnixConnection::adopt(null.as_fd(), SHORT).unwrap_err(),
            AdoptError::NotASocket
        );
    }

    #[test]
    fn only_a_connected_unix_stream_passes_the_check_standard_error_must_meet() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(connected_unix_stream(a.as_fd()), Ok(()));
        let file = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
        assert_eq!(
            connected_unix_stream(file.as_fd()),
            Err(AdoptError::NotASocket)
        );
        let (datagram, _other) = UnixDatagram::pair().unwrap();
        assert_eq!(
            connected_unix_stream(datagram.as_fd()),
            Err(AdoptError::NotAStream)
        );
    }

    #[test]
    fn a_datagram_socket_is_refused() {
        let (a, _b) = UnixDatagram::pair().unwrap();
        assert_eq!(
            UnixConnection::adopt(a.as_fd(), SHORT).unwrap_err(),
            AdoptError::NotAStream
        );
    }

    #[test]
    fn a_tcp_socket_is_refused_because_the_kernel_cannot_name_its_peer() {
        // An AF_INET stream has no SO_PEERCRED, so nothing about who is on it
        // could be attested. Unconnected is enough to reach the check.
        let tcp = rustix::net::socket(
            rustix::net::AddressFamily::INET,
            rustix::net::SocketType::STREAM,
            None,
        )
        .unwrap();
        assert_eq!(
            UnixConnection::adopt(tcp.as_fd(), SHORT).unwrap_err(),
            AdoptError::NotUnix
        );
    }

    #[test]
    fn a_listening_or_unconnected_unix_socket_is_refused() {
        // `sun_path` holds 104 bytes on macOS, which a deep checkout — a git
        // worktree — exceeds through `crates/aido-sys/../..`. Cargo runs tests
        // from the package directory, so the socket is bound by a relative
        // path into the directory `scratch` made.
        scratch("listener");
        let listener =
            UnixListener::bind(Path::new("../../target/test-tmp/conn-listener/l.sock")).unwrap();
        assert_eq!(
            UnixConnection::adopt(listener.as_fd(), SHORT).unwrap_err(),
            AdoptError::NotConnected
        );
        let unconnected = rustix::net::socket(
            rustix::net::AddressFamily::UNIX,
            rustix::net::SocketType::STREAM,
            None,
        )
        .unwrap();
        assert_eq!(
            UnixConnection::adopt(unconnected.as_fd(), SHORT).unwrap_err(),
            AdoptError::NotConnected
        );
    }

    #[test]
    fn a_zero_timeout_is_refused_rather_than_meaning_no_timeout() {
        // A zero `SO_RCVTIMEO` means "block forever" to the kernel; std refuses
        // to set it, and adoption must refuse with it.
        let (broker, _client) = UnixStream::pair().unwrap();
        let err = UnixConnection::adopt(broker.as_fd(), Duration::ZERO).unwrap_err();
        assert!(err.to_string().contains("adopt the connection"), "{err}");
    }

    #[test]
    fn both_timeouts_are_set_on_the_socket_the_broker_reads_and_writes() {
        // A client that stops reading must not hold the broker on a write any
        // more than one that stops writing holds it on a read.
        use rustix::net::sockopt::{Timeout, socket_timeout};

        let (broker, _client) = UnixStream::pair().unwrap();
        let conn = UnixConnection::adopt(broker.as_fd(), Duration::from_millis(1_500)).unwrap();
        for which in [Timeout::Recv, Timeout::Send] {
            assert_eq!(
                socket_timeout(conn.socket(), which).unwrap(),
                Some(Duration::from_millis(1_500))
            );
        }
    }

    #[test]
    fn a_client_that_says_nothing_times_out_instead_of_holding_the_broker() {
        let (broker, _client) = UnixStream::pair().unwrap();
        let conn = UnixConnection::adopt(broker.as_fd(), SHORT).unwrap();
        assert_eq!(conn.read_request(64), Err(ReadFailure::TimedOut));
    }

    #[test]
    fn a_request_one_byte_over_the_limit_is_refused_and_one_at_it_is_read() {
        let (broker, mut client) = UnixStream::pair().unwrap();
        client.write_all(&[b'x'; 9]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let conn = UnixConnection::adopt(broker.as_fd(), SHORT).unwrap();
        assert_eq!(
            conn.read_request(8),
            Err(ReadFailure::TooLarge { limit: 8 })
        );

        let (broker, mut client) = UnixStream::pair().unwrap();
        client.write_all(&[b'x'; 8]).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let conn = UnixConnection::adopt(broker.as_fd(), SHORT).unwrap();
        assert_eq!(conn.read_request(8), Ok(vec![b'x'; 8]));
    }

    #[test]
    fn a_response_to_a_peer_that_left_fails_rather_than_vanishing() {
        let (broker, client) = UnixStream::pair().unwrap();
        let conn = UnixConnection::adopt(broker.as_fd(), SHORT).unwrap();
        drop(client);
        let err = conn.write_response(b"answer").unwrap_err();
        assert!(
            err.to_string().starts_with("write the response failed"),
            "{err}"
        );
    }

    #[test]
    fn a_failed_read_is_reported_with_its_errno() {
        let reset = std::io::Error::from_raw_os_error(rustix::io::Errno::CONNRESET.raw_os_error());
        let err = request_from(Err(reset), Vec::new(), 8).unwrap_err();
        assert_eq!(
            err,
            ReadFailure::Os(SysError::os(
                "read the request",
                &std::io::Error::from_raw_os_error(rustix::io::Errno::CONNRESET.raw_os_error())
            ))
        );
        let timed_out = std::io::Error::from(ErrorKind::TimedOut);
        assert_eq!(
            request_from(Err(timed_out), Vec::new(), 8),
            Err(ReadFailure::TimedOut)
        );
        for err in [ReadFailure::TooLarge { limit: 1 }, ReadFailure::TimedOut] {
            assert!(err.to_string().len() > 10, "{err}");
        }
    }

    #[test]
    fn every_adoption_refusal_says_what_was_wrong() {
        for err in [
            AdoptError::NotASocket,
            AdoptError::NotAStream,
            AdoptError::NotUnix,
            AdoptError::NotConnected,
            AdoptError::Os(SysError::unsupported("x")),
        ] {
            assert!(err.to_string().len() > 15, "{err}");
        }
    }

    #[test]
    fn a_fake_connection_replays_its_script_and_records_what_it_was_sent() {
        let (socket, _other) = UnixStream::pair().unwrap();
        let fake = FakeConnection::new(OwnedFd::from(socket), Ok(b"0123456789".to_vec()));
        assert_eq!(fake.read_request(16), Ok(b"0123456789".to_vec()));
        assert_eq!(
            fake.read_request(4),
            Err(ReadFailure::TooLarge { limit: 4 })
        );
        assert!(rustix::fs::fstat(fake.socket()).is_ok());
        fake.write_response(b"one").unwrap();

        let broken = fake.with_write_error(SysError::unsupported("gone"));
        assert!(broken.write_response(b"two").is_err());
        assert_eq!(broken.written(), b"onetwo");

        let (socket, _other) = UnixStream::pair().unwrap();
        let silent = FakeConnection::new(OwnedFd::from(socket), Err(ReadFailure::TimedOut));
        assert_eq!(silent.read_request(16), Err(ReadFailure::TimedOut));
        assert!(format!("{silent:?}").contains("FakeConnection"));
    }
}
