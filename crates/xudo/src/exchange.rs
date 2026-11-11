//! One bounded request and response on the broker's socket.
//!
//! Connect, the write, and the read share one monotonic deadline. `EINTR`
//! retries only the call that was interrupted, with the socket timeout shrunk
//! to the time still left. A signal storm therefore ends the exchange when
//! the deadline passes. It cannot restart the original timeout, and it cannot
//! hang the front-end.
//!
//! The first connect is non-blocking. `EAGAIN`, `EINPROGRESS`, and `ETIMEDOUT`
//! mean the listen queue did not take the socket yet. The retry is one
//! blocking connect whose `SO_SNDTIMEO` is the time still left. `poll` is not
//! used: on Linux it reports that same queued socket as writable, with
//! `SO_ERROR` clear, while `getpeername` still says it is not connected.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use rustix::fd::OwnedFd;
use rustix::io::Errno;
use rustix::io::{ioctl_fioclex, ioctl_fionbio};
use rustix::net::connect as connect_fd;
use rustix::net::sockopt::{Timeout, set_socket_timeout};
use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType, socket_with};
use xudo_wire::{BrokerResponse, MAX_RESPONSE_BYTES};

/// What a caller sees when the monotonic deadline has passed.
const DEADLINE: &str = "broker response deadline expired";

/// What a caller sees when the reply will not fit.
const TOO_BIG: &str = "broker response exceeds size limit";

/// How many bytes one read asks for.
const CHUNK: usize = 8192;

/// Exchanges one request for one response on `socket`.
///
/// Connect, the write, and the read share `timeout`. The clock is monotonic
/// and starts when this function is called.
///
/// # Errors
///
/// Returns [`DEADLINE`] when the deadline passes, [`TOO_BIG`] when the
/// response passes [`MAX_RESPONSE_BYTES`], and the OS error otherwise.
/// The bytes are returned as they arrived. The caller parses them.
pub(crate) fn exchange(
    socket: &Path,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    // One body, not a copy per caller. Coverage merges generic instantiations
    // by the copy with the most regions.
    let mut now = Instant::now;
    let mut io = Live::open(socket);
    exchange_until(request, timeout, &mut now, &mut io)
}

/// What one socket operation did.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// Connect or shutdown finished.
    Ready,
    /// A read or write moved this many bytes.
    Transferred(usize),
    /// `EINTR`. Nothing about the deadline changed.
    Interrupted,
    /// Any other failure, including the deadline.
    Failed(String),
}

/// The socket operations the exchange loop needs.
trait BrokerIo {
    fn connect(&mut self, bounded: Duration) -> Step;
    fn write(&mut self, bounded: Duration, bytes: &[u8]) -> Step;
    fn shutdown_write(&mut self, bounded: Duration) -> Step;
    fn read(&mut self, bounded: Duration, buf: &mut [u8]) -> Step;
}

/// Runs the exchange against `io`, asking `now` for the monotonic time.
fn exchange_until(
    request: &[u8],
    timeout: Duration,
    now: &mut dyn FnMut() -> Instant,
    io: &mut dyn BrokerIo,
) -> Result<Vec<u8>, String> {
    let started = now();
    connect_for(timeout, started, now, io)?;
    write_for(request, timeout, started, now, io)?;
    shutdown_for(timeout, started, now, io)?;
    read_reply(timeout, started, now, io)
}

fn connect_for(
    timeout: Duration,
    started: Instant,
    now: &mut dyn FnMut() -> Instant,
    io: &mut dyn BrokerIo,
) -> Result<(), String> {
    loop {
        match io.connect(next_budget(started, now, timeout)?) {
            Step::Ready => return Ok(()),
            Step::Interrupted => {}
            Step::Failed(reason) => return Err(reason),
            Step::Transferred(_) => {
                return Err("the broker connect reported a byte count".to_owned());
            }
        }
    }
}

fn write_for(
    request: &[u8],
    timeout: Duration,
    started: Instant,
    now: &mut dyn FnMut() -> Instant,
    io: &mut dyn BrokerIo,
) -> Result<(), String> {
    let mut rest = request;
    while !rest.is_empty() {
        match io.write(next_budget(started, now, timeout)?, rest) {
            Step::Transferred(0) => {
                return Err("the broker write made no progress".to_owned());
            }
            Step::Transferred(n) => {
                rest = rest.get(n..).ok_or_else(|| {
                    "the broker write reported more bytes than were offered".to_owned()
                })?;
            }
            Step::Interrupted => {}
            Step::Ready => return Err("the broker write returned no count".to_owned()),
            Step::Failed(reason) => return Err(reason),
        }
    }
    Ok(())
}

fn shutdown_for(
    timeout: Duration,
    started: Instant,
    now: &mut dyn FnMut() -> Instant,
    io: &mut dyn BrokerIo,
) -> Result<(), String> {
    loop {
        match io.shutdown_write(next_budget(started, now, timeout)?) {
            Step::Ready => return Ok(()),
            Step::Interrupted => {}
            Step::Failed(reason) => return Err(reason),
            Step::Transferred(_) => {
                return Err("the broker shutdown reported a byte count".to_owned());
            }
        }
    }
}

fn read_reply(
    timeout: Duration,
    started: Instant,
    now: &mut dyn FnMut() -> Instant,
    io: &mut dyn BrokerIo,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    // One byte past the limit, so an oversized answer is seen and refused.
    let limit = MAX_RESPONSE_BYTES.saturating_add(1);
    loop {
        if response_candidate(&bytes) && BrokerResponse::parse(&bytes).is_ok() {
            return Ok(bytes);
        }
        if bytes.len() >= limit {
            return Err(TOO_BIG.to_owned());
        }
        let want = limit.saturating_sub(bytes.len()).min(CHUNK);
        let mut buf = [0u8; CHUNK];
        let (head, _) = buf.split_at_mut(want);
        match io.read(next_budget(started, now, timeout)?, head) {
            // End of the reply. The caller parses it. Doing that here would
            // hide the caller's parse-error path, including a body that is
            // not JSON.
            Step::Transferred(0) => return Ok(bytes),
            Step::Transferred(n) => {
                let chunk = head.get(..n).ok_or_else(|| {
                    "the broker read reported more bytes than the buffer holds".to_owned()
                })?;
                bytes.extend_from_slice(chunk);
            }
            Step::Interrupted => {}
            Step::Ready => return Err("the broker read returned no count".to_owned()),
            Step::Failed(reason) => return Err(reason),
        }
    }
}

/// The time still inside `timeout`, or the deadline sentence.
fn next_budget(
    started: Instant,
    now: &mut dyn FnMut() -> Instant,
    timeout: Duration,
) -> Result<Duration, String> {
    budget(started, now(), timeout)
}

fn budget(started: Instant, now: Instant, timeout: Duration) -> Result<Duration, String> {
    let remaining = time_left(started, now, timeout).ok_or_else(|| DEADLINE.to_owned())?;
    kernel_timeout(remaining).ok_or_else(|| DEADLINE.to_owned())
}

/// The time still inside `timeout`, measured from `started`.
///
/// `None` when the deadline has passed or the clock moved backwards. A
/// backwards step is not "no time has elapsed": that reading would hand the
/// next attempt a fresh full timeout.
fn time_left(started: Instant, now: Instant, timeout: Duration) -> Option<Duration> {
    now.checked_duration_since(started)
        .and_then(|elapsed| timeout.checked_sub(elapsed))
        .filter(|left| !left.is_zero())
}

/// A socket timeout that cannot outlast `remaining`.
///
/// `SO_SNDTIMEO` and `SO_RCVTIMEO` are timevals. rustix rounds them up to the
/// next microsecond, and a zero timeval means block forever, so one
/// microsecond is held back. What cannot spare that microsecond is already
/// the deadline.
fn kernel_timeout(remaining: Duration) -> Option<Duration> {
    remaining
        .checked_sub(Duration::from_micros(1))
        .filter(|adjusted| !adjusted.is_zero())
}

fn response_candidate(bytes: &[u8]) -> bool {
    bytes.iter().rev().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'}')
}

/// The real broker socket.
struct Live {
    path: std::path::PathBuf,
    /// The non-blocking attempt already saw a full queue. The next connect
    /// blocks in the kernel for the time still left.
    wait: bool,
    stream: Option<UnixStream>,
}

impl Live {
    fn open(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            wait: false,
            stream: None,
        }
    }

    fn apply(&mut self, settled: Settled) -> Step {
        match settled {
            Settled::Done(fd) => {
                self.stream = Some(take_stream(fd));
                Step::Ready
            }
            Settled::NeedWait => {
                self.wait = true;
                Step::Interrupted
            }
            Settled::Interrupted => Step::Interrupted,
            Settled::Failed(reason) => Step::Failed(reason),
        }
    }
}

impl BrokerIo for Live {
    fn connect(&mut self, bounded: Duration) -> Step {
        if self.stream.is_some() {
            return Step::Ready;
        }
        let started = start_connect(&self.path, bounded, self.wait);
        self.apply(settle(started, self.wait))
    }

    fn write(&mut self, bounded: Duration, bytes: &[u8]) -> Step {
        let Some(stream) = self.stream.as_mut() else {
            return Step::Failed("the broker write ran before the connection".to_owned());
        };
        let set = stream.set_write_timeout(Some(bounded));
        let transfer = Write::write(stream, bytes);
        classify_io(after_timeout(set, transfer))
    }

    fn shutdown_write(&mut self, bounded: Duration) -> Step {
        let Some(stream) = self.stream.as_mut() else {
            return Step::Failed("the broker shutdown ran before the connection".to_owned());
        };
        // `shutdown` does not block on this socket. The deadline was already
        // checked, and the timeout is set so a kernel that does wait cannot
        // outlast it.
        let set = stream.set_write_timeout(Some(bounded));
        let end = stream.shutdown(Shutdown::Write);
        let _ = set;
        classify_end(end)
    }

    fn read(&mut self, bounded: Duration, buf: &mut [u8]) -> Step {
        let Some(stream) = self.stream.as_mut() else {
            return Step::Failed("the broker read ran before the connection".to_owned());
        };
        let set = stream.set_read_timeout(Some(bounded));
        let transfer = Read::read(stream, buf);
        classify_io(after_timeout(set, transfer))
    }
}

/// A refused timeout update must not drop bytes already queued.
///
/// macOS refuses `SO_RCVTIMEO` after the peer has closed. The read result
/// still stands. A fresh socket accepts the timeout, and that is what bounds
/// the call.
fn after_timeout(set: io::Result<()>, transfer: io::Result<usize>) -> io::Result<usize> {
    drop(set);
    transfer
}

fn classify_io(result: io::Result<usize>) -> Step {
    match result {
        Ok(count) => Step::Transferred(count),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Step::Interrupted,
        Err(error) if is_timeout(&error) => Step::Failed(DEADLINE.to_owned()),
        Err(error) => Step::Failed(error.to_string()),
    }
}

fn classify_end(result: io::Result<()>) -> Step {
    match result {
        Ok(()) => Step::Ready,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Step::Interrupted,
        Err(error) if is_timeout(&error) => Step::Failed(DEADLINE.to_owned()),
        Err(error) => Step::Failed(error.to_string()),
    }
}

fn is_timeout(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut
}

fn take_stream(fd: OwnedFd) -> UnixStream {
    let stream = UnixStream::from(fd);
    // Clearing `O_NONBLOCK` fails closed. A later read returns `WouldBlock`,
    // which is the deadline, rather than blocking with no timeout.
    // `SO_RCVTIMEO` does not apply while the socket is non-blocking.
    let _ = stream.set_nonblocking(false);
    stream
}

/// How a connect attempt finished, before the wait state is applied.
#[derive(Debug)]
enum Start {
    Ready(OwnedFd),
    Interrupted,
    /// The queue did not accept the socket (`EAGAIN`, `EINPROGRESS`, `ETIMEDOUT`).
    Wait,
    Failed(String),
}

/// `Start` plus whether this socket is already on its blocking retry.
#[derive(Debug)]
enum Settled {
    Done(OwnedFd),
    NeedWait,
    Interrupted,
    Failed(String),
}

fn start_connect(path: &Path, bounded: Duration, wait: bool) -> Start {
    if wait {
        blocking_connect(path, bounded)
    } else {
        nonblocking_connect(path, bounded)
    }
}

fn nonblocking_connect(path: &Path, bounded: Duration) -> Start {
    finish_open(dial(path, true, bounded))
}

fn blocking_connect(path: &Path, bounded: Duration) -> Start {
    finish_open(dial(path, false, bounded))
}

fn dial(path: &Path, nonblock: bool, bounded: Duration) -> Result<OwnedFd, Errno> {
    open_socket(path).and_then(|(fd, address)| finish_dial(fd, &address, nonblock, bounded))
}

fn finish_dial(
    fd: OwnedFd,
    address: &SocketAddrUnix,
    nonblock: bool,
    bounded: Duration,
) -> Result<OwnedFd, Errno> {
    ensure_cloexec(&fd)
        .and_then(|()| prepare(&fd, nonblock, bounded))
        .and_then(|()| connect_fd(&fd, address))?;
    Ok(fd)
}

fn open_socket(path: &Path) -> Result<(OwnedFd, SocketAddrUnix), Errno> {
    SocketAddrUnix::new(path).and_then(|address| {
        socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            socket_flags(),
            None,
        )
        .map(|fd| (fd, address))
    })
}

fn socket_flags() -> SocketFlags {
    #[cfg(target_os = "linux")]
    {
        SocketFlags::CLOEXEC
    }
    #[cfg(not(target_os = "linux"))]
    {
        SocketFlags::empty()
    }
}

fn ensure_cloexec(fd: &OwnedFd) -> Result<(), Errno> {
    ioctl_fioclex(fd)
}

/// Non-blocking, or blocking with `SO_SNDTIMEO`. A non-blocking socket is not
/// given a send timeout: the kernel would return `EAGAIN` at once, and that
/// would look like the deadline.
fn prepare(fd: &OwnedFd, nonblock: bool, bounded: Duration) -> Result<(), Errno> {
    if nonblock {
        ioctl_fionbio(fd, true)
    } else {
        set_socket_timeout(fd, Timeout::Send, Some(bounded))
    }
}

fn finish_open(opened: Result<OwnedFd, Errno>) -> Start {
    match opened {
        Ok(fd) => Start::Ready(fd),
        Err(errno) => start_from_errno(errno),
    }
}

/// `EWOULDBLOCK` is not matched. On Linux it is `EAGAIN`, and a second arm
/// would be unreachable.
fn start_from_errno(errno: Errno) -> Start {
    match errno {
        Errno::INTR => Start::Interrupted,
        Errno::AGAIN | Errno::INPROGRESS | Errno::TIMEDOUT => Start::Wait,
        _ => Start::Failed(errno.to_string()),
    }
}

fn settle(start: Start, already_waiting: bool) -> Settled {
    match start {
        Start::Ready(fd) => Settled::Done(fd),
        Start::Interrupted => Settled::Interrupted,
        Start::Failed(reason) => Settled::Failed(reason),
        Start::Wait if already_waiting => Settled::Failed(DEADLINE.to_owned()),
        Start::Wait => Settled::NeedWait,
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

    use std::collections::VecDeque;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::time::Duration;

    use rustix::io::Errno;
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };
    use xudo_wire::{Answer, BrokerRequest, BrokerResponse, WIRE_SCHEMA_VERSION};

    use super::*;

    fn done_bytes() -> Vec<u8> {
        BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Done,
        }
        .to_json()
        .into_bytes()
    }

    fn bare_socket() -> OwnedFd {
        socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            socket_flags(),
            None,
        )
        .unwrap()
    }

    struct Clock {
        origin: Instant,
        offsets: VecDeque<Duration>,
    }

    impl Clock {
        fn new(offsets: &[Duration]) -> Self {
            Self {
                origin: Instant::now(),
                offsets: offsets.iter().copied().collect(),
            }
        }

        fn now(&mut self) -> Instant {
            let offset = self.offsets.pop_front().expect("kept reading the clock");
            self.origin.checked_add(offset).expect("clock offset")
        }
    }

    enum WriteAct {
        Step(Step),
        /// Report a transfer of the whole slice.
        Rest,
        /// Report one more byte than the slice holds.
        Overclaim,
    }

    enum ReadAct {
        Step(Step),
        Chunk(Vec<u8>),
        Fill(u8),
        Overclaim,
    }

    struct Script {
        connect: VecDeque<Step>,
        write: VecDeque<WriteAct>,
        shutdown: VecDeque<Step>,
        read: VecDeque<ReadAct>,
        seen_connect: Vec<Duration>,
        seen_write: Vec<Duration>,
        seen_shutdown: Vec<Duration>,
        seen_read: Vec<Duration>,
        reads: usize,
    }

    impl Script {
        fn new() -> Self {
            Self {
                connect: VecDeque::new(),
                write: VecDeque::new(),
                shutdown: VecDeque::new(),
                read: VecDeque::new(),
                seen_connect: Vec::new(),
                seen_write: Vec::new(),
                seen_shutdown: Vec::new(),
                seen_read: Vec::new(),
                reads: 0,
            }
        }
    }

    impl BrokerIo for Script {
        fn connect(&mut self, bounded: Duration) -> Step {
            self.seen_connect.push(bounded);
            self.connect.pop_front().expect("kept connecting")
        }

        fn write(&mut self, bounded: Duration, bytes: &[u8]) -> Step {
            self.seen_write.push(bounded);
            match self.write.pop_front().expect("kept writing") {
                WriteAct::Step(step) => step,
                WriteAct::Rest => Step::Transferred(bytes.len()),
                WriteAct::Overclaim => Step::Transferred(bytes.len().saturating_add(1)),
            }
        }

        fn shutdown_write(&mut self, bounded: Duration) -> Step {
            self.seen_shutdown.push(bounded);
            self.shutdown.pop_front().expect("kept shutting down")
        }

        fn read(&mut self, bounded: Duration, buf: &mut [u8]) -> Step {
            self.seen_read.push(bounded);
            self.reads = self.reads.saturating_add(1);
            assert!(
                self.reads <= 40,
                "the read loop did not stop at the size limit"
            );
            match self.read.pop_front().expect("kept reading") {
                ReadAct::Step(step) => step,
                ReadAct::Chunk(bytes) => {
                    let n = bytes.len().min(buf.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    Step::Transferred(n)
                }
                ReadAct::Fill(byte) => {
                    buf.fill(byte);
                    Step::Transferred(buf.len())
                }
                ReadAct::Overclaim => Step::Transferred(buf.len().saturating_add(1)),
            }
        }
    }

    fn zeros(n: usize) -> Vec<Duration> {
        vec![Duration::ZERO; n]
    }

    fn run(
        request: &[u8],
        timeout: Duration,
        offsets: &[Duration],
        io: &mut Script,
    ) -> Result<Vec<u8>, String> {
        let mut clock = Clock::new(offsets);
        exchange_until(request, timeout, &mut || clock.now(), io)
    }

    fn primed(read: Vec<ReadAct>) -> Script {
        let mut script = Script::new();
        script.connect.push_back(Step::Ready);
        script.write.push_back(WriteAct::Rest);
        script.shutdown.push_back(Step::Ready);
        script.read.extend(read);
        script
    }

    #[test]
    fn a_signal_storm_cannot_extend_the_reply_wait() {
        let timeout = Duration::from_secs(1);
        let full = kernel_timeout(timeout).unwrap();

        // started, connect, write, shutdown, one read. The next clock reading
        // is the deadline, so the loop must not read again.
        let mut storm = primed(vec![ReadAct::Step(Step::Interrupted)]);
        let offsets = [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            timeout,
        ];
        let err = run(b"{}", timeout, &offsets, &mut storm).unwrap_err();
        assert_eq!(err, DEADLINE);
        assert_eq!(storm.seen_read.len(), 1);
        assert_eq!(storm.seen_read.first().copied(), Some(full));
        assert!(full < timeout);

        let pause = Duration::from_millis(40);
        let mut shrunk = primed(vec![
            ReadAct::Step(Step::Interrupted),
            ReadAct::Chunk(done_bytes()),
        ]);
        let offsets = [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            pause,
        ];
        let got = run(b"{}", timeout, &offsets, &mut shrunk).unwrap();
        assert_eq!(got, done_bytes());
        assert_eq!(shrunk.seen_read.len(), 2);
        let first = *shrunk.seen_read.first().unwrap();
        let second = *shrunk.seen_read.get(1).unwrap();
        let left = kernel_timeout(timeout.checked_sub(pause).unwrap()).unwrap();
        assert_eq!(first, full);
        assert_eq!(second, left);
        assert!(second < first);
        assert!(second <= timeout.checked_sub(pause).unwrap());
    }

    #[test]
    fn an_interrupted_connect_retries_with_the_time_left() {
        let timeout = Duration::from_secs(1);
        let pause = Duration::from_millis(40);
        let mut script = primed(vec![ReadAct::Chunk(done_bytes())]);
        script.connect.clear();
        script.connect.push_back(Step::Interrupted);
        script.connect.push_back(Step::Ready);
        let offsets = [Duration::ZERO, Duration::ZERO, pause, pause, pause, pause];
        assert_eq!(
            run(b"{}", timeout, &offsets, &mut script).unwrap(),
            done_bytes()
        );
        let first = *script.seen_connect.first().unwrap();
        let second = *script.seen_connect.get(1).unwrap();
        assert_eq!(first, kernel_timeout(timeout).unwrap());
        assert_eq!(
            second,
            kernel_timeout(timeout.checked_sub(pause).unwrap()).unwrap()
        );
        assert!(second < first);
    }

    #[test]
    fn an_interrupted_write_retries_with_the_time_left() {
        let timeout = Duration::from_secs(1);
        let pause = Duration::from_millis(40);
        let mut script = primed(vec![ReadAct::Chunk(done_bytes())]);
        script.write.clear();
        script.write.push_back(WriteAct::Step(Step::Interrupted));
        script.write.push_back(WriteAct::Rest);
        let offsets = [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            pause,
            pause,
            pause,
        ];
        assert!(run(b"abcdef", timeout, &offsets, &mut script).is_ok());
        let first = *script.seen_write.first().unwrap();
        let second = *script.seen_write.get(1).unwrap();
        assert!(second < first);
        assert_eq!(
            second,
            kernel_timeout(timeout.checked_sub(pause).unwrap()).unwrap()
        );
    }

    #[test]
    fn an_interrupted_shutdown_retries_with_the_time_left() {
        let timeout = Duration::from_secs(1);
        let pause = Duration::from_millis(40);
        let mut script = primed(vec![ReadAct::Chunk(done_bytes())]);
        script.shutdown.clear();
        script.shutdown.push_back(Step::Interrupted);
        script.shutdown.push_back(Step::Ready);
        let offsets = [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            pause,
            pause,
        ];
        assert!(run(b"{}", timeout, &offsets, &mut script).is_ok());
        let first = *script.seen_shutdown.first().unwrap();
        let second = *script.seen_shutdown.get(1).unwrap();
        assert!(second < first);
    }

    #[test]
    fn a_backwards_clock_does_not_restart_the_deadline() {
        let mut script = Script::new();
        let offsets = [Duration::from_secs(5), Duration::ZERO];
        let err = run(b"{}", Duration::from_secs(5), &offsets, &mut script).unwrap_err();
        assert_eq!(err, DEADLINE);
        assert!(script.seen_connect.is_empty());
    }

    #[test]
    fn a_spent_deadline_stops_the_write_before_another_syscall() {
        let timeout = Duration::from_secs(1);
        let mut script = Script::new();
        script.connect.push_back(Step::Ready);
        let err = run(
            b"{}",
            timeout,
            &[Duration::ZERO, Duration::ZERO, timeout],
            &mut script,
        )
        .unwrap_err();
        assert_eq!(err, DEADLINE);
        assert_eq!(script.seen_connect.len(), 1);
        assert!(script.seen_write.is_empty());
    }

    #[test]
    fn a_spent_deadline_stops_the_shutdown_before_another_syscall() {
        let timeout = Duration::from_secs(1);
        let mut script = primed(vec![]);
        let err = run(
            b"{}",
            timeout,
            &[Duration::ZERO, Duration::ZERO, Duration::ZERO, timeout],
            &mut script,
        )
        .unwrap_err();
        assert_eq!(err, DEADLINE);
        assert_eq!(script.seen_write.len(), 1);
        assert!(script.seen_shutdown.is_empty());
    }

    #[test]
    fn a_zero_timeout_fails_before_connect() {
        let mut script = Script::new();
        let err = run(b"{}", Duration::ZERO, &zeros(2), &mut script).unwrap_err();
        assert_eq!(err, DEADLINE);
        assert!(script.seen_connect.is_empty());
    }

    #[test]
    fn a_sliver_below_one_microsecond_is_already_the_deadline() {
        let mut script = Script::new();
        let err = run(b"{}", Duration::from_nanos(500), &zeros(2), &mut script).unwrap_err();
        assert_eq!(err, DEADLINE);
        assert!(script.seen_connect.is_empty());
    }

    #[test]
    fn an_empty_request_is_still_answered() {
        let mut script = primed(vec![ReadAct::Chunk(done_bytes())]);
        script.write.clear();
        assert_eq!(
            run(b"", Duration::from_secs(1), &zeros(4), &mut script).unwrap(),
            done_bytes()
        );
    }

    #[test]
    fn a_partial_write_is_continued_until_the_request_is_sent() {
        let mut script = primed(vec![ReadAct::Chunk(done_bytes())]);
        script.write.clear();
        script.write.push_back(WriteAct::Step(Step::Transferred(1)));
        script.write.push_back(WriteAct::Rest);
        assert_eq!(
            run(b"abcdef", Duration::from_secs(1), &zeros(8), &mut script).unwrap(),
            done_bytes()
        );
    }

    #[test]
    fn a_split_reply_is_assembled_without_waiting_for_eof() {
        let bytes = done_bytes();
        let (first, second) = bytes.split_at(1);
        let mut script = primed(vec![
            ReadAct::Chunk(first.to_vec()),
            ReadAct::Chunk(second.to_vec()),
        ]);
        assert_eq!(
            run(b"{}", Duration::from_secs(1), &zeros(8), &mut script).unwrap(),
            bytes
        );
        assert_eq!(script.seen_read.len(), 2);
    }

    #[test]
    fn a_malformed_closing_brace_is_rejected_after_eof() {
        let mut script = primed(vec![
            ReadAct::Chunk(b"}".to_vec()),
            ReadAct::Step(Step::Transferred(0)),
        ]);
        let got = run(b"{}", Duration::from_secs(1), &zeros(8), &mut script).unwrap();
        assert_eq!(got, b"}");
        assert!(BrokerResponse::parse(&got).is_err());
        assert_eq!(script.seen_read.len(), 2);
    }

    #[test]
    fn an_incomplete_reply_at_eof_is_rejected() {
        let mut script = primed(vec![ReadAct::Step(Step::Transferred(0))]);
        let got = run(b"{}", Duration::from_secs(1), &zeros(8), &mut script).unwrap();
        assert!(got.is_empty());
        let err = BrokerResponse::parse(&got).unwrap_err();
        assert!(err.to_string().contains("broker response"), "{err}");
    }

    #[test]
    fn an_oversized_reply_is_refused_at_the_limit() {
        let mut script = primed(vec![]);
        for _ in 0..40 {
            script.read.push_back(ReadAct::Fill(b'x'));
        }
        let err = run(b"{}", Duration::from_secs(30), &zeros(80), &mut script).unwrap_err();
        assert_eq!(err, TOO_BIG);
        assert!(script.reads < 40, "reads {}", script.reads);
    }

    #[test]
    fn a_read_or_write_that_overclaims_is_refused() {
        let mut over_read = primed(vec![ReadAct::Overclaim]);
        let err = run(b"{}", Duration::from_secs(1), &zeros(8), &mut over_read).unwrap_err();
        assert!(err.contains("more bytes than the buffer"), "{err}");

        let mut over_write = primed(vec![ReadAct::Chunk(done_bytes())]);
        over_write.write.clear();
        over_write.write.push_back(WriteAct::Overclaim);
        let err = run(
            b"abcdef",
            Duration::from_secs(1),
            &zeros(8),
            &mut over_write,
        )
        .unwrap_err();
        assert!(err.contains("more bytes than were offered"), "{err}");

        let mut stalled = primed(vec![]);
        stalled.write.clear();
        stalled
            .write
            .push_back(WriteAct::Step(Step::Transferred(0)));
        let err = run(b"abcdef", Duration::from_secs(1), &zeros(8), &mut stalled).unwrap_err();
        assert!(err.contains("no progress"), "{err}");
    }

    #[test]
    fn an_unexpected_step_or_a_failed_call_is_refused() {
        let mut counted = Script::new();
        counted.connect.push_back(Step::Transferred(1));
        let err = run(b"{}", Duration::from_secs(1), &zeros(4), &mut counted).unwrap_err();
        assert!(err.contains("byte count"), "{err}");

        let mut failed = Script::new();
        failed
            .connect
            .push_back(Step::Failed("broker down".to_owned()));
        let err = run(b"{}", Duration::from_secs(1), &zeros(4), &mut failed).unwrap_err();
        assert!(err.contains("broker down"), "{err}");

        let mut write_ready = primed(vec![]);
        write_ready.write.clear();
        write_ready.write.push_back(WriteAct::Step(Step::Ready));
        let err = run(b"{}", Duration::from_secs(1), &zeros(4), &mut write_ready).unwrap_err();
        assert!(err.contains("no count"), "{err}");

        let mut write_failed = primed(vec![]);
        write_failed.write.clear();
        write_failed
            .write
            .push_back(WriteAct::Step(Step::Failed("write failed".to_owned())));
        let err = run(b"{}", Duration::from_secs(1), &zeros(4), &mut write_failed).unwrap_err();
        assert!(err.contains("write failed"), "{err}");

        let mut shutdown_bad = primed(vec![]);
        shutdown_bad.shutdown.clear();
        shutdown_bad.shutdown.push_back(Step::Transferred(1));
        let err = run(b"{}", Duration::from_secs(1), &zeros(4), &mut shutdown_bad).unwrap_err();
        assert!(err.contains("byte count"), "{err}");

        let mut shutdown_failed = primed(vec![]);
        shutdown_failed.shutdown.clear();
        shutdown_failed
            .shutdown
            .push_back(Step::Failed("shutdown failed".to_owned()));
        let err = run(
            b"{}",
            Duration::from_secs(1),
            &zeros(4),
            &mut shutdown_failed,
        )
        .unwrap_err();
        assert!(err.contains("shutdown failed"), "{err}");

        let mut read_ready = primed(vec![ReadAct::Step(Step::Ready)]);
        let err = run(b"{}", Duration::from_secs(1), &zeros(8), &mut read_ready).unwrap_err();
        assert!(err.contains("no count"), "{err}");

        let mut read_failed = primed(vec![ReadAct::Step(Step::Failed("read failed".to_owned()))]);
        let err = run(b"{}", Duration::from_secs(1), &zeros(8), &mut read_failed).unwrap_err();
        assert!(err.contains("read failed"), "{err}");
    }

    #[test]
    fn only_a_trailing_brace_is_a_response_candidate() {
        assert!(!response_candidate(b""));
        assert!(!response_candidate(b" \n\t"));
        assert!(!response_candidate(b"{"));
        assert!(response_candidate(b"}"));
        assert!(response_candidate(b"} \n"));
        assert!(response_candidate(b"{\"a\":1}"));
    }

    #[test]
    fn kernel_timeout_holds_back_one_microsecond() {
        assert_eq!(kernel_timeout(Duration::ZERO), None);
        assert_eq!(kernel_timeout(Duration::from_nanos(500)), None);
        assert_eq!(kernel_timeout(Duration::from_micros(1)), None);
        assert_eq!(
            kernel_timeout(Duration::from_micros(2)),
            Some(Duration::from_micros(1))
        );
    }

    #[test]
    fn time_left_refuses_a_backwards_or_spent_clock() {
        let start = Instant::now();
        let later = start.checked_add(Duration::from_secs(2)).unwrap();
        assert_eq!(time_left(later, start, Duration::from_secs(5)), None);
        assert_eq!(time_left(start, later, Duration::from_secs(1)), None);
        assert_eq!(time_left(start, start, Duration::ZERO), None);
        assert_eq!(
            time_left(start, start, Duration::from_secs(1)),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn io_results_map_to_the_deadline_or_the_error() {
        assert_eq!(
            classify_io(Err(io::Error::from(io::ErrorKind::WouldBlock))),
            Step::Failed(DEADLINE.to_owned())
        );
        assert_eq!(
            classify_io(Err(io::Error::from(io::ErrorKind::TimedOut))),
            Step::Failed(DEADLINE.to_owned())
        );
        assert_eq!(
            classify_io(Err(io::Error::from(io::ErrorKind::Interrupted))),
            Step::Interrupted
        );
        assert!(matches!(
            classify_io(Err(io::Error::other("disk"))),
            Step::Failed(reason) if reason.contains("disk")
        ));
        assert_eq!(classify_io(Ok(3)), Step::Transferred(3));

        assert_eq!(classify_end(Ok(())), Step::Ready);
        assert_eq!(
            classify_end(Err(io::Error::from(io::ErrorKind::Interrupted))),
            Step::Interrupted
        );
        assert_eq!(
            classify_end(Err(io::Error::from(io::ErrorKind::WouldBlock))),
            Step::Failed(DEADLINE.to_owned())
        );
        assert_eq!(
            classify_end(Err(io::Error::other("reset"))),
            Step::Failed("reset".to_owned())
        );
        assert_eq!(
            after_timeout(Err(io::Error::from(io::ErrorKind::InvalidInput)), Ok(4)).unwrap(),
            4
        );
    }

    #[test]
    fn connect_errno_is_classified_without_calling_the_kernel() {
        assert_eq!(
            format!("{:?}", start_from_errno(Errno::INTR)),
            "Interrupted"
        );
        assert_eq!(format!("{:?}", start_from_errno(Errno::AGAIN)), "Wait");
        assert_eq!(format!("{:?}", start_from_errno(Errno::INPROGRESS)), "Wait");
        assert_eq!(format!("{:?}", start_from_errno(Errno::TIMEDOUT)), "Wait");
        let refused = format!("{:?}", start_from_errno(Errno::CONNREFUSED));
        assert!(refused.starts_with("Failed("), "{refused}");

        let done = settle(Start::Ready(bare_socket()), false);
        assert!(format!("{done:?}").starts_with("Done("), "{done:?}");
        let interrupted = settle(Start::Interrupted, false);
        assert_eq!(format!("{interrupted:?}"), "Interrupted");
        let interrupted_again = settle(Start::Interrupted, true);
        assert_eq!(format!("{interrupted_again:?}"), "Interrupted");
        let failed = settle(Start::Failed("e".to_owned()), false);
        assert_eq!(format!("{failed:?}"), "Failed(\"e\")");
        let waiting = settle(Start::Wait, false);
        assert_eq!(format!("{waiting:?}"), "NeedWait");
        assert!(matches!(
            settle(Start::Wait, true),
            Settled::Failed(reason) if reason == DEADLINE
        ));

        let mut live = Live::open(Path::new("/nope"));
        assert_eq!(live.apply(Settled::Interrupted), Step::Interrupted);
        assert!(!live.wait);
        assert_eq!(
            live.apply(Settled::Failed("no".to_owned())),
            Step::Failed("no".to_owned())
        );
    }

    #[test]
    fn a_second_connect_does_not_dial_again() {
        let mut live = Live::open(Path::new("/nope"));
        assert_eq!(live.apply(Settled::Done(bare_socket())), Step::Ready);
        assert_eq!(live.connect(Duration::from_millis(50)), Step::Ready);
    }

    #[test]
    fn io_before_connect_fails_closed() {
        let mut live = Live::open(Path::new("/nope"));
        assert_eq!(
            live.write(Duration::from_secs(1), b"x"),
            Step::Failed("the broker write ran before the connection".to_owned())
        );
        assert_eq!(
            live.shutdown_write(Duration::from_secs(1)),
            Step::Failed("the broker shutdown ran before the connection".to_owned())
        );
        let mut buf = [0u8; 1];
        assert_eq!(
            live.read(Duration::from_secs(1), &mut buf),
            Step::Failed("the broker read ran before the connection".to_owned())
        );
    }

    #[test]
    fn a_listening_socket_accepts_a_bounded_connect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let blocking = start_connect(&path, Duration::from_secs(1), true);
        assert!(
            format!("{blocking:?}").starts_with("Ready("),
            "blocking connect did not finish: {blocking:?}"
        );
        let nonblocking = start_connect(&path, Duration::from_secs(1), false);
        // Linux accepts this connect at once. Another kernel may return
        // `EINPROGRESS` for the same non-blocking call, so only Linux pins
        // the variant. The call itself still runs everywhere.
        #[cfg(target_os = "linux")]
        assert!(
            format!("{nonblocking:?}").starts_with("Ready("),
            "nonblocking: {nonblocking:?}"
        );
        #[cfg(not(target_os = "linux"))]
        drop(nonblocking);
        drop(listener);
    }

    #[test]
    fn a_wait_uses_one_blocking_connect_and_a_silent_peer_hits_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("b.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut live = Live::open(&path);
        assert_eq!(live.apply(Settled::NeedWait), Step::Interrupted);
        assert!(live.wait);
        assert_eq!(live.connect(Duration::from_secs(1)), Step::Ready);
        assert_eq!(
            live.write(Duration::from_millis(200), b"hi"),
            Step::Transferred(2)
        );
        assert_eq!(live.shutdown_write(Duration::from_millis(200)), Step::Ready);
        let mut buf = [0u8; 4];
        assert_eq!(
            live.read(Duration::from_millis(50), &mut buf),
            Step::Failed(DEADLINE.to_owned())
        );
        drop(listener);
    }

    #[test]
    fn a_missing_or_overlong_socket_path_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.sock");
        for wait in [false, true] {
            let reason = start_connect(&missing, Duration::from_secs(1), wait);
            assert!(
                matches!(reason, Start::Failed(ref text) if text.contains("No such file")),
                "{reason:?} wait={wait}"
            );
        }
        let long = PathBuf::from(format!("/{}", "a".repeat(200)));
        for wait in [false, true] {
            let reason = start_connect(&long, Duration::from_millis(50), wait);
            assert!(
                matches!(reason, Start::Failed(ref text) if text.contains("long")),
                "{reason:?} wait={wait}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn within<T: Send + 'static>(limit: Duration, work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver.recv_timeout(limit).expect("exchange hung")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_broker_socket_that_never_accepts_times_out_within_the_deadline() {
        use rustix::net::{bind, listen};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full.sock");
        let address = SocketAddrUnix::new(&path).unwrap();
        let listener = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        bind(&listener, &address).unwrap();
        listen(&listener, 1).unwrap();

        // Hold every queued connection until the assertions finish. Dropping
        // one early would free a slot and the exchange would connect.
        let mut holders = Vec::new();
        let mut filled = false;
        for _ in 0..64 {
            let fd = socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .unwrap();
            // The first errors are the full queue (`EAGAIN`). Any other
            // failure also stops the fill; the deadline assertion then fails
            // closed instead of treating a surprise errno as a filled queue
            // that the exchange is allowed to miss.
            if connect(&fd, &address).is_ok() {
                holders.push(fd);
            } else {
                filled = true;
                break;
            }
        }
        assert!(filled, "the listen queue accepted 64 connections");

        let socket = path.clone();
        let started = Instant::now();
        let result = within(Duration::from_secs(2), move || {
            let request = BrokerRequest::new("/usr/bin/true", Vec::new(), "unattested");
            crate::exec::ask(&socket, Duration::from_millis(200), &request)
        });
        let elapsed = started.elapsed();
        let err = result.expect_err("a full backlog connected");
        assert!(err.contains("broker response deadline expired"), "{err}");
        assert!(
            elapsed >= Duration::from_millis(100),
            "returned immediately: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(1), "hung: {elapsed:?}");

        let socket = path.clone();
        let started = Instant::now();
        let result = within(Duration::from_secs(4), move || {
            let request = BrokerRequest::new("/usr/bin/true", Vec::new(), "unattested");
            crate::watch::ask_live(&socket, &request)
        });
        let elapsed = started.elapsed();
        let err = result.expect_err("watch connected through a full backlog");
        assert!(err.contains("broker response deadline expired"), "{err}");
        assert!(
            elapsed >= Duration::from_millis(500),
            "returned immediately: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(3), "hung: {elapsed:?}");

        let _kept = (listener, holders);
    }
}
