//! A one-shot fake broker for the tests that talk over a real socket.
//!
//! The thread reads the request until it parses (or the peer closes, or the
//! read bound passes), so it never waits for an end of file the client may
//! deliver late. It always writes the reply, whatever it read. The caller
//! waits for it with a bound and a message that says what did not happen, so a
//! broker that never ran fails the test in seconds, not as a client deadline
//! after a minute.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

use xudo_wire::BrokerRequest;

/// How long the broker thread waits for request bytes.
const READ_BOUND: Duration = Duration::from_secs(20);
/// How long a test waits for the broker thread to finish.
const FINISH_BOUND: Duration = Duration::from_secs(30);

/// What happened while one scripted reply was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyWrite {
    Written,
    Failed(ErrorKind),
}

/// What the broker observed. Failed writes are data for the test to inspect,
/// never a reason for the broker thread to panic.
#[derive(Debug)]
pub(crate) struct Report {
    pub(crate) requests: Vec<Vec<u8>>,
    pub(crate) writes: Vec<ReplyWrite>,
    pub(crate) accept_error: Option<String>,
}

/// A broker thread that has been started.
pub(crate) struct Served(Receiver<Report>);

type RequestCallback = dyn FnMut(usize, &[u8]) + Send;

/// Accepts one connection on `listener` (already bound, so a client may
/// connect before the thread reaches `accept`), reads the request, and writes
/// `reply`.
pub(crate) fn serve_once(listener: UnixListener, reply: Vec<u8>) -> Served {
    serve_many(listener, vec![reply])
}

/// Accepts a scripted sequence of connections and replies in order.
pub(crate) fn serve_many(listener: UnixListener, replies: Vec<Vec<u8>>) -> Served {
    serve_many_with_bound(listener, replies, READ_BOUND, Box::new(ignore_request))
}

fn ignore_request(_: usize, _: &[u8]) {}

/// Like [`serve_many`], with a callback after each complete request arrives
/// and before its reply is written.
pub(crate) fn serve_many_with<F>(
    listener: UnixListener,
    replies: Vec<Vec<u8>>,
    on_request: F,
) -> Served
where
    F: FnMut(usize, &[u8]) + Send + 'static,
{
    serve_many_with_bound(listener, replies, READ_BOUND, Box::new(on_request))
}

fn serve_many_with_bound(
    listener: UnixListener,
    replies: Vec<Vec<u8>>,
    read_bound: Duration,
    mut on_request: Box<RequestCallback>,
) -> Served {
    let (sender, receiver) = channel();
    thread::spawn(move || {
        let mut report = Report {
            requests: Vec::with_capacity(replies.len()),
            writes: Vec::with_capacity(replies.len()),
            accept_error: None,
        };
        listener.set_nonblocking(true).unwrap();
        for (index, reply) in replies.into_iter().enumerate() {
            let (mut stream, _) = match accept_bounded(&listener, read_bound) {
                Ok(connection) => connection,
                Err(error) => {
                    report.accept_error = Some(error.to_string());
                    break;
                }
            };
            // macOS and the BSDs let an accepted socket inherit the listener's
            // O_NONBLOCK (Linux does not). Without this a read before the client
            // has written returns WouldBlock and is taken for an empty request.
            stream.set_nonblocking(false).unwrap();
            let _ = stream.set_read_timeout(Some(read_bound));
            let _ = stream.set_write_timeout(Some(read_bound));
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            let mut read = 1;
            while read != 0 && BrokerRequest::parse(&request).is_err() {
                read = stream.read(&mut chunk).unwrap_or(0);
                request.extend_from_slice(&chunk[..read]);
            }
            on_request(index, &request);
            report.requests.push(request);
            report.writes.push(match stream.write_all(&reply) {
                Ok(()) => ReplyWrite::Written,
                Err(error) => ReplyWrite::Failed(error.kind()),
            });
        }
        let _ = sender.send(report);
    });
    Served(receiver)
}

fn accept_bounded(
    listener: &UnixListener,
    bound: Duration,
) -> io::Result<(UnixStream, std::os::unix::net::SocketAddr)> {
    let deadline = Instant::now()
        .checked_add(bound)
        .expect("the short test broker deadline fits in an Instant");
    let mut connection = None;
    let mut accept = || {
        connection = Some(listener.accept()?);
        Ok(())
    };
    let mut pause = thread::sleep;
    accept_bounded_with(deadline, &mut accept, &mut pause)?;
    Ok(connection.expect("a successful bounded accept stores its connection"))
}

fn accept_bounded_with(
    deadline: Instant,
    accept: &mut dyn FnMut() -> io::Result<()>,
    pause: &mut dyn FnMut(Duration),
) -> io::Result<()> {
    loop {
        match accept() {
            Ok(connection) => return Ok(connection),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        ErrorKind::TimedOut,
                        "broker accept deadline expired",
                    ));
                }
                pause(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

impl Served {
    /// The request the broker received. Fails the test when the thread did not
    /// finish: no client connected, or it panicked.
    pub(crate) fn finish(self) -> Vec<u8> {
        let report = self.finish_report();
        assert!(
            report.accept_error.is_none(),
            "fake broker accept failed: {:?}",
            report.accept_error
        );
        assert_eq!(report.requests.len(), 1, "expected one broker request");
        report.requests.into_iter().next().unwrap()
    }

    /// The request and reply outcomes, bounded by [`FINISH_BOUND`].
    pub(crate) fn finish_report(self) -> Report {
        self.0
            .recv_timeout(FINISH_BOUND)
            .expect("the fake broker did not finish: no client connected, or its thread panicked")
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::Shutdown;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};

    use xudo_wire::BrokerRequest;

    use super::{
        ReplyWrite, accept_bounded_with, ignore_request, serve_many_with_bound, serve_once,
    };

    #[test]
    fn bounded_accept_retries_would_block_then_accepts() {
        let mut calls = 0;
        let mut pauses = Vec::new();
        let deadline = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let mut accept = || {
            calls += 1;
            if calls == 1 {
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            } else {
                Ok(())
            }
        };
        let mut pause = |duration| pauses.push(duration);
        let accepted = accept_bounded_with(deadline, &mut accept, &mut pause);
        accepted.unwrap();
        assert_eq!(calls, 2);
        assert_eq!(pauses, [Duration::from_millis(10)]);
    }

    #[test]
    fn bounded_accept_reports_timeout_and_other_errors() {
        let expired = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap();
        let mut would_block = || Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        let mut pause = std::thread::sleep;
        let timeout = accept_bounded_with(expired, &mut would_block, &mut pause).unwrap_err();
        assert_eq!(timeout.kind(), std::io::ErrorKind::TimedOut);

        let mut interrupted = || Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
        let interrupted =
            accept_bounded_with(Instant::now(), &mut interrupted, &mut pause).unwrap_err();
        assert_eq!(interrupted.kind(), std::io::ErrorKind::Interrupted);
    }

    #[test]
    fn scripted_broker_reports_a_missing_connection_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("broker.sock")).unwrap();
        let broker = serve_many_with_bound(
            listener,
            vec![Vec::new()],
            Duration::ZERO,
            Box::new(ignore_request),
        );
        let report = broker.finish_report();
        assert!(report.requests.is_empty());
        assert!(report.writes.is_empty());
        assert_eq!(
            report.accept_error.as_deref(),
            Some("broker accept deadline expired")
        );
    }

    #[test]
    fn records_epipe_when_a_client_closes_after_sending_its_request() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = serve_once(listener, vec![b'x'; 1024 * 1024]);

        let mut client = UnixStream::connect(&socket).unwrap();
        client
            .write_all(
                BrokerRequest::new("/usr/bin/true", Vec::new(), "test")
                    .to_json()
                    .as_bytes(),
            )
            .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        drop(client);

        let report = broker.finish_report();
        assert_eq!(report.accept_error, None);
        assert_eq!(report.requests.len(), 1);
        assert!(BrokerRequest::parse(&report.requests[0]).is_ok());
        assert_eq!(
            report.writes,
            [ReplyWrite::Failed(std::io::ErrorKind::BrokenPipe)]
        );
    }
}
