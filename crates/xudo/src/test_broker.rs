//! A one-shot fake broker for the tests that talk over a real socket.
//!
//! The thread reads the request until it parses (or the peer closes, or the
//! read bound passes), so it never waits for an end of file the client may
//! deliver late. It always writes the reply, whatever it read. The caller
//! waits for it with a bound and a message that says what did not happen, so a
//! broker that never ran fails the test in seconds, not as a client deadline
//! after a minute.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::Duration;

use xudo_wire::BrokerRequest;

/// How long the broker thread waits for request bytes.
const READ_BOUND: Duration = Duration::from_secs(20);
/// How long a test waits for the broker thread to finish.
const FINISH_BOUND: Duration = Duration::from_secs(30);

/// A broker thread that has been started.
pub(crate) struct Served(Receiver<Vec<u8>>);

/// Accepts one connection on `listener` (already bound, so a client may
/// connect before the thread reaches `accept`), reads the request, and writes
/// `reply`.
pub(crate) fn serve_once(listener: UnixListener, reply: Vec<u8>) -> Served {
    let (sender, receiver) = channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.set_read_timeout(Some(READ_BOUND));
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut read = 1;
        while read != 0 && BrokerRequest::parse(&request).is_err() {
            read = stream.read(&mut chunk).unwrap_or(0);
            request.extend_from_slice(&chunk[..read]);
        }
        let _ = stream.write_all(&reply);
        let _ = sender.send(request);
    });
    Served(receiver)
}

impl Served {
    /// The request the broker received. Fails the test when the thread did not
    /// finish: no client connected, or it panicked.
    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
            .recv_timeout(FINISH_BOUND)
            .expect("the fake broker did not finish: no client connected, or its thread panicked")
    }
}
