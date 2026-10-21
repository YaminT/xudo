//! The real standard streams, held to what the gate promises about them.
//!
//! The gate fills a standard stream it was started without, so that its own
//! next `open` is never standard error and so that the command it execs
//! inherits a stream where it expects one. The second half is the one a fake
//! table cannot see: whether a descriptor survives an `exec` is a flag on the
//! real descriptor, and the real fill sets it wrong in exactly one case.
//!
//! `open` returns the lowest free descriptor number, which, when a stream is
//! closed, is the stream's own. Installing that file as the stream is then a
//! `dup2` of a descriptor onto itself, which the kernel does nothing about, and
//! the `O_CLOEXEC` the file was opened with stays on it. The gate would hand
//! its command that stream closed. In the shipped binary nothing reaches this,
//! because Rust's runtime fills a closed 0, 1 or 2 itself before `main` and
//! without the flag; the library does not rest on that, and this test does not
//! either.
//!
//! A process cannot be started with a stream closed and still reach the
//! library's fill, for that same reason, and closing one from inside takes
//! `unsafe`, which `aido-sys` may not have. So the test puts a real standard
//! stream in the state the fill leaves it in, descriptor and flag, and holds
//! `install` to what follows: the stream is no longer close-on-exec, which it
//! proves with an exec of a shell that duplicates all three.
//!
//! One test, in a process of its own. It sets flags on this process's own
//! standard descriptors, and while one is set an exec anywhere in the process
//! would lose that stream. Beside the library's unit tests, some of which start
//! children, it could not be made safe; alone in its binary it is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // An absolute path, as the lint asks for, and the one thing this test must
    // do is exec.
    clippy::disallowed_methods
)]

use std::os::fd::{AsFd, BorrowedFd};
use std::process::Command;

use aido_sys::hygiene::{HostStd, StdStream, StdTable};
use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd};

/// The three standard streams: the name the table uses, and the descriptor.
fn streams() -> [(StdStream, BorrowedFd<'static>); 3] {
    [
        (StdStream::In, rustix::stdio::stdin()),
        (StdStream::Out, rustix::stdio::stdout()),
        (StdStream::Err, rustix::stdio::stderr()),
    ]
}

fn closes_on_exec(fd: BorrowedFd<'_>) -> bool {
    fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC)
}

/// Whether a shell started from here has standard input, output and error:
/// it duplicates each onto a descriptor of its own, which fails on a closed one
/// and which a redirection of the shell's own error stream cannot hide.
fn a_child_has_all_three_streams() -> bool {
    Command::new("/bin/sh")
        .args(["-c", "exec 3<&0 4>&1 5>&2"])
        .status()
        .unwrap()
        .success()
}

#[test]
fn a_stream_the_gate_fills_is_not_closed_by_the_exec_that_follows() {
    // What the harness gave this process, and so what is put back: open,
    // inheritable, and a child can see it.
    for (stream, fd) in streams() {
        assert!(HostStd.is_open(stream), "{stream:?}");
        assert!(!closes_on_exec(fd), "{stream:?} starts inheritable");
    }
    assert!(
        a_child_has_all_three_streams(),
        "the probe sees open streams"
    );

    // A fresh /dev/null is close-on-exec, so a spare that is not installed as
    // a stream never leaks into whatever the gate execs.
    let spare = HostStd.open_null().unwrap();
    assert!(closes_on_exec(spare.as_fd()), "the opened /dev/null");

    for (stream, fd) in streams() {
        // The state the fill leaves a stream in when `open` handed back the
        // stream's own number: one descriptor named as source and target, and
        // the flag the open set still on it. The unfixed `install` was a
        // `dup2` of it onto itself, which changes nothing.
        fcntl_setfd(fd, FdFlags::CLOEXEC).unwrap();
        HostStd.install(stream, fd).unwrap();
        assert!(
            !closes_on_exec(fd),
            "{stream:?} is still close-on-exec after it was installed from itself"
        );
        assert!(
            a_child_has_all_three_streams(),
            "a command started now has {stream:?} closed"
        );

        // The other state, a stream filled from a different descriptor, which
        // is close-on-exec as `open_null` makes it. Another name for the same
        // open file, so what the harness prints is not redirected.
        let other = fcntl_dupfd_cloexec(fd, 10).unwrap();
        assert!(closes_on_exec(other.as_fd()));
        fcntl_setfd(fd, FdFlags::CLOEXEC).unwrap();
        HostStd.install(stream, other.as_fd()).unwrap();
        assert!(
            !closes_on_exec(fd),
            "{stream:?} is still close-on-exec after it was installed from a copy"
        );
        assert!(
            a_child_has_all_three_streams(),
            "a command started now has {stream:?} closed, filled from a copy"
        );
    }
}
