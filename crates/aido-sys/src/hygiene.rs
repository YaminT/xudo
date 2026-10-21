//! What a privileged process settles about itself before it believes anything.
//!
//! Three small facts, each of which the gate must establish and none of which
//! `aido-sys-raw` is needed for:
//!
//! * **Descriptors 0, 1 and 2 are open.** A process started with one of them
//!   closed has a hole where the kernel will put the *next* thing it opens.
//!   Open the audit log first and it becomes standard error: every diagnostic
//!   the gate or its child prints is then written into the log, and a child
//!   that writes to "stdout" writes there too. The classic set-user-ID attack.
//!   [`Hygiene::ensure_std_streams`] fills each closed one with `/dev/null`
//!   before the gate opens anything else, and leaves it open across the exec:
//!   a filled stream that the command then inherits closed would put the hole
//!   back in the command's own process. Rust's runtime does the same fill
//!   before `main`, so in a Rust binary this is the second line of defence;
//!   it is held anyway, because the guarantee must not rest on a runtime
//!   detail.
//! * **The process may not gain privilege by exec.** `PR_SET_NO_NEW_PRIVS`
//!   makes a set-user-ID or file-capability binary run with its caller's
//!   credentials, so the command the gate runs cannot be anything but what the
//!   rule named. Irreversible, and inherited across `execve`.
//! * **Which process this is**, for the lineage walk. `getpid`, not
//!   `/proc/self`, so the answer does not depend on a `/proc` not yet verified.
//!
//! The trait exists so the gate's order of operations can be tested against a
//! fake that records it, and made to fail at each step.

use std::cell::RefCell;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

use rustix::fs::{Mode, OFlags, fstat, open};
use rustix::io::{Errno, FdFlags, fcntl_setfd};

use crate::error::{SysError, lift};

/// What the gate settles about its own process.
pub trait Hygiene {
    /// Makes sure descriptors 0, 1 and 2 are open, replacing each closed one
    /// with `/dev/null`. Called before anything else is opened.
    ///
    /// # Errors
    ///
    /// [`SysError`] when `/dev/null` cannot be opened or installed: the caller
    /// cannot know what its next `open` would become, and must refuse.
    fn ensure_std_streams(&self) -> Result<(), SysError>;

    /// Sets `PR_SET_NO_NEW_PRIVS` on this process, and confirms it took.
    ///
    /// # Errors
    ///
    /// [`SysError`] when the kernel refuses, or on a platform without it.
    fn forbid_new_privileges(&self) -> Result<(), SysError>;

    /// This process's id.
    fn pid(&self) -> u32;
}

/// One of the three standard descriptors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StdStream {
    /// Descriptor 0.
    In,
    /// Descriptor 1.
    Out,
    /// Descriptor 2.
    Err,
}

/// Every standard descriptor, in the order the kernel numbers them.
const STREAMS: [StdStream; 3] = [StdStream::In, StdStream::Out, StdStream::Err];

/// The highest descriptor number that is a standard stream.
const LAST_STD_FD: i32 = 2;

impl StdStream {
    /// The descriptor, borrowed. Whether anything is open at it is the
    /// question [`StdTable::is_open`] answers.
    fn borrowed(self) -> BorrowedFd<'static> {
        match self {
            Self::In => rustix::stdio::stdin(),
            Self::Out => rustix::stdio::stdout(),
            Self::Err => rustix::stdio::stderr(),
        }
    }

    /// Makes this descriptor another name for `from`'s open file, and one that
    /// survives an `exec`.
    ///
    /// The second half is not `dup2`'s to promise. A duplicate onto a
    /// *different* descriptor is never close-on-exec, but `dup2` of a
    /// descriptor onto itself does nothing at all, and that is the ordinary
    /// case here: `open` returns the lowest free number, which, when a stream
    /// is closed, is the stream's own. The `O_CLOEXEC` that `/dev/null` was
    /// opened with would stay on it, and the command the gate execs would
    /// start without that stream, the hole the fill exists to close. So the
    /// flag is cleared by name, whichever descriptor the file arrived on.
    fn install(self, from: BorrowedFd<'_>) -> Result<(), Errno> {
        match self {
            Self::In => rustix::stdio::dup2_stdin(from),
            Self::Out => rustix::stdio::dup2_stdout(from),
            Self::Err => rustix::stdio::dup2_stderr(from),
        }
        .and_then(|()| fcntl_setfd(self.borrowed(), FdFlags::empty()))
    }
}

/// The three operations hole-filling needs from the descriptor table, so the
/// order and the failure of each can be tested without closing this process's
/// own standard streams.
pub trait StdTable {
    /// Whether `stream` is an open descriptor.
    fn is_open(&self, stream: StdStream) -> bool;

    /// Opens `/dev/null` read-write. The kernel gives it the lowest free
    /// descriptor, which may be a hole in 0 to 2.
    ///
    /// # Errors
    ///
    /// [`SysError`] when it cannot be opened.
    fn open_null(&self) -> Result<OwnedFd, SysError>;

    /// Makes `stream` another name for `null`'s open file, and leaves it open
    /// across an `exec`: a stream the gate filled and its command then
    /// inherits closed would be the hole all over again. `null` may be the
    /// stream's own descriptor, which is what `open` returns when the stream
    /// is closed.
    ///
    /// # Errors
    ///
    /// [`SysError`] when the kernel refuses.
    fn install(&self, stream: StdStream, null: BorrowedFd<'_>) -> Result<(), SysError>;
}

/// The real descriptor table of this process.
#[derive(Clone, Copy, Debug)]
pub struct HostStd;

impl StdTable for HostStd {
    fn is_open(&self, stream: StdStream) -> bool {
        // Any failure to `fstat` means the descriptor is not usable, and
        // replacing a descriptor that cannot be used is the safe direction.
        fstat(stream.borrowed()).is_ok()
    }

    fn open_null(&self) -> Result<OwnedFd, SysError> {
        lift(
            "open(/dev/null)",
            open(
                "/dev/null",
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOCTTY,
                Mode::empty(),
            ),
        )
    }

    fn install(&self, stream: StdStream, null: BorrowedFd<'_>) -> Result<(), SysError> {
        lift("dup2", stream.install(null))
    }
}

/// Closes `spare` unless it is itself a standard stream, and says whether it
/// was kept.
///
/// `open` returns the lowest free descriptor, so when descriptor 0 is closed
/// the `/dev/null` just opened *is* descriptor 0. Dropping it would close the
/// stream it was opened to fill. `last_std` is a parameter so a test can
/// reach both answers without closing this process's own streams.
fn release_if_spare(spare: OwnedFd, last_std: i32) -> bool {
    if spare.as_raw_fd() > last_std {
        return false;
    }
    // Deliberately not closed: it is standard input, output or error now.
    let _kept = std::os::fd::IntoRawFd::into_raw_fd(spare);
    true
}

/// Fills every closed standard stream from `table`.
///
/// # Errors
///
/// [`SysError`] from the table. A stream left closed is never an `Ok`.
pub fn ensure_std_streams_in(table: &dyn StdTable) -> Result<(), SysError> {
    let mut null: Option<OwnedFd> = None;
    for stream in STREAMS {
        if table.is_open(stream) {
            continue;
        }
        let fd = match null.take() {
            Some(fd) => fd,
            None => table.open_null()?,
        };
        table.install(stream, std::os::fd::AsFd::as_fd(&fd))?;
        null = Some(fd);
    }
    if let Some(fd) = null {
        release_if_spare(fd, LAST_STD_FD);
    }
    Ok(())
}

/// The running process.
#[derive(Clone, Copy, Debug)]
pub struct HostHygiene;

impl Hygiene for HostHygiene {
    fn ensure_std_streams(&self) -> Result<(), SysError> {
        ensure_std_streams_in(&HostStd)
    }

    fn forbid_new_privileges(&self) -> Result<(), SysError> {
        forbid_new_privileges()
    }

    fn pid(&self) -> u32 {
        rustix::process::getpid()
            .as_raw_nonzero()
            .get()
            .unsigned_abs()
    }
}

/// Confirms a `PR_GET_NO_NEW_PRIVS` answer says the attribute is set.
#[cfg(target_os = "linux")]
fn require_set(on: bool) -> Result<(), SysError> {
    if on {
        Ok(())
    } else {
        Err(SysError::Os {
            operation: "prctl(PR_GET_NO_NEW_PRIVS)".to_owned(),
            code: None,
            reason: "PR_SET_NO_NEW_PRIVS reported success but the attribute is not set".to_owned(),
        })
    }
}

#[cfg(target_os = "linux")]
fn forbid_new_privileges() -> Result<(), SysError> {
    lift(
        "prctl(PR_SET_NO_NEW_PRIVS)",
        rustix::thread::set_no_new_privs(true),
    )
    .and_then(|()| lift("prctl(PR_GET_NO_NEW_PRIVS)", rustix::thread::no_new_privs()))
    .and_then(require_set)
}

#[cfg(not(target_os = "linux"))]
fn forbid_new_privileges() -> Result<(), SysError> {
    Err(SysError::unsupported(
        "PR_SET_NO_NEW_PRIVS on a non-Linux platform",
    ))
}

/// One call a [`FakeHygiene`] received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HygieneCall {
    /// [`Hygiene::ensure_std_streams`].
    EnsureStdStreams,
    /// [`Hygiene::forbid_new_privileges`].
    ForbidNewPrivileges,
}

/// A scripted process, for tests: records what it was asked, in order.
#[derive(Debug)]
pub struct FakeHygiene {
    calls: RefCell<Vec<HygieneCall>>,
    streams: Result<(), SysError>,
    privileges: Result<(), SysError>,
    pid: u32,
}

impl FakeHygiene {
    /// A process everything succeeds for, with this pid.
    pub fn new(pid: u32) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            streams: Ok(()),
            privileges: Ok(()),
            pid,
        }
    }

    /// Makes [`Hygiene::ensure_std_streams`] fail.
    #[must_use]
    pub fn with_streams_error(mut self, error: SysError) -> Self {
        self.streams = Err(error);
        self
    }

    /// Makes [`Hygiene::forbid_new_privileges`] fail.
    #[must_use]
    pub fn with_privileges_error(mut self, error: SysError) -> Self {
        self.privileges = Err(error);
        self
    }

    /// Every call received so far, in order.
    pub fn calls(&self) -> Vec<HygieneCall> {
        self.calls.borrow().clone()
    }
}

impl Hygiene for FakeHygiene {
    fn ensure_std_streams(&self) -> Result<(), SysError> {
        self.calls.borrow_mut().push(HygieneCall::EnsureStdStreams);
        self.streams.clone()
    }

    fn forbid_new_privileges(&self) -> Result<(), SysError> {
        self.calls
            .borrow_mut()
            .push(HygieneCall::ForbidNewPrivileges);
        self.privileges.clone()
    }

    fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use std::os::fd::AsFd;

    use super::*;

    /// A table whose open streams a test chooses. Records what was done to it.
    struct Table {
        open: Vec<StdStream>,
        null: Result<(), SysError>,
        install: Result<(), SysError>,
        events: RefCell<Vec<String>>,
    }

    impl Table {
        fn with_open(open: &[StdStream]) -> Self {
            Self {
                open: open.to_vec(),
                null: Ok(()),
                install: Ok(()),
                events: RefCell::new(Vec::new()),
            }
        }
    }

    impl StdTable for Table {
        fn is_open(&self, stream: StdStream) -> bool {
            self.open.contains(&stream)
        }

        fn open_null(&self) -> Result<OwnedFd, SysError> {
            self.events.borrow_mut().push("open".to_owned());
            self.null.clone().and_then(|()| HostStd.open_null())
        }

        fn install(&self, stream: StdStream, _null: BorrowedFd<'_>) -> Result<(), SysError> {
            self.events.borrow_mut().push(format!("install {stream:?}"));
            self.install.clone()
        }
    }

    #[test]
    fn streams_that_are_all_open_are_left_alone_and_nothing_is_opened() {
        let table = Table::with_open(&STREAMS);
        ensure_std_streams_in(&table).unwrap();
        assert!(table.events.borrow().is_empty());
    }

    #[test]
    fn every_closed_stream_is_filled_from_one_dev_null_before_anything_else_opens() {
        // Closed 0 and 2, open 1: one open of /dev/null, installed twice, in
        // descriptor order.
        let table = Table::with_open(&[StdStream::Out]);
        ensure_std_streams_in(&table).unwrap();
        assert_eq!(
            *table.events.borrow(),
            ["open", "install In", "install Err"]
        );
    }

    #[test]
    fn all_three_closed_is_filled_and_a_failed_open_refuses() {
        let table = Table::with_open(&[]);
        ensure_std_streams_in(&table).unwrap();
        assert_eq!(
            *table.events.borrow(),
            ["open", "install In", "install Out", "install Err"]
        );

        let mut broken = Table::with_open(&[]);
        broken.null = Err(SysError::unsupported("no /dev/null"));
        let err = ensure_std_streams_in(&broken).unwrap_err();
        assert!(err.to_string().contains("no /dev/null"), "{err}");
    }

    #[test]
    fn a_stream_that_cannot_be_installed_is_a_refusal_not_a_hole() {
        let mut table = Table::with_open(&[StdStream::In]);
        table.install = Err(SysError::unsupported("dup2 refused"));
        let err = ensure_std_streams_in(&table).unwrap_err();
        assert!(err.to_string().contains("dup2 refused"), "{err}");
    }

    #[test]
    fn a_dev_null_that_became_a_standard_stream_is_not_closed_with_its_handle() {
        // `open` returns the lowest free number, so with descriptor 0 closed
        // the /dev/null just opened IS descriptor 0, and dropping the handle
        // would close the stream it was opened to fill.
        let null = HostStd.open_null().unwrap();
        let number = null.as_raw_fd();
        let name = format!("/dev/fd/{number}");
        // Treat this descriptor's own number as the last standard one.
        assert!(release_if_spare(null, number));
        // Still open: it was not closed with its handle.
        assert!(std::fs::metadata(&name).is_ok());
        // A spare above the standard streams is closed with its handle.
        let spare = HostStd.open_null().unwrap();
        assert!(!release_if_spare(spare, LAST_STD_FD));
    }

    #[test]
    fn the_real_table_installs_a_stream_as_another_name_for_the_same_file() {
        // dup2 of a duplicate of standard error onto standard error: the same
        // open file under the same number, so nothing observable changes, and
        // every arm of the install is executed on the real descriptor table.
        for stream in STREAMS {
            assert!(HostStd.is_open(stream), "{stream:?} is open under a test");
            let same = rustix::io::fcntl_dupfd_cloexec(stream.borrowed(), 10).unwrap();
            HostStd.install(stream, same.as_fd()).unwrap();
            assert!(HostStd.is_open(stream));
        }
    }

    #[test]
    fn the_host_reports_its_own_pid_and_a_fake_reports_the_one_it_was_given() {
        assert_eq!(HostHygiene.pid(), std::process::id());
        assert_eq!(FakeHygiene::new(77).pid(), 77);
        assert!(format!("{HostHygiene:?}").contains("HostHygiene"));
        assert!(format!("{HostStd:?}").contains("HostStd"));
    }

    #[test]
    fn the_host_fills_nothing_when_a_test_harness_has_all_three_streams() {
        HostHygiene.ensure_std_streams().unwrap();
    }

    #[test]
    fn the_fake_records_the_order_and_fails_where_it_is_told_to() {
        let fake = FakeHygiene::new(1);
        fake.ensure_std_streams().unwrap();
        fake.forbid_new_privileges().unwrap();
        assert_eq!(
            fake.calls(),
            [
                HygieneCall::EnsureStdStreams,
                HygieneCall::ForbidNewPrivileges
            ]
        );
        let failing = FakeHygiene::new(1)
            .with_streams_error(SysError::unsupported("streams"))
            .with_privileges_error(SysError::unsupported("privileges"));
        assert!(failing.ensure_std_streams().is_err());
        assert!(failing.forbid_new_privileges().is_err());
        assert!(format!("{failing:?}").contains("FakeHygiene"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_new_privileges_cannot_be_forbidden_and_so_the_gate_refuses() {
        let err = HostHygiene.forbid_new_privileges().unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_new_privileges_are_forbidden_and_the_kernel_agrees() {
        HostHygiene.forbid_new_privileges().unwrap();
        assert!(rustix::thread::no_new_privs().unwrap());
        // A kernel that said it was set when it is not is refused.
        let err = require_set(false).unwrap_err();
        assert!(err.to_string().contains("not set"), "{err}");
        assert!(require_set(true).is_ok());
    }
}
