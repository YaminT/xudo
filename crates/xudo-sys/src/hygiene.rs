//! What a privileged process settles about itself before it believes anything.
//!
//! Four small facts, each of which the gate must establish and none of which
//! `xudo-sys-raw` is needed for:
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
//! * **The caller's resource limits are reset from PID 1.** `/proc/1/limits`
//!   is read through a pinned descriptor verified as procfs, and every Linux
//!   limit is applied before the gate opens policy, spool, program, or audit
//!   state. The soft open-file limit is capped at 1024 and core dumps are
//!   disabled. A missing or malformed limit refuses the gate.
//! * **The umask is `022` and the working directory is `/`.** A caller umask
//!   of `000` reaching an apt hook or a maintainer script would leave a file
//!   root creates world-writable. The working directory is entered through an
//!   `O_PATH` descriptor of `/`, so a caller-chosen directory is not where
//!   the root command starts. Either failure refuses.
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

    /// Resets every Linux resource limit from PID 1's values, with a soft
    /// open-file limit capped at 1024 and core dumps disabled.
    ///
    /// The PID 1 file is read through a pinned and validated procfs descriptor.
    /// Any missing, malformed, or un-settable limit refuses before the gate
    /// touches a request, policy, program, or audit record.
    ///
    /// # Errors
    ///
    /// [`SysError`] when procfs cannot be validated/read or a limit cannot be
    /// parsed or applied. Unsupported platforms refuse.
    fn reset_rlimits_from_pid1(&self) -> Result<(), SysError>;

    /// Sets the process umask to `022`.
    ///
    /// `umask` cannot fail. The [`Result`] exists so a fake can refuse and the
    /// gate can treat that the same way it treats every other step.
    ///
    /// # Errors
    ///
    /// [`SysError`] when the implementation refuses. The host does not.
    fn reset_umask(&self) -> Result<(), SysError>;

    /// Makes `/` the working directory, through an `O_PATH` directory
    /// descriptor. A failure refuses: the command must not start in a
    /// directory the caller chose.
    ///
    /// # Errors
    ///
    /// [`SysError`] when `/` cannot be opened or entered, or on a platform
    /// without `O_PATH`.
    fn reset_cwd(&self) -> Result<(), SysError>;

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

    #[cfg(target_os = "linux")]
    fn reset_rlimits_from_pid1(&self) -> Result<(), SysError> {
        reset_rlimits_from_pid1_with(&HostLimitOps)
    }

    #[cfg(not(target_os = "linux"))]
    fn reset_rlimits_from_pid1(&self) -> Result<(), SysError> {
        Err(SysError::unsupported(
            "resetting resource limits from PID 1",
        ))
    }

    fn reset_umask(&self) -> Result<(), SysError> {
        // Fixed `022`. `027` would make a file root writes under `/etc` or
        // `/usr` unreadable to a non-root daemon. sudo's own rule combines the
        // caller's umask with `022`, and a caller mask of `077` under sudo-rs
        // or doas would do the same to other users' services. A fixed `022`
        // is deterministic and matches what classic sudo applies.
        let _previous = rustix::process::umask(Mode::from_bits_truncate(0o022));
        Ok(())
    }

    fn reset_cwd(&self) -> Result<(), SysError> {
        reset_cwd()
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

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct LimitSpec {
    resource: rustix::process::Resource,
    label: &'static str,
}

#[cfg(target_os = "linux")]
const LINUX_LIMITS: &[LimitSpec] = &[
    LimitSpec {
        resource: rustix::process::Resource::Cpu,
        label: "Max cpu time",
    },
    LimitSpec {
        resource: rustix::process::Resource::Fsize,
        label: "Max file size",
    },
    LimitSpec {
        resource: rustix::process::Resource::Data,
        label: "Max data size",
    },
    LimitSpec {
        resource: rustix::process::Resource::Stack,
        label: "Max stack size",
    },
    LimitSpec {
        resource: rustix::process::Resource::Core,
        label: "Max core file size",
    },
    LimitSpec {
        resource: rustix::process::Resource::Rss,
        label: "Max resident set",
    },
    LimitSpec {
        resource: rustix::process::Resource::Nproc,
        label: "Max processes",
    },
    LimitSpec {
        resource: rustix::process::Resource::Nofile,
        label: "Max open files",
    },
    LimitSpec {
        resource: rustix::process::Resource::Memlock,
        label: "Max locked memory",
    },
    LimitSpec {
        resource: rustix::process::Resource::As,
        label: "Max address space",
    },
    LimitSpec {
        resource: rustix::process::Resource::Locks,
        label: "Max file locks",
    },
    LimitSpec {
        resource: rustix::process::Resource::Sigpending,
        label: "Max pending signals",
    },
    LimitSpec {
        resource: rustix::process::Resource::Msgqueue,
        label: "Max msgqueue size",
    },
    LimitSpec {
        resource: rustix::process::Resource::Nice,
        label: "Max nice priority",
    },
    LimitSpec {
        resource: rustix::process::Resource::Rtprio,
        label: "Max realtime priority",
    },
    LimitSpec {
        resource: rustix::process::Resource::Rttime,
        label: "Max realtime timeout",
    },
];

#[cfg(target_os = "linux")]
fn parse_limit_value(label: &str, value: Option<&str>) -> Result<Option<u64>, SysError> {
    match value {
        Some("unlimited") => Ok(None),
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|_| SysError::malformed("1/limits", format!("invalid value for {label}"))),
        None => Err(SysError::malformed(
            "1/limits",
            format!("missing value for {label}"),
        )),
    }
}

#[cfg(target_os = "linux")]
fn parse_pid1_limit(contents: &str, label: &str) -> Result<rustix::process::Rlimit, SysError> {
    let mut found = None;
    for line in contents.lines().skip(1) {
        let Some(values) = line.strip_prefix(label) else {
            continue;
        };
        if !values.chars().next().is_some_and(char::is_whitespace) {
            continue;
        }
        let mut fields = values.split_whitespace();
        let current = parse_limit_value(label, fields.next())?;
        let maximum = parse_limit_value(label, fields.next())?;
        if found
            .replace(rustix::process::Rlimit { current, maximum })
            .is_some()
        {
            return Err(SysError::malformed(
                "1/limits",
                format!("duplicate {label}"),
            ));
        }
    }
    found.ok_or_else(|| SysError::malformed("1/limits", format!("missing {label}")))
}

#[cfg(target_os = "linux")]
trait LimitOps {
    fn pid1_limits(&self) -> Result<String, SysError>;
    fn set(
        &self,
        resource: rustix::process::Resource,
        limit: rustix::process::Rlimit,
    ) -> Result<(), SysError>;
}

#[cfg(target_os = "linux")]
trait Pid1Proc {
    fn open(&self) -> Result<Box<dyn crate::ProcSource>, SysError>;
}

#[cfg(target_os = "linux")]
struct HostPid1Proc;

#[cfg(target_os = "linux")]
impl Pid1Proc for HostPid1Proc {
    fn open(&self) -> Result<Box<dyn crate::ProcSource>, SysError> {
        crate::VerifiedProc::open().map(|proc| Box::new(proc) as Box<dyn crate::ProcSource>)
    }
}

#[cfg(target_os = "linux")]
fn read_pid1_limits(proc: &dyn Pid1Proc) -> Result<String, SysError> {
    let source = proc.open()?;
    let contents = source.read("1/limits")?;
    std::str::from_utf8(&contents)
        .map(str::to_owned)
        .map_err(|_| SysError::malformed("1/limits", "not valid UTF-8"))
}

#[cfg(target_os = "linux")]
struct HostLimitOps;

#[cfg(target_os = "linux")]
impl LimitOps for HostLimitOps {
    fn pid1_limits(&self) -> Result<String, SysError> {
        // The open descriptor is verified as procfs and every child file is
        // opened relative to that descriptor, so an attacker cannot
        // substitute the values the gate will inherit.
        read_pid1_limits(&HostPid1Proc)
    }

    fn set(
        &self,
        resource: rustix::process::Resource,
        limit: rustix::process::Rlimit,
    ) -> Result<(), SysError> {
        crate::error::lift(
            "setrlimit(PID 1 values)",
            rustix::process::setrlimit(resource, limit),
        )
    }
}

#[cfg(target_os = "linux")]
fn reset_rlimits_from_pid1_with(ops: &dyn LimitOps) -> Result<(), SysError> {
    let contents = ops.pid1_limits()?;
    apply_pid1_limits(&contents, ops)
}

#[cfg(target_os = "linux")]
fn apply_pid1_limits(contents: &str, ops: &dyn LimitOps) -> Result<(), SysError> {
    let limits = LINUX_LIMITS
        .iter()
        .map(|spec| {
            let mut limit = parse_pid1_limit(contents, spec.label)?;
            match spec.resource {
                rustix::process::Resource::Nofile => {
                    let hard = limit.maximum.unwrap_or(u64::MAX);
                    limit.current = Some(limit.current.unwrap_or(u64::MAX).min(1024).min(hard));
                }
                rustix::process::Resource::Core => {
                    limit = rustix::process::Rlimit {
                        current: Some(0),
                        maximum: Some(0),
                    };
                }
                _ => {}
            }
            Ok((spec.resource, limit))
        })
        .collect::<Result<Vec<_>, SysError>>()?;
    for (resource, limit) in limits {
        ops.set(resource, limit)?;
    }
    Ok(())
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

/// Opens `/` and enters it.
///
/// Split out so a test can fail each half without a real `fchdir` of this
/// process. Linux calls it for the host. A test calls it with a scripted
/// root. A macOS build that is not a test has neither caller, so the trait,
/// `reset_cwd_in`, and the `AsFd` import they need stay in this module and
/// are not compiled there: a dead trait fails the lint.
#[cfg(any(target_os = "linux", test))]
mod root_dir {
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

    use super::SysError;
    // Only the real `/` opens anything. A macOS test builds the trait and
    // `reset_cwd_in` and never these.
    #[cfg(target_os = "linux")]
    use crate::error::lift;
    #[cfg(target_os = "linux")]
    use rustix::fs::{Mode, OFlags, open};

    /// Opens `/` and enters it. Split out so a test can fail each half without
    /// a real `fchdir` of this process.
    pub(super) trait RootDir {
        /// Opens `/` as a directory descriptor.
        ///
        /// # Errors
        ///
        /// [`SysError`] when the open fails.
        fn open_root(&self) -> Result<OwnedFd, SysError>;

        /// Makes `fd` the working directory.
        ///
        /// # Errors
        ///
        /// [`SysError`] when `fchdir` fails.
        fn enter(&self, fd: BorrowedFd<'_>) -> Result<(), SysError>;
    }

    /// The real `/`. Linux only: `O_PATH` is how the open asks nothing of a
    /// filesystem mounted on `/`.
    #[cfg(target_os = "linux")]
    pub(super) struct HostRoot;

    #[cfg(target_os = "linux")]
    impl RootDir for HostRoot {
        fn open_root(&self) -> Result<OwnedFd, SysError> {
            lift(
                "open(/)",
                open(
                    "/",
                    OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::PATH,
                    Mode::empty(),
                ),
            )
        }

        fn enter(&self, fd: BorrowedFd<'_>) -> Result<(), SysError> {
            lift("fchdir", rustix::process::fchdir(fd))
        }
    }

    /// Enters the directory `root` opened. A failure of either half is the
    /// caller's to refuse on.
    ///
    /// # Errors
    ///
    /// [`SysError`] from `root`.
    pub(super) fn reset_cwd_in(root: &dyn RootDir) -> Result<(), SysError> {
        let fd = root.open_root()?;
        root.enter(fd.as_fd())
    }
}

#[cfg(target_os = "linux")]
fn reset_cwd() -> Result<(), SysError> {
    root_dir::reset_cwd_in(&root_dir::HostRoot)
}

#[cfg(not(target_os = "linux"))]
fn reset_cwd() -> Result<(), SysError> {
    Err(SysError::unsupported("fchdir to / on a non-Linux platform"))
}

/// One call a [`FakeHygiene`] received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HygieneCall {
    /// [`Hygiene::ensure_std_streams`].
    EnsureStdStreams,
    /// [`Hygiene::reset_rlimits_from_pid1`].
    ResetRlimitsFromPid1,
    /// [`Hygiene::reset_umask`].
    ResetUmask,
    /// [`Hygiene::reset_cwd`].
    ResetCwd,
    /// [`Hygiene::forbid_new_privileges`].
    ForbidNewPrivileges,
}

/// A scripted process, for tests: records what it was asked, in order.
#[derive(Debug)]
pub struct FakeHygiene {
    calls: RefCell<Vec<HygieneCall>>,
    streams: Result<(), SysError>,
    rlimits: Result<(), SysError>,
    umask: Result<(), SysError>,
    cwd: Result<(), SysError>,
    privileges: Result<(), SysError>,
    pid: u32,
}

impl FakeHygiene {
    /// A process everything succeeds for, with this pid.
    pub fn new(pid: u32) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            streams: Ok(()),
            rlimits: Ok(()),
            umask: Ok(()),
            cwd: Ok(()),
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

    /// Makes [`Hygiene::reset_rlimits_from_pid1`] fail.
    #[must_use]
    pub fn with_rlimits_error(mut self, error: SysError) -> Self {
        self.rlimits = Err(error);
        self
    }

    /// Makes [`Hygiene::reset_umask`] fail.
    #[must_use]
    pub fn with_umask_error(mut self, error: SysError) -> Self {
        self.umask = Err(error);
        self
    }

    /// Makes [`Hygiene::reset_cwd`] fail.
    #[must_use]
    pub fn with_cwd_error(mut self, error: SysError) -> Self {
        self.cwd = Err(error);
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

    fn reset_rlimits_from_pid1(&self) -> Result<(), SysError> {
        self.calls
            .borrow_mut()
            .push(HygieneCall::ResetRlimitsFromPid1);
        self.rlimits.clone()
    }

    fn reset_umask(&self) -> Result<(), SysError> {
        self.calls.borrow_mut().push(HygieneCall::ResetUmask);
        self.umask.clone()
    }

    fn reset_cwd(&self) -> Result<(), SysError> {
        self.calls.borrow_mut().push(HygieneCall::ResetCwd);
        self.cwd.clone()
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

    #[cfg(target_os = "linux")]
    use std::fmt::Write as _;
    use std::os::fd::{AsFd, BorrowedFd};

    use rustix::fs::Mode;

    use super::root_dir::{RootDir, reset_cwd_in};
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
        fake.reset_rlimits_from_pid1().unwrap();
        fake.reset_umask().unwrap();
        fake.reset_cwd().unwrap();
        fake.forbid_new_privileges().unwrap();
        assert_eq!(
            fake.calls(),
            [
                HygieneCall::EnsureStdStreams,
                HygieneCall::ResetRlimitsFromPid1,
                HygieneCall::ResetUmask,
                HygieneCall::ResetCwd,
                HygieneCall::ForbidNewPrivileges
            ]
        );
        let failing = FakeHygiene::new(1)
            .with_streams_error(SysError::unsupported("streams"))
            .with_rlimits_error(SysError::unsupported("rlimits"))
            .with_umask_error(SysError::unsupported("umask"))
            .with_cwd_error(SysError::unsupported("cwd"))
            .with_privileges_error(SysError::unsupported("privileges"));
        assert!(failing.ensure_std_streams().is_err());
        assert!(failing.reset_rlimits_from_pid1().is_err());
        assert!(
            failing
                .reset_umask()
                .unwrap_err()
                .to_string()
                .contains("umask")
        );
        assert!(failing.reset_cwd().unwrap_err().to_string().contains("cwd"));
        assert!(failing.forbid_new_privileges().is_err());
        assert!(format!("{failing:?}").contains("FakeHygiene"));
        assert!(format!("{:?}", HygieneCall::ResetUmask).contains("ResetUmask"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_gate_caps_open_files_and_core_after_the_pid1_copy() {
        struct Limits {
            source: String,
            applied: RefCell<Vec<(rustix::process::Resource, rustix::process::Rlimit)>>,
        }
        impl LimitOps for Limits {
            fn pid1_limits(&self) -> Result<String, SysError> {
                Ok(self.source.clone())
            }

            fn set(
                &self,
                resource: rustix::process::Resource,
                limit: rustix::process::Rlimit,
            ) -> Result<(), SysError> {
                self.applied.borrow_mut().push((resource, limit));
                Ok(())
            }
        }

        let mut proc_limits = String::from(
            "Limit                     Soft Limit           Hard Limit           Units\n",
        );
        for spec in LINUX_LIMITS {
            let pair = match spec.resource {
                rustix::process::Resource::Fsize => ("1234", "5678"),
                rustix::process::Resource::Nofile => ("1000000000", "1000000000"),
                _ => ("unlimited", "unlimited"),
            };
            writeln!(proc_limits, "{}  {} {} units", spec.label, pair.0, pair.1).unwrap();
        }
        let limits = Limits {
            source: proc_limits,
            applied: RefCell::new(Vec::new()),
        };
        reset_rlimits_from_pid1_with(&limits).unwrap();
        let applied = limits.applied.borrow();
        assert_eq!(applied.len(), LINUX_LIMITS.len());
        assert!(applied.iter().any(|(resource, limit)| {
            *resource == rustix::process::Resource::Fsize
                && *limit
                    == rustix::process::Rlimit {
                        current: Some(1234),
                        maximum: Some(5678),
                    }
        }));
        assert!(applied.iter().any(|(resource, limit)| {
            *resource == rustix::process::Resource::Nofile
                && *limit
                    == rustix::process::Rlimit {
                        current: Some(1024),
                        maximum: Some(1_000_000_000),
                    }
        }));
        assert!(applied.iter().any(|(resource, limit)| {
            *resource == rustix::process::Resource::Core
                && *limit
                    == rustix::process::Rlimit {
                        current: Some(0),
                        maximum: Some(0),
                    }
        }));
        assert!(applied.iter().any(|(_, limit)| {
            *limit
                == rustix::process::Rlimit {
                    current: None,
                    maximum: None,
                }
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn incomplete_or_malformed_pid1_limits_refuse_before_any_set() {
        struct Limits {
            source: String,
            applied: RefCell<Vec<rustix::process::Resource>>,
        }
        impl LimitOps for Limits {
            fn pid1_limits(&self) -> Result<String, SysError> {
                Ok(self.source.clone())
            }

            fn set(
                &self,
                resource: rustix::process::Resource,
                _limit: rustix::process::Rlimit,
            ) -> Result<(), SysError> {
                self.applied.borrow_mut().push(resource);
                Ok(())
            }
        }

        let limits = Limits {
            source: "Limit Soft Hard Units\n".to_owned(),
            applied: RefCell::new(Vec::new()),
        };
        assert!(reset_rlimits_from_pid1_with(&limits).is_err());
        let malformed = "Limit Soft Hard Units\nMax cpu time nope 2 seconds\n";
        let limits = Limits {
            source: malformed.to_owned(),
            applied: RefCell::new(Vec::new()),
        };
        assert!(reset_rlimits_from_pid1_with(&limits).is_err());
        assert!(limits.applied.borrow().is_empty());
        limits
            .set(
                rustix::process::Resource::Cpu,
                rustix::process::Rlimit {
                    current: Some(1),
                    maximum: Some(2),
                },
            )
            .unwrap();
        assert_eq!(limits.applied.borrow().len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn duplicate_or_incomplete_pid1_limit_rows_are_refused() {
        let duplicate =
            "Limit Soft Hard Units\nMax cpu time 1 2 seconds\nMax cpu time 3 4 seconds\n";
        assert!(parse_pid1_limit(duplicate, "Max cpu time").is_err());
        let missing_value = "Limit Soft Hard Units\nMax cpu time   \n";
        assert!(parse_pid1_limit(missing_value, "Max cpu time").is_err());
        let missing_hard = "Limit Soft Hard Units\nMax cpu time 1 seconds\n";
        assert!(parse_pid1_limit(missing_hard, "Max cpu time").is_err());
        let prefix_not_a_row = "Limit Soft Hard Units\nMax cpu timeX 1 2 seconds\n";
        assert!(parse_pid1_limit(prefix_not_a_row, "Max cpu time").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pid1_limit_proc_open_read_and_utf8_failures_refuse() {
        struct Proc(Result<crate::MapSource, SysError>);
        impl Pid1Proc for Proc {
            fn open(&self) -> Result<Box<dyn crate::ProcSource>, SysError> {
                self.0
                    .clone()
                    .map(|source| Box::new(source) as Box<dyn crate::ProcSource>)
            }
        }

        assert!(read_pid1_limits(&Proc(Err(SysError::unsupported("procfs")))).is_err());
        assert!(read_pid1_limits(&Proc(Ok(crate::MapSource::new()))).is_err());
        let invalid = crate::MapSource::new().with("1/limits", vec![0xff]);
        assert!(read_pid1_limits(&Proc(Ok(invalid))).is_err());
        let valid = crate::MapSource::new().with("1/limits", b"Limit\n".to_vec());
        assert_eq!(read_pid1_limits(&Proc(Ok(valid))).unwrap(), "Limit\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_pid1_limit_read_failure_refuses_before_any_set() {
        struct RefusingLimits(RefCell<Vec<rustix::process::Resource>>);
        impl LimitOps for RefusingLimits {
            fn pid1_limits(&self) -> Result<String, SysError> {
                Err(SysError::unsupported("PID 1 limits"))
            }

            fn set(
                &self,
                resource: rustix::process::Resource,
                _limit: rustix::process::Rlimit,
            ) -> Result<(), SysError> {
                self.0.borrow_mut().push(resource);
                Ok(())
            }
        }

        let limits = RefusingLimits(RefCell::new(Vec::new()));
        assert!(reset_rlimits_from_pid1_with(&limits).is_err());
        assert!(limits.0.borrow().is_empty());
        limits
            .set(
                rustix::process::Resource::Cpu,
                rustix::process::Rlimit {
                    current: Some(1),
                    maximum: Some(2),
                },
            )
            .unwrap();
        assert_eq!(limits.0.borrow().len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_reads_pid1_limits_from_the_verified_procfs() {
        let contents = HostLimitOps.pid1_limits().unwrap();
        assert!(contents.contains("Max file size"));
        assert!(contents.contains("Max open files"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::disallowed_methods)]
    fn the_host_attempts_to_apply_pid1_limits() {
        // Applying PID 1's values may lower the process's hard limits. Run it
        // in a fresh test-binary child so the test runner keeps its limits.
        const CHILD_MARKER: &str = "XUDO_HOST_LIMIT_TEST_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let _result = HostHygiene.reset_rlimits_from_pid1();
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "hygiene::tests::the_host_attempts_to_apply_pid1_limits",
            ])
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success(), "host limit child failed: {status}");
    }

    #[test]
    fn a_root_that_cannot_be_opened_or_entered_refuses_before_the_command_starts() {
        struct ScriptedRoot {
            open: Result<(), SysError>,
            enter: Result<(), SysError>,
            entered: RefCell<bool>,
        }
        impl RootDir for ScriptedRoot {
            fn open_root(&self) -> Result<OwnedFd, SysError> {
                self.open.clone()?;
                // A real descriptor, so `enter` is reached. Not used as a
                // working directory: the scripted enter does not `fchdir`.
                HostStd.open_null()
            }

            fn enter(&self, _fd: BorrowedFd<'_>) -> Result<(), SysError> {
                *self.entered.borrow_mut() = true;
                self.enter.clone()
            }
        }

        let closed = ScriptedRoot {
            open: Err(SysError::unsupported("open(/)")),
            enter: Ok(()),
            entered: RefCell::new(false),
        };
        let err = reset_cwd_in(&closed).unwrap_err();
        assert!(err.to_string().contains("open(/)"), "{err}");
        assert!(!*closed.entered.borrow(), "fchdir ran after a failed open");

        let stuck = ScriptedRoot {
            open: Ok(()),
            enter: Err(SysError::unsupported("fchdir")),
            entered: RefCell::new(false),
        };
        let err = reset_cwd_in(&stuck).unwrap_err();
        assert!(err.to_string().contains("fchdir"), "{err}");
        assert!(*stuck.entered.borrow());

        let open = ScriptedRoot {
            open: Ok(()),
            enter: Ok(()),
            entered: RefCell::new(false),
        };
        reset_cwd_in(&open).unwrap();
        assert!(*open.entered.borrow());
    }

    #[test]
    fn the_host_sets_umask_022_from_a_tighter_caller_mask() {
        // The umask is process-global. The other unit tests of this process
        // run in parallel threads and create files. The seed is `077`: it
        // differs from `022`, so the reset is visible, and a file created
        // in the window is only tighter. `LOCK` serialises only this test
        // with itself. This test does not `chdir`. The `fchdir` to `/`
        // runs in `tests/reset_cwd.rs`, one process.
        struct Restore {
            umask: Mode,
        }
        impl Drop for Restore {
            fn drop(&mut self) {
                let _ = rustix::process::umask(self.umask);
            }
        }
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let caller = Mode::from_bits_truncate(0o077);
        let previous_umask = rustix::process::umask(caller);
        let restore = Restore {
            umask: previous_umask,
        };
        let seeded = rustix::process::umask(caller);
        assert_eq!(seeded.bits() & 0o777, 0o077);
        HostHygiene.reset_umask().unwrap();
        #[cfg(not(target_os = "linux"))]
        {
            let err = HostHygiene.reset_cwd().unwrap_err();
            assert!(err.to_string().contains("not supported"), "{err}");
        }
        let now = rustix::process::umask(Mode::from_bits_truncate(0o022));
        assert_eq!(now.bits() & 0o777, 0o022);
        drop(restore);
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
