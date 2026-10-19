//! The four system calls that need `unsafe`, behind a trait with a fake.
//!
//! rustix wraps almost every call the broker and the gate make, safely. Four it
//! does not: `close_range`, `getsockopt(SO_PEERPIDFD)`, `ioctl(PIDFD_GET_INFO)`,
//! and `execveat` (which rustix offers only as `unsafe`). Those live in the
//! `aido-sys-raw` crate, the one crate in the workspace allowed `unsafe`, and
//! reach the rest of the code only through [`Syscalls`].
//!
//! The trait is the seam. [`HostSyscalls`] is the real thing on Linux and
//! answers [`SysError::Unsupported`] everywhere else, so a macOS developer
//! cannot exercise a privileged path by accident. [`FakeSyscalls`] scripts the
//! answer to each of the four calls and records every call, so the broker and
//! the gate can be tested on any platform, including the answers a real kernel
//! will not produce on demand.
//!
//! It covers these four calls and nothing more. The lower rungs of the
//! attestation ladder also need `SO_PEERCRED`, `pidfd_open`, and a liveness
//! check on a pidfd, all of them safe in rustix; they get a seam of their own
//! with the broker that uses them (M2b step 2), and this trait stays the list
//! of calls that need `unsafe`.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::fd::{BorrowedFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

pub use aido_sys_raw::{
    Creds, PIDFD_INFO_CGROUPID, PIDFD_INFO_CREDS, PIDFD_INFO_PID, PidfdInfo, ProcessIds,
};

use crate::error::SysError;

/// The system calls that need `unsafe`, as a seam.
pub trait Syscalls {
    /// Marks every descriptor numbered `first` or above close-on-exec.
    ///
    /// `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)`. It does not close them:
    /// closing a descriptor some `OwnedFd` in this process still holds is a
    /// use-after-close, so a safe function cannot do it. Marking closes nothing
    /// now and every marked descriptor at this process's next exec. A process
    /// that forks and waits instead keeps them open in the waiting parent.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] with `EINVAL` before Linux 5.11 (no `CLOSE_RANGE_CLOEXEC`)
    /// or `ENOSYS` before 5.9 (no `close_range`).
    fn mark_cloexec_from(&self, first: u32) -> Result<(), SysError>;

    /// The pidfd of the process at the other end of a Unix socket.
    ///
    /// `getsockopt(SO_PEERPIDFD)`. It names the thread group that called
    /// `connect()`, as the kernel recorded it at that moment, and goes on
    /// naming that process: across an `execve`, and no matter who holds the
    /// socket later. It pins the process, not its pid number — once the
    /// process is reaped the number can be reissued, so anything read from
    /// `/proc/<pid>` must be confirmed through the pidfd afterwards (see
    /// [`crate::Attestation::needs_recheck_after_pinning`]). Credentials as
    /// they were at connect time come from `SO_PEERCRED`. The pidfd is always
    /// close-on-exec.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] with:
    ///
    /// * `ENOPROTOOPT` before Linux 6.5: the kernel lacks the option. Drop a
    ///   rung. This is the only error that does not mean deny.
    /// * `ENOTSOCK` if `socket` is not one, and `ENODATA` if it has no peer.
    ///   Deny.
    /// * `EINVAL` on 6.5 to 6.15 if the peer has already exited and been
    ///   reaped. Deny; never drop a rung on it, because the rung below would
    ///   look the peer up by a pid number that may now name someone else.
    /// * `EMFILE` or `ENFILE` if this process cannot be given another
    ///   descriptor. Deny.
    ///
    /// From 6.16 a reaped peer is not an error here: the kernel hands out a
    /// pidfd for a process that no longer exists, and [`Self::pidfd_info`] on
    /// it answers `ESRCH`. A pidfd from this call is therefore not proof that
    /// the peer is alive.
    fn peer_pidfd(&self, socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError>;

    /// Asks the kernel about the process a pidfd refers to.
    ///
    /// `ioctl(PIDFD_GET_INFO)`. Read the returned record through its
    /// accessors: the kernel may report less than was asked for. What it
    /// reports is the process's state at the moment of the call, not at
    /// connect time.
    ///
    /// A process that has exited but not been reaped still answers, with its
    /// last credentials and cgroup.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] with:
    ///
    /// * `ESRCH` if the process has been reaped, or cannot be seen from the
    ///   caller's pid namespace. Deny.
    /// * `ENOTTY` on a descriptor that is not a pidfd. [`HostSyscalls`] checks
    ///   this before the call, on the filesystem the descriptor is open on,
    ///   rather than trusting the ioctl to: from 6.12 a mount-namespace
    ///   descriptor answers this request number as `NS_MNT_GET_NEXT`, which
    ///   with `CAP_SYS_ADMIN` installs a new descriptor in the caller. Deny.
    /// * On a kernel without the call, one of two errnos: `ENOTTY` before Linux
    ///   6.11, and `EINVAL` on 6.11 and 6.12, whose pidfd ioctl handler refuses
    ///   any non-zero argument before it looks at the command. Both mean "drop
    ///   a rung", never "retry".
    /// * No errno at all if the call reported success but returned no process
    ///   (see [`PidfdInfo::is_answer`]). Deny.
    ///
    /// Those are the answers of upstream and stable kernels, by version. A
    /// distribution kernel can carry the call earlier — RHEL 9 and 10 do — so
    /// a broker decides the rung by asking the kernel once, not by reading the
    /// version.
    fn pidfd_info(&self, pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, SysError>;

    /// Replaces this process with the program open on `program`.
    ///
    /// `execveat(program, "", argv, envp, AT_EMPTY_PATH)`: the descriptor that
    /// was validated is the thing executed, so there is no window in which the
    /// path can be swapped. A `#!` script cannot be run this way through a
    /// close-on-exec descriptor — the kernel refuses with `ENOENT` rather than
    /// let the interpreter reopen the script by path — so only a binary format
    /// the kernel itself loads ever runs. Returns only on failure, which is why
    /// the return type is the error itself — and only on a failure before the
    /// kernel commits to the new image. A failure after that point kills the
    /// process instead, so not every failed exec is ever seen as an error.
    fn exec_fd(&self, program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError;
}

/// Refuses a record no kernel answered.
///
/// Applied by every implementation, real and fake alike, so no caller of
/// [`Syscalls::pidfd_info`] is ever handed a record that would read as root.
fn answered(info: PidfdInfo) -> Result<PidfdInfo, SysError> {
    if info.is_answer() {
        Ok(info)
    } else {
        Err(SysError::Os {
            operation: "ioctl(PIDFD_GET_INFO)".to_owned(),
            code: None,
            reason: "the call reported success but returned no process, so nothing it says \
                     about one can be read"
                .to_owned(),
        })
    }
}

/// `PID_FS_MAGIC`: the filesystem every pidfd lives on, since Linux 6.9.
#[cfg(target_os = "linux")]
const PID_FS_MAGIC: u32 = 0x5049_4446;

/// Refuses, before the ioctl, a descriptor that is not a pidfd.
///
/// The request number `PIDFD_GET_INFO` uses is also `NS_MNT_GET_NEXT` to a
/// mount-namespace descriptor, so the kernel's own refusal cannot be relied on.
/// The call only exists on kernels where every pidfd is on pidfs, so asking the
/// filesystem loses nothing.
#[cfg(target_os = "linux")]
fn on_pidfs(fd: BorrowedFd<'_>) -> Result<(), SysError> {
    let pidfs = rustix::fs::fstatfs(fd)
        .is_ok_and(|stat| i128::from(stat.f_type) == i128::from(PID_FS_MAGIC));
    if pidfs {
        Ok(())
    } else {
        Err(SysError::Os {
            operation: "ioctl(PIDFD_GET_INFO)".to_owned(),
            code: Some(rustix::io::Errno::NOTTY.raw_os_error()),
            reason: "not a pidfd: the descriptor is not on pidfs, so the request was not sent"
                .to_owned(),
        })
    }
}

/// The running kernel.
///
/// On Linux every call goes to the kernel. On any other platform every call
/// answers [`SysError::Unsupported`], so nothing privileged can happen there.
#[derive(Clone, Copy, Debug)]
pub struct HostSyscalls;

#[cfg(target_os = "linux")]
impl Syscalls for HostSyscalls {
    fn mark_cloexec_from(&self, first: u32) -> Result<(), SysError> {
        aido_sys_raw::sys::mark_cloexec_from(first).map_err(SysError::from)
    }

    fn peer_pidfd(&self, socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
        aido_sys_raw::sys::peer_pidfd(socket).map_err(SysError::from)
    }

    fn pidfd_info(&self, pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, SysError> {
        on_pidfs(pidfd)?;
        aido_sys_raw::sys::pidfd_info(pidfd, mask)
            .map_err(SysError::from)
            .and_then(answered)
    }

    fn exec_fd(&self, program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError {
        SysError::from(aido_sys_raw::sys::exec_fd(program, argv, envp))
    }
}

#[cfg(not(target_os = "linux"))]
impl Syscalls for HostSyscalls {
    fn mark_cloexec_from(&self, _first: u32) -> Result<(), SysError> {
        Err(SysError::unsupported("close_range on a non-Linux platform"))
    }

    fn peer_pidfd(&self, _socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
        Err(SysError::unsupported(
            "SO_PEERPIDFD on a non-Linux platform",
        ))
    }

    fn pidfd_info(&self, _pidfd: BorrowedFd<'_>, _mask: u64) -> Result<PidfdInfo, SysError> {
        Err(SysError::unsupported(
            "PIDFD_GET_INFO on a non-Linux platform",
        ))
    }

    fn exec_fd(&self, _program: BorrowedFd<'_>, _argv: &[&CStr], _envp: &[&CStr]) -> SysError {
        SysError::unsupported("execveat on a non-Linux platform")
    }
}

/// One call a [`FakeSyscalls`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeCall {
    /// [`Syscalls::mark_cloexec_from`] with this lower bound.
    MarkCloexecFrom(u32),
    /// [`Syscalls::peer_pidfd`].
    PeerPidfd,
    /// [`Syscalls::pidfd_info`] with this mask.
    PidfdInfo(u64),
    /// [`Syscalls::exec_fd`].
    Exec {
        /// The `(st_dev, st_ino)` of the file the descriptor was open on, so a
        /// test can assert that the file executed is the file validated.
        program: Option<(u64, u64)>,
        /// The argument vector, `argv[0]` included.
        argv: Vec<CString>,
        /// The environment, as `KEY=value` strings.
        envp: Vec<CString>,
    },
}

/// A scripted kernel, for tests.
///
/// Unscripted, it answers like the oldest kernel the ladder knows: no
/// `close_range` (`ENOSYS`), no `SO_PEERPIDFD` (`ENOPROTOOPT`), no
/// `PIDFD_GET_INFO` (`ENOTTY`), each with the errno a real one would give, so a
/// test that forgets to script an answer takes the branch a real old kernel
/// would send it down. `exec_fd` never replaces anything; it records the call
/// and returns the scripted error.
#[derive(Debug)]
pub struct FakeSyscalls {
    calls: RefCell<Vec<FakeCall>>,
    cloexec: Result<(), SysError>,
    peer: RefCell<Option<Result<OwnedFd, SysError>>>,
    info: Result<PidfdInfo, SysError>,
    exec: SysError,
}

/// A fake's answer for a call the oldest kernel does not have.
fn missing(operation: &str, errno: rustix::io::Errno, reason: &str) -> SysError {
    SysError::Os {
        operation: operation.to_owned(),
        code: Some(errno.raw_os_error()),
        reason: format!("fake: {reason}"),
    }
}

impl FakeSyscalls {
    /// A fake with nothing scripted.
    pub fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            cloexec: Err(missing(
                "close_range",
                rustix::io::Errno::NOSYS,
                "no close_range scripted",
            )),
            peer: RefCell::new(None),
            info: Err(missing(
                "ioctl(PIDFD_GET_INFO)",
                rustix::io::Errno::NOTTY,
                "no pidfd info scripted",
            )),
            exec: SysError::unsupported("fake: exec recorded, nothing replaced"),
        }
    }

    /// Scripts every [`Syscalls::mark_cloexec_from`] answer.
    #[must_use]
    pub fn with_cloexec(mut self, answer: Result<(), SysError>) -> Self {
        self.cloexec = answer;
        self
    }

    /// Scripts the next [`Syscalls::peer_pidfd`] answer. It is handed out
    /// once, because a descriptor can only be owned once.
    #[must_use]
    pub fn with_peer(self, peer: Result<OwnedFd, SysError>) -> Self {
        self.peer.replace(Some(peer));
        self
    }

    /// Scripts every [`Syscalls::pidfd_info`] answer. A record that is not an
    /// answer is refused exactly as [`HostSyscalls`] refuses one.
    #[must_use]
    pub fn with_info(mut self, info: Result<PidfdInfo, SysError>) -> Self {
        self.info = info;
        self
    }

    /// Scripts the error [`Syscalls::exec_fd`] returns.
    #[must_use]
    pub fn with_exec_error(mut self, error: SysError) -> Self {
        self.exec = error;
        self
    }

    /// Every call received so far, in order.
    pub fn calls(&self) -> Vec<FakeCall> {
        self.calls.borrow().clone()
    }

    fn record(&self, call: FakeCall) {
        self.calls.borrow_mut().push(call);
    }
}

impl Default for FakeSyscalls {
    fn default() -> Self {
        Self::new()
    }
}

/// The `(st_dev, st_ino)` of the file a descriptor is open on.
fn identity(fd: BorrowedFd<'_>) -> Option<(u64, u64)> {
    fd.try_clone_to_owned()
        .ok()
        .map(std::fs::File::from)
        .and_then(|file| file.metadata().ok())
        .map(|meta| (meta.dev(), meta.ino()))
}

impl Syscalls for FakeSyscalls {
    fn mark_cloexec_from(&self, first: u32) -> Result<(), SysError> {
        self.record(FakeCall::MarkCloexecFrom(first));
        self.cloexec.clone()
    }

    fn peer_pidfd(&self, _socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
        self.record(FakeCall::PeerPidfd);
        self.peer.take().unwrap_or_else(|| {
            Err(missing(
                "getsockopt(SO_PEERPIDFD)",
                rustix::io::Errno::NOPROTOOPT,
                "no peer pidfd scripted, or it was already taken",
            ))
        })
    }

    fn pidfd_info(&self, _pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, SysError> {
        self.record(FakeCall::PidfdInfo(mask));
        self.info.clone().and_then(answered)
    }

    fn exec_fd(&self, program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError {
        self.record(FakeCall::Exec {
            program: identity(program),
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            envp: envp.iter().map(|s| (*s).to_owned()).collect(),
        });
        self.exec.clone()
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

    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use rustix::io::Errno;

    use super::*;

    const ROOT: Creds = Creds {
        ruid: 0,
        rgid: 0,
        euid: 0,
        egid: 0,
        suid: 0,
        sgid: 0,
        fsuid: 0,
        fsgid: 0,
    };

    const SOME_PROCESS: ProcessIds = ProcessIds {
        pid: 412,
        tgid: 412,
        ppid: 1,
    };

    #[test]
    fn an_unscripted_fake_answers_like_the_oldest_kernel_with_its_errnos() {
        // Forgetting to script an answer must land a test on the branch a real
        // old kernel takes — and that is decided by the errno, so the fake
        // carries the real one.
        let fake = FakeSyscalls::default();
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(
            fake.mark_cloexec_from(3).unwrap_err().os_code(),
            Some(Errno::NOSYS.raw_os_error())
        );
        assert_eq!(
            fake.peer_pidfd(a.as_fd()).unwrap_err().os_code(),
            Some(Errno::NOPROTOOPT.raw_os_error())
        );
        assert_eq!(
            fake.pidfd_info(a.as_fd(), PidfdInfo::ATTESTATION_MASK)
                .unwrap_err()
                .os_code(),
            Some(Errno::NOTTY.raw_os_error())
        );
        let err = fake.exec_fd(a.as_fd(), &[c"/usr/bin/true"], &[c"PATH=/usr/bin"]);
        assert!(err.to_string().contains("nothing replaced"), "{err}");
        assert_eq!(
            fake.calls(),
            vec![
                FakeCall::MarkCloexecFrom(3),
                FakeCall::PeerPidfd,
                FakeCall::PidfdInfo(PidfdInfo::ATTESTATION_MASK),
                FakeCall::Exec {
                    program: identity(a.as_fd()),
                    argv: vec![c"/usr/bin/true".to_owned()],
                    envp: vec![c"PATH=/usr/bin".to_owned()],
                },
            ]
        );
        assert!(format!("{fake:?}").contains("FakeSyscalls"));
    }

    #[test]
    fn a_fake_exec_records_which_file_was_executed() {
        // The gate's promise is that the file it validated is the file it
        // runs. A fake that dropped the descriptor could not hold a gate test
        // to that.
        let fake = FakeSyscalls::new();
        let validated = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
        let other = std::fs::File::open("/").unwrap();
        let _ = fake.exec_fd(validated.as_fd(), &[c"x"], &[]);
        let meta = validated.metadata().unwrap();
        let validated_identity = Some((meta.dev(), meta.ino()));
        assert_eq!(
            fake.calls(),
            vec![FakeCall::Exec {
                program: validated_identity,
                argv: vec![c"x".to_owned()],
                envp: Vec::new(),
            }]
        );
        assert_ne!(identity(other.as_fd()), validated_identity);
    }

    #[test]
    fn a_scripted_fake_hands_a_peer_out_once() {
        // A descriptor can be owned once. A second ask must fail rather than
        // quietly hand out something the test did not script.
        let (a, b) = UnixStream::pair().unwrap();
        let fake = FakeSyscalls::new().with_peer(Ok(OwnedFd::from(b)));
        assert!(fake.peer_pidfd(a.as_fd()).is_ok());
        let again = fake.peer_pidfd(a.as_fd()).unwrap_err();
        assert!(again.to_string().contains("already taken"), "{again}");
    }

    #[test]
    fn a_scripted_fake_returns_what_it_was_given() {
        let (a, _b) = UnixStream::pair().unwrap();
        let info = PidfdInfo::empty().with_ids(SOME_PROCESS).with_creds(ROOT);
        let eacces = SysError::os("execveat", &std::io::Error::from_raw_os_error(13));
        let fake = FakeSyscalls::new()
            .with_cloexec(Ok(()))
            .with_info(Ok(info))
            .with_exec_error(eacces.clone());
        assert_eq!(fake.mark_cloexec_from(3), Ok(()));
        assert_eq!(fake.pidfd_info(a.as_fd(), 0), Ok(info));
        assert_eq!(fake.exec_fd(a.as_fd(), &[], &[]), eacces);
    }

    #[test]
    fn a_record_no_kernel_answered_is_refused_by_the_fake_and_the_host_alike() {
        // Scripted or real, a record without the process ids is a call that
        // did not happen. Read as an answer, its zeroed credentials are root.
        let (a, _b) = UnixStream::pair().unwrap();
        for unanswered in [PidfdInfo::empty(), PidfdInfo::empty().with_creds(ROOT)] {
            let fake = FakeSyscalls::new().with_info(Ok(unanswered));
            let err = fake
                .pidfd_info(a.as_fd(), PidfdInfo::ATTESTATION_MASK)
                .unwrap_err();
            assert_eq!(err.os_code(), None);
            assert!(err.to_string().contains("returned no process"), "{err}");
        }
        assert_eq!(
            answered(PidfdInfo::empty().with_ids(SOME_PROCESS))
                .unwrap()
                .pid(),
            Some(412)
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_host_refuses_every_call_off_linux() {
        // Nothing privileged may happen on a development host, so every call
        // is the fail-closed answer, whatever descriptor it is handed.
        let (a, _b) = UnixStream::pair().unwrap();
        let host = HostSyscalls;
        let refusals = [
            host.mark_cloexec_from(3).unwrap_err(),
            host.peer_pidfd(a.as_fd()).unwrap_err(),
            host.pidfd_info(a.as_fd(), PidfdInfo::ATTESTATION_MASK)
                .unwrap_err(),
            host.exec_fd(a.as_fd(), &[c"/bin/true"], &[]),
        ];
        for err in &refusals {
            assert!(err.to_string().contains("not supported"), "{err}");
        }
        assert!(format!("{host:?}").contains("HostSyscalls"));
    }

    /// The real kernel. Written without a branch on what the kernel supports:
    /// what each kernel should do is computed from the attestation ladder and
    /// compared, so the same test passes on 6.12 and on 6.17 and a ladder that
    /// disagrees with the kernel fails it.
    #[cfg(target_os = "linux")]
    mod linux {
        #![allow(clippy::disallowed_methods)]

        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};
        use std::time::Duration;

        use rustix::fs::{CWD, Mode, OFlags, open, openat};
        use rustix::io::{Errno, FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd};
        use rustix::net::sockopt::{Timeout, set_socket_timeout};

        use super::super::*;
        use crate::kernel::{Attestation, KernelSupport};

        fn running_kernel() -> KernelSupport {
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
            KernelSupport::parse(release.trim())
        }

        #[test]
        fn these_tests_run_on_a_kernel_with_so_peerpidfd() {
            // Every test here that needs a peer pidfd unwraps one, so on a
            // kernel older than 6.5 they would fail with ENOPROTOOPT rather
            // than say why. This says why. What such a kernel answers is
            // pinned by the ladder's own tests, in kernel.rs.
            assert!(
                running_kernel().attestation >= Attestation::PeerPidfd,
                "the Linux tests need SO_PEERPIDFD, Linux 6.5 or later"
            );
        }

        fn cloexec(fd: impl AsFd) -> bool {
            fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC)
        }

        /// A fresh directory under the workspace `target/`, never `/tmp`.
        fn scratch(name: &str) -> PathBuf {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/test-tmp")
                .join(format!("sc-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        /// A listener, and a separate process connected to it that holds the
        /// connection open until its stdin closes.
        ///
        /// A real second process, because a socketpair records its creator as
        /// the peer of both ends: every socketpair test can only ever expect
        /// the test process itself, and so cannot tell a pidfd for the peer
        /// from a pidfd for anything else.
        fn connected_peer(name: &str) -> (Child, UnixStream) {
            let path = scratch(name).join("peer.sock");
            let listener = UnixListener::bind(&path).unwrap();
            // A connector that fails must fail the test, not hang it.
            set_socket_timeout(&listener, Timeout::Recv, Some(Duration::from_secs(20))).unwrap();
            let child = Command::new("/usr/bin/perl")
                .args([
                    "-MSocket",
                    "-e",
                    "socket(my $s, AF_UNIX, SOCK_STREAM, 0) or die \"socket: $!\"; \
                     connect($s, pack_sockaddr_un($ARGV[0])) or die \"connect: $!\"; \
                     sysread(STDIN, my $b, 1); exit 0;",
                ])
                .arg(&path)
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            let (stream, _) = listener.accept().unwrap();
            (child, stream)
        }

        #[test]
        fn marking_from_a_floor_reaches_every_descriptor_above_it_and_none_below() {
            // Opened without O_CLOEXEC on purpose: std sets it on everything,
            // which would make this test pass with the call deleted.
            let plain = || open("/proc/self/status", OFlags::RDONLY, Mode::empty()).unwrap();
            let mut fds = [plain(), plain(), plain()];
            fds.sort_by_key(AsRawFd::as_raw_fd);
            let [below, floor, above] = fds;
            // Far above the rest, so a bound that stops short of ~0 is caught.
            let high = fcntl_dupfd_cloexec(&below, 1000).unwrap();
            fcntl_setfd(&high, FdFlags::empty()).unwrap();
            assert!(![&below, &floor, &above, &high].into_iter().any(cloexec));

            let first = u32::try_from(floor.as_raw_fd()).unwrap();
            HostSyscalls.mark_cloexec_from(first).unwrap();

            assert!(
                !cloexec(&below),
                "a descriptor below the floor must be left alone"
            );
            assert!([&floor, &above, &high].into_iter().all(cloexec));
        }

        #[test]
        fn the_peer_pidfd_of_a_socketpair_names_this_process() {
            let (a, _b) = UnixStream::pair().unwrap();
            let pidfd = HostSyscalls.peer_pidfd(a.as_fd()).unwrap();
            let fdinfo =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
                    .unwrap();
            let expected = format!("Pid:\t{}\n", std::process::id());
            assert!(fdinfo.contains(&expected), "{fdinfo}");
            assert!(cloexec(&pidfd), "a pidfd must never leak into a command");
        }

        #[test]
        fn the_pidfd_names_the_connecting_process_not_this_one() {
            let (mut child, stream) = connected_peer("peer-alive");
            let pidfd = HostSyscalls.peer_pidfd(stream.as_fd()).unwrap();
            let fdinfo =
                std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
                    .unwrap();
            assert!(
                fdinfo.contains(&format!("Pid:\t{}\n", child.id())),
                "{fdinfo}"
            );
            assert!(!fdinfo.contains(&format!("Pid:\t{}\n", std::process::id())));
            assert!(cloexec(&pidfd), "a pidfd must never leak into a command");

            // Where the kernel answers PIDFD_GET_INFO, it names the same
            // process, and this one as its parent.
            let expect_answer = running_kernel().attestation == Attestation::PeerPidfdInfo;
            let answer = HostSyscalls.pidfd_info(pidfd.as_fd(), PidfdInfo::ATTESTATION_MASK);
            assert_eq!(
                answer.as_ref().ok().and_then(PidfdInfo::ids),
                expect_answer.then_some(ProcessIds {
                    pid: child.id(),
                    tgid: child.id(),
                    ppid: std::process::id(),
                }),
                "{answer:?}"
            );

            drop(child.stdin.take());
            assert!(child.wait().unwrap().success());
        }

        #[test]
        fn a_peer_that_exited_is_refused_or_reported_stale_by_kernel_version() {
            // Until 6.16 the kernel refuses a pidfd for a reaped peer with
            // EINVAL; from 6.16 it hands one out for a process that no longer
            // exists, and PIDFD_GET_INFO on it answers ESRCH. The broker must
            // deny on both, so both are pinned here.
            let (mut child, stream) = connected_peer("peer-exited");
            drop(child.stdin.take());
            assert!(child.wait().unwrap().success());

            let stale = running_kernel().version.at_least(6, 16);
            let pidfd = HostSyscalls.peer_pidfd(stream.as_fd());
            assert_eq!(pidfd.is_ok(), stale, "{pidfd:?}");
            assert_eq!(
                pidfd.as_ref().err().and_then(SysError::os_code),
                (!stale).then_some(Errno::INVAL.raw_os_error())
            );
            let info = pidfd
                .as_ref()
                .ok()
                .map(|fd| HostSyscalls.pidfd_info(fd.as_fd(), PidfdInfo::ATTESTATION_MASK));
            assert_eq!(
                info.and_then(Result::err)
                    .as_ref()
                    .and_then(SysError::os_code),
                stale.then_some(Errno::SRCH.raw_os_error())
            );
        }

        #[test]
        fn a_peer_pidfd_is_refused_on_something_that_is_not_a_socket() {
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let err = HostSyscalls.peer_pidfd(file.as_fd()).unwrap_err();
            assert_eq!(err.os_code(), Some(Errno::NOTSOCK.raw_os_error()));
        }

        /// The ids `/proc/self/status` lists after `key`: real, effective,
        /// saved, filesystem.
        fn status_ids(key: &str) -> Vec<u32> {
            let status = std::fs::read_to_string("/proc/self/status").unwrap();
            status
                .lines()
                .find(|line| line.starts_with(key))
                .unwrap()
                .split_whitespace()
                .skip(1)
                .map(|id| id.parse().unwrap())
                .collect()
        }

        /// The inode of this process's cgroup directory, which is the id the
        /// kernel reports for it.
        fn own_cgroup_inode() -> Option<u64> {
            let cgroups = std::fs::read_to_string("/proc/self/cgroup").unwrap();
            cgroups
                .lines()
                .find_map(|line| line.strip_prefix("0::"))
                .map(|path| PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/')))
                .and_then(|dir| std::fs::metadata(dir).ok())
                .as_ref()
                .map(MetadataExt::ino)
        }

        #[test]
        fn pidfd_info_answers_exactly_when_the_ladder_says_it_should() {
            let kernel = running_kernel();
            let expect_answer = kernel.attestation == Attestation::PeerPidfdInfo;
            // Which errno a kernel without the call gives depends on whether
            // it has the 6.11 pidfd ioctl handler. Indexed, not branched, so
            // every kernel covers the same lines.
            let missing = [Errno::NOTTY, Errno::INVAL][usize::from(kernel.version.at_least(6, 11))]
                .raw_os_error();
            let (a, _b) = UnixStream::pair().unwrap();
            let pidfd = HostSyscalls.peer_pidfd(a.as_fd()).unwrap();
            let answer = HostSyscalls.pidfd_info(pidfd.as_fd(), PidfdInfo::ATTESTATION_MASK);

            assert_eq!(answer.is_ok(), expect_answer, "{answer:?}");
            assert_eq!(
                answer.as_ref().err().map(SysError::os_code),
                (!expect_answer).then_some(Some(missing)),
            );

            // Every field the record reports, checked against what this
            // process can see of itself, so a field declared out of order is
            // caught on the first kernel that answers.
            let me = std::process::id();
            assert_eq!(
                answer.as_ref().ok().and_then(PidfdInfo::ids),
                expect_answer.then_some(ProcessIds {
                    pid: me,
                    tgid: me,
                    ppid: std::os::unix::process::parent_id(),
                }),
            );
            let (uid, gid) = (status_ids("Uid:"), status_ids("Gid:"));
            assert_eq!(
                answer.as_ref().ok().and_then(PidfdInfo::creds),
                expect_answer.then_some(Creds {
                    ruid: uid[0],
                    euid: uid[1],
                    suid: uid[2],
                    fsuid: uid[3],
                    rgid: gid[0],
                    egid: gid[1],
                    sgid: gid[2],
                    fsgid: gid[3],
                }),
            );
            assert_eq!(
                answer.as_ref().ok().and_then(PidfdInfo::cgroup_id),
                expect_answer.then_some(own_cgroup_inode()).flatten(),
            );
        }

        #[test]
        fn pidfd_info_is_refused_on_something_that_is_not_a_pidfd() {
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let err = HostSyscalls
                .pidfd_info(file.as_fd(), PidfdInfo::ATTESTATION_MASK)
                .unwrap_err();
            assert_eq!(err.os_code(), Some(Errno::NOTTY.raw_os_error()));
        }

        #[test]
        fn a_namespace_descriptor_never_reaches_the_ioctl_it_shares_a_number_with() {
            // From 6.12 this request number is also NS_MNT_GET_NEXT to a mount
            // namespace descriptor, which answers success with a mask that is
            // not pidfd_info's, and with CAP_SYS_ADMIN hands back a new
            // descriptor. Refused before the call, the same way on every
            // kernel and for every caller.
            let ns = std::fs::File::open("/proc/self/ns/mnt").unwrap();
            let err = HostSyscalls
                .pidfd_info(ns.as_fd(), PidfdInfo::ATTESTATION_MASK)
                .unwrap_err();
            assert_eq!(err.os_code(), Some(Errno::NOTTY.raw_os_error()));
            assert!(err.to_string().contains("not on pidfs"), "{err}");
        }

        #[test]
        fn exec_runs_the_descriptor_it_is_handed_not_the_working_directory() {
            // ENOEXEC can only come from the file behind this descriptor: a
            // regular file, executable by mode, on a filesystem that permits
            // exec, whose bytes are no format the kernel loads. Executing the
            // working directory instead would fail with EACCES.
            let path = scratch("exec-not-a-program").join("not-a-program");
            std::fs::write(&path, b"plain text, no interpreter line\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = std::fs::File::open(&path).unwrap();
            let err = HostSyscalls.exec_fd(file.as_fd(), &[c"not-a-program"], &[]);
            assert_eq!(err.os_code(), Some(Errno::NOEXEC.raw_os_error()));
        }

        #[test]
        fn a_script_cannot_be_exec_d_through_a_close_on_exec_descriptor() {
            // The interpreter would be handed the script as /dev/fd/N, a path
            // that is gone once the close-on-exec descriptor closes, so the
            // kernel refuses with ENOENT rather than let anything reopen the
            // script by name. If it ever ran, the exit status would fail the
            // suite instead of passing it silently.
            let path = scratch("exec-script").join("script");
            std::fs::write(&path, b"#!/bin/sh\nexit 97\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = std::fs::File::open(&path).unwrap();
            assert!(cloexec(&file));
            let err = HostSyscalls.exec_fd(file.as_fd(), &[c"script"], &[]);
            assert_eq!(err.os_code(), Some(Errno::NOENT.raw_os_error()));
        }

        #[test]
        fn exec_of_a_directory_descriptor_fails_and_returns() {
            // EACCES for root too: no execute bit is ever honoured on a
            // directory.
            let dir = openat(
                CWD,
                "/",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let err = HostSyscalls.exec_fd(dir.as_fd(), &[c"/"], &[]);
            assert_eq!(err.os_code(), Some(Errno::ACCESS.raw_os_error()));
        }

        #[test]
        fn exec_refuses_a_file_on_a_noexec_mount() {
            // /proc is mounted noexec, which the kernel checks before it looks
            // at the file's mode, so this holds for root as well.
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let err = HostSyscalls.exec_fd(file.as_fd(), &[c"status"], &[c"A=b"]);
            assert_eq!(err.os_code(), Some(Errno::ACCESS.raw_os_error()));
            assert!(format!("{HostSyscalls:?}").contains("HostSyscalls"));
        }
    }
}
