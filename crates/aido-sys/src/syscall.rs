//! The four system calls that need `unsafe`, behind a trait with a fake.
//!
//! rustix wraps almost every call the broker and the gate make, safely. Four it
//! does not: `close_range`, `getsockopt(SO_PEERPIDFD)`, `ioctl(PIDFD_GET_INFO)`,
//! and `execveat` (which rustix offers only as `unsafe`). Those live in the
//! private `raw` module, the one place in the workspace allowed `unsafe`, and
//! reach the rest of the code only through [`Syscalls`].
//!
//! The trait is the seam. [`HostSyscalls`] is the real thing on Linux and
//! answers [`SysError::Unsupported`] everywhere else, so a macOS developer
//! cannot exercise a privileged path by accident. [`FakeSyscalls`] scripts
//! every answer and records every call, so the broker and the gate can be
//! tested on any platform, including the paths a real kernel will not produce
//! on demand.

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::fd::{BorrowedFd, OwnedFd};

use crate::error::SysError;

/// `PIDFD_INFO_PID`: the pid, thread-group id, and parent pid are filled in.
pub const PIDFD_INFO_PID: u64 = 1 << 0;
/// `PIDFD_INFO_CREDS`: the eight credential ids are filled in.
pub const PIDFD_INFO_CREDS: u64 = 1 << 1;
/// `PIDFD_INFO_CGROUPID`: the cgroup v2 id is filled in.
pub const PIDFD_INFO_CGROUPID: u64 = 1 << 2;

/// What `PIDFD_GET_INFO` reported about a process.
///
/// Laid out exactly as the kernel's `struct pidfd_info` (version 0, 64 bytes),
/// because the kernel writes into it directly. Every accessor checks the mask
/// the kernel returned rather than the one that was asked for: a field the
/// kernel did not fill is zero, and zero is root's uid. Reading an unfilled
/// field as a credential would turn a missing answer into the most privileged
/// one, so an unreported field is `None`, never a number.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidfdInfo {
    mask: u64,
    cgroupid: u64,
    pid: u32,
    tgid: u32,
    ppid: u32,
    ruid: u32,
    rgid: u32,
    euid: u32,
    egid: u32,
    suid: u32,
    sgid: u32,
    fsuid: u32,
    fsgid: u32,
    // PIDFD_INFO_EXIT. Never requested: the broker asks about live peers only.
    _exit_code: i32,
}

/// The process ids `PIDFD_GET_INFO` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIds {
    /// The thread id the pidfd refers to.
    pub pid: u32,
    /// The thread-group id: the process id as userspace means it.
    pub tgid: u32,
    /// The parent's process id.
    pub ppid: u32,
}

/// The credentials `PIDFD_GET_INFO` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Creds {
    /// Real user id.
    pub ruid: u32,
    /// Real group id.
    pub rgid: u32,
    /// Effective user id.
    pub euid: u32,
    /// Effective group id.
    pub egid: u32,
    /// Saved user id.
    pub suid: u32,
    /// Saved group id.
    pub sgid: u32,
    /// Filesystem user id.
    pub fsuid: u32,
    /// Filesystem group id.
    pub fsgid: u32,
}

impl PidfdInfo {
    /// Everything attestation needs: who the process is, whose it is, and which
    /// cgroup it is in.
    pub const ATTESTATION_MASK: u64 = PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_CGROUPID;

    /// A record with only `mask` set: a request to the kernel, or the start of
    /// a fake answer.
    pub fn new(mask: u64) -> Self {
        Self {
            mask,
            cgroupid: 0,
            pid: 0,
            tgid: 0,
            ppid: 0,
            ruid: 0,
            rgid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            fsuid: 0,
            fsgid: 0,
            _exit_code: 0,
        }
    }

    /// Fills in the process ids and marks them reported.
    #[must_use]
    pub fn with_ids(mut self, ids: ProcessIds) -> Self {
        self.mask |= PIDFD_INFO_PID;
        self.pid = ids.pid;
        self.tgid = ids.tgid;
        self.ppid = ids.ppid;
        self
    }

    /// Fills in the credentials and marks them reported.
    #[must_use]
    pub fn with_creds(mut self, creds: Creds) -> Self {
        self.mask |= PIDFD_INFO_CREDS;
        self.ruid = creds.ruid;
        self.rgid = creds.rgid;
        self.euid = creds.euid;
        self.egid = creds.egid;
        self.suid = creds.suid;
        self.sgid = creds.sgid;
        self.fsuid = creds.fsuid;
        self.fsgid = creds.fsgid;
        self
    }

    /// Fills in the cgroup id and marks it reported.
    #[must_use]
    pub fn with_cgroup_id(mut self, id: u64) -> Self {
        self.mask |= PIDFD_INFO_CGROUPID;
        self.cgroupid = id;
        self
    }

    /// The mask as the kernel returned it.
    pub fn mask(&self) -> u64 {
        self.mask
    }

    /// The process ids, if the kernel reported them.
    pub fn ids(&self) -> Option<ProcessIds> {
        self.reports(PIDFD_INFO_PID).then_some(ProcessIds {
            pid: self.pid,
            tgid: self.tgid,
            ppid: self.ppid,
        })
    }

    /// The thread id, if the kernel reported it.
    ///
    /// A method rather than a closure over [`Self::ids`], so a test can name it
    /// whichever way the kernel answered.
    pub fn pid(&self) -> Option<u32> {
        self.reports(PIDFD_INFO_PID).then_some(self.pid)
    }

    /// The credentials, if the kernel reported them.
    pub fn creds(&self) -> Option<Creds> {
        self.reports(PIDFD_INFO_CREDS).then_some(Creds {
            ruid: self.ruid,
            rgid: self.rgid,
            euid: self.euid,
            egid: self.egid,
            suid: self.suid,
            sgid: self.sgid,
            fsuid: self.fsuid,
            fsgid: self.fsgid,
        })
    }

    /// The cgroup v2 id, if the kernel reported it.
    ///
    /// Absent on a host without the unified hierarchy, which is a host where no
    /// caller can be placed in a root-created scope, and so no caller can be
    /// attested.
    pub fn cgroup_id(&self) -> Option<u64> {
        self.reports(PIDFD_INFO_CGROUPID).then_some(self.cgroupid)
    }

    fn reports(&self, bit: u64) -> bool {
        self.mask & bit == bit
    }
}

/// The system calls that need `unsafe`, as a seam.
pub trait Syscalls {
    /// Marks every descriptor numbered `first` or above close-on-exec.
    ///
    /// `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)`. It does not close them:
    /// closing a descriptor some `OwnedFd` in this process still holds is a
    /// use-after-close, so a safe function cannot do it. Marking closes nothing
    /// now and closes all of them at the next exec, which for the gate is the
    /// command itself.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] with `EINVAL` before Linux 5.11 (no `CLOSE_RANGE_CLOEXEC`)
    /// or `ENOSYS` before 5.9 (no `close_range`).
    fn mark_cloexec_from(&self, first: u32) -> Result<(), SysError>;

    /// The pidfd of the process at the other end of a Unix socket.
    ///
    /// `getsockopt(SO_PEERPIDFD)`: race-free, because the kernel pinned the
    /// peer when the connection was made, so the pid cannot be recycled
    /// between asking and using.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] with `ENOPROTOOPT` before Linux 6.5, and `ENOTSOCK` if
    /// `socket` is not one.
    fn peer_pidfd(&self, socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError>;

    /// Asks the kernel about the process a pidfd refers to.
    ///
    /// `ioctl(PIDFD_GET_INFO)`. Check the returned record's accessors, not
    /// `mask`: the kernel may fill in less than was asked for.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] with `ESRCH` if the process has been reaped, and
    /// `ENOTTY` on a descriptor that is not a pidfd. A kernel without the call
    /// answers with **either** of two errnos: `ENOTTY` before Linux 6.11, and
    /// `EINVAL` on 6.11 and 6.12, whose pidfd ioctl handler refuses any
    /// non-zero argument before it looks at the command. Both mean "drop a
    /// rung", never "retry".
    fn pidfd_info(&self, pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, SysError>;

    /// Replaces this process with the program open on `program`.
    ///
    /// `execveat(program, "", argv, envp, AT_EMPTY_PATH)`: the descriptor that
    /// was validated is the thing executed, so there is no window in which the
    /// path can be swapped. Returns only on failure, which is why the return
    /// type is the error itself.
    fn exec_fd(&self, program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError;
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
        crate::raw::mark_cloexec_from(first)
    }

    fn peer_pidfd(&self, socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
        crate::raw::peer_pidfd(socket)
    }

    fn pidfd_info(&self, pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, SysError> {
        crate::raw::pidfd_info(pidfd, mask)
    }

    fn exec_fd(&self, program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError {
        crate::raw::exec_fd(program, argv, envp)
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
    /// [`Syscalls::exec_fd`] with this argv and environment.
    Exec {
        /// The argument vector, `argv[0]` included.
        argv: Vec<CString>,
        /// The environment, as `KEY=value` strings.
        envp: Vec<CString>,
    },
}

/// A scripted kernel, for tests.
///
/// Unscripted, it behaves like the oldest kernel the ladder knows: no peer
/// pidfd, no pidfd info. A test that forgets to script an answer therefore sees
/// the fail-closed one. `exec_fd` never replaces anything; it records the call
/// and returns the scripted error.
#[derive(Debug)]
pub struct FakeSyscalls {
    calls: RefCell<Vec<FakeCall>>,
    cloexec: Result<(), SysError>,
    peer: RefCell<Option<Result<OwnedFd, SysError>>>,
    info: Result<PidfdInfo, SysError>,
    exec: SysError,
}

impl FakeSyscalls {
    /// A fake with nothing scripted.
    pub fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            cloexec: Ok(()),
            peer: RefCell::new(None),
            info: Err(SysError::unsupported("fake: no pidfd info scripted")),
            exec: SysError::unsupported("fake: exec recorded, nothing replaced"),
        }
    }

    /// Makes [`Syscalls::mark_cloexec_from`] fail with `error`.
    #[must_use]
    pub fn failing_cloexec(mut self, error: SysError) -> Self {
        self.cloexec = Err(error);
        self
    }

    /// Scripts the next [`Syscalls::peer_pidfd`] answer. It is handed out
    /// once, because a descriptor can only be owned once.
    #[must_use]
    pub fn with_peer(self, peer: Result<OwnedFd, SysError>) -> Self {
        self.peer.replace(Some(peer));
        self
    }

    /// Scripts every [`Syscalls::pidfd_info`] answer.
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

impl Syscalls for FakeSyscalls {
    fn mark_cloexec_from(&self, first: u32) -> Result<(), SysError> {
        self.record(FakeCall::MarkCloexecFrom(first));
        self.cloexec.clone()
    }

    fn peer_pidfd(&self, _socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
        self.record(FakeCall::PeerPidfd);
        self.peer.take().unwrap_or_else(|| {
            Err(SysError::unsupported(
                "fake: no peer pidfd scripted, or it was already taken",
            ))
        })
    }

    fn pidfd_info(&self, _pidfd: BorrowedFd<'_>, mask: u64) -> Result<PidfdInfo, SysError> {
        self.record(FakeCall::PidfdInfo(mask));
        self.info.clone()
    }

    fn exec_fd(&self, _program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError {
        self.record(FakeCall::Exec {
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

    #[test]
    fn the_record_is_the_size_the_kernel_writes() {
        // PIDFD_INFO_SIZE_VER0. The ioctl number encodes this size, so a
        // mismatch is a request the kernel decodes as a different struct.
        assert_eq!(std::mem::size_of::<PidfdInfo>(), 64);
    }

    #[test]
    fn an_unreported_credential_is_absent_not_root() {
        // The kernel zero-fills what it did not report, and zero is root. A
        // record whose mask lacks CREDS must not read as uid 0.
        let info = PidfdInfo::new(0);
        assert_eq!(info.creds(), None);
        assert_eq!(info.ids(), None);
        assert_eq!(info.pid(), None);
        assert_eq!(info.cgroup_id(), None);
        assert_eq!(info.mask(), 0);
    }

    #[test]
    fn each_field_group_is_reported_independently() {
        let ids = ProcessIds {
            pid: 412,
            tgid: 412,
            ppid: 1,
        };
        let user = Creds {
            ruid: 1000,
            euid: 1000,
            ..ROOT
        };
        let info = PidfdInfo::new(0)
            .with_ids(ids)
            .with_creds(user)
            .with_cgroup_id(7);
        assert_eq!(info.mask(), PidfdInfo::ATTESTATION_MASK);
        assert_eq!(info.ids(), Some(ids));
        assert_eq!(info.pid(), Some(412));
        assert_eq!(info.creds(), Some(user));
        assert_eq!(info.cgroup_id(), Some(7));

        let only_cgroup = PidfdInfo::new(0).with_cgroup_id(9);
        assert_eq!(only_cgroup.cgroup_id(), Some(9));
        assert_eq!(only_cgroup.creds(), None);
    }

    #[test]
    fn an_unscripted_fake_answers_like_the_oldest_kernel() {
        // Forgetting to script an answer must land a test on the fail-closed
        // path, never on a convenient success.
        let fake = FakeSyscalls::default();
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(fake.mark_cloexec_from(3).is_ok());
        assert!(fake.peer_pidfd(a.as_fd()).is_err());
        assert!(
            fake.pidfd_info(a.as_fd(), PidfdInfo::ATTESTATION_MASK)
                .is_err()
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
                    argv: vec![c"/usr/bin/true".to_owned()],
                    envp: vec![c"PATH=/usr/bin".to_owned()],
                },
            ]
        );
        assert!(format!("{fake:?}").contains("FakeSyscalls"));
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
        let info = PidfdInfo::new(0).with_creds(ROOT);
        let enosys = SysError::os("close_range", &std::io::Error::from_raw_os_error(38));
        let eacces = SysError::os("execveat", &std::io::Error::from_raw_os_error(13));
        let fake = FakeSyscalls::new()
            .failing_cloexec(enosys.clone())
            .with_info(Ok(info))
            .with_exec_error(eacces.clone());
        assert_eq!(fake.mark_cloexec_from(3), Err(enosys));
        assert_eq!(fake.pidfd_info(a.as_fd(), 0), Ok(info));
        assert_eq!(fake.exec_fd(a.as_fd(), &[], &[]), eacces);
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
    /// compared, so the same test passes on 6.8 and on 6.13 and covers the same
    /// lines on both, and a ladder that disagrees with the kernel fails it.
    #[cfg(target_os = "linux")]
    mod linux {
        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::net::UnixStream;

        use rustix::fs::{CWD, Mode, OFlags, open, openat};
        use rustix::io::{FdFlags, fcntl_getfd};

        use super::super::*;
        use crate::kernel::{Attestation, KernelSupport};

        fn running_kernel() -> KernelSupport {
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
            KernelSupport::parse(release.trim())
        }

        #[test]
        fn marking_cloexec_reaches_a_descriptor_opened_without_it() {
            // Opened without O_CLOEXEC on purpose: std sets it on everything,
            // which would make this test pass with the call deleted.
            let fd = open("/proc/self/status", OFlags::RDONLY, Mode::empty()).unwrap();
            assert!(!fcntl_getfd(&fd).unwrap().contains(FdFlags::CLOEXEC));
            let first = u32::try_from(fd.as_raw_fd()).unwrap();
            HostSyscalls.mark_cloexec_from(first).unwrap();
            assert!(fcntl_getfd(&fd).unwrap().contains(FdFlags::CLOEXEC));
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
        }

        #[test]
        fn a_peer_pidfd_is_refused_on_something_that_is_not_a_socket() {
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let err = HostSyscalls.peer_pidfd(file.as_fd()).unwrap_err();
            assert_eq!(
                err.os_code(),
                Some(rustix::io::Errno::NOTSOCK.raw_os_error())
            );
        }

        #[test]
        fn pidfd_info_answers_exactly_when_the_ladder_says_it_should() {
            let kernel = running_kernel();
            let expect_answer = kernel.attestation == Attestation::PeerPidfdInfo;
            // Which errno a kernel without the call gives depends on whether
            // it has the 6.11 pidfd ioctl handler. Indexed, not branched, so
            // every kernel covers the same lines.
            let missing = [rustix::io::Errno::NOTTY, rustix::io::Errno::INVAL]
                [usize::from(kernel.version.at_least(6, 11))]
            .raw_os_error();
            let (a, _b) = UnixStream::pair().unwrap();
            let pidfd = HostSyscalls.peer_pidfd(a.as_fd()).unwrap();
            let answer = HostSyscalls.pidfd_info(pidfd.as_fd(), PidfdInfo::ATTESTATION_MASK);

            assert_eq!(answer.is_ok(), expect_answer, "{answer:?}");
            assert_eq!(
                answer.as_ref().ok().and_then(PidfdInfo::pid),
                expect_answer.then_some(std::process::id()),
            );
            assert_eq!(
                answer.as_ref().err().map(SysError::os_code),
                (!expect_answer).then_some(Some(missing)),
            );
        }

        #[test]
        fn pidfd_info_is_refused_on_something_that_is_not_a_pidfd() {
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let err = HostSyscalls
                .pidfd_info(file.as_fd(), PidfdInfo::ATTESTATION_MASK)
                .unwrap_err();
            assert_eq!(err.os_code(), Some(rustix::io::Errno::NOTTY.raw_os_error()));
        }

        #[test]
        fn exec_of_a_directory_descriptor_fails_and_returns() {
            // EACCES for root too: no execute bit is ever honoured on a
            // directory. If this exec succeeded the test process would be gone.
            let dir = openat(
                CWD,
                "/",
                OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let err = HostSyscalls.exec_fd(dir.as_fd(), &[c"/"], &[]);
            assert_eq!(
                err.os_code(),
                Some(rustix::io::Errno::ACCESS.raw_os_error())
            );
        }

        #[test]
        fn exec_of_a_file_with_no_execute_bit_fails_and_returns() {
            // procfs files are 0444; with no execute bit at all, root is
            // refused as well.
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let err = HostSyscalls.exec_fd(file.as_fd(), &[c"status"], &[c"A=b"]);
            assert_eq!(
                err.os_code(),
                Some(rustix::io::Errno::ACCESS.raw_os_error())
            );
            assert!(format!("{HostSyscalls:?}").contains("HostSyscalls"));
        }
    }
}
