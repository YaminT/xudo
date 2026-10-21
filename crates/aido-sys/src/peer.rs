//! The rest of identifying the process on the other end of a socket, behind a
//! seam of its own.
//!
//! [`crate::Syscalls`] is the list of calls that need `unsafe`: of the peer
//! calls, `SO_PEERPIDFD`, `PIDFD_GET_INFO`, and `SO_PEERCRED`. The calls that
//! are safe in rustix are `pidfd_open`, a poll on a pidfd, and two reads of
//! `/proc/<pid>` by number, and those live here, behind [`PeerCalls`].
//! `SO_PEERCRED` is on this seam as well, but only as a seam: [`HostPeer`]
//! answers it through [`crate::Syscalls::peer_cred`], which decodes the
//! kernel's record into plain integers (`aido-sys-raw`, the sixth `unsafe`
//! block), after a check of the socket's kind. It never answers it through
//! rustix's `socket_peercred`, which decodes the pid into a type that cannot be
//! zero and so is undefined behaviour on the pid 0 the kernel reports for a
//! peer outside this process's pid namespace; `clippy.toml` bans that function.
//! Having every peer call behind [`PeerCalls`] lets the attestation ladder
//! built on both seams in `aidod` be driven through every rung and every
//! refusal by [`FakePeer`] on any platform, including the orders of events a
//! real kernel will not produce on demand: a peer that exits between the
//! broker's read of `/proc` and its re-check through the pidfd, and a peer the
//! kernel reports as pid 0.
//!
//! # What each answer is worth
//!
//! * `SO_PEERCRED` is the kernel's record of the peer **at connect time**: its
//!   pid number, effective uid, and effective gid. On every rung, this is the
//!   identity the broker binds a request to.
//! * A `/proc/<pid>` read is by **number**, and a number can be reissued once
//!   its process is reaped. So a read proves nothing on its own; it is
//!   confirmed afterwards through a pidfd, by [`PeerCalls::has_exited`].
//! * A poll on a pidfd reports readable once the process has exited, and a
//!   process that has not exited has not been reaped, so its number still
//!   names it.
//!
//! The predicates at the bottom of this module — [`lacks_peer_pidfd`],
//! [`lacks_pidfd_open`], [`lacks_pidfd_info`] — are how a caller decides the
//! rung by **asking the kernel** rather than reading its version: a
//! distribution kernel can carry a call long before the upstream version that
//! introduced it, and only the errno says which calls exist here.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::os::fd::{BorrowedFd, OwnedFd};

use bstr::ByteSlice;

use crate::error::SysError;
#[cfg(target_os = "linux")]
use crate::syscall::{HostSyscalls, Syscalls as _};

/// What `SO_PEERCRED` reports: the peer as it was when it connected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    /// The peer's process id, as this process's pid namespace numbers it.
    ///
    /// Zero when the peer is not visible from this namespace at all.
    pub pid: u32,
    /// Its effective uid when it connected.
    pub uid: u32,
    /// Its effective gid when it connected.
    pub gid: u32,
}

/// Which file under `/proc/<pid>` to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcFile {
    /// `stat`: the start time a request is pinned by.
    Stat,
    /// `status`: the effective uid the process runs as now.
    Status,
}

impl ProcFile {
    /// The file's name under `/proc/<pid>`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Stat => "stat",
            Self::Status => "status",
        }
    }
}

/// The calls that identify a socket's peer other than the two that only
/// [`crate::Syscalls`] makes (`SO_PEERPIDFD` and `PIDFD_GET_INFO`), as a seam.
///
/// `pidfd_open`, the `/proc` reads, and the liveness poll are safe in rustix.
/// `SO_PEERCRED` is not safe there, so it is carried here only as a seam, for
/// the ladder to be faked through, and [`HostPeer`] reads it through
/// [`crate::Syscalls::peer_cred`].
pub trait PeerCalls {
    /// `getsockopt(SO_PEERCRED)`: the peer's pid, euid, and egid at connect
    /// time.
    ///
    /// On the host this is [`crate::Syscalls::peer_cred`] behind a check that
    /// the descriptor is a connected Unix stream or seqpacket socket; rustix's
    /// own decode is never used (see the module docs).
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] if the descriptor is not a connected Unix socket, and
    /// [`SysError::Unsupported`] off Linux.
    fn peer_cred(&self, socket: BorrowedFd<'_>) -> Result<PeerCred, SysError>;

    /// `pidfd_open(pid, 0)`: a pidfd for whichever process holds `pid` now.
    ///
    /// Not necessarily the process that connected: the number may have been
    /// reissued since. That is why the rung built on this call cannot carry the
    /// agent path (see [`crate::Attestation::can_attest_an_agent`]).
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] with `ENOSYS` before Linux 5.3 (drop a rung, see
    /// [`lacks_pidfd_open`]), `ESRCH` if no process has the number, `EINVAL`
    /// for a number that is not a pid, and [`SysError::Unsupported`] off Linux.
    fn pidfd_open(&self, pid: u32) -> Result<OwnedFd, SysError>;

    /// Reads `/proc/<pid>/<file>`, by number.
    ///
    /// # Errors
    ///
    /// [`SysError::Read`] if the file cannot be read — most often because the
    /// process has gone — and [`SysError::Unsupported`] off Linux.
    fn read_proc(&self, pid: u32, file: ProcFile) -> Result<Vec<u8>, SysError>;

    /// Whether the process behind `pidfd` has exited.
    ///
    /// A zero-timeout poll: the pidfd is readable once the process has exited.
    /// `false` means it has not exited, so it has not been reaped, so its pid
    /// number still names it — which is what makes a `/proc` read made before
    /// this call trustworthy.
    ///
    /// # Errors
    ///
    /// [`SysError::Os`] if the poll fails, and [`SysError::Unsupported`] off
    /// Linux.
    fn has_exited(&self, pidfd: BorrowedFd<'_>) -> Result<bool, SysError>;
}

/// The running kernel.
///
/// On Linux every call goes to the kernel and `/proc`. On any other platform
/// every call answers [`SysError::Unsupported`], so nothing on a development
/// host can identify a peer and every path through the broker there is a
/// refusal.
#[derive(Clone, Copy, Debug)]
pub struct HostPeer;

#[cfg(target_os = "linux")]
impl PeerCalls for HostPeer {
    fn peer_cred(&self, socket: BorrowedFd<'_>) -> Result<PeerCred, SysError> {
        // The record is decoded by `Syscalls::peer_cred`, into plain
        // integers, so a pid of 0 (a peer outside this process's pid
        // namespace, or none) is a number here and not undefined behaviour.
        // The socket's kind is still checked first, as defence in depth: the
        // kernel records a peer process only for a connected Unix stream or
        // seqpacket socket, and a descriptor of any other kind never gets as
        // far as the question.
        stream_peer(socket)?;
        HostSyscalls.peer_cred(socket).map(from_raw)
    }

    fn pidfd_open(&self, pid: u32) -> Result<OwnedFd, SysError> {
        let Some(pid) = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        else {
            return Err(SysError::os("pidfd_open", &rustix::io::Errno::INVAL.into()));
        };
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
            .map_err(|errno| SysError::os("pidfd_open", &errno.into()))
    }

    fn read_proc(&self, pid: u32, file: ProcFile) -> Result<Vec<u8>, SysError> {
        use crate::source::ProcSource as _;

        crate::source::DirSource::proc().read(&format!("{pid}/{}", file.name()))
    }

    fn has_exited(&self, pidfd: BorrowedFd<'_>) -> Result<bool, SysError> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};

        let mut fds = [PollFd::new(&pidfd, PollFlags::IN)];
        let polled = poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            }),
        );
        let [polled_fd] = &fds;
        exited_from_poll(polled, polled_fd.revents())
    }
}

#[cfg(not(target_os = "linux"))]
impl PeerCalls for HostPeer {
    fn peer_cred(&self, _socket: BorrowedFd<'_>) -> Result<PeerCred, SysError> {
        Err(SysError::unsupported("SO_PEERCRED on a non-Linux platform"))
    }

    fn pidfd_open(&self, _pid: u32) -> Result<OwnedFd, SysError> {
        Err(SysError::unsupported("pidfd_open on a non-Linux platform"))
    }

    fn read_proc(&self, _pid: u32, _file: ProcFile) -> Result<Vec<u8>, SysError> {
        Err(SysError::unsupported("/proc on a non-Linux platform"))
    }

    fn has_exited(&self, _pidfd: BorrowedFd<'_>) -> Result<bool, SysError> {
        Err(SysError::unsupported(
            "pidfd liveness on a non-Linux platform",
        ))
    }
}

/// Refuses, before `SO_PEERCRED` is asked, every descriptor on which the
/// kernel would answer for no process: anything but a connected `AF_UNIX`
/// stream or seqpacket socket.
///
/// The kernel records the peer's credentials when a Unix stream or seqpacket
/// socket connects, and for both ends of a socket pair. It records none for
/// another address family or for a datagram socket that called `connect` —
/// on which `getpeername` succeeds all the same — and answers those with pid
/// 0. So the address family and the type are checked, and only then whether
/// there is a peer at all.
#[cfg(target_os = "linux")]
fn stream_peer(socket: BorrowedFd<'_>) -> Result<(), SysError> {
    use rustix::net::{AddressFamily, SocketType, sockopt};

    match sockopt::socket_domain(socket) {
        Ok(domain) if domain == AddressFamily::UNIX => {}
        Ok(_) => return Err(not_a_stream_peer("the socket is not AF_UNIX")),
        Err(errno) => return Err(SysError::os("getsockopt(SO_DOMAIN)", &errno.into())),
    }
    // A Unix socket whose type cannot be read is refused with the ones whose
    // type is wrong: on a descriptor SO_DOMAIN just answered for, it is the
    // same answer either way.
    match sockopt::socket_type(socket) {
        Ok(kind) if kind == SocketType::STREAM || kind == SocketType::SEQPACKET => {}
        _ => {
            return Err(not_a_stream_peer(
                "the socket is neither a stream nor a seqpacket socket",
            ));
        }
    }
    if let Err(errno) = rustix::net::getpeername(socket) {
        return Err(SysError::os("getpeername", &errno.into()));
    }
    Ok(())
}

/// The refusal for a socket `SO_PEERCRED` is never asked about.
#[cfg(target_os = "linux")]
fn not_a_stream_peer(why: &str) -> SysError {
    SysError::Os {
        operation: "SO_PEERCRED".to_owned(),
        code: None,
        reason: format!(
            "not asked: {why}, so the kernel records no peer process for it and would answer \
             pid 0"
        ),
    }
}

/// The kernel's record as this module's [`PeerCred`].
///
/// A pid that is not positive names no process: the kernel reports 0 for a
/// peer it cannot name, and a negative number is no pid at all. Both become
/// 0, which a caller refuses (`aidod`: `PeerNotVisible`) and never looks up.
#[cfg(target_os = "linux")]
fn from_raw(raw: aido_sys_raw::PeerCred) -> PeerCred {
    PeerCred {
        pid: u32::try_from(raw.pid).unwrap_or(0),
        uid: raw.uid,
        gid: raw.gid,
    }
}

/// Reads a zero-timeout poll of a pidfd as "has exited".
///
/// Any reported event counts: readable means exited, and a hang-up, an error,
/// or an invalid descriptor all mean the broker cannot show the process is
/// still there, which for a liveness check is the same answer. Split out so
/// the failure arm is reachable from a test with a real errno rather than
/// needing a kernel that fails a poll.
#[cfg(target_os = "linux")]
fn exited_from_poll(
    polled: rustix::io::Result<usize>,
    revents: rustix::event::PollFlags,
) -> Result<bool, SysError> {
    match polled {
        Ok(_) => Ok(!revents.is_empty()),
        Err(errno) => Err(SysError::os("poll(pidfd)", &errno.into())),
    }
}

/// The effective uid in a `/proc/<pid>/status`: the second number on its
/// `Uid:` line (real, effective, saved, filesystem).
///
/// The first line beginning `Uid:` is the kernel's own: the only
/// process-chosen text in the file is the name, which the kernel escapes, so
/// a process cannot plant a line of its own above the real one.
///
/// # Errors
///
/// [`SysError::Malformed`] if there is no `Uid:` line, or either of its first
/// two fields is missing or not a number.
pub fn parse_status_euid(path: &str, bytes: &[u8]) -> Result<u32, SysError> {
    parse_status_uids(path, bytes).map(|uids| uids.effective)
}

/// The first two numbers on a `/proc/<pid>/status` `Uid:` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusUids {
    /// The real uid: who started the process. An unprivileged process cannot
    /// change it, not even by running a set-user-ID program.
    pub real: u32,
    /// The effective uid: what the process is allowed to do now.
    pub effective: u32,
}

/// The real and effective uids in a `/proc/<pid>/status`, from the first line
/// beginning `Uid:` (see [`parse_status_euid`] for why that line is the
/// kernel's).
///
/// # Errors
///
/// [`SysError::Malformed`] if there is no `Uid:` line, or either of its first
/// two fields is missing or not a number.
pub fn parse_status_uids(path: &str, bytes: &[u8]) -> Result<StatusUids, SysError> {
    let line = bytes
        .lines()
        .find_map(|line| line.strip_prefix(b"Uid:"))
        .ok_or_else(|| SysError::malformed(path, "no Uid: line"))?;
    let mut fields = line
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty());
    let real = uid_field(path, fields.next(), "real")?;
    let effective = uid_field(path, fields.next(), "effective")?;
    Ok(StatusUids { real, effective })
}

/// One numeric field of a `Uid:` line, named `which` in any refusal.
fn uid_field(path: &str, field: Option<&[u8]>, which: &str) -> Result<u32, SysError> {
    let Some(field) = field else {
        return Err(SysError::malformed(
            path,
            format!("the Uid: line has no {which} uid"),
        ));
    };
    field
        .to_str()
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| SysError::malformed(path, format!("the {which} uid is not a number")))
}

/// Whether an `SO_PEERPIDFD` failure means the kernel lacks the option.
///
/// `ENOPROTOOPT`, before Linux 6.5 — the one answer from that call that means
/// "use the rung below" rather than "deny". Every other errno is a refusal:
/// `EINVAL`, in particular, is a peer already reaped on 6.5 to 6.15, and the
/// rung below would look it up by a number that may now name someone else.
pub fn lacks_peer_pidfd(error: &SysError) -> bool {
    error.os_code() == Some(rustix::io::Errno::NOPROTOOPT.raw_os_error())
}

/// Whether a `pidfd_open` failure means the kernel lacks the call.
///
/// `ENOSYS`, before Linux 5.3. Every other errno is a refusal.
pub fn lacks_pidfd_open(error: &SysError) -> bool {
    error.os_code() == Some(rustix::io::Errno::NOSYS.raw_os_error())
}

/// Whether a `PIDFD_GET_INFO` failure means the kernel lacks the call.
///
/// `ENOTTY` before Linux 6.11, and `EINVAL` on 6.11 and 6.12, whose pidfd
/// ioctl handler refuses any non-zero argument before it looks at the command
/// (see [`crate::Syscalls::pidfd_info`]). Every other answer — `ESRCH` for a
/// reaped process above all, and a record no kernel answered — is a refusal.
pub fn lacks_pidfd_info(error: &SysError) -> bool {
    let missing = [rustix::io::Errno::NOTTY, rustix::io::Errno::INVAL];
    missing
        .iter()
        .any(|errno| error.os_code() == Some(errno.raw_os_error()))
}

/// Whether an `SO_PEERPIDFD` failure means the peer was reaped before the
/// broker asked.
///
/// `EINVAL`, on 6.5 to 6.15: the kernel will not make a pidfd for a thread
/// group that no longer exists, and the connect-time pid is always a thread
/// group's. The peer connected and went away, which is a refusal — never a
/// lower rung — and the peer's doing, not the host's.
pub fn peer_was_reaped(error: &SysError) -> bool {
    error.os_code() == Some(rustix::io::Errno::INVAL.raw_os_error())
}

/// Whether a `pidfd_open` or `PIDFD_GET_INFO` failure means the process is
/// gone.
///
/// `ESRCH`: no process has the number, or, from 6.16, the pidfd outlived the
/// process it names. A refusal, and the peer's doing.
pub fn process_is_gone(error: &SysError) -> bool {
    error.os_code() == Some(rustix::io::Errno::SRCH.raw_os_error())
}

/// One call a [`FakePeer`] received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerCall {
    /// [`PeerCalls::peer_cred`].
    PeerCred,
    /// [`PeerCalls::pidfd_open`] for this pid.
    PidfdOpen(u32),
    /// [`PeerCalls::read_proc`] of this pid's file.
    ReadProc(u32, ProcFile),
    /// [`PeerCalls::has_exited`].
    HasExited,
}

/// A scripted peer, for tests.
///
/// Each call has its own queue of answers, handed out in the order they were
/// scripted, so a test can script a *sequence* — a pid that is alive at one
/// check and gone at the next. Every call is recorded, in order, so a test can
/// also assert *when* a call was made: that the liveness check came after the
/// last `/proc` read, which is the property the whole pinning argument rests
/// on.
///
/// Unscripted, every call refuses, each the way a broken or ancient platform
/// would: no credentials, no `pidfd_open` (`ENOSYS`), no `/proc`, and no answer
/// about liveness — so a test that forgets a step lands on a refusal, never on
/// an identity nobody established.
#[derive(Debug, Default)]
pub struct FakePeer {
    calls: RefCell<Vec<PeerCall>>,
    creds: RefCell<VecDeque<Result<PeerCred, SysError>>>,
    opens: RefCell<VecDeque<Result<OwnedFd, SysError>>>,
    stats: RefCell<VecDeque<Result<Vec<u8>, SysError>>>,
    statuses: RefCell<VecDeque<Result<Vec<u8>, SysError>>>,
    exits: RefCell<VecDeque<Result<bool, SysError>>>,
    procs: RefCell<Vec<TabledProc>>,
}

/// One fixed `/proc/<pid>/<file>` of a [`FakePeer`].
type TabledProc = ((u32, ProcFile), Vec<u8>);

/// A fake's refusal for a call nobody scripted.
fn unscripted(operation: &str) -> SysError {
    SysError::Os {
        operation: operation.to_owned(),
        code: None,
        reason: "fake: nothing scripted for this call".to_owned(),
    }
}

impl FakePeer {
    /// A fake with nothing scripted.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues an answer for [`PeerCalls::peer_cred`].
    #[must_use]
    pub fn with_cred(self, answer: Result<PeerCred, SysError>) -> Self {
        self.creds.borrow_mut().push_back(answer);
        self
    }

    /// Queues an answer for [`PeerCalls::pidfd_open`].
    #[must_use]
    pub fn with_open(self, answer: Result<OwnedFd, SysError>) -> Self {
        self.opens.borrow_mut().push_back(answer);
        self
    }

    /// Queues an answer for a read of `/proc/<pid>/stat`.
    #[must_use]
    pub fn with_stat(self, answer: Result<Vec<u8>, SysError>) -> Self {
        self.stats.borrow_mut().push_back(answer);
        self
    }

    /// Queues an answer for a read of `/proc/<pid>/status`.
    #[must_use]
    pub fn with_status(self, answer: Result<Vec<u8>, SysError>) -> Self {
        self.statuses.borrow_mut().push_back(answer);
        self
    }

    /// Fixes what `/proc/<pid>/<file>` holds, for every read of it.
    ///
    /// A table, not a queue: it answers a read of any pid in any order, as
    /// often as asked, and is consulted before the queues. For a test that
    /// looks up many processes it did not script one by one.
    #[must_use]
    pub fn with_proc(self, pid: u32, file: ProcFile, contents: impl Into<Vec<u8>>) -> Self {
        self.procs.borrow_mut().push(((pid, file), contents.into()));
        self
    }

    /// Queues an answer for [`PeerCalls::has_exited`].
    #[must_use]
    pub fn with_exit(self, answer: Result<bool, SysError>) -> Self {
        self.exits.borrow_mut().push_back(answer);
        self
    }

    /// Every call received so far, in order.
    pub fn calls(&self) -> Vec<PeerCall> {
        self.calls.borrow().clone()
    }

    fn record(&self, call: PeerCall) {
        self.calls.borrow_mut().push(call);
    }
}

impl PeerCalls for FakePeer {
    fn peer_cred(&self, _socket: BorrowedFd<'_>) -> Result<PeerCred, SysError> {
        self.record(PeerCall::PeerCred);
        self.creds
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(unscripted("getsockopt(SO_PEERCRED)")))
    }

    fn pidfd_open(&self, pid: u32) -> Result<OwnedFd, SysError> {
        self.record(PeerCall::PidfdOpen(pid));
        self.opens.borrow_mut().pop_front().unwrap_or_else(|| {
            Err(SysError::Os {
                operation: "pidfd_open".to_owned(),
                code: Some(rustix::io::Errno::NOSYS.raw_os_error()),
                reason: "fake: no pidfd_open scripted, so this kernel lacks it".to_owned(),
            })
        })
    }

    fn read_proc(&self, pid: u32, file: ProcFile) -> Result<Vec<u8>, SysError> {
        self.record(PeerCall::ReadProc(pid, file));
        let fixed = self
            .procs
            .borrow()
            .iter()
            .find(|(key, _)| *key == (pid, file))
            .map(|(_, contents)| contents.clone());
        if let Some(contents) = fixed {
            return Ok(contents);
        }
        let queue = match file {
            ProcFile::Stat => &self.stats,
            ProcFile::Status => &self.statuses,
        };
        queue.borrow_mut().pop_front().unwrap_or_else(|| {
            Err(SysError::read(
                format!("{pid}/{}", file.name()),
                "fake: nothing scripted",
            ))
        })
    }

    fn has_exited(&self, _pidfd: BorrowedFd<'_>) -> Result<bool, SysError> {
        self.record(PeerCall::HasExited);
        self.exits
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(unscripted("poll(pidfd)")))
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

    fn errno(code: Errno) -> SysError {
        SysError::os("x", &code.into())
    }

    #[test]
    fn a_proc_file_names_itself() {
        assert_eq!(ProcFile::Stat.name(), "stat");
        assert_eq!(ProcFile::Status.name(), "status");
    }

    #[test]
    fn the_effective_uid_is_the_second_field_of_the_uid_line() {
        let status =
            b"Name:\tbash\nUmask:\t0022\nUid:\t1000\t0\t1000\t1000\nGid:\t100\t100\t100\t100\n";
        assert_eq!(parse_status_euid("412/status", status), Ok(0));
    }

    #[test]
    fn a_status_without_a_usable_uid_line_is_malformed_not_root() {
        // A missing effective uid must never read as uid 0, and neither may a
        // missing real one.
        for (status, reason) in [
            (&b"Name:\tbash\n"[..], "no Uid: line"),
            (b"Uid:\n", "no real uid"),
            (
                b"Uid:\troot\t1000\t1000\t1000\n",
                "the real uid is not a number",
            ),
            (b"Uid:\t1000\n", "no effective uid"),
            (
                b"Uid:\t1000\troot\t1000\t1000\n",
                "the effective uid is not a number",
            ),
            (b"Uid:\t1000\t\xff\t1000\t1000\n", "not a number"),
        ] {
            let err = parse_status_euid("412/status", status).unwrap_err();
            assert!(err.to_string().contains(reason), "{err}");
            assert!(err.to_string().contains("412/status"), "{err}");
        }
    }

    #[test]
    fn the_real_uid_survives_a_set_user_id_exec_and_is_read_beside_the_effective_one() {
        // What a set-user-ID root program looks like from outside: the
        // effective uid is root's, the real uid is still the user's.
        let status = b"Name:\tpasswd\nUid:\t1000\t0\t0\t0\n";
        assert_eq!(
            parse_status_uids("412/status", status),
            Ok(StatusUids {
                real: 1000,
                effective: 0
            })
        );
    }

    #[test]
    fn a_name_cannot_plant_a_uid_line_above_the_real_one() {
        // The kernel escapes a newline in the name, so the only way a process
        // could put "Uid:" first is at the start of a line, which it cannot.
        let status = b"Name:\tevil\\nUid:\t0\t0\t0\t0\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_status_euid("s", status), Ok(1000));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_poll_with_any_event_means_the_process_cannot_be_shown_alive() {
        use rustix::event::PollFlags;

        assert_eq!(exited_from_poll(Ok(0), PollFlags::empty()), Ok(false));
        for event in [
            PollFlags::IN,
            PollFlags::HUP,
            PollFlags::ERR,
            PollFlags::NVAL,
        ] {
            assert_eq!(exited_from_poll(Ok(1), event), Ok(true), "{event:?}");
        }
        let err = exited_from_poll(Err(Errno::INTR), PollFlags::empty()).unwrap_err();
        assert_eq!(err.os_code(), Some(Errno::INTR.raw_os_error()));
    }

    #[test]
    fn only_the_documented_errnos_mean_a_missing_call() {
        // Each predicate says "drop a rung" for exactly the errno a kernel
        // without the call gives, and "deny" for everything else — above all
        // for the errnos that mean the peer is gone.
        assert!(lacks_peer_pidfd(&errno(Errno::NOPROTOOPT)));
        for refusal in [Errno::INVAL, Errno::NOTSOCK, Errno::NODATA, Errno::MFILE] {
            assert!(!lacks_peer_pidfd(&errno(refusal)), "{refusal:?}");
        }
        assert!(lacks_pidfd_open(&errno(Errno::NOSYS)));
        for refusal in [Errno::SRCH, Errno::INVAL, Errno::MFILE] {
            assert!(!lacks_pidfd_open(&errno(refusal)), "{refusal:?}");
        }
        assert!(lacks_pidfd_info(&errno(Errno::NOTTY)));
        assert!(lacks_pidfd_info(&errno(Errno::INVAL)));
        for refusal in [Errno::SRCH, Errno::PERM, Errno::FAULT] {
            assert!(!lacks_pidfd_info(&errno(refusal)), "{refusal:?}");
        }
        // A failure with no errno at all — an unanswered record — is a refusal.
        let unanswered = SysError::Os {
            operation: "ioctl(PIDFD_GET_INFO)".to_owned(),
            code: None,
            reason: "no process".to_owned(),
        };
        assert!(!lacks_pidfd_info(&unanswered));
        assert!(!lacks_peer_pidfd(&SysError::unsupported("x")));
    }

    #[test]
    fn only_the_errnos_of_a_peer_that_went_away_are_the_peers_doing() {
        // A client that connects and exits must not be able to make the
        // broker report itself broken, and a broken host must not be passed
        // off as a client that left.
        assert!(peer_was_reaped(&errno(Errno::INVAL)));
        for host in [Errno::NOPROTOOPT, Errno::NODATA, Errno::MFILE, Errno::PERM] {
            assert!(!peer_was_reaped(&errno(host)), "{host:?}");
        }
        assert!(process_is_gone(&errno(Errno::SRCH)));
        for host in [Errno::INVAL, Errno::NOSYS, Errno::MFILE, Errno::PERM] {
            assert!(!process_is_gone(&errno(host)), "{host:?}");
        }
        assert!(!peer_was_reaped(&SysError::unsupported("x")));
        assert!(!process_is_gone(&SysError::unsupported("x")));
    }

    #[test]
    fn a_fake_hands_out_each_queue_in_order_and_records_every_call() {
        let (a, b) = UnixStream::pair().unwrap();
        let cred = PeerCred {
            pid: 412,
            uid: 1000,
            gid: 100,
        };
        let fake = FakePeer::new()
            .with_cred(Ok(cred))
            .with_open(Ok(OwnedFd::from(b)))
            .with_open(Err(errno(Errno::SRCH)))
            .with_stat(Ok(b"stat".to_vec()))
            .with_status(Ok(b"status".to_vec()))
            .with_exit(Ok(false))
            .with_exit(Ok(true));

        assert_eq!(fake.peer_cred(a.as_fd()), Ok(cred));
        assert!(fake.pidfd_open(412).is_ok());
        assert_eq!(
            fake.pidfd_open(412).unwrap_err().os_code(),
            Some(Errno::SRCH.raw_os_error())
        );
        assert_eq!(
            fake.read_proc(412, ProcFile::Status),
            Ok(b"status".to_vec())
        );
        assert_eq!(fake.read_proc(412, ProcFile::Stat), Ok(b"stat".to_vec()));
        assert_eq!(fake.has_exited(a.as_fd()), Ok(false));
        assert_eq!(fake.has_exited(a.as_fd()), Ok(true));
        assert_eq!(
            fake.calls(),
            vec![
                PeerCall::PeerCred,
                PeerCall::PidfdOpen(412),
                PeerCall::PidfdOpen(412),
                PeerCall::ReadProc(412, ProcFile::Status),
                PeerCall::ReadProc(412, ProcFile::Stat),
                PeerCall::HasExited,
                PeerCall::HasExited,
            ]
        );
        assert!(format!("{fake:?}").contains("FakePeer"));
    }

    #[test]
    fn a_fake_proc_table_answers_any_pid_in_any_order_before_the_queues() {
        let fake = FakePeer::new()
            .with_proc(7, ProcFile::Stat, "seven")
            .with_proc(8, ProcFile::Stat, "eight")
            .with_stat(Ok(b"queued".to_vec()));
        assert_eq!(fake.read_proc(8, ProcFile::Stat), Ok(b"eight".to_vec()));
        assert_eq!(fake.read_proc(7, ProcFile::Stat), Ok(b"seven".to_vec()));
        assert_eq!(fake.read_proc(8, ProcFile::Stat), Ok(b"eight".to_vec()));
        // Another file of a tabled pid, and another pid, fall to the queue.
        assert!(fake.read_proc(7, ProcFile::Status).is_err());
        assert_eq!(fake.read_proc(9, ProcFile::Stat), Ok(b"queued".to_vec()));
    }

    #[test]
    fn an_unscripted_fake_refuses_every_call() {
        // Forgetting a step must land a test on a refusal, never on an
        // identity nobody established.
        let (a, _b) = UnixStream::pair().unwrap();
        let fake = FakePeer::new();
        assert!(
            fake.peer_cred(a.as_fd())
                .unwrap_err()
                .to_string()
                .contains("fake")
        );
        assert!(lacks_pidfd_open(&fake.pidfd_open(1).unwrap_err()));
        assert!(fake.read_proc(1, ProcFile::Stat).is_err());
        assert!(fake.read_proc(1, ProcFile::Status).is_err());
        assert_eq!(fake.has_exited(a.as_fd()).unwrap_err().os_code(), None);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_host_refuses_every_call_off_linux() {
        let (a, _b) = UnixStream::pair().unwrap();
        let host = HostPeer;
        let refusals = [
            host.peer_cred(a.as_fd()).unwrap_err(),
            host.pidfd_open(1).unwrap_err(),
            host.read_proc(1, ProcFile::Stat).unwrap_err(),
            host.has_exited(a.as_fd()).unwrap_err(),
        ];
        for err in &refusals {
            assert!(err.to_string().contains("not supported"), "{err}");
        }
        assert!(format!("{host:?}").contains("HostPeer"));
    }

    /// The real kernel. Like the `Syscalls` tests, written without a branch on
    /// what this kernel supports: every call here exists on every kernel the
    /// Linux tests run on, so every line runs on every one of them.
    #[cfg(target_os = "linux")]
    mod linux {
        #![allow(clippy::disallowed_methods)]

        use std::os::fd::AsFd;
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};

        use rustix::io::Errno;

        use super::super::*;
        use crate::proc::parse_stat;

        #[test]
        fn peer_credentials_of_a_socketpair_name_this_process() {
            // A socketpair records its creator as the peer of both ends.
            let (a, _b) = UnixStream::pair().unwrap();
            let cred = HostPeer.peer_cred(a.as_fd()).unwrap();
            assert_eq!(cred.pid, std::process::id());
            assert_eq!(cred.uid, rustix::process::geteuid().as_raw());
            assert_eq!(cred.gid, rustix::process::getegid().as_raw());
        }

        #[test]
        fn peer_credentials_are_refused_on_something_that_is_not_a_socket() {
            let file = std::fs::File::open("/proc/self/status").unwrap();
            let err = HostPeer.peer_cred(file.as_fd()).unwrap_err();
            assert_eq!(err.os_code(), Some(Errno::NOTSOCK.raw_os_error()));
        }

        #[test]
        fn peer_credentials_of_a_socket_with_no_peer_are_refused_rather_than_decoded() {
            // The kernel answers SO_PEERCRED on an unconnected socket with pid
            // 0, which rustix would decode into a pid that cannot be zero.
            // Refused before the call is made, for every caller of the seam.
            let lonely = rustix::net::socket(
                rustix::net::AddressFamily::UNIX,
                rustix::net::SocketType::STREAM,
                None,
            )
            .unwrap();
            let err = HostPeer.peer_cred(lonely.as_fd()).unwrap_err();
            assert_eq!(err.os_code(), Some(Errno::NOTCONN.raw_os_error()));
            assert!(err.to_string().starts_with("getpeername"), "{err}");
        }

        #[test]
        fn peer_credentials_of_a_connected_datagram_socket_are_refused_rather_than_decoded() {
            // A datagram socket that called connect() has a peer address, so
            // a getpeername check passes; but the kernel recorded no peer
            // process, and answers SO_PEERCRED with pid 0 and uid -1. A review
            // measured rustix turning that success into "Operation not
            // permitted". Refused on the socket's type, before the call.
            use std::os::linux::net::SocketAddrExt as _;
            use std::os::unix::net::{SocketAddr, UnixDatagram};

            let name = format!("aido-peer-datagram-{}", std::process::id());
            let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
            let _bound = UnixDatagram::bind_addr(&address).unwrap();
            let connected = UnixDatagram::unbound().unwrap();
            connected.connect_addr(&address).unwrap();
            assert!(rustix::net::getpeername(&connected).is_ok());

            let err = HostPeer.peer_cred(connected.as_fd()).unwrap_err();
            assert_eq!(err.os_code(), None, "{err}");
            assert!(
                err.to_string().starts_with("SO_PEERCRED failed: not asked"),
                "{err}"
            );
            assert!(err.to_string().contains("neither a stream"), "{err}");
        }

        #[test]
        fn peer_credentials_of_a_tcp_connection_are_refused_rather_than_decoded() {
            // TCP records no peer process either; both ends answer pid 0.
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            for end in [client.as_fd(), accepted.as_fd()] {
                let err = HostPeer.peer_cred(end).unwrap_err();
                assert_eq!(err.os_code(), None, "{err}");
                assert!(err.to_string().contains("not AF_UNIX"), "{err}");
            }
        }

        #[test]
        fn peer_credentials_of_a_seqpacket_pair_name_this_process() {
            // The other type the kernel records a peer for, and accepted.
            let (a, _b) = rustix::net::socketpair(
                rustix::net::AddressFamily::UNIX,
                rustix::net::SocketType::SEQPACKET,
                rustix::net::SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            let cred = HostPeer.peer_cred(a.as_fd()).unwrap();
            assert_eq!(cred.pid, std::process::id());
        }

        #[test]
        fn a_peer_outside_the_pid_namespace_decodes_as_pid_zero_never_an_identity() {
            // What the kernel says for a peer this namespace cannot name, and
            // what a hostile record could say. Both are pid 0, which the
            // broker refuses without looking it up.
            let nobody = |pid| aido_sys_raw::PeerCred {
                pid,
                uid: u32::MAX,
                gid: u32::MAX,
            };
            for pid in [0, -1, i32::MIN] {
                assert_eq!(from_raw(nobody(pid)).pid, 0, "{pid}");
            }
            assert_eq!(from_raw(nobody(7)).pid, 7);
        }

        #[test]
        fn a_datagram_socket_the_precheck_missed_would_still_decode_as_pid_zero() {
            // The safe decode alone, without the socket-kind precheck: the
            // kernel's pid 0 arrives as a number, where rustix would have
            // stored it in a type that cannot hold it. An abstract name, so
            // that nothing is created on any filesystem.
            use std::os::linux::net::SocketAddrExt as _;
            use std::os::unix::net::{SocketAddr, UnixDatagram};

            let name = format!("aido-peer-decode-{}", std::process::id());
            let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
            let _bound = UnixDatagram::bind_addr(&address).unwrap();
            let connected = UnixDatagram::unbound().unwrap();
            connected.connect_addr(&address).unwrap();
            let raw = HostSyscalls.peer_cred(connected.as_fd()).unwrap();
            assert_eq!(raw.pid, 0, "the kernel records no process for a datagram");
            assert_eq!(from_raw(raw).pid, 0);
        }

        #[test]
        fn a_pidfd_opened_for_this_process_reads_alive() {
            let pidfd = HostPeer.pidfd_open(std::process::id()).unwrap();
            assert_eq!(HostPeer.has_exited(pidfd.as_fd()), Ok(false));
        }

        #[test]
        fn a_pidfd_for_a_child_that_exited_reads_exited() {
            // Exited and reaped: the pidfd outlives the process and reports it.
            let mut child = Command::new("/usr/bin/true")
                .stdin(Stdio::null())
                .spawn()
                .unwrap();
            let pidfd = HostPeer.pidfd_open(child.id()).unwrap();
            assert!(child.wait().unwrap().success());
            assert_eq!(HostPeer.has_exited(pidfd.as_fd()), Ok(true));
        }

        #[test]
        fn pidfd_open_refuses_a_number_that_is_not_a_pid_and_one_nobody_holds() {
            // 0 and anything above i32::MAX are not pids at all; i32::MAX is a
            // pid no kernel issues, because pid_max cannot exceed 2^22.
            for not_a_pid in [0, u32::MAX] {
                let err = HostPeer.pidfd_open(not_a_pid).unwrap_err();
                assert_eq!(
                    err.os_code(),
                    Some(Errno::INVAL.raw_os_error()),
                    "{not_a_pid}"
                );
            }
            let err = HostPeer.pidfd_open(2_147_483_647).unwrap_err();
            assert_eq!(err.os_code(), Some(Errno::SRCH.raw_os_error()));
        }

        #[test]
        fn proc_is_read_by_number() {
            let me = std::process::id();
            let stat = HostPeer.read_proc(me, ProcFile::Stat).unwrap();
            assert_eq!(parse_stat("stat", &stat).unwrap().pid, me);
            let status = HostPeer.read_proc(me, ProcFile::Status).unwrap();
            assert_eq!(
                parse_status_euid("status", &status),
                Ok(rustix::process::geteuid().as_raw())
            );
            assert!(HostPeer.read_proc(2_147_483_647, ProcFile::Stat).is_err());
            assert!(format!("{HostPeer:?}").contains("HostPeer"));
        }
    }
}
