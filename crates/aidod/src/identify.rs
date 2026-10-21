//! Who is on the other end of the socket, by the attestation ladder.
//!
//! The rung is decided by **asking the kernel**, one call at a time, never by
//! reading its version — a distribution kernel can carry a call years before
//! the upstream version that introduced it:
//!
//! ```text
//! SO_PEERCRED                          connect-time pid, euid, egid   (every rung)
//! SO_PEERPIDFD   ENOPROTOOPT -> pidfd_open(pid)   ENOSYS -> no pidfd (PeerCredOnly)
//! PIDFD_GET_INFO ENOTTY/EINVAL -> no record       (PeerPidfd, or PidfdOpen)
//! /proc/<pid>/stat     the start time the request is pinned by
//! /proc/<pid>/status   the euid it runs as now, if no record said
//! poll(pidfd)          after the last /proc read: still unreaped?
//! ```
//!
//! Only the errno that means "this kernel lacks the call" drops a rung. Every
//! other failure is a refusal, above all the ones that mean the peer is gone:
//! falling to a lower rung after a failure would look the peer up by a pid
//! number that may now belong to someone else.
//!
//! # What the pin is, and why the re-check comes last
//!
//! A request is bound to `(pid, starttime)`, both read by number: the pid from
//! `SO_PEERCRED`, the start time from `/proc/<pid>/stat`. A number can be
//! reissued once its process is reaped, even while a pidfd still refers to the
//! process. So after the last `/proc` read, the broker polls the pidfd: a
//! process that has not exited has not been reaped, so the number it read
//! still named the pinned process when it read it. A peer that exited is
//! refused, however far identification had got.
//!
//! # Credentials are compared, not trusted twice
//!
//! The euid the request is attributed to is `SO_PEERCRED`'s, captured when the
//! peer connected. The euid the peer runs as *now* — from `PIDFD_GET_INFO` if
//! the kernel answers it, otherwise from `/proc/<pid>/status` — must equal it:
//! a peer that connected and then exec'd a set-user-ID program is a different
//! program with different authority, and is refused.
//!
//! # What none of this decides
//!
//! Classification. In M2b every caller is `Unattested`, so nothing here grants
//! anything; the identity binds the request and fills the audit record. The
//! rung is still recorded honestly, because M4 will rest authority on it.

use std::os::fd::{AsFd as _, BorrowedFd, OwnedFd};

use aido_sys::{
    Attestation, PeerCalls, PidfdInfo, ProcFile, SysError, Syscalls, lacks_peer_pidfd,
    lacks_pidfd_info, lacks_pidfd_open, parse_stat, parse_status_euid, peer_was_reaped,
    process_is_gone,
};

/// The peer, as the kernel described it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    /// The rung this broker reached, by asking the kernel.
    pub rung: Attestation,
    /// The peer's pid when it connected, from `SO_PEERCRED`.
    pub pid: u32,
    /// Its effective uid when it connected.
    pub uid: u32,
    /// Its effective gid when it connected.
    pub gid: u32,
    /// Its start time, from `/proc/<pid>/stat`, in clock ticks since boot.
    pub starttime: u64,
    /// Whether a pidfd held the process while `/proc` was read and the
    /// re-check through it found the process unreaped afterwards.
    ///
    /// False only on [`Attestation::PeerCredOnly`], where there is no pidfd.
    pub pinned: bool,
    /// The cgroup id `PIDFD_GET_INFO` reported, when it answered. Recorded,
    /// never used: M4 is where a cgroup can mean something.
    pub cgroup_id: Option<u64>,
    /// Where the current effective uid that was compared came from.
    pub euid_source: EuidSource,
}

/// Where the peer's current effective uid was read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EuidSource {
    /// `PIDFD_GET_INFO`, through the pidfd.
    PidfdInfo,
    /// `/proc/<pid>/status`, by number, confirmed by the re-check.
    ProcStatus,
}

impl EuidSource {
    /// The label recorded in the audit trail.
    pub fn label(self) -> &'static str {
        match self {
            Self::PidfdInfo => "PIDFD_GET_INFO",
            Self::ProcStatus => "/proc/<pid>/status",
        }
    }
}

/// Whose failure a refusal is.
///
/// Decides the broker's exit status, so that systemd marks the instance
/// failed when the broker itself is broken and not when a client misbehaved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// The client: it went away, sent nonsense, or changed under the broker.
    Client,
    /// The broker or its host: something an administrator must fix.
    Broker,
}

impl Fault {
    /// The label recorded in the audit trail.
    pub fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Broker => "broker",
        }
    }
}

/// Why the peer could not be identified. Every variant refuses the request.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdentifyError {
    /// `SO_PEERCRED` failed: this is no connected Unix stream socket, or no
    /// Linux.
    #[error("cannot read the peer's credentials: {0}")]
    PeerCred(SysError),
    /// `SO_PEERCRED` reported pid 0: the peer is outside this pid namespace,
    /// or there is none.
    ///
    /// The kernel's answer, decoded into a plain integer (the sixth `unsafe`
    /// block, in `aido-sys-raw`), so that a pid of 0 is a value this crate can
    /// refuse and not a value its decoder cannot hold. Never turned into an
    /// identity, and never looked up: pid 0 names no process.
    #[error("the peer's pid is 0: it is not visible from the broker's pid namespace")]
    PeerNotVisible,
    /// `SO_PEERPIDFD` failed for a reason other than the kernel lacking it.
    #[error("SO_PEERPIDFD refused: {0}")]
    PeerPidfd(SysError),
    /// `pidfd_open` failed for a reason other than the kernel lacking it.
    #[error("pidfd_open refused: {0}")]
    PidfdOpen(SysError),
    /// `PIDFD_GET_INFO` failed for a reason other than the kernel lacking it.
    #[error("PIDFD_GET_INFO refused: {0}")]
    PidfdInfo(SysError),
    /// The pidfd names a different process from the one that connected.
    #[error("the peer connected as pid {connected}, but its pidfd names {pinned:?}")]
    PidMismatch {
        /// `SO_PEERCRED`'s pid.
        connected: u32,
        /// The thread-group id `PIDFD_GET_INFO` reported.
        pinned: Option<u32>,
    },
    /// The peer's `/proc` entry could not be read or parsed.
    #[error("cannot read the peer's /proc entry: {0}")]
    Proc(SysError),
    /// `/proc/<pid>/stat` describes a different pid.
    #[error("/proc/{connected}/stat describes pid {found}")]
    ProcPidMismatch {
        /// The pid that was read.
        connected: u32,
        /// The pid the file names.
        found: u32,
    },
    /// The peer's effective uid changed after it connected.
    #[error(
        "the peer connected with effective uid {connected} and now runs as {current}: it exec'd \
         a set-user-ID program after connecting"
    )]
    CredentialsChanged {
        /// `SO_PEERCRED`'s euid.
        connected: u32,
        /// The euid it runs as now.
        current: u32,
    },
    /// The re-check found the peer had exited.
    #[error(
        "the peer exited before the broker could confirm that the /proc entry it read was the \
         peer's"
    )]
    Exited,
    /// The re-check itself failed.
    #[error("cannot confirm the peer is still there: {0}")]
    Liveness(SysError),
}

impl IdentifyError {
    /// Whose failure this is.
    ///
    /// The client's when it went away, changed, or could not be read — and a
    /// pidfd call that failed because the peer is gone is the peer going away,
    /// whichever call noticed first. The broker's when the host cannot answer
    /// the questions at all.
    pub fn fault(&self) -> Fault {
        match self {
            Self::PidMismatch { .. }
            | Self::Proc(_)
            | Self::ProcPidMismatch { .. }
            | Self::CredentialsChanged { .. }
            | Self::Exited => Fault::Client,
            Self::PeerPidfd(error) if peer_was_reaped(error) => Fault::Client,
            Self::PidfdOpen(error) | Self::PidfdInfo(error) if process_is_gone(error) => {
                Fault::Client
            }
            Self::PeerCred(_)
            | Self::PeerNotVisible
            | Self::PeerPidfd(_)
            | Self::PidfdOpen(_)
            | Self::PidfdInfo(_)
            | Self::Liveness(_) => Fault::Broker,
        }
    }
}

/// How the pidfd was obtained, which decides the rung.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinSource {
    /// `SO_PEERPIDFD`: the connecting process itself.
    Socket,
    /// `pidfd_open` on `SO_PEERCRED`'s pid: whoever holds that number now.
    PidfdOpen,
}

/// Identifies the process on the other end of `socket`.
///
/// # Errors
///
/// The first step that fails, as the matching [`IdentifyError`]. A missing
/// call drops a rung; nothing else does.
pub fn identify(
    socket: BorrowedFd<'_>,
    syscalls: &dyn Syscalls,
    peers: &dyn PeerCalls,
) -> Result<PeerIdentity, IdentifyError> {
    let cred = peers.peer_cred(socket).map_err(IdentifyError::PeerCred)?;
    // Pid 0 names no process: refuse it before any call that takes a pid.
    if cred.pid == 0 {
        return Err(IdentifyError::PeerNotVisible);
    }

    let pin = pidfd_for(socket, cred.pid, syscalls, peers)?;
    let info = match &pin {
        Some((pidfd, _)) => kernel_record(pidfd.as_fd(), cred.pid, syscalls)?,
        None => None,
    };

    let starttime = read_starttime(cred.pid, peers)?;
    let (current_euid, euid_source) = match info.as_ref().and_then(PidfdInfo::creds) {
        Some(creds) => (creds.euid, EuidSource::PidfdInfo),
        None => (read_euid(cred.pid, peers)?, EuidSource::ProcStatus),
    };
    if current_euid != cred.uid {
        return Err(IdentifyError::CredentialsChanged {
            connected: cred.uid,
            current: current_euid,
        });
    }

    // After the last read of /proc by number, and not before.
    if let Some((pidfd, _)) = &pin {
        confirm_unreaped(pidfd.as_fd(), peers)?;
    }

    Ok(PeerIdentity {
        rung: rung_of(pin.as_ref().map(|(_, source)| *source), info.is_some()),
        pid: cred.pid,
        uid: cred.uid,
        gid: cred.gid,
        starttime,
        pinned: pin.is_some(),
        cgroup_id: info.as_ref().and_then(PidfdInfo::cgroup_id),
        euid_source,
    })
}

/// A pidfd for the peer, from the highest rung the kernel has.
fn pidfd_for(
    socket: BorrowedFd<'_>,
    pid: u32,
    syscalls: &dyn Syscalls,
    peers: &dyn PeerCalls,
) -> Result<Option<(OwnedFd, PinSource)>, IdentifyError> {
    match syscalls.peer_pidfd(socket) {
        Ok(pidfd) => Ok(Some((pidfd, PinSource::Socket))),
        Err(error) if lacks_peer_pidfd(&error) => match peers.pidfd_open(pid) {
            Ok(pidfd) => Ok(Some((pidfd, PinSource::PidfdOpen))),
            Err(error) if lacks_pidfd_open(&error) => Ok(None),
            Err(error) => Err(IdentifyError::PidfdOpen(error)),
        },
        Err(error) => Err(IdentifyError::PeerPidfd(error)),
    }
}

/// The kernel's record of the pinned process, if this kernel keeps one.
///
/// A record that names a different thread group from the one that connected
/// is refused rather than ignored: it would mean the pin and the connection
/// disagree about who is asking.
fn kernel_record(
    pidfd: BorrowedFd<'_>,
    pid: u32,
    syscalls: &dyn Syscalls,
) -> Result<Option<PidfdInfo>, IdentifyError> {
    match syscalls.pidfd_info(pidfd, PidfdInfo::ATTESTATION_MASK) {
        Ok(info) => {
            let pinned = info.ids().map(|ids| ids.tgid);
            if pinned == Some(pid) {
                Ok(Some(info))
            } else {
                Err(IdentifyError::PidMismatch {
                    connected: pid,
                    pinned,
                })
            }
        }
        Err(error) if lacks_pidfd_info(&error) => Ok(None),
        Err(error) => Err(IdentifyError::PidfdInfo(error)),
    }
}

/// The start time in `/proc/<pid>/stat`, from a file that names `pid`.
fn read_starttime(pid: u32, peers: &dyn PeerCalls) -> Result<u64, IdentifyError> {
    let path = format!("/proc/{pid}/stat");
    let stat = peers
        .read_proc(pid, ProcFile::Stat)
        .and_then(|bytes| parse_stat(&path, &bytes))
        .map_err(IdentifyError::Proc)?;
    if stat.pid != pid {
        return Err(IdentifyError::ProcPidMismatch {
            connected: pid,
            found: stat.pid,
        });
    }
    Ok(stat.starttime)
}

/// The effective uid in `/proc/<pid>/status`.
fn read_euid(pid: u32, peers: &dyn PeerCalls) -> Result<u32, IdentifyError> {
    let path = format!("/proc/{pid}/status");
    peers
        .read_proc(pid, ProcFile::Status)
        .and_then(|bytes| parse_status_euid(&path, &bytes))
        .map_err(IdentifyError::Proc)
}

/// Confirms, through the pidfd, that the pinned process has not exited.
fn confirm_unreaped(pidfd: BorrowedFd<'_>, peers: &dyn PeerCalls) -> Result<(), IdentifyError> {
    match peers.has_exited(pidfd) {
        Ok(false) => Ok(()),
        Ok(true) => Err(IdentifyError::Exited),
        Err(error) => Err(IdentifyError::Liveness(error)),
    }
}

/// The rung a pidfd source and a kernel record add up to.
fn rung_of(source: Option<PinSource>, answered: bool) -> Attestation {
    match (source, answered) {
        (Some(PinSource::Socket), true) => Attestation::PeerPidfdInfo,
        (Some(PinSource::Socket), false) => Attestation::PeerPidfd,
        (Some(PinSource::PidfdOpen), _) => Attestation::PidfdOpen,
        (None, _) => Attestation::PeerCredOnly,
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

    use aido_sys::{Creds, FakeCall, FakePeer, FakeSyscalls, PeerCall, PeerCred, ProcessIds};
    use rustix::io::Errno;

    use super::*;

    const PID: u32 = 4242;
    const UID: u32 = 1000;
    const GID: u32 = 100;
    const START: u64 = 998_877;

    fn cred() -> PeerCred {
        PeerCred {
            pid: PID,
            uid: UID,
            gid: GID,
        }
    }

    fn user(euid: u32) -> Creds {
        Creds {
            ruid: UID,
            rgid: GID,
            euid,
            egid: GID,
            suid: euid,
            sgid: GID,
            fsuid: euid,
            fsgid: GID,
        }
    }

    fn record(tgid: u32, euid: u32) -> PidfdInfo {
        PidfdInfo::empty()
            .with_ids(ProcessIds {
                pid: tgid,
                tgid,
                ppid: 1,
            })
            .with_creds(user(euid))
            .with_cgroup_id(77)
    }

    fn stat(pid: u32, starttime: u64) -> Vec<u8> {
        let mut tail: Vec<String> = vec!["S".into(), "1".into()];
        for _ in 0..17 {
            tail.push("0".to_owned());
        }
        tail.push(starttime.to_string());
        format!("{pid} (aido) {}", tail.join(" ")).into_bytes()
    }

    fn status(euid: u32) -> Vec<u8> {
        format!(
            "Name:\taido\nUid:\t{UID}\t{euid}\t{euid}\t{euid}\nGid:\t{GID}\t{GID}\t{GID}\t{GID}\n"
        )
        .into_bytes()
    }

    fn errno(operation: &str, code: Errno) -> SysError {
        SysError::os(operation, &code.into())
    }

    /// A descriptor to hand the fakes as a pidfd; they never look at it.
    fn a_pidfd() -> OwnedFd {
        OwnedFd::from(UnixStream::pair().unwrap().0)
    }

    fn socket() -> UnixStream {
        UnixStream::pair().unwrap().0
    }

    /// Syscalls for the top rung: a pidfd from the socket and a record.
    fn top_rung(info: Result<PidfdInfo, SysError>) -> FakeSyscalls {
        FakeSyscalls::new().with_peer(Ok(a_pidfd())).with_info(info)
    }

    /// A peer whose every read answers for [`PID`], alive at the re-check.
    fn honest_peer() -> FakePeer {
        FakePeer::new()
            .with_cred(Ok(cred()))
            .with_stat(Ok(stat(PID, START)))
            .with_status(Ok(status(UID)))
            .with_exit(Ok(false))
    }

    #[test]
    fn the_top_rung_pins_the_peer_and_reads_its_credentials_from_the_kernel() {
        let sock = socket();
        let syscalls = top_rung(Ok(record(PID, UID)));
        let peers = honest_peer();
        let identity = identify(sock.as_fd(), &syscalls, &peers).unwrap();
        assert_eq!(
            identity,
            PeerIdentity {
                rung: Attestation::PeerPidfdInfo,
                pid: PID,
                uid: UID,
                gid: GID,
                starttime: START,
                pinned: true,
                cgroup_id: Some(77),
                euid_source: EuidSource::PidfdInfo,
            }
        );
        // The record answered the euid, so status was never read; and the
        // re-check is the last call, after the only /proc read.
        assert_eq!(
            peers.calls(),
            vec![
                PeerCall::PeerCred,
                PeerCall::ReadProc(PID, ProcFile::Stat),
                PeerCall::HasExited,
            ]
        );
        assert_eq!(
            syscalls.calls(),
            vec![
                FakeCall::PeerPidfd,
                FakeCall::PidfdInfo(PidfdInfo::ATTESTATION_MASK)
            ]
        );
    }

    #[test]
    fn a_kernel_without_pidfd_get_info_stays_on_so_peerpidfd_and_reads_status() {
        // ENOTTY before 6.11, EINVAL on 6.11 and 6.12: both mean the call is
        // missing, and both leave the pin from the socket intact.
        for missing in [Errno::NOTTY, Errno::INVAL] {
            let sock = socket();
            let syscalls = top_rung(Err(errno("ioctl(PIDFD_GET_INFO)", missing)));
            let peers = honest_peer();
            let identity = identify(sock.as_fd(), &syscalls, &peers).unwrap();
            assert_eq!(identity.rung, Attestation::PeerPidfd, "{missing:?}");
            assert_eq!(identity.euid_source, EuidSource::ProcStatus);
            assert_eq!(identity.cgroup_id, None);
            assert!(identity.pinned);
            assert_eq!(
                peers.calls(),
                vec![
                    PeerCall::PeerCred,
                    PeerCall::ReadProc(PID, ProcFile::Stat),
                    PeerCall::ReadProc(PID, ProcFile::Status),
                    PeerCall::HasExited,
                ],
                "the re-check must follow the last /proc read"
            );
        }
    }

    #[test]
    fn a_kernel_without_so_peerpidfd_falls_to_pidfd_open_on_the_connect_time_pid() {
        let sock = socket();
        let syscalls = FakeSyscalls::new()
            .with_peer(Err(errno("getsockopt(SO_PEERPIDFD)", Errno::NOPROTOOPT)));
        let peers = honest_peer().with_open(Ok(a_pidfd()));
        let identity = identify(sock.as_fd(), &syscalls, &peers).unwrap();
        assert_eq!(identity.rung, Attestation::PidfdOpen);
        assert!(identity.pinned);
        assert!(!identity.rung.can_attest_an_agent());
        assert_eq!(
            peers.calls(),
            vec![
                PeerCall::PeerCred,
                PeerCall::PidfdOpen(PID),
                PeerCall::ReadProc(PID, ProcFile::Stat),
                PeerCall::ReadProc(PID, ProcFile::Status),
                PeerCall::HasExited,
            ]
        );
    }

    #[test]
    fn a_pidfd_open_rung_still_takes_the_kernel_record_when_one_exists() {
        // A distribution kernel can carry PIDFD_GET_INFO without
        // SO_PEERPIDFD. The record is used for the euid; the rung stays
        // pidfd_open, because the pin is still not bound to the connection.
        let sock = socket();
        let syscalls = FakeSyscalls::new()
            .with_peer(Err(errno("getsockopt(SO_PEERPIDFD)", Errno::NOPROTOOPT)))
            .with_info(Ok(record(PID, UID)));
        let peers = honest_peer().with_open(Ok(a_pidfd()));
        let identity = identify(sock.as_fd(), &syscalls, &peers).unwrap();
        assert_eq!(identity.rung, Attestation::PidfdOpen);
        assert_eq!(identity.euid_source, EuidSource::PidfdInfo);
    }

    #[test]
    fn a_kernel_without_pidfds_binds_the_request_unpinned_and_says_so() {
        // The oldest kernel: an unscripted fake lacks both SO_PEERPIDFD and
        // pidfd_open. The request is still bound to (pid, starttime), and the
        // record says no pidfd held it.
        let sock = socket();
        let syscalls = FakeSyscalls::new();
        let peers = FakePeer::new()
            .with_cred(Ok(cred()))
            .with_stat(Ok(stat(PID, START)))
            .with_status(Ok(status(UID)));
        let identity = identify(sock.as_fd(), &syscalls, &peers).unwrap();
        assert_eq!(identity.rung, Attestation::PeerCredOnly);
        assert!(!identity.pinned);
        assert_eq!(identity.starttime, START);
        assert!(
            !peers.calls().contains(&PeerCall::HasExited),
            "there is no pidfd to re-check through"
        );
    }

    #[test]
    fn denies_a_peer_reaped_before_so_peerpidfd_rather_than_dropping_a_rung() {
        // EINVAL on 6.5 to 6.15: the peer is gone. The rung below would look
        // it up by a number that may now name someone else.
        let sock = socket();
        let syscalls =
            FakeSyscalls::new().with_peer(Err(errno("getsockopt(SO_PEERPIDFD)", Errno::INVAL)));
        let peers = honest_peer().with_open(Ok(a_pidfd()));
        let err = identify(sock.as_fd(), &syscalls, &peers).unwrap_err();
        assert_eq!(
            err,
            IdentifyError::PeerPidfd(errno("getsockopt(SO_PEERPIDFD)", Errno::INVAL))
        );
        assert!(
            !peers.calls().contains(&PeerCall::PidfdOpen(PID)),
            "never fall to pidfd_open on a peer that has gone"
        );
        // The peer connected and left: its doing, not the host's, so it
        // cannot make the broker exit as broken.
        assert_eq!(err.fault(), Fault::Client);
    }

    #[test]
    fn denies_every_other_so_peerpidfd_errno_as_the_hosts_failure() {
        for refusal in [Errno::NOTSOCK, Errno::NODATA, Errno::MFILE, Errno::NFILE] {
            let sock = socket();
            let syscalls =
                FakeSyscalls::new().with_peer(Err(errno("getsockopt(SO_PEERPIDFD)", refusal)));
            let err = identify(sock.as_fd(), &syscalls, &honest_peer()).unwrap_err();
            assert_eq!(
                err,
                IdentifyError::PeerPidfd(errno("getsockopt(SO_PEERPIDFD)", refusal)),
                "{refusal:?}"
            );
            assert_eq!(err.fault(), Fault::Broker, "{refusal:?}");
        }
    }

    #[test]
    fn denies_a_pidfd_open_that_fails_for_any_reason_but_a_missing_call() {
        // ESRCH: nobody holds the number any more, so the peer left. Anything
        // else is the host's.
        for (refusal, fault) in [
            (Errno::SRCH, Fault::Client),
            (Errno::INVAL, Fault::Broker),
            (Errno::MFILE, Fault::Broker),
        ] {
            let sock = socket();
            let syscalls = FakeSyscalls::new()
                .with_peer(Err(errno("getsockopt(SO_PEERPIDFD)", Errno::NOPROTOOPT)));
            let peers = honest_peer().with_open(Err(errno("pidfd_open", refusal)));
            let err = identify(sock.as_fd(), &syscalls, &peers).unwrap_err();
            assert_eq!(
                err,
                IdentifyError::PidfdOpen(errno("pidfd_open", refusal)),
                "{refusal:?}"
            );
            assert_eq!(err.fault(), fault, "{refusal:?}");
        }
    }

    #[test]
    fn denies_a_peer_whose_pidfd_outlived_it_from_six_sixteen() {
        // From 6.16 SO_PEERPIDFD hands out a pidfd for a reaped peer and
        // PIDFD_GET_INFO on it answers ESRCH: the peer left.
        let sock = socket();
        let syscalls = top_rung(Err(errno("ioctl(PIDFD_GET_INFO)", Errno::SRCH)));
        let err = identify(sock.as_fd(), &syscalls, &honest_peer()).unwrap_err();
        assert_eq!(
            err,
            IdentifyError::PidfdInfo(errno("ioctl(PIDFD_GET_INFO)", Errno::SRCH))
        );
        assert_eq!(err.fault(), Fault::Client);
    }

    #[test]
    fn denies_a_kernel_record_nobody_answered() {
        // A syscall filter that returns success without running the call
        // leaves a record that reads as root; the seam refuses it, and the
        // refusal is not mistaken for a missing call, nor for a peer that
        // left: the host is broken.
        let sock = socket();
        let syscalls = top_rung(Ok(PidfdInfo::empty().with_creds(user(0))));
        let err = identify(sock.as_fd(), &syscalls, &honest_peer()).unwrap_err();
        assert!(err.to_string().contains("returned no process"), "{err}");
        assert_eq!(err.fault(), Fault::Broker);
        let refused = top_rung(Err(errno("ioctl(PIDFD_GET_INFO)", Errno::PERM)));
        let err = identify(socket().as_fd(), &refused, &honest_peer()).unwrap_err();
        assert_eq!(err.fault(), Fault::Broker);
    }

    #[test]
    fn denies_a_pidfd_that_names_a_different_process() {
        let sock = socket();
        let syscalls = top_rung(Ok(record(PID + 1, UID)));
        let err = identify(sock.as_fd(), &syscalls, &honest_peer()).unwrap_err();
        assert_eq!(
            err,
            IdentifyError::PidMismatch {
                connected: PID,
                pinned: Some(PID + 1)
            }
        );
        assert_eq!(err.fault(), Fault::Client);
    }

    #[test]
    fn denies_a_peer_that_exec_d_a_set_user_id_program_after_connecting() {
        // Connected as uid 1000; the kernel now reports euid 0.
        let sock = socket();
        let syscalls = top_rung(Ok(record(PID, 0)));
        let err = identify(sock.as_fd(), &syscalls, &honest_peer()).unwrap_err();
        assert_eq!(
            err,
            IdentifyError::CredentialsChanged {
                connected: UID,
                current: 0
            }
        );

        // The same on a kernel without the record: /proc/<pid>/status says it.
        let sock = socket();
        let syscalls = top_rung(Err(errno("ioctl(PIDFD_GET_INFO)", Errno::NOTTY)));
        let peers = FakePeer::new()
            .with_cred(Ok(cred()))
            .with_stat(Ok(stat(PID, START)))
            .with_status(Ok(status(0)))
            .with_exit(Ok(false));
        let err = identify(sock.as_fd(), &syscalls, &peers).unwrap_err();
        assert_eq!(err.fault(), Fault::Client);
        assert!(err.to_string().contains("set-user-ID"), "{err}");
    }

    #[test]
    fn denies_a_peer_that_exited_between_the_proc_read_and_the_re_check() {
        // The read succeeded, so a start time was in hand; but the pidfd says
        // the process has exited, so the number it was read by may already
        // name someone else. Refused, on every rung that has a pidfd.
        for syscalls in [
            top_rung(Ok(record(PID, UID))),
            top_rung(Err(errno("ioctl(PIDFD_GET_INFO)", Errno::NOTTY))),
        ] {
            let sock = socket();
            let peers = FakePeer::new()
                .with_cred(Ok(cred()))
                .with_stat(Ok(stat(PID, START)))
                .with_status(Ok(status(UID)))
                .with_exit(Ok(true));
            let err = identify(sock.as_fd(), &syscalls, &peers).unwrap_err();
            assert_eq!(err, IdentifyError::Exited);
            assert_eq!(err.fault(), Fault::Client);
        }
    }

    #[test]
    fn denies_when_the_re_check_itself_fails() {
        let sock = socket();
        let peers = FakePeer::new()
            .with_cred(Ok(cred()))
            .with_stat(Ok(stat(PID, START)))
            .with_exit(Err(errno("poll(pidfd)", Errno::NOMEM)));
        let err = identify(sock.as_fd(), &top_rung(Ok(record(PID, UID))), &peers).unwrap_err();
        assert_eq!(
            err,
            IdentifyError::Liveness(errno("poll(pidfd)", Errno::NOMEM))
        );
        assert_eq!(err.fault(), Fault::Broker);
    }

    #[test]
    fn denies_a_peer_whose_proc_entry_is_gone_or_names_someone_else() {
        let sock = socket();
        let peers = FakePeer::new().with_cred(Ok(cred()));
        let err = identify(sock.as_fd(), &top_rung(Ok(record(PID, UID))), &peers).unwrap_err();
        assert!(err.to_string().contains("/proc entry"), "{err}");
        assert_eq!(err.fault(), Fault::Client);

        let sock = socket();
        let peers = FakePeer::new()
            .with_cred(Ok(cred()))
            .with_stat(Ok(b"not a stat line".to_vec()));
        let err = identify(sock.as_fd(), &top_rung(Ok(record(PID, UID))), &peers).unwrap_err();
        assert!(err.to_string().contains("malformed"), "{err}");

        let sock = socket();
        let peers = FakePeer::new()
            .with_cred(Ok(cred()))
            .with_stat(Ok(stat(PID + 1, START)));
        let err = identify(sock.as_fd(), &top_rung(Ok(record(PID, UID))), &peers).unwrap_err();
        assert_eq!(
            err,
            IdentifyError::ProcPidMismatch {
                connected: PID,
                found: PID + 1
            }
        );

        let sock = socket();
        let peers = FakePeer::new()
            .with_cred(Ok(cred()))
            .with_stat(Ok(stat(PID, START)))
            .with_status(Ok(b"Name:\taido\n".to_vec()));
        let syscalls = top_rung(Err(errno("ioctl(PIDFD_GET_INFO)", Errno::NOTTY)));
        let err = identify(sock.as_fd(), &syscalls, &peers).unwrap_err();
        assert!(err.to_string().contains("no Uid: line"), "{err}");
    }

    #[test]
    fn denies_when_the_socket_has_no_credentials_or_a_peer_outside_the_namespace() {
        let sock = socket();
        let err = identify(sock.as_fd(), &FakeSyscalls::new(), &FakePeer::new()).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("cannot read the peer's credentials"),
            "{err}"
        );
        assert_eq!(err.fault(), Fault::Broker);

        let sock = socket();
        let peers = FakePeer::new().with_cred(Ok(PeerCred { pid: 0, ..cred() }));
        let err = identify(sock.as_fd(), &FakeSyscalls::new(), &peers).unwrap_err();
        assert_eq!(err, IdentifyError::PeerNotVisible);
        assert_eq!(err.fault(), Fault::Broker);
    }

    #[test]
    fn a_peer_with_pid_zero_is_refused_and_never_looked_up_as_a_process() {
        let sock = socket();
        let syscalls = FakeSyscalls::new();
        let peers = FakePeer::new().with_cred(Ok(PeerCred { pid: 0, ..cred() }));
        let err = identify(sock.as_fd(), &syscalls, &peers).unwrap_err();
        assert_eq!(err, IdentifyError::PeerNotVisible);
        // Nothing past SO_PEERCRED was asked: no pidfd, no /proc, no poll.
        assert_eq!(peers.calls(), vec![PeerCall::PeerCred]);
        assert_eq!(syscalls.calls(), Vec::<FakeCall>::new());
    }

    #[test]
    fn denies_pid_zero_even_when_every_later_answer_would_agree() {
        // The world a pid of 0 would pass through if nothing stopped it: a
        // pidfd from the socket, a kernel without a record to contradict it,
        // a /proc entry that names pid 0 and the connect-time uid, and a peer
        // that has not exited. Every answer past SO_PEERCRED is scripted to
        // agree, so the only thing between this peer and an identity pinned
        // to no process is the refusal: remove it and `identify` returns
        // `Ok` for pid 0, which is what this test fails on.
        let sock = socket();
        let syscalls = top_rung(Err(errno("ioctl(PIDFD_GET_INFO)", Errno::NOTTY)));
        let peers = FakePeer::new()
            .with_cred(Ok(PeerCred { pid: 0, ..cred() }))
            .with_stat(Ok(stat(0, START)))
            .with_status(Ok(status(UID)))
            .with_exit(Ok(false));
        let err = identify(sock.as_fd(), &syscalls, &peers).unwrap_err();
        assert_eq!(err, IdentifyError::PeerNotVisible);
        assert_eq!(err.fault(), Fault::Broker);
        assert_eq!(peers.calls(), vec![PeerCall::PeerCred]);
        assert_eq!(syscalls.calls(), Vec::<FakeCall>::new());
    }

    #[test]
    fn every_identification_refusal_renders_a_sentence() {
        let os = errno("x", Errno::PERM);
        for err in [
            IdentifyError::PeerCred(os.clone()),
            IdentifyError::PeerNotVisible,
            IdentifyError::PeerPidfd(os.clone()),
            IdentifyError::PidfdOpen(os.clone()),
            IdentifyError::PidfdInfo(os.clone()),
            IdentifyError::PidMismatch {
                connected: 1,
                pinned: None,
            },
            IdentifyError::Proc(os.clone()),
            IdentifyError::ProcPidMismatch {
                connected: 1,
                found: 2,
            },
            IdentifyError::CredentialsChanged {
                connected: 1,
                current: 0,
            },
            IdentifyError::Exited,
            IdentifyError::Liveness(os),
        ] {
            assert!(err.to_string().len() > 20, "{err:?}");
        }
        assert_eq!(EuidSource::PidfdInfo.label(), "PIDFD_GET_INFO");
        assert_eq!(EuidSource::ProcStatus.label(), "/proc/<pid>/status");
        assert_eq!(Fault::Client.label(), "client");
        assert_eq!(Fault::Broker.label(), "broker");
    }
}
