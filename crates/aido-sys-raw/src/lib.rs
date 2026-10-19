//! The four system calls `aido` cannot make without `unsafe`, and the record
//! the kernel writes for one of them.
//!
//! This is the only crate in the workspace whose lint table does not forbid
//! `unsafe_code`. It denies it here, at the crate root, and allows it in one
//! module, [`sys`], whose blocks are counted against a budget published in that
//! module's docs. Everything above it — `aido-sys`, which puts these calls
//! behind a trait with a fake, and every crate that uses that — forbids
//! `unsafe` outright, so the compiler keeps it here, not a reviewer.
//!
//! The data types live here rather than in `aido-sys` because the kernel
//! writes [`PidfdInfo`] directly: its layout is part of the unsafe contract,
//! and it is checked field by field against the kernel's struct beside the
//! call that fills it.
//!
//! `tests/unsafe_budget.rs` holds the rest of the line: no `unsafe` token
//! anywhere else in the workspace, no lint attribute that lifts `unsafe_code`
//! anywhere but [`sys`], no crate but `aido-sys` depending on this one, and no
//! drift between this crate's lint table and the workspace's.

#![deny(unsafe_code)]

// The syscall wrappers widen their arguments with `c_long::from`, which a
// 32-bit target has no impl for. Said in words rather than in a trait error.
#[cfg(all(target_os = "linux", not(target_pointer_width = "64")))]
compile_error!("aido-sys-raw supports 64-bit Linux only");

#[cfg(target_os = "linux")]
pub mod sys;

/// `PIDFD_INFO_PID`: the pid, thread-group id, and parent pid are filled in.
pub const PIDFD_INFO_PID: u64 = 1 << 0;
/// `PIDFD_INFO_CREDS`: the eight credential ids are filled in.
pub const PIDFD_INFO_CREDS: u64 = 1 << 1;
/// `PIDFD_INFO_CGROUPID`: the cgroup v2 id is filled in.
pub const PIDFD_INFO_CGROUPID: u64 = 1 << 2;

/// What `PIDFD_GET_INFO` reported about a process.
///
/// Laid out exactly as the kernel's `struct pidfd_info` (version 0, 64 bytes),
/// because the kernel writes into it directly; [`sys`] asserts the size and
/// every field's offset against the kernel headers at compile time.
///
/// # What a record vouches for
///
/// * **Only what the returned mask reports.** A field the kernel did not fill
///   is zero, and zero is root's uid, so an unreported field is `None`, never a
///   number.
/// * **Only a kernel's answer.** [`Self::is_answer`] tells a record the kernel
///   wrote from one it never touched.
/// * **The process's state at the moment of the call**, not at connect time.
///   The pidfd pins *which* process this is; its credentials and cgroup can
///   have changed since it connected, for instance across an exec of a
///   set-user-ID program. Connect-time identity comes from `SO_PEERCRED`.
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

/// The credentials `PIDFD_GET_INFO` reports, as they are at the moment of the
/// call, mapped into the caller's user namespace.
///
/// Not the credentials the process had when it connected: those come from
/// `SO_PEERCRED`, which the kernel captures at connect time.
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
    /// Everything attestation needs: which process, whose it is, and which
    /// cgroup it is in.
    pub const ATTESTATION_MASK: u64 = PIDFD_INFO_PID | PIDFD_INFO_CREDS | PIDFD_INFO_CGROUPID;

    /// A record that reports nothing. The start of a fake answer.
    pub fn empty() -> Self {
        Self::with_mask(0)
    }

    /// A record with only `mask` set. With a non-zero mask this is a request
    /// to the kernel, not an answer, so it is built only beside the call.
    fn with_mask(mask: u64) -> Self {
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

    /// Whether this record is a kernel's answer rather than a request nobody
    /// answered.
    ///
    /// The kernel reports the process ids on every successful call and never
    /// a zero pid or thread-group id — it returns `ESRCH` instead. A record
    /// without them is a call that did not happen, such as a syscall filter
    /// that returned success without running it, and must not be read as
    /// anything, least of all as root's credentials.
    pub fn is_answer(&self) -> bool {
        self.reports(PIDFD_INFO_PID) && self.pid != 0 && self.tgid != 0
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

    /// The credentials at the moment of the call, if the kernel reported them.
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

    /// The id of the process's cgroup in the unified hierarchy, if the kernel
    /// reported it.
    ///
    /// Reported on every kernel built with cgroups, whether or not the unified
    /// hierarchy is mounted. Where it is not, every process is in its root and
    /// every peer reports the same id, so a present id says nothing about
    /// whether the host can attest anyone; that has to be checked on the host
    /// itself.
    pub fn cgroup_id(&self) -> Option<u64> {
        self.reports(PIDFD_INFO_CGROUPID).then_some(self.cgroupid)
    }

    fn reports(&self, bit: u64) -> bool {
        self.mask & bit == bit
    }
}

/// A system call that failed, and the kernel's account of why.
#[derive(Debug)]
pub struct OsError {
    /// The call, named as the kernel documents it.
    pub operation: &'static str,
    /// What the kernel said: the errno, or a description where there was none.
    pub error: std::io::Error,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
        assert_eq!(size_of::<PidfdInfo>(), 64);
    }

    #[test]
    fn an_unreported_credential_is_absent_not_root() {
        // The kernel zero-fills what it did not report, and zero is root. A
        // record whose mask lacks CREDS must not read as uid 0.
        let info = PidfdInfo::empty();
        assert_eq!(info.creds(), None);
        assert_eq!(info.ids(), None);
        assert_eq!(info.pid(), None);
        assert_eq!(info.cgroup_id(), None);
        assert_eq!(info.mask(), 0);
    }

    #[test]
    fn a_request_nobody_answered_is_not_an_answer() {
        // A syscall filter can return success without running the call, which
        // leaves the request record as it was built: every bit asked for set,
        // every field zero. Read as an answer, that is root.
        let unanswered = PidfdInfo::with_mask(PidfdInfo::ATTESTATION_MASK);
        assert_eq!(
            unanswered.creds(),
            Some(ROOT),
            "the request alone reads as root"
        );
        assert!(
            !unanswered.is_answer(),
            "so it must be refused as an answer"
        );

        let ids = ProcessIds {
            pid: 412,
            tgid: 412,
            ppid: 1,
        };
        assert!(PidfdInfo::empty().with_ids(ids).is_answer());
        for broken in [ProcessIds { pid: 0, ..ids }, ProcessIds { tgid: 0, ..ids }] {
            assert!(
                !PidfdInfo::empty().with_ids(broken).is_answer(),
                "{broken:?}"
            );
        }
        assert!(
            !PidfdInfo::empty().with_creds(ROOT).is_answer(),
            "creds without ids"
        );
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
        let info = PidfdInfo::empty()
            .with_ids(ids)
            .with_creds(user)
            .with_cgroup_id(7);
        assert_eq!(info.mask(), PidfdInfo::ATTESTATION_MASK);
        assert_eq!(info.ids(), Some(ids));
        assert_eq!(info.pid(), Some(412));
        assert_eq!(info.creds(), Some(user));
        assert_eq!(info.cgroup_id(), Some(7));

        let only_cgroup = PidfdInfo::empty().with_cgroup_id(9);
        assert_eq!(only_cgroup.cgroup_id(), Some(9));
        assert_eq!(only_cgroup.creds(), None);
    }

    #[test]
    fn an_os_error_carries_the_call_and_the_kernels_answer() {
        let err = OsError {
            operation: "close_range",
            error: std::io::Error::from_raw_os_error(38),
        };
        assert_eq!(err.error.raw_os_error(), Some(38));
        assert!(format!("{err:?}").contains("close_range"));
    }
}
