//! Kernel-backed cgroup identity and recorded-scope checks.
//!
//! A cgroup path only names a place in the hierarchy; D2c showed that an
//! administrator can create a fresh scope under `xudo.slice`. Authority is a
//! live cgroup inode plus its committed, id-bound record, never its name.

use std::os::fd::{AsFd, BorrowedFd};

use crate::{SysError, parse_cgroup};

/// Which supported cgroup-id source established the peer's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupRung {
    /// `PIDFD_GET_INFO` and `/proc` agreed.
    PidfdInfo,
    /// The kernel lacks the pidfd ioctl; `/proc` and `fstat` were followed by
    /// a pidfd liveness poll.
    ProcFstat,
}

/// A cgroup id together with the kernel rung and fallback errno, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CgroupIdentity {
    /// Inode of the peer's cgroup directory.
    pub id: u64,
    /// The rung chosen by asking the kernel.
    pub rung: CgroupRung,
    /// `ENOTTY` or `EINVAL` that selected the proc rung.
    pub fallback_errno: Option<i32>,
}

/// Agent or watch scope type from a committed session record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeKind {
    /// Agent session.
    Agent,
    /// Human watcher.
    Watch,
}

/// A live, record-backed scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    /// The committed record's kind.
    pub kind: ScopeKind,
    /// Scope directory name, including `.scope`.
    pub name: String,
    /// Raw committed session record bytes.
    pub record: Vec<u8>,
}

/// Descriptor-derived facts about one candidate scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeFacts {
    /// Whether `/sys/fs/cgroup`'s descriptor reports cgroup2 magic.
    pub cgroup2: bool,
    /// Directory inode from `fstat`.
    pub inode: u64,
    /// Scope directory owner uid.
    pub owner: u32,
    /// Scope directory mode bits.
    pub mode: u32,
    /// `cgroup.procs` owner uid.
    pub procs_owner: u32,
    /// `cgroup.procs` mode bits.
    pub procs_mode: u32,
    /// `cgroup.events` populated value.
    pub populated: bool,
    /// Committed-record contents; absent means no authority.
    pub record: Option<Vec<u8>>,
    /// Record owner uid, from `fstat` on the descriptor that was read.
    pub record_owner: u32,
    /// Record mode bits, file type included.
    pub record_mode: u32,
    /// Record hard-link count.
    pub record_nlink: u64,
    /// Number and start-time pin of processes in the scope. Filled only when
    /// the caller asked for it (watch scopes).
    pub processes: Vec<(u32, u64)>,
}

/// The fields xudo-sys must compare in a committed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordIdentity {
    /// The kind encoded by the strict gate parser.
    pub kind: ScopeKind,
    /// Record owner uid.
    pub uid: u32,
    /// Whether the record boot id equals this boot. The parser behind
    /// [`scope_status`] must be built from `xudo_gate::record_identity`, fed
    /// the caller's own boot id and clock, never values the record supplied.
    pub current_boot: bool,
    /// Whether its deadline is still in the future (same rule as above).
    pub live: bool,
    /// Adopted pid and starttime.
    pub process: (u32, u64),
    /// Recorded cgroup id.
    pub cgroup_id: u64,
}

/// Security-relevant values from `/proc/<pid>/status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessSecurityStatus {
    /// Current tracer pid; zero means no tracer.
    pub tracer_pid: u32,
    /// Kernel `NoNewPrivs` bit.
    pub no_new_privs: bool,
}

/// Safe operations needed by the cgroup decision, fakeable on every host.
pub trait CgroupCalls {
    /// Checks the pinned `/sys/fs/cgroup` descriptor's filesystem magic.
    ///
    /// # Errors
    ///
    /// Returns an error unless the pinned mount is cgroup2.
    fn require_cgroup2(&self) -> Result<(), SysError>;
    /// `PIDFD_GET_INFO`'s cgroup id, if this kernel supports that rung.
    ///
    /// # Errors
    ///
    /// Returns the kernel error, including `ENOTTY` or `EINVAL` for a missing
    /// rung.
    fn pidfd_cgroup_id(&self, pidfd: BorrowedFd<'_>) -> Result<u64, SysError>;
    /// Reads `/proc/<pid>/cgroup` by the pid pinned by `pidfd`.
    ///
    /// # Errors
    ///
    /// Returns an error if the proc file cannot be read.
    fn proc_cgroup(&self, pid: u32) -> Result<Vec<u8>, SysError>;
    /// Resolves the proc path from a pinned cgroup2 root and returns its inode.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed paths, symlinks, or failed descriptor
    /// operations.
    fn cgroup_inode(&self, path: &str) -> Result<u64, SysError>;
    /// Polls the pidfd after the last by-number proc read.
    ///
    /// # Errors
    ///
    /// Returns an error if the liveness poll fails.
    fn peer_alive(&self, pidfd: BorrowedFd<'_>) -> Result<bool, SysError>;
    /// Inspects `xudo.slice/<name>` and its cgroup files using pinned dirfds.
    /// The scope directory's inode is compared with `id` first: any other
    /// scope returns `None` before a file of it is read, so one user's
    /// unreadable or exiting scope cannot fail another user's check.
    /// `with_processes` asks for the process list (watch scopes only).
    ///
    /// # Errors
    ///
    /// Returns an error if descriptor resolution or a required file read
    /// fails.
    fn scope_facts(
        &self,
        name: &str,
        id: u64,
        with_processes: bool,
    ) -> Result<Option<ScopeFacts>, SysError>;
    /// Lists candidate names from the pinned session-record directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the root-owned record directory cannot be verified
    /// or read.
    fn scope_names(&self) -> Result<Vec<String>, SysError>;
}

/// Host implementation. It pins `/sys/fs/cgroup` once and checks its magic on
/// the descriptor before resolving any peer or scope path beneath it.
#[derive(Debug)]
pub struct HostCgroup {
    #[cfg(target_os = "linux")]
    root: std::os::fd::OwnedFd,
    #[cfg(all(target_os = "linux", test))]
    test_records: Option<std::os::fd::OwnedFd>,
    #[cfg(all(target_os = "linux", test))]
    test_fixture: bool,
    #[cfg(all(target_os = "linux", test))]
    test_force_cgroup2: bool,
}

#[cfg(all(test, not(target_os = "linux")))]
impl HostCgroup {
    fn for_tests() -> Self {
        Self {}
    }
}

impl HostCgroup {
    /// Opens and pins the cgroup root, refusing hybrid and non-cgroup2 hosts.
    ///
    /// # Errors
    ///
    /// Returns an error if `/sys/fs/cgroup` cannot be opened or is not cgroup2.
    pub fn open() -> Result<Self, SysError> {
        imp::open()
    }
}

impl CgroupCalls for HostCgroup {
    fn require_cgroup2(&self) -> Result<(), SysError> {
        imp::require_cgroup2(self)
    }
    fn pidfd_cgroup_id(&self, pidfd: BorrowedFd<'_>) -> Result<u64, SysError> {
        imp::pidfd_cgroup_id(pidfd)
    }
    fn proc_cgroup(&self, pid: u32) -> Result<Vec<u8>, SysError> {
        imp::proc_cgroup(pid)
    }
    fn cgroup_inode(&self, path: &str) -> Result<u64, SysError> {
        imp::cgroup_inode(self, path)
    }
    fn peer_alive(&self, pidfd: BorrowedFd<'_>) -> Result<bool, SysError> {
        imp::peer_alive(pidfd)
    }
    fn scope_facts(
        &self,
        name: &str,
        id: u64,
        with_processes: bool,
    ) -> Result<Option<ScopeFacts>, SysError> {
        imp::scope_facts(self, name, id, with_processes)
    }
    fn scope_names(&self) -> Result<Vec<String>, SysError> {
        imp::scope_names(self)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io::Read;
    use std::os::fd::{AsFd, OwnedFd};

    use rustix::fs::{
        Dir, FileType, Mode, OFlags, ResolveFlags, fstat, fstatfs, open as open_path, openat,
        openat2,
    };

    use super::{HostCgroup, ScopeFacts, is_record_name};
    use crate::SysError;
    use crate::syscall::Syscalls as _;

    const CGROUP2_MAGIC: i128 = 0x6367_7270;
    const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);

    pub(super) fn rustix_result<T>(
        result: Result<T, rustix::io::Errno>,
        operation: &'static str,
    ) -> Result<T, SysError> {
        result.map_err(|errno| SysError::os(operation, &errno.into()))
    }

    pub(super) fn io_result<T>(
        result: std::io::Result<T>,
        operation: &'static str,
    ) -> Result<T, SysError> {
        result.map_err(|error| SysError::os(operation, &error))
    }

    pub(super) fn open() -> Result<HostCgroup, SysError> {
        finish_cgroup_root(open_path(
            "/sys/fs/cgroup",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ))
    }

    pub(super) fn finish_cgroup_root(
        root: Result<OwnedFd, rustix::io::Errno>,
    ) -> Result<HostCgroup, SysError> {
        let root = rustix_result(root, "open cgroup2 root")?;
        check_cgroup2_fd(root.as_fd())?;
        Ok(HostCgroup {
            root,
            #[cfg(test)]
            test_records: None,
            #[cfg(test)]
            test_fixture: false,
            #[cfg(test)]
            test_force_cgroup2: false,
        })
    }

    pub(super) fn require_cgroup2(host: &HostCgroup) -> Result<(), SysError> {
        #[cfg(test)]
        if host.test_force_cgroup2 || host.test_fixture {
            return Ok(());
        }
        check_cgroup2_fd(host.root.as_fd())
    }

    fn check_cgroup2_fd(fd: std::os::fd::BorrowedFd<'_>) -> Result<(), SysError> {
        cgroup2_from(fstatfs(fd).map(|stat| i128::from(stat.f_type)))
    }

    pub(super) fn cgroup2_from(magic: Result<i128, rustix::io::Errno>) -> Result<(), SysError> {
        let magic = rustix_result(magic, "fstatfs cgroup root")?;
        if magic == CGROUP2_MAGIC {
            Ok(())
        } else {
            Err(SysError::read(
                "/sys/fs/cgroup",
                "the pinned mount is not cgroup2 (hybrid hosts are refused)",
            ))
        }
    }

    pub(super) fn pidfd_cgroup_id(pidfd: std::os::fd::BorrowedFd<'_>) -> Result<u64, SysError> {
        let info = crate::HostSyscalls.pidfd_info(pidfd, crate::PidfdInfo::ATTESTATION_MASK)?;
        require_pidfd_cgroup_id(info.cgroup_id())
    }

    pub(super) fn require_pidfd_cgroup_id(id: Option<u64>) -> Result<u64, SysError> {
        id.filter(|id| *id != 0).ok_or_else(|| {
            SysError::malformed("PIDFD_GET_INFO", "kernel did not return a cgroup id")
        })
    }

    pub(super) fn proc_cgroup(pid: u32) -> Result<Vec<u8>, SysError> {
        io_result(
            std::fs::read(format!("/proc/{pid}/cgroup")),
            "read /proc/<pid>/cgroup",
        )
    }

    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::CLOEXEC);
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK);
    const READ_LIMIT: u64 = 1024 * 1024;

    // Tests fail the n-th fallible step of a host walk in turn, so every
    // early return is reached without a kernel that misbehaves on demand.
    // The hook exists only in test builds; elsewhere `inject` is a no-op.
    #[cfg(test)]
    thread_local! {
        pub(super) static FAIL_AT: std::cell::Cell<Option<usize>> =
            const { std::cell::Cell::new(None) };
    }

    #[cfg(not(test))]
    #[allow(clippy::unnecessary_wraps, reason = "same shape as the test hook")]
    fn inject(_: &'static str) -> Result<(), SysError> {
        Ok(())
    }

    #[cfg(test)]
    fn inject(operation: &'static str) -> Result<(), SysError> {
        FAIL_AT.with(|cell| match cell.get() {
            Some(0) => {
                cell.set(None);
                Err(SysError::os(
                    operation,
                    &std::io::Error::from_raw_os_error(5),
                ))
            }
            Some(n) => {
                cell.set(Some(n.saturating_sub(1)));
                Ok(())
            }
            None => Ok(()),
        })
    }

    fn stat_of(fd: &OwnedFd, operation: &'static str) -> Result<rustix::fs::Stat, SysError> {
        inject(operation)?;
        rustix_result(fstat(fd), operation)
    }

    fn open_dir_at(
        dir: &OwnedFd,
        path: &str,
        operation: &'static str,
    ) -> Result<OwnedFd, SysError> {
        inject(operation)?;
        rustix_result(
            openat2(dir, path, DIR_FLAGS, Mode::empty(), RESOLVE),
            operation,
        )
    }

    fn open_file_at(
        dir: &OwnedFd,
        name: &str,
        operation: &'static str,
    ) -> Result<OwnedFd, SysError> {
        inject(operation)?;
        rustix_result(openat(dir, name, FILE_FLAGS, Mode::empty()), operation)
    }

    pub(super) fn is_missing(error: &SysError) -> bool {
        // ESRCH: a /proc entry whose process was reaped since it was listed.
        [rustix::io::Errno::NOENT, rustix::io::Errno::SRCH]
            .iter()
            .any(|errno| error.os_code() == Some(errno.raw_os_error()))
    }

    pub(super) fn read_fd(
        fd: OwnedFd,
        limit: u64,
        operation: &'static str,
    ) -> Result<Vec<u8>, SysError> {
        inject(operation)?;
        let mut bytes = Vec::new();
        io_result(
            std::fs::File::from(fd).take(limit).read_to_end(&mut bytes),
            operation,
        )?;
        Ok(bytes)
    }

    pub(super) fn cgroup_inode(host: &HostCgroup, path: &str) -> Result<u64, SysError> {
        require_cgroup2(host)?;
        let relative = path.strip_prefix('/').ok_or_else(|| {
            SysError::malformed("/proc/<pid>/cgroup", "unified path is not absolute")
        })?;
        if relative.is_empty() {
            // A container's private cgroup namespace shows its own root as
            // "/". That is the pinned root itself: no scope can be that inode.
            return stat_of(&host.root, "fstat cgroup root").map(|stat| stat.st_ino);
        }
        if relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(SysError::malformed(
                "/proc/<pid>/cgroup",
                "unified path has an unsafe component",
            ));
        }
        let dir = open_dir_at(&host.root, relative, "openat2 cgroup path")?;
        stat_of(&dir, "fstat cgroup path").map(|stat| stat.st_ino)
    }

    pub(super) fn peer_alive(pidfd: std::os::fd::BorrowedFd<'_>) -> Result<bool, SysError> {
        use rustix::event::{PollFd, PollFlags, Timespec, poll};
        let mut fds = [PollFd::from_borrowed_fd(
            pidfd,
            PollFlags::IN | PollFlags::HUP | PollFlags::ERR,
        )];
        let timeout = Timespec::default();
        rustix_result(poll(&mut fds, Some(&timeout)), "poll(pidfd)").map(|_| {
            let [polled] = &fds;
            polled.revents().is_empty()
        })
    }

    pub(super) fn scope_names(host: &HostCgroup) -> Result<Vec<String>, SysError> {
        let dir = sessions_dir(Some(host))?;
        names_from(Dir::read_from(&dir).map(|entries| {
            entries.map(|entry| entry.map(|entry| entry.file_name().to_bytes().to_vec()))
        }))
    }

    pub(super) fn names_from<I: Iterator<Item = Result<Vec<u8>, rustix::io::Errno>>>(
        entries: Result<I, rustix::io::Errno>,
    ) -> Result<Vec<String>, SysError> {
        let mut names = Vec::new();
        for entry in rustix_result(entries, "list session records")? {
            let entry = rustix_result(entry, "read session record name")?;
            if let Ok(name) = std::str::from_utf8(&entry)
                && is_record_name(name)
            {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    pub(super) fn scope_facts(
        host: &HostCgroup,
        name: &str,
        id: u64,
        with_processes: bool,
    ) -> Result<Option<ScopeFacts>, SysError> {
        if !valid_scope_name(name) {
            return Ok(None);
        }
        require_cgroup2(host)?;
        let slice = open_dir_at(&host.root, "xudo.slice", "openat2 xudo.slice")?;
        let slice_stat = stat_of(&slice, "fstat xudo.slice")?;
        let slice_procs = stat_of(
            &open_file_at(&slice, "cgroup.procs", "open xudo.slice cgroup.procs")?,
            "fstat xudo.slice cgroup.procs",
        )?;
        if !test_mode(host)
            && !trusted_cgroup_directory(
                slice_stat.st_uid,
                slice_stat.st_mode,
                slice_procs.st_uid,
                slice_procs.st_mode,
            )
        {
            return Ok(None);
        }
        let dir = match open_dir_at(&slice, name, "openat2 scope") {
            Ok(fd) => fd,
            Err(error) if is_missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let stat = stat_of(&dir, "fstat scope")?;
        // Identity first: a scope that is not the peer's is nothing of ours to
        // read, however it is owned or whatever state its files are in.
        if stat.st_ino != id {
            return Ok(None);
        }
        let (procs_stat, procs) = read_text(&dir, "cgroup.procs")?;
        let (_, events) = read_text(&dir, "cgroup.events")?;
        let populated = events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
            .is_some_and(|value| value == "1");
        let mut processes = Vec::new();
        for line in procs.lines().filter(|_| with_processes) {
            let pid = line
                .parse::<u32>()
                .map_err(|_| SysError::malformed("cgroup.procs", "invalid process id"))?;
            match read_starttime(pid) {
                Ok(starttime) => processes.push((pid, starttime)),
                // Exited (ENOENT) or reaped (ESRCH) since the list was read.
                Err(error) if is_missing(&error) => {}
                Err(error) => return Err(error),
            }
        }
        let record_name = name.strip_suffix(".scope").unwrap_or_default();
        let record = read_record(host, record_name)?;
        let (record, record_owner, record_mode, record_nlink) = match record {
            Some(file) => (Some(file.bytes), file.owner, file.mode, file.nlink),
            None => (None, 0, 0, 0),
        };
        Ok(Some(ScopeFacts {
            cgroup2: true,
            inode: stat.st_ino,
            owner: stat.st_uid,
            mode: stat.st_mode,
            procs_owner: procs_stat.st_uid,
            procs_mode: procs_stat.st_mode,
            populated,
            record,
            record_owner,
            record_mode,
            record_nlink,
            processes,
        }))
    }

    fn valid_scope_name(name: &str) -> bool {
        name.strip_suffix(".scope").is_some_and(is_record_name)
    }

    pub(super) fn trusted_cgroup_directory(
        owner: u32,
        mode: u32,
        procs_owner: u32,
        procs_mode: u32,
    ) -> bool {
        owner == 0 && mode & 0o022 == 0 && procs_owner == 0 && procs_mode & 0o022 == 0
    }

    /// One open per file: the stat and the bytes describe the same inode.
    pub(super) fn read_text(
        dir: &OwnedFd,
        name: &str,
    ) -> Result<(rustix::fs::Stat, String), SysError> {
        let fd = open_file_at(dir, name, "open cgroup file")?;
        let stat = stat_of(&fd, "fstat cgroup file")?;
        let bytes = read_fd(fd, READ_LIMIT, "read cgroup file")?;
        let text = String::from_utf8(bytes)
            .map_err(|_| SysError::malformed("cgroup file", "not UTF-8"))?;
        Ok((stat, text))
    }

    /// A committed record's bytes with the stat of the descriptor they came
    /// from; whether to trust them is `scope_status`'s decision.
    pub(super) struct RecordFile {
        pub(super) bytes: Vec<u8>,
        pub(super) owner: u32,
        pub(super) mode: u32,
        pub(super) nlink: u64,
    }

    // The width of st_nlink differs by architecture (u64 on x86_64, u32 on aarch64), so the widening is needed on one and "useless" on the other.
    #[allow(clippy::useless_conversion)]
    pub(super) fn read_record(
        host: &HostCgroup,
        name: &str,
    ) -> Result<Option<RecordFile>, SysError> {
        let dir = sessions_dir(Some(host))?;
        let fd = match open_file_at(&dir, name, "open committed record") {
            Ok(fd) => fd,
            Err(error) if is_missing(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let stat = stat_of(&fd, "fstat committed record")?;
        // Never read a FIFO or device a writer planted under a record name.
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Ok(None);
        }
        Ok(Some(RecordFile {
            bytes: read_fd(fd, 64 * 1024, "read committed record")?,
            owner: stat.st_uid,
            mode: stat.st_mode,
            nlink: u64::from(stat.st_nlink),
        }))
    }

    pub(super) fn sessions_dir(host: Option<&HostCgroup>) -> Result<OwnedFd, SysError> {
        #[cfg(test)]
        if let Some(dir) = host.and_then(|host| host.test_records.as_ref()) {
            inject("duplicate session records")?;
            return rustix_result(
                rustix::io::fcntl_dupfd_cloexec(dir, 3),
                "duplicate session records",
            );
        }
        sessions_dir_from(
            host,
            rustix_result(
                open_path("/run", DIR_FLAGS | OFlags::NOFOLLOW, Mode::empty()),
                "open /run",
            ),
        )
    }

    pub(super) fn sessions_dir_from(
        host: Option<&HostCgroup>,
        run: Result<OwnedFd, SysError>,
    ) -> Result<OwnedFd, SysError> {
        let run = run?;
        sessions_dir_at(&run, host)
    }

    pub(super) fn sessions_dir_at(
        run: &OwnedFd,
        host: Option<&HostCgroup>,
    ) -> Result<OwnedFd, SysError> {
        let test_fixture = host.is_some_and(test_mode);
        let xudo = open_dir_at(run, "xudo", "openat2 /run/xudo")?;
        let xudo_stat = stat_of(&xudo, "fstat /run/xudo")?;
        check_session_directory(
            "/run/xudo",
            xudo_stat.st_uid,
            xudo_stat.st_mode,
            false,
            test_fixture,
        )?;
        let sessions = open_dir_at(&xudo, "sessions", "openat2 session records")?;
        validate_sessions_directory(sessions, test_fixture)
    }

    pub(super) fn validate_sessions_directory(
        sessions: OwnedFd,
        test_fixture: bool,
    ) -> Result<OwnedFd, SysError> {
        let stat = stat_of(&sessions, "fstat session records")?;
        check_session_directory(
            "/run/xudo/sessions",
            stat.st_uid,
            stat.st_mode,
            true,
            test_fixture,
        )?;
        Ok(sessions)
    }

    pub(super) fn check_session_directory(
        path: &str,
        owner: u32,
        mode: u32,
        root_only: bool,
        test_fixture: bool,
    ) -> Result<(), SysError> {
        if test_fixture {
            return Ok(());
        }
        let untrusted = if root_only {
            owner != 0 || mode & 0o077 != 0
        } else {
            owner != 0 || mode & 0o022 != 0
        };
        if untrusted {
            let reason = if root_only {
                "directory is not root-only"
            } else {
                "directory is not root-owned and protected"
            };
            return Err(SysError::read(path, reason));
        }
        Ok(())
    }

    pub(super) fn read_starttime(pid: u32) -> Result<u64, SysError> {
        inject("read scope process stat")?;
        let bytes = io_result(
            std::fs::read(format!("/proc/{pid}/stat")),
            "read scope process stat",
        )?;
        starttime_of(&bytes)
    }

    pub(super) fn starttime_of(bytes: &[u8]) -> Result<u64, SysError> {
        crate::parse_stat("/proc/<pid>/stat", bytes).map(|parsed| parsed.starttime)
    }

    // The ownership checks are never off outside this crate's own tests.
    #[cfg(test)]
    pub(super) fn test_mode(host: &HostCgroup) -> bool {
        host.test_fixture
    }

    #[cfg(not(test))]
    pub(super) fn test_mode(_: &HostCgroup) -> bool {
        false
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::os::fd::BorrowedFd;

    use super::{HostCgroup, ScopeFacts};
    use crate::SysError;

    pub(super) fn open() -> Result<HostCgroup, SysError> {
        Err(SysError::unsupported("cgroup2 attestation"))
    }
    pub(super) fn require_cgroup2(_: &HostCgroup) -> Result<(), SysError> {
        Err(SysError::unsupported("cgroup2 fstatfs"))
    }
    pub(super) fn pidfd_cgroup_id(_: BorrowedFd<'_>) -> Result<u64, SysError> {
        Err(SysError::unsupported("PIDFD_GET_INFO"))
    }
    pub(super) fn proc_cgroup(_: u32) -> Result<Vec<u8>, SysError> {
        Err(SysError::unsupported("/proc cgroup read"))
    }
    pub(super) fn cgroup_inode(_: &HostCgroup, _: &str) -> Result<u64, SysError> {
        Err(SysError::unsupported("cgroup fstat"))
    }
    pub(super) fn peer_alive(_: BorrowedFd<'_>) -> Result<bool, SysError> {
        Err(SysError::unsupported("pidfd poll"))
    }
    pub(super) fn scope_facts(
        _: &HostCgroup,
        _: &str,
        _: u64,
        _: bool,
    ) -> Result<Option<ScopeFacts>, SysError> {
        Err(SysError::unsupported("scope status"))
    }
    pub(super) fn scope_names(_: &HostCgroup) -> Result<Vec<String>, SysError> {
        Err(SysError::unsupported("session record listing"))
    }
}

/// Reads the peer's cgroup id using the kernel ladder, failing closed.
///
/// # Errors
///
/// Returns an error for every failed read, unsupported mount, disagreeing
/// source, unsupported ioctl errno, or dead pidfd.
pub fn peer_cgroup_id<C: CgroupCalls + ?Sized>(
    calls: &C,
    pid: u32,
    pidfd: BorrowedFd<'_>,
) -> Result<CgroupIdentity, SysError> {
    calls.require_cgroup2()?;
    let ioctl = calls.pidfd_cgroup_id(pidfd);
    let (id, rung, fallback_errno) = match ioctl {
        Ok(info_id) => {
            let path = read_cgroup_path(calls, pid)?;
            let proc_id = calls.cgroup_inode(&path)?;
            if info_id != proc_id {
                return Err(unattested("PIDFD_GET_INFO and /proc cgroup ids disagree"));
            }
            (proc_id, CgroupRung::PidfdInfo, None)
        }
        Err(error) if missing_pidfd_ioctl(&error) => {
            let path = read_cgroup_path(calls, pid)?;
            let proc_id = calls.cgroup_inode(&path)?;
            (proc_id, CgroupRung::ProcFstat, error.os_code())
        }
        Err(error) => return Err(error),
    };
    if !calls.peer_alive(pidfd)? {
        return Err(unattested("peer exited after its cgroup was read"));
    }
    Ok(CgroupIdentity {
        id,
        rung,
        fallback_errno,
    })
}

/// Reads status by a pinned pid and confirms liveness after the read.
///
/// # Errors
///
/// Returns an error if the status file is malformed or unreadable, or if the
/// process exits before its pidfd check.
pub fn process_security_status<P: crate::PeerCalls + ?Sized>(
    calls: &P,
    pid: u32,
    pidfd: BorrowedFd<'_>,
) -> Result<ProcessSecurityStatus, SysError> {
    let bytes = calls.read_proc(pid, crate::ProcFile::Status)?;
    let status = parse_process_security_status(&bytes)?;
    if calls.has_exited(pidfd)? {
        return Err(unattested("process exited after status was read"));
    }
    Ok(status)
}

/// Parses the two status fields used by the watcher eligibility check.
///
/// # Errors
///
/// Returns an error when either field is absent, duplicated, or malformed.
pub fn parse_process_security_status(bytes: &[u8]) -> Result<ProcessSecurityStatus, SysError> {
    let mut tracer = None;
    let mut no_new_privs = None;
    for line in bytes.split(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(b"TracerPid:") {
            if tracer.is_some() {
                return Err(SysError::malformed(
                    "/proc/<pid>/status",
                    "duplicate TracerPid",
                ));
            }
            tracer = Some(parse_status_number(value, "TracerPid")?);
        } else if let Some(value) = line.strip_prefix(b"NoNewPrivs:") {
            if no_new_privs.is_some() {
                return Err(SysError::malformed(
                    "/proc/<pid>/status",
                    "duplicate NoNewPrivs",
                ));
            }
            no_new_privs = Some(match parse_status_number(value, "NoNewPrivs")? {
                0 => false,
                1 => true,
                _ => {
                    return Err(SysError::malformed(
                        "/proc/<pid>/status",
                        "NoNewPrivs is not 0 or 1",
                    ));
                }
            });
        }
    }
    Ok(ProcessSecurityStatus {
        tracer_pid: tracer
            .ok_or_else(|| SysError::malformed("/proc/<pid>/status", "no TracerPid"))?,
        no_new_privs: no_new_privs
            .ok_or_else(|| SysError::malformed("/proc/<pid>/status", "no NoNewPrivs"))?,
    })
}

fn parse_status_number(bytes: &[u8], field: &str) -> Result<u32, SysError> {
    let value = bytes
        .split(u8::is_ascii_whitespace)
        .find(|part| !part.is_empty())
        .and_then(|part| std::str::from_utf8(part).ok())
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| SysError::malformed("/proc/<pid>/status", format!("invalid {field}")))?;
    Ok(value)
}

/// Opens a pidfd, then checks that the pinned process still has `expected_parent`.
/// The `PPid` read follows the pin, and the final poll catches pid reuse.
///
/// # Errors
///
/// Returns an error when the pidfd cannot be opened, the proc stat is
/// malformed, the parent differs, or the pinned process exits.
pub fn verify_parent_pid<P: crate::PeerCalls + ?Sized>(
    calls: &P,
    pid: u32,
    expected_parent: u32,
) -> Result<crate::ProcStat, SysError> {
    let pidfd = calls.pidfd_open(pid)?;
    let bytes = calls.read_proc(pid, crate::ProcFile::Stat)?;
    let stat = crate::parse_stat("/proc/<pid>/stat", &bytes)?;
    if stat.pid != pid || stat.ppid != expected_parent {
        return Err(unattested("pinned process has a different parent"));
    }
    if calls.has_exited(pidfd.as_fd())? {
        return Err(unattested("pinned process exited during the parent check"));
    }
    Ok(stat)
}

fn read_cgroup_path<C: CgroupCalls + ?Sized>(calls: &C, pid: u32) -> Result<String, SysError> {
    let bytes = calls.proc_cgroup(pid)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| SysError::malformed(format!("{pid}/cgroup"), "not UTF-8"))?;
    let path = parse_cgroup(text)
        .ok_or_else(|| SysError::malformed(format!("{pid}/cgroup"), "no unified cgroup path"))?;
    Ok(path.as_str().to_owned())
}

/// A committed record is trusted only as a root-owned, private, single-link
/// regular file.
fn trusted_record(owner: u32, mode: u32, nlink: u64) -> bool {
    owner == 0 && mode & 0o170_000 == 0o100_000 && mode.trailing_zeros() >= 6 && nlink == 1
}

/// Whether `name` is a committed `agent-<32 hex>` or `watch-<32 hex>` record
/// name. `pending-*` names and anything else carry no authority.
fn is_record_name(name: &str) -> bool {
    let Some((kind, suffix)) = name.split_once('-') else {
        return false;
    };
    (kind == "agent" || kind == "watch")
        && suffix.len() == 32
        && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Finds a live agent/watch scope by cgroup id, never by a name alone.
///
/// # Errors
///
/// Returns an error when candidate names or scope descriptors cannot be read.
pub fn scope_status(
    calls: &dyn CgroupCalls,
    id: u64,
    uid: u32,
    parse_record: &dyn Fn(&[u8], &str) -> Option<RecordIdentity>,
) -> Result<Option<Scope>, SysError> {
    if id == 0 || uid == 0 {
        return Ok(None);
    }
    for kind in [ScopeKind::Agent, ScopeKind::Watch] {
        let prefix = match kind {
            ScopeKind::Agent => "agent-",
            ScopeKind::Watch => "watch-",
        };
        for record_name in calls.scope_names()? {
            if !record_name.starts_with(prefix) || !is_record_name(&record_name) {
                continue;
            }
            let name = format!("{record_name}.scope");
            let Some(facts) = calls.scope_facts(&name, id, kind == ScopeKind::Watch)? else {
                continue;
            };
            if !facts.cgroup2
                || facts.inode != id
                || facts.owner != 0
                || facts.mode & 0o022 != 0
                || facts.procs_owner != 0
                || facts.procs_mode & 0o022 != 0
                || !facts.populated
            {
                continue;
            }
            if !trusted_record(facts.record_owner, facts.record_mode, facts.record_nlink) {
                continue;
            }
            let Some(record_bytes) = facts.record else {
                continue;
            };
            let Some(record) = parse_record(&record_bytes, &record_name) else {
                continue;
            };
            if record.cgroup_id != id
                || record.kind != kind
                || record.uid != uid
                || !record.current_boot
                || !record.live
            {
                continue;
            }
            if kind == ScopeKind::Watch
                && (facts.processes.len() != 1
                    || facts.processes.first().copied() != Some(record.process))
            {
                continue;
            }
            return Ok(Some(Scope {
                kind,
                name,
                record: record_bytes,
            }));
        }
    }
    Ok(None)
}

fn missing_pidfd_ioctl(error: &SysError) -> bool {
    [rustix::io::Errno::NOTTY, rustix::io::Errno::INVAL]
        .iter()
        .any(|errno| error.os_code() == Some(errno.raw_os_error()))
}

fn unattested(reason: &str) -> SysError {
    SysError::Os {
        operation: "attest peer cgroup".to_owned(),
        code: None,
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::os::fd::AsFd;
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    #[cfg(target_os = "linux")]
    use std::path::PathBuf;

    use super::*;

    #[derive(Debug)]
    struct FakeCgroup {
        cgroup2: bool,
        info: RefCell<Result<u64, SysError>>,
        proc: RefCell<Result<Vec<u8>, SysError>>,
        inode: RefCell<Result<u64, SysError>>,
        alive: RefCell<Result<bool, SysError>>,
        scopes: BTreeMap<String, ScopeFacts>,
        names: Vec<String>,
        fail_scopes: bool,
        fail_names: bool,
    }

    impl FakeCgroup {
        fn path_result(
            info: Result<u64, SysError>,
            proc: &str,
            inode: Result<u64, SysError>,
            alive: bool,
        ) -> Self {
            Self {
                cgroup2: true,
                info: RefCell::new(info),
                proc: RefCell::new(Ok(proc.as_bytes().to_vec())),
                inode: RefCell::new(inode),
                alive: RefCell::new(Ok(alive)),
                scopes: BTreeMap::new(),
                names: Vec::new(),
                fail_scopes: false,
                fail_names: false,
            }
        }
    }

    const AGENT_RECORD_NAME: &str = "agent-0123456789abcdef0123456789abcdef";
    const WATCH_RECORD_NAME: &str = "watch-0123456789abcdef0123456789abcdef";

    fn record(kind: &str, cgroup_id: u64) -> Vec<u8> {
        format!(
            "{{\"kind\":\"{kind}\",\"uid\":1000,\"label\":\"test\",\"boot_id\":\"boot\",\"created_at_boottime_ms\":1,\"deadline\":200,\"pid\":42,\"starttime\":73,\"cgroup_id\":{cgroup_id}}}"
        )
        .into_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    fn scope_fake(
        kind: &str,
        inode: u64,
        record_id: u64,
        owner: u32,
        procs_mode: u32,
        populated: bool,
        processes: Vec<(u32, u64)>,
        with_record: bool,
    ) -> FakeCgroup {
        let record_name = if kind == "agent" {
            AGENT_RECORD_NAME
        } else {
            WATCH_RECORD_NAME
        };
        let name = format!("{record_name}.scope");
        let mut fake = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::NOTTY)),
            "0::/xudo.slice/placeholder.scope\n",
            Ok(inode),
            true,
        );
        fake.names.push(record_name.to_owned());
        fake.scopes.insert(
            name,
            ScopeFacts {
                cgroup2: true,
                inode,
                owner,
                mode: 0o40_755,
                procs_owner: 0,
                procs_mode,
                populated,
                record: with_record.then(|| record(kind, record_id)),
                record_owner: 0,
                record_mode: 0o100_600,
                record_nlink: 1,
                processes,
            },
        );
        fake
    }

    fn parse_record(bytes: &[u8], name: &str) -> Option<RecordIdentity> {
        let (kind, scope_kind) = if name == AGENT_RECORD_NAME {
            ("agent", ScopeKind::Agent)
        } else if name == WATCH_RECORD_NAME {
            ("watch", ScopeKind::Watch)
        } else {
            return None;
        };
        if bytes != record(kind, 1) {
            return None;
        }
        Some(RecordIdentity {
            kind: scope_kind,
            uid: 1000,
            current_boot: true,
            live: true,
            process: (42, 73),
            cgroup_id: 1,
        })
    }

    impl CgroupCalls for FakeCgroup {
        fn require_cgroup2(&self) -> Result<(), SysError> {
            if self.cgroup2 {
                Ok(())
            } else {
                Err(SysError::read("/sys/fs/cgroup", "fstatfs was not cgroup2"))
            }
        }
        fn pidfd_cgroup_id(&self, _pidfd: BorrowedFd<'_>) -> Result<u64, SysError> {
            self.info.borrow().clone()
        }
        fn proc_cgroup(&self, _pid: u32) -> Result<Vec<u8>, SysError> {
            self.proc.borrow().clone()
        }
        fn cgroup_inode(&self, _path: &str) -> Result<u64, SysError> {
            self.inode.borrow().clone()
        }
        fn peer_alive(&self, _pidfd: BorrowedFd<'_>) -> Result<bool, SysError> {
            self.alive.borrow().clone()
        }
        fn scope_facts(
            &self,
            name: &str,
            _id: u64,
            _with_processes: bool,
        ) -> Result<Option<ScopeFacts>, SysError> {
            if self.fail_scopes {
                return Err(SysError::read("scope", "unreadable"));
            }
            Ok(self.scopes.get(name).cloned())
        }
        fn scope_names(&self) -> Result<Vec<String>, SysError> {
            if self.fail_names {
                return Err(SysError::read("records", "unreadable"));
            }
            Ok(self.names.clone())
        }
    }

    fn error(errno: rustix::io::Errno) -> SysError {
        SysError::os("PIDFD_GET_INFO", &errno.into())
    }

    fn fd() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[cfg(target_os = "linux")]
    fn fixture_host() -> HostCgroup {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let root = rustix::fs::open(
            fixture.join("cgroup"),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let records = rustix::fs::open(
            fixture.join("sessions"),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        HostCgroup {
            root,
            test_records: Some(records),
            test_fixture: true,
            test_force_cgroup2: false,
        }
    }

    #[cfg(target_os = "linux")]
    fn open_dir(path: &std::path::Path) -> std::os::fd::OwnedFd {
        rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_error_adapters_preserve_failures_and_successes() {
        assert!(imp::rustix_result(Ok(7), "test").is_ok());
        assert_eq!(
            imp::rustix_result::<()>(Err(rustix::io::Errno::NOENT), "test")
                .unwrap_err()
                .os_code(),
            Some(rustix::io::Errno::NOENT.raw_os_error())
        );
        assert!(imp::io_result(Ok(7), "test").is_ok());
        assert!(matches!(
            imp::io_result::<()>(Err(std::io::Error::other("fixture")), "test"),
            Err(SysError::Os { operation, .. }) if operation == "test"
        ));
        assert!(imp::finish_cgroup_root(Err(rustix::io::Errno::NOENT)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_host_read_failures_are_closed() {
        let host = fixture_host();
        assert!(imp::cgroup_inode(&host, "/missing.scope").is_err());
        let slice = open_dir(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cgroup/xudo.slice"),
        );
        assert!(imp::read_text(&slice, "missing").is_err());

        let temporary =
            PathBuf::from("/tmp").join(format!("xudo-e1-invalid-utf8-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temporary);
        std::fs::create_dir_all(&temporary).unwrap();
        std::fs::write(temporary.join("invalid"), [0xff]).unwrap();
        let dir = open_dir(&temporary);
        assert!(imp::read_text(&dir, "invalid").is_err());
        std::fs::remove_dir_all(temporary).unwrap();

        let missing_slice =
            PathBuf::from("/tmp").join(format!("xudo-e1-no-slice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&missing_slice);
        std::fs::create_dir_all(&missing_slice).unwrap();
        let mut host = fixture_host();
        host.root = open_dir(&missing_slice);
        assert!(
            imp::scope_facts(
                &host,
                "agent-0123456789abcdef0123456789abcdef.scope",
                1,
                true
            )
            .is_err()
        );
        std::fs::remove_dir_all(missing_slice).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_trait_methods_list_records_and_resolve_scope_facts() {
        let host = fixture_host();
        assert!(
            CgroupCalls::scope_names(&host)
                .unwrap()
                .contains(&AGENT_RECORD_NAME.to_owned())
        );
        assert!(
            CgroupCalls::scope_facts(
                &host,
                "agent-0123456789abcdef0123456789abcdef.scope",
                fixture_scope_inode(),
                false,
            )
            .unwrap()
            .is_some()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_session_directories_are_opened_beneath_the_run_descriptor() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let run = open_dir(&fixture.join("run"));
        let host = fixture_host();
        let sessions = imp::sessions_dir_from(Some(&host), Ok(run)).unwrap();
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", sessions.as_raw_fd()))
            .unwrap()
            .count();
        assert_eq!(entries, 1);
        let fixture_sessions = open_dir(&fixture.join("run/xudo/sessions"));
        assert!(imp::validate_sessions_directory(fixture_sessions, false).is_err());
        let fixture_sessions = open_dir(&fixture.join("run/xudo/sessions"));
        assert!(imp::validate_sessions_directory(fixture_sessions, true).is_ok());
        assert!(imp::sessions_dir_from(None, Ok(open_dir(&fixture.join("run")))).is_err());
        assert!(
            imp::sessions_dir_from(Some(&host), Ok(open_dir(&fixture.join("cgroup")))).is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_process_lists_are_pinned_and_starttimes_are_read() {
        let fixture = PathBuf::from("/tmp").join(format!("xudo-e1-cgroup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixture);
        let root_path = fixture.join("cgroup");
        let scope_dir = root_path
            .join("xudo.slice")
            .join("agent-0123456789abcdef0123456789abcdef.scope");
        std::fs::create_dir_all(&scope_dir).unwrap();
        std::fs::write(root_path.join("xudo.slice/cgroup.procs"), b"").unwrap();
        std::fs::write(
            scope_dir.join("cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        std::fs::write(scope_dir.join("cgroup.events"), b"populated 1\nfrozen 0\n").unwrap();
        std::os::unix::fs::symlink(
            &scope_dir,
            root_path
                .join("xudo.slice")
                .join("agent-ffffffffffffffffffffffffffffffff.scope"),
        )
        .unwrap();
        let mut host = fixture_host();
        host.root = open_dir(&root_path);
        let name = "agent-0123456789abcdef0123456789abcdef.scope";
        let id = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&scope_dir).unwrap());
        let facts = imp::scope_facts(&host, name, id, true).unwrap().unwrap();
        assert_eq!(facts.processes.len(), 1);
        // Agent scopes never pay for the process list.
        assert!(
            imp::scope_facts(&host, name, id, false)
                .unwrap()
                .unwrap()
                .processes
                .is_empty()
        );
        every_step_failing(&|| imp::scope_facts(&host, name, id, true).map(drop));
        // A process that left the scope after the list was read is dropped.
        std::fs::write(
            scope_dir.join("cgroup.procs"),
            format!("{}\n{}\n", std::process::id(), u32::MAX),
        )
        .unwrap();
        assert_eq!(
            imp::scope_facts(&host, name, id, true)
                .unwrap()
                .unwrap()
                .processes
                .len(),
            1
        );
        std::fs::write(
            scope_dir.join("cgroup.procs"),
            std::process::id().to_string(),
        )
        .unwrap();
        let process = facts.processes.first().copied().unwrap();
        assert_eq!(process.0, std::process::id());
        assert!(process.1 > 0);
        assert!(imp::read_starttime(u32::MAX).is_err());
        assert!(
            imp::scope_facts(
                &host,
                "agent-ffffffffffffffffffffffffffffffff.scope",
                id,
                true
            )
            .is_err()
        );
        std::fs::write(scope_dir.join("cgroup.procs"), b"not-a-pid\n").unwrap();
        assert!(imp::scope_facts(&host, name, id, true).is_err());
        // Another user's scope that is broken is skipped before its files are
        // read, so it cannot fail the check for the scope that matches.
        assert!(
            imp::scope_facts(&host, name, id.wrapping_add(1), true)
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(fixture).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_scope_refuses_a_non_root_slice_and_a_non_root_record() {
        let host = fixture_host();
        assert!(imp::test_mode(&host));
        // A directory under a record name is no record.
        assert!(
            imp::read_record(&host, "watch-ffffffffffffffffffffffffffffffff")
                .unwrap()
                .is_none()
        );
        assert!(
            imp::read_record(&host, "agent-ffffffffffffffffffffffffffffffff")
                .unwrap()
                .is_none()
        );
        let untrusted = HostCgroup {
            root: host.root,
            test_records: host.test_records,
            test_fixture: false,
            test_force_cgroup2: true,
        };
        assert!(!imp::test_mode(&untrusted));
        assert!(
            imp::scope_facts(
                &untrusted,
                "agent-0123456789abcdef0123456789abcdef.scope",
                fixture_scope_inode(),
                true
            )
            .unwrap()
            .is_none()
        );
        // The host reports what it saw; scope_status judges the ownership.
        let file = imp::read_record(&untrusted, "agent-0123456789abcdef0123456789abcdef")
            .unwrap()
            .unwrap();
        assert_ne!(file.owner, 0);
        assert_eq!(file.nlink, 1);
        let _ = imp::sessions_dir(None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_fifo_record_is_refused() {
        let dir = PathBuf::from("/tmp").join(format!("xudo-e1-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            dir.join(AGENT_RECORD_NAME),
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_bits_truncate(0o600),
            0,
        )
        .unwrap();
        let mut host = fixture_host();
        host.test_records = Some(open_dir(&dir));
        // Must return at once: opening a FIFO for reading may not block, and
        // its (empty) contents are never read.
        assert!(
            imp::read_record(&host, AGENT_RECORD_NAME)
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(dir).unwrap();
        assert!(!trusted_record(0, 0o010_600, 1));
    }

    #[test]
    fn a_record_with_loose_owner_or_mode_is_refused_by_scope_status() {
        for (owner, mode, nlink) in [
            (1000, 0o100_600, 1),
            (0, 0o100_640, 1),
            (0, 0o100_606, 1),
            (0, 0o100_600, 2),
            (0, 0o010_600, 1),
            (0, 0o120_600, 1),
        ] {
            let mut fake = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
            let facts = fake.scopes.values_mut().next().unwrap();
            facts.record_owner = owner;
            facts.record_mode = mode;
            facts.record_nlink = nlink;
            assert!(
                scope_status(&fake, 1, 1000, &parse_record)
                    .unwrap()
                    .is_none(),
                "{owner} {mode:o} {nlink}"
            );
        }
        let fake = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_reaped_process_in_another_users_scope_does_not_fail_the_check() {
        // The other scope's inode differs: the host returns None before it
        // reads a process, so a reaped pid there is not this peer's error.
        let mut fake = scope_fake("agent", 2, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        fake.names.push(WATCH_RECORD_NAME.to_owned());
        fake.scopes.insert(
            format!("{WATCH_RECORD_NAME}.scope"),
            fake.scopes.values().next().unwrap().clone(),
        );
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_scope_that_is_not_the_peers_is_never_read() {
        // Inode first: this scope's record is unreadable, and still no error.
        let host = fixture_host();
        let name = format!("{AGENT_RECORD_NAME}.scope");
        let id = fixture_scope_inode();
        assert!(
            imp::scope_facts(&host, &name, id.wrapping_add(1), true)
                .unwrap()
                .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_scope_without_a_committed_record_carries_no_record_facts() {
        let dir = PathBuf::from("/tmp").join(format!("xudo-e1-norecord-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut host = fixture_host();
        host.test_records = Some(open_dir(&dir));
        let name = format!("{AGENT_RECORD_NAME}.scope");
        let facts = imp::scope_facts(&host, &name, fixture_scope_inode(), false)
            .unwrap()
            .unwrap();
        assert!(facts.record.is_none());
        assert_eq!(
            (facts.record_owner, facts.record_mode, facts.record_nlink),
            (0, 0, 0)
        );
        // A directory read as a file fails; the error is not swallowed.
        assert!(imp::read_fd(open_dir(&dir), 16, "read directory").is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_reaped_pid_is_gone_not_an_error() {
        let esrch = SysError::os("x", &std::io::Error::from_raw_os_error(3));
        assert!(imp::is_missing(&esrch));
        let eio = SysError::os("x", &std::io::Error::from_raw_os_error(5));
        assert!(!imp::is_missing(&eio));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_fstatfs_failure_keeps_its_errno() {
        let error = imp::cgroup2_from(Err(rustix::io::Errno::BADF)).unwrap_err();
        assert_eq!(
            error.os_code(),
            Some(rustix::io::Errno::BADF.raw_os_error())
        );
        assert!(imp::cgroup2_from(Ok(0x6367_7270)).is_ok());
        assert!(imp::cgroup2_from(Ok(0)).is_err());
    }

    #[cfg(target_os = "linux")]
    fn fixture_scope_inode() -> u64 {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/cgroup/xudo.slice")
            .join(format!("{AGENT_RECORD_NAME}.scope"));
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(path).unwrap())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_cgroup_id_must_be_present_and_nonzero() {
        assert!(imp::require_pidfd_cgroup_id(Some(42)).is_ok());
        assert!(imp::require_pidfd_cgroup_id(None).is_err());
        assert!(imp::require_pidfd_cgroup_id(Some(0)).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn record_reads_refuse_paths_that_are_not_a_single_component() {
        let host = fixture_host();
        assert!(imp::read_record(&host, "agent-0123456789abcdef0123456789abcdef/child").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup_directory_owner_and_write_bits_are_checked_together() {
        assert!(imp::trusted_cgroup_directory(0, 0o40_755, 0, 0o100_644));
        assert!(!imp::trusted_cgroup_directory(1000, 0o40_755, 0, 0o100_644));
        assert!(!imp::trusted_cgroup_directory(0, 0o40_775, 0, 0o100_644));
        assert!(!imp::trusted_cgroup_directory(0, 0o40_755, 1000, 0o100_644));
        assert!(!imp::trusted_cgroup_directory(0, 0o40_755, 0, 0o100_664));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_directory_owner_and_mode_are_checked_for_both_levels() {
        assert!(imp::check_session_directory("/run/xudo", 0, 0o40_755, false, false).is_ok());
        assert!(imp::check_session_directory("/run/xudo", 1000, 0o40_755, false, false).is_err());
        assert!(imp::check_session_directory("/run/xudo", 0, 0o40_775, false, false).is_err());
        assert!(
            imp::check_session_directory("/run/xudo/sessions", 0, 0o40_700, true, false).is_ok()
        );
        assert!(
            imp::check_session_directory("/run/xudo/sessions", 0, 0o40_755, true, false).is_err()
        );
        assert!(
            imp::check_session_directory("/run/xudo/sessions", 1000, 0o40_700, true, false)
                .is_err()
        );
        assert!(imp::check_session_directory("/run/xudo", 1000, 0o40_777, false, true).is_ok());
    }

    #[test]
    fn pidfd_get_info_failing_enotty_selects_the_proc_rung() {
        let calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::NOTTY)),
            "0::/xudo.slice/agent-a.scope\n",
            Ok(42),
            true,
        );
        let (a, _b) = fd();
        assert_eq!(
            peer_cgroup_id(&calls, 9, a.as_fd()).unwrap().fallback_errno,
            Some(25)
        );
    }

    #[test]
    fn pidfd_get_info_failing_einval_selects_the_proc_rung() {
        let calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::INVAL)),
            "0::/xudo.slice/agent-a.scope\n",
            Ok(42),
            true,
        );
        let (a, _b) = fd();
        assert_eq!(
            peer_cgroup_id(&calls, 9, a.as_fd()).unwrap().fallback_errno,
            Some(22)
        );
    }

    #[test]
    fn any_other_pidfd_get_info_errno_is_unattested() {
        let calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::PERM)),
            "0::/xudo.slice/a.scope\n",
            Ok(42),
            true,
        );
        let (a, _b) = fd();
        assert_eq!(
            peer_cgroup_id(&calls, 9, a.as_fd()).unwrap_err().os_code(),
            Some(1)
        );
    }

    #[test]
    fn the_two_cgroup_sources_disagreeing_is_unattested() {
        let calls = FakeCgroup::path_result(Ok(41), "0::/xudo.slice/a.scope\n", Ok(42), true);
        let (a, _b) = fd();
        assert!(peer_cgroup_id(&calls, 9, a.as_fd()).is_err());
    }

    #[test]
    fn a_reaped_peer_after_the_cgroup_read_is_refused() {
        let calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::NOTTY)),
            "0::/xudo.slice/a.scope\n",
            Ok(42),
            false,
        );
        let (a, _b) = fd();
        assert!(peer_cgroup_id(&calls, 9, a.as_fd()).is_err());
    }

    #[test]
    fn a_hybrid_host_is_refused_by_fstatfs_not_by_the_0_line() {
        let mut calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::NOTTY)),
            "0::/xudo.slice/a.scope\n",
            Ok(42),
            true,
        );
        calls.cgroup2 = false;
        let (a, _b) = fd();
        // The mount magic check runs before the valid-looking proc path is read.
        assert!(peer_cgroup_id(&calls, 9, a.as_fd()).is_err());
    }

    #[test]
    fn a_cgroup_on_a_non_cgroup2_mount_is_refused() {
        let mut calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::NOTTY)),
            "0::/xudo.slice/a.scope\n",
            Ok(42),
            true,
        );
        calls.cgroup2 = false;
        let (a, _b) = fd();
        assert!(peer_cgroup_id(&calls, 9, a.as_fd()).is_err());
    }

    #[test]
    fn a_scope_not_owned_by_root_is_not_an_agent_scope() {
        let fake = scope_fake("agent", 1, 1, 1000, 0o100_644, true, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_group_writable_cgroup_procs_is_not_a_scope() {
        let fake = scope_fake("agent", 1, 1, 0, 0o100_664, true, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_peer_under_a_scope_but_not_in_it_is_not_in_it() {
        let calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::NOTTY)),
            "0::/xudo.slice/agent-x/child\n",
            Ok(2),
            true,
        );
        let (a, _b) = fd();
        assert_eq!(peer_cgroup_id(&calls, 9, a.as_fd()).unwrap().id, 2);
        let scope = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        assert!(
            scope_status(&scope, 2, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_symlinked_scope_component_is_refused() {
        let calls = FakeCgroup::path_result(
            Err(error(rustix::io::Errno::NOTTY)),
            "0::/xudo.slice/agent-x.scope\n",
            Err(SysError::read("scope", "symlink")),
            true,
        );
        let (a, _b) = fd();
        assert!(peer_cgroup_id(&calls, 9, a.as_fd()).is_err());
    }

    #[test]
    fn non_utf8_proc_cgroup_data_is_unattested() {
        let calls = FakeCgroup::path_result(Err(error(rustix::io::Errno::NOTTY)), "", Ok(42), true);
        *calls.proc.borrow_mut() = Ok(vec![0xff]);
        assert!(read_cgroup_path(&calls, 9).is_err());
    }

    #[test]
    fn an_unpopulated_scope_is_not_live() {
        let fake = scope_fake("agent", 1, 1, 0, 0o100_644, false, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_watch_scope_with_a_second_process_is_not_live() {
        let fake = scope_fake(
            "watch",
            1,
            1,
            0,
            0o100_644,
            true,
            vec![(42, 73), (43, 74)],
            true,
        );
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_user_manager_scope_named_like_an_agent_scope_is_not_one() {
        let fake = scope_fake("agent", 1, 1, 1000, 0o100_644, true, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_polkit_authorised_scope_under_the_slice_without_a_record_is_not_an_agent_scope() {
        let fake = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], false);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_polkit_authorised_scope_under_the_slice_without_a_record_is_not_a_watch_scope() {
        let fake = scope_fake("watch", 1, 1, 0, 0o100_644, true, vec![(42, 73)], false);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_scope_recreated_under_a_recorded_name_is_not_an_agent_scope() {
        let fake = scope_fake("agent", 2, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_live_agent_scope_requires_a_matching_committed_record() {
        let fake = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        let scope = scope_status(&fake, 1, 1000, &parse_record).unwrap();
        assert_eq!(scope.map(|scope| scope.kind), Some(ScopeKind::Agent));
    }

    #[test]
    fn a_watch_scope_is_live_only_for_its_single_recorded_process() {
        let fake = scope_fake("watch", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        let scope = scope_status(&fake, 1, 1000, &parse_record).unwrap();
        assert_eq!(scope.map(|scope| scope.kind), Some(ScopeKind::Watch));
    }

    #[test]
    fn an_agent_scope_with_a_record_for_another_instance_is_not_live() {
        let fake = scope_fake("agent", 1, 2, 0, 0o100_644, true, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn scope_status_refuses_zero_identity_and_unresolvable_records() {
        let fake = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        assert!(
            scope_status(&fake, 0, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
        assert!(scope_status(&fake, 1, 0, &parse_record).unwrap().is_none());
        assert!(
            scope_status(&fake, 1, 1000, &|_, _| None)
                .unwrap()
                .is_none()
        );
        let mut missing_scope =
            FakeCgroup::path_result(Err(error(rustix::io::Errno::NOTTY)), "", Ok(1), true);
        missing_scope.names.push(AGENT_RECORD_NAME.to_owned());
        assert!(
            scope_status(&missing_scope, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
        assert!(parse_record(&record("agent", 1), "unrecognized-record").is_none());
        let matching_name = AGENT_RECORD_NAME.to_owned();
        let mismatch = scope_status(&fake, 1, 1000, &|_, name| {
            (name == matching_name).then_some(RecordIdentity {
                kind: ScopeKind::Agent,
                uid: 1000,
                current_boot: true,
                live: true,
                process: (42, 73),
                cgroup_id: 2,
            })
        });
        assert!(mismatch.unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_host_scope_reads_directory_files_and_committed_record() {
        let host = fixture_host();
        let name = format!("{AGENT_RECORD_NAME}.scope");
        let facts = imp::scope_facts(&host, &name, fixture_scope_inode(), false)
            .unwrap()
            .unwrap();
        let expected_record =
            include_bytes!("../tests/fixtures/sessions/agent-0123456789abcdef0123456789abcdef");
        assert!(facts.cgroup2);
        assert!(facts.populated);
        assert_eq!(facts.record.as_deref(), Some(expected_record.as_slice()));
        assert!(
            imp::scope_names(&host)
                .unwrap()
                .contains(&AGENT_RECORD_NAME.to_owned())
        );
        assert_eq!(
            imp::cgroup_inode(&host, &format!("/xudo.slice/{name}")).unwrap(),
            facts.inode
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pinned_host_scope_refuses_unsafe_names_and_missing_components() {
        let host = fixture_host();
        assert!(
            imp::scope_facts(&host, "agent-../x.scope", 1, true)
                .unwrap()
                .is_none()
        );
        assert!(
            imp::scope_facts(
                &host,
                "agent-ffffffffffffffffffffffffffffffff.scope",
                1,
                true
            )
            .unwrap()
            .is_none()
        );
        assert!(imp::cgroup_inode(&host, "/../outside").is_err());
        assert!(imp::cgroup_inode(&host, "relative").is_err());
        assert!(imp::cgroup_inode(&host, "/").is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cgroup_sources_agree_and_print_the_selected_rung() {
        // Docker's linux-test lane currently runs on the host's 7.0 kernel;
        // the 6.8 ENOTTY and 6.12 EINVAL rungs are exercised through FakeCgroup.
        let host = HostCgroup::open().expect("linux-test runs on a cgroup2 kernel");
        let pid = std::process::id();
        let raw_pid = i32::try_from(pid).expect("own pid fits pidfd_open");
        let pid = rustix::process::Pid::from_raw(raw_pid).expect("own pid is positive");
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
            .expect("pidfd_open for this process");
        let identity = peer_cgroup_id(&host, std::process::id(), pidfd.as_fd())
            .expect("both cgroup sources describe this process");
        let path = read_cgroup_path(&host, std::process::id()).expect("read own cgroup path");
        assert_eq!(
            host.cgroup_inode(&path).expect("fstat cgroup directory"),
            identity.id
        );
        println!(
            "linux-test cgroup rung={:?} fallback_errno={:?} cgroup_id={}",
            identity.rung, identity.fallback_errno, identity.id
        );
    }

    #[test]
    fn proc_status_security_fields_are_parsed_strictly() {
        let status =
            parse_process_security_status(b"Name:\tx\nTracerPid:\t0\nNoNewPrivs:\t1\n").unwrap();
        assert_eq!(status.tracer_pid, 0);
        assert!(status.no_new_privs);
        assert!(parse_process_security_status(b"TracerPid: 0\n").is_err());
        assert!(parse_process_security_status(b"TracerPid: x\nNoNewPrivs: 0\n").is_err());
        assert!(parse_process_security_status(b"TracerPid: 0\nNoNewPrivs: 2\n").is_err());
        assert!(
            parse_process_security_status(b"TracerPid: 0\nTracerPid: 0\nNoNewPrivs: 0\n").is_err()
        );
        assert!(
            parse_process_security_status(b"TracerPid: 0\nNoNewPrivs: 0\nNoNewPrivs: 0\n").is_err()
        );
        assert!(
            !parse_process_security_status(b"TracerPid: 0\nNoNewPrivs: 0\n")
                .unwrap()
                .no_new_privs
        );
    }

    #[test]
    fn process_status_is_confirmed_through_the_pidfd_after_reading() {
        let calls = crate::FakePeer::new()
            .with_status(Ok(b"TracerPid: 7\nNoNewPrivs: 1\n".to_vec()))
            .with_exit(Ok(false));
        let (a, _b) = fd();
        let status = process_security_status(&calls, 100, a.as_fd()).unwrap();
        assert_eq!(status.tracer_pid, 7);
        assert!(status.no_new_privs);
        assert!(
            calls
                .calls()
                .last()
                .is_some_and(|call| *call == crate::PeerCall::HasExited)
        );
    }

    #[test]
    fn a_process_that_exits_after_its_status_read_is_unattested() {
        let calls = crate::FakePeer::new()
            .with_status(Ok(b"TracerPid: 0\nNoNewPrivs: 0\n".to_vec()))
            .with_exit(Ok(true));
        let (a, _b) = fd();
        assert!(process_security_status(&calls, 100, a.as_fd()).is_err());
    }

    #[test]
    fn parent_check_pins_first_then_refuses_a_different_parent() {
        let (a, _b) = fd();
        let stat = b"100 (child) S 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5000";
        let calls = crate::FakePeer::new()
            .with_open(Ok(a.into()))
            .with_stat(Ok(stat.to_vec()))
            .with_exit(Ok(false));
        let parsed = verify_parent_pid(&calls, 100, 42).unwrap();
        assert_eq!((parsed.pid, parsed.ppid), (100, 42));
        assert_eq!(
            calls.calls().first(),
            Some(&crate::PeerCall::PidfdOpen(100))
        );
    }

    #[test]
    fn parent_check_rejects_a_different_parent_and_a_reaped_child() {
        let stat = b"100 (child) S 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5000";
        let (a, _b) = fd();
        let wrong_parent = crate::FakePeer::new()
            .with_open(Ok(a.into()))
            .with_stat(Ok(stat.to_vec()))
            .with_exit(Ok(false));
        assert!(verify_parent_pid(&wrong_parent, 100, 41).is_err());
        let (a, _b) = fd();
        let exited = crate::FakePeer::new()
            .with_open(Ok(a.into()))
            .with_stat(Ok(stat.to_vec()))
            .with_exit(Ok(true));
        assert!(verify_parent_pid(&exited, 100, 42).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_fstatfs_check_rejects_a_non_cgroup_descriptor() {
        let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sessions/not-a-session");
        let root = rustix::fs::open(
            fixture,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let host = HostCgroup {
            root,
            test_records: None,
            test_fixture: false,
            test_force_cgroup2: false,
        };
        assert!(imp::require_cgroup2(&host).is_err());
    }

    #[cfg(target_os = "linux")]
    fn every_step_failing(walk: &dyn Fn() -> Result<(), SysError>) {
        let mut n = 0_usize;
        loop {
            imp::FAIL_AT.with(|cell| cell.set(Some(n)));
            let result = walk();
            let failed = imp::FAIL_AT.with(|cell| cell.get().is_none());
            imp::FAIL_AT.with(|cell| cell.set(None));
            if !failed {
                assert!(result.is_ok());
                return;
            }
            assert!(result.is_err(), "step {n} failure was swallowed");
            n = n.saturating_add(1);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failure_at_any_step_of_a_host_walk_is_closed() {
        let host = fixture_host();
        let name = format!("{AGENT_RECORD_NAME}.scope");
        every_step_failing(&|| imp::scope_names(&host).map(drop));
        every_step_failing(&|| imp::read_record(&host, AGENT_RECORD_NAME).map(drop));
        every_step_failing(&|| imp::cgroup_inode(&host, &format!("/xudo.slice/{name}")).map(drop));
        let id = fixture_scope_inode();
        every_step_failing(&|| imp::scope_facts(&host, &name, id, true).map(drop));
        let run =
            || open_dir(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/run"));
        every_step_failing(&|| imp::sessions_dir_from(Some(&host), Ok(run())).map(drop));
        every_step_failing(&|| imp::read_starttime(std::process::id()).map(drop));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_is_trusted_only_when_root_owned_private_and_unlinked() {
        assert!(trusted_record(0, 0o100_600, 1));
        assert!(!trusted_record(1000, 0o100_600, 1));
        assert!(!trusted_record(0, 0o100_640, 1));
        assert!(!trusted_record(0, 0o100_600, 2));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_listing_or_entry_or_run_directory_is_closed() {
        assert!(imp::names_from::<std::vec::IntoIter<_>>(Err(rustix::io::Errno::IO)).is_err());
        let bad = vec![Err(rustix::io::Errno::IO)].into_iter();
        assert!(imp::names_from(Ok(bad)).is_err());
        let names = vec![
            Ok(AGENT_RECORD_NAME.as_bytes().to_vec()),
            Ok(b"pending-agent-1".to_vec()),
            Ok(vec![0xff]),
        ];
        assert_eq!(imp::names_from(Ok(names.into_iter())).unwrap().len(), 1);
        let host = fixture_host();
        assert!(imp::sessions_dir_from(Some(&host), Err(SysError::read("x", "y"))).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_malformed_proc_stat_is_refused() {
        assert!(imp::starttime_of(b"garbage").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_pinned_root_that_is_not_cgroup2_is_refused_everywhere() {
        let tmp = PathBuf::from("/tmp").join(format!("xudo-e1-notcg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(imp::finish_cgroup_root(Ok(open_dir(&tmp))).is_err());
        let host = HostCgroup {
            root: open_dir(&tmp),
            test_records: None,
            test_fixture: false,
            test_force_cgroup2: false,
        };
        assert!(imp::cgroup_inode(&host, "/xudo.slice").is_err());
        assert!(imp::scope_facts(&host, &format!("{AGENT_RECORD_NAME}.scope"), 1, true).is_err());
        std::fs::remove_dir_all(tmp).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_descriptor_that_is_not_a_pidfd_gives_no_cgroup_id() {
        let (a, _b) = fd();
        assert!(imp::pidfd_cgroup_id(a.as_fd()).is_err());
    }

    #[test]
    fn a_failed_read_at_any_rung_of_the_ladder_is_unattested() {
        let (a, _b) = fd();
        let notty = || Err(error(rustix::io::Errno::NOTTY));
        let broken = || SysError::read("x", "gone");
        for info_ok in [true, false] {
            let info = if info_ok { Ok(42) } else { notty() };
            let c = FakeCgroup::path_result(info.clone(), "0::/x\n", Ok(42), true);
            *c.proc.borrow_mut() = Err(broken());
            assert!(peer_cgroup_id(&c, 9, a.as_fd()).is_err());
            let c = FakeCgroup::path_result(info.clone(), "0::/x\n", Err(broken()), true);
            assert!(peer_cgroup_id(&c, 9, a.as_fd()).is_err());
            let c = FakeCgroup::path_result(info.clone(), "0::/x\n", Ok(42), true);
            *c.alive.borrow_mut() = Err(broken());
            assert!(peer_cgroup_id(&c, 9, a.as_fd()).is_err());
            let c = FakeCgroup::path_result(info, "", Ok(42), true);
            assert!(peer_cgroup_id(&c, 9, a.as_fd()).is_err());
        }
    }

    #[test]
    fn record_names_need_a_kind_a_dash_and_32_hex_digits() {
        let hex = "0123456789abcdef0123456789ABCDEF";
        assert!(is_record_name(&format!("agent-{hex}")));
        assert!(is_record_name(&format!("watch-{hex}")));
        assert!(!is_record_name(&format!("pending-{hex}")));
        assert!(!is_record_name("nodash"));
        assert!(!is_record_name("agent-short"));
        assert!(!is_record_name(&format!("agent-{}g", &hex[..31])));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_host_without_cgroup2_attests_nothing() {
        fn unsupported<T>(result: Result<T, SysError>, what: &'static str) {
            assert_eq!(result.map(drop), Err(SysError::unsupported(what)));
        }
        unsupported(HostCgroup::open(), "cgroup2 attestation");
        let host = HostCgroup::for_tests();
        let stream = UnixStream::pair().unwrap().0;
        unsupported(host.require_cgroup2(), "cgroup2 fstatfs");
        unsupported(host.pidfd_cgroup_id(stream.as_fd()), "PIDFD_GET_INFO");
        unsupported(host.proc_cgroup(1), "/proc cgroup read");
        unsupported(host.cgroup_inode("a"), "cgroup fstat");
        unsupported(host.peer_alive(stream.as_fd()), "pidfd poll");
        unsupported(host.scope_facts("a", 1, false), "scope status");
        unsupported(host.scope_names(), "session record listing");
    }

    #[test]
    fn a_name_that_is_not_a_committed_record_name_is_never_a_scope() {
        let mut fake = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        fake.names = vec![format!("agent-{}", "g".repeat(32)), "agent-1".to_owned()];
        assert!(
            scope_status(&fake, 1, 1000, &parse_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unreadable_scope_listings_and_facts_are_errors_not_absences() {
        let mut fake = scope_fake("agent", 1, 1, 0, 0o100_644, true, vec![(42, 73)], true);
        fake.fail_scopes = true;
        assert!(scope_status(&fake, 1, 1000, &parse_record).is_err());
        fake.fail_scopes = false;
        fake.fail_names = true;
        assert!(scope_status(&fake, 1, 1000, &parse_record).is_err());
    }

    #[test]
    fn a_status_read_that_fails_or_is_malformed_or_unpollable_is_unattested() {
        let (a, _b) = fd();
        let broken = || SysError::read("x", "gone");
        let read_fails = crate::FakePeer::new().with_status(Err(broken()));
        assert!(process_security_status(&read_fails, 1, a.as_fd()).is_err());
        let malformed = crate::FakePeer::new().with_status(Ok(b"junk\n".to_vec()));
        assert!(process_security_status(&malformed, 1, a.as_fd()).is_err());
        let poll_fails = crate::FakePeer::new()
            .with_status(Ok(b"TracerPid: 0\nNoNewPrivs: 0\n".to_vec()))
            .with_exit(Err(broken()));
        assert!(process_security_status(&poll_fails, 1, a.as_fd()).is_err());
        assert!(parse_process_security_status(b"NoNewPrivs: x\nTracerPid: 0\n").is_err());
        assert!(parse_process_security_status(b"NoNewPrivs: 0\n").is_err());
    }

    #[test]
    fn a_parent_check_that_cannot_pin_read_parse_or_poll_is_unattested() {
        let broken = || SysError::read("x", "gone");
        let stat = b"100 (child) S 42 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5000";
        assert!(
            verify_parent_pid(&crate::FakePeer::new().with_open(Err(broken())), 100, 42).is_err()
        );
        let (a, _b) = fd();
        let no_stat = crate::FakePeer::new()
            .with_open(Ok(a.into()))
            .with_stat(Err(broken()));
        assert!(verify_parent_pid(&no_stat, 100, 42).is_err());
        let (a, _b) = fd();
        let bad_stat = crate::FakePeer::new()
            .with_open(Ok(a.into()))
            .with_stat(Ok(b"junk".to_vec()));
        assert!(verify_parent_pid(&bad_stat, 100, 42).is_err());
        let (a, _b) = fd();
        let poll_fails = crate::FakePeer::new()
            .with_open(Ok(a.into()))
            .with_stat(Ok(stat.to_vec()))
            .with_exit(Err(broken()));
        assert!(verify_parent_pid(&poll_fails, 100, 42).is_err());
    }
}
