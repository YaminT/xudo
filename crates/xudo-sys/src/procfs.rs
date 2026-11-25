//! A `/proc` that has proved it is `/proc`.
//!
//! The lineage walk reads `/proc/<pid>/stat` for every ancestor of the gate,
//! and a pin taken from a lie would let a spool entry minted for someone else
//! match this caller. [`crate::DirSource`] reads by path and trusts whatever
//! answers; that is right for a hint nothing depends on and wrong here. A
//! mount over `/proc` could answer with any parent chain it likes.
//!
//! [`VerifiedProc`] opens the directory once, asks the kernel on **that
//! descriptor** whether it is procfs (`fstatfs`, `PROC_SUPER_MAGIC`), and
//! reads every file through it. Each file it opens is checked the same way,
//! so a file system mounted over one entry beneath the directory is refused
//! too. Paths are relative and lexical-checked like every source's, and the
//! last component is opened `O_NOFOLLOW`.
//!
//! It gates nothing by itself: a mount over `/proc` needs `CAP_SYS_ADMIN`, so
//! only root can make one, and a user namespace's root has no authority over
//! the gate's `sudo` hop. The check is the descriptor-bound statement of what
//! the gate is reading, so that the lineage's evidence is the kernel's, not
//! whatever is mounted at a name.
//!
//! Off Linux there is no procfs: [`VerifiedProc::open`] refuses, and so does
//! every read.

use std::path::Path;

use crate::error::SysError;
use crate::source::ProcSource;

/// The most a single `/proc` read returns. A `stat` line is under a kilobyte;
/// the bound is a ceiling on what a hostile process can make the gate read.
pub const MAX_PROC_READ: u64 = 1 << 20;

/// A `/proc` directory descriptor the kernel confirmed is procfs.
#[derive(Debug)]
pub struct VerifiedProc {
    #[cfg(target_os = "linux")]
    root: std::os::fd::OwnedFd,
}

impl VerifiedProc {
    /// Opens `/proc` and proves it.
    ///
    /// # Errors
    ///
    /// [`SysError`] when `/proc` cannot be opened as a directory, is not
    /// procfs, or the platform has none.
    pub fn open() -> Result<Self, SysError> {
        Self::open_at(Path::new("/proc"))
    }

    /// Opens `path` and proves it is procfs. For tests, which point it at what
    /// is not.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_at(path: &Path) -> Result<Self, SysError> {
        imp::open_at(path)
    }
}

impl ProcSource for VerifiedProc {
    fn read(&self, relative: &str) -> Result<Vec<u8>, SysError> {
        imp::read(self, relative)
    }

    fn namespace_inode(&self, relative: &str) -> Result<u64, SysError> {
        imp::namespace_inode(self, relative)
    }

    fn file_identity(&self, relative: &str) -> Result<crate::FileId, SysError> {
        imp::file_identity(self, relative)
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io::Read;
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::path::Path;

    use rustix::fs::{Mode, OFlags, fstatfs, open, openat};
    use rustix::io::Errno;

    use super::{MAX_PROC_READ, VerifiedProc};
    use crate::error::SysError;
    use crate::source::check_relative;

    /// Whether a descriptor is on procfs.
    fn on_procfs(fd: BorrowedFd<'_>) -> bool {
        fstatfs(fd)
            .is_ok_and(|stat| i128::from(stat.f_type) == i128::from(rustix::fs::PROC_SUPER_MAGIC))
    }

    fn failed(at: &str, errno: Errno) -> SysError {
        SysError::read(at, errno.to_string())
    }

    /// Keeps `fd` only if the kernel says it is on procfs.
    pub(super) fn require_procfs(fd: OwnedFd, at: &str) -> Result<OwnedFd, SysError> {
        if on_procfs(fd.as_fd()) {
            Ok(fd)
        } else {
            Err(SysError::read(
                at,
                "not on procfs, so what it says about processes cannot be believed",
            ))
        }
    }

    pub(super) fn open_at(path: &Path) -> Result<VerifiedProc, SysError> {
        let at = path.display().to_string();
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| failed(&at, errno))
        .and_then(|root| require_procfs(root, &at))
        .map(|root| VerifiedProc { root })
    }

    pub(super) fn read(proc: &VerifiedProc, relative: &str) -> Result<Vec<u8>, SysError> {
        check_relative(relative)?;
        openat(
            &proc.root,
            relative,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|errno| failed(relative, errno))
        .and_then(|fd| require_procfs(fd, relative))
        .and_then(|fd| read_bounded(fd, relative))
    }

    /// `NSFS_MAGIC`: the filesystem every namespace file lives on.
    const NSFS_MAGIC: i128 = 0x6e73_6673;

    /// Follows the namespace link, proves the target is on nsfs, and reports
    /// its inode. Opened from the pinned descriptor, so a mount over a path
    /// elsewhere cannot answer for it.
    pub(super) fn namespace_inode(proc: &VerifiedProc, relative: &str) -> Result<u64, SysError> {
        check_relative(relative)?;
        let fd = openat(
            &proc.root,
            relative,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )
        .map_err(|errno| failed(relative, errno))?;
        let on_nsfs = fstatfs(&fd).is_ok_and(|stat| i128::from(stat.f_type) == NSFS_MAGIC);
        match rustix::fs::fstat(&fd) {
            Ok(stat) if on_nsfs => Ok(stat.st_ino),
            _ => Err(SysError::read(relative, "not a namespace file")),
        }
    }

    /// Follows the link from the pinned descriptor, as the kernel resolves it
    /// for this process, and reports the inode it leads to. The target is on
    /// an ordinary file system, so it is not required to be procfs.
    pub(super) fn file_identity(
        proc: &VerifiedProc,
        relative: &str,
    ) -> Result<crate::FileId, SysError> {
        check_relative(relative)?;
        openat(
            &proc.root,
            relative,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOCTTY,
            Mode::empty(),
        )
        .and_then(|fd| rustix::fs::fstat(&fd))
        .map(|stat| crate::FileId::of(&stat))
        .map_err(|errno| failed(relative, errno))
    }

    fn read_bounded(fd: OwnedFd, at: &str) -> Result<Vec<u8>, SysError> {
        let mut bytes = Vec::new();
        std::fs::File::from(fd)
            .take(MAX_PROC_READ)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
            .map_err(|error| SysError::read(at, error.to_string()))
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::path::Path;

    use super::VerifiedProc;
    use crate::error::SysError;

    pub(super) fn open_at(path: &Path) -> Result<VerifiedProc, SysError> {
        Err(SysError::unsupported(format!(
            "verifying {} as procfs",
            path.display()
        )))
    }

    pub(super) fn read(_proc: &VerifiedProc, relative: &str) -> Result<Vec<u8>, SysError> {
        Err(SysError::unsupported(format!(
            "reading {relative} from procfs"
        )))
    }

    pub(super) fn namespace_inode(_proc: &VerifiedProc, relative: &str) -> Result<u64, SysError> {
        Err(SysError::unsupported(format!(
            "reading {relative} from procfs"
        )))
    }

    pub(super) fn file_identity(
        _proc: &VerifiedProc,
        relative: &str,
    ) -> Result<crate::FileId, SysError> {
        Err(SysError::unsupported(format!(
            "reading {relative} from procfs"
        )))
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

    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_there_is_no_procfs_to_verify_and_every_read_refuses() {
        let err = VerifiedProc::open().unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        // A value that cannot be built outside this module, so the read path
        // is exercised from inside it.
        let proc = VerifiedProc {};
        let err = proc.read("1/stat").unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        let err = proc.namespace_inode("1/ns/user").unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        let err = proc.file_identity("self/exe").unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        assert!(format!("{proc:?}").contains("VerifiedProc"));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use crate::proc::parse_stat;

        #[test]
        fn the_real_proc_is_procfs_and_its_stat_files_parse() {
            let proc = VerifiedProc::open().unwrap();
            let pid = std::process::id();
            let bytes = proc.read(&format!("{pid}/stat")).unwrap();
            let stat = parse_stat("stat", &bytes).unwrap();
            assert_eq!(stat.pid, pid);
            assert!(format!("{proc:?}").contains("VerifiedProc"));
        }

        #[test]
        fn a_directory_that_is_not_procfs_is_refused_as_proc() {
            // A directory a user could have filled with a forged tree.
            for not_proc in ["/", env!("CARGO_MANIFEST_DIR")] {
                let err = VerifiedProc::open_at(Path::new(not_proc)).unwrap_err();
                assert!(err.to_string().contains("not on procfs"), "{err}");
            }
        }

        #[test]
        fn a_file_that_is_not_on_procfs_is_refused_wherever_it_sits_under_proc() {
            // What a file system mounted over one entry would look like.
            let file =
                std::fs::File::open(env!("CARGO_MANIFEST_DIR").to_owned() + "/Cargo.toml").unwrap();
            let err = imp::require_procfs(file.into(), "1/stat").unwrap_err();
            assert!(err.to_string().contains("not on procfs"), "{err}");
        }

        #[test]
        fn a_proc_that_cannot_be_opened_is_refused() {
            // Missing, and present but not a directory.
            for bad in ["/definitely/not/here", "/etc/passwd"] {
                assert!(VerifiedProc::open_at(Path::new(bad)).is_err(), "{bad}");
            }
        }

        #[test]
        fn a_path_that_could_leave_the_root_is_refused_before_it_is_opened() {
            let proc = VerifiedProc::open().unwrap();
            for bad in [
                "",
                "/etc/passwd",
                "../etc/passwd",
                "1/../1/stat",
                "./1/stat",
            ] {
                let err = proc.read(bad).unwrap_err();
                assert!(err.to_string().contains("cannot read"), "{bad:?}: {err}");
            }
        }

        #[test]
        fn a_final_symlink_is_not_followed_and_a_missing_process_is_an_error() {
            let proc = VerifiedProc::open().unwrap();
            // `self` is a symlink: NOFOLLOW on the last component refuses it.
            assert!(proc.read("self").is_err());
            // A pid nothing has.
            assert!(proc.read("4194999/stat").is_err());
        }

        #[test]
        fn a_namespace_link_leads_to_an_inode_and_a_non_namespace_file_is_refused() {
            let proc = VerifiedProc::open().unwrap();
            let own = std::process::id();
            let mine = proc.namespace_inode(&format!("{own}/ns/user")).unwrap();
            assert_eq!(mine, proc.namespace_inode("self/ns/user").unwrap());
            assert_ne!(mine, 0);
            // A plain procfs file is not on nsfs, so it is not a namespace.
            let err = proc.namespace_inode(&format!("{own}/stat")).unwrap_err();
            assert!(err.to_string().contains("not a namespace file"), "{err}");
            for bad in ["", "/proc/1/ns/user", "1/../1/ns/user"] {
                assert!(proc.namespace_inode(bad).is_err(), "{bad:?}");
            }
            assert!(proc.namespace_inode("4194999/ns/user").is_err());
        }

        #[test]
        fn self_exe_is_identified_through_the_verified_handle() {
            use std::os::unix::fs::MetadataExt as _;

            let proc = VerifiedProc::open().unwrap();
            let id = proc.file_identity("self/exe").unwrap();
            let meta = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
            assert_eq!((id.ino, id.nlink), (meta.ino(), meta.nlink()));
            for bad in ["", "/proc/self/exe", "self/../self/exe"] {
                assert!(proc.file_identity(bad).is_err(), "{bad:?}");
            }
            assert!(proc.file_identity("4194999/exe").is_err());
        }

        #[test]
        fn a_directory_opens_and_then_fails_to_read_rather_than_returning_nothing() {
            let proc = VerifiedProc::open().unwrap();
            let err = proc.read(&std::process::id().to_string()).unwrap_err();
            assert!(err.to_string().contains("cannot read"), "{err}");
        }
    }
}
