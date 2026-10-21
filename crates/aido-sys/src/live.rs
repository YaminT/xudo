//! The machine as `aido doctor`'s report of other paths to root sees it.
//!
//! The only implementation of [`HostView`] that touches the real filesystem,
//! and deliberately thin: six questions, each answered with the kernel's
//! semantics and no judgement. Every judgement — what is writable, by whom,
//! what a sudoers line grants — is in `aido_backend::paths_to_root`, which is
//! pure and tested against a described machine.
//!
//! Unprivileged by design: it reads as the user who ran `aido doctor`. What
//! that user cannot read comes back unreadable, with the kernel's reason, and
//! the report calls it unverified, never absent. Nothing here is used to
//! decide anything; it is shown to a human.

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use aido_backend::paths_to_root::{
    Caller, HostView, Kind, Lookup, MAX_READ, Meta, NOT_A_REGULAR_FILE, TOO_LARGE,
};
use rustix::fs::{Access, FileType, Mode, OFlags};
use rustix::process::Gid;

/// Answers the report's questions about this machine, as this process.
#[derive(Clone, Copy, Debug, Default)]
pub struct LiveHost;

impl HostView for LiveHost {
    fn caller(&self) -> Caller {
        Caller {
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            groups: groups(rustix::process::getgroups()),
        }
    }

    fn stat(&self, path: &Path) -> Lookup<Meta> {
        lookup(std::fs::symlink_metadata(path).map(|meta| meta_of(&meta)))
    }

    fn read(&self, path: &Path) -> Lookup<Vec<u8>> {
        lookup(read_regular(path, MAX_READ))
    }

    fn list(&self, path: &Path) -> Lookup<Vec<OsString>> {
        lookup(std::fs::read_dir(path).and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect()
        }))
    }

    fn read_link(&self, path: &Path) -> Lookup<PathBuf> {
        lookup(std::fs::read_link(path))
    }

    fn writable(&self, path: &Path) -> bool {
        // `access(2)` checks the real ids, which for a process that is not
        // set-user-ID are the caller's: exactly whose write access the report
        // is about.
        rustix::fs::access(path, Access::WRITE_OK).is_ok()
    }
}

/// An answer from an I/O result. Missing is `ENOENT`, or `ENOTDIR` for a path
/// through a file, and nothing else; every other failure is unreadable, with
/// the kernel's reason.
fn lookup<T>(result: io::Result<T>) -> Lookup<T> {
    match result {
        Ok(value) => Lookup::Found(value),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Lookup::Missing
        }
        Err(error) => Lookup::Unreadable(error.to_string()),
    }
}

/// This process's supplementary groups, or why they could not be read.
fn groups(result: rustix::io::Result<Vec<Gid>>) -> Lookup<Vec<u32>> {
    match result {
        Ok(groups) => Lookup::Found(groups.iter().map(|gid| gid.as_raw()).collect()),
        Err(errno) => Lookup::Unreadable(io::Error::from(errno).to_string()),
    }
}

/// The facts the report needs from `lstat`.
fn meta_of(meta: &std::fs::Metadata) -> Meta {
    let file_type = meta.file_type();
    let kind = if file_type.is_symlink() {
        Kind::Symlink
    } else if file_type.is_dir() {
        Kind::Directory
    } else if file_type.is_file() {
        Kind::File
    } else if file_type.is_char_device() {
        Kind::CharDevice
    } else {
        Kind::Other
    };
    Meta {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode() & 0o7777,
        kind,
    }
}

/// A regular file's contents, at most `cap` bytes of them.
///
/// Opened without blocking and without acquiring a terminal, then judged on
/// the descriptor: a fifo or a device someone left where a file should be is
/// refused rather than read, so it cannot stall the report, and the type that
/// is checked is the type of what was opened.
fn read_regular(path: &Path, cap: u64) -> io::Result<Vec<u8>> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOCTTY;
    rustix::fs::open(path, flags, Mode::empty())
        .and_then(|fd| rustix::fs::fstat(&fd).map(|stat| (fd, stat)))
        .map_err(io::Error::from)
        .and_then(|(fd, stat)| {
            if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
                Ok(fd)
            } else {
                Err(io::Error::other(NOT_A_REGULAR_FILE))
            }
        })
        .and_then(|fd| bounded(std::fs::File::from(fd), cap))
}

/// Everything `source` holds, or [`TOO_LARGE`] when that is more than `cap`.
fn bounded(source: impl Read, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source
        .take(cap.saturating_add(1))
        .read_to_end(&mut bytes)
        .and_then(|read| {
            if u64::try_from(read).unwrap_or(u64::MAX) > cap {
                Err(io::Error::other(TOO_LARGE))
            } else {
                Ok(bytes)
            }
        })
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

    use std::os::unix::fs::PermissionsExt;

    use aido_backend::paths_to_root::{CheckId, Input, Status, assess};

    use super::*;

    /// A throwaway directory under the workspace `target/`, never `/tmp`.
    ///
    /// Canonical, because the report follows the path the kernel follows and
    /// the fixture is reached through `..` from the manifest directory. Any
    /// sealed directory a failed run left behind is opened up before it is
    /// removed, so one failure cannot wedge the next run.
    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("live-{name}"));
        let _ =
            std::fs::set_permissions(dir.join("sealed"), std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// The reason a lookup failed, for comparing kinds of answer without
    /// pinning the operating system's wording.
    fn reason<T>(lookup: Lookup<T>) -> Option<String> {
        match lookup {
            Lookup::Unreadable(reason) => Some(reason),
            Lookup::Found(_) | Lookup::Missing => None,
        }
    }

    #[test]
    fn the_caller_is_this_process() {
        let dir = scratch("caller");
        let file = dir.join("mine");
        std::fs::write(&file, "").unwrap();
        let caller = LiveHost.caller();
        // A file this process just created is owned by its uid.
        assert_eq!(caller.uid, std::fs::metadata(&file).unwrap().uid());
        assert_ne!(caller.groups, Lookup::Missing);
        assert_eq!(reason(caller.groups.clone()), None, "{caller:?}");
        assert_eq!(caller.gid, rustix::process::getgid().as_raw());
    }

    #[test]
    fn groups_that_cannot_be_read_are_unreadable_not_none() {
        assert_eq!(
            groups(Err(rustix::io::Errno::INVAL)),
            Lookup::Unreadable(io::Error::from(rustix::io::Errno::INVAL).to_string())
        );
        assert_eq!(
            groups(Ok(vec![Gid::from_raw(27), Gid::from_raw(999)])),
            Lookup::Found(vec![27, 999])
        );
    }

    #[test]
    fn stat_reports_every_kind_without_following_a_final_link() {
        let dir = scratch("stat");
        let file = dir.join("file");
        std::fs::write(&file, "x").unwrap();
        set_mode(&file, 0o640);
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();

        let meta = |path: &Path| LiveHost.stat(path).map(|meta| (meta.kind, meta.mode));
        assert_eq!(meta(&file), Lookup::Found((Kind::File, 0o640)));
        assert_eq!(
            LiveHost.stat(&link).map(|meta| meta.kind),
            Lookup::Found(Kind::Symlink)
        );
        assert_eq!(
            LiveHost.stat(&dir).map(|meta| meta.kind),
            Lookup::Found(Kind::Directory)
        );
        // A character device on every Unix: the kind the report judges by its
        // owner alone.
        assert_eq!(
            LiveHost.stat(Path::new("/dev/null")).map(|meta| meta.kind),
            Lookup::Found(Kind::CharDevice)
        );
        // A socket, which is judged like a file. Bound by a path relative to
        // the package, which cargo makes the working directory: the absolute
        // one can exceed the 104 bytes a socket address holds.
        let socket = dir.join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(Path::new(
            "../../target/test-tmp/live-stat/socket",
        ))
        .unwrap();
        assert_eq!(
            LiveHost.stat(&socket).map(|meta| meta.kind),
            Lookup::Found(Kind::Other)
        );
        let me = std::fs::metadata(&file).unwrap();
        assert_eq!(
            LiveHost.stat(&file).map(|meta| (meta.uid, meta.gid)),
            Lookup::Found((me.uid(), me.gid()))
        );
    }

    #[test]
    fn missing_is_enoent_or_enotdir_and_everything_else_is_unreadable() {
        let dir = scratch("missing");
        let file = dir.join("file");
        std::fs::write(&file, "").unwrap();
        let sealed = dir.join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        std::fs::write(sealed.join("inside"), "").unwrap();
        set_mode(&sealed, 0o000);

        assert_eq!(LiveHost.stat(&dir.join("absent")), Lookup::Missing);
        // A path through a file: ENOTDIR, which is "does not exist".
        assert_eq!(LiveHost.stat(&file.join("below")), Lookup::Missing);
        assert_eq!(LiveHost.list(&file), Lookup::Missing);
        // A directory this process may not search hides what is in it, and
        // that is never reported as absent.
        let hidden = LiveHost.stat(&sealed.join("inside"));
        let listing = LiveHost.list(&sealed);
        set_mode(&sealed, 0o755);
        assert!(reason(hidden).is_some_and(|r| !r.is_empty()));
        assert!(reason(listing).is_some_and(|r| !r.is_empty()));
        assert_eq!(reason(LiveHost.stat(&file)), None);
    }

    #[test]
    fn read_returns_a_regular_files_bytes_and_refuses_anything_else() {
        let dir = scratch("read");
        let file = dir.join("sudoers");
        std::fs::write(&file, b"yamin ALL=NOPASSWD: ALL\n\xff").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();

        assert_eq!(
            LiveHost.read(&file),
            Lookup::Found(b"yamin ALL=NOPASSWD: ALL\n\xff".to_vec())
        );
        // Links are followed, as sudo follows them.
        assert_eq!(LiveHost.read(&link), LiveHost.read(&file));
        assert_eq!(LiveHost.read(&dir.join("absent")), Lookup::Missing);
        // A directory, and a device that would read forever or block: refused
        // on the descriptor, without blocking, in the report's own words.
        for path in [dir.as_path(), Path::new("/dev/null")] {
            assert_eq!(
                LiveHost.read(path),
                Lookup::Unreadable(NOT_A_REGULAR_FILE.to_owned()),
                "{path:?}"
            );
        }
        // Mode 000: unreadable to anyone but root, with the kernel's reason.
        set_mode(&file, 0o000);
        let denied = LiveHost.read(&file);
        set_mode(&file, 0o644);
        assert!(reason(denied).is_some_and(|r| !r.is_empty()));
    }

    #[test]
    fn a_file_larger_than_the_cap_is_refused_rather_than_read() {
        let dir = scratch("cap");
        let file = dir.join("big");
        std::fs::write(&file, b"0123456789").unwrap();
        assert_eq!(read_regular(&file, 10).unwrap(), b"0123456789".to_vec());
        assert_eq!(
            read_regular(&file, 9).unwrap_err().to_string(),
            TOO_LARGE.to_owned()
        );
        assert_eq!(bounded(&b"abc"[..], 3).unwrap(), b"abc".to_vec());
        assert_eq!(MAX_READ, 4 * 1024 * 1024);
    }

    #[test]
    fn list_names_entries_as_the_bytes_the_kernel_returned() {
        let dir = scratch("list");
        std::fs::write(dir.join("b"), "").unwrap();
        std::fs::write(dir.join("a"), "").unwrap();
        let names = LiveHost.list(&dir).map(|mut names| {
            names.sort();
            names
        });
        assert_eq!(
            names,
            Lookup::Found(vec![OsString::from("a"), OsString::from("b")])
        );
        assert_eq!(LiveHost.list(&dir.join("absent")), Lookup::Missing);
    }

    #[test]
    fn read_link_returns_the_target_as_stored() {
        let dir = scratch("readlink");
        let link = dir.join("link");
        std::os::unix::fs::symlink("../relative/target", &link).unwrap();
        assert_eq!(
            LiveHost.read_link(&link),
            Lookup::Found(PathBuf::from("../relative/target"))
        );
        assert_eq!(LiveHost.read_link(&dir.join("absent")), Lookup::Missing);
        // Not a link: EINVAL, which is a reason and not an absence.
        assert!(reason(LiveHost.read_link(&dir)).is_some_and(|r| !r.is_empty()));
    }

    #[test]
    fn writable_is_access_with_the_callers_real_ids() {
        let dir = scratch("writable");
        let file = dir.join("mine");
        std::fs::write(&file, "").unwrap();
        assert!(LiveHost.writable(&file));
        assert!(LiveHost.writable(&dir));
        // The filesystem root is root's alone; the suite never runs as root.
        assert!(!LiveHost.writable(Path::new("/")));
        assert!(!LiveHost.writable(&dir.join("absent")));
    }

    #[test]
    fn the_report_runs_against_this_machine_and_never_calls_a_gap_clean() {
        // Whatever this host has, the report's shape holds: every check, in
        // order, and none of them clean while it carries something it could
        // not examine.
        let path = std::ffi::OsString::from("/usr/bin:/bin");
        let report = assess(
            &LiveHost,
            &Input {
                user_path: Some(&path),
                backend_exe: Some(Path::new("/usr/bin/sudo")),
            },
        );
        let order: Vec<CheckId> = report.checks.iter().map(|c| c.check).collect();
        assert_eq!(order.len(), 6, "{order:?}");
        // Counted rather than branched on, so the same code runs on every
        // host whatever it holds.
        let gaps_called_clean: usize = report
            .checks
            .iter()
            .map(|c| usize::from(c.status == Status::Clean) * c.unverified.len())
            .sum();
        assert_eq!(gaps_called_clean, 0, "{report:?}");
        let above_the_whole: usize = report
            .checks
            .iter()
            .map(|c| usize::from(c.status > report.status))
            .sum();
        assert_eq!(above_the_whole, 0, "{report:?}");
        assert_eq!(report.subject.uid, LiveHost.caller().uid);
        assert!(format!("{LiveHost:?}").contains("LiveHost"));
    }
}
