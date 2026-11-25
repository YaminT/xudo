//! [`EnrolOps`] on a real filesystem: the same descriptor walk the install uses,
//! so a directory or file is believed only if root's alone, and the same
//! injected directory opener and owner, so a test can stand in for `/etc`.

use std::os::fd::AsFd;
use std::path::Path;

use rustix::fs::{AtFlags, Dir, Mode, OFlags, fchmod, fstat, mkdirat, openat, statat, unlinkat};
use rustix::io::Errno;

use super::{HostInstallOps, MAX_SHARED_BYTES, io, raw_mode, read_all};
use crate::install::enrol::{EnrolOps, Systemctl};
use crate::install::{InstallError, Removal};
use crate::trust::{Kind, facts_of};

/// systemd's control program. Absolute: nothing is searched for.
const SYSTEMCTL: &str = "/usr/bin/systemctl";

impl HostInstallOps {
    /// `Err` unless `stat` describes a directory of the trusted owner that
    /// nobody else can write.
    fn private_dir(&self, stat: &rustix::fs::Stat, path: &str) -> Result<(), InstallError> {
        let facts = facts_of(stat);
        let reason = if facts.kind != Kind::Directory {
            Some("it is not a directory")
        } else if facts.uid != self.owner {
            Some("it is not owned by root")
        } else if facts.mode & 0o022 != 0 {
            Some("it is writable by group or others")
        } else {
            None
        };
        reason.map_or(Ok(()), |reason| {
            Err(InstallError::UnsafeFile {
                path: path.to_owned(),
                reason: reason.to_owned(),
            })
        })
    }
}

/// The names in `dir`, without `.` and `..`, sorted.
fn names_of(dir: Dir, path: &str) -> Result<Vec<String>, InstallError> {
    let mut names = dir
        .map(|entry| entry.map_err(io("list", path)))
        .filter(|entry| {
            entry.as_ref().map_or(true, |entry| {
                !matches!(entry.file_name().to_bytes(), b"." | b"..")
            })
        })
        .map(|entry| {
            entry.and_then(|entry| {
                std::str::from_utf8(entry.file_name().to_bytes())
                    .map(str::to_owned)
                    .map_err(|_| InstallError::UnsafeFile {
                        path: path.to_owned(),
                        reason: "a file name is not UTF-8".to_owned(),
                    })
            })
        })
        .collect::<Result<Vec<String>, InstallError>>()?;
    names.sort();
    Ok(names)
}

impl HostInstallOps {
    /// A root-owned, singly-linked regular file's bytes, if no one else can
    /// write it and it is a configuration file's size.
    fn readable(
        &self,
        stat: &rustix::fs::Stat,
        fd: std::os::fd::BorrowedFd<'_>,
        path: &str,
    ) -> Result<Vec<u8>, InstallError> {
        let unsafe_file = |reason: &str| InstallError::UnsafeFile {
            path: path.to_owned(),
            reason: reason.to_owned(),
        };
        if let Some(reason) = self.why_not_ours(stat) {
            Err(unsafe_file(reason))
        } else if facts_of(stat).mode & 0o022 != 0 {
            Err(unsafe_file("it is writable by group or others"))
        } else {
            read_all(fd, path).and_then(|bytes| {
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SHARED_BYTES {
                    Err(unsafe_file("it is too large to be a configuration file"))
                } else {
                    Ok(bytes)
                }
            })
        }
    }
}

impl EnrolOps for HostInstallOps {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, InstallError> {
        let Some((dir, name)) = self.locate_dir(path)? else {
            return Ok(None);
        };
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = match openat(&dir, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(errno) => return Err(io("open", path)(errno)),
        };
        fstat(&fd)
            .map_err(io("stat", path))
            .and_then(|stat| self.readable(&stat, fd.as_fd(), path))
            .map(Some)
    }

    fn private_file(&self, path: &str) -> Result<(), InstallError> {
        let Some((dir, name)) = self.locate_dir(path)? else {
            return Ok(());
        };
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = match openat(&dir, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(()),
            Err(errno) => return Err(io("open", path)(errno)),
        };
        fstat(&fd).map_err(io("stat", path)).and_then(|stat| {
            let reason = self.why_not_ours(&stat).or_else(|| {
                (facts_of(&stat).mode & 0o077 != 0).then_some("it is open to group or others")
            });
            reason.map_or(Ok(()), |reason| {
                Err(InstallError::UnsafeFile {
                    path: path.to_owned(),
                    reason: reason.to_owned(),
                })
            })
        })
    }

    fn list_dir(&self, path: &str) -> Result<Option<Vec<String>>, InstallError> {
        let Some(fd) = (self.open_dir)(Path::new(path)).map_err(InstallError::Untrusted)? else {
            return Ok(None);
        };
        Dir::read_from(&fd)
            .map_err(io("list", path))
            .and_then(|dir| names_of(dir, path))
            .map(Some)
    }

    fn make_dir(&self, path: &str, mode: u32) -> Result<bool, InstallError> {
        let (dir, name) = self.locate(path)?;
        let created = match mkdirat(&dir, name, raw_mode(mode)) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(errno) => return Err(io("mkdir", path)(errno)),
        };
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        openat(&dir, name, flags, Mode::empty())
            .map_err(io("open", path))
            .and_then(|fd| {
                fstat(&fd)
                    .map_err(io("stat", path))
                    .and_then(|stat| self.private_dir(&stat, path))
                    .map(|()| fd)
            })
            .and_then(|fd| {
                if created {
                    // The process umask may have taken bits off.
                    fchmod(&fd, raw_mode(mode)).map_err(io("chmod", path))
                } else {
                    Ok(())
                }
            })
            .map(|()| created)
    }

    fn remove_dir(&self, path: &str) -> Result<Removal, InstallError> {
        let Some((dir, name)) = self.locate_dir(path)? else {
            return Ok(Removal::Absent);
        };
        match statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => return Ok(Removal::Absent),
            Err(errno) => return Err(io("stat", path)(errno)),
            Ok(stat) => self.private_dir(&stat, path)?,
        }
        unlinkat(&dir, name, AtFlags::REMOVEDIR)
            .map_err(io("rmdir", path))
            .map(|()| Removal::Removed)
    }

    fn systemctl(&self, args: &[&str]) -> Result<Systemctl, InstallError> {
        let output = self
            .runner
            .run(SYSTEMCTL, args, None)
            .map_err(|source| InstallError::Io {
                operation: "run",
                path: SYSTEMCTL.to_owned(),
                reason: source.to_string(),
            })?;
        // A failure's answer is what it printed to either stream: it is shown
        // to the operator, never parsed.
        let stdout = if output.success {
            output.stdout.trim().to_owned()
        } else {
            format!("{} {}", output.stdout.trim(), output.stderr.trim())
                .trim()
                .to_owned()
        };
        Ok(Systemctl {
            success: output.success,
            stdout,
        })
    }
}
