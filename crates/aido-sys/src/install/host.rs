//! The file operations an install performs, on a real filesystem.
//!
//! Every path is split into a directory and a name. The directory is opened by
//! the descriptor walk from `/` ([`open_trusted`]), so every ancestor is root's
//! and none is writable by anyone else, and everything after that is relative
//! to the descriptor: `openat` with `O_NOFOLLOW`, `statat` without following a
//! link, `renameat` and `unlinkat` within one directory. A path string is never
//! the thing a check and an act both rely on.
//!
//! # Whose file it is
//!
//! aido removes or replaces a file only if it can show the file is its own: a
//! regular file, owned by root, with exactly one name, beginning with
//! [`MANAGED_MARKER`], on the descriptor that was opened, with the name
//! re-checked against that descriptor before the unlink. A planted symbolic
//! link, a second hard link, a directory, or an operator's own `aido` file is
//! refused, not overwritten.
//!
//! A shared file (`/etc/doas.conf`) is the operator's. It is edited under an
//! exclusive `flock`, a whole new copy is written beside it and checked by the
//! backend's own parser, and only then is it renamed over the original, so a
//! reader sees the old file or the new one and never a half-written one. Only
//! the lines between aido's sentinels are ever added or removed.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

use aido_backend::snippet::{DOAS_BEGIN, DOAS_END, MANAGED_MARKER};
use rustix::fs::{
    AtFlags, FlockOperation, Gid, Mode, OFlags, RawMode, Stat, Uid, fchmod, fchown, flock, fstat,
    fsync, openat, renameat, statat, unlinkat,
};
use rustix::io::Errno;

use super::blocks;
use super::{FileIdentity, InstallError, InstallOps, Removal, split, substitute};
use crate::exec::{HostRunner, Runner};
use crate::trust::{Kind, TRUSTED_UID, TrustError, facts_of, open_trusted};

/// The only user and group an aido file may belong to.
const TRUSTED_GID: u32 = 0;

/// How long to wait for another process to release a shared file's lock.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The pause between attempts to take the lock.
const LOCK_RETRY: Duration = Duration::from_millis(5);

/// The largest shared file aido will read. `doas.conf` is a few lines; a file
/// this size is not one.
const MAX_SHARED_BYTES: u64 = 1 << 20;

/// What a drop-in's candidate name ends with (`aido.candidate`).
const CANDIDATE_SUFFIX: &str = ".candidate";

/// The suffix of the copy a shared file's new contents are checked on.
const COPY_SUFFIX: &str = ".aido-new";

/// The system group tools, tried in order.
const GROUP_TOOLS: [(&str, &[&str]); 2] = [
    ("/usr/sbin/groupadd", &["--system", "aido"]),
    ("/usr/sbin/addgroup", &["-S", "aido"]),
];

/// How a directory is opened: production walks it from `/` as root's, and
/// answers `None` for a directory that does not exist.
type OpenDir = Box<dyn Fn(&Path) -> Result<Option<OwnedFd>, TrustError>>;

/// What a shared file's editor does with its current contents: the new
/// contents, or `None` when there is nothing to change.
type Edit<'a> = &'a dyn Fn(&[u8]) -> Result<Option<Vec<u8>>, blocks::BlockError>;

/// Reads the real machine, and writes to it.
pub struct HostInstallOps {
    open_dir: OpenDir,
    runner: Box<dyn Runner>,
    owner: u32,
    group: u32,
    lock_wait: Duration,
}

impl HostInstallOps {
    /// The real machine: directories walked from `/` as root's, validators and
    /// group tools run as real processes, files made `root:root`.
    pub fn system() -> Self {
        Self {
            open_dir: Box::new(open_system_dir),
            runner: Box::new(HostRunner),
            owner: TRUSTED_UID,
            group: TRUSTED_GID,
            lock_wait: LOCK_WAIT,
        }
    }

    /// Splits `path` and opens its directory, or `None` when the directory is
    /// not there.
    fn locate_dir<'p>(&self, path: &'p str) -> Result<Option<(OwnedFd, &'p str)>, InstallError> {
        let (dir, name) = split(path).ok_or_else(|| InstallError::Io {
            operation: "locate",
            path: path.to_owned(),
            reason: "not an absolute path to a file".to_owned(),
        })?;
        if name == "." || name == ".." {
            return Err(InstallError::Io {
                operation: "locate",
                path: path.to_owned(),
                reason: "a file name cannot be `.` or `..`".to_owned(),
            });
        }
        let dir = if dir.is_empty() { "/" } else { dir };
        let opened = (self.open_dir)(Path::new(dir)).map_err(InstallError::Untrusted)?;
        Ok(opened.map(|fd| (fd, name)))
    }

    /// [`Self::locate_dir`] for an operation that needs the directory to be
    /// there.
    fn locate<'p>(&self, path: &'p str) -> Result<(OwnedFd, &'p str), InstallError> {
        self.locate_dir(path)?.ok_or_else(|| InstallError::Io {
            operation: "locate",
            path: path.to_owned(),
            reason: "its directory does not exist".to_owned(),
        })
    }

    /// Whether `stat` describes a regular file of the trusted owner with one
    /// name; the reason it does not, otherwise.
    fn why_not_ours(&self, stat: &Stat) -> Option<&'static str> {
        let facts = facts_of(stat);
        if facts.kind != Kind::File {
            Some("it is not a regular file")
        } else if facts.uid != self.owner {
            Some("it is not owned by root")
        } else if links(stat) != 1 {
            Some("it has more than one name")
        } else {
            None
        }
    }

    /// Whether `name` is present, and a file aido wrote: `false` when it is
    /// absent.
    ///
    /// # Errors
    ///
    /// [`InstallError::NotOurs`] for anything present that is not aido's.
    ///
    /// `partial_ok` also accepts a file that holds only the start of the marker,
    /// or nothing: what a run killed while writing a candidate leaves. Only a
    /// candidate's name asks for it; a file at a destination holds the marker or
    /// is not aido's.
    fn inspect_managed(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        path: &str,
        partial_ok: bool,
    ) -> Result<bool, InstallError> {
        let not_ours = |reason: &str| InstallError::NotOurs {
            path: path.to_owned(),
            reason: reason.to_owned(),
        };
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = match openat(dir, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(false),
            Err(Errno::LOOP) => return Err(not_ours("it is a symbolic link")),
            Err(errno) => return Err(io("open", path)(errno)),
        };
        // The checks on a descriptor that is already open: its owner, its kind,
        // its names, then its first bytes. Combinators rather than `?`, so a
        // failure of `fstat` or `read` on a descriptor just opened — which no
        // test can make happen — is not a branch of this function that nothing
        // has ever taken.
        fstat(&fd)
            .map_err(io("stat", path))
            .and_then(|stat| match self.why_not_ours(&stat) {
                Some(reason) => Err(not_ours(reason)),
                None => read_head(fd, MANAGED_MARKER.len()).map_err(io_std("read", path)),
            })
            .and_then(|head| {
                let marker = MANAGED_MARKER.as_bytes();
                if head.starts_with(marker) || (partial_ok && marker.starts_with(&head)) {
                    Ok(true)
                } else {
                    Err(not_ours("it does not begin with aido's marker"))
                }
            })
    }

    /// Renames within one directory and syncs it.
    fn rename_over(
        dir: BorrowedFd<'_>,
        from: &str,
        to: &str,
        path: &str,
    ) -> Result<(), InstallError> {
        renameat(dir, from, dir, to)
            .map_err(io("rename", path))
            .map(|()| {
                // Best effort. The new file's data is already synced, so a
                // crash leaves the old file or the whole new one; the directory
                // entry is what this makes durable, and an error here cannot
                // un-install anything.
                let _ = fsync(dir);
            })
    }

    /// Runs a validator and judges its exit status.
    fn run_validator(&self, argv: &[String]) -> Result<(), InstallError> {
        let exe = argv.first().map_or("", String::as_str);
        let rest: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
        let output = self.runner.run(exe, &rest, None).map_err(|source| {
            InstallError::ValidatorRejected {
                detail: source.to_string(),
            }
        })?;
        if output.success {
            Ok(())
        } else {
            Err(InstallError::ValidatorRejected {
                detail: format!("{} {}", output.stdout.trim(), output.stderr.trim())
                    .trim()
                    .to_owned(),
            })
        }
    }

    /// Takes `fd`'s exclusive lock, waiting a bounded time.
    fn lock(&self, fd: BorrowedFd<'_>, path: &str) -> Result<(), InstallError> {
        let started = Instant::now();
        loop {
            match flock(fd, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(()),
                Err(Errno::WOULDBLOCK) if started.elapsed() < self.lock_wait => {
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(errno) => {
                    return Err(InstallError::Locked {
                        path: path.to_owned(),
                        reason: errno.to_string(),
                    });
                }
            }
        }
    }

    /// Opens, checks, locks, and reads a shared file.
    ///
    /// Everything after the open is a chain, for the reason given at
    /// [`Self::inspect_managed`]: the steps that cannot fail in a test do not
    /// get a `?` of their own.
    fn load_shared(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        path: &str,
    ) -> Result<Shared, InstallError> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let unsafe_file = |reason: &str| InstallError::UnsafeFile {
            path: path.to_owned(),
            reason: reason.to_owned(),
        };
        openat(dir, name, flags, Mode::empty())
            .map_err(|errno| match errno {
                Errno::NOENT => InstallError::Missing {
                    path: path.to_owned(),
                },
                other => io("open", path)(other),
            })
            .and_then(|fd| {
                fstat(&fd)
                    .map(|before| (fd, before))
                    .map_err(io("stat", path))
            })
            .and_then(|(fd, before)| {
                if let Some(reason) = self.why_not_ours(&before) {
                    Err(unsafe_file(reason))
                } else if facts_of(&before).mode & 0o022 != 0 {
                    Err(unsafe_file("it is writable by group or others"))
                } else if facts_of(&before).mode & 0o7000 != 0 {
                    // The copy would carry the bit across, onto a file aido
                    // made. Nothing legitimate sets one on a configuration file.
                    Err(unsafe_file(
                        "it has a set-user-ID, set-group-ID or sticky bit",
                    ))
                } else {
                    self.lock(fd.as_fd(), path).map(|()| (fd, before))
                }
            })
            .and_then(|(fd, before)| {
                // The lock is on the inode opened. If the name has moved on,
                // the lock guards a file that is no longer the shared one.
                let still = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
                    .is_ok_and(|named| identity_of(&named) == identity_of(&before));
                if still {
                    Ok((fd, before))
                } else {
                    Err(InstallError::Locked {
                        path: path.to_owned(),
                        reason: "the file was moved or replaced while waiting for its lock"
                            .to_owned(),
                    })
                }
            })
            .and_then(|(fd, before)| {
                read_all(fd.as_fd(), path).map(|current| Shared {
                    _lock: fd,
                    uid: before.st_uid,
                    gid: before.st_gid,
                    mode: facts_of(&before).mode,
                    current,
                })
            })
            .and_then(|shared| {
                if u64::try_from(shared.current.len()).unwrap_or(u64::MAX) > MAX_SHARED_BYTES {
                    Err(unsafe_file("it is too large to be a configuration file"))
                } else {
                    Ok(shared)
                }
            })
    }

    /// Rewrites a shared file through `edit`, under its lock.
    ///
    /// `Ok(false)` when `edit` found nothing to change.
    fn rewrite_shared(
        &self,
        path: &str,
        edit: Edit<'_>,
        validator: Option<&[String]>,
    ) -> Result<bool, InstallError> {
        let Some((dir, name)) = self.locate_dir(path)? else {
            return Err(InstallError::Missing {
                path: path.to_owned(),
            });
        };
        let shared = self.load_shared(dir.as_fd(), name, path)?;
        let Some(updated) = edit(&shared.current).map_err(|source| InstallError::Block {
            path: path.to_owned(),
            source,
        })?
        else {
            return Ok(false);
        };

        let copy = format!("{path}{COPY_SUFFIX}");
        let copy_name = format!("{name}{COPY_SUFFIX}");
        // The copy replaces the operator's file, so it is made the operator's
        // file: the same owner, group and permission bits, never aido's choice.
        let written =
            self.create_candidate(&copy, &updated, (shared.uid, shared.gid), shared.mode)?;
        let verdict = validator.map_or(Ok(()), |argv| self.run_validator(&substitute(argv, &copy)));
        if let Err(rejected) = verdict {
            return Err(self.cleaned(&copy, written, rejected));
        }
        let unchanged = statat(&dir, copy_name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|now| identity_of(&now) == written);
        if !unchanged {
            return Err(InstallError::CandidateReplaced { path: copy });
        }
        // The lock in `shared` is held until here, through the rename.
        Self::rename_over(dir.as_fd(), &copy_name, name, path).map(|()| true)
    }

    /// Creates `path` exclusively, writes `contents`, and gives it `owner`
    /// (user, group) and `mode` on the descriptor. Returns the inode written.
    ///
    /// The name may be taken by what an interrupted run of aido left: that, and
    /// only that, is removed ([`Self::reclaim_stale`]), once, and the create
    /// tried again. A second refusal is an error; the loop is bounded.
    fn create_candidate(
        &self,
        path: &str,
        contents: &[u8],
        owner: (u32, u32),
        mode: u32,
    ) -> Result<FileIdentity, InstallError> {
        let (dir, name) = self.locate(path)?;
        // Exclusive: an existing name is somebody's file, never overwritten. No
        // access bits until the owner and mode are on the descriptor.
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut attempt = openat(&dir, name, flags, Mode::empty());
        if matches!(attempt, Err(Errno::EXIST)) {
            self.reclaim_stale(dir.as_fd(), name, path, contents)?;
            // The one retry. Whatever this answers is the answer: a name taken
            // again, or any other refusal, is reported and not tried a third time.
            attempt = openat(&dir, name, flags, Mode::empty());
        }
        let fd = attempt.map_err(io("create", path))?;
        // The steps on the descriptor just created, each only if the one before
        // succeeded. A chain rather than `?`, because only the owner can be made
        // to fail from a test; see [`Self::inspect_managed`].
        let mut file = File::from(fd);
        let filled = file
            .write_all(contents)
            .map_err(io_std("write", path))
            .and_then(|()| {
                fchown(
                    &file,
                    Some(Uid::from_raw(owner.0)),
                    Some(Gid::from_raw(owner.1)),
                )
                .map_err(io("chown", path))
            })
            .and_then(|()| fchmod(&file, raw_mode(mode)).map_err(io("chmod", path)))
            .and_then(|()| file.sync_all().map_err(io_std("sync", path)))
            .and_then(|()| {
                fstat(&file)
                    .map(|stat| identity_of(&stat))
                    .map_err(io("stat", path))
            });
        // This call created the name, so it is this call's to remove.
        filled.inspect_err(|_| {
            let _ = unlinkat(&dir, name, AtFlags::empty());
        })
    }

    /// Removes the file at `name` if, and only if, it is what an interrupted aido
    /// run leaves: a run killed between creating a candidate and renaming it.
    ///
    /// "Ours" is shown, not assumed: a regular file, root's, with one name, that
    /// nobody but root can write, whose bytes are a prefix of what this run is
    /// about to write. An empty file left by a crash right after the create
    /// counts; a file somebody else wrote does not. The directory was walked as
    /// root's, so nobody who could not already do worse can swap the name
    /// between this look and the unlink.
    ///
    /// # Errors
    ///
    /// [`InstallError::StaleCandidate`] for anything else, with nothing removed.
    fn reclaim_stale(
        &self,
        dir: BorrowedFd<'_>,
        name: &str,
        path: &str,
        expected: &[u8],
    ) -> Result<(), InstallError> {
        let refuse = |reason: &str| InstallError::StaleCandidate {
            path: path.to_owned(),
            reason: reason.to_owned(),
        };
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = match openat(dir, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            // Gone since the create failed: nothing in the way now.
            Err(Errno::NOENT) => return Ok(()),
            Err(Errno::LOOP) => return Err(refuse("it is a symbolic link")),
            Err(errno) => return Err(io("open", path)(errno)),
        };
        // A chain, for the reason given at [`Self::inspect_managed`].
        fstat(&fd)
            .map_err(io("stat", path))
            .and_then(|stat| match self.why_not_ours(&stat) {
                Some(reason) => Err(refuse(reason)),
                None if facts_of(&stat).mode & 0o022 != 0 => {
                    Err(refuse("it is writable by group or others"))
                }
                None => {
                    read_head(fd, expected.len().saturating_add(1)).map_err(io_std("read", path))
                }
            })
            .and_then(|found| {
                if expected.starts_with(&found) {
                    Ok(())
                } else {
                    Err(refuse(
                        "its contents are not what this run would have written",
                    ))
                }
            })?;
        unlinkat(dir, name, AtFlags::empty()).map_err(io("unlink", path))
    }

    /// Removes the copy this call wrote, and reports `error` — plus what could
    /// not be cleaned, if anything.
    fn cleaned(&self, path: &str, identity: FileIdentity, error: InstallError) -> InstallError {
        match self.discard(path, identity) {
            Ok(()) => error,
            Err(failed) => InstallError::LeftBehind {
                path: path.to_owned(),
                reason: failed.to_string(),
                cause: Box::new(error),
            },
        }
    }
}

/// The directory walk production uses: every ancestor root's, none writable by
/// anyone else. A directory that does not exist is `None`, not a refusal, so a
/// removal on a machine that never had `sudo` has nothing to do and says so.
fn open_system_dir(path: &Path) -> Result<Option<OwnedFd>, TrustError> {
    open_trusted(path).map(Some).or_else(|refused| {
        let missing = std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        if missing { Ok(None) } else { Err(refused) }
    })
}

/// A shared file, opened, checked, locked, and read.
struct Shared {
    /// The descriptor the lock is on. Dropped, and the lock with it, when the
    /// edit is over.
    _lock: OwnedFd,
    /// Its owner, which is root: [`HostInstallOps::why_not_ours`] has checked.
    uid: u32,
    /// Its group, which the copy keeps.
    gid: u32,
    /// The permission bits it had.
    mode: u32,
    /// What it held.
    current: Vec<u8>,
}

/// All of a descriptor's contents, up to one byte past the most aido will read,
/// through a duplicate so the original keeps its lock.
fn read_all(fd: BorrowedFd<'_>, path: &str) -> Result<Vec<u8>, InstallError> {
    fd.try_clone_to_owned()
        .map_err(io_std("dup", path))
        .and_then(|duplicate| {
            let mut bytes = Vec::new();
            File::from(duplicate)
                .take(MAX_SHARED_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
                .map(|_| bytes)
                .map_err(io_std("read", path))
        })
}

/// A failed system call, named.
fn io<'a>(operation: &'static str, path: &'a str) -> impl FnOnce(Errno) -> InstallError + 'a {
    move |errno| InstallError::Io {
        operation,
        path: path.to_owned(),
        reason: errno.to_string(),
    }
}

/// A failed `std::io` call, named.
fn io_std<'a>(
    operation: &'static str,
    path: &'a str,
) -> impl FnOnce(std::io::Error) -> InstallError + 'a {
    move |error| InstallError::Io {
        operation,
        path: path.to_owned(),
        reason: error.to_string(),
    }
}

/// `st_nlink` is a `u64`, a `u32`, or a `u16` depending on the platform.
#[allow(clippy::useless_conversion)]
fn links(stat: &Stat) -> u64 {
    u64::from(stat.st_nlink)
}

/// The inode a `stat` describes. `st_dev` is signed on some platforms, and the
/// pair only has to tell two files apart.
#[allow(
    clippy::cast_sign_loss,
    clippy::unnecessary_cast,
    clippy::useless_conversion
)]
fn identity_of(stat: &Stat) -> FileIdentity {
    FileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    }
}

/// The first `len` bytes of a file.
fn read_head(fd: OwnedFd, len: usize) -> std::io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(len);
    File::from(fd)
        .take(u64::try_from(len).unwrap_or(u64::MAX))
        .read_to_end(&mut head)?;
    Ok(head)
}

/// A permission mode as the kernel's type, stripped of anything beyond the
/// permission bits.
fn raw_mode(mode: u32) -> Mode {
    Mode::from_bits_truncate(RawMode::try_from(mode & 0o7777).unwrap_or(0))
}

impl InstallOps for HostInstallOps {
    fn effective_uid(&self) -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn group_exists(&self, name: &str) -> Result<bool, InstallError> {
        let group_error = |reason: String| InstallError::Group {
            name: name.to_owned(),
            reason,
        };
        let output = self
            .runner
            .run("/usr/bin/getent", &["group", name], None)
            .map_err(|source| group_error(source.to_string()))?;
        match output.code {
            Some(0) => Ok(true),
            // getent's documented answer for a key that is not in the database.
            Some(2) => Ok(false),
            _ => Err(group_error(format!(
                "getent answered {:?}: {}",
                output.code,
                output.stderr.trim()
            ))),
        }
    }

    fn create_group(&self, name: &str) -> Result<(), InstallError> {
        let mut failures = Vec::new();
        for (exe, args) in GROUP_TOOLS {
            match self.runner.run(exe, args, None) {
                Ok(output) if output.success => return Ok(()),
                Ok(output) => failures.push(format!("{exe}: {}", output.stderr.trim())),
                // A tool this distribution does not have: try the next.
                Err(source) => failures.push(source.to_string()),
            }
        }
        Err(InstallError::Group {
            name: name.to_owned(),
            reason: failures.join("; "),
        })
    }

    fn write_candidate(
        &self,
        path: &str,
        contents: &[u8],
        mode: u32,
    ) -> Result<FileIdentity, InstallError> {
        self.create_candidate(path, contents, (self.owner, self.group), mode)
    }
    fn validate(&self, argv: &[String]) -> Result<(), InstallError> {
        self.run_validator(argv)
    }

    fn identity(&self, path: &str) -> Result<FileIdentity, InstallError> {
        let (dir, name) = self.locate(path)?;
        statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW)
            .map(|stat| identity_of(&stat))
            .map_err(io("stat", path))
    }

    fn install(&self, from: &str, to: &str, identity: FileIdentity) -> Result<(), InstallError> {
        let (dir, from_name) = self.locate(from)?;
        let (_, to_name) = self.locate(to)?;
        let now = statat(&dir, from_name, AtFlags::SYMLINK_NOFOLLOW).map_err(io("stat", from))?;
        if identity_of(&now) != identity {
            return Err(InstallError::CandidateReplaced {
                path: from.to_owned(),
            });
        }
        // An existing destination must be a file aido wrote. A reinstall
        // replaces aido's own file; an operator's `aido` is refused.
        self.inspect_managed(dir.as_fd(), to_name, to, false)?;
        Self::rename_over(dir.as_fd(), from_name, to_name, to)
    }

    fn discard(&self, path: &str, identity: FileIdentity) -> Result<(), InstallError> {
        let (dir, name) = self.locate(path)?;
        match statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => Ok(()),
            Err(errno) => Err(io("stat", path)(errno)),
            Ok(stat) if identity_of(&stat) != identity => Err(InstallError::CandidateReplaced {
                path: path.to_owned(),
            }),
            Ok(_) => unlinkat(&dir, name, AtFlags::empty()).map_err(io("unlink", path)),
        }
    }

    fn remove_managed(&self, path: &str) -> Result<Removal, InstallError> {
        // A directory that is not there holds nothing of aido's.
        let Some((dir, name)) = self.locate_dir(path)? else {
            return Ok(Removal::Absent);
        };
        if !self.inspect_managed(dir.as_fd(), name, path, name.ends_with(CANDIDATE_SUFFIX))? {
            return Ok(Removal::Absent);
        }
        // The directory was walked as root's and nobody else can write it, so
        // the name cannot be swapped between the check and this unlink by
        // anyone who could not already do worse.
        unlinkat(&dir, name, AtFlags::empty())
            .map_err(io("unlink", path))
            .map(|()| Removal::Removed)
    }

    fn append_block(
        &self,
        path: &str,
        block: &str,
        validator: &[String],
    ) -> Result<(), InstallError> {
        self.rewrite_shared(
            path,
            &|current| {
                blocks::insert(
                    current,
                    block.as_bytes(),
                    DOAS_BEGIN.as_bytes(),
                    DOAS_END.as_bytes(),
                )
                .map(Some)
            },
            Some(validator),
        )
        .map(|_| ())
    }

    fn remove_block(&self, path: &str) -> Result<Removal, InstallError> {
        let changed = match self.rewrite_shared(
            path,
            &|current| blocks::remove(current, DOAS_BEGIN.as_bytes(), DOAS_END.as_bytes()),
            None,
        ) {
            // Nothing to remove from a file that is not there.
            Err(InstallError::Missing { .. }) => false,
            other => other?,
        };
        Ok(if changed {
            Removal::Removed
        } else {
            Removal::Absent
        })
    }
}

#[cfg(test)]
mod tests;
