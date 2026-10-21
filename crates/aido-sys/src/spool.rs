//! The spool: where the broker leaves a request for the gate.
//!
//! `/run/aido/req`, root-owned `0700`, under `/run` so entries vanish at boot
//! and never share a directory with anything a user can write. The broker
//! writes entries; the gate reads and consumes them.
//!
//! Everything here is bytes. What an entry *means* — `aido-gate`'s
//! `PendingRequest` — and which entries to keep is the broker's business; this
//! module only guarantees how they are opened, read, written, and removed:
//!
//! * **Through the descriptor the trust walk opened.** [`SpoolDir::open`]
//!   walks from `/` with the same per-component check as the ruleset, then
//!   demands more of the last component: a directory that gives group and
//!   other nothing at all. Every later operation is relative to that
//!   descriptor, never to a path, so the directory checked is the directory
//!   written.
//! * **Atomically.** An entry is created `O_CREAT|O_EXCL|O_NOFOLLOW`, mode
//!   `0600`, under a temporary name no nonce can have — so the gate never sees
//!   it half-written — and renamed into place with `RENAME_NOREPLACE`, so a
//!   name that already exists is a refusal, never an overwrite.
//! * **Under one lock.** [`Spool::lock`] takes `flock(LOCK_EX)` on the
//!   directory, so concurrent brokers (`Accept=yes` starts one per
//!   connection) prune and publish one at a time.
//! * **Taken by an unlink, exactly once.** The gate does not lock: two gates
//!   may read the same entry, and the unlink is what decides between them.
//!   [`Spool::consume`] is therefore the one operation here whose "already
//!   gone" is a *refusal* ([`SpoolError::Gone`]) and not a success, where the
//!   broker's tidying, [`Spool::remove`], treats the same answer as the
//!   outcome it wanted. A gate that read a missing name as consumed would run
//!   the command a second time.
//!
//! The owner is a parameter of the descriptor half only, as in `trust.rs`:
//! [`SpoolDir::open`] always demands root, and the tests point the descriptor
//! half at a directory they created, with their own uid.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use bstr::ByteSlice;
use rustix::fs::{
    AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, Stat, fchmod, flock, fstat,
    openat, renameat_with, unlinkat,
};

use crate::mounts::{HostMounts, MountView};
use crate::trust::{TRUSTED_UID, TrustError, open_trusted_with};

/// Where the broker writes a new entry before renaming it into place.
///
/// The prefix makes the name something no nonce can be — a nonce is exactly
/// 64 lowercase hex characters — so the gate's own filter skips it.
pub const TEMP_PREFIX: &str = ".tmp.";

/// Why the spool cannot be used, or one operation on it failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SpoolError {
    /// The walk from `/` refused a component.
    #[error(transparent)]
    Untrusted(#[from] TrustError),
    /// The spool is not a directory.
    #[error("{at} is not a directory")]
    NotADirectory {
        /// The spool's path.
        at: String,
    },
    /// The spool belongs to someone other than root.
    #[error("{at} is owned by uid {uid}, not root")]
    NotOwned {
        /// The spool's path.
        at: String,
        /// Who owns it.
        uid: u32,
    },
    /// Group or other may use the spool.
    #[error("{at} has mode {mode:04o}: the spool must give group and other nothing")]
    Exposed {
        /// The spool's path.
        at: String,
        /// Its mode.
        mode: u32,
    },
    /// A name is not one plain component.
    #[error("{name} is not a name an entry can have")]
    InvalidName {
        /// The name, escaped for display.
        name: String,
    },
    /// An entry cannot be read as one the spool's owner wrote privately.
    #[error("{name} cannot be read as a spool entry: {reason}")]
    Unreadable {
        /// The entry's name, escaped for display.
        name: String,
        /// Why.
        reason: String,
    },
    /// An entry is larger than the reader allows.
    #[error("{name} is larger than {limit} bytes")]
    TooLarge {
        /// The entry's name, escaped for display.
        name: String,
        /// The limit it exceeded.
        limit: usize,
    },
    /// The name an entry was to be published under is taken.
    #[error("{name} already exists in the spool")]
    Exists {
        /// The name.
        name: String,
    },
    /// The entry to consume is not there: somebody else took it first.
    ///
    /// Only [`Spool::consume`] reports it. The consumer is claiming the right
    /// to act on what the entry authorizes, the unlink is the claim, and the
    /// claimant who finds the name already gone lost.
    #[error("{name} is already gone from the spool: another consumer took it first")]
    Gone {
        /// The name.
        name: String,
    },
    /// A system call on the spool failed.
    #[error("{operation} in {at} failed: {reason}")]
    Io {
        /// The call.
        operation: String,
        /// The spool's path.
        at: String,
        /// The errno, when there was one.
        code: Option<i32>,
        /// The operating system's account of why.
        reason: String,
    },
}

/// The operations the broker performs on the spool, as a seam.
pub trait Spool {
    /// Takes the spool's exclusive lock, waiting for any other holder.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Io`] if the lock cannot be taken.
    fn lock(&self) -> Result<(), SpoolError>;

    /// Releases the lock. Best effort: it is released when the spool is
    /// closed anyway.
    fn unlock(&self);

    /// Every name in the spool, `.` and `..` excepted.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Io`] if the directory cannot be read.
    fn names(&self) -> Result<Vec<Vec<u8>>, SpoolError>;

    /// At most `limit` names in the spool, `.` and `..` excepted, and no more
    /// of the directory read than that takes.
    ///
    /// For a reader that will refuse a spool with more names than it is
    /// prepared to walk, and so must not first read all of them: a listing
    /// that stops one name past the bound is enough to see the bound crossed,
    /// at a cost that does not grow with the directory. Which names come back,
    /// when there are more than `limit`, is the directory's order and nothing
    /// a caller may rely on.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Io`] if the directory cannot be read.
    fn names_up_to(&self, limit: usize) -> Result<Vec<Vec<u8>>, SpoolError>;

    /// Reads one entry: a regular file, owned by the spool's owner, private to
    /// it, and at most `limit` bytes.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Unreadable`] for anything that is not such a file,
    /// including a link, which is never followed; [`SpoolError::TooLarge`]
    /// past the limit; [`SpoolError::InvalidName`] for a name that is not one
    /// component.
    fn read(&self, name: &[u8], limit: usize) -> Result<Vec<u8>, SpoolError>;

    /// Removes one entry. A name that is already gone is not an error: the
    /// gate may have consumed it a moment ago.
    ///
    /// This is the broker's tidying, and the opposite of [`Self::consume`] on
    /// exactly that point: here a missing name is the outcome that was wanted.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Io`] if it exists and cannot be removed, and
    /// [`SpoolError::InvalidName`] for a name that is not one component.
    fn remove(&self, name: &[u8]) -> Result<(), SpoolError>;

    /// Takes one entry, so that it can be acted on at most once.
    ///
    /// The gate's operation. The unlink is the claim: two gates that read the
    /// same entry both reach it, and exactly one succeeds. The one that finds
    /// the name already gone **lost the race** and must run nothing, so a
    /// missing name is [`SpoolError::Gone`], never `Ok`. That is the whole
    /// difference from [`Self::remove`], which treats the same answer as
    /// success.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Gone`] if the name is not there,
    /// [`SpoolError::Io`] if it exists and cannot be removed, and
    /// [`SpoolError::InvalidName`] for a name that is not one component.
    fn consume(&self, name: &[u8]) -> Result<(), SpoolError>;

    /// Writes `bytes` as the entry `name`, atomically and without replacing
    /// anything.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Exists`] if `name` is taken, [`SpoolError::InvalidName`]
    /// for a name that is not one component, and [`SpoolError::Io`] for any
    /// other failure. The temporary file is removed on every failure after it
    /// was created.
    fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), SpoolError>;
}

/// The real spool directory, held open by descriptor.
#[derive(Debug)]
pub struct SpoolDir {
    dir: OwnedFd,
    path: PathBuf,
    owner: u32,
}

impl SpoolDir {
    /// Opens the spool at `path` through the trust walk and checks that it is
    /// a root-owned directory private to root.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Untrusted`] for the first component the walk refuses —
    /// including a spool that does not exist — and otherwise
    /// [`SpoolError::NotADirectory`], [`SpoolError::NotOwned`], or
    /// [`SpoolError::Exposed`].
    pub fn open(path: &Path) -> Result<Self, SpoolError> {
        Self::open_with(path, &HostMounts::proc())
    }

    /// [`Self::open`], with the mount table as a parameter.
    fn open_with(path: &Path, view: &dyn MountView) -> Result<Self, SpoolError> {
        let dir = open_trusted_with(path, TRUSTED_UID, view)?;
        Self::from_dir(dir, path, TRUSTED_UID)
    }

    /// The descriptor half of [`Self::open`], for a directory already open.
    ///
    /// `owner` is [`TRUSTED_UID`] outside this module's tests.
    fn from_dir(dir: OwnedFd, path: &Path, owner: u32) -> Result<Self, SpoolError> {
        let at = path.display().to_string();
        // The descriptor is open, so `fstat` cannot fail on it; if it somehow
        // did, the stand-in facts describe something no check accepts.
        let (kind, uid, mode) = fstat(&dir).map_or((FileType::Unknown, u32::MAX, 0o7777), |st| {
            (
                FileType::from_raw_mode(st.st_mode),
                st.st_uid,
                mode_bits(&st),
            )
        });
        if kind != FileType::Directory {
            return Err(SpoolError::NotADirectory { at });
        }
        if uid != owner {
            return Err(SpoolError::NotOwned { at, uid });
        }
        if mode & 0o077 != 0 {
            return Err(SpoolError::Exposed { at, mode });
        }
        Ok(Self {
            dir,
            path: path.to_path_buf(),
            owner,
        })
    }

    /// Shapes a failed call on the spool.
    fn failure(&self, operation: &str, error: &std::io::Error) -> SpoolError {
        SpoolError::Io {
            operation: operation.to_owned(),
            at: self.path.display().to_string(),
            code: error.raw_os_error(),
            reason: error.to_string(),
        }
    }

    /// Shapes the result of a call that has no other failure to report.
    ///
    /// A plain function over the result, so the failure arm is reachable from
    /// a test with a real errno: `flock` and `readdir` do not fail on a
    /// directory this process holds open.
    fn checked<T>(&self, operation: &str, result: rustix::io::Result<T>) -> Result<T, SpoolError> {
        match result {
            Ok(value) => Ok(value),
            Err(errno) => Err(self.failure(operation, &errno.into())),
        }
    }

    /// Checks that a stat describes an entry the owner wrote privately.
    fn check_entry(&self, name: &str, stat: &Stat) -> Result<(), SpoolError> {
        let refuse = |reason: String| SpoolError::Unreadable {
            name: name.to_owned(),
            reason,
        };
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(refuse("not a regular file".to_owned()));
        }
        if stat.st_uid != self.owner {
            return Err(refuse(format!("owned by uid {}", stat.st_uid)));
        }
        let mode = mode_bits(stat);
        if mode & 0o077 != 0 {
            return Err(refuse(format!(
                "mode {mode:04o} gives group or other access"
            )));
        }
        // One name, because the unlink that consumes an entry removes only
        // the name it is given: an entry that is also known by another name
        // would outlive its own consumption.
        let names = link_count(stat);
        if names != 1 {
            return Err(refuse(format!(
                "{names} names, and an entry has exactly one"
            )));
        }
        Ok(())
    }

    /// Shapes a failed publish: a taken name, or anything else.
    fn publish_failure(&self, name: &str, error: &std::io::Error) -> SpoolError {
        if error.raw_os_error() == Some(rustix::io::Errno::EXIST.raw_os_error()) {
            SpoolError::Exists {
                name: name.to_owned(),
            }
        } else {
            self.failure("publish", error)
        }
    }

    /// Unlinks `name` through the directory descriptor, and says whether there
    /// was a name to unlink.
    ///
    /// The one unlink behind both [`Spool::remove`] and [`Spool::consume`], so
    /// that what they disagree about is only what to make of `false`.
    fn unlink_entry(&self, name: &[u8]) -> Result<bool, SpoolError> {
        match unlinkat(&self.dir, plain(name)?, AtFlags::empty()) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(errno) => Err(self.failure("unlinkat", &errno.into())),
        }
    }
}

/// The permission bits in a stat, masked to `0o7777`.
///
/// `st_mode` is a `u32` on Linux and a `u16` on macOS, so the widening is a
/// real conversion on one platform and an identity on the other.
#[allow(clippy::useless_conversion)]
fn mode_bits(stat: &Stat) -> u32 {
    u32::from(Mode::from_raw_mode(stat.st_mode).bits()) & 0o7777
}

/// How many names a stat says the file has.
///
/// `st_nlink` is a `u64` on x86-64 Linux, a `u32` on arm Linux, and a `u16` on
/// macOS: a real widening on two and an identity on the third, as `st_mode`
/// is for [`mode_bits`].
#[allow(clippy::useless_conversion)]
fn link_count(stat: &Stat) -> u64 {
    u64::from(stat.st_nlink)
}

/// Whether `name` is one plain component: non-empty, no `/`, not `.` or `..`.
///
/// Entry names come from this directory's own listing or from the broker's
/// hex nonce, so this never refuses a real one; it exists so no call can be
/// steered out of the directory by a name.
fn plain(name: &[u8]) -> Result<&OsStr, SpoolError> {
    if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
        return Err(SpoolError::InvalidName {
            name: name.as_bstr().to_string(),
        });
    }
    Ok(OsStr::from_bytes(name))
}

/// The first `limit` names among a directory's entries, `.` and `..` not
/// counted, and no more of the entries pulled than that takes.
///
/// A directory is read in batches as its iterator is pulled, so stopping the
/// iterator is what stops the reading: a spool of millions of names costs what
/// `limit` of them do. `.` and `..` are dropped before the count, so a
/// directory of exactly `limit` entries comes back whole. An error among the
/// first `limit` is the error; one beyond them is never reached.
fn first_names(
    entries: impl Iterator<Item = rustix::io::Result<Vec<u8>>>,
    limit: usize,
) -> rustix::io::Result<Vec<Vec<u8>>> {
    entries
        .filter(|name| !matches!(name, Ok(name) if name == b"." || name == b".."))
        .take(limit)
        .collect()
}

/// Reads the outcome of a bounded read as an entry's contents.
///
/// One byte past the limit is read on purpose, so a file that grew after its
/// size was checked is still caught. Split out so the failure arms are
/// reachable from a test: reading a regular file this process opened does not
/// fail.
fn contents_from(
    read: std::io::Result<usize>,
    bytes: Vec<u8>,
    name: String,
    limit: usize,
) -> Result<Vec<u8>, SpoolError> {
    match read {
        Ok(_) if bytes.len() > limit => Err(SpoolError::TooLarge { name, limit }),
        Ok(_) => Ok(bytes),
        Err(error) => Err(SpoolError::Unreadable {
            name,
            reason: error.to_string(),
        }),
    }
}

impl Spool for SpoolDir {
    fn lock(&self) -> Result<(), SpoolError> {
        self.checked("flock", flock(&self.dir, FlockOperation::LockExclusive))
    }

    fn unlock(&self) {
        let _ = flock(&self.dir, FlockOperation::Unlock);
    }

    fn names(&self) -> Result<Vec<Vec<u8>>, SpoolError> {
        self.names_up_to(usize::MAX)
    }

    fn names_up_to(&self, limit: usize) -> Result<Vec<Vec<u8>>, SpoolError> {
        let listed = Dir::read_from(&self.dir).and_then(|entries| {
            first_names(
                entries.map(|entry| entry.map(|e| e.file_name().to_bytes().to_vec())),
                limit,
            )
        });
        self.checked("read the directory", listed)
    }

    fn read(&self, name: &[u8], limit: usize) -> Result<Vec<u8>, SpoolError> {
        let component = plain(name)?;
        let display = name.as_bstr().to_string();
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let opened = openat(&self.dir, component, flags, Mode::empty())
            .and_then(|fd| fstat(&fd).map(|stat| (fd, stat)));
        let (fd, stat) = match opened {
            Ok(opened) => opened,
            Err(errno) => {
                return Err(SpoolError::Unreadable {
                    name: display,
                    reason: errno.to_string(),
                });
            }
        };
        self.check_entry(&display, &stat)?;
        let mut bytes = Vec::new();
        let ceiling = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        let read = std::fs::File::from(fd)
            .take(ceiling)
            .read_to_end(&mut bytes);
        contents_from(read, bytes, display, limit)
    }

    fn remove(&self, name: &[u8]) -> Result<(), SpoolError> {
        self.unlink_entry(name).map(|_| ())
    }

    fn consume(&self, name: &[u8]) -> Result<(), SpoolError> {
        if self.unlink_entry(name)? {
            Ok(())
        } else {
            Err(SpoolError::Gone {
                name: name.as_bstr().to_string(),
            })
        }
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), SpoolError> {
        plain(name.as_bytes())?;
        let temp = format!("{TEMP_PREFIX}{name}");
        let private = Mode::RUSR | Mode::WUSR;
        let created = openat(
            &self.dir,
            temp.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            private,
        )
        .map_err(|errno| self.failure("create", &errno.into()))?;
        // The mode is set again on the descriptor because the one passed to
        // `openat` is filtered by the umask; `fchmod` is not.
        let published = fchmod(&created, private)
            .map(|()| created)
            .map_err(std::io::Error::from)
            .and_then(|fd| std::fs::File::from(fd).write_all(bytes))
            .and_then(|()| {
                renameat_with(
                    &self.dir,
                    temp.as_str(),
                    &self.dir,
                    name,
                    RenameFlags::NOREPLACE,
                )
                .map_err(std::io::Error::from)
            });
        match published {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = unlinkat(&self.dir, temp.as_str(), AtFlags::empty());
                Err(self.publish_failure(name, &error))
            }
        }
    }
}

/// One call a [`FakeSpool`] received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpoolCall {
    /// [`Spool::lock`].
    Lock,
    /// [`Spool::unlock`].
    Unlock,
    /// [`Spool::names`].
    Names,
    /// [`Spool::names_up_to`], with this limit.
    NamesUpTo(usize),
    /// [`Spool::read`] of this name.
    Read(Vec<u8>),
    /// [`Spool::remove`] of this name.
    Remove(Vec<u8>),
    /// [`Spool::consume`] of this name.
    Consume(Vec<u8>),
    /// [`Spool::publish`] under this name.
    Publish(String),
}

/// An in-memory spool, for tests.
///
/// Behaves as [`SpoolDir`] does where it matters to a caller — publishing over
/// a taken name is [`SpoolError::Exists`], removing a missing name succeeds,
/// consuming one is [`SpoolError::Gone`], a read past the limit is
/// [`SpoolError::TooLarge`] — and can be told to fail
/// any operation, so every refusal a broker makes on a spool error is
/// reachable without a broken filesystem. Every call is recorded in order.
#[derive(Debug, Default)]
pub struct FakeSpool {
    files: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
    calls: RefCell<Vec<SpoolCall>>,
    lock_error: Option<SpoolError>,
    names_error: Option<SpoolError>,
    unreadable: BTreeSet<Vec<u8>>,
    remove_error: Option<SpoolError>,
    consume_error: Option<SpoolError>,
    publish_error: Option<SpoolError>,
}

impl FakeSpool {
    /// An empty spool that fails nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file.
    #[must_use]
    pub fn with_file(self, name: impl Into<Vec<u8>>, bytes: impl Into<Vec<u8>>) -> Self {
        self.files.borrow_mut().insert(name.into(), bytes.into());
        self
    }

    /// Makes [`Spool::lock`] fail.
    #[must_use]
    pub fn failing_lock(mut self, error: SpoolError) -> Self {
        self.lock_error = Some(error);
        self
    }

    /// Makes [`Spool::names`] and [`Spool::names_up_to`] fail.
    #[must_use]
    pub fn failing_names(mut self, error: SpoolError) -> Self {
        self.names_error = Some(error);
        self
    }

    /// Makes [`Spool::read`] of `name` fail as an unreadable entry.
    #[must_use]
    pub fn failing_read(mut self, name: impl Into<Vec<u8>>) -> Self {
        self.unreadable.insert(name.into());
        self
    }

    /// Makes [`Spool::remove`] fail.
    #[must_use]
    pub fn failing_remove(mut self, error: SpoolError) -> Self {
        self.remove_error = Some(error);
        self
    }

    /// Makes [`Spool::consume`] fail, leaving the entry where it is.
    #[must_use]
    pub fn failing_consume(mut self, error: SpoolError) -> Self {
        self.consume_error = Some(error);
        self
    }

    /// Makes [`Spool::publish`] fail.
    #[must_use]
    pub fn failing_publish(mut self, error: SpoolError) -> Self {
        self.publish_error = Some(error);
        self
    }

    /// Every file, by name.
    pub fn files(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        self.files.borrow().clone()
    }

    /// Every call received so far, in order.
    pub fn calls(&self) -> Vec<SpoolCall> {
        self.calls.borrow().clone()
    }

    fn record(&self, call: SpoolCall) {
        self.calls.borrow_mut().push(call);
    }
}

/// `Ok(())`, or the scripted failure.
fn scripted(error: Option<&SpoolError>) -> Result<(), SpoolError> {
    match error {
        Some(error) => Err(error.clone()),
        None => Ok(()),
    }
}

impl Spool for FakeSpool {
    fn lock(&self) -> Result<(), SpoolError> {
        self.record(SpoolCall::Lock);
        scripted(self.lock_error.as_ref())
    }

    fn unlock(&self) {
        self.record(SpoolCall::Unlock);
    }

    fn names(&self) -> Result<Vec<Vec<u8>>, SpoolError> {
        self.record(SpoolCall::Names);
        scripted(self.names_error.as_ref())?;
        Ok(self.files.borrow().keys().cloned().collect())
    }

    fn names_up_to(&self, limit: usize) -> Result<Vec<Vec<u8>>, SpoolError> {
        self.record(SpoolCall::NamesUpTo(limit));
        scripted(self.names_error.as_ref())?;
        Ok(self.files.borrow().keys().take(limit).cloned().collect())
    }

    fn read(&self, name: &[u8], limit: usize) -> Result<Vec<u8>, SpoolError> {
        self.record(SpoolCall::Read(name.to_vec()));
        let display = name.as_bstr().to_string();
        let found = self.files.borrow().get(name).cloned();
        match found {
            Some(_) if self.unreadable.contains(name) => Err(SpoolError::Unreadable {
                name: display,
                reason: "fake: scripted to fail".to_owned(),
            }),
            Some(bytes) if bytes.len() > limit => Err(SpoolError::TooLarge {
                name: display,
                limit,
            }),
            Some(bytes) => Ok(bytes),
            None => Err(SpoolError::Unreadable {
                name: display,
                reason: "fake: no such entry".to_owned(),
            }),
        }
    }

    fn remove(&self, name: &[u8]) -> Result<(), SpoolError> {
        self.record(SpoolCall::Remove(name.to_vec()));
        scripted(self.remove_error.as_ref())?;
        self.files.borrow_mut().remove(name);
        Ok(())
    }

    fn consume(&self, name: &[u8]) -> Result<(), SpoolError> {
        self.record(SpoolCall::Consume(name.to_vec()));
        scripted(self.consume_error.as_ref())?;
        match self.files.borrow_mut().remove(name) {
            Some(_) => Ok(()),
            None => Err(SpoolError::Gone {
                name: name.as_bstr().to_string(),
            }),
        }
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), SpoolError> {
        self.record(SpoolCall::Publish(name.to_owned()));
        scripted(self.publish_error.as_ref())?;
        let mut files = self.files.borrow_mut();
        if files.contains_key(name.as_bytes()) {
            return Err(SpoolError::Exists {
                name: name.to_owned(),
            });
        }
        files.insert(name.as_bytes().to_vec(), bytes.to_vec());
        Ok(())
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

    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use rustix::io::Errno;

    use super::*;
    use crate::mounts::fake::FakeMounts;

    /// A fresh `0700` directory under the workspace `target/`, never `/tmp`,
    /// and its owner.
    fn scratch(name: &str) -> (PathBuf, u32) {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-tmp")
            .join(format!("spool-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = std::fs::metadata(&dir).unwrap().uid();
        (dir, owner)
    }

    fn open_dir(dir: &Path) -> OwnedFd {
        rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap()
    }

    fn spool(name: &str) -> (SpoolDir, PathBuf) {
        let (dir, owner) = scratch(name);
        (
            SpoolDir::from_dir(open_dir(&dir), &dir, owner).unwrap(),
            dir,
        )
    }

    #[test]
    fn the_real_spool_must_be_root_owned_private_and_reached_through_trusted_components() {
        // A checkout is not root's, so the walk refuses it.
        let err = SpoolDir::open_with(Path::new(env!("CARGO_MANIFEST_DIR")), &FakeMounts::ext4())
            .unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");
        // A spool that does not exist is refused by the walk, by name.
        let err = SpoolDir::open_with(
            Path::new("/usr/definitely-not-a-spool"),
            &FakeMounts::ext4(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot be inspected"), "{err}");
        // /usr/bin passes the walk on every host — root-owned, nothing
        // writable — and is still refused: 0755 lets everyone list it.
        let err = SpoolDir::open_with(Path::new("/usr/bin"), &FakeMounts::ext4()).unwrap_err();
        assert_eq!(
            err,
            SpoolError::Exposed {
                at: "/usr/bin".to_owned(),
                mode: 0o755
            }
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_real_mount_table_is_read_and_the_spool_is_judged_by_it() {
        // The same refusal as with the fake table, now through the host's: a
        // root-owned directory on a mount root made, and still exposed. The
        // whole error is compared, not `matches!`ed: the arm of `matches!`
        // that does not match is a region no test reaches, and this test is
        // measured on Linux.
        let err = SpoolDir::open(Path::new("/usr/bin")).unwrap_err();
        assert_eq!(
            err,
            SpoolError::Exposed {
                at: "/usr/bin".to_owned(),
                mode: 0o755
            }
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_no_spool_is_trusted_because_no_mount_can_be_judged() {
        let err = SpoolDir::open(Path::new("/usr/bin")).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("the mount table cannot be checked"),
            "{err}"
        );
    }

    /// A root-owned symbolic link on every host this builds for: macOS links
    /// `/etc` to `private/etc`, and a merged-`/usr` Linux links `/bin` to
    /// `usr/bin`.
    #[cfg(target_os = "linux")]
    const ROOT_OWNED_LINK: &str = "/bin";
    #[cfg(not(target_os = "linux"))]
    const ROOT_OWNED_LINK: &str = "/etc";

    /// How the walk refuses that link. On Linux it opens the link itself,
    /// `O_PATH`, and refuses it for what it is; macOS has no `O_PATH`, and its
    /// open refuses to follow the link.
    #[cfg(target_os = "linux")]
    fn link_refusal() -> TrustError {
        TrustError::Symlink {
            at: ROOT_OWNED_LINK.to_owned(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn link_refusal() -> TrustError {
        TrustError::Unreadable {
            at: ROOT_OWNED_LINK.to_owned(),
            reason: "Too many levels of symbolic links (os error 62)".to_owned(),
        }
    }

    #[test]
    fn a_spool_reached_through_a_symbolic_link_is_refused_even_a_root_owned_one() {
        // The link is root's and so is its target, and it is still refused:
        // the path checked must be the path written, and a link makes them two.
        let err = SpoolDir::open_with(
            &Path::new(ROOT_OWNED_LINK).join("aido-req"),
            &FakeMounts::ext4(),
        )
        .unwrap_err();
        assert_eq!(err, SpoolError::Untrusted(link_refusal()));
    }

    #[test]
    fn a_spool_that_gives_group_or_other_anything_is_refused() {
        let (dir, owner) = scratch("exposed");
        for mode in [0o750, 0o701, 0o710, 0o755] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = SpoolDir::from_dir(open_dir(&dir), &dir, owner).unwrap_err();
            assert_eq!(
                err,
                SpoolError::Exposed {
                    at: dir.display().to_string(),
                    mode
                }
            );
        }
    }

    #[test]
    fn a_spool_owned_by_someone_else_is_refused() {
        let (dir, owner) = scratch("foreign");
        let err = SpoolDir::from_dir(open_dir(&dir), &dir, owner.wrapping_add(1)).unwrap_err();
        assert_eq!(
            err,
            SpoolError::NotOwned {
                at: dir.display().to_string(),
                uid: owner
            }
        );
    }

    #[test]
    fn a_spool_that_is_a_file_is_refused() {
        let (dir, owner) = scratch("file");
        let file = dir.join("not-a-dir");
        std::fs::write(&file, "x").unwrap();
        let fd = rustix::fs::open(&file, OFlags::RDONLY, Mode::empty()).unwrap();
        assert_eq!(
            SpoolDir::from_dir(fd, &file, owner).unwrap_err(),
            SpoolError::NotADirectory {
                at: file.display().to_string()
            }
        );
    }

    #[test]
    fn a_published_entry_is_private_complete_and_readable_back() {
        let (spool, dir) = spool("publish");
        spool.publish("abc", b"{\"entry\":1}").unwrap();
        let meta = std::fs::metadata(dir.join("abc")).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!(spool.read(b"abc", 64).unwrap(), b"{\"entry\":1}");
        // Nothing is left under the temporary name.
        assert_eq!(spool.names().unwrap(), vec![b"abc".to_vec()]);
    }

    #[test]
    fn publishing_over_a_taken_name_is_refused_and_leaves_both_files_alone() {
        // RENAME_NOREPLACE: a colliding nonce is a refusal, never an overwrite
        // of somebody else's pending request.
        let (spool, dir) = spool("collision");
        spool.publish("abc", b"first").unwrap();
        assert_eq!(
            spool.publish("abc", b"second").unwrap_err(),
            SpoolError::Exists {
                name: "abc".to_owned()
            }
        );
        assert_eq!(std::fs::read(dir.join("abc")).unwrap(), b"first");
        assert_eq!(spool.names().unwrap(), vec![b"abc".to_vec()]);
    }

    #[test]
    fn a_listing_with_a_limit_reads_no_further_than_the_limit() {
        // The gate refuses a spool with more names than it will walk, and must
        // not read all of a spool it is about to refuse: the listing stops at
        // the bound, whatever the directory holds.
        let (spool, _dir) = spool("names-up-to");
        for index in 0..5 {
            spool.publish(&format!("entry-{index}"), b"x").unwrap();
        }
        // More names than the limit: exactly the limit, all of them entries.
        let some = spool.names_up_to(3).unwrap();
        assert_eq!(some.len(), 3);
        assert!(some.iter().all(|name| name.starts_with(b"entry-")));
        // Exactly the limit: every name, so `.` and `..` were not counted
        // against it, and every name is one of the five.
        let mut all = spool.names_up_to(5).unwrap();
        all.sort();
        let mut unbounded = spool.names().unwrap();
        unbounded.sort();
        assert_eq!(all.len(), 5);
        assert_eq!(all, unbounded);
        // Past the number of names there are, and with no limit at all.
        assert_eq!(spool.names_up_to(6).unwrap().len(), 5);
        assert_eq!(spool.names_up_to(usize::MAX).unwrap().len(), 5);
        // A limit of nothing reads nothing.
        assert!(spool.names_up_to(0).unwrap().is_empty());
    }

    #[test]
    fn a_listing_with_a_limit_pulls_no_more_entries_than_the_limit_takes() {
        // What makes the bound a bound on the reading and not only on the
        // answer: the entries are pulled one at a time, and the pulling stops.
        // A million names stand behind `.` and `..`; three are wanted.
        let pulled = std::cell::Cell::new(0_u32);
        let entries = [b".".to_vec(), b"..".to_vec()]
            .into_iter()
            .chain((0..1_000_000).map(|index: u32| index.to_string().into_bytes()))
            .map(|name| {
                pulled.set(pulled.get() + 1);
                Ok(name)
            });
        let first = first_names(entries, 3).unwrap();
        assert_eq!(first, [b"0".to_vec(), b"1".to_vec(), b"2".to_vec()]);
        // `.`, `..`, and the three names: the fourth is never asked for.
        assert_eq!(pulled.get(), 5);

        // An error among the first names is the answer; one past them is
        // never reached.
        let failing = |position: usize| {
            (0..6).map(move |index| {
                if index == position {
                    Err(Errno::IO)
                } else {
                    Ok(vec![b'a'; index + 1])
                }
            })
        };
        assert_eq!(first_names(failing(1), 4), Err(Errno::IO));
        assert_eq!(first_names(failing(5), 4).unwrap().len(), 4);
    }

    #[test]
    fn a_planted_temporary_file_or_link_is_never_written_through() {
        // O_EXCL|O_NOFOLLOW: whatever already holds the temporary name — a
        // stale file or a link pointing anywhere — makes the publish fail
        // rather than write into it.
        let (spool, dir) = spool("planted");
        let target = dir.join("target");
        std::fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(".tmp.abc")).unwrap();
        let err = spool.publish("abc", b"payload").unwrap_err();
        assert!(err.to_string().starts_with("create in"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        assert!(!dir.join("abc").exists());
    }

    #[test]
    fn a_name_that_is_not_one_component_is_refused_everywhere() {
        let (spool, _dir) = spool("names");
        let names: [&[u8]; 5] = [b"", b".", b"..", b"../escape", b"a/b"];
        for name in names {
            let invalid = SpoolError::InvalidName {
                name: name.as_bstr().to_string(),
            };
            assert_eq!(spool.read(name, 64).unwrap_err(), invalid);
            assert_eq!(spool.remove(name).unwrap_err(), invalid);
            assert_eq!(spool.consume(name).unwrap_err(), invalid);
        }
        assert!(spool.publish("../escape", b"x").is_err());
    }

    #[test]
    fn an_entry_that_is_a_link_a_directory_or_not_private_is_unreadable() {
        let (spool, dir) = spool("shapes");
        std::fs::write(dir.join("real"), "x").unwrap();
        std::fs::set_permissions(dir.join("real"), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        std::fs::create_dir(dir.join("dir")).unwrap();
        std::fs::write(dir.join("shared"), "x").unwrap();
        std::fs::set_permissions(dir.join("shared"), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let cases: [(&[u8], &str); 4] = [
            (b"link", ""),
            (b"dir", "not a regular file"),
            (b"shared", "mode 0640"),
            (b"missing", ""),
        ];
        for (name, reason) in cases {
            let err = spool.read(name, 64).unwrap_err();
            assert!(err.to_string().contains("cannot be read"), "{err}");
            assert!(err.to_string().contains(reason), "{err}");
        }
        assert_eq!(spool.read(b"real", 64).unwrap(), b"x");
    }

    #[test]
    fn an_entry_anyone_else_can_write_is_unreadable() {
        // The gate runs what an entry says as root, so an entry that group or
        // world could have written is refused before it is read, whichever
        // write bit it is, and so is one they can merely read.
        let (spool, dir) = spool("writable");
        for mode in [0o620, 0o602, 0o660, 0o606, 0o666, 0o644, 0o604] {
            std::fs::write(dir.join("e"), "x").unwrap();
            std::fs::set_permissions(dir.join("e"), std::fs::Permissions::from_mode(mode)).unwrap();
            let err = spool.read(b"e", 64).unwrap_err();
            assert!(
                err.to_string().contains(&format!("mode {mode:04o}")),
                "{mode:o}: {err}"
            );
        }
        std::fs::set_permissions(dir.join("e"), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(spool.read(b"e", 64).unwrap(), b"x");
    }

    #[test]
    fn an_entry_owned_by_someone_else_is_unreadable() {
        let (dir, owner) = scratch("entry-owner");
        std::fs::write(dir.join("e"), "x").unwrap();
        std::fs::set_permissions(dir.join("e"), std::fs::Permissions::from_mode(0o600)).unwrap();
        // The spool's owner is somebody else, so every file in it is foreign.
        let fd = open_dir(&dir);
        let foreign = SpoolDir {
            dir: fd,
            path: dir.clone(),
            owner: owner.wrapping_add(1),
        };
        let err = foreign.read(b"e", 64).unwrap_err();
        assert!(
            err.to_string().contains(&format!("owned by uid {owner}")),
            "{err}"
        );
    }

    #[test]
    fn an_entry_larger_than_the_limit_is_refused_and_one_at_it_is_read() {
        let (spool, _dir) = spool("large");
        spool.publish("big", &[b'x'; 9]).unwrap();
        assert_eq!(
            spool.read(b"big", 8).unwrap_err(),
            SpoolError::TooLarge {
                name: "big".to_owned(),
                limit: 8
            }
        );
        assert_eq!(spool.read(b"big", 9).unwrap(), vec![b'x'; 9]);
    }

    #[test]
    fn removing_an_entry_that_is_already_gone_is_not_an_error() {
        // The gate consumes entries without the broker's lock, so a name the
        // broker listed may be gone by the time it is removed.
        let (spool, dir) = spool("remove");
        spool.publish("abc", b"x").unwrap();
        spool.remove(b"abc").unwrap();
        assert!(!dir.join("abc").exists());
        spool.remove(b"abc").unwrap();
        // A directory is not an entry and is not removed as one.
        std::fs::create_dir(dir.join("d")).unwrap();
        let err = spool.remove(b"d").unwrap_err();
        assert!(err.to_string().starts_with("unlinkat in"), "{err}");
    }

    #[test]
    fn an_entry_that_is_known_by_a_second_name_is_unreadable() {
        // The unlink that consumes an entry removes one name. An entry with
        // another name would outlive its own consumption, so it is refused
        // before anything reads it.
        let (spool, dir) = spool("second-name");
        spool.publish("abc", b"{}").unwrap();
        assert_eq!(spool.read(b"abc", 64).unwrap(), b"{}");
        std::fs::hard_link(dir.join("abc"), dir.join("alias")).unwrap();
        for name in [&b"abc"[..], b"alias"] {
            let err = spool.read(name, 64).unwrap_err();
            assert!(err.to_string().contains("2 names"), "{err}");
        }
    }

    #[test]
    fn consuming_an_entry_takes_it_and_the_second_consumer_is_told_it_is_gone() {
        // Two gates read the same entry; the unlink decides. The loser must
        // not be told it succeeded, because it would run the command again.
        let (spool, dir) = spool("consume");
        spool.publish("abc", b"x").unwrap();
        spool.consume(b"abc").unwrap();
        assert!(!dir.join("abc").exists());
        assert_eq!(
            spool.consume(b"abc").unwrap_err(),
            SpoolError::Gone {
                name: "abc".to_owned()
            }
        );
        // The broker's tidying, on the same missing name, succeeds: the two
        // operations differ in exactly this.
        spool.remove(b"abc").unwrap();
    }

    #[test]
    fn consuming_something_that_cannot_be_unlinked_is_an_error_and_not_a_claim() {
        // A directory is not an entry; the unlink fails for a reason that is
        // not "already gone", and that is reported as what it is.
        let (spool, dir) = spool("consume-dir");
        std::fs::create_dir(dir.join("d")).unwrap();
        let err = spool.consume(b"d").unwrap_err();
        assert!(err.to_string().starts_with("unlinkat in"), "{err}");
        assert!(dir.join("d").is_dir());
    }

    #[test]
    fn the_lock_is_exclusive_and_released() {
        let (spool, dir) = spool("lock");
        spool.lock().unwrap();
        // A second descriptor for the same directory cannot take it meanwhile.
        let other = open_dir(&dir);
        assert_eq!(
            flock(&other, FlockOperation::NonBlockingLockExclusive),
            Err(Errno::WOULDBLOCK)
        );
        spool.unlock();
        assert_eq!(
            flock(&other, FlockOperation::NonBlockingLockExclusive),
            Ok(())
        );
    }

    #[test]
    fn failures_with_no_reachable_trigger_still_name_the_call_and_the_errno() {
        // `flock` and `readdir` do not fail on a directory held open, and
        // reading a file this process opened does not fail either; these
        // shape what they would report if they did.
        let (spool, _dir) = spool("failures");
        let err = spool.checked::<()>("flock", Err(Errno::NOLCK)).unwrap_err();
        assert_eq!(
            err,
            SpoolError::Io {
                operation: "flock".to_owned(),
                at: spool.path.display().to_string(),
                code: Some(Errno::NOLCK.raw_os_error()),
                reason: std::io::Error::from(Errno::NOLCK).to_string(),
            }
        );
        let io = std::io::Error::from(Errno::IO);
        assert_eq!(
            contents_from(Err(io), Vec::new(), "e".to_owned(), 8).unwrap_err(),
            SpoolError::Unreadable {
                name: "e".to_owned(),
                reason: std::io::Error::from(Errno::IO).to_string(),
            }
        );
        let other = spool.publish_failure("abc", &std::io::Error::from(Errno::NOSPC));
        assert!(other.to_string().starts_with("publish in"), "{other}");
    }

    #[test]
    fn every_spool_refusal_says_what_and_where() {
        let all = [
            SpoolError::Untrusted(TrustError::NotAbsolute { at: "x".to_owned() }),
            SpoolError::NotADirectory { at: "x".to_owned() },
            SpoolError::NotOwned {
                at: "x".to_owned(),
                uid: 1,
            },
            SpoolError::Exposed {
                at: "x".to_owned(),
                mode: 0o755,
            },
            SpoolError::InvalidName {
                name: "a/b".to_owned(),
            },
            SpoolError::Unreadable {
                name: "x".to_owned(),
                reason: "y".to_owned(),
            },
            SpoolError::TooLarge {
                name: "x".to_owned(),
                limit: 1,
            },
            SpoolError::Exists {
                name: "x".to_owned(),
            },
            SpoolError::Gone {
                name: "x".to_owned(),
            },
            SpoolError::Io {
                operation: "x".to_owned(),
                at: "y".to_owned(),
                code: None,
                reason: "z".to_owned(),
            },
        ];
        for err in &all {
            assert!(err.to_string().len() > 10, "{err:?}");
        }
        assert_eq!(TEMP_PREFIX, ".tmp.");
    }

    #[test]
    fn the_fake_behaves_like_the_directory_where_a_caller_can_tell() {
        let fake = FakeSpool::new().with_file("a", "1").with_file("b", "22");
        assert_eq!(fake.lock(), Ok(()));
        assert_eq!(fake.names().unwrap(), vec![b"a".to_vec(), b"b".to_vec()]);
        assert_eq!(fake.read(b"a", 8).unwrap(), b"1");
        assert_eq!(
            fake.read(b"b", 1).unwrap_err(),
            SpoolError::TooLarge {
                name: "b".to_owned(),
                limit: 1
            }
        );
        assert!(
            fake.read(b"zz", 8)
                .unwrap_err()
                .to_string()
                .contains("no such entry")
        );
        fake.remove(b"a").unwrap();
        fake.remove(b"a").unwrap();
        // Consuming takes an entry once, and a missing one is gone, as the
        // directory says.
        fake.consume(b"b").unwrap();
        assert_eq!(
            fake.consume(b"b").unwrap_err(),
            SpoolError::Gone {
                name: "b".to_owned()
            }
        );
        fake.publish("c", b"3").unwrap();
        assert_eq!(
            fake.publish("c", b"4").unwrap_err(),
            SpoolError::Exists {
                name: "c".to_owned()
            }
        );
        fake.unlock();
        assert_eq!(
            fake.files(),
            BTreeMap::from([(b"c".to_vec(), b"3".to_vec())])
        );
        assert_eq!(
            fake.calls(),
            vec![
                SpoolCall::Lock,
                SpoolCall::Names,
                SpoolCall::Read(b"a".to_vec()),
                SpoolCall::Read(b"b".to_vec()),
                SpoolCall::Read(b"zz".to_vec()),
                SpoolCall::Remove(b"a".to_vec()),
                SpoolCall::Remove(b"a".to_vec()),
                SpoolCall::Consume(b"b".to_vec()),
                SpoolCall::Consume(b"b".to_vec()),
                SpoolCall::Publish("c".to_owned()),
                SpoolCall::Publish("c".to_owned()),
                SpoolCall::Unlock,
            ]
        );
    }

    #[test]
    fn the_fake_lists_up_to_a_limit_as_the_directory_does() {
        let fake = FakeSpool::new()
            .with_file("a", "1")
            .with_file("b", "2")
            .with_file("c", "3");
        assert_eq!(
            fake.names_up_to(2).unwrap(),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert_eq!(fake.names_up_to(3).unwrap().len(), 3);
        assert_eq!(fake.names_up_to(9).unwrap().len(), 3);
        assert!(fake.names_up_to(0).unwrap().is_empty());
        assert_eq!(
            fake.calls(),
            vec![
                SpoolCall::NamesUpTo(2),
                SpoolCall::NamesUpTo(3),
                SpoolCall::NamesUpTo(9),
                SpoolCall::NamesUpTo(0),
            ]
        );
    }

    #[test]
    fn the_fake_fails_exactly_what_it_is_told_to() {
        let broken = SpoolError::Io {
            operation: "x".to_owned(),
            at: "y".to_owned(),
            code: None,
            reason: "z".to_owned(),
        };
        let fake = FakeSpool::new()
            .with_file("a", "1")
            .failing_lock(broken.clone())
            .failing_names(broken.clone())
            .failing_read("a")
            .failing_remove(broken.clone())
            .failing_consume(broken.clone())
            .failing_publish(broken.clone());
        assert_eq!(fake.lock(), Err(broken.clone()));
        assert_eq!(fake.names(), Err(broken.clone()));
        assert_eq!(fake.names_up_to(1), Err(broken.clone()));
        assert!(
            fake.read(b"a", 8)
                .unwrap_err()
                .to_string()
                .contains("scripted")
        );
        assert_eq!(fake.remove(b"a"), Err(broken.clone()));
        assert_eq!(fake.consume(b"a"), Err(broken.clone()));
        // A scripted failure leaves the entry where it was, as an unlink that
        // failed does.
        assert_eq!(fake.files().len(), 1);
        assert_eq!(fake.publish("b", b"2"), Err(broken));
        assert!(format!("{fake:?}").contains("FakeSpool"));
    }
}
