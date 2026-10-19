//! The hash-chained log on disk: the trail's authority.
//!
//! # Where, and why not `/var/log`
//!
//! [`AUDIT_DIR`]`/`[`AUDIT_FILE_NAME`] — `/var/lib/aido/audit.jsonl`, mode
//! `0600`, in the root directory that holds the broker's other state (`0700`
//! as packaged; the writer itself demands only what the walk demands, that no
//! group or other can write it). The mode keeps other users out of the file;
//! the same records also reach the journal, which `adm` and `systemd-journal`
//! can read. Not `/var/log/aido`, which the design plan first named:
//!
//! * On Ubuntu `/var/log` is `root:syslog 0775`: rsyslog's package makes it
//!   group-writable. A directory beneath it fails the ancestor walk every
//!   privileged write target must pass, and rightly so — the `syslog` group can
//!   rename `/var/log/aido` aside and put its own directory in its place.
//! * `/var/log` is where rotation truncates and renames, and where RAM-backed
//!   setups (log2ram) keep files that never reach a disk. A chain must survive
//!   the first, and `fdatasync` on a RAM disk persists nothing.
//! * The log a person reads is the journal. This file is evidence.
//!
//! # How a record is appended
//!
//! 1. The directory is opened by the descriptor walk from `/`
//!    ([`open_trusted`]): every component root's, none writable by group or
//!    world, none a link.
//! 2. The log is opened relative to that descriptor with
//!    `O_RDWR|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC` and mode `0600`. A link
//!    planted where the log should be — dangling or not — is refused, never
//!    written through and never used to create a file elsewhere.
//! 3. `fstat` on that descriptor: a regular file, owned by root, with no
//!    access for group or other, and exactly one name. A second name
//!    (`st_nlink > 1`) is a path to the log that skips the walk.
//! 4. An exclusive `flock`, waited for within a bound, so the broker's
//!    instances and the gate append one at a time. Past the bound: refuse.
//!    Once it is held, `fstat` again and `statat` the name without following
//!    it: the file locked must still have exactly one name, and the directory
//!    must still name it (same device and inode). In the seconds a writer can
//!    wait, the log can be moved aside — as the damaged-tail refusal tells an
//!    operator to do — or deleted, and a record appended then would land in a
//!    file that is no longer the chain, or in none. When it is not, the
//!    writer closes it and opens the log again, within the same bound.
//! 5. The last record is found from the end of the log
//!    ([`aido_audit::continuation`]); the caller's record is built after it,
//!    checked to follow it and to pass the caller's own check, and refused if
//!    it is longer than [`aido_audit::MAX_RECORD_BYTES`].
//! 6. One `write` of the whole line, then `fdatasync` — and, for a log's first
//!    record, `fsync` of the directory too, since `fdatasync` makes the data
//!    durable but not the name the file was just created under.
//! 7. The record goes to the trail's mirrors (journald), the lock still held.
//!
//! Any failure from the write on — the write itself, `fdatasync`, the
//! directory `fsync`, a mirror — cuts the log back to where it ended and syncs
//! the cut, before the lock is released. So the next writer never finds a torn
//! tail from a full disk, and never chains onto a record nobody holds a
//! receipt for: not one whose `fdatasync` failed (on Linux that error is
//! reported once, so its own `fdatasync` could succeed while the earlier page
//! never reached the disk), and not a first record whose directory entry may
//! not survive a crash (the cut leaves the log without a record, so the next
//! writer syncs the directory itself). If the cut fails too, the next writer
//! finds what is left: a torn tail, which it refuses, or a whole record, which
//! it continues from — the case this cannot close.
//!
//! A receipt is made only after step 7. A log that ends in damage stops the
//! writer at step 5, for the reasons in [`aido_audit::tail`].
//!
//! On macOS, the development host, several writers *creating* the log at once
//! can see `openat(O_CREAT)` fail with `ENOENT` for all but one of them — an
//! XNU behaviour that path-based `open` does not share. That fails closed, and
//! Linux creates under the directory's lock, where it cannot happen.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aido_audit::{Record, TAIL_WINDOW, continuation, window_start};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, flock, fstat, openat, statat};
use rustix::io::Errno;

use super::{AuditError, next_record};
use crate::trust::{Kind, PathFacts, TRUSTED_UID, TrustError, facts_of, open_trusted};

/// The directory the chain lives in.
pub const AUDIT_DIR: &str = "/var/lib/aido";

/// The chain's file name within [`AUDIT_DIR`].
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";

/// How long a writer waits for another to finish before refusing.
///
/// An append holds the lock for one read, one write, one `fdatasync`, and the
/// mirrors' sends, journald's bounded at 2 s. A holder that keeps it longer is
/// stuck, and waiting on it forever would hang every privileged request behind
/// it.
const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The pause between attempts to take the lock.
const LOCK_RETRY: Duration = Duration::from_millis(5);

/// The permission bits the log must not have: any access by group or other.
const FOREIGN_ACCESS_BITS: u32 = 0o077;

/// The hash-chained log.
#[derive(Debug)]
pub struct JsonlLog {
    dir: LogDir,
    lock_wait: Duration,
}

/// How the log's directory is reached.
#[derive(Debug)]
enum LogDir {
    /// Walked from `/` on every append, each component checked root's.
    Walk(PathBuf),
    /// A directory a test opened itself, and the owner the test expects in
    /// place of root.
    #[cfg(test)]
    Opened {
        fd: OwnedFd,
        path: PathBuf,
        owner: u32,
    },
}

impl JsonlLog {
    /// The broker's and the gate's chain: [`AUDIT_FILE_NAME`] in [`AUDIT_DIR`].
    pub fn system() -> Self {
        Self::in_dir(AUDIT_DIR)
    }

    /// A chain in `dir`, which must pass the same walk as the system one.
    pub fn in_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: LogDir::Walk(dir.into()),
            lock_wait: LOCK_WAIT,
        }
    }

    /// Changes how long an append waits for another writer.
    #[must_use]
    pub fn with_lock_wait(mut self, wait: Duration) -> Self {
        self.lock_wait = wait;
        self
    }

    /// A chain in a directory the test owns, checked against the test's own
    /// uid where production checks root's.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    pub(super) fn opened_for_test(dir: &Path) -> Self {
        let owner = rustix::fs::stat(dir).unwrap().st_uid;
        Self::opened_for_test_as(dir, owner)
    }

    /// As [`Self::opened_for_test`], expecting `owner` to own the log.
    #[cfg(test)]
    #[allow(clippy::unwrap_used)]
    fn opened_for_test_as(dir: &Path, owner: u32) -> Self {
        let fd = rustix::fs::open(
            dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        Self {
            dir: LogDir::Opened {
                fd,
                path: dir.to_path_buf(),
                owner,
            },
            lock_wait: LOCK_WAIT,
        }
    }

    /// [`Self::write`] for a directory reached by `open`, with `owner` expected
    /// to own the log. Production passes the root-owned walk and root; the
    /// walk is a parameter so a test can run everything after it, on every
    /// platform, without a host whose every ancestor is root's.
    fn walked(
        &self,
        dir: &Path,
        open: &dyn Fn(&Path) -> Result<OwnedFd, TrustError>,
        owner: u32,
        build: &dyn Fn(Option<&Record>) -> Record,
        check: &dyn Fn(&Record) -> Result<(), AuditError>,
        publish: &mut dyn FnMut(&Record) -> Result<(), AuditError>,
    ) -> Result<Record, AuditError> {
        let fd = open(dir).map_err(AuditError::Untrusted)?;
        append_in(
            fd.as_fd(),
            dir,
            owner,
            self.lock_wait,
            build,
            check,
            publish,
        )
    }

    /// Appends the record `build` makes from the chain's last record, once
    /// `check` accepts it, synced to disk; hands it to `publish` while the log
    /// is still locked; and returns it. When `publish` fails, the record is
    /// cut back.
    pub(super) fn write(
        &self,
        build: &dyn Fn(Option<&Record>) -> Record,
        check: &dyn Fn(&Record) -> Result<(), AuditError>,
        publish: &mut dyn FnMut(&Record) -> Result<(), AuditError>,
    ) -> Result<Record, AuditError> {
        match &self.dir {
            LogDir::Walk(dir) => {
                self.walked(dir, &open_trusted, TRUSTED_UID, build, check, publish)
            }
            #[cfg(test)]
            LogDir::Opened { fd, path, owner } => append_in(
                fd.as_fd(),
                path,
                *owner,
                self.lock_wait,
                build,
                check,
                publish,
            ),
        }
    }
}

/// Steps 2 to 7, in a directory already walked.
fn append_in(
    dir: BorrowedFd<'_>,
    dir_path: &Path,
    owner: u32,
    wait: Duration,
    build: &dyn Fn(Option<&Record>) -> Record,
    check: &dyn Fn(&Record) -> Result<(), AuditError>,
    publish: &mut dyn FnMut(&Record) -> Result<(), AuditError>,
) -> Result<Record, AuditError> {
    let path = dir_path.join(AUDIT_FILE_NAME);
    let mut file = open_log(dir, &path, owner, wait)?;
    write_record(&mut file, &path, build, check, publish)
}

/// Opens, checks, and locks the log. Steps 2 to 4.
fn open_log<'dir>(
    dir: BorrowedFd<'dir>,
    path: &Path,
    owner: u32,
    wait: Duration,
) -> Result<HostLogFile<'dir>, AuditError> {
    let patience = Patience::from_now(wait);
    until_current(patience, path, &mut || {
        open_once(dir, path, owner, patience)
    })
}

/// One attempt at step 2 to 4: the log, opened, checked, and locked — or
/// `None` when the file this writer locked is no longer the one the directory
/// names.
fn open_once<'dir>(
    dir: BorrowedFd<'dir>,
    path: &Path,
    owner: u32,
    patience: Patience,
) -> Result<Option<HostLogFile<'dir>>, AuditError> {
    let name = OsStr::new(AUDIT_FILE_NAME);
    let flags = OFlags::RDWR | OFlags::APPEND | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let (fd, stat) = openat(dir, name, flags, Mode::RUSR | Mode::WUSR)
        .and_then(|fd| fstat(&fd).map(|stat| (fd, stat)))
        .map_err(|errno| open_failure(dir, name, path, errno))?;
    check_log(&facts_of(&stat), links(&stat), path, owner)?;
    lock_within(fd.as_fd(), patience).map_err(|errno| AuditError::Busy {
        path: path.display().to_string(),
        waited_ms: patience.wait.as_millis(),
        reason: errno.to_string(),
    })?;
    if still_named(dir, name, fd.as_fd()) {
        Ok(Some(HostLogFile {
            file: File::from(fd),
            dir,
        }))
    } else {
        // Dropping the descriptor releases the lock on the file that left.
        Ok(None)
    }
}

/// Repeats `attempt` until it yields the log, and refuses once `patience` has
/// run out with the log still changing under the writer.
///
/// Takes the attempt as a trait object rather than a generic, so the one copy
/// of this loop that ships is the copy the tests measure.
fn until_current<'dir>(
    patience: Patience,
    path: &Path,
    attempt: &mut dyn FnMut() -> Result<Option<HostLogFile<'dir>>, AuditError>,
) -> Result<HostLogFile<'dir>, AuditError> {
    loop {
        if let Some(log) = attempt()? {
            return Ok(log);
        }
        if patience.exhausted() {
            return Err(refused(
                path,
                "it was moved, replaced, or removed each time this writer took its lock, until \
                 the wait ran out; a record appended then would land in a file that is no longer \
                 the log",
            ));
        }
    }
}

/// Whether the file locked through `fd` is still the log: its only name, and
/// the one the directory holds now.
///
/// A failed `fstat` or `statat` answers "no", and the next attempt's open
/// reports what is wrong with the name.
fn still_named(dir: BorrowedFd<'_>, name: &OsStr, fd: BorrowedFd<'_>) -> bool {
    let named = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW);
    fstat(fd).is_ok_and(|locked| {
        links(&locked) == 1
            && named
                .is_ok_and(|named| (named.st_dev, named.st_ino) == (locked.st_dev, locked.st_ino))
    })
}

/// How long a writer may still wait, from when it started.
#[derive(Clone, Copy, Debug)]
struct Patience {
    started: Instant,
    wait: Duration,
}

impl Patience {
    /// A wait of `wait`, starting now.
    fn from_now(wait: Duration) -> Self {
        Self {
            started: Instant::now(),
            wait,
        }
    }

    /// Whether the wait is over.
    fn exhausted(self) -> bool {
        self.started.elapsed() >= self.wait
    }
}

/// How many names the file has.
///
/// `st_nlink` is a `u64`, a `u32`, or a `u16` depending on the platform, so
/// the widening is a real conversion on some and an identity on others.
#[allow(clippy::useless_conversion)]
fn links(stat: &rustix::fs::Stat) -> u64 {
    u64::from(stat.st_nlink)
}

/// Explains a failed open, examining the name without following it, so a
/// planted link is reported as one rather than as a bare `ELOOP`.
fn open_failure(dir: BorrowedFd<'_>, name: &OsStr, path: &Path, errno: Errno) -> AuditError {
    match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map(|stat| facts_of(&stat).kind) {
        Ok(Kind::Symlink) => refused(
            path,
            "it is a symbolic link; the log is opened without following links, so one planted \
             where it belongs is refused rather than written through",
        ),
        _ => AuditError::Io {
            op: "open",
            path: path.display().to_string(),
            reason: errno.to_string(),
        },
    }
}

/// Checks what `fstat` reports for the opened log.
fn check_log(facts: &PathFacts, links: u64, path: &Path, owner: u32) -> Result<(), AuditError> {
    if facts.kind != Kind::File {
        return Err(refused(path, "it is not a regular file"));
    }
    if facts.uid != owner {
        return Err(refused(
            path,
            &format!(
                "it is owned by uid {}, and only uid {owner} may own it: a log someone else can \
                 rewrite is not evidence",
                facts.uid
            ),
        ));
    }
    if facts.mode & FOREIGN_ACCESS_BITS != 0 {
        return Err(refused(
            path,
            &format!(
                "it has mode {:04o}; only its owner may read or write it (0600), because it \
                 records what root ran and who asked",
                facts.mode
            ),
        ));
    }
    if links != 1 {
        return Err(refused(
            path,
            &format!(
                "it has {links} names; a second name reaches the log without the walk that \
                 guards this one, and none means it was deleted"
            ),
        ));
    }
    Ok(())
}

/// A refusal of the log file itself.
fn refused(path: &Path, reason: &str) -> AuditError {
    AuditError::Refused {
        path: path.display().to_string(),
        reason: reason.to_owned(),
    }
}

/// Takes the exclusive lock, retrying until `patience` runs out. Always tries
/// at least once.
fn lock_within(fd: BorrowedFd<'_>, patience: Patience) -> Result<(), Errno> {
    loop {
        let attempt = flock(fd, FlockOperation::NonBlockingLockExclusive);
        if attempt != Err(Errno::WOULDBLOCK) || patience.exhausted() {
            return attempt;
        }
        std::thread::sleep(LOCK_RETRY);
    }
}

/// The operations an append needs from an opened, locked log.
///
/// A seam rather than a convenience: the order of the write and the
/// `fdatasync`, and what happens when either fails, are the claims this module
/// makes, and a fake is what lets a test watch them happen.
trait LogFile {
    /// The log's length in bytes.
    fn size(&mut self) -> io::Result<u64>;
    /// Fills `buf` from `offset`.
    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    /// Appends all of `bytes` at the end.
    fn append(&mut self, bytes: &[u8]) -> io::Result<()>;
    /// Cuts the log back to `len` bytes.
    fn truncate(&mut self, len: u64) -> io::Result<()>;
    /// `fdatasync`: the data is on disk when this returns.
    fn sync_data(&mut self) -> io::Result<()>;
    /// `fsync` on the log's directory, so the name the log was created under
    /// is on disk too. `fdatasync` covers a file's data, not its directory
    /// entry, and a first record whose file can vanish in a crash is not on
    /// disk at all.
    fn sync_dir(&mut self) -> io::Result<()>;
}

/// The log, opened, and the directory it was opened in.
#[derive(Debug)]
struct HostLogFile<'dir> {
    file: File,
    dir: BorrowedFd<'dir>,
}

impl LogFile for HostLogFile<'_> {
    fn size(&mut self) -> io::Result<u64> {
        self.file.metadata().map(|meta| meta.len())
    }

    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        FileExt::read_exact_at(&self.file, buf, offset)
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }

    fn sync_data(&mut self) -> io::Result<()> {
        // `fdatasync` on Linux; on macOS the standard library issues
        // `F_FULLFSYNC`, the only call there that reaches the disk.
        self.file.sync_data()
    }

    fn sync_dir(&mut self) -> io::Result<()> {
        rustix::fs::fsync(self.dir).map_err(io::Error::from)
    }
}

/// Steps 5 to 7: continue the chain from the end of `file`, and hand the
/// record to `publish` before the caller lets go of the lock.
fn write_record(
    file: &mut impl LogFile,
    path: &Path,
    build: &dyn Fn(Option<&Record>) -> Record,
    check: &dyn Fn(&Record) -> Result<(), AuditError>,
    publish: &mut dyn FnMut(&Record) -> Result<(), AuditError>,
) -> Result<Record, AuditError> {
    let failed = |op: &'static str| {
        move |error: io::Error| AuditError::Io {
            op,
            path: path.display().to_string(),
            reason: error.to_string(),
        }
    };

    let size = file.size().map_err(failed("measure"))?;
    // The window the verifier's `continuation_of` reads too, through the same
    // function, so the two can never judge different bytes.
    let start = window_start(size);
    let take = usize::try_from(size.saturating_sub(start)).unwrap_or(TAIL_WINDOW);
    let mut window = vec![0; take];
    file.read_exact_at(&mut window, start)
        .map_err(failed("read"))?;
    let tail = continuation(&window, start == 0).map_err(|reason| AuditError::DamagedTail {
        path: path.display().to_string(),
        reason,
    })?;

    let (record, line) = next_record(tail.last.as_ref(), build, check)?;

    let mut bytes = Vec::with_capacity(line.len().saturating_add(2));
    if tail.needs_newline {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(line.as_bytes());
    bytes.push(b'\n');
    let first = tail.last.is_none();
    let committed = file
        .append(&bytes)
        .map_err(failed("write"))
        .and_then(|()| file.sync_data().map_err(failed("fdatasync")))
        .and_then(|()| {
            if first {
                file.sync_dir()
                    .map_err(failed("fsync the directory holding"))
            } else {
                Ok(())
            }
        })
        .and_then(|()| publish(&record));
    match committed {
        Ok(()) => Ok(record),
        Err(error) => {
            cut_back(file, size);
            Err(error)
        }
    }
}

/// Cuts the log back to `len` bytes and syncs the cut, while the caller still
/// holds the lock and so keeps every other writer out.
///
/// Best effort, because there is nothing left to try: if the cut fails, the
/// caller's refusal still stands, and the next writer finds what is left — see
/// the module docs.
fn cut_back(file: &mut impl LogFile, len: u64) {
    let _ = file.truncate(len).and_then(|()| file.sync_data());
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

    use aido_audit::{Chain, Decision, MAX_RECORD_BYTES, Outcome, Sequence, verify};

    use super::*;
    use crate::audit::{AuditSink, FakeAuditSink};

    // --- the logic, against a fake file -------------------------------------

    /// One operation on the fake.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Size,
        Read,
        Append,
        Truncate,
        Sync,
        SyncDir,
    }

    /// A log in memory that records what was done to it, and fails on demand.
    #[derive(Debug, Default)]
    struct FakeLogFile {
        bytes: Vec<u8>,
        calls: Vec<(Op, u64)>,
        failing: Vec<Op>,
        /// How much of a failing append reaches the file first.
        partial: usize,
    }

    impl FakeLogFile {
        fn holding(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                ..Self::default()
            }
        }

        fn failing(mut self, op: Op) -> Self {
            self.failing.push(op);
            self
        }

        fn step(&mut self, op: Op, arg: u64) -> io::Result<()> {
            self.calls.push((op, arg));
            if self.failing.contains(&op) {
                Err(io::Error::other(format!("{op:?} failed")))
            } else {
                Ok(())
            }
        }

        fn ops(&self) -> Vec<Op> {
            self.calls.iter().map(|(op, _)| *op).collect()
        }
    }

    impl LogFile for FakeLogFile {
        fn size(&mut self) -> io::Result<u64> {
            let len = self.bytes.len() as u64;
            self.step(Op::Size, len).map(|()| len)
        }

        fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
            self.step(Op::Read, offset)?;
            let start = usize::try_from(offset).unwrap();
            buf.copy_from_slice(&self.bytes[start..start + buf.len()]);
            Ok(())
        }

        fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
            if self.failing.contains(&Op::Append) {
                self.bytes.extend_from_slice(&bytes[..self.partial]);
            }
            self.step(Op::Append, bytes.len() as u64)
                .map(|()| self.bytes.extend_from_slice(bytes))
        }

        fn truncate(&mut self, len: u64) -> io::Result<()> {
            self.step(Op::Truncate, len)
                .map(|()| self.bytes.truncate(usize::try_from(len).unwrap()))
        }

        fn sync_data(&mut self) -> io::Result<()> {
            self.step(Op::Sync, 0)
        }

        fn sync_dir(&mut self) -> io::Result<()> {
            self.step(Op::SyncDir, 0)
        }
    }

    fn refusal(previous: Option<&Record>) -> Record {
        Record::after(previous, Decision::Denied, Vec::new(), "unattested")
            .with_denial("gate_no_pending_request")
    }

    fn log_of(n: usize) -> Vec<u8> {
        let mut chain = Chain::new();
        for i in 0..n {
            chain.append(Decision::Allowed, vec![format!("cmd{i}")], "human");
        }
        chain.to_jsonl().into_bytes()
    }

    fn write(file: &mut FakeLogFile) -> Result<Record, AuditError> {
        write_built(file, &refusal)
    }

    /// An append of what `build` makes, with no check and no mirror. One copy
    /// of each pass-through, so every one of them runs in some test.
    fn write_built(
        file: &mut FakeLogFile,
        build: &dyn Fn(Option<&Record>) -> Record,
    ) -> Result<Record, AuditError> {
        write_record(
            file,
            Path::new("/var/lib/aido/audit.jsonl"),
            build,
            &|_| Ok(()),
            &mut |_| Ok(()),
        )
    }

    /// What a journald that is not there answers.
    fn journal_gone() -> AuditError {
        AuditError::Journal {
            socket: "/run/systemd/journal/socket".to_owned(),
            reason: "No such file or directory".to_owned(),
        }
    }

    #[test]
    fn the_first_record_starts_the_chain_and_reaches_the_disk() {
        let mut file = FakeLogFile::default();
        let record = write(&mut file).unwrap();
        assert_eq!(record.seq.get(), 1);
        assert_eq!(file.bytes, format!("{}\n", record.to_jsonl()).into_bytes());
        assert_eq!(
            file.ops(),
            [Op::Size, Op::Read, Op::Append, Op::Sync, Op::SyncDir],
            "fdatasync must follow the write, and a new log's name must reach the disk too"
        );
    }

    #[test]
    fn a_record_continues_the_chain_from_the_last_one_in_the_log() {
        let mut file = FakeLogFile::holding(&log_of(3));
        let record = write(&mut file).unwrap();
        assert_eq!(record.seq.get(), 4);
        let chain = Chain::from_jsonl(std::str::from_utf8(&file.bytes).unwrap()).unwrap();
        assert_eq!(chain.len(), 4);
        // The directory entry was made durable with the first record.
        assert_eq!(file.ops(), [Op::Size, Op::Read, Op::Append, Op::Sync]);
    }

    #[test]
    fn a_first_record_whose_directory_sync_fails_is_cut_back_so_the_next_writer_syncs_it() {
        // Left in place, record 1 sits in a file whose name may not survive a
        // crash, and the next writer — seeing a record — would never sync the
        // directory, so every receipt after it could vanish with the file. Cut
        // back to nothing, the log has no record again, and the next writer
        // makes the name durable itself.
        let mut file = FakeLogFile::default().failing(Op::SyncDir);
        let err = write(&mut file).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("cannot fsync the directory holding the audit log"),
            "{err}"
        );
        assert!(file.bytes.is_empty());
        assert_eq!(file.calls[5..], [(Op::Truncate, 0), (Op::Sync, 0)]);

        let mut next = FakeLogFile::holding(&file.bytes);
        let record = write(&mut next).unwrap();
        assert_eq!(record.seq.get(), 1);
        assert_eq!(
            next.ops(),
            [Op::Size, Op::Read, Op::Append, Op::Sync, Op::SyncDir]
        );
    }

    #[test]
    fn a_record_whose_fdatasync_fails_is_cut_back_before_any_writer_chains_on_it() {
        // The bytes may be in the page cache, but nothing says they reached
        // the disk. Linux reports a writeback error once, so the next writer's
        // own fdatasync could succeed while this page never lands: chained
        // onto, it would leave a receipted record after a hole. It is cut back
        // under the lock, and the cut synced, so the next record follows the
        // last one that did reach the disk.
        let before = log_of(2);
        let mut file = FakeLogFile::holding(&before).failing(Op::Sync);
        let err = write(&mut file).unwrap_err();
        assert!(err.to_string().starts_with("cannot fdatasync"), "{err}");
        assert_eq!(file.bytes, before);
        assert_eq!(
            file.ops(),
            [
                Op::Size,
                Op::Read,
                Op::Append,
                Op::Sync,
                Op::Truncate,
                Op::Sync
            ]
        );

        let mut next = FakeLogFile::holding(&file.bytes);
        let record = write(&mut next).unwrap();
        let chain = Chain::from_jsonl(std::str::from_utf8(&before).unwrap()).unwrap();
        assert_eq!(record.seq.get(), 3);
        assert_eq!(record.prev_hash, chain.records()[1].hash);
    }

    #[test]
    fn a_mirror_that_refuses_gets_the_record_cut_back_under_the_lock() {
        // The trail sends to journald inside the write, so a refusal there
        // undoes the append before any other writer can see it.
        let before = log_of(2);
        let mut file = FakeLogFile::holding(&before);
        let mut offered = Vec::new();
        let err = write_record(
            &mut file,
            Path::new("/log"),
            &refusal,
            &|_| Ok(()),
            &mut |record| {
                offered.push(record.seq.get());
                Err(journal_gone())
            },
        )
        .unwrap_err();
        assert_eq!(err, journal_gone());
        assert_eq!(offered, [3]);
        assert_eq!(file.bytes, before);
        assert_eq!(
            file.ops(),
            [
                Op::Size,
                Op::Read,
                Op::Append,
                Op::Sync,
                Op::Truncate,
                Op::Sync
            ]
        );
    }

    #[test]
    fn a_write_that_fails_part_way_is_cut_back_to_where_the_log_ended() {
        // A full disk mid-line. Leaving the fragment would make every later
        // writer refuse; cutting it back under the lock leaves the chain as it
        // was.
        let before = log_of(2);
        let mut file = FakeLogFile {
            partial: 17,
            ..FakeLogFile::holding(&before).failing(Op::Append)
        };
        let err = write(&mut file).unwrap_err();
        assert!(err.to_string().starts_with("cannot write"), "{err}");
        assert_eq!(file.bytes, before);
        assert_eq!(
            file.calls[2..],
            [
                (Op::Append, file.calls[2].1),
                (Op::Truncate, before.len() as u64),
                (Op::Sync, 0)
            ]
        );
    }

    #[test]
    fn a_cut_back_that_also_fails_leaves_a_tail_the_next_writer_refuses() {
        let before = log_of(2);
        let mut file = FakeLogFile {
            partial: 17,
            ..FakeLogFile::holding(&before)
                .failing(Op::Append)
                .failing(Op::Truncate)
        };
        let err = write(&mut file).unwrap_err();
        assert!(err.to_string().starts_with("cannot write"), "{err}");
        assert_eq!(file.bytes.len(), before.len() + 17);
        assert_eq!(file.ops().last(), Some(&Op::Truncate), "nothing to sync");
        let mut next = FakeLogFile::holding(&file.bytes);
        let err = write(&mut next).unwrap_err();
        assert!(err.to_string().contains("ends in damage"), "{err}");
    }

    #[test]
    fn a_torn_tail_stops_the_writer_before_anything_is_written() {
        let mut torn = log_of(3);
        torn.truncate(torn.len() - 25);
        let mut file = FakeLogFile::holding(&torn);
        let err = write(&mut file).unwrap_err();
        assert!(err.to_string().contains("ends in damage"), "{err}");
        assert!(
            err.to_string()
                .contains("neither continues past damage nor starts a new chain"),
            "{err}"
        );
        assert_eq!(file.bytes, torn, "the evidence is left as it was");
        assert!(!file.ops().contains(&Op::Append));
    }

    #[test]
    fn a_complete_last_record_missing_its_newline_is_continued_on_a_new_line() {
        let mut unterminated = log_of(2);
        unterminated.pop();
        let mut file = FakeLogFile::holding(&unterminated);
        let record = write(&mut file).unwrap();
        assert_eq!(record.seq.get(), 3);
        let text = std::str::from_utf8(&file.bytes).unwrap();
        assert_eq!(Chain::from_jsonl(text).unwrap().len(), 3);
        assert_eq!(text.lines().count(), 3);
    }

    #[test]
    fn a_record_that_does_not_follow_the_chain_is_refused_unwritten() {
        let mut file = FakeLogFile::holding(&log_of(2));
        let err = write_built(&mut file, &|_| refusal(None)).unwrap_err();
        assert!(
            err.to_string().starts_with("the record does not follow"),
            "{err}"
        );
        assert!(!file.ops().contains(&Op::Append));
    }

    #[test]
    fn a_record_too_long_for_one_line_is_refused_before_anything_is_written() {
        let huge = |previous: Option<&Record>| {
            Record::after(
                previous,
                Decision::Denied,
                vec!["x".repeat(MAX_RECORD_BYTES)],
                "unattested",
            )
        };
        let mut file = FakeLogFile::default();
        let err = write_built(&mut file, &huge).unwrap_err();
        assert!(err.to_string().contains("is not carried out"), "{err}");
        assert!(file.bytes.is_empty());
    }

    #[test]
    fn a_log_that_cannot_be_measured_or_read_is_refused() {
        let mut file = FakeLogFile::default().failing(Op::Size);
        assert!(
            write(&mut file)
                .unwrap_err()
                .to_string()
                .starts_with("cannot measure")
        );
        let mut file = FakeLogFile::holding(&log_of(1)).failing(Op::Read);
        assert!(
            write(&mut file)
                .unwrap_err()
                .to_string()
                .starts_with("cannot read")
        );
    }

    #[test]
    fn a_blank_tail_the_writer_refuses_is_reported_by_the_verifier_too() {
        // The review's reproduction, inverted: past 128 KiB of blank space the
        // writer refused every decision while `aido audit` called the log
        // intact, and the refusal sent the operator to it. Both now give the
        // writer's answer.
        let mut bytes = log_of(2);
        bytes.extend(std::iter::repeat_n(b' ', TAIL_WINDOW + 10));
        bytes.push(b'\n');
        let refusal = aido_audit::TailError::Overlong {
            window: TAIL_WINDOW,
        };
        let mut file = FakeLogFile::holding(&bytes);
        assert_eq!(
            write(&mut file).unwrap_err(),
            AuditError::DamagedTail {
                path: "/var/lib/aido/audit.jsonl".to_owned(),
                reason: refusal.clone()
            }
        );
        assert_eq!(
            aido_audit::verify_log(&bytes),
            Err(aido_audit::LogError::End(refusal))
        );
    }

    #[test]
    fn only_the_end_of_a_long_log_is_read() {
        // Each decision costs one window, not the life of the machine.
        let long = log_of(1000);
        assert!(long.len() > TAIL_WINDOW);
        let mut file = FakeLogFile::holding(&long);
        let record = write(&mut file).unwrap();
        let reads: Vec<u64> = file
            .calls
            .iter()
            .filter(|(op, _)| *op == Op::Read)
            .map(|(_, offset)| *offset)
            .collect();
        assert_eq!(reads, [(long.len() - TAIL_WINDOW) as u64]);
        let chain = Chain::from_jsonl(std::str::from_utf8(&file.bytes).unwrap()).unwrap();
        assert_eq!(chain.records().last(), Some(&record));
    }

    #[test]
    fn the_checks_on_the_opened_log_refuse_each_unsafe_shape() {
        let path = Path::new("/var/lib/aido/audit.jsonl");
        let good = PathFacts {
            uid: 0,
            mode: 0o600,
            kind: Kind::File,
        };
        assert!(check_log(&good, 1, path, 0).is_ok());
        let cases: [(PathFacts, u64, &str); 6] = [
            (
                PathFacts {
                    kind: Kind::Other,
                    ..good
                },
                1,
                "not a regular file",
            ),
            (PathFacts { uid: 1000, ..good }, 1, "owned by uid 1000"),
            (
                PathFacts {
                    mode: 0o640,
                    ..good
                },
                1,
                "mode 0640",
            ),
            (
                PathFacts {
                    mode: 0o602,
                    ..good
                },
                1,
                "mode 0602",
            ),
            (good, 2, "it has 2 names"),
            (good, 0, "none means it was deleted"),
        ];
        for (facts, links, expect) in cases {
            let err = check_log(&facts, links, path, 0).unwrap_err();
            assert!(err.to_string().contains(expect), "{expect}: {err}");
        }
    }

    // --- the real file ------------------------------------------------------

    /// A fresh directory under the workspace `target/`, never `/tmp`.
    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("audit-file-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::canonicalize(&dir).unwrap()
    }

    fn read_chain(dir: &Path) -> Vec<Record> {
        let text = std::fs::read_to_string(dir.join(AUDIT_FILE_NAME)).unwrap();
        Chain::from_jsonl(&text).unwrap().records().to_vec()
    }

    #[test]
    fn a_directory_the_walk_vouches_for_is_appended_to_and_one_it_refuses_is_not() {
        // The walk is a parameter of the production path, so this runs
        // everything after it on every platform.
        let dir = scratch("walked");
        let owner = std::fs::metadata(&dir).unwrap().uid();
        let log = JsonlLog::in_dir(&dir);
        let open = |path: &Path| {
            Ok(rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap())
        };
        let accept = |_: &Record| Ok(());
        let mut publish = |_: &Record| Ok(());
        let record = log
            .walked(&dir, &open, owner, &refusal, &accept, &mut publish)
            .unwrap();
        assert_eq!(read_chain(&dir), vec![record]);
        // The same directory, refused by the walk: nothing more is written.
        let refuse = |_: &Path| {
            Err(TrustError::NotAbsolute {
                at: "refused".to_owned(),
            })
        };
        let err = log
            .walked(&dir, &refuse, owner, &refusal, &accept, &mut publish)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            AuditError::Untrusted(TrustError::NotAbsolute {
                at: "refused".to_owned()
            })
            .to_string()
        );
        assert_eq!(read_chain(&dir).len(), 1);
    }

    #[test]
    fn records_written_by_separate_opens_form_one_chain_in_a_private_file() {
        let dir = scratch("chain");
        for _ in 0..3 {
            let mut log = JsonlLog::opened_for_test(&dir);
            let _ = log.append(&refusal).unwrap();
        }
        let records = read_chain(&dir);
        assert_eq!(records.len(), 3);
        verify(&records).unwrap();
        let meta = std::fs::metadata(dir.join(AUDIT_FILE_NAME)).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.nlink(), 1);
    }

    /// Four writers, each appending through its own open, at once.
    fn race(dir: &Path, appends: usize) {
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let dir = dir.to_path_buf();
                std::thread::spawn(move || {
                    for _ in 0..appends {
                        let mut log = JsonlLog::opened_for_test(&dir);
                        let _ = log.append(&refusal).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
    }

    #[test]
    fn concurrent_writers_never_fork_the_chain() {
        // The broker runs one instance per connection and the gate writes the
        // same file: without the lock, two writers read the same tail and both
        // append its successor. The log exists first, because macOS cannot
        // create one under concurrent `openat(O_CREAT)` (see the module docs).
        let dir = scratch("concurrent");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        race(&dir, 25);
        let records = read_chain(&dir);
        assert_eq!(records.len(), 101);
        verify(&records).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_writers_creating_the_log_never_fork_the_chain() {
        // Linux creates under the directory's lock: every racer opens the one
        // file, and exactly one of them writes record 1.
        let dir = scratch("concurrent-create");
        race(&dir, 10);
        let records = read_chain(&dir);
        assert_eq!(records.len(), 40);
        verify(&records).unwrap();
    }

    #[test]
    fn a_symlink_where_the_log_belongs_is_refused_not_written_through() {
        let dir = scratch("symlink");
        let victim = dir.join("victim");
        std::fs::write(&victim, "root's file\n").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join(AUDIT_FILE_NAME)).unwrap();
        let err = JsonlLog::opened_for_test(&dir)
            .append(&refusal)
            .unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "root's file\n");
    }

    #[test]
    fn a_dangling_symlink_cannot_make_the_writer_create_a_file_elsewhere() {
        // The classic: point the log's name at a path that does not exist yet,
        // and let root's O_CREAT make it.
        let dir = scratch("dangling");
        let target = dir.join("created-by-root");
        std::os::unix::fs::symlink(&target, dir.join(AUDIT_FILE_NAME)).unwrap();
        let err = JsonlLog::opened_for_test(&dir)
            .append(&refusal)
            .unwrap_err();
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert!(!target.exists(), "the link's target was created");
    }

    #[test]
    fn a_log_with_a_second_name_is_refused() {
        let dir = scratch("hardlink");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        std::fs::hard_link(dir.join(AUDIT_FILE_NAME), dir.join("elsewhere")).unwrap();
        let err = JsonlLog::opened_for_test(&dir)
            .append(&refusal)
            .unwrap_err();
        assert!(err.to_string().contains("it has 2 names"), "{err}");
        assert_eq!(read_chain(&dir).len(), 1);
    }

    #[test]
    fn a_log_others_can_read_or_write_is_refused() {
        for mode in [0o644, 0o620, 0o604] {
            let dir = scratch(&format!("mode-{mode:o}"));
            let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
            std::fs::set_permissions(
                dir.join(AUDIT_FILE_NAME),
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
            let err = JsonlLog::opened_for_test(&dir)
                .append(&refusal)
                .unwrap_err();
            assert!(err.to_string().contains("only its owner may"), "{err}");
        }
    }

    #[test]
    fn a_log_owned_by_someone_else_is_refused() {
        let dir = scratch("owner");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        let me = std::fs::metadata(&dir).unwrap().uid();
        let mut log = JsonlLog::opened_for_test_as(&dir, me.wrapping_add(1));
        let err = log.append(&refusal).unwrap_err();
        assert!(err.to_string().contains("only uid"), "{err}");
        assert!(format!("{log:?}").contains("Opened"), "{log:?}");
    }

    #[test]
    fn a_directory_where_the_log_belongs_is_refused() {
        let dir = scratch("dir");
        std::fs::create_dir(dir.join(AUDIT_FILE_NAME)).unwrap();
        let err = JsonlLog::opened_for_test(&dir)
            .append(&refusal)
            .unwrap_err();
        assert!(err.to_string().starts_with("cannot open"), "{err}");
    }

    #[test]
    fn a_torn_tail_on_disk_is_refused_by_the_writer_and_named_by_the_verifier() {
        let dir = scratch("torn");
        for _ in 0..2 {
            let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        }
        let path = dir.join(AUDIT_FILE_NAME);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.truncate(bytes.len() - 30);
        std::fs::write(&path, &bytes).unwrap();

        let err = JsonlLog::opened_for_test(&dir)
            .append(&refusal)
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.starts_with(&format!("the audit log {} ends in damage", path.display())),
            "{message}"
        );
        assert!(message.contains("not an audit record"), "{message}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes, "nothing was appended");
        let verified = Chain::from_jsonl(std::str::from_utf8(&bytes).unwrap());
        assert!(
            verified
                .unwrap_err()
                .to_string()
                .starts_with("line 2 is not an audit record")
        );
    }

    #[test]
    fn an_edited_last_record_on_disk_stops_the_writer_and_the_verifier_names_it() {
        // Someone with the file rewrote what the last record says ran, and
        // left its hash alone. Chaining a new record onto it would vouch for
        // the forgery; the writer refuses at the record the verifier reports.
        let dir = scratch("edited");
        for _ in 0..2 {
            let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        }
        let path = dir.join(AUDIT_FILE_NAME);
        let mut records = read_chain(&dir);
        records[1].argv.push("--smuggled".to_owned());
        let forged = format!("{}\n{}\n", records[0].to_jsonl(), records[1].to_jsonl());
        std::fs::write(&path, &forged).unwrap();

        let err = JsonlLog::opened_for_test(&dir)
            .append(&refusal)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("the last record, 2, was edited: its hash no longer covers"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), forged);
        assert!(
            Chain::from_jsonl(&forged)
                .unwrap_err()
                .to_string()
                .starts_with("record 2 was edited")
        );
    }

    #[test]
    fn a_held_lock_makes_the_writer_wait_then_refuse() {
        let dir = scratch("busy");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        let holder = File::options()
            .read(true)
            .open(dir.join(AUDIT_FILE_NAME))
            .unwrap();
        flock(&holder, FlockOperation::LockExclusive).unwrap();

        let started = Instant::now();
        let err = JsonlLog::opened_for_test(&dir)
            .with_lock_wait(Duration::from_millis(40))
            .append(&refusal)
            .unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(err.to_string().contains("stayed locked for 40 ms"), "{err}");

        drop(holder);
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        assert_eq!(read_chain(&dir).len(), 2);
    }

    /// Holds the lock on the log while a second writer, with `wait` to spare,
    /// waits for it; runs `meanwhile` on the log's path; then lets go and
    /// returns what the waiting writer got.
    fn while_a_writer_waits(
        dir: &Path,
        meanwhile: impl FnOnce(&Path),
    ) -> Result<crate::audit::AuditReceipt, AuditError> {
        let path = dir.join(AUDIT_FILE_NAME);
        let holder = File::options().read(true).open(&path).unwrap();
        flock(&holder, FlockOperation::LockExclusive).unwrap();
        let waiting = dir.to_path_buf();
        let writer = std::thread::spawn(move || {
            JsonlLog::opened_for_test(&waiting)
                .with_lock_wait(Duration::from_secs(30))
                .append(&refusal)
        });
        // Long enough for the writer to be waiting on the lock. Were it not
        // yet, it would open whatever `meanwhile` left at the path, which is
        // the outcome these tests require anyway.
        std::thread::sleep(Duration::from_millis(300));
        meanwhile(&path);
        drop(holder);
        writer.join().unwrap()
    }

    #[test]
    fn a_log_deleted_while_a_writer_waits_never_takes_the_record_with_it() {
        // Locked after the delete, the old file had no name left: a record
        // appended there would vanish when it was closed, receipt and all.
        let dir = scratch("deleted-while-waiting");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        let receipt =
            while_a_writer_waits(&dir, |path| std::fs::remove_file(path).unwrap()).unwrap();
        assert_eq!(receipt.seq(), Sequence::first());
        let live = read_chain(&dir);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].hash, receipt.hash());
    }

    #[test]
    fn a_log_moved_aside_while_a_writer_waits_keeps_its_evidence_untouched() {
        // What the damaged-tail refusal tells an operator to do. The moved log
        // is evidence and gains nothing; the record starts the chain at the
        // log's path, as the operator meant.
        let dir = scratch("moved-while-waiting");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        let aside = dir.join("audit.jsonl.damaged");
        let receipt =
            while_a_writer_waits(&dir, |path| std::fs::rename(path, &aside).unwrap()).unwrap();
        assert_eq!(receipt.seq(), Sequence::first());
        let kept = std::fs::read_to_string(&aside).unwrap();
        assert_eq!(Chain::from_jsonl(&kept).unwrap().len(), 1);
        let live = read_chain(&dir);
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].hash, receipt.hash());
    }

    #[test]
    fn a_log_replaced_while_a_writer_waits_is_written_in_its_replacement() {
        // A new file under the name: the directory names another inode than
        // the one locked, so the writer opens the replacement and starts its
        // chain there.
        let dir = scratch("replaced-while-waiting");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        let aside = dir.join("old.jsonl");
        let receipt = while_a_writer_waits(&dir, |path| {
            std::fs::rename(path, &aside).unwrap();
            std::os::unix::fs::OpenOptionsExt::mode(
                File::options().write(true).create_new(true),
                0o600,
            )
            .open(path)
            .unwrap();
        })
        .unwrap();
        assert_eq!(receipt.seq(), Sequence::first());
        assert_eq!(read_chain(&dir).len(), 1);
        assert_eq!(std::fs::read_to_string(&aside).unwrap().lines().count(), 1);
    }

    #[test]
    fn a_log_that_keeps_changing_under_the_writer_is_refused_once_the_wait_runs_out() {
        // Every attempt finds the log replaced: the writer gives up at its
        // bound rather than looping, and it does not start the bound over.
        // Within the bound, it tries until the log holds still: the three
        // races above.
        let path = Path::new("/var/lib/aido/audit.jsonl");
        let mut attempts = 0;
        let err = until_current(Patience::from_now(Duration::ZERO), path, &mut || {
            attempts += 1;
            Ok(None)
        })
        .unwrap_err();
        assert_eq!(attempts, 1);
        assert!(
            err.to_string()
                .contains("each time this writer took its lock"),
            "{err}"
        );
    }

    #[test]
    fn the_record_reaches_the_mirrors_while_the_log_is_still_locked() {
        // Sent after the lock was released, a record could be chained onto by
        // the next writer before its mirror refused it — and the cut back to
        // where the log ended would then take the other writer's receipted
        // record too.
        let dir = scratch("publish-locked");
        let path = dir.join(AUDIT_FILE_NAME);
        let mut seen_lock = None;
        let record = JsonlLog::opened_for_test(&dir)
            .write(&refusal, &|_| Ok(()), &mut |_| {
                let other = File::open(&path).unwrap();
                seen_lock = Some(flock(&other, FlockOperation::NonBlockingLockExclusive));
                Ok(())
            })
            .unwrap();
        assert_eq!(seen_lock, Some(Err(Errno::WOULDBLOCK)));
        assert_eq!(read_chain(&dir), [record]);
    }

    #[test]
    fn a_failed_append_on_the_real_file_is_cut_back() {
        // The cut-back itself, on a real descriptor: the fake shows when it is
        // called, this shows what it does.
        let dir = scratch("truncate");
        let _ = JsonlLog::opened_for_test(&dir).append(&refusal).unwrap();
        let path = dir.join(AUDIT_FILE_NAME);
        let before = std::fs::read(&path).unwrap();
        let dir_fd = rustix::fs::open(
            &dir,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mut file = HostLogFile {
            file: File::options().append(true).read(true).open(&path).unwrap(),
            dir: dir_fd.as_fd(),
        };
        file.append(b"{\"partial").unwrap();
        file.truncate(before.len() as u64).unwrap();
        file.sync_dir().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(format!("{file:?}").contains("HostLogFile"));
    }

    /// What the walk says first on this platform. On Linux it reaches the
    /// components, so the component's own fault is reported. Off Linux there
    /// is no mount table, and the walk refuses on that before it looks at any
    /// component: the fail-closed answer, and the only one these tests can
    /// observe there. The walk itself is tested against a fake mount table in
    /// `trust.rs`, on every platform.
    #[cfg(target_os = "linux")]
    fn first_refusal<'a>(on_linux: &'a str, _elsewhere: &'a str) -> &'a str {
        on_linux
    }
    #[cfg(not(target_os = "linux"))]
    fn first_refusal<'a>(_on_linux: &'a str, elsewhere: &'a str) -> &'a str {
        elsewhere
    }

    const NO_MOUNT_TABLE: &str = "mount table cannot be checked";

    #[test]
    fn the_directory_must_pass_the_walk_from_the_root() {
        // A checkout is the developer's, not root's.
        let err = JsonlLog::in_dir(env!("CARGO_MANIFEST_DIR"))
            .append(&refusal)
            .unwrap_err();
        let expected = first_refusal("not root", NO_MOUNT_TABLE);
        assert!(err.to_string().contains(expected), "{err}");
        // A path through a link is refused at the link: merged-/usr Linux has
        // /bin -> usr/bin, macOS has /tmp -> private/tmp.
        let through_link = ["/bin", "/tmp"]
            .into_iter()
            .find(|candidate| {
                std::fs::symlink_metadata(candidate).is_ok_and(|meta| meta.is_symlink())
            })
            .expect("this host has neither /bin nor /tmp as a link");
        let err = JsonlLog::in_dir(through_link).append(&refusal).unwrap_err();
        let expected = first_refusal("symbolic link", NO_MOUNT_TABLE);
        assert!(err.to_string().contains(expected), "{err}");
        // Not absolute is refused before any walk, on every platform.
        let err = JsonlLog::in_dir("relative/dir")
            .append(&refusal)
            .unwrap_err();
        assert!(err.to_string().contains("not absolute"), "{err}");
    }

    /// A root-owned directory nobody, root included, can create a file in:
    /// `/proc` on Linux, the sealed system volume on macOS.
    #[cfg(target_os = "linux")]
    const NO_CREATE_DIR: &str = "/proc";
    #[cfg(not(target_os = "linux"))]
    const NO_CREATE_DIR: &str = "/usr/bin";

    #[test]
    fn a_trusted_directory_the_log_cannot_be_created_in_fails_closed() {
        // On Linux the walk passes, so this is the system path end to end:
        // open, refused by the kernel, reported, nothing written. Off Linux
        // the walk refuses first, so nothing is opened at all.
        let err = JsonlLog::in_dir(NO_CREATE_DIR)
            .append(&refusal)
            .unwrap_err();
        let expected = first_refusal("cannot open", NO_MOUNT_TABLE);
        assert!(err.to_string().contains(expected), "{err}");
    }

    #[test]
    fn the_system_log_is_under_var_lib_aido_where_the_configuration_says() {
        assert_eq!(AUDIT_DIR, "/var/lib/aido");
        assert_eq!(AUDIT_FILE_NAME, "audit.jsonl");
        assert_eq!(
            Path::new(AUDIT_DIR).join(AUDIT_FILE_NAME),
            aido_config::SystemPaths::default().audit_log()
        );
        let rendered = format!("{:?}", JsonlLog::system());
        assert!(rendered.contains("/var/lib/aido"), "{rendered}");
        assert!(rendered.contains("5s"), "{rendered}");
    }

    #[test]
    fn the_fake_sink_and_the_real_log_agree_on_what_follows() {
        // A consumer's tests use the fake; production uses the log. A builder
        // that passes one and fails the other would be found late.
        let dir = scratch("agree");
        let mut real = JsonlLog::opened_for_test(&dir);
        let mut fake = FakeAuditSink::new();
        for _ in 0..2 {
            assert_eq!(
                real.append(&refusal).unwrap().seq(),
                fake.append(&refusal).unwrap().seq()
            );
        }
        let restart = |_: Option<&Record>| refusal(None);
        assert_eq!(
            real.append(&restart).unwrap_err(),
            fake.append(&restart).unwrap_err()
        );
        assert_eq!(read_chain(&dir), fake.records());
        let finished =
            |previous: Option<&Record>| refusal(previous).with_outcome(Outcome::Exited { code: 0 });
        assert!(real.append(&finished).is_ok());
    }

    /// A refusal whose line is `MAX_RECORD_BYTES + extra` bytes long, after
    /// whatever record comes before it.
    fn padded_to_the_limit(extra: usize) -> impl Fn(Option<&Record>) -> Record {
        move |previous| {
            let bare = Record::after(
                previous,
                Decision::Denied,
                vec![String::new()],
                "unattested",
            );
            let room = MAX_RECORD_BYTES - bare.to_jsonl().len() + extra;
            Record::after(
                previous,
                Decision::Denied,
                vec!["x".repeat(room)],
                "unattested",
            )
        }
    }

    #[test]
    fn the_fake_sink_refuses_exactly_the_records_too_long_for_the_real_log() {
        // A builder padded by a long argv passed every test against the fake
        // and failed with TooLarge only in production. The two now share one
        // check, and agree at the byte.
        let dir = scratch("agree-size");
        let mut real = JsonlLog::opened_for_test(&dir);
        let mut fake = FakeAuditSink::new();
        let at_limit = padded_to_the_limit(0);
        assert_eq!(
            real.append(&at_limit).unwrap().seq(),
            fake.append(&at_limit).unwrap().seq()
        );
        let over = padded_to_the_limit(1);
        let refused = real.append(&over).unwrap_err();
        assert_eq!(
            refused,
            AuditError::TooLarge {
                size: MAX_RECORD_BYTES + 1,
                max: MAX_RECORD_BYTES
            }
        );
        assert_eq!(fake.append(&over).unwrap_err(), refused);
        assert_eq!(read_chain(&dir), fake.records());
        assert_eq!(fake.records().len(), 1);
    }
}
