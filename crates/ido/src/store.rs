//! The queue on disk: one JSONL line per entry, private to the user.
//!
//! Layout decisions, all deliberate:
//!
//! * Under `$XDG_STATE_HOME/ido`, never a runtime or temp directory — a queue
//!   that vanishes on logout loses exactly the work the human meant to come
//!   back to. Directory `0700`, files `0600`, created with `O_EXCL`.
//! * One queue per user. There is no shared queue, ever: a shared queue is a
//!   way for one user to get another user to run their command.
//! * Queueing appends one line. Removal and state changes rewrite through a
//!   temp file in the same directory, `fsync`, then an atomic rename — a
//!   crash leaves either the old queue or the new one, never a torn file.
//! * A file with any line this version cannot parse refuses to load whole.
//! * A queue directory or file owned by someone else, or writable by group or
//!   world, refuses to load: anyone who can write the queue can choose what
//!   the human runs next. Checked on the opened descriptor, not the path.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aido_audit::{Chain, Record};

use crate::entry::Entry;
use crate::error::IdoError;

/// The queue directory and files, resolved and ready for I/O.
#[derive(Debug)]
pub struct Store {
    queue: PathBuf,
    log: PathBuf,
    lock: PathBuf,
    uid: u32,
}

/// Holds the queue lock for the lifetime of a mutation.
///
/// Dropping removes the lock file. A crash leaves it behind; the error a
/// blocked caller sees says exactly that and names the path, because a lock
/// that silently expires is a lock two processes can hold.
#[derive(Debug)]
pub struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Nothing useful can be done about a failure here, and panicking in a
        // destructor would abort: the next locker's error names the path.
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Store {
    /// Opens the store, creating its private directories if needed.
    ///
    /// `uid` is the user the queue must belong to — the caller's real uid,
    /// supplied by the binary so a test can name a different one.
    ///
    /// # Errors
    ///
    /// Fails when a directory cannot be created `0700`, and refuses one that
    /// belongs to another user or is writable by group or world.
    pub fn open(state_dir: &Path, runtime_dir: &Path, uid: u32) -> Result<Self, IdoError> {
        for dir in [state_dir, runtime_dir] {
            let meta = ensure_private_dir(dir)?;
            check_private(&meta, dir, uid)?;
        }
        Ok(Self {
            queue: state_dir.join("queue.jsonl"),
            log: state_dir.join("log.jsonl"),
            lock: runtime_dir.join("lock"),
            uid,
        })
    }

    /// The queue file path, for messages.
    #[must_use]
    pub fn queue_path(&self) -> &Path {
        &self.queue
    }

    /// The run-log path, for messages.
    #[must_use]
    pub fn log_path(&self) -> &Path {
        &self.log
    }

    /// Takes the queue lock.
    ///
    /// # Errors
    ///
    /// [`IdoError::Locked`] when another process holds it; I/O otherwise.
    pub fn lock(&self) -> Result<LockGuard, IdoError> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&self.lock)
        {
            Ok(mut file) => {
                // Contents are a courtesy for a human inspecting a stale lock.
                let _ = file.write_all(std::process::id().to_string().as_bytes());
                Ok(LockGuard {
                    path: self.lock.clone(),
                })
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => Err(IdoError::Locked {
                path: self.lock.clone(),
            }),
            Err(e) => Err(io_err("lock", &self.lock, e)),
        }
    }

    /// Takes the queue lock, retrying for up to `wait`.
    ///
    /// The lock is held for milliseconds — `ido` never holds it while a
    /// command runs — so a short wait turns a collision between an agent's
    /// `ido queue` and the human's `ido` into a pause instead of an error.
    ///
    /// # Errors
    ///
    /// As [`Store::lock`], once `wait` has passed.
    pub fn lock_waiting(&self, wait: Duration) -> Result<LockGuard, IdoError> {
        let started = Instant::now();
        loop {
            match self.lock() {
                Err(IdoError::Locked { .. }) if started.elapsed() < wait => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                other => return other,
            }
        }
    }

    /// Loads the whole queue.
    ///
    /// # Errors
    ///
    /// Refuses whole on the first unparsable line — see the module docs — and
    /// on any read failure. A missing file is an empty queue.
    pub fn load(&self) -> Result<Vec<Entry>, IdoError> {
        let Some(text) = read_private(&self.queue, self.uid)? else {
            return Ok(Vec::new());
        };
        let mut entries = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let entry: Entry =
                serde_json::from_str(line).map_err(|source| IdoError::QueueParse {
                    line: i.saturating_add(1),
                    source,
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Appends one entry.
    ///
    /// # Errors
    ///
    /// Any I/O failure. The caller holds the lock.
    pub fn append(&self, entry: &Entry) -> Result<(), IdoError> {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.queue)
            .map_err(|e| io_err("open", &self.queue, e))?;
        write_all_sync(&mut file, entry.to_jsonl().as_bytes(), &self.queue)
    }

    /// Replaces the whole queue atomically: temp file, `fsync`, rename.
    ///
    /// # Errors
    ///
    /// Any I/O failure. The caller holds the lock.
    pub fn replace(&self, entries: &[Entry]) -> Result<(), IdoError> {
        let tmp = self
            .queue
            .with_extension(format!("tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| io_err("create", &tmp, e))?;
        let mut body = String::new();
        for entry in entries {
            body.push_str(&entry.to_jsonl());
        }
        let written = file
            .write_all(body.as_bytes())
            .and_then(|()| file.sync_data());
        drop(file);
        written
            .and_then(|()| std::fs::rename(&tmp, &self.queue))
            .map_err(|e| {
                // Never leave a half-written candidate behind.
                let _ = std::fs::remove_file(&tmp);
                io_err("replace", &self.queue, e)
            })
    }

    /// Reads the run log's chain, verifying it parses.
    ///
    /// # Errors
    ///
    /// [`IdoError::LogUnreadable`] when the chain does not parse; I/O
    /// otherwise. A missing log is an empty chain.
    pub fn read_log(&self) -> Result<Chain, IdoError> {
        let Some(text) = read_if_exists(&self.log)? else {
            return Ok(Chain::new());
        };
        Chain::from_jsonl(&text).map_err(|e| IdoError::LogUnreadable {
            path: self.log.clone(),
            detail: e.to_string(),
        })
    }

    /// Appends one record to the run log, chained after the current tail.
    ///
    /// The record is written and synced before this returns: the log is the
    /// evidence of what ran, and evidence written after the fact is not
    /// evidence.
    ///
    /// # Errors
    ///
    /// Any I/O or chain failure.
    pub fn append_log(&self, record: &Record) -> Result<(), IdoError> {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.log)
            .map_err(|e| io_err("open", &self.log, e))?;
        let mut line = record.to_jsonl();
        line.push('\n');
        write_all_sync(&mut file, line.as_bytes(), &self.log)
    }
}

/// Creates `dir` (and parents) with mode `0700` if it is missing, and
/// returns what is there now.
fn ensure_private_dir(dir: &Path) -> Result<Metadata, IdoError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .and_then(|()| std::fs::metadata(dir))
        .map_err(|e| io_err("create directory", dir, e))
}

/// Refuses metadata that belongs to someone other than `uid`, or that grants
/// write access to group or world.
fn check_private(meta: &Metadata, path: &Path, uid: u32) -> Result<(), IdoError> {
    if meta.uid() != uid {
        return Err(IdoError::Refused(format!(
            "{} belongs to uid {}, not to you (uid {uid}); ido will not read a queue \
             someone else can write",
            path.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(IdoError::Refused(format!(
            "{} is writable by group or world (mode {:o}); anyone who can write the \
             queue chooses what you run next. Fix with: chmod go-w {}",
            path.display(),
            meta.mode() & 0o7777,
            path.display()
        )));
    }
    Ok(())
}

/// Reads a private file whole, checking ownership and mode on the opened
/// descriptor; "not found" is `None`.
fn read_private(path: &Path, uid: u32) -> Result<Option<String>, IdoError> {
    match File::open(path) {
        Ok(mut file) => {
            let mut text = String::new();
            let meta = file
                .metadata()
                .and_then(|meta| file.read_to_string(&mut text).map(|_| meta))
                .map_err(|e| io_err("read", path, e))?;
            // Checked on the descriptor that was read, so a swap of the path
            // between the check and the read is not possible.
            check_private(&meta, path, uid)?;
            Ok(Some(text))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err("open", path, e)),
    }
}

/// Reads a file whole, mapping "not found" to `None`.
fn read_if_exists(path: &Path) -> Result<Option<String>, IdoError> {
    match File::open(path) {
        Ok(mut file) => {
            let mut text = String::new();
            file.read_to_string(&mut text)
                .map_err(|e| io_err("read", path, e))?;
            Ok(Some(text))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err("open", path, e)),
    }
}

/// Writes everything and syncs the data to disk.
fn write_all_sync(file: &mut File, bytes: &[u8], path: &Path) -> Result<(), IdoError> {
    file.write_all(bytes)
        .and_then(|()| file.sync_data())
        .map_err(|e| io_err("write", path, e))
}

/// Shapes an I/O failure with what was attempted and where.
fn io_err(op: &'static str, path: &Path, source: std::io::Error) -> IdoError {
    IdoError::Io {
        op,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    use std::os::unix::fs::PermissionsExt;

    use crate::entry::QUEUE_SCHEMA_VERSION;

    /// A fresh directory under the workspace target dir — never `/tmp`.
    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("ido-store-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn my_uid(dir: &Path) -> u32 {
        std::fs::metadata(dir).unwrap().uid()
    }

    fn open(name: &str) -> (PathBuf, Store) {
        let dir = scratch(name);
        let uid = my_uid(&dir);
        let store = Store::open(&dir.join("state"), &dir.join("run"), uid).unwrap();
        (dir, store)
    }

    fn entry(id: u64) -> Entry {
        Entry {
            schema_version: QUEUE_SCHEMA_VERSION,
            id,
            argv: vec!["true".into()],
            reason: None,
            group: None,
            step: None,
            needs: Vec::new(),
            cwd: None,
            dry_run_of: Vec::new(),
            queued_at: 0,
            queued_by: None,
            attempts: 0,
            last_exit: None,
        }
    }

    #[test]
    fn append_load_and_replace_round_trip_privately() {
        let (dir, store) = open("round-trip");
        assert!(store.load().unwrap().is_empty(), "a missing queue is empty");
        store.append(&entry(1)).unwrap();
        store.append(&entry(2)).unwrap();
        assert_eq!(store.load().unwrap(), vec![entry(1), entry(2)]);
        store.replace(&[entry(2)]).unwrap();
        assert_eq!(store.load().unwrap(), vec![entry(2)]);
        assert_eq!(store.queue_path(), dir.join("state").join("queue.jsonl"));
        assert_eq!(store.log_path(), dir.join("state").join("log.jsonl"));
        let mode = |p: &Path| std::fs::metadata(p).unwrap().mode() & 0o777;
        assert_eq!(mode(store.queue_path()), 0o600);
        assert_eq!(mode(&dir.join("state")), 0o700);
    }

    #[test]
    fn another_users_queue_is_unreachable() {
        let dir = scratch("other-user");
        let not_me = my_uid(&dir).wrapping_add(1);
        let err = Store::open(&dir.join("state"), &dir.join("run"), not_me).unwrap_err();
        assert!(err.to_string().contains("not to you"), "{err}");
        assert_eq!(err.exit_code(), 2);

        // The same check runs on the queue file's own descriptor.
        let (_, store) = open("other-user-file");
        store.append(&entry(1)).unwrap();
        let foreign = Store {
            uid: not_me,
            ..Store::open(
                store.queue_path().parent().unwrap(),
                store.lock.parent().unwrap(),
                my_uid(store.queue_path()),
            )
            .unwrap()
        };
        let err = foreign.load().unwrap_err();
        assert!(err.to_string().contains("not to you"), "{err}");
    }

    #[test]
    fn a_group_writable_queue_is_refused() {
        let dir = scratch("group-writable");
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = Store::open(&state, &dir.join("run"), my_uid(&dir)).unwrap_err();
        assert!(
            err.to_string().contains("writable by group or world"),
            "{err}"
        );

        let (_, store) = open("world-writable-file");
        store.append(&entry(1)).unwrap();
        std::fs::set_permissions(store.queue_path(), std::fs::Permissions::from_mode(0o666))
            .unwrap();
        let err = store.load().unwrap_err();
        assert!(err.to_string().contains("chmod go-w"), "{err}");
    }

    #[test]
    fn an_unparsable_line_refuses_the_whole_queue() {
        let (_, store) = open("unparsable");
        store.append(&entry(1)).unwrap();
        let mut text = std::fs::read_to_string(store.queue_path()).unwrap();
        text.push_str("\n{\"not\":\"an entry\"}\n");
        std::fs::write(store.queue_path(), text).unwrap();
        let err = store.load().unwrap_err();
        assert!(err.to_string().starts_with("queue line 3"), "{err}");
    }

    #[test]
    fn the_lock_is_exclusive_released_on_drop_and_waited_for_briefly() {
        let (_, store) = open("lock");
        let held = store.lock().unwrap();
        let err = store.lock().unwrap_err();
        assert!(err.to_string().contains("another ido process"), "{err}");
        let started = Instant::now();
        let err = store.lock_waiting(Duration::from_millis(30)).unwrap_err();
        assert!(err.to_string().contains("another ido process"), "{err}");
        assert!(started.elapsed() >= Duration::from_millis(30));
        drop(held);
        drop(store.lock_waiting(Duration::from_millis(30)).unwrap());
        assert!(store.lock().is_ok());
    }

    #[test]
    fn io_failures_name_what_was_attempted() {
        // A file where a directory must go.
        let dir = scratch("io");
        std::fs::write(dir.join("file"), "").unwrap();
        let err = Store::open(&dir.join("file").join("state"), &dir.join("run"), 0).unwrap_err();
        assert!(err.to_string().starts_with("create directory"), "{err}");

        // The lock directory vanishing is an I/O error, not "locked".
        let (dir, store) = open("io-lock");
        std::fs::remove_dir_all(dir.join("run")).unwrap();
        let err = store.lock().unwrap_err();
        assert!(err.to_string().starts_with("lock"), "{err}");

        // A directory where the queue should be: open succeeds, read fails;
        // append and replace both fail too.
        let (_, store) = open("io-queue-dir");
        std::fs::create_dir_all(store.queue_path()).unwrap();
        assert!(store.load().unwrap_err().to_string().starts_with("read"));
        assert!(
            store
                .append(&entry(1))
                .unwrap_err()
                .to_string()
                .starts_with("open")
        );
        assert!(
            store
                .replace(&[])
                .unwrap_err()
                .to_string()
                .starts_with("replace")
        );
        let tmp = store
            .queue_path()
            .with_extension(format!("tmp.{}", std::process::id()));
        assert!(!tmp.exists(), "the candidate is cleaned up");

        // A blocked temporary path fails the replace before anything moves.
        let (_, store) = open("io-tmp");
        let tmp = store
            .queue_path()
            .with_extension(format!("tmp.{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert!(
            store
                .replace(&[])
                .unwrap_err()
                .to_string()
                .starts_with("create")
        );

        // A queue path whose parent is a file cannot be opened at all.
        let (dir, mut store) = open("io-open");
        std::fs::write(dir.join("plain"), "").unwrap();
        store.queue = dir.join("plain").join("queue.jsonl");
        assert!(store.load().unwrap_err().to_string().starts_with("open"));

        // The run log, likewise: a parent that is a file, then a directory
        // where the log should be.
        let (dir, mut store) = open("io-log-open");
        std::fs::write(dir.join("plain"), "").unwrap();
        store.log = dir.join("plain").join("log.jsonl");
        assert!(
            store
                .read_log()
                .unwrap_err()
                .to_string()
                .starts_with("open")
        );
        // The run log, likewise.
        let (_, store) = open("io-log");
        std::fs::create_dir_all(store.log_path()).unwrap();
        assert!(store.read_log().is_err());
        assert!(
            store
                .append_log(&aido_audit::Record::first(
                    aido_audit::Decision::Allowed,
                    vec!["x".into()],
                    "t"
                ))
                .unwrap_err()
                .to_string()
                .starts_with("open")
        );
    }

    #[test]
    fn a_log_that_does_not_parse_is_unreadable() {
        let (_, store) = open("log-garbage");
        assert!(
            store.read_log().unwrap().is_empty(),
            "a missing log is empty"
        );
        std::fs::write(store.log_path(), "garbage\n").unwrap();
        let err = store.read_log().unwrap_err();
        assert!(err.to_string().contains("is unreadable"), "{err}");
    }

    #[test]
    fn a_write_to_an_unwritable_file_reports_write_and_the_path() {
        // /dev/null opened read-only: write_all fails with EBADF, which is
        // exactly the arm a full disk or a yanked fd would take.
        let mut file = File::open("/dev/null").unwrap();
        let err = write_all_sync(&mut file, b"x", Path::new("/dev/null")).unwrap_err();
        let text = err.to_string();
        assert!(text.starts_with("write /dev/null"), "{text}");
    }
}
