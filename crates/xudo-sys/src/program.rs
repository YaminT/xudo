//! The program the gate runs: opened once, judged on that descriptor, run from
//! that descriptor.
//!
//! A check made on a path and an `exec` made on the path are two lookups, and
//! anything that can change what the name points at between them chooses what
//! runs as root. So the gate opens the program through the trust walk
//! ([`crate::open_trusted`]'s: every component root's, on a mount root made, no
//! link anywhere, the target the very inode that passed), keeps the descriptor,
//! and asks every further question of it:
//!
//! * `fstat`: a regular file with an execute bit.
//! * Its contents, read through the descriptor with `pread`, are hashed with
//!   SHA-256; the digest goes into the audit record, so what ran is
//!   identifiable afterwards even when the file has since been replaced.
//! * Its first two bytes are not `#!`. A script is refused, with that reason:
//!   the kernel would hand the interpreter a `/proc/self/fd/N` path it opens
//!   again by name, and through a close-on-exec descriptor refuses with the
//!   unhelpful `ENOENT`, so a script could never have run the way the gate
//!   runs things. A rule that names a script names a program the gate cannot
//!   vouch for; the operator should name the interpreter and its argument
//!   instead, and see that decision made.
//!
//! The same descriptor is what [`crate::Syscalls::exec_fd`] executes
//! (`execveat(fd, "", AT_EMPTY_PATH)`), so what was hashed is what runs.
//! Off Linux there is no mount table, so [`HostPrograms`] refuses everything.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::fstat;
use rustix::io::pread;
use sha2::{Digest, Sha256};

use crate::error::lift;
use crate::mounts::{HostMounts, MountView};
use crate::trust::{
    FORBIDDEN_WRITE_BITS, Kind, TRUSTED_UID, TrustError, facts_of, open_trusted_with,
};

/// How much of the program is read at a time.
const CHUNK: usize = 64 * 1024;

/// The `chmod` bits that make a file executable by someone.
const EXECUTE_BITS: u32 = 0o111;

/// Why a program cannot be run.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProgramError {
    /// The path, or something on it, failed the trust walk.
    #[error(transparent)]
    Untrusted(#[from] TrustError),
    /// The descriptor could not be inspected or read.
    #[error("{at} cannot be read: {reason}")]
    Unreadable {
        /// The program.
        at: String,
        /// Why.
        reason: String,
    },
    /// The program is not a regular file.
    #[error("{at} is not a regular file, so it is not a program the gate will run")]
    NotRegularFile {
        /// The program.
        at: String,
    },
    /// The program has no execute bit.
    #[error("{at} is not executable")]
    NotExecutable {
        /// The program.
        at: String,
    },
    /// The program is owned by someone other than root.
    ///
    /// The walk has already said so for the path; this is the same question
    /// asked of the descriptor that will be run.
    #[error("{at} is owned by uid {uid}, not root: its owner decides what runs as root")]
    NotRootOwned {
        /// The program.
        at: String,
        /// Who owns it.
        uid: u32,
    },
    /// The program can be written by someone other than its owner.
    #[error("{at} has mode {mode:04o}: it is writable by group or world")]
    Writable {
        /// The program.
        at: String,
        /// Its mode.
        mode: u32,
    },
    /// The program is a `#!` script.
    #[error(
        "{at} is a script (it begins with #!): the interpreter would open it again by name, so \
         the gate will not run it; name the interpreter in the rule instead"
    )]
    Script {
        /// The program.
        at: String,
    },
}

/// A program opened, judged, and hashed.
#[derive(Debug)]
pub struct Program {
    fd: OwnedFd,
    size: u64,
    dev: u64,
    ino: u64,
    sha256: String,
}

impl Program {
    /// Judges and hashes an open descriptor, whose file `owner` must own.
    ///
    /// The walk that opened it has judged the path; this asks the same of the
    /// descriptor that will be run, so a program is never run on the strength
    /// of a check made on something else.
    ///
    /// # Errors
    ///
    /// [`ProgramError`] when it is not a regular file owned by `owner`, is
    /// writable by group or world, is not executable, is a script, or cannot be
    /// read.
    pub fn from_fd(fd: OwnedFd, at: &Path, owner: u32) -> Result<Self, ProgramError> {
        let at = at.display().to_string();
        unreadable(&at, lift("fstat", fstat(&fd)))
            .and_then(|stat| Self::judged(fd, at, owner, &stat))
    }

    /// [`Self::from_fd`], once `fstat` has answered.
    ///
    /// `st_dev` is an `i32` on macOS and a `u64` on Linux, so its conversion is
    /// real on one platform and an identity on the other.
    #[allow(clippy::useless_conversion)]
    fn judged(
        fd: OwnedFd,
        at: String,
        owner: u32,
        stat: &rustix::fs::Stat,
    ) -> Result<Self, ProgramError> {
        let facts = facts_of(stat);
        if facts.kind != Kind::File {
            return Err(ProgramError::NotRegularFile { at });
        }
        if facts.uid != owner {
            return Err(ProgramError::NotRootOwned { at, uid: facts.uid });
        }
        if facts.mode & FORBIDDEN_WRITE_BITS != 0 {
            return Err(ProgramError::Writable {
                at,
                mode: facts.mode,
            });
        }
        if facts.mode & EXECUTE_BITS == 0 {
            return Err(ProgramError::NotExecutable { at });
        }
        let sha256 = digest(fd.as_fd(), &at)?;
        Ok(Self {
            size: u64::try_from(stat.st_size).unwrap_or(0),
            dev: u64::try_from(stat.st_dev).unwrap_or(0),
            ino: stat.st_ino,
            fd,
            sha256,
        })
    }

    /// The descriptor to execute.
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// The SHA-256 of the contents, 64 lowercase hex characters.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The size in bytes, as `fstat` reported it.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The `(st_dev, st_ino)` of the file, as `fstat` reported them.
    pub fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

/// Lifts a failure to inspect or read the program.
fn unreadable<T>(at: &str, result: Result<T, crate::SysError>) -> Result<T, ProgramError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(ProgramError::Unreadable {
            at: at.to_owned(),
            reason: error.to_string(),
        }),
    }
}

/// Fills `buffer` from `offset`, stopping early only at the end of the file,
/// and returns how many bytes it holds.
///
/// A single `pread` may return fewer bytes than were asked for, so a check on
/// the first two bytes of a file must not trust one call to have returned both.
fn read_fully(
    fd: BorrowedFd<'_>,
    buffer: &mut [u8],
    offset: u64,
    at: &str,
) -> Result<usize, ProgramError> {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        let position = offset.saturating_add(u64::try_from(filled).unwrap_or(0));
        let rest = buffer.get_mut(filled..).unwrap_or_default();
        let read = unreadable(at, lift("pread", pread(fd, rest, position)))?;
        if read == 0 {
            break;
        }
        filled = filled.saturating_add(read);
    }
    Ok(filled)
}

/// Something that fills a buffer from an offset and says how many bytes it
/// holds: [`read_fully`] on a descriptor, or a test's own.
trait Reader: Fn(&mut [u8], u64) -> Result<usize, ProgramError> {}

impl<F: Fn(&mut [u8], u64) -> Result<usize, ProgramError>> Reader for F {}

/// Refuses a script, then reads the whole descriptor with `pread` and returns
/// its SHA-256.
fn digest(fd: BorrowedFd<'_>, at: &str) -> Result<String, ProgramError> {
    digest_with(&|buffer, offset| read_fully(fd, buffer, offset, at), at)
}

/// [`digest`], reading through `read`, so a test can make the read fail after
/// the first bytes have been seen, as a failing disk would.
fn digest_with(read: &dyn Reader, at: &str) -> Result<String, ProgramError> {
    let mut head = [0_u8; 2];
    let got = read(&mut head, 0)?;
    if head.get(..got).is_some_and(|seen| seen == b"#!") {
        return Err(ProgramError::Script { at: at.to_owned() });
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK];
    let mut offset: u64 = 0;
    loop {
        let count = read(&mut buffer, offset)?;
        if count == 0 {
            return Ok(format!("{:x}", hasher.finalize()));
        }
        hasher.update(buffer.get(..count).unwrap_or_default());
        offset = offset.saturating_add(u64::try_from(count).unwrap_or(0));
    }
}

/// Somewhere to open the program a rule names.
pub trait Programs {
    /// Opens `path` through the trust walk and judges it.
    ///
    /// # Errors
    ///
    /// [`ProgramError`]; every one means the gate does not run it.
    fn open(&self, path: &Path) -> Result<Program, ProgramError>;
}

/// The real trust walk.
#[derive(Clone, Copy, Debug)]
pub struct HostPrograms;

impl HostPrograms {
    /// [`Programs::open`], with the owner and the mount table as parameters so
    /// a test can point it at a directory no test host has.
    pub(crate) fn open_with(
        path: &Path,
        owner: u32,
        view: &dyn MountView,
    ) -> Result<Program, ProgramError> {
        match open_trusted_with(path, owner, view) {
            Ok(fd) => Program::from_fd(fd, path, owner),
            Err(error) => Err(ProgramError::Untrusted(error)),
        }
    }
}

impl Programs for HostPrograms {
    fn open(&self, path: &Path) -> Result<Program, ProgramError> {
        Self::open_with(path, TRUSTED_UID, &HostMounts::proc())
    }
}

/// A [`Programs`] a test scripts: every path opens the same prepared answer.
#[derive(Debug)]
pub struct FakePrograms {
    opened: std::cell::RefCell<Vec<PathBuf>>,
    answer: Result<(PathBuf, u32), ProgramError>,
}

impl FakePrograms {
    /// Opens `file` (a path to a real file a test made, owned by `owner`)
    /// whatever is asked for, through [`Program::from_fd`].
    pub fn serving(file: impl Into<PathBuf>, owner: u32) -> Self {
        Self {
            opened: std::cell::RefCell::new(Vec::new()),
            answer: Ok((file.into(), owner)),
        }
    }

    /// Refuses every path with `error`.
    pub fn refusing(error: ProgramError) -> Self {
        Self {
            opened: std::cell::RefCell::new(Vec::new()),
            answer: Err(error),
        }
    }

    /// The paths asked for, in order.
    pub fn opened(&self) -> Vec<PathBuf> {
        self.opened.borrow().clone()
    }
}

impl Programs for FakePrograms {
    fn open(&self, path: &Path) -> Result<Program, ProgramError> {
        self.opened.borrow_mut().push(path.to_path_buf());
        match &self.answer {
            Ok((file, owner)) => match std::fs::File::open(file) {
                Ok(handle) => Program::from_fd(OwnedFd::from(handle), file, *owner),
                Err(error) => Err(ProgramError::Unreadable {
                    at: file.display().to_string(),
                    reason: error.to_string(),
                }),
            },
            Err(error) => Err(error.clone()),
        }
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

    use super::*;
    use crate::mounts::fake::FakeMounts;

    /// A fresh directory under the workspace `target/`, never `/tmp`, 0700.
    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("pg-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn owner_of(dir: &Path) -> u32 {
        std::fs::metadata(dir).unwrap().uid()
    }

    fn file(dir: &Path, name: &str, body: &[u8], mode: u32) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// Judges a file a test made, on a descriptor opened directly: the walk
    /// down from `/` needs every ancestor to be root's, which the checkout's
    /// are not, and the walk has tests of its own.
    fn open(path: &Path) -> Result<Program, ProgramError> {
        let handle = std::fs::File::open(path).unwrap();
        Program::from_fd(
            OwnedFd::from(handle),
            path,
            owner_of(path.parent().unwrap()),
        )
    }

    /// The variant's name, so a test can say which refusal it saw without a
    /// `matches!` whose other arm no test reaches.
    fn kind(error: &ProgramError) -> String {
        format!("{error:?}")
            .split([' ', '(', '{'])
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    /// SHA-256 of "abc", the standard test vector.
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn a_program_is_hashed_through_the_descriptor_it_will_be_run_from() {
        let dir = scratch("hash");
        let path = file(&dir, "tool", b"abc", 0o755);
        let program = open(&path).unwrap();
        assert_eq!(program.sha256(), ABC);
        assert_eq!(program.size(), 3);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(program.identity(), (meta.dev(), meta.ino()));
        // The descriptor is the file that was hashed.
        let held = std::fs::metadata(format!(
            "/dev/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&program.fd())
        ))
        .unwrap();
        assert_eq!(held.ino(), meta.ino());
        assert!(format!("{program:?}").contains("Program"));
    }

    #[test]
    fn a_program_larger_than_one_chunk_is_hashed_whole() {
        // Every chunk, and the empty read that ends them, contribute.
        let dir = scratch("big");
        let body = vec![b'x'; CHUNK * 2 + 17];
        let path = file(&dir, "big", &body, 0o755);
        let program = open(&path).unwrap();
        assert_eq!(program.sha256(), format!("{:x}", Sha256::digest(&body)));
        assert_eq!(program.size(), u64::try_from(body.len()).unwrap());
        // A program of exactly one chunk too: the read that returns zero is a
        // separate call from the one that filled the buffer.
        let exact = file(&dir, "exact", &vec![b'y'; CHUNK], 0o755);
        assert_eq!(
            open(&exact).unwrap().sha256(),
            format!("{:x}", Sha256::digest(vec![b'y'; CHUNK]))
        );
    }

    #[test]
    fn a_script_is_refused_with_that_reason_and_never_hashed() {
        // The first two bytes decide it, whatever follows and whatever the
        // interpreter is.
        let dir = scratch("script");
        for body in [&b"#!/bin/sh\nid\n"[..], b"#!", b"#!/usr/bin/env python3\n"] {
            let path = file(&dir, "script", body, 0o755);
            let err = open(&path).unwrap_err();
            assert_eq!(kind(&err), "Script", "{err}");
            assert!(err.to_string().contains("#!"), "{err}");
        }
        // Too short to be one: an empty file and a lone `#` are hashed, not
        // refused as scripts.
        assert!(open(&file(&dir, "empty", b"", 0o755)).is_ok());
        assert!(open(&file(&dir, "hash", b"#", 0o755)).is_ok());
        // `#` and `!` apart are not a shebang.
        let path = file(&dir, "not-script", b"# !/bin/sh\n", 0o755);
        assert!(open(&path).is_ok());
        // Only at the very start: a `#!` later in the file is data.
        let path = file(&dir, "later", b"x#!/bin/sh", 0o755);
        assert!(open(&path).is_ok());
    }

    #[test]
    fn a_file_with_no_execute_bit_is_refused() {
        let dir = scratch("noexec");
        let path = file(&dir, "data", b"abc", 0o644);
        assert_eq!(kind(&open(&path).unwrap_err()), "NotExecutable");
    }

    #[test]
    fn a_directory_or_a_device_is_not_a_program() {
        let dir = scratch("kind");
        std::fs::create_dir(dir.join("sub")).unwrap();
        std::fs::set_permissions(dir.join("sub"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(kind(&open(&dir.join("sub")).unwrap_err()), "NotRegularFile");
    }

    #[test]
    fn a_program_anyone_else_can_write_is_refused() {
        for mode in [0o775, 0o757, 0o777] {
            let dir = scratch(&format!("writable-{mode:o}"));
            let path = file(&dir, "tool", b"abc", mode);
            let err = open(&path).unwrap_err();
            assert!(
                err == ProgramError::Writable {
                    at: path.display().to_string(),
                    mode
                },
                "{mode:o}: {err}"
            );
            assert!(err.to_string().contains("writable by group or world"));
        }
    }

    #[test]
    fn a_program_someone_else_owns_is_refused() {
        let dir = scratch("owner");
        let path = file(&dir, "tool", b"abc", 0o755);
        let handle = std::fs::File::open(&path).unwrap();
        let me = owner_of(&dir);
        let err = Program::from_fd(OwnedFd::from(handle), &path, me.wrapping_add(1)).unwrap_err();
        assert_eq!(
            err,
            ProgramError::NotRootOwned {
                at: path.display().to_string(),
                uid: me
            }
        );
        assert!(err.to_string().contains("not root"), "{err}");
    }

    #[test]
    fn a_symlinked_program_is_refused_by_the_walk() {
        // Merged-/usr Linux has /bin -> usr/bin; macOS has /tmp -> private/tmp.
        // A program reached through a link is not the file that was checked.
        let through_link = ["/bin/sh", "/tmp", "/etc/hosts"]
            .into_iter()
            .find(|candidate| {
                crate::trust::chain_to(Path::new(candidate))
                    .unwrap()
                    .iter()
                    .any(|c| std::fs::symlink_metadata(c).is_ok_and(|m| m.is_symlink()))
            })
            .expect("this host has no symlink on any candidate path");
        let err =
            HostPrograms::open_with(Path::new(through_link), TRUSTED_UID, &FakeMounts::ext4())
                .unwrap_err();
        assert_eq!(kind(&err), "Untrusted", "{through_link}: {err}");
    }

    #[test]
    fn a_root_owned_program_is_opened_hashed_and_judged_through_the_walk() {
        let program =
            HostPrograms::open_with(Path::new("/usr/bin/true"), TRUSTED_UID, &FakeMounts::ext4())
                .unwrap();
        assert_eq!(program.sha256().len(), 64);
        assert!(program.size() > 0);
        let meta = std::fs::metadata("/usr/bin/true").unwrap();
        assert_eq!(program.identity(), (meta.dev(), meta.ino()));
    }

    #[test]
    fn a_descriptor_that_cannot_be_inspected_or_read_is_a_refusal() {
        // A socket: not a regular file.
        let (stream, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        let err = Program::from_fd(OwnedFd::from(stream), Path::new("/x"), 0).unwrap_err();
        assert_eq!(kind(&err), "NotRegularFile", "{err}");

        // A directory handle fails `pread` with EISDIR once the file checks
        // pass; reached through the digest directly.
        let dir = scratch("eisdir");
        let handle = OwnedFd::from(std::fs::File::open(&dir).unwrap());
        let err = digest(handle.as_fd(), "dir").unwrap_err();
        assert_eq!(kind(&err), "Unreadable", "{err}");
        assert!(err.to_string().contains("pread"), "{err}");
    }

    #[test]
    fn a_read_that_fails_after_the_first_bytes_is_a_refusal_not_a_short_hash() {
        // A disk that answers the header and then fails: hashing what was read
        // so far would name a file that was never whole.
        // Zero bytes at offset 0 is an empty file: hashed, with no second read.
        assert_eq!(
            digest_with(&|_, _| Ok(0), "p").unwrap(),
            format!("{:x}", Sha256::digest(b""))
        );
        let after_header = |buffer: &mut [u8], offset: u64| {
            if buffer.len() == 2 {
                Ok(0)
            } else {
                Err(ProgramError::Unreadable {
                    at: "p".to_owned(),
                    reason: format!("I/O error at {offset}"),
                })
            }
        };
        let err = digest_with(&after_header, "p").unwrap_err();
        assert!(err.to_string().contains("I/O error"), "{err}");
    }

    #[test]
    fn a_fake_serves_a_real_file_and_records_what_was_asked_for() {
        let dir = scratch("fake");
        let path = file(&dir, "tool", b"abc", 0o755);
        let fake = FakePrograms::serving(&path, owner_of(&dir));
        let program = fake.open(Path::new("/usr/bin/systemctl")).unwrap();
        assert_eq!(program.sha256(), ABC);
        assert_eq!(fake.opened(), vec![PathBuf::from("/usr/bin/systemctl")]);

        let missing = FakePrograms::serving(dir.join("missing"), 0);
        assert_eq!(
            kind(&missing.open(Path::new("/x")).unwrap_err()),
            "Unreadable"
        );

        let refusing = FakePrograms::refusing(ProgramError::Script { at: "/s".into() });
        assert_eq!(
            refusing.open(Path::new("/x")).unwrap_err(),
            ProgramError::Script { at: "/s".into() }
        );
        assert!(format!("{refusing:?}").contains("FakePrograms"));
    }

    #[test]
    fn the_real_walk_refuses_what_is_not_root_s_and_off_linux_everything() {
        let dir = scratch("host");
        let path = file(&dir, "tool", b"abc", 0o755);
        let err = HostPrograms.open(&path).unwrap_err();
        assert_eq!(kind(&err), "Untrusted", "{err}");
        assert!(format!("{HostPrograms:?}").contains("HostPrograms"));
    }

    #[test]
    fn an_unreadable_error_names_the_program_and_the_cause() {
        let err =
            unreadable::<()>("/usr/bin/x", Err(crate::SysError::unsupported("pread"))).unwrap_err();
        assert!(err.to_string().contains("/usr/bin/x"), "{err}");
        assert!(err.to_string().contains("not supported"), "{err}");
        assert_eq!(unreadable("/x", Ok::<_, crate::SysError>(3)).unwrap(), 3);
    }
}
