//! The spool: one directory of one-use requests, read and consumed safely.
//!
//! `/run/aido/req` is where the broker leaves what it approved and where the
//! gate finds it. The directory is root's alone, but the gate does not rest on
//! that: it opens the directory through the trust walk, holds the descriptor,
//! and does everything else relative to it.
//!
//! * [`Spool::names`] lists the entries, bounded: a directory with more names
//!   than [`MAX_ENTRY_NAMES`] is refused rather than walked.
//! * [`Spool::read`] opens one entry on **its own descriptor** (`O_NOFOLLOW`,
//!   so a link is never followed), checks that descriptor is a regular file
//!   root owns, that nobody else can write, that it has one name, and that it
//!   is small, and reads it through that descriptor only. Nothing is judged by
//!   path and read by path.
//! * [`Spool::consume`] unlinks the entry through the directory descriptor.
//!   Unlinking is what makes a grant one-use, so **any** failure is an error:
//!   including `ENOENT`, which means somebody else consumed the entry first
//!   and the caller must not run it a second time.
//!
//! A name is checked before it reaches the kernel: an entry name is a nonce, a
//! single path component, so one containing `/`, a NUL, or that is empty, `.`
//! or `..` is refused here, whatever the caller already checked.
//!
//! Off Linux there is no mount table, so [`DirSpool::open`] refuses
//! everything, as the trust walk it uses does.

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{AtFlags, Dir, Mode, OFlags, fstat, openat, unlinkat};

use crate::error::{SysError, lift};
use crate::mounts::{HostMounts, MountView};
use crate::trust::{FORBIDDEN_WRITE_BITS, Kind, TRUSTED_UID, facts_of, open_trusted_with};

/// The most bytes a spool entry may hold. A request is a few hundred bytes;
/// the bound is a ceiling on what the gate will read on the strength of a name.
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024;

/// The most names the gate will list. The directory is root's, so more than
/// this is a broker that is not reaping, or something wrong; either way the
/// gate does not walk it.
pub const MAX_ENTRY_NAMES: usize = 4096;

/// A directory of requests.
pub trait Spool {
    /// The entry names in the directory, as bytes.
    ///
    /// # Errors
    ///
    /// [`SysError`] when the directory cannot be listed, or holds more than
    /// [`MAX_ENTRY_NAMES`] entries.
    fn names(&self) -> Result<Vec<Vec<u8>>, SysError>;

    /// The contents of one entry, read through a descriptor of its own.
    ///
    /// # Errors
    ///
    /// [`SysError`] for a name that is not one path component, an entry that is
    /// not a regular, root-owned, singly linked file nobody else can write, one
    /// longer than [`MAX_ENTRY_BYTES`], or any failure to open or read it.
    fn read(&self, name: &str) -> Result<Vec<u8>, SysError>;

    /// Removes one entry, so that it cannot be used again.
    ///
    /// # Errors
    ///
    /// [`SysError`] for a bad name or **any** failure to unlink, `ENOENT`
    /// included: an entry that was already gone was consumed by someone else.
    fn consume(&self, name: &str) -> Result<(), SysError>;
}

/// The spool on a real directory, held by a descriptor the trust walk opened.
#[derive(Debug)]
pub struct DirSpool {
    dir: OwnedFd,
    owner: u32,
}

impl DirSpool {
    /// Opens the spool at `path` through the trust walk: every component root's
    /// and on a mount root made, no link anywhere.
    ///
    /// # Errors
    ///
    /// [`SysError`] when any component fails the walk, or `path` is not a
    /// directory.
    pub fn open(path: &Path) -> Result<Self, SysError> {
        Self::open_with(path, TRUSTED_UID, &HostMounts::proc())
    }

    /// [`Self::open`], with the owner and the mount table as parameters so a
    /// test can point it at a directory no test host has.
    pub(crate) fn open_with(
        path: &Path,
        owner: u32,
        view: &dyn MountView,
    ) -> Result<Self, SysError> {
        match open_trusted_with(path, owner, view) {
            Ok(dir) => Self::from_fd(dir, owner),
            Err(error) => Err(SysError::read(
                path.display().to_string(),
                error.to_string(),
            )),
        }
    }

    /// Holds `dir`, which must be a directory, and expects entries owned by
    /// `owner`.
    pub(crate) fn from_fd(dir: OwnedFd, owner: u32) -> Result<Self, SysError> {
        lift("fstat", fstat(&dir)).and_then(|stat| match facts_of(&stat).kind {
            Kind::Directory => Ok(Self { dir, owner }),
            _ => Err(SysError::read("spool", "not a directory")),
        })
    }
}

/// Refuses a name that is not exactly one path component.
fn check_name(name: &str) -> Result<(), SysError> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.bytes().any(|byte| byte == b'/' || byte == 0);
    if bad {
        return Err(SysError::read(
            "spool",
            "an entry name must be a single path component",
        ));
    }
    Ok(())
}

impl Spool for DirSpool {
    fn names(&self) -> Result<Vec<Vec<u8>>, SysError> {
        lift("fdopendir", Dir::read_from(&self.dir)).and_then(collect_names)
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, SysError> {
        check_name(name)?;
        let fd = lift(
            "openat",
            openat(
                &self.dir,
                name,
                OFlags::RDONLY
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC
                    | OFlags::NONBLOCK
                    | OFlags::NOCTTY,
                Mode::empty(),
            ),
        )?;
        let file = std::fs::File::from(fd);
        io_lift(name, file.metadata())
            .and_then(|meta| judge(name, &meta, self.owner))
            .and_then(|()| read_entry(file, name))
    }

    fn consume(&self, name: &str) -> Result<(), SysError> {
        check_name(name)?;
        lift(
            "unlinkat",
            unlinkat(self.dir.as_fd(), name, AtFlags::empty()),
        )
    }
}

/// Lists a directory's entries, bounded, without `.` and `..`.
///
/// Stops asking the kernel after one name more than the bound (and the two
/// dot entries every directory has), so a directory the broker never reaps is
/// refused without being read to the end.
fn collect_names(entries: Dir) -> Result<Vec<Vec<u8>>, SysError> {
    entries
        .take(MAX_ENTRY_NAMES.saturating_add(3))
        .map(|entry| {
            lift(
                "readdir",
                entry.map(|found| found.file_name().to_bytes().to_vec()),
            )
        })
        .filter(|name| !matches!(name, Ok(found) if found == b"." || found == b".."))
        .collect::<Result<Vec<_>, _>>()
        .and_then(within_bound)
}

/// Refuses a listing longer than [`MAX_ENTRY_NAMES`].
fn within_bound(names: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, SysError> {
    if names.len() > MAX_ENTRY_NAMES {
        return Err(SysError::read(
            "spool",
            format!("more than {MAX_ENTRY_NAMES} entries, so it is not listed"),
        ));
    }
    Ok(names)
}

/// Lifts an I/O failure on an entry into the crate's error.
fn io_lift<T>(name: &str, result: std::io::Result<T>) -> Result<T, SysError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(SysError::read(name, error.to_string())),
    }
}

/// Whether an open entry is what a request is: a regular file the spool's
/// owner owns, with one name, that nobody else can write, and small.
fn judge(name: &str, meta: &std::fs::Metadata, owner: u32) -> Result<(), SysError> {
    let refusal = if !meta.is_file() {
        Some("not a regular file")
    } else if meta.uid() != owner {
        Some("not owned by the spool's owner")
    } else if meta.mode() & FORBIDDEN_WRITE_BITS != 0 {
        Some("writable by group or world")
    } else if meta.nlink() != 1 {
        Some("has more than one name")
    } else if meta.len() > MAX_ENTRY_BYTES {
        Some("larger than a request can be")
    } else {
        None
    };
    match refusal {
        Some(reason) => Err(SysError::read(name, reason)),
        None => Ok(()),
    }
}

/// Reads at most [`MAX_ENTRY_BYTES`] from an entry that passed [`judge`], and
/// refuses one that grew past it.
fn read_entry(file: std::fs::File, name: &str) -> Result<Vec<u8>, SysError> {
    let mut bytes = Vec::new();
    io_lift(
        name,
        file.take(MAX_ENTRY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes),
    )
    .and_then(|_| {
        if u64::try_from(bytes.len()).is_ok_and(|len| len <= MAX_ENTRY_BYTES) {
            Ok(bytes)
        } else {
            Err(SysError::read(name, "larger than a request can be"))
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
    use std::path::PathBuf;

    use rustix::fs::{Mode, OFlags};

    use super::*;
    use crate::mounts::fake::FakeMounts;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// A fresh directory under the workspace `target/`, never `/tmp`.
    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("sp-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // 0700, as the real spool is.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn owner_of(dir: &Path) -> u32 {
        std::fs::metadata(dir).unwrap().uid()
    }

    /// The spool in a directory the test made, held by a descriptor opened
    /// directly: the walk down from `/` needs every ancestor to be the owner's,
    /// which the checkout's are not, and the walk has its own tests.
    fn spool(dir: &Path) -> DirSpool {
        let fd = rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        DirSpool::from_fd(fd, owner_of(dir)).unwrap()
    }

    fn entry(dir: &Path, name: &str, body: &[u8], mode: u32) {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn an_entry_is_listed_read_and_consumed_exactly_once() {
        let dir = scratch("once");
        entry(&dir, NONCE, b"{\"a\":1}", 0o600);
        let spool = spool(&dir);
        assert_eq!(spool.names().unwrap(), vec![NONCE.as_bytes().to_vec()]);
        assert_eq!(spool.read(NONCE).unwrap(), b"{\"a\":1}");
        spool.consume(NONCE).unwrap();
        // The second consumer finds nothing to consume, and that is a refusal:
        // it must not run what somebody else already ran.
        let again = spool.consume(NONCE).unwrap_err();
        assert_eq!(
            again.os_code(),
            Some(rustix::io::Errno::NOENT.raw_os_error())
        );
        assert!(spool.names().unwrap().is_empty());
        assert!(spool.read(NONCE).is_err());
        assert!(format!("{spool:?}").contains("DirSpool"));
    }

    #[test]
    fn a_name_that_is_not_one_path_component_never_reaches_the_kernel() {
        let dir = scratch("names");
        let spool = spool(&dir);
        for bad in ["", ".", "..", "a/b", "../x", "/etc/passwd", "a\0b"] {
            assert!(spool.read(bad).is_err(), "{bad:?}");
            assert!(spool.consume(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_entry_that_is_a_symlink_is_never_followed() {
        // A link to a file of the right shape, elsewhere: reading it would be
        // reading a file the spool never held.
        let dir = scratch("link");
        let target = scratch("link-target").join("real");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(NONCE)).unwrap();
        assert!(spool(&dir).read(NONCE).is_err());
    }

    #[test]
    fn an_entry_anyone_else_can_write_is_refused() {
        for mode in [0o620, 0o602, 0o666, 0o660] {
            let dir = scratch(&format!("mode-{mode:o}"));
            entry(&dir, NONCE, b"{}", mode);
            let err = spool(&dir).read(NONCE).unwrap_err();
            assert!(err.to_string().contains("writable"), "{mode:o}: {err}");
        }
    }

    #[test]
    fn an_entry_with_a_second_name_is_refused() {
        let dir = scratch("nlink");
        entry(&dir, NONCE, b"{}", 0o600);
        std::fs::hard_link(dir.join(NONCE), dir.join("other")).unwrap();
        let err = spool(&dir).read(NONCE).unwrap_err();
        assert!(err.to_string().contains("more than one name"), "{err}");
    }

    #[test]
    fn an_entry_owned_by_someone_else_is_refused() {
        let dir = scratch("owner");
        entry(&dir, NONCE, b"{}", 0o600);
        let me = owner_of(&dir);
        let stranger = DirSpool {
            dir: spool(&dir).dir,
            owner: me.wrapping_add(1),
        };
        let err = stranger.read(NONCE).unwrap_err();
        assert!(err.to_string().contains("not owned"), "{err}");
    }

    #[test]
    fn an_entry_that_is_not_a_regular_file_is_refused() {
        let dir = scratch("kind");
        std::fs::create_dir(dir.join(NONCE)).unwrap();
        let err = spool(&dir).read(NONCE).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    #[test]
    fn an_entry_larger_than_a_request_can_be_is_refused_before_it_is_read() {
        let dir = scratch("big");
        let body = vec![b'x'; usize::try_from(MAX_ENTRY_BYTES).unwrap() + 1];
        entry(&dir, NONCE, &body, 0o600);
        let err = spool(&dir).read(NONCE).unwrap_err();
        assert!(err.to_string().contains("larger"), "{err}");
        // At the limit it reads.
        let at_limit = vec![b'x'; usize::try_from(MAX_ENTRY_BYTES).unwrap()];
        entry(&dir, NONCE, &at_limit, 0o600);
        assert_eq!(spool(&dir).read(NONCE).unwrap().len(), at_limit.len());
    }

    #[test]
    fn an_entry_that_grew_after_it_was_judged_is_still_bounded() {
        // The judge saw a small file; by the time it is read it is larger.
        let dir = scratch("grew");
        entry(&dir, NONCE, &vec![b'x'; 100_000], 0o600);
        let file = std::fs::File::open(dir.join(NONCE)).unwrap();
        let err = read_entry(file, NONCE).unwrap_err();
        assert!(err.to_string().contains("larger"), "{err}");
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_a_refusal() {
        // A directory opened for reading judges as a non-file, so reach the
        // read failure through the reader directly: reading a directory fails.
        let dir = scratch("unreadable");
        let handle = std::fs::File::open(&dir).unwrap();
        let err = read_entry(handle, "dir").unwrap_err();
        assert!(err.to_string().contains("cannot read"), "{err}");
    }

    #[test]
    fn a_directory_with_too_many_names_is_not_listed() {
        let dir = scratch("many");
        for index in 0..=MAX_ENTRY_NAMES {
            std::fs::write(dir.join(format!("{index:05}")), b"").unwrap();
        }
        let err = spool(&dir).names().unwrap_err();
        assert!(err.to_string().contains("more than"), "{err}");
        // Exactly at the limit is listed.
        std::fs::remove_file(dir.join(format!("{MAX_ENTRY_NAMES:05}"))).unwrap();
        assert_eq!(spool(&dir).names().unwrap().len(), MAX_ENTRY_NAMES);
    }

    #[test]
    fn a_root_owned_directory_opens_as_a_spool_through_the_walk() {
        // `/usr/bin` is root's on every host this runs on, and the mount table
        // is a fake that accepts, so what is under test is the walk.
        let spool =
            DirSpool::open_with(Path::new("/usr/bin"), TRUSTED_UID, &FakeMounts::ext4()).unwrap();
        assert!(!spool.names().unwrap().is_empty());
    }

    #[test]
    fn a_file_where_the_spool_must_be_is_refused() {
        let err = DirSpool::open_with(Path::new("/usr/bin/true"), TRUSTED_UID, &FakeMounts::ext4())
            .unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn a_spool_that_fails_the_trust_walk_is_refused_with_its_path() {
        // A directory that is not root's, as one a user made would be.
        let err = DirSpool::open_with(
            Path::new("/usr/bin"),
            TRUSTED_UID.wrapping_add(1),
            &FakeMounts::ext4(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("/usr/bin"), "{err}");
        // And the real entry point: nothing here is a spool, and off Linux
        // there is no mount table to judge one by.
        assert!(DirSpool::open(Path::new("/definitely/not/a/spool")).is_err());
    }

    #[test]
    fn a_descriptor_that_is_not_a_directory_is_refused() {
        let (stream, _other) = std::os::unix::net::UnixStream::pair().unwrap();
        let err = DirSpool::from_fd(OwnedFd::from(stream), 0).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err}");
    }
}
