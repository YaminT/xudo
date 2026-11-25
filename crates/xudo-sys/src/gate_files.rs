//! Which of the gate's two files this process is.
//!
//! The gate's mode, whether a password was typed for it, must not be a thing
//! the caller can choose. `argv[0]` is the caller's: `sudo` passes it through
//! from the command line, and a symlink or a hardlink in a directory the
//! caller owns can carry any name. What the caller cannot choose is which
//! inode the kernel is executing. So the mode comes from the executed file:
//! `/proc/self/exe` is compared by `(st_dev, st_ino)` with the two gate files,
//! each opened through the trust walk (every component root's, no link, on a
//! mount root made), and the file that matches says what this process is.
//!
//! Each file must have exactly one name (`st_nlink == 1`). A second name for
//! either is a name somebody added, and with two names for one inode the
//! executed file could no longer say which mode it is. A package therefore
//! ships two files, never a hardlink pair.
//!
//! The `-nopass` file may be absent, as it is on a host installed before it
//! shipped; the `-auth` file may not, because a gate that cannot find the one
//! file that always ships cannot say what it is. Anything else, including an
//! executable that is neither file, is an error: the gate refuses.

use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

use rustix::fs::fstat;

use crate::trust::{TrustError, open_trusted};

/// The directory both gate files live in.
pub const GATE_DIR: &str = "/usr/libexec/xudo";
/// The gate sudo asks a password for.
pub const AUTH_FILE: &str = "xudo-gate-auth";
/// The gate a harness grant reaches without a password.
pub const NOPASS_FILE: &str = "xudo-gate-nopass";

/// What this process is, as its executed file says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateMode {
    /// `xudo-gate-auth`: `sudo` asked a human for a password to start it.
    Auth,
    /// `xudo-gate-nopass`: no password was asked for.
    Nopass,
}

/// Which inode a file is, and how many names it has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
    /// `st_nlink`.
    pub nlink: u64,
}

impl FileId {
    /// The facts in a `stat` result. `st_dev` is `i32` and `st_nlink` `u16` on
    /// macOS, so the conversions are real on one platform and an identity on
    /// the other.
    #[allow(clippy::useless_conversion)]
    fn of(stat: &rustix::fs::Stat) -> Self {
        Self {
            dev: u64::try_from(stat.st_dev).unwrap_or(0),
            ino: stat.st_ino,
            nlink: u64::from(stat.st_nlink),
        }
    }

    fn same_file(self, other: Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }
}

/// Why the executed file does not say which gate this is.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GateFilesError {
    /// A gate file failed the trust walk or does not exist.
    #[error(transparent)]
    Untrusted(#[from] TrustError),
    /// A file could not be inspected.
    #[error("{at} cannot be inspected: {reason}")]
    Unreadable {
        /// The file.
        at: String,
        /// Why.
        reason: String,
    },
    /// A gate file has more than one name.
    #[error("{at} has {nlink} names: the executed file could not say which gate it is")]
    HardLinked {
        /// The file.
        at: String,
        /// Its link count.
        nlink: u64,
    },
    /// The executed file is neither gate file.
    #[error("the executed file is neither {AUTH_FILE} nor {NOPASS_FILE} under {GATE_DIR}")]
    NotAGateFile,
}

/// The executed file, asked which gate it is.
pub trait GateFiles {
    /// Which mode the running executable is.
    ///
    /// # Errors
    ///
    /// [`GateFilesError`]; every one means the gate refuses.
    fn executing(&self) -> Result<GateMode, GateFilesError>;
}

/// The real files: `/proc/self/exe` against `/usr/libexec/xudo`.
#[derive(Clone, Copy, Debug)]
pub struct HostGateFiles;

impl GateFiles for HostGateFiles {
    fn executing(&self) -> Result<GateMode, GateFilesError> {
        executing_with(
            Path::new(GATE_DIR),
            Path::new("/proc/self/exe"),
            &|path| open_trusted(path),
            &|fd| fstat(fd),
        )
    }
}

/// [`GateFiles::executing`], with the directory, the executed file, the way to
/// open the gate files and the way to `fstat` them as parameters so a test can
/// point it at files it made and make an `fstat` fail.
pub(crate) fn executing_with(
    dir: &Path,
    exe: &Path,
    open: &dyn Fn(&Path) -> Result<std::os::fd::OwnedFd, TrustError>,
    stat: &dyn Fn(BorrowedFd<'_>) -> rustix::io::Result<rustix::fs::Stat>,
) -> Result<GateMode, GateFilesError> {
    let own = std::fs::File::open(exe).map_err(|error| GateFilesError::Unreadable {
        at: exe.display().to_string(),
        reason: error.to_string(),
    })?;
    let exe_id = identify(stat(own.as_fd()), exe)?;
    let auth_path = dir.join(AUTH_FILE);
    let auth = open(&auth_path)?;
    let auth_id = identify(stat(auth.as_fd()), &auth_path)?;
    let nopass_path = dir.join(NOPASS_FILE);
    let nopass_id = match open(&nopass_path) {
        Ok(fd) => Some(identify(stat(fd.as_fd()), &nopass_path)?),
        Err(TrustError::NotFound { .. }) => None,
        Err(error) => return Err(error.into()),
    };
    judge(
        exe_id,
        (&auth_path, auth_id),
        nopass_id.map(|id| (nopass_path.as_path(), id)),
    )
}

/// What `fstat` said, or why it could not.
fn identify(
    result: rustix::io::Result<rustix::fs::Stat>,
    at: &Path,
) -> Result<FileId, GateFilesError> {
    match result {
        Ok(stat) => Ok(FileId::of(&stat)),
        Err(error) => Err(GateFilesError::Unreadable {
            at: at.display().to_string(),
            reason: error.to_string(),
        }),
    }
}

/// The decision, on the facts alone: each gate file has one name, and the
/// executed file is one of them.
pub(crate) fn judge(
    exe: FileId,
    auth: (&Path, FileId),
    nopass: Option<(&Path, FileId)>,
) -> Result<GateMode, GateFilesError> {
    for (path, id) in std::iter::once(auth).chain(nopass) {
        if id.nlink != 1 {
            return Err(GateFilesError::HardLinked {
                at: path.display().to_string(),
                nlink: id.nlink,
            });
        }
    }
    if exe.same_file(auth.1) {
        Ok(GateMode::Auth)
    } else if nopass.is_some_and(|(_, id)| exe.same_file(id)) {
        Ok(GateMode::Nopass)
    } else {
        Err(GateFilesError::NotAGateFile)
    }
}

/// A [`GateFiles`] a test scripts.
#[cfg(any(test, feature = "fake"))]
#[derive(Clone, Debug)]
pub struct FakeGateFiles {
    /// What `executing` answers.
    pub answer: Result<GateMode, GateFilesError>,
}

#[cfg(any(test, feature = "fake"))]
impl FakeGateFiles {
    /// A process that is `mode`.
    #[must_use]
    pub fn running_as(mode: GateMode) -> Self {
        Self { answer: Ok(mode) }
    }

    /// A process whose executed file cannot say which gate it is.
    #[must_use]
    pub fn refusing(error: GateFilesError) -> Self {
        Self { answer: Err(error) }
    }
}

#[cfg(any(test, feature = "fake"))]
impl GateFiles for FakeGateFiles {
    fn executing(&self) -> Result<GateMode, GateFilesError> {
        self.answer.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::fd::OwnedFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    use super::*;

    /// The variant's name, so a test can say which refusal it saw without a
    /// `matches!` whose other arm no test reaches.
    fn kind(error: &GateFilesError) -> String {
        format!("{error:?}")
            .split([' ', '(', '{'])
            .next()
            .unwrap_or_default()
            .to_owned()
    }

    fn id(ino: u64, nlink: u64) -> FileId {
        FileId { dev: 1, ino, nlink }
    }

    fn auth() -> (&'static Path, FileId) {
        (Path::new("/g/auth"), id(10, 1))
    }

    fn nopass() -> (&'static Path, FileId) {
        (Path::new("/g/nopass"), id(20, 1))
    }

    #[test]
    fn the_executed_inode_names_the_mode() {
        assert_eq!(judge(id(10, 1), auth(), Some(nopass())), Ok(GateMode::Auth));
        assert_eq!(
            judge(id(20, 1), auth(), Some(nopass())),
            Ok(GateMode::Nopass)
        );
        assert_eq!(judge(id(10, 1), auth(), None), Ok(GateMode::Auth));
    }

    #[test]
    fn a_copy_under_another_name_is_not_a_gate() {
        // The caller's hardlink or copy elsewhere: neither inode.
        assert_eq!(
            judge(id(99, 1), auth(), Some(nopass())),
            Err(GateFilesError::NotAGateFile)
        );
        // The same inode on another device is another file.
        let other_device = FileId {
            dev: 2,
            ino: 10,
            nlink: 1,
        };
        assert_eq!(
            judge(other_device, auth(), Some(nopass())),
            Err(GateFilesError::NotAGateFile)
        );
        // With no nopass file installed, nothing can be the nopass gate.
        assert_eq!(
            judge(id(20, 1), auth(), None),
            Err(GateFilesError::NotAGateFile)
        );
    }

    #[test]
    fn a_hardlinked_gate_file_is_refused_in_either_mode() {
        let linked = |path, ino| (Path::new(path), id(ino, 2));
        for (exe, a, n) in [
            (id(10, 2), linked("/g/auth", 10), Some(nopass())),
            (id(20, 2), auth(), Some(linked("/g/nopass", 20))),
            // Even the other file being linked refuses: two names for one
            // inode make the mode ambiguous.
            (id(10, 1), auth(), Some(linked("/g/nopass", 20))),
        ] {
            assert_eq!(kind(&judge(exe, a, n).unwrap_err()), "HardLinked");
            assert!(
                judge(exe, a, n)
                    .unwrap_err()
                    .to_string()
                    .contains("2 names")
            );
        }
    }

    /// A directory under the workspace `target/`, never `/tmp`.
    fn scratch(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("gf-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn real_stat(fd: BorrowedFd<'_>) -> rustix::io::Result<rustix::fs::Stat> {
        fstat(fd)
    }

    #[test]
    fn a_failed_fstat_of_any_of_the_three_files_is_refused() {
        let dir = scratch("fstat");
        std::fs::write(dir.join(AUTH_FILE), b"a").unwrap();
        std::fs::write(dir.join(NOPASS_FILE), b"n").unwrap();
        // The executed file, then the auth file, then the nopass file.
        for failing in 0..3 {
            let calls = std::cell::Cell::new(0_usize);
            let stat = |fd: BorrowedFd<'_>| {
                let this = calls.get();
                calls.set(this + 1);
                if this == failing {
                    Err(rustix::io::Errno::IO)
                } else {
                    fstat(fd)
                }
            };
            let result = executing_with(&dir, &dir.join(AUTH_FILE), &plain_open, &stat);
            assert_eq!(kind(&result.unwrap_err()), "Unreadable", "{failing}");
        }
    }

    fn plain_open(path: &Path) -> Result<OwnedFd, TrustError> {
        match std::fs::File::open(path) {
            Ok(file) => Ok(OwnedFd::from(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(TrustError::NotFound {
                    at: path.display().to_string(),
                })
            }
            Err(error) => Err(TrustError::Unreadable {
                at: path.display().to_string(),
                reason: error.to_string(),
            }),
        }
    }

    #[test]
    fn the_mode_is_read_from_the_files_on_disk() {
        let dir = scratch("disk");
        std::fs::write(dir.join(AUTH_FILE), b"a").unwrap();
        std::fs::write(dir.join(NOPASS_FILE), b"n").unwrap();
        let run = |exe: &str| executing_with(&dir, &dir.join(exe), &plain_open, &real_stat);
        assert_eq!(run(AUTH_FILE), Ok(GateMode::Auth));
        assert_eq!(run(NOPASS_FILE), Ok(GateMode::Nopass));
        // A symlink to the nopass file is the nopass file: the kernel
        // executes the inode, whatever the name that reached it.
        std::os::unix::fs::symlink(dir.join(NOPASS_FILE), dir.join("sh")).unwrap();
        assert_eq!(run("sh"), Ok(GateMode::Nopass));
        // A copy is another inode.
        std::fs::write(dir.join("copy"), b"n").unwrap();
        assert_eq!(run("copy"), Err(GateFilesError::NotAGateFile));
        // A hardlink to either gate file gives that file two names.
        std::fs::hard_link(dir.join(AUTH_FILE), dir.join("link")).unwrap();
        assert_eq!(kind(&run(AUTH_FILE).unwrap_err()), "HardLinked");
        assert_eq!(std::fs::metadata(dir.join(AUTH_FILE)).unwrap().nlink(), 2);
    }

    #[test]
    fn an_absent_nopass_file_is_not_an_error_and_an_absent_auth_file_is() {
        let dir = scratch("absent");
        std::fs::write(dir.join(AUTH_FILE), b"a").unwrap();
        assert_eq!(
            executing_with(&dir, &dir.join(AUTH_FILE), &plain_open, &real_stat),
            Ok(GateMode::Auth)
        );
        let missing =
            executing_with(&dir, &dir.join("nowhere"), &plain_open, &real_stat).unwrap_err();
        assert_eq!(kind(&missing), "Unreadable");
        let no_auth = scratch("no-auth");
        std::fs::write(no_auth.join(NOPASS_FILE), b"n").unwrap();
        assert_eq!(
            executing_with(
                &no_auth,
                &no_auth.join(NOPASS_FILE),
                &plain_open,
                &real_stat
            ),
            Err(GateFilesError::Untrusted(TrustError::NotFound {
                at: no_auth.join(AUTH_FILE).display().to_string()
            }))
        );
    }

    #[test]
    fn a_file_that_cannot_be_opened_is_unreadable_not_absent() {
        let dir = scratch("enotdir");
        std::fs::write(dir.join("plain"), b"x").unwrap();
        // A path below a regular file is ENOTDIR: not "does not exist".
        let error = plain_open(&dir.join("plain").join("below")).unwrap_err();
        assert!(error.to_string().contains("cannot be inspected"), "{error}");
        assert_ne!(
            error,
            TrustError::NotFound {
                at: dir.join("plain").join("below").display().to_string()
            }
        );
    }

    #[test]
    fn an_untrusted_nopass_file_is_refused_not_ignored() {
        let dir = scratch("untrusted");
        std::fs::write(dir.join(AUTH_FILE), b"a").unwrap();
        let refuse = |path: &Path| {
            if path.ends_with(NOPASS_FILE) {
                Err(TrustError::Symlink {
                    at: path.display().to_string(),
                })
            } else {
                plain_open(path)
            }
        };
        assert_eq!(
            executing_with(&dir, &dir.join(AUTH_FILE), &refuse, &real_stat),
            Err(GateFilesError::Untrusted(TrustError::Symlink {
                at: dir.join(NOPASS_FILE).display().to_string()
            }))
        );
    }

    #[test]
    fn a_failed_fstat_is_unreadable() {
        let error = identify(Err(rustix::io::Errno::BADF), Path::new("/g/auth")).unwrap_err();
        assert_eq!(kind(&error), "Unreadable");
        assert!(error.to_string().contains("/g/auth"));
    }

    #[test]
    fn the_host_refuses_a_machine_with_no_gate_installed() {
        // No test host has `/usr/libexec/xudo/xudo-gate-auth` that is this
        // test binary, so the real seam can only refuse.
        assert!(HostGateFiles.executing().is_err());
    }

    #[test]
    fn the_fake_says_what_it_was_given() {
        assert_eq!(
            FakeGateFiles::running_as(GateMode::Nopass).executing(),
            Ok(GateMode::Nopass)
        );
        assert_eq!(
            FakeGateFiles::refusing(GateFilesError::NotAGateFile).executing(),
            Err(GateFilesError::NotAGateFile)
        );
    }
}
