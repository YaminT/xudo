//! The optional environment file of an enrolled service, behind a seam.
//!
//! systemd hands `EnvironmentFile=-/etc/xudo/agents/<label>.env` to every
//! `Exec*` line of the unit, the root `ExecStartPre=+` helper included, and it
//! checks neither owner nor mode and follows symlinks. The helper therefore
//! looks at the file itself first: the facts below are read with `lstat`.

use std::path::Path;

use crate::SysError;
use crate::trust::{Kind, PathFacts};

/// Where the per-agent environment files live.
pub const AGENT_ENV_DIR: &str = "/etc/xudo/agents";

/// What is at `<dir>/<label>.env`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvFileProbe {
    /// Nothing there (the usual case: the file is optional).
    Absent,
    /// Something is there: the entry itself, not followed, and its directory.
    Present {
        /// The entry, `lstat`ed.
        file: PathFacts,
        /// The directory holding it, `lstat`ed.
        dir: PathFacts,
    },
}

/// Looks at an agent's environment file.
pub trait EnvFiles {
    /// The state of `<label>.env`.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry or its directory cannot be inspected for a
    /// reason other than the entry not existing.
    fn probe(&self, label: &str) -> Result<EnvFileProbe, SysError>;
}

/// The real directory, or one a test points at.
#[derive(Clone, Copy, Debug)]
pub struct HostEnvFiles<'a> {
    dir: &'a Path,
}

impl HostEnvFiles<'static> {
    /// `/etc/xudo/agents`.
    #[must_use]
    pub fn system() -> Self {
        Self::at(Path::new(AGENT_ENV_DIR))
    }
}

impl<'a> HostEnvFiles<'a> {
    /// A directory of environment files.
    #[must_use]
    pub fn at(dir: &'a Path) -> Self {
        Self { dir }
    }
}

fn lstat(path: &Path) -> Result<Option<PathFacts>, SysError> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(SysError::read(
                path.display().to_string(),
                error.to_string(),
            ));
        }
    };
    let kind = meta.file_type();
    Ok(Some(PathFacts {
        uid: meta.uid(),
        mode: meta.mode() & 0o7777,
        kind: if kind.is_symlink() {
            Kind::Symlink
        } else if kind.is_dir() {
            Kind::Directory
        } else if kind.is_file() {
            Kind::File
        } else {
            Kind::Other
        },
    }))
}

impl EnvFiles for HostEnvFiles<'_> {
    fn probe(&self, label: &str) -> Result<EnvFileProbe, SysError> {
        let Some(file) = lstat(&self.dir.join(format!("{label}.env")))? else {
            return Ok(EnvFileProbe::Absent);
        };
        // A directory that vanished or cannot be inspected is read as the
        // entry's own facts: not a directory, so the caller refuses.
        let dir = lstat(self.dir).ok().flatten().unwrap_or(file);
        Ok(EnvFileProbe::Present { file, dir })
    }
}

/// A scripted directory, for tests.
#[cfg(any(test, feature = "fake"))]
#[derive(Clone, Debug)]
pub struct FakeEnvFiles(pub Result<EnvFileProbe, SysError>);

#[cfg(any(test, feature = "fake"))]
impl EnvFiles for FakeEnvFiles {
    fn probe(&self, _: &str) -> Result<EnvFileProbe, SysError> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::symlink;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("xudo-envfile-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The entry's facts and its directory's; `Absent` reads as a default so no
    /// test needs a branch that only a failure would take.
    fn facts(probe: EnvFileProbe) -> (PathFacts, PathFacts) {
        let none = PathFacts {
            uid: u32::MAX,
            mode: 0,
            kind: Kind::Other,
        };
        match probe {
            EnvFileProbe::Present { file, dir } => (file, dir),
            EnvFileProbe::Absent => (none, none),
        }
    }

    #[test]
    fn an_absent_file_is_absent_even_without_a_directory() {
        assert_eq!(facts(EnvFileProbe::Absent).0.uid, u32::MAX);
        let dir = scratch("absent");
        assert_eq!(
            HostEnvFiles::at(&dir).probe("t").unwrap(),
            EnvFileProbe::Absent
        );
        let missing = dir.join("nope");
        assert_eq!(
            HostEnvFiles::at(&missing).probe("t").unwrap(),
            EnvFileProbe::Absent
        );
        assert_eq!(
            HostEnvFiles::system().probe("no-such-label-x").unwrap(),
            EnvFileProbe::Absent
        );
    }

    #[test]
    fn a_symlink_is_reported_as_one_and_not_followed() {
        let dir = scratch("link");
        std::fs::write(dir.join("real"), "A=1\n").unwrap();
        symlink(dir.join("real"), dir.join("t.env")).unwrap();
        let (file, held) = facts(HostEnvFiles::at(&dir).probe("t").unwrap());
        assert_eq!(file.kind, Kind::Symlink);
        assert_eq!(held.kind, Kind::Directory);
    }

    #[test]
    fn a_regular_file_reports_its_owner_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("file");
        let path = dir.join("t.env");
        std::fs::write(&path, "A=1\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let (file, _) = facts(HostEnvFiles::at(&dir).probe("t").unwrap());
        assert_eq!((file.kind, file.mode), (Kind::File, 0o640));
        assert_eq!(file.uid, rustix::process::getuid().as_raw());
        // A socket is neither a file nor a link.
        let _socket = std::os::unix::net::UnixListener::bind(dir.join("f.env")).unwrap();
        let (file, _) = facts(HostEnvFiles::at(&dir).probe("f").unwrap());
        assert_eq!(file.kind, Kind::Other);
    }

    #[test]
    fn an_uninspectable_entry_is_an_error() {
        // A file where the directory should be: the entry lookup gets ENOTDIR.
        let dir = scratch("notdir");
        let not_a_dir = dir.join("plain");
        std::fs::write(&not_a_dir, "x").unwrap();
        assert!(HostEnvFiles::at(&not_a_dir).probe("t").is_err());
    }

    #[test]
    fn a_scripted_directory_answers_what_it_was_given() {
        assert_eq!(
            FakeEnvFiles(Ok(EnvFileProbe::Absent)).probe("t").unwrap(),
            EnvFileProbe::Absent
        );
        assert!(
            FakeEnvFiles(Err(SysError::read("x", "y")))
                .probe("t")
                .is_err()
        );
    }
}
