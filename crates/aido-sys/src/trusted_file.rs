//! One root-owned file that may be absent, read the way the ruleset is read.
//!
//! The settings file, `/etc/aido/config.toml`, is optional: until somebody
//! writes one, the documented defaults are the configuration. A privileged
//! reader still has to tell three cases apart that a path-based read blurs:
//! the file is **absent** (use the defaults), the file or a directory above it
//! is **not root's** (refuse), and the file is **root's** (read it through the
//! descriptor that was checked).
//!
//! Absence is decided inside the parent directory the walk already verified,
//! so it is root's decision: nobody else can create a file there. Presence is
//! then checked by the full walk again, ending on the file's own descriptor,
//! and the bytes are read through that descriptor and no other.

use std::io::Read as _;
use std::path::Path;

use rustix::fs::{AtFlags, statat};

use crate::mounts::{HostMounts, MountView};
use crate::trust::{TRUSTED_UID, TrustError, open_trusted_with};

/// Reads `path` if it exists, having verified it and every directory above it
/// on the descriptors they were opened through, or reports that it is absent.
///
/// # Errors
///
/// [`TrustError::NotAbsolute`] for a path that cannot be walked as written;
/// the first component the walk refuses; and [`TrustError::Unreadable`] if the
/// file cannot be read or is longer than `limit` bytes.
pub fn read_trusted_file(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, TrustError> {
    read_file_with(path, limit, &HostMounts::proc())
}

/// [`read_trusted_file`], with the mount table as a parameter.
fn read_file_with(
    path: &Path,
    limit: usize,
    view: &dyn MountView,
) -> Result<Option<Vec<u8>>, TrustError> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(TrustError::NotAbsolute {
            at: path.display().to_string(),
        });
    };
    let dir = open_trusted_with(parent, TRUSTED_UID, view)?;
    if let Err(rustix::io::Errno::NOENT) = statat(&dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        return Ok(None);
    }
    let file = open_trusted_with(path, TRUSTED_UID, view)?;
    let mut bytes = Vec::new();
    let ceiling = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let read = std::fs::File::from(file)
        .take(ceiling)
        .read_to_end(&mut bytes);
    contents(read, bytes, path, limit).map(Some)
}

/// Reads the outcome of a bounded read as the file's contents.
///
/// Split out so the failure arm is reachable from a test with a real error.
fn contents(
    read: std::io::Result<usize>,
    bytes: Vec<u8>,
    path: &Path,
    limit: usize,
) -> Result<Vec<u8>, TrustError> {
    match read {
        Ok(_) if bytes.len() > limit => Err(TrustError::Unreadable {
            at: path.display().to_string(),
            reason: format!("longer than {limit} bytes"),
        }),
        Ok(_) => Ok(bytes),
        Err(error) => Err(TrustError::Unreadable {
            at: path.display().to_string(),
            reason: error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::mounts::fake::FakeMounts;

    /// A root-owned regular file whose every ancestor is root's, on every
    /// platform this builds for.
    const TRUSTED_FILE: &str = "/usr/bin/true";

    #[test]
    fn a_root_owned_file_is_read_through_its_verified_descriptor() {
        let bytes = read_file_with(Path::new(TRUSTED_FILE), 1 << 24, &FakeMounts::ext4())
            .unwrap()
            .unwrap();
        assert_eq!(bytes, std::fs::read(TRUSTED_FILE).unwrap());
    }

    #[test]
    fn an_absent_file_in_a_trusted_directory_is_reported_absent() {
        assert_eq!(
            read_file_with(
                Path::new("/usr/bin/aido-surely-absent.toml"),
                64,
                &FakeMounts::ext4()
            ),
            Ok(None)
        );
    }

    #[test]
    fn a_file_in_a_directory_that_is_not_roots_is_refused_even_if_absent() {
        // Absence is only meaningful where nobody else could have created the
        // file: in a directory a user owns, "absent" proves nothing.
        let checkout = Path::new(env!("CARGO_MANIFEST_DIR"));
        let err =
            read_file_with(&checkout.join("absent.toml"), 64, &FakeMounts::ext4()).unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");
    }

    #[test]
    fn a_present_file_that_is_not_a_regular_file_is_refused() {
        // /dev is root's on every host; /dev/null is a device, which the walk
        // refuses as the last component.
        let err = read_file_with(Path::new("/dev/null"), 64, &FakeMounts::ext4()).unwrap_err();
        assert_eq!(
            err,
            TrustError::WrongKind {
                at: "/dev/null".to_owned()
            }
        );
    }

    #[test]
    fn a_file_longer_than_the_limit_is_refused_not_truncated() {
        let err = read_file_with(Path::new(TRUSTED_FILE), 10, &FakeMounts::ext4()).unwrap_err();
        assert!(err.to_string().contains("longer than 10 bytes"), "{err}");
    }

    #[test]
    fn a_path_that_cannot_be_walked_as_written_is_refused() {
        for path in ["/", "relative.toml"] {
            let err = read_file_with(Path::new(path), 64, &FakeMounts::ext4()).unwrap_err();
            assert!(err.to_string().contains("not absolute"), "{path}: {err}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_real_mount_table_is_read_and_a_root_owned_file_is_trusted() {
        let bytes = read_trusted_file(Path::new(TRUSTED_FILE), 1 << 24)
            .unwrap()
            .unwrap();
        assert_eq!(bytes, std::fs::read(TRUSTED_FILE).unwrap());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_no_file_is_trusted_because_no_mount_can_be_judged() {
        let err = read_trusted_file(Path::new(TRUSTED_FILE), 1 << 24).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("the mount table cannot be checked"),
            "{err}"
        );
    }

    #[test]
    fn a_failed_read_names_the_file() {
        let err = contents(
            Err(std::io::Error::other("device gone")),
            Vec::new(),
            Path::new("/etc/aido/config.toml"),
            64,
        )
        .unwrap_err();
        assert_eq!(
            err,
            TrustError::Unreadable {
                at: "/etc/aido/config.toml".to_owned(),
                reason: "device gone".to_owned(),
            }
        );
    }
}
