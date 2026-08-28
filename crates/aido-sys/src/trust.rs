//! Whether the rules on disk are the rules root wrote.
//!
//! Every other guarantee in `aido` rests on this one. The policy engine is a
//! pure function of the ruleset, so anyone who can edit the ruleset — or edit
//! anything on the path to it — decides what an agent may run. Checking the
//! file's own owner and mode is not enough:
//!
//! * A **symlink** anywhere on the path redirects the load. `/etc/aido` owned by
//!   root but *reachable* through a directory a user can write is a directory a
//!   user can replace.
//! * A **writable ancestor** is the same attack one level up. If `/etc/aido` is
//!   perfect but `/etc` is group-writable, the group can rename `aido` aside and
//!   put its own there. Nothing about the final file looks wrong afterwards.
//! * A **group- or world-writable** file needs no attack at all.
//!
//! So the check walks from the filesystem root down to the target and demands
//! the same three properties of every component. That is the "ancestor ownership
//! walk", and it is the reason this module exists before the executor does: an
//! exec path that trusts an unverified ruleset is not a privilege broker, it is
//! a privilege escalation.
//!
//! # Shape
//!
//! [`verify`] is pure: it takes the facts already gathered and returns the
//! **first** component that fails, with the reason. Gathering the facts is
//! [`stat_path`], which is the only part that touches a filesystem. The split is
//! what makes every refusal reachable from a test without needing to be root.

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Who may own a trusted path.
///
/// Root, and nobody else. Named rather than written as `0` at each use so the
/// intent survives someone deciding to make it configurable — which it must not
/// become, because a configurable trusted owner is an owner an attacker can
/// nominate.
pub const TRUSTED_UID: u32 = 0;

/// The permission bits that must be clear: group-write and other-write.
pub const FORBIDDEN_WRITE_BITS: u32 = 0o022;

/// What a single path component is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A directory.
    Directory,
    /// A regular file.
    File,
    /// A symbolic link.
    Symlink,
    /// Anything else: a socket, device, fifo.
    Other,
}

/// The facts about one path that decide whether it can be trusted.
///
/// Deliberately not `std::fs::Metadata`: that type cannot be constructed by a
/// test, which would make every refusal below unreachable without root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathFacts {
    /// The owning user.
    pub uid: u32,
    /// The permission bits, already masked to `0o7777`.
    pub mode: u32,
    /// What it is.
    pub kind: Kind,
}

impl PathFacts {
    /// A root-owned directory with mode 0755 — the expected case.
    pub fn trusted_directory() -> Self {
        Self {
            uid: TRUSTED_UID,
            mode: 0o755,
            kind: Kind::Directory,
        }
    }

    /// A root-owned file with mode 0644 — the expected case.
    pub fn trusted_file() -> Self {
        Self {
            uid: TRUSTED_UID,
            mode: 0o644,
            kind: Kind::File,
        }
    }
}

/// Why a path cannot be trusted.
///
/// Each variant names the component at fault rather than the target, because
/// "`/etc/aido/rules.d/20-services.toml` is untrusted" sends an operator to
/// inspect the wrong thing when the actual problem is that `/etc` is
/// group-writable.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// A component is not owned by root.
    #[error("{at} is owned by uid {uid}, not root: anyone with that uid decides what aido runs")]
    NotRootOwned {
        /// The component at fault.
        at: String,
        /// Who owns it.
        uid: u32,
    },
    /// A component can be written by someone other than its owner.
    #[error(
        "{at} has mode {mode:04o}: it is writable by group or world, so its contents are not \
         root's"
    )]
    Writable {
        /// The component at fault.
        at: String,
        /// Its mode.
        mode: u32,
    },
    /// A component is a symlink.
    ///
    /// Refused rather than followed. Following it would mean the verified path
    /// and the loaded path are different paths, which is the whole trick.
    #[error(
        "{at} is a symbolic link: the path that was checked is not the path that would be read"
    )]
    Symlink {
        /// The component at fault.
        at: String,
    },
    /// A component is neither a directory nor a regular file.
    #[error("{at} is not a directory or a regular file")]
    WrongKind {
        /// The component at fault.
        at: String,
    },
    /// An ancestor is not a directory.
    #[error("{at} is not a directory, so it cannot contain the ruleset")]
    AncestorNotDirectory {
        /// The component at fault.
        at: String,
    },
    /// A component could not be inspected.
    #[error("{at} cannot be inspected: {reason}")]
    Unreadable {
        /// The component at fault.
        at: String,
        /// Why.
        reason: String,
    },
    /// The path was relative.
    ///
    /// A relative path resolves against whatever directory the process happens
    /// to be in, which the caller may control.
    #[error("{at} is not absolute: a relative ruleset path resolves against the caller's cwd")]
    NotAbsolute {
        /// What was given.
        at: String,
    },
}

/// Every path from the filesystem root down to `target`, inclusive.
///
/// Returns `None` for a relative path or one containing `.` or `..`: normalising
/// those would mean verifying a path different from the one that gets opened.
pub fn chain_to(target: &Path) -> Option<Vec<PathBuf>> {
    // `.` is checked on the raw bytes because `Path::components` silently drops
    // it: `/etc/./aido` would arrive below looking identical to `/etc/aido`, and
    // a path this function reported as verified would not be the path the caller
    // wrote. `..` survives `components()`, so it is refused there instead — see
    // `plain_name`.
    if target
        .as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/')
        .any(|segment| segment == b".")
    {
        return None;
    }

    let mut chain = Vec::new();
    let mut current = PathBuf::new();
    let mut components = target.components();

    if components.next() != Some(Component::RootDir) {
        return None;
    }
    current.push("/");
    chain.push(current.clone());

    for component in components {
        current.push(plain_name(component)?);
        chain.push(current.clone());
    }
    Some(chain)
}

/// The name of a component that is a plain name, or `None` for anything else.
///
/// `..` and a repeated root are refused rather than resolved: resolving either
/// would mean the path this module verified is not the path that gets opened.
fn plain_name(component: Component<'_>) -> Option<&std::ffi::OsStr> {
    match component {
        Component::Normal(name) => Some(name),
        _ => None,
    }
}

/// Verifies a chain of components, innermost last.
///
/// `facts` supplies each component in the same order as [`chain_to`] produced
/// it. Every component must be a root-owned directory that only root can write,
/// except the last, which may also be a regular file.
///
/// # Errors
///
/// Returns the **first** component that fails. Everything after it is a
/// consequence rather than independent evidence, and an operator fixes the
/// outermost problem first anyway.
pub fn verify(chain: &[(PathBuf, Result<PathFacts, String>)]) -> Result<(), TrustError> {
    let last_index = chain.len().saturating_sub(1);

    for (index, (path, facts)) in chain.iter().enumerate() {
        let at = path.display().to_string();
        let facts = match facts {
            Ok(facts) => facts,
            Err(reason) => {
                return Err(TrustError::Unreadable {
                    at,
                    reason: reason.clone(),
                });
            }
        };

        // Kind first: a symlink's uid and mode are meaningless, because the
        // thing that would be read is whatever it points at.
        match facts.kind {
            Kind::Symlink => return Err(TrustError::Symlink { at }),
            Kind::Other => return Err(TrustError::WrongKind { at }),
            Kind::File if index != last_index => {
                return Err(TrustError::AncestorNotDirectory { at });
            }
            Kind::File | Kind::Directory => {}
        }

        if facts.uid != TRUSTED_UID {
            return Err(TrustError::NotRootOwned { at, uid: facts.uid });
        }

        if facts.mode & FORBIDDEN_WRITE_BITS != 0 {
            return Err(TrustError::Writable {
                at,
                mode: facts.mode,
            });
        }
    }

    Ok(())
}

/// Reads the facts about one path **without following a final symlink**.
///
/// `symlink_metadata`, not `metadata`: the point is to notice a symlink, and
/// `metadata` would silently report the target's owner and mode instead.
///
/// # Errors
///
/// Returns the operating system's message if the path cannot be inspected —
/// missing, or in a directory this process may not search.
pub fn stat_path(path: &Path) -> Result<PathFacts, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|source| source.to_string())?;
    let file_type = meta.file_type();
    let kind = if file_type.is_symlink() {
        Kind::Symlink
    } else if file_type.is_dir() {
        Kind::Directory
    } else if file_type.is_file() {
        Kind::File
    } else {
        Kind::Other
    };
    Ok(PathFacts {
        uid: MetadataExt::uid(&meta),
        mode: MetadataExt::mode(&meta) & 0o7777,
        kind,
    })
}

/// Verifies that `target` and every component above it belong to root.
///
/// # Errors
///
/// [`TrustError::NotAbsolute`] if the path cannot be verified as written, or the
/// first component that fails. See [`verify`].
pub fn verify_path(target: &Path) -> Result<(), TrustError> {
    let chain = chain_to(target).ok_or_else(|| TrustError::NotAbsolute {
        at: target.display().to_string(),
    })?;
    let facts: Vec<(PathBuf, Result<PathFacts, String>)> = chain
        .into_iter()
        .map(|path| {
            let facts = stat_path(&path);
            (path, facts)
        })
        .collect();
    verify(&facts)
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

    use super::*;

    /// Builds a chain where every component is a trusted directory except the
    /// last, which is a trusted file.
    fn clean(path: &str) -> Vec<(PathBuf, Result<PathFacts, String>)> {
        let chain = chain_to(Path::new(path)).unwrap();
        let last = chain.len() - 1;
        chain
            .into_iter()
            .enumerate()
            .map(|(index, path)| {
                let facts = if index == last {
                    PathFacts::trusted_file()
                } else {
                    PathFacts::trusted_directory()
                };
                (path, Ok(facts))
            })
            .collect()
    }

    #[test]
    fn the_chain_runs_from_the_root_down_to_the_target() {
        assert_eq!(
            chain_to(Path::new("/etc/aido/rules.d")).unwrap(),
            vec![
                PathBuf::from("/"),
                PathBuf::from("/etc"),
                PathBuf::from("/etc/aido"),
                PathBuf::from("/etc/aido/rules.d"),
            ]
        );
        assert_eq!(chain_to(Path::new("/")).unwrap(), vec![PathBuf::from("/")]);
    }

    #[test]
    fn a_path_that_cannot_be_verified_as_written_has_no_chain() {
        // Normalising any of these would mean verifying a different path from
        // the one that gets opened.
        for path in ["etc/aido", "./aido", "/etc/../root/aido", "/etc/./aido", ""] {
            assert_eq!(chain_to(Path::new(path)), None, "{path}");
        }
    }

    #[test]
    fn a_root_owned_path_with_no_writable_component_is_trusted() {
        assert_eq!(verify(&clean("/etc/aido/rules.d/20-services.toml")), Ok(()));
        // An empty chain is vacuously fine; `chain_to` never produces one.
        assert_eq!(verify(&[]), Ok(()));
    }

    #[test]
    fn a_writable_ancestor_is_refused_even_when_the_file_itself_is_perfect() {
        // The attack this module exists for: /etc/aido is immaculate, but the
        // group that can write /etc can rename it aside and substitute its own.
        let mut chain = clean("/etc/aido/rules.d/20-services.toml");
        chain[1].1 = Ok(PathFacts {
            mode: 0o775,
            ..PathFacts::trusted_directory()
        });

        let error = verify(&chain).unwrap_err();
        // Names /etc, not the file, so the operator fixes the real problem.
        assert_eq!(
            error.to_string(),
            "/etc has mode 0775: it is writable by group or world, so its contents are not root's"
        );
    }

    #[test]
    fn world_writable_is_refused_as_well_as_group_writable() {
        let mut chain = clean("/etc/aido/rules.d");
        chain[2].1 = Ok(PathFacts {
            mode: 0o757,
            ..PathFacts::trusted_directory()
        });
        assert_eq!(
            verify(&chain).unwrap_err().to_string(),
            "/etc/aido has mode 0757: it is writable by group or world, so its contents are not \
             root's"
        );
    }

    #[test]
    fn the_sticky_bit_alone_does_not_make_a_directory_untrusted() {
        // 1755 is /usr/bin's shape on some distributions. Only the write bits
        // matter; refusing setuid or sticky bits here would reject paths that
        // are perfectly safe to read through.
        let mut chain = clean("/etc/aido/rules.d");
        chain[1].1 = Ok(PathFacts {
            mode: 0o1755,
            ..PathFacts::trusted_directory()
        });
        assert_eq!(verify(&chain), Ok(()));
    }

    #[test]
    fn a_non_root_owner_is_refused_and_named() {
        let mut chain = clean("/etc/aido/rules.d");
        chain[2].1 = Ok(PathFacts {
            uid: 1000,
            ..PathFacts::trusted_directory()
        });
        assert_eq!(
            verify(&chain).unwrap_err().to_string(),
            "/etc/aido is owned by uid 1000, not root: anyone with that uid decides what aido runs"
        );
    }

    #[test]
    fn a_symlink_is_refused_rather_than_followed() {
        // Following it would mean the path that was checked and the path that
        // gets read are different paths, which is the entire trick.
        let mut chain = clean("/etc/aido/rules.d");
        chain[2].1 = Ok(PathFacts {
            kind: Kind::Symlink,
            ..PathFacts::trusted_directory()
        });
        assert_eq!(
            verify(&chain).unwrap_err().to_string(),
            "/etc/aido is a symbolic link: the path that was checked is not the path that would \
             be read"
        );
    }

    #[test]
    fn a_symlink_owned_by_root_is_still_refused() {
        // A root-owned symlink is not safe: the target need not be root-owned,
        // and the check would be attesting the wrong inode. Asserted separately
        // so nobody "optimises" the kind check to run after the uid check.
        let chain = vec![(
            PathBuf::from("/"),
            Ok(PathFacts {
                uid: TRUSTED_UID,
                mode: 0o755,
                kind: Kind::Symlink,
            }),
        )];
        assert!(
            verify(&chain)
                .unwrap_err()
                .to_string()
                .starts_with("/ is a symbolic link"),
        );
    }

    #[test]
    fn a_socket_or_device_on_the_path_is_refused() {
        let mut chain = clean("/etc/aido/rules.d");
        chain[3].1 = Ok(PathFacts {
            kind: Kind::Other,
            ..PathFacts::trusted_file()
        });
        assert_eq!(
            verify(&chain).unwrap_err().to_string(),
            "/etc/aido/rules.d is not a directory or a regular file"
        );
    }

    #[test]
    fn a_file_where_a_directory_must_be_is_refused() {
        let mut chain = clean("/etc/aido/rules.d");
        chain[1].1 = Ok(PathFacts::trusted_file());
        assert_eq!(
            verify(&chain).unwrap_err().to_string(),
            "/etc is not a directory, so it cannot contain the ruleset"
        );
    }

    #[test]
    fn the_target_may_be_a_directory_or_a_file() {
        let mut chain = clean("/etc/aido/rules.d");
        chain[3].1 = Ok(PathFacts::trusted_directory());
        assert_eq!(verify(&chain), Ok(()));
    }

    #[test]
    fn a_component_that_cannot_be_inspected_fails_closed() {
        let mut chain = clean("/etc/aido/rules.d");
        chain[2].1 = Err("Permission denied".to_owned());
        assert_eq!(
            verify(&chain).unwrap_err().to_string(),
            "/etc/aido cannot be inspected: Permission denied"
        );
    }

    #[test]
    fn the_outermost_failure_is_the_one_reported() {
        // Two problems; the operator hears about /etc first, because fixing the
        // inner one while the outer one stands fixes nothing.
        let mut chain = clean("/etc/aido/rules.d");
        chain[1].1 = Ok(PathFacts {
            mode: 0o777,
            ..PathFacts::trusted_directory()
        });
        chain[2].1 = Ok(PathFacts {
            uid: 1000,
            ..PathFacts::trusted_directory()
        });
        assert!(
            verify(&chain).unwrap_err().to_string().starts_with("/etc "),
            "the outermost failure is the one to report"
        );
    }

    #[test]
    fn the_trusted_owner_is_root_and_the_forbidden_bits_are_the_write_bits() {
        // Asserted so a change to either constant is a deliberate act with a
        // failing test behind it.
        assert_eq!(TRUSTED_UID, 0);
        assert_eq!(FORBIDDEN_WRITE_BITS, 0o022);
    }

    /// A throwaway directory under the workspace `target/`, never `/tmp`.
    fn test_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Canonicalised: the path above contains `..`, which `chain_to` refuses
        // on purpose, and refusing the fixture would test the wrong thing.
        std::fs::canonicalize(&dir).unwrap()
    }

    #[test]
    fn stat_reports_a_real_directory_and_a_real_file() {
        let dir = test_dir("trust-stat");
        let file = dir.join("rule.toml");
        std::fs::write(&file, "").unwrap();

        assert_eq!(stat_path(&dir).unwrap().kind, Kind::Directory);
        let facts = stat_path(&file).unwrap();
        assert_eq!(facts.kind, Kind::File);
        // Owned by whoever runs the suite, which is the point of the next test.
        assert_eq!(facts.mode & !0o7777, 0);
    }

    #[test]
    fn stat_does_not_follow_a_symlink() {
        // With `metadata` instead of `symlink_metadata` this reports the
        // target's kind, owner, and mode — exactly the substitution the check
        // exists to catch.
        let dir = test_dir("trust-symlink");
        let real = dir.join("real.toml");
        std::fs::write(&real, "").unwrap();
        let link = dir.join("link.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(stat_path(&link).unwrap().kind, Kind::Symlink);
        assert_eq!(stat_path(&real).unwrap().kind, Kind::File);
    }

    #[test]
    fn stat_reports_a_socket_as_neither_a_file_nor_a_directory() {
        // A real socket in the filesystem, made with std alone. Without this the
        // Other arm is dead code, and dead code in a trust check is a branch
        // nobody has ever seen behave.
        let dir = test_dir("trust-socket");
        let path = dir.join("sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert_eq!(stat_path(&path).unwrap().kind, Kind::Other);
        drop(listener);
    }

    #[test]
    fn stat_reports_why_a_missing_path_could_not_be_read() {
        let dir = test_dir("trust-missing");
        let error = stat_path(&dir.join("absent")).unwrap_err();
        assert!(!error.is_empty(), "an error must say something");
    }

    #[test]
    fn a_relative_target_is_refused_before_anything_is_inspected() {
        assert_eq!(
            verify_path(Path::new("relative/rules.d"))
                .unwrap_err()
                .to_string(),
            "relative/rules.d is not absolute: a relative ruleset path resolves against the \
             caller's cwd"
        );
    }

    #[test]
    fn a_real_directory_owned_by_the_test_user_is_refused() {
        // The suite does not run as root, so this exercises the whole host path
        // — chain, stat, verify — and lands on the refusal it should.
        let dir = test_dir("trust-real");
        let message = verify_path(&dir).unwrap_err().to_string();
        assert!(message.contains("not root"), "{message}");
    }

    #[test]
    fn the_filesystem_root_itself_is_trusted_on_a_sane_system() {
        // Not an assertion about aido; an assertion that the host path returns
        // Ok at all, so a bug that always refuses cannot hide behind the test
        // above.
        assert_eq!(verify_path(Path::new("/")), Ok(()));
    }

    #[test]
    fn facts_and_errors_are_comparable_and_debuggable() {
        let facts = PathFacts::trusted_file();
        assert_eq!(facts, PathFacts::trusted_file());
        assert!(format!("{facts:?}").contains("File"));
        assert_ne!(PathFacts::trusted_file(), PathFacts::trusted_directory());

        let error = TrustError::NotAbsolute {
            at: "aido".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "aido is not absolute: a relative ruleset path resolves against the caller's cwd"
        );
        assert_eq!(error.clone(), error);
        assert!(format!("{error:?}").contains("NotAbsolute"));
        assert!(format!("{:?}", Kind::Symlink).contains("Symlink"));
        assert_eq!(Kind::File, Kind::File);
    }
}
