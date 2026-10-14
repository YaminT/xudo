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

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, CWD, Dir, Mode, OFlags, fstat, openat, statat};

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
        let facts = match facts {
            Ok(facts) => facts,
            Err(reason) => {
                return Err(TrustError::Unreadable {
                    at: path.display().to_string(),
                    reason: reason.clone(),
                });
            }
        };
        check_component(path, facts, index == last_index, TRUSTED_UID)?;
    }

    Ok(())
}

/// Checks one component: what it is, who owns it, and who can write it.
///
/// `owner` is always [`TRUSTED_UID`] outside this module's tests; it is a
/// parameter only so the descriptor-reading code below can be exercised on a
/// directory a test created, without root.
fn check_component(
    path: &Path,
    facts: &PathFacts,
    is_last: bool,
    owner: u32,
) -> Result<(), TrustError> {
    let at = path.display().to_string();

    // Kind first: a symlink's uid and mode are meaningless, because the thing
    // that would be read is whatever it points at.
    match facts.kind {
        Kind::Symlink => return Err(TrustError::Symlink { at }),
        Kind::Other => return Err(TrustError::WrongKind { at }),
        Kind::File if !is_last => return Err(TrustError::AncestorNotDirectory { at }),
        Kind::File | Kind::Directory => {}
    }

    if facts.uid != owner {
        return Err(TrustError::NotRootOwned { at, uid: facts.uid });
    }

    if facts.mode & FORBIDDEN_WRITE_BITS != 0 {
        return Err(TrustError::Writable {
            at,
            mode: facts.mode,
        });
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

/// The facts in a `stat` result.
///
/// `st_mode` is a `u32` on Linux and a `u16` on macOS, so the widening below
/// is a real conversion on one platform and an identity on the other.
#[allow(clippy::useless_conversion)]
fn facts_of(stat: &rustix::fs::Stat) -> PathFacts {
    let raw = stat.st_mode;
    let kind = match rustix::fs::FileType::from_raw_mode(raw) {
        rustix::fs::FileType::Directory => Kind::Directory,
        rustix::fs::FileType::RegularFile => Kind::File,
        rustix::fs::FileType::Symlink => Kind::Symlink,
        _ => Kind::Other,
    };
    PathFacts {
        uid: stat.st_uid,
        mode: u32::from(rustix::fs::Mode::from_raw_mode(raw).bits()) & 0o7777,
        kind,
    }
}

/// Shapes any failure to read something already judged trustworthy.
fn or_unreadable<T, E: std::fmt::Display>(
    result: Result<T, E>,
    at: &Path,
) -> Result<T, TrustError> {
    result.map_err(|e| TrustError::Unreadable {
        at: at.display().to_string(),
        reason: e.to_string(),
    })
}

/// Opens `name` under `base` without following a link, and checks it on the
/// descriptor just opened.
///
/// When the open itself fails, the component is examined — still without
/// following — so a link is reported as a link and a file where a directory
/// must be is reported as that, rather than as a bare `ELOOP` or `ENOTDIR`.
fn open_checked(
    base: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    directory: bool,
    is_last: bool,
    owner: u32,
) -> Result<OwnedFd, TrustError> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    match openat(base, name, flags, Mode::empty()).and_then(|fd| fstat(&fd).map(|st| (fd, st))) {
        Ok((fd, stat)) => {
            check_component(path, &facts_of(&stat), is_last, owner)?;
            Ok(fd)
        }
        Err(errno) => {
            if let Ok(stat) = statat(base, name, AtFlags::SYMLINK_NOFOLLOW) {
                check_component(path, &facts_of(&stat), is_last, owner)?;
            }
            or_unreadable(Err(errno), path)
        }
    }
}

/// Opens `target` read-only, having verified every component on the
/// descriptor it was opened through.
///
/// The walk starts at `/` and opens one component at a time relative to its
/// parent's descriptor, never following a link, so the thing checked is the
/// thing opened: there is no window in which a component can be swapped after
/// its check. This is the per-component `O_NOFOLLOW` walk; `openat2`'s
/// `RESOLVE_NO_SYMLINKS` would do the same in one call where the kernel has it,
/// and nothing is lost without it.
///
/// # Errors
///
/// [`TrustError::NotAbsolute`] for a path that cannot be walked as written, and
/// otherwise the first component that fails, as [`verify`] would report it.
pub fn open_trusted(target: &Path) -> Result<OwnedFd, TrustError> {
    open_trusted_as(target, TRUSTED_UID)
}

fn open_trusted_as(target: &Path, owner: u32) -> Result<OwnedFd, TrustError> {
    let not_absolute = TrustError::NotAbsolute {
        at: target.display().to_string(),
    };
    let chain = chain_to(target).ok_or(not_absolute.clone())?;
    let last = chain.len().saturating_sub(1);
    let mut current: Option<OwnedFd> = None;
    for (index, path) in chain.iter().enumerate() {
        // The first component is `/` itself; every other is a plain name.
        let name = path.file_name().unwrap_or(path.as_os_str());
        let base = current.as_ref().map_or(CWD, AsFd::as_fd);
        current = Some(open_checked(
            base,
            name,
            path,
            index < last,
            index == last,
            owner,
        )?);
    }
    current.ok_or(not_absolute)
}

/// One rule file, read through a verified descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedFile {
    /// Its name within the directory, as the bytes the kernel returned.
    pub name: OsString,
    /// Its contents.
    pub bytes: Vec<u8>,
}

/// Reads every `*.toml` file in `dir`, each through a descriptor checked on
/// open, with `dir` and every component above it verified the same way.
///
/// This is how the privileged gate must load the ruleset. Verifying the path
/// and then reading it by name leaves a window in which any component can be
/// swapped; reading through descriptors that were themselves checked does not.
/// Files are returned sorted by name, the order rules are evaluated in.
///
/// # Errors
///
/// The first component or file that fails, or any read failure.
pub fn read_trusted_dir(dir: &Path) -> Result<Vec<TrustedFile>, TrustError> {
    let fd = open_trusted(dir)?;
    read_toml_at(fd.as_fd(), dir, TRUSTED_UID)
}

/// The descriptor half of [`read_trusted_dir`], for a directory already open.
fn read_toml_at(
    dir: BorrowedFd<'_>,
    path: &Path,
    owner: u32,
) -> Result<Vec<TrustedFile>, TrustError> {
    let names = or_unreadable(
        Dir::read_from(dir).and_then(|entries| {
            entries
                .map(|entry| entry.map(|e| e.file_name().to_bytes().to_vec()))
                .collect::<Result<Vec<Vec<u8>>, _>>()
        }),
        path,
    )?;
    let mut names: Vec<Vec<u8>> = names
        .into_iter()
        .filter(|name| name.ends_with(b".toml"))
        .collect();
    names.sort();

    let mut files = Vec::new();
    for name in names {
        let name = OsString::from_vec(name);
        let file_path = path.join(&name);
        let fd = open_checked(dir, &name, &file_path, false, true, owner)?;
        // The component check refuses a link, a socket, a device, and a fifo.
        // A directory named `*.toml` passes it, because a directory may be the
        // last component of a path; it is refused here instead, by the read,
        // which fails with EISDIR. Nothing else that passes the check can fail
        // to read, so one refusal path covers both.
        let mut bytes = Vec::new();
        or_unreadable(std::fs::File::from(fd).read_to_end(&mut bytes), &file_path)?;
        files.push(TrustedFile { name, bytes });
    }
    Ok(files)
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

    // --- the descriptor walk --------------------------------------------

    /// A root-owned regular file whose every ancestor is root's, on every
    /// platform this builds for.
    const TRUSTED_FILE: &str = "/usr/bin/true";

    /// A directory only root may search.
    #[cfg(target_os = "linux")]
    const ROOT_ONLY: &str = "/root";
    #[cfg(not(target_os = "linux"))]
    const ROOT_ONLY: &str = "/private/var/root";

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("tw-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open_dir(dir: &Path) -> OwnedFd {
        rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap()
    }

    #[test]
    fn a_root_owned_file_opens_through_verified_descriptors() {
        let fd = open_trusted(Path::new(TRUSTED_FILE)).unwrap();
        assert_eq!(facts_of(&fstat(&fd).unwrap()).kind, Kind::File);
        assert!(read_trusted_dir(Path::new("/usr/bin")).is_ok());
    }

    #[test]
    fn a_path_through_a_symlink_is_refused_on_the_descriptor_walk() {
        // Merged-/usr Linux has /bin -> usr/bin; macOS has /tmp -> private/tmp.
        let through_link = ["/bin/sh", "/tmp", "/etc/hosts"]
            .into_iter()
            .find(|candidate| {
                chain_to(Path::new(candidate))
                    .unwrap()
                    .iter()
                    .any(|c| std::fs::symlink_metadata(c).is_ok_and(|m| m.is_symlink()))
            })
            .expect("this host has no symlink on any candidate path");
        let err = open_trusted(Path::new(through_link)).unwrap_err();
        assert!(
            err.to_string().contains("symbolic link"),
            "{through_link}: {err}"
        );
    }

    #[test]
    fn a_file_where_a_directory_must_be_is_refused_on_the_walk() {
        let err = open_trusted(&Path::new(TRUSTED_FILE).join("rules.d")).unwrap_err();
        assert_eq!(
            err,
            TrustError::AncestorNotDirectory {
                at: TRUSTED_FILE.to_owned()
            }
        );
    }

    #[test]
    fn a_missing_or_unsearchable_component_fails_closed() {
        let err = open_trusted(Path::new("/usr/definitely-not-here")).unwrap_err();
        assert!(err.to_string().contains("cannot be inspected"), "{err}");

        // Root may search anything, so the refusal is only observable without it.
        let searchable = std::fs::read_dir(ROOT_ONLY).is_ok();
        let outcome = open_trusted(&Path::new(ROOT_ONLY).join("rules.d"));
        assert!(
            searchable || outcome.is_err_and(|e| e.to_string().contains("cannot be inspected")),
            "an unsearchable directory must refuse"
        );

        assert!(
            open_trusted(Path::new("relative/rules.d"))
                .unwrap_err()
                .to_string()
                .contains("not absolute")
        );
    }

    #[test]
    fn a_checkout_is_not_root_owned_on_the_walk() {
        let err = open_trusted(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");
    }

    #[test]
    fn reading_a_file_as_a_directory_fails_closed() {
        let err = read_trusted_dir(Path::new(TRUSTED_FILE)).unwrap_err();
        assert!(err.to_string().contains("cannot be inspected"), "{err}");
    }

    #[test]
    fn rule_files_are_read_in_order_through_their_own_descriptors() {
        let dir = scratch_dir("ordered");
        std::fs::write(dir.join("20-b.toml"), "b").unwrap();
        std::fs::write(dir.join("10-a.toml"), "a").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let me = std::fs::metadata(&dir).unwrap().uid();
        let files = read_toml_at(open_dir(&dir).as_fd(), &dir, me).unwrap();
        assert_eq!(
            files,
            vec![
                TrustedFile {
                    name: "10-a.toml".into(),
                    bytes: b"a".to_vec()
                },
                TrustedFile {
                    name: "20-b.toml".into(),
                    bytes: b"b".to_vec()
                },
            ]
        );
        // Someone else's files are refused, named by file.
        let err = read_toml_at(open_dir(&dir).as_fd(), &dir, me.wrapping_add(1)).unwrap_err();
        assert!(err.to_string().contains("10-a.toml"), "{err}");
    }

    #[test]
    fn a_rule_file_that_is_a_link_a_directory_or_a_socket_is_refused() {
        let cases: [(&str, &str); 3] = [
            ("link", "symbolic link"),
            ("dir", "Is a directory"),
            ("sock", "not a directory or a regular file"),
        ];
        for (shape, expect) in cases {
            let dir = scratch_dir(&format!("shape-{shape}"));
            let target = dir.join("10-x.toml");
            match shape {
                "link" => {
                    std::fs::write(dir.join("real"), "x").unwrap();
                    std::os::unix::fs::symlink(dir.join("real"), &target).unwrap();
                }
                "dir" => std::fs::create_dir(&target).unwrap(),
                _ => drop(std::os::unix::net::UnixListener::bind(&target).unwrap()),
            }
            let me = std::fs::metadata(&dir).unwrap().uid();
            let err = read_toml_at(open_dir(&dir).as_fd(), &dir, me).unwrap_err();
            assert!(err.to_string().contains(expect), "{shape}: {err}");
        }
    }

    #[test]
    fn a_writable_or_unreadable_rule_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("writable");
        let file = dir.join("10-x.toml");
        std::fs::write(&file, "x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let me = std::fs::metadata(&dir).unwrap().uid();
        let err = read_toml_at(open_dir(&dir).as_fd(), &dir, me).unwrap_err();
        assert!(
            err.to_string().contains("writable by group or world"),
            "{err}"
        );

        // Unreadable: the check passes on what `stat` sees, and the open still
        // refuses. Root reads anything, so this is only observable without it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read(&file).is_ok();
        let outcome = read_toml_at(open_dir(&dir).as_fd(), &dir, me);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            readable || outcome.is_err_and(|e| e.to_string().contains("cannot be inspected")),
            "an unreadable rule file must refuse"
        );
    }
}
