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
//!
//! # The filesystem under each component
//!
//! An owner and a mode are what a filesystem reports, and some filesystems will
//! report anything: a FUSE filesystem a user mounted answers every `stat` from
//! that user's daemon. So [`open_trusted`], [`read_trusted_dir`], and
//! [`load_trusted_rules`] also match every descriptor they open to its mount in
//! `/proc/thread-self/mountinfo` and refuse a mount whose word on ownership is
//! not taken; `crate::mounts` says which and why.
//!
//! The mount comes first. On Linux each component is opened `O_PATH`, which
//! asks its filesystem nothing — crossing into the root of a FUSE mount does
//! not reach the daemon — and its mount is judged before its owner and mode
//! are read from that descriptor, and before anything beneath it is looked up.
//! So a user's daemon is never asked anything: it can neither choose which
//! refusal the operator is shown nor stall the walk, and the refusal names the
//! outermost component at fault. Whatever is read is opened once more, since
//! nothing can be read through `O_PATH`, and refused unless it is the inode
//! that passed. Off Linux there is no mount table, so these three refuse
//! everything there.

use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use aido_policy::{LoadedRuleSet, RuleFile, RuleFilesError, is_rule_file_name, load_rule_files};
use bstr::BString;
use rustix::fs::{CWD, Dir, Mode, OFlags, Stat, fstat, openat};

use crate::mounts::{self, HostMounts, MountPolicy, MountRefusal, MountView};

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
    /// What opened to be read is not what passed.
    ///
    /// The walk's descriptors are `O_PATH`, through which nothing can be read,
    /// so the target and every rule file are opened once more, by name, in a
    /// directory that has passed. A different device or inode the second time
    /// means the name was pointed elsewhere, or a mount laid over it, in
    /// between.
    #[error("{at} changed while it was being checked: what opened to be read is not what passed")]
    Replaced {
        /// The component at fault.
        at: String,
    },
    /// A component is on a mount whose word on ownership is not taken.
    ///
    /// The ownership checks may well have passed: a filesystem a user mounted
    /// can report root as the owner of everything on it.
    ///
    /// The type and the mount point are shown with every byte that is not
    /// printable ASCII escaped. A FUSE daemon names its own subtype, and the
    /// kernel escapes only space, tab, newline, and backslash in it, so an
    /// escape sequence written there would otherwise reach the terminal of
    /// whoever runs `aido doctor`.
    #[error(
        "{at} is on {} at {}, {reason}",
        .fs_type.escape_ascii(),
        .mount_point.escape_ascii()
    )]
    UntrustedMount {
        /// The component at fault.
        at: String,
        /// The filesystem type, decoded from mountinfo (`fuse.sshfs`).
        fs_type: BString,
        /// Where that filesystem is mounted, decoded from mountinfo.
        mount_point: BString,
        /// What is wrong with the mount.
        reason: MountRefusal,
    },
    /// A component is on a mount the mount table does not list.
    #[error(
        "{at} is on mount {mount_id}, which the mount table does not list, so who made that \
         mount cannot be checked"
    )]
    MountUnlisted {
        /// The component at fault.
        at: String,
        /// The mount its descriptor is on.
        mount_id: u32,
    },
    /// The mount table could not be read, or could not be believed.
    #[error("the mount table cannot be checked, so neither can any component's mount: {reason}")]
    MountTable {
        /// Why.
        reason: String,
    },
    /// This thread is outside the initial user namespace.
    ///
    /// There, uid 0 is the namespace's owner, so "owned by root" would be a
    /// statement about someone else; and a FUSE mount's `user_id` is printed
    /// relative to the namespace the mount was made in, which mountinfo does
    /// not name.
    #[error(
        "this thread's user namespace is {namespace}, not the initial one, so uid 0 here is that \
         namespace's owner and not root, and who made a mount cannot be told"
    )]
    NamespacedRoot {
        /// The namespace, as its `/proc` link reads.
        namespace: BString,
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
/// By path, and without the mount check: a report, not a loader. What a
/// privileged reader uses is [`open_trusted`] or [`read_trusted_dir`].
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
pub(crate) fn facts_of(stat: &rustix::fs::Stat) -> PathFacts {
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

/// Shapes any failure to open, inspect, or read a component.
fn or_unreadable<T, E: std::fmt::Display>(
    result: Result<T, E>,
    at: &Path,
) -> Result<T, TrustError> {
    result.map_err(|e| TrustError::Unreadable {
        at: at.display().to_string(),
        reason: e.to_string(),
    })
}

/// How a component is first opened, before anything its filesystem says about
/// it is believed.
///
/// On Linux, `O_PATH`. It opens a link, a socket, a fifo, or a device without
/// following, reading, or blocking on it, needs no permission on the component
/// itself, and asks the component's filesystem nothing: crossing into the root
/// of a FUSE mount does not reach its daemon, where `fstat` or an ordinary
/// open would. Off Linux there is no `O_PATH`, and no mount table either, so
/// nothing there is trusted; read-only and non-blocking, so a fifo cannot hang
/// the walk.
#[cfg(target_os = "linux")]
const PROBE: OFlags = OFlags::PATH;
#[cfg(not(target_os = "linux"))]
const PROBE: OFlags = OFlags::RDONLY.union(OFlags::NONBLOCK);

/// Opens `name` under `base` as [`PROBE`] says, without following a link.
fn probe(base: BorrowedFd<'_>, name: &OsStr, path: &Path) -> Result<OwnedFd, TrustError> {
    or_unreadable(
        openat(
            base,
            name,
            PROBE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ),
        path,
    )
}

/// A component [`step`] opened and passed, with what `fstat` said of it.
type Passed = (OwnedFd, Stat);

/// One step of the walk: opens `name` under `base` without asking its
/// filesystem anything, judges the mount it is on, and only then checks its
/// kind, owner, and mode on the same descriptor.
///
/// The order is the point. On a user's FUSE mount the owner and mode are
/// whatever the daemon answers, an ordinary open waits on the daemon for as
/// long as it likes, and without `allow_other` root is refused outright. With
/// the mount judged first, the refusal names the mount, and the daemon is
/// never asked anything — neither here nor below, since nothing beneath a
/// component is looked up until it has passed.
fn step(
    base: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    is_last: bool,
    owner: u32,
    view: &dyn MountView,
    policy: MountPolicy,
) -> Result<Passed, TrustError> {
    let fd = probe(base, name, path)?;
    mounts::check(view, &[(path, fd.as_fd())], policy)?;
    checked(fd, path, is_last, owner)
}

/// The component check, on a descriptor whose mount has passed.
fn checked(fd: OwnedFd, path: &Path, is_last: bool, owner: u32) -> Result<Passed, TrustError> {
    or_unreadable(fstat(&fd), path).and_then(|stat| {
        check_component(path, &facts_of(&stat), is_last, owner).map(|()| (fd, stat))
    })
}

/// Opens a component that has passed once more, to be read, and refuses it
/// unless what opens is what passed.
///
/// Needed because nothing can be read or listed through `O_PATH`. By name, in
/// the directory the probe was opened in, which has passed and so only root
/// can write; and the device and inode must be the probe's, so a name pointed
/// elsewhere in between, or a mount laid over it, is refused rather than read.
/// The probe is held until that comparison, so its inode cannot be freed and
/// handed to another file meanwhile.
fn reopen(
    base: BorrowedFd<'_>,
    name: &OsStr,
    path: &Path,
    passed: Passed,
    directory: bool,
) -> Result<OwnedFd, TrustError> {
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    let (_held, then) = passed;
    or_unreadable(
        openat(base, name, flags, Mode::empty()).and_then(|fd| fstat(&fd).map(|now| (fd, now))),
        path,
    )
    .and_then(|(fd, now)| {
        if (now.st_dev, now.st_ino) == (then.st_dev, then.st_ino) {
            Ok(fd)
        } else {
            Err(TrustError::Replaced {
                at: path.display().to_string(),
            })
        }
    })
}

/// The name a component is opened by: its last element, or `/` for `/`.
fn name_of(path: &Path) -> &OsStr {
    path.file_name().unwrap_or(path.as_os_str())
}

/// Walks down to `target`'s parent, every component above it taken by [`step`]
/// relative to the one before, and each descriptor kept only until the next
/// is open.
///
/// Returns the parent — `None` when `target` is `/`, which has nothing above
/// it and is opened by its absolute name — and `target`'s own name, for the
/// caller's last step.
fn walk_above<'a>(
    target: &'a Path,
    owner: u32,
    view: &dyn MountView,
    policy: MountPolicy,
) -> Result<(Option<OwnedFd>, &'a OsStr), TrustError> {
    let chain = chain_to(target).ok_or_else(|| TrustError::NotAbsolute {
        at: target.display().to_string(),
    })?;
    let mut parent: Option<OwnedFd> = None;
    for path in chain.iter().take(chain.len().saturating_sub(1)) {
        let base = parent.as_ref().map_or(CWD, AsFd::as_fd);
        let (fd, _) = step(base, name_of(path), path, false, owner, view, policy)?;
        parent = Some(fd);
    }
    Ok((parent, name_of(target)))
}

/// Opens `target` read-only, having verified every component on the
/// descriptor it was opened through.
///
/// The walk starts at `/` and opens one component at a time relative to its
/// parent's descriptor, never following a link, and goes on from the
/// descriptor it checked, so there is no window in which a component can be
/// swapped after its check. The target, opened once more to be read, is
/// refused unless it is the inode that passed. This is the per-component
/// `O_NOFOLLOW` walk; `openat2`'s `RESOLVE_NO_SYMLINKS` would do the same in
/// one call where the kernel has it, and nothing is lost without it.
///
/// Each component's mount is judged before its owner and mode are believed,
/// and a mount whose owners cannot be believed is refused: a user's FUSE, an
/// idmapped mount, one the table does not list. `nosuid` and `noexec` are not
/// held against it, as they are against the ruleset: root's own mounts carry
/// them, `/run` on every systemd host among them. A ruleset is read with
/// [`read_trusted_dir`] or [`load_trusted_rules`], never through this.
///
/// # Errors
///
/// [`TrustError::NotAbsolute`] for a path that cannot be walked as written;
/// otherwise the outermost component that fails, on its mount
/// ([`TrustError::UntrustedMount`], [`TrustError::MountUnlisted`],
/// [`TrustError::MountTable`], [`TrustError::NamespacedRoot`]) or else as
/// [`verify`] would report it; and [`TrustError::Replaced`] for a target that
/// changed under the walk.
pub fn open_trusted(target: &Path) -> Result<OwnedFd, TrustError> {
    open_trusted_with(target, TRUSTED_UID, &HostMounts::proc())
}

/// [`open_trusted`], with the owner and the mount table as parameters so a test
/// can point it at what no test host has. The public functions always pass
/// [`TRUSTED_UID`] and the host's mounts.
fn open_trusted_with(
    target: &Path,
    owner: u32,
    view: &dyn MountView,
) -> Result<OwnedFd, TrustError> {
    let policy = MountPolicy::RootPath;
    let (parent, name) = walk_above(target, owner, view, policy)?;
    let base = parent.as_ref().map_or(CWD, AsFd::as_fd);
    let passed = step(base, name, target, true, owner, view, policy)?;
    reopen(base, name, target, passed, false)
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
/// Every component and every file is matched to its mount before anything its
/// filesystem says is believed and before a byte is read, and a mount a
/// non-root user could have made is refused, including one that merely
/// carries their marks, `nosuid` or `noexec`.
///
/// # Errors
///
/// The outermost component that fails, on its mount or its ownership, then
/// the first rule file that does, or any read failure.
pub fn read_trusted_dir(dir: &Path) -> Result<Vec<TrustedFile>, TrustError> {
    read_dir_with(dir, TRUSTED_UID, &HostMounts::proc())
}

/// [`read_trusted_dir`], with the owner and the mount table as parameters.
fn read_dir_with(
    dir: &Path,
    owner: u32,
    view: &dyn MountView,
) -> Result<Vec<TrustedFile>, TrustError> {
    let (parent, name) = walk_above(dir, owner, view, MountPolicy::Ruleset)?;
    read_from(
        parent.as_ref().map_or(CWD, AsFd::as_fd),
        name,
        dir,
        owner,
        view,
    )
}

/// Why the root-owned ruleset could not be loaded. Every variant fails closed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustedRulesError {
    /// A component of the path, or a rule file, failed the trust walk or the
    /// check of the mount it is on.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// The files were trusted but are not a ruleset.
    #[error(transparent)]
    Rules(#[from] RuleFilesError),
}

/// Loads the ruleset the way a privileged binary must: every component and
/// every rule file verified on the descriptor it is read through, then handed
/// to [`aido_policy::load_rule_files`], the function the front-end uses too.
///
/// The broker mints requests against this and the gate re-decides against it,
/// so the two compute the same [`aido_policy::Generation`] from the same bytes
/// and a spool entry is refused exactly when the rules really changed.
///
/// # Errors
///
/// [`TrustedRulesError::Trust`] for the first component or file that fails the
/// walk or the mount check, and [`TrustedRulesError::Rules`] for files that are
/// not a ruleset.
pub fn load_trusted_rules(dir: &Path) -> Result<LoadedRuleSet, TrustedRulesError> {
    load_rules_with(dir, TRUSTED_UID, &HostMounts::proc())
}

/// [`load_trusted_rules`], with the owner and the mount table as parameters.
fn load_rules_with(
    dir: &Path,
    owner: u32,
    view: &dyn MountView,
) -> Result<LoadedRuleSet, TrustedRulesError> {
    into_ruleset(read_dir_with(dir, owner, view)?)
}

/// Hands trusted files to the loader every reader shares.
fn into_ruleset(files: Vec<TrustedFile>) -> Result<LoadedRuleSet, TrustedRulesError> {
    let files = files
        .into_iter()
        .map(|file| RuleFile {
            name: file.name.into_vec(),
            bytes: file.bytes,
        })
        .collect();
    Ok(load_rule_files(files)?)
}

/// The walk's last step for a directory reader: the rules directory `name` in
/// `base`, judged like every component above it, then reopened to be listed,
/// and its rule files read.
///
/// The directory's mount is judged before it is listed, so not even a name is
/// taken from a filesystem whose mount is refused: a FUSE daemon would choose
/// the names, and with them which refusal is reported.
fn read_from(
    base: BorrowedFd<'_>,
    name: &OsStr,
    dir: &Path,
    owner: u32,
    view: &dyn MountView,
) -> Result<Vec<TrustedFile>, TrustError> {
    let passed = step(base, name, dir, true, owner, view, MountPolicy::Ruleset)?;
    let listed = reopen(base, name, dir, passed, true)?;
    read_rule_files(listed.as_fd(), dir, owner, view)
}

/// Every `*.toml` file in the open directory `dir`, each read through a
/// descriptor that is the file that passed.
///
/// Every file is opened as a probe first, which asks nothing of a filesystem
/// mounted on it, and their mounts are judged together — nothing but lookups
/// in `dir`, whose mount has passed, has happened yet. Only then is each
/// checked on its probe and reopened to be read, and none is read until every
/// one has passed. A file can be a mount point of its own, so its mount is its
/// own to judge.
fn read_rule_files(
    dir: BorrowedFd<'_>,
    path: &Path,
    owner: u32,
    view: &dyn MountView,
) -> Result<Vec<TrustedFile>, TrustError> {
    let probes = probe_rule_files(dir, path)?;
    let opened: Vec<(&Path, BorrowedFd<'_>)> = probes
        .iter()
        .map(|file| (file.path.as_path(), file.fd.as_fd()))
        .collect();
    mounts::check(view, &opened, MountPolicy::Ruleset)?;
    let files = probes
        .into_iter()
        .map(|file| file.pass(dir, owner))
        .collect::<Result<Vec<OpenedFile>, TrustError>>()?;
    files.into_iter().map(OpenedFile::read).collect()
}

/// A rule file that passed, opened to be read, not yet read.
struct OpenedFile {
    name: OsString,
    path: PathBuf,
    fd: OwnedFd,
}

impl OpenedFile {
    /// Reads the file through the descriptor it was reopened by, which is the
    /// file that passed.
    ///
    /// The component check refuses a link, a socket, a device, and a fifo. A
    /// directory named `*.toml` passes it, because a directory may be the last
    /// component of a path; it is refused here instead, by the read, which
    /// fails with EISDIR. Nothing else that passes the check can fail to read,
    /// so one refusal path covers both.
    fn read(self) -> Result<TrustedFile, TrustError> {
        let mut bytes = Vec::new();
        or_unreadable(
            std::fs::File::from(self.fd).read_to_end(&mut bytes),
            &self.path,
        )?;
        Ok(TrustedFile {
            name: self.name,
            bytes,
        })
    }
}

/// A rule file opened by [`probe`]: listed, its mount not yet judged, nothing
/// about it believed yet.
struct Probed {
    name: OsString,
    path: PathBuf,
    fd: OwnedFd,
}

impl Probed {
    /// Checks the file on its probe, once its mount has passed, and opens it
    /// again to be read.
    fn pass(self, dir: BorrowedFd<'_>, owner: u32) -> Result<OpenedFile, TrustError> {
        let Self { name, path, fd } = self;
        checked(fd, &path, true, owner)
            .and_then(|passed| reopen(dir, &name, &path, passed, false))
            .map(|fd| OpenedFile { name, path, fd })
    }
}

/// Lists `dir` and opens every `*.toml` file in it by [`probe`], in name
/// order. Believes nothing about them, and reads none of them.
fn probe_rule_files(dir: BorrowedFd<'_>, path: &Path) -> Result<Vec<Probed>, TrustError> {
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
        .filter(|name| is_rule_file_name(name))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let name = OsString::from_vec(name);
            let path = path.join(&name);
            probe(dir, &name, &path).map(|fd| Probed { name, path, fd })
        })
        .collect()
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

    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    use super::*;
    use crate::mounts::fake::{EXT4_ROOT, FakeMounts, Ids};

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

    /// What a socket address can hold: `sun_path` is 104 bytes on macOS and 108
    /// on Linux, and `bind` refuses a path that leaves no room for the closing
    /// NUL. The smaller figure, so one bound serves both.
    const SOCKET_ADDRESS_BYTES: usize = 104;

    /// Binds a Unix socket named `name` in `dir`, however long the path to
    /// `dir` is.
    ///
    /// The address `bind` copies into `sun_path` is a path. A checkout in a git
    /// worktree, or a copy under `/var/folders`, spells `dir` longer than that,
    /// and `bind` then fails with `path must be shorter than SUN_LEN`: the gate
    /// passed in one clone and failed in the next. So `bind` is given a short
    /// relative alias for `dir` — a symlink beside `target/test-tmp`, which the
    /// kernel follows when it creates the file — and the long path is only ever
    /// `stat`ed, which has no such limit. Cargo runs every unit test from the
    /// package directory, which is what lets the alias be spelled relative; the
    /// alias is gone again before this returns.
    fn bind_socket(dir: &Path, name: &str) -> UnixListener {
        static NEXT_ALIAS: AtomicUsize = AtomicUsize::new(0);
        let alias = Path::new("../../target/test-tmp").join(format!(
            "sun-{}-{}",
            std::process::id(),
            NEXT_ALIAS.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        // A stale alias from a run that died between the two calls below.
        let _ = std::fs::remove_file(&alias);
        std::os::unix::fs::symlink(dir, &alias).unwrap();
        let bound = UnixListener::bind(alias.join(name));
        std::fs::remove_file(&alias).unwrap();
        bound.unwrap()
    }

    #[test]
    fn a_test_socket_binds_under_a_path_longer_than_a_socket_address_can_hold() {
        // A checkout deep enough to overflow `sun_path`, made on purpose: the
        // fixture is proved against the failure it exists for, not against
        // whichever clone the suite happens to run in.
        let mut dir = test_dir("trust-deep");
        for _ in 0..3 {
            dir.push("d".repeat(80));
        }
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("sock");
        assert!(socket.as_os_str().len() > 2 * SOCKET_ADDRESS_BYTES);

        // The premise: std itself refuses this path as a socket address.
        let refused = UnixListener::bind(&socket).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);

        // The fixture does not, and what it makes is a socket, where it was
        // asked to make it.
        let listener = bind_socket(&dir, "sock");
        assert_eq!(stat_path(&socket).unwrap().kind, Kind::Other);
        drop(listener);
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
        let listener = bind_socket(&dir, "sock");
        assert_eq!(stat_path(&dir.join("sock")).unwrap().kind, Kind::Other);
        drop(listener);
    }

    #[test]
    fn the_stat_of_a_link_or_a_socket_is_never_taken_for_a_file() {
        // What the walk reads a component's kind from. On Linux its O_PATH
        // probe opens a link or a socket itself, and the stat of that
        // descriptor arrives here; it must say what the component is, never
        // what a link points at. Fed here from lstat, so every kind is seen on
        // every platform: macOS cannot open a link or a socket at all.
        let dir = test_dir("trust-kinds");
        let file = dir.join("file");
        std::fs::write(&file, "").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let listener = bind_socket(&dir, "sock");
        let sock = dir.join("sock");
        let kind = |path: &Path| {
            let stat =
                rustix::fs::statat(CWD, path, rustix::fs::AtFlags::SYMLINK_NOFOLLOW).unwrap();
            facts_of(&stat).kind
        };
        assert_eq!(kind(&dir), Kind::Directory);
        assert_eq!(kind(&file), Kind::File);
        assert_eq!(kind(&link), Kind::Symlink);
        assert_eq!(kind(&sock), Kind::Other);
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

    fn my_uid(dir: &Path) -> u32 {
        std::fs::metadata(dir).unwrap().uid()
    }

    /// Reads the rule files in a directory the test made, as `owner`: the
    /// files only, the directory itself neither judged nor checked.
    fn read_at(dir: &Path, owner: u32, view: &FakeMounts) -> Result<Vec<TrustedFile>, TrustError> {
        read_rule_files(open_dir(dir).as_fd(), dir, owner, view)
    }

    /// Reads a directory the test made, as `owner`, as the walk's last step
    /// does: the directory judged and checked from the one above it, then its
    /// rule files.
    fn read_step(
        dir: &Path,
        owner: u32,
        view: &FakeMounts,
    ) -> Result<Vec<TrustedFile>, TrustError> {
        let above = open_dir(dir.parent().unwrap());
        read_from(above.as_fd(), dir.file_name().unwrap(), dir, owner, view)
    }

    /// How a link where a rule file should be is refused. On Linux the walk
    /// opens the link itself, `O_PATH`, and refuses it for what it is; macOS
    /// has no `O_PATH`, and its open refuses to follow the link.
    #[cfg(target_os = "linux")]
    const LINK_REFUSED: &str = "is a symbolic link";
    #[cfg(not(target_os = "linux"))]
    const LINK_REFUSED: &str = "Too many levels of symbolic links";

    /// How a socket is refused: on Linux opened `O_PATH` and refused for what
    /// it is; macOS will not open one at all.
    #[cfg(target_os = "linux")]
    const SOCKET_REFUSED: &str = "is not a directory or a regular file";
    #[cfg(not(target_os = "linux"))]
    const SOCKET_REFUSED: &str = "Operation not supported on socket";

    #[test]
    fn a_root_owned_file_opens_through_verified_descriptors() {
        // On every platform, with the mount table a fake that accepts: what is
        // under test is the walk, and the walk does not depend on the host.
        let ext4 = FakeMounts::ext4();
        let fd = open_trusted_with(Path::new(TRUSTED_FILE), TRUSTED_UID, &ext4).unwrap();
        assert_eq!(facts_of(&fstat(&fd).unwrap()).kind, Kind::File);
        assert!(read_dir_with(Path::new("/usr/bin"), TRUSTED_UID, &ext4).is_ok());
        assert!(load_rules_with(Path::new("/usr/bin"), TRUSTED_UID, &ext4).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_the_real_mount_table_is_read_and_a_root_owned_path_is_trusted() {
        let fd = open_trusted(Path::new(TRUSTED_FILE)).unwrap();
        assert_eq!(facts_of(&fstat(&fd).unwrap()).kind, Kind::File);
        assert!(read_trusted_dir(Path::new("/usr/bin")).is_ok());
        // `/`, which holds no rule file on any host, so nothing is parsed: the
        // loader the broker will call, end to end against the real table.
        assert_eq!(load_trusted_rules(Path::new("/")).unwrap().rules.len(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_is_refused_as_a_home_for_rules_by_its_mount() {
        // Every component of /proc/sys is root's and writable by nobody else,
        // so the ownership walk passes; the real mount table says /proc is
        // mounted nosuid, as systemd and every container runtime mount it.
        let err = read_trusted_dir(Path::new("/proc/sys")).unwrap_err();
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: "/proc".to_owned(),
                fs_type: "proc".into(),
                mount_point: "/proc".into(),
                reason: MountRefusal::NoSuid,
            }
        );
        // Not refused to `open_trusted`, which every root-owned path goes
        // through: root made that nosuid mount, as systemd makes /run, where
        // the gate's spool is.
        assert!(open_trusted(Path::new("/proc/sys")).is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_nothing_is_trusted_because_no_mount_can_be_judged() {
        // The walk itself passes here; with no /proc there is no mount table,
        // and a ruleset whose mounts cannot be judged is not trusted.
        let refusals = [
            open_trusted(Path::new(TRUSTED_FILE)).unwrap_err(),
            read_trusted_dir(Path::new("/usr/bin")).unwrap_err(),
        ];
        for err in &refusals {
            assert!(
                err.to_string()
                    .starts_with("the mount table cannot be checked"),
                "{err}"
            );
            assert!(err.to_string().contains("not supported"), "{err}");
        }
        let err = load_trusted_rules(Path::new("/usr/bin")).unwrap_err();
        assert!(
            format!("{err:?}").starts_with("Trust(MountTable"),
            "{err:?}"
        );
    }

    #[test]
    fn a_fuse_mount_is_refused_even_when_every_owner_on_it_reads_as_root() {
        // The attack this check exists for: a directory on the path is the
        // user's, the user mounts sshfs over it, and the daemon answers every
        // stat with root:root 0755. The path here is a real root-owned one, so
        // its owners would pass exactly as the daemon's answers would; only
        // the mount table says who is answering, and it is asked first.
        let table = format!(
            "{EXT4_ROOT}7 1 0:75 / /usr/bin rw,nosuid,nodev,relatime - fuse.sshfs u@h:/ \
             rw,user_id=1000,group_id=1000\n"
        );
        let fuse = FakeMounts::new(&table, Ids::Each(vec![1, 1, 7, 7]));
        let err = open_trusted_with(Path::new(TRUSTED_FILE), TRUSTED_UID, &fuse).unwrap_err();
        // Named at the outermost component on the mount, /usr/bin.
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: "/usr/bin".to_owned(),
                fs_type: "fuse.sshfs".into(),
                mount_point: "/usr/bin".into(),
                reason: MountRefusal::FuseUser { uid: 1000 },
            }
        );
        // The directory reader asks about the same three components, plus any
        // rule file, and refuses at the same place.
        let fuse = FakeMounts::new(&table, Ids::Each(vec![1, 1, 7]));
        let dir_err = read_dir_with(Path::new("/usr/bin"), TRUSTED_UID, &fuse).unwrap_err();
        assert!(
            dir_err.to_string().starts_with("/usr/bin is on fuse.sshfs"),
            "{dir_err}"
        );
    }

    #[test]
    fn a_user_mount_over_the_target_file_itself_is_refused() {
        // fusermount3 mounts on a regular file a user can write as readily as
        // on a directory. Over a file left writable in a root-owned directory,
        // the daemon then answers its stat with root:root 0644 while every
        // directory above it really is root's: only the target is on the
        // user's mount, and a check that stopped at its parent would open it.
        let table = format!(
            "{EXT4_ROOT}7 1 0:75 / /usr/bin/true rw,nosuid,nodev,relatime - fuse.x x \
             rw,user_id=1000\n"
        );
        let fuse = FakeMounts::new(&table, Ids::Each(vec![1, 1, 1, 7]));
        let err = open_trusted_with(Path::new(TRUSTED_FILE), TRUSTED_UID, &fuse).unwrap_err();
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: TRUSTED_FILE.to_owned(),
                fs_type: "fuse.x".into(),
                mount_point: "/usr/bin/true".into(),
                reason: MountRefusal::FuseUser { uid: 1000 },
            }
        );
    }

    #[test]
    fn a_spool_on_a_nosuid_mount_opens_while_rules_there_are_refused() {
        // systemd mounts /run nosuid,nodev on every host, and the gate's spool
        // is /run/aido/req: refusing nosuid to every root-owned path would
        // refuse the spool on every real host, while a container, whose /run
        // is a directory on its root, never shows it. /usr stands in for /run
        // here, as a root-made tmpfs under a root-owned path every test host
        // has.
        let table = format!(
            "{EXT4_ROOT}25 1 0:24 / /usr rw,nosuid,nodev,relatime - tmpfs tmpfs rw,mode=755\n\
             26 1 0:25 / /usr/bin rw,nosuid,nodev,relatime - tmpfs tmpfs rw,mode=755\n"
        );
        let run = FakeMounts::new(&table, Ids::Each(vec![1, 25, 25, 25]));
        assert!(open_trusted_with(Path::new(TRUSTED_FILE), TRUSTED_UID, &run).is_ok());
        // The same mount under the rules is refused, by both ruleset readers:
        // nosuid is the mark of removable media and of a mount a user may
        // make, and the design plan holds it against /etc/aido. Above the
        // rules directory, or as the rules directory itself.
        let refused = |at: &str| TrustError::UntrustedMount {
            at: at.to_owned(),
            fs_type: "tmpfs".into(),
            mount_point: at.into(),
            reason: MountRefusal::NoSuid,
        };
        let run = FakeMounts::new(&table, Ids::Each(vec![1, 25, 25]));
        assert_eq!(
            read_dir_with(Path::new("/usr/bin"), TRUSTED_UID, &run),
            Err(refused("/usr"))
        );
        let run = FakeMounts::new(&table, Ids::Each(vec![1, 1, 26]));
        assert_eq!(
            read_dir_with(Path::new("/usr/bin"), TRUSTED_UID, &run),
            Err(refused("/usr/bin"))
        );
        let run = FakeMounts::new(&table, Ids::Each(vec![1, 1, 26]));
        assert_eq!(
            load_rules_with(Path::new("/usr/bin"), TRUSTED_UID, &run),
            Err(TrustedRulesError::Trust(refused("/usr/bin")))
        );
    }

    #[test]
    fn a_rule_file_bound_nosuid_over_the_ruleset_is_refused() {
        // A file can be a mount point of its own, and its mount is judged by
        // the ruleset's measure, not the directory's: a nosuid bind laid over
        // one rule file is refused though the directory's mount passes.
        let dir = scratch_dir("file-nosuid");
        std::fs::write(dir.join("10-a.toml"), "a").unwrap();
        std::fs::write(dir.join("20-b.toml"), "b").unwrap();
        let table = format!("{EXT4_ROOT}26 1 8:17 / /x rw,nosuid,relatime - ext4 /dev/sdb1 rw\n");
        let err = read_at(
            &dir,
            my_uid(&dir),
            &FakeMounts::new(&table, Ids::Each(vec![1, 26])),
        )
        .unwrap_err();
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: dir.join("20-b.toml").display().to_string(),
                fs_type: "ext4".into(),
                mount_point: "/x".into(),
                reason: MountRefusal::NoSuid,
            }
        );
    }

    #[test]
    fn the_owner_a_daemon_reports_is_never_asked_for_before_its_mount_is_refused() {
        // A user's daemon answers every stat on its mount: asked first, an
        // owner of its choosing (uid 4242 in the review's probe) is what the
        // operator would be told, and the mount never mentioned. Here the
        // directory's owner fails the check too, and the mount is what is
        // reported: judged first, on the descriptor opened before anything
        // was asked of the filesystem.
        let dir = scratch_dir("mount-before-owner");
        let table = format!("{EXT4_ROOT}7 1 0:75 / /x rw,relatime - fuse.x x rw,user_id=1000\n");
        let foreign = my_uid(&dir).wrapping_add(1);
        let err = read_step(&dir, foreign, &FakeMounts::new(&table, Ids::All(7))).unwrap_err();
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: dir.display().to_string(),
                fs_type: "fuse.x".into(),
                mount_point: "/x".into(),
                reason: MountRefusal::FuseUser { uid: 1000 },
            }
        );
        // On a mount that passes, the owner is checked, and refused.
        let err = read_step(&dir, foreign, &FakeMounts::ext4()).unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");
        // And a table that cannot be read refuses at the first component,
        // before any owner on the path is believed.
        let unreadable = FakeMounts {
            fail: Some(crate::error::SysError::read("fake", "the table was read")),
            ..FakeMounts::ext4()
        };
        let err = open_trusted_with(
            Path::new(env!("CARGO_MANIFEST_DIR")),
            TRUSTED_UID,
            &unreadable,
        )
        .unwrap_err();
        assert!(err.to_string().contains("the table was read"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn on_linux_a_component_nobody_may_open_is_still_refused_for_its_mount() {
        // Without allow_other, a user's FUSE mount refuses root itself: an
        // ordinary open, and fstat, both come back EACCES, and the operator
        // was told only "Permission denied". The walk's O_PATH open needs no
        // permission on the component, so its mount is judged all the same.
        // Mode 0000 stands in for the daemon's refusal.
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("mount-unopenable");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let openable = std::fs::read_dir(&dir).is_ok();
        let table = format!("{EXT4_ROOT}7 1 0:75 / /x rw,relatime - fuse.x x rw,user_id=1000\n");
        let outcome = read_step(&dir, my_uid(&dir), &FakeMounts::new(&table, Ids::All(7)));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Root opens anything, so the case is only observable without it.
        assert!(
            openable
                || outcome
                    .as_ref()
                    .is_err_and(|e| e.to_string().contains("is on fuse.x")),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_rule_file_on_a_refused_mount_is_refused_before_any_file_is_read() {
        // 20-b.toml is a directory, so reading it would fail with EISDIR. The
        // mount refusal arriving instead is the proof that every mount is
        // judged before a byte is read.
        let dir = scratch_dir("mount-file");
        std::fs::write(dir.join("10-a.toml"), "a").unwrap();
        std::fs::create_dir(dir.join("20-b.toml")).unwrap();
        let table = format!("{EXT4_ROOT}7 1 0:75 / /x rw,relatime - fuse.x x rw,user_id=1000\n");
        let fuse = FakeMounts::new(&table, Ids::Each(vec![1, 7]));
        let err = read_at(&dir, my_uid(&dir), &fuse).unwrap_err();
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: dir.join("20-b.toml").display().to_string(),
                fs_type: "fuse.x".into(),
                mount_point: "/x".into(),
                reason: MountRefusal::FuseUser { uid: 1000 },
            }
        );
        // And the directory itself is judged: on the refused mount, it fails
        // first.
        let fuse = FakeMounts::new(&table, Ids::All(7));
        let err = read_step(&dir, my_uid(&dir), &fuse).unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&format!("{} is on fuse.x", dir.display())),
            "{err}"
        );
    }

    #[test]
    fn a_directory_on_a_refused_mount_is_not_listed_so_its_daemon_cannot_pick_the_refusal() {
        // On a user's FUSE mount the daemon answers the listing and every
        // stat after it. Listed first, a file it reports as world-writable
        // would decide what the operator is told, under a name it chose. The
        // directory's mount is judged before a single name is read from it.
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("mount-unlisted-names");
        let file = dir.join("10-a.toml");
        std::fs::write(&file, "a").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        let table = format!("{EXT4_ROOT}7 1 0:75 / /x rw,relatime - fuse.x x rw,user_id=1000\n");
        let err = read_step(&dir, my_uid(&dir), &FakeMounts::new(&table, Ids::All(7))).unwrap_err();
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: dir.display().to_string(),
                fs_type: "fuse.x".into(),
                mount_point: "/x".into(),
                reason: MountRefusal::FuseUser { uid: 1000 },
            }
        );
        // On a mount that passes, the same file is refused for what it is.
        let err = read_step(&dir, my_uid(&dir), &FakeMounts::ext4()).unwrap_err();
        assert!(
            err.to_string().contains("writable by group or world"),
            "{err}"
        );
    }

    #[test]
    fn a_rule_file_replaced_after_it_passed_is_refused_rather_than_read() {
        // Between the check on a file's probe and the open it is read through,
        // its name is pointed at another file. The second open is compared
        // with the probe by device and inode, and the stranger is refused
        // unread, though it too is the test user's and mode 0644.
        let dir = scratch_dir("replaced");
        let (checked, stranger) = (dir.join("10-a.toml"), dir.join("stranger"));
        std::fs::write(&checked, "checked").unwrap();
        std::fs::write(&stranger, "never checked").unwrap();
        let (from, to) = (stranger.clone(), checked.clone());
        // The rule files' mounts are the only ones judged here, so the swap
        // happens while they are, after the probes opened the files.
        let swap = FakeMounts {
            meanwhile: Some(Box::new(move || {
                let _ = std::fs::rename(&from, &to);
            })),
            ..FakeMounts::ext4()
        };
        let err = read_at(&dir, my_uid(&dir), &swap).unwrap_err();
        assert_eq!(
            err,
            TrustError::Replaced {
                at: checked.display().to_string()
            }
        );
        assert!(
            err.to_string()
                .contains("changed while it was being checked")
        );
        // Undisturbed, the file that is there now is read.
        let files = read_at(&dir, my_uid(&dir), &FakeMounts::ext4()).unwrap();
        assert_eq!(files[0].bytes, b"never checked");
    }

    #[test]
    fn a_target_swapped_after_it_passed_is_refused_rather_than_opened() {
        // The same race on the walk's own target: the directory is judged
        // and checked, its name is pointed at another directory while its
        // mount is judged, and the reopen it would be listed through is
        // refused.
        let dir = scratch_dir("swapped-target");
        let (target, other) = (dir.join("rules.d"), dir.join("other"));
        std::fs::create_dir(&target).unwrap();
        std::fs::create_dir(&other).unwrap();
        let (from, to) = (other.clone(), target.clone());
        let swap = FakeMounts {
            meanwhile: Some(Box::new(move || {
                let _ = std::fs::rename(&from, &to);
            })),
            ..FakeMounts::ext4()
        };
        let err = read_step(&target, my_uid(&dir), &swap).unwrap_err();
        assert_eq!(
            err,
            TrustError::Replaced {
                at: target.display().to_string()
            }
        );
    }

    #[test]
    fn the_new_refusals_are_comparable_and_say_what_to_look_at() {
        let unlisted = TrustError::MountUnlisted {
            at: "/etc/aido".to_owned(),
            mount_id: 41,
        };
        assert_eq!(unlisted.clone(), unlisted);
        assert!(
            unlisted.to_string().starts_with("/etc/aido is on mount 41"),
            "{unlisted}"
        );
        let table = TrustError::MountTable {
            reason: "x".to_owned(),
        };
        assert!(table.to_string().ends_with(": x"), "{table}");
        assert!(format!("{table:?}").contains("MountTable"));
        let reason = MountRefusal::Idmapped;
        assert_eq!(reason.clone(), MountRefusal::Idmapped);
        assert!(format!("{reason:?}").contains("Idmapped"));
    }

    // The walk itself, through a mount table that accepts, on every platform:
    // off Linux the host's own table refuses at `/`, before the walk could
    // show anything.

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
        let err = open_trusted_with(Path::new(through_link), TRUSTED_UID, &FakeMounts::ext4())
            .unwrap_err();
        assert!(
            err.to_string().contains(LINK_REFUSED),
            "{through_link}: {err}"
        );
    }

    #[test]
    fn a_file_where_a_directory_must_be_is_refused_on_the_walk() {
        let err = open_trusted_with(
            &Path::new(TRUSTED_FILE).join("rules.d"),
            TRUSTED_UID,
            &FakeMounts::ext4(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            TrustError::AncestorNotDirectory {
                at: TRUSTED_FILE.to_owned()
            }
        );
    }

    #[test]
    fn a_missing_or_unsearchable_component_fails_closed() {
        let ext4 = FakeMounts::ext4();
        let err = open_trusted_with(Path::new("/usr/definitely-not-here"), TRUSTED_UID, &ext4)
            .unwrap_err();
        assert!(err.to_string().contains("cannot be inspected"), "{err}");

        // Root may search anything, so the refusal is only observable without it.
        let searchable = std::fs::read_dir(ROOT_ONLY).is_ok();
        let outcome = open_trusted_with(&Path::new(ROOT_ONLY).join("rules.d"), TRUSTED_UID, &ext4);
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
        let err = open_trusted_with(
            Path::new(env!("CARGO_MANIFEST_DIR")),
            TRUSTED_UID,
            &FakeMounts::ext4(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");
    }

    #[test]
    fn reading_a_file_as_a_directory_fails_closed() {
        // The file passes as the walk's last component, which may be a file;
        // the directory reader then reopens it as a directory to list it, and
        // that open refuses it, before anything is read.
        let err =
            read_dir_with(Path::new(TRUSTED_FILE), TRUSTED_UID, &FakeMounts::ext4()).unwrap_err();
        assert!(err.to_string().contains("cannot be inspected"), "{err}");
        assert!(err.to_string().contains(TRUSTED_FILE), "{err}");
    }

    #[test]
    fn a_descriptor_that_cannot_be_listed_is_refused_naming_it() {
        // The walk never hands the reader anything but a directory; a
        // descriptor that is not one is refused here all the same, before
        // anything is read through it.
        let dir = scratch_dir("unlistable");
        let file = dir.join("10-a.toml");
        std::fs::write(&file, "a").unwrap();
        let fd = rustix::fs::open(&file, OFlags::RDONLY, Mode::empty()).unwrap();
        let err =
            read_rule_files(fd.as_fd(), &file, my_uid(&dir), &FakeMounts::ext4()).unwrap_err();
        assert!(err.to_string().contains("cannot be inspected"), "{err}");
        assert!(err.to_string().contains("10-a.toml"), "{err}");
    }

    #[test]
    fn rule_files_are_read_in_order_through_their_own_descriptors() {
        let dir = scratch_dir("ordered");
        std::fs::write(dir.join("20-b.toml"), "b").unwrap();
        std::fs::write(dir.join("10-a.toml"), "a").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let me = my_uid(&dir);
        let ext4 = FakeMounts::ext4();
        let files = read_at(&dir, me, &ext4).unwrap();
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
        let err = read_at(&dir, me.wrapping_add(1), &ext4).unwrap_err();
        assert!(err.to_string().contains("10-a.toml"), "{err}");
    }

    #[test]
    fn the_trusted_ruleset_carries_the_generation_every_reader_computes() {
        let dir = scratch_dir("trusted-rules");
        std::fs::write(dir.join("10-a.toml"), "# a").unwrap();
        std::fs::write(dir.join(".toml"), "not selected by any reader").unwrap();
        let files = read_at(&dir, my_uid(&dir), &FakeMounts::ext4()).unwrap();
        let loaded = into_ruleset(files).unwrap();
        let expected = load_rule_files(vec![RuleFile {
            name: b"10-a.toml".to_vec(),
            bytes: b"# a".to_vec(),
        }])
        .unwrap();
        assert_eq!(loaded, expected);
    }

    #[test]
    fn a_trusted_but_malformed_ruleset_is_refused_naming_the_file() {
        let dir = scratch_dir("trusted-malformed");
        std::fs::write(dir.join("10-a.toml"), "[[action]\nid =").unwrap();
        let files = read_at(&dir, my_uid(&dir), &FakeMounts::ext4()).unwrap();
        let err = into_ruleset(files).unwrap_err();
        assert!(err.to_string().contains("10-a.toml"), "{err}");
        assert!(format!("{err:?}").starts_with("Rules("), "{err:?}");
    }

    #[test]
    fn an_untrusted_ruleset_is_refused_before_it_is_parsed() {
        // Someone else's file: the walk refuses it, and the parser never sees
        // bytes that are not root's.
        let dir = scratch_dir("trusted-foreign");
        std::fs::write(dir.join("10-a.toml"), "[[action]\nid =").unwrap();
        let foreign = my_uid(&dir).wrapping_add(1);
        let err = read_at(&dir, foreign, &FakeMounts::ext4()).unwrap_err();
        assert!(err.to_string().contains("not root"), "{err}");

        // And the loader walks from `/`: a file is not a directory of rules,
        // whoever owns it, and a checkout is not root's.
        let ext4 = FakeMounts::ext4();
        let err = load_rules_with(Path::new(TRUSTED_FILE), TRUSTED_UID, &ext4).unwrap_err();
        assert!(err.to_string().contains("cannot be inspected"), "{err}");
        assert!(format!("{err:?}").starts_with("Trust("), "{err:?}");
        assert!(
            load_rules_with(Path::new(env!("CARGO_MANIFEST_DIR")), TRUSTED_UID, &ext4)
                .unwrap_err()
                .to_string()
                .contains("not root"),
        );
    }

    #[test]
    fn a_rule_file_that_is_a_link_a_directory_or_a_socket_is_refused() {
        let cases: [(&str, &str); 3] = [
            ("link", LINK_REFUSED),
            ("dir", "Is a directory"),
            ("sock", SOCKET_REFUSED),
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
                // Bound through `bind_socket`: under a deep checkout — a git
                // worktree — the path to `dir` is longer than an address.
                _ => drop(bind_socket(&dir, "10-x.toml")),
            }
            let err = read_at(&dir, my_uid(&dir), &FakeMounts::ext4()).unwrap_err();
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
        let me = my_uid(&dir);
        let ext4 = FakeMounts::ext4();
        let err = read_at(&dir, me, &ext4).unwrap_err();
        assert!(
            err.to_string().contains("writable by group or world"),
            "{err}"
        );

        // Unreadable: the check passes on what `stat` sees, and the open still
        // refuses. Root reads anything, so this is only observable without it.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable = std::fs::read(&file).is_ok();
        let outcome = read_at(&dir, me, &ext4);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            readable || outcome.is_err_and(|e| e.to_string().contains("cannot be inspected")),
            "an unreadable rule file must refuse"
        );
    }
}
