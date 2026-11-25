//! Remove a path under a fixed tree, by descriptor, never by `/bin/rm`.
//!
//! The walk is one function over [`RemoveFs`]. A fake implements the trait in
//! memory, so every branch — symlink, mount, rename, hard link, limits — runs
//! on macOS. The Linux host is the only code that calls `openat2` and
//! `unlinkat`. It is behind `cfg(target_os = "linux")`. Other platforms fail
//! closed.
//!
//! Nothing here decides policy. The caller passes a tree, a relative target,
//! and an owner filter that `xudo-policy` already accepted. The walk still
//! refuses the tree root, a `..` component, a symlink component, a mount, and
//! an ancestor that is not root-owned and closed to group and other writes.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// `ENOENT`.
const ENOENT: i32 = 2;
/// `EXDEV`.
const EXDEV: i32 = 18;
/// `ENOTDIR`.
const ENOTDIR: i32 = 20;
/// `ELOOP`.
const ELOOP: i32 = 40;
/// `EBADF`.
const EBADF: i32 = 9;

/// Group and other write bits. An ancestor with either is not a safe tree.
const WRITABLE_BY_OTHERS: u32 = 0o022;

/// Domain separating this digest from every other SHA-256 in the project.
const PATH_DOMAIN: &[u8] = b"xudo.remove-path.paths.v1\0";

/// How many paths an audit record quotes before the rest exist only as a hash.
pub const AUDIT_PATH_HEAD: usize = 64;

/// Whose names the walk may unlink.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerPolicy {
    /// Any uid except root.
    AnyButRoot,
    /// Only these uids.
    Only(Vec<u32>),
}

/// What to remove, already checked by policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveRequest {
    /// Absolute tree. The directory itself is never removed.
    pub under: Vec<u8>,
    /// Path relative to `under`. No leading slash, no `..`, no empty component.
    pub relative: Vec<u8>,
    /// Whether a directory target is removed with its contents.
    pub recursive: bool,
    /// Deepest relative component count, measured from `under`.
    pub max_depth: u32,
    /// Most entries that may be removed.
    pub max_entries: u32,
    /// Owner filter.
    pub owners: OwnerPolicy,
    /// List the paths and unlink nothing.
    pub dry_run: bool,
}

/// What the walk did, or would have done.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveReport {
    /// Full paths, deepest first within each directory. The complete list.
    pub removed: Vec<Vec<u8>>,
    /// Sum of `st_size` of removed files and symlinks. Directories add nothing.
    pub bytes: u64,
    /// The walk stopped early. Already-removed names stay removed.
    pub partial: bool,
    /// The syscall or walk error that stopped a partial walk, when one did.
    pub error: Option<RemoveError>,
    /// Copied from the request so a record can tell a list from a deletion.
    pub dry_run: bool,
    /// SHA-256 of the full path list, length-framed.
    pub digest: [u8; 32],
}

/// Why the walk removed nothing.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RemoveError {
    /// This platform has no `openat2` walk.
    #[error("remove-path is not available on this platform")]
    Unsupported,
    /// The target is the tree itself.
    #[error("the tree root is never removed")]
    TreeRoot,
    /// The relative path is not a safe sequence of components.
    #[error("{0}")]
    BadTarget(&'static str),
    /// An ancestor is missing, not a directory, not root-owned, or writable
    /// by group or other.
    #[error(
        "an ancestor of the tree is not a root-owned directory closed to group and other writes"
    )]
    AncestorRefused,
    /// The operation tree itself is a mount point, detected by comparing its
    /// device with its opened parent at execution time.
    #[error("the operation tree is a mount point")]
    MountPoint,
    /// `recursive` is false and the target is a directory.
    #[error("a directory target needs recursive = true")]
    DirectoryRequiresRecursive,
    /// A system call failed.
    #[error("{op} failed with errno {errno}")]
    Os {
        /// Which call.
        op: &'static str,
        /// The errno, as a portable number.
        errno: i32,
    },
}

/// What an opened or looked-up node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A symlink. Never followed.
    Symlink,
    /// A socket, device, fifo, or anything else. Not removed.
    Other,
}

/// `fstat` / `lstat` facts the walk compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeStat {
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
    /// Owner.
    pub uid: u32,
    /// Permission bits.
    pub mode: u32,
    /// `st_size`.
    pub size: u64,
    /// `st_nlink`.
    pub nlink: u64,
    /// File type. A symlink is reported as a symlink, not its target.
    pub kind: NodeKind,
    /// The kernel says this is the root of a mount (`STATX_ATTR_MOUNT_ROOT`).
    /// A bind mount from the same filesystem shares `st_dev` with its parent
    /// and shows only here. Kernels before 5.8 never set it.
    pub mount_root: bool,
}

/// `STATX_ATTR_MOUNT_ROOT`.
#[cfg(any(target_os = "linux", test))]
const STATX_ATTR_MOUNT_ROOT: u64 = 0x2000;

/// True only when the kernel supports the attribute (`mask`) and sets it.
#[cfg(any(target_os = "linux", test))]
fn mount_root_bits(attributes: u64, mask: u64) -> bool {
    mask & attributes & STATX_ATTR_MOUNT_ROOT != 0
}

#[cfg(any(target_os = "linux", test))]
fn verify_dir_stat_result(
    result: Result<NodeStat, i32>,
    expected: NodeStat,
) -> Result<bool, RemoveError> {
    let actual = result.map_err(|errno| RemoveError::Os { op: "fstat", errno })?;
    Ok(actual.dev == expected.dev && actual.ino == expected.ino && actual.kind == NodeKind::Dir)
}

/// The syscalls the walk uses. One object, so the algorithm is not generic.
pub trait RemoveFs {
    /// Open `/` with `RESOLVE_NO_SYMLINKS`.
    ///
    /// # Errors
    ///
    /// Returns the failing syscall's error.
    fn open_root(&mut self) -> Result<u64, RemoveError>;

    /// Open one directory component. `beneath` selects
    /// `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`.
    /// Without it, only `RESOLVE_NO_SYMLINKS` is set. A symlink is `ELOOP`. A
    /// non-directory is `ENOTDIR`. Another filesystem with `beneath` is `EXDEV`.
    ///
    /// # Errors
    ///
    /// Returns the failing syscall's error.
    fn open_dir(&mut self, dir: u64, name: &[u8], beneath: bool) -> Result<u64, RemoveError>;

    /// `fstat` an opened descriptor.
    ///
    /// # Errors
    ///
    /// Returns the failing syscall's error.
    fn fstat(&mut self, fd: u64) -> Result<NodeStat, RemoveError>;

    /// Re-resolve a held directory from the pinned operation root and compare
    /// its inode. An empty relative path checks the root itself.
    ///
    /// # Errors
    ///
    /// Returns the failing descriptor or resolution syscall error.
    fn verify_dir(
        &mut self,
        root: u64,
        relative: &[u8],
        expected: NodeStat,
    ) -> Result<bool, RemoveError>;

    /// Close a directory token when its stack frame is done.
    ///
    /// # Errors
    ///
    /// Returns an error when the token is stale or the close operation fails.
    fn close(&mut self, fd: u64) -> Result<(), RemoveError>;

    /// `statat` with `AT_SYMLINK_NOFOLLOW`.
    ///
    /// # Errors
    ///
    /// Returns the failing syscall's error.
    fn lstat(&mut self, dir: u64, name: &[u8]) -> Result<NodeStat, RemoveError>;

    /// Up to `limit` directory entry names, without `.` and `..`, sorted
    /// among themselves. A larger directory is not read to the end.
    ///
    /// # Errors
    ///
    /// Returns the failing syscall's error.
    fn list(&mut self, dir: u64, limit: usize) -> Result<Vec<Vec<u8>>, RemoveError>;

    /// `unlinkat`. `directory` sets `AT_REMOVEDIR`. A symlink is removed only
    /// when `directory` is false: the call never follows the link.
    ///
    /// # Errors
    ///
    /// Returns the failing syscall's error.
    fn unlink(&mut self, dir: u64, name: &[u8], directory: bool) -> Result<(), RemoveError>;
}

/// SHA-256 of every removed path, length-framed, under a fixed domain.
pub fn removal_digest(paths: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PATH_DOMAIN);
    for path in paths {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path);
    }
    hasher.finalize().into()
}

/// The first [`AUDIT_PATH_HEAD`] paths. The digest covers the rest.
pub fn audit_path_head(paths: &[Vec<u8>]) -> &[Vec<u8>] {
    let end = paths.len().min(AUDIT_PATH_HEAD);
    paths.get(..end).unwrap_or(paths)
}

/// Run `req` on `fs`.
///
/// # Errors
///
/// A grammar failure, a refused ancestor, or an `under` that will not open
/// returns [`Err`] and removes nothing. A mismatch, mount, or limit during
/// the walk returns [`Ok`] with [`RemoveReport::partial`].
pub fn remove_path(
    fs: &mut dyn RemoveFs,
    req: &RemoveRequest,
) -> Result<RemoveReport, RemoveError> {
    let (under_fd, under_stat) = open_under(fs, &req.under)?;
    remove_from_open(fs, under_fd, under_stat, req)
}

/// The walk once `under` is an open directory the caller has already accepted.
fn remove_from_open(
    fs: &mut dyn RemoveFs,
    under_fd: u64,
    under_stat: NodeStat,
    req: &RemoveRequest,
) -> Result<RemoveReport, RemoveError> {
    let mut walk = Walk {
        fs,
        req,
        tree_dev: under_stat.dev,
        root_fd: under_fd,
        removed: Vec::new(),
        bytes: 0,
        partial: false,
        error: None,
    };
    let outcome = walk.remove_target(under_fd, under_stat);
    let report = walk.finish();
    match outcome {
        Ok(()) => Ok(report),
        Err(error) if !report.removed.is_empty() => {
            let mut partial = report;
            partial.partial = true;
            partial.error = Some(error);
            partial.digest = removal_digest(&partial.removed);
            Ok(partial)
        }
        Err(error) => Err(error),
    }
}

/// Open `under` from `/`, checking every ancestor on the descriptor.
fn open_under(fs: &mut dyn RemoveFs, under: &[u8]) -> Result<(u64, NodeStat), RemoveError> {
    let components = split_absolute(under)?;
    let mut dir = fs.open_root()?;
    let mut stat = fs.fstat(dir)?;
    if !ancestor_ok(&stat) {
        return Err(RemoveError::AncestorRefused);
    }
    for (index, name) in components.iter().enumerate() {
        let parent_dev = stat.dev;
        let parent = dir;
        dir = fs.open_dir(parent, name, false).map_err(|error| {
            if matches_errno(&error, ENOENT) || matches_errno(&error, ELOOP) {
                RemoveError::AncestorRefused
            } else {
                error
            }
        })?;
        stat = fs.fstat(dir)?;
        fs.close(parent)?;
        if !ancestor_ok(&stat) {
            return Err(RemoveError::AncestorRefused);
        }
        if index.saturating_add(1) == components.len()
            && (stat.dev != parent_dev || stat.mount_root)
        {
            return Err(RemoveError::MountPoint);
        }
    }
    Ok((dir, stat))
}

/// An entry that is neither `.` nor `..`; an error passes through.
#[cfg(target_os = "linux")]
fn keeps_entry<E>(name: &Result<Vec<u8>, E>) -> bool {
    !matches!(name, Ok(name) if name == b"." || name == b"..")
}

fn ancestor_ok(stat: &NodeStat) -> bool {
    stat.kind == NodeKind::Dir && stat.uid == 0 && stat.mode & WRITABLE_BY_OTHERS == 0
}

fn split_absolute(path: &[u8]) -> Result<Vec<Vec<u8>>, RemoveError> {
    if path.is_empty() || !path.starts_with(b"/") || path.contains(&0) || path.len() > 4096 {
        return Err(RemoveError::BadTarget("under is not a clean absolute path"));
    }
    if path == b"/" {
        return Err(RemoveError::TreeRoot);
    }
    let mut parts = Vec::new();
    for component in path.split(|byte| *byte == b'/').skip(1) {
        if component.is_empty() || component == b"." || component == b".." || component.len() > 255
        {
            return Err(RemoveError::BadTarget(
                "under has an empty, current, or parent component",
            ));
        }
        parts.push(component.to_vec());
    }
    Ok(parts)
}

fn split_relative(path: &[u8]) -> Result<Vec<Vec<u8>>, RemoveError> {
    if path.starts_with(b"/") || path.contains(&0) || path.len() > 4096 {
        return Err(RemoveError::BadTarget(
            "relative target is absolute or contains NUL",
        ));
    }
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = Vec::new();
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." || component.len() > 255
        {
            return Err(RemoveError::BadTarget(
                "relative target has an empty, current, or parent component",
            ));
        }
        parts.push(component.to_vec());
    }
    Ok(parts)
}

struct Walk<'a> {
    fs: &'a mut dyn RemoveFs,
    req: &'a RemoveRequest,
    tree_dev: u64,
    root_fd: u64,
    removed: Vec<Vec<u8>>,
    bytes: u64,
    partial: bool,
    error: Option<RemoveError>,
}

impl Walk<'_> {
    fn finish(&self) -> RemoveReport {
        RemoveReport {
            digest: removal_digest(&self.removed),
            removed: self.removed.clone(),
            bytes: self.bytes,
            partial: self.partial,
            error: self.error.clone(),
            dry_run: self.req.dry_run,
        }
    }

    fn at_cap(&self) -> bool {
        self.removed.len() >= usize::try_from(self.req.max_entries).unwrap_or(usize::MAX)
    }

    fn owner_ok(&self, uid: u32) -> bool {
        match &self.req.owners {
            OwnerPolicy::AnyButRoot => uid != 0,
            OwnerPolicy::Only(ids) => ids.contains(&uid),
        }
    }

    fn remove_target(&mut self, under_fd: u64, under_stat: NodeStat) -> Result<(), RemoveError> {
        let mut parts = split_relative(&self.req.relative)?;
        let Some(leaf) = parts.pop() else {
            return Err(RemoveError::TreeRoot);
        };
        let depth = u32::try_from(parts.len().saturating_add(1)).unwrap_or(u32::MAX);
        if depth > self.req.max_depth {
            return Err(RemoveError::BadTarget("target is deeper than max-depth"));
        }
        let mut dir = under_fd;
        let mut dir_stat = under_stat;
        let mut path = self.req.under.clone();
        for name in &parts {
            let parent = dir;
            dir = match self.fs.open_dir(parent, name, true) {
                Ok(fd) => fd,
                Err(error) if stop_errno(&error) => {
                    if parent != under_fd {
                        let _ = self.fs.close(parent);
                    }
                    self.partial = true;
                    return Ok(());
                }
                Err(error) => {
                    if parent != under_fd {
                        let _ = self.fs.close(parent);
                    }
                    return Err(error);
                }
            };
            dir_stat = self.fs.fstat(dir)?;
            if parent != under_fd {
                self.fs.close(parent)?;
            }
            if dir_stat.dev != self.tree_dev || dir_stat.kind != NodeKind::Dir {
                self.partial = true;
                return Ok(());
            }
            push_component(&mut path, name);
        }
        let result = self.remove_named(dir, dir_stat, &path, &leaf, depth, true);
        if dir != under_fd {
            self.fs.close(dir)?;
        }
        result
    }

    fn remove_named(
        &mut self,
        parent: u64,
        parent_stat: NodeStat,
        parent_path: &[u8],
        name: &[u8],
        depth: u32,
        is_target: bool,
    ) -> Result<(), RemoveError> {
        if self.at_cap() {
            self.partial = true;
            return Ok(());
        }
        let path = child_path(parent_path, name);
        match self.fs.open_dir(parent, name, true) {
            Ok(child) => {
                self.remove_directory(parent, parent_stat, child, name, &path, (depth, is_target))
            }
            Err(error) if matches_errno(&error, ENOTDIR) || matches_errno(&error, ELOOP) => {
                self.remove_leaf(parent, parent_stat, name, &path)
            }
            Err(error) if stop_errno(&error) => {
                self.partial = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn remove_directory(
        &mut self,
        parent: u64,
        parent_stat: NodeStat,
        child: u64,
        name: &[u8],
        path: &[u8],
        (depth, is_target): (u32, bool),
    ) -> Result<(), RemoveError> {
        let result = self.remove_directory_contents(
            parent,
            parent_stat,
            child,
            name,
            path,
            (depth, is_target),
        );
        self.fs.close(child)?;
        result
    }

    fn remove_directory_contents(
        &mut self,
        parent: u64,
        parent_stat: NodeStat,
        child: u64,
        name: &[u8],
        path: &[u8],
        (depth, is_target): (u32, bool),
    ) -> Result<(), RemoveError> {
        let stat = self.fs.fstat(child)?;
        if stat.dev != self.tree_dev || stat.kind != NodeKind::Dir {
            self.partial = true;
            return Ok(());
        }
        if !self.owner_ok(stat.uid) {
            return Ok(());
        }
        if is_target && !self.req.recursive {
            return Err(RemoveError::DirectoryRequiresRecursive);
        }
        let cap = usize::try_from(self.req.max_entries).unwrap_or(usize::MAX);
        let names = self.fs.list(child, cap.saturating_add(1))?;
        let truncated = names.len() > cap;
        for entry in &names {
            if self.partial || self.at_cap() {
                self.partial = true;
                return Ok(());
            }
            let next = depth.saturating_add(1);
            if next > self.req.max_depth {
                self.partial = true;
                return Ok(());
            }
            self.remove_named(child, stat, path, entry, next, false)?;
            if self.partial {
                return Ok(());
            }
        }
        if truncated {
            self.partial = true;
            return Ok(());
        }
        if !self.req.dry_run {
            let left = self.fs.list(child, 1)?;
            if !left.is_empty() {
                return Ok(());
            }
        }
        self.commit(
            parent,
            parent_stat,
            name,
            path,
            true,
            (stat.dev, stat.ino, 0),
        )
    }

    fn remove_leaf(
        &mut self,
        parent: u64,
        parent_stat: NodeStat,
        name: &[u8],
        path: &[u8],
    ) -> Result<(), RemoveError> {
        let stat = match self.fs.lstat(parent, name) {
            Ok(stat) => stat,
            Err(error) if stop_errno(&error) || matches_errno(&error, ENOENT) => {
                self.partial = true;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if stat.kind == NodeKind::Other {
            self.partial = true;
            return Ok(());
        }
        if stat.dev != self.tree_dev && stat.kind != NodeKind::Symlink {
            self.partial = true;
            return Ok(());
        }
        if !self.owner_ok(stat.uid) {
            return Ok(());
        }
        let directory = false;
        let size = stat.size;
        self.commit(
            parent,
            parent_stat,
            name,
            path,
            directory,
            (stat.dev, stat.ino, size),
        )
    }

    fn commit(
        &mut self,
        parent: u64,
        parent_stat: NodeStat,
        name: &[u8],
        path: &[u8],
        directory: bool,
        (dev, ino, size): (u64, u64, u64),
    ) -> Result<(), RemoveError> {
        if self.at_cap() {
            self.partial = true;
            return Ok(());
        }
        let parent_relative = relative_parent(&self.req.under, path);
        match self
            .fs
            .verify_dir(self.root_fd, &parent_relative, parent_stat)
        {
            Ok(true) => {}
            Ok(false) => {
                self.partial = true;
                return Ok(());
            }
            Err(error) if matches_errno(&error, ENOENT) || stop_errno(&error) => {
                self.partial = true;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        let leaf = match self.fs.lstat(parent, name) {
            Ok(stat) => stat,
            Err(error) if stop_errno(&error) || matches_errno(&error, ENOENT) => {
                self.partial = true;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let (directory, size) = if leaf.kind == NodeKind::Symlink {
            (false, leaf.size)
        } else if leaf.dev != dev || leaf.ino != ino || leaf.kind == NodeKind::Other {
            self.partial = true;
            return Ok(());
        } else {
            (directory, size)
        };
        if !self.owner_ok(leaf.uid) {
            return Ok(());
        }
        if !self.req.dry_run {
            self.fs.unlink(parent, name, directory)?;
        }
        self.bytes = self.bytes.saturating_add(size);
        self.removed.push(path.to_vec());
        Ok(())
    }
}

fn stop_errno(error: &RemoveError) -> bool {
    matches_errno(error, EXDEV) || matches_errno(error, ENOENT) || matches_errno(error, ELOOP)
}

fn matches_errno(error: &RemoveError, errno: i32) -> bool {
    let RemoveError::Os { errno: found, .. } = error else {
        return false;
    };
    *found == errno
}

fn push_component(path: &mut Vec<u8>, name: &[u8]) {
    // `under` is validated without a trailing slash, so a slash always joins.
    path.push(b'/');
    path.extend_from_slice(name);
}

fn relative_parent(under: &[u8], path: &[u8]) -> Vec<u8> {
    let Some(relative) = path
        .strip_prefix(under)
        .and_then(|rest| rest.strip_prefix(b"/"))
    else {
        return Vec::new();
    };
    relative
        .iter()
        .rposition(|byte| *byte == b'/')
        .and_then(|index| relative.get(..index))
        .map_or_else(Vec::new, <[u8]>::to_vec)
}

fn child_path(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut path = parent.to_vec();
    push_component(&mut path, name);
    path
}

/// The host walk. On Linux this is `openat2` and `unlinkat`. Elsewhere it
/// fails closed without touching a path.
///
/// # Errors
///
/// Returns the failing syscall's error.
pub fn remove_path_on_host(req: &RemoveRequest) -> Result<RemoveReport, RemoveError> {
    #[cfg(target_os = "linux")]
    {
        let mut host = LinuxRemoveFs::default();
        remove_path(&mut host, req)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = req;
        Err(RemoveError::Unsupported)
    }
}

/// Linux real-kernel hook used by the root lane to race a directory rename
/// immediately before its ancestry re-resolution.
///
/// # Errors
///
/// Returns the walk's refusal or syscall error.
#[cfg(all(target_os = "linux", feature = "root-tests"))]
pub fn remove_path_on_host_with_before_verify(
    req: &RemoveRequest,
    hook: impl FnMut(&[u8]) + 'static,
) -> Result<RemoveReport, RemoveError> {
    let mut host = LinuxRemoveFs {
        before_verify: Some(Box::new(hook)),
        ..LinuxRemoveFs::default()
    };
    remove_path(&mut host, req)
}

#[cfg(all(target_os = "linux", test))]
type BeforeUnlink = Box<dyn FnMut(&std::os::fd::OwnedFd, &[u8])>;

#[cfg(all(target_os = "linux", any(test, feature = "root-tests")))]
type BeforeVerify = Box<dyn FnMut(&[u8])>;

/// Linux `openat2` / `unlinkat` host. Not part of the macOS build.
#[cfg(target_os = "linux")]
struct LinuxRemoveFs {
    fds: BTreeMap<u64, std::os::fd::OwnedFd>,
    next: u64,
    #[cfg(test)]
    before_unlink: Option<BeforeUnlink>,
    #[cfg(any(test, feature = "root-tests"))]
    before_verify: Option<BeforeVerify>,
}

#[cfg(target_os = "linux")]
impl Default for LinuxRemoveFs {
    fn default() -> Self {
        Self {
            fds: BTreeMap::new(),
            next: 1,
            #[cfg(test)]
            before_unlink: None,
            #[cfg(any(test, feature = "root-tests"))]
            before_verify: None,
        }
    }
}

#[cfg(target_os = "linux")]
impl LinuxRemoveFs {
    fn insert(&mut self, fd: std::os::fd::OwnedFd) -> u64 {
        let token = self.next;
        self.next = self.next.saturating_add(1);
        self.fds.insert(token, fd);
        token
    }

    fn fd(&self, token: u64, op: &'static str) -> Result<&std::os::fd::OwnedFd, RemoveError> {
        self.fds
            .get(&token)
            .ok_or(RemoveError::Os { op, errno: EBADF })
    }
}

// The raw field widths differ by architecture, so the conversions are written
// to be infallible on every one of them and may be identities on some.
#[cfg(target_os = "linux")]
#[allow(clippy::useless_conversion)]
fn host_stat(stat: &rustix::fs::Stat) -> NodeStat {
    let mode = u32::from(stat.st_mode);
    NodeStat {
        dev: u64::from(stat.st_dev),
        ino: u64::from(stat.st_ino),
        uid: stat.st_uid,
        mode: mode & 0o7777,
        size: i64::from(stat.st_size).unsigned_abs(),
        nlink: u64::from(stat.st_nlink),
        kind: kind_of(mode),
        mount_root: false,
    }
}

#[cfg(target_os = "linux")]
fn kind_of(mode: u32) -> NodeKind {
    match rustix::fs::FileType::from_raw_mode(mode) {
        rustix::fs::FileType::Directory => NodeKind::Dir,
        rustix::fs::FileType::RegularFile => NodeKind::File,
        rustix::fs::FileType::Symlink => NodeKind::Symlink,
        _ => NodeKind::Other,
    }
}

#[cfg(target_os = "linux")]
fn host_err(op: &'static str) -> impl Fn(rustix::io::Errno) -> RemoveError {
    move |err| RemoveError::Os {
        op,
        errno: err.raw_os_error(),
    }
}

#[cfg(target_os = "linux")]
fn resolve_flags(beneath: bool) -> rustix::fs::ResolveFlags {
    let mut flags = rustix::fs::ResolveFlags::NO_SYMLINKS;
    if beneath {
        flags = flags
            .union(rustix::fs::ResolveFlags::BENEATH)
            .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
            .union(rustix::fs::ResolveFlags::NO_XDEV);
    }
    flags
}

#[cfg(target_os = "linux")]
fn open_at(
    parent: &std::os::fd::OwnedFd,
    name: &[u8],
    beneath: bool,
) -> Result<std::os::fd::OwnedFd, RemoveError> {
    rustix::fs::openat2(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
        resolve_flags(beneath),
    )
    .map_err(host_err("openat2"))
}

#[cfg(target_os = "linux")]
impl RemoveFs for LinuxRemoveFs {
    fn open_root(&mut self) -> Result<u64, RemoveError> {
        rustix::fs::openat2(
            rustix::fs::CWD,
            "/",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS,
        )
        .map(|fd| self.insert(fd))
        .map_err(host_err("openat2"))
    }

    fn open_dir(&mut self, dir: u64, name: &[u8], beneath: bool) -> Result<u64, RemoveError> {
        let opened = open_at(self.fd(dir, "openat2")?, name, beneath);
        opened.map(|fd| self.insert(fd))
    }

    fn fstat(&mut self, fd: u64) -> Result<NodeStat, RemoveError> {
        let fd = self.fd(fd, "fstat")?;
        rustix::fs::fstat(fd)
            .map_err(host_err("fstat"))
            .and_then(|raw| {
                rustix::fs::statx(
                    fd,
                    c"",
                    rustix::fs::AtFlags::EMPTY_PATH,
                    rustix::fs::StatxFlags::empty(),
                )
                .map_err(host_err("statx"))
                .map(|extra| NodeStat {
                    mount_root: mount_root_bits(
                        extra.stx_attributes.bits(),
                        extra.stx_attributes_mask.bits(),
                    ),
                    ..host_stat(&raw)
                })
            })
    }

    fn verify_dir(
        &mut self,
        root: u64,
        relative: &[u8],
        expected: NodeStat,
    ) -> Result<bool, RemoveError> {
        #[cfg(any(test, feature = "root-tests"))]
        if let Some(hook) = self.before_verify.as_mut() {
            hook(relative);
        }
        let root_fd = self.fd(root, "openat2")?;
        let opened = if relative.is_empty() {
            None
        } else {
            Some(open_at(root_fd, relative, true)?)
        };
        let fd = opened.as_ref().unwrap_or(root_fd);
        let stat = rustix::fs::fstat(fd)
            .map(|stat| host_stat(&stat))
            .map_err(rustix::io::Errno::raw_os_error);
        verify_dir_stat_result(stat, expected)
    }

    fn close(&mut self, fd: u64) -> Result<(), RemoveError> {
        self.fds.remove(&fd).map(|_| ()).ok_or(RemoveError::Os {
            op: "close",
            errno: EBADF,
        })
    }

    fn lstat(&mut self, dir: u64, name: &[u8]) -> Result<NodeStat, RemoveError> {
        let parent = self.fd(dir, "statat")?;
        rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .map(|stat| host_stat(&stat))
            .map_err(host_err("statat"))
    }

    fn list(&mut self, dir: u64, limit: usize) -> Result<Vec<Vec<u8>>, RemoveError> {
        let parent = self.fd(dir, "getdents")?;
        rustix::fs::Dir::read_from(parent)
            .and_then(|entries| {
                entries
                    .map(|entry| entry.map(|entry| entry.file_name().to_bytes().to_vec()))
                    .filter(keeps_entry)
                    .take(limit)
                    .collect::<Result<Vec<_>, _>>()
            })
            .map(|mut names| {
                names.sort_unstable();
                names
            })
            .map_err(host_err("getdents"))
    }

    fn unlink(&mut self, dir: u64, name: &[u8], directory: bool) -> Result<(), RemoveError> {
        #[cfg(test)]
        if let Some(hook) = self.before_unlink.as_mut()
            && let Some(fd) = self.fds.get(&dir)
        {
            hook(fd, name);
        }
        let parent = self.fd(dir, "unlinkat")?;
        let flags = if directory {
            rustix::fs::AtFlags::REMOVEDIR
        } else {
            rustix::fs::AtFlags::empty()
        };
        rustix::fs::unlinkat(parent, name, flags).map_err(host_err("unlinkat"))
    }
}

/// In-memory filesystem. Every attack the walk must refuse is built here.
#[cfg(any(test, feature = "fake"))]
#[derive(Clone, Debug)]
struct Node {
    dev: u64,
    ino: u64,
    uid: u32,
    mode: u32,
    kind: NodeKind,
    size: u64,
    nlink: u64,
    mount_root: bool,
    link: Vec<u8>,
    children: BTreeMap<Vec<u8>, u64>,
}

/// The fake. Methods the walk does not happen to call are still callable, and
/// a test calls each of them.
#[cfg(any(test, feature = "fake"))]
pub struct FakeRemoveFs {
    nodes: BTreeMap<u64, Node>,
    opens: BTreeMap<u64, u64>,
    next_fd: u64,
    next_ino: u64,
    diverge: Option<u64>,
    diverge_hits: u32,
    /// Before `unlink` of this name, replace the entry with a symlink to `ino`.
    swap: Option<(Vec<u8>, u64)>,
    unlinked: Vec<Vec<u8>>,
    /// The next `open_dir` fails with this errno, then the field clears.
    fail_open: Option<i32>,
    /// `(call name, calls to let through, errno)`.
    faults: Vec<(&'static str, usize, i32)>,
    /// This inode is on another device from the moment it is opened.
    remount: Option<(u64, u64)>,
    /// The owner the diverging inode reports from its second `stat` on.
    diverge_uid: Option<u32>,
    rename_out: Option<(Vec<u8>, Vec<u8>, bool)>,
}

#[cfg(any(test, feature = "fake"))]
impl FakeRemoveFs {
    /// A root directory, uid 0, mode `0755`, device 1.
    pub fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            1,
            Node {
                dev: 1,
                ino: 1,
                uid: 0,
                mode: 0o755,
                kind: NodeKind::Dir,
                size: 0,
                nlink: 2,
                mount_root: false,
                link: Vec::new(),
                children: BTreeMap::new(),
            },
        );
        Self {
            nodes,
            opens: BTreeMap::new(),
            next_fd: 1,
            next_ino: 2,
            diverge: None,
            diverge_hits: 0,
            swap: None,
            unlinked: Vec::new(),
            fail_open: None,
            faults: Vec::new(),
            remount: None,
            diverge_uid: None,
            rename_out: None,
        }
    }

    /// The `skip`-th next call of `op` (`"fstat"`, `"lstat"`, `"list"`,
    /// `"unlinkat"`, `"openat2"`) fails with `errno`; earlier calls pass.
    pub fn fail_at(&mut self, op: &'static str, skip: usize, errno: i32) {
        self.faults.push((op, skip, errno));
    }

    /// Change the permission bits of `ino`.
    pub fn set_mode(&mut self, ino: u64, mode: u32) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.mode = mode;
        }
    }

    /// `ino` moves to device `dev` the moment a directory open returns it.
    pub fn remount_on_open(&mut self, ino: u64, dev: u64) {
        self.remount = Some((ino, dev));
    }

    /// From the second `stat` on, the diverging inode also reports `uid`.
    pub fn diverge_uid_on_restat(&mut self, uid: u32) {
        self.diverge_uid = Some(uid);
    }

    fn fault(&mut self, op: &'static str) -> Result<(), RemoveError> {
        let mut hit = None;
        for (index, fault) in self.faults.iter_mut().enumerate() {
            if fault.0 != op {
                continue;
            }
            if fault.1 > 0 {
                fault.1 = fault.1.saturating_sub(1);
            } else {
                hit = Some(index);
            }
            break;
        }
        let Some(index) = hit else {
            return Ok(());
        };
        let (_, _, errno) = self.faults.remove(index);
        Err(RemoveError::Os { op, errno })
    }

    /// The next directory open fails with `errno` and is not rewritten.
    pub fn fail_next_open(&mut self, errno: i32) {
        self.fail_open = Some(errno);
    }

    /// Add a child. `parent` is a sequence of components under `/`.
    pub fn add(
        &mut self,
        parent: &[&[u8]],
        name: &[u8],
        kind: NodeKind,
        uid: u32,
        mode: u32,
        size: u64,
    ) -> u64 {
        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);
        let dev = self
            .ino_at(parent)
            .and_then(|parent_ino| self.nodes.get(&parent_ino).map(|node| node.dev))
            .unwrap_or(1);
        self.nodes.insert(
            ino,
            Node {
                dev,
                ino,
                uid,
                mode,
                kind,
                size,
                nlink: 1,
                mount_root: false,
                link: Vec::new(),
                children: BTreeMap::new(),
            },
        );
        self.link_name(parent, name, ino);
        ino
    }

    /// Another name for an existing inode. `nlink` grows by one.
    pub fn hardlink(&mut self, parent: &[&[u8]], name: &[u8], ino: u64) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.nlink = node.nlink.saturating_add(1);
        }
        self.link_name(parent, name, ino);
    }

    /// Put `ino` on another device, as a bind mount would.
    pub fn set_device(&mut self, ino: u64, dev: u64) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.dev = dev;
        }
    }

    /// Mark `ino` as a mount root on the same device, as a same-filesystem bind
    /// mount is.
    pub fn set_mount_root(&mut self, ino: u64) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.mount_root = true;
        }
    }

    /// The second `fstat` of this inode reports a different inode number.
    pub fn diverge_on_restat(&mut self, ino: u64) {
        self.diverge = Some(ino);
        self.diverge_hits = 0;
    }

    /// Move a directory out of its relative name immediately before ancestry
    /// verification, so the resolver observes a different tree entry.
    pub fn rename_out_before_verify(&mut self, relative: Vec<u8>, replacement: Vec<u8>) {
        self.rename_out = Some((relative, replacement, false));
    }

    /// Move a directory out and plant a different directory at its old name.
    pub fn replace_path_before_verify(&mut self, relative: Vec<u8>, replacement: Vec<u8>) {
        self.rename_out = Some((relative, replacement, true));
    }

    /// The next `unlink` of `name` first turns that entry into a symlink.
    pub fn swap_to_symlink_before_unlink(&mut self, name: Vec<u8>, target: u64) {
        self.swap = Some((name, target));
    }

    /// Whether `path` components still name something.
    pub fn exists(&self, path: &[&[u8]]) -> bool {
        self.ino_at(path).is_some()
    }

    /// The node at `path`, if any. Test-only: `Node` is not a public type.
    #[cfg(test)]
    fn node(&self, path: &[&[u8]]) -> Option<&Node> {
        self.ino_at(path).and_then(|ino| self.nodes.get(&ino))
    }

    /// Names passed to `unlink`, in order.
    pub fn unlinked(&self) -> &[Vec<u8>] {
        &self.unlinked
    }

    /// Number of currently open fake directory descriptors.
    pub fn open_count(&self) -> usize {
        self.opens.len()
    }

    fn ino_at(&self, path: &[&[u8]]) -> Option<u64> {
        let mut ino = 1u64;
        for name in path {
            ino = self
                .nodes
                .get(&ino)
                .and_then(|node| node.children.get(*name))
                .copied()?;
        }
        Some(ino)
    }

    fn link_name(&mut self, parent: &[&[u8]], name: &[u8], ino: u64) {
        if let Some(parent_ino) = self.ino_at(parent) {
            self.nodes
                .entry(parent_ino)
                .and_modify(|node| _ = node.children.insert(name.to_vec(), ino));
        }
    }

    /// Replace the entry `name` of `parent` with a symlink like `target`.
    fn swap_in(&mut self, parent: u64, name: Vec<u8>, target: u64) {
        let old = self
            .nodes
            .get(&parent)
            .and_then(|node| node.children.get(&name).copied());
        if let Some(old) = old {
            self.nodes
                .entry(old)
                .and_modify(|node| node.nlink = node.nlink.saturating_sub(1));
        }
        let link = self
            .nodes
            .get(&target)
            .map(|node| node.link.clone())
            .unwrap_or_default();
        let ino = self.next_ino;
        self.next_ino = self.next_ino.saturating_add(1);
        self.nodes.insert(
            ino,
            Node {
                dev: 1,
                ino,
                uid: 1000,
                mode: 0o777,
                kind: NodeKind::Symlink,
                size: link.len() as u64,
                nlink: 1,
                mount_root: false,
                link,
                children: BTreeMap::new(),
            },
        );
        self.nodes
            .entry(parent)
            .and_modify(|node| _ = node.children.insert(name, ino));
    }

    /// Drop the record of `ino` but keep the names that point at it, as a
    /// corrupt table would.
    pub fn forget(&mut self, ino: u64) {
        self.nodes.remove(&ino);
    }

    /// The child `name` of the open directory `dir`, and the device of `dir`.
    fn lookup(&self, dir: u64, name: &[u8]) -> Result<(u64, u64), RemoveError> {
        let parent = self.opens.get(&dir).ok_or(RemoveError::Os {
            op: "openat2",
            errno: EBADF,
        })?;
        let node = self.nodes.get(parent).ok_or(RemoveError::Os {
            op: "openat2",
            errno: ENOENT,
        })?;
        let child = node.children.get(name).ok_or(RemoveError::Os {
            op: "openat2",
            errno: ENOENT,
        })?;
        Ok((*child, node.dev))
    }

    fn stat_of(&mut self, ino: u64) -> Result<NodeStat, RemoveError> {
        let node = self.nodes.get(&ino).ok_or(RemoveError::Os {
            op: "fstat",
            errno: ENOENT,
        })?;
        let mut stat = NodeStat {
            dev: node.dev,
            ino: node.ino,
            uid: node.uid,
            mode: node.mode,
            size: node.size,
            nlink: node.nlink,
            kind: node.kind,
            mount_root: node.mount_root,
        };
        if self.diverge == Some(ino) {
            self.diverge_hits = self.diverge_hits.saturating_add(1);
            if self.diverge_hits >= 2 {
                stat.ino = stat.ino.saturating_add(1000);
                if let Some(uid) = self.diverge_uid {
                    stat.uid = uid;
                }
            }
        }
        Ok(stat)
    }
}

#[cfg(any(test, feature = "fake"))]
impl Default for FakeRemoveFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "fake"))]
impl RemoveFs for FakeRemoveFs {
    fn open_root(&mut self) -> Result<u64, RemoveError> {
        self.fault("openat2")?;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        self.opens.insert(fd, 1);
        Ok(fd)
    }

    fn open_dir(&mut self, dir: u64, name: &[u8], beneath: bool) -> Result<u64, RemoveError> {
        self.fault("openat2")?;
        if let Some(errno) = self.fail_open.take() {
            return Err(RemoveError::Os {
                op: "openat2",
                errno,
            });
        }
        let (ino, parent_dev) = self.lookup(dir, name)?;
        let node = self.nodes.get(&ino).ok_or(RemoveError::Os {
            op: "openat2",
            errno: ENOENT,
        })?;
        if node.kind == NodeKind::Symlink {
            return Err(RemoveError::Os {
                op: "openat2",
                errno: ELOOP,
            });
        }
        if node.kind != NodeKind::Dir {
            return Err(RemoveError::Os {
                op: "openat2",
                errno: ENOTDIR,
            });
        }
        if beneath && node.dev != parent_dev {
            return Err(RemoveError::Os {
                op: "openat2",
                errno: EXDEV,
            });
        }
        if let Some((moved, dev)) = self.remount
            && moved == ino
            && let Some(node) = self.nodes.get_mut(&ino)
        {
            node.dev = dev;
        }
        let fd = self.next_fd;
        self.next_fd = self.next_fd.saturating_add(1);
        self.opens.insert(fd, ino);
        Ok(fd)
    }

    fn fstat(&mut self, fd: u64) -> Result<NodeStat, RemoveError> {
        self.fault("fstat")?;
        let ino = self.opens.get(&fd).copied().ok_or(RemoveError::Os {
            op: "fstat",
            errno: EBADF,
        })?;
        self.stat_of(ino)
    }

    fn verify_dir(
        &mut self,
        root: u64,
        relative: &[u8],
        expected: NodeStat,
    ) -> Result<bool, RemoveError> {
        self.fault("verify_dir")?;
        let root_ino = self.opens.get(&root).copied().ok_or(RemoveError::Os {
            op: "openat2",
            errno: EBADF,
        })?;
        if let Some((moved, replacement, replace_original)) = self.rename_out.clone()
            && moved == relative
        {
            self.rename_out = None;
            let mut components = relative.split(|byte| *byte == b'/');
            let leaf = components.next_back().unwrap_or_default();
            let parent = components.fold(root_ino, |at, component| {
                self.nodes
                    .get(&at)
                    .and_then(|node| node.children.get(component))
                    .copied()
                    .unwrap_or(0)
            });
            let moved_ino = self
                .nodes
                .get_mut(&parent)
                .and_then(|node| node.children.remove(leaf));
            if let Some(moved_ino) = moved_ino {
                self.nodes
                    .entry(parent)
                    .and_modify(|node| _ = node.children.insert(replacement, moved_ino));
                if replace_original {
                    let replacement_ino = self.next_ino;
                    self.next_ino = self.next_ino.saturating_add(1);
                    let parent_dev = self.nodes.get(&parent).map_or(1, |node| node.dev);
                    self.nodes.insert(
                        replacement_ino,
                        Node {
                            dev: parent_dev,
                            ino: replacement_ino,
                            uid: 1000,
                            mode: 0o755,
                            kind: NodeKind::Dir,
                            size: 0,
                            nlink: 2,
                            mount_root: false,
                            link: Vec::new(),
                            children: BTreeMap::new(),
                        },
                    );
                    self.nodes.entry(parent).and_modify(|node| {
                        _ = node.children.insert(leaf.to_vec(), replacement_ino);
                    });
                }
            }
        }
        let mut ino = root_ino;
        if !relative.is_empty() {
            for component in relative.split(|byte| *byte == b'/') {
                ino = self
                    .nodes
                    .get(&ino)
                    .and_then(|node| node.children.get(component))
                    .copied()
                    .ok_or(RemoveError::Os {
                        op: "openat2",
                        errno: ENOENT,
                    })?;
            }
        }
        let stat = self.stat_of(ino)?;
        Ok(stat.dev == expected.dev && stat.ino == expected.ino && stat.kind == NodeKind::Dir)
    }

    fn close(&mut self, fd: u64) -> Result<(), RemoveError> {
        self.fault("close")?;
        self.opens.remove(&fd).map(|_| ()).ok_or(RemoveError::Os {
            op: "close",
            errno: EBADF,
        })
    }

    fn lstat(&mut self, dir: u64, name: &[u8]) -> Result<NodeStat, RemoveError> {
        self.fault("lstat")?;
        let (ino, _) = self.lookup(dir, name)?;
        self.stat_of(ino)
    }

    fn list(&mut self, dir: u64, limit: usize) -> Result<Vec<Vec<u8>>, RemoveError> {
        self.fault("list")?;
        let ino = self.opens.get(&dir).ok_or(RemoveError::Os {
            op: "getdents",
            errno: EBADF,
        })?;
        Ok(self
            .nodes
            .get(ino)
            .map(|node| node.children.keys().take(limit).cloned().collect())
            .unwrap_or_default())
    }

    fn unlink(&mut self, dir: u64, name: &[u8], directory: bool) -> Result<(), RemoveError> {
        self.fault("unlinkat")?;
        let parent = *self.opens.get(&dir).ok_or(RemoveError::Os {
            op: "unlinkat",
            errno: EBADF,
        })?;
        if let Some((swap_name, target)) = self.swap.clone()
            && swap_name == name
        {
            self.swap = None;
            self.swap_in(parent, swap_name, target);
        }
        let (child, kind) = self
            .nodes
            .get(&parent)
            .and_then(|node| node.children.get(name))
            .and_then(|child| self.nodes.get(child))
            .map(|node| (node.ino, node.kind))
            .ok_or(RemoveError::Os {
                op: "unlinkat",
                errno: ENOENT,
            })?;
        if directory && kind != NodeKind::Dir {
            return Err(RemoveError::Os {
                op: "unlinkat",
                errno: ENOTDIR,
            });
        }
        if !directory && kind == NodeKind::Dir {
            return Err(RemoveError::Os {
                op: "unlinkat",
                errno: 21, // EISDIR
            });
        }
        self.nodes.entry(parent).and_modify(|node| {
            node.children.remove(name);
        });
        self.nodes
            .entry(child)
            .and_modify(|node| node.nlink = node.nlink.saturating_sub(1));
        self.unlinked.push(name.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_remove_path_fails_closed() {
        assert_eq!(
            remove_path_on_host(&req("x")).unwrap_err(),
            RemoveError::Unsupported
        );
    }

    fn tree() -> (FakeRemoveFs, u64) {
        let mut fs = FakeRemoveFs::new();
        fs.add(&[], b"srv", NodeKind::Dir, 0, 0o755, 0);
        fs.add(&[b"srv"], b"app", NodeKind::Dir, 0, 0o755, 0);
        let under = fs.add(&[b"srv", b"app"], b"build", NodeKind::Dir, 0, 0o755, 0);
        (fs, under)
    }

    fn req(relative: &str) -> RemoveRequest {
        RemoveRequest {
            under: b"/srv/app/build".to_vec(),
            relative: relative.as_bytes().to_vec(),
            recursive: true,
            max_depth: 8,
            max_entries: 100,
            owners: OwnerPolicy::AnyButRoot,
            dry_run: false,
        }
    }

    #[test]
    fn a_symlink_planted_by_the_agent_is_never_followed() {
        let (mut fs, _) = tree();
        let secret = fs.add(&[], b"secret", NodeKind::File, 1000, 0o644, 4);
        fs.nodes
            .entry(secret)
            .and_modify(|node| node.link = b"/secret".to_vec());
        fs.add(
            &[b"srv", b"app", b"build"],
            b"sub",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        let link = fs.add(
            &[b"srv", b"app", b"build", b"sub"],
            b"link",
            NodeKind::Symlink,
            1000,
            0o777,
            7,
        );
        fs.nodes
            .entry(link)
            .and_modify(|node| node.link = b"/secret".to_vec());
        fs.add(
            &[b"srv", b"app", b"build", b"sub"],
            b"file",
            NodeKind::File,
            1000,
            0o644,
            3,
        );
        let report = remove_path(&mut fs, &req("sub")).unwrap();
        assert!(!report.partial);
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"sub"]));
        assert!(fs.exists(&[b"secret"]));
        assert_eq!(fs.node(&[b"secret"]).unwrap().nlink, 1);

        let (mut fs, _) = tree();
        let secret = fs.add(&[], b"secret", NodeKind::File, 1000, 0o644, 4);
        let link = fs.add(
            &[b"srv", b"app", b"build"],
            b"link",
            NodeKind::Symlink,
            1000,
            0o777,
            7,
        );
        fs.nodes
            .entry(link)
            .and_modify(|node| node.link = b"/secret".to_vec());
        let planted = remove_path(&mut fs, &req("link/secret"));
        assert!(planted.is_err() || planted.unwrap().removed.is_empty());
        assert!(fs.exists(&[b"secret"]));
        assert_eq!(fs.node(&[b"secret"]).unwrap().ino, secret);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"link"]));
    }

    #[test]
    fn a_trailing_slash_through_a_symlink_is_refused() {
        let (mut fs, _) = tree();
        let secret = fs.add(&[], b"secret", NodeKind::File, 1000, 0o644, 9);
        let link = fs.add(
            &[b"srv", b"app", b"build"],
            b"link",
            NodeKind::Symlink,
            1000,
            0o777,
            7,
        );
        fs.nodes
            .entry(link)
            .and_modify(|node| node.link = b"/secret".to_vec());
        let error = remove_path(&mut fs, &req("link/")).unwrap_err();
        assert_eq!(
            error,
            RemoveError::BadTarget("relative target has an empty, current, or parent component")
        );
        assert!(fs.exists(&[b"secret"]));
        assert_eq!(fs.node(&[b"secret"]).unwrap().ino, secret);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"link"]));
        assert!(fs.unlinked().is_empty());
    }

    #[test]
    fn a_bind_mount_under_the_tree_is_not_crossed() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"box"],
            b"a",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        let mnt = fs.add(
            &[b"srv", b"app", b"build", b"box"],
            b"mnt",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.set_device(mnt, 9);
        fs.add(
            &[b"srv", b"app", b"build", b"box", b"mnt"],
            b"inside",
            NodeKind::File,
            1000,
            0o644,
            5,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"box"],
            b"z",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(report.partial);
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"mnt"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"mnt", b"inside"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"z"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box"]));
    }

    #[test]
    fn a_tree_that_is_a_mount_point_is_refused() {
        let (mut fs, tree_root) = tree();
        fs.set_device(tree_root, 9);
        assert_eq!(
            remove_path(&mut fs, &req("item")).unwrap_err(),
            RemoveError::MountPoint
        );
        assert!(fs.unlinked().is_empty());
    }

    #[test]
    fn a_same_device_bind_mount_as_the_tree_is_refused() {
        let (mut fs, tree_root) = tree();
        fs.set_mount_root(tree_root);
        fs.set_mount_root(9999);
        assert_eq!(
            remove_path(&mut fs, &req("item")).unwrap_err(),
            RemoveError::MountPoint
        );
        assert!(fs.unlinked().is_empty());
    }

    #[test]
    fn mount_root_needs_kernel_support_and_the_attribute() {
        assert!(mount_root_bits(0x2000, 0x2000));
        assert!(!mount_root_bits(0x2000, 0));
        assert!(!mount_root_bits(0, 0x2000));
        assert!(!mount_root_bits(0xdfff, 0xffff));
    }

    #[test]
    fn a_directory_renamed_out_mid_walk_stops_the_walk() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"cache",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"cache"],
            b"a",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"cache"],
            b"b",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        fs.rename_out_before_verify(b"cache".to_vec(), b"moved-cache".to_vec());
        let report = remove_path(&mut fs, &req("cache")).unwrap();
        assert!(report.partial);
        assert!(report.removed.is_empty());
        assert!(fs.exists(&[b"srv", b"app", b"build", b"moved-cache", b"a"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"moved-cache", b"b"]));
    }

    #[test]
    fn a_nested_directory_renamed_out_mid_walk_stops_the_walk() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(&BOX, b"sub", NodeKind::Dir, 1000, 0o755, 0);
        fs.add(
            &[b"srv", b"app", b"build", b"box", b"sub"],
            b"a",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        fs.rename_out_before_verify(b"box/sub".to_vec(), b"moved-sub".to_vec());
        let report = remove_path(&mut fs, &req("box/sub/a")).unwrap();
        assert!(report.partial);
        assert!(report.removed.is_empty());
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"moved-sub", b"a"]));
    }

    #[test]
    fn a_stale_rename_hook_with_a_missing_parent_fails_closed() {
        let mut fs = FakeRemoveFs::new();
        let root = fs.open_root().unwrap();
        let expected = fs.fstat(root).unwrap();
        fs.rename_out_before_verify(b"missing/sub".to_vec(), b"moved-sub".to_vec());
        assert_eq!(
            fs.verify_dir(root, b"missing/sub", expected).unwrap_err(),
            os("openat2", ENOENT)
        );
        fs.close(root).unwrap();
    }

    #[test]
    fn a_swap_to_a_symlink_between_resolve_and_unlink_removes_only_the_link() {
        let (mut fs, _) = tree();
        let secret = fs.add(&[], b"secret", NodeKind::File, 1000, 0o644, 11);
        fs.nodes
            .entry(secret)
            .and_modify(|node| node.link = b"/secret".to_vec());
        fs.add(
            &[b"srv", b"app", b"build"],
            b"victim",
            NodeKind::File,
            1000,
            0o644,
            2,
        );
        fs.swap_to_symlink_before_unlink(b"victim".to_vec(), secret);
        let report = remove_path(&mut fs, &req("victim")).unwrap();
        assert!(!report.partial);
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"victim"]));
        assert!(fs.exists(&[b"secret"]));
        assert_eq!(fs.node(&[b"secret"]).unwrap().size, 11);
        assert_eq!(fs.unlinked(), &[b"victim".to_vec()]);
    }

    #[test]
    fn a_hardlink_to_a_root_file_is_unlinked_and_the_file_survives() {
        let (mut fs, _) = tree();
        let root_file = fs.add(&[], b"root-file", NodeKind::File, 0, 0o644, 6);
        fs.hardlink(&[b"srv", b"app", b"build"], b"alias", root_file);
        let mut request = req("alias");
        request.owners = OwnerPolicy::Only(vec![0]);
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(!report.partial);
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"alias"]));
        assert!(fs.exists(&[b"root-file"]));
        assert_eq!(fs.node(&[b"root-file"]).unwrap().nlink, 1);
        assert_eq!(fs.node(&[b"root-file"]).unwrap().ino, root_file);
    }

    #[test]
    fn a_file_named_dash_rf_is_only_a_name() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"-rf",
            NodeKind::File,
            1000,
            0o644,
            2,
        );
        let report = remove_path(&mut fs, &req("-rf")).unwrap();
        assert_eq!(report.removed.len(), 1);
        assert_eq!(report.removed.first().unwrap(), b"/srv/app/build/-rf");
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"-rf"]));
        assert!(fs.exists(&[b"srv"]));
    }

    #[test]
    fn the_tree_root_is_never_removed() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"a",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        let mut request = req("");
        request.relative.clear();
        let error = remove_path(&mut fs, &request).unwrap_err();
        assert_eq!(error, RemoveError::TreeRoot);
        assert!(fs.exists(&[b"srv", b"app", b"build"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"a"]));
        let mut root = req("/");
        root.under = b"/".to_vec();
        root.relative = b"srv".to_vec();
        // `/` has no component, so opening it as `under` is the tree root.
        root.under = b"/".to_vec();
        let error = remove_path(&mut fs, &root).unwrap_err();
        assert_eq!(error, RemoveError::TreeRoot);
        assert!(fs.exists(&[b"srv"]));
    }

    #[test]
    fn stops_at_max_entries_and_reports_partial() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        for name in [b"a".as_slice(), b"b", b"c", b"d", b"e"] {
            fs.add(
                &[b"srv", b"app", b"build", b"box"],
                name,
                NodeKind::File,
                1000,
                0o644,
                1,
            );
        }
        let mut request = req("box");
        request.max_entries = 2;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.partial);
        assert_eq!(report.removed.len(), 2);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box"]));
        let left = ["a", "b", "c", "d", "e"]
            .into_iter()
            .filter(|name| fs.exists(&[b"srv", b"app", b"build", b"box", name.as_bytes()]))
            .count();
        assert_eq!(left, 3);
    }

    #[test]
    fn dry_run_removes_nothing() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"a",
            NodeKind::File,
            1000,
            0o644,
            4,
        );
        fs.add(
            &[b"srv", b"app", b"build"],
            b"b",
            NodeKind::File,
            1000,
            0o644,
            5,
        );
        let mut request = req("a");
        request.dry_run = true;
        let one = remove_path(&mut fs, &request).unwrap();
        assert!(one.dry_run);
        assert!(!one.partial);
        assert_eq!(one.removed, vec![b"/srv/app/build/a".to_vec()]);
        assert_eq!(one.bytes, 4);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"a"]));
        assert!(fs.unlinked().is_empty());
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"box"],
            b"c",
            NodeKind::File,
            1000,
            0o644,
            6,
        );
        let mut request = req("box");
        request.dry_run = true;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.dry_run);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"c"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box"]));
        assert!(fs.unlinked().is_empty());
        assert!(report.removed.iter().any(|path| path.ends_with(b"/c")));
        assert!(report.removed.contains(&b"/srv/app/build/box".to_vec()));
    }

    #[test]
    fn an_unlink_error_after_a_partial_walk_is_preserved() {
        let (mut fs, _) = boxed(&[b"a", b"b"]);
        fs.fail_at("unlinkat", 1, 5);
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(report.partial);
        assert_eq!(report.error, Some(os("unlinkat", 5)));
        assert_eq!(report.removed.len(), 1);
    }

    #[test]
    fn directory_descriptors_are_closed_as_the_walk_unwinds() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(&BOX, b"one", NodeKind::Dir, 1000, 0o755, 0);
        fs.add(
            &[b"srv", b"app", b"build", b"box", b"one"],
            b"two",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"box", b"one", b"two"],
            b"item",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(!report.partial, "{report:?}");
        assert_eq!(fs.open_count(), 1);
    }

    #[test]
    fn an_entry_of_an_unlisted_owner_is_kept() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"box"],
            b"agent",
            NodeKind::File,
            1000,
            0o644,
            2,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"box"],
            b"root-kept",
            NodeKind::File,
            0,
            0o644,
            8,
        );
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(!report.partial);
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"box", b"agent"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"root-kept"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box"]));
        assert!(
            !report
                .removed
                .iter()
                .any(|path| path.ends_with(b"root-kept"))
        );
    }

    #[test]
    fn every_removed_path_is_in_the_record_or_its_hash() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        for index in 0..70u32 {
            let name = format!("f{index:02}");
            fs.add(
                &[b"srv", b"app", b"build", b"box"],
                name.as_bytes(),
                NodeKind::File,
                1000,
                0o644,
                1,
            );
        }
        let mut request = req("box");
        request.max_entries = 1000;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.removed.len() > AUDIT_PATH_HEAD);
        assert_eq!(report.digest, removal_digest(&report.removed));
        let head: Vec<Vec<u8>> = audit_path_head(&report.removed).to_vec();
        assert_eq!(head.len(), AUDIT_PATH_HEAD);
        assert_ne!(report.digest, removal_digest(&head));
        for path in &report.removed {
            let without: Vec<Vec<u8>> = report
                .removed
                .iter()
                .filter(|other| *other != path)
                .cloned()
                .collect();
            assert_ne!(removal_digest(&without), report.digest);
        }
    }

    #[test]
    fn fake_remove_fs_answers_every_call() {
        let mut fs = FakeRemoveFs::new();
        let root = fs.open_root().unwrap();
        let stat = fs.fstat(root).unwrap();
        assert_eq!(stat.kind, NodeKind::Dir);
        assert_eq!(stat.uid, 0);
        fs.add(&[], b"dir", NodeKind::Dir, 0, 0o755, 0);
        let dir = fs.open_dir(root, b"dir", false).unwrap();
        assert!(fs.list(dir, 99).unwrap().is_empty());
        fs.add(&[b"dir"], b"file", NodeKind::File, 1000, 0o644, 3);
        let listed = fs.list(dir, 99).unwrap();
        assert_eq!(listed, vec![b"file".to_vec()]);
        let leaf = fs.lstat(dir, b"file").unwrap();
        assert_eq!(leaf.kind, NodeKind::File);
        assert_eq!(leaf.size, 3);
        fs.unlink(dir, b"file", false).unwrap();
        assert!(fs.lstat(dir, b"file").is_err());
        let missing = fs.open_dir(dir, b"nope", true).unwrap_err();
        assert_eq!(
            missing,
            RemoveError::Os {
                op: "openat2",
                errno: ENOENT,
            }
        );
        assert!(matches_errno(&missing, ENOENT));
        assert!(!matches_errno(&missing, EXDEV));
        assert!(!matches_errno(&RemoveError::TreeRoot, ENOENT));
        assert!(!matches_errno(&RemoveError::Unsupported, ENOENT));
        assert!(!matches_errno(
            &RemoveError::BadTarget("relative target is absolute or contains NUL"),
            ENOENT
        ));
        assert!(!matches_errno(&RemoveError::AncestorRefused, ENOENT));
        assert!(!matches_errno(
            &RemoveError::DirectoryRequiresRecursive,
            ENOENT
        ));
        assert_eq!(fs.unlinked(), &[b"file".to_vec()]);
        let _ = fs.node(&[]);
        assert!(fs.exists(&[]));
        fs.set_device(1, 1);
        fs.diverge_on_restat(1);
        fs.swap_to_symlink_before_unlink(b"gone".to_vec(), 1);
        fs.hardlink(&[], b"root-again", 1);
        fs.fail_next_open(13);
        let failed = fs.open_dir(dir, b"file", false).unwrap_err();
        assert_eq!(
            failed,
            RemoveError::Os {
                op: "openat2",
                errno: 13,
            }
        );
    }

    #[test]
    fn an_unexpected_open_error_is_returned_unchanged() {
        let (mut fs, _) = tree();
        fs.fail_next_open(13);
        let error = remove_path(&mut fs, &req("a")).unwrap_err();
        assert_eq!(
            error,
            RemoveError::Os {
                op: "openat2",
                errno: 13,
            }
        );
    }

    #[test]
    fn a_directory_without_recursive_is_refused() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        fs.add(
            &[b"srv", b"app", b"build", b"box"],
            b"a",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        let mut request = req("box");
        request.recursive = false;
        let error = remove_path(&mut fs, &request).unwrap_err();
        assert_eq!(error, RemoveError::DirectoryRequiresRecursive);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn remove_path_fails_closed_where_openat2_does_not_exist() {
        let request = req("a");
        assert_eq!(
            remove_path_on_host(&request).unwrap_err(),
            RemoveError::Unsupported
        );
    }

    #[cfg(target_os = "linux")]
    fn host_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(target_os = "linux")]
    fn path_bytes(path: &std::path::Path) -> Vec<u8> {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }

    /// Walk `path`'s normal components from `/`. The temporary directory is
    /// wherever this host puts it, not a hardcoded `/tmp`.
    #[cfg(target_os = "linux")]
    fn open_components(host: &mut LinuxRemoveFs, path: &std::path::Path) -> u64 {
        use std::os::unix::ffi::OsStrExt;
        let mut fd = host.open_root().unwrap();
        for component in path.components() {
            if let std::path::Component::Normal(name) = component {
                fd = host.open_dir(fd, name.as_bytes(), false).unwrap();
            }
        }
        fd
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_real_walk_refuses_a_tree_under_tmp() {
        let dir = host_dir("xudo-t1-under-tmp");
        std::fs::write(dir.join("keep"), b"stay").unwrap();
        let request = RemoveRequest {
            under: path_bytes(&dir),
            relative: b"keep".to_vec(),
            recursive: false,
            max_depth: 2,
            max_entries: 4,
            owners: OwnerPolicy::AnyButRoot,
            dry_run: false,
        };
        let error = remove_path_on_host(&request).unwrap_err();
        assert_eq!(error, RemoveError::AncestorRefused);
        assert_eq!(std::fs::read(dir.join("keep")).unwrap(), b"stay");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_remove_fs_lists_stats_and_unlinks_without_following() {
        use std::os::unix::fs::PermissionsExt;

        let uid = rustix::process::getuid().as_raw();
        let dir = host_dir("xudo-t1-host");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub").join("note"), b"abc").unwrap();
        std::fs::write(dir.join("secret"), b"secret").unwrap();
        std::os::unix::fs::symlink("../secret", dir.join("sub").join("link")).unwrap();
        let fifo = dir.join("sub").join("fifo");
        let _ = std::fs::remove_file(&fifo);
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        let mut host = LinuxRemoveFs::default();
        let root = host.open_root().unwrap();
        let root_stat = host.fstat(root).unwrap();
        assert_eq!(root_stat.kind, NodeKind::Dir);
        assert_eq!(root_stat.uid, 0);
        let fd = open_components(&mut host, &dir);
        let names = host.list(fd, 99).unwrap();
        assert!(names.iter().any(|name| name == b"sub"));
        assert_eq!(host.list(fd, 1).unwrap().len(), 1);
        let sub = host.open_dir(fd, b"sub", true).unwrap();
        let note = host.lstat(sub, b"note").unwrap();
        assert_eq!(note.kind, NodeKind::File);
        assert_eq!(note.size, 3);
        let link = host.lstat(sub, b"link").unwrap();
        assert_eq!(link.kind, NodeKind::Symlink);
        let other = host.lstat(sub, b"fifo").unwrap();
        assert_eq!(other.kind, NodeKind::Other);
        host.unlink(sub, b"link", false).unwrap();
        assert_eq!(std::fs::read(dir.join("secret")).unwrap(), b"secret");
        host.unlink(sub, b"note", false).unwrap();
        assert!(!dir.join("sub").join("note").exists());
        std::fs::create_dir(dir.join("sub").join("empty")).unwrap();
        host.unlink(sub, b"empty", true).unwrap();
        assert!(!dir.join("sub").join("empty").exists());
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(uid, rustix::process::getuid().as_raw());
        let _ = mode;
        let _ = std::fs::remove_dir_all(&dir);
    }

    const BOX: [&[u8]; 4] = [b"srv", b"app", b"build", b"box"];

    fn boxed(files: &[&[u8]]) -> (FakeRemoveFs, u64) {
        let (mut fs, _) = tree();
        let dir = fs.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        for name in files {
            fs.add(&BOX, name, NodeKind::File, 1000, 0o644, 1);
        }
        (fs, dir)
    }

    fn os(op: &'static str, errno: i32) -> RemoveError {
        RemoveError::Os { op, errno }
    }

    #[test]
    fn a_request_for_no_entries_removes_nothing() {
        let (mut fs, _) = boxed(&[b"a"]);
        let mut request = req("box/a");
        request.max_entries = 0;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.partial);
        assert!(report.removed.is_empty());
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[test]
    fn a_nested_target_is_resolved_one_component_at_a_time() {
        let (mut fs, _) = boxed(&[b"a", b"b"]);
        let report = remove_path(&mut fs, &req("box/a")).unwrap();
        assert!(!report.partial);
        assert_eq!(report.removed, [b"/srv/app/build/box/a".to_vec()]);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"b"]));
    }

    #[test]
    fn a_walk_that_loses_its_way_to_the_target_stops_or_fails() {
        // A vanished or crossed directory is a stop. Anything else is an error.
        for (errno, stops) in [(ENOENT, true), (EXDEV, true), (5, false)] {
            let (mut fs, _) = boxed(&[b"a"]);
            // `/`, `srv`, `app`, `build`; the fifth open is `box`.
            fs.fail_at("openat2", 4, errno);
            let result = remove_path(&mut fs, &req("box/a"));
            if stops {
                assert!(result.unwrap().partial);
            } else {
                assert_eq!(result.unwrap_err(), os("openat2", errno));
            }
            assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
        }
        // Four fstats open the tree (`/`, `srv`, `app`, `build`); the fifth
        // is the intermediate `box`.
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("fstat", 4, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box/a")).unwrap_err(),
            os("fstat", 5)
        );
    }

    #[test]
    fn an_intermediate_directory_on_another_device_stops_the_walk() {
        let (mut fs, dir) = boxed(&[b"a"]);
        fs.remount_on_open(dir, 2);
        // The remount lands after `openat2` resolved `box`: only the fstat
        // sees it.
        let report = remove_path(&mut fs, &req("box/a")).unwrap();
        assert!(report.partial);
        assert!(report.removed.is_empty());
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[test]
    fn a_target_directory_that_moves_device_after_the_open_is_not_walked() {
        let (mut fs, dir) = boxed(&[b"a"]);
        fs.remount_on_open(dir, 2);
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(report.partial);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn a_directory_of_an_unlisted_owner_is_left_alone() {
        let (mut fs, _) = tree();
        fs.add(
            &[b"srv", b"app", b"build"],
            b"rootdir",
            NodeKind::Dir,
            0,
            0o755,
            0,
        );
        let report = remove_path(&mut fs, &req("rootdir")).unwrap();
        assert!(!report.partial);
        assert!(report.removed.is_empty());
        assert!(fs.exists(&[b"srv", b"app", b"build", b"rootdir"]));
    }

    #[test]
    fn a_directory_deeper_than_max_depth_is_not_emptied() {
        let (mut fs, _) = boxed(&[b"a"]);
        let mut request = req("box");
        request.max_depth = 1;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.partial);
        assert!(report.removed.is_empty());
    }

    #[test]
    fn the_last_entry_allowed_leaves_its_directory_in_place() {
        let (mut fs, _) = boxed(&[b"a"]);
        let mut request = req("box");
        request.max_entries = 1;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.partial);
        assert_eq!(report.removed.len(), 1);
        assert!(fs.exists(&BOX));
    }

    #[test]
    fn a_fifo_and_a_foreign_device_file_are_never_removed() {
        let (mut fs, _) = boxed(&[]);
        fs.add(&BOX, b"fifo", NodeKind::Other, 1000, 0o644, 0);
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(report.partial);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"fifo"]));

        let (mut fs, _) = boxed(&[]);
        let mounted = fs.add(&BOX, b"mnt", NodeKind::File, 1000, 0o644, 0);
        fs.set_device(mounted, 2);
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(report.partial);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"mnt"]));
    }

    #[test]
    fn a_failing_stat_of_a_leaf_stops_or_fails_and_keeps_earlier_work_reported() {
        // The first lstat is remove_leaf's, the second is commit's.
        for (skip, errno, stops) in [
            (0, ENOENT, true),
            (0, 5, false),
            (1, ENOENT, true),
            (1, 5, false),
        ] {
            let (mut fs, _) = boxed(&[b"a"]);
            fs.fail_at("lstat", skip, errno);
            let result = remove_path(&mut fs, &req("box/a"));
            if stops {
                assert!(result.unwrap().partial);
            } else {
                assert_eq!(result.unwrap_err(), os("lstat", errno));
            }
            assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
        }
        // Two files; the third lstat is for `b`, after `a` is gone.
        let (mut fs, _) = boxed(&[b"a", b"b"]);
        fs.fail_at("lstat", 2, 5);
        let report = remove_path(&mut fs, &req("box")).unwrap();
        assert!(report.partial);
        assert_eq!(report.removed, [b"/srv/app/build/box/a".to_vec()]);
        assert_eq!(report.digest, removal_digest(&report.removed));
    }

    #[test]
    fn a_leaf_that_changes_between_its_two_stats_is_not_unlinked() {
        let (mut fs, _) = boxed(&[]);
        let file = fs.add(&BOX, b"a", NodeKind::File, 1000, 0o644, 1);
        fs.diverge_on_restat(file);
        let report = remove_path(&mut fs, &req("box/a")).unwrap();
        assert!(report.partial);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[test]
    fn a_symlink_that_changes_owner_between_its_two_stats_is_kept() {
        let (mut fs, _) = boxed(&[]);
        let link = fs.add(&BOX, b"l", NodeKind::Symlink, 1000, 0o777, 1);
        fs.diverge_on_restat(link);
        fs.diverge_uid_on_restat(0);
        let report = remove_path(&mut fs, &req("box/l")).unwrap();
        assert!(!report.partial);
        assert!(report.removed.is_empty());
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"l"]));
    }

    #[test]
    fn a_parent_renamed_out_before_unlink_stops_the_walk() {
        let (mut fs, _) = boxed(&[b"a"]);
        fs.rename_out_before_verify(b"box".to_vec(), b"moved-box".to_vec());
        let report = remove_path(&mut fs, &req("box/a")).unwrap();
        assert!(report.partial);
        assert!(fs.exists(&[b"srv", b"app", b"build", b"moved-box", b"a"]));
    }

    #[test]
    fn a_directory_listing_or_unlink_failure_is_returned() {
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("list", 0, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box")).unwrap_err(),
            os("list", 5)
        );
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("list", 1, 5);
        assert!(remove_path(&mut fs, &req("box")).unwrap().partial);
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("unlinkat", 0, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box/a")).unwrap_err(),
            os("unlinkat", 5)
        );
        // A fault for another call does not disturb this one.
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("unlinkat", 0, 5);
        fs.fail_at("lstat", 9, 5);
        assert!(remove_path(&mut fs, &req("box/a")).is_err());
    }

    #[test]
    fn the_fake_refuses_what_a_kernel_would() {
        let mut fs = FakeRemoveFs::default();
        assert_eq!(fs.lstat(77, b"x").unwrap_err(), os("openat2", EBADF));
        assert_eq!(fs.close(77).unwrap_err(), os("close", EBADF));
        // A name added under a parent that is not there links nothing.
        fs.add(&[b"nope"], b"x", NodeKind::File, 0, 0o644, 0);
        assert!(!fs.exists(&[b"nope", b"x"]));
        let root = fs.open_root().unwrap();
        fs.add(&[], b"f", NodeKind::File, 0, 0o644, 0);
        fs.add(&[], b"d", NodeKind::Dir, 0, 0o755, 0);
        assert_eq!(
            fs.unlink(root, b"f", true).unwrap_err(),
            os("unlinkat", ENOTDIR)
        );
        assert_eq!(
            fs.unlink(root, b"d", false).unwrap_err(),
            os("unlinkat", 21)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_stale_linux_remove_descriptor_reports_the_actual_operation() {
        let mut fs = LinuxRemoveFs::default();
        let expected = |op| RemoveError::Os { op, errno: EBADF };
        assert_eq!(
            fs.open_dir(99, b"x", true).unwrap_err(),
            expected("openat2")
        );
        assert_eq!(fs.fstat(99).unwrap_err(), expected("fstat"));
        assert_eq!(fs.lstat(99, b"x").unwrap_err(), expected("statat"));
        assert_eq!(fs.list(99, 99).unwrap_err(), expected("getdents"));
        assert_eq!(
            fs.unlink(99, b"x", false).unwrap_err(),
            expected("unlinkat")
        );
        let expected_stat = NodeStat {
            dev: 1,
            ino: 1,
            uid: 0,
            mode: 0o755,
            size: 0,
            nlink: 1,
            kind: NodeKind::Dir,
            mount_root: false,
        };
        assert_eq!(
            fs.verify_dir(99, b"", expected_stat).unwrap_err(),
            expected("openat2")
        );
        assert_eq!(fs.close(99).unwrap_err(), expected("close"));
    }

    #[test]
    fn a_malformed_tree_or_target_is_refused_before_anything_opens() {
        let (mut fs, _) = boxed(&[b"a"]);
        let mut request = req("box/a");
        for under in [&b"srv"[..], b"", b"/srv/../etc", b"/srv//app", b"/a\0b"] {
            request.under = under.to_vec();
            let err = remove_path(&mut fs, &request).unwrap_err();
            assert!(format!("{err:?}").contains("BadTarget"), "{err:?}");
        }
        request.under = b"/".to_vec();
        assert_eq!(
            remove_path(&mut fs, &request).unwrap_err(),
            RemoveError::TreeRoot
        );
        let request = req("/etc/passwd");
        assert_eq!(
            remove_path(&mut fs, &request).unwrap_err(),
            RemoveError::BadTarget("relative target is absolute or contains NUL")
        );
        let mut request = req("box/a");
        request.max_depth = 1;
        assert_eq!(
            remove_path(&mut fs, &request).unwrap_err(),
            RemoveError::BadTarget("target is deeper than max-depth")
        );
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[test]
    fn an_unexpected_error_opening_an_ancestor_is_returned_not_reworded() {
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("openat2", 1, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box")).unwrap_err(),
            os("openat2", 5)
        );
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("openat2", 1, ELOOP);
        assert_eq!(
            remove_path(&mut fs, &req("box")).unwrap_err(),
            RemoveError::AncestorRefused
        );
    }

    #[test]
    fn a_group_writable_filesystem_root_is_refused() {
        let (mut fs, _) = boxed(&[b"a"]);
        fs.set_mode(1, 0o777);
        assert_eq!(
            remove_path(&mut fs, &req("box/a")).unwrap_err(),
            RemoveError::AncestorRefused
        );
    }

    #[test]
    fn a_crowded_directory_of_skipped_entries_is_partial_and_stays() {
        let (mut fs, _) = boxed(&[]);
        fs.add(&BOX, b"a", NodeKind::File, 0, 0o644, 1);
        fs.add(&BOX, b"b", NodeKind::File, 1000, 0o644, 1);
        fs.add(&BOX, b"c", NodeKind::File, 1000, 0o644, 1);
        let mut request = req("box");
        request.max_entries = 2;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.partial);
        assert!(fs.exists(&BOX));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[test]
    fn an_intermediate_ancestor_that_is_group_writable_refuses_the_tree() {
        let (mut fs, _) = tree();
        let app = fs.ino_at(&[b"srv", b"app"]).unwrap();
        fs.set_mode(app, 0o775);
        assert_eq!(
            remove_path(&mut fs, &req("x")).unwrap_err(),
            RemoveError::AncestorRefused
        );
    }

    #[test]
    fn an_intermediate_ancestor_not_owned_by_root_refuses_the_tree() {
        let mut fs = FakeRemoveFs::new();
        fs.add(&[], b"srv", NodeKind::Dir, 1000, 0o755, 0);
        fs.add(&[b"srv"], b"app", NodeKind::Dir, 0, 0o755, 0);
        fs.add(&[b"srv", b"app"], b"build", NodeKind::Dir, 0, 0o755, 0);
        assert_eq!(
            remove_path(&mut fs, &req("x")).unwrap_err(),
            RemoveError::AncestorRefused
        );
    }

    #[test]
    fn a_directory_larger_than_the_limit_is_not_read_to_the_end() {
        let (mut fs, _) = boxed(&[]);
        for index in 0..50u8 {
            fs.add(&BOX, &[b'f', index], NodeKind::File, 1000, 0o644, 1);
        }
        let open = fs.open_root().unwrap();
        let mut dir = open;
        for name in BOX {
            dir = fs.open_dir(dir, name, false).unwrap();
        }
        assert_eq!(fs.list(dir, 3).unwrap().len(), 3);
        let mut request = req("box");
        request.max_entries = 4;
        let report = remove_path(&mut fs, &request).unwrap();
        assert!(report.partial);
        assert_eq!(report.removed.len(), 4);
        assert!(fs.exists(&BOX));
    }

    #[test]
    fn an_unexpected_error_opening_a_child_is_returned() {
        // `/`, `srv`, `app`, `build`, `box`; the sixth open is `a`.
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("openat2", 5, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box")).unwrap_err(),
            os("openat2", 5)
        );
    }

    #[test]
    fn a_failing_stat_while_opening_the_tree_or_walking_is_returned() {
        // `/`, `srv`, `app`, `build`: four fstats open the tree.
        for (skip, relative) in [(0, "box"), (1, "box"), (4, "box"), (5, "box/sub/file")] {
            let (mut fs, _) = boxed(&[b"a"]);
            fs.add(&BOX, b"sub", NodeKind::Dir, 1000, 0o755, 0);
            fs.add(
                &[b"srv", b"app", b"build", b"box", b"sub"],
                b"file",
                NodeKind::File,
                1000,
                0o644,
                1,
            );
            fs.fail_at("fstat", skip, 5);
            assert_eq!(
                remove_path(&mut fs, &req(relative)).unwrap_err(),
                os("fstat", 5),
                "{skip} {relative}"
            );
            assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
        }
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("openat2", 0, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box")).unwrap_err(),
            os("openat2", 5)
        );
    }

    #[test]
    fn an_intermediate_stop_errno_closes_its_open_parent() {
        let (mut fs, _) = boxed(&[]);
        fs.add(&BOX, b"sub", NodeKind::Dir, 1000, 0o755, 0);
        fs.fail_at("openat2", 5, ENOENT);
        assert!(remove_path(&mut fs, &req("box/sub/file")).unwrap().partial);
        assert_eq!(fs.open_count(), 1);
    }

    #[test]
    fn an_intermediate_non_stop_open_error_closes_its_parent_and_is_returned() {
        let (mut fs, _) = boxed(&[]);
        fs.add(&BOX, b"sub", NodeKind::Dir, 1000, 0o755, 0);
        fs.fail_at("openat2", 5, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box/sub/file")).unwrap_err(),
            os("openat2", 5)
        );
        assert_eq!(fs.open_count(), 1);
    }

    #[test]
    fn an_intermediate_parent_close_error_is_returned() {
        let (mut fs, _) = boxed(&[]);
        fs.add(&BOX, b"sub", NodeKind::Dir, 1000, 0o755, 0);
        fs.add(
            &[b"srv", b"app", b"build", b"box", b"sub"],
            b"file",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        fs.fail_at("close", 3, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box/sub/file")).unwrap_err(),
            os("close", 5)
        );
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"sub", b"file"]));
    }

    #[test]
    fn a_tree_parent_close_error_stops_before_the_walk_starts() {
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("close", 0, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box/a")).unwrap_err(),
            os("close", 5)
        );
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[test]
    fn a_walk_parent_close_error_is_reported_after_the_target_unlink() {
        let (mut fs, _) = boxed(&[]);
        fs.add(&BOX, b"sub", NodeKind::Dir, 1000, 0o755, 0);
        fs.add(
            &[b"srv", b"app", b"build", b"box", b"sub"],
            b"file",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        fs.fail_at("close", 4, 5);
        let report = remove_path(&mut fs, &req("box/sub/file")).unwrap();
        assert!(report.partial);
        assert_eq!(report.error, Some(os("close", 5)));
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"box", b"sub", b"file"]));
    }

    #[test]
    fn a_removed_directory_close_error_is_reported_after_its_contents() {
        let (mut fs, _) = boxed(&[]);
        fs.add(&BOX, b"dir", NodeKind::Dir, 1000, 0o755, 0);
        fs.add(
            &[b"srv", b"app", b"build", b"box", b"dir"],
            b"file",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        fs.fail_at("close", 3, 5);
        let report = remove_path(&mut fs, &req("box/dir")).unwrap();
        assert!(report.partial);
        assert_eq!(report.error, Some(os("close", 5)));
        assert!(!fs.exists(&[b"srv", b"app", b"build", b"box", b"dir", b"file"]));
    }

    #[test]
    fn a_parent_replaced_by_another_directory_stops_the_walk() {
        let (mut fs, _) = boxed(&[b"a"]);
        fs.replace_path_before_verify(b"box".to_vec(), b"moved-box".to_vec());
        let report = remove_path(&mut fs, &req("box/a")).unwrap();
        assert!(report.partial);
        assert!(report.removed.is_empty());
        assert!(fs.exists(&[b"srv", b"app", b"build", b"moved-box", b"a"]));
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box"]));
    }

    #[test]
    fn a_non_stop_ancestry_verification_error_is_returned() {
        let (mut fs, _) = boxed(&[b"a"]);
        fs.fail_at("verify_dir", 0, 5);
        assert_eq!(
            remove_path(&mut fs, &req("box/a")).unwrap_err(),
            os("verify_dir", 5)
        );
        assert!(fs.exists(&[b"srv", b"app", b"build", b"box", b"a"]));
    }

    #[test]
    fn relative_parent_returns_empty_for_a_path_outside_the_tree() {
        assert!(relative_parent(b"/srv/app/build", b"/elsewhere/box/a").is_empty());
    }

    #[test]
    fn the_fake_tolerates_unknown_inodes_and_stale_descriptors() {
        let mut fs = FakeRemoveFs::new();
        fs.set_device(99, 2);
        fs.set_mode(99, 0o777);
        fs.hardlink(&[], b"ghost", 99);
        assert!(fs.exists(&[b"ghost"]));
        let root = fs.open_root().unwrap();
        assert_eq!(fs.list(55, 99).unwrap_err(), os("getdents", EBADF));
        assert_eq!(
            fs.unlink(55, b"x", false).unwrap_err(),
            os("unlinkat", EBADF)
        );
        assert_eq!(fs.fstat(55).unwrap_err(), os("fstat", EBADF));
        assert_eq!(
            fs.open_dir(55, b"x", false).unwrap_err(),
            os("openat2", EBADF)
        );
        // A name that points at a record that is gone.
        assert_eq!(fs.lstat(root, b"ghost").unwrap_err(), os("fstat", ENOENT));
        assert_eq!(
            fs.open_dir(root, b"ghost", false).unwrap_err(),
            os("openat2", ENOENT)
        );
        assert_eq!(
            fs.unlink(root, b"ghost", false).unwrap_err(),
            os("unlinkat", ENOENT)
        );
        // A descriptor whose directory record is gone.
        let dir = fs.add(&[], b"d", NodeKind::Dir, 0, 0o755, 0);
        let open = fs.open_dir(root, b"d", false).unwrap();
        fs.forget(dir);
        assert_eq!(fs.lstat(open, b"x").unwrap_err(), os("openat2", ENOENT));
        assert!(fs.list(open, 99).unwrap().is_empty());
        assert_eq!(fs.fstat(open).unwrap_err(), os("fstat", ENOENT));
    }

    #[test]
    fn a_fake_ancestry_check_fails_closed_for_a_missing_inode() {
        let mut fs = FakeRemoveFs::new();
        fs.hardlink(&[], b"ghost", 99);
        let root = fs.open_root().unwrap();
        let expected = fs.fstat(root).unwrap();
        assert_eq!(
            fs.verify_dir(root, b"ghost", expected).unwrap_err(),
            os("fstat", ENOENT)
        );
    }

    #[test]
    fn a_fake_ancestry_check_fails_closed_for_a_stale_root_token() {
        let mut fs = FakeRemoveFs::new();
        let root = fs.open_root().unwrap();
        let expected = fs.fstat(root).unwrap();
        assert_eq!(
            fs.verify_dir(99, b"", expected).unwrap_err(),
            os("openat2", EBADF)
        );
    }

    #[test]
    fn directory_stat_result_propagates_fstat_errno_and_compares_identity() {
        let expected = NodeStat {
            dev: 7,
            ino: 11,
            uid: 1000,
            mode: 0o755,
            size: 0,
            nlink: 2,
            kind: NodeKind::Dir,
            mount_root: false,
        };
        assert_eq!(
            verify_dir_stat_result(Err(EBADF), expected).unwrap_err(),
            os("fstat", EBADF)
        );
        assert!(verify_dir_stat_result(Ok(expected), expected).unwrap());
        let mut changed = expected;
        changed.ino += 1;
        assert!(!verify_dir_stat_result(Ok(changed), expected).unwrap());
    }

    #[test]
    fn a_swap_for_a_name_that_is_not_there_plants_a_link_that_is_then_removed() {
        let mut fs = FakeRemoveFs::new();
        let root = fs.open_root().unwrap();
        fs.swap_to_symlink_before_unlink(b"missing".to_vec(), 9999);
        fs.unlink(root, b"missing", false).unwrap();
        assert_eq!(fs.unlinked(), &[b"missing".to_vec()]);
        assert!(!fs.exists(&[b"missing"]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_reports_a_stale_token_and_a_missing_name() {
        let mut host = LinuxRemoveFs::default();
        assert_eq!(
            host.open_dir(77, b"x", false).unwrap_err(),
            os("openat2", EBADF)
        );
        assert_eq!(host.fstat(77).unwrap_err(), os("fstat", EBADF));
        assert_eq!(host.lstat(77, b"x").unwrap_err(), os("statat", EBADF));
        assert_eq!(host.list(77, 99).unwrap_err(), os("getdents", EBADF));
        assert_eq!(
            host.unlink(77, b"x", false).unwrap_err(),
            os("unlinkat", EBADF)
        );
        let root = host.open_root().unwrap();
        let missing = b"xudo-no-such-name-t1";
        assert_eq!(
            host.open_dir(root, missing, false).unwrap_err(),
            os("openat2", ENOENT)
        );
        assert_eq!(host.lstat(root, missing).unwrap_err(), os("statat", ENOENT));
        assert_eq!(
            host.unlink(root, missing, false).unwrap_err(),
            os("unlinkat", ENOENT)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_ancestry_verification_reopens_from_the_pinned_root_and_calls_its_hook() {
        let mut host = LinuxRemoveFs {
            before_verify: Some(Box::new(|relative| assert!(!relative.is_empty()))),
            ..LinuxRemoveFs::default()
        };
        let tree = host_dir("xudo-remove-verify");
        std::fs::create_dir(tree.join("child")).unwrap();
        let root = open_components(&mut host, &tree);
        let child = host.open_dir(root, b"child", true).unwrap();
        let stat = host.fstat(child).unwrap();
        assert!(host.verify_dir(root, b"child", stat).unwrap());
        host.close(child).unwrap();
        host.close(root).unwrap();
        std::fs::remove_dir_all(tree).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ancestry_resolution_rejects_a_parent_escape() {
        let mut host = LinuxRemoveFs::default();
        let root = host.open_root().unwrap();
        let expected = host.fstat(root).unwrap();
        assert_eq!(
            host.verify_dir(root, b"../", expected).unwrap_err(),
            os("openat2", EXDEV)
        );
        host.close(root).unwrap();
    }

    #[cfg(all(target_os = "linux", feature = "root-tests"))]
    #[test]
    fn the_linux_race_hook_api_fails_closed_for_an_invalid_tree() {
        fn ignore_relative(_relative: &[u8]) {}
        ignore_relative(b"");
        let mut request = req("x");
        request.under = b"/".to_vec();
        assert_eq!(
            remove_path_on_host_with_before_verify(&request, ignore_relative),
            Err(RemoveError::TreeRoot)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_kernel_swap_to_a_symlink_removes_only_the_link() {
        let uid = rustix::process::getuid().as_raw();
        let dir = host_dir("xudo-t1-swap");
        std::fs::write(dir.join("secret"), b"secret-bytes").unwrap();
        std::fs::write(dir.join("victim"), b"victim").unwrap();
        let mut host = LinuxRemoveFs {
            before_unlink: Some(Box::new(|fd, name| {
                let _ = rustix::fs::unlinkat(fd, name, rustix::fs::AtFlags::empty());
                // Plant the symlink on the parent descriptor. The following
                // `unlinkat` removes that link and does not follow it.
                let _ = rustix::fs::symlinkat("secret", fd, name);
            })),
            ..LinuxRemoveFs::default()
        };
        let fd = open_components(&mut host, &dir);
        let stat = host.fstat(fd).unwrap();
        let request = RemoveRequest {
            under: b"/unused".to_vec(),
            relative: b"victim".to_vec(),
            recursive: false,
            max_depth: 2,
            max_entries: 4,
            owners: OwnerPolicy::Only(vec![uid]),
            dry_run: false,
        };
        let report = remove_from_open(&mut host, fd, stat, &request).unwrap();
        assert!(!report.partial, "{report:?}");
        assert_eq!(std::fs::read(dir.join("secret")).unwrap(), b"secret-bytes");
        assert!(!dir.join("victim").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
