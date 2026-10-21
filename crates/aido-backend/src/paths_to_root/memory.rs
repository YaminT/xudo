//! A described machine, for tests.
//!
//! Public so the front-end can snapshot a whole report against the same
//! described machine the report's own tests use. It models the parts of the
//! kernel's path lookup the report depends on, because a fake that answers
//! differently from the real thing is a test proving nothing: every link but a
//! final one is followed, a relative target from the link's own directory; `..`
//! steps back from where the lookup is, not from how the path was spelled; a
//! directory that cannot be searched hides its entries; a file where a
//! directory should be makes the path missing (`ENOTDIR`), as `aido-sys`
//! reports it.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use super::{Caller, HostView, Kind, Lookup, Meta, NOT_A_REGULAR_FILE};

/// How many links a lookup follows before giving up, as the kernel does.
const MAX_LINKS: usize = 40;

/// The kernel's words for the failures this models.
const DENIED: &str = "Permission denied (os error 13)";
const LOOP: &str = "Too many levels of symbolic links (os error 40)";
const NOT_A_LINK: &str = "Invalid argument (os error 22)";

/// One entry of a described machine.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Dir {
        meta: Meta,
        searchable: bool,
        listable: bool,
    },
    File {
        meta: Meta,
        contents: Option<Vec<u8>>,
    },
    Link {
        target: PathBuf,
        uid: u32,
    },
    Fault {
        reason: String,
    },
}

/// A machine described by a table, answering every [`HostView`] question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryHost {
    caller: Caller,
    nodes: BTreeMap<PathBuf, Node>,
    writable: BTreeSet<PathBuf>,
}

impl MemoryHost {
    /// A machine with nothing on it, asked by `caller`.
    pub fn new(caller: Caller) -> Self {
        Self {
            caller,
            nodes: BTreeMap::new(),
            writable: BTreeSet::new(),
        }
    }

    /// Adds a directory.
    #[must_use]
    pub fn dir(self, path: &str, uid: u32, gid: u32, mode: u32) -> Self {
        self.node(
            path,
            Node::Dir {
                meta: meta(uid, gid, mode, Kind::Directory),
                searchable: true,
                listable: true,
            },
        )
    }

    /// Adds a directory this process may not search: its entries cannot be
    /// examined or listed, as `/root` is to everyone but root.
    #[must_use]
    pub fn sealed_dir(self, path: &str, uid: u32, gid: u32, mode: u32) -> Self {
        self.node(
            path,
            Node::Dir {
                meta: meta(uid, gid, mode, Kind::Directory),
                searchable: false,
                listable: false,
            },
        )
    }

    /// Adds a directory whose entries can be examined by name but not listed:
    /// mode `0711`.
    #[must_use]
    pub fn unlistable_dir(self, path: &str, uid: u32, gid: u32, mode: u32) -> Self {
        self.node(
            path,
            Node::Dir {
                meta: meta(uid, gid, mode, Kind::Directory),
                searchable: true,
                listable: false,
            },
        )
    }

    /// Adds a regular file with these contents.
    #[must_use]
    pub fn file(self, path: &str, uid: u32, gid: u32, mode: u32, contents: &[u8]) -> Self {
        self.node(
            path,
            Node::File {
                meta: meta(uid, gid, mode, Kind::File),
                contents: Some(contents.to_vec()),
            },
        )
    }

    /// Adds a regular file this process may examine but not read: mode
    /// `0440`, as `/etc/sudoers` is.
    #[must_use]
    pub fn unreadable_file(self, path: &str, uid: u32, gid: u32, mode: u32) -> Self {
        self.node(
            path,
            Node::File {
                meta: meta(uid, gid, mode, Kind::File),
                contents: None,
            },
        )
    }

    /// Adds a character device.
    #[must_use]
    pub fn char_device(self, path: &str, uid: u32, gid: u32, mode: u32) -> Self {
        self.node(
            path,
            Node::File {
                meta: meta(uid, gid, mode, Kind::CharDevice),
                contents: None,
            },
        )
    }

    /// Adds a socket, a fifo, or a block device.
    #[must_use]
    pub fn special(self, path: &str, uid: u32, gid: u32, mode: u32) -> Self {
        self.node(
            path,
            Node::File {
                meta: meta(uid, gid, mode, Kind::Other),
                contents: None,
            },
        )
    }

    /// Adds a symbolic link owned by root. A relative target is followed from
    /// the link's own directory, as the kernel follows it.
    #[must_use]
    pub fn link(self, path: &str, target: &str) -> Self {
        self.owned_link(path, target, 0)
    }

    /// Adds a symbolic link owned by `uid`.
    #[must_use]
    pub fn owned_link(self, path: &str, target: &str, uid: u32) -> Self {
        self.node(
            path,
            Node::Link {
                target: PathBuf::from(target),
                uid,
            },
        )
    }

    /// Adds a path that cannot be examined at all, for this reason.
    #[must_use]
    pub fn fault(self, path: &str, reason: &str) -> Self {
        self.node(
            path,
            Node::Fault {
                reason: reason.to_owned(),
            },
        )
    }

    /// Marks a path as one `access(2)` says this process may write, whatever
    /// its mode bits say: the shape of an ACL.
    #[must_use]
    pub fn acl_writable(mut self, path: &str) -> Self {
        self.writable.insert(PathBuf::from(path));
        self
    }

    fn node(mut self, path: &str, node: Node) -> Self {
        self.nodes.insert(PathBuf::from(path), node);
        self
    }

    /// Looks a path up the way the kernel does: every link but a final one is
    /// followed, and `follow_last` decides the final one.
    fn resolve(&self, path: &Path, follow_last: bool) -> Result<(PathBuf, &Node), Failure> {
        let root = self.nodes.get(Path::new("/")).ok_or(Failure::Missing)?;
        let root = (PathBuf::from("/"), root);
        let mut stack: Vec<(PathBuf, &Node)> = Vec::new();
        let mut pending: Vec<Component<'_>> = Vec::new();
        push_components(&mut pending, path);
        let mut links = 0usize;
        while let Some(component) = pending.pop() {
            let (here, node) = stack.last().unwrap_or(&root).clone();
            match node {
                Node::Dir {
                    searchable: false, ..
                } => return Err(Failure::Unreadable(DENIED.to_owned())),
                Node::Dir { .. } => {}
                // A file, or a fault, where a directory must be.
                Node::File { .. } | Node::Fault { .. } | Node::Link { .. } => {
                    return Err(Failure::Missing);
                }
            }
            let Component::Normal(name) = component else {
                // `..`, which at `/` stays at `/`.
                stack.pop();
                continue;
            };
            let candidate = here.join(name);
            let node = self.nodes.get(&candidate).ok_or(Failure::Missing)?;
            match node {
                Node::Fault { reason } => return Err(Failure::Unreadable(reason.clone())),
                Node::Link { target, .. } if follow_last || !pending.is_empty() => {
                    links = links.saturating_add(1);
                    if links > MAX_LINKS {
                        return Err(Failure::Unreadable(LOOP.to_owned()));
                    }
                    if target.is_absolute() {
                        stack.clear();
                    }
                    push_components(&mut pending, target);
                }
                _ => stack.push((candidate, node)),
            }
        }
        Ok(stack.pop().unwrap_or(root))
    }
}

/// Why a lookup failed.
enum Failure {
    Missing,
    Unreadable(String),
}

/// A failed lookup as an answer.
fn failed<T>(failure: Failure) -> Lookup<T> {
    match failure {
        Failure::Missing => Lookup::Missing,
        Failure::Unreadable(reason) => Lookup::Unreadable(reason),
    }
}

/// Queues a path's components, last first, so the next to visit is on top.
/// `/` and `.` name where the lookup already is.
fn push_components<'p>(pending: &mut Vec<Component<'p>>, path: &'p Path) {
    let steps: Vec<Component<'p>> = path
        .components()
        .filter(|component| matches!(component, Component::Normal(_) | Component::ParentDir))
        .collect();
    pending.extend(steps.into_iter().rev());
}

fn meta(uid: u32, gid: u32, mode: u32, kind: Kind) -> Meta {
    Meta {
        uid,
        gid,
        mode,
        kind,
    }
}

impl HostView for MemoryHost {
    fn caller(&self) -> Caller {
        self.caller.clone()
    }

    fn stat(&self, path: &Path) -> Lookup<Meta> {
        match self.resolve(path, false) {
            Ok((_, Node::Dir { meta, .. } | Node::File { meta, .. })) => Lookup::Found(*meta),
            Ok((_, Node::Link { uid, .. })) => {
                Lookup::Found(meta(*uid, *uid, 0o777, Kind::Symlink))
            }
            Ok((_, Node::Fault { reason })) => Lookup::Unreadable(reason.clone()),
            Err(failure) => failed(failure),
        }
    }

    fn read(&self, path: &Path) -> Lookup<Vec<u8>> {
        match self.resolve(path, true) {
            Ok((
                _,
                Node::File {
                    contents: Some(contents),
                    ..
                },
            )) => Lookup::Found(contents.clone()),
            Ok((_, Node::File { meta, .. })) if meta.kind == Kind::File => {
                Lookup::Unreadable(DENIED.to_owned())
            }
            Ok(_) => Lookup::Unreadable(NOT_A_REGULAR_FILE.to_owned()),
            Err(failure) => failed(failure),
        }
    }

    fn list(&self, path: &Path) -> Lookup<Vec<OsString>> {
        match self.resolve(path, true) {
            Ok((dir, Node::Dir { listable: true, .. })) => Lookup::Found(
                self.nodes
                    .keys()
                    .filter(|candidate| candidate.parent() == Some(dir.as_path()))
                    .filter_map(|candidate| candidate.file_name().map(ToOwned::to_owned))
                    .collect(),
            ),
            // `ENOTDIR`, which `aido-sys` reports as missing.
            Ok((_, Node::File { .. })) => Lookup::Missing,
            Ok(_) => Lookup::Unreadable(DENIED.to_owned()),
            Err(failure) => failed(failure),
        }
    }

    fn read_link(&self, path: &Path) -> Lookup<PathBuf> {
        match self.resolve(path, false) {
            Ok((_, Node::Link { target, .. })) => Lookup::Found(target.clone()),
            Ok(_) => Lookup::Unreadable(NOT_A_LINK.to_owned()),
            Err(failure) => failed(failure),
        }
    }

    fn writable(&self, path: &Path) -> bool {
        self.resolve(path, true)
            .is_ok_and(|(resolved, _)| self.writable.contains(&resolved))
    }
}
