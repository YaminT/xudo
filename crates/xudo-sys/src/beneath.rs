//! Open a path beneath a pinned directory, with `openat2` or without it.
//!
//! Every open here asks `openat2` for `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS` first. A seccomp filter that cannot read `openat2`'s
//! flag struct answers it with `ENOSYS` instead: systemd's
//! `RestrictSUIDSGID=yes` does, and the broker unit sets it. A gate started
//! under such a unit inherits the filter. On `ENOSYS`, and only then, the same
//! path is opened one component at a time from the pinned directory: every
//! directory with `O_PATH | O_DIRECTORY | O_NOFOLLOW`, the last name with the
//! caller's flags plus `O_NOFOLLOW`. That is the walk `kernel.rs` calls
//! equivalent. It never follows a link, magic or not, so `RESOLVE_NO_SYMLINKS`
//! and `RESOLVE_NO_MAGICLINKS` hold. It refuses `..` and a leading `/`
//! outright, so it cannot leave the directory and `RESOLVE_BENEATH` holds. With
//! `RESOLVE_NO_XDEV`, each step compares devices and asks `statx` whether it
//! is a mount root. Each step opens from the descriptor the last step
//! returned, so a component renamed or swapped after it was opened changes
//! nothing.
//!
//! The walk refuses `O_PATH` without `O_DIRECTORY` (a final link would come
//! back as the link, not `ELOOP`) and, with `RESOLVE_NO_XDEV`, any flag that
//! makes the open itself act (`O_CREAT`, `O_TRUNC`, write access), because it
//! opens before it can compare mounts. Both are `EINVAL`.
//!
//! On kernels 5.6 and 5.7, `statx` has no `STATX_ATTR_MOUNT_ROOT`. Where a
//! filter forces the walk there, every `RESOLVE_NO_XDEV` open fails closed
//! with `EXDEV`, so `remove-path` does not work. `openat2` itself is fine.
//!
//! The walk only ever withholds compared with `openat2`. An empty component
//! (`a//b`, a trailing `/`) or a `.` is refused, where `openat2` would accept
//! it. No caller sends one.

use rustix::io::Errno;

/// What one open needs from the system. The host is Linux; tests use a tree in
/// memory, so the walk runs on every platform.
pub(crate) trait Resolve {
    /// A held directory or file.
    type Fd;
    /// `openat2` with the resolution flags this open was made with.
    fn openat2(&mut self, dir: &Self::Fd, path: &[u8]) -> Result<Self::Fd, Errno>;
    /// One directory, never through a link.
    fn step(&mut self, dir: &Self::Fd, name: &[u8]) -> Result<Self::Fd, Errno>;
    /// The last name, with the caller's flags and never through a link.
    fn last(&mut self, dir: &Self::Fd, name: &[u8]) -> Result<Self::Fd, Errno>;
    /// Whether `dir/name` is a link, to answer as `openat2` does: `O_NOFOLLOW`
    /// with `O_DIRECTORY` says `ENOTDIR` for a link where `openat2` says `ELOOP`.
    fn is_link(&mut self, dir: &Self::Fd, name: &[u8]) -> bool;
    /// Whether the walk can honour this open's flags: not `O_PATH` without
    /// `O_DIRECTORY`, and no side-effecting flag under `RESOLVE_NO_XDEV`.
    fn walkable(&self) -> bool;
    /// Whether the open must stay on one mount (`RESOLVE_NO_XDEV`).
    fn no_xdev(&self) -> bool;
    /// Whether `child` is on another mount than `parent`.
    fn crosses(&mut self, parent: &Self::Fd, child: &Self::Fd) -> Result<bool, Errno>;
}

/// `openat2`, and the walk where `openat2` is answered with `ENOSYS`.
pub(crate) fn open<R: Resolve>(host: &mut R, dir: &R::Fd, path: &[u8]) -> Result<R::Fd, Errno> {
    let resolved = host.openat2(dir, path);
    on_nosys(resolved, || walk(host, dir, path))
}

/// `result`, or `fallback`'s where `result` is `ENOSYS`.
pub(crate) fn on_nosys<T>(
    result: Result<T, Errno>,
    fallback: impl FnOnce() -> Result<T, Errno>,
) -> Result<T, Errno> {
    match result {
        Err(errno) if errno == Errno::NOSYS => fallback(),
        other => other,
    }
}

/// The component walk, on its own.
pub(crate) fn walk<R: Resolve>(host: &mut R, dir: &R::Fd, path: &[u8]) -> Result<R::Fd, Errno> {
    if !host.walkable() {
        return Err(Errno::INVAL);
    }
    let (last, parents) = components(path)?;
    let mut held: Option<R::Fd> = None;
    for name in parents {
        let parent = held.as_ref().unwrap_or(dir);
        let next = host
            .step(parent, name)
            .map_err(|errno| as_openat2(host, parent, name, errno))?;
        same_mount(host, parent, &next)?;
        held = Some(next);
    }
    let parent = held.as_ref().unwrap_or(dir);
    let opened = host
        .last(parent, last)
        .map_err(|errno| as_openat2(host, parent, last, errno))?;
    same_mount(host, parent, &opened)?;
    Ok(opened)
}

/// `ELOOP` for a link refused as "not a directory", as `openat2` refuses it.
fn as_openat2<R: Resolve>(host: &mut R, dir: &R::Fd, name: &[u8], errno: Errno) -> Errno {
    if errno == Errno::NOTDIR && host.is_link(dir, name) {
        Errno::LOOP
    } else {
        errno
    }
}

fn same_mount<R: Resolve>(host: &mut R, parent: &R::Fd, child: &R::Fd) -> Result<(), Errno> {
    if host.no_xdev() && host.crosses(parent, child)? {
        return Err(Errno::XDEV);
    }
    Ok(())
}

/// The path as names, last apart. `EXDEV` for what would leave the
/// directory, as `RESOLVE_BENEATH` answers it; `EINVAL` for what the walk
/// does not take; `ENOENT` for nothing at all.
fn components(path: &[u8]) -> Result<(&[u8], Vec<&[u8]>), Errno> {
    if path.is_empty() {
        return Err(Errno::NOENT);
    }
    if path.starts_with(b"/") {
        return Err(Errno::XDEV);
    }
    let mut names = Vec::new();
    for name in path.split(|byte| *byte == b'/') {
        if name == b".." {
            return Err(Errno::XDEV);
        }
        if name.is_empty() || name == b"." || name.contains(&0) {
            return Err(Errno::INVAL);
        }
        names.push(name);
    }
    // `split` yields at least one item, and none was empty.
    let last = names.pop().unwrap_or_default();
    Ok((last, names))
}

/// Whether a child is on another mount: another device, or a mount root, or
/// a kernel that cannot say (fails closed).
fn crossed(
    parent_dev: Result<u64, Errno>,
    child_dev: Result<u64, Errno>,
    child_attributes: Result<(u64, u64), Errno>,
) -> Result<bool, Errno> {
    /// `STATX_ATTR_MOUNT_ROOT`.
    const MOUNT_ROOT: u64 = 0x2000;
    let (mask, attributes) = child_attributes?;
    Ok(parent_dev? != child_dev? || mask & MOUNT_ROOT == 0 || attributes & MOUNT_ROOT != 0)
}

#[cfg(all(test, target_os = "linux"))]
thread_local! {
    /// Tests answer `openat2` with `ENOSYS`, as the broker unit's filter does.
    static NO_OPENAT2: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `body` with every `openat2` on this thread answered `ENOSYS`.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn without_openat2<T>(body: impl FnOnce() -> T) -> T {
    NO_OPENAT2.with(|cell| cell.set(true));
    let result = body();
    NO_OPENAT2.with(|cell| cell.set(false));
    result
}

#[cfg(target_os = "linux")]
pub(crate) use host::{open_beneath, open_root};

#[cfg(target_os = "linux")]
mod host {
    use std::os::fd::{AsFd, OwnedFd};

    use rustix::fs::{
        AtFlags, CWD, FileType, Mode, OFlags, ResolveFlags, StatxFlags, fstat, openat, statat,
        statx,
    };
    use rustix::io::Errno;

    use super::{Resolve, crossed, on_nosys};

    /// Whether the walk can open with `flags` and keep what `openat2` promises.
    /// `O_PATH` on a final link returns the link where `openat2` says `ELOOP`, so
    /// it needs `O_DIRECTORY`. With `NO_XDEV`, `openat2` refuses a crossing before
    /// it opens; the walk opens first, so no flag with a side effect on the open
    /// (`O_CREAT`, `O_TRUNC`, write access) may reach it.
    pub(super) fn walkable(flags: OFlags, no_xdev: bool) -> bool {
        let path_without_directory =
            flags.contains(OFlags::PATH) && !flags.contains(OFlags::DIRECTORY);
        let side_effects =
            flags.intersects(OFlags::CREATE | OFlags::TRUNC | OFlags::WRONLY | OFlags::RDWR);
        !(path_without_directory || no_xdev && side_effects)
    }

    /// Opens `/` with `RESOLVE_NO_SYMLINKS`. `/` has no component to be a
    /// link, so where `openat2` is `ENOSYS` a plain open is the same open.
    pub(crate) fn open_root(flags: OFlags, mode: Mode) -> Result<OwnedFd, Errno> {
        on_nosys(
            openat2_or_nosys(CWD, b"/", flags, mode, ResolveFlags::NO_SYMLINKS),
            || rustix::fs::open("/", flags, mode),
        )
    }

    /// `openat2`, or `ENOSYS` where a test says the filter is on.
    pub(super) fn openat2_or_nosys(
        dir: impl AsFd,
        path: &[u8],
        flags: OFlags,
        mode: Mode,
        resolve: ResolveFlags,
    ) -> Result<OwnedFd, Errno> {
        #[cfg(test)]
        if super::NO_OPENAT2.with(std::cell::Cell::get) {
            return Err(Errno::NOSYS);
        }
        rustix::fs::openat2(dir, path, flags, mode, resolve)
    }

    /// Opens `path` beneath `dir`: `openat2` with `resolve`, which must hold
    /// `RESOLVE_NO_SYMLINKS`, or the walk where `openat2` is `ENOSYS`.
    pub(crate) fn open_beneath(
        dir: &OwnedFd,
        path: &[u8],
        flags: OFlags,
        mode: Mode,
        resolve: ResolveFlags,
    ) -> Result<OwnedFd, Errno> {
        super::open(
            &mut Host {
                flags,
                mode,
                resolve,
            },
            dir,
            path,
        )
    }

    struct Host {
        flags: OFlags,
        mode: Mode,
        resolve: ResolveFlags,
    }

    // The raw field widths differ by architecture; the conversions may be
    // identities on some.
    #[allow(clippy::useless_conversion)]
    fn dev_of(fd: &OwnedFd) -> Result<u64, Errno> {
        fstat(fd).map(|stat| u64::from(stat.st_dev))
    }

    impl Resolve for Host {
        type Fd = OwnedFd;

        fn openat2(&mut self, dir: &OwnedFd, path: &[u8]) -> Result<OwnedFd, Errno> {
            openat2_or_nosys(dir, path, self.flags, self.mode, self.resolve)
        }

        fn step(&mut self, dir: &OwnedFd, name: &[u8]) -> Result<OwnedFd, Errno> {
            openat(
                dir,
                name,
                OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
        }

        fn last(&mut self, dir: &OwnedFd, name: &[u8]) -> Result<OwnedFd, Errno> {
            openat(
                dir,
                name,
                self.flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                self.mode,
            )
        }

        fn is_link(&mut self, dir: &OwnedFd, name: &[u8]) -> bool {
            statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
                .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Symlink)
        }

        fn walkable(&self) -> bool {
            walkable(self.flags, self.no_xdev())
        }

        fn no_xdev(&self) -> bool {
            self.resolve.contains(ResolveFlags::NO_XDEV)
        }

        fn crosses(&mut self, parent: &OwnedFd, child: &OwnedFd) -> Result<bool, Errno> {
            let attributes =
                statx(child, c"", AtFlags::EMPTY_PATH, StatxFlags::empty()).map(|extra| {
                    (
                        extra.stx_attributes_mask.bits(),
                        extra.stx_attributes.bits(),
                    )
                });
            crossed(dev_of(parent), dev_of(child), attributes)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use std::collections::BTreeMap;

    use proptest::prelude::*;
    use rustix::io::Errno;

    use super::{Resolve, components, crossed, on_nosys, open, walk};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Node {
        Dir { dev: u64, mount_root: bool },
        File,
        Link,
        Magic,
    }

    type Swap = Box<dyn FnMut(&mut Tree)>;

    /// A tree in memory. `openat2` is the kernel's resolution as the man page
    /// states it; `step` and `last` are `openat` with `O_NOFOLLOW`.
    #[allow(clippy::struct_excessive_bools)]
    struct Tree {
        nodes: Vec<Node>,
        edges: BTreeMap<(usize, Vec<u8>), usize>,
        xdev: bool,
        openat2: bool,
        steps: usize,
        /// Runs after every `step`: a racer renaming the tree under the walk.
        swap: Option<Swap>,
        /// `crosses` fails, as `fstat` would on a closed descriptor.
        broken_stat: bool,
        /// The caller's flags are ones the walk refuses.
        unwalkable: bool,
    }

    impl Tree {
        /// ```text
        /// /        dev 1
        ///   a/
        ///     b/
        ///       f
        ///     f
        ///     l  -> (symlink)
        ///     m  -> (magic link)
        ///   mnt/   dev 2, a mount root
        ///     f
        ///   bind/  dev 1, a mount root (a bind mount of the same file system)
        ///   f
        ///   l  -> (symlink)
        /// ```
        fn sample() -> Self {
            let mut tree = Self {
                nodes: vec![dir(1, false)],
                edges: BTreeMap::new(),
                xdev: false,
                openat2: true,
                steps: 0,
                swap: None,
                broken_stat: false,
                unwalkable: false,
            };
            let a = tree.add(0, b"a", dir(1, false));
            let b = tree.add(a, b"b", dir(1, false));
            tree.add(b, b"f", Node::File);
            tree.add(a, b"f", Node::File);
            tree.add(a, b"l", Node::Link);
            tree.add(a, b"m", Node::Magic);
            let mnt = tree.add(0, b"mnt", dir(2, true));
            tree.add(mnt, b"f", Node::File);
            tree.add(0, b"bind", dir(1, true));
            tree.add(0, b"f", Node::File);
            tree.add(0, b"l", Node::Link);
            tree
        }

        /// Adds `node` as `parent/name`, replacing what was there.
        fn add(&mut self, parent: usize, name: &[u8], node: Node) -> usize {
            let index = self.nodes.len();
            self.nodes.push(node);
            self.edges.insert((parent, name.to_vec()), index);
            index
        }

        fn child(&self, dir: usize, name: &[u8]) -> Result<(usize, Node), Errno> {
            let index = *self.edges.get(&(dir, name.to_vec())).ok_or(Errno::NOENT)?;
            Ok((index, self.nodes[index]))
        }

        fn mount(&self, node: usize) -> (u64, bool) {
            match self.nodes[node] {
                Node::Dir { dev, mount_root } => (dev, mount_root),
                _ => (1, false),
            }
        }

        fn crossing(&self, parent: usize, child: usize) -> bool {
            let (parent_dev, _) = self.mount(parent);
            let (child_dev, child_root) = self.mount(child);
            parent_dev != child_dev || child_root
        }

        /// `openat2(RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS [| NO_XDEV])`
        /// for a caller whose flags do not hold `O_PATH`.
        fn model(&self, dir: usize, path: &[u8]) -> Result<usize, Errno> {
            if path.is_empty() {
                return Err(Errno::NOENT);
            }
            if path.starts_with(b"/") {
                return Err(Errno::XDEV);
            }
            let names: Vec<&[u8]> = path.split(|byte| *byte == b'/').collect();
            let mut stack = vec![dir];
            for (index, name) in names.iter().enumerate() {
                let here = *stack.last().unwrap();
                let last = index + 1 == names.len();
                match *name {
                    b"" | b"." => {}
                    b".." => {
                        if stack.len() == 1 {
                            return Err(Errno::XDEV);
                        }
                        stack.pop();
                    }
                    name => match self.child(here, name)? {
                        (_, Node::Link | Node::Magic) => return Err(Errno::LOOP),
                        (_, Node::File) if !last => return Err(Errno::NOTDIR),
                        (index, Node::File) => stack.push(index),
                        (index, Node::Dir { .. }) => {
                            if self.xdev && self.crossing(here, index) {
                                return Err(Errno::XDEV);
                            }
                            stack.push(index);
                        }
                    },
                }
            }
            Ok(*stack.last().unwrap())
        }
    }

    fn dir(dev: u64, mount_root: bool) -> Node {
        Node::Dir { dev, mount_root }
    }

    impl Resolve for Tree {
        type Fd = usize;

        fn openat2(&mut self, dir: &usize, path: &[u8]) -> Result<usize, Errno> {
            if !self.openat2 {
                return Err(Errno::NOSYS);
            }
            self.model(*dir, path)
        }

        fn step(&mut self, dir: &usize, name: &[u8]) -> Result<usize, Errno> {
            // O_DIRECTORY | O_NOFOLLOW: a link of any kind is not a directory.
            let (opened, Node::Dir { .. }) = self.child(*dir, name)? else {
                return Err(Errno::NOTDIR);
            };
            self.steps += 1;
            if let Some(mut swap) = self.swap.take() {
                swap(self);
                self.swap = Some(swap);
            }
            Ok(opened)
        }

        fn last(&mut self, dir: &usize, name: &[u8]) -> Result<usize, Errno> {
            match self.child(*dir, name)? {
                (_, Node::Link | Node::Magic) => Err(Errno::LOOP),
                (index, _) => Ok(index),
            }
        }

        fn is_link(&mut self, dir: &usize, name: &[u8]) -> bool {
            matches!(self.child(*dir, name), Ok((_, Node::Link | Node::Magic)))
        }

        fn walkable(&self) -> bool {
            !self.unwalkable
        }

        fn no_xdev(&self) -> bool {
            self.xdev
        }

        fn crosses(&mut self, parent: &usize, child: &usize) -> Result<bool, Errno> {
            if self.broken_stat {
                return Err(Errno::BADF);
            }
            Ok(self.crossing(*parent, *child))
        }
    }

    fn walked(tree: &mut Tree, path: &str) -> Result<usize, Errno> {
        walk(tree, &0, path.as_bytes())
    }

    fn node_at(tree: &Tree, path: &str) -> usize {
        tree.model(0, path.as_bytes()).unwrap()
    }

    #[test]
    fn the_model_is_openat2_as_documented() {
        let mut tree = Tree::sample();
        let ab = node_at(&tree, "a/b");
        assert_eq!(tree.model(0, b"a/./b"), Ok(ab));
        assert_eq!(tree.model(0, b"a//b/"), Ok(ab));
        assert_eq!(tree.model(0, b"a/b/f/.."), Err(Errno::NOTDIR));
        assert_eq!(tree.model(0, b"a/b/.."), Ok(node_at(&tree, "a")));
        assert_eq!(tree.model(0, b"a/../.."), Err(Errno::XDEV));
        assert_eq!(tree.model(0, b"f/"), Err(Errno::NOTDIR));
        assert_eq!(tree.model(0, b"a/l/f"), Err(Errno::LOOP));
        assert_eq!(tree.model(0, b"a/m"), Err(Errno::LOOP));
        assert_eq!(tree.model(0, b""), Err(Errno::NOENT));
        assert_eq!(tree.model(0, b"/a"), Err(Errno::XDEV));
        assert_eq!(tree.model(0, b"mnt/.."), Ok(0));
        let mnt = node_at(&tree, "mnt");
        tree.xdev = true;
        assert_eq!(tree.model(0, b"mnt"), Err(Errno::XDEV));
        assert_eq!(tree.model(mnt, b".."), Err(Errno::XDEV));
        assert_eq!(tree.model(0, b"a/.."), Ok(0));
    }

    #[test]
    fn the_walk_opens_what_openat2_opens() {
        let mut tree = Tree::sample();
        for path in ["a", "a/b", "a/b/f", "a/f", "f", "mnt", "mnt/f", "bind"] {
            assert_eq!(walked(&mut tree, path), Ok(node_at(&tree, path)), "{path}");
        }
    }

    #[test]
    fn openat2_is_used_while_it_exists_and_the_walk_only_on_enosys() {
        let mut tree = Tree::sample();
        // openat2 accepts `.`; the walk never sees it while openat2 answers.
        assert_eq!(open(&mut tree, &0, b"a/./b"), Ok(node_at(&tree, "a/b")));
        assert_eq!(open(&mut tree, &0, b"a/l"), Err(Errno::LOOP));
        assert_eq!(tree.steps, 0);
        tree.openat2 = false;
        assert_eq!(open(&mut tree, &0, b"a/b/f"), Ok(node_at(&tree, "a/b/f")));
        assert_eq!(tree.steps, 2);
        assert_eq!(open(&mut tree, &0, b"a/./b"), Err(Errno::INVAL));
    }

    #[test]
    fn the_walk_refuses_flags_it_cannot_keep_openat2s_promises_for() {
        let mut tree = Tree::sample();
        tree.unwalkable = true;
        assert_eq!(walked(&mut tree, "a/f"), Err(Errno::INVAL));
        tree.openat2 = false;
        assert_eq!(open(&mut tree, &0, b"a/f"), Err(Errno::INVAL));
        tree.openat2 = true;
        assert_eq!(open(&mut tree, &0, b"a/f"), Ok(node_at(&tree, "a/f")));
    }

    #[test]
    fn the_fallback_runs_only_on_enosys() {
        for errno in [
            Errno::PERM,
            Errno::ACCESS,
            Errno::INVAL,
            Errno::LOOP,
            Errno::XDEV,
            Errno::NOENT,
            Errno::AGAIN,
            Errno::TOOBIG,
            Errno::NOTDIR,
            Errno::BADF,
        ] {
            assert_eq!(on_nosys(Err(errno), || Ok(7)), Err(errno), "{errno:?}");
        }
        assert_eq!(on_nosys(Err(Errno::NOSYS), || Ok(7)), Ok(7));
        assert_eq!(on_nosys(Ok(1), || Ok(7)), Ok(1));
    }

    #[test]
    fn the_walk_refuses_a_parent_component_even_one_that_stays_beneath() {
        let mut tree = Tree::sample();
        for path in ["..", "../a", "a/..", "a/../a", "a/b/../../f"] {
            assert_eq!(walked(&mut tree, path), Err(Errno::XDEV), "{path}");
        }
    }

    #[test]
    fn the_walk_refuses_an_absolute_path() {
        let mut tree = Tree::sample();
        for path in ["/", "/a", "/etc/shadow"] {
            assert_eq!(walked(&mut tree, path), Err(Errno::XDEV), "{path}");
        }
    }

    #[test]
    fn the_walk_refuses_a_symlinked_component_anywhere() {
        let mut tree = Tree::sample();
        assert_eq!(walked(&mut tree, "l"), Err(Errno::LOOP));
        assert_eq!(walked(&mut tree, "a/l"), Err(Errno::LOOP));
        assert_eq!(walked(&mut tree, "l/f"), Err(Errno::LOOP));
        assert_eq!(walked(&mut tree, "a/l/f"), Err(Errno::LOOP));
    }

    #[test]
    fn the_walk_refuses_a_magic_link_anywhere() {
        let mut tree = Tree::sample();
        assert_eq!(walked(&mut tree, "a/m"), Err(Errno::LOOP));
        assert_eq!(walked(&mut tree, "a/m/x"), Err(Errno::LOOP));
    }

    #[test]
    fn the_walk_refuses_what_it_does_not_take() {
        let mut tree = Tree::sample();
        assert_eq!(walked(&mut tree, ""), Err(Errno::NOENT));
        for path in ["a//b", "a/", ".", "a/.", "./a", "a\0"] {
            assert_eq!(walked(&mut tree, path), Err(Errno::INVAL), "{path:?}");
        }
        assert_eq!(walked(&mut tree, "f/x"), Err(Errno::NOTDIR));
        assert_eq!(walked(&mut tree, "a/nothing"), Err(Errno::NOENT));
        assert_eq!(walked(&mut tree, "nothing/f"), Err(Errno::NOENT));
    }

    #[test]
    fn the_walk_with_no_xdev_refuses_every_mount_crossing() {
        let mut tree = Tree::sample();
        tree.xdev = true;
        assert_eq!(walked(&mut tree, "mnt"), Err(Errno::XDEV));
        assert_eq!(walked(&mut tree, "mnt/f"), Err(Errno::XDEV));
        // A bind mount of the same file system has the same device.
        assert_eq!(walked(&mut tree, "bind"), Err(Errno::XDEV));
        assert_eq!(walked(&mut tree, "a/b/f"), Ok(node_at(&tree, "a/b/f")));
        tree.xdev = false;
        assert_eq!(walked(&mut tree, "mnt/f"), Ok(node_at(&tree, "mnt/f")));
    }

    #[test]
    fn the_walk_fails_closed_when_it_cannot_tell_the_mount() {
        let mut tree = Tree::sample();
        tree.xdev = true;
        tree.broken_stat = true;
        assert_eq!(walked(&mut tree, "a/f"), Err(Errno::BADF));
        assert_eq!(walked(&mut tree, "f"), Err(Errno::BADF));
    }

    #[test]
    fn a_component_swapped_for_a_link_mid_walk_is_refused() {
        let mut tree = Tree::sample();
        let a = node_at(&tree, "a");
        // Once `a` is open, a racer makes `a/b` a link.
        tree.swap = Some(Box::new(move |tree: &mut Tree| {
            tree.add(a, b"b", Node::Link);
        }));
        assert_eq!(walked(&mut tree, "a/b/f"), Err(Errno::LOOP));
    }

    #[test]
    fn a_parent_swapped_after_it_was_opened_changes_nothing() {
        let mut tree = Tree::sample();
        let expected = node_at(&tree, "a/b/f");
        // Once `a` is open, a racer replaces `/a` with a link. The walk holds
        // the directory it opened and finishes inside it.
        tree.swap = Some(Box::new(|tree: &mut Tree| {
            tree.add(0, b"a", Node::Link);
        }));
        assert_eq!(walked(&mut tree, "a/b/f"), Ok(expected));
        // The next walk meets the link.
        assert_eq!(walked(&mut tree, "a/b/f"), Err(Errno::LOOP));
    }

    #[test]
    fn a_mount_is_crossed_on_another_device_a_mount_root_or_an_unknown_answer() {
        assert_eq!(crossed(Ok(1), Ok(1), Ok((0x2000, 0))), Ok(false));
        assert_eq!(crossed(Ok(1), Ok(2), Ok((0x2000, 0))), Ok(true));
        assert_eq!(crossed(Ok(1), Ok(1), Ok((0x2000, 0x2000))), Ok(true));
        // A kernel that does not report the attribute cannot vouch for it.
        assert_eq!(crossed(Ok(1), Ok(1), Ok((0, 0))), Ok(true));
        assert_eq!(
            crossed(Err(Errno::BADF), Ok(1), Ok((0x2000, 0))),
            Err(Errno::BADF)
        );
        assert_eq!(
            crossed(Ok(1), Err(Errno::IO), Ok((0x2000, 0))),
            Err(Errno::IO)
        );
        assert_eq!(crossed(Ok(1), Ok(1), Err(Errno::NOSYS)), Err(Errno::NOSYS));
    }

    #[test]
    fn components_split_the_last_name_off() {
        assert_eq!(components(b"a"), Ok((&b"a"[..], vec![])));
        assert_eq!(
            components(b"a/b/c"),
            Ok((&b"c"[..], vec![&b"a"[..], &b"b"[..]]))
        );
    }

    fn plain(path: &[u8]) -> bool {
        !path.is_empty()
            && !path.starts_with(b"/")
            && path
                .split(|byte| *byte == b'/')
                .all(|name| !name.is_empty() && name != b"." && name != b"..")
    }

    fn any_path() -> impl Strategy<Value = Vec<u8>> {
        let name = prop::sample::select(vec![
            "a", "b", "f", "l", "m", "mnt", "bind", "x", ".", "..", "",
        ]);
        (any::<bool>(), prop::collection::vec(name, 0..6)).prop_map(|(absolute, names)| {
            let joined = names.join("/");
            if absolute {
                format!("/{joined}").into_bytes()
            } else {
                joined.into_bytes()
            }
        })
    }

    proptest! {
        /// On every path the walk takes it opens exactly what `openat2` opens;
        /// on every other path it refuses. It never opens what `openat2`
        /// refuses.
        #[test]
        fn the_walk_is_openat2_or_withholds(path in any_path(), xdev in any::<bool>()) {
            let mut tree = Tree::sample();
            tree.xdev = xdev;
            let expected = tree.model(0, &path);
            let got = walk(&mut tree, &0, &path);
            if plain(&path) {
                prop_assert_eq!(got, expected);
            } else {
                prop_assert!(got.is_err());
            }
            tree.openat2 = false;
            prop_assert_eq!(open(&mut tree, &0, &path).ok(), walk(&mut tree, &0, &path).ok());
        }
    }

    #[cfg(target_os = "linux")]
    mod host {
        use std::os::fd::OwnedFd;
        use std::path::{Path, PathBuf};

        use proptest::prelude::*;
        use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, fstat, open as open_path};
        use rustix::io::Errno;

        use super::super::host::{openat2_or_nosys, walkable};
        use super::super::{open_beneath, open_root, without_openat2};
        use super::{any_path, plain};

        const BENEATH: ResolveFlags = ResolveFlags::BENEATH
            .union(ResolveFlags::NO_SYMLINKS)
            .union(ResolveFlags::NO_MAGICLINKS);
        const FLAGS: OFlags = OFlags::RDONLY.union(OFlags::CLOEXEC);

        #[test]
        fn the_walk_refuses_o_path_on_a_possible_link_and_side_effects_under_no_xdev() {
            let ok = [
                (OFlags::RDONLY, false),
                (OFlags::PATH | OFlags::DIRECTORY, false),
                (OFlags::PATH | OFlags::DIRECTORY, true),
                (OFlags::RDONLY | OFlags::DIRECTORY, true),
                (OFlags::CREATE | OFlags::TRUNC | OFlags::RDWR, false),
            ];
            for (flags, xdev) in ok {
                assert!(walkable(flags, xdev), "{flags:?} {xdev}");
            }
            let refused = [
                (OFlags::PATH, false),
                (OFlags::PATH | OFlags::NOFOLLOW, true),
                (OFlags::CREATE, true),
                (OFlags::TRUNC, true),
                (OFlags::WRONLY, true),
                (OFlags::RDWR, true),
            ];
            for (flags, xdev) in refused {
                assert!(!walkable(flags, xdev), "{flags:?} {xdev}");
            }
        }

        fn scratch(label: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "xudo-beneath-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("a/b")).unwrap();
            std::fs::create_dir_all(dir.join("mnt")).unwrap();
            std::fs::create_dir_all(dir.join("bind")).unwrap();
            for file in ["a/b/f", "a/f", "f", "mnt/f"] {
                std::fs::write(dir.join(file), file).unwrap();
            }
            std::os::unix::fs::symlink("b", dir.join("a/l")).unwrap();
            std::os::unix::fs::symlink("/proc/self/cwd", dir.join("a/m")).unwrap();
            std::os::unix::fs::symlink("a", dir.join("l")).unwrap();
            std::os::unix::fs::symlink("/etc", dir.join("x")).unwrap();
            dir
        }

        fn dir_fd(path: &Path) -> OwnedFd {
            open_path(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap()
        }

        #[allow(clippy::useless_conversion)]
        fn identity(fd: &OwnedFd) -> (u64, u64) {
            let stat = fstat(fd).unwrap();
            (u64::from(stat.st_dev), u64::from(stat.st_ino))
        }

        fn opened(dir: &OwnedFd, path: &[u8], resolve: ResolveFlags) -> Option<(u64, u64)> {
            resolved(dir, path, resolve).ok()
        }

        fn resolved(
            dir: &OwnedFd,
            path: &[u8],
            resolve: ResolveFlags,
        ) -> Result<(u64, u64), Errno> {
            open_beneath(dir, path, FLAGS, Mode::empty(), resolve).map(|fd| identity(&fd))
        }

        #[test]
        fn the_real_walk_opens_what_openat2_opens() {
            let dir = scratch("same");
            let fd = dir_fd(&dir);
            for path in ["a", "a/b", "a/b/f", "a/f", "f"] {
                let kernel = opened(&fd, path.as_bytes(), BENEATH);
                assert!(kernel.is_some(), "{path}");
                let walked = without_openat2(|| opened(&fd, path.as_bytes(), BENEATH));
                assert_eq!(walked, kernel, "{path}");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn the_real_walk_refuses_links_parents_and_absolute_paths() {
            let dir = scratch("refuse");
            let fd = dir_fd(&dir);
            for path in ["l", "l/f", "a/l", "a/l/f", "a/m", "a/m/x", "x", "x/passwd"] {
                let refused = without_openat2(|| resolved(&fd, path.as_bytes(), BENEATH));
                assert_eq!(refused, Err(Errno::LOOP), "{path}");
                assert_eq!(resolved(&fd, path.as_bytes(), BENEATH), refused, "{path}");
            }
            for path in ["..", "a/../f", "/etc/passwd"] {
                let refused = without_openat2(|| {
                    open_beneath(&fd, path.as_bytes(), FLAGS, Mode::empty(), BENEATH)
                });
                assert_eq!(refused.unwrap_err(), Errno::XDEV, "{path}");
            }
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn the_real_walk_refuses_procs_magic_links() {
            let proc_self = dir_fd(Path::new("/proc/self"));
            for path in ["cwd", "root", "exe", "fd/0", "cwd/etc", "root/etc/passwd"] {
                let refused = without_openat2(|| resolved(&proc_self, path.as_bytes(), BENEATH));
                assert_eq!(refused, Err(Errno::LOOP), "{path}");
                assert_eq!(
                    resolved(&proc_self, path.as_bytes(), BENEATH),
                    refused,
                    "{path}"
                );
            }
        }

        #[test]
        fn the_real_walk_with_no_xdev_refuses_a_real_mount() {
            let root = dir_fd(Path::new("/"));
            let xdev = BENEATH.union(ResolveFlags::NO_XDEV);
            for path in ["proc", "proc/self"] {
                assert!(opened(&root, path.as_bytes(), xdev).is_none(), "{path}");
                let walked = without_openat2(|| {
                    open_beneath(&root, path.as_bytes(), FLAGS, Mode::empty(), xdev)
                });
                assert_eq!(walked.unwrap_err(), Errno::XDEV, "{path}");
            }
            // Without NO_XDEV the same mount is opened, both ways.
            let kernel = opened(&root, b"proc", BENEATH);
            assert!(kernel.is_some());
            assert_eq!(without_openat2(|| opened(&root, b"proc", BENEATH)), kernel);
        }

        #[test]
        fn the_test_switch_answers_openat2_with_enosys_and_only_inside() {
            let inside = without_openat2(|| {
                openat2_or_nosys(CWD, b"/", FLAGS, Mode::empty(), ResolveFlags::NO_SYMLINKS)
            });
            assert_eq!(inside.unwrap_err(), Errno::NOSYS);
            assert!(
                openat2_or_nosys(CWD, b"/", FLAGS, Mode::empty(), ResolveFlags::NO_SYMLINKS)
                    .is_ok()
            );
        }

        #[test]
        fn the_root_opens_with_or_without_openat2() {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
            let kernel = identity(&open_root(flags, Mode::empty()).unwrap());
            let plain = without_openat2(|| open_root(flags, Mode::empty())).unwrap();
            assert_eq!(identity(&plain), kernel);
        }

        proptest! {
            /// The real walk against the real `openat2`, on a real tree.
            #[test]
            fn the_real_walk_is_openat2_or_withholds(path in any_path()) {
                let dir = scratch("prop");
                let fd = dir_fd(&dir);
                let kernel = resolved(&fd, &path, BENEATH);
                let walked = without_openat2(|| resolved(&fd, &path, BENEATH));
                if plain(&path) {
                    prop_assert_eq!(walked, kernel, "{:?}", path);
                } else {
                    prop_assert!(walked.is_err());
                }
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
}
