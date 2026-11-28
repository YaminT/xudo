//! Reading the pack file named on the command line, through no symbolic link.
//!
//! `sudo xudo rules add --reviewed` runs this as root on a path the agent
//! that wrote the pack may control, any directory of it included. So:
//!
//! * **No component is a link.** The directories are opened with
//!   `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` (`openat2`, or the walk in
//!   `beneath.rs` where a filter answers it `ENOSYS`), and the last name with
//!   `O_PATH | O_NOFOLLOW`, which holds a link as the link. A directory swapped
//!   for a link to `/dev` or `/etc` after the review is refused, not followed.
//! * **Nothing is opened for reading before it is known to be a regular
//!   file.** The last name is held with `O_PATH`, which runs no driver's open:
//!   a watchdog, a tape or a serial line named through the path is never
//!   started, rewound or raised. Only after `fstat` says "regular file" is it
//!   opened for reading, through `/proc/self/fd`, which reopens that inode and
//!   no other, and `fstat` must then name the same inode again.
//! * **One fixed refusal.** Whatever failed (no such file, no permission, a
//!   link, a FIFO, a device, a directory), the text is the same, so root's
//!   answer does not tell the agent whether a path only root can see exists.
//!
//! Off Linux there is no `O_PATH`: the last name is opened for reading with
//! `O_NOFOLLOW` and the directories with `O_NOFOLLOW_ANY`. macOS is a
//! development platform, where nothing runs as root.
//!
//! `.` and empty components are dropped before anything is opened; `..` is
//! taken as the kernel takes it (refused only where the `ENOSYS` walk runs).

use rustix::io::Errno;

use super::{MAX_PACK_BYTES, PackFileError};

/// What reading a pack file asks of the system: a seam, so the order (check,
/// then open for reading) is tested without a kernel.
pub(super) trait PackFs {
    /// A held file or directory.
    type Fd;
    /// `/` for an absolute path, the working directory for a relative one.
    fn start(&mut self, absolute: bool) -> Result<Self::Fd, Errno>;
    /// The directories `path` names below `dir`, no component a link.
    fn parents(&mut self, dir: &Self::Fd, path: &[u8]) -> Result<Self::Fd, Errno>;
    /// `name` in `dir`, never followed, and on Linux not opened for reading.
    fn find(&mut self, dir: &Self::Fd, name: &[u8]) -> Result<Self::Fd, Errno>;
    /// Whether `fd` is a regular file, and its device and inode.
    fn stat(&mut self, fd: &Self::Fd) -> Result<(bool, u64, u64), Errno>;
    /// The file `fd` holds, opened for reading.
    fn reopen(&mut self, fd: &Self::Fd) -> Result<Self::Fd, Errno>;
    /// At most `limit` bytes of `fd`.
    fn read(&mut self, fd: Self::Fd, limit: u64) -> std::io::Result<Vec<u8>>;
}

/// The path as `(absolute, directories, last name)`, without `.` or empty
/// components. `None` when no name is left (`/`, `.`, empty).
fn split(path: &[u8]) -> Option<(bool, Vec<u8>, &[u8])> {
    let names: Vec<&[u8]> = path
        .split(|byte| *byte == b'/')
        .filter(|name| !name.is_empty() && *name != b".")
        .collect();
    let (last, parents) = names.split_last()?;
    Some((path.starts_with(b"/"), parents.join(&b'/'), last))
}

/// The device and inode of a regular file, from a `stat` answer.
fn regular(stat: Result<(bool, u64, u64), Errno>) -> Option<(u64, u64)> {
    match stat {
        Ok((true, dev, ino)) => Some((dev, ino)),
        _ => None,
    }
}

/// Reads the pack at `path`, shown as `shown`, through `fs`.
pub(super) fn read_with<F: PackFs>(
    fs: &mut F,
    path: &[u8],
    shown: &str,
) -> Result<Vec<u8>, PackFileError> {
    let unusable = || PackFileError::Unusable {
        path: shown.to_owned(),
    };
    let (absolute, parents, last) = split(path).ok_or_else(unusable)?;
    let start = fs.start(absolute).map_err(|_| unusable())?;
    let dir = if parents.is_empty() {
        start
    } else {
        fs.parents(&start, &parents).map_err(|_| unusable())?
    };
    let found = fs.find(&dir, last).map_err(|_| unusable())?;
    let identity = regular(fs.stat(&found)).ok_or_else(unusable)?;
    let opened = fs.reopen(&found).map_err(|_| unusable())?;
    if regular(fs.stat(&opened)) != Some(identity) {
        return Err(unusable());
    }
    let ceiling = u64::try_from(MAX_PACK_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    match fs.read(opened, ceiling) {
        Ok(bytes) if bytes.len() > MAX_PACK_BYTES => Err(PackFileError::TooLarge {
            path: shown.to_owned(),
        }),
        Ok(bytes) => Ok(bytes),
        Err(error) => Err(PackFileError::Read {
            path: shown.to_owned(),
            reason: error.to_string(),
        }),
    }
}

/// The running system.
pub(super) struct Host;

impl PackFs for Host {
    type Fd = std::os::fd::OwnedFd;

    #[cfg(target_os = "linux")]
    fn start(&mut self, absolute: bool) -> Result<Self::Fd, Errno> {
        use rustix::fs::{Mode, OFlags};
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        if absolute {
            crate::beneath::open_root(flags, Mode::empty())
        } else {
            rustix::fs::open(".", flags, Mode::empty())
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn start(&mut self, absolute: bool) -> Result<Self::Fd, Errno> {
        use rustix::fs::{Mode, OFlags};
        let at = if absolute { "/" } else { "." };
        rustix::fs::open(
            at,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    #[cfg(target_os = "linux")]
    fn parents(&mut self, dir: &Self::Fd, path: &[u8]) -> Result<Self::Fd, Errno> {
        use rustix::fs::{Mode, OFlags, ResolveFlags};
        crate::beneath::open_beneath(
            dir,
            path,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn parents(&mut self, dir: &Self::Fd, path: &[u8]) -> Result<Self::Fd, Errno> {
        use rustix::fs::{Mode, OFlags};
        rustix::fs::openat(
            dir,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW_ANY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    #[cfg(target_os = "linux")]
    fn find(&mut self, dir: &Self::Fd, name: &[u8]) -> Result<Self::Fd, Errno> {
        use rustix::fs::{Mode, OFlags};
        rustix::fs::openat(
            dir,
            name,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn find(&mut self, dir: &Self::Fd, name: &[u8]) -> Result<Self::Fd, Errno> {
        use rustix::fs::{Mode, OFlags};
        rustix::fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    fn stat(&mut self, fd: &Self::Fd) -> Result<(bool, u64, u64), Errno> {
        use rustix::fs::FileType;
        rustix::fs::fstat(fd).map(|stat| {
            let id = crate::FileId::of(&stat);
            (
                FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
                id.dev,
                id.ino,
            )
        })
    }

    #[cfg(target_os = "linux")]
    fn reopen(&mut self, fd: &Self::Fd) -> Result<Self::Fd, Errno> {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsRawFd as _;
        rustix::fs::open(
            format!("/proc/self/fd/{}", fd.as_raw_fd()),
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn reopen(&mut self, fd: &Self::Fd) -> Result<Self::Fd, Errno> {
        rustix::io::dup(fd)
    }

    fn read(&mut self, fd: Self::Fd, limit: u64) -> std::io::Result<Vec<u8>> {
        use std::io::Read as _;
        let mut bytes = Vec::new();
        std::fs::File::from(fd)
            .take(limit)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::collections::BTreeMap;

    use rustix::io::Errno;

    use super::{MAX_PACK_BYTES, PackFileError, PackFs, read_with, regular, split};

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Node {
        Dir,
        File(Vec<u8>),
        Link,
        Fifo,
        Device,
    }

    /// A machine in memory, keyed by the path as the walk builds it. It
    /// records what was found and what was opened for reading.
    #[derive(Default)]
    struct Fake {
        nodes: BTreeMap<Vec<u8>, Node>,
        found: Vec<Vec<u8>>,
        reopened: Vec<Vec<u8>>,
        /// The call that fails, by name.
        fail: Option<&'static str>,
        /// What `reopen` hands back instead of what it was given: a file
        /// replaced between the check and the open.
        swap: Option<Vec<u8>>,
        /// `stat` on the opened file fails.
        stat_fails_after_reopen: bool,
    }

    impl Fake {
        /// ```text
        /// /dev/watchdog   a device
        /// /etc/shadow     a secret
        /// /home/x/        the agent's directory
        /// /home/x/pack    the pack the operator reviewed
        /// /home/l         a link (to /dev, say)
        /// /home/x/link    a link
        /// /home/x/fifo    a FIFO
        /// /home/x/dir/    a directory
        /// rel/pack        a pack below the working directory
        /// ```
        fn sample() -> Self {
            let mut fake = Self::default();
            for (path, node) in [
                ("/dev", Node::Dir),
                ("/dev/watchdog", Node::Device),
                ("/etc", Node::Dir),
                ("/etc/shadow", Node::File(b"root:secret".to_vec())),
                ("/home", Node::Dir),
                ("/home/x", Node::Dir),
                ("/home/x/pack", Node::File(b"[pack]".to_vec())),
                ("/home/l", Node::Link),
                ("/home/x/link", Node::Link),
                ("/home/x/fifo", Node::Fifo),
                ("/home/x/dir", Node::Dir),
                ("./rel", Node::Dir),
                ("./rel/pack", Node::File(b"[pack] rel".to_vec())),
                ("./big", Node::File(vec![b'#'; MAX_PACK_BYTES + 1])),
            ] {
                fake.nodes.insert(path.as_bytes().to_vec(), node);
            }
            fake
        }

        fn failing(&self, call: &str) -> Result<(), Errno> {
            if self.fail == Some(call) {
                Err(Errno::ACCESS)
            } else {
                Ok(())
            }
        }

        fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
            let mut path = dir.to_vec();
            if path != b"/" {
                path.push(b'/');
            }
            path.extend_from_slice(name);
            path
        }
    }

    impl PackFs for Fake {
        type Fd = Vec<u8>;

        fn start(&mut self, absolute: bool) -> Result<Vec<u8>, Errno> {
            self.failing("start")?;
            Ok(if absolute {
                b"/".to_vec()
            } else {
                b".".to_vec()
            })
        }

        fn parents(&mut self, dir: &Vec<u8>, path: &[u8]) -> Result<Vec<u8>, Errno> {
            self.failing("parents")?;
            let mut here = dir.clone();
            for name in path.split(|byte| *byte == b'/') {
                here = Self::join(&here, name);
                match self.nodes.get(&here) {
                    Some(Node::Dir) => {}
                    Some(Node::Link) => return Err(Errno::LOOP),
                    Some(_) => return Err(Errno::NOTDIR),
                    None => return Err(Errno::NOENT),
                }
            }
            Ok(here)
        }

        fn find(&mut self, dir: &Vec<u8>, name: &[u8]) -> Result<Vec<u8>, Errno> {
            self.failing("find")?;
            let path = Self::join(dir, name);
            self.nodes.get(&path).ok_or(Errno::NOENT)?;
            self.found.push(path.clone());
            Ok(path)
        }

        fn stat(&mut self, fd: &Vec<u8>) -> Result<(bool, u64, u64), Errno> {
            if self.stat_fails_after_reopen && self.reopened.contains(fd) {
                return Err(Errno::IO);
            }
            let index = self.nodes.keys().position(|key| key == fd).unwrap();
            let node = &self.nodes[fd];
            Ok((matches!(node, Node::File(_)), 1, index as u64))
        }

        fn reopen(&mut self, fd: &Vec<u8>) -> Result<Vec<u8>, Errno> {
            self.failing("reopen")?;
            let opened = self.swap.clone().unwrap_or_else(|| fd.clone());
            self.reopened.push(opened.clone());
            Ok(opened)
        }

        fn read(&mut self, fd: Vec<u8>, limit: u64) -> std::io::Result<Vec<u8>> {
            if self.fail == Some("read") {
                return Err(std::io::Error::other("device gone"));
            }
            let Some(Node::File(bytes)) = self.nodes.get(&fd) else {
                return Err(std::io::Error::other("not a file"));
            };
            Ok(bytes
                .iter()
                .copied()
                .take(usize::try_from(limit).unwrap())
                .collect())
        }
    }

    fn read(fake: &mut Fake, path: &str) -> Result<Vec<u8>, PackFileError> {
        read_with(fake, path.as_bytes(), path)
    }

    fn unusable(path: &str) -> PackFileError {
        PackFileError::Unusable {
            path: path.to_owned(),
        }
    }

    #[test]
    fn a_regular_pack_is_checked_then_opened_once() {
        let mut fake = Fake::sample();
        assert_eq!(read(&mut fake, "/home/x/pack").unwrap(), b"[pack]");
        assert_eq!(fake.reopened, vec![b"/home/x/pack".to_vec()]);
        let mut fake = Fake::sample();
        assert_eq!(read(&mut fake, "rel/pack").unwrap(), b"[pack] rel");
        let mut fake = Fake::sample();
        assert_eq!(read(&mut fake, "/home/./x//pack").unwrap(), b"[pack]");
    }

    #[test]
    fn a_parent_directory_swapped_for_a_link_to_dev_opens_nothing() {
        // The agent turned `/home/l` into a link to `/dev` after the review:
        // root must not even look up `watchdog`.
        let mut fake = Fake::sample();
        assert_eq!(
            read(&mut fake, "/home/l/watchdog"),
            Err(unusable("/home/l/watchdog"))
        );
        assert!(fake.found.is_empty());
        assert!(fake.reopened.is_empty());
    }

    #[test]
    fn a_device_named_directly_is_held_but_never_opened_for_reading() {
        let mut fake = Fake::sample();
        assert_eq!(
            read(&mut fake, "/dev/watchdog"),
            Err(unusable("/dev/watchdog"))
        );
        assert_eq!(fake.found, vec![b"/dev/watchdog".to_vec()]);
        assert!(fake.reopened.is_empty());
    }

    #[test]
    fn a_last_component_link_a_fifo_or_a_directory_is_never_opened_for_reading() {
        for path in ["/home/x/link", "/home/x/fifo", "/home/x/dir", "/home/x/.."] {
            let mut fake = Fake::sample();
            assert_eq!(read(&mut fake, path), Err(unusable(path)), "{path}");
            assert!(fake.reopened.is_empty(), "{path}");
        }
    }

    #[test]
    fn a_file_swapped_between_the_check_and_the_open_is_refused() {
        let mut fake = Fake::sample();
        fake.swap = Some(b"/etc/shadow".to_vec());
        assert_eq!(
            read(&mut fake, "/home/x/pack"),
            Err(unusable("/home/x/pack"))
        );
        let mut fake = Fake::sample();
        fake.stat_fails_after_reopen = true;
        assert_eq!(
            read(&mut fake, "/home/x/pack"),
            Err(unusable("/home/x/pack"))
        );
    }

    #[test]
    fn every_failure_reads_the_same_so_root_reveals_no_path() {
        let cases = [
            ("start", "/home/x/pack"),
            ("parents", "/home/x/pack"),
            ("find", "/home/x/pack"),
            ("reopen", "/home/x/pack"),
        ];
        for (fail, path) in cases {
            let mut fake = Fake::sample();
            fake.fail = Some(fail);
            assert_eq!(read(&mut fake, path), Err(unusable(path)), "{fail}");
        }
        // A missing file, a missing directory and a file used as a directory
        // read exactly like a secret that exists.
        let texts: Vec<String> = [
            "/etc/nothing",
            "/nowhere/pack",
            "/etc/shadow/x",
            "/home/l/shadow",
        ]
        .iter()
        .map(|path| {
            read(&mut Fake::sample(), path)
                .unwrap_err()
                .to_string()
                .replace(path, "P")
        })
        .collect();
        assert!(texts.iter().all(|text| *text == texts[0]), "{texts:?}");
        for path in ["", "/", ".", "./"] {
            assert_eq!(read(&mut Fake::sample(), path), Err(unusable(path)));
        }
    }

    #[test]
    fn an_oversized_or_unreadable_pack_says_so_after_the_check() {
        let mut fake = Fake::sample();
        assert_eq!(
            read(&mut fake, "big"),
            Err(PackFileError::TooLarge {
                path: "big".to_owned()
            })
        );
        let mut fake = Fake::sample();
        fake.fail = Some("read");
        assert_eq!(
            read(&mut fake, "/home/x/pack"),
            Err(PackFileError::Read {
                path: "/home/x/pack".to_owned(),
                reason: "device gone".to_owned()
            })
        );
    }

    #[test]
    fn the_fake_reads_only_files() {
        let mut fake = Fake::sample();
        assert!(fake.read(b"/home/x".to_vec(), 1).is_err());
    }

    #[test]
    fn split_drops_dot_and_empty_components() {
        assert_eq!(split(b"a"), Some((false, Vec::new(), &b"a"[..])));
        assert_eq!(
            split(b"//a/./b//c/"),
            Some((true, b"a/b".to_vec(), &b"c"[..]))
        );
        assert_eq!(split(b"../p"), Some((false, b"..".to_vec(), &b"p"[..])));
        assert_eq!(split(b"/."), None);
        assert_eq!(regular(Err(Errno::IO)), None);
        assert_eq!(regular(Ok((false, 1, 2))), None);
        assert_eq!(regular(Ok((true, 1, 2))), Some((1, 2)));
    }
}
