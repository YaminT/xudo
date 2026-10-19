//! Whether the filesystems under the ruleset are ones a non-root user made.
//!
//! The trust walk in [`crate::trust`] checks every component's owner and mode on
//! the descriptor it opened. That evidence is only as good as the filesystem
//! reporting it. A FUSE filesystem reports whatever owner and mode its daemon
//! likes, and any user can mount one through the set-user-ID `fusermount3`; an
//! idmapped mount reports owners through a mapping; removable media a user
//! mounted holds whatever that user wrote on it. So the walk matches every
//! descriptor it opens to its mount, and judges the mount before it believes
//! anything else about the component.
//!
//! # Which mount a descriptor is on
//!
//! The one `/proc/thread-self/fdinfo/<fd>` names as `mnt_id`, which is the first
//! field of that mount's line in `/proc/thread-self/mountinfo`. Exact. `mnt_id`
//! is in fdinfo since Linux 3.15 and `/proc/thread-self` exists since 3.17; on
//! an older kernel the read fails, and a read that fails refuses.
//!
//! Not by `st_dev`. btrfs gives every subvolume a device number of its own, and
//! none of them appears in mountinfo, so on a btrfs root — Fedora's default — no
//! descriptor's `st_dev` matches any mount at all; overlayfs reports a per-layer
//! device for some files; and two mounts of one filesystem share a device while
//! differing in exactly the options judged below. Measured on Linux 6.12: two
//! btrfs mounts listed as `0:72`, files on them reporting `0:73` and `0:74`, and
//! `fdinfo` telling the two mounts of subvolume `0:74` apart (see
//! `docs/CONCERNS.md`, 2026-10-19).
//!
//! The id cannot be reissued to another mount while the descriptor is open,
//! because an open descriptor keeps its mount alive. A mount detached after the
//! open simply stops being listed, and an unlisted mount is refused.
//!
//! # What is refused
//!
//! The kernel does not record who asked for a mount. In the initial user
//! namespace every mount needs `CAP_SYS_ADMIN`, so a non-root user mounts only
//! through something running as root on their behalf — the set-user-ID
//! `fusermount3` and `mount(8)`, or the udisks2 daemon — and each leaves marks:
//!
//! * `fusermount3` records the user as the FUSE filesystem's `user_id`. A
//!   `fuse`, `fuseblk`, or `fuse.<subtype>` mount is refused unless it names
//!   exactly one `user_id` and that is `0`.
//! * `fusermount3`, udisks2, and `mount(8)` for an fstab entry marked `user`,
//!   `users`, `owner`, or `group` all mount `nosuid`; `user` and `users` imply
//!   `noexec` as well. Under the ruleset a mount carrying either is refused, as
//!   the design plan says of `/etc/aido` ([`MountPolicy::Ruleset`]). Under any
//!   other root-owned path it is not: root's own mounts carry the same marks —
//!   `/run`, which holds the gate's spool, is `nosuid` on every systemd host —
//!   so there they are evidence of nothing ([`MountPolicy::RootPath`]).
//! * An `idmapped` mount reports owners translated through a mapping chosen at
//!   mount time, not the owners on disk. Refused to every reader.
//! * A thread outside the initial user namespace reads uid 0 as that
//!   namespace's owner rather than root, and the kernel prints a FUSE mount's
//!   `user_id` relative to the user namespace the mount was made in, which
//!   mountinfo does not name. Everything is refused there. A kernel built
//!   without user namespaces has only the initial one.
//!
//! What is accepted, and why, is recorded in `docs/CONCERNS.md`: in short,
//! anything else root mounted, network and virtual filesystems included,
//! because root chose to put it there.
//!
//! # Where the table comes from
//!
//! `/proc`, and believed only on proof: every file is read through a descriptor
//! that `fstatfs` reports to be on procfs, because a hostile mount over `/proc`
//! could otherwise hand back a table of its choosing. `thread-self` rather than
//! `self`: the walk resolved its paths in this thread's mount namespace, and the
//! descriptors are in this thread's descriptor table. Anything that cannot be
//! read, parsed, or found refuses.

use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use bstr::BString;

use crate::error::SysError;
use crate::proc::MountEntry;
use crate::trust::TrustError;

/// How `/proc/<pid>/ns/user` reads in the initial user namespace.
///
/// The number is the kernel's fixed `PROC_USER_INIT_INO`, `0xEFFFFFFD`.
pub(crate) const INITIAL_USER_NAMESPACE: &[u8] = b"user:[4026531837]";

/// What the trust walk asks about mounts.
///
/// A trait so the walk can be tested against tables no test host has: a FUSE
/// mount a user made, a btrfs, a namespace.
pub(crate) trait MountView {
    /// The mount table, this thread's user namespace, and the mount each of
    /// `fds` is on, read together.
    ///
    /// # Errors
    ///
    /// [`SysError`] when any of it cannot be read or cannot be believed.
    fn inspect(&self, fds: &[BorrowedFd<'_>]) -> Result<Inspection, SysError>;
}

/// What [`MountView::inspect`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Inspection {
    /// Every mount this thread can see.
    pub(crate) table: Vec<MountEntry>,
    /// This thread's user namespace, as its `/proc` link reads.
    pub(crate) user_namespace: Vec<u8>,
    /// The mount id of each descriptor, in the order they were asked about.
    pub(crate) mount_ids: Vec<u32>,
}

/// Why a mount's word on who owns a file is not taken.
///
/// Each reason reads after the mount it is about, as in "/etc/aido is on
/// fuse.sshfs at /etc/aido, a FUSE filesystem mounted by uid 1000, ...".
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MountRefusal {
    /// A FUSE filesystem a non-root user mounted.
    #[error(
        "a FUSE filesystem mounted by uid {uid}, so every owner and mode on it is whatever \
         that user's daemon chooses to report"
    )]
    FuseUser {
        /// Its `user_id`.
        uid: u32,
    },
    /// A FUSE filesystem that does not name exactly one `user_id`.
    #[error(
        "a FUSE filesystem that does not name exactly one user_id, so who serves it is unknown"
    )]
    FuseOwnerUnknown,
    /// An idmapped mount.
    #[error(
        "an idmapped mount, so the owners it reports are a mapping chosen at mount time, not \
         the owners on disk"
    )]
    Idmapped,
    /// A mount with `nosuid`.
    #[error(
        "mounted nosuid, the mark of removable media and of mounts a user may make, so what is \
         on it need not be root's"
    )]
    NoSuid,
    /// A mount with `noexec`.
    #[error(
        "mounted noexec, the mark of removable media and of mounts a user may make, so what is \
         on it need not be root's"
    )]
    NoExec,
}

/// How much a mount must prove: which of its marks are refused.
///
/// Two, because the walk has two kinds of reader. Every reader needs the owners
/// a filesystem reports to be owners it can believe. Only the ruleset readers
/// also refuse a mount for merely carrying the marks a user's mount carries,
/// because those marks are on root's own mounts too: systemd mounts `/run`
/// `nosuid` on every host, and the gate's spool, `/run/aido/req`, is under it;
/// `/var`, and with it `/var/lib/aido`, is `nosuid` on some.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountPolicy {
    /// Any root-owned path, as [`crate::trust::open_trusted`] opens one: a
    /// mount is refused when the owners it reports cannot be believed — a
    /// user's FUSE, an idmapped mount — and when it is not listed.
    RootPath,
    /// The ruleset, as [`crate::trust::read_trusted_dir`] and
    /// [`crate::trust::load_trusted_rules`] read it: all of the above, and a
    /// mount carrying `nosuid` or `noexec`, as the design plan says of
    /// `/etc/aido`.
    Ruleset,
}

impl MountPolicy {
    /// The per-mount options refused under this policy, each with its reason,
    /// in the order they are reported.
    fn marks(self) -> &'static [(&'static [u8], MountRefusal)] {
        match self {
            Self::RootPath => &[(b"idmapped", MountRefusal::Idmapped)],
            Self::Ruleset => &[
                (b"idmapped", MountRefusal::Idmapped),
                (b"nosuid", MountRefusal::NoSuid),
                (b"noexec", MountRefusal::NoExec),
            ],
        }
    }
}

/// What is wrong with a mount under `policy`, or `None` if nothing is.
///
/// FUSE first: when its daemon is a user's, nothing else about the mount is
/// worth reporting. A FUSE mount that root made is then judged like any other
/// mount, so a stick a desktop automounted through a root-run `ntfs-3g` is
/// still refused for the ruleset by the `nosuid` udisks2 gave it.
pub(crate) fn refusal(entry: &MountEntry, policy: MountPolicy) -> Option<MountRefusal> {
    if is_fuse(&entry.fs_type) {
        let mut owners = entry.super_option_values(b"user_id");
        match (owners.next().and_then(user_id_value), owners.next()) {
            (Some(0), None) => {}
            (Some(uid), None) => return Some(MountRefusal::FuseUser { uid }),
            _ => return Some(MountRefusal::FuseOwnerUnknown),
        }
    }
    policy
        .marks()
        .iter()
        .find(|(option, _)| entry.has_mount_option(option))
        .map(|(_, refused)| refused.clone())
}

/// Whether a filesystem type is FUSE: `fuse` or `fuseblk`, with or without a
/// subtype. The kernel writes the subtype after the type and a dot, so a FUSE
/// daemon can choose what follows the dot and never what precedes it.
fn is_fuse(fs_type: &[u8]) -> bool {
    matches!(
        fs_type.split(|byte| *byte == b'.').next(),
        Some(b"fuse" | b"fuseblk")
    )
}

/// A `user_id` value: decimal digits and nothing else.
fn user_id_value(value: &[u8]) -> Option<u32> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse().ok())
}

/// Judges the mount of every descriptor in `opened` under `policy`, outermost
/// first.
///
/// # Errors
///
/// [`TrustError::MountTable`] when the table cannot be read or believed,
/// [`TrustError::NamespacedRoot`] outside the initial user namespace, and
/// otherwise the first component whose mount is unlisted or refused.
pub(crate) fn check(
    view: &dyn MountView,
    opened: &[(&Path, BorrowedFd<'_>)],
    policy: MountPolicy,
) -> Result<(), TrustError> {
    let fds: Vec<BorrowedFd<'_>> = opened.iter().map(|(_, fd)| *fd).collect();
    let seen = view.inspect(&fds).map_err(|error| TrustError::MountTable {
        reason: error.to_string(),
    })?;
    let paths: Vec<&Path> = opened.iter().map(|(path, _)| *path).collect();
    judge(&paths, &seen, policy)
}

/// The pure half of [`check`].
fn judge(paths: &[&Path], seen: &Inspection, policy: MountPolicy) -> Result<(), TrustError> {
    if seen.user_namespace != INITIAL_USER_NAMESPACE {
        return Err(TrustError::NamespacedRoot {
            namespace: BString::from(seen.user_namespace.clone()),
        });
    }
    // A component without an answer would otherwise be skipped by the zip
    // below, and a skipped component is one nobody judged.
    if seen.mount_ids.len() != paths.len() {
        return Err(TrustError::MountTable {
            reason: format!(
                "asked which mount {} descriptor(s) are on and told about {}",
                paths.len(),
                seen.mount_ids.len()
            ),
        });
    }
    for (path, mount_id) in paths.iter().zip(&seen.mount_ids) {
        judge_one(path, *mount_id, &seen.table, policy)?;
    }
    Ok(())
}

/// Judges one component against every line the table has for its mount.
///
/// Every line, not the first: a table read while mounts changed can list one
/// mount twice, and each listing must pass.
fn judge_one(
    at: &Path,
    mount_id: u32,
    table: &[MountEntry],
    policy: MountPolicy,
) -> Result<(), TrustError> {
    let mut listed = false;
    for entry in table.iter().filter(|entry| entry.mount_id == mount_id) {
        listed = true;
        if let Some(reason) = refusal(entry, policy) {
            return Err(TrustError::UntrustedMount {
                at: at.display().to_string(),
                fs_type: BString::from(entry.fs_type.clone()),
                mount_point: BString::from(entry.mount_point.clone()),
                reason,
            });
        }
    }
    if listed {
        Ok(())
    } else {
        Err(TrustError::MountUnlisted {
            at: at.display().to_string(),
            mount_id,
        })
    }
}

/// The mount table of this machine, read through `/proc`.
#[derive(Clone, Debug)]
pub(crate) struct HostMounts {
    root: PathBuf,
}

impl HostMounts {
    /// Reads through the real `/proc`.
    pub(crate) fn proc() -> Self {
        Self::at(Path::new("/proc"))
    }

    /// Reads through whatever is at `root`, which must prove itself procfs.
    pub(crate) fn at(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl MountView for HostMounts {
    fn inspect(&self, _fds: &[BorrowedFd<'_>]) -> Result<Inspection, SysError> {
        Err(SysError::unsupported(format!(
            "reading {}/thread-self/mountinfo",
            self.root.display()
        )))
    }
}

#[cfg(target_os = "linux")]
mod host {
    //! The Linux half: every file read through a descriptor proven to be on
    //! procfs.

    use std::ffi::CString;
    use std::io::Read;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

    use rustix::fs::{Mode, OFlags, fstatfs, open, openat, readlinkat};
    use rustix::io::Errno;

    use super::{HostMounts, INITIAL_USER_NAMESPACE, Inspection, MountView};
    use crate::error::SysError;
    use crate::proc::{parse_fdinfo_mount_id, parse_mountinfo};

    /// The mount table, relative to the procfs root.
    const MOUNTINFO: &str = "thread-self/mountinfo";

    /// What [`user_namespace`] answers when the link cannot be read. Not a
    /// namespace any kernel names, so it is refused like a foreign one.
    pub(super) const UNREADABLE: &[u8] = b"(unreadable)";

    impl MountView for HostMounts {
        fn inspect(&self, fds: &[BorrowedFd<'_>]) -> Result<Inspection, SysError> {
            open(
                &self.root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| SysError::read(self.root.display().to_string(), error.to_string()))
            .and_then(|root| inspect_at(root.as_fd(), fds))
        }
    }

    /// [`HostMounts::inspect`] with the procfs root open.
    ///
    /// Written as one chain rather than with `?`: each failure is still
    /// propagated, and each is reached by a test of the function that
    /// produces it.
    fn inspect_at(root: BorrowedFd<'_>, fds: &[BorrowedFd<'_>]) -> Result<Inspection, SysError> {
        read_verified(root, MOUNTINFO)
            .and_then(|text| parse_mountinfo(MOUNTINFO, &text))
            .and_then(|table| {
                fds.iter()
                    .map(|fd| mount_id(root, *fd))
                    .collect::<Result<Vec<u32>, SysError>>()
                    .map(|mount_ids| Inspection {
                        table,
                        user_namespace: user_namespace(root),
                        mount_ids,
                    })
            })
    }

    /// The mount `fd` was opened through.
    fn mount_id(root: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> Result<u32, SysError> {
        let name = format!("thread-self/fdinfo/{}", fd.as_raw_fd());
        read_verified(root, &name).and_then(|text| parse_fdinfo_mount_id(&name, &text))
    }

    /// This thread's user namespace, read from the `user` link in its `ns`
    /// directory: what [`user_namespace_from`] makes of the link, or
    /// [`UNREADABLE`] when the directory cannot be opened or is not on procfs.
    pub(super) fn user_namespace(root: BorrowedFd<'_>) -> Vec<u8> {
        verified_open(root, "thread-self/ns", OFlags::DIRECTORY).map_or(UNREADABLE.to_vec(), |ns| {
            user_namespace_from(readlinkat(&ns, "user", Vec::new()))
        })
    }

    /// What reading the `user` link, in an `ns` directory already proven to
    /// be on procfs, says about this thread's user namespace.
    ///
    /// The link itself when it reads. `ENOENT` is the initial namespace: a
    /// kernel built without `CONFIG_USER_NS` lists no `user` entry there, and
    /// has no user namespace but the initial one, while every kernel built
    /// with it lists the entry for every thread. Anything else that fails is
    /// [`UNREADABLE`], and refused.
    pub(super) fn user_namespace_from(link: Result<CString, Errno>) -> Vec<u8> {
        match link {
            Ok(link) => link.into_bytes(),
            Err(Errno::NOENT) => INITIAL_USER_NAMESPACE.to_vec(),
            Err(_) => UNREADABLE.to_vec(),
        }
    }

    /// Whether a descriptor is on procfs.
    fn on_procfs(fd: BorrowedFd<'_>) -> bool {
        fstatfs(fd)
            .is_ok_and(|stat| i128::from(stat.f_type) == i128::from(rustix::fs::PROC_SUPER_MAGIC))
    }

    /// Opens `name` under the procfs root without following a final link, and
    /// keeps the descriptor only if it is on procfs.
    pub(super) fn verified_open(
        root: BorrowedFd<'_>,
        name: &str,
        extra: OFlags,
    ) -> Result<OwnedFd, SysError> {
        let fd = openat(
            root,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | extra,
            Mode::empty(),
        )
        .map_err(|error| SysError::read(name, error.to_string()))?;
        if on_procfs(fd.as_fd()) {
            Ok(fd)
        } else {
            Err(SysError::read(
                name,
                "not on procfs, so what it says about this process's mounts cannot be believed",
            ))
        }
    }

    /// Reads `name` through a descriptor [`verified_open`] accepted.
    pub(super) fn read_verified(root: BorrowedFd<'_>, name: &str) -> Result<Vec<u8>, SysError> {
        verified_open(root, name, OFlags::empty()).and_then(|fd| {
            let mut bytes = Vec::new();
            std::fs::File::from(fd)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
                .map_err(|error| SysError::read(name, error.to_string()))
        })
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A mount table a test writes.

    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::os::fd::BorrowedFd;

    use super::{INITIAL_USER_NAMESPACE, Inspection, MountView};
    use crate::error::SysError;
    use crate::proc::{MountEntry, parse_mountinfo};

    /// A root-made ext4 root, the shape of an ordinary host.
    pub(crate) const EXT4_ROOT: &str = "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";

    /// Which mount the fake says each descriptor is on.
    pub(crate) enum Ids {
        /// Every descriptor on this mount.
        All(u32),
        /// These ids, one per descriptor in the order descriptors are asked
        /// about, across every inspection: the walk asks about each component
        /// in turn, outermost first, and a directory reader about its rule
        /// files after. Fewer ids than descriptors is an answer that falls
        /// short.
        Each(Vec<u32>),
    }

    /// What a test does to the filesystem while a mount is being judged: the
    /// moment after a descriptor is opened and before anything about it is
    /// believed.
    pub(crate) type Meanwhile = Box<dyn Fn()>;

    /// A [`MountView`] that answers from a script.
    pub(crate) struct FakeMounts {
        pub(crate) table: Vec<MountEntry>,
        pub(crate) ids: Ids,
        pub(crate) user_namespace: Vec<u8>,
        pub(crate) fail: Option<SysError>,
        /// How many descriptors have been asked about so far.
        pub(crate) asked: Cell<usize>,
        pub(crate) meanwhile: Option<Meanwhile>,
    }

    impl FakeMounts {
        /// The mounts in `table`, in the initial user namespace.
        pub(crate) fn new(table: &str, ids: Ids) -> Self {
            Self {
                table: parse_mountinfo("fake/mountinfo", table.as_bytes()).unwrap(),
                ids,
                user_namespace: INITIAL_USER_NAMESPACE.to_vec(),
                fail: None,
                asked: Cell::new(0),
                meanwhile: None,
            }
        }

        /// Every descriptor on [`EXT4_ROOT`].
        pub(crate) fn ext4() -> Self {
            Self::new(EXT4_ROOT, Ids::All(1))
        }
    }

    impl MountView for FakeMounts {
        fn inspect(&self, fds: &[BorrowedFd<'_>]) -> Result<Inspection, SysError> {
            if let Some(error) = &self.fail {
                return Err(error.clone());
            }
            let first = self
                .asked
                .replace(self.asked.get().saturating_add(fds.len()));
            if let Some(meanwhile) = &self.meanwhile {
                meanwhile();
            }
            let mount_ids = match &self.ids {
                Ids::All(id) => vec![*id; fds.len()],
                Ids::Each(ids) => ids.iter().skip(first).take(fds.len()).copied().collect(),
            };
            Ok(Inspection {
                table: self.table.clone(),
                user_namespace: self.user_namespace.clone(),
                mount_ids,
            })
        }
    }
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

    use std::os::fd::AsFd;

    use super::fake::{EXT4_ROOT, FakeMounts, Ids};
    use super::*;
    use crate::proc::parse_mountinfo;

    fn entry(line: &str) -> MountEntry {
        parse_mountinfo("t", format!("{line}\n").as_bytes())
            .unwrap()
            .remove(0)
    }

    /// Both policies, the stricter last.
    const POLICIES: [MountPolicy; 2] = [MountPolicy::RootPath, MountPolicy::Ruleset];

    #[test]
    fn a_fuse_mount_is_refused_unless_root_mounted_it() {
        // `fusermount3` writes the invoking user's uid as `user_id`, and the
        // user's daemon then answers every stat. Root's own FUSE mounts, made
        // through mount(2) directly, name uid 0. Whose daemon answers matters
        // to every reader, so both policies refuse alike.
        let cases: [(&str, Option<MountRefusal>); 9] = [
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse.sshfs u@h:/ rw,user_id=1000,group_id=1000",
                Some(MountRefusal::FuseUser { uid: 1000 }),
            ),
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse u rw,user_id=1000,group_id=1000",
                Some(MountRefusal::FuseUser { uid: 1000 }),
            ),
            (
                "9 1 8:17 / /etc/aido rw,relatime - fuseblk /dev/sdb1 rw,user_id=1000",
                Some(MountRefusal::FuseUser { uid: 1000 }),
            ),
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse.lxcfs lxcfs rw,user_id=0,group_id=0",
                None,
            ),
            // No user_id, two of them, or one that is not a number: who serves
            // the filesystem cannot be told, so it is refused.
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse.x x rw,group_id=0",
                Some(MountRefusal::FuseOwnerUnknown),
            ),
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse.x x rw,user_id=1000,user_id=0",
                Some(MountRefusal::FuseOwnerUnknown),
            ),
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse.x x rw,user_id=0,user_id=0",
                Some(MountRefusal::FuseOwnerUnknown),
            ),
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse.x x rw,user_id=+0",
                Some(MountRefusal::FuseOwnerUnknown),
            ),
            (
                "9 1 0:75 / /etc/aido rw,relatime - fuse.x x rw,user_id=",
                Some(MountRefusal::FuseOwnerUnknown),
            ),
        ];
        for (line, expected) in cases {
            for policy in POLICIES {
                assert_eq!(
                    refusal(&entry(line), policy),
                    expected,
                    "{policy:?}: {line}"
                );
            }
        }
    }

    #[test]
    fn a_fuse_subtype_cannot_disguise_the_type_it_follows() {
        // The daemon names what follows the dot; the kernel writes what
        // precedes it. fusectl, the FUSE control filesystem, is root's.
        assert!(is_fuse(b"fuse"));
        assert!(is_fuse(b"fuseblk.ntfs-3g"));
        assert!(is_fuse(b"fuse.ext4"));
        assert!(!is_fuse(b"fusectl"));
        assert!(!is_fuse(b"ext4.fuse"));
        assert!(!is_fuse(b""));
    }

    #[test]
    fn a_user_id_is_digits_and_nothing_else() {
        assert_eq!(user_id_value(b"0"), Some(0));
        assert_eq!(user_id_value(b"1000"), Some(1000));
        for bad in [&b""[..], b"+0", b"-1", b"0x0", b" 0", b"4294967296"] {
            assert_eq!(user_id_value(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_marks_of_a_user_mount_are_refused_for_the_ruleset() {
        // Each case: the line, what the ruleset readers say, and what any
        // other root-owned path is told.
        type Case = (&'static str, Option<MountRefusal>, Option<MountRefusal>);
        let cases: [Case; 8] = [
            // fusermount3 adds nosuid on its own, so a user's FUSE mount is
            // refused on two counts; the FUSE one is reported, to every reader.
            (
                "200 286 0:75 / /m rw,nosuid,nodev,noatime - fuse.fuse-overlayfs f rw,user_id=1000",
                Some(MountRefusal::FuseUser { uid: 1000 }),
                Some(MountRefusal::FuseUser { uid: 1000 }),
            ),
            (
                "9 1 8:17 / /media/u/stick rw,nosuid,nodev,relatime - vfat /dev/sdb1 rw,uid=1000",
                Some(MountRefusal::NoSuid),
                None,
            ),
            (
                "9 1 8:17 / /mnt/usb rw,noexec,relatime - ext4 /dev/sdb1 rw",
                Some(MountRefusal::NoExec),
                None,
            ),
            // The tmpfs systemd puts on /run, the gate's spool among it: root
            // made it, and only a reader of the ruleset holds nosuid against
            // it.
            (
                "25 1 0:24 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,mode=755",
                Some(MountRefusal::NoSuid),
                None,
            ),
            // An idmapped mount's owners are a mapping, whoever reads them.
            (
                "9 1 8:1 / /etc/aido rw,relatime,idmapped - ext4 /dev/sda1 rw",
                Some(MountRefusal::Idmapped),
                Some(MountRefusal::Idmapped),
            ),
            (
                "9 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro",
                None,
                None,
            ),
            (
                "286 201 0:70 / / rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u",
                None,
                None,
            ),
            // nodev alone is on half the mounts of a normal host and says
            // nothing about who made it.
            (
                "9 1 0:30 / /boot ro,nodev,relatime - xfs /dev/sda2 ro",
                None,
                None,
            ),
        ];
        for (line, ruleset, root_path) in cases {
            let parsed = entry(line);
            assert_eq!(refusal(&parsed, MountPolicy::Ruleset), ruleset, "{line}");
            assert_eq!(refusal(&parsed, MountPolicy::RootPath), root_path, "{line}");
        }
    }

    #[test]
    fn a_root_mounted_fuse_still_carries_the_marks_of_a_user_mount() {
        // The shape a desktop gives a stick it automounts through a root-run
        // ntfs-3g: user_id=0, so no FUSE refusal, and nosuid from udisks2,
        // which is the only mark that says a user put it there. A judge that
        // stopped at "root serves it" would take the user's stick for the
        // rules.
        let stick = entry(
            "40 1 8:17 / /media/u/STICK rw,nosuid,nodev,relatime - fuseblk /dev/sdb1 \
             rw,user_id=0,group_id=0,default_permissions,allow_other,blksize=4096",
        );
        assert_eq!(
            refusal(&stick, MountPolicy::Ruleset),
            Some(MountRefusal::NoSuid)
        );
        assert_eq!(refusal(&stick, MountPolicy::RootPath), None);
        let noexec = entry("41 1 0:75 / /srv/x rw,noexec,relatime - fuse.x x rw,user_id=0");
        assert_eq!(
            refusal(&noexec, MountPolicy::Ruleset),
            Some(MountRefusal::NoExec)
        );
        // And idmapped is refused to every reader, root's daemon or not.
        let idmapped = entry("42 1 0:75 / /srv/y rw,relatime,idmapped - fuse.y y rw,user_id=0");
        for policy in POLICIES {
            assert_eq!(
                refusal(&idmapped, policy),
                Some(MountRefusal::Idmapped),
                "{policy:?}"
            );
        }
    }

    /// Two descriptors' worth of paths, for the judge.
    const PATHS: [&str; 2] = ["/", "/etc"];

    /// The judge's verdict on two descriptors, as the ruleset readers ask.
    fn judged(fake: &FakeMounts) -> Result<(), TrustError> {
        judged_as(fake, MountPolicy::Ruleset)
    }

    fn judged_as(fake: &FakeMounts, policy: MountPolicy) -> Result<(), TrustError> {
        let paths: Vec<&Path> = PATHS.iter().map(Path::new).collect();
        let fds = [
            std::fs::File::open("/").unwrap(),
            std::fs::File::open("/").unwrap(),
        ];
        let opened: Vec<(&Path, BorrowedFd<'_>)> = paths
            .iter()
            .copied()
            .zip(fds.iter().map(AsFd::as_fd))
            .collect();
        check(fake, &opened, policy)
    }

    #[test]
    fn a_root_made_ext4_is_accepted() {
        assert_eq!(judged(&FakeMounts::ext4()), Ok(()));
    }

    #[test]
    fn devices_that_mountinfo_cannot_tell_apart_the_mount_id_can() {
        // One btrfs, three mounts, one device number in every line: a match by
        // st_dev could not choose, and on btrfs would match nothing at all,
        // because every subvolume reports a device of its own. The bind mount
        // that root made nosuid is told from the root by its id alone.
        let table = "\
30 1 0:33 /root / rw,relatime - btrfs /dev/vda3 rw,subvolid=257,subvol=/root
31 30 0:33 /home /home rw,relatime - btrfs /dev/vda3 rw,subvolid=256,subvol=/home
32 30 0:33 /root/srv/rules /etc rw,nosuid,relatime - btrfs /dev/vda3 rw,subvolid=257,subvol=/root
";
        assert_eq!(
            judged(&FakeMounts::new(table, Ids::Each(vec![30, 31]))),
            Ok(())
        );
        let err = judged(&FakeMounts::new(table, Ids::Each(vec![30, 32]))).unwrap_err();
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: "/etc".to_owned(),
                fs_type: "btrfs".into(),
                mount_point: "/etc".into(),
                reason: MountRefusal::NoSuid,
            }
        );
        // The same bind, judged for a root-owned path that is not the ruleset:
        // nosuid on a mount root made is not held against it.
        assert_eq!(
            judged_as(
                &FakeMounts::new(table, Ids::Each(vec![30, 32])),
                MountPolicy::RootPath
            ),
            Ok(())
        );
    }

    #[test]
    fn a_fuse_mount_under_the_ruleset_is_refused_by_name() {
        let table =
            format!("{EXT4_ROOT}7 1 0:75 / /etc rw,relatime - fuse.sshfs u@h:/ rw,user_id=1000\n");
        let err = judged(&FakeMounts::new(&table, Ids::Each(vec![1, 7]))).unwrap_err();
        assert_eq!(
            err.to_string(),
            "/etc is on fuse.sshfs at /etc, a FUSE filesystem mounted by uid 1000, so every owner \
             and mode on it is whatever that user's daemon chooses to report"
        );
    }

    #[test]
    fn a_fuse_subtype_cannot_write_to_the_terminal_that_shows_its_refusal() {
        // The daemon names its subtype, and the kernel escapes only space,
        // tab, newline, and backslash in it, which the parser decodes back. An
        // OSC sequence, a bell, and a newline that would forge a line of
        // `aido doctor`'s report all arrive as visible text; so does a screen
        // clear in the mount point.
        let table = format!(
            "{EXT4_ROOT}7 1 0:75 / /etc/\u{1b}[2J rw,nosuid,nodev - \
             fuse.\u{1b}]0;owned\u{7}\\012rules\\040trust\\040ok src rw,user_id=1000\n"
        );
        let err = judged(&FakeMounts::new(&table, Ids::Each(vec![1, 7]))).unwrap_err();
        // The bytes are kept as they are, for anything that compares them.
        assert_eq!(
            err,
            TrustError::UntrustedMount {
                at: "/etc".to_owned(),
                fs_type: "fuse.\u{1b}]0;owned\u{7}\nrules trust ok".into(),
                mount_point: "/etc/\u{1b}[2J".into(),
                reason: MountRefusal::FuseUser { uid: 1000 },
            }
        );
        let shown = err.to_string();
        assert!(
            !shown.bytes().any(|byte| byte.is_ascii_control()),
            "{shown:?}"
        );
        assert!(
            shown.starts_with(
                "/etc is on fuse.\\x1b]0;owned\\x07\\nrules trust ok at /etc/\\x1b[2J, a FUSE"
            ),
            "{shown:?}"
        );
    }

    #[test]
    fn a_mount_the_table_does_not_list_is_refused() {
        // Detached after the walk opened it, or a table read while it changed:
        // either way nobody can say who made it.
        let err = judged(&FakeMounts::new(EXT4_ROOT, Ids::Each(vec![1, 99]))).unwrap_err();
        assert_eq!(
            err,
            TrustError::MountUnlisted {
                at: "/etc".to_owned(),
                mount_id: 99
            }
        );
        assert!(err.to_string().contains("does not list"), "{err}");
    }

    #[test]
    fn every_listing_of_a_mount_must_pass() {
        // A table read while it changed can list one mount twice. The second
        // listing is not ignored because the first one passed.
        let table = format!("{EXT4_ROOT}1 0 8:1 / / rw,nosuid,relatime - ext4 /dev/sda1 rw\n");
        let err = judged(&FakeMounts::new(&table, Ids::All(1))).unwrap_err();
        assert!(err.to_string().contains("nosuid"), "{err}");
    }

    #[test]
    fn a_thread_outside_the_initial_user_namespace_is_refused() {
        // There, uid 0 and user_id=0 are the namespace owner's: the walk's
        // "owned by root" no longer means root.
        let foreign = FakeMounts {
            user_namespace: b"user:[4026532190]".to_vec(),
            ..FakeMounts::ext4()
        };
        let err = judged(&foreign).unwrap_err();
        assert_eq!(
            err,
            TrustError::NamespacedRoot {
                namespace: "user:[4026532190]".into()
            }
        );
        assert!(err.to_string().contains("not the initial one"), "{err}");
    }

    #[test]
    fn a_mount_table_that_cannot_be_read_refuses_everything() {
        let unreadable = FakeMounts {
            fail: Some(SysError::read("thread-self/mountinfo", "No such file")),
            ..FakeMounts::ext4()
        };
        let err = judged(&unreadable).unwrap_err();
        assert!(
            err.to_string()
                .starts_with("the mount table cannot be checked"),
            "{err}"
        );
        assert!(err.to_string().contains("No such file"), "{err}");
    }

    #[test]
    fn an_answer_for_fewer_descriptors_than_were_asked_about_is_refused() {
        // Zipped as it stood, the second component would never be judged.
        let short = FakeMounts::new(EXT4_ROOT, Ids::Each(vec![1]));
        let err = judged(&short).unwrap_err();
        assert!(err.to_string().contains("told about 1"), "{err}");
    }

    #[test]
    fn the_host_view_starts_from_the_real_proc() {
        assert_eq!(HostMounts::proc().root, Path::new("/proc"));
        assert!(format!("{:?}", HostMounts::proc()).contains("proc"));
        let inspection = FakeMounts::ext4().inspect(&[]).unwrap();
        assert_eq!(inspection.clone(), inspection);
        assert!(format!("{inspection:?}").contains("mount_ids"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_host_view_refuses_off_linux() {
        // No /proc to read, so no mount can be judged, so nothing is trusted.
        let err = HostMounts::proc().inspect(&[]).unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        assert!(
            err.to_string().contains("/proc/thread-self/mountinfo"),
            "{err}"
        );
    }

    /// The real kernel. CI and `just linux-test` both run in the initial user
    /// namespace with procfs at `/proc`, mounted `nosuid`, as systemd and every
    /// container runtime mount it.
    #[cfg(target_os = "linux")]
    mod linux {
        use std::os::fd::AsFd;
        use std::path::PathBuf;

        use rustix::fs::{Mode, OFlags, open};

        use std::ffi::CString;

        use rustix::fs::readlinkat;
        use rustix::io::Errno;

        use super::super::host::{
            UNREADABLE, read_verified, user_namespace, user_namespace_from, verified_open,
        };
        use super::super::*;

        /// A fresh directory under the workspace `target/`, never `/tmp`.
        fn scratch(name: &str) -> PathBuf {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/test-tmp")
                .join(format!("mounts-{name}"));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn open_dir(path: &Path) -> std::os::fd::OwnedFd {
            open(path, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap()
        }

        #[test]
        fn the_real_table_names_the_mount_of_every_descriptor() {
            let root = std::fs::File::open("/").unwrap();
            let proc = std::fs::File::open("/proc").unwrap();
            let seen = HostMounts::proc()
                .inspect(&[root.as_fd(), proc.as_fd()])
                .unwrap();
            let mount = |id: u32| {
                seen.table
                    .iter()
                    .find(|entry| entry.mount_id == id)
                    .unwrap()
            };
            assert_eq!(mount(seen.mount_ids[0]).mount_point, b"/");
            assert_eq!(mount(seen.mount_ids[1]).mount_point, b"/proc");
            assert_eq!(mount(seen.mount_ids[1]).fs_type, b"proc");
            assert_eq!(seen.user_namespace, INITIAL_USER_NAMESPACE);
        }

        #[test]
        fn a_forged_proc_is_refused_before_its_table_is_read() {
            // A directory laid out like procfs, holding a table in which every
            // mount is a root-made ext4. Only fstatfs can tell it from the
            // real thing, and it does.
            let forged = scratch("forged");
            std::fs::create_dir_all(forged.join("thread-self/ns")).unwrap();
            std::fs::write(forged.join("thread-self/mountinfo"), fake::EXT4_ROOT).unwrap();
            let err = HostMounts::at(&forged).inspect(&[]).unwrap_err();
            assert!(err.to_string().contains("not on procfs"), "{err}");
            // Its namespace link is not believed either.
            assert_eq!(user_namespace(open_dir(&forged).as_fd()), UNREADABLE);
        }

        #[test]
        fn a_missing_proc_is_refused() {
            let absent = scratch("absent").join("proc");
            let err = HostMounts::at(&absent).inspect(&[]).unwrap_err();
            assert!(err.to_string().contains("cannot read"), "{err}");
        }

        #[test]
        fn a_procfs_entry_that_cannot_be_opened_or_read_is_refused() {
            let proc = open_dir(Path::new("/proc"));
            let missing = read_verified(proc.as_fd(), "thread-self/no-such-entry").unwrap_err();
            assert!(missing.to_string().contains("no-such-entry"), "{missing}");
            // On procfs and opened, but a directory: the read itself fails.
            let unreadable = read_verified(proc.as_fd(), "thread-self/ns").unwrap_err();
            assert!(
                unreadable.to_string().contains("thread-self/ns"),
                "{unreadable}"
            );
            // And a directory on procfs opens as one.
            assert!(verified_open(proc.as_fd(), "thread-self/ns", OFlags::DIRECTORY).is_ok());
        }

        #[test]
        fn a_kernel_without_user_namespaces_is_not_refused_as_unreadable() {
            // Built without CONFIG_USER_NS, a kernel lists no `user` entry in
            // a procfs ns directory and has no user namespace but the initial
            // one. Read as "(unreadable)", every ruleset on such a host would
            // be refused; ENOENT there is the initial namespace.
            assert_eq!(
                user_namespace_from(Err(Errno::NOENT)),
                INITIAL_USER_NAMESPACE
            );
            // Every other failure is still refused.
            for errno in [Errno::ACCESS, Errno::INVAL, Errno::LOOP, Errno::NOTDIR] {
                assert_eq!(user_namespace_from(Err(errno)), UNREADABLE, "{errno:?}");
            }
            let foreign = CString::new("user:[4026532190]").unwrap();
            assert_eq!(user_namespace_from(Ok(foreign)), b"user:[4026532190]");
            // And ENOENT is what a real procfs ns directory answers for an
            // entry it does not list, which is how such a kernel answers for
            // `user`.
            let proc = open_dir(Path::new("/proc"));
            let ns = verified_open(proc.as_fd(), "thread-self/ns", OFlags::DIRECTORY).unwrap();
            assert_eq!(
                readlinkat(&ns, "no-such-namespace", Vec::new()),
                Err(Errno::NOENT)
            );
        }
    }
}
