//! Whether anyone but root can change, or create, something root trusts.
//!
//! A path is followed the way the kernel follows it: one component at a time
//! from `/`, every symbolic link replaced by what it names, `..` taken from
//! where the lookup actually is rather than from the spelling. Every directory
//! the lookup passes through is examined, because a writable ancestor can
//! rename the whole subtree aside and nothing about the final path looks wrong
//! afterwards; and so is the directory of every link it follows, because
//! whoever can write that directory can point the link somewhere else. A path
//! reached through `/usr/bin/editor -> /etc/alternatives/editor ->
//! /usr/bin/vim.basic` is therefore judged on `/etc/alternatives` too, which a
//! check of the resolved path alone would never look at.
//!
//! The entries of a trusted directory are judged the same way when they are
//! links: `systemctl link` leaves a unit in `/etc/systemd/system` that names a
//! file anywhere, and systemd follows it as root.
//!
//! A character device is judged by its owner alone: its mode bits say who may
//! write *to* it, and the one a trusted directory routinely points at is
//! `/dev/null` — mode `0666`, the target of every masked unit, holding
//! nothing. A fifo, a socket, and a block device are judged like a file,
//! because writing to one is exactly what root would read: a world-writable
//! fifo in `/etc/profile.d` is a script anyone can write.
//!
//! In a sticky directory such as `/tmp` the owner of an entry may delete or
//! replace it, so a link, or a file where a directory should be, that anyone
//! but root owns is writable by its owner whatever the directory's own mode
//! says.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use super::{Check, CheckId, Ctx, Finding, Kind, Lookup, Meta, Status, Unverified, Via, Writer};

/// The sticky bit: in a directory, only an entry's owner may rename it.
pub(super) const STICKY: u32 = 0o1000;
/// Group may write.
const GROUP_WRITE: u32 = 0o020;
/// Everyone may write.
const OTHER_WRITE: u32 = 0o002;

/// How many links one lookup follows before giving up, as the kernel does.
pub(super) const MAX_LINKS: usize = 40;

/// Unit directories whose subdirectories carry drop-ins and dependency links,
/// and are read like the directory itself.
const DROP_IN_SUFFIXES: [&[u8]; 4] = [b".d", b".wants", b".requires", b".upholds"];

/// What one path came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Nobody but root can change it, or create it.
    Clean {
        /// Where the path leads and what is there; `None` when it does not
        /// exist.
        target: Option<(PathBuf, Kind)>,
    },
    /// Someone else can.
    Writable(Writable),
    /// It could not be examined.
    Unverified(Unverified),
}

/// A writable path, before it becomes a [`Finding`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Writable {
    path: PathBuf,
    at: PathBuf,
    via: Via,
    writers: Vec<Writer>,
}

impl Writable {
    /// The finding, with the backend it shadows when it is a `PATH` entry.
    pub(super) fn into_finding(self, shadows: Option<String>) -> Finding {
        Finding::Writable {
            path: self.path,
            at: self.at,
            via: self.via,
            writers: self.writers,
            shadows,
        }
    }
}

/// What a directory's entries are, and how deep to read them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Entries {
    /// Read every entry.
    Files,
    /// Read every entry, and the entries of drop-in subdirectories.
    Units,
}

/// Collects one check's results.
#[derive(Debug, Default)]
pub(super) struct Sink {
    pub(super) findings: Vec<Finding>,
    pub(super) unverified: Vec<Unverified>,
    pub(super) examined: usize,
}

impl Sink {
    /// The value of a lookup, counting it as examined; a failure is recorded
    /// as unverified and a miss is nothing.
    pub(super) fn take<T>(&mut self, path: &Path, lookup: Lookup<T>) -> Option<T> {
        match lookup {
            Lookup::Found(value) => {
                self.examined = self.examined.saturating_add(1);
                Some(value)
            }
            Lookup::Missing => None,
            Lookup::Unreadable(reason) => {
                self.unverified.push(Unverified::new(path, path, reason));
                None
            }
        }
    }

    /// Records one examined path.
    pub(super) fn push(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::Clean { .. } => {}
            Outcome::Writable(found) => self.findings.push(found.into_finding(None)),
            Outcome::Unverified(gap) => self.unverified.push(gap),
        }
    }

    /// The check, with its status decided by what was collected: anything
    /// found, then anything unverified, then clean.
    pub(super) fn into_check(self, check: CheckId, note: Option<String>) -> Check {
        let status = if !self.findings.is_empty() {
            Status::Found
        } else if !self.unverified.is_empty() {
            Status::Unverified
        } else {
            Status::Clean
        };
        Check {
            check,
            status,
            examined: self.examined,
            findings: self.findings,
            unverified: self.unverified,
            note,
        }
    }

    /// A check that does not apply, and why.
    pub(super) fn into_skipped(self, check: CheckId, note: &str) -> Check {
        Check {
            status: Status::Skipped,
            note: Some(note.to_owned()),
            ..self.into_check(check, None)
        }
    }
}

/// Examines one path root trusts: who other than root can change it, or
/// create it while it is missing.
pub(super) fn examine(ctx: &Ctx<'_>, path: &Path) -> Outcome {
    lookup(ctx, path, true)
}

/// Where `path` leads, without judging anything on the way; `None` when it
/// cannot be followed to something that exists.
pub(super) fn resolve(ctx: &Ctx<'_>, path: &Path) -> Option<PathBuf> {
    match lookup(ctx, path, false) {
        Outcome::Clean {
            target: Some((resolved, _)),
        } => Some(resolved),
        Outcome::Clean { target: None } | Outcome::Writable(_) | Outcome::Unverified(_) => None,
    }
}

/// One step of a lookup still to take.
enum Step {
    /// `..`: back to the directory above where the lookup is.
    Up,
    /// A name to look up where the lookup is.
    Name(OsString),
}

/// Queues the components of `path`, last first, so the next one is on top.
fn queue(pending: &mut Vec<Step>, path: &Path) {
    let steps: Vec<Step> = path
        .components()
        .filter_map(|component| match component {
            Component::ParentDir => Some(Step::Up),
            Component::Normal(name) => Some(Step::Name(name.to_os_string())),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect();
    pending.extend(steps.into_iter().rev());
}

/// The kernel's lookup of `path`, putting every directory it passes through
/// to [`writers`] when `judged` is set.
///
/// `stack` holds the directories below `/` the lookup stands in, each already
/// examined. None of them is a link, so `..` is simply the one before.
fn lookup(ctx: &Ctx<'_>, path: &Path, judged: bool) -> Outcome {
    let unverified =
        |at: &Path, reason: &str| Outcome::Unverified(Unverified::new(path, at, reason));
    if !path.is_absolute() {
        return unverified(
            path,
            "it is not an absolute path, so what it names depends on where it is looked up from",
        );
    }
    let root = Path::new("/");
    let mut pending = Vec::new();
    queue(&mut pending, path);
    let root_meta = match ctx.host.stat(root) {
        Lookup::Found(meta) => meta,
        Lookup::Missing => return unverified(root, "the filesystem root cannot be examined"),
        Lookup::Unreadable(reason) => return unverified(root, &reason),
    };
    if let Some(found) = judge(ctx, path, root, &root_meta, pending.is_empty(), judged) {
        return Outcome::Writable(found);
    }
    let root = (root.to_path_buf(), root_meta);
    let mut stack: Vec<(PathBuf, Meta)> = Vec::new();
    let mut links = 0usize;
    while let Some(step) = pending.pop() {
        let (here, here_meta) = stack.last().unwrap_or(&root).clone();
        let Step::Name(name) = step else {
            // `..`, which at `/` stays at `/`.
            stack.pop();
            continue;
        };
        let candidate = here.join(&name);
        // Whether this is the last component, links not yet followed.
        let last = pending.is_empty();
        let meta = match ctx.host.stat(&candidate) {
            Lookup::Found(meta) => meta,
            // The rest does not exist, and would be created in `here`, where a
            // sticky bit no longer shields anything.
            Lookup::Missing => {
                return judge(ctx, path, &here, &here_meta, true, judged).map_or(
                    Outcome::Clean { target: None },
                    |found| {
                        Outcome::Writable(Writable {
                            via: Via::Missing,
                            ..found
                        })
                    },
                );
            }
            Lookup::Unreadable(reason) => return unverified(&candidate, &reason),
        };
        if meta.kind == Kind::Symlink {
            if let Some(found) = replaceable(ctx, path, &candidate, &meta, &here_meta, last, judged)
            {
                return Outcome::Writable(found);
            }
            links = links.saturating_add(1);
            if links > MAX_LINKS {
                return unverified(&candidate, "it passes through too many symbolic links");
            }
            match ctx.host.read_link(&candidate) {
                Lookup::Found(target) => {
                    if target.is_absolute() {
                        stack.clear();
                    }
                    queue(&mut pending, &target);
                }
                Lookup::Missing => {
                    return unverified(&candidate, "it changed while it was being examined");
                }
                Lookup::Unreadable(reason) => return unverified(&candidate, &reason),
            }
            continue;
        }
        if !last && meta.kind != Kind::Directory {
            // A file where a directory must be: nothing below it can exist.
            // Replacing it needs the directory it is in, already examined,
            // unless that is sticky and the file is someone's own.
            return replaceable(ctx, path, &candidate, &meta, &here_meta, last, judged)
                .map_or(Outcome::Clean { target: None }, Outcome::Writable);
        }
        if let Some(found) = judge(ctx, path, &candidate, &meta, last, judged) {
            return Outcome::Writable(found);
        }
        stack.push((candidate, meta));
    }
    let (resolved, meta) = stack.pop().unwrap_or(root);
    Outcome::Clean {
        target: Some((resolved, meta.kind)),
    }
}

/// A link, or a file in the way, that its owner can replace because the
/// directory it is in is sticky: sticky stops everyone else deleting it, and
/// lets its owner.
fn replaceable(
    ctx: &Ctx<'_>,
    path: &Path,
    at: &Path,
    meta: &Meta,
    parent: &Meta,
    last: bool,
    judged: bool,
) -> Option<Writable> {
    if !judged || parent.mode & STICKY == 0 || meta.uid == 0 {
        return None;
    }
    Some(Writable {
        path: path.to_path_buf(),
        at: at.to_path_buf(),
        via: if last { Via::Itself } else { Via::Ancestor },
        writers: vec![Writer::Owner {
            uid: meta.uid,
            name: ctx.user_name(meta.uid),
            you: meta.uid == ctx.subject.uid,
        }],
    })
}

/// Who can write `at`, when `judged` and anyone but root can.
fn judge(
    ctx: &Ctx<'_>,
    path: &Path,
    at: &Path,
    meta: &Meta,
    last: bool,
    judged: bool,
) -> Option<Writable> {
    if !judged {
        return None;
    }
    let found = writers(ctx, at, meta, last);
    if found.is_empty() {
        return None;
    }
    Some(Writable {
        path: path.to_path_buf(),
        at: at.to_path_buf(),
        via: if last { Via::Itself } else { Via::Ancestor },
        writers: found,
    })
}

/// Examines a directory root trusts, and then each entry in it.
///
/// Entries are skipped when the directory itself is writable (they are moot)
/// and when the same directory was already read under another name — `/bin`
/// and `/usr/bin` on a merged-`/usr` host. They are read where the directory
/// actually is, and reported there.
pub(super) fn examine_dir(
    ctx: &Ctx<'_>,
    dir: &Path,
    entries: Entries,
    scanned: &mut BTreeSet<PathBuf>,
    sink: &mut Sink,
) {
    sink.examined = sink.examined.saturating_add(1);
    match examine(ctx, dir) {
        Outcome::Clean {
            target: Some((resolved, Kind::Directory)),
        } => {
            if scanned.insert(resolved.clone()) {
                read_entries(ctx, &resolved, entries, sink);
            }
        }
        outcome => sink.push(outcome),
    }
}

/// Examines every entry of a directory that is itself clean.
fn read_entries(ctx: &Ctx<'_>, dir: &Path, entries: Entries, sink: &mut Sink) {
    let names = match ctx.host.list(dir) {
        Lookup::Found(names) => names,
        Lookup::Missing => return,
        Lookup::Unreadable(reason) => {
            return sink.unverified.push(Unverified::new(dir, dir, reason));
        }
    };
    let mut names = names;
    names.sort();
    for name in names {
        let entry = dir.join(&name);
        sink.examined = sink.examined.saturating_add(1);
        let meta = match ctx.host.stat(&entry) {
            Lookup::Found(meta) => meta,
            Lookup::Missing => continue,
            Lookup::Unreadable(reason) => {
                sink.unverified
                    .push(Unverified::new(&entry, &entry, reason));
                continue;
            }
        };
        if meta.kind == Kind::Symlink {
            // What root reads is what the link names, so that is followed and
            // examined from `/` down. A link named like a drop-in directory
            // that leads to a clean directory is read like one: systemd
            // follows it.
            match examine(ctx, &entry) {
                Outcome::Clean {
                    target: Some((resolved, Kind::Directory)),
                } if entries == Entries::Units && is_drop_in(&name) => {
                    read_entries(ctx, &resolved, Entries::Files, sink);
                }
                outcome => sink.push(outcome),
            }
            continue;
        }
        let writers = writers(ctx, &entry, &meta, true);
        if !writers.is_empty() {
            sink.findings
                .push(writable_finding(&entry, &entry, Via::Itself, writers));
        } else if entries == Entries::Units && meta.kind == Kind::Directory && is_drop_in(&name) {
            read_entries(ctx, &entry, Entries::Files, sink);
        }
    }
}

/// Whether an entry's name is that of a drop-in or dependency directory.
fn is_drop_in(name: &OsStr) -> bool {
    DROP_IN_SUFFIXES
        .iter()
        .any(|suffix| name.as_bytes().ends_with(suffix))
}

/// Who other than root can write `at`.
///
/// `last` says whether `at` is the thing root trusts (or where it would be
/// created) rather than a directory above it: only above it does a sticky bit
/// shield, because a sticky directory still lets anyone add a new entry.
pub(super) fn writers(ctx: &Ctx<'_>, at: &Path, meta: &Meta, last: bool) -> Vec<Writer> {
    // Above the target a sticky directory shields an entry from rename. A
    // character device holds nothing root reads (see the module docs), and a
    // link cannot be rewritten in place, only replaced through its directory
    // — callers follow links rather than ask about them, and a link's `0777`
    // must never read as everyone's. Each way, only the owner is left.
    let owner_only = matches!(meta.kind, Kind::Symlink | Kind::CharDevice)
        || (!last && meta.kind == Kind::Directory && meta.mode & STICKY != 0);
    let mut found = Vec::new();
    if meta.uid != 0 {
        found.push(Writer::Owner {
            uid: meta.uid,
            name: ctx.user_name(meta.uid),
            you: meta.uid == ctx.subject.uid,
        });
    }
    if owner_only {
        return found;
    }
    if meta.mode & GROUP_WRITE != 0 {
        found.push(Writer::Group {
            gid: meta.gid,
            name: ctx.group_name(meta.gid),
            you: ctx.gids.contains(&meta.gid),
        });
    }
    if meta.mode & OTHER_WRITE != 0 {
        found.push(Writer::Everyone);
    }
    if !ctx.subject.is_root && !found.iter().any(Writer::includes_you) && ctx.host.writable(at) {
        found.push(Writer::You);
    }
    found
}

/// A writable finding that names no backend.
fn writable_finding(path: &Path, at: &Path, via: Via, writers: Vec<Writer>) -> Finding {
    Finding::Writable {
        path: path.to_path_buf(),
        at: at.to_path_buf(),
        via,
        writers,
        shadows: None,
    }
}
