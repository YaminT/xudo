//! Every other path to root: what makes `aido` decorative on this host.
//!
//! `aido` decides whether one command may run as root. That decision protects
//! nothing on a host where the same caller already has another way there: a
//! standing `NOPASSWD` rule, membership of a group that is root by another
//! name, a directory root executes from that someone else can write. This
//! module finds those from facts a [`HostView`] supplies, and says plainly what
//! it could not see. It is pure: `aido-sys` answers the questions on a real
//! host, and [`MemoryHost`] answers them in tests.
//!
//! # Unverified is not absent
//!
//! `aido` runs unprivileged, and much of what decides this is readable only by
//! root: `/etc/sudoers` is `0440`, `/root` is `0700`. Everything this module
//! cannot read is an [`Unverified`] entry carrying the reason, and a check that
//! met one is never reported [`Status::Clean`]. A report that said "no
//! `NOPASSWD` entries" because it could not open the file would be the most
//! dangerous line `aido` prints.
//!
//! # Conservative, not exact
//!
//! The sudoers and doas readers here are not those programs' parsers, and they
//! do not try to be. They find the tokens that remove a password — `NOPASSWD`,
//! `!authenticate`, `nopass` — on any line that is not a whole-line comment,
//! and report the line. When they cannot tell whether a rule applies to the
//! caller they say "maybe". Every ambiguity resolves towards reporting.
//!
//! # What "writable" means
//!
//! Something root trusts — a unit directory, a directory on root's `PATH`, a
//! file root's shell reads — is a path to root if anyone but root can change
//! it, or create it while it is missing. That is decided on every directory
//! the kernel's lookup passes through, links followed one at a time, because a
//! writable ancestor can rename the whole subtree aside and a writable link
//! directory can point the link elsewhere: the owner if it is not root, the
//! group if group-writable, everyone if world-writable, and the caller if
//! `access(2)` says so where the mode bits do not. A sticky ancestor shields a
//! root-owned child from rename; it does not stop anyone creating a new entry,
//! so a sticky directory that is the thing root trusts is still writable. And
//! in a sticky directory the *owner* of an entry may delete and replace it, so
//! a link, or a file standing where a directory should be, that anyone but root
//! owns counts as writable by that owner.
//!
//! # What it cannot see
//!
//! A directory service (LDAP, SSSD): accounts and memberships it holds are not
//! in `/etc/passwd` or `/etc/group`, and a held group with no local name is
//! reported as unverified rather than assumed harmless. sudo rules kept in a
//! directory service, polkit rules, file capabilities, set-user-ID programs,
//! cron, `/etc/pam.d`, `/etc/sudo.conf`, whether the sudoers and doas files
//! are themselves writable, `/etc/passwd` and `/etc/shadow`, `/root/.ssh`,
//! systemd's shutdown and sleep hooks, udev rules, the caller's own shell rc
//! files, and the dynamic loader's configuration are not examined at all, and
//! `SECURITY.md` lists them as such. An ACL that lets *someone else* write is visible only through the group bits
//! it sets (the ACL mask), and is reported against the owning group; an ACL or
//! a capability that lets the caller write is caught by `access(2)`.

mod accounts;
mod config;
mod memory;
mod proposals;
mod walk;

use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use serde::{Serialize, Serializer};

pub use config::Grant;
pub use memory::MemoryHost;
pub use proposals::{Proposal, propose};

use accounts::{Account, GroupEntry};
use config::{Include, RuleLine, Scope};
use walk::{Outcome, Sink};

/// The sudoers files a sudo-family backend reads first. `sudo-rs` prefers its
/// own file when it exists, so both are read.
const SUDOERS_FILES: [&str; 2] = ["/etc/sudoers", "/etc/sudoers-rs"];

/// The sudoers file whose `secure_path` decides root's `PATH`.
const SUDOERS: &str = "/etc/sudoers";

/// The drop-in directory every stock sudoers file includes. Read on its own
/// when `/etc/sudoers` cannot be: its names, and any file in it that can be
/// read, are better evidence than nothing.
const SUDOERS_D: &str = "/etc/sudoers.d";

/// The most a configuration or accounts file may hold before it is reported
/// unverified rather than read. Far above any real one; it exists so that a
/// file which never ends cannot stall the report.
pub const MAX_READ: u64 = 4 * 1024 * 1024;

/// Why something that is not a regular file was not read. The same words from
/// every [`HostView`], so a report reads alike on a real host and in a test.
pub const NOT_A_REGULAR_FILE: &str = "it is not a regular file";

/// Why a file larger than [`MAX_READ`] was not read.
pub const TOO_LARGE: &str = "it is larger than any real configuration file";

/// Why something an include names was not read when it is not there.
const MISSING_INCLUDE: &str = "an include names it, and it does not exist";

/// doas's configuration, and the drop-in directory some ports have.
const DOAS_CONF: &str = "/etc/doas.conf";
const DOAS_DIR: &str = "/etc/doas.d";

/// How deep sudoers includes are followed. `sudo` allows more; real
/// configurations nest two or three deep, and a deeper chain is reported as
/// unverified rather than silently cut off.
const MAX_INCLUDE_DEPTH: usize = 8;

/// The directories a stock `secure_path` names on Debian, Ubuntu, Fedora, and
/// Arch, and that `OpenDoas` puts on root's `PATH`. Checked whether or not the
/// real `secure_path` could be read, because root's login shells use them too.
const STOCK_SECURE_PATH: [&str; 7] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/snap/bin",
];

/// Where the system manager looks for units and for generators, which it runs
/// as root at boot and at every `daemon-reload`. From `systemd.unit(5)` and
/// `systemd.generator(7)`, plus `/lib` for hosts without a merged `/usr`.
const UNIT_DIRECTORIES: [&str; 18] = [
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
    "/etc/systemd/system-generators",
    "/run/systemd/system-generators",
    "/usr/local/lib/systemd/system-generators",
    "/usr/lib/systemd/system-generators",
    "/lib/systemd/system-generators",
];

/// System-wide files a root shell reads: bash, sh, zsh, and fish, in the
/// Debian and the Fedora spellings, plus the `pam_env` file every session
/// reads.
const SYSTEM_STARTUP_FILES: [&str; 13] = [
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/bashrc",
    "/etc/environment",
    "/etc/zsh/zshenv",
    "/etc/zsh/zprofile",
    "/etc/zsh/zshrc",
    "/etc/zsh/zlogin",
    "/etc/zshenv",
    "/etc/zprofile",
    "/etc/zshrc",
    "/etc/zlogin",
    "/etc/fish/config.fish",
];

/// Directories whose every entry a root shell sources.
const STARTUP_DIRECTORIES: [&str; 2] = ["/etc/profile.d", "/etc/fish/conf.d"];

/// Files in root's home directory that its shells read.
const ROOT_HOME_FILES: [&str; 9] = [
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
    ".zshenv",
    ".zprofile",
    ".zshrc",
    ".zlogin",
    ".config/fish/config.fish",
];

/// The groups whose membership is root, or a way to it, and why.
///
/// `wheel`, `sudo`, `docker`, and `lxd` are the design plan's. The others are
/// added because each is the same capability under another name: `admin` is
/// Ubuntu's sudo group before 12.04 and is still in its default sudoers;
/// `incus-admin` is `lxd` after the fork; `libvirt` can start a VM with the
/// host's disks attached; `disk` writes block devices below every permission
/// check; `input` reads the keystrokes of the password typed at a sudo prompt.
const ROOT_GROUPS: [RootGroup; 9] = [
    RootGroup {
        name: "sudo",
        passwordless: false,
        grants: "the group the stock sudoers file grants: any command as root, with your \
                 password, and for a few minutes after you type it on a terminal anything \
                 else running as you there may use sudo without it",
        instead: "",
    },
    RootGroup {
        name: "wheel",
        passwordless: false,
        grants: "the administrators' group on Fedora, Arch, and Alpine: any command as root \
                 through sudo or doas, with your password, and while the credential is cached \
                 anything else running as you may use it",
        instead: "",
    },
    RootGroup {
        name: "admin",
        passwordless: false,
        grants: "Ubuntu's sudo group before 12.04, still granted in its default sudoers: any \
                 command as root, with your password, and while it is cached without",
        instead: "",
    },
    RootGroup {
        name: "docker",
        passwordless: true,
        grants: "the Docker daemon runs as root and starts any container you ask for, \
                 including one with / mounted (`docker run -v /:/host`): root, with no \
                 password",
        instead: "Rootless Docker or Podman runs containers without it.",
    },
    RootGroup {
        name: "lxd",
        passwordless: true,
        grants: "the LXD daemon starts a privileged container with the host's / attached on \
                 request: root, with no password",
        instead: "Containers you manage will need sudo afterwards.",
    },
    RootGroup {
        name: "incus-admin",
        passwordless: true,
        grants: "Incus, LXD's fork, starts a privileged container with the host's / \
                 attached on request: root, with no password",
        instead: "Containers you manage will need sudo afterwards.",
    },
    RootGroup {
        name: "libvirt",
        passwordless: true,
        grants: "the system libvirt daemon starts a VM with the host's disks attached on \
                 request: root, with no password",
        instead: "Your own session VMs (qemu:///session) keep working without it.",
    },
    RootGroup {
        name: "disk",
        passwordless: true,
        grants: "raw read and write access to every disk: any file can be edited below the \
                 permission checks, /etc/shadow included",
        instead: "Tools that write devices directly will need sudo afterwards.",
    },
    RootGroup {
        name: "input",
        passwordless: true,
        grants: "you can read every keystroke on this machine, including the password typed \
                 at a sudo prompt",
        instead: "A game or an input remapper that needs one device can be given a udev rule \
                  for that device instead.",
    },
];

/// The group whose members may invoke aido's gate.
const AIDO_GROUP: &str = crate::snippet::AIDO_GROUP;

/// What the report asks of the machine.
///
/// A trait so the whole report is testable against a described machine. The
/// real implementation, `aido_sys::LiveHost`, answers from the filesystem and
/// the process's own credentials; [`MemoryHost`] answers from a table. Both
/// answer with the kernel's semantics, which is what each method documents:
/// a fake that answers differently from the real thing is a test proving
/// nothing.
///
/// [`Lookup::Missing`] means "does not exist" and nothing else: `ENOENT`, or
/// `ENOTDIR` for a path through a file. Every other failure is
/// [`Lookup::Unreadable`], carrying the reason, and is reported as unverified.
pub trait HostView {
    /// This process's real ids, as the kernel reports them.
    fn caller(&self) -> Caller;

    /// The facts about `path`, without following a final symbolic link
    /// (`lstat`).
    fn stat(&self, path: &Path) -> Lookup<Meta>;

    /// A regular file's contents, following links. Anything else — a
    /// directory, a device, a fifo — is unreadable with [`NOT_A_REGULAR_FILE`],
    /// and a file larger than [`MAX_READ`] with [`TOO_LARGE`], both without
    /// blocking.
    fn read(&self, path: &Path) -> Lookup<Vec<u8>>;

    /// The names in a directory, following links, in no particular order.
    fn list(&self, path: &Path) -> Lookup<Vec<OsString>>;

    /// What a symbolic link names, exactly as stored (`readlink`): relative
    /// targets stay relative.
    fn read_link(&self, path: &Path) -> Lookup<PathBuf>;

    /// Whether this process may write `path`, following links: `access(2)`
    /// with `W_OK`, which sees what the mode bits do not — an ACL, a
    /// capability, a read-only mount.
    fn writable(&self, path: &Path) -> bool;
}

/// The answer to one question about a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup<T> {
    /// It exists, and here it is.
    Found(T),
    /// It does not exist.
    Missing,
    /// It could not be examined, for this reason. Never read as "absent".
    Unreadable(String),
}

impl<T> Lookup<T> {
    /// Transforms a found value, keeping a miss or a failure as it was.
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> Lookup<U> {
        match self {
            Self::Found(value) => Lookup::Found(transform(value)),
            Self::Missing => Lookup::Missing,
            Self::Unreadable(reason) => Lookup::Unreadable(reason),
        }
    }
}

/// What a path is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A directory.
    Directory,
    /// A regular file.
    File,
    /// A symbolic link.
    Symlink,
    /// A character device, which holds nothing root reads: `/dev/null`, the
    /// target of every masked unit.
    CharDevice,
    /// Anything else: a socket, a fifo, a block device.
    Other,
}

/// Who owns a path and who may write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Meta {
    /// The owning user.
    pub uid: u32,
    /// The owning group.
    pub gid: u32,
    /// The permission bits, masked to `0o7777`.
    pub mode: u32,
    /// What it is.
    pub kind: Kind,
}

/// This process's credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    /// The real user id.
    pub uid: u32,
    /// The real group id.
    pub gid: u32,
    /// The supplementary groups.
    pub groups: Lookup<Vec<u32>>,
}

/// What the report needs from the invocation rather than the machine.
#[derive(Clone, Copy, Debug, Default)]
pub struct Input<'a> {
    /// `PATH` as the invoking user exported it. Inspected, never searched;
    /// `None` when it was not available.
    pub user_path: Option<&'a OsStr>,
    /// The backend's executable, so a writable `PATH` entry ahead of it can
    /// be called what it is.
    pub backend_exe: Option<&'a Path>,
}

/// The whole report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Whose report this is.
    pub subject: Subject,
    /// The worst status of any check.
    pub status: Status,
    /// Every check, in a fixed order.
    pub checks: Vec<Check>,
    /// Whether aido's own group exists and holds the subject.
    pub aido_group: AidoGroup,
}

impl Report {
    /// How many findings there are across every check.
    pub fn finding_count(&self) -> usize {
        self.checks.iter().map(|check| check.findings.len()).sum()
    }

    /// How many checks could not be completed.
    pub fn unverified_count(&self) -> usize {
        self.checks
            .iter()
            .filter(|check| !check.unverified.is_empty())
            .count()
    }
}

/// Who the report describes: the process that asked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Subject {
    /// The real user id.
    pub uid: u32,
    /// The name `/etc/passwd` gives that uid, when it gives one.
    pub name: Option<String>,
    /// Whether this is root, for whom group and write checks mean nothing.
    pub is_root: bool,
    /// Every group the subject holds or is listed in.
    pub groups: Vec<GroupRef>,
}

/// One group the subject belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupRef {
    /// Its id.
    pub gid: u32,
    /// Its name, when `/etc/group` gives one.
    pub name: Option<String>,
    /// Held by this process now.
    pub active: bool,
    /// Listed for the subject in `/etc/group`, or its primary group in
    /// `/etc/passwd`, and so held by the next login.
    pub listed: bool,
}

/// How a check came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Not applicable to this subject, and said why.
    Skipped,
    /// Everything was examined and nothing was found.
    Clean,
    /// Nothing was found, but something could not be examined.
    Unverified,
    /// At least one other path to root exists.
    Found,
}

/// Which check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    /// Rules in sudoers or doas configuration that skip the password.
    PasswordlessRules,
    /// Membership of a group that is root by another name.
    GroupMemberships,
    /// Unit and generator directories the system manager reads.
    UnitDirectories,
    /// The directories on root's `PATH`, and their entries.
    RootPath,
    /// The directories on the invoking user's `PATH`.
    UserPath,
    /// The files root's shells read when they start.
    RootShellStartup,
}

/// One check's result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Which check.
    pub check: CheckId,
    /// How it came out.
    pub status: Status,
    /// How many files, directories, groups, or entries were examined.
    pub examined: usize,
    /// What was found.
    pub findings: Vec<Finding>,
    /// What could not be examined, and why.
    pub unverified: Vec<Unverified>,
    /// Anything else the reader must know to interpret the result.
    pub note: Option<String>,
}

/// One other path to root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Finding {
    /// A rule that runs commands as root without asking for a password.
    PasswordlessRule {
        /// The file it is in.
        #[serde(serialize_with = "display")]
        file: PathBuf,
        /// Its first line, counting from 1.
        line: usize,
        /// The rule as written, continuation lines joined.
        text: String,
        /// What removes the password.
        grant: Grant,
        /// Whether it names the subject.
        applies_to_you: Applies,
    },
    /// Membership of a group that is root, or a way to it.
    GroupMembership {
        /// The group.
        group: String,
        /// Its id.
        gid: u32,
        /// Whether a process running as the subject needs no password to use
        /// it.
        passwordless: bool,
        /// What it grants, in one sentence.
        grants: String,
        /// Listed in `/etc/group` or as the primary group.
        listed: bool,
        /// Held by this process now.
        active: bool,
    },
    /// Something root trusts that another principal can change or create.
    Writable {
        /// What root trusts.
        #[serde(serialize_with = "display")]
        path: PathBuf,
        /// The component someone other than root can write.
        #[serde(serialize_with = "display")]
        at: PathBuf,
        /// How `at` relates to `path`.
        via: Via,
        /// Who can write `at`.
        writers: Vec<Writer>,
        /// For an entry of your `PATH`: the backend it comes ahead of, whose
        /// name a program placed here would take — or `/usr/bin`, when no
        /// backend was found to name.
        shadows: Option<String>,
    },
    /// A `PATH` entry that is not absolute, so it is looked up in whatever
    /// directory the shell happens to be in. On your `PATH`, reported only
    /// ahead of the backend.
    RelativePathEntry {
        /// The entry as written; empty means the current directory.
        #[serde(serialize_with = "display")]
        entry: PathBuf,
    },
}

/// How the writable component relates to the path root trusts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// It is the path itself.
    Itself,
    /// It is a directory above it, so whoever writes it can replace the path.
    Ancestor,
    /// The path does not exist, and this is where it would be created.
    Missing,
}

/// Who can write something root trusts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Writer {
    /// The subject, by a grant the mode bits do not show: an ACL, most often.
    You,
    /// Its owner, which is not root.
    Owner {
        /// The owning uid.
        uid: u32,
        /// Its name, when `/etc/passwd` gives one.
        name: Option<String>,
        /// Whether the owner is the subject.
        you: bool,
    },
    /// Its group, because it is group-writable.
    Group {
        /// The owning gid.
        gid: u32,
        /// Its name, when `/etc/group` gives one.
        name: Option<String>,
        /// Whether the subject is in it.
        you: bool,
    },
    /// Everyone, because it is world-writable.
    Everyone,
}

impl Writer {
    /// Whether this writer includes the subject.
    pub fn includes_you(&self) -> bool {
        match self {
            Self::You | Self::Everyone => true,
            Self::Owner { you, .. } | Self::Group { you, .. } => *you,
        }
    }
}

/// Whether a rule names the subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Applies {
    /// It names the subject, a group the subject is in, or everyone.
    Yes,
    /// It names something aido does not resolve: an alias, a netgroup, a
    /// negation, a command or host scope.
    Maybe,
    /// It names only others.
    No,
}

/// Something that could not be examined.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unverified {
    /// What was being examined.
    #[serde(serialize_with = "display")]
    pub path: PathBuf,
    /// The component that could not be examined; the same as `path` when the
    /// file itself could not be read.
    #[serde(serialize_with = "display")]
    pub at: PathBuf,
    /// Why.
    pub reason: String,
}

impl Unverified {
    fn new(path: &Path, at: &Path, reason: impl Into<String>) -> Self {
        Self {
            path: path.to_path_buf(),
            at: at.to_path_buf(),
            reason: reason.into(),
        }
    }
}

/// aido's own group, which `doctor --fix` offers to join.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AidoGroup {
    /// Whether `/etc/group` has it.
    pub exists: bool,
    /// Its id, when it exists.
    pub gid: Option<u32>,
    /// Whether the subject holds it or is listed in it.
    pub member: bool,
}

/// Serializes a path as text, for a reader. Never compared against anything.
fn display<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&path.display())
}

/// One entry of [`ROOT_GROUPS`].
struct RootGroup {
    name: &'static str,
    passwordless: bool,
    grants: &'static str,
    /// What to use instead, for a group worth leaving.
    instead: &'static str,
}

/// Assesses this host.
///
/// Every check runs, in a fixed order, whatever the others found: an operator
/// fixing one path to root needs to know about the rest in the same pass.
pub fn assess(host: &dyn HostView, input: &Input<'_>) -> Report {
    let ctx = Ctx::new(host);
    let config = passwordless_rules(&ctx);
    let checks = vec![
        config.check,
        group_memberships(&ctx),
        unit_directories(&ctx),
        root_path(
            &ctx,
            &config.secure_paths,
            &config.sudoers,
            &config.unread,
            &config.unmodelled,
        ),
        user_path(&ctx, input),
        root_shell_startup(&ctx),
    ];
    let status = checks
        .iter()
        .map(|check| check.status)
        .max()
        // An empty report is not a clean one: it examined nothing.
        .unwrap_or(Status::Unverified);
    Report {
        aido_group: ctx.aido_group(),
        subject: ctx.subject,
        status,
        checks,
    }
}

/// What the report knows about the subject and the accounts database.
struct Ctx<'h> {
    host: &'h dyn HostView,
    subject: Subject,
    /// The subject's name, as the bytes `/etc/passwd` holds.
    name: Option<Vec<u8>>,
    /// Every gid the subject holds or is listed in.
    gids: BTreeSet<u32>,
    /// The gids this process holds now.
    active: BTreeSet<u32>,
    /// The gids the next login gets: the primary group and every group that
    /// lists the subject.
    listed: BTreeSet<u32>,
    /// Every account, for naming owners.
    accounts: Vec<Account>,
    /// Every group, for naming and membership.
    groups: Vec<GroupEntry>,
    /// Root's home directory, from `/etc/passwd` or the conventional one.
    root_home: PathBuf,
    /// What could not be read about identities, reported by the checks that
    /// depend on it.
    passwd_gap: Option<Unverified>,
    group_gap: Option<Unverified>,
    supplementary_gap: Option<String>,
}

impl<'h> Ctx<'h> {
    fn new(host: &'h dyn HostView) -> Self {
        let caller = host.caller();
        let (accounts, passwd_gap) = read_table(host, accounts::PASSWD, accounts::parse_passwd);
        let (groups, group_gap) = read_table(host, accounts::GROUP, accounts::parse_group);

        let account = accounts.iter().find(|a| a.uid == caller.uid);
        let name = account.map(|a| a.name.clone());
        let root_home = accounts
            .iter()
            .find(|a| a.uid == 0)
            .map_or_else(|| PathBuf::from("/root"), |a| a.home.clone());

        let (active, supplementary_gap) = match caller.groups {
            Lookup::Found(supplementary) => (supplementary, None),
            Lookup::Missing | Lookup::Unreadable(_) => (
                Vec::new(),
                Some("this process's supplementary groups could not be read".to_owned()),
            ),
        };
        let active: BTreeSet<u32> = active.into_iter().chain([caller.gid]).collect();
        let mut listed: BTreeSet<u32> = account.map(|a| a.gid).into_iter().collect();
        if let Some(name) = &name {
            listed.extend(
                groups
                    .iter()
                    .filter(|g| g.members.contains(name))
                    .map(|g| g.gid),
            );
        }
        let gids: BTreeSet<u32> = active.union(&listed).copied().collect();
        let refs = gids
            .iter()
            .map(|gid| GroupRef {
                gid: *gid,
                name: group_name_in(&groups, *gid),
                active: active.contains(gid),
                listed: listed.contains(gid),
            })
            .collect();

        Self {
            host,
            subject: Subject {
                uid: caller.uid,
                name: name.clone().and_then(|bytes| String::from_utf8(bytes).ok()),
                is_root: caller.uid == 0,
                groups: refs,
            },
            name,
            gids,
            active,
            listed,
            accounts,
            groups,
            root_home,
            passwd_gap,
            group_gap,
            supplementary_gap,
        }
    }

    /// The name of a uid, for a reader.
    fn user_name(&self, uid: u32) -> Option<String> {
        self.accounts
            .iter()
            .find(|a| a.uid == uid)
            .and_then(|a| String::from_utf8(a.name.clone()).ok())
    }

    /// The name of a gid, for a reader.
    fn group_name(&self, gid: u32) -> Option<String> {
        group_name_in(&self.groups, gid)
    }

    /// Whether the subject is in the group with this name. Membership lists
    /// are already folded into `gids`, by gid.
    fn in_group_named(&self, name: &[u8]) -> bool {
        self.groups
            .iter()
            .any(|g| g.name == name && self.gids.contains(&g.gid))
    }

    /// Whether a rule's user list names the subject.
    fn applies(&self, scope: &Scope) -> Applies {
        match scope {
            Scope::Everyone => Applies::Yes,
            Scope::Unknown => Applies::Maybe,
            Scope::DoasIdentity(identity) => self.doas_names(identity),
            Scope::Users(items) => {
                let mut maybe = false;
                for item in items {
                    match self.names(item) {
                        Applies::Yes => return Applies::Yes,
                        Applies::Maybe => maybe = true,
                        Applies::No => {}
                    }
                }
                if maybe { Applies::Maybe } else { Applies::No }
            }
        }
    }

    /// Whether one user-list item names the subject.
    fn names(&self, item: &[u8]) -> Applies {
        if item == b"ALL" {
            return Applies::Yes;
        }
        let yes = |hit: bool| if hit { Applies::Yes } else { Applies::No };
        match item {
            [b'%', b'#', id @ ..] => {
                config::number(id).map_or(Applies::Maybe, |gid| yes(self.gids.contains(&gid)))
            }
            [b'#', id @ ..] => {
                config::number(id).map_or(Applies::Maybe, |uid| yes(uid == self.subject.uid))
            }
            [b'%', b':', ..] | [b'+' | b'!', ..] => Applies::Maybe,
            [b'%', group @ ..] => self.group_named(group),
            _ if config::is_alias(item) => Applies::Maybe,
            user => self.user_named(user),
        }
    }

    /// Whether a doas identity names the subject: `user` or `:group`, either
    /// by name or by number.
    fn doas_names(&self, identity: &[u8]) -> Applies {
        let yes = |hit: bool| if hit { Applies::Yes } else { Applies::No };
        match identity {
            [b':', group @ ..] => config::number(group).map_or_else(
                || self.group_named(group),
                |gid| yes(self.gids.contains(&gid)),
            ),
            user => config::number(user)
                .map_or_else(|| self.user_named(user), |uid| yes(uid == self.subject.uid)),
        }
    }

    /// Whether the group with this name holds the subject: `Maybe` when
    /// `/etc/group` has no such group, because a directory service may.
    fn group_named(&self, name: &[u8]) -> Applies {
        if !self.groups.iter().any(|g| g.name == name) {
            Applies::Maybe
        } else if self.in_group_named(name) {
            Applies::Yes
        } else {
            Applies::No
        }
    }

    /// Whether the user with this name is the subject: `Maybe` when
    /// `/etc/passwd` has no such user, because a directory service may.
    fn user_named(&self, name: &[u8]) -> Applies {
        match self.accounts.iter().find(|a| a.name == name) {
            None => Applies::Maybe,
            Some(account) if account.uid == self.subject.uid => Applies::Yes,
            Some(_) => Applies::No,
        }
    }

    /// aido's own group, as `/etc/group` and this process see it.
    fn aido_group(&self) -> AidoGroup {
        let entry = self.groups.iter().find(|g| g.name == AIDO_GROUP.as_bytes());
        AidoGroup {
            exists: entry.is_some(),
            gid: entry.map(|g| g.gid),
            member: self.in_group_named(AIDO_GROUP.as_bytes()),
        }
    }
}

/// The first name `/etc/group` gives a gid.
fn group_name_in(groups: &[GroupEntry], gid: u32) -> Option<String> {
    groups
        .iter()
        .find(|g| g.gid == gid)
        .and_then(|g| String::from_utf8(g.name.clone()).ok())
}

/// Reads and parses one accounts file, or says why it could not.
fn read_table<T>(
    host: &dyn HostView,
    file: &str,
    parse: fn(&[u8]) -> Vec<T>,
) -> (Vec<T>, Option<Unverified>) {
    let path = Path::new(file);
    match host.read(path) {
        Lookup::Found(bytes) => (parse(&bytes), None),
        Lookup::Missing => (
            Vec::new(),
            Some(Unverified::new(path, path, "it does not exist")),
        ),
        Lookup::Unreadable(reason) => (Vec::new(), Some(Unverified::new(path, path, reason))),
    }
}

/// The passwordless-rules check, and what the sudoers files say about root's
/// `PATH`.
struct ConfigOutcome {
    check: Check,
    secure_paths: Vec<PathBuf>,
    sudoers: Lookup<()>,
    /// Where each sudoers file, or directory of them, that could not be read
    /// stopped the reader: any of them may have set `secure_path`.
    unread: Vec<PathBuf>,
    /// Each sudoers file that was read and has lines aido does not model (see
    /// `config`): `secure_path` may be set on one of those lines, in a file that
    /// is not unread.
    unmodelled: Vec<PathBuf>,
}

/// Reads every sudoers and doas file a backend would, following includes.
fn passwordless_rules(ctx: &Ctx<'_>) -> ConfigOutcome {
    let mut sink = Sink::default();
    let mut secure_paths = Vec::new();
    let mut sudoers = Lookup::Missing;
    let mut note = None;
    // The gaps that are a file read and not fully modelled, kept apart from the
    // ones that are a file not read: root's `PATH` says a different thing of
    // each.
    let mut unmodelled = Vec::new();
    // Each file with its depth, and whether something named it: a file an
    // include names must exist, and one that does not is unverified, because
    // the include may have been misread.
    let mut queue: VecDeque<(PathBuf, usize, bool)> = SUDOERS_FILES
        .iter()
        .map(|file| (PathBuf::from(file), 0, false))
        .collect();
    let mut seen = BTreeSet::new();

    while let Some((file, depth, named)) = queue.pop_front() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let read = ctx.host.read(&file);
        if named && read == Lookup::Missing {
            sink.unverified
                .push(Unverified::new(&file, &file, MISSING_INCLUDE));
            continue;
        }
        if file == Path::new(SUDOERS) {
            sudoers = read.clone().map(|_| ());
            if matches!(read, Lookup::Unreadable(_)) {
                // What it includes cannot be known, but every stock one
                // includes this directory, and a cloud image's standing
                // `NOPASSWD` grant lives there.
                note = Some(format!(
                    "{SUDOERS} could not be read, so {SUDOERS_D} was read as the directory it \
                     conventionally includes; whether this one does could not be verified"
                ));
                let conventional = Include::Dir(SUDOERS_D.as_bytes().to_vec());
                queue.extend(
                    included(ctx, &file, &conventional, false, &mut sink)
                        .into_iter()
                        .map(|path| (path, 1, true)),
                );
            }
        }
        let Some(bytes) = sink.take(&file, read) else {
            continue;
        };
        let scan = config::scan_sudoers(&bytes);
        if let Some(gap) = unmodelled_gap(&file, &scan.unmodelled) {
            unmodelled.push(gap.clone());
            sink.unverified.push(gap);
        }
        for rule in scan.rules {
            sink.findings.push(passwordless(ctx, &file, &rule));
        }
        secure_paths.extend(
            scan.secure_paths
                .iter()
                .flat_map(|raw| split_path_list(raw)),
        );
        let next = depth.saturating_add(1);
        for include in scan.includes {
            if next > MAX_INCLUDE_DEPTH {
                sink.unverified.push(Unverified::new(
                    &file,
                    &file,
                    "its includes nest deeper than aido follows",
                ));
                continue;
            }
            queue.extend(
                included(ctx, &file, &include, true, &mut sink)
                    .into_iter()
                    .map(|p| (p, next, true)),
            );
        }
    }

    let unread = sink
        .unverified
        .iter()
        .filter(|gap| !unmodelled.contains(gap))
        .map(|gap| gap.at.clone())
        .collect();
    let unmodelled = unmodelled.into_iter().map(|gap| gap.at).collect();
    for file in doas_files(ctx, &mut sink) {
        let read = ctx.host.read(&file);
        if let Some(bytes) = sink.take(&file, read) {
            sink.unverified
                .extend(unmodelled_gap(&file, &config::doas_unmodelled(&bytes)));
            for rule in config::scan_doas(&bytes) {
                sink.findings.push(passwordless(ctx, &file, &rule));
            }
        }
    }

    ConfigOutcome {
        check: sink.into_check(CheckId::PasswordlessRules, note),
        secure_paths,
        sudoers,
        unread,
        unmodelled,
    }
}

/// What a file's unmodelled lines leave unverified, if it has any: which
/// lines, so a reader can look at exactly them.
fn unmodelled_gap(file: &Path, lines: &[usize]) -> Option<Unverified> {
    if lines.is_empty() {
        return None;
    }
    let numbers: Vec<String> = lines.iter().map(ToString::to_string).collect();
    Some(Unverified::new(
        file,
        file,
        format!(
            "line(s) {} end in a backslash, or use an escape or quote, that aido does not \
             model, so which lines they join, and so whom a rule near it names, could not \
             be verified",
            numbers.join(", ")
        ),
    ))
}

/// The files one include directive brings in.
///
/// `named` says whether a file named the directory, as opposed to the
/// conventional one read when no file could be: a named directory that does
/// not exist is unverified, never nothing.
fn included(
    ctx: &Ctx<'_>,
    from: &Path,
    include: &Include,
    named: bool,
    sink: &mut Sink,
) -> Vec<PathBuf> {
    let (raw, is_dir) = match include {
        Include::File(raw) => (raw, false),
        Include::Dir(raw) => (raw, true),
    };
    let Some(target) = config::resolve_include(from, raw) else {
        sink.unverified.push(Unverified::new(
            from,
            from,
            "an include names the host (%h), which aido does not expand",
        ));
        return Vec::new();
    };
    if !is_dir {
        return vec![target];
    }
    // sudo skips a name containing a dot or ending in a tilde, so a file it
    // never reads is not reported as a rule in effect.
    listed_names(ctx, &target, named, sink, |name| {
        !name.contains(&b'.') && !name.ends_with(b"~")
    })
}

/// doas's configuration file, and every entry of its drop-in directory.
fn doas_files(ctx: &Ctx<'_>, sink: &mut Sink) -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from(DOAS_CONF)];
    files.extend(listed_names(
        ctx,
        Path::new(DOAS_DIR),
        false,
        sink,
        |name| !name.starts_with(b".") && !name.ends_with(b"~"),
    ));
    files
}

/// The entries of `dir` that `keep` accepts, sorted, as paths. A directory
/// that is `required` and missing is unverified.
fn listed_names(
    ctx: &Ctx<'_>,
    dir: &Path,
    required: bool,
    sink: &mut Sink,
    keep: fn(&[u8]) -> bool,
) -> Vec<PathBuf> {
    let listing = match ctx.host.list(dir) {
        Lookup::Missing if required => Lookup::Unreadable(MISSING_INCLUDE.to_owned()),
        other => other,
    };
    let Some(mut names) = sink.take(dir, listing) else {
        return Vec::new();
    };
    names.sort();
    names
        .into_iter()
        .filter(|name| keep(name.as_bytes()))
        .map(|name| dir.join(name))
        .collect()
}

/// One passwordless rule, as a finding.
///
/// The rule's text is made a string for a reader, lossily: it is shown, never
/// compared — the same exception `CLAUDE.md` makes for `Path::display` — and
/// everything this module decides about the rule was decided on its bytes.
fn passwordless(ctx: &Ctx<'_>, file: &Path, rule: &RuleLine) -> Finding {
    Finding::PasswordlessRule {
        file: file.to_path_buf(),
        line: rule.line,
        text: String::from_utf8_lossy(rule.text.trim_ascii()).into_owned(),
        grant: rule.grant,
        applies_to_you: ctx.applies(&rule.scope),
    }
}

/// The group-membership check.
fn group_memberships(ctx: &Ctx<'_>) -> Check {
    let mut sink = Sink::default();
    if ctx.subject.is_root {
        return sink.into_skipped(
            CheckId::GroupMemberships,
            "you are root, so no group grants you more; run `aido doctor` as the user an agent \
             runs as",
        );
    }
    sink.unverified.extend(ctx.passwd_gap.clone());
    sink.unverified.extend(ctx.group_gap.clone());
    if let Some(reason) = &ctx.supplementary_gap {
        let status = Path::new("/proc/self/status");
        sink.unverified
            .push(Unverified::new(status, status, reason));
    }
    if ctx.passwd_gap.is_none() && ctx.name.is_none() {
        sink.unverified.push(Unverified::new(
            Path::new(accounts::PASSWD),
            Path::new(accounts::PASSWD),
            format!(
                "uid {} has no entry, so memberships /etc/group lists by name were not checked \
                 (a directory service is not consulted)",
                ctx.subject.uid
            ),
        ));
    }
    for gid in ctx
        .active
        .iter()
        .filter(|gid| ctx.group_name(**gid).is_none())
    {
        sink.unverified.push(Unverified::new(
            Path::new(accounts::GROUP),
            Path::new(accounts::GROUP),
            format!(
                "this process holds gid {gid}, which has no name there, so whether it is one of \
                 the groups below cannot be told (a directory service is not consulted)"
            ),
        ));
    }

    for root_group in &ROOT_GROUPS {
        sink.examined = sink.examined.saturating_add(1);
        for entry in ctx
            .groups
            .iter()
            .filter(|g| g.name == root_group.name.as_bytes())
        {
            let listed = ctx.listed.contains(&entry.gid);
            let active = ctx.active.contains(&entry.gid);
            if listed || active {
                sink.findings.push(Finding::GroupMembership {
                    group: root_group.name.to_owned(),
                    gid: entry.gid,
                    passwordless: root_group.passwordless,
                    grants: root_group.grants.to_owned(),
                    listed,
                    active,
                });
            }
        }
    }
    sink.into_check(CheckId::GroupMemberships, None)
}

/// The unit-directory check.
fn unit_directories(ctx: &Ctx<'_>) -> Check {
    let mut sink = Sink::default();
    let mut scanned = BTreeSet::new();
    for dir in UNIT_DIRECTORIES {
        walk::examine_dir(
            ctx,
            Path::new(dir),
            walk::Entries::Units,
            &mut scanned,
            &mut sink,
        );
    }
    sink.into_check(CheckId::UnitDirectories, None)
}

/// The root-`PATH` check: the real `secure_path` where it could be read, and
/// the stock directories always.
fn root_path(
    ctx: &Ctx<'_>,
    from_sudoers: &[PathBuf],
    sudoers: &Lookup<()>,
    unread: &[PathBuf],
    unmodelled: &[PathBuf],
) -> Check {
    let mut sink = Sink::default();
    let mut dirs: Vec<PathBuf> = Vec::new();
    for dir in from_sudoers
        .iter()
        .cloned()
        .chain(STOCK_SECURE_PATH.iter().map(PathBuf::from))
    {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    let note = match sudoers {
        Lookup::Found(()) => {
            "the directories /etc/sudoers names in secure_path, and the stock ones"
        }
        Lookup::Missing => "the stock secure_path directories; there is no /etc/sudoers",
        Lookup::Unreadable(reason) => {
            sink.unverified.push(Unverified::new(
                Path::new(SUDOERS),
                Path::new(SUDOERS),
                format!(
                    "root's secure_path is set there and could not be read ({reason}); the stock \
                     directories were examined instead"
                ),
            ));
            "the stock secure_path directories"
        }
    };
    // `/etc/sudoers` was not the one that failed, but something else was: the
    // `secure_path` that wins is the last one sudo reads, and it may be there.
    let reported = matches!(sudoers, Lookup::Unreadable(_));
    if let Some(first) = unread.first().filter(|_| !reported) {
        sink.unverified.push(Unverified::new(
            Path::new(SUDOERS),
            first,
            format!(
                "root's secure_path may be set in a sudoers file that could not be read ({} \
                 such, the first at {}); the stock directories were examined instead",
                unread.len(),
                first.display()
            ),
        ));
    }
    // A file that was read is not one that could not be read, and the reason
    // must not say so: what is wrong with it is a line aido did not model, and
    // `secure_path` may be set on that line.
    if let Some(first) = unmodelled.first() {
        sink.unverified.push(Unverified::new(
            Path::new(SUDOERS),
            first,
            format!(
                "root's secure_path may be set on a line aido does not model, in a sudoers file \
                 it read ({} such, the first at {}); the directories it did find in secure_path, \
                 and the stock ones, were examined",
                unmodelled.len(),
                first.display()
            ),
        ));
    }
    let mut scanned = BTreeSet::new();
    for dir in &dirs {
        if dir.is_absolute() {
            walk::examine_dir(ctx, dir, walk::Entries::Files, &mut scanned, &mut sink);
        } else {
            sink.findings
                .push(Finding::RelativePathEntry { entry: dir.clone() });
        }
    }
    sink.into_check(CheckId::RootPath, Some(note.to_owned()))
}

/// The user-`PATH` check: every entry ahead of the backend's directory that
/// anyone but root can write, or that is relative.
///
/// Ahead is what makes one a path to root. A program named `sudo` in such a
/// directory runs when the human types `sudo`, and is handed the password they
/// type next; one behind the backend's directory is never reached by that name.
fn user_path(ctx: &Ctx<'_>, input: &Input<'_>) -> Check {
    let mut sink = Sink::default();
    let Some(raw) = input.user_path else {
        sink.unverified.push(Unverified::new(
            Path::new("$PATH"),
            Path::new("$PATH"),
            "it was not provided to this check",
        ));
        return sink.into_check(CheckId::UserPath, None);
    };
    let anchor_dir = input
        .backend_exe
        .and_then(Path::parent)
        .unwrap_or(Path::new("/usr/bin"));
    let anchor = walk::resolve(ctx, anchor_dir);
    let entries = split_path_list(raw.as_bytes());
    let shadows = input
        .backend_exe
        .unwrap_or(anchor_dir)
        .display()
        .to_string();

    // Entries are taken in order, each judged, until one that is itself clean
    // leads to the backend's directory. Only such an entry ends the search: an
    // entry that reaches that directory through a link someone else can
    // replace is a finding, and everything after it is still ahead of what the
    // next `sudo` runs.
    let mut seen = BTreeSet::new();
    let mut anchored: Option<(&Path, usize)> = None;
    for (at, entry) in entries.iter().enumerate() {
        if !seen.insert(entry.clone()) {
            continue;
        }
        if !entry.is_absolute() {
            sink.findings.push(Finding::RelativePathEntry {
                entry: entry.clone(),
            });
            continue;
        }
        let outcome = walk::examine(ctx, entry);
        let reaches = matches!(&outcome, Outcome::Clean { target: Some((resolved, _)) }
            if Some(resolved) == anchor.as_ref());
        if reaches {
            anchored = Some((entry, entries.len().saturating_sub(at)));
            break;
        }
        sink.examined = sink.examined.saturating_add(1);
        match outcome {
            Outcome::Writable(found) => {
                sink.findings
                    .push(found.into_finding(Some(shadows.clone())));
            }
            Outcome::Unverified(gap) => sink.unverified.push(gap),
            Outcome::Clean { .. } => {}
        }
    }
    let note = anchored.map(|(entry, behind)| {
        format!(
            "the entries from {} on ({behind}) were not examined: nothing there is found \
             before {shadows}",
            entry.display()
        )
    });
    sink.into_check(CheckId::UserPath, note)
}

/// The root-shell-startup check.
fn root_shell_startup(ctx: &Ctx<'_>) -> Check {
    let mut sink = Sink::default();
    let mut scanned = BTreeSet::new();
    for file in SYSTEM_STARTUP_FILES {
        sink.examined = sink.examined.saturating_add(1);
        sink.push(walk::examine(ctx, Path::new(file)));
    }
    let home: Vec<Outcome> = ROOT_HOME_FILES
        .iter()
        .map(|file| walk::examine(ctx, &ctx.root_home.join(file)))
        .collect();
    sink.examined = sink.examined.saturating_add(home.len());
    // Root's home is `0700` on every normal host, so to anyone else each file
    // in it fails for the same reason. Said once, not once per file.
    let gaps: Vec<&Unverified> = home
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Unverified(gap) => Some(gap),
            Outcome::Clean { .. } | Outcome::Writable(_) => None,
        })
        .collect();
    let reason = gaps.first().map(|gap| gap.reason.clone());
    let sealed =
        gaps.len() == home.len() && gaps.iter().all(|gap| Some(&gap.reason) == reason.as_ref());
    match reason.filter(|_| sealed) {
        Some(reason) => sink.unverified.push(Unverified::new(
            &ctx.root_home,
            &ctx.root_home,
            format!(
                "{reason}: none of the files root's shells read there ({}) could be examined",
                ROOT_HOME_FILES.join(", ")
            ),
        )),
        None => home.into_iter().for_each(|outcome| sink.push(outcome)),
    }
    for dir in STARTUP_DIRECTORIES {
        walk::examine_dir(
            ctx,
            Path::new(dir),
            walk::Entries::Files,
            &mut scanned,
            &mut sink,
        );
    }
    let note = ctx.passwd_gap.as_ref().map(|_| {
        "root's home was taken to be /root, because /etc/passwd could not be read".to_owned()
    });
    sink.into_check(CheckId::RootShellStartup, note)
}

/// Splits a colon-separated list into paths, keeping empty entries: an empty
/// `PATH` entry means the current directory.
fn split_path_list(raw: &[u8]) -> Vec<PathBuf> {
    raw.split(|byte| *byte == b':')
        .map(|entry| PathBuf::from(OsString::from_vec(entry.to_vec())))
        .collect()
}

#[cfg(test)]
mod tests;
