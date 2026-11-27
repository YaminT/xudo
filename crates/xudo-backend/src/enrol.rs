//! Enrolling a harness: what `xudo agent enrol` writes, decided from facts.
//!
//! Pure. The facts (the accounts files, the registry as it stands, the state of
//! the drop-in directory, what the other-paths-to-root scan says about the
//! account) are gathered elsewhere and handed in; the answer is a plan of three
//! files or a refusal. Nothing here makes a command run without a password:
//! the registry entry names an account and its reviewers, and no rule grants
//! that harness anything.
//!
//! # What an enrolled account must not be
//!
//! A harness runs as an account root chose, and the rule set is the boundary
//! around it. That only holds if the account has no way to root of its own, so
//! each refusal below is a way to root the account would carry into the unit:
//! uid 0, a password someone could type, a group that is root by another name,
//! a sudo or doas rule that names it, a reviewer seat on its own queue, and a
//! drop-in that could change who the unit runs as.

use std::path::Path;

use xudo_policy::{HarnessError, HarnessRegistry, valid_account_name, valid_harness_label};

use crate::paths_to_root::{
    Applies, Caller, Check, CheckId, Finding, HostView, Input, Kind, Lookup, Meta, Writer, assess,
};
use crate::snippet::{GATE_NOPASS, SUDOERS_PATH, XUDO_AGENT_GROUP, XUDO_GROUP};

/// Where registry files live.
pub const REGISTRY_DIR: &str = "/etc/xudo/harnesses.d";

/// Where each agent's private environment file lives.
pub const AGENTS_DIR: &str = "/etc/xudo/agents";

/// The system unit directory, where an operator's drop-ins go.
pub const UNIT_DIR: &str = "/etc/systemd/system";

/// The file a registry entry and a drop-in are written under, in its directory.
pub const DROP_IN_NAME: &str = "10-xudo.conf";

/// First line of every file `enrol` writes, so `remove` touches only its own.
pub use crate::snippet::MANAGED_MARKER;

/// Groups that are root by another name, or that read the audit trail.
///
/// `adm` and `systemd-journal` read the journal, which mirrors the audit
/// records; an agent that read them could see what other callers were refused.
pub const ROOT_EQUIVALENT_GROUPS: [&str; 11] = [
    "sudo",
    "wheel",
    "root",
    "docker",
    "lxd",
    "incus",
    "libvirt",
    "disk",
    "shadow",
    "adm",
    "systemd-journal",
];

/// The groups an enrolled account joins: the broker's door and the agent path's.
/// Neither grants anything by itself: the sudoers snippet and the rules do.
pub const AGENT_GROUPS: [&str; 2] = [XUDO_GROUP, XUDO_AGENT_GROUP];

/// The registry comment that records which groups `enrol` itself added the
/// account to, so `remove` undoes those and no others.
pub const JOINED_MARKER: &str = "# xudo-joined-groups:";

/// How many concurrent sessions the entry declares. One service, one process.
const MAX_SESSIONS: u32 = 1;

/// What `enrol` was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolRequest {
    /// The label: the unit instance name, the record name, the registry key.
    pub label: String,
    /// The existing account the harness runs as.
    pub account: String,
    /// Who decides what the harness queues. At least one.
    pub reviewers: Vec<String>,
    /// The program and its arguments; the first is an absolute path.
    pub argv: Vec<String>,
}

/// What the other-paths-to-root scan said about the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountScan {
    /// The uid the scan resolved the account to.
    pub uid: u32,
    /// One line per rule, listing or gap that stands in the way. Empty is clean.
    pub blockers: Vec<String>,
    /// The machine's escalator is doas, which has no passwordless agent path.
    pub doas: bool,
}

/// The drop-in directory for this label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DropInState {
    /// There is none.
    Absent,
    /// There is one, root's, and nothing is in it.
    Empty,
    /// It holds files, which could set `User=` after ours.
    Occupied,
    /// It, or something above it, is not root's alone, or could not be examined.
    Untrusted(String),
}

/// Everything `enrol` reads before it decides.
#[derive(Clone, Debug)]
pub struct Facts {
    /// `/etc/passwd`, as bytes.
    pub passwd: Vec<u8>,
    /// `/etc/shadow`, when it could be read.
    pub shadow: Option<Vec<u8>>,
    /// `/etc/group`, as bytes.
    pub group: Vec<u8>,
    /// Every registry file now present: its name and its text.
    pub registry: Vec<(String, String)>,
    /// The label's drop-in directory.
    pub drop_in: DropInState,
    /// Whether the environment file already exists, and so is kept.
    pub env_present: bool,
    /// The scan of the account.
    pub scan: AccountScan,
}

/// Why `enrol` stopped. Every variant is a reason nothing was written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The label is not `[a-z][a-z0-9-]{0,31}`.
    #[error("{0:?} is not a harness label ([a-z][a-z0-9-], at most 32 characters)")]
    BadLabel(String),
    /// The account name is not an account name.
    #[error("{0:?} is not an account name")]
    BadAccount(String),
    /// A reviewer name is not an account name.
    #[error("reviewer {0:?} is not an account name")]
    BadReviewer(String),
    /// No reviewer was named.
    #[error(
        "name at least one reviewer with --reviewer: someone must decide what the agent queues"
    )]
    NoReviewer,
    /// No program was given after `--`.
    #[error("give the program to run after `--`")]
    NoProgram,
    /// The program is not an absolute path.
    #[error("the program {0:?} is not an absolute path: nothing is searched for on a PATH")]
    ProgramNotAbsolute(String),
    /// An argument holds a control character, which a unit file cannot carry.
    #[error("an argument holds a control character: a unit file line cannot carry it")]
    ControlCharacter,
    /// A harness with this label is already registered.
    #[error("harness {0} is already enrolled; `xudo agent remove {0}` first")]
    LabelTaken(String),
    /// The account is not in `/etc/passwd`.
    #[error(
        "account {0} is not in /etc/passwd (no directory service is consulted); create it first"
    )]
    AccountUnknown(String),
    /// The account name or its uid appears twice.
    #[error("account {0} is ambiguous in /etc/passwd: its name or uid appears more than once")]
    AccountAmbiguous(String),
    /// Uid 0 or group 0.
    #[error("account {0} is root (uid or primary group 0)")]
    AccountIsRoot(String),
    /// A password could be typed for the account.
    #[error("account {0} has a usable password; lock it first (`passwd -l {0}`)")]
    PasswordUsable(String),
    /// The password state could not be read.
    #[error("whether account {0} has a password could not be read from /etc/shadow; refusing")]
    PasswordUnknown(String),
    /// The account holds a group that is root by another name.
    #[error(
        "account {account} is in group {group}, which is root by another name or reads the audit trail"
    )]
    RootGroup {
        /// The account.
        account: String,
        /// The group.
        group: String,
    },
    /// The scan found a rule, a listing or a gap.
    #[error("account {account} has another way to root: {blockers}")]
    OtherPathToRoot {
        /// The account.
        account: String,
        /// The scan's findings, joined.
        blockers: String,
    },
    /// The scan and the file read disagree about the account's uid.
    #[error("account {0} changed uid while enrolling; refusing")]
    AccountChanged(String),
    /// Another label runs as this account, or lists it as a session user.
    #[error("account {account} is already used by harness {label}")]
    AccountInUse {
        /// The account.
        account: String,
        /// The other label.
        label: String,
    },
    /// The account is its own reviewer.
    #[error("account {0} cannot be its own reviewer: an agent would approve itself")]
    ReviewerIsAccount(String),
    /// A reviewer is not in `/etc/passwd`.
    #[error("reviewer {0} is not in /etc/passwd")]
    ReviewerUnknown(String),
    /// The registry, with this entry added, does not load.
    #[error("the registry would not load: {0}")]
    Registry(String),
    /// A group the account would join is, by gid, a group that is root by another name.
    #[error(
        "group {group} has gid {gid}, which is also the gid of {alias}: joining it would be joining that"
    )]
    AgentGroupIsRoot {
        /// The group `enrol` would join.
        group: String,
        /// Its gid.
        gid: u32,
        /// The root-equivalent group sharing the gid.
        alias: String,
    },
    /// The machine's escalator is doas.
    #[error(
        "the agent path is sudo or sudo-rs only: this machine uses doas, which has no \
         equivalent of the passwordless helper, so no harness is enrolled"
    )]
    AgentPathNeedsSudo,
    /// The drop-in directory holds files that could override `User=`.
    #[error(
        "the drop-in directory for xudo-agent@{0}.service is not empty: remove its files first"
    )]
    DropInOccupied(String),
    /// The drop-in directory is not root's alone.
    #[error("the drop-in directory is not trusted: {0}")]
    DropInUntrusted(String),
}

/// One file the plan writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedFile {
    /// Absolute path.
    pub path: String,
    /// Contents; every file begins with [`MANAGED_MARKER`].
    pub contents: String,
    /// Mode: no write bit for anyone.
    pub mode: u32,
    /// The file is already there and is kept as it is.
    pub keep: bool,
}

/// One group the account joins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The group.
    pub group: String,
    /// It does not exist and is created, empty, first.
    pub create: bool,
    /// The account is added to it. False when it is already a member: that
    /// membership is not ours and `remove` leaves it.
    pub join: bool,
}

/// The three files, the groups, and the unit they configure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolPlan {
    /// The label.
    pub label: String,
    /// The account.
    pub account: String,
    /// `xudo-agent@<label>.service`.
    pub unit: String,
    /// The registry entry.
    pub registry: PlannedFile,
    /// The drop-in's directory, created if absent.
    pub drop_in_dir: String,
    /// `User=` and `ExecStart=`.
    pub drop_in: PlannedFile,
    /// The private environment file, an empty stub.
    pub env: PlannedFile,
    /// The groups the account joins, as the last write.
    pub memberships: Vec<Membership>,
}

impl EnrolPlan {
    /// The plan as text for the human, additions only: nothing it writes
    /// replaces a file.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for file in [&self.registry, &self.drop_in, &self.env] {
            let state = if file.keep {
                "already there, kept as it is"
            } else {
                "new"
            };
            let _ = writeln!(
                out,
                "--- {} (mode {:04o}, root, {state})",
                file.path, file.mode
            );
            if !file.keep {
                for line in file.contents.lines() {
                    let _ = writeln!(out, "+ {line}");
                }
            }
        }
        for member in &self.memberships {
            let what = match (member.create, member.join) {
                (true, _) => "create the group, then add",
                (false, true) => "add",
                (false, false) => "already a member of the group, kept as it is:",
            };
            let _ = writeln!(out, "group {}: {what} {}", member.group, self.account);
        }
        let _ = writeln!(
            out,
            "then: systemctl daemon-reload; check User= is {}; systemctl enable --now {}",
            self.account, self.unit
        );
        out
    }
}

/// The unit's name.
#[must_use]
pub fn unit_name(label: &str) -> String {
    format!("xudo-agent@{label}.service")
}

/// The registry file for a label.
#[must_use]
pub fn registry_path(label: &str) -> String {
    format!("{REGISTRY_DIR}/{label}.toml")
}

/// The drop-in directory for a label.
#[must_use]
pub fn drop_in_dir(label: &str) -> String {
    format!("{UNIT_DIR}/{}.d", unit_name(label))
}

/// The environment file for a label.
#[must_use]
pub fn env_path(label: &str) -> String {
    format!("{AGENTS_DIR}/{label}.env")
}

/// One account line of `/etc/passwd`.
pub(crate) struct Passwd<'a> {
    pub(crate) name: &'a [u8],
    password: &'a [u8],
    uid: u32,
    pub(crate) gid: u32,
}

pub(crate) fn parse_passwd(bytes: &[u8]) -> Vec<Passwd<'_>> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
            let [name, password, uid, gid, ..] = fields.as_slice() else {
                return None;
            };
            Some(Passwd {
                name,
                password,
                uid: number(uid)?,
                gid: number(gid)?,
            })
        })
        .collect()
}

pub(crate) fn number(bytes: &[u8]) -> Option<u32> {
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// Runs the scan of other paths to root with `name` as the subject.
///
/// `xudo agent enrol` runs as root, so the report would be about root and
/// skip every check. The host is wrapped so that the process answers as the
/// account does: its uid and primary group, and no supplementary group beyond
/// the ones `/etc/group` lists for its name. Write access is answered from the
/// mode bits alone; an ACL is not seen.
///
/// `managed` is the exact text of the passwordless sudoers snippet xudo itself
/// would install (see [`managed_snippet`]). When `/etc/sudoers.d/xudo`
/// holds exactly those bytes, that one file's passwordless rule is the agent
/// path and is not a blocker. A file that differs by a byte exempts nothing,
/// and any other line naming `%xudo-agent`, the account or the `-nopass`
/// helper is a blocker.
///
/// # Errors
///
/// [`Refusal::AccountUnknown`] and [`Refusal::AccountAmbiguous`], when
/// `/etc/passwd` cannot say who the account is.
pub fn scan_account(
    host: &dyn HostView,
    name: &str,
    input: &Input<'_>,
    managed: Option<&str>,
) -> Result<AccountScan, Refusal> {
    let Lookup::Found(passwd) = host.read(Path::new("/etc/passwd")) else {
        return Err(Refusal::AccountUnknown(name.to_owned()));
    };
    let entries = parse_passwd(&passwd);
    let mut named = entries.iter().filter(|entry| entry.name == name.as_bytes());
    let (Some(entry), None) = (named.next(), named.next()) else {
        return Err(if entries.iter().any(|e| e.name == name.as_bytes()) {
            Refusal::AccountAmbiguous(name.to_owned())
        } else {
            Refusal::AccountUnknown(name.to_owned())
        });
    };
    // The account is judged as the agent it is about to be: already a member
    // of both agent groups. A grant that only membership of `xudo` or
    // `xudo-agent` gives it would otherwise look like nobody's.
    let group_file = match host.read(Path::new("/etc/group")) {
        Lookup::Found(group) => Some(with_membership(&group, name)),
        _ => None,
    };
    let as_account = AsAccount {
        inner: host,
        uid: entry.uid,
        gid: entry.gid,
        group: group_file.clone(),
    };
    let report = assess(&as_account, input);
    let (held, mut gaps) = match &group_file {
        Some(group) => (held_gids(name, entry.gid, group), Vec::new()),
        None => (
            vec![entry.gid],
            vec!["could not examine /etc/group: unreadable or missing".to_owned()],
        ),
    };
    // Every check counts, not only the sudo and doas rules: any other way to
    // root is one the unit would carry.
    let exempt = managed_installed(host, managed);
    let mut blockers: Vec<String> = report
        .checks
        .iter()
        // The user `PATH` check is about whoever invoked `enrol`, who is root.
        .filter(|check| check.check != CheckId::UserPath)
        .flat_map(|check| blockers_of(check, name, entry.uid, &held, exempt))
        .collect();
    blockers.append(&mut gaps);
    let group_gids: Vec<u32> = AGENT_GROUPS
        .iter()
        .filter_map(|group| group_gid(&as_account, group))
        .collect();
    // A group enrol will create takes a gid no rule can be told apart by yet:
    // a leftover `%#996` would name it. Until it exists, any numeric group
    // in a rule counts.
    let numeric_groups = group_gids.len() < AGENT_GROUPS.len();
    blockers.extend(rules_naming(
        host,
        name,
        entry.uid,
        &group_gids,
        numeric_groups,
        exempt,
    ));
    blockers.extend(pam::blockers(host));
    Ok(AccountScan {
        uid: entry.uid,
        blockers,
        doas: input.doas_exe.is_some(),
    })
}

/// `group_file` with `account` listed in each agent group that exists.
fn with_membership(group_file: &[u8], account: &str) -> Vec<u8> {
    let lines: Vec<Vec<u8>> = group_file
        .split(|byte| *byte == b'\n')
        .map(|line| {
            let mut fields: Vec<Vec<u8>> = line
                .split(|byte| *byte == b':')
                .map(<[u8]>::to_vec)
                .collect();
            let agent = fields
                .first()
                .is_some_and(|name| AGENT_GROUPS.iter().any(|g| g.as_bytes() == name.as_slice()));
            if agent && let Some(members) = fields.get_mut(3) {
                let listed = members
                    .split(|byte| *byte == b',')
                    .any(|member| member == account.as_bytes());
                if !listed {
                    if !members.is_empty() {
                        members.push(b',');
                    }
                    members.extend_from_slice(account.as_bytes());
                }
            }
            fields.join(&b':')
        })
        .collect();
    lines.join(&b'\n')
}

/// The exact text [`scan_account`] exempts; see [`crate::snippet::managed_agent_snippet`].
pub use crate::snippet::managed_agent_snippet as managed_snippet;

/// Whether the sudoers file xudo manages is root's alone (a regular file, uid
/// 0, no group or world write) and holds exactly one of xudo's two texts, for
/// the backend version its own header names ([`crate::snippet::recognize`],
/// the reader `xudo doctor` uses): after a sudo upgrade the file an older
/// version wrote is still xudo's. Both name `%xudo`; nothing else is exempt.
/// `managed` is `None` where xudo writes no sudoers file (doas, no backend).
fn managed_installed(host: &dyn HostView, managed: Option<&str>) -> bool {
    let trusted = matches!(
        host.stat(Path::new(SUDOERS_PATH)),
        Lookup::Found(meta) if meta.kind == Kind::File && meta.uid == 0 && meta.mode & 0o022 == 0
    );
    managed.is_some()
        && trusted
        && matches!(
            host.read(Path::new(SUDOERS_PATH)),
            Lookup::Found(bytes) if crate::snippet::recognize(&bytes).is_some()
        )
}

/// The gid of the group named `group` in `/etc/group`, when it appears once.
pub(crate) fn group_gid(host: &dyn HostView, group: &str) -> Option<u32> {
    let Lookup::Found(file) = host.read(Path::new("/etc/group")) else {
        return None;
    };
    let gids: Vec<u32> = file
        .split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
            match fields.as_slice() {
                [name, _, gid, ..] if *name == group.as_bytes() => number(gid),
                _ => None,
            }
        })
        .collect();
    match gids.as_slice() {
        [gid] => Some(*gid),
        _ => None,
    }
}

/// The gids the account holds: its primary one and every group that lists it.
fn held_gids(account: &str, primary: u32, group_file: &[u8]) -> Vec<u32> {
    let mut held = vec![primary];
    for line in group_file.split(|byte| *byte == b'\n') {
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        if let [_, _, gid, members, ..] = fields.as_slice()
            && members
                .split(|byte| *byte == b',')
                .any(|member| member == account.as_bytes())
            && let Some(gid) = number(gid)
        {
            held.push(gid);
        }
    }
    held
}

/// Where sudo, sudo-rs and doas read rules, and the directories that add to
/// them.
pub(crate) const RULE_FILES: [&str; 4] = [
    "/etc/sudoers",
    "/etc/sudoers-rs",
    "/etc/doas.conf",
    "/usr/local/etc/doas.conf",
];
pub(crate) const RULE_DIRS: [&str; 2] = ["/etc/sudoers.d", "/etc/doas.d"];

/// Every line of every sudo or doas file that names the account (by name or
/// `#uid`), with or without a password, or that names everyone, or that
/// includes something this cannot follow. A rule that asks for a password is
/// still a way to root: `rootpw` and `targetpw` make it the root password, and
/// a PAM module may accept something else.
fn rules_naming(
    host: &dyn HostView,
    name: &str,
    uid: u32,
    group_gids: &[u32],
    numeric_groups: bool,
    exempt: bool,
) -> Vec<String> {
    let mut files: Vec<std::path::PathBuf> =
        RULE_FILES.iter().map(std::path::PathBuf::from).collect();
    let mut out = Vec::new();
    for dir in RULE_DIRS {
        match host.list(Path::new(dir)) {
            Lookup::Found(names) => files.extend(names.iter().map(|n| Path::new(dir).join(n))),
            Lookup::Missing => {}
            Lookup::Unreadable(why) => out.push(format!("could not examine {dir}: {why}")),
        }
    }
    for file in files {
        // The one file whose bytes are exactly the managed snippet.
        if exempt && file == Path::new(SUDOERS_PATH) {
            continue;
        }
        match host.read(&file) {
            Lookup::Found(bytes) => out.extend(
                lines_naming(&bytes, name, uid, group_gids, numeric_groups)
                    .into_iter()
                    .map(|line| format!("{} line {line} names the account", file.display())),
            ),
            Lookup::Missing => {}
            Lookup::Unreadable(why) => {
                out.push(format!("could not examine {}: {why}", file.display()));
            }
        }
    }
    out
}

fn lines_naming(
    bytes: &[u8],
    name: &str,
    uid: u32,
    group_gids: &[u32],
    numeric_groups: bool,
) -> Vec<usize> {
    let uid_hash = format!("#{uid}");
    // The agent groups by name and by gid, and the account's own gid hash.
    let group_tokens: Vec<String> = AGENT_GROUPS
        .iter()
        .map(|group| format!("%{group}"))
        .chain(
            group_gids
                .iter()
                .flat_map(|gid| [format!("%#{gid}"), format!("%{gid}")]),
        )
        .collect();
    let is_word = |byte: &u8| byte.is_ascii_alphanumeric() || b"_.-#".contains(byte);
    let mut found = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line_no = index.saturating_add(1);
        let trimmed = line.trim_ascii_start();
        let directive = [&b"#include"[..], b"@include"]
            .iter()
            .any(|word| trimmed.starts_with(word));
        if directive {
            let mut parts = trimmed.split(u8::is_ascii_whitespace);
            let standard = matches!(
                (parts.next(), parts.next()),
                (
                    Some(b"#includedir" | b"@includedir"),
                    Some(b"/etc/sudoers.d")
                )
            );
            if !standard {
                found.push(line_no);
            }
            continue;
        }
        if trimmed.first() == Some(&b'#') && !trimmed.get(1).is_some_and(u8::is_ascii_digit) {
            continue;
        }
        let words: Vec<&[u8]> = line
            .split(|byte| !is_word(byte))
            .filter(|word| !word.is_empty())
            .collect();
        let names_account = words
            .iter()
            .any(|word| *word == name.as_bytes() || *word == uid_hash.as_bytes());
        // `ALL ALL=(ALL) ALL`: the first field of a sudoers rule is everyone.
        let names_everyone = words.first() == Some(&&b"ALL"[..]);
        // Either agent group, by name or by gid, and the passwordless helper
        // by its path: the agent path, hand-written. The account joins both.
        let names_agent_path = contains(line, GATE_NOPASS.as_bytes())
            || group_tokens
                .iter()
                .any(|token| names_token(line, token.as_bytes(), &is_word));
        let names_future_group = numeric_groups && names_numeric_group(line);
        if names_account || names_everyone || names_agent_path || names_future_group {
            found.push(line_no);
        }
    }
    found
}

/// Whether `token` occurs in `line` as a whole word: not followed by another
/// word byte, so `%xudo` is not `%xudo-agent` and `%#99` is not `%#998`.
pub(crate) fn names_token(line: &[u8], token: &[u8], is_word: &dyn Fn(&u8) -> bool) -> bool {
    line.windows(token.len().max(1))
        .enumerate()
        .any(|(at, window)| {
            window == token
                && !line
                    .get(at.saturating_add(token.len()))
                    .is_some_and(is_word)
        })
}

/// Whether `line` has a `%#N` or `%N` group, `N` being digits.
pub(crate) fn names_numeric_group(line: &[u8]) -> bool {
    line.split(|byte| *byte == b'%').skip(1).any(|rest| {
        let rest = rest.strip_prefix(b":").unwrap_or(rest);
        let rest = rest.strip_prefix(b"#").unwrap_or(rest);
        rest.first().is_some_and(u8::is_ascii_digit)
    })
}

/// Whether `needle` occurs in `haystack`.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len().max(1))
        .any(|window| window == needle)
}

fn blockers_of(check: &Check, name: &str, uid: u32, held: &[u32], exempt: bool) -> Vec<String> {
    let mut lines: Vec<String> = check
        .findings
        .iter()
        .filter(|finding| !is_managed(finding, name, exempt))
        .filter(|finding| concerns(finding, uid, held))
        .map(|finding| format!("{finding:?}"))
        .collect();
    lines.extend(
        check
            .unverified
            .iter()
            .map(|gap| format!("could not examine {}: {}", gap.path.display(), gap.reason)),
    );
    lines
}

/// Whether a finding is the managed passwordless snippet and nothing else:
/// exempt only while its file holds exactly the bytes xudo would write.
fn is_managed(finding: &Finding, name: &str, exempt: bool) -> bool {
    if !exempt {
        return false;
    }
    match finding {
        Finding::PasswordlessRule { file, .. } => file == Path::new(SUDOERS_PATH),
        // sudo's own listing for the account: only the helper, exactly.
        Finding::BackendListing { user, listing } => {
            user == name
                && !listing.trim().is_empty()
                && listing.lines().all(|line| {
                    line.split_whitespace().collect::<Vec<_>>()
                        == ["(root)", "NOPASSWD:", GATE_NOPASS, "\"\""]
                })
        }
        _ => false,
    }
}

/// Whether a finding is about this account. Only what names others alone, or
/// can be written by others alone, is left out.
fn concerns(finding: &Finding, uid: u32, held: &[u32]) -> bool {
    match finding {
        Finding::PasswordlessRule { applies_to_you, .. } => *applies_to_you != Applies::No,
        Finding::Writable { writers, .. } => {
            writers.is_empty()
                || writers.iter().any(|writer| match writer {
                    Writer::You | Writer::Everyone => true,
                    Writer::Owner { uid: owner, .. } => *owner == uid,
                    Writer::Group { gid, .. } => held.contains(gid),
                })
        }
        _ => true,
    }
}

/// The host, answering as another account.
struct AsAccount<'a> {
    inner: &'a dyn HostView,
    uid: u32,
    gid: u32,
    /// `/etc/group` as the account will see it, with the agent groups joined.
    group: Option<Vec<u8>>,
}

impl HostView for AsAccount<'_> {
    fn caller(&self) -> Caller {
        Caller {
            uid: self.uid,
            gid: self.gid,
            groups: Lookup::Found(Vec::new()),
        }
    }

    fn stat(&self, path: &Path) -> Lookup<Meta> {
        self.inner.stat(path)
    }

    fn read(&self, path: &Path) -> Lookup<Vec<u8>> {
        match &self.group {
            Some(group) if path == Path::new("/etc/group") => Lookup::Found(group.clone()),
            _ => self.inner.read(path),
        }
    }

    fn list(&self, path: &Path) -> Lookup<Vec<std::ffi::OsString>> {
        self.inner.list(path)
    }

    fn read_link(&self, path: &Path) -> Lookup<std::path::PathBuf> {
        self.inner.read_link(path)
    }

    fn writable(&self, _path: &Path) -> bool {
        // access(2) would answer for root, to whom everything is writable.
        false
    }

    fn ask_sudo(&self, exe: &str, user: &str) -> crate::paths_to_root::Answer {
        self.inner.ask_sudo(exe, user)
    }

    fn ask_doas(&self, exe: &str, file: &Path, command: &str) -> crate::paths_to_root::Answer {
        self.inner.ask_doas(exe, file, command)
    }
}

/// Renders one `ExecStart=` line value from an argv.
///
/// One-way, never parsed back: every word is double-quoted, `\` and `"` are
/// escaped for the quotes, and `%` and `$` are doubled so systemd expands
/// neither a specifier (`%i`, `%u`) nor a variable (`$HOME`, `${X}`) from
/// what the operator typed.
///
/// # Errors
///
/// [`Refusal::NoProgram`], [`Refusal::ProgramNotAbsolute`] and
/// [`Refusal::ControlCharacter`].
pub fn exec_start(argv: &[String]) -> Result<String, Refusal> {
    let Some(program) = argv.first() else {
        return Err(Refusal::NoProgram);
    };
    if !program.starts_with('/') {
        return Err(Refusal::ProgramNotAbsolute(program.clone()));
    }
    if argv.iter().any(|word| word.chars().any(char::is_control)) {
        return Err(Refusal::ControlCharacter);
    }
    let words: Vec<String> = argv
        .iter()
        .map(|word| {
            let escaped = word
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('%', "%%")
                .replace('$', "$$");
            format!("\"{escaped}\"")
        })
        .collect();
    Ok(words.join(" "))
}

/// Decides what to write.
///
/// # Errors
///
/// The first [`Refusal`] that applies.
pub fn plan(request: &EnrolRequest, facts: &Facts) -> Result<EnrolPlan, Refusal> {
    if facts.scan.doas {
        return Err(Refusal::AgentPathNeedsSudo);
    }
    let exec = check_request(request)?;
    check_account(request, facts)?;
    check_registry(request, facts)?;
    match &facts.drop_in {
        DropInState::Absent | DropInState::Empty => {}
        DropInState::Occupied => return Err(Refusal::DropInOccupied(request.label.clone())),
        DropInState::Untrusted(reason) => return Err(Refusal::DropInUntrusted(reason.clone())),
    }
    let label = &request.label;
    let memberships = memberships(request, facts)?;
    let joined: Vec<&str> = memberships
        .iter()
        .filter(|member| member.join)
        .map(|member| member.group.as_str())
        .collect();
    let joined_line = if joined.is_empty() {
        String::new()
    } else {
        format!("{JOINED_MARKER} {}\n", joined.join(" "))
    };
    let registry = format!(
        "{MANAGED_MARKER}\n{joined_line}label = \"{label}\"\nway = \"service\"\naccount = \"{}\"\nreviewers = [{}]\nmax-sessions = {MAX_SESSIONS}\n",
        request.account,
        request
            .reviewers
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let drop_in = format!(
        "{MANAGED_MARKER}\n[Service]\nUser={}\nExecStart={exec}\n",
        request.account
    );
    let env = format!(
        "{MANAGED_MARKER}\n# Credentials for {}: KEY=value, one per line. Root's alone (0600).\n",
        unit_name(label)
    );
    let plan = EnrolPlan {
        label: label.clone(),
        account: request.account.clone(),
        unit: unit_name(label),
        registry: PlannedFile {
            path: registry_path(label),
            contents: registry,
            mode: 0o644,
            keep: false,
        },
        drop_in_dir: drop_in_dir(label),
        drop_in: PlannedFile {
            path: format!("{}/{DROP_IN_NAME}", drop_in_dir(label)),
            contents: drop_in,
            mode: 0o644,
            keep: false,
        },
        env: PlannedFile {
            path: env_path(label),
            contents: env,
            mode: 0o600,
            keep: facts.env_present,
        },
        memberships,
    };
    check_loads(&plan, facts)?;
    Ok(plan)
}

/// What happens to each agent group. A group that exists is never redefined:
/// only a member is added. A group whose gid is shared with a root-equivalent
/// group is refused, because joining it is joining that one.
fn memberships(request: &EnrolRequest, facts: &Facts) -> Result<Vec<Membership>, Refusal> {
    let lines: Vec<Vec<&[u8]>> = facts
        .group
        .split(|byte| *byte == b'\n')
        .map(|line| line.split(|byte| *byte == b':').collect())
        .collect();
    let mut out = Vec::new();
    for group in AGENT_GROUPS {
        let found: Vec<&Vec<&[u8]>> = lines
            .iter()
            .filter(|fields| fields.first() == Some(&group.as_bytes()))
            .collect();
        for gid in found
            .iter()
            .filter_map(|fields| fields.get(2).and_then(|gid| number(gid)))
        {
            let alias = if gid == 0 {
                Some("root")
            } else {
                lines.iter().find_map(|line| {
                    let [name, _, other, ..] = line.as_slice() else {
                        return None;
                    };
                    let same = number(other) == Some(gid);
                    ROOT_EQUIVALENT_GROUPS
                        .iter()
                        .find(|bad| same && bad.as_bytes() == *name)
                        .copied()
                })
            };
            if let Some(alias) = alias {
                return Err(Refusal::AgentGroupIsRoot {
                    group: group.to_owned(),
                    gid,
                    alias: alias.to_owned(),
                });
            }
        }
        out.push(Membership {
            group: group.to_owned(),
            create: found.is_empty(),
            join: !is_member(&facts.passwd, &facts.group, &request.account, group),
        });
    }
    Ok(out)
}

/// The groups a registry file says `enrol` added its account to: only the
/// agent groups, whatever else the line says.
#[must_use]
pub fn joined_groups(registry: &str) -> Vec<String> {
    registry
        .lines()
        .filter_map(|line| line.strip_prefix(JOINED_MARKER))
        .flat_map(str::split_whitespace)
        .filter(|name| AGENT_GROUPS.contains(name))
        .map(str::to_owned)
        .collect()
}

/// Whether `account` is listed in `group`, or has it as its primary group.
#[must_use]
pub fn is_member(passwd: &[u8], group_file: &[u8], account: &str, group: &str) -> bool {
    let primary = parse_passwd(passwd)
        .iter()
        .find(|entry| entry.name == account.as_bytes())
        .map(|entry| entry.gid);
    is_listed(group_file, account, group)
        || group_file.split(|byte| *byte == b'\n').any(|line| {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
            matches!(
                fields.as_slice(),
                [name, _, gid, ..]
                    if *name == group.as_bytes()
                        && primary.is_some_and(|primary| number(gid) == Some(primary))
            )
        })
}

/// Whether `/etc/group` lists `account` among the members of `group`. A
/// primary group is not a listing: `gpasswd --delete` cannot remove it.
#[must_use]
pub fn is_listed(group_file: &[u8], account: &str, group: &str) -> bool {
    group_file.split(|byte| *byte == b'\n').any(|line| {
        let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
        matches!(
            fields.as_slice(),
            [name, _, _, members, ..]
                if *name == group.as_bytes()
                    && members
                        .split(|byte| *byte == b',')
                        .any(|member| member == account.as_bytes())
        )
    })
}

fn check_request(request: &EnrolRequest) -> Result<String, Refusal> {
    if !valid_harness_label(&request.label) {
        return Err(Refusal::BadLabel(request.label.clone()));
    }
    if !valid_account_name(&request.account) {
        return Err(Refusal::BadAccount(request.account.clone()));
    }
    if request.reviewers.is_empty() {
        return Err(Refusal::NoReviewer);
    }
    if let Some(bad) = request
        .reviewers
        .iter()
        .find(|name| !valid_account_name(name))
    {
        return Err(Refusal::BadReviewer(bad.clone()));
    }
    exec_start(&request.argv)
}

fn check_account(request: &EnrolRequest, facts: &Facts) -> Result<(), Refusal> {
    let account = request.account.as_str();
    let entries = parse_passwd(&facts.passwd);
    let uid = check_standing(
        account,
        &facts.passwd,
        facts.shadow.as_deref(),
        &facts.group,
    )?;
    if facts.scan.uid != uid {
        return Err(Refusal::AccountChanged(account.to_owned()));
    }
    if !facts.scan.blockers.is_empty() {
        return Err(Refusal::OtherPathToRoot {
            account: account.to_owned(),
            blockers: facts.scan.blockers.join("; "),
        });
    }
    if request.reviewers.iter().any(|name| name == account) {
        return Err(Refusal::ReviewerIsAccount(account.to_owned()));
    }
    for reviewer in &request.reviewers {
        if !entries.iter().any(|e| e.name == reviewer.as_bytes()) {
            return Err(Refusal::ReviewerUnknown(reviewer.clone()));
        }
    }
    Ok(())
}

/// What must hold of an account at enrolment and for as long as it is
/// enrolled: it exists once, is not root, has no password and holds no group
/// that is root by another name. Returns its uid.
fn check_standing(
    account: &str,
    passwd: &[u8],
    shadow: Option<&[u8]>,
    group: &[u8],
) -> Result<u32, Refusal> {
    let entries = parse_passwd(passwd);
    let mut named = entries
        .iter()
        .filter(|entry| entry.name == account.as_bytes());
    let Some(entry) = named.next() else {
        return Err(Refusal::AccountUnknown(account.to_owned()));
    };
    if named.next().is_some() || entries.iter().filter(|e| e.uid == entry.uid).count() > 1 {
        return Err(Refusal::AccountAmbiguous(account.to_owned()));
    }
    if entry.uid == 0 || entry.gid == 0 {
        return Err(Refusal::AccountIsRoot(account.to_owned()));
    }
    check_password(account, entry, shadow)?;
    check_groups(account, entry.gid, group)?;
    Ok(entry.uid)
}

/// Whether the field locks the account: `!` or `*` first. An empty field is a
/// login with no password at all.
fn locked(field: &[u8]) -> bool {
    matches!(field.first(), Some(b'!' | b'*'))
}

fn check_password(account: &str, entry: &Passwd<'_>, shadow: Option<&[u8]>) -> Result<(), Refusal> {
    let field = if entry.password == b"x" {
        let unknown = || Refusal::PasswordUnknown(account.to_owned());
        let shadow = shadow.ok_or_else(unknown)?;
        shadow
            .split(|byte| *byte == b'\n')
            .find_map(|line| {
                let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
                match fields.as_slice() {
                    [name, hash, ..] if *name == account.as_bytes() => Some(*hash),
                    _ => None,
                }
            })
            .ok_or_else(unknown)?
    } else {
        entry.password
    };
    if locked(field) {
        Ok(())
    } else {
        Err(Refusal::PasswordUsable(account.to_owned()))
    }
}

fn check_groups(account: &str, primary: u32, group_file: &[u8]) -> Result<(), Refusal> {
    // A group is root-equivalent by its gid, and any name sharing that gid
    // (`dockerish:x:999:agent` beside `docker:x:999:`) is the same group.
    let held = held_gids(account, primary, group_file);
    for line in group_file.split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let (Some(name), Some(_), Some(gid)) = (fields.next(), fields.next(), fields.next()) else {
            continue;
        };
        let bad = ROOT_EQUIVALENT_GROUPS
            .iter()
            .find(|bad| bad.as_bytes() == name);
        if let (Some(bad), Some(gid)) = (bad, number(gid))
            && held.contains(&gid)
        {
            return Err(Refusal::RootGroup {
                account: account.to_owned(),
                group: (*bad).to_owned(),
            });
        }
    }
    Ok(())
}

fn check_registry(request: &EnrolRequest, facts: &Facts) -> Result<(), Refusal> {
    let file = format!("{}.toml", request.label);
    if facts.registry.iter().any(|(name, _)| *name == file) {
        return Err(Refusal::LabelTaken(request.label.clone()));
    }
    let existing = HarnessRegistry::from_files(
        facts
            .registry
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str())),
    )
    .map_err(|error| registry_refusal(&error))?;
    // An account that already runs another harness, or may start its sessions.
    for entry in existing.entries() {
        let same = entry.account.as_deref() == Some(request.account.as_str())
            || entry.users.contains(&request.account);
        if same {
            return Err(Refusal::AccountInUse {
                account: request.account.clone(),
                label: entry.label.clone(),
            });
        }
    }
    Ok(())
}

fn registry_refusal(error: &HarnessError) -> Refusal {
    Refusal::Registry(error.to_string())
}

/// The registry as it would stand: the plan's file read back through the
/// parser the broker and the gate use, beside every file already there. This is
/// what proves the rendered text is the entry that was meant, and that no
/// reviewer is a harness account.
fn check_loads(plan: &EnrolPlan, facts: &Facts) -> Result<(), Refusal> {
    let name = format!("{}.toml", plan.label);
    let mut files: Vec<(&str, &str)> = facts
        .registry
        .iter()
        .map(|(name, text)| (name.as_str(), text.as_str()))
        .collect();
    files.push((&name, &plan.registry.contents));
    HarnessRegistry::from_files(files)
        .map(|_| ())
        .map_err(|error| registry_refusal(&error))
}

/// What a standing check found about one enrolled account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountReport {
    /// The label.
    pub label: String,
    /// The account.
    pub account: String,
    /// Each way to root the account now has, or each way its unit could run as
    /// someone else. Empty is clean.
    pub problems: Vec<String>,
    /// What could not be examined from here (the shadow file as a non-root user).
    pub unverified: Vec<String>,
}

/// Re-runs the account checks `enrol` ran, for every registry entry that is an
/// agent unit: password, root-equivalent groups, other paths to root, the
/// drop-in directory and the `User=` it sets. An account that was clean when
/// enrolled and has since gained a way to root is reported here.
///
/// # Errors
///
/// A description of why the registry could not be read or does not load.
pub fn recheck_accounts(
    host: &dyn HostView,
    input: &Input<'_>,
    managed: Option<&str>,
) -> Result<Vec<AccountReport>, String> {
    let names = match host.list(Path::new(REGISTRY_DIR)) {
        Lookup::Found(names) => names,
        Lookup::Missing => return Ok(Vec::new()),
        Lookup::Unreadable(why) => return Err(format!("{REGISTRY_DIR} cannot be read: {why}")),
    };
    let mut files = Vec::new();
    for name in names {
        let Some(file) = name
            .to_str()
            .filter(|n| Path::new(n).extension().is_some_and(|ext| ext == "toml"))
        else {
            continue;
        };
        let path = Path::new(REGISTRY_DIR).join(file);
        match host.read(&path) {
            Lookup::Found(bytes) => match String::from_utf8(bytes) {
                Ok(text) => files.push((file.to_owned(), text)),
                Err(_) => return Err(format!("{} is not UTF-8 text", path.display())),
            },
            Lookup::Missing => {}
            Lookup::Unreadable(why) => {
                return Err(format!("{} cannot be read: {why}", path.display()));
            }
        }
    }
    let agents = listed(&files).map_err(|refusal| refusal.to_string())?;
    let read = |path: &str| match host.read(Path::new(path)) {
        Lookup::Found(bytes) => Some(bytes),
        _ => None,
    };
    let (passwd, shadow, group) = (read("/etc/passwd"), read("/etc/shadow"), read("/etc/group"));
    Ok(agents
        .into_iter()
        .map(|agent| {
            let mut report = AccountReport {
                label: agent.label.clone(),
                account: agent.account.clone(),
                problems: Vec::new(),
                unverified: Vec::new(),
            };
            let standing = check_standing(
                &agent.account,
                passwd.as_deref().unwrap_or_default(),
                shadow.as_deref(),
                group.as_deref().unwrap_or_default(),
            );
            match standing {
                Ok(_) => {}
                Err(refusal @ Refusal::PasswordUnknown(_)) => {
                    report.unverified.push(refusal.to_string());
                }
                Err(refusal) => report.problems.push(refusal.to_string()),
            }
            // An account `passwd` cannot name is already in the standing check.
            if let Ok(scan) = scan_account(host, &agent.account, input, managed) {
                report.problems.extend(scan.blockers);
                if scan.doas {
                    report
                        .problems
                        .push(Refusal::AgentPathNeedsSudo.to_string());
                }
            }
            report.problems.extend(drop_in_problems(host, &agent));
            report
        })
        .collect())
}

/// The drop-in directory must hold exactly the one file `enrol` wrote, both
/// root's alone, and that file must run the unit as the registry's account.
fn drop_in_problems(host: &dyn HostView, agent: &Listed) -> Vec<String> {
    let dir = drop_in_dir(&agent.label);
    let mut out = Vec::new();
    let root_alone = |path: &str, out: &mut Vec<String>| match host.stat(Path::new(path)) {
        Lookup::Found(meta) if meta.uid == 0 && meta.mode & 0o022 == 0 => {}
        Lookup::Found(_) => out.push(format!("{path} is not root's alone")),
        Lookup::Missing => out.push(format!("{path} does not exist")),
        Lookup::Unreadable(why) => out.push(format!("could not examine {path}: {why}")),
    };
    root_alone(&dir, &mut out);
    match host.list(Path::new(&dir)) {
        Lookup::Found(names) if names == [std::ffi::OsString::from(DROP_IN_NAME)] => {}
        Lookup::Found(_) => out.push(format!(
            "{dir} holds more than {DROP_IN_NAME}: another file could change who the unit runs as"
        )),
        Lookup::Missing => {}
        Lookup::Unreadable(why) => out.push(format!("could not examine {dir}: {why}")),
    }
    let file = format!("{dir}/{DROP_IN_NAME}");
    root_alone(&file, &mut out);
    if let Lookup::Found(bytes) = host.read(Path::new(&file)) {
        let text = std::str::from_utf8(&bytes).unwrap_or_default();
        out.extend(drop_in_content_problems(&file, text, &agent.account));
    }
    out.extend(other_unit_sources(host, &agent.label));
    out
}

/// systemd's own reading of the drop-in: keys and values are trimmed, `User=`
/// is last-wins, and nothing but `User=` and an `ExecStart=` that keeps the
/// unit's privileges may be set. A key that could change who the unit runs as
/// or what it keeps (another section, `DynamicUser=`, `ExecStart=+`) is a
/// problem, and so is text that is not text at all.
fn drop_in_content_problems(file: &str, text: &str, account: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut user: Option<&str> = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line == "[Service]" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            out.push(format!("{file} has a line xudo did not write: {line:?}"));
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "User" => user = Some(value),
            "ExecStart" if !value.starts_with(['+', '!', ':', '@', '-']) => {}
            _ => out.push(format!(
                "{file} sets {key}= beyond User= and a plain ExecStart=: it could change what the unit keeps"
            )),
        }
    }
    // Not text is no `User=` at all, and so a mismatch.
    if user != Some(account) {
        out.push(format!(
            "{file} does not run the unit as {account} alone (User= says {user:?})"
        ));
    }
    out
}

/// Unit files and drop-in directories, besides ours, that systemd would merge
/// into `xudo-agent@<label>.service`: any one could change the user.
fn other_unit_sources(host: &dyn HostView, label: &str) -> Vec<String> {
    const ROOTS: [&str; 11] = [
        "/etc/systemd/system.control",
        "/run/systemd/system.control",
        "/run/systemd/transient",
        "/run/systemd/generator.early",
        "/etc/systemd/system",
        "/run/systemd/system",
        "/run/systemd/generator",
        "/usr/local/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/run/systemd/generator.late",
    ];
    // Where the packaged template itself lives: a template there is ours.
    const PACKAGED: [&str; 2] = ["/usr/lib/systemd/system", "/lib/systemd/system"];
    let unit = unit_name(label);
    let mut out = Vec::new();
    for root in ROOTS {
        let dirs = [
            format!("{unit}.d"),
            "xudo-agent@.service.d".to_owned(),
            "xudo-agent-.service.d".to_owned(),
            "xudo-.service.d".to_owned(),
            "service.d".to_owned(),
        ];
        for dir in dirs {
            let path = format!("{root}/{dir}");
            if path == drop_in_dir(label) {
                continue;
            }
            match host.list(Path::new(&path)) {
                Lookup::Found(names) if names.is_empty() => {}
                Lookup::Found(_) => out.push(format!(
                    "{path} holds drop-ins that could change who the unit runs as"
                )),
                Lookup::Missing => {}
                Lookup::Unreadable(why) => out.push(format!("could not examine {path}: {why}")),
            }
        }
        // A whole unit file by the instance's name replaces the template.
        // So does a template file anywhere but where the package puts it.
        let template = (!PACKAGED.contains(&root)).then(|| format!("{root}/xudo-agent@.service"));
        for file in std::iter::once(format!("{root}/{unit}")).chain(template) {
            if !matches!(host.stat(Path::new(&file)), Lookup::Missing) {
                out.push(format!("{file} would replace the packaged template"));
            }
        }
    }
    out
}

/// One enrolled agent, for `list`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// The label.
    pub label: String,
    /// The account.
    pub account: String,
    /// The reviewers.
    pub reviewers: Vec<String>,
}

/// The service entries of a registry, for `list`. A session entry is not an
/// agent unit and is skipped.
///
/// # Errors
///
/// [`Refusal::Registry`] when the registry does not load.
pub fn listed(files: &[(String, String)]) -> Result<Vec<Listed>, Refusal> {
    let registry = HarnessRegistry::from_files(
        files
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str())),
    )
    .map_err(|error| registry_refusal(&error))?;
    Ok(registry
        .entries()
        .filter_map(|entry| {
            Some(Listed {
                label: entry.label.clone(),
                account: entry.account.clone()?,
                reviewers: entry.reviewers.clone(),
            })
        })
        .collect())
}

mod pam;
#[cfg(test)]
mod tests;
