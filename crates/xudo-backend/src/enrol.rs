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
    Applies, Caller, Check, CheckId, Finding, HostView, Input, Lookup, Meta, assess,
};

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

/// The three files, and the unit they configure.
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
struct Passwd<'a> {
    name: &'a [u8],
    password: &'a [u8],
    uid: u32,
    gid: u32,
}

fn parse_passwd(bytes: &[u8]) -> Vec<Passwd<'_>> {
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

fn number(bytes: &[u8]) -> Option<u32> {
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
/// # Errors
///
/// [`Refusal::AccountUnknown`] and [`Refusal::AccountAmbiguous`], when
/// `/etc/passwd` cannot say who the account is.
pub fn scan_account(
    host: &dyn HostView,
    name: &str,
    input: &Input<'_>,
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
    let as_account = AsAccount {
        inner: host,
        uid: entry.uid,
        gid: entry.gid,
    };
    let report = assess(&as_account, input);
    let blockers = report
        .checks
        .iter()
        .filter(|check| check.check == CheckId::PasswordlessRules)
        .flat_map(blockers_of)
        .collect();
    Ok(AccountScan {
        uid: entry.uid,
        blockers,
    })
}

fn blockers_of(check: &Check) -> Vec<String> {
    // A rule that names only others is a finding of the report and not of this
    // account's.
    let others = |finding: &&Finding| {
        matches!(
            finding,
            Finding::PasswordlessRule {
                applies_to_you: Applies::No,
                ..
            }
        )
    };
    let mut lines: Vec<String> = check
        .findings
        .iter()
        .filter(|finding| !others(finding))
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

/// The host, answering as another account.
struct AsAccount<'a> {
    inner: &'a dyn HostView,
    uid: u32,
    gid: u32,
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
        self.inner.read(path)
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
    let exec = check_request(request)?;
    check_account(request, facts)?;
    check_registry(request, facts)?;
    match &facts.drop_in {
        DropInState::Absent | DropInState::Empty => {}
        DropInState::Occupied => return Err(Refusal::DropInOccupied(request.label.clone())),
        DropInState::Untrusted(reason) => return Err(Refusal::DropInUntrusted(reason.clone())),
    }
    let label = &request.label;
    let registry = format!(
        "{MANAGED_MARKER}\nlabel = \"{label}\"\nway = \"service\"\naccount = \"{}\"\nreviewers = [{}]\nmax-sessions = {MAX_SESSIONS}\n",
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
    };
    check_loads(&plan, facts)?;
    Ok(plan)
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
    if facts.scan.uid != entry.uid {
        return Err(Refusal::AccountChanged(account.to_owned()));
    }
    check_password(account, entry, facts.shadow.as_deref())?;
    check_groups(account, entry.gid, &facts.group)?;
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
    for line in group_file.split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let (Some(name), Some(_), Some(gid), Some(members)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let held = number(gid) == Some(primary)
            || members
                .split(|byte| *byte == b',')
                .any(|member| member == account.as_bytes());
        if held
            && ROOT_EQUIVALENT_GROUPS
                .iter()
                .any(|bad| bad.as_bytes() == name)
        {
            return Err(Refusal::RootGroup {
                account: account.to_owned(),
                group: String::from_utf8_lossy(name).into_owned(),
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

#[cfg(test)]
mod tests;
