//! Enrolling, listing and removing a harness, through two seams.
//!
//! `xudo-backend` decides what `enrol` writes ([`xudo_backend::enrol::plan`]).
//! This module gathers what that decision reads, performs the plan, and takes
//! it back. Files are written through [`InstallOps`], so every one begins with
//! xudo's marker, replaces nothing that is not xudo's, and lands by an atomic
//! rename; what [`InstallOps`] cannot do (list a directory, create one, ask
//! systemd) is [`EnrolOps`].
//!
//! Nothing here grants a run. The unit this starts holds a registry entry and
//! an account; the rules still decide, and no rule names the harness.
//!
//! # Order, and what undoes it
//!
//! Environment stub, drop-in, registry entry, then systemd is told. Before the
//! unit is enabled `User=` is asked of systemd itself, because a drop-in
//! elsewhere in its search path could have the last word, and so are the drop-in
//! and unit file paths, which must be exactly ours and the template. Any failure takes
//! back what this run wrote, in reverse. `remove` stops the unit first: the
//! unit's own `ExecStopPost` voids the record (the helper insists that pid 1
//! started it, so `remove` must not run it), and the registry entry is deleted
//! last, so a unit that did not stop is still a registered one.

use xudo_backend::enrol::{
    AGENTS_DIR, AccountScan, DropInState, EnrolPlan, EnrolRequest, Facts, Listed, MANAGED_MARKER,
    Membership, REGISTRY_DIR, Refusal, drop_in_dir, env_path, is_listed, is_member, joined_groups,
    listed, plan, registry_path, unit_name,
};
use xudo_policy::valid_harness_label;

use super::{FileIdentity, InstallError, InstallOps, Removal};

/// Where the package installs the unit template.
const TEMPLATE_PATH: &str = "/usr/lib/systemd/system/xudo-agent@.service";

/// What a `systemctl` run said.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Systemctl {
    /// Exit status zero.
    pub success: bool,
    /// Standard output, trimmed.
    pub stdout: String,
}

/// What enrolment needs beyond [`InstallOps`].
pub trait EnrolOps {
    /// A root-owned file's contents, read through a verified descriptor; `None`
    /// when it does not exist.
    ///
    /// # Errors
    ///
    /// A file that is not root's, is writable by others, or is too large.
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, InstallError>;

    /// Succeeds only for an existing regular file that is root's, not a link,
    /// and has no group or other permission bit. An absent file is `Ok`.
    ///
    /// # Errors
    ///
    /// A file that is a link, not root's, or open to group or others.
    fn private_file(&self, path: &str) -> Result<(), InstallError>;

    /// The names in a directory the walk from `/` finds root's alone; `None`
    /// when it does not exist.
    ///
    /// # Errors
    ///
    /// A directory, or an ancestor, anyone else could change.
    fn list_dir(&self, path: &str) -> Result<Option<Vec<String>>, InstallError>;

    /// Creates a directory in a root-owned parent, or accepts one that is
    /// already root's alone. `true` when this call created it.
    ///
    /// # Errors
    ///
    /// An existing directory that is not root's alone, or a refused call.
    fn make_dir(&self, path: &str, mode: u32) -> Result<bool, InstallError>;

    /// Removes an empty directory.
    ///
    /// # Errors
    ///
    /// A directory that is not empty, or a refused call.
    fn remove_dir(&self, path: &str) -> Result<Removal, InstallError>;

    /// Adds `account` to the existing group `group` and changes nothing else
    /// about the group. The caller has checked it is not a member yet.
    ///
    /// # Errors
    ///
    /// When the tool could not be run or refused.
    fn add_member(&self, group: &str, account: &str) -> Result<(), InstallError>;

    /// Removes `account` from `group` and changes nothing else about the group.
    /// The caller has checked it is a listed member.
    ///
    /// # Errors
    ///
    /// When the tool could not be run or refused.
    fn remove_member(&self, group: &str, account: &str) -> Result<(), InstallError>;

    /// Runs `/usr/bin/systemctl` with `args`.
    ///
    /// # Errors
    ///
    /// When it could not be run at all. A non-zero exit is an answer.
    fn systemctl(&self, args: &[&str]) -> Result<Systemctl, InstallError>;
}

/// Why `agent` stopped.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AgentError {
    /// Not root.
    #[error("this needs root (effective uid {uid}); nothing was changed")]
    NotRoot {
        /// The effective uid.
        uid: u32,
    },
    /// `enrol` refused the request.
    #[error("{0}")]
    Refused(#[from] Refusal),
    /// A file, directory or process step failed.
    #[error("{0}")]
    Install(#[from] InstallError),
    /// A registry file is not UTF-8.
    #[error("{0} is not UTF-8 text")]
    NotText(String),
    /// systemd would load the unit from more than our drop-in and the template.
    #[error(
        "systemd would build {unit} from drop-ins {drop_ins:?} and unit file {fragment:?}, not \
         only our drop-in and the packaged template: another file could change what runs; \
         nothing was left in place"
    )]
    UnitSources {
        /// The unit.
        unit: String,
        /// What `DropInPaths` said.
        drop_ins: String,
        /// What `FragmentPath` said.
        fragment: String,
    },
    /// systemd would run the unit as someone else.
    #[error(
        "systemd would run {unit} as {found:?}, not {expected}: another drop-in or unit file \
         has the last word on User=; nothing was left in place"
    )]
    UserMismatch {
        /// The unit.
        unit: String,
        /// The registry account.
        expected: String,
        /// What `systemctl show` said.
        found: String,
    },
    /// The account joined a group by other means between the plan and the join.
    #[error(
        "{account} is already in group {group}, though the plan said enrol would add it: \
         the registry would claim a membership that is not enrol's; nothing was left in place"
    )]
    MembershipChanged {
        /// The group.
        group: String,
        /// The account.
        account: String,
    },
    /// A systemctl call failed.
    #[error("systemctl {args} failed: {detail}")]
    Unit {
        /// The arguments.
        args: String,
        /// What it said.
        detail: String,
    },
    /// `remove` named a label that is not an enrolled agent.
    #[error("{0} is not an enrolled agent")]
    NotEnrolled(String),
    /// The unit would not stop, so the registry entry stays.
    #[error("{0} is still running after stop: the registry entry was kept")]
    StillRunning(String),
}

/// One row of `xudo agent list`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRow {
    /// The entry.
    pub agent: Listed,
    /// What `systemctl is-active` said.
    pub state: String,
}

fn require_root(ops: &dyn InstallOps) -> Result<(), AgentError> {
    match ops.effective_uid() {
        0 => Ok(()),
        uid => Err(AgentError::NotRoot { uid }),
    }
}

fn text(path: &str, bytes: Vec<u8>) -> Result<String, AgentError> {
    String::from_utf8(bytes).map_err(|_| AgentError::NotText(path.to_owned()))
}

/// One registry file as text; nothing for a name listed and gone before the read.
fn registry_file(
    host: &dyn EnrolOps,
    name: String,
) -> Result<Option<(String, String)>, AgentError> {
    let path = format!("{REGISTRY_DIR}/{name}");
    host.read_file(&path)?
        .map(|bytes| text(&path, bytes).map(|text| (name, text)))
        .transpose()
}

fn registry_files(host: &dyn EnrolOps) -> Result<Vec<(String, String)>, AgentError> {
    let names = host.list_dir(REGISTRY_DIR)?.unwrap_or_default();
    let mut files = Vec::new();
    for name in names
        .into_iter()
        .filter(|name| name.strip_suffix(".toml").is_some())
    {
        files.extend(registry_file(host, name)?);
    }
    Ok(files)
}

/// Reads what `enrol` decides from, and decides.
///
/// `scan` is the other-paths-to-root report on the account, which the caller
/// ran against the live host.
///
/// # Errors
///
/// [`AgentError::Refused`], or whatever stopped a read.
pub fn plan_enrol(
    request: &EnrolRequest,
    scan: AccountScan,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
) -> Result<EnrolPlan, AgentError> {
    require_root(ops)?;
    let read = |path: &str| host.read_file(path).map(Option::unwrap_or_default);
    // Unreadable is "unknown", which `plan` turns into a refusal.
    let shadow = host.read_file("/etc/shadow").ok().flatten();
    let drop_in = match host.list_dir(&drop_in_dir(&request.label)) {
        Ok(None) => DropInState::Absent,
        Ok(Some(names)) if names.is_empty() => DropInState::Empty,
        Ok(Some(_)) => DropInState::Occupied,
        Err(error) => DropInState::Untrusted(error.to_string()),
    };
    let env_name = format!("{}.env", request.label);
    let env_present = host
        .list_dir(AGENTS_DIR)?
        .is_some_and(|names| names.contains(&env_name));
    if env_present {
        // The record helper refuses this file at start; refuse here, before
        // anything is written, when it would.
        host.private_file(&env_path(&request.label))?;
    }
    let facts = Facts {
        passwd: read("/etc/passwd")?,
        shadow,
        group: read("/etc/group")?,
        registry: registry_files(host)?,
        drop_in,
        env_present,
        scan,
    };
    Ok(plan(request, &facts)?)
}

/// What this run created, for taking it back.
#[derive(Default)]
struct Made {
    files: Vec<String>,
    dirs: Vec<String>,
    /// Memberships this run added: group and account. Groups this run created
    /// stay, empty: nothing in one grants anything.
    joined: Vec<(String, String)>,
}

impl Made {
    fn undo(&self, ops: &dyn InstallOps, host: &dyn EnrolOps) {
        // Best effort, newest first: this runs because something already
        // failed, and the first error is the one worth reporting.
        for path in self.files.iter().rev() {
            let _ = ops.remove_managed(path);
        }
        for path in self.dirs.iter().rev() {
            let _ = host.remove_dir(path);
        }
        for (group, account) in self.joined.iter().rev() {
            let _ = host.remove_member(group, account);
        }
        let _ = host.systemctl(&["daemon-reload"]);
    }
}

fn put(
    ops: &dyn InstallOps,
    path: &str,
    contents: &str,
    mode: u32,
    ledger: &mut Made,
) -> Result<(), InstallError> {
    let candidate = format!("{path}.candidate");
    let identity: FileIdentity = ops.write_candidate(&candidate, contents.as_bytes(), mode)?;
    if let Err(error) = ops.install(&candidate, path, identity) {
        let _ = ops.discard(&candidate, identity);
        return Err(error);
    }
    ledger.files.push(path.to_owned());
    Ok(())
}

fn systemctl_ok(host: &dyn EnrolOps, args: &[&str]) -> Result<Systemctl, AgentError> {
    let answer = host.systemctl(args)?;
    if answer.success {
        Ok(answer)
    } else {
        Err(AgentError::Unit {
            args: args.join(" "),
            detail: answer.stdout,
        })
    }
}

fn perform(
    plan: &EnrolPlan,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
    made: &mut Made,
) -> Result<(), AgentError> {
    for (dir, mode) in [(REGISTRY_DIR, 0o755), (AGENTS_DIR, 0o700)] {
        if host.make_dir(dir, mode)? {
            made.dirs.push(dir.to_owned());
        }
    }
    if host.make_dir(&plan.drop_in_dir, 0o755)? {
        made.dirs.push(plan.drop_in_dir.clone());
    }
    if !plan.env.keep {
        put(ops, &plan.env.path, &plan.env.contents, plan.env.mode, made)?;
    }
    put(
        ops,
        &plan.drop_in.path,
        &plan.drop_in.contents,
        plan.drop_in.mode,
        made,
    )?;
    put(
        ops,
        &plan.registry.path,
        &plan.registry.contents,
        plan.registry.mode,
        made,
    )?;
    systemctl_ok(host, &["daemon-reload"])?;
    let user = systemctl_ok(
        host,
        &["show", "--property=User", "--value", plan.unit.as_str()],
    )?;
    if user.stdout != plan.account {
        return Err(AgentError::UserMismatch {
            unit: plan.unit.clone(),
            expected: plan.account.clone(),
            found: user.stdout,
        });
    }
    // A drop-in or unit file anywhere else in systemd's search path could add
    // groups, capabilities or an `ExecStartPost=+` while `User=` still reads
    // right. Only our drop-in and the packaged template may be in play.
    let drop_ins = systemctl_ok(
        host,
        &[
            "show",
            "--property=DropInPaths",
            "--value",
            plan.unit.as_str(),
        ],
    )?;
    let fragment = systemctl_ok(
        host,
        &[
            "show",
            "--property=FragmentPath",
            "--value",
            plan.unit.as_str(),
        ],
    )?;
    if drop_ins.stdout != plan.drop_in.path || fragment.stdout != TEMPLATE_PATH {
        return Err(AgentError::UnitSources {
            unit: plan.unit.clone(),
            drop_ins: drop_ins.stdout,
            fragment: fragment.stdout,
        });
    }
    // The last write, before the unit starts so it starts holding its groups.
    // Nothing above checked a group: the groups carry no rule of their own.
    join_groups(plan, ops, host, made)?;
    systemctl_ok(host, &["enable", "--now", plan.unit.as_str()])?;
    Ok(())
}

/// Creates the agent groups that are missing and adds the account to the
/// ones it is not in. A group that exists keeps its definition: only a member
/// is added, and only if `/etc/group` does not already list it.
fn join_groups(
    plan: &EnrolPlan,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
    made: &mut Made,
) -> Result<(), AgentError> {
    for Membership {
        group,
        create,
        join,
    } in &plan.memberships
    {
        // The plan was made earlier; the machine may have moved on.
        if *create && !ops.group_exists(group)? {
            ops.create_group(group)?;
        }
        if *join {
            let file = host.read_file("/etc/group")?.unwrap_or_default();
            let passwd = host.read_file("/etc/passwd")?.unwrap_or_default();
            // The registry already says enrol made this membership. If the
            // account got it some other way since the plan, `remove` would
            // later take away what is not ours: refuse, and roll back.
            if is_member(&passwd, &file, &plan.account, group) {
                return Err(AgentError::MembershipChanged {
                    group: group.clone(),
                    account: plan.account.clone(),
                });
            }
            host.add_member(group, &plan.account)?;
            made.joined.push((group.clone(), plan.account.clone()));
        }
    }
    Ok(())
}

/// Writes the plan and starts the unit; on any failure, takes it back.
///
/// # Errors
///
/// What stopped it. The files and directories this run created are removed
/// first, and a unit that was enabled is disabled again.
pub fn apply_enrol(
    plan: &EnrolPlan,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
) -> Result<(), AgentError> {
    require_root(ops)?;
    let mut made = Made::default();
    perform(plan, ops, host, &mut made).inspect_err(|_| {
        let _ = host.systemctl(&["disable", "--now", plan.unit.as_str()]);
        made.undo(ops, host);
    })
}

/// The enrolled agents and whether each unit is running.
///
/// # Errors
///
/// [`AgentError::Refused`] for a registry that does not load, or a failed read.
pub fn list_agents(host: &dyn EnrolOps) -> Result<Vec<AgentRow>, AgentError> {
    let files = registry_files(host)?;
    let mut rows = Vec::new();
    for agent in listed(&files)? {
        let unit = unit_name(&agent.label);
        let state = host.systemctl(&["is-active", unit.as_str()])?.stdout;
        rows.push(AgentRow { agent, state });
    }
    Ok(rows)
}

/// Stops an enrolled agent and takes its files away.
///
/// The record is not voided here: `xudo-session void` insists that pid 1 started
/// it, and the unit's `ExecStopPost` is what does. The environment file stays,
/// because an operator wrote credentials in it.
///
/// # Errors
///
/// [`AgentError::NotEnrolled`] for a label with no registry file of xudo's;
/// [`AgentError::StillRunning`] for a unit that did not stop, in which case
/// nothing is removed.
pub fn remove_agent(
    label: &str,
    ops: &dyn InstallOps,
    host: &dyn EnrolOps,
) -> Result<Vec<String>, AgentError> {
    require_root(ops)?;
    let not_enrolled = || AgentError::NotEnrolled(label.to_owned());
    if !valid_harness_label(label) {
        return Err(not_enrolled());
    }
    let registry = registry_path(label);
    let current = host.read_file(&registry)?.ok_or_else(not_enrolled)?;
    // A hand-written entry is the operator's: stopping its unit and then being
    // unable to delete it would leave the worst of both.
    if !current.starts_with(MANAGED_MARKER.as_bytes()) {
        return Err(not_enrolled());
    }
    let unit = unit_name(label);
    let registry_text = text(&registry, current)?;
    let account = listed(&[(format!("{label}.toml"), registry_text.clone())])?
        .into_iter()
        .next()
        .map(|agent| agent.account);
    systemctl_ok(host, &["disable", "--now", unit.as_str()])?;
    // Only a unit that is down: `activating`, `deactivating` and `reloading`
    // are not.
    let state = host.systemctl(&["is-active", unit.as_str()])?.stdout;
    if !matches!(state.as_str(), "inactive" | "failed") {
        return Err(AgentError::StillRunning(unit));
    }
    let mut lines = vec![format!("stopped {unit}")];
    let drop_in = format!(
        "{}/{}",
        drop_in_dir(label),
        xudo_backend::enrol::DROP_IN_NAME
    );
    ops.remove_managed(&drop_in)?;
    host.remove_dir(&drop_in_dir(label))?;
    lines.push(format!("removed {}", drop_in_dir(label)));
    systemctl_ok(host, &["daemon-reload"])?;
    // Only the memberships enrol recorded as its own; a group is never deleted.
    if let Some(account) = account {
        for group in joined_groups(&registry_text) {
            let file = host.read_file("/etc/group")?.unwrap_or_default();
            if is_listed(&file, &account, &group) {
                host.remove_member(&group, &account)?;
                lines.push(format!("removed {account} from group {group}"));
            }
        }
    }
    // Last: until this, the entry that attests the harness is still there.
    ops.remove_managed(&registry)?;
    lines.push(format!("removed {registry}"));
    lines.push(format!(
        "kept {} (it may hold credentials)",
        env_path(label)
    ));
    Ok(lines)
}

#[cfg(test)]
mod tests;
