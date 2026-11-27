//! Executing the install plan.
//!
//! `xudo-backend` decides what to write and in what order and never touches a
//! file. This module is the other half: it takes that plan and performs it,
//! through [`InstallOps`], so that every ordering rule and every failure path
//! is driven against a fake and measured, and only the file operations
//! themselves ([`HostInstallOps`]) need a real directory.
//!
//! # What the executor refuses on its own
//!
//! The plan is data, and an executor that does whatever a plan says is a root
//! write primitive for whoever can build one. So before any step runs:
//!
//! * **Root only.** An effective uid other than 0 is refused first, before the
//!   plan is even read.
//! * **Only files xudo writes.** Every path a step names must be one of the six
//!   xudo's snippets install to (the sysctl drop-in of `--raise-ptrace-scope`
//!   among them), or the candidate beside one. `/etc/sudoers`,
//!   `/etc/passwd`, and anything else are refused, so the executor cannot touch
//!   a file it did not write however the plan was assembled.
//! * **No name sudo ignores.** A drop-in whose name contains a dot or ends in
//!   `~` is silently skipped by sudo, so an install onto one would report
//!   success and grant nothing. Refused before it can happen.
//! * **No writable modes.** A file xudo installs is `0440` or `0400`; a mode
//!   with any write bit, or any access for others, is refused.
//! * **One validator, one candidate.** A validator that never names the
//!   candidate checks nothing, so its argv must contain `{candidate}` exactly
//!   once and start with an absolute path.
//!
//! and while it runs:
//!
//! * **The passwordless helper refuses first.** A `RefusalProbe` that does not
//!   show the helper refusing a caller it cannot attest stops the run. The
//!   agent-path plan puts it first, so nothing has been written.
//! * **An edited file is left alone.** A `RefuseEdited` step reads the file and
//!   stops when it holds an edit (`xudo_backend::plan::edited`). A
//!   `RemoveUnlessEdited` step leaves such a file in place with a warning
//!   instead, so an uninstall still removes the passwordless line.
//! * **All or nothing, once a plan checks the whole configuration.** A plan
//!   with a `ValidateWhole` step records what each file it installs replaced.
//!   Any failure after an install restores those files: the whole-config check
//!   failing, a listing check (`MustList`, `MustNotList`) that fails or
//!   cannot run, or a functional probe that ran and failed. Only a functional
//!   probe that cannot run is reported as such and restores nothing. A file
//!   whose earlier bytes cannot be put back is removed instead, so the line
//!   just shown wrong never stays.
//!
//! * **Validate before install, structurally.** An `Install` step is refused
//!   unless the candidate it names was written by this run and validated by
//!   this run, in that order, and the inode that was validated is the inode
//!   that was written.
//! * **On any failure the candidate is removed** (only if it is still the inode
//!   this run created) and the previous file is never touched: the rename is
//!   the last act, and it is atomic.
//!
//! # What "installed" does and does not mean
//!
//! The plan's last real step is a functional probe: run the gate through the
//! backend and see it print `0`. [`InstallProbe`] is the seam; `xudo` supplies
//! the real one, because minting the request the gate waits for needs the
//! broker client. A probe that cannot run leaves the install
//! [`Verification::Unverified`] with the reason, never "verified". A file in
//! `/etc/sudoers.d` proves nothing: `sudo-rs` ignores directives it does not
//! support, and `sudo` ignores a badly named file entirely. So [`HostInstaller`]
//! also asks the backend ([`check_effect`]) and will not call an install
//! verified when the backend does not list the gate.

mod effect;
mod enrol;
#[cfg(test)]
mod fake;
mod host;
mod pack;

use xudo_backend::enrol::{AccountScan, EnrolPlan, EnrolRequest};
use xudo_backend::snippet::{
    DOAS_BEGIN, DOAS_CONF_PATH, DOAS_DROP_IN_PATH, DOAS_END, PTRACE_DROP_IN_PATH, SUDOERS_PATH,
    XUDO_AGENT_GROUP, XUDO_GROUP,
};
use xudo_backend::{BackendKind, InstallPlan, PlanStep};

pub use effect::{Effect, check_effect};
pub use enrol::{
    AgentError, AgentRow, EnrolOps, Systemctl, apply_enrol, list_agents, plan_enrol, remove_agent,
};
pub use host::HostInstallOps;
pub use pack::{
    HostWhereabouts, MAX_PACK_BYTES, PackError, PackFileError, PackReport, PackRequest, RULES_DIR,
    Whereabouts, add_pack, read_pack_file, remove_pack,
};
pub use xudo_backend::blocks::BlockError;

use crate::exec::{HostRunner, Runner};
use crate::trust::TrustError;

/// The token in a validator's argv that stands for the candidate's path.
pub const CANDIDATE_PLACEHOLDER: &str = "{candidate}";

/// A file, named by the inode it is rather than the path it was found at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    /// The device.
    pub device: u64,
    /// The inode.
    pub inode: u64,
}

/// What removing something found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// xudo's file or block was there and is gone.
    Removed,
    /// Nothing of xudo's was there. A second uninstall succeeds.
    Absent,
}

/// Why an install or removal stopped. Every variant is a reason nothing further
/// was done.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InstallError {
    /// The caller is not root.
    #[error("installing requires root (effective uid {uid}); nothing was changed")]
    NotRoot {
        /// The effective uid.
        uid: u32,
    },
    /// A step names a file xudo does not write.
    #[error("{path} is not a file xudo writes; refusing to touch it")]
    PathNotManaged {
        /// The path.
        path: String,
    },
    /// A step names a group other than xudo's.
    #[error(
        "refusing to create group {name}: xudo manages only the groups {XUDO_GROUP} and \
         {XUDO_AGENT_GROUP}"
    )]
    GroupNotManaged {
        /// The group.
        name: String,
    },
    /// A file mode that is writable or open to others.
    #[error("refusing mode {mode:04o} for {path}: an installed file must be 0440 or 0400")]
    UnsafeMode {
        /// The file.
        path: String,
        /// The mode.
        mode: u32,
    },
    /// A destination name that sudo would silently skip.
    #[error(
        "refusing to install onto {path}: sudo ignores a drop-in whose name contains a dot or \
         ends in `~`, so the install would report success and grant nothing"
    )]
    NameSudoIgnores {
        /// The destination.
        path: String,
    },
    /// A move between two directories, which is not atomic.
    #[error(
        "refusing to move {from} to {to}: they are in different directories, so the rename is not atomic"
    )]
    CrossDirectory {
        /// The candidate.
        from: String,
        /// The destination.
        to: String,
    },
    /// A validator that cannot validate the candidate.
    #[error("refusing the validator {argv:?}: {reason}")]
    BadValidator {
        /// The argv.
        argv: Vec<String>,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A plan that names markers other than xudo's.
    #[error("refusing to edit a shared file between markers xudo did not write")]
    ForeignMarkers,
    /// Steps in an order that would skip a check.
    #[error("step out of order: {reason}")]
    OutOfOrder {
        /// What was attempted.
        reason: &'static str,
    },
    /// The backend's validator rejected the candidate.
    #[error("the backend rejected the candidate and nothing was installed: {detail}")]
    ValidatorRejected {
        /// What the validator said.
        detail: String,
    },
    /// The backend cannot validate a named file, so there is no honest check.
    #[error("{reason}; there is no way to validate the candidate, so nothing was installed")]
    ValidationUnavailable {
        /// Why.
        reason: String,
    },
    /// The candidate is not the inode this run wrote.
    #[error(
        "{path} is no longer the file this run wrote and was left in place; refusing to install \
         or remove a file xudo did not write"
    )]
    CandidateReplaced {
        /// The path.
        path: String,
    },
    /// An existing file at a destination is not one xudo wrote.
    #[error(
        "{path} exists and is not a file xudo wrote: {reason}; refusing to replace or remove it"
    )]
    NotOurs {
        /// The path.
        path: String,
        /// How it was told apart.
        reason: String,
    },
    /// A candidate name is already taken by something this run cannot show is a
    /// leftover of an earlier, interrupted xudo run.
    #[error(
        "{path} already exists and is not a leftover of an interrupted xudo run: {reason}; \
         nothing was removed. Inspect it, remove it by hand if it is not wanted, and run the \
         command again"
    )]
    StaleCandidate {
        /// The path.
        path: String,
        /// Why it is not xudo's.
        reason: String,
    },
    /// A shared file does not exist where xudo must edit it.
    #[error("{path} does not exist; xudo edits a shared file and never creates one")]
    Missing {
        /// The path.
        path: String,
    },
    /// A shared file is not one xudo may edit.
    #[error("refusing to edit {path}: {reason}")]
    UnsafeFile {
        /// The path.
        path: String,
        /// Why.
        reason: String,
    },
    /// A shared file's lock was not obtained.
    #[error("could not lock {path}: {reason}")]
    Locked {
        /// The path.
        path: String,
        /// Why.
        reason: String,
    },
    /// A shared file's sentinels cannot be read unambiguously.
    #[error("{path}: {source}")]
    Block {
        /// The path.
        path: String,
        /// What was wrong.
        source: BlockError,
    },
    /// A directory on the way to a file could not be trusted.
    #[error("{0}")]
    Untrusted(TrustError),
    /// The group could not be looked up or created.
    #[error("group {name}: {reason}")]
    Group {
        /// The group.
        name: String,
        /// Why.
        reason: String,
    },
    /// A system call refused.
    #[error("{operation} {path}: {reason}")]
    Io {
        /// What was attempted.
        operation: &'static str,
        /// The path.
        path: String,
        /// The operating system's account.
        reason: String,
    },
    /// An install that failed and then could not clean up after itself.
    #[error("{cause}; and then {path} could not be removed: {reason}")]
    LeftBehind {
        /// The file still on disk.
        path: String,
        /// Why it could not be removed.
        reason: String,
        /// The failure that started it.
        cause: Box<InstallError>,
    },
    /// This context has no installer.
    #[error("this context cannot modify the machine; nothing was changed")]
    NoInstaller,
    /// The passwordless helper was not shown to refuse an unattested caller.
    #[error(
        "the passwordless helper was not shown to refuse a caller it cannot attest: {reason}; \
         nothing was written"
    )]
    HelperDidNotRefuse {
        /// What the probe saw.
        reason: String,
    },
    /// A file xudo would replace or remove holds an edit.
    #[error("{path} was left as it is: {reason}")]
    Edited {
        /// The file.
        path: String,
        /// How it was told apart.
        reason: &'static str,
    },
    /// The backend rejected its whole configuration once xudo's file was in
    /// place, though it accepted the file alone.
    #[error("the backend rejected its whole configuration with xudo's file in place: {detail}")]
    WholeRejected {
        /// What the validator said.
        detail: String,
    },
    /// A post-install check ran and showed the install wrong.
    #[error("a check after the install failed: {reason}")]
    ProbeFailed {
        /// What it saw.
        reason: String,
    },
    /// A failure after an install, with every installed file restored.
    #[error("{cause}; every file this run installed was restored to what it was before")]
    RolledBack {
        /// The failure.
        cause: Box<InstallError>,
    },
    /// A failure after an install, and a file whose earlier bytes could not be
    /// put back, so it was removed: what this run wrote is gone, and so is
    /// what was there before.
    #[error(
        "{cause}; and then {path} could not be restored ({reason}), so it was removed: \
         nothing this run wrote stays. `sudo xudo install` writes it again"
    )]
    RemovedInstead {
        /// The file.
        path: String,
        /// Why the restore failed.
        reason: String,
        /// The failure.
        cause: Box<InstallError>,
    },
    /// A failure after an install, and a file that could be neither restored
    /// nor removed.
    #[error(
        "{cause}; and then {path} could be neither restored nor removed: {reason}. The line \
         this run wrote MAY BE LIVE: remove {path} by hand before relying on sudo"
    )]
    NotRolledBack {
        /// The file.
        path: String,
        /// Why not.
        reason: String,
        /// The failure.
        cause: Box<InstallError>,
    },
    /// A read-back asked to stand in for a parser where one exists.
    #[error(
        "refusing to read back {path} in place of a parser: only the sysctl drop-in has no \
         parser of its own"
    )]
    ReadBackRefused {
        /// The candidate.
        path: String,
    },
}

/// What a functional probe saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    /// The gate ran through the backend and printed `0`.
    Verified,
    /// It ran and did not print `0`. The install stays, reported unverified.
    Failed {
        /// What it saw.
        reason: String,
    },
    /// The check cannot be made on this build.
    Unavailable {
        /// Why.
        reason: String,
    },
}

/// The post-install check: use the integration, do not look at a file.
pub trait InstallProbe {
    /// Runs `argv` and judges the outcome against the plan's expectation.
    fn verify(&self, argv: &[String]) -> ProbeResult;

    /// Runs the passwordless helper through `argv` as a caller it cannot
    /// attest. [`ProbeResult::Verified`] only when it refused and ran nothing.
    /// A probe that cannot run it says so, which stops the install.
    fn refuses(&self, _argv: &[String]) -> ProbeResult {
        ProbeResult::Unavailable {
            reason: "this probe cannot run the passwordless helper".to_owned(),
        }
    }

    /// Asks the backend, through `argv`, whether it lists the passwordless
    /// helper. [`ProbeResult::Verified`] when it does not; [`ProbeResult::Failed`]
    /// when it does; unavailable when it could not be asked.
    fn not_listed(&self, _argv: &[String]) -> ProbeResult {
        ProbeResult::Unavailable {
            reason: "this probe cannot ask the backend".to_owned(),
        }
    }

    /// The control for [`Self::not_listed`]: [`ProbeResult::Verified`] only
    /// when the backend, asked through `argv`, does list the helper.
    fn listed(&self, _argv: &[String]) -> ProbeResult {
        ProbeResult::Unavailable {
            reason: "this probe cannot ask the backend".to_owned(),
        }
    }
}

/// Whether the integration was shown to work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verification {
    /// The functional probe passed.
    Verified,
    /// Files were written and nothing proved they take effect.
    Unverified {
        /// Why not.
        reason: String,
    },
    /// The plan wrote nothing, so there is nothing to verify.
    NotRequired,
}

/// What a plan did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstallReport {
    /// The backend the plan was for.
    pub backend: BackendKind,
    /// One line per step that did something, in order.
    pub events: Vec<String>,
    /// Text the operator must read.
    pub notices: Vec<String>,
    /// Whether the result was shown to work.
    pub verification: Verification,
}

/// The effects an install performs, behind a seam.
///
/// Paths are the absolute strings the plan carries. Every method either does
/// exactly what it says or returns an error having changed nothing it did not
/// create.
pub trait InstallOps {
    /// The effective uid of this process.
    fn effective_uid(&self) -> u32;

    /// Whether the unix group exists.
    ///
    /// # Errors
    ///
    /// When the lookup could not be made.
    fn group_exists(&self, name: &str) -> Result<bool, InstallError>;

    /// Creates the system group, empty.
    ///
    /// # Errors
    ///
    /// When it could not be created.
    fn create_group(&self, name: &str) -> Result<(), InstallError>;

    /// Creates `path` exclusively, writes `contents`, and sets `root:root` and
    /// `mode` on the descriptor. Returns the inode that was written.
    ///
    /// # Errors
    ///
    /// When the file exists, or any step failed; a file this call created is
    /// removed first.
    fn write_candidate(
        &self,
        path: &str,
        contents: &[u8],
        mode: u32,
    ) -> Result<FileIdentity, InstallError>;

    /// Runs a validator whose argv already names the candidate.
    ///
    /// # Errors
    ///
    /// [`InstallError::ValidatorRejected`] when the backend refuses the file.
    fn validate(&self, argv: &[String]) -> Result<(), InstallError>;

    /// The inode currently at `path`, not following a link.
    ///
    /// # Errors
    ///
    /// When it cannot be examined.
    fn identity(&self, path: &str) -> Result<FileIdentity, InstallError>;

    /// Atomically renames the candidate onto `to`, if the candidate is still
    /// `identity` and `to` is absent or a file xudo wrote.
    ///
    /// # Errors
    ///
    /// [`InstallError::CandidateReplaced`], [`InstallError::NotOurs`], or the
    /// system's refusal. Nothing is changed.
    fn install(&self, from: &str, to: &str, identity: FileIdentity) -> Result<(), InstallError>;

    /// Removes `path` if it is still `identity`.
    ///
    /// # Errors
    ///
    /// [`InstallError::CandidateReplaced`] when something else is there now.
    fn discard(&self, path: &str, identity: FileIdentity) -> Result<(), InstallError>;

    /// The whole of a file xudo wrote, checked as [`Self::remove_managed`]
    /// checks it; `None` when nothing is there.
    ///
    /// # Errors
    ///
    /// [`InstallError::NotOurs`] for a file that is anything else.
    fn read_managed(&self, path: &str) -> Result<Option<Vec<u8>>, InstallError>;

    /// Removes a file xudo wrote: a regular, root-owned, singly-linked file
    /// that begins with xudo's marker.
    ///
    /// # Errors
    ///
    /// [`InstallError::NotOurs`] for a file that is anything else.
    fn remove_managed(&self, path: &str) -> Result<Removal, InstallError>;

    /// Under a lock, sets xudo's block in a shared file, validating the whole
    /// result on a temporary copy before it replaces the original. The new file
    /// has the owner, group and permission bits the old one had.
    ///
    /// # Errors
    ///
    /// Anything that stopped it; the shared file is unchanged.
    fn append_block(
        &self,
        path: &str,
        block: &str,
        validator: &[String],
    ) -> Result<(), InstallError>;

    /// Under a lock, removes xudo's block from a shared file and nothing else.
    ///
    /// # Errors
    ///
    /// Anything that stopped it; the shared file is unchanged.
    fn remove_block(&self, path: &str) -> Result<Removal, InstallError>;

    /// Takes the exclusive lock on a directory xudo writes into, waiting a
    /// bounded time, and holds it until the returned value is dropped.
    ///
    /// # Errors
    ///
    /// [`InstallError::Missing`], an untrusted directory, or
    /// [`InstallError::Locked`].
    fn lock_dir(&self, path: &str) -> Result<DirLock, InstallError>;
}

/// A held lock on a directory, released when dropped.
#[derive(Debug, Default)]
pub struct DirLock {
    _fd: Option<std::os::fd::OwnedFd>,
}

/// Something that executes a plan: the seam the front-end holds.
pub trait Installer {
    /// Executes `plan`.
    ///
    /// # Errors
    ///
    /// Whatever stopped it.
    fn run(&self, plan: &InstallPlan) -> Result<InstallReport, InstallError>;

    /// Decides what enrolling `request` would write, reading the machine.
    ///
    /// `scan` is the report of other paths to root on the account.
    ///
    /// # Errors
    ///
    /// A refusal, or whatever stopped a read.
    fn agent_plan(
        &self,
        request: &EnrolRequest,
        scan: AccountScan,
    ) -> Result<EnrolPlan, AgentError>;

    /// Writes an enrolment and starts its unit.
    ///
    /// # Errors
    ///
    /// Whatever stopped it, after what it wrote was taken back.
    fn agent_apply(&self, plan: &EnrolPlan) -> Result<(), AgentError>;

    /// The enrolled agents and their unit state.
    ///
    /// # Errors
    ///
    /// A registry that does not load, or a failed read.
    fn agent_list(&self) -> Result<Vec<AgentRow>, AgentError>;

    /// Stops an enrolled agent and removes what enrolling wrote.
    ///
    /// # Errors
    ///
    /// Whatever stopped it.
    fn agent_remove(&self, label: &str) -> Result<Vec<String>, AgentError>;

    /// Checks a reviewed rule pack again as root and installs it.
    ///
    /// # Errors
    ///
    /// Whatever refused or stopped it; nothing is left changed.
    fn pack_add(&self, request: &PackRequest) -> Result<PackReport, PackError>;

    /// Removes a rule pack `pack_add` installed, when `reviewed` is the token
    /// the operator's review of the removal printed.
    ///
    /// # Errors
    ///
    /// Whatever refused or stopped it; nothing is left changed.
    fn pack_remove(&self, name: &str, reviewed: &str) -> Result<PackReport, PackError>;
}

/// The installer for a real machine: real file operations and the given probe.
#[derive(Clone, Copy)]
pub struct HostInstaller<'a> {
    probe: &'a dyn InstallProbe,
}

impl<'a> HostInstaller<'a> {
    /// An installer that checks its work with `probe`.
    #[must_use]
    pub fn new(probe: &'a dyn InstallProbe) -> Self {
        Self { probe }
    }
}

impl Installer for HostInstaller<'_> {
    fn run(&self, plan: &InstallPlan) -> Result<InstallReport, InstallError> {
        finish(
            execute(plan, &HostInstallOps::system(), self.probe),
            &HostRunner,
        )
    }

    fn agent_plan(
        &self,
        request: &EnrolRequest,
        scan: AccountScan,
    ) -> Result<EnrolPlan, AgentError> {
        let ops = HostInstallOps::system();
        plan_enrol(request, scan, &ops, &ops)
    }

    fn agent_apply(&self, plan: &EnrolPlan) -> Result<(), AgentError> {
        let ops = HostInstallOps::system();
        apply_enrol(plan, &ops, &ops)
    }

    fn agent_list(&self) -> Result<Vec<AgentRow>, AgentError> {
        list_agents(&HostInstallOps::system())
    }

    fn agent_remove(&self, label: &str) -> Result<Vec<String>, AgentError> {
        let ops = HostInstallOps::system();
        remove_agent(label, &ops, &ops)
    }

    fn pack_add(&self, request: &PackRequest) -> Result<PackReport, PackError> {
        let ops = HostInstallOps::system();
        add_pack(request, &HostWhereabouts::system(), &ops, &ops)
    }

    fn pack_remove(&self, name: &str, reviewed: &str) -> Result<PackReport, PackError> {
        let ops = HostInstallOps::system();
        remove_pack(name, reviewed, &HostWhereabouts::system(), &ops, &ops)
    }
}

/// Adds the backend's own account of the rule to a finished install, as a
/// notice of its own. A probe pass does not stand if the backend says it does
/// not list the gate. An install that wrote nothing has nothing to ask about,
/// and a refusal is passed on as it is.
fn finish(
    result: Result<InstallReport, InstallError>,
    runner: &dyn Runner,
) -> Result<InstallReport, InstallError> {
    result.map(|mut report| {
        if report.verification != Verification::NotRequired {
            let effect = check_effect(runner, report.backend);
            report.notices.push(effect.describe());
            if report.verification == Verification::Verified
                && matches!(effect, Effect::NotInEffect { .. })
            {
                report.verification = Verification::Unverified {
                    reason: "the gate ran as root, but the backend does not list it for a member \
                             of the xudo group"
                        .to_owned(),
                };
            }
        }
        report
    })
}

/// The installer for a context that must not modify the machine.
#[derive(Clone, Copy, Debug)]
pub struct RefusingInstaller;

impl Installer for RefusingInstaller {
    fn run(&self, _plan: &InstallPlan) -> Result<InstallReport, InstallError> {
        Err(InstallError::NoInstaller)
    }

    fn agent_plan(
        &self,
        _request: &EnrolRequest,
        _scan: AccountScan,
    ) -> Result<EnrolPlan, AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn agent_apply(&self, _plan: &EnrolPlan) -> Result<(), AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn agent_list(&self) -> Result<Vec<AgentRow>, AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn agent_remove(&self, _label: &str) -> Result<Vec<String>, AgentError> {
        Err(InstallError::NoInstaller.into())
    }

    fn pack_add(&self, _request: &PackRequest) -> Result<PackReport, PackError> {
        Err(InstallError::NoInstaller.into())
    }

    fn pack_remove(&self, _name: &str, _reviewed: &str) -> Result<PackReport, PackError> {
        Err(InstallError::NoInstaller.into())
    }
}

/// Executes `plan` through `ops`, checking with `probe`.
///
/// # Errors
///
/// Every refusal listed in the module documentation, and any failure of a step.
/// The candidate this run created is removed; the previous state of every file
/// is otherwise as it was. A functional probe that fails is not an error: the
/// validated install stays and the report says [`Verification::Unverified`].
pub fn execute(
    plan: &InstallPlan,
    ops: &dyn InstallOps,
    probe: &dyn InstallProbe,
) -> Result<InstallReport, InstallError> {
    let uid = ops.effective_uid();
    if uid != 0 {
        return Err(InstallError::NotRoot { uid });
    }
    for step in &plan.steps {
        preflight(step)?;
    }
    let mut run = Run {
        transactional: plan
            .steps
            .iter()
            .any(|step| matches!(step, PlanStep::ValidateWhole { .. })),
        ..Run::default()
    };
    match run.steps(plan, ops, probe) {
        Ok(()) => Ok(run.report(plan.backend)),
        Err(error) => Err(run.abandon(ops, error)),
    }
}

/// Whether `path` is one xudo's snippets install to, or the candidate beside one.
fn is_managed(path: &str) -> bool {
    let candidate_of = |base: &str| path.strip_suffix(".candidate") == Some(base);
    path == SUDOERS_PATH
        || path == DOAS_DROP_IN_PATH
        || path == DOAS_CONF_PATH
        || path == PTRACE_DROP_IN_PATH
        || candidate_of(SUDOERS_PATH)
        || candidate_of(DOAS_DROP_IN_PATH)
        || candidate_of(PTRACE_DROP_IN_PATH)
}

fn managed(path: &str) -> Result<(), InstallError> {
    if is_managed(path) {
        Ok(())
    } else {
        Err(InstallError::PathNotManaged {
            path: path.to_owned(),
        })
    }
}

/// A mode that is no more than read access for owner and group.
fn check_mode(path: &str, mode: u32) -> Result<(), InstallError> {
    if mode & !0o440 == 0 {
        Ok(())
    } else {
        Err(InstallError::UnsafeMode {
            path: path.to_owned(),
            mode,
        })
    }
}

/// Whether `sudo` would skip a drop-in with this file name.
fn sudo_skips(name: &str) -> bool {
    name.contains('.') || name.ends_with('~')
}

/// The directory and the name of an absolute path.
fn split(path: &str) -> Option<(&str, &str)> {
    path.rsplit_once('/').filter(|(_, name)| !name.is_empty())
}

fn check_validator(argv: &[String]) -> Result<(), InstallError> {
    let bad = |reason| InstallError::BadValidator {
        argv: argv.to_vec(),
        reason,
    };
    if !argv.first().is_some_and(|exe| exe.starts_with('/')) {
        return Err(bad("the validator must be an absolute path"));
    }
    if argv.iter().filter(|a| *a == CANDIDATE_PLACEHOLDER).count() != 1 {
        return Err(bad(
            "it must name the candidate exactly once, or it validates something else",
        ));
    }
    Ok(())
}

/// Everything that can be refused without touching the machine.
fn preflight(step: &PlanStep) -> Result<(), InstallError> {
    match step {
        PlanStep::CreateGroup { name } => {
            if name == XUDO_GROUP || name == XUDO_AGENT_GROUP {
                Ok(())
            } else {
                Err(InstallError::GroupNotManaged { name: name.clone() })
            }
        }
        PlanStep::WriteCandidate {
            path,
            mode,
            contents,
        } => {
            managed(path)?;
            check_mode(path, *mode)?;
            // The drop-in has no parser to ask, so its one text is pinned
            // here: no plan can put another value in it.
            match xudo_backend::plan::edited(PTRACE_DROP_IN_PATH, contents.as_bytes()) {
                Some(reason) if path.strip_suffix(".candidate") == Some(PTRACE_DROP_IN_PATH) => {
                    Err(InstallError::Edited {
                        path: path.clone(),
                        reason,
                    })
                }
                _ => Ok(()),
            }
        }
        PlanStep::Validate { argv } => check_validator(argv),
        PlanStep::ValidateBySubstitution { candidate, .. } => managed(candidate),
        PlanStep::Install { from, to } => {
            managed(from)?;
            managed(to)?;
            if split(from).map(|(dir, _)| dir) != split(to).map(|(dir, _)| dir) {
                return Err(InstallError::CrossDirectory {
                    from: from.clone(),
                    to: to.clone(),
                });
            }
            match split(to) {
                Some((dir, name)) if dir == "/etc/sudoers.d" && sudo_skips(name) => {
                    Err(InstallError::NameSudoIgnores { path: to.clone() })
                }
                _ => Ok(()),
            }
        }
        PlanStep::RemoveBlock { path, begin, end } => {
            managed(path)?;
            if begin == DOAS_BEGIN && end == DOAS_END {
                Ok(())
            } else {
                Err(InstallError::ForeignMarkers)
            }
        }
        PlanStep::AppendBlock { path, .. }
        | PlanStep::Remove { path }
        | PlanStep::RemoveUnlessEdited { path }
        | PlanStep::RefuseEdited { path } => managed(path),
        PlanStep::ValidateWhole { argv } => {
            if !argv.first().is_some_and(|exe| exe.starts_with('/')) {
                return Err(InstallError::BadValidator {
                    argv: argv.clone(),
                    reason: "the validator must be an absolute path",
                });
            }
            if argv.iter().any(|arg| arg == CANDIDATE_PLACEHOLDER) {
                return Err(InstallError::BadValidator {
                    argv: argv.clone(),
                    reason: "a whole-configuration check names no candidate",
                });
            }
            Ok(())
        }
        PlanStep::ReadBack { candidate } => {
            if candidate.strip_suffix(".candidate") == Some(PTRACE_DROP_IN_PATH) {
                Ok(())
            } else {
                Err(InstallError::ReadBackRefused {
                    path: candidate.clone(),
                })
            }
        }
        PlanStep::FunctionalProbe { .. }
        | PlanStep::Notice { .. }
        | PlanStep::MustNotList { .. }
        | PlanStep::MustList { .. }
        | PlanStep::RefusalProbe { .. } => Ok(()),
    }
}

/// The candidate this run wrote and has not yet installed.
struct Candidate {
    path: String,
    identity: FileIdentity,
    contents: Vec<u8>,
}

/// One execution's state.
#[derive(Default)]
struct Run {
    candidate: Option<Candidate>,
    validated: bool,
    armed: Option<Vec<String>>,
    wrote: bool,
    /// Whether a failure after an install restores what it replaced.
    transactional: bool,
    /// Each file installed by a transactional run, last last, with what it
    /// replaced: `None` when nothing was there.
    installed: Vec<(String, Option<Vec<u8>>)>,
    events: Vec<String>,
    notices: Vec<String>,
    verification: Option<Verification>,
}

impl Run {
    fn steps(
        &mut self,
        plan: &InstallPlan,
        ops: &dyn InstallOps,
        probe: &dyn InstallProbe,
    ) -> Result<(), InstallError> {
        for step in &plan.steps {
            self.step(step, ops, probe)?;
        }
        if self.candidate.is_some() {
            return Err(InstallError::OutOfOrder {
                reason: "the plan ended with a candidate that was never installed",
            });
        }
        if self.armed.is_some() {
            return Err(InstallError::OutOfOrder {
                reason: "the plan named a validator and then validated nothing with it",
            });
        }
        Ok(())
    }

    fn step(
        &mut self,
        step: &PlanStep,
        ops: &dyn InstallOps,
        probe: &dyn InstallProbe,
    ) -> Result<(), InstallError> {
        match step {
            PlanStep::CreateGroup { name } => {
                if ops.group_exists(name)? {
                    self.events.push(format!("group {name} already exists"));
                } else {
                    ops.create_group(name)?;
                    self.events.push(format!("created group {name}, empty"));
                }
            }
            PlanStep::WriteCandidate {
                path,
                contents,
                mode,
            } => {
                if self.candidate.is_some() {
                    return Err(InstallError::OutOfOrder {
                        reason: "a second candidate before the first was installed",
                    });
                }
                let identity = ops.write_candidate(path, contents.as_bytes(), *mode)?;
                self.candidate = Some(Candidate {
                    path: path.clone(),
                    identity,
                    contents: contents.as_bytes().to_vec(),
                });
                self.validated = false;
                self.events.push(format!("wrote candidate {path}"));
            }
            PlanStep::Validate { argv } => self.validate(argv, ops)?,
            PlanStep::ValidateBySubstitution { reason, .. } => {
                return Err(InstallError::ValidationUnavailable {
                    reason: reason.clone(),
                });
            }
            PlanStep::Install { from, to } => self.install(from, to, ops)?,
            PlanStep::AppendBlock { path, block } => {
                let validator = self.armed.take().ok_or(InstallError::OutOfOrder {
                    reason: "a block appended with no validator named before it",
                })?;
                ops.append_block(path, block, &validator)?;
                self.wrote = true;
                self.events.push(format!("set xudo's block in {path}"));
            }
            PlanStep::RemoveBlock { path, .. } => {
                let removal = ops.remove_block(path)?;
                self.events.push(match removal {
                    Removal::Removed => format!("removed xudo's block from {path}"),
                    Removal::Absent => format!("no xudo block in {path}"),
                });
            }
            PlanStep::Remove { path } => {
                let removal = ops.remove_managed(path)?;
                self.events.push(match removal {
                    Removal::Removed => format!("removed {path}"),
                    Removal::Absent => format!("{path} was not present"),
                });
            }
            PlanStep::FunctionalProbe { argv, .. } => self.functional_probe(argv, probe)?,
            // After the rename, because before it the candidate's name holds
            // a dot and sudo's `@includedir` skips it, so the whole
            // configuration cannot be checked with it in. For the few
            // milliseconds in between sudo reads a configuration not checked
            // as a whole. Accepted: the candidate passed alone, and only a
            // clash with another file that the front-end's scan for lines
            // naming xudo's group, aliases and helpers missed could matter in
            // that window. A failure here undoes the rename.
            PlanStep::ValidateWhole { argv } => {
                ops.validate(argv).map_err(|error| match error {
                    InstallError::ValidatorRejected { detail } => {
                        InstallError::WholeRejected { detail }
                    }
                    other => other,
                })?;
                self.events.push(format!(
                    "the backend parsed its whole configuration: {}",
                    argv.join(" ")
                ));
            }
            // Both listings ran the backend seconds after the refusal probe
            // did, so one that cannot run now is an anomaly, and an anomaly
            // after the rename is not a line to keep.
            PlanStep::MustNotList { argv, expectation } => {
                self.listing(probe.not_listed(argv), expectation)?;
            }
            PlanStep::MustList { argv, expectation } => {
                self.listing(probe.listed(argv), expectation)?;
            }
            PlanStep::RemoveUnlessEdited { path } => self.remove_unless_edited(path, ops)?,
            PlanStep::Notice { text } => self.notices.push(text.clone()),
            PlanStep::RefusalProbe { argv, .. } => self.refusal_probe(argv, probe)?,
            PlanStep::RefuseEdited { path } => self.refuse_edited(path, ops)?,
            PlanStep::ReadBack { candidate } => self.read_back(candidate, ops)?,
        }
        Ok(())
    }

    /// A listing check's answer: verified, or the install is undone.
    fn listing(&mut self, answer: ProbeResult, expectation: &str) -> Result<(), InstallError> {
        match answer {
            ProbeResult::Verified => {
                self.events.push(format!("verified: {expectation}"));
                Ok(())
            }
            ProbeResult::Failed { reason } => Err(InstallError::ProbeFailed { reason }),
            ProbeResult::Unavailable { reason } => Err(InstallError::ProbeFailed {
                reason: format!("could not check that {expectation}: {reason}"),
            }),
        }
    }

    /// A `RefusalProbe` step: the helper must refuse a caller it cannot attest.
    fn refusal_probe(
        &mut self,
        argv: &[String],
        probe: &dyn InstallProbe,
    ) -> Result<(), InstallError> {
        match probe.refuses(argv) {
            ProbeResult::Verified => {
                self.events
                    .push("the passwordless helper refused a caller it cannot attest".to_owned());
                Ok(())
            }
            ProbeResult::Failed { reason } | ProbeResult::Unavailable { reason } => {
                Err(InstallError::HelperDidNotRefuse { reason })
            }
        }
    }

    /// A `RefuseEdited` step: a file that holds an edit stops the run.
    fn refuse_edited(&mut self, path: &str, ops: &dyn InstallOps) -> Result<(), InstallError> {
        if let Some(reason) = ops
            .read_managed(path)?
            .and_then(|bytes| xudo_backend::plan::edited(path, &bytes))
        {
            return Err(InstallError::Edited {
                path: path.to_owned(),
                reason,
            });
        }
        self.events.push(format!("{path} holds no edit"));
        Ok(())
    }

    /// An `Install` step: the candidate this run wrote and validated is
    /// renamed into place. A transactional run first keeps what it replaces.
    fn install(&mut self, from: &str, to: &str, ops: &dyn InstallOps) -> Result<(), InstallError> {
        let candidate =
            self.candidate
                .as_ref()
                .filter(|c| c.path == from)
                .ok_or(InstallError::OutOfOrder {
                    reason: "an install of a file this run did not write as a candidate",
                })?;
        if !self.validated {
            return Err(InstallError::OutOfOrder {
                reason: "an install before the candidate was validated",
            });
        }
        let identity = candidate.identity;
        let replaced = if self.transactional {
            Some(ops.read_managed(to)?)
        } else {
            None
        };
        ops.install(from, to, identity)?;
        if let Some(replaced) = replaced {
            self.installed.push((to.to_owned(), replaced));
        }
        self.candidate = None;
        self.validated = false;
        self.wrote = true;
        self.events.push(format!("installed {to}"));
        Ok(())
    }

    /// A `FunctionalProbe` step.
    fn functional_probe(
        &mut self,
        argv: &[String],
        probe: &dyn InstallProbe,
    ) -> Result<(), InstallError> {
        self.verification = Some(match probe.verify(argv) {
            ProbeResult::Verified => Verification::Verified,
            ProbeResult::Unavailable { reason } => Verification::Unverified { reason },
            // It ran and the answer was wrong: an all-or-nothing run
            // restores what it installed.
            ProbeResult::Failed { reason } if self.transactional => {
                return Err(InstallError::ProbeFailed {
                    reason: format!("the functional probe ran and failed: {reason}"),
                });
            }
            // Otherwise the snippet passed the backend's own parser, so it
            // stays; the operator is told.
            ProbeResult::Failed { reason } => Verification::Unverified {
                reason: format!("the probe ran and failed: {reason}"),
            },
        });
        Ok(())
    }

    /// A `RemoveUnlessEdited` step: remove the file, or leave an edited one
    /// (one without xudo's marker included) and warn.
    fn remove_unless_edited(
        &mut self,
        path: &str,
        ops: &dyn InstallOps,
    ) -> Result<(), InstallError> {
        let edited = match ops.read_managed(path) {
            Ok(bytes) => bytes
                .and_then(|bytes| xudo_backend::plan::edited(path, &bytes))
                .map(str::to_owned),
            Err(InstallError::NotOurs { reason, .. }) => Some(reason),
            Err(other) => return Err(other),
        };
        if let Some(reason) = edited {
            self.notices.push(format!(
                "WARNING: {path} was left in place: {reason}. Everything else was removed; \
                 remove or restore it by hand."
            ));
            return Ok(());
        }
        let removal = ops.remove_managed(path)?;
        self.events.push(match removal {
            Removal::Removed => format!("removed {path}"),
            Removal::Absent => format!("{path} was not present"),
        });
        Ok(())
    }

    /// A `ReadBack` step: the candidate this run wrote must hold exactly the
    /// bytes written, and still be the inode written.
    fn read_back(&mut self, path: &str, ops: &dyn InstallOps) -> Result<(), InstallError> {
        let candidate =
            self.candidate
                .as_ref()
                .filter(|c| c.path == path)
                .ok_or(InstallError::OutOfOrder {
                    reason: "a read-back of a file this run did not write as a candidate",
                })?;
        if ops.read_managed(path)?.as_deref() != Some(candidate.contents.as_slice()) {
            return Err(InstallError::ValidatorRejected {
                detail: format!("{path} does not hold what was written"),
            });
        }
        let identity = candidate.identity;
        self.confirm_identity(ops, path, identity)?;
        self.events.push(format!("read back {path}"));
        Ok(())
    }

    /// A `Validate` step: of the candidate when there is one, otherwise armed
    /// for the block that follows, which validates a merged copy.
    fn validate(&mut self, argv: &[String], ops: &dyn InstallOps) -> Result<(), InstallError> {
        let Some(candidate) = &self.candidate else {
            self.armed = Some(argv.to_vec());
            return Ok(());
        };
        ops.validate(&substitute(argv, &candidate.path))?;
        let (path, identity) = (candidate.path.clone(), candidate.identity);
        self.confirm_identity(ops, &path, identity)?;
        self.events
            .push("validated by the backend's own parser".to_owned());
        Ok(())
    }

    /// The inode that passed a check must be the inode this run wrote. A
    /// rename into the path in between would have the check bless one file
    /// and the install move another. Marks the candidate validated.
    fn confirm_identity(
        &mut self,
        ops: &dyn InstallOps,
        path: &str,
        identity: FileIdentity,
    ) -> Result<(), InstallError> {
        if ops.identity(path)? != identity {
            // Not this run's file any more, so it is not this run's to remove.
            self.candidate = None;
            return Err(InstallError::CandidateReplaced {
                path: path.to_owned(),
            });
        }
        self.validated = true;
        Ok(())
    }

    /// Cleans up after `error`, and returns what to report: the candidate is
    /// discarded, and in a transactional run every installed file is put back
    /// as it was, last first.
    fn abandon(&mut self, ops: &dyn InstallOps, error: InstallError) -> InstallError {
        let mut error = error;
        if let Some(candidate) = self.candidate.take() {
            if let Err(failed) = ops.discard(&candidate.path, candidate.identity) {
                error = InstallError::LeftBehind {
                    path: candidate.path,
                    reason: failed.to_string(),
                    cause: Box::new(error),
                };
            }
        }
        if self.installed.is_empty() {
            return error;
        }
        let mut failed = None;
        let mut removed = None;
        while let Some((path, replaced)) = self.installed.pop() {
            let restored = match &replaced {
                // What stands at `path` now is what this run just showed
                // wrong. When the earlier bytes cannot go back (no space, an
                // I/O error), it is removed: an unlink needs no space, and no
                // file grants less than the one that failed its check.
                Some(bytes) => restore(ops, &path, bytes).or_else(|why| {
                    ops.remove_managed(&path)
                        .map(|_| {
                            removed.get_or_insert((path.clone(), why.to_string()));
                        })
                        .map_err(|_| why)
                }),
                None => ops.remove_managed(&path).map(|_| ()),
            };
            if let Err(why) = restored {
                failed.get_or_insert((path, why.to_string()));
            }
        }
        let cause = Box::new(error);
        match (failed, removed) {
            (Some((path, reason)), _) => InstallError::NotRolledBack {
                path,
                reason,
                cause,
            },
            (None, Some((path, reason))) => InstallError::RemovedInstead {
                path,
                reason,
                cause,
            },
            (None, None) => InstallError::RolledBack { cause },
        }
    }

    fn report(self, backend: BackendKind) -> InstallReport {
        let wrote = self.wrote;
        let verification = self.verification.unwrap_or(if wrote {
            Verification::Unverified {
                reason: "the plan has no functional probe".to_owned(),
            }
        } else {
            Verification::NotRequired
        });
        InstallReport {
            backend,
            events: self.events,
            notices: self.notices,
            verification,
        }
    }
}

/// Puts `bytes`, what an install replaced, back at `path`: written beside it
/// and renamed over it, as every install is. Not validated again: it is the
/// configuration the backend was reading before this run. The mode is 0440,
/// the mode every install writes, not read from the file replaced: an
/// operator's chmod of xudo's own file is the one thing not put back.
fn restore(ops: &dyn InstallOps, path: &str, bytes: &[u8]) -> Result<(), InstallError> {
    let candidate = format!("{path}.candidate");
    let identity = ops.write_candidate(&candidate, bytes, 0o440)?;
    ops.install(&candidate, path, identity).inspect_err(|_| {
        // The rename failed and the restore with it; the candidate is ours.
        let _ = ops.discard(&candidate, identity);
    })
}

/// `argv` with the candidate's path in place of the placeholder.
pub(crate) fn substitute(argv: &[String], path: &str) -> Vec<String> {
    argv.iter()
        .map(|a| {
            if a == CANDIDATE_PLACEHOLDER {
                path.to_owned()
            } else {
                a.clone()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
