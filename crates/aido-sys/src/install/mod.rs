//! Executing the install plan.
//!
//! `aido-backend` decides what to write and in what order and never touches a
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
//! * **Only files aido writes.** Every path a step names must be one of the five
//!   aido's snippets install to, or the candidate beside one. `/etc/sudoers`,
//!   `/etc/passwd`, and anything else are refused, so the executor cannot touch
//!   a file it did not write however the plan was assembled.
//! * **No name sudo ignores.** A drop-in whose name contains a dot or ends in
//!   `~` is silently skipped by sudo, so an install onto one would report
//!   success and grant nothing. Refused before it can happen.
//! * **No writable modes.** A file aido installs is `0440` or `0400`; a mode
//!   with any write bit, or any access for others, is refused.
//! * **One validator, one candidate.** A validator that never names the
//!   candidate checks nothing, so its argv must contain `{candidate}` exactly
//!   once and start with an absolute path.
//!
//! and while it runs:
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
//! backend and see it execute as uid 0. The gate exists, but minting the request
//! it waits for needs a broker client in the front-end (M2b plan item C1), so
//! [`InstallProbe`] is the seam and the only production implementation,
//! [`PendingGateProbe`], answers [`ProbeResult::Unavailable`]: a completed
//! install reports [`Verification::Unverified`] with the reason, never
//! "verified". A file in `/etc/sudoers.d` proves nothing: `sudo-rs` ignores
//! directives it does not support, and `sudo` ignores a badly named file
//! entirely. What the host installer adds is [`check_effect`], the backend's own
//! answer to "do you read this rule", as a notice of its own; it is not the probe.

mod blocks;
mod effect;
#[cfg(test)]
mod fake;
mod host;

use aido_backend::snippet::{
    AIDO_GROUP, DOAS_BEGIN, DOAS_CONF_PATH, DOAS_DROP_IN_PATH, DOAS_END, SUDOERS_PATH,
};
use aido_backend::{BackendKind, InstallPlan, PlanStep};

pub use blocks::BlockError;
pub use effect::{Effect, check_effect};
pub use host::HostInstallOps;

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
    /// aido's file or block was there and is gone.
    Removed,
    /// Nothing of aido's was there. A second uninstall succeeds.
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
    /// A step names a file aido does not write.
    #[error("{path} is not a file aido writes; refusing to touch it")]
    PathNotManaged {
        /// The path.
        path: String,
    },
    /// A step names a group other than aido's.
    #[error("refusing to create group {name}: aido manages only the group {AIDO_GROUP}")]
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
    /// A plan that names markers other than aido's.
    #[error("refusing to edit a shared file between markers aido did not write")]
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
         or remove a file aido did not write"
    )]
    CandidateReplaced {
        /// The path.
        path: String,
    },
    /// An existing file at a destination is not one aido wrote.
    #[error(
        "{path} exists and is not a file aido wrote: {reason}; refusing to replace or remove it"
    )]
    NotOurs {
        /// The path.
        path: String,
        /// How it was told apart.
        reason: String,
    },
    /// A candidate name is already taken by something this run cannot show is a
    /// leftover of an earlier, interrupted aido run.
    #[error(
        "{path} already exists and is not a leftover of an interrupted aido run: {reason}; \
         nothing was removed. Inspect it, remove it by hand if it is not wanted, and run the \
         command again"
    )]
    StaleCandidate {
        /// The path.
        path: String,
        /// Why it is not aido's.
        reason: String,
    },
    /// A shared file does not exist where aido must edit it.
    #[error("{path} does not exist; aido edits a shared file and never creates one")]
    Missing {
        /// The path.
        path: String,
    },
    /// A shared file is not one aido may edit.
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
    /// The functional probe ran and the integration is not in effect.
    #[error("the functional probe failed, so the integration was removed: {reason}")]
    ProbeFailed {
        /// What the probe observed.
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
}

/// What a functional probe saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    /// The gate ran through the backend as uid 0, and refused without a
    /// password rather than reporting that no rule permits it.
    Verified,
    /// It ran and the integration is not in effect.
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
}

/// The probe this build ships: unable to check anything yet.
///
/// **An explicit open item, not a stub to forget.** The functional probe runs
/// the gate through `sudo` or `doas`, with a request pinned to the caller, and
/// asserts it ran as uid 0. The gate exists (`aido-gate-bin`) and so does the
/// broker, but the front-end has no client for the broker (M2b plan item C1,
/// `aido exec`), so `aido install` cannot mint the request the gate waits for.
/// Until it can, an install completes and is never called verified.
///
/// The gate-through-sudo path is proven where a request can be written by
/// hand: `aido-gate-bin/tests/root_probe.rs`, in the root lane. That proves
/// the installed snippet reaches the gate; it is not this probe.
#[derive(Clone, Copy, Debug)]
pub struct PendingGateProbe;

impl InstallProbe for PendingGateProbe {
    fn verify(&self, _argv: &[String]) -> ProbeResult {
        ProbeResult::Unavailable {
            reason: "the front-end cannot yet ask the broker for a request (M2b plan item C1), so \
                     the gate cannot be driven from here and nothing shows it runs as root"
                .to_owned(),
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
    /// `identity` and `to` is absent or a file aido wrote.
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

    /// Removes a file aido wrote: a regular, root-owned, singly-linked file
    /// that begins with aido's marker.
    ///
    /// # Errors
    ///
    /// [`InstallError::NotOurs`] for a file that is anything else.
    fn remove_managed(&self, path: &str) -> Result<Removal, InstallError>;

    /// Under a lock, sets aido's block in a shared file, validating the whole
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

    /// Under a lock, removes aido's block from a shared file and nothing else.
    ///
    /// # Errors
    ///
    /// Anything that stopped it; the shared file is unchanged.
    fn remove_block(&self, path: &str) -> Result<Removal, InstallError>;
}

/// Something that executes a plan: the seam the front-end holds.
pub trait Installer {
    /// Executes `plan`.
    ///
    /// # Errors
    ///
    /// Whatever stopped it.
    fn run(&self, plan: &InstallPlan) -> Result<InstallReport, InstallError>;
}

/// The installer for a real machine: real file operations, and the probe this
/// build has.
#[derive(Clone, Copy, Debug)]
pub struct HostInstaller;

impl Installer for HostInstaller {
    fn run(&self, plan: &InstallPlan) -> Result<InstallReport, InstallError> {
        finish(
            execute(plan, &HostInstallOps::system(), &PendingGateProbe),
            &HostRunner,
        )
    }
}

/// Adds the backend's own account of the rule to a finished install, as a
/// notice of its own. An install that wrote nothing has nothing to ask about,
/// and a refusal is passed on as it is.
fn finish(
    result: Result<InstallReport, InstallError>,
    runner: &dyn Runner,
) -> Result<InstallReport, InstallError> {
    result.map(|mut report| {
        if report.verification != Verification::NotRequired {
            report
                .notices
                .push(check_effect(runner, report.backend).describe());
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
}

/// Executes `plan` through `ops`, checking with `probe`.
///
/// # Errors
///
/// Every refusal listed in the module documentation, and any failure of a step.
/// The candidate this run created is removed; the previous state of every file
/// is otherwise as it was, except that a failed functional probe removes what
/// this run installed.
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
    let mut run = Run::default();
    match run.steps(plan, ops, probe) {
        Ok(()) => Ok(run.report(plan.backend)),
        Err(error) => Err(run.abandon(ops, error)),
    }
}

/// Whether `path` is one aido's snippets install to, or the candidate beside one.
fn is_managed(path: &str) -> bool {
    let candidate_of = |base: &str| path.strip_suffix(".candidate") == Some(base);
    path == SUDOERS_PATH
        || path == DOAS_DROP_IN_PATH
        || path == DOAS_CONF_PATH
        || candidate_of(SUDOERS_PATH)
        || candidate_of(DOAS_DROP_IN_PATH)
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
            if name == AIDO_GROUP {
                Ok(())
            } else {
                Err(InstallError::GroupNotManaged { name: name.clone() })
            }
        }
        PlanStep::WriteCandidate { path, mode, .. } => {
            managed(path)?;
            check_mode(path, *mode)
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
        PlanStep::AppendBlock { path, .. } | PlanStep::Remove { path } => managed(path),
        PlanStep::FunctionalProbe { .. } | PlanStep::Notice { .. } => Ok(()),
    }
}

/// The candidate this run wrote and has not yet installed.
struct Candidate {
    path: String,
    identity: FileIdentity,
}

/// What an install put on the machine, so a failed probe can take it off.
enum Installed {
    File(String),
    Block(String),
}

/// One execution's state.
#[derive(Default)]
struct Run {
    candidate: Option<Candidate>,
    validated: bool,
    armed: Option<Vec<String>>,
    installed: Vec<Installed>,
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
            PlanStep::Install { from, to } => {
                let candidate = self.candidate.as_ref().filter(|c| c.path == *from).ok_or(
                    InstallError::OutOfOrder {
                        reason: "an install of a file this run did not write as a candidate",
                    },
                )?;
                if !self.validated {
                    return Err(InstallError::OutOfOrder {
                        reason: "an install before the candidate was validated",
                    });
                }
                ops.install(from, to, candidate.identity)?;
                self.candidate = None;
                self.validated = false;
                self.installed.push(Installed::File(to.clone()));
                self.events.push(format!("installed {to}"));
            }
            PlanStep::AppendBlock { path, block } => {
                let validator = self.armed.take().ok_or(InstallError::OutOfOrder {
                    reason: "a block appended with no validator named before it",
                })?;
                ops.append_block(path, block, &validator)?;
                self.installed.push(Installed::Block(path.clone()));
                self.events.push(format!("set aido's block in {path}"));
            }
            PlanStep::RemoveBlock { path, .. } => {
                let removal = ops.remove_block(path)?;
                self.events.push(match removal {
                    Removal::Removed => format!("removed aido's block from {path}"),
                    Removal::Absent => format!("no aido block in {path}"),
                });
            }
            PlanStep::Remove { path } => {
                let removal = ops.remove_managed(path)?;
                self.events.push(match removal {
                    Removal::Removed => format!("removed {path}"),
                    Removal::Absent => format!("{path} was not present"),
                });
            }
            PlanStep::FunctionalProbe { argv, .. } => {
                self.verification = Some(match probe.verify(argv) {
                    ProbeResult::Verified => Verification::Verified,
                    ProbeResult::Unavailable { reason } => Verification::Unverified { reason },
                    ProbeResult::Failed { reason } => {
                        return Err(InstallError::ProbeFailed { reason });
                    }
                });
            }
            PlanStep::Notice { text } => self.notices.push(text.clone()),
        }
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
        // The inode that passed the backend's parser must be the inode this run
        // wrote. A rename into the path in between would have the parser bless
        // one file and the install move another.
        let now = ops.identity(&candidate.path)?;
        if now != candidate.identity {
            let path = candidate.path.clone();
            // Not this run's file any more, so it is not this run's to remove.
            self.candidate = None;
            return Err(InstallError::CandidateReplaced { path });
        }
        self.validated = true;
        self.events
            .push("validated by the backend's own parser".to_owned());
        Ok(())
    }

    /// Cleans up after `error`, and returns what to report.
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
        if matches!(error, InstallError::ProbeFailed { .. }) {
            // An integration that is installed and not in effect looks
            // installed. Take off exactly what this run put on.
            for item in self.installed.drain(..).rev() {
                let (path, outcome) = match &item {
                    Installed::File(path) => (path, ops.remove_managed(path)),
                    Installed::Block(path) => (path, ops.remove_block(path)),
                };
                if let Err(failed) = outcome {
                    error = InstallError::LeftBehind {
                        path: path.clone(),
                        reason: failed.to_string(),
                        cause: Box::new(error),
                    };
                }
            }
        }
        error
    }

    fn report(self, backend: BackendKind) -> InstallReport {
        let wrote = !self.installed.is_empty();
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
