//! The second decision, made from root's state.
//!
//! The front-end already decided. That verdict does not travel: it ran in a
//! process the caller controls, so the gate re-derives everything and consults
//! the spool entry only for the *question*.
//!
//! # What the gate refuses that the front-end cannot
//!
//! Three refusals exist only here, because only here are they meaningful:
//!
//! * **No pending request.** The expected shape of a hostile invocation. `sudo
//!   /usr/libexec/xudo/xudo-gate-auth` is available to every member of the
//!   `xudo` group by design; with no entry to act on, the gate exits non-zero
//!   having done nothing privileged, and says so at high severity.
//! * **An unconfirmed action whose rule demands confirmation.** The gate has no
//!   confirmation channel — every terminal it can reach belongs to the process
//!   tree that asked — so it cannot supply what is missing. Invariant 3 makes
//!   this a refusal rather than a prompt.
//! * **A program that is not the program the rule names.** Caught by
//!   [`xudo_policy::evaluate`] via the exe comparison, which is why the entry's
//!   `program` is passed through to it rather than trusted.
//!
//! # Severity is about what the refusal implies, not how bad it sounds
//!
//! An expired request is a race: the human took too long, the deadline passed,
//! nothing is wrong. A request naming a *different caller* is someone trying to
//! use an approval that was granted to another process. Both are refusals; only
//! one is worth waking someone for. [`Severity`] carries that distinction so the
//! audit sink can route on it, and it is derived from the refusal rather than
//! chosen at each call site, where it would drift.

use xudo_audit::record::{Approval, Decision as AuditDecision, Outcome, Record};
use xudo_policy::{
    ActionId, Arg, Argv, CallerFacts, Classification, Confirm, Decision, DenialCode, ExitCode,
    Request, RuleSet, Verdict, engine,
};

use xudo_sys::GateMode;

use crate::env::child_environment;
use crate::request::{AttestedClass, BoottimeMillis, CallerPin, PendingRequest, RequestError, Via};

/// The caller, as the gate itself established it.
///
/// `facts` comes from kernel attestation performed by the gate, not from the
/// spool entry's claim. The entry's `claimed_classification` is carried into the
/// audit record beside this and compared nowhere.
#[derive(Clone, Debug)]
pub struct GateCaller {
    /// The pinned identity of the `xudo` process that asked.
    pub pin: CallerPin,
    /// What the gate attested about it.
    pub facts: CallerFacts,
    /// The attested class established from the live caller.
    pub attested_class: crate::request::AttestedClass,
    /// The caller's live scope id, when enrolled.
    pub attested_scope_id: Option<u64>,
    /// The live boot id used to qualify a scope id.
    pub boot_id: Option<String>,
}

impl GateCaller {
    /// A caller the gate has not identified, for a refusal made before the
    /// lineage was walked: this process's own pin is not the caller's, so the
    /// pin carries pid 0 and no start time, and the attestation says why.
    pub fn unidentified(gate_pid: u32) -> Self {
        Self {
            pin: CallerPin::new(0, 0),
            facts: CallerFacts::new(
                Classification::Unattested {
                    reason: format!(
                        "the gate (pid {gate_pid}) refused before it identified its caller"
                    ),
                },
                UNKNOWN_UID,
            ),
            attested_class: crate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }
}

/// The uid recorded for a caller whose uid the gate did not establish.
///
/// Not 0: root's uid in a record reads as a root caller. The gate takes no
/// decision from the uid, and `SO_PEERCRED` at the broker is where it is read.
pub const UNKNOWN_UID: u32 = u32::MAX;

/// The state the gate decides against.
#[derive(Clone, Copy, Debug)]
pub struct GateContext {
    /// The policy generation currently in force, read from root-owned state.
    pub generation: u64,
    /// The current boottime reading.
    pub now: BoottimeMillis,
    /// Global settings, loaded from the root-owned config.
    pub settings: engine::Settings,
    /// Whether this invocation proves a human typed a password.
    ///
    /// True only for the `xudo-gate-auth` name, which `sudo` reaches only after
    /// a PAM conversation on a fresh pty that the requesting process tree cannot
    /// answer without the secret. It satisfies the password half of a
    /// confirmation requirement; when `confirm_human_path` is enabled, a
    /// checked watch approval is required as well. Never true for a request
    /// that was merely approved: that is the broker's `confirmed`, which adds
    /// the watch fact but never replaces this password fact.
    pub password_confirms: bool,
    /// Which gate file this process is, as the executed file says.
    ///
    /// Never read from `argv[0]`: the caller chooses that. `Nopass` skips the
    /// password half of a confirmation and so asks for more, not less: see
    /// [`ModeRefusal`] and [`decide`].
    pub mode: GateMode,
    /// Whether the caller's live uid is a registered agent account.
    ///
    /// Read by the gate from the registry and `/etc/passwd`, whatever class
    /// the lineage gave: a process of the account that left its scope reads
    /// as a human, and the password it passed PAM with is not a human's.
    pub caller_is_agent_account: bool,
}

/// How loudly a refusal should be reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// A dry-run operation: listed, nothing removed.
    Low,
    /// An ordinary refusal: a policy denial, a race, an expiry.
    Normal,
    /// A refusal that only happens when someone is trying something.
    High,
}

impl Severity {
    /// The label recorded in the audit trail.
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

/// Why the gate will not execute.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// There is no pending request for this caller.
    #[error(
        "no pending request for pid {pid}: the gate executes only what the broker minted, and \
         nothing was minted for this caller"
    )]
    NoPendingRequest {
        /// The pid that invoked the gate.
        pid: u32,
    },
    /// The entry exists but cannot be acted on.
    #[error("pending request rejected: {0}")]
    Request(#[from] RequestError),
    /// Root's ruleset does not permit this.
    #[error("policy denied: {}", denial_of(_0))]
    Policy(Box<Decision>),
    /// The rule demands a confirmation the entry does not carry.
    #[error(
        "action requires a human approval that this request does not carry, and the gate has no \
         channel to ask on"
    )]
    ConfirmationMissing(Box<Decision>),
    /// The entry does not belong to the gate file that is running it.
    #[error("the {mode} gate refuses this entry: {reason}")]
    Mode {
        /// Which gate file ran.
        mode: &'static str,
        /// Which requirement failed.
        reason: ModeRefusal,
    },
    /// The account is over the `-nopass` ceiling: nothing ran and nothing was
    /// queued.
    ///
    /// `suppressed` is `Some(n)` for the one refusal a minute that is written
    /// to the audit trail, and `n` is how many refusals the record stands for.
    /// Every other refusal over the ceiling is `None` and writes nothing, so
    /// an agent that floods the door cannot fill the trail every gate needs.
    #[error("the -nopass ceiling is reached: {minute} runs in the last minute, {hour} in the hour")]
    RateCeiling {
        /// Invocations counted in the last minute.
        minute: usize,
        /// Invocations counted in the last hour.
        hour: usize,
        /// What the audit record stands for, when this one is written.
        suppressed: Option<u64>,
    },
    /// A `remove-path` walk would have followed a symbolic link or crossed a
    /// mount: someone planted it in the tree. Nothing was removed.
    #[error("the remove-path walk refused an escape: {reason}")]
    WalkEscape {
        /// What the walk met. Display only.
        reason: &'static str,
    },
    /// The gate could not do one of the steps that come before or after the
    /// decision, and so did not run anything.
    ///
    /// Not a statement about the request: a host that cannot mark its
    /// descriptors, a rules directory that fails the trust walk, an audit trail
    /// that will not take the record. Each is a refusal, because the gate's
    /// alternative to a step it could not take is running something as root
    /// without it.
    #[error("the gate could not {stage}: {reason}")]
    Failed {
        /// Which step.
        stage: Stage,
        /// Why, in words. Display only.
        reason: String,
    },
}

/// Which requirement of the gate file's mode an entry failed.
///
/// `-auth` requires an `auth` entry. `-nopass` requires, all together: a
/// `harness` entry, a stored and a live class that are both an enrolled
/// agent, the live label equal to the label the entry was minted for, and a
/// decision that is a plain `Allow` with a harness grant: an
/// `AllowWithConfirmation` is refused whatever `confirmed` says, because no
/// password was asked for and none may be assumed. Every one is a refusal at
/// high severity: none happens unless someone is trying the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModeRefusal {
    /// The entry's `via` is not the one this gate file runs.
    #[error("the entry was minted for the other gate file")]
    WrongVia,
    /// The stored or the live class is not an enrolled agent.
    #[error("the caller is not a live enrolled agent")]
    NotAnEnrolledAgent,
    /// The live label is not the one the entry was minted for.
    #[error("the live harness label is not the one the entry was minted for")]
    LabelDiffers,
    /// The ruleset does not grant this command to this harness without a
    /// confirmation.
    #[error("no rule grants this command to this harness without a password")]
    NotGranted,
    /// A live enrolled agent reached `-auth` with no broker-recorded human
    /// approval: a password typed through sudo is not one, because the agent
    /// is in the group that may run `-auth` and PAM is not the boundary.
    #[error("an enrolled agent cannot pass the password gate without a recorded human approval")]
    AgentWithoutApproval,
}

impl ModeRefusal {
    /// The stable code recorded in the audit trail.
    pub fn code(self) -> &'static str {
        match self {
            Self::WrongVia => "gate_mode_wrong_via",
            Self::NotAnEnrolledAgent => "gate_mode_not_an_enrolled_agent",
            Self::LabelDiffers => "gate_mode_label_differs",
            Self::NotGranted => "gate_mode_not_granted",
            Self::AgentWithoutApproval => "gate_mode_agent_without_approval",
        }
    }
}

/// The steps of the gate's sequence that can fail without the request being at
/// fault, in the order the gate takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Mark every inherited descriptor close-on-exec.
    Descriptors,
    /// Replace closed standard streams with `/dev/null`.
    Streams,
    /// Reset every resource limit from PID 1, then set umask `022` and cwd `/`.
    CallerState,
    /// Forbid gaining privilege by exec.
    Privileges,
    /// Accept the invocation: no arguments, and the one name that runs.
    Invocation,
    /// Open `/proc` and prove it is procfs.
    Procfs,
    /// Walk the lineage above the gate.
    Lineage,
    /// Load the root-owned ruleset.
    Rules,
    /// Read the boottime clock.
    Clock,
    /// Open, list, or consume the spool.
    Spool,
    /// Open, judge, and hash the program.
    Program,
    /// Write the authorization to the audit trail.
    Audit,
    /// Build the exec vector and exec.
    Exec,
    /// Load and parse the root-owned configuration.
    Config,
    /// Count the invocation in the `-nopass` rate ledger.
    Ledger,
}

impl Stage {
    /// What the gate could not do, as the end of "the gate could not ...".
    pub fn describe(self) -> &'static str {
        match self {
            Self::Descriptors => "mark its inherited descriptors close-on-exec",
            Self::Streams => "settle its standard streams",
            Self::CallerState => "reset its resource limits and caller state",
            Self::Privileges => "forbid new privileges",
            Self::Invocation => "accept this invocation",
            Self::Procfs => "verify /proc",
            Self::Lineage => "walk its lineage",
            Self::Rules => "load the root-owned ruleset",
            Self::Config => "load the root-owned configuration",
            Self::Clock => "read the boottime clock",
            Self::Spool => "use the spool",
            Self::Program => "open the program",
            Self::Audit => "record the authorization",
            Self::Exec => "execute the program",
            Self::Ledger => "count this invocation in the rate ledger",
        }
    }

    /// The stable code recorded in the audit trail.
    pub fn code(self) -> &'static str {
        match self {
            Self::Descriptors => "gate_failed_descriptors",
            Self::Streams => "gate_failed_streams",
            Self::CallerState => "gate_failed_caller_state",
            Self::Privileges => "gate_failed_privileges",
            Self::Invocation => "gate_failed_invocation",
            Self::Procfs => "gate_failed_procfs",
            Self::Lineage => "gate_failed_lineage",
            Self::Rules => "gate_failed_rules",
            Self::Config => "gate_failed_config",
            Self::Clock => "gate_failed_clock",
            Self::Spool => "gate_failed_spool",
            Self::Program => "gate_failed_program",
            Self::Audit => "gate_failed_audit",
            Self::Exec => "gate_failed_exec",
            Self::Ledger => "gate_failed_ledger",
        }
    }

    /// How loudly a failure at this step is reported.
    ///
    /// High where a step only fails when somebody is making it: an invocation
    /// that is not the one `sudo` makes, a spool or a program that is not what
    /// the broker and the operator left. A host that cannot take a step is
    /// ordinary.
    pub fn severity(self) -> Severity {
        match self {
            Self::Invocation | Self::Spool | Self::Program | Self::Ledger => Severity::High,
            _ => Severity::Normal,
        }
    }
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.describe())
    }
}

impl Refusal {
    /// The stable code recorded in the audit trail.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoPendingRequest { .. } => "gate_no_pending_request",
            Self::Request(error) => error.code(),
            Self::Policy(decision) => decision
                .denial
                .map_or("gate_policy_denied", DenialCode::as_str),
            Self::ConfirmationMissing(_) => "gate_confirmation_missing",
            Self::Mode { reason, .. } => reason.code(),
            Self::RateCeiling { .. } => "gate_rate_ceiling",
            Self::WalkEscape { .. } => "gate_walk_escape",
            Self::Failed { stage, .. } => stage.code(),
        }
    }

    /// How loudly to report it.
    ///
    /// High for anything that does not happen by accident. An expired or
    /// superseded request is the one genuinely ordinary case in this enum: it is
    /// what a slow human or a policy edit produces.
    pub fn severity(&self) -> Severity {
        match self {
            Self::Request(RequestError::Expired { .. } | RequestError::StaleGeneration { .. })
            | Self::Policy(_) => Severity::Normal,
            Self::Failed { stage, .. } => stage.severity(),
            Self::NoPendingRequest { .. }
            | Self::Request(_)
            | Self::ConfirmationMissing(_)
            | Self::RateCeiling { .. }
            | Self::WalkEscape { .. }
            | Self::Mode { .. } => Severity::High,
        }
    }

    /// The exit status the gate leaves with.
    ///
    /// Never zero: nothing ran, so a success status would be a lie to the
    /// caller's script. 17, 18 and 19 are `xudo`'s reserved refusal codes, but
    /// the gate execs in place, so a child that exits 17, 18 or 19 cannot be
    /// told from a refusal by status alone. The refusal line on standard error
    /// is the distinguishing signal, and the front-end must use it.
    ///
    /// The rate ceiling is 19 and not 17 on purpose: 17 is "policy decided no
    /// to this command", a final answer a script gives up on, while the
    /// ceiling says nothing about the command and passes with the clock, which
    /// is what 19 ("could not operate now") already means.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Policy(_) => ExitCode::Denied,
            Self::ConfirmationMissing(_) => ExitCode::NotConfirmed,
            Self::NoPendingRequest { .. }
            | Self::Request(_)
            | Self::Mode { .. }
            | Self::RateCeiling { .. }
            | Self::WalkEscape { .. }
            | Self::Failed { .. } => ExitCode::Unusable,
        }
    }
}

/// Renders a decision's denial for the error message.
fn denial_of(decision: &Decision) -> &'static str {
    decision
        .denial
        .map_or("no reason recorded", DenialCode::as_str)
}

/// What the gate will run, once it has decided it may.
///
/// Holds no `Decision` and no request: by the time this exists, every question
/// has been answered, and carrying the inputs forward invites a later change to
/// re-read one of them instead of trusting the answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Approved {
    /// The absolute program, as **the ruleset spells it** — not as the request
    /// did. The two were compared; this is the copy that was authorized.
    pub program: String,
    /// The canonicalized operands, rendered for the audit record.
    ///
    /// Display only: a record is text. What the kernel is handed is
    /// [`Self::exec_argv`].
    pub argv: Vec<String>,
    /// The canonicalized operands as the bytes the kernel will be given.
    ///
    /// The exec vector is built from these, never from [`Self::argv`], which
    /// came through a renderer that escapes: the program must receive exactly
    /// the bytes the matcher accepted.
    pub exec_argv: Vec<Vec<u8>>,
    /// The complete environment for the child.
    pub environment: Vec<String>,
    /// The action whose requirement governed the decision: of every action
    /// that accepts this command, the strictest. This is the rule that
    /// authorized the command, and the one an audit record must cite.
    pub action: String,
    /// Where the governing rule lives, as `file:line`.
    pub rule_source: String,
    /// The action the request named. The caller's choice, relayed by the
    /// broker; it differs from [`Self::action`] when a stricter rule accepts
    /// the same command, and is recorded beside it, never instead of it.
    pub requested_action: String,
    /// Where the requested action's rule lives, as `file:line`.
    pub requested_rule_source: String,
    /// The nonce to consume before executing.
    ///
    /// Carried so the caller cannot forget: consuming it is what makes the grant
    /// one-use, and a grant that is not consumed is a grant that can be replayed.
    pub nonce: String,
}

/// What the record of this approval must say: the program the ruleset spells
/// and the operands, and the action that governed. `xudo_sys::authorize`
/// refuses a record that says otherwise, and [`authorization_record`] builds
/// its `argv` from here, so the two cannot drift.
impl Approval for Approved {
    fn command(&self) -> Vec<String> {
        let mut argv = vec![self.program.clone()];
        argv.extend(self.argv.iter().cloned());
        argv
    }

    fn action(&self) -> &str {
        &self.action
    }
}

/// Decides whether the gate may execute, and exactly what.
///
/// # Errors
///
/// A [`Refusal`]. Every path that is not an explicit authorization returns one —
/// there is no fallthrough, and no error that means "proceed".
pub fn decide(
    rules: &RuleSet,
    caller: &GateCaller,
    pending: Option<&PendingRequest>,
    context: GateContext,
) -> Result<Approved, Refusal> {
    let Some(pending) = pending else {
        return Err(Refusal::NoPendingRequest {
            pid: caller.pin.pid,
        });
    };
    validate_pending_identity(pending, caller, &context)?;

    let action_id = ActionId::new(pending.action.clone());
    let request = Request::for_program(
        action_id.clone(),
        pending.program.as_str(),
        Argv::new(pending.argv.iter().map(String::as_str)),
    );

    // The gate looks the action up itself, before evaluating, rather than
    // reading the program and provenance off the decision afterwards. Two
    // reasons, and only the second is about types:
    //
    // * The program it execs then comes from the ruleset it read, not from a
    //   field on a `Decision` that some other code path could have filled in.
    // * A rule that exists has an `exe` and a `Source`, both non-optional. So
    //   there is no "permitted but nothing to run" branch here to leave
    //   untested and unreasoned-about.
    let Some(action) = rules.get(&action_id) else {
        return Err(Refusal::Policy(Box::new(Decision::deny(
            DenialCode::UnknownAction,
            canonical_argv(&request),
            Vec::new(),
        ))));
    };

    let decision = engine::evaluate(rules, &caller.facts, &request, context.settings);

    check_verdict(&decision, pending, &context)?;
    // After the verdict, so a denial or a freeze still names its own reason.
    require_human_for_agent(caller, pending, &context)?;

    // The engine cites the governing action on every allowing decision. The
    // defaults are the requested action, eagerly built, so there is no arm
    // here that only a broken engine could reach.
    let governing_action = decision
        .action
        .as_ref()
        .map_or(action.id.as_str(), ActionId::as_str)
        .to_owned();
    let governing_source = decision
        .rule_source
        .as_ref()
        .map_or(action.source.to_string(), ToString::to_string);

    Ok(Approved {
        // The rule's spelling, not the request's. `evaluate` compared the two
        // byte-for-byte and denied `ExeMismatch` on any difference, and every
        // action that accepts the command names the same program, so this is
        // the same bytes — taken from the copy that carries authority.
        program: action.exe.clone(),
        exec_argv: request
            .argv
            .canonicalize()
            .as_slice()
            .iter()
            .map(|arg| arg.as_bytes().to_vec())
            .collect(),
        argv: decision.resolved_argv,
        environment: child_environment(),
        action: governing_action,
        rule_source: governing_source,
        requested_action: action.id.as_str().to_owned(),
        requested_rule_source: action.source.to_string(),
        nonce: pending.nonce.clone(),
    })
}

/// Validate common spool-entry invariants on every gate path, including typed
/// operations which do not pass through the ordinary action decision.
pub(crate) fn validate_pending_identity(
    pending: &PendingRequest,
    caller: &GateCaller,
    context: &GateContext,
) -> Result<(), Refusal> {
    pending.validate(caller.pin, context.generation, context.now)?;
    require_mode(pending, caller, context)?;
    if !pending.live_attested_identity_matches(
        &caller.attested_class,
        caller.attested_scope_id,
        caller.boot_id.as_deref(),
    ) {
        return Err(Refusal::Request(RequestError::WrongAttestedIdentity));
    }
    Ok(())
}

/// Whether the verdict lets the gate file that is running proceed.
///
/// `-auth` proceeds on an `Allow`, and on an `AllowWithConfirmation` that the
/// entry's confirmation satisfies. `-nopass` proceeds only on a plain `Allow`
/// that names a harness grant: no password was asked for, so a confirmation
/// requirement is refused whatever `confirmed` says, and an `Allow` with no
/// grant (a human's `confirm = "never"`) is refused too.
fn check_verdict(
    decision: &Decision,
    pending: &PendingRequest,
    context: &GateContext,
) -> Result<(), Refusal> {
    match (context.mode, decision.verdict) {
        (_, Verdict::Deny) => Err(Refusal::Policy(Box::new(decision.clone()))),
        (GateMode::Nopass, Verdict::Allow) if decision.harness_grant.is_some() => Ok(()),
        (GateMode::Nopass, _) => Err(mode_refusal(context.mode, ModeRefusal::NotGranted)),
        // A confirmation requirement the entry does not satisfy is a refusal
        // here even though the front-end may already have shown a prompt: the
        // gate's evidence that a human approved is the broker's record, and
        // there isn't one.
        (GateMode::Auth, Verdict::AllowWithConfirmation)
            if !confirmation_satisfied(pending, context) =>
        {
            Err(Refusal::ConfirmationMissing(Box::new(decision.clone())))
        }
        (GateMode::Auth, Verdict::Allow | Verdict::AllowWithConfirmation) => Ok(()),
    }
}

/// The agent account is in `xudo`, so it can reach `-auth`: whatever PAM does
/// with a password, only the broker's record of a human's decision lets a live
/// enrolled agent, or any process of an agent's account, through the password
/// gate.
fn require_human_for_agent(
    caller: &GateCaller,
    pending: &PendingRequest,
    context: &GateContext,
) -> Result<(), Refusal> {
    if context.mode == GateMode::Auth
        && (caller.facts.classification.is_enrolled_agent() || context.caller_is_agent_account)
        && !pending.confirmed
    {
        return Err(mode_refusal(
            context.mode,
            ModeRefusal::AgentWithoutApproval,
        ));
    }
    Ok(())
}

/// The refusal for an entry that does not belong to the running gate file.
pub(crate) fn mode_refusal(mode: GateMode, reason: ModeRefusal) -> Refusal {
    Refusal::Mode {
        mode: match mode {
            GateMode::Auth => "-auth",
            GateMode::Nopass => "-nopass",
        },
        reason,
    }
}

/// What the gate file that is running requires of the entry, before the
/// decision is made.
///
/// `-auth` runs only an `auth` entry. `-nopass` runs only a `harness` entry
/// for a caller that is, on the gate's own reading, a live enrolled agent
/// whose label is the one the broker minted the entry for. The grant itself
/// is [`decide`]'s: it needs the decision.
fn require_mode(
    pending: &PendingRequest,
    caller: &GateCaller,
    context: &GateContext,
) -> Result<(), Refusal> {
    let outcome = match context.mode {
        GateMode::Auth if pending.via == Via::Auth => Ok(()),
        GateMode::Auth => Err(ModeRefusal::WrongVia),
        GateMode::Nopass => require_live_harness(pending, caller),
    };
    outcome.map_err(|reason| mode_refusal(context.mode, reason))
}

/// The `-nopass` half of [`require_mode`].
fn require_live_harness(pending: &PendingRequest, caller: &GateCaller) -> Result<(), ModeRefusal> {
    if pending.via != Via::Harness {
        return Err(ModeRefusal::WrongVia);
    }
    let (AttestedClass::EnrolledAgent { .. }, AttestedClass::EnrolledAgent { .. }) =
        (&pending.attested_class, &caller.attested_class)
    else {
        return Err(ModeRefusal::NotAnEnrolledAgent);
    };
    let Classification::EnrolledAgent { agent_id, .. } = &caller.facts.classification else {
        return Err(ModeRefusal::NotAnEnrolledAgent);
    };
    if pending.attested_harness.as_deref() != Some(agent_id.as_str()) {
        return Err(ModeRefusal::LabelDiffers);
    }
    Ok(())
}

fn confirmation_satisfied(pending: &PendingRequest, context: &GateContext) -> bool {
    if context.settings.confirm_human_path {
        pending.confirmed && context.password_confirms
    } else {
        pending.confirmed || context.password_confirms
    }
}

/// The canonical operands of a request, rendered for a decision envelope.
fn canonical_argv(request: &Request) -> Vec<String> {
    request
        .argv
        .canonicalize()
        .as_slice()
        .iter()
        .map(Arg::display)
        .collect()
}

/// The audit record for a refusal.
///
/// Emitted by the gate itself, independently of the broker, so that a direct
/// invocation which never touched the front-end still leaves a trace. The
/// caller's *claim* about its own classification is recorded as evidence beside
/// the gate's own attestation, because "it claimed to be an enrolled agent and
/// the claim carried no weight" is the sentence an investigator needs.
pub fn refusal_record(
    previous: Option<&Record>,
    refusal: &Refusal,
    caller: &GateCaller,
    pending: Option<&PendingRequest>,
) -> Record {
    let argv = pending.map(request_argv).unwrap_or_default();
    let mut evidence = vec![
        format!("severity={}", refusal.severity().label()),
        format!("gate_caller_pid={}", caller.pin.pid),
    ];
    if let Some(pending) = pending {
        evidence.push(format!(
            "claimed_classification={}",
            pending.claimed_classification
        ));
        evidence.push(format!("nonce={}", pending.nonce));
    }
    // What the gate could not do, and why, in the operating system's words:
    // the code says which step, and this says what the step reported.
    // A walk escape names what the walk met, the same way.
    let detail = match refusal {
        Refusal::Failed { reason, .. } => Some(reason.as_str()),
        Refusal::WalkEscape { reason } => Some(*reason),
        _ => None,
    };
    if let Some(reason) = detail {
        evidence.push(format!(
            "detail={}",
            reason
                .chars()
                .take(FAILURE_REASON_CHARS)
                .collect::<String>()
        ));
    }
    if let Refusal::RateCeiling {
        minute,
        hour,
        suppressed,
    } = refusal
    {
        evidence.push(format!("ledger_minute={minute} ledger_hour={hour}"));
        if let Some(count) = suppressed {
            evidence.push(format!("suppressed={count}"));
        }
    }
    if let Refusal::Policy(decision) | Refusal::ConfirmationMissing(decision) = refusal
        && let Some(id) = deciding_deny_rule_id(decision)
    {
        evidence.push(format!("deny_rule_id={id}"));
    }

    Record::after(
        previous,
        AuditDecision::Denied,
        argv,
        caller.facts.classification.label(),
    )
    .with_denial(refusal.code())
    .with_evidence(evidence)
    .with_outcome(Outcome::NotExecuted)
}

fn deciding_deny_rule_id(decision: &Decision) -> Option<&str> {
    decision.trace.iter().find_map(|step| match step {
        xudo_policy::TraceStep::DenyRulesEvaluated { matched } => {
            matched.first().map(|rule| rule.id.as_str())
        }
        _ => None,
    })
}

/// The audit record for an authorization, before the child runs.
///
/// Written *before* execution. The order matters: a record written only after
/// the child exits is a record that a crash — or a kill — erases, which loses
/// exactly the events worth keeping. The log is append-only
/// (`xudo_sys::AuditSink`), so an outcome learnt afterwards is a second record
/// naming this one, never an edit of it.
pub fn authorization_record(
    previous: Option<&Record>,
    approved: &Approved,
    caller: &GateCaller,
    confirmed_by: Option<&str>,
) -> Record {
    let argv = approved.command();

    let mut evidence = vec![format!("gate_caller_pid={}", caller.pin.pid)];
    if let Some(channel) = confirmed_by {
        evidence.push(format!("confirmed_by={channel}"));
    }
    // The rule cited is the one that governed. When the caller named a
    // different action that accepts the same command, that name is evidence:
    // "asked for the quiet duplicate, governed by the confirming rule" is what
    // an investigator needs to read.
    if approved.requested_action != approved.action {
        evidence.push(format!(
            "requested_action={} at {}",
            approved.requested_action, approved.requested_rule_source
        ));
    }
    // Bound to the spool nonce before the verdict is chosen, so a queued run
    // can require this record and no other allow.
    evidence.push(format!("nonce={}", approved.nonce));

    let decision = if confirmed_by.is_some() {
        AuditDecision::AwaitingConfirmation
    } else {
        AuditDecision::Allowed
    };

    Record::after(
        previous,
        decision,
        argv,
        caller.facts.classification.label(),
    )
    .with_rule(&approved.action, &approved.rule_source)
    .with_evidence(evidence)
    .with_outcome(Outcome::NotExecuted)
}

/// The audit record for an exec that failed after its authorization was
/// written.
///
/// The log is append-only, so the failure is a record of its own naming the
/// authorization it follows. It carries the outcome the authorization could
/// not know: the command was allowed, and did not start. `reason` is cut to a
/// bounded length, because it is an operating system's account of a failure
/// and the record is a line in a log.
pub fn exec_failure_record(
    previous: Option<&Record>,
    approved: &Approved,
    caller: &GateCaller,
    authorization_seq: u64,
    reason: &str,
) -> Record {
    Record::after(
        previous,
        AuditDecision::Allowed,
        approved.command(),
        caller.facts.classification.label(),
    )
    .with_rule(&approved.action, &approved.rule_source)
    .with_evidence(vec![
        format!("authorization_seq={authorization_seq}"),
        format!("gate_caller_pid={}", caller.pin.pid),
    ])
    .with_outcome(Outcome::Failed {
        reason: reason.chars().take(FAILURE_REASON_CHARS).collect(),
    })
}

/// The longest failure reason a record carries.
const FAILURE_REASON_CHARS: usize = 200;

/// The request's command as one argv, program first.
fn request_argv(pending: &PendingRequest) -> Vec<String> {
    let mut argv = vec![pending.program.clone()];
    argv.extend(pending.argv.iter().cloned());
    argv
}

/// Whether a decision demanded confirmation, for the caller's reporting.
pub fn demanded_confirmation(decision: &Decision) -> bool {
    matches!(decision.confirm, Confirm::Required { .. })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use xudo_policy::{Classification, Hint, HintSource};

    use super::*;
    use crate::request::{BoottimeMillis, REQUEST_SCHEMA_VERSION};

    const NONCE: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const GENERATION: u64 = 12;

    /// The gate's view of root's ruleset.
    ///
    /// Deliberately parsed from TOML rather than built from structs: the gate
    /// must agree with the file format that actually ships, and a struct literal
    /// would let a rename drift past this test.
    fn rules() -> RuleSet {
        RuleSet::from_toml(
            "test-rules.toml",
            r#"
[[action]]
id = "xudo.svc.status"
tier = "diag-read"
exe = "/usr/bin/systemctl"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "verb", matcher = { literal = "status" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "xudo.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "xudo.always.confirms"
tier = "svc-control"
exe = "/usr/bin/systemctl"
confirm = "always"
args = [
  { name = "verb", matcher = { literal = "daemon-reload" } },
]

[[action]]
id = "xudo.human.only"
tier = "svc-control"
exe = "/usr/bin/systemctl"
agent-allowed = false
args = [
  { name = "verb", matcher = { literal = "stop" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#,
        )
        .unwrap()
    }

    fn package_protection_rules() -> RuleSet {
        RuleSet::from_toml(
            "00-protect.toml",
            r#"
[[action]]
id = "xudo.pkg.remove"
tier = "pkg-remove"
exe = "/usr/bin/apt-get"
args = [
  { name = "verb", matcher = { literal = "remove" } },
  { name = "separator", matcher = { literal = "--" } },
  { name = "pkg", matcher = { name = "deb-name-literal" }, repeat = { between = { min = 1, max = 10 } } },
]

[[deny]]
id = "xudo.protect.pkg-remove"
reason = "protected package"
program = ["apt-get"]
all = [
  { any-arg = ["remove", "purge", "autoremove", "autopurge"] },
  { any-deb-name = ["xudo", "sudo"] },
]
"#,
        )
        .unwrap()
    }

    fn agent(pid: u32) -> GateCaller {
        GateCaller {
            pin: CallerPin::new(pid, 555),
            facts: CallerFacts::new(
                Classification::EnrolledAgent {
                    agent_id: "claude-code".into(),
                    session_id: "s-9".into(),
                    declared_yolo: false,
                },
                1000,
            ),
            attested_class: crate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }

    fn human(pid: u32) -> GateCaller {
        GateCaller {
            pin: CallerPin::new(pid, 555),
            facts: CallerFacts::new(Classification::Human, 1000),
            // What the gate attests of anyone until E6, and what these entries carry.
            attested_class: crate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }

    fn context() -> GateContext {
        GateContext {
            generation: GENERATION,
            now: BoottimeMillis(100),
            settings: engine::Settings::default(),
            password_confirms: false,
            mode: GateMode::Auth,
            caller_is_agent_account: false,
        }
    }

    fn request(pid: u32, action: &str, argv: &[&str]) -> PendingRequest {
        PendingRequest {
            schema_version: REQUEST_SCHEMA_VERSION,
            nonce: NONCE.to_owned(),
            caller_pid: pid,
            caller_starttime: 555,
            action: action.to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            generation: GENERATION,
            deadline: BoottimeMillis(200),
            confirmed: false,
            confirmed_by: None,
            state: crate::request::ConfirmationState::Pending,
            caller_uid: 1000,
            caller_sid: 10,
            caller_tty: 20,
            needs_watch: false,
            shown_at_ms: None,
            shown_to: None,
            fingerprint: "0".repeat(64),
            claimed_classification: "enrolled-agent".to_owned(),
            attested_class: crate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
            attested_harness: None,
            via: crate::request::Via::Auth,
            queue_id: None,
            operation: None,
        }
    }

    fn status_request(pid: u32) -> PendingRequest {
        request(
            pid,
            "xudo.svc.status",
            &["--no-pager", "status", "nginx.service"],
        )
    }

    /// The decision a refusal carries, if it carries one.
    ///
    /// A helper rather than a destructure in each test: both arms run here, so
    /// neither the match nor its failure path is a region only a broken test
    /// could reach. A `let ... else { panic!() }` in a test leaves exactly that.
    fn refused_decision(refusal: &Refusal) -> Option<&Decision> {
        match refusal {
            Refusal::Policy(decision) | Refusal::ConfirmationMissing(decision) => Some(decision),
            Refusal::NoPendingRequest { .. }
            | Refusal::Request(_)
            | Refusal::Mode { .. }
            | Refusal::RateCeiling { .. }
            | Refusal::WalkEscape { .. }
            | Refusal::Failed { .. } => None,
        }
    }

    #[test]
    fn denies_a_direct_invocation_with_nothing_to_act_on() {
        // The expected shape of a hostile call: every member of the `xudo` group
        // may run the gate through sudo, so "no pending request" is not an
        // internal error, it is the common case and it must be a refusal.
        let refusal = decide(&rules(), &agent(77), None, context()).unwrap_err();
        assert_eq!(refusal, Refusal::NoPendingRequest { pid: 77 });
        assert_eq!(refusal.code(), "gate_no_pending_request");
        assert_eq!(refusal.severity(), Severity::High);
        assert_eq!(refusal.exit_code(), ExitCode::Unusable);
        // Nothing was evaluated, so there is no decision to describe.
        assert!(refused_decision(&refusal).is_none());
    }

    #[test]
    fn a_permitted_action_names_the_rules_program_not_the_requests() {
        let approved = decide(&rules(), &human(77), Some(&status_request(77)), context()).unwrap();
        assert_eq!(approved.program, "/usr/bin/systemctl");
        assert_eq!(approved.argv, ["--no-pager", "status", "nginx.service"]);
        assert_eq!(approved.action, "xudo.svc.status");
        assert_eq!(approved.rule_source, "test-rules.toml:3");
        assert_eq!(approved.nonce, NONCE);
        assert_eq!(approved.environment, child_environment());
    }

    #[test]
    fn the_gate_refuses_what_a_deny_rule_matches() {
        let mut pending = request(77, "xudo.pkg.remove", &["remove", "--", "xudo"]);
        pending.program = "/usr/bin/apt-get".to_owned();
        let refusal = decide(
            &package_protection_rules(),
            &human(77),
            Some(&pending),
            context(),
        )
        .unwrap_err();
        assert_eq!(refusal.code(), "deny_rule");
        let decision = refused_decision(&refusal).unwrap();
        assert_eq!(decision.denial, Some(DenialCode::DenyRule));
        assert!(
            decision.trace.iter().any(|step| matches!(step,
                xudo_policy::TraceStep::DenyRulesEvaluated { matched }
                    if matched.iter().any(|rule| rule.id.as_str() == "xudo.protect.pkg-remove")
            )),
            "the gate's decision did not cite the shipped rule: {:?}",
            decision.trace
        );
        let record = refusal_record(None, &refusal, &human(77), Some(&pending));
        assert!(
            record
                .evidence
                .contains(&"deny_rule_id=xudo.protect.pkg-remove".to_owned())
        );
    }

    #[test]
    fn a_confirmation_refusal_record_carries_no_deny_rule_id() {
        let refusal = Refusal::ConfirmationMissing(Box::new(Decision::deny(
            DenialCode::ArgvRejected,
            vec!["x".to_owned()],
            Vec::new(),
        )));
        let record = refusal_record(None, &refusal, &human(77), None);
        assert!(
            !record
                .evidence
                .iter()
                .any(|item| item.starts_with("deny_rule_id=")),
            "a confirmation refusal has no deciding deny rule: {:?}",
            record.evidence
        );
    }

    #[test]
    fn a_deny_rule_added_after_mint_makes_the_entry_stale() {
        let mut pending = request(77, "xudo.pkg.remove", &["remove", "--", "xudo"]);
        pending.program = "/usr/bin/apt-get".to_owned();
        let mut after_rule_change = context();
        after_rule_change.generation = GENERATION.saturating_add(1);
        let refusal = decide(
            &package_protection_rules(),
            &human(77),
            Some(&pending),
            after_rule_change,
        )
        .unwrap_err();
        assert_eq!(refusal.code(), "request_stale_generation");
    }

    #[test]
    fn a_refused_spool_entry_never_reaches_the_ruleset() {
        // Shape and liveness are settled before policy, so a forged entry cannot
        // provoke a policy *answer* it can learn from.
        let mut pending = status_request(77);
        pending.deadline = BoottimeMillis(50);
        let refusal = decide(&rules(), &human(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "request_expired");
        assert_eq!(refusal.severity(), Severity::Normal);
        assert_eq!(refusal.exit_code(), ExitCode::Unusable);
    }

    #[test]
    fn denies_an_approval_minted_for_another_process_at_high_severity() {
        // A stolen grant and a slow human are both refusals; only one of them
        // means someone is trying something, and the audit sink routes on that.
        let refusal =
            decide(&rules(), &human(78), Some(&status_request(77)), context()).unwrap_err();
        assert_eq!(refusal.code(), "request_wrong_caller");
        assert_eq!(refusal.severity(), Severity::High);
    }

    #[test]
    fn a_superseded_generation_is_an_ordinary_refusal() {
        let mut pending = status_request(77);
        pending.generation = GENERATION.saturating_sub(1);
        let refusal = decide(&rules(), &human(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "request_stale_generation");
        assert_eq!(refusal.severity(), Severity::Normal);
    }

    #[test]
    fn denies_an_action_the_gates_own_ruleset_does_not_define() {
        // The gate looks the action up itself. A front-end that decided against
        // a wider ruleset, or an entry that names an action that was deleted,
        // both land here.
        let pending = request(77, "xudo.svc.enable", &["enable", "nginx.service"]);
        let refusal = decide(&rules(), &human(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "unknown_action");
        assert_eq!(refusal.severity(), Severity::Normal);
        assert_eq!(refusal.exit_code(), ExitCode::Denied);
        assert_eq!(
            refused_decision(&refusal).map(|decision| decision.resolved_argv.as_slice()),
            Some(["enable".to_owned(), "nginx.service".to_owned()].as_slice())
        );
    }

    #[test]
    fn denies_a_program_smuggled_in_under_another_actions_rule() {
        // The entry carries the program as well as the action so that a mismatch
        // is visible *as* a mismatch. Reported as `exe_mismatch`, never folded
        // into an argument complaint, because it is the shape of a bypass.
        let mut pending = status_request(77);
        pending.program = "/bin/sh".to_owned();
        let refusal = decide(&rules(), &human(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "exe_mismatch");
    }

    #[test]
    fn denies_arguments_the_rule_does_not_permit() {
        let pending = request(77, "xudo.svc.restart", &["restart", "nginx.service; sh"]);
        let refusal = decide(&rules(), &human(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "argv_rejected");
        assert_eq!(refusal.exit_code(), ExitCode::Denied);
    }

    #[test]
    fn denies_an_agent_an_action_reserved_for_a_person() {
        let pending = request(77, "xudo.human.only", &["stop", "nginx.service"]);
        assert_eq!(
            decide(&rules(), &agent(77), Some(&pending), context())
                .unwrap_err()
                .code(),
            "human_path_only"
        );
        // Same argv, same rule, a human: permitted. Misclassification may only
        // withhold capability.
        assert!(decide(&rules(), &human(77), Some(&pending), context()).is_ok());
    }

    #[test]
    fn the_gate_cannot_supply_a_confirmation_it_has_no_channel_for() {
        // The gate's every reachable terminal belongs to the process tree that
        // asked, which is exactly where invariant 3 forbids reading an approval.
        // So an unconfirmed entry under a confirming rule is a refusal, not a
        // prompt — and the exit status says "nobody has approved" so the caller
        // can retry once someone has.
        let pending = status_request(77);
        let refusal = decide(&rules(), &agent(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "gate_confirmation_missing");
        assert_eq!(refusal.severity(), Severity::High);
        assert_eq!(refusal.exit_code(), ExitCode::NotConfirmed);
        assert!(refused_decision(&refusal).is_some_and(demanded_confirmation));
    }

    #[test]
    fn a_broker_recorded_approval_lets_the_same_request_through() {
        let mut pending = status_request(77);
        pending.confirmed = true;
        pending.state = crate::request::ConfirmationState::Consumed;
        pending.needs_watch = true;
        pending.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        pending.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        pending.shown_to = pending.confirmed_by.clone();
        let approved = decide(&rules(), &agent(77), Some(&pending), context()).unwrap();
        assert_eq!(approved.action, "xudo.svc.status");
    }

    #[test]
    fn a_rule_that_always_confirms_confirms_a_human_too() {
        let mut pending = request(77, "xudo.always.confirms", &["daemon-reload"]);
        assert_eq!(
            decide(&rules(), &human(77), Some(&pending), context())
                .unwrap_err()
                .code(),
            "gate_confirmation_missing"
        );
        pending.confirmed = true;
        pending.state = crate::request::ConfirmationState::Consumed;
        pending.needs_watch = true;
        pending.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        pending.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        pending.shown_to = pending.confirmed_by.clone();
        assert!(decide(&rules(), &human(77), Some(&pending), context()).is_ok());
    }

    #[test]
    fn the_gate_refuses_a_consumed_entry_whose_caller_left_the_scope() {
        let mut pending = status_request(77);
        pending.confirmed = true;
        pending.state = crate::request::ConfirmationState::Consumed;
        pending.needs_watch = true;
        pending.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        pending.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        pending.shown_to = pending.confirmed_by.clone();
        pending.attested_class = crate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        pending.attested_scope_id = Some(44);
        pending.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        pending.attested_harness = Some("codex".to_owned());
        let caller = GateCaller {
            pin: CallerPin::new(77, 555),
            facts: CallerFacts::new(
                Classification::EnrolledAgent {
                    agent_id: "claude-code".into(),
                    session_id: "s-9".into(),
                    declared_yolo: false,
                },
                1000,
            ),
            attested_class: crate::request::AttestedClass::EnrolledAgent { scope_id: 45 },
            attested_scope_id: Some(45),
            boot_id: Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned()),
        };
        assert_eq!(
            decide(&rules(), &caller, Some(&pending), context())
                .unwrap_err()
                .code(),
            "request_wrong_attested_identity"
        );
    }

    #[test]
    fn the_human_path_runs_while_frozen() {
        let mut ctx = context();
        ctx.settings.frozen = true;
        let pending = status_request(77);
        assert_eq!(
            decide(&rules(), &agent(77), Some(&pending), ctx)
                .unwrap_err()
                .code(),
            "frozen"
        );
        assert!(decide(&rules(), &human(77), Some(&pending), ctx).is_ok());
    }

    #[test]
    fn an_entry_minted_before_freeze_is_refused_by_the_gate_for_an_agent() {
        let minted_before_freeze = status_request(77);
        let mut ctx = context();
        ctx.settings.frozen = true;
        assert_eq!(
            decide(&rules(), &agent(77), Some(&minted_before_freeze), ctx)
                .unwrap_err()
                .code(),
            "frozen"
        );
    }

    #[test]
    fn the_entrys_claim_about_its_own_caller_carries_no_weight() {
        // Invariant 1, at the gate. The entry may claim to be an enrolled agent
        // in yolo mode; the verdict is identical either way, because the gate
        // classifies from its own attestation.
        let mut honest = status_request(77);
        honest.claimed_classification = "human".to_owned();
        let mut lying = status_request(77);
        lying.claimed_classification = "enrolled-agent-yolo".to_owned();

        let a = decide(&rules(), &human(77), Some(&honest), context());
        let b = decide(&rules(), &human(77), Some(&lying), context());
        assert_eq!(a, b);
    }

    #[test]
    fn an_unattested_caller_is_treated_as_a_person_never_as_an_agent() {
        // Invariant 2. Failure to attest must withhold capability, so it routes
        // to the human path — which here means it is *not* subject to the
        // agent-confirmation setting and *is* refused the agent-only widenings.
        let unattested = GateCaller {
            pin: CallerPin::new(77, 555),
            facts: CallerFacts::new(
                Classification::Unattested {
                    reason: "kernel too old for SO_PEERPIDFD".into(),
                },
                1000,
            ),
            attested_class: crate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        };
        let human_only = request(77, "xudo.human.only", &["stop", "nginx.service"]);
        assert!(decide(&rules(), &unattested, Some(&human_only), context()).is_ok());
        assert!(decide(&rules(), &agent(77), Some(&human_only), context()).is_err());
    }

    #[test]
    fn appending_an_argument_can_only_narrow_the_gates_answer() {
        let mut widened = status_request(77);
        assert!(decide(&rules(), &human(77), Some(&widened), context()).is_ok());
        widened.argv.push("--now".to_owned());
        assert!(decide(&rules(), &human(77), Some(&widened), context()).is_err());
    }

    #[test]
    fn every_refusal_reports_a_status_that_cannot_be_mistaken_for_a_child() {
        // Nothing ran, so a status inside a command's own range would be a lie
        // to the caller's script.
        let refusals = [
            Refusal::NoPendingRequest { pid: 1 },
            Refusal::Request(RequestError::MalformedNonce),
            Refusal::Request(RequestError::Expired {
                deadline: 1,
                now: 2,
            }),
            Refusal::Policy(Box::new(Decision::deny(
                DenialCode::DenyListed,
                Vec::new(),
                Vec::new(),
            ))),
            Refusal::ConfirmationMissing(Box::new(Decision::deny(
                DenialCode::NoConfirmationChannel,
                Vec::new(),
                Vec::new(),
            ))),
            Refusal::Request(RequestError::Ambiguous { matches: 2 }),
            Refusal::Request(RequestError::ForgedNonce {
                name: NONCE.to_owned(),
            }),
            Refusal::Failed {
                stage: Stage::Spool,
                reason: "the spool refused".to_owned(),
            },
        ];
        for refusal in &refusals {
            let status = refusal.exit_code().as_i32();
            assert_ne!(status, 0, "{refusal:?} reports success");
            assert_ne!(
                status,
                ExitCode::Delegated.as_i32(),
                "{refusal:?} reports the status that means a child ran"
            );
            assert!(
                (17..128).contains(&status),
                "{refusal:?} reports {status}, which collides with 128+signal"
            );
            assert!(refusal.to_string().len() > 20, "{refusal:?} renders thinly");
            assert!(!refusal.code().is_empty());
        }
    }

    #[test]
    fn a_policy_refusal_with_no_recorded_reason_still_renders() {
        // `Decision.denial` is `Option`, so the rendering must not assume one is
        // present. A refusal that panics while explaining itself is a refusal
        // nobody can act on.
        let mut decision = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        decision.denial = None;
        let refusal = Refusal::Policy(Box::new(decision));
        assert_eq!(refusal.code(), "gate_policy_denied");
        assert!(refusal.to_string().contains("no reason recorded"));
    }

    #[test]
    fn severity_labels_are_the_strings_an_alert_matches_on() {
        assert_eq!(Severity::Low.label(), "low");
        assert_eq!(Severity::Normal.label(), "normal");
        assert_eq!(Severity::High.label(), "high");
    }

    #[test]
    fn a_refusal_record_keeps_the_claim_that_carried_no_weight() {
        // "It claimed to be an enrolled agent and the claim changed nothing" is
        // the sentence an investigator needs, so the claim is evidence in the
        // record beside the gate's own attestation.
        let mut pending = status_request(77);
        pending.claimed_classification = "enrolled-agent-yolo".to_owned();
        let refusal = decide(&rules(), &human(78), Some(&pending), context()).unwrap_err();
        let record = refusal_record(None, &refusal, &human(78), Some(&pending));

        assert_eq!(record.decision, AuditDecision::Denied);
        assert_eq!(record.denial.as_deref(), Some("request_wrong_caller"));
        assert_eq!(record.classification, "human");
        assert_eq!(
            record.argv,
            [
                "/usr/bin/systemctl",
                "--no-pager",
                "status",
                "nginx.service"
            ]
        );
        assert!(record.evidence.contains(&"severity=high".to_owned()));
        assert!(record.evidence.contains(&"gate_caller_pid=78".to_owned()));
        assert!(
            record
                .evidence
                .contains(&"claimed_classification=enrolled-agent-yolo".to_owned())
        );
        assert!(record.evidence.contains(&format!("nonce={NONCE}")));
        assert_eq!(record.outcome, Outcome::NotExecuted);
        assert!(record.is_sealed());
    }

    #[test]
    fn a_direct_invocation_leaves_a_record_even_with_nothing_to_describe() {
        // The whole point of the gate emitting its own trail: a call that never
        // touched the front-end still shows up.
        let refusal = decide(&rules(), &agent(77), None, context()).unwrap_err();
        let record = refusal_record(None, &refusal, &agent(77), None);
        assert_eq!(record.denial.as_deref(), Some("gate_no_pending_request"));
        assert!(record.argv.is_empty());
        assert_eq!(record.classification, "enrolled-agent");
        assert!(record.evidence.contains(&"severity=high".to_owned()));
        assert!(record.is_sealed());
    }

    #[test]
    fn an_authorization_is_recorded_before_the_child_runs() {
        // Written first; an outcome is a later record. A record written only on
        // exit is one that a crash or a kill erases — losing exactly the events
        // worth having.
        let approved = decide(&rules(), &human(77), Some(&status_request(77)), context()).unwrap();
        let record = authorization_record(None, &approved, &human(77), None);

        // The record describes the approval it is for: the binding
        // `xudo_sys::authorize` refuses to write without.
        assert_eq!(record.describes(&approved), Ok(()));
        assert_eq!(record.argv, approved.command());
        assert_eq!(record.decision, AuditDecision::Allowed);
        assert_eq!(record.action.as_deref(), Some("xudo.svc.status"));
        assert_eq!(record.rule_source.as_deref(), Some("test-rules.toml:3"));
        assert_eq!(
            record.argv,
            [
                "/usr/bin/systemctl",
                "--no-pager",
                "status",
                "nginx.service"
            ]
        );
        assert_eq!(record.outcome, Outcome::NotExecuted);
        assert!(record.evidence.contains(&"gate_caller_pid=77".to_owned()));
        assert!(
            record
                .evidence
                .contains(&format!("nonce={}", approved.nonce))
        );
        assert!(record.is_sealed());
    }

    #[test]
    fn a_confirmed_authorization_records_which_channel_approved_it() {
        let mut pending = status_request(77);
        pending.confirmed = true;
        pending.state = crate::request::ConfirmationState::Consumed;
        pending.needs_watch = true;
        pending.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        pending.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        pending.shown_to = pending.confirmed_by.clone();
        let approved = decide(&rules(), &agent(77), Some(&pending), context()).unwrap();
        let record = authorization_record(
            None,
            &approved,
            &agent(77),
            pending
                .confirmed_by
                .as_ref()
                .map(crate::request::WatcherPin::audit_text)
                .as_deref(),
        );

        assert_eq!(record.decision, AuditDecision::AwaitingConfirmation);
        assert!(record.evidence.contains(&format!(
            "confirmed_by=uid=1000,pid=88,starttime=99,tty={},sid=11",
            (136 << 8) | 1
        )));
    }

    #[test]
    fn the_gates_records_chain_onto_the_previous_one() {
        let first = refusal_record(
            None,
            &decide(&rules(), &agent(1), None, context()).unwrap_err(),
            &agent(1),
            None,
        );
        let second = refusal_record(
            Some(&first),
            &decide(&rules(), &agent(2), None, context()).unwrap_err(),
            &agent(2),
            None,
        );
        assert_eq!(second.prev_hash, first.hash);
        assert_eq!(second.seq.get(), first.seq.get().saturating_add(1));
        assert!(second.is_sealed());
    }

    #[test]
    fn hints_recorded_on_the_caller_do_not_move_the_verdict() {
        let mut hinted = human(77);
        hinted.facts = hinted
            .facts
            .with_hint(Hint::new(HintSource::Environment, "CLAUDECODE", "1"))
            .with_hint(Hint::new(HintSource::Comm, "comm", "claude"));
        let pending = status_request(77);
        assert_eq!(
            decide(&rules(), &hinted, Some(&pending), context()),
            decide(&rules(), &human(77), Some(&pending), context())
        );
    }

    /// Rules where two actions accept one command: a confirming rule and a
    /// duplicate that never asks, and a human-only rule and a duplicate open
    /// to agents.
    fn overlapping_rules() -> RuleSet {
        RuleSet::from_toml(
            "overlap-rules.toml",
            r#"
[[action]]
id = "xudo.reload.confirmed"
tier = "svc-control"
exe = "/usr/bin/systemctl"
confirm = "always"
args = [{ name = "verb", matcher = { literal = "daemon-reload" } }]

[[action]]
id = "xudo.reload.quiet"
tier = "svc-control"
exe = "/usr/bin/systemctl"
confirm = "never"
args = [{ name = "verb", matcher = { literal = "daemon-reload" } }]

[[action]]
id = "xudo.stop.by-hand"
tier = "svc-control"
exe = "/usr/bin/systemctl"
agent-allowed = false
args = [
  { name = "verb", matcher = { literal = "stop" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "xudo.stop.open"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "stop" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#,
        )
        .unwrap()
    }

    #[test]
    fn an_entry_naming_a_permissive_duplicate_still_needs_the_stricter_confirmation() {
        // The gate re-decides from root's ruleset, and the action an entry
        // names is the caller's choice relayed by the broker. Naming the
        // duplicate that never asks must not drop the confirmation the other
        // rule demands for the same command.
        let rules = overlapping_rules();
        let mut pending = request(77, "xudo.reload.quiet", &["daemon-reload"]);
        let refusal = decide(&rules, &human(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "gate_confirmation_missing");
        assert_eq!(
            refused_decision(&refusal).and_then(|decision| decision.action.clone()),
            Some(ActionId::new("xudo.reload.confirmed"))
        );
        pending.confirmed = true;
        pending.state = crate::request::ConfirmationState::Consumed;
        pending.needs_watch = true;
        pending.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        pending.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        pending.shown_to = pending.confirmed_by.clone();
        let approved = decide(&rules, &human(77), Some(&pending), context()).unwrap();

        // The authorization cites the rule that demanded the approval, not the
        // permissive one the caller named, and records the name beside it.
        assert_eq!(approved.action, "xudo.reload.confirmed");
        assert_eq!(approved.requested_action, "xudo.reload.quiet");
        assert_ne!(approved.rule_source, approved.requested_rule_source);
        let record = authorization_record(
            None,
            &approved,
            &human(77),
            pending
                .confirmed_by
                .as_ref()
                .map(crate::request::WatcherPin::audit_text)
                .as_deref(),
        );
        assert_eq!(record.action.as_deref(), Some("xudo.reload.confirmed"));
        // And the binding `authorize` checks before writing holds on the
        // governing action, not the requested one.
        assert_eq!(record.describes(&approved), Ok(()));
        assert_eq!(Approval::action(&approved), "xudo.reload.confirmed");
        assert_eq!(
            record.rule_source.as_deref(),
            Some(approved.rule_source.as_str())
        );
        let requested = format!(
            "requested_action=xudo.reload.quiet at {}",
            approved.requested_rule_source
        );
        assert!(
            record.evidence.contains(&requested),
            "{:?}",
            record.evidence
        );
    }

    #[test]
    fn an_authorization_for_the_governing_rule_records_no_requested_duplicate() {
        // Asked under the governing rule's own name, there is nothing beside it
        // to record.
        let rules = overlapping_rules();
        let mut pending = request(77, "xudo.reload.confirmed", &["daemon-reload"]);
        pending.confirmed = true;
        pending.state = crate::request::ConfirmationState::Consumed;
        pending.needs_watch = true;
        pending.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        pending.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        pending.shown_to = pending.confirmed_by.clone();
        let approved = decide(&rules, &human(77), Some(&pending), context()).unwrap();
        assert_eq!(approved.action, approved.requested_action);
        let record = authorization_record(
            None,
            &approved,
            &human(77),
            pending
                .confirmed_by
                .as_ref()
                .map(crate::request::WatcherPin::audit_text)
                .as_deref(),
        );
        assert!(
            !record
                .evidence
                .iter()
                .any(|e| e.starts_with("requested_action=")),
            "{:?}",
            record.evidence
        );
    }

    #[test]
    fn an_entry_naming_an_agent_open_duplicate_cannot_reach_a_human_only_command() {
        let rules = overlapping_rules();
        let pending = request(77, "xudo.stop.open", &["stop", "nginx.service"]);
        assert_eq!(
            decide(&rules, &agent(77), Some(&pending), context())
                .unwrap_err()
                .code(),
            "human_path_only"
        );
        assert!(decide(&rules, &human(77), Some(&pending), context()).is_ok());
    }

    #[test]
    fn a_decision_that_asks_for_nothing_is_not_a_confirmation_requirement() {
        let decision = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        assert!(!demanded_confirmation(&decision));
    }

    #[test]
    fn a_watch_approval_never_stands_in_for_the_password() {
        let rules = overlapping_rules();
        let mut pending = request(77, "xudo.reload.confirmed", &["daemon-reload"]);
        pending.needs_watch = true;
        pending.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        pending.shown_to = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        let watch_required = GateContext {
            settings: engine::Settings {
                confirm_human_path: true,
                ..engine::Settings::default()
            },
            password_confirms: false,
            ..context()
        };
        let refused = decide(&rules, &human(77), Some(&pending), watch_required).unwrap_err();
        assert_eq!(refused.code(), "gate_confirmation_missing");
        // A password is still insufficient when the setting requires a watch.
        let typed = GateContext {
            settings: watch_required.settings,
            password_confirms: true,
            ..watch_required
        };
        assert_eq!(
            decide(&rules, &human(77), Some(&pending), typed)
                .unwrap_err()
                .code(),
            "gate_confirmation_missing"
        );
        let mut watched = pending.clone();
        watched.confirmed = true;
        watched.state = crate::request::ConfirmationState::Consumed;
        watched.needs_watch = true;
        watched.shown_at_ms = Some(crate::request::BoottimeMillis(99));
        watched.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        watched.shown_to = watched.confirmed_by.clone();
        assert_eq!(
            decide(&rules, &human(77), Some(&watched), watch_required)
                .unwrap_err()
                .code(),
            "gate_confirmation_missing"
        );
        let watched_and_typed = GateContext {
            password_confirms: true,
            ..watch_required
        };
        assert!(decide(&rules, &human(77), Some(&watched), watched_and_typed).is_ok());
        // With the channel off, the existing password path remains valid.
        let typed = GateContext {
            password_confirms: true,
            ..context()
        };
        assert!(decide(&rules, &human(77), Some(&pending), typed).is_ok());
        // It does not widen a refusal that is not about confirmation.
        let denied = request(77, "xudo.reload.confirmed", &["daemon-reload", "--now"]);
        assert!(decide(&rules, &human(77), Some(&denied), typed).is_err());
        let expired = GateContext {
            now: BoottimeMillis(300),
            ..typed
        };
        assert_eq!(
            decide(&rules, &human(77), Some(&pending), expired)
                .unwrap_err()
                .code(),
            "request_expired"
        );
    }

    #[test]
    fn the_exec_operands_are_taken_from_bytes_not_from_the_rendering() {
        let approved = decide(&rules(), &human(77), Some(&status_request(77)), context()).unwrap();
        assert_eq!(
            approved.exec_argv,
            [
                b"--no-pager".to_vec(),
                b"status".to_vec(),
                b"nginx.service".to_vec()
            ]
        );
        let rendered: Vec<Vec<u8>> = approved
            .argv
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect();
        assert_eq!(approved.exec_argv, rendered);
    }

    #[test]
    fn every_stage_has_a_distinct_code_and_a_sentence_and_only_tampering_is_high() {
        let stages = [
            Stage::Descriptors,
            Stage::Streams,
            Stage::CallerState,
            Stage::Privileges,
            Stage::Invocation,
            Stage::Procfs,
            Stage::Lineage,
            Stage::Rules,
            Stage::Clock,
            Stage::Spool,
            Stage::Program,
            Stage::Audit,
            Stage::Exec,
            Stage::Config,
            Stage::Ledger,
        ];
        let mut codes: Vec<&str> = stages.iter().map(|stage| stage.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), stages.len(), "two stages share an audit code");
        for stage in stages {
            assert!(stage.code().starts_with("gate_failed_"));
            assert!(stage.describe().len() > 8);
            assert_eq!(stage.to_string(), stage.describe());
            let refusal = Refusal::Failed {
                stage,
                reason: "why".to_owned(),
            };
            assert_eq!(refusal.code(), stage.code());
            assert_eq!(refusal.severity(), stage.severity());
            assert_eq!(refusal.exit_code(), ExitCode::Unusable);
            assert!(refusal.to_string().contains("could not"), "{refusal}");
            let high = matches!(
                stage,
                Stage::Invocation | Stage::Spool | Stage::Program | Stage::Ledger
            );
            assert_eq!(stage.severity() == Severity::High, high, "{stage:?}");
        }
    }

    #[test]
    fn a_refusal_over_the_ceiling_has_its_own_code_and_says_what_it_stands_for() {
        let written = Refusal::RateCeiling {
            minute: 60,
            hour: 61,
            suppressed: Some(17),
        };
        assert_eq!(written.code(), "gate_rate_ceiling");
        assert_eq!(written.severity(), Severity::High);
        assert_eq!(written.exit_code(), ExitCode::Unusable);
        assert!(written.to_string().contains("60 runs in the last minute"));
        let record = refusal_record(None, &written, &GateCaller::unidentified(77), None);
        assert_eq!(record.denial.as_deref(), Some("gate_rate_ceiling"));
        assert!(record.evidence.contains(&"suppressed=17".to_owned()));
        assert!(
            record
                .evidence
                .contains(&"ledger_minute=60 ledger_hour=61".to_owned())
        );
        // A refusal that is not the minute's record has no count to carry.
        let silent = Refusal::RateCeiling {
            minute: 60,
            hour: 61,
            suppressed: None,
        };
        let record = refusal_record(None, &silent, &GateCaller::unidentified(77), None);
        assert!(
            !record
                .evidence
                .iter()
                .any(|line| line.starts_with("suppressed="))
        );
    }

    #[test]
    fn a_failure_record_says_which_step_and_what_it_reported() {
        let refusal = Refusal::Failed {
            stage: Stage::Rules,
            reason: "x".repeat(500),
        };
        let caller = GateCaller::unidentified(77);
        let record = refusal_record(None, &refusal, &caller, None);
        assert_eq!(record.denial.as_deref(), Some("gate_failed_rules"));
        assert_eq!(record.classification, "unattested");
        let detail = record
            .evidence
            .iter()
            .find(|line| line.starts_with("detail="))
            .unwrap();
        // Bounded: a reason is a line in a log.
        assert_eq!(detail.len(), "detail=".len() + FAILURE_REASON_CHARS);
        assert!(record.evidence.contains(&"severity=normal".to_owned()));
        assert_eq!(caller.facts.uid, UNKNOWN_UID);
        assert_eq!(caller.pin, CallerPin::new(0, 0));
    }

    #[test]
    fn an_exec_that_failed_after_its_authorization_is_a_record_naming_it() {
        let approved = decide(&rules(), &human(77), Some(&status_request(77)), context()).unwrap();
        let first = authorization_record(None, &approved, &human(77), None);
        let record = exec_failure_record(Some(&first), &approved, &human(77), 1, &"y".repeat(500));
        assert_eq!(record.seq.get(), 2);
        assert_eq!(record.prev_hash, first.hash);
        assert_eq!(record.action.as_deref(), Some("xudo.svc.status"));
        assert!(record.evidence.contains(&"authorization_seq=1".to_owned()));
        assert_eq!(
            record.outcome,
            Outcome::Failed {
                reason: "y".repeat(FAILURE_REASON_CHARS)
            }
        );
        assert!(!record.outcome.executed());
        assert!(record.describes(&approved).is_ok());
    }

    // ---- the `-nopass` gate file (inert: nothing mints a `harness` entry) ----

    const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";

    fn nopass_context() -> GateContext {
        GateContext {
            mode: GateMode::Nopass,
            password_confirms: false,
            ..context()
        }
    }

    /// A live enrolled agent, as the gate itself reads it.
    fn live_agent(pid: u32, label: &str, scope: u64) -> GateCaller {
        GateCaller {
            pin: CallerPin::new(pid, 555),
            facts: CallerFacts::new(
                Classification::EnrolledAgent {
                    agent_id: label.into(),
                    session_id: "s-9".into(),
                    declared_yolo: false,
                },
                1000,
            ),
            attested_class: AttestedClass::EnrolledAgent { scope_id: scope },
            attested_scope_id: Some(scope),
            boot_id: Some(BOOT.to_owned()),
        }
    }

    /// What the broker would write for a harness grant, once it does.
    fn harness_entry(pid: u32) -> PendingRequest {
        let mut pending = status_request(pid);
        pending.via = Via::Harness;
        pending.attested_class = AttestedClass::EnrolledAgent { scope_id: 44 };
        pending.attested_scope_id = Some(44);
        pending.boot_id = Some(BOOT.to_owned());
        pending.attested_harness = Some("claude-code".to_owned());
        pending
    }

    const GRANT_RULES: &str = r#"
[[action]]
id = "xudo.svc.status"
tier = "diag-read"
exe = "/usr/bin/systemctl"
harness = ["claude-code"]
outcome = "allow"
gtfobins-waiver = "service manager pager escape: the unit is a name matcher and no option can be passed here, so no pager ever runs"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "verb", matcher = { literal = "status" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;

    fn grant_rules() -> RuleSet {
        RuleSet::from_toml("grant.toml", GRANT_RULES).unwrap()
    }

    fn mode_code(result: Result<Approved, Refusal>) -> String {
        let refusal = result.unwrap_err();
        if matches!(refusal, Refusal::Mode { .. }) {
            assert_eq!(refusal.severity(), Severity::High, "{refusal}");
            assert_eq!(refusal.exit_code(), ExitCode::Unusable);
        }
        refusal.code().to_owned()
    }

    #[test]
    fn nopass_refuses_an_auth_entry() {
        // The `-nopass` file never runs what a password was meant to confirm.
        let pending = status_request(77);
        assert_eq!(pending.via, Via::Auth);
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &live_agent(77, "claude-code", 44),
                Some(&pending),
                nopass_context()
            )),
            "gate_mode_wrong_via"
        );
    }

    #[test]
    fn the_auth_gate_refuses_a_harness_entry() {
        // And the password gate never runs an entry minted to skip the password.
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &live_agent(77, "claude-code", 44),
                Some(&harness_entry(77)),
                context()
            )),
            "gate_mode_wrong_via"
        );
    }

    #[test]
    fn auth_refuses_an_enrolled_agent_whose_password_got_through_pam() {
        // The agent account is in `xudo`; if PAM let it pass sudo, the typed
        // password still is not a human approval, so an unconfirmed entry
        // for a live agent is refused even when the gate counts the password.
        for password_confirms in [false, true] {
            let mut ctx = context();
            ctx.password_confirms = password_confirms;
            let mut pending = harness_entry(77);
            pending.via = Via::Auth;
            assert!(!pending.confirmed);
            assert_eq!(
                mode_code(decide(
                    &grant_rules(),
                    &live_agent(77, "claude-code", 44),
                    Some(&pending),
                    ctx
                )),
                "gate_mode_agent_without_approval"
            );
        }
    }

    #[test]
    fn auth_refuses_an_agent_account_process_outside_its_scope() {
        // A crontab job or ssh login of the agent account reads as a human:
        // the uid is what gives it away.
        let mut ctx = context();
        ctx.password_confirms = true;
        ctx.caller_is_agent_account = true;
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &human(77),
                Some(&status_request(77)),
                ctx
            )),
            "gate_mode_agent_without_approval"
        );
        let mut approved = status_request(77);
        approved.confirmed = true;
        let result = decide(&grant_rules(), &human(77), Some(&approved), ctx);
        let refused: Vec<&str> = result
            .as_ref()
            .err()
            .into_iter()
            .map(Refusal::code)
            .collect();
        assert!(!refused.contains(&"gate_mode_agent_without_approval"));
    }

    #[test]
    fn auth_lets_an_enrolled_agent_through_only_with_a_recorded_approval() {
        let mut pending = harness_entry(77);
        pending.via = Via::Auth;
        pending.confirmed = true;
        let result = decide(
            &grant_rules(),
            &live_agent(77, "claude-code", 44),
            Some(&pending),
            context(),
        );
        let refused: Vec<&str> = result
            .as_ref()
            .err()
            .into_iter()
            .map(Refusal::code)
            .collect();
        assert!(!refused.contains(&"gate_mode_agent_without_approval"));
    }

    #[test]
    fn auth_still_runs_a_human_for_whom_the_password_is_the_approval() {
        let mut ctx = context();
        ctx.password_confirms = true;
        let result = decide(&grant_rules(), &human(77), Some(&status_request(77)), ctx);
        let refused: Vec<&str> = result
            .as_ref()
            .err()
            .into_iter()
            .map(Refusal::code)
            .collect();
        assert!(!refused.contains(&"gate_mode_agent_without_approval"));
    }

    #[test]
    fn nopass_refuses_a_human_entry_in_every_state() {
        for caller in [human(77), agent(77)] {
            for class in [AttestedClass::Unattested, AttestedClass::Human] {
                let mut pending = harness_entry(77);
                pending.attested_class = class;
                pending.attested_scope_id = None;
                pending.boot_id = None;
                pending.attested_harness = None;
                assert_eq!(
                    mode_code(decide(
                        &grant_rules(),
                        &caller,
                        Some(&pending),
                        nopass_context()
                    )),
                    "gate_mode_not_an_enrolled_agent"
                );
            }
        }
        // A stored human or unattested entry with a live enrolled agent (and
        // its scope), the one pairing only `require_live_harness` refuses.
        for class in [AttestedClass::Unattested, AttestedClass::Human] {
            let mut pending = harness_entry(77);
            pending.attested_class = class;
            let live = live_agent(77, "claude-code", 44);
            assert_eq!(
                require_live_harness(&pending, &live),
                Err(ModeRefusal::NotAnEnrolledAgent)
            );
            assert!(decide(&grant_rules(), &live, Some(&pending), nopass_context()).is_err());
        }
        // A stored enrolled agent whose live read is a human or nothing.
        for live in [human(77), agent(77)] {
            assert_eq!(
                mode_code(decide(
                    &grant_rules(),
                    &live,
                    Some(&harness_entry(77)),
                    nopass_context()
                )),
                "gate_mode_not_an_enrolled_agent"
            );
        }
    }

    #[test]
    fn nopass_refuses_a_live_class_that_differs_from_the_stored_one() {
        // Same label, another scope: the entry was minted for a scope the
        // caller has left.
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &live_agent(77, "claude-code", 45),
                Some(&harness_entry(77)),
                nopass_context()
            )),
            "request_wrong_attested_identity"
        );
        // Same scope, another label: the registry names another harness now.
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &live_agent(77, "codex", 44),
                Some(&harness_entry(77)),
                nopass_context()
            )),
            "gate_mode_label_differs"
        );
        // An entry that names no label at all is not an enrolled entry.
        let mut unlabelled = harness_entry(77);
        unlabelled.attested_harness = None;
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &live_agent(77, "claude-code", 44),
                Some(&unlabelled),
                nopass_context()
            )),
            "request_invalid_attested_identity"
        );
    }

    #[test]
    fn nopass_refuses_a_rule_without_this_harness() {
        let other = GRANT_RULES.replace("claude-code", "codex");
        let rules = RuleSet::from_toml("other.toml", &other).unwrap();
        assert_eq!(
            mode_code(decide(
                &rules,
                &live_agent(77, "claude-code", 44),
                Some(&harness_entry(77)),
                nopass_context()
            )),
            "gate_mode_not_granted"
        );
        // And a rule that lists no harness at all.
        assert_eq!(
            mode_code(decide(
                &rules_without_harness(),
                &live_agent(77, "claude-code", 44),
                Some(&harness_entry(77)),
                nopass_context()
            )),
            "gate_mode_not_granted"
        );
    }

    fn rules_without_harness() -> RuleSet {
        rules()
    }

    #[test]
    fn nopass_refuses_an_ask_human_rule() {
        let ask = GRANT_RULES.replace("outcome = \"allow\"", "outcome = \"ask-human\"");
        let rules = RuleSet::from_toml("ask.toml", &ask).unwrap();
        assert_eq!(
            mode_code(decide(
                &rules,
                &live_agent(77, "claude-code", 44),
                Some(&harness_entry(77)),
                nopass_context()
            )),
            "ask_human"
        );
    }

    #[test]
    fn nopass_ignores_a_confirmed_flag() {
        // The verdict decides under `-nopass`: what the entry says a human
        // approved is not read. Both settings of the watch channel.
        let mut pending = harness_entry(77);
        pending.confirmed = true;
        for confirm_human_path in [false, true] {
            let mut context = nopass_context();
            context.settings.confirm_human_path = confirm_human_path;
            // An approval on a harness entry is not one the broker wrote.
            assert_eq!(
                decide(
                    &grant_rules(),
                    &live_agent(77, "claude-code", 44),
                    Some(&pending),
                    context
                )
                .unwrap_err()
                .code(),
                "request_unattributed_confirmation"
            );
        }
        // And a stand-alone verdict that confirms is not made an `Allow` by a
        // confirmed entry, whatever `password_confirms` says.
        let decision = confirming_decision();
        let mut context = nopass_context();
        context.password_confirms = true;
        let mut approved = harness_entry(77);
        approved.confirmed = true;
        assert_eq!(
            check_verdict(&decision, &approved, &context)
                .unwrap_err()
                .code(),
            "gate_mode_not_granted"
        );
    }

    /// What the engine says for a listed harness on an allow rule: a plain
    /// allow that names the grant.
    fn granted_decision() -> Decision {
        let decision = engine::evaluate(
            &grant_rules(),
            &live_agent(77, "claude-code", 44).facts,
            &Request::for_program(
                ActionId::new("xudo.svc.status"),
                "/usr/bin/systemctl",
                Argv::new(["--no-pager", "status", "nginx.service"]),
            ),
            engine::Settings::default(),
        );
        assert_eq!(decision.verdict, Verdict::Allow);
        assert!(decision.harness_grant.is_some());
        decision
    }

    /// The granted decision as if something stricter had demanded a
    /// confirmation while the grant stayed recorded: never the engine's own
    /// output, and what `-nopass` must refuse if it ever were.
    fn confirming_decision() -> Decision {
        let mut decision = granted_decision();
        decision.verdict = Verdict::AllowWithConfirmation;
        decision.confirm = xudo_policy::Confirm::Required {
            reason: xudo_policy::ConfirmReason::AgentActionsConfirmed,
        };
        decision
    }

    #[test]
    fn a_live_granted_harness_entry_passes_the_nopass_decision() {
        // Every fact holds and a rule grants the harness: `-nopass` would run
        // it. `sudo` still asks a password for this file until root adds a
        // sudoers line naming it, which nothing installs.
        let approved = decide(
            &grant_rules(),
            &live_agent(77, "claude-code", 44),
            Some(&harness_entry(77)),
            nopass_context(),
        )
        .unwrap();
        assert_eq!(approved.program, "/usr/bin/systemctl");
        assert_eq!(approved.action, "xudo.svc.status");
        // The same entry under another label, or as a human, is refused.
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &live_agent(77, "codex", 44),
                Some(&harness_entry(77)),
                nopass_context()
            )),
            "gate_mode_label_differs"
        );
        assert_eq!(
            mode_code(decide(
                &grant_rules(),
                &human(77),
                Some(&harness_entry(77)),
                nopass_context()
            )),
            "gate_mode_not_an_enrolled_agent"
        );
    }

    /// Wherever `-nopass` would run an entry, `-auth` runs the same command
    /// for a human after the password: the agent path never reaches what the
    /// human path cannot. Exhaustive rather than sampled, over the granting
    /// action's tier and `confirm`, a second action on the same command (none,
    /// plain, always-confirming, granting another harness, human-only), and
    /// argvs inside and outside the matchers.
    #[test]
    fn every_action_nopass_can_run_auth_can_run_too() {
        const ARGS: &str = r#"args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "verb", matcher = { literal = "status" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;
        const WAIVER: &str = "gtfobins-waiver = \"service manager pager escape: the unit is a name matcher and no option can be passed here, so no pager ever runs\"\n";
        let tiers = [
            "diag-read",
            "svc-control",
            "pkg-install",
            "pkg-remove",
            "sys-tunable",
            "net-filter",
            "critical",
        ];
        let confirms = ["", "confirm = \"never\"\n", "confirm = \"always\"\n"];
        let seconds = [
            String::new(),
            format!(
                "[[action]]\nid = \"b.plain\"\ntier = \"diag-read\"\nexe = \"/usr/bin/systemctl\"\n{ARGS}"
            ),
            format!(
                "[[action]]\nid = \"b.always\"\ntier = \"diag-read\"\nconfirm = \"always\"\nexe = \"/usr/bin/systemctl\"\n{ARGS}"
            ),
            format!(
                "[[action]]\nid = \"b.codex\"\ntier = \"diag-read\"\nharness = [\"codex\"]\noutcome = \"allow\"\n{WAIVER}exe = \"/usr/bin/systemctl\"\n{ARGS}"
            ),
            format!(
                "[[action]]\nid = \"b.human\"\ntier = \"diag-read\"\nagent-allowed = false\nexe = \"/usr/bin/systemctl\"\n{ARGS}"
            ),
        ];
        let argvs: [&[&str]; 5] = [
            &["--no-pager", "status", "nginx.service"],
            &["--no-pager", "status", "ssh.service"],
            &["--no-pager", "status", "../x"],
            &["--no-pager", "status", "nginx.service", "--now"],
            &["status"],
        ];
        let (mut loaded, mut refused_at_load, mut granted) = (0_u32, 0_u32, 0_u32);
        for tier in tiers {
            for confirm in confirms {
                for second in &seconds {
                    let text = format!(
                        "[[action]]\nid = \"xudo.svc.status\"\ntier = \"{tier}\"\n{confirm}harness = [\"claude-code\"]\noutcome = \"allow\"\n{WAIVER}exe = \"/usr/bin/systemctl\"\n{ARGS}\n{second}"
                    );
                    let Ok(rules) = RuleSet::from_toml("grant.toml", &text) else {
                        refused_at_load += 1;
                        continue;
                    };
                    loaded += 1;
                    for argv in argvs {
                        let mut entry = harness_entry(77);
                        entry.argv = argv.iter().map(|a| (*a).to_owned()).collect();
                        let Ok(agent) = decide(
                            &rules,
                            &live_agent(77, "claude-code", 44),
                            Some(&entry),
                            nopass_context(),
                        ) else {
                            continue;
                        };
                        granted += 1;
                        let mut human_entry = status_request(77);
                        human_entry.argv.clone_from(&entry.argv);
                        let mut auth = context();
                        auth.password_confirms = true;
                        let human_run =
                            decide(&rules, &human(77), Some(&human_entry), auth).unwrap();
                        assert_eq!(human_run.program, agent.program, "{text}");
                        assert_eq!(human_run.exec_argv, agent.exec_argv, "{text}");
                    }
                }
            }
        }
        // The space holds rules the loader refuses, rules that grant, and
        // rules that do not.
        assert!(refused_at_load > 0 && loaded > 0 && granted > 0);
        assert!(granted < loaded * 5);
    }

    #[test]
    fn the_verdict_check_proceeds_only_on_a_plain_allow_that_names_a_grant() {
        let base = confirming_decision();
        let mut granted_allow = base.clone();
        granted_allow.verdict = Verdict::Allow;
        let mut bare_allow = granted_allow.clone();
        bare_allow.harness_grant = None;
        let pending = harness_entry(77);
        let nopass = nopass_context();
        assert_eq!(check_verdict(&granted_allow, &pending, &nopass), Ok(()));
        for refused in [&base, &bare_allow] {
            assert_eq!(
                check_verdict(refused, &pending, &nopass)
                    .unwrap_err()
                    .code(),
                "gate_mode_not_granted"
            );
        }
        let mut denied = granted_allow.clone();
        denied.verdict = Verdict::Deny;
        assert_eq!(
            check_verdict(&denied, &pending, &nopass)
                .unwrap_err()
                .code(),
            "gate_policy_denied"
        );
        // The same plain allow is fine under `-auth`, and the confirming one
        // is not, without the password.
        assert_eq!(check_verdict(&granted_allow, &pending, &context()), Ok(()));
        assert_eq!(
            check_verdict(&base, &pending, &context())
                .unwrap_err()
                .code(),
            "gate_confirmation_missing"
        );
    }

    #[test]
    fn a_live_class_that_is_enrolled_while_the_facts_say_otherwise_is_refused() {
        // The two live readings must agree: the attested class and the
        // classification the engine decides on.
        let mut caller = live_agent(77, "claude-code", 44);
        caller.facts = human(77).facts;
        assert_eq!(
            require_live_harness(&harness_entry(77), &caller),
            Err(ModeRefusal::NotAnEnrolledAgent)
        );
    }

    #[test]
    fn the_live_harness_requirements_hold_for_a_matching_entry() {
        // The positive half: what a future grant must also satisfy.
        assert_eq!(
            require_live_harness(&harness_entry(77), &live_agent(77, "claude-code", 44)),
            Ok(())
        );
    }

    #[test]
    fn direct_nopass_invocation_with_no_entry_does_nothing() {
        let refusal = decide(
            &grant_rules(),
            &live_agent(77, "claude-code", 44),
            None,
            nopass_context(),
        )
        .unwrap_err();
        assert_eq!(refusal.code(), "gate_no_pending_request");
    }

    #[test]
    fn a_mode_refusal_is_audited_with_its_code_and_names_its_gate_file() {
        let refusal = decide(
            &grant_rules(),
            &human(77),
            Some(&status_request(77)),
            nopass_context(),
        )
        .unwrap_err();
        assert_eq!(
            refusal.to_string(),
            "the -nopass gate refuses this entry: the entry was minted for the other gate file"
        );
        let record = refusal_record(None, &refusal, &human(77), None);
        assert_eq!(record.denial.as_deref(), Some("gate_mode_wrong_via"));
        let auth = decide(
            &grant_rules(),
            &human(77),
            Some(&harness_entry(77)),
            context(),
        )
        .unwrap_err();
        assert!(auth.to_string().starts_with("the -auth gate refuses"));
        for reason in [
            ModeRefusal::WrongVia,
            ModeRefusal::NotAnEnrolledAgent,
            ModeRefusal::LabelDiffers,
            ModeRefusal::NotGranted,
        ] {
            assert!(!reason.to_string().is_empty());
        }
    }

    /// Over class × via × scope × label × verdict × grant (all 432 cases, no
    /// sampling: a sampled space this small let a mutant through), `-nopass`
    /// proceeds for exactly one combination: a harness entry, a stored and a
    /// live enrolled agent with the stored label, and a plain allow with a
    /// grant. The scope is `decide`'s separate check
    /// (`request_wrong_attested_identity`), not this function's, so the
    /// expectation does not depend on it.
    #[test]
    fn nopass_refuses_any_entry_that_is_not_a_live_granted_harness() {
        let class = |kind: u8, scope: u64| match kind {
            0 => AttestedClass::Unattested,
            1 => AttestedClass::Human,
            _ => AttestedClass::EnrolledAgent { scope_id: scope },
        };
        let mut cases = 0_u32;
        for via_harness in [false, true] {
            for stored in 0_u8..3 {
                for live in 0_u8..3 {
                    for same_scope in [false, true] {
                        for same_label in [false, true] {
                            for verdict in 0_u8..3 {
                                for grant in [false, true] {
                                    cases += 1;
                                    let mut pending = harness_entry(77);
                                    pending.via =
                                        if via_harness { Via::Harness } else { Via::Auth };
                                    pending.attested_class = class(stored, 44);
                                    let label = if same_label { "claude-code" } else { "codex" };
                                    let mut caller = live_agent(77, label, 44);
                                    caller.attested_class =
                                        class(live, if same_scope { 44 } else { 45 });
                                    let required = require_live_harness(&pending, &caller);
                                    let mut decision = confirming_decision();
                                    decision.verdict = match verdict {
                                        0 => Verdict::Allow,
                                        1 => Verdict::AllowWithConfirmation,
                                        _ => Verdict::Deny,
                                    };
                                    if !grant {
                                        decision.harness_grant = None;
                                    }
                                    let verdict_ok =
                                        check_verdict(&decision, &pending, &nopass_context())
                                            .is_ok();
                                    let expected = via_harness
                                        && stored == 2
                                        && live == 2
                                        && same_label
                                        && verdict == 0
                                        && grant;
                                    assert_eq!(
                                        required.is_ok() && verdict_ok,
                                        expected,
                                        "{via_harness} {stored} {live} {same_scope} {same_label} {verdict} {grant}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 432);
    }
}
