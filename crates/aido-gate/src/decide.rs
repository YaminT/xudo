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
//!   /usr/libexec/aido/aido-gate-auth` is available to every member of the
//!   `aido` group by design; with no entry to act on, the gate exits non-zero
//!   having done nothing privileged, and says so at high severity.
//! * **An unconfirmed action whose rule demands confirmation.** The gate has no
//!   confirmation channel — every terminal it can reach belongs to the process
//!   tree that asked — so it cannot supply what is missing. Invariant 3 makes
//!   this a refusal rather than a prompt.
//! * **A program that is not the program the rule names.** Caught by
//!   [`aido_policy::evaluate`] via the exe comparison, which is why the entry's
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

use aido_audit::record::{Decision as AuditDecision, Outcome, Record};
use aido_policy::{
    ActionId, Arg, Argv, CallerFacts, Confirm, Decision, DenialCode, ExitCode, Request, RuleSet,
    Verdict, engine,
};

use crate::env::child_environment;
use crate::request::{CallerPin, MonotonicSecs, PendingRequest, RequestError};

/// The caller, as the gate itself established it.
///
/// `facts` comes from kernel attestation performed by the gate, not from the
/// spool entry's claim. The entry's `claimed_classification` is carried into the
/// audit record beside this and compared nowhere.
#[derive(Clone, Debug)]
pub struct GateCaller {
    /// The pinned identity of the `aido` process that asked.
    pub pin: CallerPin,
    /// What the gate attested about it.
    pub facts: CallerFacts,
}

/// The state the gate decides against.
#[derive(Clone, Copy, Debug)]
pub struct GateContext {
    /// The policy generation currently in force, read from root-owned state.
    pub generation: u64,
    /// The current monotonic reading.
    pub now: MonotonicSecs,
    /// Global settings, loaded from the root-owned config.
    pub settings: engine::Settings,
}

/// How loudly a refusal should be reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// An ordinary refusal: a policy denial, a race, an expiry.
    Normal,
    /// A refusal that only happens when someone is trying something.
    High,
}

impl Severity {
    /// The label recorded in the audit trail.
    pub fn label(self) -> &'static str {
        match self {
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
            Self::NoPendingRequest { .. } | Self::Request(_) | Self::ConfirmationMissing(_) => {
                Severity::High
            }
        }
    }

    /// The exit status the gate leaves with.
    ///
    /// Never zero, and never the child's range: nothing ran, so a status that
    /// could be mistaken for a command's own would be a lie to the caller's
    /// script.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Policy(_) => ExitCode::Denied,
            Self::ConfirmationMissing(_) => ExitCode::NotConfirmed,
            Self::NoPendingRequest { .. } | Self::Request(_) => ExitCode::Unusable,
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
    /// The canonicalized operands.
    pub argv: Vec<String>,
    /// The complete environment for the child.
    pub environment: Vec<String>,
    /// The action that matched.
    pub action: String,
    /// Where the matching rule lives, as `file:line`.
    pub rule_source: String,
    /// The nonce to consume before executing.
    ///
    /// Carried so the caller cannot forget: consuming it is what makes the grant
    /// one-use, and a grant that is not consumed is a grant that can be replayed.
    pub nonce: String,
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
    pending.validate(caller.pin, context.generation, context.now)?;

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

    match decision.verdict {
        Verdict::Deny => return Err(Refusal::Policy(Box::new(decision))),
        // A confirmation requirement the entry does not satisfy is a refusal
        // here even though the front-end may already have shown a prompt: the
        // gate's evidence that a human approved is the broker's record, and
        // there isn't one.
        Verdict::AllowWithConfirmation if !pending.confirmed => {
            return Err(Refusal::ConfirmationMissing(Box::new(decision)));
        }
        Verdict::Allow | Verdict::AllowWithConfirmation => {}
    }

    Ok(Approved {
        // The rule's spelling, not the request's. `evaluate` compared the two
        // byte-for-byte and denied `ExeMismatch` on any difference, so this is
        // the same bytes — taken from the copy that carries authority.
        program: action.exe.clone(),
        argv: decision.resolved_argv,
        environment: child_environment(),
        action: action.id.as_str().to_owned(),
        rule_source: action.source.to_string(),
        nonce: pending.nonce.clone(),
    })
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

/// The audit record for an authorization, before the child runs.
///
/// Written *before* execution, and updated with the outcome afterwards. The
/// order matters: a record written only after the child exits is a record that a
/// crash — or a kill — erases, which loses exactly the events worth keeping.
pub fn authorization_record(
    previous: Option<&Record>,
    approved: &Approved,
    caller: &GateCaller,
    confirmed_by: Option<&str>,
) -> Record {
    let mut argv = vec![approved.program.clone()];
    argv.extend(approved.argv.iter().cloned());

    let mut evidence = vec![format!("gate_caller_pid={}", caller.pin.pid)];
    if let Some(channel) = confirmed_by {
        evidence.push(format!("confirmed_by={channel}"));
    }

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

    use aido_policy::{Classification, Hint, HintSource};

    use super::*;
    use crate::request::{MonotonicSecs, REQUEST_SCHEMA_VERSION};

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
id = "aido.svc.status"
tier = "diag-read"
exe = "/usr/bin/systemctl"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "verb", matcher = { literal = "status" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "aido.always.confirms"
tier = "svc-control"
exe = "/usr/bin/systemctl"
confirm = "always"
args = [
  { name = "verb", matcher = { literal = "daemon-reload" } },
]

[[action]]
id = "aido.human.only"
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
        }
    }

    fn human(pid: u32) -> GateCaller {
        GateCaller {
            pin: CallerPin::new(pid, 555),
            facts: CallerFacts::new(Classification::Human, 1000),
        }
    }

    fn context() -> GateContext {
        GateContext {
            generation: GENERATION,
            now: MonotonicSecs(100),
            settings: engine::Settings::default(),
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
            deadline: MonotonicSecs(200),
            confirmed: false,
            confirmed_by: None,
            claimed_classification: "enrolled-agent".to_owned(),
        }
    }

    fn status_request(pid: u32) -> PendingRequest {
        request(
            pid,
            "aido.svc.status",
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
            Refusal::NoPendingRequest { .. } | Refusal::Request(_) => None,
        }
    }

    #[test]
    fn denies_a_direct_invocation_with_nothing_to_act_on() {
        // The expected shape of a hostile call: every member of the `aido` group
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
        assert_eq!(approved.action, "aido.svc.status");
        assert_eq!(approved.rule_source, "test-rules.toml:3");
        assert_eq!(approved.nonce, NONCE);
        assert_eq!(approved.environment, child_environment());
    }

    #[test]
    fn a_refused_spool_entry_never_reaches_the_ruleset() {
        // Shape and liveness are settled before policy, so a forged entry cannot
        // provoke a policy *answer* it can learn from.
        let mut pending = status_request(77);
        pending.deadline = MonotonicSecs(50);
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
        let pending = request(77, "aido.svc.enable", &["enable", "nginx.service"]);
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
        let pending = request(77, "aido.svc.restart", &["restart", "nginx.service; sh"]);
        let refusal = decide(&rules(), &human(77), Some(&pending), context()).unwrap_err();
        assert_eq!(refusal.code(), "argv_rejected");
        assert_eq!(refusal.exit_code(), ExitCode::Denied);
    }

    #[test]
    fn denies_an_agent_an_action_reserved_for_a_person() {
        let pending = request(77, "aido.human.only", &["stop", "nginx.service"]);
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
        pending.confirmed_by = Some("broker-tty:/dev/pts/3".to_owned());
        let approved = decide(&rules(), &agent(77), Some(&pending), context()).unwrap();
        assert_eq!(approved.action, "aido.svc.status");
    }

    #[test]
    fn a_rule_that_always_confirms_confirms_a_human_too() {
        let mut pending = request(77, "aido.always.confirms", &["daemon-reload"]);
        assert_eq!(
            decide(&rules(), &human(77), Some(&pending), context())
                .unwrap_err()
                .code(),
            "gate_confirmation_missing"
        );
        pending.confirmed = true;
        pending.confirmed_by = Some("broker-tty:/dev/pts/3".to_owned());
        assert!(decide(&rules(), &human(77), Some(&pending), context()).is_ok());
    }

    #[test]
    fn a_frozen_agent_path_leaves_the_human_path_open() {
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
        };
        let human_only = request(77, "aido.human.only", &["stop", "nginx.service"]);
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
        // Written first and updated after. A record written only on exit is one
        // that a crash or a kill erases — losing exactly the events worth having.
        let approved = decide(&rules(), &human(77), Some(&status_request(77)), context()).unwrap();
        let record = authorization_record(None, &approved, &human(77), None);

        assert_eq!(record.decision, AuditDecision::Allowed);
        assert_eq!(record.action.as_deref(), Some("aido.svc.status"));
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
        assert!(record.is_sealed());
    }

    #[test]
    fn a_confirmed_authorization_records_which_channel_approved_it() {
        let mut pending = status_request(77);
        pending.confirmed = true;
        pending.confirmed_by = Some("broker-tty:/dev/pts/3".to_owned());
        let approved = decide(&rules(), &agent(77), Some(&pending), context()).unwrap();
        let record =
            authorization_record(None, &approved, &agent(77), pending.confirmed_by.as_deref());

        assert_eq!(record.decision, AuditDecision::AwaitingConfirmation);
        assert!(
            record
                .evidence
                .contains(&"confirmed_by=broker-tty:/dev/pts/3".to_owned())
        );
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

    #[test]
    fn a_decision_that_asks_for_nothing_is_not_a_confirmation_requirement() {
        let decision = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        assert!(!demanded_confirmation(&decision));
    }
}
