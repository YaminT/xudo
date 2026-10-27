//! Snapshots of every decision record, through both rendered surfaces.
//!
//! `render::human` and `render::json` are what a person reads and what an
//! agent branches on, so their exact output is a reviewed artifact: a diff in
//! either is a policy or UX change (`CLAUDE.md` § Tests are adversarial).
//! Every verdict shape is pinned — the allow, all three confirmation reasons,
//! and all eight denial codes — each through a decision produced the way the
//! real caller produces it wherever a producer exists. So are the two shapes
//! overlapping rules add: a confirmation decided by a stricter action than the
//! one asked for, and an agent refused because an overlapping action is
//! human-only.
//!
//! To accept a deliberate change: `INSTA_UPDATE=always cargo test -p aido`
//! (or `cargo insta review`), then commit the changed `.snap` files so review
//! sees the surface move.

#![allow(clippy::unwrap_used, clippy::panic)]

use aido::render;
use aido_policy::decision::ConfirmReason;
use aido_policy::engine::Settings;
use aido_policy::{
    Argv, CallerFacts, Classification, Confirm, Decision, DenialCode, Request, RuleSet, Verdict,
    evaluate,
};

/// One action per confirmation shape, one human-only action, and one action
/// the deny-list refuses — enough ruleset to reach every verdict the engine
/// can produce.
const FIXTURE: &str = r#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "aido.pkg.autoremove"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "autoremove" } }]

# Critical tier. Deliberately not a power-state or unit-mutation verb: those
# sit on the compiled-in deny-list (PowerState, UnitDefinitionMutation), so a
# critical action over one denies before reaching the confirmation shape this
# fixture exists to pin.
[[action]]
id = "aido.pkg.dist-upgrade"
tier = "critical"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "dist-upgrade" } }]

[[action]]
id = "aido.pkg.upgrade"
tier = "pkg-remove"
agent-allowed = false
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "upgrade" } }]

[[action]]
id = "aido.oops.shell"
tier = "diag-read"
exe = "/bin/sh"
args = [{ name = "flag", matcher = { literal = "-c" } }]
"#;

const ALL_CODES: [DenialCode; 8] = [
    DenialCode::UnknownAction,
    DenialCode::ArgvRejected,
    DenialCode::DenyListed,
    DenialCode::PolicyUnloadable,
    DenialCode::Frozen,
    DenialCode::NoConfirmationChannel,
    DenialCode::HumanPathOnly,
    DenialCode::ExeMismatch,
];

const ALL_REASONS: [ConfirmReason; 3] = [
    ConfirmReason::AgentActionsConfirmed,
    ConfirmReason::RuleRequiresConfirmation,
    ConfirmReason::CriticalTier,
];

fn rules() -> RuleSet {
    RuleSet::from_toml("snapshot-fixture.toml", FIXTURE).unwrap()
}

fn human_caller() -> CallerFacts {
    CallerFacts::new(Classification::Human, 1000)
}

fn agent_caller() -> CallerFacts {
    CallerFacts::new(
        Classification::EnrolledAgent {
            agent_id: "claude-code".into(),
            session_id: "s".into(),
            declared_yolo: true,
        },
        1000,
    )
}

fn decide(caller: &CallerFacts, request: &Request, settings: Settings) -> Decision {
    evaluate(&rules(), caller, request, settings)
}

/// A decision carrying `code`, produced the way the real producer produces it.
///
/// Exhaustive by construction: a new denial code stops this compiling, and the
/// fix is a fixture, which is a snapshot.
fn denial(code: DenialCode) -> Decision {
    match code {
        DenialCode::UnknownAction => decide(
            &human_caller(),
            &Request::new("aido.absent", Argv::default()),
            Settings::default(),
        ),
        DenialCode::ArgvRejected => decide(
            &human_caller(),
            &Request::for_program(
                "aido.svc.restart",
                "/usr/bin/systemctl",
                Argv::new(["restart", "nginx"]),
            ),
            Settings::default(),
        ),
        DenialCode::DenyListed => decide(
            &human_caller(),
            &Request::for_program("aido.oops.shell", "/bin/sh", Argv::new(["-c"])),
            Settings::default(),
        ),
        // No layer produces these two yet — the loader's failure envelope and
        // M3's channel check respectively — so the record is pinned through
        // the constructor those producers will use. When a producer lands, its
        // decision must render exactly this way or the snapshot moves.
        DenialCode::PolicyUnloadable | DenialCode::NoConfirmationChannel => {
            Decision::deny(code, Vec::new(), Vec::new())
        }
        DenialCode::Frozen => decide(
            &agent_caller(),
            &Request::for_program(
                "aido.svc.restart",
                "/usr/bin/systemctl",
                Argv::new(["restart", "nginx.service"]),
            ),
            Settings {
                frozen: true,
                confirm_agent_actions: true,
            },
        ),
        DenialCode::HumanPathOnly => decide(
            &agent_caller(),
            &Request::for_program(
                "aido.pkg.upgrade",
                "/usr/bin/apt-get",
                Argv::new(["upgrade"]),
            ),
            Settings::default(),
        ),
        DenialCode::ExeMismatch => decide(
            &human_caller(),
            &Request::for_program(
                "aido.svc.restart",
                "/bin/sh",
                Argv::new(["restart", "nginx.service"]),
            ),
            Settings::default(),
        ),
    }
}

/// A decision confirming for `reason`. Exhaustive the same way [`denial`] is.
fn confirming(reason: ConfirmReason) -> Decision {
    match reason {
        ConfirmReason::AgentActionsConfirmed => decide(
            &agent_caller(),
            &Request::for_program(
                "aido.svc.restart",
                "/usr/bin/systemctl",
                Argv::new(["restart", "nginx.service"]),
            ),
            Settings::default(),
        ),
        ConfirmReason::RuleRequiresConfirmation => decide(
            &human_caller(),
            &Request::for_program(
                "aido.pkg.autoremove",
                "/usr/bin/apt-get",
                Argv::new(["autoremove"]),
            ),
            Settings::default(),
        ),
        ConfirmReason::CriticalTier => decide(
            &human_caller(),
            &Request::for_program(
                "aido.pkg.dist-upgrade",
                "/usr/bin/apt-get",
                Argv::new(["dist-upgrade"]),
            ),
            Settings::default(),
        ),
    }
}

/// The snapshot-name fragment for a reason. Exhaustive so a new reason cannot
/// reuse a name.
fn reason_slug(reason: ConfirmReason) -> &'static str {
    match reason {
        ConfirmReason::AgentActionsConfirmed => "agent_actions_confirmed",
        ConfirmReason::RuleRequiresConfirmation => "rule_requires_confirmation",
        ConfirmReason::CriticalTier => "critical_tier",
    }
}

#[test]
fn the_allow_record_and_its_rendering_are_pinned() {
    let decision = decide(
        &human_caller(),
        &Request::for_program(
            "aido.svc.restart",
            "/usr/bin/systemctl",
            Argv::new(["restart", "nginx.service"]),
        ),
        Settings::default(),
    );
    assert_eq!(decision.verdict, Verdict::Allow);
    insta::assert_snapshot!("human__allow", render::human(&decision));
    insta::assert_snapshot!("json__allow", render::json(&decision));
}

#[test]
fn every_confirmation_shape_is_pinned() {
    for reason in ALL_REASONS {
        let decision = confirming(reason);
        assert_eq!(
            decision.confirm,
            Confirm::Required { reason },
            "fixture for {reason:?} did not confirm as expected: {decision:?}"
        );
        assert_eq!(decision.verdict, Verdict::AllowWithConfirmation);
        let slug = reason_slug(reason);
        insta::assert_snapshot!(format!("human__confirm_{slug}"), render::human(&decision));
        insta::assert_snapshot!(format!("json__confirm_{slug}"), render::json(&decision));
    }
}

/// Actions that accept one command between them: a confirming rule and its
/// permissive duplicate, and an agent-allowed rule overlapping one reserved
/// for a person. Kept apart from [`FIXTURE`] so the shapes above stay
/// single-action.
const OVERLAP_FIXTURE: &str = r#"
[[action]]
id = "aido.pkg.autoremove"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "autoremove" } }]

[[action]]
id = "aido.pkg.autoremove-quick"
tier = "pkg-remove"
confirm = "never"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "autoremove" } }]

[[action]]
id = "aido.svc.stop-by-hand"
tier = "svc-control"
agent-allowed = false
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "stop" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "aido.svc.stop"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "stop" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;

fn overlap_rules() -> RuleSet {
    RuleSet::from_toml("snapshot-overlap.toml", OVERLAP_FIXTURE).unwrap()
}

#[test]
fn a_confirmation_decided_by_an_overlapping_action_is_pinned() {
    // Asked under the permissive name, decided by the confirming rule: the
    // record cites the rule whose requirement it carries, and the trace lists
    // both and says the strictest applied.
    let decision = evaluate(
        &overlap_rules(),
        &human_caller(),
        &Request::for_program(
            "aido.pkg.autoremove-quick",
            "/usr/bin/apt-get",
            Argv::new(["autoremove"]),
        ),
        Settings::default(),
    );
    assert_eq!(
        decision.confirm,
        Confirm::Required {
            reason: ConfirmReason::RuleRequiresConfirmation
        }
    );
    insta::assert_snapshot!("human__confirm_overlap_strictest", render::human(&decision));
    insta::assert_snapshot!("json__confirm_overlap_strictest", render::json(&decision));
}

#[test]
fn an_agent_refused_by_an_overlapping_human_only_action_is_pinned() {
    let decision = evaluate(
        &overlap_rules(),
        &agent_caller(),
        &Request::for_program(
            "aido.svc.stop",
            "/usr/bin/systemctl",
            Argv::new(["stop", "nginx.service"]),
        ),
        Settings::default(),
    );
    assert_eq!(decision.denial, Some(DenialCode::HumanPathOnly));
    insta::assert_snapshot!(
        "human__deny_human_path_only_overlap",
        render::human(&decision)
    );
    insta::assert_snapshot!(
        "json__deny_human_path_only_overlap",
        render::json(&decision)
    );
}

#[test]
fn every_denial_code_record_and_rendering_are_pinned() {
    for code in ALL_CODES {
        let decision = denial(code);
        assert_eq!(
            decision.denial,
            Some(code),
            "fixture for {code:?} produced a different denial"
        );
        assert_eq!(decision.verdict, Verdict::Deny);
        insta::assert_snapshot!(
            format!("human__deny_{}", code.as_str()),
            render::human(&decision)
        );
        insta::assert_snapshot!(
            format!("json__deny_{}", code.as_str()),
            render::json(&decision)
        );
    }
}

// ---------------------------------------------------------------------------
// `aido exec`: every string it adds is a reviewed surface.
// ---------------------------------------------------------------------------

use aido::exec::{self, ExecError};
use aido_backend::DetectError;
use aido_wire::{RefusalCode, ResponseError};

/// The snapshot-name fragment for an error. Exhaustive, so a new variant stops
/// this compiling until it has a place in [`exec_errors`] and so a snapshot.
fn exec_error_slug(error: &ExecError) -> &'static str {
    match error {
        ExecError::NothingToRun => "nothing_to_run",
        ExecError::NonUtf8Argument { .. } => "non_utf8_argument",
        ExecError::InteriorNul { .. } => "interior_nul",
        ExecError::ProgramNotAbsolute => "program_not_absolute",
        ExecError::BrokerUnreachable => "broker_unreachable",
        ExecError::BrokerAnswerUnreadable(_) => "broker_answer_unreadable",
        ExecError::PermittedWithoutMint => "permitted_without_mint",
        ExecError::MintedWithoutPermission => "minted_without_permission",
        ExecError::GateNotTheCompiledOne => "gate_not_the_compiled_one",
        ExecError::NoBackend(_) => "no_backend",
        ExecError::BackendNotStarted => "backend_not_started",
    }
}

fn exec_errors() -> Vec<ExecError> {
    vec![
        ExecError::NothingToRun,
        ExecError::NonUtf8Argument { index: 2 },
        ExecError::InteriorNul { index: 1 },
        ExecError::ProgramNotAbsolute,
        ExecError::BrokerUnreachable,
        ExecError::BrokerAnswerUnreadable(ResponseError::TooLarge { limit: 262_144 }),
        ExecError::PermittedWithoutMint,
        ExecError::MintedWithoutPermission,
        ExecError::GateNotTheCompiledOne,
        ExecError::NoBackend(DetectError::NoBackend),
        ExecError::BackendNotStarted,
    ]
}

#[test]
fn every_exec_refusal_is_pinned() {
    let errors = exec_errors();
    let slugs: std::collections::BTreeSet<_> = errors.iter().map(exec_error_slug).collect();
    assert_eq!(slugs.len(), errors.len(), "two samples share a variant");
    for error in &errors {
        insta::assert_snapshot!(
            format!("exec__{}", exec_error_slug(error)),
            error.to_string()
        );
    }
}

#[test]
fn every_broker_refusal_as_exec_prints_it_is_pinned() {
    for code in RefusalCode::ALL {
        insta::assert_snapshot!(
            format!("exec__broker_refused_{}", code.as_str()),
            exec::refusal_line(code, code.remediation())
        );
    }
}

#[test]
fn the_ido_queue_line_for_every_denial_a_person_can_act_on_is_pinned() {
    let command = ["/usr/bin/apt-get".to_owned(), "upgrade".to_owned()];
    let mut offered = 0;
    for code in ALL_CODES {
        if let Some(reason) = exec::queue_reason(code) {
            offered += 1;
            insta::assert_snapshot!(
                format!("exec__queue_{}", code.as_str()),
                exec::queue_line(reason, &command)
            );
        }
    }
    assert_eq!(offered, 2, "only a human-only or frozen denial is queued");
}

#[test]
fn the_gate_note_and_the_signal_line_are_pinned() {
    insta::assert_snapshot!("exec__gate_note", exec::gate_note("no_pending_request"));
    insta::assert_snapshot!("exec__signal_line", exec::signal_line("sudo", 9));
}
