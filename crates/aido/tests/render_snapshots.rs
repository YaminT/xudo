//! Snapshots of every decision record, through both rendered surfaces.
//!
//! `render::human` and `render::json` are what a person reads and what an
//! agent branches on, so their exact output is a reviewed artifact: a diff in
//! either is a policy or UX change (`CLAUDE.md` § Tests are adversarial).
//! Every verdict shape is pinned — the allow, all three confirmation reasons,
//! and all eight denial codes — each through a decision produced the way the
//! real caller produces it wherever a producer exists.
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
