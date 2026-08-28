//! Evaluation order, and the reasons for it.
//!
//! ```text
//! canonicalize argv
//!   -> look up the named action        (unknown action  -> deny)
//!   -> match the typed argument list   (argv rejected   -> deny)
//!   -> agent-path eligibility          (human-only      -> deny)
//!   -> COMPILED-IN DENY-LIST           (any class hit   -> deny)
//!   -> confirmation requirement        (required        -> allow-with-confirmation)
//!   -> allow
//! ```
//!
//! # Why the deny-list runs last
//!
//! Running it *after* allow matching is deliberate. If it ran first, a rule
//! author could believe their narrow rule had been checked when in fact the
//! deny-list had short-circuited on the executable and never examined the
//! arguments — and worse, a future refactor could reorder the two and silently
//! change which requests are refused. Running it last means the deny-list sees
//! exactly the canonicalized `(exe, argv)` tuple that would be executed, and
//! its verdict cannot be reached by any other path.
//!
//! It is also why *deny always wins*: there is no branch in which a matched
//! allow rule causes the deny-list to be skipped.

use crate::argv::{Arg, Argv};
use crate::caller::CallerFacts;
use crate::decision::{
    Confirm, ConfirmReason, Decision, DenialCode, ENVELOPE_SCHEMA_VERSION, TraceStep, Verdict,
};
use crate::deny::{deny_list_version, evaluate_deny_list};
use crate::matcher::match_argv;
use crate::rule::{ActionId, ConfirmPolicy, RuleSet};

/// A request to evaluate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The named action being asked for.
    pub action: ActionId,
    /// The program the caller wants to run, as absolute bytes.
    ///
    /// Carried separately from [`Self::argv`] and compared here rather than in
    /// the front-end, because a front-end that decides which program an action
    /// may run is a front-end making a decision. `None` means the caller did not
    /// name one, which is only legitimate for an introspection command that has
    /// already been told which action to interrogate.
    pub exe: Option<Arg>,
    /// The operands — the arguments **after** the program name.
    pub argv: Argv,
}

impl Request {
    /// Builds a request that names no program.
    ///
    /// For interrogating one action's argument list in isolation. A request that
    /// will actually run something must use [`Self::for_program`].
    pub fn new(action: impl Into<ActionId>, argv: Argv) -> Self {
        Self {
            action: action.into(),
            exe: None,
            argv,
        }
    }

    /// Builds a request to run `exe` with `argv` as its operands.
    pub fn for_program(action: impl Into<ActionId>, exe: impl Into<Arg>, argv: Argv) -> Self {
        Self {
            action: action.into(),
            exe: Some(exe.into()),
            argv,
        }
    }
}

/// Global settings that affect a decision.
///
/// Note what is *not* here: there is no field that turns confirmation off
/// globally. Narrowing the confirmation requirement takes a root-authored
/// `trust.d` record plus a per-invocation flag, both enforced by the broker,
/// because the realistic failure mode for this whole project is someone
/// disabling a noisy prompt to unstick a workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Whether an enrolled agent's actions are confirmed by a human.
    ///
    /// Defaults to `true` via [`Settings::default`].
    pub confirm_agent_actions: bool,
    /// Whether the agent path is frozen.
    pub frozen: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            confirm_agent_actions: true,
            frozen: false,
        }
    }
}

/// Evaluates a request. The whole crate exists to implement this function.
///
/// Every path through it either returns [`Verdict::Deny`] or has explicitly
/// established that the action is allowlisted, its arguments fit a typed
/// matcher, the caller is eligible, and no deny-list class matched.
pub fn evaluate(
    rules: &RuleSet,
    caller: &CallerFacts,
    request: &Request,
    settings: Settings,
) -> Decision {
    let canonical = request.argv.canonicalize();
    let resolved_argv: Vec<String> = canonical.as_slice().iter().map(Arg::display).collect();

    let mut trace = vec![TraceStep::Canonicalized {
        before: request.argv.display(),
        after: canonical.display(),
    }];

    // A frozen agent path denies before anything else is considered, so that
    // freezing is instant and cannot be raced by a request already in flight.
    // The human path stays open: an operator must always be able to recover.
    if settings.frozen && caller.classification.is_enrolled_agent() {
        return Decision::deny(DenialCode::Frozen, resolved_argv, trace);
    }

    let Some(action) = rules.get(&request.action) else {
        trace.push(TraceStep::ActionRejected {
            action: request.action.to_string(),
            reason: "no action with this id is defined in the ruleset".to_owned(),
        });
        return Decision::deny(DenialCode::UnknownAction, resolved_argv, trace);
    };

    // The program is checked before the arguments. A caller asking to run
    // /bin/sh under a rule for /usr/bin/systemctl is not making an argument
    // mistake, and reporting it as one would bury an attempted bypass among
    // ordinary typos. Compared byte-exactly: the rule's exe is an absolute path
    // and no normalisation happens here, because normalising is how two
    // different paths start comparing equal.
    if let Some(requested_exe) = &request.exe
        && requested_exe.as_bytes() != action.exe.as_bytes()
    {
        trace.push(TraceStep::ActionRejected {
            action: action.id.to_string(),
            reason: format!("this action runs {}, not the requested program", action.exe),
        });
        return Decision::deny(DenialCode::ExeMismatch, resolved_argv, trace)
            .about_program(requested_exe.display());
    }

    if let Err(err) = match_argv(&action.args, &canonical) {
        trace.push(TraceStep::ActionRejected {
            action: action.id.to_string(),
            reason: err.to_string(),
        });
        return Decision::deny(DenialCode::ArgvRejected, resolved_argv, trace);
    }

    trace.push(TraceStep::ActionMatched {
        action: action.id.to_string(),
        source: action.source.to_string(),
    });

    if !action.agent_allowed && caller.classification.is_enrolled_agent() {
        return Decision::deny(DenialCode::HumanPathOnly, resolved_argv, trace);
    }

    // The deny-list sees the exact tuple that would be executed.
    let findings = evaluate_deny_list(action.exe.as_bytes(), &canonical);
    trace.push(TraceStep::DenyListEvaluated {
        version: deny_list_version(),
        matched: findings
            .iter()
            .map(|f| format!("{:?}: {}", f.class, f.evidence))
            .collect(),
    });
    if !findings.is_empty() {
        return Decision::deny(DenialCode::DenyListed, resolved_argv, trace);
    }

    let confirm_reason = if action.confirm == ConfirmPolicy::Always {
        Some(ConfirmReason::RuleRequiresConfirmation)
    } else if action.tier.always_confirms() {
        // A critical tier confirms even when the rule asked not to. `RuleSet`
        // refuses that combination at load time; this is the second, redundant
        // check, because a tier promise that depends on the loader having run
        // is not a promise.
        Some(ConfirmReason::CriticalTier)
    } else if action.confirm == ConfirmPolicy::Never {
        None
    } else if caller.classification.is_enrolled_agent() && settings.confirm_agent_actions {
        Some(ConfirmReason::AgentActionsConfirmed)
    } else {
        None
    };

    trace.push(TraceStep::ConfirmationDecided {
        required: confirm_reason.is_some(),
        reason: confirm_reason.map_or_else(
            || "no confirmation requirement applies".to_owned(),
            |r| r.explain().to_owned(),
        ),
    });

    let (verdict, confirm) = match confirm_reason {
        Some(reason) => (Verdict::AllowWithConfirmation, Confirm::Required { reason }),
        None => (Verdict::Allow, Confirm::NotRequired),
    };

    Decision {
        schema_version: ENVELOPE_SCHEMA_VERSION,
        verdict,
        denial: None,
        remediation: None,
        action: Some(action.id.clone()),
        rule_source: Some(action.source.clone()),
        // The rule's own program, not the caller's spelling of it. They are
        // byte-identical by the time execution is permitted — the check above
        // guarantees it — and taking the rule's copy means an allowed decision
        // records the path policy authorised rather than the one that was typed.
        resolved_exe: Some(action.exe.clone()),
        resolved_argv,
        confirm,
        trace,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::caller::{Classification, Hint, HintSource};
    use crate::matcher::{ArgSpec, Matcher, NameKind, Repeat};
    use crate::rule::{Action, Source, Tier};

    fn svc_restart() -> Action {
        Action {
            id: ActionId::new("aido.svc.restart"),
            tier: Tier::SvcControl,
            exe: "/usr/bin/systemctl".into(),
            args: vec![
                ArgSpec::one("verb", Matcher::Literal("restart".into())),
                ArgSpec::one("unit", Matcher::Name(NameKind::UnitName)),
            ],
            confirm: ConfirmPolicy::Default,
            agent_allowed: true,
            env_allow: Vec::new(),
            source: Source::new("20-services.toml", 3),
        }
    }

    fn pkg_install() -> Action {
        Action {
            id: ActionId::new("aido.pkg.install"),
            tier: Tier::PkgInstall,
            exe: "/usr/bin/apt-get".into(),
            args: vec![
                ArgSpec::one("y", Matcher::Literal("-y".into())),
                ArgSpec::one("verb", Matcher::Literal("install".into())),
                ArgSpec::repeated(
                    "pkg",
                    Matcher::Name(NameKind::DebName),
                    Repeat::Between { min: 1, max: 20 },
                ),
            ],
            confirm: ConfirmPolicy::Default,
            agent_allowed: true,
            env_allow: Vec::new(),
            source: Source::new("30-packages.toml", 4),
        }
    }

    fn rules() -> RuleSet {
        RuleSet::load(vec![svc_restart(), pkg_install()]).unwrap()
    }

    fn agent() -> CallerFacts {
        CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "claude-code".into(),
                session_id: "s-1".into(),
                declared_yolo: false,
            },
            1000,
        )
    }

    fn human() -> CallerFacts {
        CallerFacts::new(Classification::Human, 1000)
    }

    fn restart_request() -> Request {
        Request::new("aido.svc.restart", Argv::new(["restart", "nginx.service"]))
    }

    #[test]
    fn request_builder_takes_a_str_id() {
        let r = Request::new("a.b", Argv::default());
        assert_eq!(r.action, ActionId::new("a.b"));
        assert!(format!("{r:?}").contains("a.b"));
    }

    #[test]
    fn settings_default_to_confirming_agent_actions() {
        // The requirement: confirm even in yolo mode, unless explicitly
        // narrowed. The default must not be silent.
        let s = Settings::default();
        assert!(s.confirm_agent_actions);
        assert!(!s.frozen);
        assert!(format!("{s:?}").contains("confirm_agent_actions"));
    }

    #[test]
    fn a_human_running_an_allowed_action_is_allowed_outright() {
        let d = evaluate(&rules(), &human(), &restart_request(), Settings::default());
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.confirm, Confirm::NotRequired);
        assert_eq!(d.action, Some(ActionId::new("aido.svc.restart")));
        assert_eq!(
            d.rule_source.as_ref().map(ToString::to_string),
            Some("20-services.toml:3".to_owned())
        );
        assert!(d.denial.is_none());
        assert!(d.remediation.is_none());
    }

    #[test]
    fn an_agent_running_the_same_action_must_be_confirmed() {
        let d = evaluate(&rules(), &agent(), &restart_request(), Settings::default());
        assert_eq!(d.verdict, Verdict::AllowWithConfirmation);
        assert_eq!(
            d.confirm,
            Confirm::Required {
                reason: ConfirmReason::AgentActionsConfirmed
            }
        );
    }

    #[test]
    fn a_yolo_agent_is_still_confirmed() {
        // The core requirement. Declaring auto-approve changes the wording of
        // the prompt, never whether there is one.
        let mut yolo = agent();
        yolo.classification = Classification::EnrolledAgent {
            agent_id: "claude-code".into(),
            session_id: "s-1".into(),
            declared_yolo: true,
        };
        let d = evaluate(&rules(), &yolo, &restart_request(), Settings::default());
        assert_eq!(d.verdict, Verdict::AllowWithConfirmation);
    }

    #[test]
    fn narrowing_the_confirmation_requires_the_setting_and_the_rule_to_agree() {
        // Turning the global setting off is not enough on its own for a rule
        // that always confirms, and turning it off for an ordinary rule is the
        // only combination that yields a bare allow on the agent path.
        let mut always = svc_restart();
        always.confirm = ConfirmPolicy::Always;
        let strict = RuleSet::load(vec![always]).unwrap();
        let off = Settings {
            confirm_agent_actions: false,
            frozen: false,
        };
        assert_eq!(
            evaluate(&strict, &agent(), &restart_request(), off).verdict,
            Verdict::AllowWithConfirmation
        );
        assert_eq!(
            evaluate(&rules(), &agent(), &restart_request(), off).verdict,
            Verdict::Allow
        );
    }

    #[test]
    fn a_rule_may_opt_out_of_confirmation_entirely() {
        let mut never = svc_restart();
        never.confirm = ConfirmPolicy::Never;
        let set = RuleSet::load(vec![never]).unwrap();
        let d = evaluate(&set, &agent(), &restart_request(), Settings::default());
        assert_eq!(d.verdict, Verdict::Allow);
    }

    #[test]
    fn a_critical_tier_confirms_even_for_a_human() {
        let mut critical = svc_restart();
        critical.tier = Tier::Critical;
        let set = RuleSet::load(vec![critical]).unwrap();
        let d = evaluate(&set, &human(), &restart_request(), Settings::default());
        assert_eq!(
            d.confirm,
            Confirm::Required {
                reason: ConfirmReason::CriticalTier
            }
        );
    }

    #[test]
    fn an_unknown_action_is_denied_with_a_next_step() {
        let d = evaluate(
            &rules(),
            &human(),
            &Request::new("aido.nope", Argv::default()),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::UnknownAction));
        assert!(d.remediation.is_some());
        let rejected = d.trace.iter().any(
            |s| matches!(s, TraceStep::ActionRejected { action, .. } if action == "aido.nope"),
        );
        assert!(rejected, "{:?}", d.trace);
    }

    #[test]
    fn a_rejected_argv_names_the_offending_position() {
        let d = evaluate(
            &rules(),
            &human(),
            &Request::new("aido.svc.restart", Argv::new(["restart", "nginx"])),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::ArgvRejected));
        let reason = d
            .trace
            .iter()
            .find_map(|s| match s {
                TraceStep::ActionRejected { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .unwrap();
        assert!(reason.contains("unit"), "{reason}");
    }

    #[test]
    fn a_frozen_agent_path_denies_while_the_human_path_still_works() {
        let frozen = Settings {
            confirm_agent_actions: true,
            frozen: true,
        };
        let denied = evaluate(&rules(), &agent(), &restart_request(), frozen);
        assert_eq!(denied.denial, Some(DenialCode::Frozen));
        // Recovery must remain possible.
        let allowed = evaluate(&rules(), &human(), &restart_request(), frozen);
        assert_eq!(allowed.verdict, Verdict::Allow);
    }

    #[test]
    fn a_human_only_action_is_denied_to_an_agent_and_allowed_to_a_human() {
        let mut human_only = svc_restart();
        human_only.agent_allowed = false;
        let set = RuleSet::load(vec![human_only]).unwrap();
        assert_eq!(
            evaluate(&set, &agent(), &restart_request(), Settings::default()).denial,
            Some(DenialCode::HumanPathOnly)
        );
        assert_eq!(
            evaluate(&set, &human(), &restart_request(), Settings::default()).verdict,
            Verdict::Allow
        );
    }

    /// A rule permitting `systemctl restart <unit>`.
    fn restart_action() -> Action {
        Action {
            id: ActionId::new("aido.svc.restart"),
            tier: Tier::SvcControl,
            exe: "/usr/bin/systemctl".into(),
            args: vec![
                ArgSpec::one("verb", Matcher::Literal("restart".into())),
                ArgSpec::one("unit", Matcher::Name(crate::matcher::NameKind::UnitName)),
            ],
            confirm: ConfirmPolicy::Never,
            agent_allowed: true,
            env_allow: Vec::new(),
            source: Source::new("20-services.toml", 1),
        }
    }

    #[test]
    fn a_request_naming_another_program_is_denied_before_the_arguments_matter() {
        // The bypass this check exists for. Without it a rule's `exe` was never
        // compared to anything: whatever program the caller named, only the
        // arguments were matched, so a rule for /usr/bin/systemctl authorised
        // `restart nginx.service` no matter which binary was about to run it.
        let set = RuleSet::load(vec![restart_action()]).unwrap();
        let d = evaluate(
            &set,
            &human(),
            &Request::for_program(
                "aido.svc.restart",
                "/bin/sh",
                Argv::new(["restart", "nginx.service"]),
            ),
            Settings::default(),
        );
        assert_eq!(d.verdict, Verdict::Deny);
        assert_eq!(d.denial, Some(DenialCode::ExeMismatch));
        // Reported before the argument list is consulted, so the trace names the
        // program rather than an argument position.
        assert!(
            format!("{:?}", d.trace).contains("not the requested program"),
            "{:?}",
            d.trace
        );
    }

    #[test]
    fn the_program_is_compared_byte_exactly_and_not_normalised() {
        // Every one of these resolves to the same file on a real filesystem, and
        // every one is refused. Normalising here is how two different paths
        // start comparing equal, and the engine performs no I/O so it cannot
        // know what a path resolves to anyway.
        let set = RuleSet::load(vec![restart_action()]).unwrap();
        for program in [
            "/usr/bin/./systemctl",
            "/usr/bin//systemctl",
            "/usr/bin/systemctl/",
            "/usr/local/../bin/systemctl",
            "systemctl",
            "/usr/bin/Systemctl",
            "",
        ] {
            let d = evaluate(
                &set,
                &human(),
                &Request::for_program(
                    "aido.svc.restart",
                    program,
                    Argv::new(["restart", "nginx.service"]),
                ),
                Settings::default(),
            );
            assert_eq!(d.denial, Some(DenialCode::ExeMismatch), "{program}");
        }
    }

    #[test]
    fn naming_the_rules_own_program_permits_the_command() {
        let set = RuleSet::load(vec![restart_action()]).unwrap();
        let d = evaluate(
            &set,
            &human(),
            &Request::for_program(
                "aido.svc.restart",
                "/usr/bin/systemctl",
                Argv::new(["restart", "nginx.service"]),
            ),
            Settings::default(),
        );
        assert_eq!(d.verdict, Verdict::Allow);
    }

    #[test]
    fn a_request_that_names_no_program_still_checks_the_arguments() {
        // `Request::new` is for interrogating one action's argument list in
        // isolation, and it must not become a way to skip the program check on a
        // path that runs something — which is why the executor will only ever
        // build requests through `for_program`.
        let set = RuleSet::load(vec![restart_action()]).unwrap();
        let d = evaluate(
            &set,
            &human(),
            &Request::new("aido.svc.restart", Argv::new(["reboot"])),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::ArgvRejected));
        let named = Request::for_program(
            "aido.svc.restart",
            "/usr/bin/systemctl",
            Argv::new(["restart", "nginx.service"]),
        );
        assert_eq!(
            named.exe.as_ref().map(Arg::as_bytes),
            Some(&b"/usr/bin/systemctl"[..])
        );
        assert_eq!(
            Request::new("aido.svc.restart", Argv::new(["reboot"])).exe,
            None
        );
    }

    #[test]
    fn the_deny_list_overrides_a_matching_allow_rule() {
        // The whole point of running it last: an operator who allowlists a
        // shell gets a denial, not a root shell.
        let shell = Action {
            id: ActionId::new("aido.oops.shell"),
            tier: Tier::DiagRead,
            exe: "/bin/sh".into(),
            args: vec![ArgSpec::one("c", Matcher::Literal("-c".into()))],
            confirm: ConfirmPolicy::Never,
            agent_allowed: true,
            env_allow: Vec::new(),
            source: Source::new("99-oops.toml", 1),
        };
        let set = RuleSet::load(vec![shell]).unwrap();
        let d = evaluate(
            &set,
            &human(),
            &Request::new("aido.oops.shell", Argv::new(["-c"])),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::DenyListed));
        // The trace must show the rule matched *and then* was overridden, so an
        // operator can see why their rule did not take effect.
        assert!(
            d.trace
                .iter()
                .any(|s| matches!(s, TraceStep::ActionMatched { .. }))
        );
        let matched = d
            .trace
            .iter()
            .find_map(|s| match s {
                TraceStep::DenyListEvaluated { matched, .. } => Some(matched.clone()),
                _ => None,
            })
            .unwrap();
        assert!(
            matched.iter().any(|m| m.contains("SpawnsShell")),
            "{matched:?}"
        );
    }

    #[test]
    fn a_deny_listed_argument_defeats_a_well_intentioned_rule() {
        // The rule permits a package name; the deny-list still refuses a local
        // artefact, so the rule author's omission is caught.
        let mut loose = pkg_install();
        loose.args = vec![
            ArgSpec::one("y", Matcher::Literal("-y".into())),
            ArgSpec::one("verb", Matcher::Literal("install".into())),
            ArgSpec::one(
                "pkg",
                Matcher::Pattern(crate::matcher::AnchoredPattern::new(".+").unwrap()),
            ),
        ];
        let set = RuleSet::load(vec![loose]).unwrap();
        let d = evaluate(
            &set,
            &human(),
            &Request::new(
                "aido.pkg.install",
                Argv::new(["-y", "install", "./evil.deb"]),
            ),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::DenyListed));
    }

    #[test]
    fn the_trace_records_canonicalization() {
        let d = evaluate(
            &rules(),
            &human(),
            &Request::new(
                "aido.pkg.install",
                Argv::new(["-y", "install", "ripgrep", "--"]),
            ),
            Settings::default(),
        );
        assert_eq!(d.verdict, Verdict::Allow);
        // Scan the whole trace rather than stopping at the first match, so this
        // also asserts the argv is canonicalized exactly once. Canonicalizing
        // twice in one evaluation would mean two different views of the argv.
        let canonicalized: Vec<(String, String)> = d
            .trace
            .iter()
            .filter_map(|s| match s {
                TraceStep::Canonicalized { before, after } => Some((before.clone(), after.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(canonicalized.len(), 1, "{:?}", d.trace);
        let (before, after) = canonicalized.into_iter().next().unwrap_or_default();
        assert!(before.ends_with("--"), "{before}");
        assert!(!after.ends_with("--"), "{after}");
    }

    #[test]
    fn the_resolved_argv_is_the_canonical_one() {
        let d = evaluate(
            &rules(),
            &human(),
            &Request::new("aido.svc.restart", Argv::new(["restart", "nginx.service"])),
            Settings::default(),
        );
        assert_eq!(d.resolved_argv, vec!["restart", "nginx.service"]);
    }

    #[test]
    fn hints_are_recorded_but_never_believed() {
        // A forged agent marker must not change a human's verdict.
        let forged = human()
            .with_hint(Hint::new(HintSource::Environment, "CLAUDECODE", "1"))
            .with_hint(Hint::new(HintSource::Comm, "comm", "claude"))
            .with_hint(Hint::new(HintSource::AncestorExe, "exe", "/usr/bin/claude"));
        let with_hints = evaluate(&rules(), &forged, &restart_request(), Settings::default());
        let without = evaluate(&rules(), &human(), &restart_request(), Settings::default());
        assert_eq!(with_hints.verdict, without.verdict);
        assert_eq!(with_hints.confirm, without.confirm);
        // Specifically: it did not become the passwordless path.
        assert_eq!(with_hints.verdict, Verdict::Allow);
    }

    #[test]
    fn unattested_callers_take_the_human_path() {
        let unattested = CallerFacts::new(
            Classification::Unattested {
                reason: "namespace divergence".into(),
            },
            1000,
        );
        let d = evaluate(
            &rules(),
            &unattested,
            &restart_request(),
            Settings::default(),
        );
        assert_eq!(d.verdict, Verdict::Allow);
        // And a freeze does not touch them, because they are not on the agent
        // path at all.
        let frozen = Settings {
            confirm_agent_actions: true,
            frozen: true,
        };
        assert_eq!(
            evaluate(&rules(), &unattested, &restart_request(), frozen).verdict,
            Verdict::Allow
        );
    }
}
