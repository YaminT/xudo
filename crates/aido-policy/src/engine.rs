//! Evaluation order, and the reasons for it.
//!
//! ```text
//! canonicalize argv
//!   -> frozen agent path               (agent, frozen   -> deny)
//!   -> look up the named action        (unknown action  -> deny)
//!   -> compare the program             (exe mismatch    -> deny)
//!   -> match the typed argument list   (argv rejected   -> deny)
//!   -> gather every action that accepts the same command
//!   -> agent-path eligibility          (any human-only  -> deny)
//!   -> COMPILED-IN DENY-LIST           (any class hit   -> deny)
//!   -> confirmation requirement        (the strictest   -> allow-with-confirmation)
//!   -> allow
//! ```
//!
//! [`evaluate_command`] is the same pipeline for a command that names no
//! action: it gathers every action that runs the program and accepts the
//! arguments, and decides over all of them.
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
//! allow rule causes the deny-list to be skipped, and overlapping actions do
//! not change that — every action that accepts a command names the same
//! program and accepts the same arguments, so the deny-list sees one tuple
//! whichever of them the command was asked under.
//!
//! # Overlapping actions resolve to the strictest
//!
//! Two actions can accept the same command: a broad rule and a narrow one, or
//! one rule file repeating another. A requirement belongs to the command, not
//! to the name it was asked under. The caller chooses which action to name, so
//! a requirement that bound only the named action would let the caller pick
//! the weakest rule; and a search that stopped at the first permitting action
//! would let the sort order of two file names decide whether a human is asked.
//! So every action that accepts the command contributes:
//!
//! * if any of them is human-only, an enrolled agent is refused;
//! * the confirmation requirement is the strictest any of them demands, ranked
//!   by what it takes to lift: a critical tier, then a rule that always
//!   confirms, then the agent-path setting, then none.
//!
//! Adding a rule can grant a command that no rule accepted before; for a
//! command some rule already accepts, it can only make the answer stricter.
//! Reordering rules changes nothing but which of two equally strict actions a
//! decision cites. Both are standing properties in `tests/invariants.rs`.
//!
//! A permitted decision cites the action whose requirement it carries. Among
//! actions that tie, it cites the one that was asked for, or, when none was,
//! the first in declaration order.
//!
//! There is no last-match-wins and no negation: a negated rule is a way to
//! widen by reordering, which is what this resolution exists to rule out.

use crate::argv::{Arg, Argv};
use crate::caller::CallerFacts;
use crate::decision::{
    Confirm, ConfirmReason, Decision, DenialCode, ENVELOPE_SCHEMA_VERSION, TraceStep, Verdict,
};
use crate::deny::{deny_list_version, evaluate_deny_list};
use crate::matcher::match_argv;
use crate::rule::{Action, ActionId, ConfirmPolicy, RuleSet};

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

/// Evaluates a request that names an action. The whole crate exists to
/// implement this function and [`evaluate_command`].
///
/// Every path through it either returns [`Verdict::Deny`] or has explicitly
/// established that the action is allowlisted, its arguments fit a typed
/// matcher, the caller is eligible under every action that accepts the same
/// command, and no deny-list class matched.
///
/// The named action must accept the command itself; every other action that
/// accepts it contributes its requirement too (see the [module
/// documentation](crate::engine)), so naming a more permissive duplicate gains
/// nothing.
pub fn evaluate(
    rules: &RuleSet,
    caller: &CallerFacts,
    request: &Request,
    settings: Settings,
) -> Decision {
    let mut run = Run::start(caller, settings, &request.argv);

    if run.frozen_out() {
        return run.deny(DenialCode::Frozen);
    }

    let Some(action) = rules.get(&request.action) else {
        run.trace.push(TraceStep::ActionRejected {
            action: request.action.to_string(),
            reason: "no action with this id is defined in the ruleset".to_owned(),
        });
        return run.deny(DenialCode::UnknownAction);
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
        run.trace.push(TraceStep::ActionRejected {
            action: action.id.to_string(),
            reason: format!("this action runs {}, not the requested program", action.exe),
        });
        return run
            .deny(DenialCode::ExeMismatch)
            .about_program(requested_exe.display());
    }

    if let Err(err) = match_argv(&action.args, &run.canonical) {
        run.trace.push(TraceStep::ActionRejected {
            action: action.id.to_string(),
            reason: err.to_string(),
        });
        return run.deny(DenialCode::ArgvRejected);
    }

    let accepting = run.accepting(rules, action.exe.as_bytes());
    run.settle(action, &accepting)
}

/// Evaluates a command against every action in the ruleset, without naming
/// one.
///
/// What `aido explain` asks when no `--action` is given, and what anything
/// holding only a command line must ask. Every action that runs `program`,
/// byte for byte, and accepts `argv` takes part; the decision is the strictest
/// they reach together, and cites the action whose requirement it carries, the
/// first in declaration order among equals.
///
/// When none accepts the command, the refusal says why: every action that runs
/// the program is listed in the trace with the reason it refused, and when no
/// action runs it at all the decision names the program, because there is no
/// rule to cite instead.
pub fn evaluate_command(
    rules: &RuleSet,
    caller: &CallerFacts,
    program: &Arg,
    argv: &Argv,
    settings: Settings,
) -> Decision {
    let mut run = Run::start(caller, settings, argv);

    if run.frozen_out() {
        return run.deny(DenialCode::Frozen);
    }

    let accepting = run.accepting(rules, program.as_bytes());
    if let Some((first, _)) = accepting.split_first() {
        return run.settle(first, &accepting);
    }

    let refusals = run.refusals(rules, program.as_bytes());
    if refusals.is_empty() {
        return run
            .deny(DenialCode::UnknownAction)
            .about_program(program.display());
    }
    run.trace.extend(refusals);
    run.deny(DenialCode::ArgvRejected)
}

/// One evaluation in progress: who is asking, the command's operands in
/// canonical form, and the trace so far.
struct Run<'c> {
    caller: &'c CallerFacts,
    settings: Settings,
    canonical: Argv,
    trace: Vec<TraceStep>,
}

impl<'c> Run<'c> {
    /// Canonicalizes the operands, once, and opens the trace with it.
    fn start(caller: &'c CallerFacts, settings: Settings, argv: &Argv) -> Self {
        let canonical = argv.canonicalize();
        let trace = vec![TraceStep::Canonicalized {
            before: argv.display(),
            after: canonical.display(),
        }];
        Self {
            caller,
            settings,
            canonical,
            trace,
        }
    }

    /// Whether a freeze refuses this caller before anything else is
    /// considered.
    ///
    /// A frozen agent path denies first, so that freezing is instant and
    /// cannot be raced by a request already in flight. The human path stays
    /// open: an operator must always be able to recover.
    fn frozen_out(&self) -> bool {
        self.settings.frozen && self.caller.classification.is_enrolled_agent()
    }

    /// The canonical operands, rendered for the decision record.
    fn resolved_argv(&self) -> Vec<String> {
        self.canonical.as_slice().iter().map(Arg::display).collect()
    }

    /// Ends the evaluation with a refusal.
    fn deny(self, code: DenialCode) -> Decision {
        Decision::deny(code, self.resolved_argv(), self.trace)
    }

    /// Every action that runs `exe` and accepts the operands, in declaration
    /// order.
    fn accepting<'r>(&self, rules: &'r RuleSet, exe: &[u8]) -> Vec<&'r Action> {
        rules
            .actions()
            .iter()
            .filter(|action| {
                action.exe.as_bytes() == exe && match_argv(&action.args, &self.canonical).is_ok()
            })
            .collect()
    }

    /// Why each action that runs `exe` refuses the operands, in declaration
    /// order. Asked only when none accepts them.
    fn refusals(&self, rules: &RuleSet, exe: &[u8]) -> Vec<TraceStep> {
        rules
            .actions()
            .iter()
            .filter(|action| action.exe.as_bytes() == exe)
            .filter_map(|action| {
                match_argv(&action.args, &self.canonical).err().map(|err| {
                    TraceStep::ActionRejected {
                        action: action.id.to_string(),
                        reason: err.to_string(),
                    }
                })
            })
            .collect()
    }

    /// Decides over every action that accepts the command.
    ///
    /// `accepting` is in declaration order and includes `seed`, the action
    /// that wins a tie: the one asked for, or the first that accepts.
    fn settle(mut self, seed: &Action, accepting: &[&Action]) -> Decision {
        for action in accepting {
            self.trace.push(TraceStep::ActionMatched {
                action: action.id.to_string(),
                source: action.source.to_string(),
            });
        }

        // Human-only binds the command: when any action that accepts it is
        // reserved for a person, no other action can hand it to an agent.
        if self.caller.classification.is_enrolled_agent()
            && let Some(reserving) = accepting.iter().find(|action| !action.agent_allowed)
        {
            for other in accepting.iter().filter(|action| action.agent_allowed) {
                self.trace.push(TraceStep::ActionRejected {
                    action: other.id.to_string(),
                    reason: format!(
                        "{} at {} accepts this command too and reserves it for the human path",
                        reserving.id, reserving.source
                    ),
                });
            }
            return self.deny(DenialCode::HumanPathOnly);
        }

        // The deny-list sees the exact tuple that would be executed: every
        // accepting action names the same program as `seed`.
        let findings = evaluate_deny_list(seed.exe.as_bytes(), &self.canonical);
        self.trace.push(TraceStep::DenyListEvaluated {
            version: deny_list_version(),
            matched: findings
                .iter()
                .map(|f| format!("{:?}: {}", f.class, f.evidence))
                .collect(),
        });
        if !findings.is_empty() {
            return self.deny(DenialCode::DenyListed);
        }

        let (cited, reason) = strictest(seed, accepting, self.caller, self.settings);
        self.trace.push(TraceStep::ConfirmationDecided {
            required: reason.is_some(),
            reason: confirmation_text(reason, accepting.len()),
        });

        let (verdict, confirm) = match reason {
            Some(reason) => (Verdict::AllowWithConfirmation, Confirm::Required { reason }),
            None => (Verdict::Allow, Confirm::NotRequired),
        };

        Decision {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            verdict,
            denial: None,
            remediation: None,
            action: Some(cited.id.clone()),
            rule_source: Some(cited.source.clone()),
            // The rule's own program, not the caller's spelling of it. They are
            // byte-identical by the time execution is permitted — the program
            // check guarantees it — and taking the rule's copy means an allowed
            // decision records the path policy authorised rather than the one
            // that was typed.
            resolved_exe: Some(cited.exe.clone()),
            resolved_argv: self.resolved_argv(),
            confirm,
            trace: self.trace,
        }
    }
}

/// What one action demands before it runs a command for this caller,
/// considered on its own.
fn confirmation_for(
    action: &Action,
    caller: &CallerFacts,
    settings: Settings,
) -> Option<ConfirmReason> {
    if action.tier.always_confirms() {
        // Checked first, so a critical action reports the critical reason
        // whatever its own `confirm` says: with `always`, ranking it as an
        // ordinary always-confirming rule would let an ordinary duplicate tie
        // with it and be cited instead. And it confirms even when the rule
        // asked not to — `RuleSet` refuses that at load time, and this is the
        // second check, because a tier promise that depends on the loader
        // having run is not a promise.
        Some(ConfirmReason::CriticalTier)
    } else if action.confirm == ConfirmPolicy::Always {
        Some(ConfirmReason::RuleRequiresConfirmation)
    } else if action.confirm == ConfirmPolicy::Never {
        None
    } else if caller.classification.is_enrolled_agent() && settings.confirm_agent_actions {
        Some(ConfirmReason::AgentActionsConfirmed)
    } else {
        None
    }
}

/// The action whose requirement is strictest, and that requirement.
///
/// A candidate replaces the current choice only when strictly stricter, and
/// the fold starts from `seed` and walks declaration order, so a tie cites the
/// action asked for, or else the earliest.
fn strictest<'a>(
    seed: &'a Action,
    accepting: &[&'a Action],
    caller: &CallerFacts,
    settings: Settings,
) -> (&'a Action, Option<ConfirmReason>) {
    let rank = |reason: Option<ConfirmReason>| reason.map_or(0, ConfirmReason::strictness);
    accepting.iter().fold(
        (seed, confirmation_for(seed, caller, settings)),
        |(cited, reason), &action| {
            let candidate = confirmation_for(action, caller, settings);
            if rank(candidate) > rank(reason) {
                (action, candidate)
            } else {
                (cited, reason)
            }
        },
    )
}

/// The trace's account of the requirement, which says so when more than one
/// action accepted the command.
fn confirmation_text(reason: Option<ConfirmReason>, accepting: usize) -> String {
    match (reason, accepting) {
        (Some(reason), 1) => reason.explain().to_owned(),
        (None, 1) => "no confirmation requirement applies".to_owned(),
        (Some(reason), count) => format!(
            "{}; the strictest requirement among the {count} actions that accept this command",
            reason.explain()
        ),
        (None, count) => {
            format!("none of the {count} actions that accept this command requires confirmation")
        }
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

    // --- overlapping actions resolve to the strictest -----------------------

    /// `apt-get -y remove <pkg>`, demanding nothing beyond the agent setting.
    fn remove(id: &str, line: u32) -> Action {
        Action {
            id: ActionId::new(id),
            tier: Tier::PkgRemove,
            exe: "/usr/bin/apt-get".into(),
            args: vec![
                ArgSpec::one("y", Matcher::Literal("-y".into())),
                ArgSpec::one("verb", Matcher::Literal("remove".into())),
                ArgSpec::one("pkg", Matcher::Name(NameKind::DebName)),
            ],
            confirm: ConfirmPolicy::Default,
            agent_allowed: true,
            env_allow: Vec::new(),
            source: Source::new("30-packages.toml", line),
        }
    }

    /// The same command, under a rule that always confirms.
    fn confirming_remove(id: &str, line: u32) -> Action {
        Action {
            confirm: ConfirmPolicy::Always,
            ..remove(id, line)
        }
    }

    fn apt_get() -> Arg {
        Arg::from("/usr/bin/apt-get")
    }

    fn remove_ripgrep() -> Argv {
        Argv::new(["-y", "remove", "ripgrep"])
    }

    fn matched_ids(decision: &Decision) -> Vec<String> {
        decision
            .trace
            .iter()
            .filter_map(|step| match step {
                TraceStep::ActionMatched { action, .. } => Some(action.clone()),
                _ => None,
            })
            .collect()
    }

    fn confirmation_reason(decision: &Decision) -> String {
        decision
            .trace
            .iter()
            .filter_map(|step| match step {
                TraceStep::ConfirmationDecided { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_later_permissive_duplicate_cannot_weaken_an_earlier_confirming_rule() {
        // The hole this resolution closes. With the first permitting action
        // winning, whichever of these two was declared first decided whether a
        // human was asked; now both orders demand the confirmation, and cite
        // the rule that demands it.
        for declared in [
            vec![
                confirming_remove("aido.pkg.remove", 3),
                remove("aido.pkg.remove-quiet", 9),
            ],
            vec![
                remove("aido.pkg.remove-quiet", 3),
                confirming_remove("aido.pkg.remove", 9),
            ],
        ] {
            let set = RuleSet::load(declared).unwrap();
            let d = evaluate_command(
                &set,
                &human(),
                &apt_get(),
                &remove_ripgrep(),
                Settings::default(),
            );
            assert_eq!(d.verdict, Verdict::AllowWithConfirmation);
            assert_eq!(
                d.confirm,
                Confirm::Required {
                    reason: ConfirmReason::RuleRequiresConfirmation
                }
            );
            assert_eq!(d.action, Some(ActionId::new("aido.pkg.remove")));
            assert_eq!(d.resolved_exe.as_deref(), Some("/usr/bin/apt-get"));
            // Both actions are on the record, and the trace says why the
            // stricter one decided.
            assert_eq!(matched_ids(&d).len(), 2, "{:?}", d.trace);
            assert!(
                confirmation_reason(&d).contains("strictest requirement among the 2 actions"),
                "{:?}",
                d.trace
            );
        }
    }

    #[test]
    fn naming_the_permissive_duplicate_cannot_skip_the_confirmation() {
        // The caller chooses which action to name. A requirement that bound
        // only the named action would let it name the weakest one.
        let set = RuleSet::load(vec![
            confirming_remove("aido.pkg.remove", 3),
            remove("aido.pkg.remove-quiet", 9),
        ])
        .unwrap();
        let d = evaluate(
            &set,
            &human(),
            &Request::for_program("aido.pkg.remove-quiet", apt_get(), remove_ripgrep()),
            Settings::default(),
        );
        assert_eq!(d.verdict, Verdict::AllowWithConfirmation);
        // Cited: the rule whose requirement the decision carries, not the one
        // that was named, so the human approving sees why they were asked.
        assert_eq!(d.action, Some(ActionId::new("aido.pkg.remove")));
        assert_eq!(
            d.rule_source.as_ref().map(ToString::to_string),
            Some("30-packages.toml:3".to_owned())
        );
    }

    #[test]
    fn a_permissive_duplicate_cannot_hand_a_human_only_command_to_an_agent() {
        let reserved = Action {
            agent_allowed: false,
            ..remove("aido.pkg.remove-by-hand", 3)
        };
        let set = RuleSet::load(vec![reserved, remove("aido.pkg.remove-quiet", 9)]).unwrap();
        let named = evaluate(
            &set,
            &agent(),
            &Request::for_program("aido.pkg.remove-quiet", apt_get(), remove_ripgrep()),
            Settings::default(),
        );
        let searched = evaluate_command(
            &set,
            &agent(),
            &apt_get(),
            &remove_ripgrep(),
            Settings::default(),
        );
        for d in [&named, &searched] {
            assert_eq!(d.denial, Some(DenialCode::HumanPathOnly));
            // The permissive duplicate is set aside by name, with the rule
            // that reserved the command, so an operator can see which one did.
            let set_aside = d.trace.iter().any(|step| {
                matches!(
                    step,
                    TraceStep::ActionRejected { action, reason }
                        if action == "aido.pkg.remove-quiet"
                            && reason.contains("aido.pkg.remove-by-hand at 30-packages.toml:3")
                )
            });
            assert!(set_aside, "{:?}", d.trace);
        }
        // Misclassification may only withhold: a person is still served.
        let person = evaluate_command(
            &set,
            &human(),
            &apt_get(),
            &remove_ripgrep(),
            Settings::default(),
        );
        assert_eq!(person.verdict, Verdict::Allow);
    }

    #[test]
    fn the_hardest_requirement_to_lift_wins_whatever_the_order() {
        let critical = Action {
            tier: Tier::Critical,
            ..remove("aido.pkg.remove-critical", 5)
        };
        for declared in [
            vec![
                remove("aido.pkg.remove", 1),
                confirming_remove("aido.pkg.remove-always", 3),
                critical.clone(),
            ],
            vec![
                critical.clone(),
                confirming_remove("aido.pkg.remove-always", 3),
                remove("aido.pkg.remove", 1),
            ],
        ] {
            let set = RuleSet::load(declared).unwrap();
            let d = evaluate_command(
                &set,
                &agent(),
                &apt_get(),
                &remove_ripgrep(),
                Settings::default(),
            );
            assert_eq!(
                d.confirm,
                Confirm::Required {
                    reason: ConfirmReason::CriticalTier
                }
            );
            assert_eq!(d.action, Some(ActionId::new("aido.pkg.remove-critical")));
        }
    }

    #[test]
    fn a_tie_cites_the_named_action_or_else_the_first_declared() {
        let set = RuleSet::load(vec![
            remove("aido.pkg.remove", 3),
            remove("aido.pkg.remove-again", 9),
        ])
        .unwrap();
        let searched = evaluate_command(
            &set,
            &agent(),
            &apt_get(),
            &remove_ripgrep(),
            Settings::default(),
        );
        assert_eq!(searched.action, Some(ActionId::new("aido.pkg.remove")));
        let named = evaluate(
            &set,
            &agent(),
            &Request::for_program("aido.pkg.remove-again", apt_get(), remove_ripgrep()),
            Settings::default(),
        );
        assert_eq!(named.action, Some(ActionId::new("aido.pkg.remove-again")));
        // A tie is a tie: the requirement is the same either way.
        assert_eq!(searched.confirm, named.confirm);
        assert_eq!(searched.verdict, Verdict::AllowWithConfirmation);
    }

    #[test]
    fn overlapping_actions_that_demand_nothing_say_so() {
        let set = RuleSet::load(vec![
            remove("aido.pkg.remove", 3),
            remove("aido.pkg.remove-again", 9),
        ])
        .unwrap();
        let d = evaluate_command(
            &set,
            &human(),
            &apt_get(),
            &remove_ripgrep(),
            Settings::default(),
        );
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(
            confirmation_reason(&d),
            "none of the 2 actions that accept this command requires confirmation"
        );
    }

    #[test]
    fn the_deny_list_still_wins_over_every_overlapping_allow() {
        let shell = |id: &str| Action {
            id: ActionId::new(id),
            tier: Tier::DiagRead,
            exe: "/bin/sh".into(),
            args: vec![ArgSpec::one("c", Matcher::Literal("-c".into()))],
            confirm: ConfirmPolicy::Never,
            agent_allowed: true,
            env_allow: Vec::new(),
            source: Source::new("99-oops.toml", 1),
        };
        let set = RuleSet::load(vec![shell("aido.oops.one"), shell("aido.oops.two")]).unwrap();
        let d = evaluate_command(
            &set,
            &human(),
            &Arg::from("/bin/sh"),
            &Argv::new(["-c"]),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::DenyListed));
        assert_eq!(matched_ids(&d), ["aido.oops.one", "aido.oops.two"]);
    }

    #[test]
    fn a_command_no_action_runs_is_refused_naming_the_program() {
        let d = evaluate_command(
            &rules(),
            &human(),
            &Arg::from("/bin/sh"),
            &Argv::new(["-c", "id"]),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::UnknownAction));
        // There is no rule to cite, so the record carries the command itself.
        assert_eq!(d.resolved_command(), ["/bin/sh", "-c", "id"]);
        assert_eq!(d.trace.len(), 1, "{:?}", d.trace);
    }

    #[test]
    fn a_command_every_candidate_refuses_lists_each_refusal() {
        let set =
            RuleSet::load(vec![svc_restart(), restart_action_named("aido.svc.again")]).unwrap();
        let d = evaluate_command(
            &set,
            &human(),
            &Arg::from("/usr/bin/systemctl"),
            &Argv::new(["restart", "nginx"]),
            Settings::default(),
        );
        assert_eq!(d.denial, Some(DenialCode::ArgvRejected));
        let refused: Vec<&str> = d
            .trace
            .iter()
            .filter_map(|step| match step {
                TraceStep::ActionRejected { action, .. } => Some(action.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(refused, ["aido.svc.restart", "aido.svc.again"]);
    }

    /// `restart_action` under another id, so two actions accept one command.
    fn restart_action_named(id: &str) -> Action {
        Action {
            id: ActionId::new(id),
            ..restart_action()
        }
    }

    #[test]
    fn a_frozen_agent_is_refused_before_any_action_is_consulted() {
        let frozen = Settings {
            confirm_agent_actions: true,
            frozen: true,
        };
        // Even with nothing in the ruleset: the freeze is the answer, not a
        // missing rule that would send an operator hunting.
        let d = evaluate_command(
            &RuleSet::default(),
            &agent(),
            &Arg::from("/usr/bin/systemctl"),
            &Argv::new(["restart", "nginx.service"]),
            frozen,
        );
        assert_eq!(d.denial, Some(DenialCode::Frozen));
        assert_eq!(d.resolved_argv, ["restart", "nginx.service"]);
    }

    #[test]
    fn searching_and_naming_agree_on_a_command_only_one_action_accepts() {
        let searched = evaluate_command(
            &rules(),
            &agent(),
            &Arg::from("/usr/bin/systemctl"),
            &Argv::new(["restart", "nginx.service"]),
            Settings::default(),
        );
        let named = evaluate(
            &rules(),
            &agent(),
            &Request::for_program(
                "aido.svc.restart",
                "/usr/bin/systemctl",
                Argv::new(["restart", "nginx.service"]),
            ),
            Settings::default(),
        );
        assert_eq!(searched, named);
    }
}
