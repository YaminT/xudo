//! A typed operation the gate runs itself. It never execs.
//!
//! The `-auth` gate runs it after `sudo` asked the password. The `-nopass`
//! gate runs it only for a live harness the operation rule lists with
//! `outcome = "allow"`, re-decided here from root's rules: the broker's
//! verdict is not an input. Either way the walk is the same one, with the
//! rule's tree, depth, entry cap and owners.

use xudo_audit::record::{Decision as AuditDecision, Outcome, Record};
use xudo_policy::{CallerFacts, OwnerPolicy, RuleSet, engine::Settings};
use xudo_sys::{RemoveError, RemoveOwnerPolicy, RemoveReport, RemoveRequest};
use xudo_wire::OPERATION_PROGRAM;

use xudo_sys::GateMode;

use crate::decide::{GateCaller, ModeRefusal, Refusal, Severity, Stage, mode_refusal};
use crate::request::PendingRequest;

/// What the walk is allowed to do, plus the fields the audit record cites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OperationWork {
    /// The walk's request.
    pub(crate) request: RemoveRequest,
    /// The operation id.
    pub(crate) id: String,
    /// `file:line` of the rule.
    pub(crate) source: String,
    /// The tree, for the record. The same bytes as [`RemoveRequest::under`].
    pub(crate) under: Vec<u8>,
    /// The absolute target the caller asked for.
    pub(crate) target: Vec<u8>,
    /// Sequence number of the pre-walk intent record.
    pub(crate) intent_sequence: Option<u64>,
    /// The entry's `via`: `auth` after a password, `harness` for a grant.
    pub(crate) via: &'static str,
}

/// Re-decide `pending` and build the walk request.
///
/// # Errors
///
/// A missing human-path confirmation, a program that is not the operation
/// marker, an unknown op, a policy denial, or, on `-nopass`, no grant for
/// this harness. Nothing has been removed.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_remove(
    rules: &RuleSet,
    caller: &CallerFacts,
    pending: &PendingRequest,
    op_name: &str,
    target: &[u8],
    dry_run: bool,
    settings: Settings,
    passwd: &str,
    mode: GateMode,
) -> Result<OperationWork, Refusal> {
    // On `-nopass` the setting withholds the grant instead (see
    // `judge_remove_path`), so a harness entry never waits on a watcher.
    if mode == GateMode::Auth && settings.confirm_human_path && !pending.confirmed {
        return Err(Refusal::Failed {
            stage: Stage::Invocation,
            reason: "remove-path requires the configured human-path confirmation".to_owned(),
        });
    }
    if pending.program != OPERATION_PROGRAM || op_name != "remove-path" {
        return Err(Refusal::Failed {
            stage: Stage::Invocation,
            reason: "the spool entry is not a remove-path operation".to_owned(),
        });
    }
    let grant = match xudo_policy::judge_remove_path(rules, caller, target, settings, passwd) {
        Ok(grant) => grant,
        Err(decision) => return Err(Refusal::Policy(decision)),
    };
    // No password was asked: only the rule's grant to this live harness, the
    // label the broker minted the entry for, lets the walk run.
    if mode == GateMode::Nopass
        && (grant.harness.is_none() || grant.harness != pending.attested_harness)
    {
        return Err(mode_refusal(mode, ModeRefusal::NotGranted));
    }
    let requested_target = target.escape_ascii().to_string();
    if pending.action != grant.id.as_str()
        || pending.operation.as_ref().is_none_or(|operation| {
            operation.op != op_name || operation.target.as_slice() != target
        })
        || pending.argv.len() != 1
        || pending
            .argv
            .first()
            .is_none_or(|argument| argument != &requested_target)
    {
        return Err(Refusal::Failed {
            stage: Stage::Rules,
            reason: "the spool entry does not match the gate-selected operation and target"
                .to_owned(),
        });
    }
    Ok(OperationWork {
        request: RemoveRequest {
            under: grant.under.clone(),
            relative: grant.relative,
            recursive: grant.recursive,
            max_depth: grant.max_depth,
            max_entries: grant.max_entries,
            owners: walk_owners(grant.owners),
            dry_run,
        },
        id: grant.id.to_string(),
        source: grant.source.to_string(),
        under: grant.under,
        target: target.to_vec(),
        intent_sequence: None,
        via: pending.via.label(),
    })
}

fn walk_owners(owners: OwnerPolicy) -> RemoveOwnerPolicy {
    match owners {
        OwnerPolicy::AnyButRoot => RemoveOwnerPolicy::AnyButRoot,
        OwnerPolicy::Only(ids) => RemoveOwnerPolicy::Only(ids),
    }
}

/// Evidence for the one record of a finished walk.
pub(crate) fn remove_evidence(work: &OperationWork, report: &RemoveReport) -> Vec<String> {
    let severity = if report.dry_run {
        Severity::Low
    } else {
        Severity::Normal
    };
    let mut evidence = vec![
        "op=remove-path".to_owned(),
        format!("via={}", work.via),
        format!("tree={}", work.under.escape_ascii()),
        format!("target={}", work.target.escape_ascii()),
        format!("count={}", report.removed.len()),
        format!("bytes={}", report.bytes),
        format!("dry_run={}", report.dry_run),
        format!("severity={}", severity.label()),
        format!("partial={}", report.partial),
        format!("paths_sha256={}", hex_digest(&report.digest)),
    ];
    if let Some(error) = &report.error {
        evidence.push(format!("error={error}"));
    }
    if let Some(sequence) = work.intent_sequence {
        evidence.push(format!("intent_seq={sequence}"));
    }
    for path in xudo_sys::remove::audit_path_head(&report.removed) {
        evidence.push(format!("path={}", path.escape_ascii()));
    }
    evidence
}

/// Audit the planned tree and target before any unlink can occur.
pub(crate) fn intent_record(
    previous: Option<&Record>,
    caller: &GateCaller,
    work: &OperationWork,
    planned: &RemoveReport,
) -> Record {
    let argv = vec![
        OPERATION_PROGRAM.to_owned(),
        work.target.escape_ascii().to_string(),
    ];
    Record::after(
        previous,
        AuditDecision::Allowed,
        argv,
        caller.facts.classification.label(),
    )
    .with_rule(&work.id, &work.source)
    // `planned_sha256` is an audit trace of the gate's own dry-run, computed
    // after the request was consumed. It is not an approval binding: the
    // broker never approves a digest and nothing requires it to match one.
    .with_evidence(vec![
        "op=remove-path-intent".to_owned(),
        format!("via={}", work.via),
        format!("tree={}", work.under.escape_ascii()),
        format!("target={}", work.target.escape_ascii()),
        format!("planned_count={}", planned.removed.len()),
        format!("planned_partial={}", planned.partial),
        format!("planned_sha256={}", hex_digest(&planned.digest)),
    ])
    .with_outcome(Outcome::NotExecuted)
}

/// The audit record written after the walk. A dry run did not exec and did
/// not unlink. A real removal is recorded as an exit so a later query can
/// see that privileged names were deleted.
pub(crate) fn remove_record(
    previous: Option<&Record>,
    caller: &GateCaller,
    work: &OperationWork,
    report: &RemoveReport,
) -> Record {
    let argv = vec![
        OPERATION_PROGRAM.to_owned(),
        work.target.escape_ascii().to_string(),
    ];
    let outcome = if report.dry_run {
        Outcome::NotExecuted
    } else {
        Outcome::Exited {
            code: i32::from(report.partial),
        }
    };
    Record::after(
        previous,
        AuditDecision::Allowed,
        argv,
        caller.facts.classification.label(),
    )
    .with_rule(&work.id, &work.source)
    .with_evidence(remove_evidence(work, report))
    .with_outcome(outcome)
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

fn hex_digit(nibble: u8) -> char {
    match nibble {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'a',
        11 => 'b',
        12 => 'c',
        13 => 'd',
        14 => 'e',
        _ => 'f',
    }
}

/// A walk error before any name was removed. The caller has already consumed
/// the spool entry.
pub(crate) fn walk_refusal(error: &RemoveError) -> Refusal {
    Refusal::Failed {
        stage: Stage::Exec,
        reason: error.to_string(),
    }
}

/// Whether a policy denial from this path is `DenialCode::OperationRefused`.
#[cfg(test)]
pub(crate) fn is_operation_refusal(refusal: &Refusal) -> bool {
    match refusal {
        Refusal::Policy(decision) => {
            decision.denial == Some(xudo_policy::DenialCode::OperationRefused)
        }
        Refusal::NoPendingRequest { .. }
        | Refusal::Request(_)
        | Refusal::ConfirmationMissing(_)
        | Refusal::Mode { .. }
        | Refusal::RateCeiling { .. }
        | Refusal::Failed { .. } => false,
    }
}

/// Exit status of a finished walk. Partial is 1. A complete walk, including a
/// dry run, is 0.
pub(crate) fn operation_status(report: &RemoveReport) -> i32 {
    i32::from(report.partial)
}

/// The line the gate prints after a walk. Not a refusal.
pub(crate) fn operation_message(report: &RemoveReport) -> String {
    if report.dry_run {
        format!("xudo-gate: dry-run listed {} paths", report.removed.len())
    } else if report.partial {
        format!(
            "xudo-gate: partial remove of {} paths",
            report.removed.len()
        )
    } else {
        format!("xudo-gate: removed {} paths", report.removed.len())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use xudo_policy::{
        CallerFacts, Classification, Decision, DenialCode, RuleSet, Verdict, engine::Settings,
    };
    use xudo_sys::{RemoveError, RemoveOwnerPolicy, RemoveReport};

    use super::*;
    use crate::decide::GateCaller;
    use crate::request::{
        AttestedClass, BoottimeMillis, CallerPin, PendingRequest, RequestError, RequestedOp,
    };

    const PASSWD: &str = "agent:x:1000:1000:agent:/home/agent:/bin/sh\n";

    fn rules(text: &str) -> RuleSet {
        RuleSet::from_toml("50-remove-path.toml", text).unwrap()
    }

    fn sample() -> RuleSet {
        rules(
            r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 4
max-entries = 10
"#,
        )
    }

    fn named_owners() -> RuleSet {
        rules(
            r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = false
max-depth = 2
max-entries = 3
owners = ["agent"]
"#,
        )
    }

    fn human() -> CallerFacts {
        CallerFacts::new(Classification::Human, 1000)
    }

    fn pending(program: &str, op: &str) -> PendingRequest {
        PendingRequest {
            schema_version: crate::request::REQUEST_SCHEMA_VERSION,
            nonce: "ab".repeat(32),
            caller_pid: 1,
            caller_starttime: 2,
            action: "web.clean-build".into(),
            program: program.into(),
            argv: vec![b"/srv/app/build/cache".escape_ascii().to_string()],
            generation: 1,
            deadline: BoottimeMillis(9),
            confirmed: false,
            confirmed_by: None,
            state: crate::request::ConfirmationState::Pending,
            caller_uid: 1000,
            caller_sid: 1,
            caller_tty: 1,
            needs_watch: false,
            shown_at_ms: None,
            shown_to: None,
            fingerprint: "0".repeat(64),
            claimed_classification: "unattested".into(),
            attested_class: AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
            attested_harness: None,
            via: crate::request::Via::Auth,
            queue_id: None,
            operation: Some(RequestedOp {
                op: op.into(),
                target: b"/srv/app/build/cache".to_vec(),
                dry_run: false,
            }),
        }
    }

    fn prepare<'a>(
        rules: &'a RuleSet,
        pending: &'a PendingRequest,
        password: bool,
    ) -> Result<OperationWork, Refusal> {
        prepare_as(rules, &human(), pending, password, Settings::default())
    }

    fn prepare_as(
        rules: &RuleSet,
        caller: &CallerFacts,
        pending: &PendingRequest,
        password: bool,
        settings: Settings,
    ) -> Result<OperationWork, Refusal> {
        let op = pending.operation.as_ref().unwrap();
        prepare_remove(
            rules,
            caller,
            pending,
            &op.op,
            &op.target,
            op.dry_run,
            settings,
            PASSWD,
            if password {
                GateMode::Auth
            } else {
                GateMode::Nopass
            },
        )
    }

    fn codex() -> CallerFacts {
        CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "codex".into(),
                session_id: "s".into(),
                declared_yolo: false,
            },
            1000,
        )
    }

    fn granting() -> RuleSet {
        rules(
            r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 4
max-entries = 10
harness = ["codex"]
outcome = "allow"
"#,
        )
    }

    fn harness_pending() -> PendingRequest {
        let mut entry = pending(OPERATION_PROGRAM, "remove-path");
        entry.via = crate::request::Via::Harness;
        entry.attested_harness = Some("codex".into());
        entry
    }

    fn not_granted() -> Refusal {
        Refusal::Mode {
            mode: "-nopass",
            reason: ModeRefusal::NotGranted,
        }
    }

    #[test]
    fn prepare_remove_grants_any_owner_but_root_on_the_password_path() {
        let work = prepare(&sample(), &pending(OPERATION_PROGRAM, "remove-path"), true).unwrap();
        assert_eq!(work.id, "web.clean-build");
        assert_eq!(work.request.relative, b"cache");
        assert_eq!(work.request.owners, RemoveOwnerPolicy::AnyButRoot);
        assert!(!work.request.dry_run);
    }

    #[test]
    fn prepare_remove_resolves_a_listed_owner() {
        let work = prepare(
            &named_owners(),
            &pending(OPERATION_PROGRAM, "remove-path"),
            true,
        )
        .unwrap();
        assert_eq!(work.request.owners, RemoveOwnerPolicy::Only(vec![1000]));
    }

    #[test]
    fn nopass_runs_a_remove_path_the_rule_grants_this_harness() {
        let work = prepare_as(
            &granting(),
            &codex(),
            &harness_pending(),
            false,
            Settings::default(),
        )
        .unwrap();
        // The same walk the password path would run: the rule's bounds.
        assert_eq!(work.request.under, b"/srv/app/build");
        assert_eq!(work.request.relative, b"cache");
        assert_eq!(work.request.max_depth, 4);
        assert_eq!(work.request.max_entries, 10);
        assert_eq!(work.request.owners, RemoveOwnerPolicy::AnyButRoot);
    }

    #[test]
    fn nopass_refuses_a_remove_path_without_a_grant() {
        // A human, an unlisted harness, and a rule that lists nobody: no
        // password was asked, so nothing runs.
        let claude = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "claude".into(),
                session_id: "s".into(),
                declared_yolo: false,
            },
            1000,
        );
        for (set, caller) in [
            (sample(), codex()),
            (granting(), human()),
            (granting(), claude),
        ] {
            let error = prepare_as(
                &set,
                &caller,
                &harness_pending(),
                false,
                Settings::default(),
            )
            .unwrap_err();
            assert_eq!(error, not_granted(), "{caller:?}");
            assert!(!is_operation_refusal(&error));
        }
    }

    #[test]
    fn nopass_refuses_a_grant_for_a_label_the_entry_was_not_minted_for() {
        let mut entry = harness_pending();
        entry.attested_harness = Some("claude".into());
        assert_eq!(
            prepare_as(&granting(), &codex(), &entry, false, Settings::default()).unwrap_err(),
            not_granted()
        );
        entry.attested_harness = None;
        assert_eq!(
            prepare_as(&granting(), &codex(), &entry, false, Settings::default()).unwrap_err(),
            not_granted()
        );
    }

    #[test]
    fn nopass_withholds_a_remove_path_grant_under_confirm_human_path() {
        // The human-path watch is a confirmation a harness cannot give: the
        // grant is withheld rather than waited on, and nothing runs.
        let settings = Settings {
            confirm_human_path: true,
            ..Settings::default()
        };
        assert_eq!(
            prepare_as(&granting(), &codex(), &harness_pending(), false, settings).unwrap_err(),
            not_granted()
        );
    }

    #[test]
    fn nopass_refuses_a_target_outside_the_granted_tree() {
        let mut entry = harness_pending();
        entry.argv = vec!["/etc/passwd".into()];
        entry.operation = Some(RequestedOp {
            op: "remove-path".into(),
            target: b"/etc/passwd".to_vec(),
            dry_run: false,
        });
        let error =
            prepare_as(&granting(), &codex(), &entry, false, Settings::default()).unwrap_err();
        assert!(is_operation_refusal(&error));
    }

    #[test]
    fn nopass_entry_for_one_path_cannot_remove_another() {
        // The entry's argv names one path and its operation another: the gate
        // refuses rather than pick either.
        let mut entry = harness_pending();
        entry.argv = vec!["/srv/app/build/other".into()];
        assert_eq!(
            prepare_as(&granting(), &codex(), &entry, false, Settings::default()).unwrap_err(),
            Refusal::Failed {
                stage: Stage::Rules,
                reason: "the spool entry does not match the gate-selected operation and target"
                    .into(),
            }
        );
    }

    #[test]
    fn nopass_refuses_a_frozen_harness_before_the_walk() {
        let frozen = Settings {
            frozen: true,
            ..Settings::default()
        };
        let error =
            prepare_as(&granting(), &codex(), &harness_pending(), false, frozen).unwrap_err();
        assert_eq!(denial_of(&error), Some(DenialCode::Frozen));
    }

    #[test]
    fn prepare_remove_requires_the_configured_human_path_confirmation() {
        let settings = Settings {
            confirm_human_path: true,
            ..Settings::default()
        };
        let entry = pending(OPERATION_PROGRAM, "remove-path");
        assert_eq!(
            prepare_remove(
                &sample(),
                &human(),
                &entry,
                "remove-path",
                b"/srv/app/build/cache",
                false,
                settings,
                PASSWD,
                GateMode::Auth,
            )
            .unwrap_err(),
            Refusal::Failed {
                stage: Stage::Invocation,
                reason: "remove-path requires the configured human-path confirmation".into(),
            }
        );
        let mut confirmed = entry;
        confirmed.confirmed = true;
        confirmed.confirmed_by = Some(crate::request::WatcherPin {
            uid: 1000,
            pid: 9,
            starttime: 10,
            tty: 2,
            sid: 3,
        });
        assert!(
            prepare_remove(
                &sample(),
                &human(),
                &confirmed,
                "remove-path",
                b"/srv/app/build/cache",
                false,
                settings,
                PASSWD,
                GateMode::Auth,
            )
            .is_ok()
        );
    }

    #[test]
    fn prepare_remove_refuses_a_marker_mismatch_and_an_unknown_op() {
        let wrong_program =
            prepare(&sample(), &pending("/bin/true", "remove-path"), true).unwrap_err();
        assert_eq!(
            wrong_program,
            Refusal::Failed {
                stage: Stage::Invocation,
                reason: "the spool entry is not a remove-path operation".into(),
            }
        );
        let wrong_op =
            prepare(&sample(), &pending(OPERATION_PROGRAM, "write-file"), true).unwrap_err();
        assert_eq!(wrong_op, wrong_program);
    }

    #[test]
    fn prepare_remove_refuses_a_target_outside_the_tree() {
        let mut entry = pending(OPERATION_PROGRAM, "remove-path");
        entry.operation = Some(RequestedOp {
            op: "remove-path".into(),
            target: b"/etc/passwd".to_vec(),
            dry_run: false,
        });
        let error = prepare(&sample(), &entry, true).unwrap_err();
        assert!(is_operation_refusal(&error));
        assert_eq!(denial_of(&error), Some(DenialCode::OperationRefused));
        assert_eq!(verdict_of(&error), Some(Verdict::Deny));
        let frozen = Refusal::Policy(Box::new(Decision::deny(
            DenialCode::Frozen,
            Vec::new(),
            Vec::new(),
        )));
        assert!(!is_operation_refusal(&frozen));
        assert_eq!(denial_of(&frozen), Some(DenialCode::Frozen));
        assert_eq!(verdict_of(&frozen), Some(Verdict::Deny));
        let mut bare = Decision::deny(DenialCode::Frozen, Vec::new(), Vec::new());
        bare.denial = None;
        bare.verdict = Verdict::Allow;
        let bare = Refusal::Policy(Box::new(bare));
        assert!(!is_operation_refusal(&bare));
        assert_eq!(denial_of(&bare), None);
        assert_eq!(verdict_of(&bare), Some(Verdict::Allow));
    }

    fn denial_of(refusal: &Refusal) -> Option<DenialCode> {
        match refusal {
            Refusal::Policy(decision) => decision.denial,
            Refusal::NoPendingRequest { .. }
            | Refusal::Request(_)
            | Refusal::ConfirmationMissing(_)
            | Refusal::Mode { .. }
            | Refusal::RateCeiling { .. }
            | Refusal::Failed { .. } => None,
        }
    }

    fn verdict_of(refusal: &Refusal) -> Option<Verdict> {
        match refusal {
            Refusal::Policy(decision) => Some(decision.verdict),
            Refusal::NoPendingRequest { .. }
            | Refusal::Request(_)
            | Refusal::ConfirmationMissing(_)
            | Refusal::Mode { .. }
            | Refusal::RateCeiling { .. }
            | Refusal::Failed { .. } => None,
        }
    }

    fn report(paths: &[&[u8]], dry_run: bool, partial: bool) -> RemoveReport {
        let removed = paths.iter().map(|path| path.to_vec()).collect::<Vec<_>>();
        RemoveReport {
            digest: xudo_sys::removal_digest(&removed),
            removed,
            bytes: 4,
            partial,
            error: None,
            dry_run,
        }
    }

    fn caller() -> GateCaller {
        GateCaller {
            pin: CallerPin::new(1, 2),
            facts: human(),
            attested_class: AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }

    #[test]
    fn a_dry_run_record_is_low_severity_and_a_real_removal_names_every_path_or_its_hash() {
        let work = prepare(&sample(), &pending(OPERATION_PROGRAM, "remove-path"), true).unwrap();
        let dry = remove_record(
            None,
            &caller(),
            &work,
            &report(&[b"/srv/app/build/cache"], true, false),
        );
        assert_eq!(dry.outcome.kind(), "not_executed");
        assert!(dry.evidence.iter().any(|line| line == "severity=low"));
        assert!(dry.evidence.iter().any(|line| line == "dry_run=true"));
        assert_eq!(dry.action.as_deref(), Some("web.clean-build"));

        let mut many = Vec::new();
        for index in 0..70u8 {
            many.push(format!("/srv/app/build/f{index}").into_bytes());
        }
        let full = report_owned(&many, false, true);
        let head = report_owned(
            &many.iter().take(64).cloned().collect::<Vec<_>>(),
            false,
            true,
        );
        let real = remove_record(None, &caller(), &work, &full);
        assert_eq!(real.outcome.kind(), "exited");
        let paths = real
            .evidence
            .iter()
            .filter(|line| line.starts_with("path="))
            .count();
        assert_eq!(paths, 64);
        let full_hash = real
            .evidence
            .iter()
            .find(|line| line.starts_with("paths_sha256="))
            .unwrap()
            .clone();
        let head_record = remove_record(None, &caller(), &work, &head);
        let head_hash = head_record
            .evidence
            .iter()
            .find(|line| line.starts_with("paths_sha256="))
            .unwrap();
        assert_ne!(full_hash.as_str(), head_hash);
        assert!(real.evidence.iter().any(|line| line == "severity=normal"));
        assert!(real.evidence.iter().any(|line| line == "partial=true"));
        assert_eq!(operation_status(&full), 1);
        assert_eq!(operation_status(&head), 1);
        let mut complete = report(&[b"/srv/app/build/cache"], false, false);
        complete.error = Some(xudo_sys::RemoveError::Os {
            op: "unlinkat",
            errno: 5,
        });
        let complete_record = remove_record(None, &caller(), &work, &complete);
        assert!(
            complete_record
                .evidence
                .iter()
                .any(|line| line == "bytes=4")
        );
        assert!(
            complete_record
                .evidence
                .iter()
                .any(|line| line == "error=unlinkat failed with errno 5")
        );
        assert_eq!(operation_status(&complete), 0);
        assert!(operation_message(&complete).contains("removed 1"));
        assert!(operation_message(&report(&[b"/a"], true, false)).contains("dry-run"));
        assert!(operation_message(&full).contains("partial"));
        let refusal = walk_refusal(&RemoveError::AncestorRefused);
        assert_eq!(
            refusal,
            Refusal::Failed {
                stage: Stage::Exec,
                reason: RemoveError::AncestorRefused.to_string(),
            }
        );
        let request = Refusal::Request(RequestError::NoAction);
        let missing = Refusal::NoPendingRequest { pid: 1 };
        let confirm = Refusal::ConfirmationMissing(Box::new(Decision::deny(
            DenialCode::Frozen,
            Vec::new(),
            Vec::new(),
        )));
        let failed = Refusal::Failed {
            stage: Stage::Audit,
            reason: "audit".to_owned(),
        };
        for case in [&request, &missing, &confirm, &failed, &refusal] {
            assert!(!is_operation_refusal(case));
            assert_eq!(denial_of(case), None);
            assert_eq!(verdict_of(case), None);
        }
    }

    fn report_owned(paths: &[Vec<u8>], dry_run: bool, partial: bool) -> RemoveReport {
        RemoveReport {
            digest: xudo_sys::removal_digest(paths),
            removed: paths.to_vec(),
            bytes: 1,
            partial,
            error: None,
            dry_run,
        }
    }

    #[test]
    fn hex_digits_cover_every_nibble() {
        let digest = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef].repeat(4);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        assert_eq!(
            hex_digest(&bytes),
            "0123456789abcdef".repeat(2) + &"0123456789abcdef".repeat(2)
        );
    }
}
