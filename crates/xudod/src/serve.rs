//! One connection, start to finish.
//!
//! ```text
//! identify the peer      kernel facts only; refuse if it cannot be pinned honestly
//! read the request       bounded in size and time; parsed as hostile
//! check the spool        root-owned, private, reached through trusted components
//! load root's policy     the trusted ruleset and settings, or refuse
//! classify               Unattested, always, in M2b
//! decide                 the function behind `xudo explain`
//! mint                   permitted decisions only; recorded before it exists
//! answer                 one response, then close
//! ```
//!
//! Every step that fails answers with a refusal and an audit record, and the
//! steps run in this order so that a refusal never describes something that
//! was not established: the peer is known before its request is read, and the
//! request is known before anything is said about the spool or the policy.
//! Nothing after a failure runs.

use serde::{Deserialize, Serialize};
use xudo_audit::record::Record;
use xudo_policy::{CallerFacts, Decision};
use xudo_sys::{
    AuditError, AuditSink, Clock, Connection, Entropy, Hygiene, PeerCalls, Spool, SpoolError,
    Syscalls, authorize,
};
use xudo_wire::{BrokerRequest, BrokerResponse, MAX_REQUEST_BYTES, Minted, RefusalCode};

use crate::identify::{Fault, PeerIdentity, identify};
use crate::mint::{
    AttestedCaller, Grant, MintError, Minting, REQUEST_TTL_MILLIS, draw_nonce,
    entry_for_classified, publish,
};
use crate::policy::{LoadedPolicy, PolicySource, classify, decide, stored_caller};
use crate::record::{decided, refused};
use crate::refusal::Refusal;

/// The exit status of a broker that could not do its job: `xudo`'s own
/// "unusable", 19.
pub const UNUSABLE: u8 = 19;

/// Everything the broker asks of its host, as seams.
pub struct Platform<'a> {
    /// Establishes process hygiene before the peer or request is inspected.
    pub hygiene: &'a dyn Hygiene,
    /// The calls that need `unsafe` and that the ladder makes itself:
    /// `SO_PEERPIDFD` and `PIDFD_GET_INFO`.
    pub syscalls: &'a dyn Syscalls,
    /// `pidfd_open`, `/proc`, and the liveness poll, which are safe in rustix,
    /// and `SO_PEERCRED`, which is not and is carried here only as a seam: the
    /// host reads it through `Syscalls::peer_cred`, behind a check of the
    /// socket's kind, and never through rustix's own decode.
    pub peers: &'a dyn PeerCalls,
    /// `CLOCK_BOOTTIME`, for deadlines.
    pub clock: &'a dyn Clock,
    /// The random source nonces are drawn from.
    pub entropy: &'a dyn Entropy,
    /// Root's ruleset and settings.
    pub policy: &'a dyn PolicySource,
    /// The audit trail. A permitted request is minted only once its record is
    /// on it; refusals are recorded best-effort.
    pub audit: &'a mut dyn AuditSink,
    /// `/run/xudo/confirm`, accessed through the spool syscall seam.
    pub confirmations: Option<&'a dyn Spool>,
    /// `/var/lib/xudo`, used only for the freeze marker.
    pub freeze_file: Option<&'a dyn Spool>,
}

/// How a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    /// An entry was minted and the client told so.
    Minted,
    /// The policy decided against the request and the client was told.
    Decided,
    /// The broker refused and the client was told.
    Refused(Fault),
    /// The answer could not be delivered: the client went away, or stopped
    /// reading until the send timeout fired.
    Undelivered,
}

impl Served {
    /// The exit status for systemd.
    ///
    /// Zero whenever the broker did its job, whatever it decided — a denial,
    /// a client's malformed request, or a client that left before its answer
    /// is not the broker failing. Non-zero only when the broker or its host is
    /// broken, so that what systemd records as a failure is something an
    /// administrator must look at, and a client cannot manufacture one.
    pub fn exit_status(self) -> u8 {
        match self {
            Self::Minted | Self::Decided | Self::Refused(Fault::Client) | Self::Undelivered => 0,
            Self::Refused(Fault::Broker) => UNUSABLE,
        }
    }
}

/// What a permitted request has established by the time it is minted.
struct Evaluated {
    decision: Decision,
    caller: CallerFacts,
    identity: PeerIdentity,
    request: BrokerRequest,
    policy: LoadedPolicy,
}

enum ConfirmRun {
    Continue(Box<Evaluated>),
    Served(Served),
}

fn confirm_run(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    evaluated: Evaluated,
) -> ConfirmRun {
    let Evaluated {
        decision,
        caller,
        identity,
        request,
        policy,
    } = evaluated;
    if decision.verdict != xudo_policy::Verdict::AllowWithConfirmation
        || !policy.settings.confirm_human_path
    {
        return ConfirmRun::Continue(Box::new(Evaluated {
            decision,
            caller,
            identity,
            request,
            policy,
        }));
    }
    let now = platform.clock.boottime_millis();
    let search = ApprovalSearch {
        request: &request,
        identity: &identity,
        caller: &caller,
        syscalls: platform.syscalls,
        action: decision.action.as_ref().map(xudo_policy::ActionId::as_str),
        generation: policy.rules.generation.id(),
        now,
    };
    let approved = match take_matching_approval(spool, &search) {
        Ok(approved) => approved,
        Err(error) => {
            return ConfirmRun::Served(refuse(
                conn,
                platform.audit,
                &error,
                Some(&identity),
                Some(&request),
            ));
        }
    };
    if let Some(approved) = approved {
        let evaluated = Evaluated {
            decision,
            caller,
            identity,
            request,
            policy,
        };
        return ConfirmRun::Served(mint_approved(conn, platform, spool, evaluated, approved));
    }
    if !has_live_watcher(
        platform.confirmations,
        platform.peers,
        identity.uid,
        &identity,
        now,
    ) {
        return ConfirmRun::Served(serve_confirmation_denial(
            conn,
            platform,
            Evaluated {
                decision,
                caller,
                identity,
                request,
                policy,
            },
            xudo_policy::DenialCode::NoConfirmationChannel,
        ));
    }
    let code = if active_backoff(platform.confirmations, identity.uid, &request, now)
        || pending_by_identity(spool, &request, &caller, &identity, now)
    {
        xudo_policy::DenialCode::ConfirmationThrottled
    } else {
        return ConfirmRun::Continue(Box::new(Evaluated {
            decision,
            caller,
            identity,
            request,
            policy,
        }));
    };
    ConfirmRun::Served(serve_confirmation_denial(
        conn,
        platform,
        Evaluated {
            decision,
            caller,
            identity,
            request,
            policy,
        },
        code,
    ))
}

fn serve_confirmation_denial(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    evaluated: Evaluated,
    code: xudo_policy::DenialCode,
) -> Served {
    let Evaluated {
        decision,
        caller,
        identity,
        request,
        policy,
    } = evaluated;
    let denied = confirmation_denial(decision, code);
    let _receipt = platform.audit.append(&|previous| {
        decided(
            previous,
            &denied,
            &caller,
            &identity,
            &request,
            &policy.rules.generation,
            None,
        )
    });
    answer(
        conn,
        &BrokerResponse::decided(denied, None),
        Served::Decided,
    )
}

/// Serves one connection: identifies, reads, decides, mints, answers.
///
/// `spool` is the result of opening the spool, opened before the connection
/// is served and refused only once the request is known.
pub fn serve(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    spool: Result<&dyn Spool, &SpoolError>,
) -> Served {
    if let Err(error) = platform.hygiene.forbid_new_privileges() {
        return refuse_hygiene_failure(conn, platform.audit, &error);
    }
    let identity = match identify(conn.socket(), platform.syscalls, platform.peers) {
        Ok(identity) => identity,
        Err(error) => return refuse(conn, platform.audit, &Refusal::from(&error), None, None),
    };
    let request = match receive(conn) {
        Ok(request) => request,
        Err(refusal) => return refuse(conn, platform.audit, &refusal, Some(&identity), None),
    };
    let spool = match spool {
        Ok(spool) => spool,
        Err(error) => {
            return refuse(
                conn,
                platform.audit,
                &Refusal::from(error),
                Some(&identity),
                Some(&request),
            );
        }
    };
    let should_expire = match &request.question {
        xudo_wire::Question::Run { .. } => platform.confirmations.is_some(),
        xudo_wire::Question::Watch => {
            !identity.diverged && xudo_gate::request::is_watch_terminal(identity.tty)
        }
        xudo_wire::Question::Pending
        | xudo_wire::Question::Status { .. }
        | xudo_wire::Question::Answer { .. } => true,
        _ => false,
    };
    if should_expire {
        if let Err(refusal) = expire_entries(platform, spool, &request) {
            return refuse(
                conn,
                platform.audit,
                &refusal,
                Some(&identity),
                Some(&request),
            );
        }
    }
    serve_request(conn, platform, spool, identity, request)
}

fn serve_request(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: PeerIdentity,
    request: BrokerRequest,
) -> Served {
    if !matches!(request.question, xudo_wire::Question::Run { .. }) {
        return serve_confirmation_question(conn, platform, spool, &identity, &request);
    }
    let mut policy = match platform.policy.load() {
        Ok(policy) => policy,
        Err(error) => {
            return refuse(
                conn,
                platform.audit,
                &Refusal::from(&error),
                Some(&identity),
                Some(&request),
            );
        }
    };
    policy.settings.frozen |= user_freeze_stands(platform, identity.uid);

    let caller = classify(&identity);
    let decision = decide(&policy, &caller, &request);
    let evaluated = Evaluated {
        decision,
        caller,
        identity,
        request,
        policy,
    };
    let evaluated = match confirm_run(conn, platform, spool, evaluated) {
        ConfirmRun::Served(served) => return served,
        ConfirmRun::Continue(evaluated) => *evaluated,
    };
    let Evaluated {
        decision,
        caller,
        identity,
        request,
        policy,
    } = evaluated;
    if !decision.verdict.is_permitted() {
        // Nothing is enabled by this record, so a sink that cannot take it
        // does not change the answer.
        let _ = platform.audit.append(&|previous| {
            decided(
                previous,
                &decision,
                &caller,
                &identity,
                &request,
                &policy.rules.generation,
                None,
            )
        });
        return answer(
            conn,
            &BrokerResponse::decided(decision, None),
            Served::Decided,
        );
    }
    mint(
        conn,
        platform,
        spool,
        Evaluated {
            decision,
            caller,
            identity,
            request,
            policy,
        },
    )
}

fn expire_entries(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    _request: &BrokerRequest,
) -> Result<(), Refusal> {
    let store = platform.confirmations.ok_or_else(|| {
        Refusal::broker(
            RefusalCode::SpoolUnusable,
            "confirmation directory is unavailable",
        )
    })?;
    let _confirm_guard = SpoolGuard::lock(store).map_err(|error| Refusal::from(&error))?;
    let _spool_guard = SpoolGuard::lock(spool).map_err(|error| Refusal::from(&error))?;
    let now = platform.clock.boottime_millis();
    let names = spool
        .names_up_to(crate::mint::MAX_SPOOL_NAMES_TO_WALK)
        .map_err(|error| Refusal::from(&error))?;
    for id in names {
        let Ok(bytes) = spool.read(&id, crate::mint::MAX_ENTRY_BYTES) else {
            continue;
        };
        let Ok(mut entry) = parse_entry(&bytes) else {
            continue;
        };
        if !entry.needs_watch || !crate::confirm::expire(&mut entry, now) {
            continue;
        }
        let command: Vec<String> = std::iter::once(entry.program.clone())
            .chain(entry.argv.clone())
            .collect();
        let audit_request = BrokerRequest::new(
            entry.program.clone(),
            entry.argv.clone(),
            entry.claimed_classification.clone(),
        );
        let _receipt = platform
            .audit
            .append(&|previous| {
                xudo_audit::record::Record::after(
                    previous,
                    xudo_audit::record::Decision::Denied,
                    command.clone(),
                    "unattested",
                )
                .with_denial("confirmation_expired")
                .with_evidence(vec![
                    "broker=xudod".to_owned(),
                    format!("nonce={}", entry.nonce),
                    format!("question={:?}", audit_request.question),
                ])
                .with_outcome(xudo_audit::record::Outcome::NotExecuted)
            })
            .map_err(|_| {
                Refusal::broker(
                    RefusalCode::BrokerUnusable,
                    "expiry audit record was refused",
                )
            })?;
        record_outcome_locked(store, &entry, TerminalOutcome::Expired, now, true)?;
        spool.remove(&id).map_err(|error| Refusal::from(&error))?;
    }
    Ok(())
}

fn record_outcome_locked(
    store: &dyn Spool,
    entry: &xudo_gate::request::PendingRequest,
    outcome: TerminalOutcome,
    now: u64,
    strike: bool,
) -> Result<(), Refusal> {
    let name = format!("{}.json", entry.caller_uid);
    let (old, data) = read_confirm_data(store, &name).map_err(|error| Refusal::from(&error))?;
    let mut data = data.unwrap_or(ConfirmData {
        heartbeat: None,
        backoff: Vec::new(),
        outcomes: Vec::new(),
    });
    data.outcomes
        .retain(|item| item.until_ms > now && item.id != entry.nonce);
    data.backoff.retain(|item| item.until_ms > now);
    data.outcomes.push(RecentOutcome {
        id: entry.nonce.clone(),
        outcome,
        until_ms: now.saturating_add(crate::mint::REQUEST_TTL_MILLIS),
        pid: entry.caller_pid,
        starttime: entry.caller_starttime,
    });
    if data.outcomes.len() > MAX_RECENT_OUTCOMES_PER_UID {
        let excess = data
            .outcomes
            .len()
            .saturating_sub(MAX_RECENT_OUTCOMES_PER_UID);
        data.outcomes.drain(..excess);
    }
    if strike {
        let fp = &entry.fingerprint;
        if data.backoff.len() >= MAX_BACKOFF_ENTRIES_PER_UID
            && !data.backoff.iter().any(|old| old.fingerprint == *fp)
        {
            data.backoff.remove(0);
        }
        let strikes = data
            .backoff
            .iter()
            .find(|old| old.fingerprint == *fp)
            .map_or(1, |old| old.strikes.saturating_add(1));
        let until_ms = now.saturating_add(crate::confirm::backoff_ms(strikes));
        data.backoff.retain(|old| old.fingerprint != *fp);
        data.backoff.push(BackoffEntry {
            fingerprint: fp.clone(),
            strikes,
            until_ms,
        });
    }
    write_confirm(store, &name, old, &data).map_err(|error| refusal_from_confirm_write(&error))
}

fn request_fingerprint(request: &BrokerRequest, uid: u32) -> Option<String> {
    let (program, argv, _) = request.run_fields()?;
    Some(crate::confirm::fingerprint(
        uid,
        program.as_bytes(),
        &argv.iter().map(String::as_bytes).collect::<Vec<_>>(),
    ))
}

fn active_backoff(store: Option<&dyn Spool>, uid: u32, request: &BrokerRequest, now: u64) -> bool {
    let (Some(store), Some(fingerprint)) = (store, request_fingerprint(request, uid)) else {
        return true;
    };
    let name = format!("{uid}.json");
    store
        .read(name.as_bytes(), CONFIRM_FILE_LIMIT)
        .ok()
        .and_then(|bytes| parse_confirm_data(&bytes).ok())
        .is_none_or(|data| {
            data.backoff
                .iter()
                .any(|entry| entry.fingerprint == fingerprint && now < entry.until_ms)
        })
}

fn clear_backoff(
    store: Option<&dyn Spool>,
    uid: u32,
    fingerprint: &str,
    now: u64,
) -> Result<(), SpoolError> {
    let store = store.ok_or_else(|| SpoolError::Io {
        operation: "confirmation state".to_owned(),
        at: crate::CONFIRM_DIR.to_owned(),
        code: None,
        reason: "directory unavailable".to_owned(),
    })?;
    let _guard = SpoolGuard::lock(store)?;
    let name = format!("{uid}.json");
    let (Some(old), Some(mut data)) = read_confirm_data(store, &name)? else {
        return Err(SpoolError::Io {
            operation: "read confirmation state".to_owned(),
            at: crate::CONFIRM_DIR.to_owned(),
            code: None,
            reason: "confirmation file is missing".to_owned(),
        });
    };
    data.backoff.retain(|entry| entry.until_ms > now);
    data.outcomes.retain(|entry| entry.until_ms > now);
    let original = data.backoff.len();
    data.backoff
        .retain(|entry| entry.fingerprint != fingerprint);
    if data.backoff.len() == original {
        return Ok(());
    }
    write_confirm(store, &name, Some(old), &data)
}

fn read_confirm_data(
    store: &dyn Spool,
    name: &str,
) -> Result<(Option<Vec<u8>>, Option<ConfirmData>), SpoolError> {
    let names = store.names_up_to(MAX_CONFIRM_UIDS + 1)?;
    if names.len() > MAX_CONFIRM_UIDS {
        return Err(SpoolError::Io {
            operation: "read confirmation directory".to_owned(),
            at: crate::CONFIRM_DIR.to_owned(),
            code: None,
            reason: "confirmation directory exceeds its bound".to_owned(),
        });
    }
    let exists = names.iter().any(|item| item == name.as_bytes());
    if !exists {
        return Ok((None, None));
    }
    let bytes = store.read(name.as_bytes(), CONFIRM_FILE_LIMIT)?;
    let data = validated_confirm(&bytes)?;
    Ok((Some(bytes), Some(data)))
}

/// One uid file, or why it cannot be treated as confirmation state.
///
/// A file that fails here is kept. Deleting bytes we could not validate could
/// drop a backoff strike the parser did not show us.
fn validated_confirm(bytes: &[u8]) -> Result<ConfirmData, SpoolError> {
    let data = parse_confirm_data(bytes).map_err(|error| SpoolError::Io {
        operation: "parse confirmation state".to_owned(),
        at: crate::CONFIRM_DIR.to_owned(),
        code: None,
        reason: error.to_string(),
    })?;
    if data.backoff.len() > MAX_BACKOFF_ENTRIES_PER_UID
        || data.outcomes.len() > MAX_RECENT_OUTCOMES_PER_UID
        || data.backoff.iter().any(|item| item.fingerprint.len() != 64)
        || data.outcomes.iter().any(|item| item.id.len() != 64)
    {
        return Err(SpoolError::Io {
            operation: "validate confirmation state".to_owned(),
            at: crate::CONFIRM_DIR.to_owned(),
            code: None,
            reason: "confirmation state exceeds a field or item bound".to_owned(),
        });
    }
    Ok(data)
}

fn clear_approved_backoff(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    identity: &PeerIdentity,
    request: &BrokerRequest,
    fingerprint: &str,
    now: u64,
) -> Result<(), Served> {
    if clear_backoff(platform.confirmations, identity.uid, fingerprint, now).is_err() {
        return Err(refuse(
            conn,
            platform.audit,
            &Refusal::broker(
                RefusalCode::SpoolUnusable,
                "cannot clear confirmation backoff after the approval was consumed",
            ),
            Some(identity),
            Some(request),
        ));
    }
    Ok(())
}

struct ApprovalSearch<'a> {
    request: &'a BrokerRequest,
    identity: &'a PeerIdentity,
    caller: &'a CallerFacts,
    syscalls: &'a dyn Syscalls,
    action: Option<&'a str>,
    generation: u64,
    now: u64,
}

fn take_matching_approval(
    spool: &dyn Spool,
    search: &ApprovalSearch<'_>,
) -> Result<Option<xudo_gate::request::PendingRequest>, Refusal> {
    let ApprovalSearch {
        request,
        identity,
        caller,
        syscalls,
        action,
        generation,
        now,
    } = *search;
    let Some((program, argv, _)) = request.run_fields() else {
        return Ok(None);
    };
    let Some(action) = action else {
        return Ok(None);
    };
    let _guard = SpoolGuard::lock(spool).map_err(|error| Refusal::from(&error))?;
    let names = spool
        .names_up_to(crate::mint::MAX_SPOOL_NAMES_TO_WALK)
        .map_err(|error| Refusal::from(&error))?;
    let argv_bytes = argv.iter().map(String::as_bytes).collect::<Vec<_>>();
    let live = live_attestation(syscalls, caller, identity)?;
    let binding = live.binding(identity);
    for name in names {
        let bytes = spool
            .read(&name, crate::mint::MAX_ENTRY_BYTES)
            .map_err(|error| Refusal::from(&error))?;
        let Ok(entry) = parse_entry(&bytes) else {
            continue;
        };
        let (_, consumed) = crate::confirm::take_approval(
            Some(entry),
            program.as_bytes(),
            &argv_bytes,
            generation,
            action,
            now,
            &binding,
        );
        if let Some(approved) = consumed {
            return Ok(Some(approved));
        }
    }
    Ok(None)
}

fn pin_to_consumer(entry: &mut xudo_gate::request::PendingRequest, identity: &PeerIdentity) {
    entry.caller_pid = identity.pid;
    entry.caller_starttime = identity.starttime;
    entry.caller_sid = identity.sid;
    entry.caller_tty = identity.tty;
}

/// The live attestation, once the approved entry is known to be this caller's.
fn checked_live_identity(
    syscalls: &dyn Syscalls,
    entry: &xudo_gate::request::PendingRequest,
    caller: &CallerFacts,
    identity: &PeerIdentity,
) -> Result<LiveAttestation, Refusal> {
    let live = live_attestation(syscalls, caller, identity)?;
    if crate::confirm::identity_matches(entry, &live.binding(identity)) {
        Ok(live)
    } else {
        Err(Refusal::client(
            RefusalCode::RequestUnknown,
            "approval no longer matches the caller",
        ))
    }
}

fn mint_approved(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    evaluated: Evaluated,
    mut entry: xudo_gate::request::PendingRequest,
) -> Served {
    let Evaluated {
        decision,
        caller,
        identity,
        request,
        policy,
    } = evaluated;
    let Some((program, argv, _)) = request.run_fields() else {
        return refuse(
            conn,
            platform.audit,
            &Refusal::client(
                RefusalCode::RequestMalformed,
                "approval did not match a run",
            ),
            Some(&identity),
            Some(&request),
        );
    };
    if decision.verdict != xudo_policy::Verdict::AllowWithConfirmation {
        return refuse(
            conn,
            platform.audit,
            &Refusal::broker(
                RefusalCode::BrokerUnusable,
                "fresh decision no longer requires confirmation",
            ),
            Some(&identity),
            Some(&request),
        );
    }
    let live = match checked_live_identity(platform.syscalls, &entry, &caller, &identity) {
        Ok(live) => live,
        Err(error) => {
            return refuse(
                conn,
                platform.audit,
                &error,
                Some(&identity),
                Some(&request),
            );
        }
    };
    // Re-pinned to the consumer; only a copy until the compare-and-swap lands.
    pin_to_consumer(&mut entry, &identity);
    program.clone_into(&mut entry.program);
    entry.argv = argv.to_vec();
    // Audit first: nothing is swapped without a record, and a failed record
    // leaves the entry Approved.
    let build = |previous: Option<&Record>, grant: &Grant| {
        decided(
            previous,
            &decision,
            &caller,
            &identity,
            &request,
            &policy.rules.generation,
            Some(&grant.0),
        )
    };
    let Ok(authorized) = authorize(&mut *platform.audit, Grant(entry), &build) else {
        return refuse(
            conn,
            platform.audit,
            &Refusal::broker(
                RefusalCode::BrokerUnusable,
                "approval audit record was refused",
            ),
            Some(&identity),
            Some(&request),
        );
    };
    if let Err(error) = publish_consumed_approval(
        spool,
        &live.binding(&identity),
        &authorized,
        platform.clock.boottime_millis(),
    ) {
        // Best effort: `refuse` ignores a failed append, and a crash between
        // authorize and swap leaves a grant with no denial after it.
        return refuse(
            conn,
            platform.audit,
            &error,
            Some(&identity),
            Some(&request),
        );
    }
    // Only a real consume clears the backoff.
    if let Err(served) = clear_approved_backoff(
        conn,
        platform,
        &identity,
        &request,
        &authorized.approval().0.fingerprint,
        platform.clock.boottime_millis(),
    ) {
        return served;
    }
    answer_minted(conn, platform, decision, &authorized)
}

fn answer_minted(
    conn: &dyn Connection,
    platform: &Platform<'_>,
    decision: xudo_policy::Decision,
    authorized: &xudo_sys::Authorized<Grant>,
) -> Served {
    let minted = Minted {
        nonce: authorized.approval().0.nonce.clone(),
        expires_in_ms: remaining_millis(
            authorized.approval().0.deadline.0,
            platform.clock.boottime_millis(),
        ),
        gate: xudo_backend::snippet::GATE_AUTH.to_owned(),
    };
    answer(
        conn,
        &BrokerResponse::decided(decision, Some(minted)),
        Served::Minted,
    )
}

/// The caller's class, scope and boot id as the kernel attests them now.
struct LiveAttestation {
    class: xudo_gate::request::AttestedClass,
    scope_id: Option<u64>,
    boot_id: Option<String>,
}

impl LiveAttestation {
    fn binding(&self, identity: &PeerIdentity) -> crate::confirm::ApprovalCaller<'_> {
        crate::confirm::ApprovalCaller {
            pid: identity.pid,
            starttime: identity.starttime,
            uid: identity.uid,
            sid: identity.sid,
            tty: identity.tty,
            attested_class: &self.class,
            scope_id: self.scope_id,
            boot_id: self.boot_id.as_deref(),
        }
    }
}

/// The one place a live caller's attested class is derived.
///
/// A scope or boot id the kernel will not give is a broker that cannot attest,
/// not a client mistake, so the refusal says so.
fn live_attestation(
    syscalls: &dyn Syscalls,
    caller: &CallerFacts,
    identity: &PeerIdentity,
) -> Result<LiveAttestation, Refusal> {
    use xudo_gate::request::AttestedClass;
    match &caller.classification {
        xudo_policy::Classification::Unattested { .. } => Ok(LiveAttestation {
            class: AttestedClass::Unattested,
            scope_id: None,
            boot_id: None,
        }),
        xudo_policy::Classification::Human => Ok(LiveAttestation {
            class: AttestedClass::Human,
            scope_id: None,
            boot_id: None,
        }),
        xudo_policy::Classification::EnrolledAgent { .. } => {
            let Some(scope_id) = identity.cgroup_id else {
                return Err(Refusal::broker(
                    RefusalCode::BrokerUnusable,
                    "caller scope is unavailable",
                ));
            };
            let boot_id = syscalls
                .boot_id()
                .ok()
                .filter(|id| xudo_gate::request::is_boot_id(id));
            if boot_id.is_none() {
                return Err(Refusal::broker(
                    RefusalCode::BrokerUnusable,
                    "live boot id is unavailable",
                ));
            }
            Ok(LiveAttestation {
                class: AttestedClass::EnrolledAgent { scope_id },
                scope_id: Some(scope_id),
                boot_id,
            })
        }
    }
}

/// Replaces the on-disk approval with its consumed copy.
///
/// The compare-and-swap checks the entry on disk against the caller's live
/// identity, not against the in-memory copy, which was read from the same
/// place and would agree with itself. The consumed copy may differ from the
/// disk only in state, deadline and the consumer's pin.
fn publish_consumed_approval(
    spool: &dyn Spool,
    live: &crate::confirm::ApprovalCaller<'_>,
    authorized: &xudo_sys::Authorized<Grant>,
    now: u64,
) -> Result<(), Refusal> {
    swap_to_consumed(spool, live, authorized, now).map_err(|mut error| {
        // The swap can fail after the exchange put the consumed bytes in
        // place (the last unlink, a failed swap back): then the entry on disk
        // is spendable and the record must not claim the grant is gone.
        let landed = matches!(
            spool.read(authorized.approval().0.nonce.as_bytes(), crate::mint::MAX_ENTRY_BYTES),
            Ok(bytes) if bytes == authorized.approval().0.to_json().as_bytes()
        );
        let note = if landed {
            "consume outcome unknown; the consumed entry is on disk"
        } else {
            "supersedes the grant"
        };
        error.detail = format!(
            "{} ({note} for nonce={})",
            error.detail,
            authorized.approval().0.nonce
        );
        error
    })
}

fn swap_to_consumed(
    spool: &dyn Spool,
    live: &crate::confirm::ApprovalCaller<'_>,
    authorized: &xudo_sys::Authorized<Grant>,
    now: u64,
) -> Result<(), Refusal> {
    let entry = &authorized.approval().0;
    let json = entry.to_json();
    let _guard = SpoolGuard::lock(spool).map_err(|error| Refusal::from(&error))?;
    let id = entry.nonce.as_bytes();
    let old = spool
        .read(id, crate::mint::MAX_ENTRY_BYTES)
        .map_err(|error| Refusal::from(&error))?;
    let current = parse_entry(&old)?;
    let matches = current.state == xudo_gate::request::ConfirmationState::Approved
        && entry.state == xudo_gate::request::ConfirmationState::Consumed
        && crate::confirm::identity_matches(&current, live)
        && entry.caller_pid == live.pid
        && entry.caller_starttime == live.starttime
        && entry.caller_sid == live.sid
        && entry.caller_tty == live.tty
        && current.nonce == entry.nonce
        && current.fingerprint == entry.fingerprint
        && current.attested_class == entry.attested_class
        && current.attested_scope_id == entry.attested_scope_id
        && current.boot_id == entry.boot_id
        && current.action == entry.action
        && current.program == entry.program
        && current.argv == entry.argv
        && current.generation == entry.generation
        && current.confirmed_by == entry.confirmed_by
        && current.deadline.0 > now
        && entry.deadline.0 <= current.deadline.0;
    if !matches {
        return Err(Refusal::client(
            RefusalCode::RequestUnknown,
            "approval changed before it was consumed",
        ));
    }
    spool
        .replace(id, &old, json.as_bytes())
        .map_err(|error| Refusal::from(&error))
}

/// The class a pending entry of this caller would be minted with. An agent
/// whose scope the kernel will not give has none, and so matches nothing.
fn pending_class(
    caller: &CallerFacts,
    identity: &PeerIdentity,
) -> Option<xudo_gate::request::AttestedClass> {
    use xudo_gate::request::AttestedClass;
    match &caller.classification {
        xudo_policy::Classification::Unattested { .. } => Some(AttestedClass::Unattested),
        xudo_policy::Classification::Human => Some(AttestedClass::Human),
        xudo_policy::Classification::EnrolledAgent { .. } => identity
            .cgroup_id
            .map(|scope_id| AttestedClass::EnrolledAgent { scope_id }),
    }
}

/// Whether this caller already has this command pending, as this class.
fn pending_by_identity(
    spool: &dyn Spool,
    request: &BrokerRequest,
    caller: &CallerFacts,
    identity: &PeerIdentity,
    now: u64,
) -> bool {
    let class = pending_class(caller, identity);
    pending_duplicate(spool, request, identity.uid, class.as_ref(), now)
}

fn pending_duplicate(
    spool: &dyn Spool,
    request: &BrokerRequest,
    uid: u32,
    class: Option<&xudo_gate::request::AttestedClass>,
    now: u64,
) -> bool {
    let Some(class) = class else {
        return false;
    };
    let Some((program, argv, _)) = request.run_fields() else {
        return false;
    };
    let fingerprint = crate::confirm::fingerprint(
        uid,
        program.as_bytes(),
        &argv.iter().map(String::as_bytes).collect::<Vec<_>>(),
    );
    let Ok(_guard) = SpoolGuard::lock(spool) else {
        return true;
    };
    let Ok(names) = spool.names_up_to(crate::mint::MAX_SPOOL_NAMES_TO_WALK) else {
        return true;
    };
    names.into_iter().any(|name| {
        spool
            .read(&name, crate::mint::MAX_ENTRY_BYTES)
            .ok()
            .and_then(|bytes| parse_entry(&bytes).ok())
            .is_some_and(|entry| crate::confirm::is_duplicate(&entry, &fingerprint, class, now))
    })
}

#[cfg(feature = "fuzzing")]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(from = "CompactConfirmData", into = "CompactConfirmData")]
/// Compact persistent watcher, backoff, and outcome state.
pub struct ConfirmData {
    heartbeat: Option<WatcherHeartbeat>,
    backoff: Vec<BackoffEntry>,
    #[serde(default)]
    outcomes: Vec<RecentOutcome>,
}

#[cfg(not(feature = "fuzzing"))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(from = "CompactConfirmData", into = "CompactConfirmData")]
/// Compact persistent watcher, backoff, and outcome state.
pub(crate) struct ConfirmData {
    heartbeat: Option<WatcherHeartbeat>,
    backoff: Vec<BackoffEntry>,
    #[serde(default)]
    outcomes: Vec<RecentOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactConfirmData {
    h: Option<CompactHeartbeat>,
    b: Vec<CompactBackoff>,
    o: Vec<CompactOutcome>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactHeartbeat {
    p: u32,
    s: u64,
    t: i64,
    d: i64,
    a: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactBackoff {
    f: String,
    s: u32,
    u: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompactOutcome {
    i: String,
    r: TerminalOutcome,
    u: u64,
    p: u32,
    s: u64,
}

impl From<CompactConfirmData> for ConfirmData {
    fn from(value: CompactConfirmData) -> Self {
        Self {
            heartbeat: value.h.map(|v| WatcherHeartbeat {
                pid: v.p,
                starttime: v.s,
                tty: v.t,
                sid: v.d,
                at_ms: v.a,
            }),
            backoff: value
                .b
                .into_iter()
                .map(|v| BackoffEntry {
                    fingerprint: v.f,
                    strikes: v.s,
                    until_ms: v.u,
                })
                .collect(),
            outcomes: value
                .o
                .into_iter()
                .map(|v| RecentOutcome {
                    id: v.i,
                    outcome: v.r,
                    until_ms: v.u,
                    pid: v.p,
                    starttime: v.s,
                })
                .collect(),
        }
    }
}

impl From<ConfirmData> for CompactConfirmData {
    fn from(value: ConfirmData) -> Self {
        Self {
            h: value.heartbeat.map(|v| CompactHeartbeat {
                p: v.pid,
                s: v.starttime,
                t: v.tty,
                d: v.sid,
                a: v.at_ms,
            }),
            b: value
                .backoff
                .into_iter()
                .map(|v| CompactBackoff {
                    f: v.fingerprint,
                    s: v.strikes,
                    u: v.until_ms,
                })
                .collect(),
            o: value
                .outcomes
                .into_iter()
                .map(|v| CompactOutcome {
                    i: v.id,
                    r: v.outcome,
                    u: v.until_ms,
                    p: v.pid,
                    s: v.starttime,
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecentOutcome {
    id: String,
    outcome: TerminalOutcome,
    until_ms: u64,
    pid: u32,
    starttime: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TerminalOutcome {
    Denied,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatcherHeartbeat {
    pid: u32,
    starttime: u64,
    tty: i64,
    sid: i64,
    at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackoffEntry {
    fingerprint: String,
    strikes: u32,
    until_ms: u64,
}

const MAX_CONFIRM_UIDS: usize = 4_096;
/// How long a heartbeat still counts as a live watcher. The same window the
/// channel check and the second-watcher refusal use.
const HEARTBEAT_FRESH_MS: u64 = 3_000;
const CONFIRM_DIRECTORY_FULL: &str = "confirmation directory is full";
const MAX_BACKOFF_ENTRIES_PER_UID: usize = 64;
const MAX_RECENT_OUTCOMES_PER_UID: usize = 64;

const MAX_OUTCOME_BYTES: usize = 155;
const MAX_BACKOFF_BYTES: usize = 112;
const MAX_HEARTBEAT_BYTES: usize = 116;
const MAX_CONFIRM_DATA_BYTES: usize = r#"{"h":null,"b":[],"o":[]}"#.len()
    + MAX_HEARTBEAT_BYTES
    + MAX_BACKOFF_ENTRIES_PER_UID * MAX_BACKOFF_BYTES
    + MAX_RECENT_OUTCOMES_PER_UID * MAX_OUTCOME_BYTES
    + MAX_BACKOFF_ENTRIES_PER_UID
    + MAX_RECENT_OUTCOMES_PER_UID;

/// Parses compact confirmation state while preserving duplicate-key errors.
///
/// # Errors
///
/// Returns the serde error for invalid JSON, positional fields, or duplicate keys.
fn parse_confirm_data_inner(bytes: &[u8]) -> Result<ConfirmData, serde_json::Error> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let valid_rows = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|rows| rows.iter().all(serde_json::Value::is_object))
    };
    let heartbeat_is_object = value
        .get("h")
        .is_some_and(|heartbeat| heartbeat.is_null() || heartbeat.is_object());
    if !value.is_object() || !heartbeat_is_object || !valid_rows("b") || !valid_rows("o") {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "confirmation records must use object forms",
        ));
    }
    serde_json::from_slice(bytes)
}

#[cfg(feature = "fuzzing")]
/// Parses compact confirmation state while preserving duplicate-key errors.
///
/// # Errors
///
/// Returns the serde error for invalid JSON, positional fields, or duplicate keys.
pub fn parse_confirm_data(bytes: &[u8]) -> Result<ConfirmData, serde_json::Error> {
    parse_confirm_data_inner(bytes)
}

#[cfg(not(feature = "fuzzing"))]
pub(crate) fn parse_confirm_data(bytes: &[u8]) -> Result<ConfirmData, serde_json::Error> {
    parse_confirm_data_inner(bytes)
}
const _: () = assert!(MAX_CONFIRM_DATA_BYTES <= CONFIRM_FILE_LIMIT);

// A plain struct of strings and integers cannot fail to serialize. The
// explicit `None` path still refuses to write if serialization ever fails.
const CONFIRM_FILE_LIMIT: usize = 20 * 1024;

/// The state as bytes, or `None` when it cannot be serialized or would exceed
/// what the reader accepts: such a file could never be read back.
fn encode(value: &ConfirmData) -> Option<Vec<u8>> {
    serde_json::to_vec(value)
        .ok()
        .filter(|bytes| bytes.len() <= CONFIRM_FILE_LIMIT)
}

/// Encode within the size limit, then replace the file just read (`Some`) or
/// publish a new one (`None`). An oversize or unencodable value writes nothing.
fn write_confirm(
    store: &dyn Spool,
    name: &str,
    old: Option<Vec<u8>>,
    value: &ConfirmData,
) -> Result<(), SpoolError> {
    let bytes = encode(value).ok_or_else(|| SpoolError::Io {
        operation: "encode confirmation state".to_owned(),
        at: crate::CONFIRM_DIR.to_owned(),
        code: None,
        reason: "confirmation state cannot be encoded within its size limit".to_owned(),
    })?;
    match old {
        Some(expected) => store.replace(name.as_bytes(), &expected, &bytes),
        None => publish_confirmation(store, name, &bytes),
    }
}

/// Publishes a new uid file only while the directory is inside
/// [`MAX_CONFIRM_UIDS`].
///
/// The caller already counted under the confirm lock. This lists again at the
/// moment of publishing. A second publisher can land a file between those two
/// counts when the spool lock does not keep them apart, and file 4097 makes
/// every later read of the directory fail. Asking for exactly the bound is
/// enough to see that it has been reached.
fn publish_confirmation(store: &dyn Spool, name: &str, bytes: &[u8]) -> Result<(), SpoolError> {
    let names = store.names_up_to(MAX_CONFIRM_UIDS)?;
    if names.len() >= MAX_CONFIRM_UIDS {
        return Err(SpoolError::Full {
            at: crate::CONFIRM_DIR.to_owned(),
            limit: MAX_CONFIRM_UIDS,
        });
    }
    store.publish(name, bytes)
}

fn refusal_from_confirm_write(error: &SpoolError) -> Refusal {
    match error {
        SpoolError::Full { .. } => Refusal::broker(RefusalCode::SpoolFull, CONFIRM_DIRECTORY_FULL),
        other => Refusal::from(other),
    }
}

fn confirmation_denial(mut decision: Decision, code: xudo_policy::DenialCode) -> Decision {
    decision.verdict = xudo_policy::Verdict::Deny;
    decision.denial = Some(code);
    decision
}

/// A heartbeat is live when it is recent, names a real pid, and `/proc` still
/// shows that pid and start time. A pid of 0 is never live: the kernel reports
/// it for a peer that is not in this pid namespace.
fn heartbeat_is_live(peers: &dyn PeerCalls, heartbeat: &WatcherHeartbeat, now: u64) -> bool {
    if heartbeat.pid == 0 || now.saturating_sub(heartbeat.at_ms) > HEARTBEAT_FRESH_MS {
        return false;
    }
    peers
        .read_proc(heartbeat.pid, xudo_sys::ProcFile::Stat)
        .ok()
        .and_then(|bytes| xudo_sys::parse_stat("watcher", &bytes).ok())
        .is_some_and(|stat| stat.pid == heartbeat.pid && stat.starttime == heartbeat.starttime)
}

fn has_live_watcher(
    store: Option<&dyn Spool>,
    peers: &dyn PeerCalls,
    uid: u32,
    caller: &PeerIdentity,
    now: u64,
) -> bool {
    let Some(store) = store else { return false };
    let Ok(bytes) = store.read(format!("{uid}.json").as_bytes(), CONFIRM_FILE_LIMIT) else {
        return false;
    };
    let Ok(data) = parse_confirm_data(&bytes) else {
        return false;
    };
    let Some(heartbeat) = data.heartbeat else {
        return false;
    };
    heartbeat_is_live(peers, &heartbeat, now)
        && xudo_gate::request::WatcherPin {
            uid,
            pid: heartbeat.pid,
            starttime: heartbeat.starttime,
            tty: heartbeat.tty,
            sid: heartbeat.sid,
        }
        .is_eligible_for(uid, caller.pid, caller.starttime, caller.sid, caller.tty)
}

fn serve_confirmation_question(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
    request: &BrokerRequest,
) -> Served {
    let result = match &request.question {
        xudo_wire::Question::Status { id } => status(conn, platform, spool, identity, request, id),
        xudo_wire::Question::Watch => watch(platform, spool, identity),
        xudo_wire::Question::Pending => pending_list(platform, spool, identity),
        xudo_wire::Question::Answer { .. } => {
            answer_confirmation(platform, spool, identity, request)
        }
        xudo_wire::Question::Freeze { reason } => {
            freeze(platform, spool, identity, request, reason)
        }
        xudo_wire::Question::Thaw => thaw(platform, identity, &classify(identity), request),
        xudo_wire::Question::Run { .. } => return Served::Refused(Fault::Broker),
    };
    match result {
        Ok(response) => answer(conn, &response, Served::Decided),
        Err(refusal) => refuse(
            conn,
            platform.audit,
            &refusal,
            Some(identity),
            Some(request),
        ),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FreezeRecord {
    reason: String,
    uid: u32,
    time: u64,
}

fn done() -> BrokerResponse {
    BrokerResponse {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        answer: xudo_wire::Answer::Done,
    }
}

fn freeze(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
    request: &BrokerRequest,
    reason: &str,
) -> Result<BrokerResponse, Refusal> {
    freeze_with(
        platform,
        spool,
        identity,
        &classify(identity),
        request,
        reason,
        &serde_json::to_vec,
    )
}

/// The most names the state directory is listed to: the audit log, root's
/// marker, and one marker per non-root freezer. Bounds both the listing a
/// thaw walks and the markers a group member can make the directory hold.
const MAX_STATE_NAMES: usize = 128;

/// A freeze or a thaw is a lever over every agent in its scope, so an
/// attested agent never pulls it: the class is the broker's, from kernel
/// facts, and an agent that could freeze could stop its owner's other agents.
fn refuse_attested_agent(caller: &CallerFacts, what: &'static str) -> Result<(), Refusal> {
    if caller.classification.is_enrolled_agent() {
        return Err(Refusal::client(RefusalCode::ChannelUntrusted, what));
    }
    Ok(())
}

/// A peer in another user namespace presents uids it chose, so its uid names
/// no one: it could mint a marker per uid and fill the directory. Refused
/// like a watch from it.
fn refuse_diverged(identity: &PeerIdentity, what: &'static str) -> Result<(), Refusal> {
    if identity.diverged {
        return Err(Refusal::client(RefusalCode::ChannelUntrusted, what));
    }
    Ok(())
}

/// Whether `uid`'s own freeze marker stands. Root's global marker is part of
/// the loaded policy, so root asks nothing more. Storage that cannot be
/// listed counts as frozen: this only ever withholds an enrolled agent.
fn user_freeze_stands(platform: &Platform<'_>, uid: u32) -> bool {
    if uid == 0 {
        return false;
    }
    let Some(state) = platform.freeze_file else {
        return true;
    };
    let Ok(names) = state.names_up_to(MAX_STATE_NAMES + 1) else {
        return true;
    };
    // A listing cut off one past the bound may have cut the marker off too.
    if names.len() > MAX_STATE_NAMES {
        return true;
    }
    let marker = xudo_gate::policy::freeze_marker_name(uid);
    names
        .iter()
        .any(|name| name.as_slice() == marker.as_bytes())
}

fn freeze_with(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
    caller: &CallerFacts,
    request: &BrokerRequest,
    reason: &str,
    encode: &dyn Fn(&FreezeRecord) -> Result<Vec<u8>, serde_json::Error>,
) -> Result<BrokerResponse, Refusal> {
    refuse_diverged(identity, "freeze requires an undiverged peer")?;
    refuse_attested_agent(caller, "an attested agent cannot freeze")?;
    let state = platform.freeze_file.ok_or_else(|| {
        Refusal::broker(RefusalCode::SpoolUnusable, "freeze storage is unavailable")
    })?;
    let bytes = encoded_freeze_record(
        &FreezeRecord {
            reason: reason.to_owned(),
            uid: identity.uid,
            time: platform.clock.wall_millis(),
        },
        encode,
    )?;
    if bytes.len() > xudo_gate::policy::MAX_FREEZE_BYTES {
        return Err(Refusal::client(
            RefusalCode::RequestTooLarge,
            "freeze reason is too large once encoded",
        ));
    }
    let record = platform
        .audit
        .append(&|previous| {
            Record::after(
                previous,
                xudo_audit::record::Decision::Denied,
                vec!["xudo freeze".to_owned()],
                "human",
            )
            .with_denial("freeze")
            .with_evidence(vec![
                "broker=xudod".to_owned(),
                format!("uid={}", identity.uid),
                format!("reason={}", reason.escape_debug()),
            ])
            .with_outcome(xudo_audit::record::Outcome::NotExecuted)
        })
        .map_err(|_| {
            Refusal::broker(
                RefusalCode::BrokerUnusable,
                "freeze audit record was refused",
            )
        })?;
    drop(record);
    publish_freeze(
        state,
        &xudo_gate::policy::freeze_marker_name(identity.uid),
        &bytes,
    )?;
    deny_pending(platform, spool, identity, request)?;
    Ok(done())
}

/// A killed broker can leave the temporary name behind, and the publish would
/// then fail on it for ever. Under the directory lock no other freeze is
/// mid-publish, so a name found here is stale.
fn publish_freeze(state: &dyn Spool, name: &str, bytes: &[u8]) -> Result<(), Refusal> {
    let _lock = SpoolGuard::lock(state).map_err(|e| Refusal::from(&e))?;
    let names = state
        .names_up_to(MAX_STATE_NAMES + 1)
        .map_err(|e| Refusal::from(&e))?;
    // Root's global marker is never refused for room: one slot is held back
    // for it, so a full directory of user markers cannot disable root's freeze.
    let is_roots = name == xudo_gate::policy::freeze_marker_name(0);
    let present = names.iter().any(|n| n.as_slice() == name.as_bytes());
    if !is_roots && !present && names.len() >= MAX_STATE_NAMES - 1 {
        return Err(Refusal::client(
            RefusalCode::SpoolFull,
            "too many freeze markers; root can free room by removing the extra files in /var/lib/xudo by hand",
        ));
    }
    state
        .remove(&freeze_temp(name))
        .map_err(|e| Refusal::from(&e))?;
    match state.publish(name, bytes) {
        Ok(()) | Err(SpoolError::Exists { .. }) => Ok(()),
        Err(error) => Err(Refusal::from(&error)),
    }
}

/// What `Spool::publish` names its temporary file for the marker `name`.
fn freeze_temp(name: &str) -> Vec<u8> {
    format!("{}{name}", xudo_sys::TEMP_PREFIX).into_bytes()
}

fn encode_freeze_record(
    record: &FreezeRecord,
    encode: &dyn Fn(&FreezeRecord) -> Result<Vec<u8>, serde_json::Error>,
) -> Result<Vec<u8>, serde_json::Error> {
    encode(record)
}

fn encoded_freeze_record(
    record: &FreezeRecord,
    encode: &dyn Fn(&FreezeRecord) -> Result<Vec<u8>, serde_json::Error>,
) -> Result<Vec<u8>, Refusal> {
    encode_freeze_record(record, encode).map_err(|_| {
        Refusal::broker(
            RefusalCode::BrokerUnusable,
            "freeze record could not be encoded",
        )
    })
}

fn deny_pending(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
    request: &BrokerRequest,
) -> Result<(), Refusal> {
    let store = platform.confirmations.ok_or_else(|| {
        Refusal::broker(
            RefusalCode::SpoolUnusable,
            "confirmation directory is unavailable",
        )
    })?;
    let _confirm = SpoolGuard::lock(store).map_err(|e| Refusal::from(&e))?;
    let _spool = SpoolGuard::lock(spool).map_err(|e| Refusal::from(&e))?;
    let names = spool
        .names_up_to(crate::mint::MAX_SPOOL_NAMES_TO_WALK)
        .map_err(|e| Refusal::from(&e))?;
    for name in names {
        let Ok(bytes) = spool.read(&name, crate::mint::MAX_ENTRY_BYTES) else {
            continue;
        };
        let Ok(mut entry) = parse_entry(&bytes) else {
            continue;
        };
        if !frozen_agent_entry(&entry) || !in_freeze_scope(identity, &entry) {
            continue;
        }
        entry.state = xudo_gate::request::ConfirmationState::Denied;
        let caller = stored_caller(&entry);
        let policy = platform.policy.load().map_err(|_| {
            Refusal::broker(RefusalCode::PolicyUnloadable, "policy cannot be loaded")
        })?;
        let mut decision = decide(
            &policy,
            &caller,
            &BrokerRequest::new(
                entry.program.clone(),
                entry.argv.clone(),
                STORED_CLASS_CLAIM,
            ),
        );
        decision.verdict = xudo_policy::Verdict::Deny;
        decision.denial = Some(xudo_policy::DenialCode::ConfirmationRefused);
        let _receipt = platform
            .audit
            .append(&|previous| {
                decided(
                    previous,
                    &decision,
                    &caller,
                    identity,
                    request,
                    &policy.rules.generation,
                    None,
                )
            })
            .map_err(|_| {
                Refusal::broker(
                    RefusalCode::BrokerUnusable,
                    "pending denial audit record was refused",
                )
            })?;
        spool.remove(&name).map_err(|e| Refusal::from(&e))?;
        record_outcome_locked(
            store,
            &entry,
            TerminalOutcome::Denied,
            platform.clock.boottime_millis(),
            false,
        )?;
    }
    Ok(())
}

/// The entries a freeze takes back: an enrolled agent's, pending or approved,
/// which the gate would refuse while frozen anyway. The class is the one the
/// broker stored at mint from kernel facts; the requester's claim is a hint
/// and is never read. A human's or unattested request keeps its place because
/// the password path keeps working.
fn frozen_agent_entry(entry: &xudo_gate::request::PendingRequest) -> bool {
    use xudo_gate::request::ConfirmationState::{Approved, Pending};
    entry.needs_watch
        && matches!(entry.state, Pending | Approved)
        && matches!(
            entry.attested_class,
            xudo_gate::request::AttestedClass::EnrolledAgent { .. }
        )
}

/// A non-root freeze takes back only its own uid's agents; root's takes back
/// everyone's. The uid is the requester's, stored at mint from kernel facts.
fn in_freeze_scope(freezer: &PeerIdentity, entry: &xudo_gate::request::PendingRequest) -> bool {
    freezer.uid == 0 || entry.caller_uid == freezer.uid
}

/// The fixed claim string a re-decision carries. The decision never reads a
/// claim; passing a constant makes that structural, not a convention.
const STORED_CLASS_CLAIM: &str = "stored-class";

/// Thaw lifts the freezer's own scope: a user's marker, or, for root, the
/// global one and every user's. An agent cannot thaw, and a user cannot lift
/// root's global marker or another user's.
fn thaw(
    platform: &mut Platform<'_>,
    identity: &PeerIdentity,
    caller: &CallerFacts,
    _request: &BrokerRequest,
) -> Result<BrokerResponse, Refusal> {
    refuse_diverged(identity, "thaw requires an undiverged peer")?;
    refuse_attested_agent(caller, "an attested agent cannot thaw")?;
    let state = platform.freeze_file.ok_or_else(|| {
        Refusal::broker(RefusalCode::SpoolUnusable, "freeze storage is unavailable")
    })?;
    let _receipt = platform
        .audit
        .append(&|previous| {
            Record::after(
                previous,
                xudo_audit::record::Decision::Allowed,
                vec!["xudo thaw".to_owned()],
                "human",
            )
            .with_evidence(vec![
                "broker=xudod".to_owned(),
                format!("uid={}", identity.uid),
            ])
            .with_outcome(xudo_audit::record::Outcome::NotExecuted)
        })
        .map_err(|_| {
            Refusal::broker(RefusalCode::BrokerUnusable, "thaw audit record was refused")
        })?;
    if identity.uid != 0 {
        let marker = xudo_gate::policy::freeze_marker_name(identity.uid);
        state
            .remove(marker.as_bytes())
            .map_err(|e| Refusal::from(&e))?;
        return Ok(done());
    }
    let _lock = SpoolGuard::lock(state).map_err(|e| Refusal::from(&e))?;
    let names = state
        .names_up_to(MAX_STATE_NAMES + 1)
        .map_err(|e| Refusal::from(&e))?;
    if names.len() > MAX_STATE_NAMES {
        return Err(Refusal::broker(
            RefusalCode::SpoolFull,
            "the state directory holds too many names to thaw",
        ));
    }
    for name in names
        .iter()
        .filter(|name| xudo_gate::policy::is_freeze_marker_name(name))
    {
        state.remove(name).map_err(|e| Refusal::from(&e))?;
    }
    Ok(done())
}

fn pending_list(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
) -> Result<BrokerResponse, Refusal> {
    let now = platform.clock.boottime_millis();
    let _guard = SpoolGuard::lock(spool).map_err(|error| Refusal::from(&error))?;
    let names = spool
        .names_up_to(crate::mint::MAX_SPOOL_NAMES_TO_WALK)
        .map_err(|error| Refusal::from(&error))?;
    let mut prompts = Vec::new();
    let mut omitted = 0;
    for name in names {
        let Ok(bytes) = spool.read(&name, crate::mint::MAX_ENTRY_BYTES) else {
            continue;
        };
        let Ok(entry) = parse_entry(&bytes) else {
            continue;
        };
        if entry.caller_uid == identity.uid
            && entry.needs_watch
            && entry.state == xudo_gate::request::ConfirmationState::Pending
            && entry.deadline.0 > now
        {
            let candidate = bounded_prompt(&entry, now);
            let mut proposed = prompts.clone();
            proposed.push(candidate.clone());
            let response = BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer: xudo_wire::Answer::Watching {
                    prompts: proposed,
                    omitted,
                },
            };
            if prompts.len() < xudo_wire::MAX_PROMPTS
                && response.to_json().len() <= xudo_wire::MAX_RESPONSE_BYTES.saturating_sub(16)
            {
                prompts.push(candidate);
            } else {
                omitted = omitted.saturating_add(1);
            }
        }
    }
    Ok(BrokerResponse {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        answer: xudo_wire::Answer::Watching { prompts, omitted },
    })
}

fn status(
    _conn: &dyn Connection,
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
    _request: &BrokerRequest,
    id: &str,
) -> Result<BrokerResponse, Refusal> {
    let Ok(bytes) = spool.read(id.as_bytes(), crate::mint::MAX_ENTRY_BYTES) else {
        return status_outcome(platform, identity, id);
    };
    let entry = parse_entry(&bytes)?;
    if entry.caller_uid != identity.uid
        || entry.caller_pid != identity.pid
        || entry.caller_starttime != identity.starttime
    {
        return Err(Refusal::client(
            RefusalCode::ChannelUntrusted,
            "status is limited to the requesting process",
        ));
    }
    let response = match entry.state {
        xudo_gate::request::ConfirmationState::Pending => xudo_wire::Answer::Pending {
            id: entry.nonce,
            expires_in_ms: entry
                .deadline
                .0
                .saturating_sub(platform.clock.boottime_millis()),
        },
        state => {
            let code = match state {
                xudo_gate::request::ConfirmationState::Expired => {
                    Some(xudo_policy::DenialCode::ConfirmationExpired)
                }
                xudo_gate::request::ConfirmationState::Denied => {
                    Some(xudo_policy::DenialCode::ConfirmationRefused)
                }
                xudo_gate::request::ConfirmationState::Consumed
                | xudo_gate::request::ConfirmationState::Pending
                | xudo_gate::request::ConfirmationState::Approved => None,
            };
            let command = std::iter::once(entry.program.clone())
                .chain(entry.argv.clone())
                .collect();
            let mut decision = Decision::deny(
                code.unwrap_or(xudo_policy::DenialCode::ConfirmationRefused),
                command,
                Vec::new(),
            )
            .about_program(&entry.program);
            decision.action = Some(xudo_policy::ActionId::new(entry.action.clone()));
            if state == xudo_gate::request::ConfirmationState::Consumed {
                decision.verdict = xudo_policy::Verdict::Allow;
                decision.denial = None;
                decision.remediation = None;
            }
            let minted = if state == xudo_gate::request::ConfirmationState::Approved {
                decision.verdict = xudo_policy::Verdict::AllowWithConfirmation;
                decision.denial = None;
                Some(Minted {
                    nonce: entry.nonce.clone(),
                    expires_in_ms: entry
                        .deadline
                        .0
                        .saturating_sub(platform.clock.boottime_millis()),
                    gate: xudo_backend::snippet::GATE_AUTH.to_owned(),
                })
            } else {
                None
            };
            return Ok(BrokerResponse::decided(decision, minted));
        }
    };
    Ok(BrokerResponse {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        answer: response,
    })
}

fn status_outcome(
    platform: &Platform<'_>,
    identity: &PeerIdentity,
    id: &str,
) -> Result<BrokerResponse, Refusal> {
    let store = platform
        .confirmations
        .ok_or_else(|| Refusal::client(RefusalCode::RequestUnknown, "request does not exist"))?;
    let bytes = store
        .read(
            format!("{}.json", identity.uid).as_bytes(),
            CONFIRM_FILE_LIMIT,
        )
        .map_err(|_| Refusal::client(RefusalCode::RequestUnknown, "request does not exist"))?;
    let data: ConfirmData = parse_confirm_data(&bytes)
        .map_err(|_| Refusal::client(RefusalCode::RequestUnknown, "request does not exist"))?;
    let now = platform.clock.boottime_millis();
    let outcome = data
        .outcomes
        .iter()
        .find(|item| {
            item.id == id
                && item.until_ms > now
                && item.pid == identity.pid
                && item.starttime == identity.starttime
        })
        .ok_or_else(|| Refusal::client(RefusalCode::RequestUnknown, "request does not exist"))?;
    let code = match outcome.outcome {
        TerminalOutcome::Denied => xudo_policy::DenialCode::ConfirmationRefused,
        TerminalOutcome::Expired => xudo_policy::DenialCode::ConfirmationExpired,
    };
    Ok(BrokerResponse::decided(
        Decision::deny(code, Vec::new(), Vec::new()),
        None,
    ))
}

fn watch(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
) -> Result<BrokerResponse, Refusal> {
    if identity.diverged || !xudo_gate::request::is_watch_terminal(identity.tty) {
        return Err(Refusal::client(
            RefusalCode::ChannelUntrusted,
            "watch requires a checked terminal",
        ));
    }
    let now = platform.clock.boottime_millis();
    save_heartbeat(platform, spool, identity, now)?;
    let watcher = crate::confirm::WatcherFacts {
        uid: identity.uid,
        pid: identity.pid,
        starttime: identity.starttime,
        tty: identity.tty,
        sid: identity.sid,
        diverged: identity.diverged,
    };
    let mut candidates = Vec::new();
    let _guard = SpoolGuard::lock(spool).map_err(|e| Refusal::from(&e))?;
    let names = spool
        .names_up_to(crate::mint::MAX_SPOOL_NAMES_TO_WALK)
        .map_err(|e| Refusal::from(&e))?;
    for id in names {
        let Ok(bytes) = spool.read(&id, crate::mint::MAX_ENTRY_BYTES) else {
            continue;
        };
        let Ok(entry) = parse_entry(&bytes) else {
            continue;
        };
        if crate::confirm::watcher_eligible(&entry, watcher) {
            let already_shown = entry.shown_to.as_ref() == Some(&watcher.pin());
            let mut candidate = entry;
            if !crate::confirm::mark_shown(&mut candidate, watcher, now) {
                continue;
            }
            candidates.push((!already_shown, candidate.deadline.0, id, bytes, candidate));
        }
    }
    // Earliest deadline is oldest mint time while every entry has the same lifetime.
    candidates.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    let mut prompts = Vec::new();
    if let Some((needs_first_delivery, _, id, bytes, entry)) = candidates.into_iter().next() {
        let prompt = bounded_prompt(&entry, now);
        if needs_first_delivery {
            let json = entry.to_json();
            spool
                .replace(&id, &bytes, json.as_bytes())
                .map_err(|e| Refusal::from(&e))?;
        }
        prompts.push(prompt);
    }
    Ok(BrokerResponse {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        answer: xudo_wire::Answer::Watching {
            prompts,
            omitted: 0,
        },
    })
}

fn bounded_prompt(
    entry: &xudo_gate::request::PendingRequest,
    now_ms: u64,
) -> xudo_wire::WatchPrompt {
    xudo_wire::WatchPrompt {
        id: entry.nonce.clone(),
        action: entry.action.clone(),
        program: entry.program.clone(),
        argv: entry.argv.clone(),
        classification: stored_caller(entry).classification.label().to_owned(),
        evidence: "watch approval is pending; the password remains required".to_owned(),
        expires_in_ms: entry.deadline.0.saturating_sub(now_ms),
    }
}

/// Drops uid files that can no longer change a decision, once the directory
/// is at [`MAX_CONFIRM_UIDS`].
///
/// A file is idle when it has no live heartbeat, no backoff strike still
/// inside its window, and no outcome a status read would still return.
/// Anything unreadable, malformed, or over a field bound stays: deleting it
/// could drop a strike the parser did not show us. Live state is never
/// deleted, so a directory full of live uids still refuses. Below the bound
/// the files stay, so a failed heartbeat write cannot erase them. The caller
/// holds the confirm lock.
fn prune_idle_confirmations(
    store: &dyn Spool,
    requests: &dyn Spool,
    peers: &dyn PeerCalls,
    own_name: &[u8],
    now: u64,
) -> Result<(), SpoolError> {
    loop {
        let names = store.names_up_to(MAX_CONFIRM_UIDS + 1)?;
        if names.len() < MAX_CONFIRM_UIDS
            || (names.len() == MAX_CONFIRM_UIDS && names.iter().any(|name| name == own_name))
        {
            return Ok(());
        }
        let _requests_guard = SpoolGuard::lock(requests)?;
        let request_names = requests.names_up_to(crate::mint::MAX_SPOOL_NAMES_TO_WALK)?;
        let mut live_uids = Vec::new();
        for id in request_names {
            let bytes = requests.read(&id, crate::mint::MAX_ENTRY_BYTES)?;
            let Ok(entry) = parse_entry(&bytes) else {
                continue;
            };
            if request_uid_is_live(&entry) {
                live_uids.push(entry.caller_uid);
            }
        }
        live_uids.sort_unstable();
        live_uids.dedup();
        let mut removed = false;
        for name in &names {
            if !uid_file_is_live(name, &live_uids) && confirmation_is_idle(store, peers, name, now)
            {
                store.remove(name)?;
                removed = true;
            }
        }
        if !removed {
            return Ok(());
        }
    }
}

fn request_uid_is_live(entry: &xudo_gate::request::PendingRequest) -> bool {
    if !entry.needs_watch {
        return false;
    }
    matches!(
        entry.state,
        xudo_gate::request::ConfirmationState::Pending
            | xudo_gate::request::ConfirmationState::Approved
    )
}

fn uid_file_is_live(name: &[u8], live_uids: &[u32]) -> bool {
    let Some(uid) = name
        .strip_suffix(b".json")
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|text| text.parse::<u32>().ok())
    else {
        return false;
    };
    live_uids.binary_search(&uid).is_ok()
}

/// `true` only when the file is safe to delete. A read or parse failure is
/// not idle.
fn confirmation_is_idle(store: &dyn Spool, peers: &dyn PeerCalls, name: &[u8], now: u64) -> bool {
    let Ok(bytes) = store.read(name, CONFIRM_FILE_LIMIT) else {
        return false;
    };
    let Ok(data) = validated_confirm(&bytes) else {
        return false;
    };
    if data.backoff.iter().any(|entry| now < entry.until_ms) {
        return false;
    }
    if data.outcomes.iter().any(|entry| now < entry.until_ms) {
        return false;
    }
    data.heartbeat
        .as_ref()
        .is_none_or(|heartbeat| !heartbeat_is_live(peers, heartbeat, now))
}

fn save_heartbeat(
    platform: &mut Platform<'_>,
    requests: &dyn Spool,
    identity: &PeerIdentity,
    now: u64,
) -> Result<(), Refusal> {
    let store = platform.confirmations.ok_or_else(|| {
        Refusal::broker(
            RefusalCode::SpoolUnusable,
            "confirmation directory is unavailable",
        )
    })?;
    let _guard = SpoolGuard::lock(store).map_err(|e| Refusal::from(&e))?;
    let name = format!("{}.json", identity.uid);
    prune_idle_confirmations(store, requests, platform.peers, name.as_bytes(), now)
        .map_err(|error| Refusal::from(&error))?;
    let heartbeat = WatcherHeartbeat {
        pid: identity.pid,
        starttime: identity.starttime,
        tty: identity.tty,
        sid: identity.sid,
        at_ms: now,
    };
    let (old, data) = read_confirm_data(store, &name).map_err(|_| {
        Refusal::broker(
            RefusalCode::SpoolUnusable,
            "confirmation file is unreadable or malformed; operator repair is required",
        )
    })?;
    if let Some(data) = &data {
        if let Some(first) = &data.heartbeat {
            if (first.pid != identity.pid || first.starttime != identity.starttime)
                && heartbeat_is_live(platform.peers, first, now)
            {
                return Err(Refusal::client(
                    RefusalCode::ChannelUntrusted,
                    format!(
                        "watcher already active: pid {}, tty {}",
                        first.pid, first.tty
                    ),
                ));
            }
        }
    }
    let data = data.unwrap_or(ConfirmData {
        heartbeat: None,
        backoff: Vec::new(),
        outcomes: Vec::new(),
    });
    let mut updated = data;
    updated.outcomes.retain(|outcome| outcome.until_ms > now);
    updated.backoff.retain(|entry| entry.until_ms > now);
    updated.heartbeat = Some(heartbeat);
    write_confirm(store, &name, old, &updated).map_err(|error| refusal_from_confirm_write(&error))
}

fn answer_confirmation(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
    request: &BrokerRequest,
) -> Result<BrokerResponse, Refusal> {
    let xudo_wire::Question::Answer { id, token, approve } = &request.question else {
        return Err(Refusal::client(
            RefusalCode::RequestMalformed,
            "answer question required",
        ));
    };
    let (id, token, approve) = (id.as_str(), token.as_str(), *approve);
    let _confirm_guard = if approve {
        None
    } else {
        let store = platform.confirmations.ok_or_else(|| {
            Refusal::broker(
                RefusalCode::SpoolUnusable,
                "confirmation directory is unavailable",
            )
        })?;
        Some(SpoolGuard::lock(store).map_err(|e| Refusal::from(&e))?)
    };
    let _guard = SpoolGuard::lock(spool).map_err(|e| Refusal::from(&e))?;
    let bytes = spool
        .read(id.as_bytes(), crate::mint::MAX_ENTRY_BYTES)
        .map_err(|_| Refusal::client(RefusalCode::RequestUnknown, "request does not exist"))?;
    let mut entry = parse_entry(&bytes)?;
    let watcher = crate::confirm::WatcherFacts {
        uid: identity.uid,
        pid: identity.pid,
        starttime: identity.starttime,
        tty: identity.tty,
        sid: identity.sid,
        diverged: identity.diverged,
    };
    let answer = if approve {
        crate::confirm::Answer::Approve(token.as_bytes())
    } else {
        crate::confirm::Answer::Deny
    };
    crate::confirm::answer(
        &mut entry,
        watcher,
        platform.clock.boottime_millis(),
        crate::confirm::Settings::default(),
        answer,
    )
    .map_err(|_| Refusal::client(RefusalCode::AnswerRejected, "answer was refused"))?;
    complete_answer(
        platform,
        spool,
        identity,
        request,
        AnsweredEntry {
            id: id.to_owned(),
            bytes,
            entry,
        },
        approve,
    )
}

struct AnsweredEntry {
    id: String,
    bytes: Vec<u8>,
    entry: xudo_gate::request::PendingRequest,
}

fn complete_answer(
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    identity: &PeerIdentity,
    request: &BrokerRequest,
    answered: AnsweredEntry,
    approve: bool,
) -> Result<BrokerResponse, Refusal> {
    let AnsweredEntry { id, bytes, entry } = answered;
    let caller = stored_caller(&entry);
    let policy = platform
        .policy
        .load()
        .map_err(|_| Refusal::broker(RefusalCode::PolicyUnloadable, "policy cannot be loaded"))?;
    let decision_request = BrokerRequest::new(
        entry.program.clone(),
        entry.argv.clone(),
        STORED_CLASS_CLAIM,
    );
    let mut policy = policy;
    // The entry's owner may have frozen their own agents since it was minted.
    policy.settings.frozen |= user_freeze_stands(platform, entry.caller_uid);
    let mut decision = decide(&policy, &caller, &decision_request);
    if approve && decision.verdict != xudo_policy::Verdict::AllowWithConfirmation {
        return Err(Refusal::broker(
            RefusalCode::PolicyUnloadable,
            "fresh decision no longer allows this confirmation",
        ));
    }
    if !approve {
        decision.verdict = xudo_policy::Verdict::Deny;
        decision.denial = Some(xudo_policy::DenialCode::ConfirmationRefused);
    }
    if approve {
        let grant = Grant(entry.clone());
        let generation = &policy.rules.generation;
        let authorized = authorize(&mut *platform.audit, grant, &|previous, grant| {
            decided(
                previous,
                &decision,
                &caller,
                identity,
                request,
                generation,
                Some(&grant.0),
            )
        })
        .map_err(|error| {
            Refusal::broker(
                RefusalCode::BrokerUnusable,
                format!("approval audit record was refused: {error}"),
            )
        })?;
        let replace = spool.replace(
            id.as_bytes(),
            &bytes,
            authorized.approval().0.to_json().as_bytes(),
        );
        replace.map_err(|e| Refusal::from(&e))?;
    } else {
        let record = platform
            .audit
            .append(&|previous| {
                decided(
                    previous,
                    &decision,
                    &caller,
                    identity,
                    request,
                    &policy.rules.generation,
                    None,
                )
            })
            .map_err(|_| {
                Refusal::broker(
                    RefusalCode::BrokerUnusable,
                    "denial audit record was refused",
                )
            })?;
        drop(record);
        record_outcome_locked(
            platform.confirmations.ok_or_else(|| {
                Refusal::broker(
                    RefusalCode::SpoolUnusable,
                    "confirmation directory is unavailable",
                )
            })?,
            &entry,
            TerminalOutcome::Denied,
            platform.clock.boottime_millis(),
            true,
        )?;
        spool.remove(id.as_bytes()).map_err(|e| Refusal::from(&e))?;
    }
    Ok(BrokerResponse {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        answer: xudo_wire::Answer::Done,
    })
}

struct SpoolGuard<'a, S: Spool + ?Sized>(&'a S);

impl<'a, S: Spool + ?Sized> SpoolGuard<'a, S> {
    fn lock(spool: &'a S) -> Result<Self, SpoolError> {
        spool.lock()?;
        Ok(Self(spool))
    }
}

impl<S: Spool + ?Sized> Drop for SpoolGuard<'_, S> {
    fn drop(&mut self) {
        self.0.unlock();
    }
}

fn parse_entry(bytes: &[u8]) -> Result<xudo_gate::request::PendingRequest, Refusal> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| xudo_gate::request::PendingRequest::parse(s).ok())
        .filter(xudo_gate::request::PendingRequest::has_consistent_attested_identity)
        .ok_or_else(|| Refusal::client(RefusalCode::RequestUnknown, "request entry is invalid"))
}

/// Reads and parses the request.
fn receive(conn: &dyn Connection) -> Result<BrokerRequest, Refusal> {
    let bytes = conn
        .read_request(MAX_REQUEST_BYTES)
        .map_err(|error| Refusal::from(&error))?;
    BrokerRequest::parse(&bytes).map_err(|error| Refusal::from(&error))
}

/// Mints the entry for a permitted decision and answers with it.
fn mint(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    spool: &dyn Spool,
    evaluated: Evaluated,
) -> Served {
    let Evaluated {
        decision,
        caller,
        identity,
        request,
        policy,
    } = evaluated;
    let known = (Some(&identity), Some(&request));

    let nonce = match draw_nonce(platform.entropy) {
        Ok(nonce) => nonce,
        Err(error) => {
            let refusal = Refusal::broker(
                RefusalCode::BrokerUnusable,
                format!("cannot draw a nonce: {error}"),
            );
            return refuse(conn, platform.audit, &refusal, known.0, known.1);
        }
    };
    let now = platform.clock.boottime_millis();
    let deadline = now.saturating_add(REQUEST_TTL_MILLIS);
    let entry = match entry_for_classified(
        &decision,
        &AttestedCaller {
            identity: &identity,
            facts: &caller,
            boot_id: None,
        },
        &request,
        policy.rules.generation.id(),
        policy.settings.confirm_human_path,
        deadline,
        nonce,
    ) {
        Ok(entry) => entry,
        Err(error) => {
            return refuse(
                conn,
                platform.audit,
                &Refusal::from(&error),
                known.0,
                known.1,
            );
        }
    };

    // No record, no entry: `publish` takes the authorization.
    let build = |previous: Option<&Record>, grant: &Grant| {
        decided(
            previous,
            &decision,
            &caller,
            &identity,
            &request,
            &policy.rules.generation,
            Some(&grant.0),
        )
    };
    let authorized = match authorize(&mut *platform.audit, Grant(entry), &build) {
        Ok(authorized) => authorized,
        Err(error) => {
            let why =
                format!("the audit record could not be written, so nothing was minted: {error}");
            // A request too big to record is the client's doing, not the broker's.
            let refusal = if matches!(error, AuditError::TooLarge { .. }) {
                Refusal::client(RefusalCode::RequestTooLarge, why)
            } else {
                Refusal::broker(RefusalCode::BrokerUnusable, why)
            };
            return refuse(conn, platform.audit, &refusal, known.0, known.1);
        }
    };
    let nonce = authorized.approval().0.nonce.clone();
    let json = authorized.approval().0.to_json();
    let minting = Minting {
        authorized: &authorized,
        json: &json,
        uid: identity.uid,
        now,
    };
    if let Err(error) = publish(spool, platform.peers, &minting) {
        return mint_failure(
            conn,
            platform,
            &error,
            Evaluated {
                decision,
                caller,
                identity,
                request,
                policy,
            },
        );
    }

    let minted = Minted {
        nonce,
        expires_in_ms: remaining_millis(deadline, platform.clock.boottime_millis()),
        gate: xudo_backend::snippet::GATE_AUTH.to_owned(),
    };
    let response = minted_response(&authorized.approval().0, decision, minted);
    answer(conn, &response, Served::Minted)
}

fn minted_response(
    entry: &xudo_gate::request::PendingRequest,
    decision: Decision,
    minted: Minted,
) -> BrokerResponse {
    if entry.needs_watch {
        BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: xudo_wire::Answer::Pending {
                id: minted.nonce,
                expires_in_ms: minted.expires_in_ms,
            },
        }
    } else {
        BrokerResponse::decided(decision, Some(minted))
    }
}

fn mint_failure(
    conn: &dyn Connection,
    platform: &mut Platform<'_>,
    error: &MintError,
    evaluated: Evaluated,
) -> Served {
    if *error == MintError::ConfirmationThrottled {
        return serve_confirmation_denial(
            conn,
            platform,
            evaluated,
            xudo_policy::DenialCode::ConfirmationThrottled,
        );
    }
    let Evaluated {
        identity, request, ..
    } = evaluated;
    refuse(
        conn,
        platform.audit,
        &Refusal::from(error),
        Some(&identity),
        Some(&request),
    )
}

fn remaining_millis(deadline: u64, now: u64) -> u64 {
    deadline.saturating_sub(now)
}

/// Records a refusal and sends it.
fn refuse(
    conn: &dyn Connection,
    audit: &mut dyn AuditSink,
    refusal: &Refusal,
    identity: Option<&PeerIdentity>,
    request: Option<&BrokerRequest>,
) -> Served {
    let _ = audit.append(&|previous| refused(previous, refusal, identity, request));
    let response = if refusal.code == RefusalCode::ChannelUntrusted && !refusal.detail.is_empty() {
        BrokerResponse::refused_with_detail(
            refusal.code,
            refusal.detail.chars().take(256).collect(),
        )
    } else {
        BrokerResponse::refused(refusal.code)
    };
    answer(conn, &response, Served::Refused(refusal.fault))
}

/// Sends the response, reporting `served` if it arrived.
///
/// A broker fault stays one whether or not the client heard about it: the
/// client leaving does not make a broken spool any less broken.
fn answer(conn: &dyn Connection, response: &BrokerResponse, served: Served) -> Served {
    match conn.write_response(response.to_json().as_bytes()) {
        Ok(()) => served,
        Err(_) if served == Served::Refused(Fault::Broker) => served,
        Err(_) => Served::Undelivered,
    }
}

/// Answers and records a startup hygiene failure before any other broker work.
pub(crate) fn refuse_hygiene_failure(
    conn: &dyn Connection,
    audit: &mut dyn AuditSink,
    error: &xudo_sys::SysError,
) -> Served {
    refuse(
        conn,
        audit,
        &Refusal::broker(RefusalCode::BrokerUnusable, error.to_string()),
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use std::cell::{Cell, RefCell};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use xudo_audit::record::{Decision as AuditDecision, Record};
    use xudo_gate::request::{BoottimeMillis, PendingRequest};
    use xudo_policy::{DenialCode, RuleFile, Verdict, load_rule_files};
    use xudo_sys::{
        Creds, FakeAuditSink, FakeConnection, FakeEntropy, FakeHygiene, FakePeer, FakeSpool,
        FakeSyscalls, FixedClock, PeerCred, PidfdInfo, ProcFile, ProcessIds, ReadFailure, Spool,
        SpoolCall, SysError,
    };
    use xudo_wire::{Answer, WIRE_SCHEMA_VERSION};

    use super::*;
    use crate::mint::{MAX_SPOOL_ENTRIES, MintError, entry_for};
    use crate::policy::PolicyError;

    const PID: u32 = 4242;
    const UID: u32 = 1000;
    const GID: u32 = 100;
    const START: u64 = 998_877;
    const NOW: u64 = 10_000;

    #[test]
    fn an_expired_mint_reports_zero_remaining_lifetime() {
        assert_eq!(remaining_millis(NOW, NOW + 1), 0);
        assert_eq!(remaining_millis(NOW + 7, NOW), 7);
    }

    /// Three rules: one that runs freely, one that always confirms, and one a
    /// careless operator wrote for a shell.
    const RULES: &str = r#"
[[action]]
id = "xudo.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "xudo.pkg.remove"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "pkg", matcher = { one-of = ["gcc"] } },
]

[[action]]
id = "xudo.pkg.purge-human"
tier = "pkg-remove"
confirm = "always"
agent-allowed = false
exe = "/usr/bin/apt-get"
args = [
  { name = "verb", matcher = { literal = "purge" } },
  { name = "pkg", matcher = { one-of = ["gcc"] } },
]

[[action]]
id = "xudo.oops.shell"
tier = "diag-read"
exe = "/bin/sh"
args = [{ name = "c", matcher = { literal = "-c" } }]
"#;

    fn policy() -> LoadedPolicy {
        LoadedPolicy {
            rules: load_rule_files(vec![RuleFile {
                name: b"10-test.toml".to_vec(),
                bytes: RULES.as_bytes().to_vec(),
            }])
            .unwrap(),
            settings: xudo_policy::engine::Settings::default(),
        }
    }

    /// Root's policy, fixed, counting how often it was asked for.
    struct FixedPolicy {
        answer: Result<LoadedPolicy, PolicyError>,
        loads: Cell<u32>,
    }

    impl PolicySource for FixedPolicy {
        fn load(&self) -> Result<LoadedPolicy, PolicyError> {
            self.loads.set(self.loads.get() + 1);
            self.answer.clone()
        }
    }

    /// Everything the broker asks of its host, faked: by default a peer that
    /// identifies honestly on the top rung, a fixed clock, one scripted
    /// nonce, and the test ruleset.
    struct Host {
        hygiene: FakeHygiene,
        syscalls: FakeSyscalls,
        peers: FakePeer,
        clock: FixedClock,
        entropy: FakeEntropy,
        policy: FixedPolicy,
        audit: FakeAuditSink,
        confirmations: FakeSpool,
        confirmations_available: bool,
        freeze_file: FakeSpool,
        freeze_available: bool,
    }

    impl Host {
        fn honest() -> Self {
            Self::honest_as(UID)
        }

        /// A peer that identifies honestly as `uid`.
        fn honest_as(uid: u32) -> Self {
            let record = PidfdInfo::empty()
                .with_ids(ProcessIds {
                    pid: PID,
                    tgid: PID,
                    ppid: 1,
                })
                .with_creds(Creds {
                    ruid: uid,
                    rgid: GID,
                    euid: uid,
                    egid: GID,
                    suid: uid,
                    sgid: GID,
                    fsuid: uid,
                    fsgid: GID,
                });
            Self {
                hygiene: FakeHygiene::new(PID),
                syscalls: FakeSyscalls::new()
                    .with_peer(Ok(a_descriptor()))
                    .with_info(Ok(record)),
                peers: FakePeer::new()
                    .with_cred(Ok(PeerCred {
                        pid: PID,
                        uid,
                        gid: GID,
                    }))
                    .with_stat(Ok(stat_line(PID, START)))
                    .with_proc(
                        PID,
                        ProcFile::Status,
                        format!("NSpid:\t{PID}\n").into_bytes(),
                    )
                    .with_proc(PID, ProcFile::UidMap, b"0 0 4294967295\n".to_vec())
                    .with_exit(Ok(false)),
                clock: FixedClock(NOW),
                entropy: FakeEntropy::new().with(Ok(vec![0xab; 32])),
                policy: FixedPolicy {
                    answer: Ok(policy()),
                    loads: Cell::new(0),
                },
                audit: FakeAuditSink::new(),
                confirmations: FakeSpool::new(),
                confirmations_available: true,
                freeze_file: FakeSpool::new(),
                freeze_available: true,
            }
        }

        fn platform(&mut self) -> Platform<'_> {
            Platform {
                hygiene: &self.hygiene,
                syscalls: &self.syscalls,
                peers: &self.peers,
                clock: &self.clock,
                entropy: &self.entropy,
                policy: &self.policy,
                audit: &mut self.audit,
                confirmations: self.confirmations_available.then_some(&self.confirmations),
                freeze_file: self.freeze_available.then_some(&self.freeze_file),
            }
        }
    }

    /// Any descriptor: the fakes are handed it and never look at it.
    fn a_descriptor() -> OwnedFd {
        OwnedFd::from(UnixStream::pair().unwrap().0)
    }

    fn stat_line(pid: u32, starttime: u64) -> Vec<u8> {
        let mut tail: Vec<String> = vec!["S".into(), "1".into()];
        tail.extend(std::iter::repeat_n("0".to_owned(), 17));
        tail.push(starttime.to_string());
        format!("{pid} (xudo) {}", tail.join(" ")).into_bytes()
    }

    fn stat_line_with_terminal(pid: u32, starttime: u64, sid: i64, tty: i64) -> Vec<u8> {
        let mut tail: Vec<String> = vec![
            "S".into(),
            "1".into(),
            "1".into(),
            sid.to_string(),
            tty.to_string(),
        ];
        tail.extend(std::iter::repeat_n("0".to_owned(), 14));
        tail.push(starttime.to_string());
        format!("{pid} (xudo) {}", tail.join(" ")).into_bytes()
    }

    fn connection(request: Result<Vec<u8>, ReadFailure>) -> FakeConnection {
        FakeConnection::new(a_descriptor(), request)
    }

    fn asking(program: &str, argv: &[&str]) -> FakeConnection {
        let request = BrokerRequest::new(
            program,
            argv.iter().map(|a| (*a).to_owned()).collect(),
            "enrolled-agent-yolo",
        );
        connection(Ok(request.to_json().into_bytes()))
    }

    fn restart() -> FakeConnection {
        asking("/usr/bin/systemctl", &["restart", "nginx.service"])
    }

    fn confirming_policy() -> LoadedPolicy {
        let mut policy = policy();
        policy.settings.confirm_human_path = true;
        policy
    }

    fn turn_on_confirmation(host: &mut Host) {
        host.policy.answer = Ok(confirming_policy());
    }

    const NONCE: &str = "abababababababababababababababababababababababababababababababab";

    /// What one connection produced: how it ended, the answer the client
    /// read, and the audit records, one per line.
    struct Outcome {
        served: Served,
        answer: Answer,
        records: Vec<Record>,
    }

    fn serve_with(
        host: &mut Host,
        conn: &FakeConnection,
        spool: Result<&FakeSpool, &SpoolError>,
    ) -> Outcome {
        let spool = spool.map(|spool| spool as &dyn Spool);
        let served = serve(conn, &mut host.platform(), spool);
        let written = conn.written();
        let response = BrokerResponse::parse(&written).unwrap();
        assert_eq!(response.schema_version, WIRE_SCHEMA_VERSION);
        let records = host.audit.records().to_vec();
        Outcome {
            served,
            answer: response.answer,
            records,
        }
    }

    fn refusal_of(answer: &Answer) -> Option<RefusalCode> {
        match answer {
            Answer::Refused { code, .. } => Some(*code),
            Answer::Decided { .. }
            | Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::Done => None,
        }
    }

    #[test]
    fn a_watcher_without_a_terminal_is_refused() {
        let mut host = Host::honest();
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Watch,
        };
        let conn = connection(Ok(request.to_json().into_bytes()));
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &conn, Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Client));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::ChannelUntrusted)
        );
        assert_eq!(host.policy.loads.get(), 0);
        assert!(spool.calls().is_empty());
        assert_eq!(outcome.records.len(), 1);
        assert!(
            outcome.records[0]
                .evidence
                .contains(&"question=watch".to_owned())
        );
    }

    #[test]
    fn a_new_request_with_no_watcher_is_still_denied_no_confirmation_channel() {
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        let conn = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &conn, Ok(&spool));
        assert_eq!(outcome.served, Served::Decided);
        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.denial, Some(DenialCode::NoConfirmationChannel));
        assert!(minted.is_none());
        assert!(spool.files().is_empty());
        // One record, a denial: no grant record is written without a watcher.
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].decision, xudo_audit::Decision::Denied);
    }

    #[test]
    fn an_unreadable_approval_spool_is_refused_with_no_live_watcher() {
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        let spool = FakeSpool::new()
            .with_file("approval.json", b"malformed but unreadable".to_vec())
            .failing_read("approval.json");
        let outcome = serve_with(
            &mut host,
            &asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]),
            Ok(&spool),
        );
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );
        assert_eq!(outcome.records.len(), 1);
    }

    /// Serves a re-run from `PID + 7` with no live watcher against the
    /// requester's approval after `damage` has damaged it, and checks that the
    /// answer is a denial, nothing is minted and the spool is untouched.
    fn assert_damaged_approval_is_denied_without_a_watcher(
        damage: fn(&mut PendingRequest),
    ) -> (FakeSpool, std::collections::BTreeMap<Vec<u8>, Vec<u8>>) {
        let (spool, id) = approved_for_the_requester();
        let mut entry = the_entry(&spool, &id);
        damage(&mut entry);
        let spool =
            FakeSpool::new().with_file(id.as_bytes().to_vec(), entry.to_json().into_bytes());
        let before = spool.files();
        let mut host = rerun_host(PID + 7, START + 7, 0, 0);
        host.confirmations = FakeSpool::new();
        let outcome = serve_with(
            &mut host,
            &asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]),
            Ok(&spool),
        );
        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.denial, Some(DenialCode::NoConfirmationChannel));
        assert!(minted.is_none());
        (spool, before)
    }

    fn assert_damaged_approval_is_left_alone(damage: fn(&mut PendingRequest)) {
        let (spool, before) = assert_damaged_approval_is_denied_without_a_watcher(damage);
        assert_eq!(spool.files(), before);
    }

    #[test]
    fn an_expired_approval_cannot_skip_a_missing_live_channel() {
        // The sweep removes the dead entry; it is never consumed.
        let (spool, _) = assert_damaged_approval_is_denied_without_a_watcher(|entry| {
            entry.deadline = BoottimeMillis(NOW);
        });
        assert!(spool.files().is_empty());
    }

    #[test]
    fn a_consumed_approval_cannot_skip_a_missing_live_channel() {
        assert_damaged_approval_is_left_alone(|entry| {
            entry.state = xudo_gate::request::ConfirmationState::Consumed;
        });
    }

    #[test]
    fn an_approval_for_different_argv_cannot_skip_a_missing_live_channel() {
        assert_damaged_approval_is_left_alone(|entry| {
            entry.argv[2] = "make".to_owned();
        });
    }

    #[test]
    fn an_approval_for_different_generation_cannot_skip_a_missing_live_channel() {
        assert_damaged_approval_is_left_alone(|entry| {
            entry.generation = entry.generation.saturating_add(1);
        });
    }

    #[test]
    fn an_approval_for_different_action_cannot_skip_a_missing_live_channel() {
        assert_damaged_approval_is_left_alone(|entry| {
            entry.action = "xudo.pkg.install".to_owned();
        });
    }

    #[test]
    fn a_different_identity_caller_with_no_watcher_is_denied_not_minted() {
        assert_damaged_approval_is_left_alone(|entry| {
            entry.caller_uid = UID.saturating_add(1);
        });
    }

    #[test]
    fn an_approval_of_another_class_with_no_watcher_is_denied_not_minted() {
        assert_damaged_approval_is_left_alone(|entry| {
            entry.attested_class = xudo_gate::request::AttestedClass::Human;
        });
    }

    #[test]
    fn a_pending_entry_cannot_skip_a_missing_live_channel() {
        assert_damaged_approval_is_left_alone(|entry| {
            entry.state = xudo_gate::request::ConfirmationState::Pending;
            entry.confirmed = false;
            entry.confirmed_by = None;
        });
    }

    #[test]
    fn an_approved_rerun_runs_after_the_watcher_has_closed() {
        let (spool, id) = approved_for_the_requester();
        let mut host = rerun_host(PID + 7, START + 7, 9, 9);
        host.confirmations = FakeSpool::new().with_file(
            format!("{UID}.json").into_bytes(),
            serde_json::to_vec(&ConfirmData {
                heartbeat: Some(WatcherHeartbeat {
                    pid: 5000,
                    starttime: 77,
                    tty: 34816,
                    sid: 2,
                    at_ms: NOW - HEARTBEAT_FRESH_MS - 1,
                }),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        let outcome = serve_with(
            &mut host,
            &asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]),
            Ok(&spool),
        );
        assert_eq!(outcome.served, Served::Minted);
        let (_, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(minted.map(|m| m.nonce.clone()), Some(id.clone()));
        assert_eq!(
            minted.map(|m| m.gate.as_str()),
            Some(xudo_backend::snippet::GATE_AUTH)
        );
        let entry = the_entry(&spool, &id);
        assert_eq!(entry.state, xudo_gate::request::ConfirmationState::Consumed);
        assert_eq!(
            (entry.caller_pid, entry.caller_sid, entry.caller_tty),
            (PID + 7, 9, 9)
        );
    }

    #[test]
    fn an_approval_search_spool_error_is_a_refusal() {
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        host.peers = peer_with_live_watcher();
        let spool = FakeSpool::new().failing_lock(SpoolError::Gone {
            name: "approval lock".to_owned(),
        });
        let outcome = serve_with(
            &mut host,
            &asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]),
            Ok(&spool),
        );
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
    }

    #[test]
    fn a_stale_heartbeat_is_not_a_live_channel() {
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        let heartbeat = WatcherHeartbeat {
            pid: 5000,
            starttime: 77,
            tty: 34816,
            sid: 2,
            at_ms: NOW - 3_001,
        };
        let data = ConfirmData {
            heartbeat: Some(heartbeat),
            backoff: Vec::new(),
            outcomes: Vec::new(),
        };
        host.confirmations =
            FakeSpool::new().with_file("1000.json", serde_json::to_vec(&data).unwrap());
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(PID, START)))
            .with_exit(Ok(false))
            .with_proc(5000, ProcFile::Stat, stat_line(5000, 77));
        let conn = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &conn, Ok(&spool));
        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.denial, Some(DenialCode::NoConfirmationChannel));
        assert!(minted.is_none());
        assert!(spool.files().is_empty());
    }

    #[test]
    fn a_reused_pid_is_not_the_live_watcher() {
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        let heartbeat = WatcherHeartbeat {
            pid: 5000,
            starttime: 77,
            tty: 34816,
            sid: 2,
            at_ms: NOW,
        };
        let data = ConfirmData {
            heartbeat: Some(heartbeat),
            backoff: Vec::new(),
            outcomes: Vec::new(),
        };
        host.confirmations =
            FakeSpool::new().with_file("1000.json", serde_json::to_vec(&data).unwrap());
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(PID, START)))
            .with_exit(Ok(false))
            .with_proc(5000, ProcFile::Stat, stat_line(5000, 78));
        let conn = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &conn, Ok(&spool));
        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.denial, Some(DenialCode::NoConfirmationChannel));
        assert!(minted.is_none());
        assert!(spool.files().is_empty());
    }

    #[test]
    fn a_duplicate_request_does_not_prompt_twice() {
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        let heartbeat = WatcherHeartbeat {
            pid: 5000,
            starttime: 77,
            tty: 34816,
            sid: 2,
            at_ms: NOW,
        };
        host.confirmations = FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: Some(heartbeat),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(PID, START)))
            .with_exit(Ok(false))
            .with_proc(5000, ProcFile::Stat, stat_line(5000, 77));
        let first = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let spool = FakeSpool::new();
        let first_outcome = serve_with(&mut host, &first, Ok(&spool));
        assert!(pending_id(&first_outcome.answer).is_some());
        let pending = spool.files().into_iter().next().unwrap();
        let spool = FakeSpool::new().with_file(pending.0, pending.1);
        let mut retry_host = Host::honest();
        turn_on_confirmation(&mut retry_host);
        let heartbeat = WatcherHeartbeat {
            pid: 5000,
            starttime: 77,
            tty: 34816,
            sid: 2,
            at_ms: NOW,
        };
        retry_host.confirmations = FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: Some(heartbeat),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        retry_host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(PID, START)))
            .with_exit(Ok(false))
            .with_proc(5000, ProcFile::Stat, stat_line(5000, 77));
        let second = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let second_outcome = serve_with(&mut retry_host, &second, Ok(&spool));
        let (decision, minted) = decision_of(&second_outcome.answer).unwrap();
        assert_eq!(decision.denial, Some(DenialCode::ConfirmationThrottled));
        assert!(minted.is_none());
        assert_eq!(spool.files().len(), 1);
    }

    #[test]
    fn a_rerun_consumes_one_approval_for_the_same_user_and_argv() {
        let request = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let mut first_host = Host::honest();
        turn_on_confirmation(&mut first_host);
        first_host.confirmations = live_confirmation_store();
        first_host.peers = peer_with_live_watcher();
        let first_spool = FakeSpool::new();
        let first = serve_with(&mut first_host, &request, Ok(&first_spool));
        let id = pending_id(&first.answer).unwrap();
        let mut entry = entry_in(&first_spool);
        let watcher = xudo_gate::request::WatcherPin {
            uid: UID,
            pid: 5000,
            starttime: 77,
            tty: 34816,
            sid: 2,
        };
        entry.state = xudo_gate::request::ConfirmationState::Approved;
        entry.confirmed = true;
        entry.confirmed_by = Some(watcher.clone());
        entry.shown_at_ms = Some(BoottimeMillis(NOW - 2_000));
        entry.shown_to = Some(watcher);
        let approved_spool =
            FakeSpool::new().with_file(id.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut retry_host = Host::honest();
        turn_on_confirmation(&mut retry_host);
        retry_host.confirmations = live_confirmation_store();
        retry_host.peers = peer_with_live_watcher();
        let retry_request = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let retry = serve_with(&mut retry_host, &retry_request, Ok(&approved_spool));
        let (decision, minted) = decision_of(&retry.answer).unwrap();
        assert!(decision.verdict.is_permitted());
        assert_eq!(
            minted.as_ref().map(|value| value.nonce.as_str()),
            Some(id.as_str())
        );
        assert_eq!(approved_spool.files().len(), 1);
        let reminted_bytes = approved_spool.files().get(id.as_bytes()).unwrap().clone();
        let reminted =
            PendingRequest::parse(std::str::from_utf8(&reminted_bytes).unwrap()).unwrap();
        assert_eq!(
            reminted.state,
            xudo_gate::request::ConfirmationState::Consumed
        );
        assert_eq!(
            reminted.deadline.0,
            NOW + REQUEST_TTL_MILLIS.min(crate::confirm::CONSUMED_TTL_MS)
        );
    }

    /// A host whose peer is a different process, in the given session and on
    /// the given terminal, still with the watcher live.
    fn rerun_host(pid: u32, starttime: u64, sid: i64, tty: i64) -> Host {
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        host.confirmations = live_confirmation_store();
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line_with_terminal(pid, starttime, sid, tty)))
            .with_exit(Ok(false))
            .with_proc(5000, ProcFile::Stat, stat_line(5000, 77));
        host.syscalls = host.syscalls.with_info(Ok(PidfdInfo::empty()
            .with_ids(ProcessIds {
                pid,
                tgid: pid,
                ppid: 1,
            })
            .with_creds(Creds {
                ruid: UID,
                rgid: GID,
                euid: UID,
                egid: GID,
                suid: UID,
                sgid: GID,
                fsuid: UID,
                fsgid: GID,
            })));
        host
    }

    /// A spool holding the approved entry for the requester of `PID`, as the
    /// watcher left it after the first run exited.
    fn approved_for_the_requester() -> (FakeSpool, String) {
        let request = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let mut first_host = Host::honest();
        turn_on_confirmation(&mut first_host);
        first_host.confirmations = live_confirmation_store();
        first_host.peers = peer_with_live_watcher();
        let first_spool = FakeSpool::new();
        let first = serve_with(&mut first_host, &request, Ok(&first_spool));
        let id = pending_id(&first.answer).unwrap();
        let mut entry = entry_in(&first_spool);
        let watcher = watcher_pin(&test_identity(5000, 77, 2, 34816));
        entry.state = xudo_gate::request::ConfirmationState::Approved;
        entry.confirmed = true;
        entry.confirmed_by = Some(watcher.clone());
        entry.shown_at_ms = Some(BoottimeMillis(NOW - 2_000));
        entry.shown_to = Some(watcher);
        let spool =
            FakeSpool::new().with_file(id.as_bytes().to_vec(), entry.to_json().into_bytes());
        (spool, id)
    }

    fn the_entry(spool: &FakeSpool, id: &str) -> PendingRequest {
        parse_entry(&spool.files()[id.as_bytes()]).unwrap()
    }

    #[test]
    fn a_same_identity_rerun_from_a_new_process_consumes_the_approval() {
        let (spool, id) = approved_for_the_requester();
        let mut host = rerun_host(PID + 7, START + 7, 0, 0);
        let rerun = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let outcome = serve_with(&mut host, &rerun, Ok(&spool));
        assert_eq!(outcome.served, Served::Minted);
        let (_, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(minted.map(|m| m.nonce.clone()), Some(id.clone()));
        let entry = the_entry(&spool, &id);
        assert_eq!(entry.state, xudo_gate::request::ConfirmationState::Consumed);
        assert_eq!(
            (entry.caller_pid, entry.caller_starttime),
            (PID + 7, START + 7)
        );
    }

    #[test]
    fn an_unattested_rerun_from_another_session_spends_the_approval_behind_the_password() {
        let (spool, id) = approved_for_the_requester();
        let rerun = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let mut host = rerun_host(PID + 1, START + 1, 9, 9);
        let outcome = serve_with(&mut host, &rerun, Ok(&spool));
        assert_eq!(outcome.served, Served::Minted);
        let (_, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(
            minted.map(|m| m.gate.as_str()),
            Some(xudo_backend::snippet::GATE_AUTH)
        );
        let entry = the_entry(&spool, &id);
        assert_eq!(entry.state, xudo_gate::request::ConfirmationState::Consumed);
        assert_eq!(
            (
                entry.caller_pid,
                entry.caller_starttime,
                entry.caller_sid,
                entry.caller_tty
            ),
            (PID + 1, START + 1, 9, 9)
        );
        assert_eq!(
            entry.attested_class,
            xudo_gate::request::AttestedClass::Unattested
        );
    }

    #[test]
    fn a_rerun_from_the_watchers_session_is_refused() {
        let (spool, id) = approved_for_the_requester();
        // An entry whose requester shares the watcher's session and terminal
        // is not one a watcher could have approved; it is still not consumable.
        let mut entry = the_entry(&spool, &id);
        entry.caller_sid = 2;
        entry.caller_tty = 34816;
        let spool =
            FakeSpool::new().with_file(id.as_bytes().to_vec(), entry.to_json().into_bytes());
        let before = spool.files()[id.as_bytes()].clone();
        let mut host = rerun_host(PID + 1, START + 1, 2, 34816);
        let rerun = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let outcome = serve_with(&mut host, &rerun, Ok(&spool));
        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        // The approval is searched first and found not to match this caller;
        // the watcher sitting in the caller's own session is no channel.
        assert_eq!(decision.denial, Some(DenialCode::NoConfirmationChannel));
        assert!(minted.is_none());
        assert_eq!(spool.files()[id.as_bytes()], before);
    }

    fn search_for<'a>(
        request: &'a BrokerRequest,
        identity: &'a PeerIdentity,
        caller: &'a CallerFacts,
        syscalls: &'a dyn Syscalls,
        action: &'a str,
    ) -> ApprovalSearch<'a> {
        ApprovalSearch {
            request,
            identity,
            caller,
            syscalls,
            action: Some(action),
            generation: policy().rules.generation.id(),
            now: NOW,
        }
    }

    #[test]
    fn a_consume_race_spends_the_approval_once() {
        let (spool, id) = approved_for_the_requester();
        let action = the_entry(&spool, &id).action;
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let syscalls = xudo_sys::FakeSyscalls::new();
        let first = test_identity(PID + 1, START + 1, 8, 0);
        let second = test_identity(PID + 2, START + 2, 9, 0);
        // Both read the entry as Approved before either has published.
        let mut taken = Vec::new();
        for identity in [&first, &second] {
            let caller = classify(identity);
            let approved = take_matching_approval(
                &spool,
                &search_for(&request, identity, &caller, &syscalls, &action),
            )
            .unwrap()
            .unwrap();
            taken.push((identity, approved));
        }
        let mut wins = 0;
        for (identity, approved) in &taken {
            let live = unattested_live(identity);
            if publish_consumed_approval(&spool, &live.binding(identity), &grant(approved), NOW)
                .is_ok()
            {
                wins += 1;
            }
        }
        assert_eq!(wins, 1);
        let entry = the_entry(&spool, &id);
        assert_eq!(entry.state, xudo_gate::request::ConfirmationState::Consumed);
        assert_eq!(entry.caller_pid, PID + 1);
    }

    fn agent_approval(scope_id: u64) -> (FakeSpool, PendingRequest) {
        let mut entry = shown_entry();
        entry.state = xudo_gate::request::ConfirmationState::Approved;
        entry.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        entry.confirmed_by = Some(pin.clone());
        entry.shown_to = Some(pin);
        entry.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id };
        entry.attested_scope_id = Some(scope_id);
        entry.boot_id = Some(BOOT_ID.to_owned());
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        (spool, entry)
    }

    const BOOT_ID: &str = "abcdef01-2345-6789-abcd-ef0123456789";

    fn enrolled_caller() -> CallerFacts {
        xudo_policy::CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "test-agent".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            UID,
        )
    }

    #[test]
    fn an_agent_rerun_from_a_new_process_in_the_same_scope_consumes() {
        let (spool, entry) = agent_approval(44);
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        // A new process, session and terminal; only the scope is the same.
        let mut identity = test_identity(PID + 9, START + 9, 7, 7);
        identity.cgroup_id = Some(44);
        let syscalls = xudo_sys::FakeSyscalls::new().with_boot_id(Ok(BOOT_ID.to_owned()));
        let caller = enrolled_caller();
        let consumed = take_matching_approval(
            &spool,
            &search_for(&request, &identity, &caller, &syscalls, &entry.action),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            consumed.state,
            xudo_gate::request::ConfirmationState::Consumed
        );
        assert_eq!(consumed.caller_pid, PID + 9);
        assert_eq!((consumed.caller_sid, consumed.caller_tty), (7, 7));
    }

    #[test]
    fn an_agent_in_another_scope_opens_its_own_request() {
        let (spool, entry) = agent_approval(44);
        let before = spool.files()[NONCE.as_bytes()].clone();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        let mut identity = test_identity(PID, START, 7, 7);
        identity.cgroup_id = Some(45);
        let syscalls = xudo_sys::FakeSyscalls::new().with_boot_id(Ok(BOOT_ID.to_owned()));
        let caller = enrolled_caller();
        // No refusal: the caller falls through to its own pending request.
        let taken = take_matching_approval(
            &spool,
            &search_for(&request, &identity, &caller, &syscalls, &entry.action),
        )
        .unwrap();
        assert!(taken.is_none());
        assert_eq!(spool.files()[NONCE.as_bytes()], before);
    }

    #[test]
    fn a_caller_of_another_class_opens_its_own_request_beside_the_approval() {
        let (spool, id) = approved_for_the_requester();
        let mut approved = the_entry(&spool, &id);
        approved.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        approved.attested_scope_id = Some(44);
        approved.boot_id = Some(BOOT_ID.to_owned());
        let spool =
            FakeSpool::new().with_file(id.as_bytes().to_vec(), approved.to_json().into_bytes());
        let before = spool.files()[id.as_bytes()].clone();
        let mut host = rerun_host(PID + 1, START + 1, 9, 9);
        host.entropy = FakeEntropy::new().with(Ok(vec![0xcd; 32]));
        let rerun = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let outcome = serve_with(&mut host, &rerun, Ok(&spool));
        assert_eq!(refusal_of(&outcome.answer), None);
        assert_eq!(pending_id(&outcome.answer), Some("cd".repeat(32)));
        assert_eq!(spool.files()[id.as_bytes()], before);
        assert_eq!(spool.files().len(), 2);
    }

    #[test]
    fn an_approval_for_a_human_cannot_be_consumed_by_an_attested_agent_at_the_broker() {
        let (_, mut entry) = agent_approval(44);
        entry.attested_class = xudo_gate::request::AttestedClass::Human;
        entry.attested_scope_id = None;
        entry.boot_id = None;
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let before = spool.files()[NONCE.as_bytes()].clone();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        let mut identity = test_identity(PID, START, 0, 0);
        identity.cgroup_id = Some(44);
        let syscalls = xudo_sys::FakeSyscalls::new().with_boot_id(Ok(BOOT_ID.to_owned()));
        let caller = enrolled_caller();
        let taken = take_matching_approval(
            &spool,
            &search_for(&request, &identity, &caller, &syscalls, &entry.action),
        )
        .unwrap();
        assert!(taken.is_none());
        assert_eq!(spool.files()[NONCE.as_bytes()], before);
    }

    #[test]
    fn an_approval_for_an_agent_cannot_be_consumed_by_an_unattested_caller_at_the_broker() {
        let (spool, entry) = agent_approval(44);
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID, START, 7, 7);
        let caller = classify(&identity);
        let syscalls = xudo_sys::FakeSyscalls::new();
        let taken = take_matching_approval(
            &spool,
            &search_for(&request, &identity, &caller, &syscalls, &entry.action),
        )
        .unwrap();
        assert!(taken.is_none());
    }

    #[test]
    fn another_callers_entry_does_not_hide_the_callers_own_approval() {
        let (spool, entry) = agent_approval(44);
        let mut other = entry.clone();
        other.nonce = "cd".repeat(32);
        other.attested_scope_id = Some(45);
        other.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 45 };
        let both = FakeSpool::new()
            .with_file(
                other.nonce.as_bytes().to_vec(),
                other.to_json().into_bytes(),
            )
            .with_file(
                NONCE.as_bytes().to_vec(),
                spool.files()[NONCE.as_bytes()].clone(),
            );
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        let mut identity = test_identity(PID + 1, START + 1, 7, 7);
        identity.cgroup_id = Some(44);
        let syscalls = xudo_sys::FakeSyscalls::new().with_boot_id(Ok(BOOT_ID.to_owned()));
        let caller = enrolled_caller();
        let consumed = take_matching_approval(
            &both,
            &search_for(&request, &identity, &caller, &syscalls, &entry.action),
        )
        .unwrap()
        .unwrap();
        assert_eq!(consumed.nonce, NONCE);
    }

    #[test]
    fn approval_store_clear_failure_refuses_after_the_consume_is_swapped() {
        let request = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let parsed = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent-yolo",
        );
        let fingerprint = request_fingerprint(&parsed, UID).unwrap();
        let mut entry = shown_entry();
        entry.state = xudo_gate::request::ConfirmationState::Approved;
        entry.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        entry.confirmed_by = Some(pin.clone());
        entry.shown_to = Some(pin);
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let state = ConfirmData {
            heartbeat: Some(WatcherHeartbeat {
                pid: 5000,
                starttime: 77,
                tty: 34816,
                sid: 2,
                at_ms: NOW,
            }),
            backoff: vec![BackoffEntry {
                fingerprint,
                strikes: 1,
                until_ms: NOW + 1_000,
            }],
            outcomes: Vec::new(),
        };
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        host.peers = peer_with_live_watcher();
        host.confirmations = FakeSpool::new()
            .with_file("1000.json", serde_json::to_vec(&state).unwrap())
            .failing_replace(SpoolError::Gone {
                name: "confirm".to_owned(),
            });
        let outcome = serve_with(&mut host, &request, Ok(&spool));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );
        assert_eq!(spool.files().len(), 1);
    }

    #[test]
    fn approved_remint_refusals_are_reported_to_the_client() {
        let make_entry = || {
            let mut entry = shown_entry();
            entry.state = xudo_gate::request::ConfirmationState::Approved;
            entry.confirmed = true;
            let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
            entry.confirmed_by = Some(pin.clone());
            entry.shown_to = Some(pin);
            entry
        };
        let make_evaluated = |host: &Host, request: BrokerRequest| {
            let conn = connection(Ok(Vec::new()));
            let identity = identify(conn.socket(), &host.syscalls, &host.peers).unwrap();
            let policy = confirming_policy();
            let caller = classify(&identity);
            let decision = decide(&policy, &caller, &request);
            Evaluated {
                decision,
                caller,
                identity,
                request,
                policy,
            }
        };
        let entry = make_entry();

        let mut host = Host::honest();
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: NONCE.to_owned(),
            },
        };
        let evaluated = make_evaluated(&host, request);
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &FakeSpool::new(),
            evaluated,
            entry.clone(),
        );
        assert_eq!(served, Served::Refused(Fault::Client));

        let mut host = Host::honest();
        host.entropy = FakeEntropy::new().with(Err(SysError::unsupported("getrandom")));
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let evaluated = make_evaluated(&host, request);
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &FakeSpool::new(),
            evaluated,
            entry.clone(),
        );
        assert_eq!(served, Served::Refused(Fault::Broker));

        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("audit down");
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let evaluated = make_evaluated(&host, request);
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut consumed = entry.clone();
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &spool,
            evaluated,
            consumed,
        );
        assert_eq!(served, Served::Refused(Fault::Broker));
        // Audit comes first, so its failure swaps nothing: the bytes on disk
        // are the approved ones, which a swap-before-audit would have replaced.
        assert_eq!(
            spool.files()[NONCE.as_bytes()],
            entry.to_json().into_bytes()
        );

        let mut host = Host::honest();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let evaluated = make_evaluated(&host, request);
        let spool = FakeSpool::new().failing_publish(SpoolError::Gone {
            name: "publish".to_owned(),
        });
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &spool,
            evaluated,
            entry,
        );
        assert_eq!(served, Served::Refused(Fault::Broker));
    }

    #[test]
    fn approved_remint_refuses_if_the_fresh_decision_changed() {
        let mut host = Host::honest();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID, START, 0, 0);
        let policy = confirming_policy();
        let caller = classify(&identity);
        let mut evaluated = Evaluated {
            decision: decide(&policy, &caller, &request),
            caller,
            identity,
            request,
            policy,
        };
        evaluated.decision.verdict = Verdict::Deny;
        let mut entry = shown_entry();
        entry.state = xudo_gate::request::ConfirmationState::Approved;
        entry.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        entry.confirmed_by = Some(pin.clone());
        entry.shown_to = Some(pin);
        assert_eq!(
            mint_approved(
                &connection(Ok(Vec::new())),
                &mut host.platform(),
                &FakeSpool::new(),
                evaluated,
                entry
            ),
            Served::Refused(Fault::Broker)
        );
    }

    #[test]
    fn status_from_another_process_is_refused() {
        let entry = shown_entry();
        let spool = FakeSpool::new().with_file(
            entry.nonce.as_bytes().to_vec(),
            entry.to_json().into_bytes(),
        );
        let mut host = Host::honest();
        let other = test_identity(PID + 1, START + 1, 0, 0);
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: NONCE.to_owned(),
            },
        };
        let err = status(
            &connection(Ok(request.to_json().into_bytes())),
            &mut host.platform(),
            &spool,
            &other,
            &request,
            NONCE,
        )
        .unwrap_err();
        assert_eq!(err.code, RefusalCode::ChannelUntrusted);
    }

    #[test]
    fn status_returns_pending_to_its_requesting_pin() {
        let entry = shown_entry();
        let spool = FakeSpool::new().with_file(
            entry.nonce.as_bytes().to_vec(),
            entry.to_json().into_bytes(),
        );
        let mut host = Host::honest();
        let identity = test_identity(PID, START, 0, 0);
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: NONCE.to_owned(),
            },
        };
        let response = status(
            &connection(Ok(request.to_json().into_bytes())),
            &mut host.platform(),
            &spool,
            &identity,
            &request,
            NONCE,
        )
        .unwrap();
        assert!(matches!(response.answer, Answer::Pending { id, .. } if id == NONCE));
    }

    #[test]
    fn confirmation_question_dispatch_covers_supported_and_deferred_questions() {
        let caller = test_identity(PID, START, 0, 0);
        let entry = shown_entry();
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut host = Host::honest();
        host.confirmations = live_confirmation_store();
        let status_request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: NONCE.to_owned(),
            },
        };
        let conn = connection(Ok(status_request.to_json().into_bytes()));
        assert_eq!(
            serve_confirmation_question(
                &conn,
                &mut host.platform(),
                &spool,
                &caller,
                &status_request
            ),
            Served::Decided
        );

        let watcher = test_identity(5000, 77, 2, 34816);
        let watch_request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Watch,
        };
        let conn = connection(Ok(watch_request.to_json().into_bytes()));
        assert_eq!(
            serve_confirmation_question(
                &conn,
                &mut host.platform(),
                &spool,
                &watcher,
                &watch_request
            ),
            Served::Decided
        );

        let answer_request = answer_request(NONCE, "remove", true);
        let conn = connection(Ok(answer_request.to_json().into_bytes()));
        assert_eq!(
            serve_confirmation_question(
                &conn,
                &mut host.platform(),
                &spool,
                &watcher,
                &answer_request
            ),
            Served::Decided
        );

        let run = BrokerRequest::new("/usr/bin/true", Vec::<String>::new(), "unattested");
        let conn = connection(Ok(run.to_json().into_bytes()));
        assert_eq!(
            serve_confirmation_question(&conn, &mut host.platform(), &spool, &caller, &run),
            Served::Refused(Fault::Broker)
        );

        let unknown = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: "cd".repeat(32),
            },
        };
        let conn = connection(Ok(unknown.to_json().into_bytes()));
        assert_eq!(
            serve_confirmation_question(&conn, &mut host.platform(), &spool, &caller, &unknown),
            Served::Refused(Fault::Client)
        );
    }

    #[test]
    fn pending_question_dispatch_lists_entries() {
        let caller = test_identity(PID, START, 0, 0);
        let entry = shown_entry();
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut host = Host::honest();
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Pending,
        };
        let conn = connection(Ok(request.to_json().into_bytes()));
        assert_eq!(
            serve_confirmation_question(&conn, &mut host.platform(), &spool, &caller, &request),
            Served::Decided
        );
        assert!(matches!(
            BrokerResponse::parse(&conn.written()).unwrap().answer,
            Answer::Watching { prompts, .. } if prompts.len() == 1
        ));
    }

    #[test]
    fn serve_expires_before_status_answer_and_watch_dispatch() {
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let status = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: NONCE.to_owned(),
            },
        };
        let spool = FakeSpool::new();
        let outcome = serve_with(
            &mut host,
            &connection(Ok(status.to_json().into_bytes())),
            Ok(&spool),
        );
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::RequestUnknown)
        );

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_lock(SpoolError::Gone {
            name: "confirm".to_owned(),
        });
        let run = asking("/usr/bin/systemctl", &["restart", "nginx.service"]);
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &run, Ok(&spool));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );

        let mut host = Host::honest();
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line_with_terminal(PID, START, 2, 34816)))
            .with_proc(
                PID,
                ProcFile::Status,
                format!("NSpid:\t{PID}\n").into_bytes(),
            )
            .with_proc(PID, ProcFile::UidMap, b"0 0 4294967295\n".to_vec())
            .with_exit(Ok(false));
        host.confirmations = FakeSpool::new();
        let watch = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Watch,
        };
        let outcome = serve_with(
            &mut host,
            &connection(Ok(watch.to_json().into_bytes())),
            Ok(&spool),
        );
        assert!(watching_prompts(&outcome.answer).is_some());

        let mut host = Host::honest();
        let thaw = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Thaw,
        };
        let outcome = serve_with(
            &mut host,
            &connection(Ok(thaw.to_json().into_bytes())),
            Ok(&spool),
        );
        assert_eq!(outcome.answer, Answer::Done);
    }

    fn thaw_request() -> BrokerRequest {
        BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Thaw,
        }
    }

    /// What a freeze from an attested agent would be classified as. The broker
    /// classifies everyone `Unattested` until M4, so the agent paths are
    /// reached only by handing the handler these facts.
    fn an_attested_agent() -> CallerFacts {
        CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "scope-44".to_owned(),
                session_id: "stored".to_owned(),
                declared_yolo: false,
            },
            UID,
        )
    }

    const MARKER: &[u8] = b"{}";

    #[test]
    fn a_users_thaw_lifts_only_their_own_marker() {
        let mut host = Host::honest();
        for name in ["frozen", "frozen-1000", "frozen-2000", "audit.jsonl"] {
            host.freeze_file.publish(name, MARKER).unwrap();
        }
        let outcome = serve_with(
            &mut host,
            &connection(Ok(thaw_request().to_json().into_bytes())),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(outcome.answer, Answer::Done);
        let left: Vec<_> = host.freeze_file.files().into_keys().collect();
        assert_eq!(
            left,
            [
                b"audit.jsonl".to_vec(),
                b"frozen".to_vec(),
                b"frozen-2000".to_vec()
            ]
        );
        assert_eq!(host.audit.records().len(), 1);
    }

    #[test]
    fn root_thaw_lifts_every_marker_and_nothing_else() {
        let mut host = Host::honest_as(0);
        for name in [
            "frozen",
            "frozen-1000",
            "frozen-2000",
            "frozen-x",
            "audit.jsonl",
        ] {
            host.freeze_file.publish(name, MARKER).unwrap();
        }
        let outcome = serve_with(
            &mut host,
            &connection(Ok(thaw_request().to_json().into_bytes())),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(outcome.answer, Answer::Done);
        let left: Vec<_> = host.freeze_file.files().into_keys().collect();
        assert_eq!(left, [b"audit.jsonl".to_vec(), b"frozen-x".to_vec()]);
    }

    #[test]
    fn root_thaw_refuses_storage_it_cannot_list_or_clear() {
        let broken = SpoolError::InvalidName {
            name: "state".to_owned(),
        };
        let identity = test_identity(PID, START, 0, 0);
        let mut root = identity.clone();
        root.uid = 0;
        for state in [
            FakeSpool::new().failing_lock(broken.clone()),
            FakeSpool::new().failing_names(broken.clone()),
        ] {
            let mut host = Host::honest_as(0);
            host.freeze_file = state;
            assert!(
                thaw(
                    &mut host.platform(),
                    &root,
                    &classify(&root),
                    &thaw_request()
                )
                .is_err()
            );
        }
        let mut host = Host::honest_as(0);
        host.freeze_file = FakeSpool::new()
            .with_file("frozen-1000", MARKER)
            .failing_remove(broken);
        assert!(
            thaw(
                &mut host.platform(),
                &root,
                &classify(&root),
                &thaw_request()
            )
            .is_err()
        );
    }

    #[test]
    fn a_users_freeze_and_thaw_refuse_storage_that_fails() {
        let broken = SpoolError::InvalidName {
            name: "state".to_owned(),
        };
        let identity = test_identity(PID, START, 0, 0);
        let mut host = Host::honest();
        host.freeze_file = FakeSpool::new().failing_names(broken.clone());
        let error = freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &identity,
            &freeze_request(),
            "maintenance",
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::SpoolUnusable);

        let mut host = Host::honest();
        host.freeze_file = FakeSpool::new()
            .with_file("frozen-1000", MARKER)
            .failing_remove(broken);
        let error = thaw(
            &mut host.platform(),
            &identity,
            &classify(&identity),
            &thaw_request(),
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::SpoolUnusable);
        assert!(
            host.freeze_file
                .files()
                .contains_key(b"frozen-1000".as_slice())
        );
    }

    #[test]
    fn an_attested_agent_cannot_thaw() {
        for uid in [UID, 0] {
            let mut identity = test_identity(PID, START, 0, 0);
            identity.uid = uid;
            let mut host = Host::honest_as(uid);
            for name in ["frozen", "frozen-1000"] {
                host.freeze_file.publish(name, MARKER).unwrap();
            }
            let refused = thaw(
                &mut host.platform(),
                &identity,
                &an_attested_agent(),
                &thaw_request(),
            )
            .unwrap_err();
            assert_eq!(refused.code, RefusalCode::ChannelUntrusted);
            assert_eq!(host.freeze_file.files().len(), 2);
            assert!(host.audit.records().is_empty());
        }
    }

    #[test]
    fn an_attested_agent_cannot_freeze() {
        for uid in [UID, 0] {
            let mut identity = test_identity(PID, START, 0, 0);
            identity.uid = uid;
            let entry = enrolled_entry(NONCE, UID);
            let spool = FakeSpool::new().with_file(NONCE, entry.to_json());
            let mut host = Host::honest_as(uid);
            let refused = freeze_with(
                &mut host.platform(),
                &spool,
                &identity,
                &an_attested_agent(),
                &freeze_request(),
                "maintenance",
                &serde_json::to_vec,
            )
            .unwrap_err();
            assert_eq!(refused.code, RefusalCode::ChannelUntrusted);
            // Nothing was published, audited, or taken back.
            assert!(host.freeze_file.files().is_empty());
            assert!(host.audit.records().is_empty());
            assert_eq!(
                spool.files()[NONCE.as_bytes()],
                entry.to_json().into_bytes()
            );
        }
    }

    #[test]
    fn a_users_freeze_does_not_touch_another_users_agents() {
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let mut kept = Vec::new();
        for (nonce, uid) in [
            ("a".repeat(64), UID),
            ("b".repeat(64), 2000),
            ("c".repeat(64), 0),
        ] {
            let entry = enrolled_entry(&nonce, uid);
            spool.publish(&nonce, entry.to_json().as_bytes()).unwrap();
            if uid != UID {
                kept.push((nonce, entry.to_json().into_bytes()));
            }
        }
        let outcome = serve_with(
            &mut host,
            &connection(Ok(freeze_request().to_json().into_bytes())),
            Ok(&spool),
        );
        assert_eq!(outcome.answer, Answer::Done);
        let files = spool.files();
        assert!(!files.contains_key("a".repeat(64).as_bytes()));
        for (nonce, bytes) in kept {
            assert_eq!(files[nonce.as_bytes()], bytes);
        }
        // Only the freezer's own marker exists, so it cannot stand for anyone
        // else: the global one is root's.
        let markers: Vec<_> = host.freeze_file.files().into_keys().collect();
        assert_eq!(markers, [b"frozen-1000".to_vec()]);
        let platform = host.platform();
        assert!(user_freeze_stands(&platform, UID));
        assert!(!user_freeze_stands(&platform, 2000));
    }

    #[test]
    fn root_freeze_covers_every_users_agents() {
        let mut host = Host::honest_as(0);
        let spool = FakeSpool::new();
        for (nonce, uid) in [
            ("a".repeat(64), UID),
            ("b".repeat(64), 2000),
            ("c".repeat(64), 0),
        ] {
            let entry = enrolled_entry(&nonce, uid);
            spool.publish(&nonce, entry.to_json().as_bytes()).unwrap();
        }
        let outcome = serve_with(
            &mut host,
            &connection(Ok(freeze_request().to_json().into_bytes())),
            Ok(&spool),
        );
        assert_eq!(outcome.answer, Answer::Done);
        assert!(spool.files().is_empty());
        let markers: Vec<_> = host.freeze_file.files().into_keys().collect();
        assert_eq!(markers, [b"frozen".to_vec()]);
    }

    #[test]
    fn a_marker_for_one_user_is_not_a_marker_for_another_and_root_asks_nothing() {
        let mut host = Host::honest();
        host.freeze_file.publish("frozen-1000", MARKER).unwrap();
        host.freeze_file.publish("frozen-10", MARKER).unwrap();
        let platform = host.platform();
        assert!(user_freeze_stands(&platform, 1000));
        assert!(user_freeze_stands(&platform, 10));
        assert!(!user_freeze_stands(&platform, 100));
        assert!(!user_freeze_stands(&platform, 0));

        // Storage that is missing or cannot be listed withholds, never grants.
        let mut host = Host::honest();
        host.freeze_available = false;
        assert!(user_freeze_stands(&host.platform(), UID));
        let mut host = Host::honest();
        host.freeze_file = FakeSpool::new().failing_names(SpoolError::InvalidName {
            name: "state".to_owned(),
        });
        assert!(user_freeze_stands(&host.platform(), UID));
    }

    #[test]
    fn an_overflowing_state_listing_counts_as_frozen_and_blocks_a_thaw_all() {
        let junk = || {
            (0..=MAX_STATE_NAMES).fold(FakeSpool::new(), |state, index| {
                state.with_file(format!("junk-{index:04}"), MARKER)
            })
        };
        let mut host = Host::honest();
        host.freeze_file = junk();
        assert!(user_freeze_stands(&host.platform(), 2000));

        let mut root = test_identity(PID, START, 0, 0);
        root.uid = 0;
        let mut host = Host::honest_as(0);
        host.freeze_file = junk();
        let refused = thaw(
            &mut host.platform(),
            &root,
            &classify(&root),
            &thaw_request(),
        )
        .unwrap_err();
        assert_eq!(refused.code, RefusalCode::SpoolFull);
    }

    #[test]
    fn a_full_state_directory_cannot_refuse_roots_freeze() {
        let mut host = Host::honest_as(0);
        host.freeze_file = (0..MAX_STATE_NAMES - 1).fold(FakeSpool::new(), |state, index| {
            state.with_file(format!("frozen-{}", 5000 + index), MARKER)
        });
        let mut root = test_identity(PID, START, 0, 0);
        root.uid = 0;
        freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &root,
            &freeze_request(),
            "maintenance",
        )
        .unwrap();
        assert!(host.freeze_file.files().contains_key(b"frozen".as_slice()));
    }

    #[test]
    fn a_group_member_cannot_fill_the_state_directory_with_markers() {
        let full = || {
            (0..MAX_STATE_NAMES).fold(FakeSpool::new(), |state, index| {
                state.with_file(format!("frozen-{}", 5000 + index), MARKER)
            })
        };
        let mut host = Host::honest();
        host.freeze_file = full();
        let refused = freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &test_identity(PID, START, 0, 0),
            &freeze_request(),
            "maintenance",
        )
        .unwrap_err();
        assert_eq!(refused.code, RefusalCode::SpoolFull);
        assert!(
            !host
                .freeze_file
                .files()
                .contains_key(b"frozen-1000".as_slice())
        );

        // A marker already there is not a new name, so it still publishes.
        let mut host = Host::honest();
        host.freeze_file = (1..MAX_STATE_NAMES)
            .fold(FakeSpool::new(), |state, index| {
                state.with_file(format!("frozen-{}", 5000 + index), MARKER)
            })
            .with_file("frozen-1000", MARKER);
        assert_eq!(host.freeze_file.files().len(), MAX_STATE_NAMES);
        freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &test_identity(PID, START, 0, 0),
            &freeze_request(),
            "maintenance",
        )
        .unwrap();
    }

    const MAX_NAMES_U32: u32 = 128;
    const _: () = assert!(MAX_STATE_NAMES == MAX_NAMES_U32 as usize);

    fn diverged_as(uid: u32) -> PeerIdentity {
        let mut identity = test_identity(PID, START, 0, 0);
        identity.uid = uid;
        identity.diverged = true;
        identity
    }

    #[test]
    fn a_diverged_peer_cannot_freeze() {
        for uid in [UID, 0] {
            let identity = diverged_as(uid);
            let mut host = Host::honest_as(uid);
            let refused = freeze(
                &mut host.platform(),
                &FakeSpool::new(),
                &identity,
                &freeze_request(),
                "maintenance",
            )
            .unwrap_err();
            assert_eq!(refused.code, RefusalCode::ChannelUntrusted);
            assert!(host.freeze_file.files().is_empty());
            assert!(host.audit.records().is_empty());
        }
    }

    #[test]
    fn a_diverged_peer_cannot_thaw() {
        for uid in [UID, 0] {
            let identity = diverged_as(uid);
            let mut host = Host::honest_as(uid);
            for name in ["frozen", "frozen-1000"] {
                host.freeze_file.publish(name, MARKER).unwrap();
            }
            let refused = thaw(
                &mut host.platform(),
                &identity,
                &classify(&identity),
                &thaw_request(),
            )
            .unwrap_err();
            assert_eq!(refused.code, RefusalCode::ChannelUntrusted);
            assert_eq!(host.freeze_file.files().len(), 2);
            assert!(host.audit.records().is_empty());
        }
    }

    #[test]
    fn many_diverged_uids_cannot_fill_the_marker_slots() {
        let mut host = Host::honest();
        for uid in 1..=2 * MAX_NAMES_U32 {
            let identity = diverged_as(uid);
            let refused = freeze(
                &mut host.platform(),
                &FakeSpool::new(),
                &identity,
                &freeze_request(),
                "maintenance",
            )
            .unwrap_err();
            assert_eq!(refused.code, RefusalCode::ChannelUntrusted);
        }
        assert!(host.freeze_file.files().is_empty());
        // An honest user is not locked out.
        freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &test_identity(PID, START, 0, 0),
            &freeze_request(),
            "maintenance",
        )
        .unwrap();
    }

    fn markers_to(count: usize) -> FakeSpool {
        (0..count).fold(FakeSpool::new(), |state, index| {
            state.with_file(format!("frozen-{}", 5000 + index), MARKER)
        })
    }

    #[test]
    fn the_user_marker_limit_is_one_short_of_the_directory_bound() {
        let freeze_as_user = |present: usize| {
            let mut host = Host::honest();
            host.freeze_file = markers_to(present);
            let result = freeze(
                &mut host.platform(),
                &FakeSpool::new(),
                &test_identity(PID, START, 0, 0),
                &freeze_request(),
                "maintenance",
            );
            (result, host.freeze_file.files().len())
        };
        let (allowed, total) = freeze_as_user(MAX_STATE_NAMES - 2);
        assert!(allowed.is_ok());
        assert_eq!(total, MAX_STATE_NAMES - 1);
        let (refused, total) = freeze_as_user(MAX_STATE_NAMES - 1);
        assert_eq!(refused.unwrap_err().code, RefusalCode::SpoolFull);
        assert_eq!(total, MAX_STATE_NAMES - 1);
    }

    #[test]
    fn roots_reserved_slot_survives_users_filling_the_directory() {
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let mut refused_at = None;
        for uid in 1000..1000 + 2 * MAX_NAMES_U32 {
            let mut identity = test_identity(PID, START, 0, 0);
            identity.uid = uid;
            if freeze(
                &mut host.platform(),
                &spool,
                &identity,
                &freeze_request(),
                "maintenance",
            )
            .is_err()
            {
                refused_at = Some(uid);
                break;
            }
        }
        assert_eq!(refused_at, Some(1000 + MAX_NAMES_U32 - 1));
        assert_eq!(host.freeze_file.files().len(), MAX_STATE_NAMES - 1);

        let mut root = test_identity(PID, START, 0, 0);
        root.uid = 0;
        freeze(
            &mut host.platform(),
            &spool,
            &root,
            &freeze_request(),
            "maintenance",
        )
        .unwrap();
        assert!(host.freeze_file.files().contains_key(b"frozen".as_slice()));
        assert_eq!(host.freeze_file.files().len(), MAX_STATE_NAMES);

        thaw(
            &mut host.platform(),
            &root,
            &classify(&root),
            &thaw_request(),
        )
        .unwrap();
        assert!(host.freeze_file.files().is_empty());
    }

    #[test]
    fn a_users_freeze_denies_the_approval_of_their_own_agent_entry() {
        let approve = |marker: Option<&str>| {
            let entry = approved_entry(
                xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 },
                "unattested",
            );
            let mut pending = entry.clone();
            pending.state = xudo_gate::request::ConfirmationState::Pending;
            pending.confirmed = false;
            pending.confirmed_by = None;
            let bytes = pending.to_json().into_bytes();
            let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone());
            let mut host = Host::honest();
            if let Some(marker) = marker {
                host.freeze_file.publish(marker, MARKER).unwrap();
            }
            let result = complete_answer(
                &mut host.platform(),
                &spool,
                &arbitrary_watcher(5000, UID, 2, 34816, None),
                &answer_request(NONCE, "remove", true),
                AnsweredEntry {
                    id: NONCE.to_owned(),
                    bytes,
                    entry,
                },
                true,
            );
            (result.err().map(|e| e.code), host.audit.records().len())
        };
        assert_eq!(approve(None), (None, 1));
        // Another user's marker is not the entry owner's.
        assert_eq!(approve(Some("frozen-2000")), (None, 1));
        // The entry's owner froze: nothing is granted and nothing is audited.
        assert_eq!(
            approve(Some("frozen-1000")),
            (Some(RefusalCode::PolicyUnloadable), 0)
        );
    }

    #[test]
    fn freeze_audit_refusal_changes_nothing() {
        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("test refusal");
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        };
        let outcome = serve_with(
            &mut host,
            &connection(Ok(request.to_json().into_bytes())),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::BrokerUnusable)
        );
        assert!(host.freeze_file.files().is_empty());
    }

    #[test]
    fn freeze_publishes_a_bounded_marker_after_audit() {
        let mut host = Host::honest();
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        };
        let outcome = serve_with(
            &mut host,
            &connection(Ok(request.to_json().into_bytes())),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(outcome.answer, Answer::Done);
        let marker = host
            .freeze_file
            .files()
            .get(b"frozen-1000".as_slice())
            .cloned()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&marker).unwrap();
        assert_eq!(value["reason"], "maintenance");
        assert_eq!(value["uid"], UID);
    }

    #[test]
    fn freeze_refuses_missing_storage_and_publish_failures() {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        };
        let identity = test_identity(PID, START, 0, 0);
        let spool = FakeSpool::new();
        let mut host = Host::honest();
        host.freeze_available = false;
        let error = freeze(
            &mut host.platform(),
            &spool,
            &identity,
            &request,
            "maintenance",
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::SpoolUnusable);

        let mut host = Host::honest();
        host.freeze_file = FakeSpool::new().failing_publish(SpoolError::InvalidName {
            name: "frozen".to_owned(),
        });
        let error = freeze(
            &mut host.platform(),
            &spool,
            &identity,
            &request,
            "maintenance",
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::SpoolUnusable);
    }

    #[test]
    fn freeze_file_encoding_failure_is_reported() {
        let record = FreezeRecord {
            reason: "x".to_owned(),
            uid: UID,
            time: NOW,
        };
        let error = encoded_freeze_record(&record, &|_| {
            Err(serde_json::from_str::<()>("invalid").unwrap_err())
        })
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::BrokerUnusable);

        let mut host = Host::honest();
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "x".to_owned(),
            },
        };
        let identity = test_identity(PID, START, 0, 0);
        let error = freeze_with(
            &mut host.platform(),
            &FakeSpool::new(),
            &identity,
            &classify(&identity),
            &request,
            "x",
            &|_| Err(serde_json::from_str::<()>("invalid").unwrap_err()),
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::BrokerUnusable);
    }

    #[test]
    fn freeze_refuses_when_pending_state_cannot_be_locked_or_listed() {
        let broken = SpoolError::InvalidName {
            name: "state".to_owned(),
        };
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        };
        let identity = test_identity(PID, START, 0, 0);
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_lock(broken.clone());
        let spool = FakeSpool::new();
        let error = freeze(
            &mut host.platform(),
            &spool,
            &identity,
            &request,
            "maintenance",
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::SpoolUnusable);
        for request_spool in [
            FakeSpool::new().failing_lock(broken.clone()),
            FakeSpool::new().failing_names(broken.clone()),
        ] {
            let mut host = Host::honest();
            let error = deny_pending(&mut host.platform(), &request_spool, &identity, &request)
                .unwrap_err();
            assert_eq!(error.code, RefusalCode::SpoolUnusable);
        }
    }

    #[test]
    fn freeze_refuses_without_confirmation_storage() {
        let mut host = Host::honest();
        host.confirmations_available = false;
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        };
        let identity = test_identity(PID, START, 0, 0);
        let error = freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &identity,
            &request,
            "maintenance",
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::SpoolUnusable);
        assert!(!host.freeze_file.files().is_empty());
    }

    #[test]
    fn freeze_skips_unreadable_malformed_and_non_pending_entries() {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        };
        let identity = test_identity(PID, START, 0, 0);
        let mut non_watch = shown_entry();
        non_watch.needs_watch = false;
        let mut denied = shown_entry();
        denied.state = xudo_gate::request::ConfirmationState::Denied;
        let spool = FakeSpool::new()
            .with_file("broken-json", b"bad".to_vec())
            .with_file("unreadable", b"bad".to_vec())
            .with_file("not-watch", non_watch.to_json())
            .with_file("already-denied", denied.to_json())
            .failing_read(b"unreadable".to_vec());
        let mut host = Host::honest();
        deny_pending(&mut host.platform(), &spool, &identity, &request).unwrap();
        assert_eq!(spool.files().len(), 4);
    }

    #[test]
    fn freeze_pending_denials_fail_closed_at_policy_audit_removal_and_outcome() {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        };
        let identity = test_identity(PID, START, 0, 0);
        let broken = SpoolError::InvalidName {
            name: "state".to_owned(),
        };
        let pending = || {
            let entry = enrolled_entry(NONCE, UID);
            FakeSpool::new().with_file(entry.nonce.clone(), entry.to_json())
        };

        let mut host = Host::honest();
        host.policy.answer = Err(PolicyError::Config(xudo_gate::SettingsError::NotUtf8 {
            file: "config".to_owned(),
        }));
        assert!(deny_pending(&mut host.platform(), &pending(), &identity, &request).is_err());

        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("refused");
        assert!(deny_pending(&mut host.platform(), &pending(), &identity, &request).is_err());

        let mut host = Host::honest();
        let spool = pending().failing_remove(broken.clone());
        assert!(deny_pending(&mut host.platform(), &spool, &identity, &request).is_err());

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_publish(broken);
        assert!(deny_pending(&mut host.platform(), &pending(), &identity, &request).is_err());
    }

    #[test]
    fn root_thaw_audits_then_removes_the_marker() {
        let mut identity = test_identity(PID, START, 0, 0);
        identity.uid = 0;
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Thaw,
        };
        let mut host = Host::honest();
        host.freeze_file.publish("frozen", b"marker").unwrap();
        assert_eq!(
            thaw(
                &mut host.platform(),
                &identity,
                &classify(&identity),
                &request
            )
            .unwrap()
            .answer,
            Answer::Done
        );
        assert!(host.freeze_file.files().is_empty());

        let mut host = Host::honest();
        host.freeze_available = false;
        assert!(
            thaw(
                &mut host.platform(),
                &identity,
                &classify(&identity),
                &request
            )
            .is_err()
        );

        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("refused");
        host.freeze_file.publish("frozen", b"marker").unwrap();
        assert!(
            thaw(
                &mut host.platform(),
                &identity,
                &classify(&identity),
                &request
            )
            .is_err()
        );
        assert!(!host.freeze_file.files().is_empty());
    }

    #[test]
    fn freeze_denies_pending_agent_entries() {
        let mut host = Host::honest_as(0);
        let spool = FakeSpool::new();
        let mut approved = enrolled_entry(&"b".repeat(64), 2000);
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        for entry in [
            enrolled_entry(NONCE, UID),
            enrolled_entry(&"a".repeat(64), 2000),
            enrolled_entry(&"c".repeat(64), 3000),
            approved,
        ] {
            spool
                .publish(&entry.nonce, entry.to_json().as_bytes())
                .unwrap();
        }
        let outcome = serve_with(
            &mut host,
            &connection(Ok(freeze_request().to_json().into_bytes())),
            Ok(&spool),
        );
        assert_eq!(outcome.answer, Answer::Done);
        assert!(spool.files().is_empty());
        let confirmation = host.confirmations.files();
        for uid in [UID, 2000, 3000] {
            let state: ConfirmData =
                serde_json::from_slice(&confirmation[format!("{uid}.json").as_bytes()]).unwrap();
            assert_eq!(
                state.outcomes.last().map(|item| item.outcome),
                Some(TerminalOutcome::Denied)
            );
        }
    }

    #[test]
    fn freeze_does_not_deny_another_users_human_request() {
        use xudo_gate::request::AttestedClass::{Human, Unattested};
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let mut humans = Vec::new();
        for (nonce, uid, class, stored) in [
            (NONCE.to_owned(), UID, "unattested", Unattested),
            ("d".repeat(64), 2000, "human", Human),
            ("e".repeat(64), 3000, "yolo-human", Human),
        ] {
            let mut entry = enrolled_entry(&nonce, uid);
            class.clone_into(&mut entry.claimed_classification);
            stored_as(&mut entry, stored);
            spool
                .publish(&entry.nonce, entry.to_json().as_bytes())
                .unwrap();
            humans.push(entry.nonce);
        }
        let outcome = serve_with(
            &mut host,
            &connection(Ok(freeze_request().to_json().into_bytes())),
            Ok(&spool),
        );
        assert_eq!(outcome.answer, Answer::Done);
        for nonce in humans {
            let bytes = spool.files()[nonce.as_bytes()].clone();
            let kept = PendingRequest::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
            assert_eq!(kept.state, xudo_gate::request::ConfirmationState::Pending);
        }
        assert!(host.confirmations.files().is_empty());
        assert!(
            host.freeze_file
                .files()
                .contains_key(b"frozen-1000".as_slice())
        );
    }

    #[test]
    fn freeze_adds_no_strike() {
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let entry = enrolled_entry(NONCE, UID);
        spool
            .publish(&entry.nonce, entry.to_json().as_bytes())
            .unwrap();
        serve_with(
            &mut host,
            &connection(Ok(freeze_request().to_json().into_bytes())),
            Ok(&spool),
        );
        let files = host.confirmations.files();
        let state: ConfirmData =
            serde_json::from_slice(&files[format!("{UID}.json").as_bytes()]).unwrap();
        assert!(state.backoff.is_empty());
        assert_eq!(state.outcomes.len(), 1);
    }

    #[test]
    fn a_stale_freeze_temp_does_not_disable_freeze() {
        let mut host = Host::honest();
        host.freeze_file
            .publish(".tmp.frozen-1000", b"half")
            .unwrap();
        let outcome = serve_with(
            &mut host,
            &connection(Ok(freeze_request().to_json().into_bytes())),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(outcome.answer, Answer::Done);
        let files = host.freeze_file.files();
        assert!(files.contains_key(b"frozen-1000".as_slice()));
        assert!(!files.contains_key(b".tmp.frozen-1000".as_slice()));
        assert!(host.freeze_file.calls().contains(&SpoolCall::Lock));

        let identity = test_identity(PID, START, 0, 0);
        let again = freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &identity,
            &freeze_request(),
            "again",
        )
        .unwrap();
        assert_eq!(again.answer, Answer::Done);
    }

    #[test]
    fn freeze_refuses_a_lock_or_stale_temp_it_cannot_clear() {
        let broken = SpoolError::InvalidName {
            name: "state".to_owned(),
        };
        let identity = test_identity(PID, START, 0, 0);
        for state in [
            FakeSpool::new().failing_lock(broken.clone()),
            FakeSpool::new().failing_remove(broken.clone()),
        ] {
            let mut host = Host::honest();
            host.freeze_file = state;
            let error = freeze(
                &mut host.platform(),
                &FakeSpool::new(),
                &identity,
                &freeze_request(),
                "maintenance",
            )
            .unwrap_err();
            assert_eq!(error.code, RefusalCode::SpoolUnusable);
        }
    }

    #[test]
    fn an_oversized_freeze_leaves_no_freeze_record() {
        let reason = "\u{1}".repeat(xudo_wire::MAX_REASON_BYTES);
        let mut host = Host::honest();
        let error = freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &test_identity(PID, START, 0, 0),
            &freeze_request(),
            &reason,
        )
        .unwrap_err();
        assert_eq!(error.code, RefusalCode::RequestTooLarge);
        assert!(host.freeze_file.files().is_empty());
        assert!(host.audit.records().is_empty());
    }

    #[test]
    fn the_freeze_record_carries_the_escaped_reason_and_wall_time() {
        let mut host = Host::honest();
        let reason = "line\nbreak";
        freeze(
            &mut host.platform(),
            &FakeSpool::new(),
            &test_identity(PID, START, 0, 0),
            &freeze_request(),
            reason,
        )
        .unwrap();
        let record = host.audit.records().last().unwrap();
        assert!(record.evidence.contains(&"reason=line\\nbreak".to_owned()));
        let marker = host.freeze_file.files()[b"frozen-1000".as_slice()].clone();
        let value: serde_json::Value = serde_json::from_slice(&marker).unwrap();
        assert!(value["time"].as_u64().unwrap() > 1_700_000_000_000);
    }

    #[test]
    fn status_reports_a_denial_after_the_entry_is_gone() {
        let entry = shown_entry();
        let store = FakeSpool::new();
        store.lock().unwrap();
        record_outcome_locked(&store, &entry, TerminalOutcome::Denied, NOW, true).unwrap();
        store.unlock();
        let mut host = Host::honest();
        host.confirmations = store;
        let response =
            status_outcome(&host.platform(), &test_identity(PID, START, 0, 0), NONCE).unwrap();
        assert!(
            matches!(response.answer, Answer::Decided { decision, minted: None } if decision.denial == Some(DenialCode::ConfirmationRefused))
        );
    }

    #[test]
    fn status_reports_a_consumed_approval_as_allowed_and_used() {
        let mut consumed = shown_entry();
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        consumed.confirmed = true;
        let watcher = watcher_pin(&test_identity(5000, 77, 2, 34816));
        consumed.confirmed_by = Some(watcher.clone());
        consumed.shown_to = Some(watcher);
        consumed.shown_at_ms = Some(BoottimeMillis(0));
        let spool = FakeSpool::new().with_file(
            consumed.nonce.as_bytes().to_vec(),
            consumed.to_json().into_bytes(),
        );
        let request = a_status_request();
        let mut host = Host::honest();

        let response = status(
            &connection(Ok(request.to_json().into_bytes())),
            &mut host.platform(),
            &spool,
            &test_identity(PID, START, 0, 0),
            &request,
            NONCE,
        )
        .unwrap();

        assert!(matches!(
            response.answer,
            Answer::Decided { decision, minted: None }
                if decision.verdict == Verdict::Allow && decision.denial.is_none()
        ));
    }

    #[test]
    fn status_reports_a_denied_entry_as_refused() {
        let mut denied = shown_entry();
        denied.state = xudo_gate::request::ConfirmationState::Denied;
        denied.confirmed = false;
        denied.confirmed_by = None;
        denied.shown_at_ms = None;
        denied.shown_to = None;
        let spool = FakeSpool::new().with_file(
            denied.nonce.as_bytes().to_vec(),
            denied.to_json().into_bytes(),
        );
        let request = a_status_request();
        let mut host = Host::honest();

        let response = status(
            &connection(Ok(request.to_json().into_bytes())),
            &mut host.platform(),
            &spool,
            &test_identity(PID, START, 0, 0),
            &request,
            NONCE,
        )
        .unwrap();

        assert!(matches!(
            response.answer,
            Answer::Decided { decision, minted: None }
                if decision.denial == Some(DenialCode::ConfirmationRefused)
        ));
    }

    #[test]
    fn status_reports_expiry() {
        let entry = shown_entry();
        let store = FakeSpool::new();
        store.lock().unwrap();
        record_outcome_locked(&store, &entry, TerminalOutcome::Expired, NOW, true).unwrap();
        store.unlock();
        let mut host = Host::honest();
        host.confirmations = store;
        let response =
            status_outcome(&host.platform(), &test_identity(PID, START, 0, 0), NONCE).unwrap();
        assert!(
            matches!(response.answer, Answer::Decided { decision, minted: None } if decision.denial == Some(DenialCode::ConfirmationExpired))
        );
    }

    #[test]
    fn status_reports_live_approved_and_expired_entries() {
        let identity = test_identity(PID, START, 0, 0);
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: NONCE.to_owned(),
            },
        };
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        approved.confirmed_by = Some(watcher_pin(&test_identity(5000, 77, 2, 34816)));
        let approved_spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), approved.to_json().into_bytes());
        let mut host = Host::honest();
        let answer = status(
            &connection(Ok(request.to_json().into_bytes())),
            &mut host.platform(),
            &approved_spool,
            &identity,
            &request,
            NONCE,
        )
        .unwrap();
        assert!(decision_of(&answer.answer).unwrap().1.is_some());

        let mut expired = shown_entry();
        expired.state = xudo_gate::request::ConfirmationState::Expired;
        let expired_spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), expired.to_json().into_bytes());
        let answer = status(
            &connection(Ok(request.to_json().into_bytes())),
            &mut host.platform(),
            &expired_spool,
            &identity,
            &request,
            NONCE,
        )
        .unwrap();
        assert!(
            matches!(answer.answer, Answer::Decided { decision, minted: None } if decision.denial == Some(DenialCode::ConfirmationExpired))
        );
    }

    #[test]
    fn recent_outcomes_are_bounded() {
        let mut entry = shown_entry();
        let store = FakeSpool::new();
        store.lock().unwrap();
        for i in 0..MAX_RECENT_OUTCOMES_PER_UID + 3 {
            entry.nonce = format!("{i:064x}");
            record_outcome_locked(
                &store,
                &entry,
                TerminalOutcome::Denied,
                NOW + i as u64,
                true,
            )
            .unwrap();
        }
        store.unlock();
        let data: ConfirmData =
            serde_json::from_slice(&store.files()[b"1000.json".as_slice()]).unwrap();
        assert_eq!(data.outcomes.len(), MAX_RECENT_OUTCOMES_PER_UID);
        assert_eq!(data.outcomes[0].id, format!("{:064x}", 3));
    }

    #[test]
    fn confirm_file_caps_and_fields_fit_the_read_limit() {
        let data = ConfirmData {
            heartbeat: Some(WatcherHeartbeat {
                pid: u32::MAX,
                starttime: u64::MAX,
                tty: i64::MIN,
                sid: i64::MIN,
                at_ms: u64::MAX,
            }),
            backoff: (0..MAX_BACKOFF_ENTRIES_PER_UID)
                .map(|_| BackoffEntry {
                    fingerprint: "f".repeat(64),
                    strikes: u32::MAX,
                    until_ms: u64::MAX,
                })
                .collect(),
            outcomes: (0..MAX_RECENT_OUTCOMES_PER_UID)
                .map(|_| RecentOutcome {
                    id: "a".repeat(64),
                    outcome: TerminalOutcome::Expired,
                    until_ms: u64::MAX,
                    pid: u32::MAX,
                    starttime: u64::MAX,
                })
                .collect(),
        };
        let bytes = encode(&data).unwrap();
        assert!(bytes.len() <= MAX_CONFIRM_DATA_BYTES);
    }

    #[test]
    fn an_oversized_confirmation_state_is_never_written() {
        let mut data = ConfirmData {
            heartbeat: None,
            backoff: Vec::new(),
            outcomes: Vec::new(),
        };
        data.backoff.push(BackoffEntry {
            fingerprint: "x".repeat(CONFIRM_FILE_LIMIT),
            strikes: 1,
            until_ms: NOW,
        });
        assert!(encode(&data).is_none());
        let store = FakeSpool::new();
        assert!(write_confirm(&store, "1.json", None, &data).is_err());
        assert!(store.names_up_to(4).unwrap().is_empty());
    }

    #[test]
    fn confirm_reader_rejects_oversized_directories_and_fields() {
        let store = (0..=MAX_CONFIRM_UIDS).fold(FakeSpool::new(), |store, uid| {
            store.with_file(format!("{uid}.json"), b"{}".to_vec())
        });
        assert!(read_confirm_data(&store, "missing.json").is_err());
        let broken_listing = FakeSpool::new().failing_names(SpoolError::Io {
            operation: "list confirmation directory".to_owned(),
            at: crate::CONFIRM_DIR.to_owned(),
            code: None,
            reason: "listing failed".to_owned(),
        });
        assert!(read_confirm_data(&broken_listing, "missing.json").is_err());

        let invalid = ConfirmData {
            heartbeat: None,
            backoff: vec![BackoffEntry {
                fingerprint: "short".to_owned(),
                strikes: 1,
                until_ms: NOW + 1,
            }],
            outcomes: Vec::new(),
        };
        let store = FakeSpool::new().with_file("1000.json", serde_json::to_vec(&invalid).unwrap());
        assert!(read_confirm_data(&store, "1000.json").is_err());
    }

    #[test]
    fn save_heartbeat_refuses_a_broken_confirm_file() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut host = Host::honest();
        host.confirmations =
            FakeSpool::new().with_file("1000.json", b"oversized or malformed".to_vec());
        let err =
            save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW).unwrap_err();
        assert_eq!(err.code, RefusalCode::SpoolUnusable);
        assert!(err.detail.contains("operator repair"));
        assert_eq!(
            host.confirmations.files()[b"1000.json".as_slice()],
            b"oversized or malformed"
        );
    }

    #[test]
    fn heartbeat_sweeps_expired_backoff_and_a_failed_write_changes_nothing() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let state = ConfirmData {
            heartbeat: None,
            backoff: vec![BackoffEntry {
                fingerprint: "f".repeat(64),
                strikes: 1,
                until_ms: NOW - 1,
            }],
            outcomes: Vec::new(),
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().with_file("1000.json", bytes.clone());
        save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW).unwrap();
        let saved: ConfirmData =
            serde_json::from_slice(&host.confirmations.files()[b"1000.json".as_slice()]).unwrap();
        assert!(saved.backoff.is_empty() && saved.heartbeat.is_some());
        host.confirmations = FakeSpool::new()
            .with_file("1000.json", bytes.clone())
            .failing_replace(SpoolError::Gone {
                name: "state".to_owned(),
            });
        let err =
            save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW).unwrap_err();
        assert_eq!(err.code, RefusalCode::SpoolUnusable);
        assert_eq!(host.confirmations.files()[b"1000.json".as_slice()], bytes);
    }

    #[test]
    fn clearing_a_strike_sweeps_expired_outcomes_and_keeps_the_rest() {
        let state = ConfirmData {
            heartbeat: None,
            backoff: vec![BackoffEntry {
                fingerprint: "f".repeat(64),
                strikes: 1,
                until_ms: NOW + 1000,
            }],
            outcomes: vec![
                RecentOutcome {
                    id: "o".repeat(64),
                    outcome: TerminalOutcome::Expired,
                    until_ms: NOW - 1,
                    pid: 1,
                    starttime: 1,
                },
                RecentOutcome {
                    id: "l".repeat(64),
                    outcome: TerminalOutcome::Expired,
                    until_ms: NOW + 1000,
                    pid: 1,
                    starttime: 1,
                },
            ],
        };
        let store = FakeSpool::new().with_file("1000.json", serde_json::to_vec(&state).unwrap());
        clear_backoff(Some(&store), UID, &"f".repeat(64), NOW).unwrap();
        let saved: ConfirmData =
            serde_json::from_slice(&store.files()[b"1000.json".as_slice()]).unwrap();
        assert!(saved.backoff.is_empty());
        assert_eq!(saved.outcomes.len(), 1);
        assert_eq!(saved.outcomes[0].id, "l".repeat(64));
    }

    #[test]
    fn outcome_writer_refuses_a_broken_confirm_file() {
        let entry = shown_entry();
        let store = FakeSpool::new().with_file("1000.json", b"bad".to_vec());
        assert_eq!(
            record_outcome_locked(&store, &entry, TerminalOutcome::Denied, NOW, true)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
        assert_eq!(store.files()[b"1000.json".as_slice()], b"bad");
    }

    #[test]
    fn a_changed_approval_is_not_republished_as_consumed() {
        let identity = test_identity(PID, START, 0, 0);
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        approved.confirmed_by = Some(pin.clone());
        approved.shown_to = Some(pin);
        let mut consumed = approved.clone();
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        consumed.deadline.0 = NOW + crate::confirm::CONSUMED_TTL_MS;
        let mut changed = approved;
        changed.state = xudo_gate::request::ConfirmationState::Expired;
        let bytes = changed.to_json();
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.into_bytes());
        let live = unattested_live(&identity);
        let err =
            publish_consumed_approval(&spool, &live.binding(&identity), &grant(&consumed), NOW)
                .unwrap_err();
        assert_eq!(err.code, RefusalCode::RequestUnknown);
        assert_eq!(
            spool.files()[NONCE.as_bytes()],
            changed.to_json().as_bytes()
        );
    }

    #[test]
    fn consumed_publication_cannot_repin_an_approval_to_another_class() {
        let other = test_identity(PID + 1, START + 1, 9, 9);
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        approved.confirmed_by = Some(pin.clone());
        approved.shown_to = Some(pin);
        let mut consumed = approved.clone();
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        consumed.deadline.0 = NOW + crate::confirm::CONSUMED_TTL_MS;
        consumed.caller_pid = other.pid;
        consumed.caller_starttime = other.starttime;
        consumed.caller_sid = other.sid;
        consumed.caller_tty = other.tty;
        let bytes = approved.to_json();
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone().into_bytes());
        let live = LiveAttestation {
            class: xudo_gate::request::AttestedClass::Human,
            scope_id: None,
            boot_id: None,
        };
        let error =
            publish_consumed_approval(&spool, &live.binding(&other), &grant(&consumed), NOW)
                .unwrap_err();
        assert_eq!(error.code, RefusalCode::RequestUnknown);
        assert_eq!(spool.files()[NONCE.as_bytes()], bytes.as_bytes());
    }

    #[test]
    fn consumed_publication_cannot_repin_an_approval_to_another_scope() {
        let other = test_identity(PID + 1, START + 1, 9, 9);
        let (spool, entry) = agent_approval(44);
        let before = spool.files()[NONCE.as_bytes()].clone();
        let mut consumed = entry;
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        consumed.caller_pid = other.pid;
        consumed.caller_starttime = other.starttime;
        consumed.caller_sid = other.sid;
        consumed.caller_tty = other.tty;
        let live = LiveAttestation {
            class: xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 45 },
            scope_id: Some(45),
            boot_id: Some(BOOT_ID.to_owned()),
        };
        let error =
            publish_consumed_approval(&spool, &live.binding(&other), &grant(&consumed), NOW)
                .unwrap_err();
        assert_eq!(error.code, RefusalCode::RequestUnknown);
        assert_eq!(spool.files()[NONCE.as_bytes()], before);
    }

    #[test]
    fn consumed_publication_accepts_a_new_session_of_the_same_identity() {
        let other = test_identity(PID + 1, START + 1, 9, 9);
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        approved.confirmed_by = Some(pin.clone());
        approved.shown_to = Some(pin);
        let mut consumed = approved.clone();
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        consumed.deadline.0 = NOW + 1;
        consumed.caller_pid = other.pid;
        consumed.caller_starttime = other.starttime;
        consumed.caller_sid = other.sid;
        consumed.caller_tty = other.tty;
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), approved.to_json().into_bytes());
        let live = unattested_live(&other);
        let binding = live.binding(&other);
        // A consumed copy pinned to someone else is refused.
        let mut stale = consumed.clone();
        stale.caller_pid = PID;
        assert!(publish_consumed_approval(&spool, &binding, &grant(&stale), NOW).is_err());
        publish_consumed_approval(&spool, &binding, &grant(&consumed), NOW).unwrap();
        let saved = parse_entry(&spool.files()[NONCE.as_bytes()]).unwrap();
        assert_eq!(saved.state, xudo_gate::request::ConfirmationState::Consumed);
        assert_eq!(saved.caller_pid, other.pid);
    }

    /// An entry whose authorization is on a trail, as `mint_approved` has it.
    fn grant(entry: &PendingRequest) -> xudo_sys::Authorized<Grant> {
        authorize(
            &mut FakeAuditSink::new(),
            Grant(entry.clone()),
            &|previous, grant| {
                Record::after(
                    previous,
                    AuditDecision::Allowed,
                    Grant::command_of(&grant.0),
                    "unattested",
                )
                .with_rule(grant.0.action.clone(), "test:1")
            },
        )
        .unwrap()
    }

    fn unattested_live(identity: &PeerIdentity) -> LiveAttestation {
        live_attestation(
            &xudo_sys::FakeSyscalls::new(),
            &classify(identity),
            identity,
        )
        .unwrap()
    }

    #[test]
    fn approved_remint_for_an_agent_without_a_live_scope_is_a_broker_fault() {
        let mut host = Host::honest();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        let identity = test_identity(PID, START, 0, 0);
        let policy = confirming_policy();
        let caller = enrolled_caller();
        let evaluated = Evaluated {
            decision: decide(&policy, &caller, &request),
            caller,
            identity,
            request,
            policy,
        };
        let (_, entry) = agent_approval(44);
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &FakeSpool::new(),
            evaluated,
            entry,
        );
        assert_eq!(served, Served::Refused(Fault::Broker));
    }

    #[test]
    fn approved_remint_refuses_a_caller_of_another_class() {
        let mut host = Host::honest();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID + 1, START + 1, 9, 9);
        let policy = confirming_policy();
        let caller = classify(&identity);
        let evaluated = Evaluated {
            decision: decide(&policy, &caller, &request),
            caller,
            identity,
            request,
            policy,
        };
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        approved.confirmed_by = Some(pin.clone());
        approved.shown_to = Some(pin);
        approved.attested_class = xudo_gate::request::AttestedClass::Human;
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &FakeSpool::new(),
            evaluated,
            approved,
        );
        assert_eq!(served, Served::Refused(Fault::Client));
    }

    #[test]
    fn approved_remint_spends_the_approval_for_a_caller_of_another_session() {
        let mut host = Host::honest();
        host.confirmations = live_confirmation_store();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID + 1, START + 1, 9, 9);
        let policy = confirming_policy();
        let caller = classify(&identity);
        let evaluated = Evaluated {
            decision: decide(&policy, &caller, &request),
            caller,
            identity,
            request,
            policy,
        };
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        approved.confirmed_by = Some(pin.clone());
        approved.shown_to = Some(pin);
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), approved.to_json().into_bytes());
        let mut consumed = approved;
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &spool,
            evaluated,
            consumed,
        );
        assert_eq!(served, Served::Minted);
        let saved = parse_entry(&spool.files()[NONCE.as_bytes()]).unwrap();
        assert_eq!(saved.state, xudo_gate::request::ConfirmationState::Consumed);
        assert_eq!((saved.caller_sid, saved.caller_tty), (9, 9));
    }

    #[test]
    fn a_race_loser_is_audited_as_granted_then_superseded_by_a_denial() {
        let mut host = Host::honest();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID + 1, START + 1, 9, 9);
        let policy = confirming_policy();
        let caller = classify(&identity);
        let evaluated = Evaluated {
            decision: decide(&policy, &caller, &request),
            caller,
            identity,
            request,
            policy,
        };
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        approved.confirmed_by = Some(pin.clone());
        approved.shown_to = Some(pin);
        let mut on_disk = approved.clone();
        on_disk.state = xudo_gate::request::ConfirmationState::Expired;
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), on_disk.to_json().into_bytes());
        let mut consumed = approved;
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        let served = mint_approved(
            &connection(Ok(Vec::new())),
            &mut host.platform(),
            &spool,
            evaluated,
            consumed,
        );
        assert_eq!(served, Served::Refused(Fault::Client));
        // The log never ends in a grant for a consume that did not happen.
        let records = host.audit.records();
        let (last, earlier) = records.split_last().unwrap();
        assert_eq!(last.decision, xudo_audit::record::Decision::Denied);
        assert!(last.evidence.iter().any(|line| line.contains(NONCE)));
        assert_eq!(
            earlier.last().map(|record| record.decision),
            Some(xudo_audit::record::Decision::AwaitingConfirmation)
        );
        assert_eq!(
            the_entry(&spool, NONCE).state,
            xudo_gate::request::ConfirmationState::Expired
        );
    }

    #[test]
    fn audit_failure_after_a_matching_approval_leaves_no_spendable_consumed_entry() {
        let (spool, id) = approved_for_the_requester();
        let before = spool.files()[id.as_bytes()].clone();
        let request = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let mut host = rerun_host(PID + 7, START + 7, 0, 0);
        host.audit = FakeAuditSink::failing("audit down");
        let outcome = serve_with(&mut host, &request, Ok(&spool));
        assert_ne!(outcome.served, Served::Minted);
        assert_eq!(spool.files()[id.as_bytes()], before);
        assert!(spool.files().values().all(|bytes| {
            parse_entry(bytes)
                .is_ok_and(|entry| entry.state != xudo_gate::request::ConfirmationState::Consumed)
        }));
    }

    #[test]
    fn an_agent_facing_a_human_approval_consumes_nothing() {
        let (spool, id) = approved_for_the_requester();
        let action = the_entry(&spool, &id).action;
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent-yolo",
        );
        let mut identity = test_identity(PID + 1, START + 1, 8, 0);
        identity.cgroup_id = Some(44);
        let caller = xudo_policy::CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "test-agent".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            UID,
        );
        let syscalls = xudo_sys::FakeSyscalls::new().with_boot_id(Ok(BOOT_ID.to_owned()));
        let taken = take_matching_approval(
            &spool,
            &search_for(&request, &identity, &caller, &syscalls, &action),
        );
        assert!(taken.unwrap().is_none());
        assert_eq!(
            the_entry(&spool, &id).state,
            xudo_gate::request::ConfirmationState::Approved
        );
    }

    #[test]
    fn an_enrolled_approval_requires_the_live_boot_id_in_the_gate_binding() {
        let identity = test_identity(PID, START, 0, 0);
        let caller = xudo_policy::CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "test-agent".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            UID,
        );
        let mut entry = shown_entry();
        entry.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        entry.attested_scope_id = Some(44);
        entry.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        let mut scoped_identity = identity.clone();
        scoped_identity.cgroup_id = Some(44);
        let wrong_boot = xudo_sys::FakeSyscalls::new()
            .with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456780".to_owned()));
        let live = live_attestation(&wrong_boot, &caller, &scoped_identity).unwrap();
        assert!(!crate::confirm::identity_matches(
            &entry,
            &live.binding(&scoped_identity)
        ));
        // A boot id the kernel will not give is a broker fault, not a client one.
        let unreadable_boot = xudo_sys::FakeSyscalls::new();
        let error = live_attestation(&unreadable_boot, &caller, &scoped_identity)
            .err()
            .unwrap();
        assert_eq!(error.code, RefusalCode::BrokerUnusable);
        let garbled = xudo_sys::FakeSyscalls::new().with_boot_id(Ok("garbled".to_owned()));
        assert!(live_attestation(&garbled, &caller, &scoped_identity).is_err());
        let unscoped = live_attestation(&wrong_boot, &caller, &identity)
            .err()
            .unwrap();
        assert_eq!(unscoped.code, RefusalCode::BrokerUnusable);
    }

    #[test]
    fn swapping_in_an_entry_that_is_not_consumed_is_refused() {
        let identity = test_identity(PID, START, 0, 0);
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        let json = approved.to_json().into_bytes();
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), json.clone());
        let live = unattested_live(&identity);
        // A grant proves some record exists, not that it is a consume record.
        let error =
            publish_consumed_approval(&spool, &live.binding(&identity), &grant(&approved), NOW)
                .unwrap_err();
        assert_eq!(error.code, RefusalCode::RequestUnknown);
        assert_eq!(spool.files()[NONCE.as_bytes()], json);
        assert!(
            !spool
                .calls()
                .contains(&xudo_sys::SpoolCall::Replace(NONCE.as_bytes().to_vec()))
        );
    }

    #[test]
    fn a_swap_that_errors_after_the_exchange_is_not_logged_as_a_lost_grant() {
        let identity = test_identity(PID, START, 0, 0);
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        let mut consumed = approved.clone();
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        let live = unattested_live(&identity);
        let after = FakeSpool::new()
            .with_file(NONCE.as_bytes().to_vec(), approved.to_json().into_bytes())
            .failing_replace_after_exchange(SpoolError::Gone {
                name: "unlink".to_owned(),
            });
        let error =
            publish_consumed_approval(&after, &live.binding(&identity), &grant(&consumed), NOW)
                .unwrap_err();
        assert!(error.detail.contains("consume outcome unknown"));
        assert!(!error.detail.contains("supersedes the grant"));
        // The consumed bytes really are on disk.
        assert_eq!(
            the_entry(&after, NONCE).state,
            xudo_gate::request::ConfirmationState::Consumed
        );
        // A swap that failed before the exchange still supersedes the grant.
        let before = FakeSpool::new()
            .with_file(NONCE.as_bytes().to_vec(), approved.to_json().into_bytes())
            .failing_replace(SpoolError::Gone {
                name: "exchange".to_owned(),
            });
        let error =
            publish_consumed_approval(&before, &live.binding(&identity), &grant(&consumed), NOW)
                .unwrap_err();
        assert!(error.detail.contains("supersedes the grant"));
        assert!(!error.detail.contains("consume outcome unknown"));
    }

    fn backoff_store(fingerprint: &str) -> FakeSpool {
        FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: None,
                backoff: vec![BackoffEntry {
                    fingerprint: fingerprint.to_owned(),
                    strikes: 1,
                    until_ms: NOW + 60_000,
                }],
                outcomes: Vec::new(),
            })
            .unwrap(),
        )
    }

    fn backoff_left(host: &Host) -> usize {
        serde_json::from_slice::<ConfirmData>(&host.confirmations.files()[b"1000.json".as_slice()])
            .unwrap()
            .backoff
            .len()
    }

    #[test]
    fn a_lost_consume_leaves_the_backoff_in_place() {
        let (approved, id) = approved_for_the_requester();
        let fingerprint = the_entry(&approved, &id).fingerprint;
        let rerun = || asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        // The swap is refused.
        let lost = FakeSpool::new()
            .with_file(
                id.as_bytes().to_vec(),
                approved.files()[id.as_bytes()].clone(),
            )
            .failing_replace(SpoolError::Gone {
                name: "replace".to_owned(),
            });
        let mut host = rerun_host(PID + 7, START + 7, 0, 0);
        host.confirmations = backoff_store(&fingerprint);
        let outcome = serve_with(&mut host, &rerun(), Ok(&lost));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(backoff_left(&host), 1);
        // The audit record is refused: nothing is swapped, nothing cleared.
        let mut host = rerun_host(PID + 7, START + 7, 0, 0);
        host.confirmations = backoff_store(&fingerprint);
        host.audit = FakeAuditSink::failing("audit down");
        let outcome = serve_with(&mut host, &rerun(), Ok(&approved));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(backoff_left(&host), 1);
        // A real consume clears it.
        let mut host = rerun_host(PID + 7, START + 7, 0, 0);
        host.confirmations = backoff_store(&fingerprint);
        let outcome = serve_with(&mut host, &rerun(), Ok(&approved));
        assert_eq!(outcome.served, Served::Minted);
        assert_eq!(backoff_left(&host), 0);
    }

    #[test]
    fn consumed_publication_fails_closed_on_lock_read_parse_and_replace_errors() {
        let identity = test_identity(PID, START, 0, 0);
        let mut approved = shown_entry();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        let io = |reason: &str| SpoolError::Io {
            operation: "test".to_owned(),
            at: "x".to_owned(),
            code: None,
            reason: reason.to_owned(),
        };
        let id = NONCE.as_bytes().to_vec();
        let json = approved.to_json().into_bytes();
        let with = || FakeSpool::new().with_file(id.clone(), json.clone());
        let mut consumed = approved.clone();
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        let live = unattested_live(&identity);
        let publish = |spool: &FakeSpool| {
            publish_consumed_approval(spool, &live.binding(&identity), &grant(&consumed), NOW)
                .unwrap_err()
        };
        assert_eq!(
            publish(&with().failing_lock(io("lock"))).code,
            RefusalCode::SpoolUnusable
        );
        assert_eq!(publish(&FakeSpool::new()).code, RefusalCode::SpoolUnusable);
        let garbage = FakeSpool::new().with_file(id.clone(), b"not json".to_vec());
        assert!(
            publish_consumed_approval(&garbage, &live.binding(&identity), &grant(&consumed), NOW)
                .is_err()
        );
        assert_eq!(garbage.files()[&id], b"not json");
        let failing = with().failing_replace(io("replace"));
        assert_eq!(publish(&failing).code, RefusalCode::SpoolUnusable);
        assert_eq!(failing.files()[&id], json);
    }

    #[test]
    fn an_unreadable_confirmation_file_is_an_error_and_not_an_empty_state() {
        let store = FakeSpool::new()
            .with_file("1000.json", b"{}".to_vec())
            .failing_read("1000.json");
        assert!(read_confirm_data(&store, "1000.json").is_err());
    }

    #[test]
    fn a_confirm_file_with_a_positional_heartbeat_is_refused() {
        let bytes = br#"{"h":[42,99,34816,41,1],"b":[],"o":[]}"#;
        assert!(parse_confirm_data(bytes).is_err());
    }

    #[test]
    fn a_confirm_file_with_positional_backoff_and_outcome_rows_is_refused() {
        for bytes in [
            br#"{"h":null,"b":[["fingerprint",1,2]],"o":[]}"#.as_slice(),
            br#"{"h":null,"b":[],"o":[["nonce","expired",2,3,4]]}"#.as_slice(),
        ] {
            assert!(parse_confirm_data(bytes).is_err());
        }
    }

    #[test]
    fn duplicate_keys_in_confirmation_files_are_refused() {
        assert!(parse_confirm_data(br#"{"h":null,"h":null,"b":[],"o":[]}"#).is_err());
    }

    #[test]
    fn expiry_strikes_double_and_the_backoff_table_drops_its_oldest_entry() {
        let mut entry = shown_entry();
        let store = FakeSpool::new();
        store.lock().unwrap();
        record_outcome_locked(&store, &entry, TerminalOutcome::Expired, NOW, true).unwrap();
        record_outcome_locked(&store, &entry, TerminalOutcome::Expired, NOW + 1, true).unwrap();
        assert_eq!(
            serde_json::from_slice::<ConfirmData>(&store.files()[b"1000.json".as_slice()])
                .unwrap()
                .backoff[0]
                .strikes,
            2
        );
        for index in 0..MAX_BACKOFF_ENTRIES_PER_UID {
            entry.fingerprint = format!("{index:064x}");
            entry.nonce = format!("{index:064x}");
            record_outcome_locked(
                &store,
                &entry,
                TerminalOutcome::Expired,
                NOW + index as u64 + 2,
                true,
            )
            .unwrap();
        }
        store.unlock();
        let data: ConfirmData =
            serde_json::from_slice(&store.files()[b"1000.json".as_slice()]).unwrap();
        assert_eq!(data.backoff.len(), MAX_BACKOFF_ENTRIES_PER_UID);
        assert!(
            !data
                .backoff
                .iter()
                .any(|item| item.fingerprint == shown_entry().fingerprint)
        );
    }

    #[test]
    fn backoff_reads_and_clears_cover_the_confirmation_store_failures() {
        let request =
            BrokerRequest::new("/usr/bin/apt-get", vec!["remove".to_owned()], "unattested");
        assert!(active_backoff(None, UID, &request, NOW));
        assert!(active_backoff(
            Some(&FakeSpool::new().with_file("1000.json", b"bad".to_vec())),
            UID,
            &request,
            NOW
        ));
        assert!(clear_backoff(None, UID, "fingerprint", NOW).is_err());
        let no_match = FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: None,
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        assert!(clear_backoff(Some(&no_match), UID, "absent", NOW).is_ok());
        let bad_lock = FakeSpool::new().failing_lock(SpoolError::Gone {
            name: "lock".to_owned(),
        });
        assert!(clear_backoff(Some(&bad_lock), UID, "absent", NOW).is_err());
        assert!(clear_backoff(Some(&FakeSpool::new()), UID, "absent", NOW).is_err());
        let bad_json = FakeSpool::new().with_file("1000.json", b"bad".to_vec());
        assert!(clear_backoff(Some(&bad_json), UID, "absent", NOW).is_err());
        let fingerprint = request_fingerprint(&request, UID).unwrap();
        let state = ConfirmData {
            heartbeat: None,
            backoff: vec![BackoffEntry {
                fingerprint: fingerprint.clone(),
                strikes: 1,
                until_ms: NOW + 1000,
            }],
            outcomes: Vec::new(),
        };
        let failing = FakeSpool::new()
            .with_file("1000.json", serde_json::to_vec(&state).unwrap())
            .failing_replace(SpoolError::Gone {
                name: "state".to_owned(),
            });
        assert!(active_backoff(Some(&failing), UID, &request, NOW));
        assert!(clear_backoff(Some(&failing), UID, &fingerprint, NOW).is_err());
    }

    #[test]
    fn matching_approval_searches_cover_malformed_and_failed_spool_paths() {
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID, START, 0, 0);
        let generation = policy().rules.generation.id();
        assert!(
            take_matching_approval(
                &FakeSpool::new(),
                &ApprovalSearch {
                    request: &BrokerRequest {
                        schema_version: WIRE_SCHEMA_VERSION,
                        question: xudo_wire::Question::Status {
                            id: NONCE.to_owned()
                        }
                    },
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: Some("xudo.pkg.remove"),
                    generation,
                    now: NOW
                }
            )
            .is_ok_and(|approval| approval.is_none())
        );
        assert!(
            take_matching_approval(
                &FakeSpool::new(),
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: None,
                    generation,
                    now: NOW
                }
            )
            .is_ok_and(|approval| approval.is_none())
        );
        assert!(
            take_matching_approval(
                &FakeSpool::new().failing_lock(SpoolError::Gone {
                    name: "lock".to_owned()
                }),
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: Some("xudo.pkg.remove"),
                    generation,
                    now: NOW
                }
            )
            .is_err()
        );
        assert!(
            take_matching_approval(
                &FakeSpool::new().failing_names(SpoolError::Gone {
                    name: "names".to_owned()
                }),
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: Some("xudo.pkg.remove"),
                    generation,
                    now: NOW
                }
            )
            .is_err()
        );
        assert!(
            take_matching_approval(
                &FakeSpool::new()
                    .with_file("0bad", b"x".to_vec())
                    .failing_read(b"0bad".to_vec()),
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: Some("xudo.pkg.remove"),
                    generation,
                    now: NOW
                }
            )
            .is_err()
        );
    }

    #[test]
    fn an_enrolled_retry_with_an_unreadable_live_boot_id_is_denied() {
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        let mut identity = test_identity(PID, START, 0, 0);
        identity.cgroup_id = Some(44);
        let caller = xudo_policy::CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "test-agent".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            UID,
        );
        let mut approved = enrolled_entry(NONCE, UID);
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        approved.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        approved.attested_scope_id = Some(44);
        approved.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), approved.to_json().into_bytes());
        assert!(
            take_matching_approval(
                &spool,
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &caller,
                    syscalls: &xudo_sys::FakeSyscalls::new(),
                    action: Some("xudo.pkg.remove"),
                    generation: policy().rules.generation.id(),
                    now: NOW
                }
            )
            .is_err()
        );
    }

    #[test]
    fn an_agent_scope_id_from_another_boot_cannot_consume_an_approval() {
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        let mut identity = test_identity(PID, START, 0, 0);
        identity.cgroup_id = Some(44);
        let caller = xudo_policy::CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "test-agent".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            UID,
        );
        let mut approved = enrolled_entry(NONCE, UID);
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        approved.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        approved.attested_scope_id = Some(44);
        approved.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), approved.to_json().into_bytes());
        assert!(
            take_matching_approval(
                &spool,
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &caller,
                    syscalls: &xudo_sys::FakeSyscalls::new()
                        .with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456780".to_owned())),
                    action: Some("xudo.pkg.remove"),
                    generation: policy().rules.generation.id(),
                    now: NOW
                }
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn an_enrolled_identity_without_a_live_scope_is_denied() {
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "enrolled-agent",
        );
        let identity = test_identity(PID, START, 0, 0);
        let caller = xudo_policy::CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "test-agent".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            UID,
        );
        assert!(
            take_matching_approval(
                &FakeSpool::new(),
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &caller,
                    syscalls: &xudo_sys::FakeSyscalls::new(),
                    action: Some("xudo.pkg.remove"),
                    generation: policy().rules.generation.id(),
                    now: NOW,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn attested_class_conversion_keeps_human_and_live_scope_facts() {
        let identity = test_identity(PID, START, 0, 0);
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "human",
        );
        let class_of = |caller: &CallerFacts, identity: &PeerIdentity| {
            live_attestation(&xudo_sys::FakeSyscalls::new(), caller, identity)
                .ok()
                .map(|live| live.class)
        };
        let unattested = classify(&identity);
        assert_eq!(
            class_of(&unattested, &identity),
            Some(xudo_gate::request::AttestedClass::Unattested)
        );
        let human = xudo_policy::CallerFacts::new(xudo_policy::Classification::Human, UID);
        assert_eq!(
            class_of(&human, &identity),
            Some(xudo_gate::request::AttestedClass::Human)
        );
        assert!(
            take_matching_approval(
                &FakeSpool::new(),
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &human,
                    syscalls: &xudo_sys::FakeSyscalls::new(),
                    action: Some("xudo.pkg.remove"),
                    generation: policy().rules.generation.id(),
                    now: NOW,
                },
            )
            .is_ok_and(|approval| approval.is_none())
        );
        let agent = xudo_policy::CallerFacts::new(
            xudo_policy::Classification::EnrolledAgent {
                agent_id: "test-agent".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            UID,
        );
        assert_eq!(class_of(&agent, &identity), None);
        let mut scoped = identity;
        scoped.cgroup_id = Some(44);
        let live = live_attestation(
            &xudo_sys::FakeSyscalls::new()
                .with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456789".to_owned())),
            &agent,
            &scoped,
        )
        .unwrap();
        assert_eq!(
            live.class,
            xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 }
        );
    }

    #[test]
    fn scans_find_the_last_entry_in_a_full_mixed_spool() {
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID, START, 0, 0);
        let last_nonce = "f".repeat(64);
        let fillers = || {
            (0..crate::mint::MAX_SPOOL_ENTRIES + crate::mint::MAX_WATCH_ENTRIES - 1).fold(
                FakeSpool::new(),
                |spool, index| {
                    let mut entry = someone_elses_entry();
                    entry.nonce = format!("{:064x}", index + 1);
                    spool.with_file(entry.nonce.clone(), entry.to_json())
                },
            )
        };

        let mut approved = shown_entry();
        approved.nonce = last_nonce.clone();
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        approved.confirmed_by = Some(pin.clone());
        approved.shown_to = Some(pin);
        let approval_spool = fillers().with_file(last_nonce.clone(), approved.to_json());
        assert!(
            take_matching_approval(
                &approval_spool,
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: Some("xudo.pkg.remove"),
                    generation: policy().rules.generation.id(),
                    now: NOW
                }
            )
            .is_ok_and(|approval| approval.is_some())
        );

        let mut duplicate = shown_entry();
        duplicate.nonce = last_nonce.clone();
        let duplicate_spool = fillers().with_file(last_nonce.clone(), duplicate.to_json());
        assert!(pending_duplicate(
            &duplicate_spool,
            &request,
            UID,
            Some(&xudo_gate::request::AttestedClass::Unattested),
            NOW
        ));

        let mut expired = shown_entry();
        expired.nonce = last_nonce.clone();
        expired.deadline = BoottimeMillis(NOW);
        let expiry_spool = fillers().with_file(last_nonce.as_bytes().to_vec(), expired.to_json());
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        expire_entries(&mut host.platform(), &expiry_spool, &request).unwrap();
        assert!(!expiry_spool.files().contains_key(last_nonce.as_bytes()));
        assert_eq!(host.audit.records().len(), 1);
        assert!(
            host.audit.records()[0]
                .evidence
                .iter()
                .any(|item| item.contains(&last_nonce))
        );
    }

    #[test]
    fn freeze_pending_and_watch_scan_the_last_entry_in_a_full_spool() {
        let identity = test_identity(PID, START, 0, 0);
        let last_nonce = "f".repeat(64);
        let fillers = || {
            (0..crate::mint::MAX_SPOOL_ENTRIES + crate::mint::MAX_WATCH_ENTRIES - 1).fold(
                FakeSpool::new(),
                |spool, index| {
                    let mut entry = someone_elses_entry();
                    entry.nonce = format!("{:064x}", index + 1);
                    spool.with_file(entry.nonce.clone(), entry.to_json())
                },
            )
        };

        let mut approved = enrolled_entry(&last_nonce, UID);
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        let freeze_spool = fillers().with_file(last_nonce.clone(), approved.to_json());
        let mut host = Host::honest();
        deny_pending(
            &mut host.platform(),
            &freeze_spool,
            &identity,
            &freeze_request(),
        )
        .unwrap();
        assert!(!freeze_spool.files().contains_key(last_nonce.as_bytes()));
        assert_eq!(host.audit.records().len(), 1);
        let denial_record = &host.audit.records()[0];
        assert_eq!(denial_record.decision, xudo_audit::record::Decision::Denied);
        assert_eq!(
            denial_record.denial.as_deref(),
            Some("confirmation_refused")
        );
        assert!(
            denial_record
                .argv
                .iter()
                .any(|item| item == "/usr/bin/apt-get")
        );

        let mut pending_last = shown_entry();
        pending_last.nonce = last_nonce.clone();
        let pending_spool = fillers().with_file(last_nonce.clone(), pending_last.to_json());
        let mut host = Host::honest();
        let response = pending_list(&mut host.platform(), &pending_spool, &identity).unwrap();
        assert!(
            watching_prompts(&response.answer)
                .unwrap()
                .iter()
                .any(|prompt| prompt.id == last_nonce)
        );

        let watcher = test_identity(5000, 77, 2, 34816);
        let watch_spool = fillers().with_file(last_nonce.clone(), pending_last.to_json());
        let mut host = Host::honest();
        let response = watch(&mut host.platform(), &watch_spool, &watcher).unwrap();
        assert!(
            watching_prompts(&response.answer)
                .unwrap()
                .iter()
                .any(|prompt| prompt.id == last_nonce)
        );
    }

    #[test]
    fn malformed_approval_entries_are_skipped_but_failed_consumption_is_not() {
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID, START, 0, 0);
        let mut entry = shown_entry();
        entry.state = xudo_gate::request::ConfirmationState::Approved;
        entry.confirmed = true;
        let pin = watcher_pin(&test_identity(5000, 77, 2, 34816));
        entry.confirmed_by = Some(pin.clone());
        entry.shown_to = Some(pin);
        let valid = entry.to_json().into_bytes();
        let generation = policy().rules.generation.id();
        let malformed_then_valid = FakeSpool::new()
            .with_file("0bad", b"x".to_vec())
            .with_file(NONCE.as_bytes().to_vec(), valid.clone());
        assert!(
            take_matching_approval(
                &malformed_then_valid,
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: Some("xudo.pkg.remove"),
                    generation,
                    now: NOW
                }
            )
            .is_ok_and(|approval| approval.is_some())
        );
        let consume_error = FakeSpool::new()
            .with_file(NONCE.as_bytes().to_vec(), valid)
            .failing_consume(SpoolError::Gone {
                name: NONCE.to_owned(),
            });
        assert!(
            take_matching_approval(
                &consume_error,
                &ApprovalSearch {
                    request: &request,
                    identity: &identity,
                    caller: &classify(&identity),
                    syscalls: &xudo_sys::HostSyscalls,
                    action: Some("xudo.pkg.remove"),
                    generation,
                    now: NOW
                }
            )
            .is_ok_and(|approval| approval.is_some())
        );
    }

    #[test]
    fn a_pending_request_of_another_class_does_not_throttle_this_one() {
        use xudo_gate::request::AttestedClass::{EnrolledAgent, Human, Unattested};
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), {
            let mut entry = shown_entry();
            stored_as_agent(&mut entry);
            entry.to_json().into_bytes()
        });
        let ask = |class: Option<&xudo_gate::request::AttestedClass>| {
            pending_duplicate(&spool, &request, UID, class, NOW)
        };
        assert!(ask(Some(&EnrolledAgent { scope_id: 44 })));
        assert!(!ask(Some(&EnrolledAgent { scope_id: 45 })));
        assert!(!ask(Some(&Human)));
        assert!(!ask(Some(&Unattested)));
        assert!(!ask(None));
    }

    #[test]
    fn a_caller_class_is_what_its_kernel_facts_attest() {
        use xudo_gate::request::AttestedClass::{EnrolledAgent, Human, Unattested};
        let mut identity = test_identity(PID, START, 0, 0);
        let facts = |classification| xudo_policy::CallerFacts::new(classification, UID);
        let agent = || xudo_policy::Classification::EnrolledAgent {
            agent_id: "a".to_owned(),
            session_id: "s".to_owned(),
            declared_yolo: false,
        };
        assert_eq!(pending_class(&facts(agent()), &identity), None);
        identity.cgroup_id = Some(44);
        assert_eq!(
            pending_class(&facts(agent()), &identity),
            Some(EnrolledAgent { scope_id: 44 })
        );
        assert_eq!(
            pending_class(&facts(xudo_policy::Classification::Human), &identity),
            Some(Human)
        );
        assert_eq!(
            pending_class(
                &facts(xudo_policy::Classification::Unattested {
                    reason: "test".to_owned()
                }),
                &identity
            ),
            Some(Unattested)
        );
    }

    #[test]
    fn pending_duplicate_failures_are_throttled_closed() {
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        assert!(!pending_duplicate(
            &FakeSpool::new(),
            &BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question: xudo_wire::Question::Thaw
            },
            UID,
            Some(&xudo_gate::request::AttestedClass::Unattested),
            NOW
        ));
        assert!(pending_duplicate(
            &FakeSpool::new().failing_lock(SpoolError::Gone {
                name: "lock".to_owned()
            }),
            &request,
            UID,
            Some(&xudo_gate::request::AttestedClass::Unattested),
            NOW
        ));
        assert!(pending_duplicate(
            &FakeSpool::new().failing_names(SpoolError::Gone {
                name: "names".to_owned()
            }),
            &request,
            UID,
            Some(&xudo_gate::request::AttestedClass::Unattested),
            NOW
        ));
    }

    #[test]
    fn watcher_heartbeat_parse_and_empty_cases_are_not_live() {
        let peers = FakePeer::new();
        let caller = test_identity(PID, START, 2, 34816);
        assert!(!has_live_watcher(None, &peers, UID, &caller, NOW));
        assert!(!has_live_watcher(
            Some(&FakeSpool::new().with_file("1000.json", b"bad".to_vec())),
            &peers,
            UID,
            &caller,
            NOW
        ));
        let empty = ConfirmData {
            heartbeat: None,
            backoff: Vec::new(),
            outcomes: Vec::new(),
        };
        assert!(!has_live_watcher(
            Some(&FakeSpool::new().with_file("1000.json", serde_json::to_vec(&empty).unwrap())),
            &peers,
            UID,
            &caller,
            NOW
        ));
    }

    #[test]
    fn a_watcher_in_the_requesters_session_is_not_a_live_channel() {
        let caller = test_identity(5000, 77, 2, 34816);
        let store = FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: Some(WatcherHeartbeat {
                    pid: 5000,
                    starttime: 77,
                    tty: 34816,
                    sid: 2,
                    at_ms: NOW,
                }),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        let peers = FakePeer::new().with_proc(5000, ProcFile::Stat, stat_line(5000, 77));
        assert!(!has_live_watcher(Some(&store), &peers, UID, &caller, NOW));
    }

    #[test]
    fn one_long_argv_reaches_the_watcher_without_truncation() {
        let mut entry = shown_entry();
        entry.argv = vec!["界".repeat(1_000), "語".repeat(1_000)];
        entry.shown_at_ms = None;
        entry.shown_to = None;
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut host = Host::honest();
        let watcher = test_identity(5000, 77, 2, 34816);
        let response = watch(&mut host.platform(), &spool, &watcher).unwrap();
        let prompts = watching_prompts(&response.answer).unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].action, "xudo.pkg.remove");
        assert_eq!(prompts[0].argv, entry.argv);
        assert_eq!(prompts[0].expires_in_ms, 100_000);
        let shown =
            PendingRequest::parse(std::str::from_utf8(&spool.files()[NONCE.as_bytes()]).unwrap())
                .unwrap();
        assert_eq!(shown.state, xudo_gate::request::ConfirmationState::Pending);
        assert!(shown.shown_at_ms.is_some());
    }

    #[test]
    fn watch_prompt_keeps_a_long_action_and_argv() {
        let mut entry = shown_entry();
        entry.action = "a".repeat(xudo_wire::MAX_PROMPT_BYTES);
        let prompt = bounded_prompt(&entry, NOW);
        assert_eq!(prompt.action, entry.action);
        assert_eq!(prompt.expires_in_ms, 100_000);
    }

    #[test]
    fn the_watcher_delivers_one_prompt_per_heartbeat() {
        let spool = (0..=xudo_wire::MAX_PROMPTS).fold(FakeSpool::new(), |spool, index| {
            let mut entry = shown_entry();
            entry.nonce = format!("{index:064x}");
            entry.shown_at_ms = None;
            entry.shown_to = None;
            spool.with_file(
                entry.nonce.as_bytes().to_vec(),
                entry.to_json().into_bytes(),
            )
        });
        let mut host = Host::honest();
        let watcher = test_identity(5000, 77, 2, 34816);
        let response = watch(&mut host.platform(), &spool, &watcher).unwrap();
        let prompts = watching_prompts(&response.answer).unwrap();
        assert_eq!(prompts.len(), 1);
        let shown = spool
            .files()
            .values()
            .filter(|bytes| {
                PendingRequest::parse(std::str::from_utf8(bytes).unwrap())
                    .is_ok_and(|entry| entry.shown_at_ms.is_some())
            })
            .count();
        assert_eq!(shown, 1);
    }

    #[test]
    fn the_oldest_request_is_shown_first() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut newer = shown_entry();
        newer.nonce = "cd".repeat(32);
        newer.deadline = BoottimeMillis(NOW + 20_000);
        let mut older = shown_entry();
        older.deadline = BoottimeMillis(NOW + 10_000);
        let spool = FakeSpool::new()
            .with_file(
                newer.nonce.as_bytes().to_vec(),
                newer.to_json().into_bytes(),
            )
            .with_file(
                older.nonce.as_bytes().to_vec(),
                older.to_json().into_bytes(),
            );
        let mut host = Host::honest();

        let response = watch(&mut host.platform(), &spool, &watcher).unwrap();

        assert_eq!(
            watching_prompts(&response.answer).unwrap()[0].id,
            older.nonce
        );
    }

    #[test]
    fn an_already_shown_request_stays_ahead_of_older_unshown_requests() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut previously_shown = shown_entry();
        previously_shown.deadline = BoottimeMillis(NOW + 20_000);
        let mut older_unshown = shown_entry();
        older_unshown.nonce = "cd".repeat(32);
        older_unshown.deadline = BoottimeMillis(NOW + 10_000);
        older_unshown.shown_at_ms = None;
        older_unshown.shown_to = None;
        let spool = FakeSpool::new()
            .with_file(
                previously_shown.nonce.as_bytes().to_vec(),
                previously_shown.to_json().into_bytes(),
            )
            .with_file(
                older_unshown.nonce.as_bytes().to_vec(),
                older_unshown.to_json().into_bytes(),
            );
        let mut host = Host::honest();

        let response = watch(&mut host.platform(), &spool, &watcher).unwrap();

        assert_eq!(
            watching_prompts(&response.answer).unwrap()[0].id,
            previously_shown.nonce
        );
    }

    #[test]
    fn a_heartbeat_does_not_rewrite_an_unchanged_entry() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut entry = shown_entry();
        entry.shown_at_ms = None;
        entry.shown_to = None;
        let spool = FakeSpool::new().with_file(
            entry.nonce.as_bytes().to_vec(),
            entry.to_json().into_bytes(),
        );
        let mut host = Host::honest();

        watch(&mut host.platform(), &spool, &watcher).unwrap();
        let replace_calls = || {
            spool
                .calls()
                .iter()
                .filter(|call| matches!(call, SpoolCall::Replace(_)))
                .count()
        };
        let after_first_heartbeat = replace_calls();
        watch(&mut host.platform(), &spool, &watcher).unwrap();

        assert_eq!(after_first_heartbeat, 1);
        assert_eq!(replace_calls(), after_first_heartbeat);
    }

    #[test]
    fn an_expired_entry_is_recorded_struck_and_removed_before_dedup() {
        let mut entry = shown_entry();
        entry.deadline = BoottimeMillis(NOW);
        let spool = FakeSpool::new().with_file(
            entry.nonce.as_bytes().to_vec(),
            entry.to_json().into_bytes(),
        );
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        expire_entries(&mut host.platform(), &spool, &request).unwrap();
        assert!(spool.files().is_empty());
        assert_eq!(host.audit.records().len(), 1);
        let data: ConfirmData =
            serde_json::from_slice(&host.confirmations.files()[b"1000.json".as_slice()]).unwrap();
        assert_eq!(data.backoff.len(), 1);
        assert_eq!(data.backoff[0].strikes, 1);
        assert_eq!(data.outcomes[0].outcome, TerminalOutcome::Expired);
    }

    #[test]
    fn an_expiry_refuses_and_keeps_the_request_when_outcome_storage_fails() {
        let mut entry = shown_entry();
        entry.deadline = BoottimeMillis(NOW);
        let spool = FakeSpool::new().with_file(
            entry.nonce.as_bytes().to_vec(),
            entry.to_json().into_bytes(),
        );
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_publish(SpoolError::Io {
            operation: "publish".to_owned(),
            at: "confirm".to_owned(),
            code: None,
            reason: "full".to_owned(),
        });
        let request = BrokerRequest::new("/usr/bin/true", Vec::<String>::new(), "unattested");

        assert_eq!(
            expire_entries(&mut host.platform(), &spool, &request)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
        assert_eq!(spool.files().len(), 1);
        assert_eq!(host.audit.records().len(), 1);
    }

    #[test]
    fn a_password_only_entry_is_never_swept_as_a_confirmation() {
        let mut entry = shown_entry();
        entry.deadline = BoottimeMillis(NOW);
        entry.needs_watch = false;
        entry.state = xudo_gate::request::ConfirmationState::Pending;
        entry.confirmed = false;
        entry.confirmed_by = None;
        entry.shown_at_ms = None;
        entry.shown_to = None;
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        expire_entries(
            &mut host.platform(),
            &spool,
            &BrokerRequest::new("/usr/bin/true", Vec::<String>::new(), "unattested"),
        )
        .unwrap();
        assert_eq!(spool.files().len(), 1);
        assert!(host.audit.records().is_empty());
        assert!(host.confirmations.files().is_empty());
    }

    #[test]
    fn expiry_refusals_leave_the_entry_available_for_retry() {
        let mut entry = shown_entry();
        entry.deadline = BoottimeMillis(NOW);
        let bytes = entry.to_json().into_bytes();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_lock(SpoolError::Gone {
            name: "confirm".to_owned(),
        });
        let spool = FakeSpool::new().with_file(entry.nonce.as_bytes().to_vec(), bytes.clone());
        assert_eq!(
            expire_entries(&mut host.platform(), &spool, &request)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
        assert_eq!(spool.files().get(NONCE.as_bytes()), Some(&bytes));

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        host.audit = FakeAuditSink::failing("audit down");
        let spool = FakeSpool::new().with_file(entry.nonce.as_bytes().to_vec(), bytes.clone());
        assert_eq!(
            expire_entries(&mut host.platform(), &spool, &request)
                .unwrap_err()
                .code,
            RefusalCode::BrokerUnusable
        );
        assert_eq!(spool.files().get(NONCE.as_bytes()), Some(&bytes));

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let spool = FakeSpool::new()
            .with_file(entry.nonce.as_bytes().to_vec(), bytes.clone())
            .failing_remove(SpoolError::Io {
                operation: "remove".to_owned(),
                at: "spool".to_owned(),
                code: None,
                reason: "failed".to_owned(),
            });
        assert_eq!(
            expire_entries(&mut host.platform(), &spool, &request)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
        assert_eq!(spool.files().get(NONCE.as_bytes()), Some(&bytes));
    }

    #[test]
    fn expiry_requires_the_confirmation_directory() {
        let mut host = Host::honest();
        let mut platform = host.platform();
        platform.confirmations = None;
        let request = BrokerRequest::new("/usr/bin/true", Vec::<String>::new(), "unattested");
        assert_eq!(
            expire_entries(&mut platform, &FakeSpool::new(), &request)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
    }

    #[test]
    fn expiry_skips_unreadable_and_unparseable_entries() {
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let spool = FakeSpool::new()
            .with_file("unreadable", b"x".to_vec())
            .with_file("malformed", b"not-json".to_vec())
            .failing_read(b"unreadable".to_vec());
        let request = BrokerRequest::new("/usr/bin/true", Vec::<String>::new(), "unattested");
        expire_entries(&mut host.platform(), &spool, &request).unwrap();
        assert_eq!(spool.files().len(), 2);
        assert!(host.audit.records().is_empty());
    }

    #[test]
    fn an_approval_the_audit_sink_refuses_is_not_applied() {
        let entry = shown_entry();
        let before = entry.to_json().into_bytes();
        let spool = FakeSpool::new().with_file(entry.nonce.as_bytes().to_vec(), before.clone());
        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("audit unavailable");
        let watcher = test_identity(5000, 77, 2, 34816);
        let request = answer_request(NONCE, "remove", true);
        let result = answer_confirmation(&mut host.platform(), &spool, &watcher, &request);
        assert!(result.is_err());
        assert_eq!(spool.files().get(NONCE.as_bytes()), Some(&before));
    }

    #[test]
    fn answer_refusals_cover_bad_questions_and_store_failures() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let not_answer = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Thaw,
        };
        assert_eq!(
            answer_confirmation(&mut host.platform(), &spool, &watcher, &not_answer)
                .unwrap_err()
                .code,
            RefusalCode::RequestMalformed
        );

        let denial = answer_request(NONCE, "no", false);
        let mut platform = host.platform();
        platform.confirmations = None;
        assert_eq!(
            answer_confirmation(&mut platform, &spool, &watcher, &denial)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let mut host = Host::honest();
        let spool = FakeSpool::new().failing_lock(SpoolError::Gone {
            name: "lock".to_owned(),
        });
        assert_eq!(
            answer_confirmation(
                &mut host.platform(),
                &spool,
                &watcher,
                &answer_request(NONCE, "remove", true)
            )
            .unwrap_err()
            .code,
            RefusalCode::SpoolUnusable
        );

        let malformed = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), b"bad".to_vec());
        assert_eq!(
            answer_confirmation(
                &mut host.platform(),
                &malformed,
                &watcher,
                &answer_request(NONCE, "remove", true)
            )
            .unwrap_err()
            .code,
            RefusalCode::RequestUnknown
        );

        let mut too_fast = shown_entry();
        too_fast.shown_at_ms = Some(BoottimeMillis(NOW));
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), too_fast.to_json().into_bytes());
        assert_eq!(
            answer_confirmation(
                &mut host.platform(),
                &spool,
                &watcher,
                &answer_request(NONCE, "remove", true)
            )
            .unwrap_err()
            .code,
            RefusalCode::AnswerRejected
        );
    }

    #[test]
    fn denial_completion_refusals_cover_audit_outcome_and_removal() {
        let identity = test_identity(5000, 77, 2, 34816);
        let mut entry = shown_entry();
        entry.state = xudo_gate::request::ConfirmationState::Denied;
        let bytes = entry.to_json().into_bytes();
        let request = answer_request(NONCE, "no", false);
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone());

        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("audit down");
        let answered = AnsweredEntry {
            id: NONCE.to_owned(),
            bytes: bytes.clone(),
            entry: entry.clone(),
        };
        assert_eq!(
            complete_answer(
                &mut host.platform(),
                &spool,
                &identity,
                &request,
                answered,
                false
            )
            .unwrap_err()
            .code,
            RefusalCode::BrokerUnusable
        );

        let mut host = Host::honest();
        let mut platform = host.platform();
        platform.confirmations = None;
        let answered = AnsweredEntry {
            id: NONCE.to_owned(),
            bytes: bytes.clone(),
            entry: entry.clone(),
        };
        assert_eq!(
            complete_answer(&mut platform, &spool, &identity, &request, answered, false)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let state = ConfirmData {
            heartbeat: None,
            backoff: Vec::new(),
            outcomes: Vec::new(),
        };
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new()
            .with_file("1000.json", serde_json::to_vec(&state).unwrap())
            .failing_replace(SpoolError::Gone {
                name: "state".to_owned(),
            });
        let answered = AnsweredEntry {
            id: NONCE.to_owned(),
            bytes: bytes.clone(),
            entry: entry.clone(),
        };
        assert_eq!(
            complete_answer(
                &mut host.platform(),
                &spool,
                &identity,
                &request,
                answered,
                false
            )
            .unwrap_err()
            .code,
            RefusalCode::SpoolUnusable
        );

        let mut host = Host::honest();
        host.confirmations =
            FakeSpool::new().with_file("1000.json", serde_json::to_vec(&state).unwrap());
        let remove_error = FakeSpool::new()
            .with_file(NONCE.as_bytes().to_vec(), bytes.clone())
            .failing_remove(SpoolError::Gone {
                name: NONCE.to_owned(),
            });
        let answered = AnsweredEntry {
            id: NONCE.to_owned(),
            bytes,
            entry,
        };
        assert_eq!(
            complete_answer(
                &mut host.platform(),
                &remove_error,
                &identity,
                &request,
                answered,
                false
            )
            .unwrap_err()
            .code,
            RefusalCode::SpoolUnusable
        );
    }

    #[test]
    fn every_transition_leaves_one_record() {
        let entry = shown_entry();
        let spool = FakeSpool::new().with_file(
            entry.nonce.as_bytes().to_vec(),
            entry.to_json().into_bytes(),
        );
        let mut host = Host::honest();
        let watcher = test_identity(5000, 77, 2, 34816);
        let request = answer_request(NONCE, "remove", true);
        let response =
            answer_confirmation(&mut host.platform(), &spool, &watcher, &request).unwrap();
        assert_eq!(response.answer, Answer::Done);
        assert_eq!(host.audit.records().len(), 1);
        let entry =
            PendingRequest::parse(std::str::from_utf8(&spool.files()[NONCE.as_bytes()]).unwrap())
                .unwrap();
        assert_eq!(entry.state, xudo_gate::request::ConfirmationState::Approved);
        let record = &host.audit.records()[0];
        assert!(!record.evidence.join(" ").contains("remove"));
        assert!(!record.evidence.join(" ").contains("secret-token"));
    }

    #[test]
    fn a_denial_records_once_removes_the_entry_and_never_audits_the_token() {
        let entry = shown_entry();
        let spool = FakeSpool::new().with_file(
            entry.nonce.as_bytes().to_vec(),
            entry.to_json().into_bytes(),
        );
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: None,
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        let watcher = test_identity(5000, 77, 2, 34816);
        let request = answer_request(NONCE, "private-token", false);
        answer_confirmation(&mut host.platform(), &spool, &watcher, &request).unwrap();
        assert!(spool.files().is_empty());
        assert_eq!(host.audit.records().len(), 1);
        assert!(
            !host.audit.records()[0]
                .evidence
                .join(" ")
                .contains("private-token")
        );
    }

    #[test]
    fn a_denied_request_is_throttled_on_rerun() {
        let entry = shown_entry();
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: Some(WatcherHeartbeat {
                    pid: 5000,
                    starttime: 77,
                    tty: 34816,
                    sid: 2,
                    at_ms: NOW,
                }),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        let watcher = test_identity(5000, 77, 2, 34816);
        answer_confirmation(
            &mut host.platform(),
            &spool,
            &watcher,
            &answer_request(NONCE, "no", false),
        )
        .unwrap();
        let denied_data = host.confirmations.files()[b"1000.json".as_slice()].clone();
        let mut retry_host = Host::honest();
        turn_on_confirmation(&mut retry_host);
        retry_host.confirmations = FakeSpool::new().with_file("1000.json", denied_data);
        retry_host.peers = peer_with_live_watcher();
        let outcome = serve_with(
            &mut retry_host,
            &asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(
            decision_of(&outcome.answer).unwrap().0.denial,
            Some(DenialCode::ConfirmationThrottled)
        );
    }

    #[test]
    fn a_same_process_waiting_entry_is_denied_and_audited_on_mint() {
        let pending = shown_entry();
        let pending_bytes = pending.to_json().into_bytes();
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), pending_bytes.clone());
        let mut host = Host::honest();

        let outcome = serve_with(&mut host, &restart(), Ok(&spool));

        assert_eq!(outcome.served, Served::Decided);
        assert_eq!(
            decision_of(&outcome.answer).unwrap().0.denial,
            Some(DenialCode::ConfirmationThrottled)
        );
        assert_eq!(spool.files()[NONCE.as_bytes()], pending_bytes);
        assert_eq!(
            outcome.records.last().unwrap().denial.as_deref(),
            Some("confirmation_throttled")
        );
    }

    #[test]
    fn a_denied_entry_stays_available_when_the_outcome_write_fails() {
        let entry = shown_entry();
        let bytes = entry.to_json().into_bytes();
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone());
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new()
            .with_file(
                "1000.json",
                serde_json::to_vec(&ConfirmData {
                    heartbeat: None,
                    backoff: Vec::new(),
                    outcomes: Vec::new(),
                })
                .unwrap(),
            )
            .failing_replace(gone("outcome"));
        let result = complete_answer(
            &mut host.platform(),
            &spool,
            &test_identity(5000, 77, 2, 34816),
            &answer_request(NONCE, "no", false),
            AnsweredEntry {
                id: NONCE.to_owned(),
                bytes: bytes.clone(),
                entry,
            },
            false,
        );
        assert_eq!(result.unwrap_err().code, RefusalCode::SpoolUnusable);
        assert_eq!(spool.files().get(NONCE.as_bytes()), Some(&bytes));
    }

    #[test]
    fn watch_marks_only_eligible_entries_and_writes_a_heartbeat() {
        let mut entry = shown_entry();
        entry.shown_at_ms = None;
        entry.shown_to = None;
        let mut ineligible = entry.clone();
        ineligible.nonce = format!("{:064x}", 1);
        ineligible.caller_sid = 2;
        ineligible.caller_tty = 0;
        let spool = FakeSpool::new()
            .with_file(
                entry.nonce.as_bytes().to_vec(),
                entry.to_json().into_bytes(),
            )
            .with_file(
                ineligible.nonce.as_bytes().to_vec(),
                ineligible.to_json().into_bytes(),
            );
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let watcher = test_identity(5000, 77, 2, 34816);
        let response = watch(&mut host.platform(), &spool, &watcher).unwrap();
        let prompts = watching_prompts(&response.answer).unwrap();
        assert_eq!(prompts.len(), 1);
        assert!(
            host.confirmations
                .files()
                .contains_key(b"1000.json".as_slice())
        );
        let shown =
            PendingRequest::parse(std::str::from_utf8(&spool.files()[NONCE.as_bytes()]).unwrap())
                .unwrap();
        assert_eq!(shown.shown_to, Some(watcher_pin(&watcher)));
    }

    #[test]
    fn a_too_fast_answer_does_not_lose_the_prompt() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut entry = shown_entry();
        entry.shown_at_ms = Some(BoottimeMillis(NOW));
        let spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json().into_bytes());
        let mut host = Host::honest();

        let first = watch(&mut host.platform(), &spool, &watcher).unwrap();
        assert_eq!(watching_prompts(&first.answer).unwrap().len(), 1);
        let too_fast = answer_confirmation(
            &mut host.platform(),
            &spool,
            &watcher,
            &answer_request(NONCE, "remove", true),
        )
        .unwrap_err();
        assert_eq!(too_fast.code, RefusalCode::AnswerRejected);

        host.clock.0 = NOW + 2_000;
        let retry = watch(&mut host.platform(), &spool, &watcher).unwrap();
        assert_eq!(watching_prompts(&retry.answer).unwrap().len(), 1);
        let approved = answer_confirmation(
            &mut host.platform(),
            &spool,
            &watcher,
            &answer_request(NONCE, "remove", true),
        )
        .unwrap();
        assert_eq!(approved.answer, Answer::Done);
    }

    #[test]
    fn a_second_request_is_shown_after_the_first_is_answered() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let first = shown_entry();
        let mut second = first.clone();
        second.nonce = "cd".repeat(32);
        second.shown_at_ms = None;
        second.shown_to = None;
        let spool = FakeSpool::new()
            .with_file(
                first.nonce.as_bytes().to_vec(),
                first.to_json().into_bytes(),
            )
            .with_file(
                second.nonce.as_bytes().to_vec(),
                second.to_json().into_bytes(),
            );
        let mut host = Host::honest();

        let first_prompt = watch(&mut host.platform(), &spool, &watcher).unwrap();
        let first_id = watching_prompts(&first_prompt.answer).unwrap()[0]
            .id
            .clone();
        assert_eq!(first_id, first.nonce);
        answer_confirmation(
            &mut host.platform(),
            &spool,
            &watcher,
            &answer_request(&first_id, "remove", true),
        )
        .unwrap();

        let second_prompt = watch(&mut host.platform(), &spool, &watcher).unwrap();
        let prompts = watching_prompts(&second_prompt.answer).unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].id, second.nonce);
        host.clock.0 += 2_000;
        answer_confirmation(
            &mut host.platform(),
            &spool,
            &watcher,
            &answer_request(&second.nonce, "remove", true),
        )
        .unwrap();
    }

    #[test]
    fn pending_list_is_read_only_and_scoped_to_pending_entries_for_this_uid() {
        let mut valid = shown_entry();
        valid.shown_at_ms = None;
        valid.shown_to = None;
        let mut another_user = valid.clone();
        another_user.nonce = format!("{:064x}", 1);
        another_user.caller_uid = 2000;
        let mut no_watch = valid.clone();
        no_watch.nonce = format!("{:064x}", 2);
        no_watch.needs_watch = false;
        let mut approved = valid.clone();
        approved.nonce = format!("{:064x}", 3);
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        let mut expired = valid.clone();
        expired.nonce = format!("{:064x}", 4);
        expired.deadline = BoottimeMillis(NOW);
        let spool = FakeSpool::new()
            .with_file(
                valid.nonce.as_bytes().to_vec(),
                valid.to_json().into_bytes(),
            )
            .with_file(
                another_user.nonce.as_bytes().to_vec(),
                another_user.to_json().into_bytes(),
            )
            .with_file(
                no_watch.nonce.as_bytes().to_vec(),
                no_watch.to_json().into_bytes(),
            )
            .with_file(
                approved.nonce.as_bytes().to_vec(),
                approved.to_json().into_bytes(),
            )
            .with_file(
                expired.nonce.as_bytes().to_vec(),
                expired.to_json().into_bytes(),
            );
        let mut host = Host::honest();
        let response = pending_list(
            &mut host.platform(),
            &spool,
            &test_identity(PID, START, 0, 0),
        )
        .unwrap();
        let prompts = watching_prompts(&response.answer).unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].id, valid.nonce);
        assert_eq!(prompts[0].expires_in_ms, 100_000);
        let still_pending = PendingRequest::parse(
            std::str::from_utf8(&spool.files()[prompts[0].id.as_bytes()]).unwrap(),
        )
        .unwrap();
        assert_eq!(still_pending.shown_at_ms, None);
        assert_eq!(still_pending.shown_to, None);
    }

    #[test]
    fn pending_list_fails_closed_on_spool_enumeration_errors_and_skips_bad_files() {
        let identity = test_identity(PID, START, 0, 0);
        let mut host = Host::honest();
        assert_eq!(
            pending_list(
                &mut host.platform(),
                &FakeSpool::new().failing_lock(SpoolError::Gone {
                    name: "lock".to_owned()
                }),
                &identity,
            )
            .unwrap_err()
            .code,
            RefusalCode::SpoolUnusable
        );
        let mut host = Host::honest();
        assert_eq!(
            pending_list(
                &mut host.platform(),
                &FakeSpool::new().failing_names(SpoolError::Gone {
                    name: "names".to_owned()
                }),
                &identity,
            )
            .unwrap_err()
            .code,
            RefusalCode::SpoolUnusable
        );
        let spool = FakeSpool::new()
            .with_file(b"bad-entry".to_vec(), b"not json".to_vec())
            .with_file(b"unreadable".to_vec(), b"ignored".to_vec())
            .failing_read(b"unreadable".to_vec());
        let mut host = Host::honest();
        let response = pending_list(&mut host.platform(), &spool, &identity).unwrap();
        assert!(matches!(response.answer, Answer::Watching { prompts, .. } if prompts.is_empty()));
    }

    #[test]
    fn pending_list_stops_at_the_wire_prompt_limit() {
        let spool = (0..=xudo_wire::MAX_PROMPTS).fold(FakeSpool::new(), |spool, index| {
            let mut entry = shown_entry();
            entry.nonce = format!("{index:064x}");
            spool.with_file(
                entry.nonce.as_bytes().to_vec(),
                entry.to_json().into_bytes(),
            )
        });
        let mut host = Host::honest();
        let response = pending_list(
            &mut host.platform(),
            &spool,
            &test_identity(PID, START, 0, 0),
        )
        .unwrap();
        assert_eq!(
            watching_prompts(&response.answer).unwrap().len(),
            xudo_wire::MAX_PROMPTS
        );
        let json: serde_json::Value = serde_json::from_str(&response.to_json()).unwrap();
        assert_eq!(json["answer"]["watching"]["omitted"], 1);
    }

    #[test]
    fn many_large_requests_cannot_blind_the_watcher() {
        let spool = (0..24).fold(FakeSpool::new(), |spool, index| {
            let mut entry = shown_entry();
            entry.nonce = format!("{index:064x}");
            entry.argv = vec!["x".repeat(20_000)];
            spool.with_file(
                entry.nonce.as_bytes().to_vec(),
                entry.to_json().into_bytes(),
            )
        });
        let mut host = Host::honest();
        let response = pending_list(
            &mut host.platform(),
            &spool,
            &test_identity(PID, START, 0, 0),
        )
        .unwrap();
        assert!(response.to_json().len() <= xudo_wire::MAX_RESPONSE_BYTES);
        assert!(matches!(response.answer, Answer::Watching { omitted, .. } if omitted > 0));
    }

    #[test]
    fn watch_list_failures_and_bad_entries_are_handled() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let lock_error = FakeSpool::new().failing_lock(SpoolError::Gone {
            name: "lock".to_owned(),
        });
        assert_eq!(
            watch(&mut host.platform(), &lock_error, &watcher)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let list_error = FakeSpool::new().failing_names(SpoolError::Gone {
            name: "names".to_owned(),
        });
        assert_eq!(
            watch(&mut host.platform(), &list_error, &watcher)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let entries = FakeSpool::new()
            .with_file("00-unreadable", b"bad".to_vec())
            .with_file("01-malformed", b"bad".to_vec())
            .with_file(
                NONCE.as_bytes().to_vec(),
                shown_entry().to_json().into_bytes(),
            )
            .failing_read(b"00-unreadable".to_vec());
        let response = watch(&mut host.platform(), &entries, &watcher).unwrap();
        assert!(matches!(response.answer, Answer::Watching { prompts, .. } if prompts.len() == 1));

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new();
        let mut entry = shown_entry();
        entry.shown_at_ms = None;
        entry.shown_to = None;
        let bytes = entry.to_json().into_bytes();
        let replace_error = FakeSpool::new()
            .with_file(NONCE.as_bytes().to_vec(), bytes)
            .failing_replace(SpoolError::Gone {
                name: NONCE.to_owned(),
            });
        assert_eq!(
            watch(&mut host.platform(), &replace_error, &watcher)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
    }

    fn watcher_pin(identity: &PeerIdentity) -> xudo_gate::request::WatcherPin {
        xudo_gate::request::WatcherPin {
            uid: identity.uid,
            pid: identity.pid,
            starttime: identity.starttime,
            tty: identity.tty,
            sid: identity.sid,
        }
    }

    #[test]
    fn a_second_watcher_is_refused_and_told_the_first() {
        let heartbeat = WatcherHeartbeat {
            pid: 6000,
            starttime: 88,
            tty: 34817,
            sid: 3,
            at_ms: NOW,
        };
        let store = FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: Some(heartbeat),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        );
        let mut host = Host::honest();
        host.confirmations = store;
        host.peers = FakePeer::new().with_proc(6000, ProcFile::Stat, stat_line(6000, 88));
        let err = save_heartbeat(
            &mut host.platform(),
            &FakeSpool::new(),
            &test_identity(5000, 77, 2, 34816),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err.code, RefusalCode::ChannelUntrusted);
        assert!(err.detail.contains("6000"));
        assert!(err.detail.contains("34817"));
        let response = BrokerResponse::refused_with_detail(err.code, err.detail.clone());
        let parsed = BrokerResponse::parse(response.to_json().as_bytes()).unwrap();
        let detail = refusal_detail(&parsed.answer).unwrap();
        assert!(detail.contains("6000"));
        assert!(detail.contains("34817"));
        assert_eq!(
            host.confirmations
                .files()
                .get(b"1000.json".as_slice())
                .unwrap(),
            &serde_json::to_vec(&ConfirmData {
                heartbeat: Some(WatcherHeartbeat {
                    pid: 6000,
                    starttime: 88,
                    tty: 34817,
                    sid: 3,
                    at_ms: NOW
                }),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap()
        );
    }

    #[test]
    fn a_full_parseable_live_confirm_directory_refuses_and_preserves_every_file() {
        let live = backoff_file(NOW + 1);
        let store = (0..MAX_CONFIRM_UIDS).fold(FakeSpool::new(), |store, uid| {
            store.with_file(format!("{uid}.json"), live.clone())
        });
        let mut host = Host::honest();
        host.confirmations = store;
        let before = host.confirmations.files();
        let mut another_uid = test_identity(PID, START, 2, 34816);
        another_uid.uid = 50_000;
        let err =
            save_heartbeat(&mut host.platform(), &FakeSpool::new(), &another_uid, NOW).unwrap_err();
        assert_eq!(err.code, RefusalCode::SpoolFull);
        assert_eq!(err.detail, CONFIRM_DIRECTORY_FULL);
        assert_eq!(host.confirmations.files(), before);
    }

    #[test]
    fn a_pending_request_keeps_its_uid_file_live_during_pruning() {
        let idle = empty_confirm();
        let mut store = (0..MAX_CONFIRM_UIDS).fold(FakeSpool::new(), |store, uid| {
            store.with_file(format!("{uid}.json"), idle.clone())
        });
        let broken_confirm = b"malformed confirmation state".to_vec();
        store = store
            .with_file("1000.json", idle)
            .with_file("not-a-uid.json", broken_confirm.clone());
        let mut request_entry = shown_entry();
        request_entry.caller_uid = 1000;
        let mut password_only = shown_entry();
        password_only.nonce = format!("{:064x}", 1);
        password_only.needs_watch = false;
        password_only.state = xudo_gate::request::ConfirmationState::Pending;
        password_only.confirmed = false;
        password_only.confirmed_by = None;
        password_only.shown_at_ms = None;
        password_only.shown_to = None;
        let requests = FakeSpool::new()
            .with_file(b"unparseable".to_vec(), b"not-json".to_vec())
            .with_file(
                password_only.nonce.as_bytes().to_vec(),
                password_only.to_json().into_bytes(),
            )
            .with_file(
                request_entry.nonce.as_bytes().to_vec(),
                request_entry.to_json().into_bytes(),
            );
        let mut host = Host::honest();
        host.confirmations = store;
        let mut watcher = test_identity(5000, 77, 2, 34816);
        watcher.uid = 80_000;
        watch(&mut host.platform(), &requests, &watcher).unwrap();
        let files = host.confirmations.files();
        assert_eq!(files[b"1000.json".as_slice()], empty_confirm());
        assert_eq!(files[b"not-a-uid.json".as_slice()], broken_confirm);
        assert!(files.contains_key(b"80000.json".as_slice()));
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn pending_and_approved_requests_keep_their_uid_files_live() {
        let mut entry = shown_entry();
        assert!(request_uid_is_live(&entry));

        entry.state = xudo_gate::request::ConfirmationState::Approved;
        assert!(request_uid_is_live(&entry));

        entry.needs_watch = false;
        assert!(!request_uid_is_live(&entry));

        entry.needs_watch = true;
        entry.state = xudo_gate::request::ConfirmationState::Consumed;
        assert!(!request_uid_is_live(&entry));

        entry.state = xudo_gate::request::ConfirmationState::Denied;
        assert!(!request_uid_is_live(&entry));

        entry.state = xudo_gate::request::ConfirmationState::Expired;
        assert!(!request_uid_is_live(&entry));
    }

    #[test]
    fn a_full_bound_with_the_callers_file_skips_the_prune_walk() {
        let live = backoff_file(NOW + 1);
        let store = (0..MAX_CONFIRM_UIDS).fold(FakeSpool::new(), |store, uid| {
            store.with_file(format!("{uid}.json"), live.clone())
        });
        let mut host = Host::honest();
        host.confirmations = store;
        let watcher = test_identity(PID, START, 2, 34816);
        save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW).unwrap();
        assert_eq!(
            host.confirmations
                .calls()
                .iter()
                .filter(|call| matches!(call, SpoolCall::Read(_)))
                .count(),
            1,
            "only the caller's file is read for its heartbeat update"
        );
        assert!(
            !host
                .confirmations
                .calls()
                .iter()
                .any(|call| matches!(call, SpoolCall::Remove(_)))
        );
    }

    #[test]
    fn pruning_fails_closed_when_the_request_spool_cannot_be_inspected() {
        let live = backoff_file(NOW + 1);
        let store = (0..MAX_CONFIRM_UIDS).fold(FakeSpool::new(), |store, uid| {
            store.with_file(format!("{uid}.json"), live.clone())
        });
        let mut host = Host::honest();
        host.confirmations = store;
        let mut watcher = test_identity(5000, 77, 2, 34816);
        watcher.uid = 50_000;

        for requests in [
            FakeSpool::new().failing_lock(gone("request lock")),
            FakeSpool::new().failing_names(gone("request names")),
            FakeSpool::new()
                .with_file(b"request".to_vec(), b"unreadable".to_vec())
                .failing_read(b"request".to_vec()),
        ] {
            let before = host.confirmations.files();
            let err = save_heartbeat(&mut host.platform(), &requests, &watcher, NOW).unwrap_err();
            assert_eq!(err.code, RefusalCode::SpoolUnusable);
            assert_eq!(host.confirmations.files(), before);
        }
    }

    fn empty_confirm() -> Vec<u8> {
        serde_json::to_vec(&ConfirmData {
            heartbeat: None,
            backoff: Vec::new(),
            outcomes: Vec::new(),
        })
        .unwrap()
    }

    fn confirm_bytes(data: &ConfirmData) -> Vec<u8> {
        serde_json::to_vec(data).unwrap()
    }

    fn hb(pid: u32, starttime: u64, at_ms: u64) -> WatcherHeartbeat {
        WatcherHeartbeat {
            pid,
            starttime,
            tty: 1,
            sid: 1,
            at_ms,
        }
    }

    fn backoff_file(until_ms: u64) -> Vec<u8> {
        confirm_bytes(&ConfirmData {
            heartbeat: None,
            backoff: vec![BackoffEntry {
                fingerprint: "b".repeat(64),
                strikes: 2,
                until_ms,
            }],
            outcomes: Vec::new(),
        })
    }

    fn outcome_file(until_ms: u64) -> Vec<u8> {
        confirm_bytes(&ConfirmData {
            heartbeat: None,
            backoff: Vec::new(),
            outcomes: vec![RecentOutcome {
                id: "a".repeat(64),
                outcome: TerminalOutcome::Denied,
                until_ms,
                pid: 1,
                starttime: 1,
            }],
        })
    }

    fn heartbeat_file(pid: u32, starttime: u64, at_ms: u64) -> Vec<u8> {
        confirm_bytes(&ConfirmData {
            heartbeat: Some(hb(pid, starttime, at_ms)),
            backoff: Vec::new(),
            outcomes: Vec::new(),
        })
    }

    /// Another publisher's file appears on the publish-time listing, which asks
    /// for exactly [`MAX_CONFIRM_UIDS`] names. Earlier listings ask for one past
    /// the bound and must not see it.
    enum ListingFault {
        Insert(Vec<(String, Vec<u8>)>),
        Fail(SpoolError),
    }

    struct InterleavedSpool {
        inner: FakeSpool,
        at_limit: usize,
        action: RefCell<Option<ListingFault>>,
    }

    impl InterleavedSpool {
        fn inserting(files: Vec<(String, Vec<u8>)>) -> Self {
            Self {
                inner: FakeSpool::new(),
                at_limit: MAX_CONFIRM_UIDS,
                action: RefCell::new(Some(ListingFault::Insert(files))),
            }
        }

        fn failing(error: SpoolError) -> Self {
            Self {
                inner: FakeSpool::new(),
                at_limit: MAX_CONFIRM_UIDS,
                action: RefCell::new(Some(ListingFault::Fail(error))),
            }
        }

        fn failing_interleaved_publish(error: SpoolError) -> Self {
            Self {
                inner: FakeSpool::new().failing_publish(error),
                at_limit: MAX_CONFIRM_UIDS,
                action: RefCell::new(Some(ListingFault::Insert(vec![(
                    "raced.json".to_owned(),
                    b"raced".to_vec(),
                )]))),
            }
        }

        fn files(&self) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
            self.inner.files()
        }
    }

    impl Spool for InterleavedSpool {
        fn lock(&self) -> Result<(), SpoolError> {
            self.inner.lock()
        }

        fn unlock(&self) {
            self.inner.unlock();
        }

        fn names(&self) -> Result<Vec<Vec<u8>>, SpoolError> {
            self.inner.names()
        }

        fn names_up_to(&self, limit: usize) -> Result<Vec<Vec<u8>>, SpoolError> {
            if limit == self.at_limit {
                let action = self.action.borrow_mut().take();
                if let Some(action) = action {
                    match action {
                        ListingFault::Insert(files) => {
                            for (name, bytes) in files {
                                self.inner.publish(&name, &bytes)?;
                            }
                        }
                        ListingFault::Fail(error) => return Err(error),
                    }
                }
            }
            self.inner.names_up_to(limit)
        }

        fn read(&self, name: &[u8], limit: usize) -> Result<Vec<u8>, SpoolError> {
            self.inner.read(name, limit)
        }

        fn remove(&self, name: &[u8]) -> Result<(), SpoolError> {
            self.inner.remove(name)
        }

        fn consume(&self, name: &[u8]) -> Result<(), SpoolError> {
            self.inner.consume(name)
        }

        fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), SpoolError> {
            self.inner.publish(name, bytes)
        }

        fn replace(&self, name: &[u8], expected: &[u8], bytes: &[u8]) -> Result<(), SpoolError> {
            self.inner.replace(name, expected, bytes)
        }
    }

    #[test]
    fn interleaved_spool_delegates_its_fake_operations() {
        let spool = InterleavedSpool::inserting(Vec::new());
        spool.lock().unwrap();
        spool.publish("1.json", b"old").unwrap();
        assert_eq!(spool.read(b"1.json", 16).unwrap(), b"old");
        spool.replace(b"1.json", b"old", b"new").unwrap();
        assert_eq!(spool.names().unwrap(), vec![b"1.json".to_vec()]);
        assert_eq!(spool.names_up_to(1).unwrap(), vec![b"1.json".to_vec()]);
        assert_eq!(spool.names_up_to(MAX_CONFIRM_UIDS).unwrap().len(), 1);
        assert_eq!(spool.names_up_to(MAX_CONFIRM_UIDS).unwrap().len(), 1);
        spool.remove(b"1.json").unwrap();
        spool.publish("2.json", b"used").unwrap();
        spool.consume(b"2.json").unwrap();
        assert!(spool.files().is_empty());
        spool.unlock();
    }

    #[test]
    fn four_thousand_and_ninety_seven_idle_uids_do_not_lock_out_watch() {
        // Every way a uid file can look occupied and still be idle: an empty
        // record, a heartbeat the channel check would reject, and a strike or
        // outcome whose window has closed (including exactly at `until_ms`).
        let idle = empty_confirm();
        let mut store = FakeSpool::new();
        for uid in 0..=MAX_CONFIRM_UIDS {
            store = store.with_file(format!("{uid}.json"), idle.clone());
        }
        store = store
            .with_file("4087.json", outcome_file(NOW))
            .with_file("4088.json", heartbeat_file(7300, 77, NOW - 3_001))
            .with_file("4089.json", heartbeat_file(0, 77, NOW))
            .with_file("4090.json", heartbeat_file(7202, 77, NOW))
            .with_file("4091.json", heartbeat_file(7200, 77, NOW))
            .with_file("4092.json", heartbeat_file(7201, 77, NOW))
            .with_file("4093.json", heartbeat_file(7203, 77, NOW))
            .with_file("4094.json", backoff_file(NOW - 1))
            .with_file("4095.json", backoff_file(NOW))
            .with_file("4096.json", outcome_file(NOW - 1));
        let mut host = Host::honest();
        host.peers = std::mem::take(&mut host.peers)
            .with_proc(7300, ProcFile::Stat, stat_line(7300, 77))
            .with_proc(0, ProcFile::Stat, stat_line(0, 77))
            .with_proc(7200, ProcFile::Stat, stat_line(1, 77))
            .with_proc(7201, ProcFile::Stat, b"not-a-stat".to_vec())
            .with_proc(7203, ProcFile::Stat, stat_line(7203, 1));
        host.confirmations = store;
        let watcher = test_identity(5000, 77, 2, 34816);
        let response = watch(&mut host.platform(), &FakeSpool::new(), &watcher).unwrap();
        assert_eq!(
            response.answer,
            Answer::Watching {
                prompts: Vec::new(),
                omitted: 0
            }
        );
        let files = host.confirmations.files();
        assert_eq!(files.len(), 1, "idle uid files must not keep the bound");
        let saved: ConfirmData = serde_json::from_slice(&files[b"1000.json".as_slice()]).unwrap();
        assert_eq!(saved.heartbeat.unwrap().pid, watcher.pid);
        assert!(saved.backoff.is_empty());
        assert!(saved.outcomes.is_empty());
    }

    #[test]
    fn a_uid_with_live_backoff_is_never_pruned() {
        let idle = empty_confirm();
        let mut store = FakeSpool::new();
        for uid in 0..MAX_CONFIRM_UIDS {
            store = store.with_file(format!("{uid}.json"), idle.clone());
        }
        let live_backoff = backoff_file(NOW + 1);
        let live_outcome = outcome_file(NOW + 1);
        let live_heartbeat = heartbeat_file(6100, 91, NOW);
        let boundary_heartbeat = heartbeat_file(6101, 91, NOW - HEARTBEAT_FRESH_MS);
        let unreadable = b"do-not-delete".to_vec();
        store = store
            .with_file("10.json", live_backoff.clone())
            .with_file("11.json", live_outcome.clone())
            .with_file("12.json", live_heartbeat.clone())
            .with_file("13.json", unreadable.clone())
            .with_file("14.json", boundary_heartbeat.clone())
            .failing_read("13.json");
        let mut host = Host::honest();
        host.peers = std::mem::take(&mut host.peers)
            .with_proc(6100, ProcFile::Stat, stat_line(6100, 91))
            .with_proc(6101, ProcFile::Stat, stat_line(6101, 91));
        host.confirmations = store;
        let mut watcher = test_identity(5000, 77, 2, 34816);
        watcher.uid = 80_000;
        let response = watch(&mut host.platform(), &FakeSpool::new(), &watcher).unwrap();
        assert_eq!(
            response.answer,
            Answer::Watching {
                prompts: Vec::new(),
                omitted: 0
            }
        );
        let files = host.confirmations.files();
        assert_eq!(files[b"10.json".as_slice()], live_backoff);
        assert_eq!(files[b"11.json".as_slice()], live_outcome);
        assert_eq!(files[b"12.json".as_slice()], live_heartbeat);
        assert_eq!(files[b"13.json".as_slice()], unreadable);
        assert_eq!(files[b"14.json".as_slice()], boundary_heartbeat);
        assert!(!files.contains_key(b"0.json".as_slice()));
        assert!(files.contains_key(b"80000.json".as_slice()));
        assert_eq!(files.len(), 6);
    }

    #[test]
    fn the_bound_holds_when_two_publishers_race() {
        let raced = (0..MAX_CONFIRM_UIDS)
            .map(|uid| (format!("r{uid}.json"), b"raced".to_vec()))
            .collect();
        let store = InterleavedSpool::inserting(raced);
        let mut host = Host::honest();
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut platform = host.platform();
        platform.confirmations = Some(&store);
        let err = watch(&mut platform, &FakeSpool::new(), &watcher).unwrap_err();
        assert_eq!(err.code, RefusalCode::SpoolFull);
        assert_eq!(store.files().len(), MAX_CONFIRM_UIDS);
        assert!(!store.files().contains_key(b"1000.json".as_slice()));

        // The publish-time listing itself failing must not then publish.
        // An I/O error whose reason is not "directory full" stays unusable.
        let store = InterleavedSpool::failing(SpoolError::Io {
            operation: "list confirmation directory".to_owned(),
            at: crate::CONFIRM_DIR.to_owned(),
            code: None,
            reason: "listing failed".to_owned(),
        });
        let mut host = Host::honest();
        let mut platform = host.platform();
        platform.confirmations = Some(&store);
        let err = watch(&mut platform, &FakeSpool::new(), &watcher).unwrap_err();
        assert_eq!(err.code, RefusalCode::SpoolUnusable);
        assert!(store.files().is_empty());

        // A failure while applying the interleaving fault is also a listing
        // failure and must not be mistaken for a full directory.
        let store = InterleavedSpool::failing_interleaved_publish(SpoolError::Io {
            operation: "publish interleaved file".to_owned(),
            at: crate::CONFIRM_DIR.to_owned(),
            code: None,
            reason: "injected failure".to_owned(),
        });
        let mut host = Host::honest();
        let mut platform = host.platform();
        platform.confirmations = Some(&store);
        let err = watch(&mut platform, &FakeSpool::new(), &watcher).unwrap_err();
        assert_eq!(err.code, RefusalCode::SpoolUnusable);
        assert!(store.files().is_empty());
    }

    #[test]
    fn a_failed_unlink_cannot_be_skipped_to_publish_past_the_bound() {
        let idle = empty_confirm();
        let store = (0..MAX_CONFIRM_UIDS).fold(FakeSpool::new(), |store, uid| {
            store.with_file(format!("{uid}.json"), idle.clone())
        });
        let store = store.failing_remove(SpoolError::Io {
            operation: "unlink".to_owned(),
            at: crate::CONFIRM_DIR.to_owned(),
            code: None,
            reason: "busy".to_owned(),
        });
        let before = store.files();
        let mut host = Host::honest();
        host.confirmations = store;
        let mut watcher = test_identity(5000, 77, 2, 34816);
        watcher.uid = 50_000;
        let err = watch(&mut host.platform(), &FakeSpool::new(), &watcher).unwrap_err();
        assert_eq!(err.code, RefusalCode::SpoolUnusable);
        assert!(err.detail.contains("busy"));
        assert_eq!(host.confirmations.files(), before);
    }

    #[test]
    fn heartbeat_update_refusals_and_stale_state_are_covered() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut host = Host::honest();
        let mut platform = host.platform();
        platform.confirmations = None;
        assert_eq!(
            save_heartbeat(&mut platform, &FakeSpool::new(), &watcher, NOW)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_names(SpoolError::Gone {
            name: "names".to_owned(),
        });
        assert_eq!(
            save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let no_heartbeat = ConfirmData {
            heartbeat: None,
            backoff: Vec::new(),
            outcomes: Vec::new(),
        };
        let mut host = Host::honest();
        host.confirmations =
            FakeSpool::new().with_file("1000.json", serde_json::to_vec(&no_heartbeat).unwrap());
        assert!(save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW).is_ok());

        let oversized = ConfirmData {
            heartbeat: None,
            backoff: (0..=MAX_BACKOFF_ENTRIES_PER_UID)
                .map(|i| BackoffEntry {
                    fingerprint: format!("{i}"),
                    strikes: 1,
                    until_ms: NOW + 1_000,
                })
                .collect(),
            outcomes: Vec::new(),
        };
        let mut host = Host::honest();
        host.confirmations =
            FakeSpool::new().with_file("1000.json", serde_json::to_vec(&oversized).unwrap());
        assert_eq!(
            save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let mut host = Host::honest();
        host.confirmations = FakeSpool::new()
            .with_file("1000.json", b"not-json".to_vec())
            .failing_replace(SpoolError::Gone {
                name: "state".to_owned(),
            });
        assert_eq!(
            save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );

        let stale = ConfirmData {
            heartbeat: Some(WatcherHeartbeat {
                pid: 6000,
                starttime: 88,
                tty: 34817,
                sid: 3,
                at_ms: NOW - 3_001,
            }),
            backoff: Vec::new(),
            outcomes: vec![RecentOutcome {
                id: NONCE.to_owned(),
                outcome: TerminalOutcome::Denied,
                until_ms: NOW - 1,
                pid: PID,
                starttime: START,
            }],
        };
        let mut host = Host::honest();
        host.confirmations =
            FakeSpool::new().with_file("1000.json", serde_json::to_vec(&stale).unwrap());
        assert!(save_heartbeat(&mut host.platform(), &FakeSpool::new(), &watcher, NOW).is_ok());
        let saved: ConfirmData =
            serde_json::from_slice(&host.confirmations.files()[b"1000.json".as_slice()]).unwrap();
        assert!(saved.outcomes.is_empty());
    }

    fn live_confirmation_store() -> FakeSpool {
        FakeSpool::new().with_file(
            "1000.json",
            serde_json::to_vec(&ConfirmData {
                heartbeat: Some(WatcherHeartbeat {
                    pid: 5000,
                    starttime: 77,
                    tty: 34816,
                    sid: 2,
                    at_ms: NOW,
                }),
                backoff: Vec::new(),
                outcomes: Vec::new(),
            })
            .unwrap(),
        )
    }

    fn peer_with_live_watcher() -> FakePeer {
        FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(PID, START)))
            .with_exit(Ok(false))
            .with_proc(5000, ProcFile::Stat, stat_line(5000, 77))
    }

    fn test_identity(pid: u32, starttime: u64, sid: i64, tty: i64) -> PeerIdentity {
        PeerIdentity {
            rung: xudo_sys::Attestation::PeerPidfdInfo,
            pid,
            uid: UID,
            gid: GID,
            starttime,
            sid,
            tty,
            diverged: false,
            pinned: true,
            cgroup_id: None,
            euid_source: crate::identify::EuidSource::PidfdInfo,
        }
    }

    fn shown_entry() -> PendingRequest {
        let policy = policy();
        let request = BrokerRequest::new(
            "/usr/bin/apt-get",
            vec!["-y".to_owned(), "remove".to_owned(), "gcc".to_owned()],
            "unattested",
        );
        let identity = test_identity(PID, START, 0, 0);
        let caller = classify(&identity);
        let decision = decide(&policy, &caller, &request);
        let mut entry = entry_for(
            &decision,
            &identity,
            &request,
            policy.rules.generation.id(),
            true,
            NOW + 100_000,
            NONCE.to_owned(),
        )
        .unwrap();
        let watcher = crate::confirm::WatcherFacts {
            uid: UID,
            pid: 5000,
            starttime: 77,
            tty: 34816,
            sid: 2,
            diverged: false,
        };
        assert!(crate::confirm::mark_shown(&mut entry, watcher, NOW - 2_000));
        entry
    }

    fn enrolled_entry(nonce: &str, uid: u32) -> PendingRequest {
        let mut entry = shown_entry();
        entry.claimed_classification = "enrolled-agent".to_owned();
        stored_as_agent(&mut entry);
        entry.nonce = nonce.to_owned();
        entry.caller_uid = uid;
        entry
    }

    /// What the broker stores at mint for an attested agent.
    fn stored_as_agent(entry: &mut PendingRequest) {
        entry.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        entry.attested_scope_id = Some(44);
        entry.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
    }

    /// What the broker stores at mint for a human or an unattested caller.
    fn stored_as(entry: &mut PendingRequest, class: xudo_gate::request::AttestedClass) {
        entry.attested_class = class;
        entry.attested_scope_id = None;
        entry.boot_id = None;
    }

    fn freeze_request() -> BrokerRequest {
        BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Freeze {
                reason: "maintenance".to_owned(),
            },
        }
    }

    fn answer_request(id: &str, token: &str, approve: bool) -> BrokerRequest {
        BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Answer {
                id: id.to_owned(),
                token: token.to_owned(),
                approve,
            },
        }
    }

    #[test]
    fn a_broker_without_no_new_privs_refuses_before_reading_or_minting() {
        let mut host = Host::honest();
        host.hygiene = FakeHygiene::new(PID)
            .with_privileges_error(SysError::unsupported("PR_SET_NO_NEW_PRIVS"));
        let conn = restart();
        let spool = FakeSpool::new();

        let outcome = serve_with(&mut host, &conn, Ok(&spool));

        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(outcome.served.exit_status(), UNUSABLE);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::BrokerUnusable)
        );
        assert_eq!(
            host.hygiene.calls(),
            [xudo_sys::HygieneCall::ForbidNewPrivileges]
        );
        assert!(host.syscalls.calls().is_empty());
        assert_eq!(host.policy.loads.get(), 0);
        assert!(spool.calls().is_empty());
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(
            outcome.records[0].denial.as_deref(),
            Some("broker_unusable")
        );
        assert!(
            outcome.records[0]
                .evidence
                .join(" ")
                .contains("PR_SET_NO_NEW_PRIVS")
        );
    }

    fn decision_of(answer: &Answer) -> Option<(&Decision, Option<&Minted>)> {
        match answer {
            Answer::Decided { decision, minted } => Some((decision, minted.as_ref())),
            Answer::Refused { .. }
            | Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::Done => None,
        }
    }

    fn pending_id(answer: &Answer) -> Option<String> {
        match answer {
            Answer::Pending { id, .. } => Some(id.clone()),
            Answer::Refused { .. }
            | Answer::Decided { .. }
            | Answer::Watching { .. }
            | Answer::Done => None,
        }
    }

    fn watching_prompts(answer: &Answer) -> Option<&[xudo_wire::WatchPrompt]> {
        match answer {
            Answer::Watching { prompts, .. } => Some(prompts),
            Answer::Refused { .. }
            | Answer::Decided { .. }
            | Answer::Pending { .. }
            | Answer::Done => None,
        }
    }

    fn refusal_detail(answer: &Answer) -> Option<&str> {
        match answer {
            Answer::Refused { detail, .. } => detail.as_deref(),
            Answer::Decided { .. }
            | Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::Done => None,
        }
    }

    #[test]
    fn answer_extractors_refuse_the_wrong_shape() {
        assert_eq!(pending_id(&Answer::Done), None);
        assert_eq!(watching_prompts(&Answer::Done), None);
        assert_eq!(refusal_detail(&Answer::Done), None);
    }

    fn gone(name: &str) -> SpoolError {
        SpoolError::Gone {
            name: name.to_owned(),
        }
    }

    fn a_status_request() -> BrokerRequest {
        BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: xudo_wire::Question::Status {
                id: NONCE.to_owned(),
            },
        }
    }

    #[test]
    fn expiry_refuses_when_the_spool_lock_or_listing_fails() {
        let request = BrokerRequest::new("/usr/bin/true", Vec::<String>::new(), "unattested");
        let mut host = Host::honest();
        let locked = FakeSpool::new().failing_lock(gone("spool lock"));
        assert_eq!(
            expire_entries(&mut host.platform(), &locked, &request)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
        let unlistable = FakeSpool::new().failing_names(gone("names"));
        assert_eq!(
            expire_entries(&mut host.platform(), &unlistable, &request)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
    }

    #[test]
    fn a_broken_confirm_file_refuses_a_run_when_expiry_cannot_record_its_strike() {
        let request = asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]);
        let mut expired = shown_entry();
        expired.caller_uid = UID + 1;
        expired.caller_pid = 3000;
        expired.caller_starttime = 44;
        expired.caller_sid = 3;
        expired.caller_tty = 34817;
        expired.deadline = BoottimeMillis(NOW);
        expired.state = xudo_gate::request::ConfirmationState::Pending;
        expired.confirmed = false;
        expired.confirmed_by = None;
        expired.shown_at_ms = None;
        expired.shown_to = None;
        let spool = FakeSpool::new().with_file(
            expired.nonce.as_bytes().to_vec(),
            expired.to_json().into_bytes(),
        );
        let mut host = Host::honest();
        turn_on_confirmation(&mut host);
        host.peers = peer_with_live_watcher();
        host.confirmations = FakeSpool::new()
            .with_file(
                "1000.json",
                serde_json::to_vec(&ConfirmData {
                    heartbeat: Some(WatcherHeartbeat {
                        pid: 5000,
                        starttime: 77,
                        tty: 34816,
                        sid: 2,
                        at_ms: NOW,
                    }),
                    backoff: Vec::new(),
                    outcomes: Vec::new(),
                })
                .unwrap(),
            )
            .with_file("1001.json", b"broken confirm state".to_vec());
        let outcome = serve_with(&mut host, &request, Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(spool.files().len(), 1);
        assert!(spool.files().contains_key(expired.nonce.as_bytes()));
        assert_eq!(
            host.confirmations.files()[b"1001.json".as_slice()],
            b"broken confirm state"
        );
    }

    #[test]
    fn a_status_request_has_no_fingerprint() {
        assert_eq!(request_fingerprint(&a_status_request(), UID), None);
    }

    #[test]
    fn status_refuses_an_entry_that_does_not_parse() {
        let mut host = Host::honest();
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), b"bad".to_vec());
        let request = a_status_request();
        let result = status(
            &connection(Ok(request.to_json().into_bytes())),
            &mut host.platform(),
            &spool,
            &test_identity(PID, START, 0, 0),
            &request,
            NONCE,
        );
        assert_eq!(result.unwrap_err().code, RefusalCode::RequestUnknown);
    }

    #[test]
    fn status_of_a_gone_entry_without_usable_outcomes_is_unknown() {
        let identity = test_identity(PID, START, 0, 0);
        let mut host = Host::honest();
        let mut platform = host.platform();
        platform.confirmations = None;
        assert_eq!(
            status_outcome(&platform, &identity, NONCE)
                .unwrap_err()
                .code,
            RefusalCode::RequestUnknown
        );
        host.confirmations = FakeSpool::new().with_file("1000.json", b"bad".to_vec());
        assert_eq!(
            status_outcome(&host.platform(), &identity, NONCE)
                .unwrap_err()
                .code,
            RefusalCode::RequestUnknown
        );
    }

    #[test]
    fn a_watcher_whose_state_cannot_be_locked_is_refused() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_lock(gone("confirm"));
        assert_eq!(
            watch(&mut host.platform(), &FakeSpool::new(), &watcher)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
        let mut host = Host::honest();
        let locked = FakeSpool::new().failing_lock(gone("spool"));
        assert_eq!(
            watch(&mut host.platform(), &locked, &watcher)
                .unwrap_err()
                .code,
            RefusalCode::SpoolUnusable
        );
    }

    #[test]
    fn a_denial_whose_state_cannot_be_locked_is_refused() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut host = Host::honest();
        host.confirmations = FakeSpool::new().failing_lock(gone("confirm"));
        assert_eq!(
            answer_confirmation(
                &mut host.platform(),
                &FakeSpool::new(),
                &watcher,
                &answer_request(NONCE, "no", false)
            )
            .unwrap_err()
            .code,
            RefusalCode::SpoolUnusable
        );
    }

    #[test]
    fn an_answer_to_an_unknown_request_is_refused() {
        let watcher = test_identity(5000, 77, 2, 34816);
        let mut host = Host::honest();
        assert_eq!(
            answer_confirmation(
                &mut host.platform(),
                &FakeSpool::new(),
                &watcher,
                &answer_request(NONCE, "remove", true)
            )
            .unwrap_err()
            .code,
            RefusalCode::RequestUnknown
        );
    }

    #[test]
    fn an_approval_cannot_complete_without_policy_or_a_writable_entry() {
        let identity = test_identity(5000, 77, 2, 34816);
        let entry = shown_entry();
        let bytes = entry.to_json().into_bytes();
        let request = answer_request(NONCE, "remove", true);
        let answered = || AnsweredEntry {
            id: NONCE.to_owned(),
            bytes: bytes.clone(),
            entry: entry.clone(),
        };
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone());

        let mut host = Host::honest();
        host.policy.answer = Err(PolicyError::Config(xudo_gate::SettingsError::NotUtf8 {
            file: "/etc/xudo/config.toml".to_owned(),
        }));
        assert_eq!(
            complete_answer(
                &mut host.platform(),
                &spool,
                &identity,
                &request,
                answered(),
                true
            )
            .unwrap_err()
            .code,
            RefusalCode::PolicyUnloadable
        );

        let mut host = Host::honest();
        let failing = FakeSpool::new()
            .with_file(NONCE.as_bytes().to_vec(), bytes.clone())
            .failing_replace(gone("entry"));
        assert_eq!(
            complete_answer(
                &mut host.platform(),
                &failing,
                &identity,
                &request,
                answered(),
                true
            )
            .unwrap_err()
            .code,
            RefusalCode::SpoolUnusable
        );
        assert_eq!(failing.files().get(NONCE.as_bytes()), Some(&bytes));

        let mut changed = entry.clone();
        changed.program = "/usr/bin/false".to_owned();
        changed.argv.clear();
        let mut host = Host::honest();
        let changed_bytes = changed.to_json().into_bytes();
        let changed_spool =
            FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), changed_bytes.clone());
        let err = complete_answer(
            &mut host.platform(),
            &changed_spool,
            &identity,
            &request,
            AnsweredEntry {
                id: NONCE.to_owned(),
                bytes: changed_bytes,
                entry: changed,
            },
            true,
        )
        .unwrap_err();
        assert_eq!(err.code, RefusalCode::PolicyUnloadable);
        assert!(host.audit.records().is_empty());
    }

    fn entry_in(spool: &FakeSpool) -> PendingRequest {
        let files = spool.files();
        PendingRequest::parse(std::str::from_utf8(&files[NONCE.as_bytes()]).unwrap()).unwrap()
    }

    #[test]
    fn a_permitted_request_is_minted_for_the_peer_the_kernel_named() {
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Minted);
        assert_eq!(outcome.served.exit_status(), 0);
        assert_eq!(refusal_of(&outcome.answer), None);

        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(
            minted,
            Some(&Minted {
                nonce: NONCE.to_owned(),
                expires_in_ms: REQUEST_TTL_MILLIS,
                gate: "/usr/libexec/xudo/xudo-gate-auth".to_owned(),
            })
        );

        // The entry the gate will read: bound to the pin from the kernel, the
        // question as asked, the generation of the rules decided under.
        let entry = entry_in(&spool);
        assert_eq!((entry.caller_pid, entry.caller_starttime), (PID, START));
        assert_eq!(entry.action, "xudo.svc.restart");
        assert_eq!(entry.program, "/usr/bin/systemctl");
        assert_eq!(entry.argv, ["restart", "nginx.service"]);
        assert_eq!(entry.generation, policy().rules.generation.id());
        assert_eq!(entry.deadline, BoottimeMillis(NOW + REQUEST_TTL_MILLIS));
        assert!(!entry.confirmed);
        assert_eq!(
            spool.calls(),
            [
                SpoolCall::Lock,
                SpoolCall::NamesUpTo(crate::mint::MAX_SPOOL_NAMES_TO_WALK),
                SpoolCall::Unlock,
                SpoolCall::Lock,
                SpoolCall::Names,
                SpoolCall::Publish(NONCE.to_owned()),
                SpoolCall::Unlock
            ]
        );

        // One record, written before the entry existed, naming the nonce.
        assert_eq!(outcome.records.len(), 1);
        let record = &outcome.records[0];
        assert_eq!(record.decision, AuditDecision::Allowed);
        assert!(record.evidence.contains(&format!("nonce={NONCE}")));
        assert!(record.evidence.contains(&format!("peer_pid={PID}")));
    }

    #[test]
    fn the_claimed_classification_is_recorded_and_changes_nothing() {
        // Invariant 1 at the broker: the request claimed to be a yolo agent;
        // the broker classified it from kernel facts, as unattested, and
        // routed it to the password path regardless.
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        let entry = entry_in(&spool);
        assert_eq!(entry.claimed_classification, "enrolled-agent-yolo");
        let record = &outcome.records[0];
        assert_eq!(record.classification, "unattested");
        assert!(
            record
                .evidence
                .contains(&"claimed_classification=enrolled-agent-yolo".to_owned())
        );
        let (_, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(minted.unwrap().gate, xudo_backend::snippet::GATE_AUTH);
    }

    #[test]
    fn a_rule_that_demands_confirmation_still_mints_and_the_password_confirms() {
        let mut host = Host::honest();
        let spool = FakeSpool::new();
        let outcome = serve_with(
            &mut host,
            &asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]),
            Ok(&spool),
        );
        assert_eq!(outcome.served, Served::Minted);
        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.verdict, Verdict::AllowWithConfirmation);
        assert!(minted.is_some());
        let entry = entry_in(&spool);
        assert!(
            !entry.confirmed,
            "no channel confirmed it; sudo's password will"
        );
        assert_eq!(entry.confirmed_by, None);
        assert_eq!(
            outcome.records[0].decision,
            AuditDecision::AwaitingConfirmation
        );
    }

    #[test]
    fn denied_requests_mint_nothing_and_never_touch_the_spool() {
        // A program no rule runs, an operand the rule rejects, and a shell a
        // rule allows but the compiled-in deny-list refuses.
        for (program, argv, denial) in [
            ("/usr/bin/rm", &["-rf", "/"][..], DenialCode::UnknownAction),
            (
                "/usr/bin/systemctl",
                &["restart", "../../evil"][..],
                DenialCode::ArgvRejected,
            ),
            ("/bin/sh", &["-c"][..], DenialCode::DenyListed),
        ] {
            let mut host = Host::honest();
            let spool = FakeSpool::new();
            let outcome = serve_with(&mut host, &asking(program, argv), Ok(&spool));
            assert_eq!(outcome.served, Served::Decided, "{program}");
            assert_eq!(outcome.served.exit_status(), 0);
            let (decision, minted) = decision_of(&outcome.answer).unwrap();
            assert_eq!(decision.denial, Some(denial), "{program}");
            assert_eq!(minted, None);
            assert_eq!(
                spool.calls(),
                [
                    SpoolCall::Lock,
                    SpoolCall::NamesUpTo(crate::mint::MAX_SPOOL_NAMES_TO_WALK),
                    SpoolCall::Unlock
                ],
                "{program}"
            );
            assert_eq!(outcome.records.len(), 1);
            assert_eq!(outcome.records[0].denial.as_deref(), Some(denial.as_str()));
        }
    }

    #[test]
    fn a_peer_that_cannot_be_identified_is_refused_before_its_request_is_read() {
        // No credentials at all: the host cannot say who asked.
        let mut host = Host::honest();
        host.peers = FakePeer::new();
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(outcome.served.exit_status(), UNUSABLE);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PeerUnidentified)
        );
        assert_eq!(decision_of(&outcome.answer), None);
        assert_eq!(host.policy.loads.get(), 0);
        assert_eq!(spool.calls(), []);
        // The record carries no request: none was read.
        assert!(outcome.records[0].argv.is_empty());
    }

    #[test]
    fn a_peer_the_kernel_reports_as_pid_zero_is_never_minted_for() {
        // SO_PEERCRED names pid 0 for a peer outside the broker's pid
        // namespace. Every other answer is scripted to agree with it — a
        // pidfd, no kernel record to contradict it, a /proc entry for "pid 0"
        // — so that the refusal in `identify` is all that stands between this
        // peer and a request that is read, decided, and minted.
        let mut host = Host::honest();
        host.syscalls = FakeSyscalls::new()
            .with_peer(Ok(a_descriptor()))
            .with_info(Err(SysError::os(
                "ioctl(PIDFD_GET_INFO)",
                &rustix::io::Errno::NOTTY.into(),
            )));
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: 0,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(0, START)))
            .with_status(Ok(
                format!("Uid:\t{UID}\t{UID}\t{UID}\t{UID}\n").into_bytes()
            ))
            .with_exit(Ok(false));
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PeerUnidentified)
        );
        assert_eq!(decision_of(&outcome.answer), None);
        // Nothing was read, decided, or written: the policy was never loaded
        // and the spool never touched, and the record carries no request.
        assert_eq!(host.policy.loads.get(), 0);
        assert_eq!(spool.calls(), []);
        assert!(outcome.records[0].argv.is_empty());
        assert_eq!(
            outcome.records[0].denial.as_deref(),
            Some("peer_unidentified")
        );
        let evidence = &outcome.records[0].evidence;
        assert!(
            evidence.iter().any(|e| e.contains("pid is 0")),
            "{evidence:?}"
        );
        assert!(!evidence.iter().any(|e| e.starts_with("peer_pid=")));
    }

    #[test]
    fn a_peer_that_exits_mid_identification_is_refused_as_its_own_doing() {
        let mut host = Host::honest();
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(PID, START)))
            .with_exit(Ok(true));
        let outcome = serve_with(&mut host, &restart(), Ok(&FakeSpool::new()));
        assert_eq!(outcome.served, Served::Refused(Fault::Client));
        assert_eq!(outcome.served.exit_status(), 0);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PeerUnidentified)
        );
        let evidence = &outcome.records[0].evidence;
        assert!(
            evidence.iter().any(|e| e.contains("exited")),
            "{evidence:?}"
        );
    }

    #[test]
    fn a_request_that_cannot_be_read_is_refused_as_the_clients_fault() {
        for (failure, code) in [
            (
                ReadFailure::TooLarge { limit: 1 },
                RefusalCode::RequestTooLarge,
            ),
            (ReadFailure::TimedOut, RefusalCode::RequestTimedOut),
            (
                ReadFailure::Os(SysError::unsupported("reset")),
                RefusalCode::RequestUnreadable,
            ),
        ] {
            let mut host = Host::honest();
            let outcome = serve_with(&mut host, &connection(Err(failure)), Ok(&FakeSpool::new()));
            assert_eq!(outcome.served, Served::Refused(Fault::Client));
            assert_eq!(refusal_of(&outcome.answer), Some(code));
            assert_eq!(host.policy.loads.get(), 0);
            // The peer was identified, so the record says who it was.
            assert!(
                outcome.records[0]
                    .evidence
                    .contains(&format!("peer_pid={PID}"))
            );
        }
    }

    #[test]
    fn a_request_one_byte_over_the_limit_is_refused_without_being_parsed() {
        let mut host = Host::honest();
        let over = vec![b' '; MAX_REQUEST_BYTES + 1];
        let outcome = serve_with(&mut host, &connection(Ok(over)), Ok(&FakeSpool::new()));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::RequestTooLarge)
        );
    }

    #[test]
    fn a_malformed_request_is_refused_before_policy_or_spool_is_consulted() {
        let valid = BrokerRequest::new("/usr/bin/systemctl", vec!["restart".to_owned()], "x");
        let mut unknown: serde_json::Value = serde_json::from_str(&valid.to_json()).unwrap();
        unknown["skip_confirmation"] = serde_json::Value::Bool(true);
        let mut future = valid.clone();
        future.schema_version = WIRE_SCHEMA_VERSION + 1;
        let mut relative = valid.clone();
        relative.question = xudo_wire::Question::Run {
            program: "systemctl".to_owned(),
            argv: vec!["restart".to_owned()],
            claimed_classification: "x".to_owned(),
        };
        let mut nul = valid.clone();
        nul.question = xudo_wire::Question::Run {
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart\0--force".to_owned()],
            claimed_classification: "x".to_owned(),
        };
        let mut not_utf8 =
            br#"{"schema_version":2,"question":{"run":{"program":"/usr/bin/systemctl","argv":[""#
                .to_vec();
        not_utf8.extend_from_slice(b"\xff\"],\"claimed_classification\":\"x\"}}}");

        for (bytes, code) in [
            (b"restart nginx".to_vec(), RefusalCode::RequestMalformed),
            (not_utf8, RefusalCode::RequestNotUtf8),
            (
                unknown.to_string().into_bytes(),
                RefusalCode::RequestMalformed,
            ),
            (
                future.to_json().into_bytes(),
                RefusalCode::RequestWrongSchema,
            ),
            (
                relative.to_json().into_bytes(),
                RefusalCode::ProgramNotAbsolute,
            ),
            (nul.to_json().into_bytes(), RefusalCode::InteriorNul),
        ] {
            let mut host = Host::honest();
            let spool = FakeSpool::new();
            let outcome = serve_with(&mut host, &connection(Ok(bytes)), Ok(&spool));
            assert_eq!(outcome.served, Served::Refused(Fault::Client), "{code:?}");
            assert_eq!(refusal_of(&outcome.answer), Some(code));
            assert_eq!(host.policy.loads.get(), 0, "{code:?}");
            assert_eq!(spool.calls(), [], "{code:?}");
        }
    }

    #[test]
    fn a_spool_that_failed_its_checks_refuses_every_request() {
        let mut host = Host::honest();
        let untrusted = SpoolError::NotOwned {
            at: "/run/xudo/req".to_owned(),
            uid: 1000,
        };
        let outcome = serve_with(&mut host, &restart(), Err(&untrusted));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(outcome.served.exit_status(), UNUSABLE);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );
        assert_eq!(host.policy.loads.get(), 0);
        // The detail is root's to read, not the client's.
        let record = &outcome.records[0];
        assert!(record.evidence.iter().any(|e| e.contains("uid 1000")));
        assert_eq!(
            record.argv,
            ["/usr/bin/systemctl", "restart", "nginx.service"]
        );
    }

    #[test]
    fn a_policy_that_cannot_be_loaded_refuses_rather_than_deciding() {
        let mut host = Host::honest();
        host.policy.answer = Err(PolicyError::Config(xudo_gate::SettingsError::NotUtf8 {
            file: "/etc/xudo/config.toml".to_owned(),
        }));
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PolicyUnloadable)
        );
        assert_eq!(
            spool.calls(),
            [
                SpoolCall::Lock,
                SpoolCall::NamesUpTo(crate::mint::MAX_SPOOL_NAMES_TO_WALK),
                SpoolCall::Unlock
            ]
        );
    }

    #[test]
    fn no_nonce_means_no_entry() {
        let mut host = Host::honest();
        host.entropy = FakeEntropy::new().with(Err(SysError::unsupported("getrandom")));
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::BrokerUnusable)
        );
        assert_eq!(
            spool.calls(),
            [
                SpoolCall::Lock,
                SpoolCall::NamesUpTo(crate::mint::MAX_SPOOL_NAMES_TO_WALK),
                SpoolCall::Unlock
            ]
        );
        assert!(
            outcome.records[0]
                .evidence
                .iter()
                .any(|e| e.contains("cannot draw a nonce"))
        );
    }

    /// A live entry for another caller, under [`NONCE`].
    fn someone_elses_entry() -> PendingRequest {
        PendingRequest {
            schema_version: xudo_gate::request::REQUEST_SCHEMA_VERSION,
            nonce: NONCE.to_owned(),
            caller_pid: 7,
            caller_starttime: 7,
            action: "xudo.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "cron.service".to_owned()],
            generation: 1,
            deadline: BoottimeMillis(NOW + 60),
            confirmed: false,
            confirmed_by: None,
            state: xudo_gate::request::ConfirmationState::Pending,
            caller_uid: 1000,
            caller_sid: 10,
            caller_tty: 20,
            needs_watch: false,
            shown_at_ms: None,
            shown_to: None,
            fingerprint: "0".repeat(64),
            claimed_classification: "unattested".to_owned(),
            attested_class: xudo_gate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }

    /// Makes `entry`'s caller a running process of uid `uid`.
    fn running(host: &mut Host, entry: &PendingRequest, uid: u32) {
        let (pid, start) = (entry.caller_pid, entry.caller_starttime);
        host.peers = std::mem::take(&mut host.peers)
            .with_proc(pid, ProcFile::Stat, stat_line(pid, start))
            .with_proc(
                pid,
                ProcFile::Status,
                format!("Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            );
    }

    #[test]
    fn nothing_is_minted_when_the_audit_trail_refuses() {
        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("the journal is gone");
        let spool = FakeSpool::new();
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(outcome.served.exit_status(), UNUSABLE);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::BrokerUnusable)
        );
        assert_eq!(
            spool.calls(),
            [
                SpoolCall::Lock,
                SpoolCall::NamesUpTo(crate::mint::MAX_SPOOL_NAMES_TO_WALK),
                SpoolCall::Unlock
            ],
            "no entry without its record"
        );
        assert!(spool.files().is_empty());
    }

    #[test]
    fn a_denial_is_answered_even_when_there_is_no_trail_to_write() {
        let mut host = Host::honest();
        host.audit = FakeAuditSink::failing("the journal is gone");
        let outcome = serve_with(
            &mut host,
            &connection(Ok(BrokerRequest::new("/bin/sh", Vec::new(), "unattested")
                .to_json()
                .into_bytes())),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(outcome.served, Served::Decided);
    }

    #[test]
    fn a_colliding_nonce_is_refused_and_never_overwrites_a_pending_request() {
        let theirs = someone_elses_entry();
        let mut host = Host::honest();
        running(&mut host, &theirs, UID + 1);
        let spool = FakeSpool::new().with_file(NONCE, theirs.to_json());
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::NonceCollision)
        );
        assert_eq!(entry_in(&spool), theirs);
        // The decision was recorded before minting was attempted, and the
        // refusal after it, so the trail shows both.
        assert_eq!(outcome.records.len(), 2);
        assert_eq!(
            outcome.records[1].denial.as_deref(),
            Some("nonce_collision")
        );
    }

    #[test]
    fn a_full_spool_refuses_instead_of_growing() {
        let mut spool = FakeSpool::new();
        let mut host = Host::honest();
        for index in 0..MAX_SPOOL_ENTRIES {
            let mut live = someone_elses_entry();
            live.nonce = format!("{:064x}", index + 1);
            live.caller_pid = 10_000 + u32::try_from(index).unwrap();
            spool = spool.with_file(live.nonce.clone(), live.to_json());
            // Eight callers a uid: the spool is full of everyone, not of one.
            running(
                &mut host,
                &live,
                UID + 1 + u32::try_from(index.div_euclid(8)).unwrap(),
            );
        }
        let outcome = serve_with(&mut host, &restart(), Ok(&spool));
        assert_eq!(refusal_of(&outcome.answer), Some(RefusalCode::SpoolFull));
        // Other clients filled it; the broker refusing to grow it is the
        // broker working, so systemd is not told it failed.
        assert_eq!(outcome.served, Served::Refused(Fault::Client));
        assert_eq!(outcome.served.exit_status(), 0);
    }

    #[test]
    fn sixty_four_clients_that_ran_and_exited_cannot_lock_another_user_out() {
        // The review's attack: one user runs 64 clients one after another,
        // each gone before the next starts. The host shows none of them.
        let mut spool = FakeSpool::new();
        for index in 0..MAX_SPOOL_ENTRIES {
            let mut gone = someone_elses_entry();
            gone.nonce = format!("{:064x}", index + 1);
            gone.caller_pid = 10_000 + u32::try_from(index).unwrap();
            spool = spool.with_file(gone.nonce.clone(), gone.to_json());
        }
        let outcome = serve_with(&mut Host::honest(), &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Minted);
        assert_eq!(spool.files().len(), 1);
    }

    #[test]
    fn a_client_that_connects_and_exits_cannot_make_the_broker_report_itself_broken() {
        // A review connected and exited three times and got three instances
        // that exited 19 with fault=broker: SO_PEERPIDFD refuses a reaped peer
        // with EINVAL on 6.5 to 6.15; from 6.16 PIDFD_GET_INFO answers ESRCH;
        // on the pidfd_open rung, pidfd_open answers ESRCH. Each is the peer
        // leaving.
        let gone = |operation: &str, code: rustix::io::Errno| SysError::os(operation, &code.into());
        let reaped_before_so_peerpidfd = FakeSyscalls::new().with_peer(Err(gone(
            "getsockopt(SO_PEERPIDFD)",
            rustix::io::Errno::INVAL,
        )));
        let outlived_by_its_pidfd = FakeSyscalls::new()
            .with_peer(Ok(a_descriptor()))
            .with_info(Err(gone("ioctl(PIDFD_GET_INFO)", rustix::io::Errno::SRCH)));
        let gone_before_pidfd_open = FakeSyscalls::new().with_peer(Err(gone(
            "getsockopt(SO_PEERPIDFD)",
            rustix::io::Errno::NOPROTOOPT,
        )));
        for syscalls in [
            reaped_before_so_peerpidfd,
            outlived_by_its_pidfd,
            gone_before_pidfd_open,
        ] {
            let mut host = Host::honest();
            host.syscalls = syscalls;
            host.peers = FakePeer::new()
                .with_cred(Ok(PeerCred {
                    pid: PID,
                    uid: UID,
                    gid: GID,
                }))
                .with_open(Err(gone("pidfd_open", rustix::io::Errno::SRCH)));
            let outcome = serve_with(&mut host, &restart(), Ok(&FakeSpool::new()));
            assert_eq!(
                refusal_of(&outcome.answer),
                Some(RefusalCode::PeerUnidentified)
            );
            assert_eq!(outcome.served, Served::Refused(Fault::Client));
            assert_eq!(outcome.served.exit_status(), 0);
            assert!(
                outcome.records[0]
                    .evidence
                    .contains(&"fault=client".to_owned())
            );
        }
    }

    #[test]
    fn a_spool_that_fails_while_publishing_is_refused() {
        let mut host = Host::honest();
        let broken = SpoolError::Io {
            operation: "publish".to_owned(),
            at: "/run/xudo/req".to_owned(),
            code: None,
            reason: "no space left on device".to_owned(),
        };
        let outcome = serve_with(
            &mut host,
            &restart(),
            Ok(&FakeSpool::new().failing_publish(broken)),
        );
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );
    }

    #[test]
    fn a_client_that_leaves_before_its_answer_cannot_make_the_broker_fail() {
        // Minted or refused for its own fault, a client that went away is not
        // the broker failing: if it were, any group member could fill
        // systemd's record of failed units by hanging up.
        for conn in [restart(), connection(Err(ReadFailure::TimedOut))] {
            let mut host = Host::honest();
            let conn = conn.with_write_error(SysError::unsupported("peer gone"));
            let served = serve(&conn, &mut host.platform(), Ok(&FakeSpool::new()));
            assert_eq!(served, Served::Undelivered);
            assert_eq!(served.exit_status(), 0);
            // It was still recorded.
            assert!(!host.audit.records().is_empty());
        }
    }

    #[test]
    fn a_broken_broker_still_fails_when_its_client_has_left() {
        let mut host = Host::honest();
        let conn = restart().with_write_error(SysError::unsupported("peer gone"));
        let untrusted = SpoolError::NotADirectory {
            at: "/run/xudo/req".to_owned(),
        };
        let served = serve(&conn, &mut host.platform(), Err(&untrusted));
        assert_eq!(served, Served::Refused(Fault::Broker));
        assert_eq!(served.exit_status(), UNUSABLE);
    }

    #[test]
    fn a_permitted_decision_that_names_no_action_is_refused_not_minted() {
        // The engine never produces one; if it ever did, the gate would have
        // no action to look up, so the broker refuses rather than guessing.
        let mut host = Host::honest();
        let conn = restart();
        let spool = FakeSpool::new();
        let mut decision = Decision::deny(DenialCode::UnknownAction, Vec::new(), Vec::new());
        decision.verdict = Verdict::Allow;
        decision.denial = None;
        let request = BrokerRequest::new("/usr/bin/systemctl", Vec::new(), "x");
        let identity = identify(conn.socket(), &host.syscalls, &host.peers).unwrap();
        let evaluated = Evaluated {
            caller: crate::policy::classify(&identity),
            decision,
            identity,
            request,
            policy: policy(),
        };
        let served = mint(&conn, &mut host.platform(), &spool, evaluated);
        assert_eq!(served, Served::Refused(Fault::Broker));
        assert_eq!(spool.calls(), []);
        let answer = BrokerResponse::parse(&conn.written()).unwrap().answer;
        assert_eq!(refusal_of(&answer), Some(RefusalCode::BrokerUnusable));
        let detail = host.audit.records().last().unwrap().evidence.join(" ");
        assert!(
            detail.contains(&MintError::NoAction.to_string()),
            "{detail}"
        );
    }

    #[test]
    fn a_request_too_big_to_record_is_the_clients_fault_and_mints_nothing() {
        // Control characters grow sixfold in a JSON record, so a request under
        // the wire's limit can still overflow a log line.
        let mut host = Host::honest();
        let conn = restart();
        let spool = FakeSpool::new();
        let identity = identify(conn.socket(), &host.syscalls, &host.peers).unwrap();
        let caller = crate::policy::classify(&identity);
        let loaded = policy();
        let mut request = BrokerRequest::new(
            "/usr/bin/systemctl",
            vec!["restart".to_owned(), "nginx.service".to_owned()],
            "x",
        );
        let decision = decide(&loaded, &caller, &request);
        request.question = xudo_wire::Question::Run {
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "\u{1}".repeat(12_000)],
            claimed_classification: "x".to_owned(),
        };
        let evaluated = Evaluated {
            decision,
            caller,
            identity,
            request,
            policy: loaded,
        };
        let served = mint(&conn, &mut host.platform(), &spool, evaluated);
        assert_eq!(served, Served::Refused(Fault::Client));
        assert_eq!(spool.calls(), []);
        let answer = BrokerResponse::parse(&conn.written()).unwrap().answer;
        assert_eq!(refusal_of(&answer), Some(RefusalCode::RequestTooLarge));
    }

    #[test]
    fn the_exit_status_separates_a_broken_broker_from_a_refused_client() {
        assert_eq!(Served::Minted.exit_status(), 0);
        assert_eq!(Served::Decided.exit_status(), 0);
        assert_eq!(Served::Refused(Fault::Client).exit_status(), 0);
        assert_eq!(Served::Refused(Fault::Broker).exit_status(), UNUSABLE);
        assert_eq!(Served::Undelivered.exit_status(), 0);
    }

    /// What an answer or a freeze did, with every field that could carry a
    /// claim or a watcher fact left out.
    #[derive(Debug, PartialEq)]
    struct Redecided {
        refused: Option<RefusalCode>,
        labels: Vec<String>,
        verdicts: Vec<xudo_audit::record::Decision>,
        denials: Vec<Option<String>>,
        after: Option<xudo_gate::request::ConfirmationState>,
    }

    fn approved_entry(class: xudo_gate::request::AttestedClass, claim: &str) -> PendingRequest {
        let mut entry = shown_entry();
        stored_as(&mut entry, class);
        claim.clone_into(&mut entry.claimed_classification);
        entry.state = xudo_gate::request::ConfirmationState::Approved;
        entry.confirmed = true;
        entry.confirmed_by = entry.shown_to.clone();
        entry
    }

    fn class_label(class: &xudo_gate::request::AttestedClass) -> &'static str {
        stored_caller(&PendingRequest {
            attested_class: class.clone(),
            ..shown_entry()
        })
        .classification
        .label()
    }

    fn stored_state(spool: &FakeSpool) -> Option<xudo_gate::request::ConfirmationState> {
        let files = spool.files();
        let bytes = files.get(NONCE.as_bytes())?;
        PendingRequest::parse(std::str::from_utf8(bytes).unwrap())
            .ok()
            .map(|entry| entry.state)
    }

    fn redecided(host: &Host, spool: &FakeSpool, refused: Option<RefusalCode>) -> Redecided {
        let records = host.audit.records();
        Redecided {
            refused,
            labels: records.iter().map(|r| r.classification.clone()).collect(),
            verdicts: records.iter().map(|r| r.decision).collect(),
            denials: records.iter().map(|r| r.denial.clone()).collect(),
            after: stored_state(spool),
        }
    }

    /// The answer path, called at the function level: the entry is already
    /// marked answered, as `confirm::answer` leaves it.
    fn answered_by(entry: &PendingRequest, watcher: &PeerIdentity, approve: bool) -> Redecided {
        let mut answered = entry.clone();
        answered.state = if approve {
            xudo_gate::request::ConfirmationState::Approved
        } else {
            xudo_gate::request::ConfirmationState::Denied
        };
        let mut pending = entry.clone();
        pending.state = xudo_gate::request::ConfirmationState::Pending;
        pending.confirmed = false;
        pending.confirmed_by = None;
        let bytes = pending.to_json().into_bytes();
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone());
        let mut host = Host::honest();
        let result = complete_answer(
            &mut host.platform(),
            &spool,
            watcher,
            &answer_request(NONCE, "remove", approve),
            AnsweredEntry {
                id: NONCE.to_owned(),
                bytes,
                entry: answered,
            },
            approve,
        );
        redecided(&host, &spool, result.err().map(|e| e.code))
    }

    fn frozen_by(entry: &PendingRequest, freezer: &PeerIdentity) -> Redecided {
        let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), entry.to_json());
        let mut host = Host::honest();
        let result = deny_pending(&mut host.platform(), &spool, freezer, &freeze_request());
        redecided(&host, &spool, result.err().map(|e| e.code))
    }

    fn arbitrary_watcher(
        pid: u32,
        uid: u32,
        sid: i64,
        tty: i64,
        cgroup: Option<u64>,
    ) -> PeerIdentity {
        let mut identity = test_identity(pid, START + 5, sid, tty);
        identity.uid = uid;
        identity.cgroup_id = cgroup;
        identity
    }

    proptest::proptest! {
        #[test]
        fn a_watchers_classification_never_changes_the_requesters_decision(
            pid in 1u32..,
            uid in proptest::prelude::any::<u32>(),
            sid in proptest::prelude::any::<i64>(),
            tty in proptest::prelude::any::<i64>(),
            cgroup in proptest::option::of(proptest::prelude::any::<u64>()),
            stored in 0u8..3,
            approve in proptest::prelude::any::<bool>(),
        ) {
            use xudo_gate::request::AttestedClass;
            let class = match stored {
                0 => AttestedClass::Unattested,
                1 => AttestedClass::Human,
                _ => AttestedClass::EnrolledAgent { scope_id: 44 },
            };
            let label = class_label(&class);
            let entry = approved_entry(class, "unattested");
            let baseline = arbitrary_watcher(5000, UID, 2, 34816, None);
            let other = arbitrary_watcher(pid, uid, sid, tty, cgroup);
            let by_baseline = answered_by(&entry, &baseline, approve);
            let by_other = answered_by(&entry, &other, approve);
            // The labels are the stored class's, whoever answers. The old
            // re-decision classified the watcher and recorded "unattested".
            proptest::prop_assert_eq!(&by_other.labels, &[label.to_owned()]);
            proptest::prop_assert_eq!(by_baseline, by_other);
            // A freeze reaches only the freezer's own uid (or all, for root),
            // so the comparison holds the freezer's uid at the entry's.
            let mut same_uid = other.clone();
            same_uid.uid = UID;
            proptest::prop_assert_eq!(frozen_by(&entry, &baseline), frozen_by(&entry, &same_uid));
        }

        #[test]
        fn an_attacker_controlled_claim_never_reaches_the_decision(
            claim in proptest::prop_oneof![
                proptest::prelude::any::<String>(),
                "enrolled-agent.*",
                proptest::prelude::Just("enrolled-agent-yolo".to_string()),
                proptest::prelude::Just("human".to_string()),
                proptest::prelude::Just("unattested".to_string()),
            ],
            stored in 0u8..3,
            approve in proptest::prelude::any::<bool>(),
        ) {
            use xudo_gate::request::AttestedClass;
            let class = || match stored {
                0 => AttestedClass::Unattested,
                1 => AttestedClass::Human,
                _ => AttestedClass::EnrolledAgent { scope_id: 44 },
            };
            let watcher = arbitrary_watcher(5000, UID, 2, 34816, None);
            let plain = approved_entry(class(), "unattested");
            let claimed = approved_entry(class(), &claim);
            proptest::prop_assert_eq!(
                answered_by(&plain, &watcher, approve),
                answered_by(&claimed, &watcher, approve)
            );
            proptest::prop_assert_eq!(frozen_by(&plain, &watcher), frozen_by(&claimed, &watcher));
        }
    }

    fn purge_entry(class: xudo_gate::request::AttestedClass) -> PendingRequest {
        let mut entry = approved_entry(class, "unattested");
        entry.action = "xudo.pkg.purge-human".to_owned();
        entry.argv = vec!["purge".to_owned(), "gcc".to_owned()];
        entry
    }

    #[test]
    fn a_watchers_approval_cannot_escalate_an_agent_entry_past_agent_allowed_false() {
        use xudo_gate::request::{AttestedClass, ConfirmationState};
        let watcher = arbitrary_watcher(5000, UID, 2, 34816, None);
        // Stored as an agent: approve is refused as human-path-only, and the
        // entry is not turned into an approval. Deny still works.
        let agent = purge_entry(AttestedClass::EnrolledAgent { scope_id: 44 });
        let refused = answered_by(&agent, &watcher, true);
        assert_eq!(refused.refused, Some(RefusalCode::PolicyUnloadable));
        assert!(refused.labels.is_empty());
        assert_eq!(refused.after, Some(ConfirmationState::Pending));
        let denied = answered_by(&agent, &watcher, false);
        assert_eq!(denied.refused, None);
        assert_eq!(denied.labels, ["enrolled-agent"]);
        assert_eq!(denied.denials, [Some("confirmation_refused".to_owned())]);
        // The same action, stored as unattested, is approved: the old
        // re-decision as the watcher's class did exactly that for the agent.
        let human = purge_entry(AttestedClass::Unattested);
        let approved = answered_by(&human, &watcher, true);
        assert_eq!(approved.refused, None);
        assert_eq!(approved.labels, ["unattested"]);
        assert_eq!(approved.after, Some(ConfirmationState::Approved));
    }

    #[test]
    fn the_engine_ignores_the_stored_callers_placeholder_names() {
        use xudo_policy::Classification;
        let policy = policy();
        let entry = enrolled_entry(NONCE, UID);
        let request = BrokerRequest::new(entry.program.clone(), entry.argv.clone(), "x");
        let baseline = stored_caller(&entry);
        let expected = decide(&policy, &baseline, &request);
        for yolo in [false, true] {
            for (agent, session) in [("scope-44", "stored"), ("", ""), ("root", "other")] {
                let mut caller = baseline.clone();
                caller.classification = Classification::EnrolledAgent {
                    agent_id: agent.to_owned(),
                    session_id: session.to_owned(),
                    declared_yolo: yolo,
                };
                let got = decide(&policy, &caller, &request);
                assert_eq!(got.verdict, expected.verdict);
                assert_eq!(got.denial, expected.denial);
            }
        }
    }

    #[test]
    fn a_claimed_class_never_appears_as_the_shown_classification() {
        use xudo_gate::request::AttestedClass;
        for claim in ["enrolled-agent-yolo", "human", "unattested", "x"] {
            for class in [
                AttestedClass::Unattested,
                AttestedClass::Human,
                AttestedClass::EnrolledAgent { scope_id: 44 },
            ] {
                let mut entry = shown_entry();
                stored_as(&mut entry, class.clone());
                claim.clone_into(&mut entry.claimed_classification);
                let prompt = bounded_prompt(&entry, NOW);
                assert_eq!(prompt.classification, class_label(&class));
            }
        }
    }

    #[test]
    fn a_claimed_agent_class_on_a_human_entry_does_not_make_it_an_agent_entry() {
        use xudo_gate::request::AttestedClass::Human;
        let watcher = arbitrary_watcher(5000, UID, 2, 34816, None);
        let mut entry = approved_entry(Human, "enrolled-agent-yolo");
        entry.state = xudo_gate::request::ConfirmationState::Pending;
        entry.confirmed = false;
        entry.confirmed_by = None;
        // Freeze leaves it alone: the password path stays open for a human.
        let frozen = frozen_by(&entry, &watcher);
        assert_eq!(
            frozen.after,
            Some(xudo_gate::request::ConfirmationState::Pending)
        );
        assert!(frozen.labels.is_empty());
        // Deny re-decides it as a human, whatever it claimed.
        let denied = answered_by(&entry, &watcher, false);
        assert_eq!(denied.labels, ["human"]);
        assert_eq!(denied.refused, None);
    }

    #[test]
    fn a_freeze_takes_back_exactly_the_stored_agent_class() {
        use xudo_gate::request::AttestedClass::{Human, Unattested};
        let freezer = arbitrary_watcher(5000, UID, 2, 34816, None);
        let mut agent = enrolled_entry(NONCE, UID);
        // An agent that claims nothing is still an agent.
        "human".clone_into(&mut agent.claimed_classification);
        let frozen = frozen_by(&agent, &freezer);
        assert_eq!(frozen.after, None);
        assert_eq!(frozen.labels, ["enrolled-agent"]);
        // An unattested or human entry claiming to be an agent is kept.
        for class in [Unattested, Human] {
            let mut entry = enrolled_entry(NONCE, UID);
            stored_as(&mut entry, class);
            let kept = frozen_by(&entry, &freezer);
            assert_eq!(
                kept.after,
                Some(xudo_gate::request::ConfirmationState::Pending)
            );
            assert!(kept.labels.is_empty());
        }
    }

    #[test]
    fn an_answer_is_decided_as_the_stored_class_whoever_answers() {
        use xudo_gate::request::AttestedClass::{EnrolledAgent, Human, Unattested};
        let watcher = arbitrary_watcher(5000, UID, 2, 34816, None);
        for (class, label) in [
            (Unattested, "unattested"),
            (Human, "human"),
            (EnrolledAgent { scope_id: 44 }, "enrolled-agent"),
        ] {
            let denied = answered_by(&approved_entry(class, "enrolled-agent"), &watcher, false);
            assert_eq!(denied.labels, [label]);
            assert_eq!(denied.after, None);
        }
    }

    #[test]
    fn an_entry_with_an_unparseable_or_missing_stored_class_fails_closed() {
        let watcher = arbitrary_watcher(5000, UID, 2, 34816, None);
        let entry = enrolled_entry(NONCE, UID);
        let good: serde_json::Value = serde_json::from_str(&entry.to_json()).unwrap();
        let mangled = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut value = good.clone();
            edit(&mut value);
            serde_json::to_vec(&value).unwrap()
        };
        let broken = [
            mangled(&|v| v["attested_class"] = serde_json::json!("root")),
            mangled(&|v| {
                v.as_object_mut().unwrap().remove("attested_class");
            }),
            mangled(&|v| {
                v["attested_class"] = serde_json::json!({"enrolled_agent": {"scope_id": 9}});
            }),
            mangled(&|v| v["attested_scope_id"] = serde_json::Value::Null),
        ];
        for bytes in broken {
            // Answering refuses and changes nothing.
            let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone());
            let mut host = Host::honest();
            let refused = answer_confirmation(
                &mut host.platform(),
                &spool,
                &watcher,
                &answer_request(NONCE, "remove", true),
            )
            .unwrap_err();
            assert_eq!(refused.code, RefusalCode::RequestUnknown);
            assert_eq!(spool.files()[NONCE.as_bytes()], bytes);
            assert!(host.audit.records().is_empty());
            // A freeze never acts on it either: nothing is decided or removed.
            let spool = FakeSpool::new().with_file(NONCE.as_bytes().to_vec(), bytes.clone());
            let mut host = Host::honest();
            deny_pending(&mut host.platform(), &spool, &watcher, &freeze_request()).unwrap();
            assert_eq!(spool.files()[NONCE.as_bytes()], bytes);
            assert!(host.audit.records().is_empty());
        }
    }
    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Over a spool of human, unattested and enrolled-agent entries of
        /// several uids, in every state, a freeze takes back exactly the live
        /// enrolled-agent entries in its scope (the freezer's own uid, or
        /// everyone's for root) and leaves every other byte alone.
        #[test]
        fn freeze_never_denies_a_human_entry(
            rows in proptest::collection::vec((0usize..4, 0u8..3, 0u8..3), 1..12),
            freezer in 0usize..4,
        ) {
            use xudo_gate::request::{AttestedClass, ConfirmationState};
            let uids = [0u32, 1000, 2000, 3000];
            let freezer_uid = uids[freezer];
            let spool = FakeSpool::new();
            let mut expected_taken = Vec::new();
            let mut before = std::collections::BTreeMap::new();
            for (index, (uid_at, class, state)) in rows.into_iter().enumerate() {
                let uid = uids[uid_at];
                let nonce = format!("{:064x}", index + 1);
                let mut entry = enrolled_entry(&nonce, uid);
                match class {
                    0 => stored_as(&mut entry, AttestedClass::Human),
                    1 => stored_as(&mut entry, AttestedClass::Unattested),
                    _ => {}
                }
                entry.state = match state {
                    0 => ConfirmationState::Pending,
                    1 => ConfirmationState::Approved,
                    _ => ConfirmationState::Denied,
                };
                let live_agent = class == 2 && state < 2;
                if live_agent && (freezer_uid == 0 || uid == freezer_uid) {
                    expected_taken.push(nonce.clone());
                }
                before.insert(nonce.clone().into_bytes(), entry.to_json().into_bytes());
                spool.publish(&nonce, entry.to_json().as_bytes()).unwrap();
            }
            let mut identity = test_identity(PID, START, 0, 0);
            identity.uid = freezer_uid;
            let mut host = Host::honest_as(freezer_uid);
            deny_pending(&mut host.platform(), &spool, &identity, &freeze_request()).unwrap();
            let after = spool.files();
            for (name, bytes) in &before {
                let nonce = String::from_utf8(name.clone()).unwrap();
                if expected_taken.contains(&nonce) {
                    proptest::prop_assert!(!after.contains_key(name));
                } else {
                    proptest::prop_assert_eq!(after.get(name), Some(bytes));
                }
            }
        }
    }
}
