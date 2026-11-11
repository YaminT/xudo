//! Minting: the spool entry the gate will act on, and the rules of the spool
//! it goes into.
//!
//! An entry is minted only for a permitted decision. On the password path a
//! decision that demands confirmation is permitted too — the password `sudo`
//! asks for *is* the confirmation — so it
//! mints with `confirmed = false`, and the gate's `-auth` name is what tells
//! the gate a password was typed.
//!
//! # The spool's rules
//!
//! Applied under the spool's exclusive lock, every time an entry is minted:
//!
//! * **One gate lookup entry per caller.** A pending or approved watch entry
//!   for the same `(pid, starttime)` refuses a new run and stays in place; a
//!   non-watch or consumed entry is superseded so the gate's lookup finds one
//!   entry or none, never two to choose between.
//! * **Expired entries go.** Non-watch entries and non-waiting watch entries
//!   at or past their deadline are removed; waiting watch entries remain for
//!   the audited expiry sweep, then for a 60-second fallback grace.
//! * **Entries nobody can use go.** A non-watch entry whose caller is no longer the
//!   process it was minted for — exited, or its pid now someone else's — can
//!   never be consumed: the gate checks its own caller against the pin. So an
//!   entry counts as live only while `/proc/<pid>/stat` still shows the pinned
//!   `(pid, starttime)`, and a caller that cannot be shown alive is pruned.
//!   Without this, one group member could run 64 clients one after another,
//!   each exiting before the next, and refuse everyone for fifteen minutes.
//!   Pending and approved watch entries are different: timeout-zero clients
//!   exit by design, so those entries remain until the audited expiry sweep.
//! * **Junk goes.** A temporary file left by a broker that died mid-write —
//!   no write can be in progress while the lock is held — and any nonce-named
//!   entry that cannot be read back as a request.
//! * **Bounded.** The password path has its own [`MAX_SPOOL_ENTRIES`] entry,
//!   [`MAX_SPOOL_BYTES`] byte, and [`MAX_ENTRIES_PER_UID`] per-uid limits.
//!   Watch entries have separate [`MAX_WATCH_ENTRIES`] and
//!   [`MAX_WATCH_ENTRIES_PER_UID`] limits, so watcher requests cannot consume
//!   the password path's capacity.
//!   The entry does not record a uid, so the count reads each live caller's
//!   real and effective uids from `/proc/<pid>/status` and counts the entry
//!   against both: a caller that exec'd a set-user-ID program after minting
//!   keeps its real uid, so it stays on its user's share.
//!
//! Names that are neither nonces nor temporary files are left alone: only root
//! can create them, and the broker removes only what it can identify as its
//! own.

use std::fmt::Write as _;

use xudo_audit::Approval;
use xudo_gate::request::{
    AttestedClass, BoottimeMillis, PendingRequest, REQUEST_SCHEMA_VERSION, is_boot_id, is_nonce,
};
use xudo_policy::{CallerFacts, Classification, Decision};
use xudo_sys::{
    Authorized, Entropy, PeerCalls, ProcFile, Spool, SpoolError, StatusUids, SysError, TEMP_PREFIX,
    parse_stat, parse_status_uids,
};
use xudo_wire::BrokerRequest;

use crate::identify::PeerIdentity;

/// How long a minted entry lives in the test-only short-TTL build: twenty seconds.
#[cfg(feature = "lane-short-ttl")]
pub const REQUEST_TTL_SECS: u64 = 20;
/// How long a minted entry lives, in seconds: fifteen minutes.
///
/// Long enough for `sudo`'s whole conversation at its defaults —
/// `passwd_timeout` is five minutes per prompt and `passwd_tries` is three —
/// so a human who mistypes twice slowly is not refused for being human. Short
/// enough that an entry for a process that died does not outlive the session
/// it belonged to by much; and the entry is bound to that process's
/// `(pid, starttime)` and consumed on use, so its lifetime is not the window
/// in which it can be abused.
#[cfg(not(feature = "lane-short-ttl"))]
pub const REQUEST_TTL_SECS: u64 = 15 * 60;
/// Request lifetime in the clock's millisecond unit.
pub const REQUEST_TTL_MILLIS: u64 = REQUEST_TTL_SECS * 1_000;

#[cfg(feature = "lane-short-ttl")]
#[used]
static XUDOD_LANE_SHORT_TTL_MARKER: &[u8] = b"xudo-lane-short-ttl-20-seconds";

#[cfg(feature = "lane-short-ttl")]
#[inline(never)]
fn keep_lane_short_ttl_marker_linked() {
    std::hint::black_box(XUDOD_LANE_SHORT_TTL_MARKER);
}

/// Extra time an expired watch request stays available for the audited expiry
/// sweep before a mint may prune it when the confirmation store is absent.
const EXPIRED_WATCH_GRACE_MILLIS: u64 = 60_000;

/// The most live entries the spool holds.
pub const MAX_SPOOL_ENTRIES: usize = 64;

/// The most bytes of live entries the spool holds.
pub const MAX_SPOOL_BYTES: usize = 1024 * 1024;

/// The most live entries whose callers run as one uid: an eighth of the
/// spool.
///
/// One caller holds at most one entry, so this is eight `xudo` processes of
/// one user waiting on `sudo` at once — the same number of connections the
/// socket lets one uid hold open (`MaxConnectionsPerSource=`).
pub const MAX_ENTRIES_PER_UID: usize = 8;

/// The most waiting watch entries across all users.
pub const MAX_WATCH_ENTRIES: usize = 16;

/// The most waiting watch entries belonging to one uid.
pub const MAX_WATCH_ENTRIES_PER_UID: usize = 2;

/// Number of spool names broker scans must request to cover every live entry
/// and distinguish a spool that exceeds the broker's own limits.
pub const MAX_SPOOL_NAMES_TO_WALK: usize = MAX_SPOOL_ENTRIES + MAX_WATCH_ENTRIES + 1;

// One uid must never be able to take the whole spool.
const _: () = assert!(MAX_ENTRIES_PER_UID < MAX_SPOOL_ENTRIES);
const _: () = assert!(MAX_WATCH_ENTRIES_PER_UID < MAX_WATCH_ENTRIES);
const _: () = assert!(MAX_SPOOL_NAMES_TO_WALK == MAX_SPOOL_ENTRIES + MAX_WATCH_ENTRIES + 1);
const _: () = assert!(MAX_WATCH_ENTRIES * MAX_ENTRY_BYTES <= MAX_SPOOL_BYTES);

/// The largest entry the broker reads back, in bytes.
///
/// Comfortably above anything it writes: an entry is a request of at most
/// `xudo_wire::MAX_REQUEST_BYTES` plus fields of known size.
pub const MAX_ENTRY_BYTES: usize = 32 * 1024;

// An entry the broker wrote must always be one it can read back.
const _: () = assert!(MAX_ENTRY_BYTES > xudo_wire::MAX_REQUEST_BYTES);

// And a spool kept within the broker's limits must be one the gate will walk
// and read: it refuses a spool with more names than `MAX_SPOOL_NAMES` and
// reads no entry past its own `MAX_ENTRY_BYTES`. The broker's ceilings sit
// well below the gate's, so the gate's bounds only ever bite on a spool the
// broker did not keep.
const _: () = assert!(MAX_ENTRY_BYTES <= xudo_gate::run::MAX_ENTRY_BYTES);

/// Random bytes in a nonce: 32, so 64 hex characters.
const NONCE_BYTES: usize = 32;

/// Why an entry could not be minted. Every variant refuses the request.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MintError {
    /// A permitted decision names no action.
    ///
    /// The engine never produces one; refused rather than assumed, because
    /// the gate looks the action up by this name.
    #[error("a permitted decision names no action, so the gate would have nothing to look up")]
    NoAction,
    /// An agent classification lacks the kernel cgroup id needed to bind it.
    #[error("the broker could not bind the agent to a valid cgroup scope and boot id")]
    NoAttestedScope,
    /// The spool refused an operation.
    #[error(transparent)]
    Spool(SpoolError),
    /// The spool is at its limits.
    #[error(
        "the spool holds {entries} live entries and {bytes} bytes; the limits are \
         {MAX_SPOOL_ENTRIES} entries and {MAX_SPOOL_BYTES} bytes"
    )]
    Full {
        /// Live entries.
        entries: usize,
        /// Their bytes.
        bytes: usize,
    },
    /// The asking uid's live callers hold as many entries as one uid may.
    #[error(
        "uid {uid} already holds {entries} live entries; the limit for one uid is \
         {MAX_ENTRIES_PER_UID}"
    )]
    UidFull {
        /// The uid that asked.
        uid: u32,
        /// The live entries counted against it.
        entries: usize,
    },
    /// The nonce already names an entry.
    #[error("nonce {nonce} already names a pending request")]
    Collision {
        /// The nonce drawn.
        nonce: String,
    },
    /// This process already has a pending or approved watched request.
    #[error("watch confirmation is throttled by a per-process or capacity limit")]
    ConfirmationThrottled,
}

pub(crate) struct AttestedCaller<'a> {
    pub(crate) identity: &'a PeerIdentity,
    pub(crate) facts: &'a CallerFacts,
    pub(crate) boot_id: Option<&'a str>,
}

/// The entry as an approval: the command and action its audit record must
/// carry before the broker may mint it.
#[derive(Clone, Debug)]
pub struct Grant(pub PendingRequest);

impl Grant {
    /// The entry's command, program first.
    pub fn command_of(entry: &PendingRequest) -> Vec<String> {
        let mut command = vec![entry.program.clone()];
        command.extend(entry.argv.iter().cloned());
        command
    }
}

impl Approval for Grant {
    fn command(&self) -> Vec<String> {
        Self::command_of(&self.0)
    }

    fn action(&self) -> &str {
        &self.0.action
    }
}

/// An entry about to be published, and whose share of the spool it takes.
#[derive(Clone, Copy, Debug)]
pub struct Minting<'a> {
    /// The entry, whose record is on the trail.
    pub authorized: &'a Authorized<Grant>,
    /// The entry as it is written.
    pub json: &'a str,
    /// The effective uid its caller connected with.
    pub uid: u32,
    /// Now, in milliseconds of `CLOCK_BOOTTIME`.
    pub now: u64,
}

impl Minting<'_> {
    fn entry(&self) -> &PendingRequest {
        &self.authorized.approval().0
    }
}

/// Draws a fresh nonce: 32 random bytes, as 64 lowercase hex characters.
///
/// # Errors
///
/// Whatever the random source refuses with. A nonce is never built from
/// fewer bytes than asked for.
pub fn draw_nonce(entropy: &dyn Entropy) -> Result<String, SysError> {
    let mut bytes = [0u8; NONCE_BYTES];
    entropy.fill(&mut bytes)?;
    Ok(bytes.iter().fold(
        String::with_capacity(NONCE_BYTES.saturating_mul(2)),
        |mut hex, byte| {
            // Writing into a String cannot fail.
            let _ = write!(hex, "{byte:02x}");
            hex
        },
    ))
}

/// The spool entry for a permitted decision.
///
/// The program and operands are the request's, exactly as asked — the gate
/// canonicalizes them itself, the same way — and the action is the one the
/// decision matched. Nothing in the entry comes from the request but the
/// question and the unauthenticated claim, which the gate records and
/// ignores.
///
/// # Errors
///
/// [`MintError::NoAction`] if the decision names no action.
pub fn entry_for(
    decision: &Decision,
    identity: &PeerIdentity,
    request: &BrokerRequest,
    generation: u64,
    confirm_human_path: bool,
    deadline: u64,
    nonce: String,
) -> Result<PendingRequest, MintError> {
    let caller = crate::policy::classify(identity);
    entry_for_classified(
        decision,
        &AttestedCaller {
            identity,
            facts: &caller,
            boot_id: None,
        },
        request,
        generation,
        confirm_human_path,
        deadline,
        nonce,
    )
}

pub(crate) fn entry_for_classified(
    decision: &Decision,
    attested: &AttestedCaller<'_>,
    request: &BrokerRequest,
    generation: u64,
    confirm_human_path: bool,
    deadline: u64,
    nonce: String,
) -> Result<PendingRequest, MintError> {
    let AttestedCaller {
        identity,
        facts: caller,
        boot_id,
    } = attested;
    let Some(action) = &decision.action else {
        return Err(MintError::NoAction);
    };
    let Some((program, argv, claimed_classification)) = request.run_fields() else {
        return Err(MintError::NoAction);
    };
    let (attested_class, attested_scope_id, boot_id) = match &caller.classification {
        Classification::Unattested { .. } => (AttestedClass::Unattested, None, None),
        Classification::Human => (AttestedClass::Human, None, None),
        Classification::EnrolledAgent { .. } => {
            let Some(scope_id) = identity.cgroup_id else {
                return Err(MintError::NoAttestedScope);
            };
            let Some(boot_id) = boot_id.filter(|id| is_boot_id(id)) else {
                return Err(MintError::NoAttestedScope);
            };
            (
                AttestedClass::EnrolledAgent { scope_id },
                Some(scope_id),
                Some(boot_id.to_owned()),
            )
        }
    };
    Ok(PendingRequest {
        schema_version: REQUEST_SCHEMA_VERSION,
        nonce,
        caller_pid: identity.pid,
        caller_starttime: identity.starttime,
        action: action.as_str().to_owned(),
        program: program.to_owned(),
        argv: argv.to_vec(),
        generation,
        deadline: BoottimeMillis(deadline),
        confirmed: false,
        confirmed_by: None,
        state: xudo_gate::request::ConfirmationState::Pending,
        caller_uid: identity.uid,
        caller_sid: identity.sid,
        caller_tty: identity.tty,
        needs_watch: xudo_gate::demanded_confirmation(decision) && confirm_human_path,
        shown_at_ms: None,
        shown_to: None,
        fingerprint: crate::confirm::fingerprint(
            identity.uid,
            program.as_bytes(),
            &argv.iter().map(String::as_bytes).collect::<Vec<_>>(),
        ),
        claimed_classification: claimed_classification.to_owned(),
        attested_class,
        attested_scope_id,
        boot_id,
    })
}

/// Publishes an entry under the spool's lock, after applying the spool's
/// rules (see the module docs).
///
/// `callers` is how the live entries' callers are looked up in `/proc`.
///
/// # Errors
///
/// [`MintError::Spool`] if the spool refuses an operation,
/// [`MintError::Full`] at its limits, [`MintError::UidFull`] at the asking
/// uid's, and [`MintError::Collision`] if the nonce is taken. The lock is
/// released on every path.
pub fn publish<S: Spool + ?Sized>(
    spool: &S,
    callers: &dyn PeerCalls,
    minting: &Minting<'_>,
) -> Result<(), MintError> {
    #[cfg(feature = "lane-short-ttl")]
    keep_lane_short_ttl_marker_linked();

    spool.lock().map_err(MintError::Spool)?;
    let published = prune_and_publish(spool, callers, minting);
    spool.unlock();
    published
}

/// The body of [`publish`], run with the lock held.
fn prune_and_publish<S: Spool + ?Sized>(
    spool: &S,
    callers: &dyn PeerCalls,
    minting: &Minting<'_>,
) -> Result<(), MintError> {
    let mut entries = 0usize;
    let mut bytes = 0usize;
    let mut this_uid = 0usize;
    let mut watch_entries = 0usize;
    let mut watch_uid = 0usize;
    for name in spool.names().map_err(MintError::Spool)? {
        match classify(spool, callers, &name, minting) {
            Existing::Live {
                size,
                same_uid,
                watch,
            } => {
                if watch {
                    watch_entries = watch_entries.saturating_add(1);
                    watch_uid = watch_uid.saturating_add(usize::from(same_uid));
                } else {
                    entries = entries.saturating_add(1);
                    bytes = bytes.saturating_add(size);
                    this_uid = this_uid.saturating_add(usize::from(same_uid));
                }
            }
            Existing::Stale => spool.remove(&name).map_err(MintError::Spool)?,
            Existing::ConfirmationThrottled => return Err(MintError::ConfirmationThrottled),
            Existing::Foreign => {}
        }
    }
    if minting.entry().needs_watch {
        if watch_entries >= MAX_WATCH_ENTRIES || watch_uid >= MAX_WATCH_ENTRIES_PER_UID {
            return Err(MintError::ConfirmationThrottled);
        }
    } else {
        if entries >= MAX_SPOOL_ENTRIES
            || bytes.saturating_add(minting.json.len()) > MAX_SPOOL_BYTES
        {
            return Err(MintError::Full { entries, bytes });
        }
        if this_uid >= MAX_ENTRIES_PER_UID {
            return Err(MintError::UidFull {
                uid: minting.uid,
                entries: this_uid,
            });
        }
    }
    match spool.publish(&minting.entry().nonce, minting.json.as_bytes()) {
        Ok(()) => Ok(()),
        Err(SpoolError::Exists { .. }) => Err(MintError::Collision {
            nonce: minting.entry().nonce.clone(),
        }),
        Err(error) => Err(MintError::Spool(error)),
    }
}

/// What a name already in the spool is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Existing {
    /// A live entry for someone else.
    Live {
        /// Its length in bytes.
        size: usize,
        /// Whether its caller runs as the asking uid, really or effectively.
        same_uid: bool,
        /// Whether the entry uses the separate watch quota.
        watch: bool,
    },
    /// Something to remove: expired, superseded, misnamed, unreadable, a
    /// temporary file, or a non-watch entry whose caller cannot be shown alive.
    Stale,
    /// The asking process already has a waiting watched request.
    ConfirmationThrottled,
    /// A name the broker does not own.
    Foreign,
}

/// Decides what one name in the spool is.
fn classify<S: Spool + ?Sized>(
    spool: &S,
    callers: &dyn PeerCalls,
    name: &[u8],
    minting: &Minting<'_>,
) -> Existing {
    if name.starts_with(TEMP_PREFIX.as_bytes()) {
        // The lock is held, so no write is in progress: a broker died here.
        return Existing::Stale;
    }
    let Ok(text) = std::str::from_utf8(name) else {
        return Existing::Foreign;
    };
    if !is_nonce(text) {
        return Existing::Foreign;
    }
    let Ok(bytes) = spool.read(name, MAX_ENTRY_BYTES) else {
        return Existing::Stale;
    };
    let parsed = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|json| PendingRequest::parse(json).ok());
    let Some(existing) = parsed else {
        return Existing::Stale;
    };
    let misnamed = existing.nonce != text;
    if misnamed {
        return Existing::Stale;
    }
    let request_survives_requester = existing.needs_watch
        && matches!(
            existing.state,
            xudo_gate::request::ConfirmationState::Pending
                | xudo_gate::request::ConfirmationState::Approved
        );
    let same_pin = existing.caller_pid == minting.entry().caller_pid
        && existing.caller_starttime == minting.entry().caller_starttime;
    let past_watch_grace = existing
        .deadline
        .0
        .saturating_add(EXPIRED_WATCH_GRACE_MILLIS)
        <= minting.now;
    if request_survives_requester && past_watch_grace {
        return Existing::Stale;
    }
    // A watched request owns the caller's gate lookup slot until the audited
    // expiry sweep runs, or until the grace period permits fallback pruning.
    if request_survives_requester && same_pin {
        return Existing::ConfirmationThrottled;
    }
    let superseded = same_pin;
    if superseded {
        return Existing::Stale;
    }
    let expired = existing.deadline <= BoottimeMillis(minting.now);
    if expired && !request_survives_requester {
        return Existing::Stale;
    }
    if request_survives_requester {
        return Existing::Live {
            size: bytes.len(),
            same_uid: existing.caller_uid == minting.uid,
            watch: true,
        };
    }
    match live_caller(callers, &existing) {
        Some(uids) => Existing::Live {
            size: bytes.len(),
            same_uid: uids.real == minting.uid || uids.effective == minting.uid,
            watch: existing.needs_watch,
        },
        None => Existing::Stale,
    }
}

/// The uids of an entry's caller, if the caller is still the process the
/// entry was minted for.
///
/// `status` is read first and `stat` last, the same order the identification
/// ladder keeps: a `stat` that still shows the pinned `(pid, starttime)` proves
/// the pinned process held the number when it was read, so it held it when
/// `status` was read before. Anything that cannot be read, parsed, or matched
/// is `None` — the entry is pruned, which can only take away a request, never
/// grant one.
fn live_caller(callers: &dyn PeerCalls, entry: &PendingRequest) -> Option<StatusUids> {
    let pid = entry.caller_pid;
    let status = callers.read_proc(pid, ProcFile::Status).ok()?;
    let uids = parse_status_uids("status", &status).ok()?;
    let stat = callers.read_proc(pid, ProcFile::Stat).ok()?;
    let stat = parse_stat("stat", &stat).ok()?;
    (stat.pid == pid && stat.starttime == entry.caller_starttime).then_some(uids)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use proptest::prelude::*;
    use xudo_audit::record::{Decision as AuditDecision, Record};
    use xudo_policy::{ActionId, DenialCode, Verdict};
    use xudo_sys::{
        Attestation, FakeAuditSink, FakeEntropy, FakePeer, FakeSpool, PeerCall, SpoolCall,
        authorize,
    };

    use super::*;
    use crate::identify::EuidSource;

    const NOW: u64 = 1_000;

    fn identity(pid: u32, starttime: u64) -> PeerIdentity {
        PeerIdentity {
            rung: Attestation::PeerPidfd,
            pid,
            uid: 1000,
            gid: 100,
            starttime,
            sid: 1,
            tty: 0,
            diverged: false,
            pinned: true,
            cgroup_id: None,
            euid_source: EuidSource::ProcStatus,
        }
    }

    fn nonce(fill: char) -> String {
        std::iter::repeat_n(fill, 64).collect()
    }

    fn entry(fill: char, pid: u32, starttime: u64, deadline: u64) -> PendingRequest {
        PendingRequest {
            schema_version: REQUEST_SCHEMA_VERSION,
            nonce: nonce(fill),
            caller_pid: pid,
            caller_starttime: starttime,
            action: "xudo.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
            generation: 7,
            deadline: BoottimeMillis(deadline),
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
            attested_class: AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }

    /// A spool holding `existing` under its own nonce.
    fn spool_with(existing: &[&PendingRequest]) -> FakeSpool {
        existing.iter().fold(FakeSpool::new(), |spool, entry| {
            spool.with_file(entry.nonce.clone(), entry.to_json())
        })
    }

    /// A `/proc/<pid>/stat` that shows `pid` started at `starttime`.
    fn stat(pid: u32, starttime: u64) -> Vec<u8> {
        let mut tail: Vec<String> = vec!["S".into(), "1".into()];
        tail.extend(std::iter::repeat_n("0".to_owned(), 17));
        tail.push(starttime.to_string());
        format!("{pid} (xudo) {}", tail.join(" ")).into_bytes()
    }

    /// A `/proc/<pid>/status` whose process has these real and effective uids.
    fn status(real: u32, effective: u32) -> Vec<u8> {
        format!("Name:\txudo\nUid:\t{real}\t{effective}\t{effective}\t{effective}\n").into_bytes()
    }

    /// A host on which this caller is still running as `real`/`effective`.
    fn running(host: FakePeer, caller: &PendingRequest, real: u32, effective: u32) -> FakePeer {
        host.with_proc(
            caller.caller_pid,
            ProcFile::Stat,
            stat(caller.caller_pid, caller.caller_starttime),
        )
        .with_proc(caller.caller_pid, ProcFile::Status, status(real, effective))
    }

    /// A host on which every one of these callers is running as `uid`.
    fn all_running(callers: &[&PendingRequest], uid: u32) -> FakePeer {
        callers.iter().fold(FakePeer::new(), |host, caller| {
            running(host, caller, uid, uid)
        })
    }

    /// The entry with its record on a (fake) trail. Its operands are dropped
    /// so a test of the spool's byte limit is not stopped by a log line's.
    fn authorized(entry: &PendingRequest) -> Authorized<Grant> {
        let grant = Grant(PendingRequest {
            argv: Vec::new(),
            ..entry.clone()
        });
        authorize(&mut FakeAuditSink::new(), grant, &|previous, g| {
            Record::after(previous, AuditDecision::Allowed, g.command(), "unattested")
                .with_rule(g.action(), "t.toml:1")
        })
        .unwrap()
    }

    /// Publishes `minting` for a caller running as uid 1000, at `NOW`.
    fn publish_as_1000(
        spool: &FakeSpool,
        host: &FakePeer,
        minting: &PendingRequest,
    ) -> Result<(), MintError> {
        publish_at(spool, host, minting, NOW)
    }

    fn publish_at(
        spool: &FakeSpool,
        host: &FakePeer,
        minting: &PendingRequest,
        now: u64,
    ) -> Result<(), MintError> {
        let authorized = authorized(minting);
        publish(
            spool,
            host,
            &Minting {
                authorized: &authorized,
                json: &minting.to_json(),
                uid: 1000,
                now,
            },
        )
    }

    fn permitted() -> Decision {
        let mut decision = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        decision.verdict = Verdict::Allow;
        decision.denial = None;
        decision.action = Some(ActionId::new("xudo.svc.restart"));
        decision
    }

    #[test]
    fn a_nonce_is_64_lowercase_hex_characters_of_the_drawn_bytes() {
        let entropy = FakeEntropy::new().with(Ok((0..32).collect()));
        let drawn = draw_nonce(&entropy).unwrap();
        assert_eq!(
            drawn,
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        assert!(is_nonce(&drawn));
        let err = draw_nonce(&FakeEntropy::new()).unwrap_err();
        assert!(err.to_string().contains("no randomness"), "{err}");
    }

    #[test]
    fn an_entry_carries_the_question_the_pin_and_no_confirmation() {
        let request = BrokerRequest::new(
            "/usr/bin/systemctl",
            vec!["restart".to_owned(), "nginx.service".to_owned()],
            "enrolled-agent-yolo",
        );
        let minted = entry_for(
            &permitted(),
            &identity(4242, 5_000),
            &request,
            7,
            true,
            1_900,
            nonce('a'),
        )
        .unwrap();
        assert_eq!(
            minted,
            PendingRequest {
                schema_version: REQUEST_SCHEMA_VERSION,
                nonce: nonce('a'),
                caller_pid: 4242,
                caller_starttime: 5_000,
                action: "xudo.svc.restart".to_owned(),
                program: "/usr/bin/systemctl".to_owned(),
                argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
                generation: 7,
                deadline: BoottimeMillis(1_900),
                confirmed: false,
                confirmed_by: None,
                state: xudo_gate::request::ConfirmationState::Pending,
                caller_uid: 1000,
                caller_sid: 1,
                caller_tty: 0,
                needs_watch: false,
                shown_at_ms: None,
                shown_to: None,
                fingerprint: crate::confirm::fingerprint(
                    1000,
                    b"/usr/bin/systemctl",
                    &[b"restart", b"nginx.service"],
                ),
                claimed_classification: "enrolled-agent-yolo".to_owned(),
                attested_class: AttestedClass::Unattested,
                attested_scope_id: None,
                boot_id: None,
            }
        );
    }

    proptest! {
        #[test]
        fn claimed_classification_never_reaches_attested_class(
            claim_a in prop_oneof![
                any::<String>(),
                Just("enrolled_agent".to_owned()),
                Just("human".to_owned()),
                Just("scope_id=77".to_owned()),
            ],
            claim_b in prop_oneof![
                any::<String>(),
                Just("enrolled_agent".to_owned()),
                Just("human".to_owned()),
                Just("scope_id=77".to_owned()),
            ],
        ) {
            let mut peer = identity(4242, 5_000);
            peer.cgroup_id = Some(77);
            let facts = CallerFacts::new(
                Classification::EnrolledAgent {
                    agent_id: "worker".to_owned(),
                    session_id: "session".to_owned(),
                    declared_yolo: false,
                },
                peer.uid,
            );
            let request = BrokerRequest::new(
                "/usr/bin/systemctl",
                vec!["restart".to_owned()],
                &claim_a,
            );
            let attest = AttestedCaller {
                identity: &peer,
                facts: &facts,
                boot_id: Some("abcdef01-2345-6789-abcd-ef0123456789"),
            };
            let first = entry_for_classified(
                &permitted(),
                &attest,
                &request,
                7,
                true,
                1_900,
                nonce('a'),
            );
            let second_request = BrokerRequest::new(
                "/usr/bin/systemctl",
                vec!["restart".to_owned()],
                &claim_b,
            );
            let second = entry_for_classified(
                &permitted(),
                &attest,
                &second_request,
                7,
                true,
                1_900,
                nonce('b'),
            );
            prop_assert!(first.is_ok());
            prop_assert!(second.is_ok());
            if let (Ok(first), Ok(second)) = (first, second) {
                prop_assert_eq!(first.claimed_classification, claim_a);
                prop_assert_eq!(second.claimed_classification, claim_b);
                prop_assert_eq!(
                    (
                        &first.attested_class,
                        first.attested_scope_id,
                        &first.boot_id,
                    ),
                    (
                        &second.attested_class,
                        second.attested_scope_id,
                        &second.boot_id,
                    ),
                );
                prop_assert_eq!(first.attested_class, AttestedClass::EnrolledAgent { scope_id: 77 });
                prop_assert_eq!(first.attested_scope_id, Some(77));
                prop_assert_eq!(first.boot_id.as_deref(), Some("abcdef01-2345-6789-abcd-ef0123456789"));
            }
        }
    }

    #[test]
    fn a_faked_enrolled_class_is_bound_to_its_kernel_scope_id() {
        let mut peer = identity(4242, 5_000);
        peer.cgroup_id = Some(77);
        let caller = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "worker".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            peer.uid,
        );
        let request = BrokerRequest::new("/usr/bin/systemctl", vec!["restart".to_owned()], "human");
        let minted = entry_for_classified(
            &permitted(),
            &AttestedCaller {
                identity: &peer,
                facts: &caller,
                boot_id: Some("abcdef01-2345-6789-abcd-ef0123456789"),
            },
            &request,
            7,
            true,
            1_900,
            nonce('a'),
        );
        let entry = minted.unwrap();
        assert_eq!(
            entry.attested_class,
            AttestedClass::EnrolledAgent { scope_id: 77 }
        );
        assert_eq!(entry.attested_scope_id, Some(77));
        assert_eq!(
            entry.boot_id.as_deref(),
            Some("abcdef01-2345-6789-abcd-ef0123456789")
        );
    }

    #[test]
    fn a_faked_human_class_does_not_inherit_an_agent_claim() {
        let peer = identity(4242, 5_000);
        let caller = CallerFacts::new(Classification::Human, peer.uid);
        let request = BrokerRequest::new(
            "/usr/bin/systemctl",
            vec!["restart".to_owned()],
            "enrolled-agent-yolo",
        );
        let entry = entry_for_classified(
            &permitted(),
            &AttestedCaller {
                identity: &peer,
                facts: &caller,
                boot_id: None,
            },
            &request,
            7,
            true,
            1_900,
            nonce('a'),
        )
        .unwrap();
        assert_eq!(entry.attested_class, AttestedClass::Human);
        assert_eq!(entry.attested_scope_id, None);
        assert_eq!(entry.boot_id, None);
    }

    #[test]
    fn an_enrolled_class_without_a_kernel_scope_is_not_minted() {
        let peer = identity(4242, 5_000);
        let caller = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "worker".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            peer.uid,
        );
        let request = BrokerRequest::new("/usr/bin/systemctl", vec!["restart".to_owned()], "x");
        assert_eq!(
            entry_for_classified(
                &permitted(),
                &AttestedCaller {
                    identity: &peer,
                    facts: &caller,
                    boot_id: Some("abcdef01-2345-6789-abcd-ef0123456789"),
                },
                &request,
                7,
                true,
                1_900,
                nonce('a'),
            ),
            Err(MintError::NoAttestedScope)
        );
    }

    #[test]
    fn an_enrolled_class_without_a_boot_id_is_not_minted() {
        let mut peer = identity(4242, 5_000);
        peer.cgroup_id = Some(77);
        let caller = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "worker".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            peer.uid,
        );
        let request = BrokerRequest::new("/usr/bin/systemctl", vec!["restart".to_owned()], "x");
        assert_eq!(
            entry_for_classified(
                &permitted(),
                &AttestedCaller {
                    identity: &peer,
                    facts: &caller,
                    boot_id: None,
                },
                &request,
                7,
                true,
                1_900,
                nonce('a'),
            ),
            Err(MintError::NoAttestedScope)
        );
        assert_eq!(
            entry_for_classified(
                &permitted(),
                &AttestedCaller {
                    identity: &peer,
                    facts: &caller,
                    boot_id: Some(""),
                },
                &request,
                7,
                true,
                1_900,
                nonce('a'),
            ),
            Err(MintError::NoAttestedScope)
        );
    }

    #[test]
    fn an_enrolled_class_with_a_boot_id_newline_is_not_minted() {
        let mut peer = identity(4242, 5_000);
        peer.cgroup_id = Some(77);
        let caller = CallerFacts::new(
            Classification::EnrolledAgent {
                agent_id: "worker".to_owned(),
                session_id: "session".to_owned(),
                declared_yolo: false,
            },
            peer.uid,
        );
        let request = BrokerRequest::new("/usr/bin/systemctl", vec!["restart".to_owned()], "x");
        assert_eq!(
            entry_for_classified(
                &permitted(),
                &AttestedCaller {
                    identity: &peer,
                    facts: &caller,
                    boot_id: Some("abcdef01-2345-6789-abcd-ef0123456789\n"),
                },
                &request,
                7,
                true,
                1_900,
                nonce('a'),
            ),
            Err(MintError::NoAttestedScope)
        );
    }

    #[test]
    fn confirmation_setting_controls_watch_requirement_at_mint() {
        let mut decision = permitted();
        decision.confirm = xudo_policy::Confirm::Required {
            reason: xudo_policy::ConfirmReason::RuleRequiresConfirmation,
        };
        let request = BrokerRequest::new("/usr/bin/systemctl", vec!["restart".to_owned()], "human");
        for (setting, expected) in [(true, true), (false, false)] {
            let minted = entry_for(
                &decision,
                &identity(4242, 5000),
                &request,
                7,
                setting,
                1900,
                nonce('a'),
            )
            .unwrap();
            assert_eq!(minted.needs_watch, expected);
            assert_eq!(minted.state, xudo_gate::request::ConfirmationState::Pending);
        }
    }

    #[test]
    fn a_non_run_question_cannot_be_minted() {
        let mut request = BrokerRequest::new("/usr/bin/systemctl", Vec::new(), "x");
        request.question = xudo_wire::Question::Watch;
        assert_eq!(
            entry_for(
                &permitted(),
                &identity(1, 1),
                &request,
                7,
                true,
                1,
                nonce('a')
            ),
            Err(MintError::NoAction)
        );
    }

    #[test]
    fn a_permitted_decision_that_names_no_action_mints_nothing() {
        let mut decision = permitted();
        decision.action = None;
        let request = BrokerRequest::new("/usr/bin/systemctl", Vec::new(), "x");
        assert_eq!(
            entry_for(&decision, &identity(1, 1), &request, 7, true, 1, nonce('a')),
            Err(MintError::NoAction)
        );
    }

    #[test]
    fn publishing_takes_the_lock_writes_the_entry_and_releases_the_lock() {
        let spool = FakeSpool::new();
        let minting = entry('a', 4242, 5_000, NOW + 900);
        publish_as_1000(&spool, &FakePeer::new(), &minting).unwrap();
        assert_eq!(
            spool.calls(),
            vec![
                SpoolCall::Lock,
                SpoolCall::Names,
                SpoolCall::Publish(nonce('a')),
                SpoolCall::Unlock,
            ]
        );
        let written = &spool.files()[nonce('a').as_bytes()];
        assert_eq!(
            PendingRequest::parse(std::str::from_utf8(written).unwrap()).unwrap(),
            minting
        );
    }

    #[test]
    fn an_older_entry_for_the_same_caller_is_replaced_so_the_gate_finds_one() {
        let older = entry('b', 4242, 5_000, NOW + 100);
        let spool = spool_with(&[&older]);
        let minting = entry('a', 4242, 5_000, NOW + 900);
        publish_as_1000(&spool, &FakePeer::new(), &minting).unwrap();
        let names: Vec<Vec<u8>> = spool.files().into_keys().collect();
        assert_eq!(names, vec![nonce('a').into_bytes()]);
        assert!(
            spool
                .calls()
                .contains(&SpoolCall::Remove(nonce('b').into_bytes()))
        );
    }

    #[test]
    fn the_same_pid_with_another_start_time_is_another_caller() {
        // A reused pid is a different process; its entry is not superseded.
        let other = entry('b', 4242, 4_999, NOW + 100);
        let spool = spool_with(&[&other]);
        let minting = entry('a', 4242, 5_000, NOW + 900);
        let host = all_running(&[&other], 2000);
        publish_as_1000(&spool, &host, &minting).unwrap();
        assert_eq!(spool.files().len(), 2);
    }

    #[test]
    fn expired_misnamed_oversized_unreadable_and_half_written_entries_are_removed() {
        let expired = entry('b', 1, 1, NOW);
        let mut misnamed = entry('c', 2, 2, NOW + 100);
        misnamed.nonce = nonce('d');
        let mut oversized = entry('7', 3, 3, NOW + 100);
        oversized.argv = vec!["x".repeat(MAX_ENTRY_BYTES)];
        let spool = spool_with(&[&expired, &oversized])
            .with_file(nonce('c'), misnamed.to_json())
            .with_file(nonce('e'), "{}")
            .with_file(nonce('f'), b"\xff".to_vec())
            .with_file(".tmp.0123", "half")
            .with_file(nonce('9'), "{}")
            .failing_read(nonce('9'));
        let minting = entry('a', 4242, 5_000, NOW + 900);
        publish_as_1000(&spool, &FakePeer::new(), &minting).unwrap();
        let names: Vec<Vec<u8>> = spool.files().into_keys().collect();
        assert_eq!(names, vec![nonce('a').into_bytes()]);
    }

    #[test]
    fn names_the_broker_does_not_own_are_left_alone_and_not_counted() {
        let spool = FakeSpool::new()
            .with_file("README", "root put this here")
            .with_file(b"\xff\xfe".to_vec(), "not utf-8")
            .with_file("ABCDEF", "not a nonce");
        let minting = entry('a', 4242, 5_000, NOW + 900);
        publish_as_1000(&spool, &FakePeer::new(), &minting).unwrap();
        assert_eq!(spool.files().len(), 4);
        assert_eq!(
            spool.calls(),
            vec![
                SpoolCall::Lock,
                SpoolCall::Names,
                SpoolCall::Publish(nonce('a')),
                SpoolCall::Unlock,
            ],
            "nothing it does not own is read or removed"
        );
    }

    #[test]
    fn a_full_spool_refuses_rather_than_growing_by_count() {
        let mut spool = FakeSpool::new();
        let mut host = FakePeer::new();
        for index in 0..MAX_SPOOL_ENTRIES {
            let mut live = entry('b', 10_000 + u32::try_from(index).unwrap(), 1, NOW + 100);
            live.nonce = format!("{:064x}", index + 1);
            spool = spool.with_file(live.nonce.clone(), live.to_json());
            // Eight callers a uid, so no one uid is what fills it.
            host = running(
                host,
                &live,
                2000 + u32::try_from(index.div_euclid(8)).unwrap(),
                0,
            );
        }
        let minting = entry('a', 4242, 5_000, NOW + 900);
        let err = publish_as_1000(&spool, &host, &minting).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("{MAX_SPOOL_ENTRIES} live entries")),
            "{err}"
        );
        assert_eq!(spool.calls().last(), Some(&SpoolCall::Unlock));
        assert!(!spool.files().contains_key(nonce('a').as_bytes()));
    }

    #[test]
    fn a_full_spool_refuses_rather_than_growing_by_bytes() {
        // Twenty live entries is far under the count limit; their bytes and
        // the new entry's together are over the byte limit.
        let mut spool = FakeSpool::new();
        let mut host = FakePeer::new();
        for index in 0..20u32 {
            let mut live = entry('b', 100 + index, 1, NOW + 100);
            live.nonce = format!("{:064x}", index + 1);
            live.argv = vec!["x".repeat(30_000)];
            spool = spool.with_file(live.nonce.clone(), live.to_json());
            host = running(host, &live, 2000 + index.div_euclid(8), 0);
        }
        let mut minting = entry('a', 4242, 5_000, NOW + 900);
        minting.argv = vec!["x".repeat(500_000)];
        let err = publish_as_1000(&spool, &host, &minting).unwrap_err();
        assert!(err.to_string().contains("20 live entries"), "{err}");
        assert!(!spool.files().contains_key(nonce('a').as_bytes()));
    }

    #[test]
    fn a_colliding_nonce_is_refused_and_overwrites_nothing() {
        let other = entry('a', 1, 1, NOW + 100);
        let spool = spool_with(&[&other]);
        let minting = entry('a', 4242, 5_000, NOW + 900);
        assert_eq!(
            publish_as_1000(&spool, &all_running(&[&other], 2000), &minting),
            Err(MintError::Collision { nonce: nonce('a') })
        );
        assert_eq!(
            spool.files()[nonce('a').as_bytes()],
            other.to_json().into_bytes()
        );
    }

    #[test]
    fn every_spool_failure_refuses_and_still_releases_the_lock() {
        let broken = SpoolError::Io {
            operation: "x".to_owned(),
            at: "/run/xudo/req".to_owned(),
            code: None,
            reason: "broken".to_owned(),
        };
        let expired = entry('b', 1, 1, 0);
        let minting = entry('a', 4242, 5_000, NOW + 900);
        let cases = [
            FakeSpool::new().failing_names(broken.clone()),
            spool_with(&[&expired]).failing_remove(broken.clone()),
            FakeSpool::new().failing_publish(broken.clone()),
        ];
        for spool in cases {
            assert_eq!(
                publish_as_1000(&spool, &FakePeer::new(), &minting),
                Err(MintError::Spool(broken.clone()))
            );
            assert_eq!(spool.calls().last(), Some(&SpoolCall::Unlock));
        }
        let unlockable = FakeSpool::new().failing_lock(broken.clone());
        assert_eq!(
            publish_as_1000(&unlockable, &FakePeer::new(), &minting),
            Err(MintError::Spool(broken))
        );
        assert_eq!(unlockable.calls(), vec![SpoolCall::Lock]);
    }

    #[test]
    fn every_mint_refusal_renders_a_sentence() {
        for err in [
            MintError::NoAction,
            MintError::Spool(SpoolError::Exists {
                name: "x".to_owned(),
            }),
            MintError::Full {
                entries: 1,
                bytes: 2,
            },
            MintError::UidFull {
                uid: 1000,
                entries: 8,
            },
            MintError::Collision { nonce: nonce('a') },
        ] {
            assert!(err.to_string().len() > 20, "{err:?}");
        }
    }

    /// `count` entries minted for callers `20_000`.., one after another.
    fn entries_of_callers(count: u32) -> (Vec<PendingRequest>, FakeSpool) {
        let entries: Vec<PendingRequest> = (0..count)
            .map(|index| {
                let mut each = entry('b', 20_000 + index, 7, NOW + 100);
                each.nonce = format!("{:064x}", index + 1);
                each
            })
            .collect();
        let spool = entries.iter().fold(FakeSpool::new(), |spool, each| {
            spool.with_file(each.nonce.clone(), each.to_json())
        });
        (entries, spool)
    }

    fn watch_entry(letter: char, pid: u32) -> PendingRequest {
        let mut entry = entry(letter, pid, 7, NOW + 100);
        entry.needs_watch = true;
        entry
    }

    #[test]
    fn watch_entries_are_throttled_at_their_uid_and_global_limits() {
        let mut same_uid = FakeSpool::new();
        for index in 0..MAX_WATCH_ENTRIES_PER_UID {
            let mut watched = watch_entry('b', 20_000 + u32::try_from(index).unwrap());
            watched.nonce = format!("{:064x}", index + 1);
            same_uid = same_uid.with_file(watched.nonce.clone(), watched.to_json());
        }
        let next = watch_entry('a', 4242);
        assert_eq!(
            publish_as_1000(&same_uid, &FakePeer::new(), &next),
            Err(MintError::ConfirmationThrottled)
        );

        let mut global = FakeSpool::new();
        for index in 0..MAX_WATCH_ENTRIES {
            let mut watched = watch_entry('b', 30_000 + u32::try_from(index).unwrap());
            watched.nonce = format!("{:064x}", index + 1);
            watched.caller_uid = 2_000 + u32::try_from(index).unwrap();
            global = global.with_file(watched.nonce.clone(), watched.to_json());
        }
        assert_eq!(
            publish_as_1000(&global, &FakePeer::new(), &next),
            Err(MintError::ConfirmationThrottled)
        );
    }

    #[test]
    fn watch_mints_succeed_one_below_each_quota() {
        let mut same_uid = FakeSpool::new();
        for index in 0..MAX_WATCH_ENTRIES_PER_UID - 1 {
            let mut watched = watch_entry('b', 20_000 + u32::try_from(index).unwrap());
            watched.nonce = format!("{:064x}", index + 1);
            same_uid = same_uid.with_file(watched.nonce.clone(), watched.to_json());
        }
        let next = watch_entry('a', 4242);
        publish_as_1000(&same_uid, &FakePeer::new(), &next).unwrap();
        assert_eq!(same_uid.files().len(), MAX_WATCH_ENTRIES_PER_UID);

        let mut global = FakeSpool::new();
        for index in 0..MAX_WATCH_ENTRIES - 1 {
            let mut watched = watch_entry('b', 30_000 + u32::try_from(index).unwrap());
            watched.nonce = format!("{:064x}", index + 1);
            watched.caller_uid = 2_000 + u32::try_from(index).unwrap();
            global = global.with_file(watched.nonce.clone(), watched.to_json());
        }
        publish_as_1000(&global, &FakePeer::new(), &next).unwrap();
        assert_eq!(global.files().len(), MAX_WATCH_ENTRIES);
    }

    #[test]
    fn a_pending_entry_survives_its_requester_exiting() {
        let pending = watch_entry('b', 4243);
        let spool = spool_with(&[&pending]);
        let next = entry('a', 4242, 5_000, NOW + 900);

        publish_as_1000(&spool, &FakePeer::new(), &next).unwrap();

        assert!(spool.files().contains_key(pending.nonce.as_bytes()));
        assert!(spool.files().contains_key(next.nonce.as_bytes()));
    }

    #[test]
    fn an_approval_survives_until_the_rerun() {
        let mut approved = watch_entry('b', 4243);
        approved.state = xudo_gate::request::ConfirmationState::Approved;
        approved.confirmed = true;
        approved.shown_at_ms = Some(BoottimeMillis(0));
        let watcher = xudo_gate::request::WatcherPin {
            uid: approved.caller_uid,
            pid: 5000,
            starttime: 77,
            tty: (136 << 8) | 1,
            sid: approved.caller_sid + 1,
        };
        approved.confirmed_by = Some(watcher.clone());
        approved.shown_to = Some(watcher);
        let spool = spool_with(&[&approved]);
        let next = entry('a', 4242, 5_000, NOW + 900);

        publish_as_1000(&spool, &FakePeer::new(), &next).unwrap();

        assert!(spool.files().contains_key(approved.nonce.as_bytes()));
    }

    #[test]
    fn a_consumed_watch_entry_still_tracks_its_gate_caller() {
        let mut consumed = watch_entry('b', 4243);
        consumed.state = xudo_gate::request::ConfirmationState::Consumed;
        consumed.confirmed = true;
        consumed.shown_at_ms = Some(BoottimeMillis(0));
        let watcher = xudo_gate::request::WatcherPin {
            uid: consumed.caller_uid,
            pid: 5000,
            starttime: 77,
            tty: (136 << 8) | 1,
            sid: consumed.caller_sid + 1,
        };
        consumed.confirmed_by = Some(watcher.clone());
        consumed.shown_to = Some(watcher);
        let spool = spool_with(&[&consumed]);
        let caller_is_live = running(FakePeer::new(), &consumed, 1000, 1000);
        let next = entry('a', 4242, 5_000, NOW + 900);

        publish_as_1000(&spool, &caller_is_live, &next).unwrap();

        assert!(spool.files().contains_key(consumed.nonce.as_bytes()));
    }

    #[test]
    fn alternating_requests_cannot_sweep_each_others_pending_entry() {
        let request_a = watch_entry('b', 4243);
        let request_b = watch_entry('c', 4244);
        let spool = spool_with(&[&request_a]);

        publish_as_1000(&spool, &FakePeer::new(), &request_b).unwrap();
        publish_as_1000(
            &spool,
            &FakePeer::new(),
            &entry('a', 4242, 5_000, NOW + 900),
        )
        .unwrap();

        assert!(spool.files().contains_key(request_a.nonce.as_bytes()));
        assert!(spool.files().contains_key(request_b.nonce.as_bytes()));
    }

    #[test]
    fn one_process_alternating_requests_cannot_supersede_its_pending_entry() {
        let pending_a = watch_entry('b', 4242);
        let spool = spool_with(&[&pending_a]);
        let request_b = watch_entry('c', 4242);
        assert_eq!(
            publish_as_1000(&spool, &FakePeer::new(), &request_b),
            Err(MintError::ConfirmationThrottled)
        );
        let request_a_again = watch_entry('d', 4242);
        assert_eq!(
            publish_as_1000(&spool, &FakePeer::new(), &request_a_again),
            Err(MintError::ConfirmationThrottled)
        );
        assert_eq!(spool.files().len(), 1);
        assert_eq!(
            spool.files()[pending_a.nonce.as_bytes()],
            pending_a.to_json().into_bytes()
        );
    }

    #[test]
    fn a_password_only_request_cannot_supersede_a_pending_entry_of_the_same_process() {
        let pending = watch_entry('b', 4242);
        let spool = spool_with(&[&pending]);
        let password_only = entry('a', 4242, 7, NOW + 900);
        assert!(!password_only.needs_watch);

        assert_eq!(
            publish_as_1000(&spool, &FakePeer::new(), &password_only),
            Err(MintError::ConfirmationThrottled)
        );
        assert_eq!(spool.files().len(), 1);
        assert_eq!(
            spool.files()[pending.nonce.as_bytes()],
            pending.to_json().into_bytes()
        );
    }

    #[test]
    fn an_expired_waiting_entry_is_pruned_after_grace_even_without_the_confirm_dir() {
        let expired = watch_entry('b', 4242);
        let deadline = expired.deadline.0;
        let spool = spool_with(&[&expired]);
        let next = entry('a', 5000, 8, deadline + EXPIRED_WATCH_GRACE_MILLIS + 900);

        publish_at(
            &spool,
            &FakePeer::new(),
            &next,
            deadline + EXPIRED_WATCH_GRACE_MILLIS,
        )
        .unwrap();

        assert!(!spool.files().contains_key(expired.nonce.as_bytes()));
        assert!(spool.files().contains_key(next.nonce.as_bytes()));
    }

    #[test]
    fn watch_entries_do_not_consume_password_path_uid_slots() {
        let mut spool = FakeSpool::new();
        for index in 0..MAX_WATCH_ENTRIES_PER_UID {
            let mut watched = watch_entry(
                char::from(b'b' + u8::try_from(index).unwrap()),
                20_000 + u32::try_from(index).unwrap(),
            );
            watched.nonce = format!("{:064x}", index + 1);
            spool = spool.with_file(watched.nonce.clone(), watched.to_json());
        }
        let next = entry('a', 4242, 5_000, NOW + 900);

        publish_as_1000(&spool, &FakePeer::new(), &next).unwrap();
        assert_eq!(spool.files().len(), MAX_WATCH_ENTRIES_PER_UID + 1);
    }

    #[test]
    fn watch_entries_cannot_exhaust_the_spool_for_the_password_path() {
        let mut spool = FakeSpool::new();
        let mut host = FakePeer::new();
        for index in 0..MAX_WATCH_ENTRIES {
            let mut watched = watch_entry('b', 20_000 + u32::try_from(index).unwrap());
            watched.nonce = format!("{:064x}", index + 1);
            watched.caller_uid = 4_000 + u32::try_from(index).unwrap();
            spool = spool.with_file(watched.nonce.clone(), watched.to_json());
        }
        for index in 0..MAX_SPOOL_ENTRIES - 1 {
            let mut password = entry('c', 30_000 + u32::try_from(index).unwrap(), 7, NOW + 100);
            password.nonce = format!("{:064x}", MAX_WATCH_ENTRIES + index + 1);
            let uid = 2_000 + u32::try_from(index.div_euclid(MAX_ENTRIES_PER_UID)).unwrap();
            host = running(host, &password, uid, uid);
            spool = spool.with_file(password.nonce.clone(), password.to_json());
        }
        let next = entry('a', 4242, 5_000, NOW + 900);

        publish_as_1000(&spool, &host, &next).unwrap();
        assert_eq!(spool.files().len(), MAX_WATCH_ENTRIES + MAX_SPOOL_ENTRIES);
        assert!(spool.files().contains_key(next.nonce.as_bytes()));
    }

    proptest! {
        #[test]
        fn any_mix_of_watch_entries_never_blocks_a_fresh_password_mint(
            watch_states in prop::collection::vec(0u8..3, 0..=MAX_WATCH_ENTRIES),
            owned_watch_count in 0..=MAX_WATCH_ENTRIES,
            password_count in 0..MAX_SPOOL_ENTRIES,
        ) {
            let mut spool = FakeSpool::new();
            let mut host = FakePeer::new();
            for (index, state) in watch_states.into_iter().enumerate() {
                let mut watched = watch_entry('b', 20_000 + u32::try_from(index).unwrap());
                watched.nonce = format!("{:064x}", index + 1);
                watched.caller_uid = if index < owned_watch_count {
                    1000
                } else {
                    4_000 + u32::try_from(index).unwrap()
                };
                let watcher = xudo_gate::request::WatcherPin {
                    uid: watched.caller_uid,
                    pid: 50_000 + u32::try_from(index).unwrap(),
                    starttime: 77,
                    tty: (136 << 8) | 1,
                    sid: watched.caller_sid + 1,
                };
                match state {
                    0 => {}
                    1 => {
                        watched.state = xudo_gate::request::ConfirmationState::Approved;
                        watched.confirmed = true;
                        watched.confirmed_by = Some(watcher.clone());
                        watched.shown_to = Some(watcher);
                        watched.shown_at_ms = Some(BoottimeMillis(NOW - 2));
                    }
                    _ => {
                        watched.state = xudo_gate::request::ConfirmationState::Consumed;
                        watched.confirmed = true;
                        watched.confirmed_by = Some(watcher.clone());
                        watched.shown_to = Some(watcher);
                        watched.shown_at_ms = Some(BoottimeMillis(NOW - 2));
                        host = running(host, &watched, watched.caller_uid, watched.caller_uid);
                    }
                }
                spool = spool.with_file(watched.nonce.clone(), watched.to_json());
            }
            for index in 0..password_count {
                let mut password = entry('c', 30_000 + u32::try_from(index).unwrap(), 7, NOW + 100);
                password.nonce = format!("{:064x}", MAX_WATCH_ENTRIES + index + 1);
                let uid = 2_000 + u32::try_from(index.div_euclid(MAX_ENTRIES_PER_UID)).unwrap();
                host = running(host, &password, uid, uid);
                spool = spool.with_file(password.nonce.clone(), password.to_json());
            }
            let next = entry('a', 4242, 5_000, NOW + 900);

            prop_assert!(publish_as_1000(&spool, &host, &next).is_ok());
        }
    }

    #[test]
    fn sixty_four_exited_callers_cannot_lock_everyone_else_out() {
        // The attack: one group member runs clients one after another, each
        // exiting before the next starts. Their entries can never be used --
        // the gate checks its caller against the pin -- so they must not count.
        let (entries, spool) = entries_of_callers(u32::try_from(MAX_SPOOL_ENTRIES).unwrap());
        assert_eq!(spool.files().len(), MAX_SPOOL_ENTRIES);
        let bob = entry('a', 4242, 5_000, NOW + 900);
        // Nothing runs any more: every `/proc` read refuses.
        publish_as_1000(&spool, &FakePeer::new(), &bob).unwrap();
        let names: Vec<Vec<u8>> = spool.files().into_keys().collect();
        assert_eq!(names, vec![nonce('a').into_bytes()]);
        assert_eq!(entries.len(), MAX_SPOOL_ENTRIES);
    }

    #[test]
    fn a_pid_reused_by_another_process_does_not_keep_an_entry_alive() {
        // The pid is running -- as someone else, started later. The entry
        // names the process that is gone.
        let gone = entry('b', 4243, 5_000, NOW + 100);
        let spool = spool_with(&[&gone]);
        let reused = FakePeer::new()
            .with_proc(4243, ProcFile::Stat, stat(4243, 9_999))
            .with_proc(4243, ProcFile::Status, status(1000, 1000));
        let minting = entry('a', 4242, 5_000, NOW + 900);
        publish_as_1000(&spool, &reused, &minting).unwrap();
        assert!(!spool.files().contains_key(gone.nonce.as_bytes()));
        // And a stat that names another pid altogether is no better.
        let spool = spool_with(&[&gone]);
        let wrong = FakePeer::new()
            .with_proc(4243, ProcFile::Stat, stat(1, 5_000))
            .with_proc(4243, ProcFile::Status, status(1000, 1000));
        publish_as_1000(&spool, &wrong, &minting).unwrap();
        assert!(!spool.files().contains_key(gone.nonce.as_bytes()));
    }

    #[test]
    fn an_entry_whose_caller_cannot_be_read_is_pruned_not_trusted() {
        let gone = entry('b', 4243, 5_000, NOW + 100);
        let minting = entry('a', 4242, 5_000, NOW + 900);
        let hosts = [
            // Neither file.
            FakePeer::new(),
            // Only status.
            FakePeer::new().with_proc(4243, ProcFile::Status, status(1000, 1000)),
            // Status that is not a status.
            FakePeer::new()
                .with_proc(4243, ProcFile::Status, "Name: x\n")
                .with_proc(4243, ProcFile::Stat, stat(4243, 5_000)),
            // Stat that is not a stat.
            FakePeer::new()
                .with_proc(4243, ProcFile::Status, status(1000, 1000))
                .with_proc(4243, ProcFile::Stat, "garbage"),
        ];
        for host in hosts {
            let spool = spool_with(&[&gone]);
            publish_as_1000(&spool, &host, &minting).unwrap();
            assert!(
                !spool.files().contains_key(gone.nonce.as_bytes()),
                "{host:?}"
            );
        }
    }

    #[test]
    fn a_callers_status_is_read_before_its_stat_so_the_stat_vouches_for_both() {
        let live = entry('b', 4243, 5_000, NOW + 100);
        let spool = spool_with(&[&live]);
        let host = all_running(&[&live], 2000);
        let minting = entry('a', 4242, 5_000, NOW + 900);
        publish_as_1000(&spool, &host, &minting).unwrap();
        assert_eq!(
            host.calls(),
            vec![
                PeerCall::ReadProc(4243, ProcFile::Status),
                PeerCall::ReadProc(4243, ProcFile::Stat),
            ]
        );
    }

    #[test]
    fn one_uid_cannot_hold_more_than_its_share_of_the_spool() {
        let (entries, spool) = entries_of_callers(u32::try_from(MAX_ENTRIES_PER_UID).unwrap());
        let refs: Vec<&PendingRequest> = entries.iter().collect();
        let minting = entry('a', 4242, 5_000, NOW + 900);

        // Eight live callers of uid 1000: a ninth is refused, and nothing is
        // written for it.
        let err = publish_as_1000(&spool, &all_running(&refs, 1000), &minting).unwrap_err();
        assert_eq!(
            err,
            MintError::UidFull {
                uid: 1000,
                entries: MAX_ENTRIES_PER_UID
            }
        );
        assert!(!spool.files().contains_key(nonce('a').as_bytes()));
        assert_eq!(spool.calls().last(), Some(&SpoolCall::Unlock));

        // The same eight, running as someone else, are not its share.
        publish_as_1000(&spool, &all_running(&refs, 2000), &minting).unwrap();
    }

    #[test]
    fn a_set_uid_caller_stays_on_its_real_users_share() {
        // Each caller exec'd a set-user-ID-root program after minting: its
        // effective uid is 0 now, its real uid is still 1000. Counting only
        // the effective uid would let it shed its share by doing so.
        let (entries, spool) = entries_of_callers(u32::try_from(MAX_ENTRIES_PER_UID).unwrap());
        let host = entries
            .iter()
            .fold(FakePeer::new(), |host, each| running(host, each, 1000, 0));
        let minting = entry('a', 4242, 5_000, NOW + 900);
        assert_eq!(
            publish_as_1000(&spool, &host, &minting),
            Err(MintError::UidFull {
                uid: 1000,
                entries: 8
            })
        );
    }

    #[test]
    fn a_caller_that_became_the_asking_uid_counts_against_it() {
        // Started as another user, now effectively 1000: the effective uid is
        // what the broker matches the asker by, so that counts too.
        let (entries, spool) = entries_of_callers(u32::try_from(MAX_ENTRIES_PER_UID).unwrap());
        let host = entries.iter().fold(FakePeer::new(), |host, each| {
            running(host, each, 2000, 1000)
        });
        let minting = entry('a', 4242, 5_000, NOW + 900);
        assert_eq!(
            publish_as_1000(&spool, &host, &minting),
            Err(MintError::UidFull {
                uid: 1000,
                entries: 8
            })
        );
    }

    #[test]
    fn the_ttl_covers_sudos_default_conversation() {
        // passwd_timeout (5 minutes) times passwd_tries (3).
        #[cfg(not(feature = "lane-short-ttl"))]
        assert_eq!(REQUEST_TTL_MILLIS, 5 * 60 * 3 * 1_000);
        #[cfg(feature = "lane-short-ttl")]
        assert_eq!(REQUEST_TTL_MILLIS, 20 * 1_000);
    }
}
