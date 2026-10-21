//! Minting: the spool entry the gate will act on, and the rules of the spool
//! it goes into.
//!
//! An entry is minted only for a permitted decision. On the password path a
//! decision that demands confirmation is permitted too — the password `sudo`
//! asks for *is* the confirmation (decision 6 in `docs/todo/README.md`) — so it
//! mints with `confirmed = false`, and the gate's `-auth` name is what tells
//! the gate a password was typed.
//!
//! # The spool's rules
//!
//! Applied under the spool's exclusive lock, every time an entry is minted:
//!
//! * **One live entry per caller.** An older entry for the same
//!   `(pid, starttime)` is removed first, so the gate's lookup by its caller's
//!   pin finds exactly one entry or none, never two to choose between.
//! * **Expired entries go.** Anything at or past its deadline is removed.
//! * **Entries nobody can use go.** An entry whose caller is no longer the
//!   process it was minted for — exited, or its pid now someone else's — can
//!   never be consumed: the gate checks its own caller against the pin. So an
//!   entry counts as live only while `/proc/<pid>/stat` still shows the pinned
//!   `(pid, starttime)`, and a caller that cannot be shown alive is pruned.
//!   Without this, one group member could run 64 clients one after another,
//!   each exiting before the next, and refuse everyone for fifteen minutes.
//! * **Junk goes.** A temporary file left by a broker that died mid-write —
//!   no write can be in progress while the lock is held — and any nonce-named
//!   entry that cannot be read back as a request.
//! * **Bounded.** At most [`MAX_SPOOL_ENTRIES`] live entries and
//!   [`MAX_SPOOL_BYTES`] of them, so no member of the `aido` group can fill
//!   `/run` by asking; and at most [`MAX_ENTRIES_PER_UID`] whose live caller
//!   runs as the asking uid, so filling the spool takes eight members, not one.
//!   The entry does not record a uid, so the count reads each live caller's
//!   real and effective uids from `/proc/<pid>/status` and counts the entry
//!   against both: a caller that exec'd a set-user-ID program after minting
//!   keeps its real uid, so it stays on its user's share.
//!
//! Names that are neither nonces nor temporary files are left alone: only root
//! can create them, and the broker removes only what it can identify as its
//! own.

use std::fmt::Write as _;

use aido_gate::request::{MonotonicSecs, PendingRequest, REQUEST_SCHEMA_VERSION, is_nonce};
use aido_policy::Decision;
use aido_sys::{
    Entropy, PeerCalls, ProcFile, Spool, SpoolError, StatusUids, SysError, TEMP_PREFIX, parse_stat,
    parse_status_uids,
};
use aido_wire::BrokerRequest;

use crate::identify::PeerIdentity;

/// How long a minted entry lives, in seconds: fifteen minutes.
///
/// Long enough for `sudo`'s whole conversation at its defaults —
/// `passwd_timeout` is five minutes per prompt and `passwd_tries` is three —
/// so a human who mistypes twice slowly is not refused for being human. Short
/// enough that an entry for a process that died does not outlive the session
/// it belonged to by much; and the entry is bound to that process's
/// `(pid, starttime)` and consumed on use, so its lifetime is not the window
/// in which it can be abused.
pub const REQUEST_TTL_SECS: u64 = 15 * 60;

/// The most live entries the spool holds.
pub const MAX_SPOOL_ENTRIES: usize = 64;

/// The most bytes of live entries the spool holds.
pub const MAX_SPOOL_BYTES: usize = 1024 * 1024;

/// The most live entries whose callers run as one uid: an eighth of the
/// spool.
///
/// One caller holds at most one entry, so this is eight `aido` processes of
/// one user waiting on `sudo` at once — the same number of connections the
/// socket lets one uid hold open (`MaxConnectionsPerSource=`).
pub const MAX_ENTRIES_PER_UID: usize = 8;

// One uid must never be able to take the whole spool.
const _: () = assert!(MAX_ENTRIES_PER_UID < MAX_SPOOL_ENTRIES);

/// The largest entry the broker reads back, in bytes.
///
/// Comfortably above anything it writes: an entry is a request of at most
/// `aido_wire::MAX_REQUEST_BYTES` plus fields of known size.
pub const MAX_ENTRY_BYTES: usize = 32 * 1024;

// An entry the broker wrote must always be one it can read back.
const _: () = assert!(MAX_ENTRY_BYTES > aido_wire::MAX_REQUEST_BYTES);

// And a spool kept within the broker's limits must be one the gate will walk
// and read: it refuses a spool with more names than `MAX_SPOOL_NAMES` and
// reads no entry past its own `MAX_ENTRY_BYTES`. The broker's ceilings sit
// well below the gate's, so the gate's bounds only ever bite on a spool the
// broker did not keep.
const _: () = assert!(MAX_SPOOL_ENTRIES < aido_gate::run::MAX_SPOOL_NAMES);
const _: () = assert!(MAX_ENTRY_BYTES <= aido_gate::run::MAX_ENTRY_BYTES);

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
}

/// An entry about to be published, and whose share of the spool it takes.
#[derive(Clone, Copy, Debug)]
pub struct Minting<'a> {
    /// The entry.
    pub entry: &'a PendingRequest,
    /// The entry as it is written.
    pub json: &'a str,
    /// The effective uid its caller connected with.
    pub uid: u32,
    /// Now, in whole seconds of `CLOCK_MONOTONIC`.
    pub now: u64,
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
    deadline: u64,
    nonce: String,
) -> Result<PendingRequest, MintError> {
    let Some(action) = &decision.action else {
        return Err(MintError::NoAction);
    };
    Ok(PendingRequest {
        schema_version: REQUEST_SCHEMA_VERSION,
        nonce,
        caller_pid: identity.pid,
        caller_starttime: identity.starttime,
        action: action.as_str().to_owned(),
        program: request.program.clone(),
        argv: request.argv.clone(),
        generation,
        deadline: MonotonicSecs(deadline),
        confirmed: false,
        confirmed_by: None,
        claimed_classification: request.claimed_classification.clone(),
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
    for name in spool.names().map_err(MintError::Spool)? {
        match classify(spool, callers, &name, minting) {
            Existing::Live { size, same_uid } => {
                entries = entries.saturating_add(1);
                bytes = bytes.saturating_add(size);
                this_uid = this_uid.saturating_add(usize::from(same_uid));
            }
            Existing::Stale => spool.remove(&name).map_err(MintError::Spool)?,
            Existing::Foreign => {}
        }
    }
    if entries >= MAX_SPOOL_ENTRIES || bytes.saturating_add(minting.json.len()) > MAX_SPOOL_BYTES {
        return Err(MintError::Full { entries, bytes });
    }
    if this_uid >= MAX_ENTRIES_PER_UID {
        return Err(MintError::UidFull {
            uid: minting.uid,
            entries: this_uid,
        });
    }
    match spool.publish(&minting.entry.nonce, minting.json.as_bytes()) {
        Ok(()) => Ok(()),
        Err(SpoolError::Exists { .. }) => Err(MintError::Collision {
            nonce: minting.entry.nonce.clone(),
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
    },
    /// Something to remove: expired, superseded, misnamed, unreadable, a
    /// temporary file, or an entry whose caller cannot be shown alive.
    Stale,
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
    let expired = existing.deadline <= MonotonicSecs(minting.now);
    let misnamed = existing.nonce != text;
    let superseded = existing.caller_pid == minting.entry.caller_pid
        && existing.caller_starttime == minting.entry.caller_starttime;
    if expired || misnamed || superseded {
        return Existing::Stale;
    }
    match live_caller(callers, &existing) {
        Some(uids) => Existing::Live {
            size: bytes.len(),
            same_uid: uids.real == minting.uid || uids.effective == minting.uid,
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

    use aido_policy::{ActionId, DenialCode, Verdict};
    use aido_sys::{Attestation, FakeEntropy, FakePeer, FakeSpool, PeerCall, SpoolCall};

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
            action: "aido.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
            generation: 7,
            deadline: MonotonicSecs(deadline),
            confirmed: false,
            confirmed_by: None,
            claimed_classification: "unattested".to_owned(),
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
        format!("{pid} (aido) {}", tail.join(" ")).into_bytes()
    }

    /// A `/proc/<pid>/status` whose process has these real and effective uids.
    fn status(real: u32, effective: u32) -> Vec<u8> {
        format!("Name:\taido\nUid:\t{real}\t{effective}\t{effective}\t{effective}\n").into_bytes()
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

    /// Publishes `minting` for a caller running as uid 1000, at `NOW`.
    fn publish_as_1000(
        spool: &FakeSpool,
        host: &FakePeer,
        minting: &PendingRequest,
    ) -> Result<(), MintError> {
        publish(
            spool,
            host,
            &Minting {
                entry: minting,
                json: &minting.to_json(),
                uid: 1000,
                now: NOW,
            },
        )
    }

    fn permitted() -> Decision {
        let mut decision = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        decision.verdict = Verdict::Allow;
        decision.denial = None;
        decision.action = Some(ActionId::new("aido.svc.restart"));
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
            1_900,
            nonce('a'),
        )
        .unwrap();
        assert_eq!(minted, {
            let mut expected = entry('a', 4242, 5_000, 1_900);
            expected.claimed_classification = "enrolled-agent-yolo".to_owned();
            expected
        });
        assert!(!minted.confirmed);
        assert_eq!(minted.confirmed_by, None);
    }

    #[test]
    fn a_permitted_decision_that_names_no_action_mints_nothing() {
        let mut decision = permitted();
        decision.action = None;
        let request = BrokerRequest::new("/usr/bin/systemctl", Vec::new(), "x");
        assert_eq!(
            entry_for(&decision, &identity(1, 1), &request, 7, 1, nonce('a')),
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
            at: "/run/aido/req".to_owned(),
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
        assert_eq!(REQUEST_TTL_SECS, 5 * 60 * 3);
    }
}
