//! Root-held requests that need a human decision.
//!
//! Queue records contain the broker's canonical command and the policy
//! generation under which it was requested. A record is only a request: it
//! never authorizes execution. The caller must be a listed reviewer and the
//! command must be re-decided against the current rules before the password
//! gate can be reached.

use serde::{Deserialize, Serialize};
use term_sanitize::{Clean, Limits, display_bytes, display_str};
use xudo_policy::HarnessRegistry;

/// Default lifetime of a queued request. Root may configure a shorter one.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
/// Pending requests allowed for one harness uid.
pub const MAX_PER_UID: usize = 32;
/// Pending requests allowed across all harnesses.
pub const MAX_TOTAL: usize = 1024;
/// Largest serialized entry accepted from the root-held store.
pub const MAX_ENTRY_BYTES: usize = 32 * 1024;
/// Maximum argument count retained in one queue entry.
pub const MAX_ARGV_COUNT: usize = 256;
/// Maximum untrusted reason length in UTF-8 bytes.
pub const MAX_REASON_BYTES: usize = 1024;
/// Maximum directory entries read while counting the queue.
pub const MAX_FILES_WALKED: usize = MAX_TOTAL + 1;

/// Applies the root setting. Values longer than one day are clamped, never
/// allowed to extend the queue's default lifetime.
#[must_use]
pub const fn effective_ttl(configured_secs: Option<u64>) -> u64 {
    match configured_secs {
        Some(value) if value < DEFAULT_TTL_SECS => value,
        _ => DEFAULT_TTL_SECS,
    }
}

/// State kept by the broker. The agent can neither set nor update it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueState {
    /// Waiting for a reviewer.
    Pending,
    /// A human has atomically taken the entry for the Q1c gate path.
    Claimed,
    /// Completed after the gate's audit record was observed.
    Done,
}

/// A single broker-owned request. `reason` is untrusted display text only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueEntry {
    /// 64-character lowercase identifier, also the storage filename stem.
    pub id: String,
    /// Canonical program followed by canonical operands.
    pub argv: Vec<Vec<u8>>,
    /// Working directory the agent supplied.
    ///
    /// Display only. A queued command is never started from this path. Q1c
    /// reads `/proc/<pid>/cwd` through the pidfd when a reviewer runs it.
    pub cwd: Vec<u8>,
    /// Kernel boot id captured when the broker admitted the request.
    ///
    /// A record whose boot id is not the current one is expired: boottime
    /// milliseconds restart their meaning across a reboot, so a persisted
    /// deadline must not come back to life.
    pub boot_id: String,
    /// Root registry label that classified the requester.
    pub harness: String,
    /// Kernel-attested uid of the harness.
    pub uid: u32,
    /// Rule that produced `ask-human`.
    pub rule_id: String,
    /// Ruleset generation at submission.
    pub generation: u64,
    /// `CLOCK_BOOTTIME` milliseconds at submission.
    pub queued_at: u64,
    /// `CLOCK_BOOTTIME` milliseconds after which the record cannot be run.
    pub expires_at: u64,
    /// Untrusted text; render only after terminal sanitization.
    pub reason: Option<String>,
    /// Broker-owned terminal status.
    pub state: QueueState,
}

impl QueueEntry {
    /// Validated constructor used by the broker before persistence.
    ///
    /// # Errors
    ///
    /// Returns the first validation error for any untrusted or oversized field.
    pub fn new(entry: Self) -> Result<Self, QueueError> {
        entry.validate()?;
        Ok(entry)
    }
    /// Validates fields before they can become a filename or persistent record.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an unsafe id, invalid argv/cwd, or
    /// oversized record.
    pub fn validate(&self) -> Result<(), QueueError> {
        if self.id.len() != 64
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(QueueError::InvalidId);
        }
        if self.argv.is_empty() || self.argv.len() > MAX_ARGV_COUNT {
            return Err(QueueError::InvalidArgvCount);
        }
        if !self.cwd.starts_with(b"/") || self.cwd.contains(&0) {
            return Err(QueueError::InvalidCwd);
        }
        if self
            .argv
            .iter()
            .any(|arg| arg.len() > 4096 || arg.contains(&0))
        {
            return Err(QueueError::InvalidArgument);
        }
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.len() > MAX_REASON_BYTES || reason.contains('\0'))
        {
            return Err(QueueError::InvalidReason);
        }
        if !xudo_wire::is_boot_id(&self.boot_id) {
            return Err(QueueError::InvalidBootId);
        }
        let size = validated_encoded_size(serde_json::to_vec(self));
        if size > MAX_ENTRY_BYTES {
            return Err(QueueError::TooLarge);
        }
        Ok(())
    }

    /// Sanitizes every request-controlled field before it is shown to a person.
    #[must_use]
    pub fn display_fields(&self) -> QueueDisplay {
        let limits = Limits {
            max_cols: 4096,
            max_lines: 1,
        };
        QueueDisplay {
            argv: self
                .argv
                .iter()
                .map(|arg| display_bytes(arg, limits))
                .collect(),
            cwd: display_bytes(&self.cwd, limits),
            harness: display_str(&self.harness, limits),
            reason: self
                .reason
                .as_ref()
                .map(|reason| display_str(reason, limits)),
        }
    }

    /// Whether an entry remains active at `now` on `boot_id`.
    ///
    /// A different boot, or a boot id that is not a lowercase UUID, is expired.
    #[must_use]
    pub fn is_live(&self, now: u64, ttl: u64, boot_id: &str) -> bool {
        // The boot id is checked before equality so a malformed id is expired
        // even when it does not match the stored one. Both arms are reachable
        // from the previous-boot test.
        xudo_wire::is_boot_id(boot_id)
            && self.boot_id == boot_id
            && matches!(self.state, QueueState::Pending | QueueState::Claimed)
            && now >= self.queued_at
            && now < self.expires_at.min(self.queued_at.saturating_add(ttl))
    }

    /// Whether a freshly evaluated request may enter the password path.
    ///
    /// The recorded generation is deliberately not an authorization token:
    /// both the live policy decision and its generation must still match.
    #[must_use]
    pub fn may_run(
        &self,
        now: u64,
        current_generation: u64,
        ttl: u64,
        fresh_human_allow: bool,
        boot_id: &str,
    ) -> bool {
        self.state == QueueState::Pending
            && self.is_live(now, ttl, boot_id)
            && self.generation == current_generation
            && fresh_human_allow
            && !self.argv.is_empty()
    }
}

fn validated_encoded_size(encoded: Result<Vec<u8>, serde_json::Error>) -> usize {
    encoded.map_or_else(|_| MAX_ENTRY_BYTES.saturating_add(1), |bytes| bytes.len())
}

fn publish_encoded_entry(
    store: &dyn xudo_sys::Spool,
    name: &str,
    encoded: Result<Vec<u8>, serde_json::Error>,
) -> Result<(), StoreError> {
    let bytes = encoded.map_err(|_| StoreError::InvalidEntry)?;
    store.publish(name, &bytes)?;
    Ok(())
}

fn replace_encoded_entry(
    store: &dyn xudo_sys::Spool,
    name: &[u8],
    expected: &[u8],
    encoded: Result<Vec<u8>, serde_json::Error>,
) -> Result<(), StoreError> {
    let bytes = encoded.map_err(|_| StoreError::InvalidEntry)?;
    store.replace(name, expected, &bytes)?;
    Ok(())
}

/// Re-decides a claimed command from the exact stored bytes against the current policy.
/// A changed generation, expired record, or non-claimed record is refused before matching.
#[must_use]
pub fn redecide_for_run(
    entry: &QueueEntry,
    policy: &xudo_policy::LoadedRuleSet,
    caller: &xudo_policy::CallerFacts,
    settings: xudo_policy::engine::Settings,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> xudo_policy::Decision {
    if entry.state != QueueState::Claimed
        || !entry.is_live(now, ttl, boot_id)
        || entry.generation != policy.generation.id()
    {
        return xudo_policy::Decision::deny(
            xudo_policy::DenialCode::AskHuman,
            Vec::new(),
            Vec::new(),
        );
    }
    let Some(program) = entry.argv.first() else {
        return xudo_policy::Decision::deny(
            xudo_policy::DenialCode::AskHuman,
            Vec::new(),
            Vec::new(),
        );
    };
    let program = xudo_policy::Arg::new(program.clone());
    let operands = xudo_policy::Argv::new(
        entry
            .argv
            .iter()
            .skip(1)
            .cloned()
            .map(xudo_policy::Arg::new),
    );
    xudo_policy::evaluate_command(&policy.rules, caller, &program, &operands, settings)
}

/// Terminal-safe rendering of request-influenced fields. Never use for policy comparisons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueDisplay {
    /// Sanitized argv bytes.
    pub argv: Vec<Clean>,
    /// Sanitized working directory bytes.
    pub cwd: Clean,
    /// Sanitized root registry label.
    pub harness: Clean,
    /// Sanitized requester reason.
    pub reason: Option<Clean>,
}

/// Whether the peer may see an entry. The harness may inspect its own status;
/// only a configured reviewer may run or dismiss it.
#[must_use]
pub struct Visibility {
    /// Peer may see the entry or its status.
    pub visible: bool,
    /// Peer may act as a reviewer. Must be false for every `EnrolledAgent`.
    pub reviewer: bool,
}

/// Peer class is established by the broker, never supplied in the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerClass {
    /// Peer is classified as a human.
    Human,
    /// Peer is a verified harness.
    EnrolledAgent,
    /// Peer could not be verified.
    Unattested,
}

/// Applies owner-status and reviewer authority rules to a queue entry.
pub fn visibility(
    entry: &QueueEntry,
    peer_uid: u32,
    peer_class: PeerClass,
    registry: &HarnessRegistry,
    passwd: &str,
) -> Visibility {
    let owner = entry.uid == peer_uid;
    let reviewer = peer_class == PeerClass::Human
        && registry.get(&entry.harness).is_some_and(|harness| {
            harness
                .reviewers
                .iter()
                .any(|name| xudo_policy::passwd_uid(passwd, name) == Some(peer_uid))
        });
    Visibility {
        visible: owner || reviewer,
        reviewer: reviewer && !owner,
    }
}

/// Queue capacity decision over the live records only.
#[must_use]
pub fn within_bounds(entries: &[QueueEntry], uid: u32, now: u64, ttl: u64, boot_id: &str) -> bool {
    let live: Vec<&QueueEntry> = entries
        .iter()
        .filter(|entry| entry.is_live(now, ttl, boot_id))
        .collect();
    live.len() < MAX_TOTAL && live.iter().filter(|entry| entry.uid == uid).count() < MAX_PER_UID
}

/// Validation failures for a queue record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QueueError {
    /// Identifier is not a safe 64-character lowercase hex filename.
    #[error("queue id must be 64 lowercase hexadecimal characters")]
    InvalidId,
    /// Argument count is empty or exceeds the storage bound.
    #[error("queue argv count is outside its allowed range")]
    InvalidArgvCount,
    /// Cwd is not an absolute byte path or contains NUL.
    #[error("queue cwd must be an absolute byte path without NUL")]
    InvalidCwd,
    /// Argument violates its byte bound.
    #[error("queue argument exceeds its byte bound or contains NUL")]
    InvalidArgument,
    /// Reason exceeds its byte bound.
    #[error("queue reason exceeds its byte bound or contains NUL")]
    InvalidReason,
    /// Boot id is not the shared lowercase UUID form.
    #[error("queue boot id must be a lowercase UUID")]
    InvalidBootId,
    /// Encoded entry exceeds its storage bound.
    #[error("serialized queue entry exceeds MAX_ENTRY_BYTES")]
    TooLarge,
}

/// Queue store failures. Every failure denies admission or a claim.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// Backing spool operation failed.
    #[error(transparent)]
    Spool(#[from] xudo_sys::SpoolError),
    /// Stored bytes did not decode to a valid entry.
    #[error("invalid queue entry")]
    InvalidEntry,
    /// Queue capacity was reached.
    #[error("queue capacity reached")]
    Full,
    /// Too many files were present to inspect safely.
    #[error("queue directory exceeds the bounded file walk")]
    TooManyFiles,
    /// Entry is absent, expired, or already claimed.
    #[error("queue entry is not pending and live")]
    NotPending,
    /// The records a plan would prune changed before publication.
    ///
    /// Publication is refused so an audit of that plan is not followed by a
    /// different deletion.
    #[error("queue changed before admission could be published")]
    Conflict,
    /// Completion lacks a successful gate audit receipt.
    #[error("queue completion requires a successful gate audit receipt")]
    MissingGateAudit,
}

/// Lists and validates all queue records with a strict walk bound.
///
/// # Errors
///
/// Returns an error if listing, reading, decoding, or validating any entry
/// fails, or if the bounded walk detects too many files.
pub fn load_all(store: &dyn xudo_sys::Spool) -> Result<Vec<QueueEntry>, StoreError> {
    let names = store.names_up_to(MAX_FILES_WALKED)?;
    if names.len() >= MAX_FILES_WALKED {
        return Err(StoreError::TooManyFiles);
    }
    let mut entries = Vec::new();
    for name in names {
        if !name.ends_with(b".json") {
            continue;
        }
        let bytes = store.read(&name, MAX_ENTRY_BYTES)?;
        let entry: QueueEntry =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidEntry)?;
        entry.validate().map_err(|_| StoreError::InvalidEntry)?;
        entries.push(entry);
    }
    Ok(entries)
}

/// Removes completed and expired records under the cross-process queue lock.
///
/// # Errors
///
/// Returns an error if the lock, bounded scan, or removal fails.
pub fn prune(
    store: &dyn xudo_sys::Spool,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<Vec<String>, StoreError> {
    store.lock()?;
    let result = (|| {
        let entries = load_all(store)?;
        let mut removed = Vec::new();
        for entry in entries {
            if !entry.is_live(now, ttl, boot_id) {
                store.remove(format!("{}.json", entry.id).as_bytes())?;
                removed.push(entry.id);
            }
        }
        Ok(removed)
    })();
    store.unlock();
    result
}

/// The ids `commit_admission` would remove, without removing or publishing.
///
/// The caller audits this set, then [`commit_admission`] publishes only when
/// the set is still exactly these ids.
///
/// # Errors
///
/// Returns an error if the entry is invalid or not live, the lock or scan
/// fails, or the live records are already at capacity.
pub fn plan_admission(
    store: &dyn xudo_sys::Spool,
    entry: &QueueEntry,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<Vec<String>, StoreError> {
    entry.validate().map_err(|_| StoreError::InvalidEntry)?;
    if !entry.is_live(now, ttl, boot_id) {
        return Err(StoreError::NotPending);
    }
    store.lock()?;
    let result = admission_plan(store, entry, now, ttl, boot_id);
    store.unlock();
    result
}

/// Removes `expected_pruned` and publishes `entry` when that set is unchanged.
///
/// # Errors
///
/// Returns [`StoreError::Conflict`] when the prune set changed, and does not
/// publish. Capacity, validation, lock, and publication failures also refuse.
pub fn commit_admission(
    store: &dyn xudo_sys::Spool,
    entry: &QueueEntry,
    expected_pruned: &[String],
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<(), StoreError> {
    entry.validate().map_err(|_| StoreError::InvalidEntry)?;
    store.lock()?;
    let result = (|| {
        let pruned = admission_plan(store, entry, now, ttl, boot_id)?;
        if pruned != expected_pruned {
            return Err(StoreError::Conflict);
        }
        for id in &pruned {
            store.remove(format!("{id}.json").as_bytes())?;
        }
        publish_encoded_entry(
            store,
            &format!("{}.json", entry.id),
            serde_json::to_vec(entry),
        )?;
        Ok(())
    })();
    store.unlock();
    result
}

fn admission_plan(
    store: &dyn xudo_sys::Spool,
    entry: &QueueEntry,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<Vec<String>, StoreError> {
    let entries = load_all(store)?;
    let live: Vec<QueueEntry> = entries
        .iter()
        .filter(|old| old.is_live(now, ttl, boot_id))
        .cloned()
        .collect();
    if !within_bounds(&live, entry.uid, now, ttl, boot_id) {
        return Err(StoreError::Full);
    }
    let mut pruned: Vec<String> = entries
        .into_iter()
        .filter(|old| !old.is_live(now, ttl, boot_id))
        .map(|old| old.id)
        .collect();
    pruned.sort();
    Ok(pruned)
}

/// Inserts one record while holding the cross-process directory lock.
/// Expired and completed entries are removed first so they free capacity.
///
/// # Errors
///
/// Returns an error if validation, the bounded scan, pruning, capacity check,
/// lock, or publication fails.
pub fn admit(
    store: &dyn xudo_sys::Spool,
    entry: &QueueEntry,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<Vec<String>, StoreError> {
    let pruned = plan_admission(store, entry, now, ttl, boot_id)?;
    commit_admission(store, entry, &pruned, now, ttl, boot_id)?;
    Ok(pruned)
}

/// Atomically claims a pending live entry. Two broker processes cannot both win.
///
/// # Errors
///
/// Returns an error if the entry is invalid, absent, expired, already claimed,
/// or the locked compare-and-replace fails.
pub fn claim(
    store: &dyn xudo_sys::Spool,
    id: &str,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<QueueEntry, StoreError> {
    store.lock()?;
    let result = (|| {
        let name = format!("{id}.json");
        let bytes = store.read(name.as_bytes(), MAX_ENTRY_BYTES)?;
        let mut entry: QueueEntry =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidEntry)?;
        entry.validate().map_err(|_| StoreError::InvalidEntry)?;
        if entry.id != id || entry.state != QueueState::Pending || !entry.is_live(now, ttl, boot_id)
        {
            return Err(StoreError::NotPending);
        }
        entry.state = QueueState::Claimed;
        replace_encoded_entry(store, name.as_bytes(), &bytes, serde_json::to_vec(&entry))?;
        Ok(entry)
    })();
    store.unlock();
    result
}

/// Marks a claimed entry done after the caller has observed the gate's audit record.
/// The Q1c execution path will own that observation; this API deliberately does not execute.
///
/// # Errors
///
/// Returns an error if the receipt is not an allowed gate audit, the entry is
/// invalid or not claimed, or the locked compare-and-replace fails.
pub fn complete_after_gate_audit(
    store: &dyn xudo_sys::Spool,
    id: &str,
    receipt: &xudo_sys::AuditReceipt,
) -> Result<QueueEntry, StoreError> {
    if receipt.decision() != xudo_audit::record::Decision::Allowed {
        return Err(StoreError::MissingGateAudit);
    }
    store.lock()?;
    let result = (|| {
        let name = format!("{id}.json");
        let bytes = store.read(name.as_bytes(), MAX_ENTRY_BYTES)?;
        let mut entry: QueueEntry =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidEntry)?;
        entry.validate().map_err(|_| StoreError::InvalidEntry)?;
        if entry.id != id || entry.state != QueueState::Claimed {
            return Err(StoreError::NotPending);
        }
        entry.state = QueueState::Done;
        replace_encoded_entry(store, name.as_bytes(), &bytes, serde_json::to_vec(&entry))?;
        Ok(entry)
    })();
    store.unlock();
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;

    struct Unserializable;

    impl serde::Serialize for Unserializable {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("deliberate test failure"))
        }
    }

    fn entry(id: u64) -> QueueEntry {
        QueueEntry {
            id: format!("{id:064x}"),
            argv: vec![b"/usr/bin/apt-get".to_vec(), b"upgrade".to_vec()],
            cwd: b"/srv".to_vec(),
            harness: "codex".into(),
            uid: 1001,
            rule_id: "xudo.pkg.upgrade".into(),
            generation: 7,
            queued_at: 100,
            expires_at: 100 + DEFAULT_TTL_SECS * 1000,
            reason: Some("please run".into()),
            state: QueueState::Pending,
            boot_id: BOOT.to_owned(),
        }
    }

    const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";

    #[test]
    fn admission_accepts_the_last_per_uid_slot_and_refuses_the_next() {
        let store = xudo_sys::FakeSpool::new();
        for id in 0..MAX_PER_UID - 1 {
            admit(
                &store,
                &entry(id as u64),
                101,
                DEFAULT_TTL_SECS * 1000,
                BOOT,
            )
            .unwrap();
        }
        admit(
            &store,
            &entry((MAX_PER_UID - 1) as u64),
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT,
        )
        .unwrap();
        assert_eq!(
            admit(
                &store,
                &entry(MAX_PER_UID as u64),
                101,
                DEFAULT_TTL_SECS * 1000,
                BOOT
            ),
            Err(StoreError::Full)
        );
    }

    #[test]
    fn broker_admission_and_claim_use_a_private_on_disk_spool() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-tmp")
            .join(format!("queue-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = xudo_sys::SpoolDir::open_test_directory(&path).unwrap();
        let record = entry(9);
        admit(&store, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let stored = load_all(&store).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored.first(), Some(&record));
        assert_eq!(
            claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT)
                .unwrap()
                .state,
            QueueState::Claimed
        );
        assert_eq!(
            claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT),
            Err(StoreError::NotPending)
        );
        let metadata = std::fs::metadata(path.join(format!("{}.json", record.id))).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        drop(store);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn expired_and_done_entries_free_capacity_during_admission() {
        let store = xudo_sys::FakeSpool::new();
        for id in 0..MAX_PER_UID {
            let mut record = entry(id as u64);
            if id == 0 {
                record.state = QueueState::Done;
            }
            xudo_sys::Spool::publish(
                &store,
                &format!("{}.json", record.id),
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }
        let pruned = admit(
            &store,
            &entry(MAX_PER_UID as u64),
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT,
        )
        .unwrap();
        assert_eq!(pruned, [entry(0).id]);

        let expired = xudo_sys::FakeSpool::new();
        let mut stale = entry(77);
        stale.expires_at = 200;
        admit(&expired, &stale, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let pruned = admit(&expired, &entry(78), 201, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        assert_eq!(pruned, [stale.id]);
    }

    #[test]
    fn prune_removes_expired_entries_from_the_store() {
        let expired = entry(91);
        let store = xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", expired.id),
            serde_json::to_vec(&expired).unwrap(),
        );
        assert_eq!(
            prune(&store, expired.expires_at, 1000, BOOT).unwrap(),
            [expired.id]
        );
        assert!(load_all(&store).unwrap().is_empty());
    }

    #[test]
    fn two_concurrent_claims_for_one_entry_have_only_one_winner() {
        use std::{os::unix::fs::PermissionsExt, sync::Barrier};
        // Two open file descriptions of one directory. `flock` excludes across
        // those descriptions, which is what two processes get from two opens.
        // This does not spawn a second OS process.
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-tmp")
            .join(format!("queue-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = xudo_sys::SpoolDir::open_test_directory(&path).unwrap();
        let second = xudo_sys::SpoolDir::open_test_directory(&path).unwrap();
        let record = entry(42);
        admit(&first, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let barrier = std::sync::Arc::new(Barrier::new(3));
        let spawn = |store: xudo_sys::SpoolDir| {
            let barrier = std::sync::Arc::clone(&barrier);
            let id = record.id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                claim(&store, &id, 101, DEFAULT_TTL_SECS * 1000, BOOT).is_ok()
            })
        };
        let claims = [spawn(first), spawn(second)];
        barrier.wait();
        let mut winners = 0;
        for claim in claims {
            if claim.join().unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn an_entry_from_a_previous_boot_is_expired() {
        let mut previous = entry(9);
        previous.boot_id = "11111111-2222-3333-4444-555555555555".to_owned();
        assert!(!previous.is_live(101, DEFAULT_TTL_SECS * 1000, BOOT));
        assert!(!entry(1).is_live(101, DEFAULT_TTL_SECS * 1000, "not-a-uuid"));
        let store = xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", previous.id),
            serde_json::to_vec(&previous).unwrap(),
        );
        assert_eq!(
            prune(&store, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap(),
            [previous.id]
        );
        assert!(load_all(&store).unwrap().is_empty());
    }

    #[test]
    fn plan_admission_refuses_an_entry_from_a_previous_boot() {
        let mut previous = entry(9);
        previous.boot_id = "11111111-2222-3333-4444-555555555555".to_owned();
        let store = xudo_sys::FakeSpool::new();
        assert_eq!(
            plan_admission(&store, &previous, 101, DEFAULT_TTL_SECS * 1000, BOOT),
            Err(StoreError::NotPending)
        );
        assert!(load_all(&store).unwrap().is_empty());
    }

    #[test]
    fn commit_admission_refuses_before_it_publishes() {
        let mut bad = entry(1);
        bad.boot_id = "not-a-boot-id".to_owned();
        let store = xudo_sys::FakeSpool::new();
        assert_eq!(
            commit_admission(&store, &bad, &[], 101, 1000, BOOT),
            Err(StoreError::InvalidEntry)
        );
        let error = xudo_sys::SpoolError::NotADirectory { at: "queue".into() };
        assert_eq!(
            commit_admission(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &entry(1),
                &[],
                101,
                1000,
                BOOT
            ),
            Err(StoreError::Spool(error.clone()))
        );
        assert_eq!(
            commit_admission(
                &xudo_sys::FakeSpool::new().failing_names(error.clone()),
                &entry(2),
                &[],
                101,
                1000,
                BOOT
            ),
            Err(StoreError::Spool(error))
        );
        assert!(load_all(&store).unwrap().is_empty());
    }

    #[test]
    fn a_queue_entry_with_a_malformed_boot_id_is_refused() {
        let mut bad = entry(1);
        bad.boot_id = "not-a-boot-id".to_owned();
        let error = QueueEntry::new(bad).unwrap_err();
        assert_eq!(error, QueueError::InvalidBootId);
        assert_eq!(error.to_string(), "queue boot id must be a lowercase UUID");
    }

    #[test]
    fn a_changed_prune_set_is_not_published() {
        let mut stale = entry(3);
        stale.expires_at = 50;
        let store = xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", stale.id),
            serde_json::to_vec(&stale).unwrap(),
        );
        let fresh = entry(4);
        let planned = plan_admission(&store, &fresh, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        assert_eq!(planned, [stale.id.clone()]);
        let error =
            commit_admission(&store, &fresh, &[], 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap_err();
        assert_eq!(error, StoreError::Conflict);
        assert_eq!(
            error.to_string(),
            "queue changed before admission could be published"
        );
        let left = load_all(&store).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, stale.id);
        assert_ne!(left[0].id, fresh.id);
    }

    #[test]
    fn a_denial_audit_cannot_mark_a_claim_done() {
        let store = xudo_sys::FakeSpool::new();
        let record = entry(43);
        admit(&store, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let mut audit = xudo_sys::FakeAuditSink::new();
        let receipt = xudo_sys::AuditSink::append(&mut audit, &|previous| {
            xudo_audit::record::Record::after(
                previous,
                xudo_audit::record::Decision::Denied,
                Vec::new(),
                "human",
            )
        })
        .unwrap();
        assert_eq!(
            complete_after_gate_audit(&store, &record.id, &receipt),
            Err(StoreError::MissingGateAudit)
        );
        assert_eq!(load_all(&store).unwrap()[0].state, QueueState::Claimed);
        let mut gate_audit = xudo_sys::FakeAuditSink::new();
        let gate_receipt = xudo_sys::AuditSink::append(&mut gate_audit, &|previous| {
            xudo_audit::record::Record::after(
                previous,
                xudo_audit::record::Decision::Allowed,
                Vec::new(),
                "human",
            )
        })
        .unwrap();
        let completed = complete_after_gate_audit(&store, &record.id, &gate_receipt).unwrap();
        assert_eq!(completed.state, QueueState::Done);
    }

    fn registry() -> HarnessRegistry {
        HarnessRegistry::from_files([(
            "codex.toml",
            "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n",
        )])
        .unwrap()
    }

    fn policy_for(exe: &str) -> xudo_policy::LoadedRuleSet {
        let text = format!(
            "[[action]]\nid = \"xudo.queue.test\"\ntier = \"diag-read\"\nexe = \"{exe}\"\nargs = [{{ name = \"verb\", matcher = {{ literal = \"upgrade\" }} }}]\n"
        );
        xudo_policy::load_rule_files(vec![xudo_policy::RuleFile {
            name: b"queue.toml".to_vec(),
            bytes: text.into_bytes(),
        }])
        .unwrap()
    }

    #[test]
    fn an_agent_cannot_edit_or_delete_a_queued_entry() {
        let record = entry(1);
        let access = visibility(
            &record,
            1001,
            PeerClass::EnrolledAgent,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(access.visible);
        assert!(!access.reviewer);
        assert_eq!(record.state, QueueState::Pending);
    }

    #[test]
    fn a_queued_entry_runs_only_through_the_password_path() {
        let store = xudo_sys::FakeSpool::new();
        let record = entry(1);
        admit(&store, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let claimed = claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        assert_eq!(claimed.state, QueueState::Claimed);
        // Q1b exposes only the claim. Q1c must send this claim through the -auth gate.
        assert!(!claimed.may_run(101, 7, DEFAULT_TTL_SECS * 1000, true, BOOT));
    }

    #[test]
    fn a_queued_entry_is_re_decided_at_run_time() {
        let record = entry(1);
        assert!(!record.may_run(101, 7, DEFAULT_TTL_SECS * 1000, false, BOOT));
        assert!(record.may_run(101, 7, DEFAULT_TTL_SECS * 1000, true, BOOT));
        let policy = policy_for("/usr/bin/apt-get");
        let mut claimed = record.clone();
        claimed.state = QueueState::Claimed;
        claimed.generation = policy.generation.id();
        let human = xudo_policy::CallerFacts::new(xudo_policy::Classification::Human, 1000);
        let decision = redecide_for_run(
            &claimed,
            &policy,
            &human,
            xudo_policy::engine::Settings::default(),
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT,
        );
        assert_eq!(decision.verdict, xudo_policy::Verdict::Allow);
    }

    #[test]
    fn a_rules_change_after_queueing_denies_the_run() {
        let mut claimed = entry(1);
        claimed.state = QueueState::Claimed;
        let old_policy = policy_for("/usr/bin/apt-get");
        claimed.generation = old_policy.generation.id();
        let changed_policy = policy_for("/usr/bin/true");
        let human = xudo_policy::CallerFacts::new(xudo_policy::Classification::Human, 1000);
        let decision = redecide_for_run(
            &claimed,
            &changed_policy,
            &human,
            xudo_policy::engine::Settings::default(),
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT,
        );
        assert_eq!(decision.verdict, xudo_policy::Verdict::Deny);
        assert_eq!(decision.denial, Some(xudo_policy::DenialCode::AskHuman));
    }

    #[test]
    fn an_expired_entry_cannot_run() {
        let record = entry(1);
        assert!(!record.may_run(record.expires_at, 7, DEFAULT_TTL_SECS * 1000, true, BOOT));
    }

    #[test]
    fn a_harness_cannot_run_or_dismiss_its_own_entry() {
        let access = visibility(
            &entry(1),
            1001,
            PeerClass::EnrolledAgent,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(access.visible);
        assert!(!access.reviewer);
    }

    #[test]
    fn queue_flood_stops_at_the_per_uid_bound() {
        let entries: Vec<QueueEntry> = (0..MAX_PER_UID).map(|id| entry(id as u64)).collect();
        assert!(!within_bounds(
            &entries,
            1001,
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT
        ));
        assert!(within_bounds(
            &entries,
            2002,
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT
        ));
    }

    #[test]
    fn queue_flood_stops_at_the_global_bound() {
        let entries: Vec<QueueEntry> = (0..MAX_TOTAL)
            .map(|uid| {
                let mut record = entry(uid as u64);
                record.uid = u32::try_from(uid).unwrap();
                record
            })
            .collect();
        assert!(!within_bounds(
            &entries,
            u32::MAX,
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT
        ));
    }

    #[test]
    fn a_completed_entry_is_not_pending_or_runnable() {
        let mut record = entry(1);
        record.state = QueueState::Done;
        assert!(!record.is_live(101, DEFAULT_TTL_SECS * 1000, BOOT));
        assert!(!record.may_run(101, 7, DEFAULT_TTL_SECS * 1000, true, BOOT));
    }

    #[test]
    fn a_non_reviewer_cannot_list_another_harness_queue() {
        let access = visibility(
            &entry(1),
            2002,
            PeerClass::Human,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(!access.visible);
        assert!(!access.reviewer);
    }

    #[test]
    fn a_configured_reviewer_can_list_another_harness_entry() {
        let access = visibility(
            &entry(1),
            1000,
            PeerClass::Human,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(access.visible);
        assert!(access.reviewer);
    }

    #[test]
    fn a_reviewer_uid_equal_to_the_owner_cannot_review_its_own_entry() {
        let access = visibility(
            &entry(1),
            1001,
            PeerClass::Human,
            &registry(),
            "alice:x:1001:1000::/:/bin/sh\n",
        );
        assert!(access.visible);
        assert!(!access.reviewer);
    }

    #[test]
    fn an_enrolled_agent_cannot_act_as_a_configured_reviewer() {
        let access = visibility(
            &entry(1),
            1000,
            PeerClass::EnrolledAgent,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(!access.visible);
        assert!(!access.reviewer);
    }

    #[test]
    fn an_entry_from_the_future_is_expired_and_a_shortened_ttl_applies() {
        let mut record = entry(1);
        assert!(!record.is_live(99, DEFAULT_TTL_SECS * 1000, BOOT));
        record.queued_at = 100;
        record.expires_at = 100 + DEFAULT_TTL_SECS * 1000;
        assert!(!record.is_live(60_101, 60_000, BOOT));
    }

    #[test]
    fn queue_entry_rejects_filename_and_payload_attacks() {
        let mut record = entry(1);
        assert_eq!(record.validate(), Ok(()));
        record.id = "../outside".into();
        assert_eq!(record.validate(), Err(QueueError::InvalidId));
        record = entry(1);
        record.argv[0] = b"bad\0arg".to_vec();
        assert_eq!(record.validate(), Err(QueueError::InvalidArgument));
        record = entry(1);
        record.reason = Some("x".repeat(MAX_REASON_BYTES + 1));
        assert_eq!(record.validate(), Err(QueueError::InvalidReason));
        record = entry(1);
        record.cwd = b"relative".to_vec();
        assert_eq!(record.validate(), Err(QueueError::InvalidCwd));
        record = entry(1);
        record.reason = Some("bad\0reason".into());
        assert_eq!(record.validate(), Err(QueueError::InvalidReason));
        record = entry(1);
        record.argv = vec![vec![b'x'; 4097]];
        assert_eq!(record.validate(), Err(QueueError::InvalidArgument));
        record = entry(1);
        record.argv = vec![vec![b'x'; 4096]; MAX_ARGV_COUNT];
        assert_eq!(record.validate(), Err(QueueError::TooLarge));
        record = entry(1);
        record.argv.clear();
        assert_eq!(record.validate(), Err(QueueError::InvalidArgvCount));
    }

    #[test]
    fn queue_constructors_and_storage_fail_closed_on_serialization_errors() {
        let mut invalid = entry(1);
        invalid.id = "bad".into();
        assert_eq!(QueueEntry::new(invalid), Err(QueueError::InvalidId));

        let impossible_json_value = Unserializable;
        assert_eq!(
            validated_encoded_size(serde_json::to_vec(&impossible_json_value)),
            MAX_ENTRY_BYTES.saturating_add(1)
        );
        assert_eq!(
            publish_encoded_entry(
                &xudo_sys::FakeSpool::new(),
                "entry.json",
                serde_json::to_vec(&impossible_json_value),
            ),
            Err(StoreError::InvalidEntry)
        );
        assert_eq!(
            replace_encoded_entry(
                &xudo_sys::FakeSpool::new(),
                b"entry.json",
                b"old",
                serde_json::to_vec(&impossible_json_value),
            ),
            Err(StoreError::InvalidEntry)
        );

        let invalid_record = entry(2);
        let mut invalid_record = invalid_record;
        invalid_record.id = "bad".into();
        let bytes = serde_json::to_vec(&invalid_record).unwrap();
        let invalid_store =
            xudo_sys::FakeSpool::new().with_file(format!("{}.json", entry(2).id), bytes);
        assert_eq!(load_all(&invalid_store), Err(StoreError::InvalidEntry));
        assert_eq!(
            prune(&invalid_store, 101, 1000, BOOT),
            Err(StoreError::InvalidEntry)
        );

        let mut bad_admission = entry(3);
        bad_admission.id = "bad".into();
        assert_eq!(
            admit(&xudo_sys::FakeSpool::new(), &bad_admission, 101, 1000, BOOT),
            Err(StoreError::InvalidEntry)
        );
    }

    #[test]
    fn queue_claim_and_completion_cover_lock_decode_validation_and_replace_refusals() {
        let error = xudo_sys::SpoolError::NotADirectory { at: "queue".into() };
        let record = entry(61);
        assert_eq!(
            claim(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &record.id,
                101,
                1000,
                BOOT
            ),
            Err(StoreError::Spool(error.clone()))
        );
        let invalid_json =
            xudo_sys::FakeSpool::new().with_file(format!("{}.json", record.id), b"no".to_vec());
        assert_eq!(
            claim(&invalid_json, &record.id, 101, 1000, BOOT),
            Err(StoreError::InvalidEntry)
        );
        let mut invalid = record.clone();
        invalid.id = "bad".into();
        let invalid_record = xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", record.id),
            serde_json::to_vec(&invalid).unwrap(),
        );
        assert_eq!(
            claim(&invalid_record, &record.id, 101, 1000, BOOT),
            Err(StoreError::InvalidEntry)
        );
        let mismatched = xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", entry(62).id),
            serde_json::to_vec(&record).unwrap(),
        );
        assert_eq!(
            claim(&mismatched, &entry(62).id, 101, 1000, BOOT),
            Err(StoreError::NotPending)
        );
        let replace = xudo_sys::FakeSpool::new()
            .with_file(
                format!("{}.json", record.id),
                serde_json::to_vec(&record).unwrap(),
            )
            .failing_replace(error.clone());
        assert_eq!(
            claim(&replace, &record.id, 101, 1000, BOOT),
            Err(StoreError::Spool(error.clone()))
        );

        let mut audit = xudo_sys::FakeAuditSink::new();
        let receipt = xudo_sys::AuditSink::append(&mut audit, &|previous| {
            xudo_audit::record::Record::after(
                previous,
                xudo_audit::record::Decision::Allowed,
                Vec::new(),
                "human",
            )
        })
        .unwrap();
        let unreadable = xudo_sys::FakeSpool::new()
            .with_file(
                format!("{}.json", record.id),
                serde_json::to_vec(&record).unwrap(),
            )
            .failing_read(format!("{}.json", record.id));
        assert_eq!(
            complete_after_gate_audit(&unreadable, &record.id, &receipt),
            Err(StoreError::Spool(xudo_sys::SpoolError::Unreadable {
                name: format!("{}.json", record.id),
                reason: "fake: scripted to fail".into(),
            }))
        );
        assert_eq!(
            complete_after_gate_audit(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &record.id,
                &receipt
            ),
            Err(StoreError::Spool(error.clone()))
        );
        assert_eq!(
            complete_after_gate_audit(&invalid_json, &record.id, &receipt),
            Err(StoreError::InvalidEntry)
        );
        assert_eq!(
            complete_after_gate_audit(&invalid_record, &record.id, &receipt),
            Err(StoreError::InvalidEntry)
        );
        let claimed = {
            let store = xudo_sys::FakeSpool::new();
            admit(&store, &record, 101, 1000, BOOT).unwrap();
            claim(&store, &record.id, 101, 1000, BOOT).unwrap();
            store
        };
        let broken_replace = claimed.failing_replace(error.clone());
        assert_eq!(
            complete_after_gate_audit(&broken_replace, &record.id, &receipt),
            Err(StoreError::Spool(error))
        );
    }

    #[test]
    fn display_sanitizes_all_agent_influenced_fields_without_changing_stored_bytes() {
        let mut record = entry(1);
        record.argv = vec![b"/usr/bin/echo\x1b[2J".to_vec()];
        record.cwd = b"/tmp/\x1b]0;fake\x07".to_vec();
        record.harness = "co\u{202e}dex".into();
        record.reason = Some("run this\x1b[31m now".into());
        let display = record.display_fields();
        assert!(!display.argv[0].text.contains('\x1b'));
        assert!(!display.cwd.text.contains('\x1b'));
        assert!(!display.harness.text.contains('\u{202e}'));
        assert!(!display.reason.unwrap().text.contains('\x1b'));
        assert!(record.argv[0].ends_with(b"\x1b[2J"));
    }

    #[test]
    fn an_unmentioned_command_is_denied_not_queued() {
        // No queue entry can be authorized without the policy's fresh allow.
        assert!(!entry(1).may_run(101, 7, DEFAULT_TTL_SECS * 1000, false, BOOT));
    }

    #[test]
    fn queue_store_rejects_invalid_files_and_walks_are_bounded() {
        let invalid = xudo_sys::FakeSpool::new().with_file("bad.json", b"not json".to_vec());
        assert_eq!(load_all(&invalid), Err(StoreError::InvalidEntry));
        let ignored = xudo_sys::FakeSpool::new().with_file("notes.txt", b"not an entry".to_vec());
        assert!(load_all(&ignored).unwrap().is_empty());

        let mut too_many = xudo_sys::FakeSpool::new();
        for index in 0..MAX_FILES_WALKED {
            too_many = too_many.with_file(format!("{index:04}.txt"), Vec::new());
        }
        assert_eq!(load_all(&too_many), Err(StoreError::TooManyFiles));
    }

    #[test]
    fn queue_storage_reports_lock_read_publish_and_remove_failures() {
        let error = xudo_sys::SpoolError::NotADirectory { at: "queue".into() };
        assert_eq!(
            admit(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &entry(1),
                101,
                1000,
                BOOT
            ),
            Err(StoreError::Spool(error.clone()))
        );
        let broken_read = xudo_sys::FakeSpool::new()
            .with_file(format!("{}.json", entry(1).id), b"{}".to_vec())
            .failing_read(format!("{}.json", entry(1).id));
        assert_eq!(
            admit(&broken_read, &entry(2), 101, 1000, BOOT),
            Err(StoreError::Spool(xudo_sys::SpoolError::Unreadable {
                name: format!("{}.json", entry(1).id),
                reason: "fake: scripted to fail".into(),
            }))
        );
        let publish = xudo_sys::FakeSpool::new().failing_publish(error.clone());
        assert_eq!(
            admit(&publish, &entry(1), 101, 1000, BOOT),
            Err(StoreError::Spool(error.clone()))
        );

        let stale = entry(3);
        let remove = xudo_sys::FakeSpool::new()
            .with_file(
                format!("{}.json", stale.id),
                serde_json::to_vec(&stale).unwrap(),
            )
            .failing_remove(error.clone());
        let mut fresh = entry(4);
        fresh.queued_at = stale.expires_at;
        fresh.expires_at = stale.expires_at.saturating_add(1000);
        assert_eq!(
            admit(&remove, &fresh, stale.expires_at, 1000, BOOT),
            Err(StoreError::Spool(error.clone()))
        );
        assert_eq!(
            prune(&remove, stale.expires_at, 1000, BOOT),
            Err(StoreError::Spool(error))
        );
    }

    #[test]
    fn queue_claim_and_completion_refuse_mismatched_or_invalid_records() {
        let record = entry(5);
        let files = xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", record.id),
            serde_json::to_vec(&record).unwrap(),
        );
        assert_eq!(
            claim(&files, &entry(6).id, 101, 1000, BOOT),
            Err(StoreError::Spool(xudo_sys::SpoolError::Unreadable {
                name: format!("{}.json", entry(6).id),
                reason: "fake: no such entry".into(),
            }))
        );
        assert_eq!(
            claim(&files, &record.id, record.expires_at, 1000, BOOT),
            Err(StoreError::NotPending)
        );
        let mut audit = xudo_sys::FakeAuditSink::new();
        let receipt = xudo_sys::AuditSink::append(&mut audit, &|previous| {
            xudo_audit::record::Record::after(
                previous,
                xudo_audit::record::Decision::Allowed,
                Vec::new(),
                "human",
            )
        })
        .unwrap();
        assert_eq!(
            complete_after_gate_audit(&files, &record.id, &receipt),
            Err(StoreError::NotPending)
        );
        assert_eq!(
            claim(&files, &record.id, 101, 1000, BOOT).unwrap(),
            QueueEntry {
                state: QueueState::Claimed,
                ..record
            }
        );
    }

    #[test]
    fn redecision_of_a_malformed_empty_argv_fails_closed() {
        let policy = policy_for("/usr/bin/apt-get");
        let mut malformed = entry(8);
        malformed.argv.clear();
        malformed.state = QueueState::Claimed;
        malformed.generation = policy.generation.id();
        let human = xudo_policy::CallerFacts::new(xudo_policy::Classification::Human, 1000);
        let decision = redecide_for_run(
            &malformed,
            &policy,
            &human,
            xudo_policy::engine::Settings::default(),
            101,
            DEFAULT_TTL_SECS * 1000,
            BOOT,
        );
        assert_eq!(decision.denial, Some(xudo_policy::DenialCode::AskHuman));
    }

    #[test]
    fn root_queue_expiry_setting_can_only_shorten_the_default() {
        assert_eq!(effective_ttl(None), DEFAULT_TTL_SECS);
        assert_eq!(effective_ttl(Some(60)), 60);
        assert_eq!(effective_ttl(Some(DEFAULT_TTL_SECS)), DEFAULT_TTL_SECS);
        assert_eq!(effective_ttl(Some(DEFAULT_TTL_SECS + 1)), DEFAULT_TTL_SECS);
    }
}
