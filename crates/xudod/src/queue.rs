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
/// How long a claim stays exclusive to the peer that took it.
///
/// Fifteen minutes, the same bound as a normal request's lifetime. A different
/// reviewer may recover a claim only after this window, and only when the
/// audit trail has no gate record for the entry. A claim exactly this old is
/// still exclusive. A missing `claimed_at`, or a clock that moved backwards,
/// is not stale.
pub const CLAIM_LIFETIME_MS: u64 = 15 * 60 * 1000;

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
    /// Completed after the gate's audit record for this entry was observed.
    Done,
    /// The claim was re-decided and refused. Terminal, not live, and pruned.
    Failed,
}

impl QueueState {
    /// The wire and display word for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
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
    /// Display only. A queued command is never started from this path. The
    /// reviewer path uses the fixed directory `/`, which the gate also
    /// resets to before exec.
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
    /// Nonce of the human-path spool entry minted for a claim.
    ///
    /// Set only while [`QueueState::Claimed`], and kept after the entry is
    /// marked done so a pruned record can still be tied to the gate run.
    /// Completion accepts a gate record only when that record names this nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_nonce: Option<String>,
    /// Uid of the peer that moved the entry to [`QueueState::Claimed`].
    ///
    /// Absent on records written before claims recorded an owner, and cleared
    /// when a claim returns to pending or failed with no gate record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimant_uid: Option<u32>,
    /// Secret the claimant must present to release, fail, or complete.
    ///
    /// The same 64 lowercase hex value later bound as [`Self::run_nonce`].
    /// Another reviewer does not have it. An empty or absent token never
    /// matches, so a stale recovery is the only way for someone else to settle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_token: Option<String>,
    /// Boottime milliseconds when the entry was claimed.
    ///
    /// Stale recovery compares this with [`CLAIM_LIFETIME_MS`]. Absent means
    /// the claim is not stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<u64>,
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
        self.state == QueueState::Claimed
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
    /// Completion lacks the gate's audit record for this entry.
    #[error("queue completion requires the gate audit record for this entry")]
    MissingGateAudit,
    /// The peer is not the claimant, and the claim is not stale.
    #[error("queue claim belongs to another reviewer")]
    NotClaimant,
}

/// Who is settling a claim, and the clock used for the stale-claim window.
#[derive(Clone, Copy, Debug)]
pub struct ClaimAct<'a> {
    /// Uid of the peer asking to bind, release, fail, or complete.
    pub uid: u32,
    /// Claim token presented by that peer. Empty never matches a real token.
    pub token: &'a str,
    /// Boottime milliseconds. A claim older than [`CLAIM_LIFETIME_MS`] is stale.
    pub now: u64,
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
/// `claim_token` is recorded on the entry. Later release, failure, and
/// completion accept that token from `claimant_uid`, or a stale recovery.
///
/// # Errors
///
/// Returns [`StoreError::InvalidEntry`] when `claim_token` is not 64 lowercase
/// hex characters. Returns an error if the entry is invalid, absent, expired,
/// already claimed, or the locked compare-and-replace fails.
pub fn claim(
    store: &dyn xudo_sys::Spool,
    id: &str,
    now: u64,
    ttl: u64,
    boot_id: &str,
    claimant_uid: u32,
    claim_token: &str,
) -> Result<QueueEntry, StoreError> {
    if !is_nonce(claim_token) {
        return Err(StoreError::InvalidEntry);
    }
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
        entry.claimant_uid = Some(claimant_uid);
        entry.claim_token = Some(claim_token.to_owned());
        entry.claimed_at = Some(now);
        replace_encoded_entry(store, name.as_bytes(), &bytes, serde_json::to_vec(&entry))?;
        Ok(entry)
    })();
    store.unlock();
    result
}

/// A claim refused before or after the atomic transition.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// The store refused, or the entry is not a live pending record.
    Store(StoreError),
    /// The peer is not a human reviewer distinct from the owner.
    ///
    /// Checked before [`claim`], so an agent or the owner never changes the
    /// record. Checked again on the record [`claim`] returns: if that record
    /// is not reviewable, the claim is released back to pending. A release
    /// that fails is [`ClaimError::Store`] and the record may stay claimed.
    NotReviewer,
}

/// The reviewer and the clock a claim is judged against.
pub struct ReviewerClaim<'a> {
    /// Boottime milliseconds.
    pub now: u64,
    /// Queue lifetime in milliseconds.
    pub ttl: u64,
    /// Boot id the entry must still belong to.
    pub boot_id: &'a str,
    /// Reviewer uid.
    pub peer_uid: u32,
    /// Reviewer class. An agent is refused.
    pub peer_class: PeerClass,
    /// Current harness registry.
    pub registry: &'a HarnessRegistry,
    /// Passwd contents used to name reviewers.
    pub passwd: &'a str,
    /// Token recorded on the claim. The same value is later the run nonce.
    pub claim_token: &'a str,
}

/// Claims `id` for a reviewer, or refuses without leaving an agent holding it.
///
/// # Errors
///
/// [`ClaimError::NotReviewer`] when the peer may not run the entry.
/// [`ClaimError::Store`] when the entry cannot be claimed or a post-claim
/// release fails.
pub fn claim_for_reviewer(
    store: &dyn xudo_sys::Spool,
    id: &str,
    reviewer: &ReviewerClaim<'_>,
) -> Result<QueueEntry, ClaimError> {
    let entries = load_all(store).map_err(ClaimError::Store)?;
    let Some(existing) = entries.into_iter().find(|entry| entry.id == id) else {
        return Err(ClaimError::Store(StoreError::NotPending));
    };
    if !visibility(
        &existing,
        reviewer.peer_uid,
        reviewer.peer_class,
        reviewer.registry,
        reviewer.passwd,
    )
    .reviewer
    {
        return Err(ClaimError::NotReviewer);
    }
    let claimed = claim(
        store,
        id,
        reviewer.now,
        reviewer.ttl,
        reviewer.boot_id,
        reviewer.peer_uid,
        reviewer.claim_token,
    )
    .map_err(ClaimError::Store)?;
    if visibility(
        &claimed,
        reviewer.peer_uid,
        reviewer.peer_class,
        reviewer.registry,
        reviewer.passwd,
    )
    .reviewer
    {
        Ok(claimed)
    } else {
        // The nonce is still unset, so this release does not lock a spool.
        // The queue store is passed only to satisfy the signature.
        release_claim(
            store,
            store,
            id,
            &ClaimAct {
                uid: reviewer.peer_uid,
                token: reviewer.claim_token,
                now: reviewer.now,
            },
            &[],
        )
        .map_err(ClaimError::Store)?;
        Err(ClaimError::NotReviewer)
    }
}

/// The ids [`commit_prune`] would remove, without removing them.
///
/// # Errors
///
/// Returns an error if the lock or the bounded scan fails.
pub fn plan_prune(
    store: &dyn xudo_sys::Spool,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<Vec<String>, StoreError> {
    store.lock()?;
    let result = prune_ids(store, now, ttl, boot_id);
    store.unlock();
    result
}

/// Removes `expected` when that set is still exactly the non-live ids.
///
/// # Errors
///
/// Returns [`StoreError::Conflict`] when the set changed, and deletes nothing
/// in that case. Lock and removal failures also refuse.
pub fn commit_prune(
    store: &dyn xudo_sys::Spool,
    expected: &[String],
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<(), StoreError> {
    store.lock()?;
    let result = (|| {
        let planned = prune_ids(store, now, ttl, boot_id)?;
        if planned != expected {
            return Err(StoreError::Conflict);
        }
        for id in &planned {
            store.remove(format!("{id}.json").as_bytes())?;
        }
        Ok(())
    })();
    store.unlock();
    result
}

fn prune_ids(
    store: &dyn xudo_sys::Spool,
    now: u64,
    ttl: u64,
    boot_id: &str,
) -> Result<Vec<String>, StoreError> {
    let mut ids: Vec<String> = load_all(store)?
        .into_iter()
        .filter(|entry| !entry.is_live(now, ttl, boot_id))
        .map(|entry| entry.id)
        .collect();
    ids.sort();
    Ok(ids)
}

/// Returns a claimed entry to pending, or marks it done when a gate record binds.
///
/// A password or gate denial uses this so the reviewer can try again, but only
/// when `records` contains no gate record for the entry. A binding record marks
/// the entry done and keeps the nonce: the command must not return to pending.
/// The minted spool file is removed under `requests`' lock before the queue
/// file changes. `requests` must be the request spool, not the queue store,
/// except when the nonce is still unset (that path does not lock it).
///
/// `act` must be the claimant. A different reviewer is accepted only when the
/// claim is older than [`CLAIM_LIFETIME_MS`].
///
/// # Errors
///
/// Returns [`StoreError::NotClaimant`] when the peer may not settle the claim.
/// Returns [`StoreError::NotPending`] when the entry is not claimed. A spool
/// revoke or replace failure leaves the entry claimed.
pub fn release_claim(
    store: &dyn xudo_sys::Spool,
    requests: &dyn xudo_sys::Spool,
    id: &str,
    act: &ClaimAct<'_>,
    records: &[xudo_audit::Record],
) -> Result<QueueEntry, StoreError> {
    settle_claim(store, requests, id, act, records, QueueState::Pending)
}

/// Marks a claimed entry failed, or done when a gate record already binds.
///
/// Used when the stored command is re-decided and no longer allowed, including
/// a rules change after queueing and argv that cannot be sent on the wire.
/// A binding gate record never becomes [`QueueState::Failed`]: the entry is
/// marked done, same as [`release_claim`]. The spool file is revoked first.
///
/// # Errors
///
/// Returns [`StoreError::NotClaimant`] when the peer may not settle the claim.
/// Returns [`StoreError::NotPending`] when the entry is not claimed. A spool
/// revoke or replace failure leaves the entry claimed.
pub fn fail_claim(
    store: &dyn xudo_sys::Spool,
    requests: &dyn xudo_sys::Spool,
    id: &str,
    act: &ClaimAct<'_>,
    records: &[xudo_audit::Record],
) -> Result<QueueEntry, StoreError> {
    settle_claim(store, requests, id, act, records, QueueState::Failed)
}

/// Records the nonce that the human-path mint is about to publish.
///
/// Called before mint. A later mint failure must [`release_claim`]. Only the
/// claimant may bind, including after the claim would be stale for someone else.
///
/// # Errors
///
/// Returns [`StoreError::InvalidEntry`] when `nonce` is not 64 lowercase hex
/// characters or a nonce is already bound. Returns [`StoreError::NotClaimant`]
/// when `act` is not the claimant. Any other claim state is
/// [`StoreError::NotPending`].
pub fn bind_run_nonce(
    store: &dyn xudo_sys::Spool,
    id: &str,
    nonce: &str,
    act: &ClaimAct<'_>,
) -> Result<QueueEntry, StoreError> {
    if !is_nonce(nonce) {
        return Err(StoreError::InvalidEntry);
    }
    update_claimed(store, id, &mut |entry| {
        if !same_claimant(entry, act) {
            return Err(StoreError::NotClaimant);
        }
        if entry.run_nonce.is_some() {
            return Err(StoreError::InvalidEntry);
        }
        entry.run_nonce = Some(nonce.to_owned());
        Ok(())
    })
}

fn is_nonce(nonce: &str) -> bool {
    nonce.len() == 64
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `record` is the gate's allow record for this claimed entry.
///
/// A broker receipt is not enough: the record must be an allow that did not
/// execute, name this entry's run nonce, carry the password-confirmation
/// marker the gate writes, match the stored argv bytes, and not be a broker
/// record.
#[must_use]
pub fn gate_record_binds(entry: &QueueEntry, record: &xudo_audit::Record) -> bool {
    if record.decision != xudo_audit::Decision::Allowed
        || record.outcome != xudo_audit::Outcome::NotExecuted
    {
        return false;
    }
    let Some(nonce) = entry.run_nonce.as_deref() else {
        return false;
    };
    if record.evidence.iter().any(|line| line == "broker=xudod") {
        return false;
    }
    let nonce_line = format!("nonce={nonce}");
    if !record.evidence.iter().any(|line| line == &nonce_line) {
        return false;
    }
    if !record
        .evidence
        .iter()
        .any(|line| line.starts_with("confirmation=password"))
    {
        return false;
    }
    argv_bytes_match(&entry.argv, &record.argv)
}

fn argv_bytes_match(stored: &[Vec<u8>], recorded: &[String]) -> bool {
    if stored.len() != recorded.len() {
        return false;
    }
    stored.iter().zip(recorded.iter()).all(|(left, right)| {
        std::str::from_utf8(left).is_ok_and(|text| text.as_bytes() == right.as_bytes())
    })
}

/// Marks a claimed entry done when `record` is the gate record for it.
///
/// `audit_seq` of zero accepts the binding record's own sequence. Any other
/// value must equal `record.seq`. The claimant must present the claim token,
/// or the claim must be stale. A leftover spool file for the nonce is removed
/// before the queue file is marked done.
///
/// # Errors
///
/// Returns [`StoreError::MissingGateAudit`] when the record does not bind.
/// Returns [`StoreError::NotClaimant`] when the peer may not settle the claim.
/// Returns [`StoreError::NotPending`] when the entry is not claimed. Lock,
/// decode, revoke, and replace failures refuse as well. A revoke or replace
/// failure leaves the entry claimed.
pub fn complete_after_gate_audit(
    store: &dyn xudo_sys::Spool,
    requests: &dyn xudo_sys::Spool,
    id: &str,
    act: &ClaimAct<'_>,
    record: &xudo_audit::Record,
    audit_seq: u64,
) -> Result<QueueEntry, StoreError> {
    store.lock()?;
    let result = (|| {
        let (name, previous, mut entry) = load_claimed(store, id)?;
        if !claimant_may_settle(&entry, act) {
            return Err(StoreError::NotClaimant);
        }
        if audit_seq != 0 && record.seq.get() != audit_seq {
            return Err(StoreError::MissingGateAudit);
        }
        if !gate_record_binds(&entry, record) {
            return Err(StoreError::MissingGateAudit);
        }
        let nonce = entry.run_nonce.clone();
        entry.state = QueueState::Done;
        revoke_spool_nonce(requests, nonce.as_deref())?;
        replace_encoded_entry(
            store,
            name.as_bytes(),
            &previous,
            serde_json::to_vec(&entry),
        )?;
        Ok(entry)
    })();
    store.unlock();
    result
}

fn settle_claim(
    store: &dyn xudo_sys::Spool,
    requests: &dyn xudo_sys::Spool,
    id: &str,
    act: &ClaimAct<'_>,
    records: &[xudo_audit::Record],
    when_clear: QueueState,
) -> Result<QueueEntry, StoreError> {
    store.lock()?;
    let result = (|| {
        let (name, previous, mut entry) = load_claimed(store, id)?;
        if !claimant_may_settle(&entry, act) {
            return Err(StoreError::NotClaimant);
        }
        let nonce = entry.run_nonce.clone();
        if records
            .iter()
            .any(|record| gate_record_binds(&entry, record))
        {
            entry.state = QueueState::Done;
        } else {
            entry.state = when_clear;
            entry.run_nonce = None;
            entry.claimant_uid = None;
            entry.claim_token = None;
            entry.claimed_at = None;
        }
        revoke_spool_nonce(requests, nonce.as_deref())?;
        replace_encoded_entry(
            store,
            name.as_bytes(),
            &previous,
            serde_json::to_vec(&entry),
        )?;
        Ok(entry)
    })();
    store.unlock();
    result
}

fn load_claimed(
    store: &dyn xudo_sys::Spool,
    id: &str,
) -> Result<(String, Vec<u8>, QueueEntry), StoreError> {
    let name = format!("{id}.json");
    let bytes = store.read(name.as_bytes(), MAX_ENTRY_BYTES)?;
    let entry: QueueEntry = serde_json::from_slice(&bytes).map_err(|_| StoreError::InvalidEntry)?;
    entry.validate().map_err(|_| StoreError::InvalidEntry)?;
    if entry.id != id || entry.state != QueueState::Claimed {
        return Err(StoreError::NotPending);
    }
    Ok((name, bytes, entry))
}

fn same_claimant(entry: &QueueEntry, act: &ClaimAct<'_>) -> bool {
    let Some(token) = entry.claim_token.as_deref() else {
        return false;
    };
    entry.claimant_uid == Some(act.uid) && token == act.token && is_nonce(token)
}

fn claim_is_stale(entry: &QueueEntry, now: u64) -> bool {
    let Some(claimed_at) = entry.claimed_at else {
        return false;
    };
    now.saturating_sub(claimed_at) > CLAIM_LIFETIME_MS
}

fn claimant_may_settle(entry: &QueueEntry, act: &ClaimAct<'_>) -> bool {
    same_claimant(entry, act) || claim_is_stale(entry, act.now)
}

/// Removes the minted spool file. A missing file is success.
///
/// An invalid nonce is refused before the lock, and the queue entry is left
/// unchanged by the caller. Lock order is the queue lock, then this one.
fn revoke_spool_nonce(
    requests: &dyn xudo_sys::Spool,
    nonce: Option<&str>,
) -> Result<(), StoreError> {
    let Some(nonce) = nonce else {
        return Ok(());
    };
    if !is_nonce(nonce) {
        return Err(StoreError::InvalidEntry);
    }
    requests.lock()?;
    let removed = requests.remove(nonce.as_bytes());
    requests.unlock();
    removed.map_err(StoreError::from)
}

fn update_claimed(
    store: &dyn xudo_sys::Spool,
    id: &str,
    change: &mut dyn FnMut(&mut QueueEntry) -> Result<(), StoreError>,
) -> Result<QueueEntry, StoreError> {
    store.lock()?;
    let result = (|| {
        let (name, bytes, mut entry) = load_claimed(store, id)?;
        change(&mut entry)?;
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
    use xudo_sys::Spool;

    const TEST_UID: u32 = 1000;
    const TEST_TOKEN: &str = "abababababababababababababababababababababababababababababababab";

    fn test_act(now: u64) -> ClaimAct<'static> {
        ClaimAct {
            uid: TEST_UID,
            token: TEST_TOKEN,
            now,
        }
    }

    fn claim(
        store: &dyn xudo_sys::Spool,
        id: &str,
        now: u64,
        ttl: u64,
        boot_id: &str,
    ) -> Result<QueueEntry, StoreError> {
        super::claim(store, id, now, ttl, boot_id, TEST_UID, TEST_TOKEN)
    }

    fn release_claim(store: &dyn xudo_sys::Spool, id: &str) -> Result<QueueEntry, StoreError> {
        let act = test_act(0);
        super::release_claim(store, store, id, &act, &[])
    }

    fn fail_claim(store: &dyn xudo_sys::Spool, id: &str) -> Result<QueueEntry, StoreError> {
        let act = test_act(0);
        super::fail_claim(store, store, id, &act, &[])
    }

    fn bind_run_nonce(
        store: &dyn xudo_sys::Spool,
        id: &str,
        nonce: &str,
    ) -> Result<QueueEntry, StoreError> {
        let act = test_act(0);
        super::bind_run_nonce(store, id, nonce, &act)
    }

    fn complete_after_gate_audit(
        store: &dyn xudo_sys::Spool,
        id: &str,
        record: &xudo_audit::Record,
        audit_seq: u64,
    ) -> Result<QueueEntry, StoreError> {
        let act = test_act(0);
        super::complete_after_gate_audit(store, store, id, &act, record, audit_seq)
    }

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
            run_nonce: None,
            claimant_uid: None,
            claim_token: None,
            claimed_at: None,
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
        let mut live = entry(92);
        live.queued_at = expired.expires_at;
        live.expires_at = expired.expires_at.saturating_add(10_000);
        let store = xudo_sys::FakeSpool::new()
            .with_file(
                format!("{}.json", expired.id),
                serde_json::to_vec(&expired).unwrap(),
            )
            .with_file(
                format!("{}.json", live.id),
                serde_json::to_vec(&live).unwrap(),
            );
        let removed = prune(&store, expired.expires_at, 1000, BOOT).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], expired.id);
        assert_eq!(load_all(&store).unwrap(), [live]);
        let error = xudo_sys::SpoolError::NotADirectory { at: "queue".into() };
        assert_eq!(
            prune(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                expired.expires_at,
                1000,
                BOOT
            )
            .unwrap_err(),
            StoreError::Spool(error)
        );
    }

    #[test]
    fn two_concurrent_claims_have_one_winner() {
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
        bind_run_nonce(&store, &record.id, &"ab".repeat(32)).unwrap();
        let denied =
            xudo_audit::Record::after(None, xudo_audit::Decision::Denied, Vec::new(), "human");
        assert_eq!(
            complete_after_gate_audit(&store, &record.id, &denied, 0),
            Err(StoreError::MissingGateAudit)
        );
        let bare_allow =
            xudo_audit::Record::after(None, xudo_audit::Decision::Allowed, Vec::new(), "human");
        assert_eq!(
            complete_after_gate_audit(&store, &record.id, &bare_allow, 0),
            Err(StoreError::MissingGateAudit)
        );
        assert_eq!(load_all(&store).unwrap()[0].state, QueueState::Claimed);
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
        assert!(!record.may_run(101, 7, DEFAULT_TTL_SECS * 1000, true, BOOT));
        assert!(claimed.may_run(101, 7, DEFAULT_TTL_SECS * 1000, true, BOOT));
        assert!(!claimed.may_run(101, 7, DEFAULT_TTL_SECS * 1000, false, BOOT));
    }

    #[test]
    fn a_queued_entry_is_re_decided_at_run_time() {
        let record = entry(1);
        assert!(!record.may_run(101, 7, DEFAULT_TTL_SECS * 1000, false, BOOT));
        assert!(!record.may_run(101, 7, DEFAULT_TTL_SECS * 1000, true, BOOT));
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

        let bare =
            xudo_audit::Record::after(None, xudo_audit::Decision::Allowed, Vec::new(), "human");
        let unreadable = xudo_sys::FakeSpool::new()
            .with_file(
                format!("{}.json", record.id),
                serde_json::to_vec(&record).unwrap(),
            )
            .failing_read(format!("{}.json", record.id));
        assert_eq!(
            complete_after_gate_audit(&unreadable, &record.id, &bare, 0),
            Err(StoreError::Spool(xudo_sys::SpoolError::Unreadable {
                name: format!("{}.json", record.id),
                reason: "fake: scripted to fail".into(),
            }))
        );
        assert_eq!(
            complete_after_gate_audit(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &record.id,
                &bare,
                0
            ),
            Err(StoreError::Spool(error.clone()))
        );
        assert_eq!(
            complete_after_gate_audit(&invalid_json, &record.id, &bare, 0),
            Err(StoreError::InvalidEntry)
        );
        assert_eq!(
            complete_after_gate_audit(&invalid_record, &record.id, &bare, 0),
            Err(StoreError::InvalidEntry)
        );
        let claimed = {
            let store = xudo_sys::FakeSpool::new();
            admit(&store, &record, 101, 1000, BOOT).unwrap();
            claim(&store, &record.id, 101, 1000, BOOT).unwrap();
            bind_run_nonce(&store, &record.id, &"cd".repeat(32)).unwrap();
            store
        };
        let stored = load_all(&claimed).unwrap().remove(0);
        let binding = gate_record_for(&stored);
        let broken_replace = claimed.failing_replace(error.clone());
        assert_eq!(
            complete_after_gate_audit(&broken_replace, &record.id, &binding, 0),
            Err(StoreError::Spool(error))
        );
        let unsigned = gate_record_for(&entry(8));
        assert!(
            unsigned
                .evidence
                .iter()
                .any(|line| line == &format!("nonce={}", "ab".repeat(32)))
        );
    }

    fn gate_record_for(entry: &QueueEntry) -> xudo_audit::Record {
        let argv = entry
            .argv
            .iter()
            .map(|arg| String::from_utf8(arg.clone()).unwrap())
            .collect();
        let nonce = entry.run_nonce.clone().unwrap_or_else(|| "ab".repeat(32));
        xudo_audit::Record::after(None, xudo_audit::Decision::Allowed, argv, "human").with_evidence(
            vec![
                format!("nonce={nonce}"),
                "confirmation=password (sudo's own prompt, on the -auth name)".into(),
                "gate_caller_pid=1".into(),
            ],
        )
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
        let bare =
            xudo_audit::Record::after(None, xudo_audit::Decision::Allowed, Vec::new(), "human");
        assert_eq!(
            complete_after_gate_audit(&files, &record.id, &bare, 0),
            Err(StoreError::NotPending)
        );
        assert_eq!(
            claim(&files, &record.id, 101, 1000, BOOT).unwrap(),
            QueueEntry {
                state: QueueState::Claimed,
                claimant_uid: Some(TEST_UID),
                claim_token: Some(TEST_TOKEN.to_owned()),
                claimed_at: Some(101),
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

    #[test]
    fn completion_requires_the_gates_audit_record_for_that_entry() {
        let store = xudo_sys::FakeSpool::new();
        let record = entry(77);
        admit(&store, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let nonce = "ef".repeat(32);
        bind_run_nonce(&store, &record.id, &nonce).unwrap();
        let mut stored = load_all(&store).unwrap().remove(0);
        let bound = gate_record_for(&stored);
        assert_eq!(bound.seq.get(), 1);
        assert_eq!(
            complete_after_gate_audit(&store, &record.id, &bound, 9),
            Err(StoreError::MissingGateAudit)
        );
        let done = complete_after_gate_audit(&store, &record.id, &bound, 0).unwrap();
        assert_eq!(done.state, QueueState::Done);
        assert_eq!(done.state.as_str(), "done");

        stored.run_nonce = None;
        assert!(!gate_record_binds(&stored, &bound));
        stored.run_nonce = Some(nonce.clone());
        let mut broker_evidence = bound.evidence.clone();
        broker_evidence.insert(0, "broker=xudod".into());
        let broker = bound.clone().with_evidence(broker_evidence);
        assert!(!gate_record_binds(&stored, &broker));
        let other_nonce = bound
            .clone()
            .with_evidence(vec!["nonce=ab".into(), "confirmation=password".into()]);
        assert!(!gate_record_binds(&stored, &other_nonce));
        let passwordless: Vec<String> = bound
            .evidence
            .iter()
            .filter(|line| !line.starts_with("confirmation=password"))
            .cloned()
            .collect();
        let no_password = bound.clone().with_evidence(passwordless);
        assert!(!gate_record_binds(&stored, &no_password));
        let failed = bound.clone().with_outcome(xudo_audit::Outcome::Failed {
            reason: "the command exited 1".into(),
        });
        assert!(!gate_record_binds(&stored, &failed));
        let denied = xudo_audit::Record::after(
            None,
            xudo_audit::Decision::Denied,
            bound.argv.clone(),
            "human",
        )
        .with_evidence(bound.evidence.clone());
        assert!(!gate_record_binds(&stored, &denied));
        let mut longer = bound.argv.clone();
        longer.push("extra".into());
        let wrong_length =
            xudo_audit::Record::after(None, xudo_audit::Decision::Allowed, longer, "human")
                .with_evidence(bound.evidence.clone());
        assert!(!gate_record_binds(&stored, &wrong_length));
        let mut mismatched = bound.argv.clone();
        mismatched[0] = "other".into();
        let wrong_argv =
            xudo_audit::Record::after(None, xudo_audit::Decision::Allowed, mismatched, "human")
                .with_evidence(bound.evidence.clone());
        assert!(!gate_record_binds(&stored, &wrong_argv));
        stored.argv[0] = vec![0xff];
        assert!(!gate_record_binds(&stored, &bound));
        assert_eq!(QueueState::Failed.as_str(), "failed");
        assert_eq!(QueueState::Pending.as_str(), "pending");
        assert_eq!(QueueState::Claimed.as_str(), "claimed");
    }

    #[test]
    fn a_claim_is_released_or_failed_when_the_run_is_denied() {
        let store = xudo_sys::FakeSpool::new();
        let record = entry(78);
        admit(&store, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        assert_eq!(
            release_claim(&store, &record.id).unwrap_err(),
            StoreError::NotPending
        );
        claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        bind_run_nonce(&store, &record.id, &"ab".repeat(32)).unwrap();
        assert_eq!(
            bind_run_nonce(&store, &record.id, &"cd".repeat(32)).unwrap_err(),
            StoreError::InvalidEntry
        );
        assert_eq!(
            bind_run_nonce(&store, &record.id, "short").unwrap_err(),
            StoreError::InvalidEntry
        );
        let released = release_claim(&store, &record.id).unwrap();
        assert_eq!(released.state, QueueState::Pending);
        assert_eq!(released.run_nonce, None);
        assert_eq!(released.claimant_uid, None);
        assert_eq!(released.claim_token, None);
        assert_eq!(released.claimed_at, None);
        claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let failed = fail_claim(&store, &record.id).unwrap();
        assert_eq!(failed.state, QueueState::Failed);
        assert_eq!(failed.run_nonce, None);
        assert_eq!(failed.claim_token, None);
        assert!(!failed.is_live(101, DEFAULT_TTL_SECS * 1000, BOOT));
        assert_eq!(
            release_claim(&store, &record.id).unwrap_err(),
            StoreError::NotPending
        );
    }

    #[test]
    fn prune_is_planned_before_it_is_committed() {
        let mut stale = entry(3);
        stale.expires_at = 50;
        stale.state = QueueState::Failed;
        let store = xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", stale.id),
            serde_json::to_vec(&stale).unwrap(),
        );
        let planned = plan_prune(&store, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        assert_eq!(planned, [stale.id.clone()]);
        assert_eq!(load_all(&store).unwrap().len(), 1);
        assert_eq!(
            commit_prune(&store, &[], 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap_err(),
            StoreError::Conflict
        );
        assert_eq!(load_all(&store).unwrap().len(), 1);
        commit_prune(&store, &planned, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        assert!(load_all(&store).unwrap().is_empty());
        let error = xudo_sys::SpoolError::NotADirectory { at: "queue".into() };
        assert_eq!(
            plan_prune(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                101,
                1000,
                BOOT
            )
            .unwrap_err(),
            StoreError::Spool(error.clone())
        );
        assert_eq!(
            commit_prune(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &planned,
                101,
                1000,
                BOOT
            )
            .unwrap_err(),
            StoreError::Spool(error.clone())
        );
        let stuck = xudo_sys::FakeSpool::new()
            .with_file(
                format!("{}.json", stale.id),
                serde_json::to_vec(&stale).unwrap(),
            )
            .failing_remove(error.clone());
        assert_eq!(
            commit_prune(&stuck, &planned, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap_err(),
            StoreError::Spool(error)
        );
        assert_eq!(load_all(&stuck).unwrap().len(), 1);
    }

    /// The claim read returns a different record than the authority read.
    ///
    /// `claim` then succeeds, the post-check sees an owner, and the claim is
    /// released. A second spool fails that release.
    struct ReviewerFlip {
        files: std::cell::RefCell<std::collections::BTreeMap<Vec<u8>, Vec<u8>>>,
        reads: std::cell::Cell<usize>,
        replaces: std::cell::Cell<usize>,
        second: Vec<u8>,
        fail_release: bool,
    }

    impl xudo_sys::Spool for ReviewerFlip {
        fn lock(&self) -> Result<(), xudo_sys::SpoolError> {
            Ok(())
        }

        fn unlock(&self) {}

        fn names(&self) -> Result<Vec<Vec<u8>>, xudo_sys::SpoolError> {
            Ok(self.files.borrow().keys().cloned().collect())
        }

        fn names_up_to(&self, limit: usize) -> Result<Vec<Vec<u8>>, xudo_sys::SpoolError> {
            Ok(self.files.borrow().keys().take(limit).cloned().collect())
        }

        fn read(&self, name: &[u8], limit: usize) -> Result<Vec<u8>, xudo_sys::SpoolError> {
            let nth = self.reads.get().saturating_add(1);
            self.reads.set(nth);
            if nth == 2 {
                return Ok(self.second.clone());
            }
            let files = self.files.borrow();
            let Some(bytes) = files.get(name) else {
                return Err(xudo_sys::SpoolError::Unreadable {
                    name: "missing".into(),
                    reason: "no such entry".into(),
                });
            };
            if bytes.len() > limit {
                return Err(xudo_sys::SpoolError::TooLarge {
                    name: "entry".into(),
                    limit,
                });
            }
            Ok(bytes.clone())
        }

        fn remove(&self, name: &[u8]) -> Result<(), xudo_sys::SpoolError> {
            self.files.borrow_mut().remove(name);
            Ok(())
        }

        fn consume(&self, name: &[u8]) -> Result<(), xudo_sys::SpoolError> {
            match self.files.borrow_mut().remove(name) {
                Some(_) => Ok(()),
                None => Err(xudo_sys::SpoolError::Gone {
                    name: "missing".into(),
                }),
            }
        }

        fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), xudo_sys::SpoolError> {
            self.files
                .borrow_mut()
                .insert(name.as_bytes().to_vec(), bytes.to_vec());
            Ok(())
        }

        fn replace(
            &self,
            name: &[u8],
            expected: &[u8],
            bytes: &[u8],
        ) -> Result<(), xudo_sys::SpoolError> {
            let nth = self.replaces.get().saturating_add(1);
            self.replaces.set(nth);
            if self.fail_release && nth == 2 {
                return Err(xudo_sys::SpoolError::Io {
                    operation: "replace".into(),
                    at: "queue".into(),
                    code: None,
                    reason: "scripted".into(),
                });
            }
            let mut files = self.files.borrow_mut();
            let Some(current) = files.get_mut(name) else {
                return Err(xudo_sys::SpoolError::Gone {
                    name: "missing".into(),
                });
            };
            if expected == self.second.as_slice() || current.as_slice() == expected {
                *current = bytes.to_vec();
                return Ok(());
            }
            Err(xudo_sys::SpoolError::Gone {
                name: "mismatch".into(),
            })
        }
    }

    fn reviewer_flip(fail_release: bool) -> (ReviewerFlip, String) {
        let reviewer = entry(7);
        let mut owner = reviewer.clone();
        owner.uid = 1000;
        let mut files = std::collections::BTreeMap::new();
        files.insert(
            format!("{}.json", reviewer.id).into_bytes(),
            serde_json::to_vec(&reviewer).unwrap(),
        );
        (
            ReviewerFlip {
                files: std::cell::RefCell::new(files),
                reads: std::cell::Cell::new(0),
                replaces: std::cell::Cell::new(0),
                second: serde_json::to_vec(&owner).unwrap(),
                fail_release,
            },
            reviewer.id,
        )
    }

    /// The store error inside a claim refusal.
    ///
    /// Both arms run: a reviewer who stops being one is [`ClaimError::NotReviewer`],
    /// and a release that cannot be written is [`ClaimError::Store`].
    fn claim_store(error: &ClaimError) -> Option<&StoreError> {
        match error {
            ClaimError::Store(error) => Some(error),
            ClaimError::NotReviewer => None,
        }
    }

    fn as_human<'a>(registry: &'a HarnessRegistry, passwd: &'a str) -> ReviewerClaim<'a> {
        ReviewerClaim {
            now: 101,
            ttl: DEFAULT_TTL_SECS * 1000,
            boot_id: BOOT,
            peer_uid: 1000,
            peer_class: PeerClass::Human,
            registry,
            passwd,
            claim_token: TEST_TOKEN,
        }
    }

    #[test]
    fn a_claim_that_stops_being_reviewable_is_released() {
        let registry = registry();
        let passwd = "alice:x:1000:1000::/:/bin/sh\n";
        let (spool, id) = reviewer_flip(false);
        let error = claim_for_reviewer(&spool, &id, &as_human(&registry, passwd)).unwrap_err();
        assert_eq!(error, ClaimError::NotReviewer);
        assert_eq!(claim_store(&error), None);
        let stored = load_all(&spool).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].state, QueueState::Pending);
        assert_eq!(stored[0].uid, 1000);
        assert_eq!(spool.names().unwrap().len(), 1);
        assert!(spool.names_up_to(0).unwrap().is_empty());
        spool.publish("note.json", b"x").unwrap();
        spool.remove(b"note.json").unwrap();
        spool.publish("once.json", b"y").unwrap();
        spool.consume(b"once.json").unwrap();
        assert_eq!(
            spool.consume(b"once.json").unwrap_err(),
            xudo_sys::SpoolError::Gone {
                name: "missing".into(),
            }
        );
        assert!(spool.read(b"absent", 8).is_err());
        assert!(spool.read(format!("{id}.json").as_bytes(), 1).is_err());
        assert!(spool.replace(b"absent", b"a", b"b").is_err());
        assert!(
            spool
                .replace(format!("{id}.json").as_bytes(), b"nope", b"b")
                .is_err()
        );
        let (stuck, stuck_id) = reviewer_flip(true);
        let error =
            claim_for_reviewer(&stuck, &stuck_id, &as_human(&registry, passwd)).unwrap_err();
        assert_eq!(
            claim_store(&error),
            Some(&StoreError::Spool(xudo_sys::SpoolError::Io {
                operation: "replace".into(),
                at: "queue".into(),
                code: None,
                reason: "scripted".into(),
            }))
        );
        assert_eq!(load_all(&stuck).unwrap()[0].state, QueueState::Claimed);
        stuck.lock().unwrap();
        stuck.unlock();
    }

    fn store_of(entry: &QueueEntry) -> xudo_sys::FakeSpool {
        xudo_sys::FakeSpool::new().with_file(
            format!("{}.json", entry.id),
            serde_json::to_vec(entry).unwrap(),
        )
    }

    fn claimed_pair(id: u64) -> (xudo_sys::FakeSpool, xudo_sys::FakeSpool, String) {
        let store = xudo_sys::FakeSpool::new();
        let record = entry(id);
        admit(&store, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let nonce = "cd".repeat(32);
        bind_run_nonce(&store, &record.id, &nonce).unwrap();
        let requests = xudo_sys::FakeSpool::new();
        requests.publish(&nonce, b"minted").unwrap();
        (store, requests, nonce)
    }

    fn foreign(token: &str, now: u64) -> ClaimAct<'_> {
        ClaimAct {
            uid: TEST_UID.saturating_add(1),
            token,
            now,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn release_by_another_reviewer_mid_run_is_refused() {
        assert_eq!(
            StoreError::NotClaimant.to_string(),
            "queue claim belongs to another reviewer"
        );
        let foreign_token = "ef".repeat(32);
        let act = test_act(101);
        let (store, requests, nonce) = claimed_pair(90);
        let id = load_all(&store).unwrap()[0].id.clone();
        let fresh = foreign(&foreign_token, 101);
        assert_eq!(
            super::release_claim(&store, &requests, &id, &fresh, &[]).unwrap_err(),
            StoreError::NotClaimant
        );
        assert_eq!(load_all(&store).unwrap()[0].state, QueueState::Claimed);
        assert!(requests.files().contains_key(nonce.as_bytes()));
        let wrong_token = "11".repeat(32);
        let wrong = ClaimAct {
            uid: TEST_UID,
            token: &wrong_token,
            now: 101,
        };
        assert_eq!(
            super::fail_claim(&store, &requests, &id, &wrong, &[]).unwrap_err(),
            StoreError::NotClaimant
        );
        let exact = foreign(&foreign_token, 101_u64.saturating_add(CLAIM_LIFETIME_MS));
        assert_eq!(
            super::release_claim(&store, &requests, &id, &exact, &[]).unwrap_err(),
            StoreError::NotClaimant
        );
        let backwards = foreign(&foreign_token, 100);
        assert_eq!(
            super::release_claim(&store, &requests, &id, &backwards, &[]).unwrap_err(),
            StoreError::NotClaimant
        );
        let mut missing_clock = load_all(&store).unwrap().remove(0);
        missing_clock.claimed_at = None;
        let clockless = store_of(&missing_clock);
        let later = foreign(&foreign_token, u64::MAX);
        assert_eq!(
            super::release_claim(&clockless, &requests, &missing_clock.id, &later, &[])
                .unwrap_err(),
            StoreError::NotClaimant
        );
        let mut bad_token = load_all(&store).unwrap().remove(0);
        bad_token.claim_token = Some("not-a-nonce".into());
        let planted = store_of(&bad_token);
        let invalid = ClaimAct {
            uid: TEST_UID,
            token: "not-a-nonce",
            now: 101,
        };
        assert_eq!(
            super::release_claim(&planted, &requests, &bad_token.id, &invalid, &[]).unwrap_err(),
            StoreError::NotClaimant
        );
        let mut no_owner = entry(91);
        no_owner.state = QueueState::Claimed;
        let ownerless = store_of(&no_owner);
        assert_eq!(
            super::release_claim(&ownerless, &requests, &no_owner.id, &act, &[]).unwrap_err(),
            StoreError::NotClaimant
        );
        assert_eq!(
            super::claim(
                &xudo_sys::FakeSpool::new(),
                &entry(1).id,
                101,
                1000,
                BOOT,
                TEST_UID,
                "short"
            )
            .unwrap_err(),
            StoreError::InvalidEntry
        );
        let unbound = xudo_sys::FakeSpool::new();
        let record = entry(92);
        admit(&unbound, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        claim(&unbound, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let stale_binder = foreign(
            &foreign_token,
            101_u64.saturating_add(CLAIM_LIFETIME_MS).saturating_add(1),
        );
        assert_eq!(
            super::bind_run_nonce(&unbound, &record.id, &"ab".repeat(32), &stale_binder)
                .unwrap_err(),
            StoreError::NotClaimant
        );
        assert!(load_all(&unbound).unwrap()[0].run_nonce.is_none());

        let mut broken_nonce = load_all(&store).unwrap().remove(0);
        broken_nonce.run_nonce = Some("not-a-nonce".into());
        let broken = store_of(&broken_nonce);
        assert_eq!(
            super::release_claim(&broken, &requests, &broken_nonce.id, &act, &[]).unwrap_err(),
            StoreError::InvalidEntry
        );
        assert_eq!(load_all(&broken).unwrap()[0].state, QueueState::Claimed);

        let revoke_lock = xudo_sys::FakeSpool::new()
            .with_file(nonce.as_bytes().to_vec(), b"minted".to_vec())
            .failing_lock(xudo_sys::SpoolError::NotADirectory { at: "req".into() });
        assert_eq!(
            super::release_claim(&store, &revoke_lock, &id, &act, &[]).unwrap_err(),
            StoreError::Spool(xudo_sys::SpoolError::NotADirectory { at: "req".into() })
        );
        assert_eq!(load_all(&store).unwrap()[0].state, QueueState::Claimed);
        let revoke_remove = xudo_sys::FakeSpool::new()
            .with_file(nonce.as_bytes().to_vec(), b"minted".to_vec())
            .failing_remove(xudo_sys::SpoolError::Io {
                operation: "unlink".into(),
                at: "req".into(),
                code: None,
                reason: "scripted".into(),
            });
        assert!(
            super::release_claim(&store, &revoke_remove, &id, &act, &[])
                .unwrap_err()
                .to_string()
                .contains("unlink")
        );
        assert!(requests.files().contains_key(nonce.as_bytes()));

        let error = xudo_sys::SpoolError::Io {
            operation: "replace".into(),
            at: "queue".into(),
            code: None,
            reason: "scripted".into(),
        };
        let stuck = xudo_sys::FakeSpool::new().failing_replace_on_call(3, error.clone());
        let stuck_record = entry(93);
        admit(&stuck, &stuck_record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        claim(&stuck, &stuck_record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        let stuck_nonce = "22".repeat(32);
        bind_run_nonce(&stuck, &stuck_record.id, &stuck_nonce).unwrap();
        let stuck_requests = xudo_sys::FakeSpool::new();
        stuck_requests.publish(&stuck_nonce, b"minted").unwrap();
        assert_eq!(
            super::release_claim(&stuck, &stuck_requests, &stuck_record.id, &act, &[]).unwrap_err(),
            StoreError::Spool(error)
        );
        assert_eq!(load_all(&stuck).unwrap()[0].state, QueueState::Claimed);
        assert!(!stuck_requests.files().contains_key(stuck_nonce.as_bytes()));

        let stale = foreign(
            &foreign_token,
            101_u64.saturating_add(CLAIM_LIFETIME_MS).saturating_add(1),
        );
        let released = super::release_claim(&store, &requests, &id, &stale, &[]).unwrap();
        assert_eq!(released.state, QueueState::Pending);
        assert_eq!(released.run_nonce, None);
        assert_eq!(released.claimant_uid, None);
        assert!(!requests.files().contains_key(nonce.as_bytes()));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn release_after_a_gate_record_exists_marks_done_not_pending() {
        let foreign_token = "ef".repeat(32);
        let (store, requests, _nonce) = claimed_pair(94);
        let stored = load_all(&store).unwrap().remove(0);
        let denied =
            xudo_audit::Record::after(None, xudo_audit::Decision::Denied, Vec::new(), "human");
        let act = test_act(101);
        let still = super::release_claim(
            &store,
            &requests,
            &stored.id,
            &act,
            std::slice::from_ref(&denied),
        );
        // A non-binding record must not be what stops the release. Rebuild a
        // fresh pair for that check so the binding case below keeps its file.
        assert!(still.is_ok());
        assert_eq!(still.unwrap().state, QueueState::Pending);

        let (store, requests, nonce) = claimed_pair(95);
        let stored = load_all(&store).unwrap().remove(0);
        let bound = gate_record_for(&stored);
        let act = test_act(101);
        let done = super::release_claim(
            &store,
            &requests,
            &stored.id,
            &act,
            std::slice::from_ref(&bound),
        )
        .unwrap();
        assert_eq!(done.state, QueueState::Done);
        assert_eq!(done.run_nonce.as_deref(), Some(nonce.as_str()));
        assert_eq!(done.claimant_uid, Some(TEST_UID));
        assert!(!requests.files().contains_key(nonce.as_bytes()));
        assert!(!done.is_live(101, DEFAULT_TTL_SECS * 1000, BOOT));

        let (store, requests, nonce) = claimed_pair(96);
        let stored = load_all(&store).unwrap().remove(0);
        let bound = gate_record_for(&stored);
        let failed = super::fail_claim(
            &store,
            &requests,
            &stored.id,
            &act,
            std::slice::from_ref(&bound),
        )
        .unwrap();
        assert_eq!(failed.state, QueueState::Done);
        assert_eq!(failed.run_nonce.as_deref(), Some(nonce.as_str()));
        assert!(!requests.files().contains_key(nonce.as_bytes()));

        let (store, requests, nonce) = claimed_pair(97);
        let stored = load_all(&store).unwrap().remove(0);
        let stale = foreign(
            &foreign_token,
            101_u64.saturating_add(CLAIM_LIFETIME_MS).saturating_add(1),
        );
        let bound = gate_record_for(&stored);
        let done = super::release_claim(
            &store,
            &requests,
            &stored.id,
            &stale,
            std::slice::from_ref(&bound),
        )
        .unwrap();
        assert_eq!(done.state, QueueState::Done);
        assert_eq!(done.run_nonce.as_deref(), Some(nonce.as_str()));

        let (store, requests, _nonce) = claimed_pair(98);
        let stored = load_all(&store).unwrap().remove(0);
        let fresh = foreign(&foreign_token, 101);
        let bound = gate_record_for(&stored);
        assert_eq!(
            super::complete_after_gate_audit(&store, &requests, &stored.id, &fresh, &bound, 0)
                .unwrap_err(),
            StoreError::NotClaimant
        );
        assert_eq!(load_all(&store).unwrap()[0].state, QueueState::Claimed);
        let stale = foreign(
            &foreign_token,
            101_u64.saturating_add(CLAIM_LIFETIME_MS).saturating_add(1),
        );
        let done =
            super::complete_after_gate_audit(&store, &requests, &stored.id, &stale, &bound, 0)
                .unwrap();
        assert_eq!(done.state, QueueState::Done);

        let mut value = serde_json::to_value(entry(99)).unwrap();
        value.as_object_mut().unwrap().remove("run_nonce");
        value.as_object_mut().unwrap().remove("claimant_uid");
        value.as_object_mut().unwrap().remove("claim_token");
        value.as_object_mut().unwrap().remove("claimed_at");
        let parsed: QueueEntry = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.claimant_uid, None);
        assert_eq!(parsed.claim_token, None);
        assert_eq!(parsed.claimed_at, None);
        assert_eq!(parsed.run_nonce, None);
        let claimed_text = serde_json::to_vec(&done).unwrap();
        let claimed_text = String::from_utf8(claimed_text).unwrap();
        assert!(claimed_text.contains("claimant_uid"));
        let pending_text = String::from_utf8(serde_json::to_vec(&entry(1)).unwrap()).unwrap();
        assert!(!pending_text.contains("claimant_uid"));
    }

    #[test]
    fn a_lock_or_load_failure_refuses_before_the_claim_changes() {
        let error = xudo_sys::SpoolError::NotADirectory { at: "queue".into() };
        let registry = HarnessRegistry::empty();
        let reviewer = ReviewerClaim {
            now: 101,
            ttl: 1000,
            boot_id: BOOT,
            peer_uid: TEST_UID,
            peer_class: PeerClass::Human,
            registry: &registry,
            passwd: "",
            claim_token: TEST_TOKEN,
        };
        let missing = entry(70).id;
        assert_eq!(
            super::claim_for_reviewer(
                &xudo_sys::FakeSpool::new().failing_names(error.clone()),
                &missing,
                &reviewer,
            ),
            Err(ClaimError::Store(StoreError::Spool(error.clone())))
        );
        let act = test_act(0);
        assert_eq!(
            super::release_claim(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &xudo_sys::FakeSpool::new(),
                &missing,
                &act,
                &[],
            ),
            Err(StoreError::Spool(error.clone()))
        );
        assert_eq!(
            super::bind_run_nonce(
                &xudo_sys::FakeSpool::new().failing_lock(error.clone()),
                &missing,
                &"cd".repeat(32),
                &act,
            ),
            Err(StoreError::Spool(error.clone()))
        );
        assert_eq!(
            super::bind_run_nonce(
                &xudo_sys::FakeSpool::new(),
                &missing,
                &"cd".repeat(32),
                &act,
            ),
            Err(StoreError::Spool(xudo_sys::SpoolError::Unreadable {
                name: format!("{missing}.json"),
                reason: "fake: no such entry".into(),
            }))
        );

        let store = xudo_sys::FakeSpool::new();
        let record = entry(71);
        admit(&store, &record, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        claim(&store, &record.id, 101, DEFAULT_TTL_SECS * 1000, BOOT).unwrap();
        bind_run_nonce(&store, &record.id, &"cd".repeat(32)).unwrap();
        let stored = load_all(&store).unwrap().remove(0);
        let binding = gate_record_for(&stored);
        let requests = xudo_sys::FakeSpool::new().failing_lock(error.clone());
        assert_eq!(
            super::complete_after_gate_audit(&store, &requests, &record.id, &act, &binding, 0),
            Err(StoreError::Spool(error))
        );
        assert_eq!(load_all(&store).unwrap()[0].state, QueueState::Claimed);
    }
}
