//! Root-held requests that need a human decision.
//!
//! Queue records contain the broker's canonical command and the policy
//! generation under which it was requested. A record is only a request: it
//! never authorizes execution. The caller must be a listed reviewer and the
//! command must be re-decided against the current rules before the password
//! gate can be reached.

use serde::{Deserialize, Serialize};
use xudo_policy::HarnessRegistry;

/// Default lifetime of a queued request. Root may configure a shorter one.
pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
/// Pending requests allowed for one harness uid.
pub const MAX_PER_UID: usize = 32;
/// Pending requests allowed across all harnesses.
pub const MAX_TOTAL: usize = 1024;
/// Largest serialized entry accepted from the root-held store.
pub const MAX_ENTRY_BYTES: usize = 32 * 1024;

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
    pub argv: Vec<String>,
    /// Working directory captured by the broker.
    pub cwd: String,
    /// Root registry label that classified the requester.
    pub harness: String,
    /// Kernel-attested uid of the harness.
    pub uid: u32,
    /// Rule that produced `ask-human`.
    pub rule_id: String,
    /// Ruleset generation at submission.
    pub generation: String,
    /// Unix time at submission.
    pub queued_at: u64,
    /// Unix time after which the record cannot be run.
    pub expires_at: u64,
    /// Untrusted text; render only after terminal sanitization.
    pub reason: Option<String>,
    /// Broker-owned terminal status.
    pub state: QueueState,
}

impl QueueEntry {
    /// Whether an entry remains pending at `now`.
    #[must_use]
    pub fn is_live(&self, now: u64) -> bool {
        self.state == QueueState::Pending && now < self.expires_at
    }

    /// Whether a freshly evaluated request may enter the password path.
    ///
    /// The recorded generation is deliberately not an authorization token:
    /// both the live policy decision and its generation must still match.
    #[must_use]
    pub fn may_run(&self, now: u64, current_generation: &str, fresh_human_allow: bool) -> bool {
        self.is_live(now)
            && self.generation == current_generation
            && fresh_human_allow
            && !self.argv.is_empty()
    }
}

/// Whether the peer may see an entry. The harness may inspect its own status;
/// only a configured reviewer may run or dismiss it.
#[must_use]
pub fn visibility(
    entry: &QueueEntry,
    peer_uid: u32,
    registry: &HarnessRegistry,
    passwd: &str,
) -> (bool, bool) {
    let owner = entry.uid == peer_uid;
    let reviewer = registry.get(&entry.harness).is_some_and(|harness| {
        harness
            .reviewers
            .iter()
            .any(|name| xudo_policy::passwd_uid(passwd, name) == Some(peer_uid))
    });
    (owner || reviewer, reviewer && !owner)
}

/// Queue capacity decision over the live records only.
#[must_use]
pub fn within_bounds(entries: &[QueueEntry], uid: u32, now: u64) -> bool {
    let live: Vec<&QueueEntry> = entries.iter().filter(|entry| entry.is_live(now)).collect();
    live.len() < MAX_TOTAL && live.iter().filter(|entry| entry.uid == uid).count() < MAX_PER_UID
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::*;

    fn entry(id: u64) -> QueueEntry {
        QueueEntry {
            id: format!("{id:064x}"),
            argv: vec!["/usr/bin/apt-get".into(), "upgrade".into()],
            cwd: "/srv".into(),
            harness: "codex".into(),
            uid: 1001,
            rule_id: "xudo.pkg.upgrade".into(),
            generation: "generation-a".into(),
            queued_at: 100,
            expires_at: 100 + DEFAULT_TTL_SECS,
            reason: Some("please run".into()),
            state: QueueState::Pending,
        }
    }

    fn registry() -> HarnessRegistry {
        HarnessRegistry::from_files([(
            "codex.toml",
            "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n",
        )])
        .unwrap()
    }

    #[test]
    fn an_agent_cannot_edit_or_delete_a_queued_entry() {
        let record = entry(1);
        let (visible, may_mutate) =
            visibility(&record, 1001, &registry(), "alice:x:1000:1000::/:/bin/sh\n");
        assert!(visible);
        assert!(!may_mutate);
        assert_eq!(record.state, QueueState::Pending);
    }

    #[test]
    fn a_queued_entry_runs_only_through_the_password_path() {
        let record = entry(1);
        assert!(record.may_run(101, "generation-a", true));
        // This module provides no passwordless capability or alternate gate.
        assert!(!record.may_run(101, "generation-a", false));
    }

    #[test]
    fn a_queued_entry_is_re_decided_at_run_time() {
        let record = entry(1);
        assert!(!record.may_run(101, "generation-a", false));
        assert!(record.may_run(101, "generation-a", true));
    }

    #[test]
    fn a_rules_change_after_queueing_denies_the_run() {
        assert!(!entry(1).may_run(101, "generation-b", true));
    }

    #[test]
    fn an_expired_entry_cannot_run() {
        let record = entry(1);
        assert!(!record.may_run(record.expires_at, "generation-a", true));
    }

    #[test]
    fn a_harness_cannot_run_or_dismiss_its_own_entry() {
        let (visible, may_mutate) = visibility(
            &entry(1),
            1001,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(visible);
        assert!(!may_mutate);
    }

    #[test]
    fn queue_flood_stops_at_the_per_uid_bound() {
        let entries: Vec<QueueEntry> = (0..MAX_PER_UID).map(|id| entry(id as u64)).collect();
        assert!(!within_bounds(&entries, 1001, 101));
        assert!(within_bounds(&entries, 2002, 101));
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
        assert!(!within_bounds(&entries, u32::MAX, 101));
    }

    #[test]
    fn a_completed_entry_is_not_pending_or_runnable() {
        let mut record = entry(1);
        record.state = QueueState::Done;
        assert!(!record.is_live(101));
        assert!(!record.may_run(101, "generation-a", true));
    }

    #[test]
    fn a_non_reviewer_cannot_list_another_harness_queue() {
        let (visible, may_mutate) = visibility(
            &entry(1),
            2002,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(!visible);
        assert!(!may_mutate);
    }

    #[test]
    fn a_configured_reviewer_can_list_another_harness_entry() {
        let (visible, may_mutate) = visibility(
            &entry(1),
            1000,
            &registry(),
            "alice:x:1000:1000::/:/bin/sh\n",
        );
        assert!(visible);
        assert!(may_mutate);
    }

    #[test]
    fn an_unmentioned_command_is_denied_not_queued() {
        // No queue entry can be authorized without the policy's fresh allow.
        assert!(!entry(1).may_run(101, "generation-a", false));
    }

    #[test]
    fn root_queue_expiry_setting_can_only_shorten_the_default() {
        assert_eq!(effective_ttl(None), DEFAULT_TTL_SECS);
        assert_eq!(effective_ttl(Some(60)), 60);
        assert_eq!(effective_ttl(Some(DEFAULT_TTL_SECS)), DEFAULT_TTL_SECS);
        assert_eq!(effective_ttl(Some(DEFAULT_TTL_SECS + 1)), DEFAULT_TTL_SECS);
    }
}
