//! Derived entry state: what may run now, what is waiting, and why.
//!
//! Status is computed from the queue, never stored in it. A stored state can
//! drift from the facts it summarizes; a derived one cannot.

use std::collections::BTreeMap;

use crate::entry::{Entry, STALE_AFTER_SECS};

/// What an entry can do right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// May run.
    Ready,
    /// Ran and failed; may be retried.
    Failed {
        /// The exit code of the last attempt.
        code: i32,
    },
    /// May not run yet, and the literal reason.
    Blocked {
        /// Why, in the words the human sees.
        reason: String,
    },
    /// An earlier step or dependency failed; running this needs an explicit
    /// human override.
    Halted {
        /// Why, in the words the human sees.
        reason: String,
    },
    /// Older than the retention window; runnable, shown greyed.
    Stale,
}

impl Status {
    /// Whether the human may select this entry to run.
    ///
    /// Blocked and halted entries are unselectable; a failed or stale entry
    /// is a deliberate retry or a late run, both the human's call.
    #[must_use]
    pub fn selectable(&self) -> bool {
        matches!(self, Self::Ready | Self::Failed { .. } | Self::Stale)
    }

    /// One word for the list row.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Failed { .. } => "failed",
            Self::Blocked { .. } => "blocked",
            Self::Halted { .. } => "halted",
            Self::Stale => "stale",
        }
    }

    /// The reason to show beside the label, when there is one.
    #[must_use]
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::Ready | Self::Stale => None,
            Self::Failed { code } => Some(format!("exit {code}")),
            Self::Blocked { reason } | Self::Halted { reason } => Some(reason.clone()),
        }
    }
}

/// Computes the status of `entry` against the whole queue.
#[must_use]
pub fn status_of(entry: &Entry, queue: &[Entry], now_unix: u64) -> Status {
    // A failed earlier step halts the group: running step n after step n-1
    // failed is overriding a dependency, and that choice must be explicit.
    if let (Some(group), Some(step)) = (&entry.group, entry.step) {
        let mut earlier: Vec<&Entry> = queue
            .iter()
            .filter(|e| {
                e.id != entry.id
                    && e.group.as_deref() == Some(group.as_str())
                    && e.step.is_some_and(|s| s < step)
            })
            .collect();
        earlier.sort_by_key(|e| e.step);
        if let Some(failed) = earlier.iter().find(|e| e.last_exit.is_some_and(|c| c != 0)) {
            let (s, c) = (step_of(failed), failed.last_exit.unwrap_or(1));
            return Status::Halted {
                reason: format!("step {s} failed with exit {c}"),
            };
        }
        if let Some(waiting) = earlier.first() {
            return Status::Blocked {
                reason: format!("step {} has not run", step_of(waiting)),
            };
        }
    }

    // A dependency still in the queue has not succeeded: success removes an
    // entry. One that failed halts this one; one that is waiting blocks it.
    // An id that is gone was either run successfully or deliberately dropped,
    // and both satisfy the dependency.
    for needed in &entry.needs {
        if let Some(dep) = queue.iter().find(|e| e.id == *needed) {
            if dep.last_exit.is_some_and(|c| c != 0) {
                return Status::Halted {
                    reason: format!("needs #{needed}, which failed"),
                };
            }
            return Status::Blocked {
                reason: format!("needs #{needed}, which has not run"),
            };
        }
    }

    if let Some(code) = entry.last_exit.filter(|c| *c != 0) {
        return Status::Failed { code };
    }

    if now_unix.saturating_sub(entry.queued_at) > STALE_AFTER_SECS {
        return Status::Stale;
    }

    Status::Ready
}

/// The step number for a message, tolerating the impossible absence.
fn step_of(entry: &Entry) -> u32 {
    entry.step.unwrap_or(0)
}

/// Orders entries for a whole-queue run.
///
/// Queue order by id, except that a group's steps run in step order no matter
/// what order they were queued in: the group is keyed by its first-queued id,
/// so groups themselves still run where they first appeared.
#[must_use]
pub fn run_order(queue: &[Entry]) -> Vec<u64> {
    let mut first_id_of_group: BTreeMap<&str, u64> = BTreeMap::new();
    for e in queue {
        if let Some(g) = &e.group {
            let slot = first_id_of_group.entry(g.as_str()).or_insert(e.id);
            *slot = (*slot).min(e.id);
        }
    }
    let mut keyed: Vec<(u64, u32, u64)> = queue
        .iter()
        .map(|e| {
            let anchor = e
                .group
                .as_deref()
                .and_then(|g| first_id_of_group.get(g).copied())
                .unwrap_or(e.id);
            (anchor, e.step.unwrap_or(0), e.id)
        })
        .collect();
    keyed.sort_unstable();
    keyed.into_iter().map(|(_, _, id)| id).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::entry::QUEUE_SCHEMA_VERSION;

    fn entry(id: u64, group: Option<&str>, step: Option<u32>) -> Entry {
        Entry {
            schema_version: QUEUE_SCHEMA_VERSION,
            id,
            argv: vec!["true".into()],
            reason: None,
            group: group.map(str::to_owned),
            step,
            needs: Vec::new(),
            cwd: None,
            dry_run_of: Vec::new(),
            queued_at: 1000,
            queued_by: None,
            attempts: 0,
            last_exit: None,
        }
    }

    #[test]
    fn an_independent_fresh_entry_is_ready() {
        let e = entry(1, None, None);
        let status = status_of(&e, std::slice::from_ref(&e), 1000);
        assert_eq!(status, Status::Ready);
        assert!(status.selectable());
        assert_eq!(status.label(), "ready");
        assert_eq!(status.detail(), None);
    }

    #[test]
    fn a_blocked_step_cannot_be_selected() {
        let one = entry(1, Some("deploy"), Some(1));
        let two = entry(2, Some("deploy"), Some(2));
        let queue = [one, two.clone()];
        let status = status_of(&two, &queue, 1000);
        assert_eq!(
            status,
            Status::Blocked {
                reason: "step 1 has not run".into()
            }
        );
        assert!(!status.selectable());
        assert_eq!(status.detail().unwrap(), "step 1 has not run");
    }

    #[test]
    fn a_completed_earlier_step_unblocks_the_next() {
        // Success removes the entry, so "step 1 gone" is "step 1 ran".
        let two = entry(2, Some("deploy"), Some(2));
        assert_eq!(
            status_of(&two, std::slice::from_ref(&two), 1000),
            Status::Ready
        );
    }

    #[test]
    fn a_failed_step_halts_its_group() {
        let mut one = entry(1, Some("deploy"), Some(1));
        one.last_exit = Some(3);
        one.attempts = 1;
        let two = entry(2, Some("deploy"), Some(2));
        let queue = [one.clone(), two.clone()];
        let status = status_of(&two, &queue, 1000);
        assert_eq!(
            status,
            Status::Halted {
                reason: "step 1 failed with exit 3".into()
            }
        );
        assert!(!status.selectable());
        // The failed step itself is retryable.
        let own = status_of(&one, &queue, 1000);
        assert_eq!(own, Status::Failed { code: 3 });
        assert!(own.selectable());
        assert_eq!(own.detail().unwrap(), "exit 3");
        assert_eq!(own.label(), "failed");
    }

    #[test]
    fn the_lowest_waiting_step_is_the_one_named() {
        let one = entry(1, Some("g"), Some(1));
        let two = entry(2, Some("g"), Some(2));
        let three = entry(3, Some("g"), Some(3));
        let queue = [one, two, three.clone()];
        let status = status_of(&three, &queue, 1000);
        assert_eq!(
            status,
            Status::Blocked {
                reason: "step 1 has not run".into()
            }
        );
    }

    #[test]
    fn a_pending_dependency_blocks_and_a_failed_one_halts() {
        let dep = entry(1, None, None);
        let mut needy = entry(2, None, None);
        needy.needs = vec![1];

        let queue = [dep.clone(), needy.clone()];
        assert_eq!(
            status_of(&needy, &queue, 1000),
            Status::Blocked {
                reason: "needs #1, which has not run".into()
            }
        );

        let mut failed_dep = dep;
        failed_dep.last_exit = Some(1);
        let queue = [failed_dep, needy.clone()];
        assert_eq!(
            status_of(&needy, &queue, 1000),
            Status::Halted {
                reason: "needs #1, which failed".into()
            }
        );

        // Gone means satisfied: ran successfully or deliberately dropped.
        assert_eq!(
            status_of(&needy, std::slice::from_ref(&needy), 1000),
            Status::Ready
        );
    }

    #[test]
    fn an_old_entry_goes_stale_but_stays_selectable() {
        let e = entry(1, None, None);
        let much_later = 1000 + STALE_AFTER_SECS + 1;
        let status = status_of(&e, std::slice::from_ref(&e), much_later);
        assert_eq!(status, Status::Stale);
        assert!(status.selectable());
        assert_eq!(status.label(), "stale");
    }

    #[test]
    fn steps_run_in_step_order_even_when_queued_backwards() {
        let two = entry(1, Some("g"), Some(2));
        let one = entry(2, Some("g"), Some(1));
        let lone = entry(3, None, None);
        assert_eq!(run_order(&[two, one, lone]), vec![2, 1, 3]);
    }

    #[test]
    fn groups_hold_their_place_in_the_queue() {
        let a = entry(1, None, None);
        let g1 = entry(2, Some("g"), Some(1));
        let b = entry(3, None, None);
        let g2 = entry(4, Some("g"), Some(2));
        assert_eq!(run_order(&[a, g1, b, g2]), vec![1, 2, 4, 3]);
    }

    #[test]
    fn a_step_message_survives_a_hand_edited_stepless_sibling() {
        // A group member with no step is unordered; it neither blocks nor is
        // named, and the tolerated-absence helper stays exercised.
        let stepless = entry(1, Some("g"), None);
        assert_eq!(step_of(&stepless), 0);
        let two = entry(2, Some("g"), Some(2));
        let queue = [stepless, two.clone()];
        assert_eq!(status_of(&two, &queue, 1000), Status::Ready);
    }
}
