//! Pure confirmation state and matching rules.

use sha2::{Digest, Sha256};
use xudo_gate::request::{ConfirmationState, PendingRequest, WatcherPin};

/// Backoff base duration.
pub const BACKOFF_BASE_MS: u64 = 30_000;
/// Maximum backoff duration.
pub const BACKOFF_MAX_MS: u64 = 15 * 60 * 1_000;
/// Maximum time allowed at the password prompt after an approval is used.
pub const CONSUMED_TTL_MS: u64 = 120_000;

/// Settings used by confirmation transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Minimum time from first display before an answer is accepted.
    pub reaction_floor_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            reaction_floor_ms: 2_000,
        }
    }
}

/// Kernel facts about a possible watcher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatcherFacts {
    /// Effective uid from peer credentials.
    pub uid: u32,
    /// Pid from peer credentials.
    pub pid: u32,
    /// Start time from proc stat.
    pub starttime: u64,
    /// Controlling terminal number.
    pub tty: i64,
    /// Session id.
    pub sid: i64,
    /// Namespace divergence was found or could not be ruled out.
    pub diverged: bool,
}

impl WatcherFacts {
    /// Pins the watcher facts to an approved entry.
    pub fn pin(self) -> WatcherPin {
        WatcherPin {
            uid: self.uid,
            pid: self.pid,
            starttime: self.starttime,
            tty: self.tty,
            sid: self.sid,
        }
    }
}

/// What a watcher answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer<'a> {
    /// Approve only when the typed word matches byte-for-byte.
    Approve(&'a [u8]),
    /// Deny the request.
    Deny,
}

/// Why a confirmation transition was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfirmError {
    /// The entry is not pending.
    #[error("entry is not pending")]
    NotPending,
    /// The peer cannot watch or answer this entry.
    #[error("watcher is not eligible")]
    IneligibleWatcher,
    /// The answer arrived before the reaction floor.
    #[error("answer arrived before the reaction floor")]
    TooFast,
    /// The answer did not match the action's final word.
    #[error("answer did not match the action word")]
    WrongWord,
    /// The action has no non-empty final word.
    #[error("action has no approval word")]
    MissingWord,
    /// The entry deadline has passed.
    #[error("entry expired")]
    Expired,
}

/// Whether the watcher may see or answer this request.
pub fn watcher_eligible(entry: &PendingRequest, watcher: WatcherFacts) -> bool {
    !watcher.diverged
        && watcher.pin().is_eligible_for(
            entry.caller_uid,
            entry.caller_pid,
            entry.caller_starttime,
            entry.caller_sid,
            entry.caller_tty,
        )
}

/// Records when this watcher first saw the prompt.
pub fn mark_shown(entry: &mut PendingRequest, watcher: WatcherFacts, now_ms: u64) -> bool {
    if entry.state != ConfirmationState::Pending || !entry.needs_watch {
        return false;
    }
    if !watcher_eligible(entry, watcher) {
        return false;
    }
    let pin = watcher.pin();
    if entry.shown_to.as_ref() == Some(&pin) {
        return true;
    }
    if now_ms >= entry.deadline.0 {
        entry.state = ConfirmationState::Expired;
        return false;
    }
    entry.shown_at_ms = Some(xudo_gate::request::BoottimeMillis(now_ms));
    entry.shown_to = Some(pin);
    true
}

/// Applies a watcher answer. Rejected answers leave a live pending entry unchanged.
///
/// # Errors
///
/// Returns a refusal when the entry is no longer pending, the watcher is
/// ineligible, the deadline passed, the prompt floor has not elapsed, or the
/// approval word does not match the action.
pub fn answer(
    entry: &mut PendingRequest,
    watcher: WatcherFacts,
    now_ms: u64,
    settings: Settings,
    answer: Answer<'_>,
) -> Result<(), ConfirmError> {
    if entry.state != ConfirmationState::Pending {
        return Err(ConfirmError::NotPending);
    }
    if !watcher_eligible(entry, watcher) {
        return Err(ConfirmError::IneligibleWatcher);
    }
    if now_ms >= entry.deadline.0 {
        entry.state = ConfirmationState::Expired;
        entry.confirmed = false;
        entry.confirmed_by = None;
        return Err(ConfirmError::Expired);
    }
    let shown_at = entry.shown_at_ms.ok_or(ConfirmError::TooFast)?.0;
    if entry.shown_to.as_ref() != Some(&watcher.pin()) {
        return Err(ConfirmError::IneligibleWatcher);
    }
    if now_ms.saturating_sub(shown_at) < settings.reaction_floor_ms {
        return Err(ConfirmError::TooFast);
    }
    if let Answer::Approve(word) = answer {
        let expected = action_word(entry.action.as_bytes()).ok_or(ConfirmError::MissingWord)?;
        if word != expected {
            return Err(ConfirmError::WrongWord);
        }
        entry.state = ConfirmationState::Approved;
        entry.confirmed = true;
        entry.confirmed_by = Some(watcher.pin());
    } else {
        entry.state = ConfirmationState::Denied;
        entry.confirmed = false;
        entry.confirmed_by = None;
    }
    Ok(())
}

fn action_word(action: &[u8]) -> Option<&[u8]> {
    let word = match action.iter().rposition(|byte| *byte == b'.') {
        Some(separator) => action
            .get(separator.saturating_add(1)..)
            .unwrap_or_default(),
        None => action,
    };
    (!word.is_empty()).then_some(word)
}

/// Builds a length-framed SHA-256 fingerprint for a request.
pub fn fingerprint(uid: u32, program: &[u8], argv: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    frame(&mut hash, &uid.to_be_bytes());
    frame(&mut hash, program);
    hash.update((argv.len() as u64).to_be_bytes());
    for argument in argv {
        frame(&mut hash, argument);
    }
    let bytes = hash.finalize();
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

/// Backoff duration for a one-based strike count. Zero strikes has no delay.
pub fn backoff_ms(strikes: u32) -> u64 {
    if strikes == 0 {
        return 0;
    }
    let shift = strikes.saturating_sub(1).min(63);
    BACKOFF_BASE_MS
        .saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX))
        .min(BACKOFF_MAX_MS)
}

/// Whether this pending entry has the requested fingerprint.
pub fn is_duplicate(entry: &PendingRequest, candidate: &str, now_ms: u64) -> bool {
    entry.state == ConfirmationState::Pending
        && entry.needs_watch
        && now_ms < entry.deadline.0
        && entry.fingerprint == candidate
}

/// Marks an overdue pending or approved entry expired.
pub fn expire(entry: &mut PendingRequest, now_ms: u64) -> bool {
    if matches!(
        entry.state,
        ConfirmationState::Pending | ConfirmationState::Approved
    ) && now_ms >= entry.deadline.0
    {
        entry.state = ConfirmationState::Expired;
        entry.confirmed = false;
        entry.confirmed_by = None;
        true
    } else {
        false
    }
}

/// Takes a matching approval from a collection, returning the remaining entry and consumed entry.
/// The caller persists `remaining` before proceeding to the password gate.
#[derive(Clone, Debug)]
pub struct ApprovalCaller<'a> {
    /// Pid of the caller that is retrying the approved command.
    pub pid: u32,
    /// Kernel start time of the retrying caller.
    pub starttime: u64,
    /// Effective uid of the caller.
    pub uid: u32,
    /// Session id of the caller.
    pub sid: i64,
    /// Controlling terminal number of the caller.
    pub tty: i64,
    /// Broker-attested class of the caller.
    pub attested_class: &'a xudo_gate::request::AttestedClass,
    /// Live cgroup scope id, when the caller is an enrolled agent.
    pub scope_id: Option<u64>,
    /// Live kernel boot id, when a scope id is present.
    pub boot_id: Option<&'a str>,
}

/// Takes an approved entry only when its complete caller identity matches.
///
/// Returns the unmatched entry unchanged, or the consumed entry. The caller
/// must persist the transition before proceeding to the password gate.
pub fn take_approval(
    entry: Option<PendingRequest>,
    program: &[u8],
    argv: &[&[u8]],
    generation: u64,
    action: &str,
    now_ms: u64,
    caller: &ApprovalCaller<'_>,
) -> (Option<PendingRequest>, Option<PendingRequest>) {
    let Some(mut candidate) = entry else {
        return (None, None);
    };
    let exact_argv = candidate.program.as_bytes() == program
        && candidate.argv.len() == argv.len()
        && candidate
            .argv
            .iter()
            .zip(argv)
            .all(|(left, right)| left.as_bytes() == *right);
    if candidate.state == ConfirmationState::Approved
        && candidate.needs_watch
        && candidate.caller_uid == caller.uid
        && candidate.caller_pid == caller.pid
        && candidate.caller_starttime == caller.starttime
        && candidate.caller_sid == caller.sid
        && candidate.caller_tty == caller.tty
        && candidate.attested_class == *caller.attested_class
        && candidate.attested_scope_id == caller.scope_id
        && candidate.boot_id.as_deref() == caller.boot_id
        && candidate.generation == generation
        && candidate.action == action
        && exact_argv
        && now_ms < candidate.deadline.0
    {
        candidate.state = ConfirmationState::Consumed;
        candidate.deadline.0 = candidate
            .deadline
            .0
            .min(now_ms.saturating_add(CONSUMED_TTL_MS));
        (None, Some(candidate))
    } else {
        (Some(candidate), None)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use proptest::prelude::*;
    use xudo_gate::request::{BoottimeMillis, REQUEST_SCHEMA_VERSION};

    fn matching_caller() -> ApprovalCaller<'static> {
        ApprovalCaller {
            pid: 10,
            starttime: 20,
            uid: 1000,
            sid: 2,
            tty: 3,
            attested_class: &xudo_gate::request::AttestedClass::Unattested,
            scope_id: None,
            boot_id: None,
        }
    }

    fn entry() -> PendingRequest {
        PendingRequest {
            schema_version: REQUEST_SCHEMA_VERSION,
            nonce: "a".repeat(64),
            caller_pid: 10,
            caller_starttime: 20,
            action: "xudo.pkg.remove".to_owned(),
            program: "/usr/bin/pkg".to_owned(),
            argv: vec!["remove".to_owned(), "demo".to_owned()],
            generation: 1,
            deadline: BoottimeMillis(10_000),
            confirmed: false,
            confirmed_by: None,
            state: ConfirmationState::Pending,
            caller_uid: 1000,
            caller_sid: 2,
            caller_tty: 3,
            needs_watch: true,
            shown_at_ms: None,
            shown_to: None,
            fingerprint: "0".repeat(64),
            claimed_classification: "human".to_owned(),
            attested_class: xudo_gate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }

    fn approved_entry() -> PendingRequest {
        let mut approved = entry();
        approved.state = ConfirmationState::Approved;
        approved.confirmed = true;
        approved
    }

    #[test]
    fn an_approval_for_an_agent_scope_cannot_be_consumed_from_another_scope() {
        let mut approved = approved_entry();
        approved.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        approved.attested_scope_id = Some(44);
        approved.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        let live = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 45 };
        let mut caller = matching_caller();
        caller.attested_class = &live;
        caller.scope_id = Some(45);
        caller.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789");
        let (remaining, consumed) = take_approval(
            Some(approved),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            2_000,
            &caller,
        );
        assert!(remaining.is_some());
        assert!(consumed.is_none());
    }

    #[test]
    fn an_approval_for_a_human_cannot_be_consumed_by_an_attested_agent() {
        let mut approved = approved_entry();
        approved.attested_class = xudo_gate::request::AttestedClass::Human;
        let live = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        let mut caller = matching_caller();
        caller.attested_class = &live;
        caller.scope_id = Some(44);
        caller.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789");
        let (remaining, consumed) = take_approval(
            Some(approved),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            2_000,
            &caller,
        );
        assert!(remaining.is_some());
        assert!(consumed.is_none());
    }

    #[test]
    fn an_agent_approval_from_another_boot_cannot_be_consumed() {
        let mut approved = approved_entry();
        approved.attested_class = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        approved.attested_scope_id = Some(44);
        approved.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        let live = xudo_gate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        let mut caller = matching_caller();
        caller.attested_class = &live;
        caller.scope_id = Some(44);
        caller.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456780");
        let (remaining, consumed) = take_approval(
            Some(approved),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            2_000,
            &caller,
        );
        assert!(remaining.is_some());
        assert!(consumed.is_none());
    }

    #[test]
    fn a_same_uid_process_cannot_spend_someone_elses_approval() {
        let approved = approved_entry();
        let mut caller = matching_caller();
        caller.pid = 11;
        caller.starttime = 21;
        let (remaining, consumed) = take_approval(
            Some(approved),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            2_000,
            &caller,
        );
        assert!(remaining.is_some());
        assert!(consumed.is_none());
    }

    fn watcher() -> WatcherFacts {
        WatcherFacts {
            uid: 1000,
            pid: 11,
            starttime: 21,
            tty: (136 << 8) | 1,
            sid: 5,
            diverged: false,
        }
    }

    fn approve(entry: &mut PendingRequest, now: u64, word: &[u8]) -> Result<(), ConfirmError> {
        answer(
            entry,
            watcher(),
            now,
            Settings::default(),
            Answer::Approve(word),
        )
    }

    proptest! {
        #[test]
        fn take_approval_never_consumes_non_approved_entries(
            state in prop_oneof![Just(ConfirmationState::Pending), Just(ConfirmationState::Denied), Just(ConfirmationState::Expired), Just(ConfirmationState::Approved), Just(ConfirmationState::Consumed)],
        ) {
            let mut request = entry();
            request.state = state;
            request.needs_watch = state != ConfirmationState::Approved;
            request.confirmed = state == ConfirmationState::Approved;
            let (_, consumed) = take_approval(
            Some(request),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            2_000,
            &matching_caller()
        );
            prop_assert!(consumed.is_none());
        }

        #[test]
        fn no_transition_leaves_denied_or_expired(denied in any::<bool>(), now in 0u64..20_000) {
            let mut request = entry();
            request.state = if denied { ConfirmationState::Denied } else { ConfirmationState::Expired };
            let before = request.clone();
            prop_assert_eq!(answer(&mut request, watcher(), now, Settings::default(), Answer::Deny), Err(ConfirmError::NotPending));
            prop_assert_eq!(answer(&mut request, watcher(), now, Settings::default(), Answer::Approve(b"remove")), Err(ConfirmError::NotPending));
            prop_assert!(!mark_shown(&mut request, watcher(), now));
            prop_assert_eq!(request, before);
        }

        #[test]
        fn an_approval_never_outlives_the_entry_ttl(shown in 0u64..10_000, extra in 2_000u64..20_000) {
            let mut request = entry();
            request.deadline = BoottimeMillis(shown.saturating_add(extra));
            prop_assert!(mark_shown(&mut request, watcher(), shown));
            let now = request.deadline.0;
            prop_assert_eq!(approve(&mut request, now, b"remove"), Err(ConfirmError::Expired));
            prop_assert_eq!(request.state, ConfirmationState::Expired);
            prop_assert!(!request.confirmed);
        }

        #[test]
        fn appending_an_argument_changes_the_fingerprint(tail in any::<Vec<u8>>()) {
            let before = fingerprint(1000, b"/bin/tool", &[b"run"]);
            let after = fingerprint(1000, b"/bin/tool", &[b"run", &tail]);
            prop_assert_ne!(before, after);
        }
    }

    #[test]
    fn a_watcher_in_the_requesters_session_cannot_approve() {
        let mut request = entry();
        let mut peer = watcher();
        peer.sid = request.caller_sid;
        assert_eq!(
            answer(
                &mut request,
                peer,
                3_000,
                Settings::default(),
                Answer::Approve(b"remove")
            ),
            Err(ConfirmError::IneligibleWatcher)
        );
        assert_eq!(request.state, ConfirmationState::Pending);
    }

    #[test]
    fn a_second_rerun_does_not_get_the_approval() {
        let mut approved = entry();
        approved.deadline = BoottimeMillis(1_000_000);
        assert!(mark_shown(&mut approved, watcher(), 1_000));
        approve(&mut approved, 3_000, b"remove").unwrap();
        let (_, consumed) = take_approval(
            Some(approved),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            4_000,
            &matching_caller(),
        );
        let consumed = consumed.unwrap();
        assert_eq!(consumed.state, ConfirmationState::Consumed);
        let (remaining, replay) = take_approval(
            Some(consumed),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            5_000,
            &matching_caller(),
        );
        assert!(replay.is_none());
        assert_eq!(remaining.unwrap().state, ConfirmationState::Consumed);
    }

    #[test]
    fn a_consumed_approval_expires_two_minutes_after_use() {
        let mut approved = entry();
        approved.deadline = BoottimeMillis(1_000_000);
        assert!(mark_shown(&mut approved, watcher(), 1_000));
        approve(&mut approved, 3_000, b"remove").unwrap();
        let (_, consumed) = take_approval(
            Some(approved),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            5_000,
            &matching_caller(),
        );
        assert_eq!(consumed.unwrap().deadline.0, 125_000);
    }

    #[test]
    fn a_watcher_on_the_requesters_tty_cannot_approve() {
        let mut request = entry();
        let mut peer = watcher();
        peer.tty = request.caller_tty;
        assert_eq!(
            answer(
                &mut request,
                peer,
                3_000,
                Settings::default(),
                Answer::Approve(b"remove")
            ),
            Err(ConfirmError::IneligibleWatcher)
        );
    }

    #[test]
    fn a_requester_pin_cannot_watch_its_own_entry() {
        let request = entry();
        let mut peer = watcher();
        peer.pid = request.caller_pid;
        peer.starttime = request.caller_starttime;
        assert!(!watcher_eligible(&request, peer));
    }

    #[test]
    fn a_watcher_without_a_terminal_cannot_approve() {
        let mut request = entry();
        let mut peer = watcher();
        peer.tty = 0;
        assert!(!watcher_eligible(&request, peer));
        assert_eq!(
            answer(
                &mut request,
                peer,
                3_000,
                Settings::default(),
                Answer::Approve(b"remove")
            ),
            Err(ConfirmError::IneligibleWatcher)
        );
    }

    #[test]
    fn a_diverged_watcher_cannot_approve() {
        let mut request = entry();
        let mut peer = watcher();
        peer.diverged = true;
        assert_eq!(
            answer(
                &mut request,
                peer,
                3_000,
                Settings::default(),
                Answer::Approve(b"remove")
            ),
            Err(ConfirmError::IneligibleWatcher)
        );
    }

    #[test]
    fn another_users_watcher_cannot_see_or_answer() {
        let mut request = entry();
        let mut peer = watcher();
        peer.uid += 1;
        assert!(!watcher_eligible(&request, peer));
        assert_eq!(
            answer(
                &mut request,
                peer,
                3_000,
                Settings::default(),
                Answer::Approve(b"remove")
            ),
            Err(ConfirmError::IneligibleWatcher)
        );
        assert!(!mark_shown(&mut request, peer, 1_000));
    }

    #[test]
    fn a_request_that_needs_no_watch_is_never_shown() {
        let mut request = entry();
        request.needs_watch = false;
        let before = request.clone();
        assert!(!mark_shown(&mut request, watcher(), 1_000));
        assert_eq!(request, before);
    }

    #[test]
    fn an_answer_before_the_two_second_floor_is_refused_and_stays_pending() {
        let mut request = entry();
        assert!(mark_shown(&mut request, watcher(), 1_000));
        assert!(mark_shown(&mut request, watcher(), 2_000));
        assert_eq!(request.shown_at_ms, Some(BoottimeMillis(1_000)));
        assert_eq!(
            approve(&mut request, 2_999, b"remove"),
            Err(ConfirmError::TooFast)
        );
        assert_eq!(request.state, ConfirmationState::Pending);
        assert_eq!(approve(&mut request, 3_000, b"remove"), Ok(()));
        assert_eq!(request.state, ConfirmationState::Approved);
    }

    #[test]
    fn a_wrong_last_word_is_refused_and_stays_pending() {
        let mut request = entry();
        mark_shown(&mut request, watcher(), 1_000);
        assert_eq!(
            approve(&mut request, 3_000, b"REMOVE"),
            Err(ConfirmError::WrongWord)
        );
        assert_eq!(request.state, ConfirmationState::Pending);
        assert_eq!(
            approve(&mut request, 3_000, b"remove "),
            Err(ConfirmError::WrongWord)
        );
        assert_eq!(approve(&mut request, 3_000, b"remove"), Ok(()));
    }

    #[test]
    fn an_action_without_a_last_word_cannot_be_approved() {
        let mut request = entry();
        request.action.clear();
        mark_shown(&mut request, watcher(), 1_000);
        assert_eq!(
            approve(&mut request, 3_000, b""),
            Err(ConfirmError::MissingWord)
        );
        assert_eq!(request.state, ConfirmationState::Pending);
    }

    #[test]
    fn a_missing_prompt_time_and_a_prompt_after_expiry_cannot_be_answered() {
        let mut missing = entry();
        assert_eq!(
            approve(&mut missing, 3_000, b"remove"),
            Err(ConfirmError::TooFast)
        );
        assert_eq!(missing.state, ConfirmationState::Pending);
        let mut expired = entry();
        let deadline = expired.deadline.0;
        assert!(!mark_shown(&mut expired, watcher(), deadline));
        assert_eq!(expired.state, ConfirmationState::Expired);
    }

    #[test]
    fn an_approval_after_the_entry_ttl_is_refused() {
        let mut request = entry();
        mark_shown(&mut request, watcher(), 1_000);
        request.deadline = BoottimeMillis(3_000);
        assert_eq!(
            approve(&mut request, 3_000, b"remove"),
            Err(ConfirmError::Expired)
        );
        assert_eq!(request.state, ConfirmationState::Expired);
    }

    #[test]
    fn an_approval_is_consumed_once_and_cannot_satisfy_a_different_argv_or_user() {
        let mut request = entry();
        mark_shown(&mut request, watcher(), 1_000);
        approve(&mut request, 3_000, b"remove").unwrap();
        let mut other_user = matching_caller();
        other_user.uid = 2000;
        let (different_user, matched_user) = take_approval(
            Some(request.clone()),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            4_000,
            &other_user,
        );
        assert!(matched_user.is_none());
        let (different_argv, matched_argv) = take_approval(
            different_user,
            b"/usr/bin/pkg",
            &[b"remove", b"demo", b"--force"],
            1,
            "xudo.pkg.remove",
            4_000,
            &matching_caller(),
        );
        assert!(matched_argv.is_none());
        let (remaining, consumed) = take_approval(
            different_argv,
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            4_000,
            &matching_caller(),
        );
        assert!(remaining.is_none());
        assert!(consumed.is_some());
        let (after_second, consumed_again) = take_approval(
            remaining,
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            4_000,
            &matching_caller(),
        );
        assert!(after_second.is_none());
        assert!(consumed_again.is_none());
    }

    #[test]
    fn an_approval_does_not_survive_a_policy_reload() {
        let mut request = entry();
        mark_shown(&mut request, watcher(), 1_000);
        approve(&mut request, 3_000, b"remove").unwrap();
        let (remaining, consumed) = take_approval(
            Some(request),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            2,
            "xudo.pkg.remove",
            4_000,
            &matching_caller(),
        );
        assert!(remaining.is_some());
        assert!(consumed.is_none());
    }

    #[test]
    fn an_approval_for_a_different_governing_action_stays_unconsumed() {
        let mut request = entry();
        mark_shown(&mut request, watcher(), 1_000);
        approve(&mut request, 3_000, b"remove").unwrap();
        let (remaining, consumed) = take_approval(
            Some(request),
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.install",
            4_000,
            &matching_caller(),
        );
        assert!(remaining.is_some());
        assert!(consumed.is_none());
    }

    #[test]
    fn an_approval_cannot_match_shorter_reordered_or_empty_argv_or_survive_any_late_time() {
        let approved = || {
            let mut request = entry();
            mark_shown(&mut request, watcher(), 1_000);
            approve(&mut request, 3_000, b"remove").unwrap();
            request
        };
        let attacks: [&[&[u8]]; 4] = [
            &[&b"remove"[..]],
            &[&b"demo"[..], &b"remove"[..]],
            &[&b""[..]],
            &[],
        ];
        for argv in attacks {
            let (_, consumed) = take_approval(
                Some(approved()),
                b"/usr/bin/pkg",
                argv,
                1,
                "xudo.pkg.remove",
                4_000,
                &matching_caller(),
            );
            assert!(consumed.is_none(), "accepted argv {argv:?}");
        }
        for now in [10_000, 10_001, u64::MAX] {
            let (_, consumed) = take_approval(
                Some(approved()),
                b"/usr/bin/pkg",
                &[b"remove", b"demo"],
                1,
                "xudo.pkg.remove",
                now,
                &matching_caller(),
            );
            assert!(consumed.is_none(), "consumed at {now}");
        }
    }

    #[test]
    fn a_different_program_or_expired_approval_stays_unconsumed() {
        let mut request = entry();
        mark_shown(&mut request, watcher(), 1_000);
        approve(&mut request, 3_000, b"remove").unwrap();
        let (same_entry, wrong_program) = take_approval(
            Some(request),
            b"/usr/bin/other",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            4_000,
            &matching_caller(),
        );
        assert!(wrong_program.is_none());
        let (expired_entry, expired_match) = take_approval(
            same_entry,
            b"/usr/bin/pkg",
            &[b"remove", b"demo"],
            1,
            "xudo.pkg.remove",
            10_000,
            &matching_caller(),
        );
        assert!(expired_match.is_none());
        assert!(expired_entry.is_some());
        let (empty, no_match) = take_approval(
            None,
            b"/usr/bin/pkg",
            &[b"remove"],
            1,
            "xudo.pkg.remove",
            4_000,
            &matching_caller(),
        );
        assert!(empty.is_none());
        assert!(no_match.is_none());
    }

    #[test]
    fn a_duplicate_request_does_not_prompt_twice() {
        let mut request = entry();
        request.fingerprint = fingerprint(1000, b"/usr/bin/pkg", &[b"remove", b"demo"]);
        assert!(is_duplicate(&request, &request.fingerprint.clone(), 1_000));
        assert!(!is_duplicate(&request, &"f".repeat(64), 1_000));
        request.needs_watch = false;
        assert!(!is_duplicate(&request, &request.fingerprint.clone(), 1_000));
        request.needs_watch = true;
        request.state = ConfirmationState::Approved;
        assert!(!is_duplicate(&request, &request.fingerprint.clone(), 1_000));
        request.state = ConfirmationState::Pending;
        assert!(!is_duplicate(
            &request,
            &request.fingerprint.clone(),
            request.deadline.0
        ));
    }

    #[test]
    fn request_fingerprint_frames_each_boundary_and_identity_field() {
        assert_ne!(
            fingerprint(1000, b"/bin", &[b"ab", b"c"]),
            fingerprint(1000, b"/bin", &[b"a", b"bc"])
        );
        assert_ne!(
            fingerprint(1000, b"/bin/ab", &[]),
            fingerprint(1000, b"/bin/a", &[b"b"])
        );
        assert_ne!(
            fingerprint(1000, b"/bin", &[]),
            fingerprint(1001, b"/bin", &[])
        );
    }

    #[test]
    fn a_second_watcher_cannot_answer_immediately_after_their_first_view() {
        let mut request = entry();
        assert!(mark_shown(&mut request, watcher(), 1_000));
        let mut second = watcher();
        second.pid += 1;
        second.starttime += 1;
        assert!(mark_shown(&mut request, second, 2_999));
        assert_eq!(
            answer(
                &mut request,
                second,
                2_999,
                Settings::default(),
                Answer::Approve(b"remove")
            ),
            Err(ConfirmError::TooFast)
        );
    }

    #[test]
    fn a_watcher_who_did_not_see_the_current_prompt_cannot_answer() {
        let mut request = entry();
        assert!(mark_shown(&mut request, watcher(), 1_000));
        let mut second = watcher();
        second.pid += 1;
        second.starttime += 1;
        assert_eq!(
            answer(
                &mut request,
                second,
                3_000,
                Settings::default(),
                Answer::Approve(b"remove")
            ),
            Err(ConfirmError::IneligibleWatcher)
        );
    }

    #[test]
    fn an_ineligible_watcher_cannot_learn_that_an_entry_expired() {
        let mut request = entry();
        let mut attacker = watcher();
        attacker.uid += 1;
        let deadline = request.deadline.0;
        assert_eq!(
            answer(
                &mut request,
                attacker,
                deadline,
                Settings::default(),
                Answer::Deny
            ),
            Err(ConfirmError::IneligibleWatcher)
        );
        assert_eq!(request.state, ConfirmationState::Pending);
    }

    #[test]
    fn backoff_doubles_and_caps_at_fifteen_minutes() {
        assert_eq!(backoff_ms(0), 0);
        assert_eq!(backoff_ms(1), 30_000);
        assert_eq!(backoff_ms(2), 60_000);
        assert_eq!(backoff_ms(3), 120_000);
        assert_eq!(backoff_ms(6), BACKOFF_MAX_MS);
        assert_eq!(backoff_ms(7), BACKOFF_MAX_MS);
        assert_eq!(backoff_ms(u32::MAX), BACKOFF_MAX_MS);
    }

    #[test]
    fn denial_is_terminal_and_expiry_is_inclusive() {
        let mut request = entry();
        mark_shown(&mut request, watcher(), 1_000);
        assert_eq!(
            answer(
                &mut request,
                watcher(),
                3_000,
                Settings::default(),
                Answer::Deny
            ),
            Ok(())
        );
        assert_eq!(request.state, ConfirmationState::Denied);
        assert!(!request.confirmed);
        let mut expired = entry();
        let deadline = expired.deadline.0;
        assert_eq!(
            answer(
                &mut expired,
                watcher(),
                deadline,
                Settings::default(),
                Answer::Deny
            ),
            Err(ConfirmError::Expired)
        );
    }

    #[test]
    fn expiry_only_transitions_overdue_pending_or_approved_entries() {
        let mut pending = entry();
        let deadline = pending.deadline.0;
        assert!(!expire(&mut pending, deadline - 1));
        assert!(expire(&mut pending, deadline));
        assert_eq!(pending.state, ConfirmationState::Expired);

        let mut approved = entry();
        approved.state = ConfirmationState::Approved;
        approved.confirmed = true;
        approved.confirmed_by = Some(watcher().pin());
        let deadline = approved.deadline.0;
        assert!(expire(&mut approved, deadline));
        assert!(!approved.confirmed);
        assert_eq!(approved.confirmed_by, None);

        let mut denied = entry();
        denied.state = ConfirmationState::Denied;
        assert!(!expire(&mut denied, u64::MAX));
        assert_eq!(denied.state, ConfirmationState::Denied);
    }
}
