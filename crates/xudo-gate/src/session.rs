//! The committed session-record format shared with the cgroup attestor.
//!
//! Only committed names are read: `pending-*` records describe an adoption in
//! progress and are never authority. Keeping this parser pure lets xudo-sys
//! refuse malformed or stale records without trusting a path name.

use serde::Deserialize;
use xudo_policy::{HarnessRegistry, HarnessWay, passwd_uid};
use xudo_sys::{RecordIdentity, ScopeKind};

/// The longest a `session`-way record may live, in milliseconds: twelve hours.
///
/// A person starts a session, so it expires. Only a `service` record, written
/// by the unit's own start and removed by its stop, may name no deadline.
pub const SESSION_MAX_LIFETIME_MS: u64 = 12 * 60 * 60 * 1000;

/// The deadline of a service record: the unit's stop removes the record, so
/// the clock never does. Accepted for `way = service` and for nothing else.
pub const NO_DEADLINE: u64 = u64::MAX;

/// Parsed contents of a committed record: `/run/xudo/sessions/agent-<n>` for
/// a session scope, `/run/xudo/sessions/svc-<label>` for an enrolled service
/// (record version 2).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    /// The non-root uid that owns the peer.
    pub uid: u32,
    /// The root-registered harness label.
    pub label: String,
    /// How root registered the harness.
    pub way: HarnessWay,
    /// Hash of the exact registry entry this record names.
    pub registry_entry_hash: String,
    /// Kernel boot id that scopes the cgroup id.
    pub boot_id: String,
    /// Creation time in `CLOCK_BOOTTIME` milliseconds.
    pub created_at_boottime_ms: u64,
    /// Absolute `CLOCK_BOOTTIME` deadline in milliseconds.
    pub deadline: u64,
    /// Adopted process id.
    pub pid: u32,
    /// Adopted process start time in clock ticks.
    pub starttime: u64,
    /// The post-checked scope cgroup id. Required for every committed record.
    pub cgroup_id: u64,
}

/// Parses and validates a committed record against its filename and live facts.
pub fn parse_session_record(
    bytes: &[u8],
    name: &str,
    uid: u32,
    boot_id: &str,
    now_boottime_ms: u64,
) -> Option<SessionRecord> {
    if uid == 0 {
        return None;
    }
    let form = committed_name(name)?;
    let record: SessionRecord = serde_json::from_slice(bytes).ok()?;
    // The label in the unit name, the record and the registry entry must be
    // the same one, and only a service has a unit of its own.
    if let NameForm::Service(label) = form
        && (record.label != label || record.way != HarnessWay::Service)
    {
        return None;
    }
    if !deadline_is_allowed(&record, &form) {
        return None;
    }
    if record.uid != uid
        || record.boot_id != boot_id
        || record.created_at_boottime_ms > now_boottime_ms
        || record.deadline <= now_boottime_ms
        || record.deadline <= record.created_at_boottime_ms
        || !xudo_policy::valid_harness_label(&record.label)
        || !valid_hash(&record.registry_entry_hash)
        || record.cgroup_id == 0
        || record.pid == 0
        || record.starttime == 0
    {
        return None;
    }
    Some(record)
}

/// A scope's record expires within twelve hours of its creation, whatever
/// its `way` says: a scope has no stop hook to remove its record. The absent
/// deadline, or a longer one, belongs to a service unit's record alone, whose
/// `ExecStopPost` voids it. The name decides, never a field inside the record.
fn deadline_is_allowed(record: &SessionRecord, form: &NameForm<'_>) -> bool {
    match form {
        NameForm::Service(_) => true,
        NameForm::Scope => {
            record.deadline != NO_DEADLINE
                && record
                    .deadline
                    .saturating_sub(record.created_at_boottime_ms)
                    <= SESSION_MAX_LIFETIME_MS
        }
    }
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Adapter used by xudo-sys without making the privileged syscall crate depend
/// on this higher-level pure parser.
///
/// `boot_id` and `now_boottime_ms` must be the caller's own reads of the boot
/// id and `CLOCK_BOOTTIME`; `xudo_sys::scope_status` trusts the two booleans.
pub fn record_identity(
    bytes: &[u8],
    name: &str,
    uid: u32,
    boot_id: &str,
    now_boottime_ms: u64,
) -> Option<RecordIdentity> {
    let record = parse_session_record(bytes, name, uid, boot_id, now_boottime_ms)?;
    Some(RecordIdentity {
        kind: ScopeKind::Agent,
        uid: record.uid,
        current_boot: record.boot_id == boot_id,
        live: record.deadline > now_boottime_ms,
        process: (record.pid, record.starttime),
        cgroup_id: record.cgroup_id,
    })
}

/// Parses a live record and requires its exact current registry entry and uid.
pub fn record_identity_registered(
    bytes: &[u8],
    name: &str,
    uid: u32,
    boot_id: &str,
    now_boottime_ms: u64,
    registry: &HarnessRegistry,
    passwd: &str,
) -> Option<RecordIdentity> {
    let record = parse_session_record(bytes, name, uid, boot_id, now_boottime_ms)?;
    let resolve = |account: &str| passwd_uid(passwd, account);
    if !registry.attests(
        &record.label,
        record.way,
        &record.registry_entry_hash,
        uid,
        &resolve,
    ) {
        return None;
    }
    record_identity(bytes, name, uid, boot_id, now_boottime_ms)
}

/// The registry label a committed record still attests, if it attests one.
///
/// The gate copies this into the caller facts it gives the policy engine. A
/// record that does not attest returns nothing, and the caller stays
/// unattested rather than being named `scope-N`.
pub fn attested_harness_label(
    bytes: &[u8],
    uid: u32,
    registry: &HarnessRegistry,
    passwd: &str,
) -> Option<String> {
    let record: SessionRecord = serde_json::from_slice(bytes).ok()?;
    if record.uid != uid || !xudo_policy::valid_harness_label(&record.label) {
        return None;
    }
    let resolve = |account: &str| passwd_uid(passwd, account);
    if !registry.attests(
        &record.label,
        record.way,
        &record.registry_entry_hash,
        uid,
        &resolve,
    ) {
        return None;
    }
    Some(record.label)
}

/// The two committed names that carry authority.
enum NameForm<'a> {
    /// `agent-<32 hex>`: a session scope.
    Scope,
    /// `svc-<label>`: the unit `xudo-agent@<label>.service`.
    Service(&'a str),
}

fn committed_name(name: &str) -> Option<NameForm<'_>> {
    if let Some(label) = name.strip_prefix(xudo_sys::SERVICE_RECORD_PREFIX) {
        return xudo_policy::valid_harness_label(label).then_some(NameForm::Service(label));
    }
    let suffix = name.strip_prefix("agent-")?;
    (suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(NameForm::Scope)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const NAME: &str = "agent-0123456789abcdef0123456789abcdef";
    const RECORD: &str = r#"{"uid":1000,"label":"codex","way":"service","registry_entry_hash":"0000000000000000000000000000000000000000000000000000000000000000","boot_id":"boot-a","created_at_boottime_ms":20,"deadline":200,"pid":42,"starttime":71,"cgroup_id":9001}"#;
    const SERVICE: &str = "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 4\n";

    fn registered_record(max_sessions: u32) -> (String, HarnessRegistry) {
        let text = SERVICE.replace(
            "max-sessions = 4",
            &format!("max-sessions = {max_sessions}"),
        );
        let registry = HarnessRegistry::from_files([("codex.toml", text)]).unwrap();
        let hash = registry.get("codex").unwrap().hash_hex();
        (RECORD.replace(&"0".repeat(64), &hash), registry)
    }

    #[test]
    fn parses_a_committed_record_bound_to_its_live_scope() {
        let record = parse_session_record(RECORD.as_bytes(), NAME, 1000, "boot-a", 199);
        assert_eq!(record.as_ref().map(|value| value.cgroup_id), Some(9001));
        assert_eq!(
            record.as_ref().map(|value| value.way),
            Some(HarnessWay::Service)
        );
        assert_eq!(
            record.as_ref().map(|value| value.label.as_str()),
            Some("codex")
        );
    }

    #[test]
    fn attested_harness_label_is_the_registry_label_only_when_the_record_attests() {
        const PASSWD: &str = "agent:x:1000:1000:agent:/home/agent:/bin/sh\n";
        let (bytes, registry) = registered_record(4);
        assert_eq!(
            attested_harness_label(bytes.as_bytes(), 1000, &registry, PASSWD).as_deref(),
            Some("codex")
        );
        assert_eq!(attested_harness_label(b"{}", 1000, &registry, PASSWD), None);
        assert_eq!(
            attested_harness_label(bytes.as_bytes(), 1001, &registry, PASSWD),
            None
        );
        let uppercase = bytes.replace("\"label\":\"codex\"", "\"label\":\"Codex\"");
        assert_eq!(
            attested_harness_label(uppercase.as_bytes(), 1000, &registry, PASSWD),
            None
        );
        assert_eq!(
            attested_harness_label(RECORD.as_bytes(), 1000, &registry, PASSWD),
            None
        );
    }

    #[test]
    fn a_session_record_with_an_unknown_or_missing_key_is_refused() {
        let unknown = RECORD.replace("\"cgroup_id\":9001", "\"cgroup_id\":9001,\"extra\":1");
        let missing = RECORD.replace(",\"cgroup_id\":9001", "");
        assert!(parse_session_record(unknown.as_bytes(), NAME, 1000, "boot-a", 0).is_none());
        assert!(parse_session_record(missing.as_bytes(), NAME, 1000, "boot-a", 0).is_none());
    }

    #[test]
    fn a_committed_record_without_a_cgroup_id_is_refused() {
        let missing = RECORD.replace(",\"cgroup_id\":9001", "");
        assert!(parse_session_record(missing.as_bytes(), NAME, 1000, "boot-a", 0).is_none());
    }

    #[test]
    fn a_pending_or_watch_name_never_parses_as_authority() {
        for name in [
            "pending-agent-0123456789abcdef0123456789abcdef",
            "watch-0123456789abcdef0123456789abcdef",
        ] {
            assert!(parse_session_record(RECORD.as_bytes(), name, 1000, "boot-a", 0).is_none());
        }
    }

    #[test]
    fn a_record_never_accepts_a_missing_or_unknown_field() {
        let removed = [
            "\"uid\":1000,",
            "\"label\":\"codex\",",
            "\"way\":\"service\",",
            "\"registry_entry_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",",
            "\"boot_id\":\"boot-a\",",
            "\"created_at_boottime_ms\":20,",
            "\"deadline\":200,",
            "\"pid\":42,",
            "\"starttime\":71,",
            ",\"cgroup_id\":9001",
        ];
        for field in removed {
            let candidate = RECORD.replace(field, "");
            assert!(parse_session_record(candidate.as_bytes(), NAME, 1000, "boot-a", 0).is_none());
        }
        let extra = RECORD.replace("\"cgroup_id\":9001", "\"cgroup_id\":9001,\"future\":true");
        assert!(parse_session_record(extra.as_bytes(), NAME, 1000, "boot-a", 0).is_none());
    }

    #[test]
    fn an_expired_or_foreign_record_is_refused() {
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 1000, "boot-a", 200).is_none());
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 1001, "boot-a", 0).is_none());
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 1000, "boot-b", 0).is_none());
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 0, "boot-a", 0).is_none());
    }

    #[test]
    fn record_identity_preserves_the_live_scope_binding_for_the_sys_seam() {
        let agent = record_identity(RECORD.as_bytes(), NAME, 1000, "boot-a", 199).unwrap();
        assert_eq!(agent.kind, ScopeKind::Agent);
        assert!(agent.current_boot && agent.live);
        assert_eq!(agent.process, (42, 71));
        assert_eq!(agent.cgroup_id, 9001);
        assert!(record_identity(RECORD.as_bytes(), NAME, 1000, "boot-a", 200).is_none());
        assert!(record_identity(RECORD.as_bytes(), "not-a-record", 1000, "boot-a", 1).is_none());
        assert!(record_identity(RECORD.as_bytes(), "unseparated", 1000, "boot-a", 1).is_none());
    }

    #[test]
    fn a_record_whose_label_left_the_registry_is_not_a_harness() {
        let (record, _registered) = registered_record(4);
        assert!(
            record_identity_registered(
                record.as_bytes(),
                NAME,
                1000,
                "boot-a",
                199,
                &HarnessRegistry::empty(),
                "agent:x:1000:1000:agent:/home/agent:/bin/sh\n"
            )
            .is_none()
        );
    }

    #[test]
    fn a_changed_registry_entry_voids_its_records() {
        let (record, _) = registered_record(4);
        let changed = HarnessRegistry::from_files([(
            "codex.toml",
            SERVICE.replace("max-sessions = 4", "max-sessions = 5"),
        )])
        .unwrap();
        assert!(
            record_identity_registered(
                record.as_bytes(),
                NAME,
                1000,
                "boot-a",
                199,
                &changed,
                "agent:x:1000:1000:agent:/home/agent:/bin/sh\n"
            )
            .is_none()
        );
    }

    #[test]
    fn an_unregistered_same_uid_process_is_not_a_harness() {
        let (record, registered) = registered_record(4);
        assert!(
            record_identity_registered(
                record.as_bytes(),
                NAME,
                1000,
                "boot-a",
                199,
                &registered,
                "other:x:1000:1000:other:/home/other:/bin/sh\n"
            )
            .is_none()
        );
    }

    #[test]
    fn malformed_label_hash_or_impossible_boottime_order_is_refused() {
        let bad_label = RECORD.replace("codex", "Bad label");
        let bad_hash = RECORD.replace(&"0".repeat(64), "XYZ");
        let future_created = RECORD.replace(
            "\"created_at_boottime_ms\":20",
            "\"created_at_boottime_ms\":201",
        );
        let backward_deadline = RECORD.replace(
            "\"created_at_boottime_ms\":20",
            "\"created_at_boottime_ms\":200",
        );
        for label in ["1codex", "-codex"] {
            let candidate = RECORD.replace("codex", label);
            assert!(
                parse_session_record(candidate.as_bytes(), NAME, 1000, "boot-a", 199).is_none(),
                "{label}"
            );
        }
        for candidate in [bad_label, bad_hash, future_created, backward_deadline] {
            assert!(
                parse_session_record(candidate.as_bytes(), NAME, 1000, "boot-a", 199).is_none()
            );
        }
    }

    const SERVICE_NAME: &str = "svc-codex";

    fn with_way_and_deadline(way: &str, deadline: u64) -> String {
        RECORD
            .replace("\"way\":\"service\"", &format!("\"way\":\"{way}\""))
            .replace("\"deadline\":200", &format!("\"deadline\":{deadline}"))
    }

    #[test]
    fn a_service_record_is_named_for_its_unit_and_may_name_no_deadline() {
        let forever = with_way_and_deadline("service", NO_DEADLINE);
        let record =
            parse_session_record(forever.as_bytes(), SERVICE_NAME, 1000, "boot-a", 199).unwrap();
        assert_eq!(record.deadline, NO_DEADLINE);
        assert_eq!(record.label, "codex");
        let identity =
            record_identity(forever.as_bytes(), SERVICE_NAME, 1000, "boot-a", 199).unwrap();
        assert_eq!(identity.kind, ScopeKind::Agent);
        assert!(identity.live && identity.current_boot);
    }

    #[test]
    fn a_session_record_with_no_deadline_is_refused() {
        let forever = with_way_and_deadline("session", NO_DEADLINE);
        assert!(parse_session_record(forever.as_bytes(), NAME, 1000, "boot-a", 199).is_none());
        // Not even by its other way of spelling "very far away".
        let far = with_way_and_deadline("session", NO_DEADLINE - 1);
        assert!(parse_session_record(far.as_bytes(), NAME, 1000, "boot-a", 199).is_none());
    }

    #[test]
    fn a_scope_name_with_the_service_way_and_no_deadline_is_refused() {
        // The name decides, not the record's own `way`: a scope has no stop
        // hook to remove a record that never expires.
        for deadline in [NO_DEADLINE, 20 + SESSION_MAX_LIFETIME_MS + 1] {
            let record = with_way_and_deadline("service", deadline);
            assert!(
                parse_session_record(record.as_bytes(), NAME, 1000, "boot-a", 199).is_none(),
                "{deadline}"
            );
        }
        let capped = with_way_and_deadline("service", 20 + SESSION_MAX_LIFETIME_MS);
        assert!(parse_session_record(capped.as_bytes(), NAME, 1000, "boot-a", 199).is_some());
    }

    #[test]
    fn a_session_record_must_expire_within_twelve_hours() {
        let at_limit = with_way_and_deadline("session", 20 + SESSION_MAX_LIFETIME_MS);
        let past_limit = with_way_and_deadline("session", 20 + SESSION_MAX_LIFETIME_MS + 1);
        assert!(parse_session_record(at_limit.as_bytes(), NAME, 1000, "boot-a", 199).is_some());
        assert!(parse_session_record(past_limit.as_bytes(), NAME, 1000, "boot-a", 199).is_none());
    }

    #[test]
    fn a_record_for_one_label_in_another_labels_unit_is_refused() {
        assert!(
            parse_session_record(RECORD.as_bytes(), "svc-claude", 1000, "boot-a", 199).is_none()
        );
        assert!(
            parse_session_record(RECORD.as_bytes(), SERVICE_NAME, 1000, "boot-a", 199).is_some()
        );
    }

    #[test]
    fn a_service_unit_name_never_carries_a_session_record() {
        let session = with_way_and_deadline("session", 200);
        assert!(
            parse_session_record(session.as_bytes(), SERVICE_NAME, 1000, "boot-a", 199).is_none()
        );
    }

    #[test]
    fn a_service_record_name_needs_a_registry_label() {
        for name in [
            "svc-",
            "svc-Codex",
            "svc-1codex",
            "svc-co dex",
            "svc-codex/x",
            "svc-",
        ] {
            assert!(
                parse_session_record(RECORD.as_bytes(), name, 1000, "boot-a", 199).is_none(),
                "{name}"
            );
        }
        let long = format!("svc-a{}", "b".repeat(32));
        assert!(parse_session_record(RECORD.as_bytes(), &long, 1000, "boot-a", 199).is_none());
    }

    mod properties {
        use proptest::prelude::*;

        use super::*;

        fn record_with(way: &str, created: u64, deadline: u64) -> String {
            RECORD
                .replace("\"way\":\"service\"", &format!("\"way\":\"{way}\""))
                .replace(
                    "\"created_at_boottime_ms\":20",
                    &format!("\"created_at_boottime_ms\":{created}"),
                )
                .replace("\"deadline\":200", &format!("\"deadline\":{deadline}"))
        }

        proptest! {
            #[test]
            fn only_a_service_record_outlives_twelve_hours_or_names_no_deadline(
                created in 0u64..1_000_000,
                deadline in prop_oneof![any::<u64>(), Just(NO_DEADLINE), 0u64..100_000_000],
                session in any::<bool>(),
            ) {
                let way = if session { "session" } else { "service" };
                let bytes = record_with(way, created, deadline);
                let name = if session { NAME } else { "svc-codex" };
                let parsed = parse_session_record(bytes.as_bytes(), name, 1000, "boot-a", created);
                if let Some(record) = parsed {
                    prop_assert!(record.deadline > created);
                    if session {
                        prop_assert!(record.deadline != NO_DEADLINE);
                        prop_assert!(record.deadline.saturating_sub(created) <= SESSION_MAX_LIFETIME_MS);
                    }
                }
            }

            #[test]
            fn a_service_name_never_accepts_a_record_of_another_label(label in "[a-z][a-z0-9-]{0,31}") {
                let name = format!("svc-{label}");
                let parsed = parse_session_record(RECORD.as_bytes(), &name, 1000, "boot-a", 199);
                prop_assert_eq!(parsed.is_some(), label == "codex");
            }
        }
    }
}
