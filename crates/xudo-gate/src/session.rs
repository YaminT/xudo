//! The committed session-record format shared with the cgroup attestor.
//!
//! Only committed names are read: `pending-*` records describe an adoption in
//! progress and are never authority. Keeping this parser pure lets xudo-sys
//! refuse malformed or stale records without trusting a path name.

use serde::Deserialize;
use xudo_policy::{HarnessRegistry, HarnessWay, passwd_uid};
use xudo_sys::{RecordIdentity, ScopeKind};

/// Parsed contents of `/run/xudo/sessions/agent-<n>` (record version 2).
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
    if uid == 0 || !valid_committed_name(name) {
        return None;
    }
    let record: SessionRecord = serde_json::from_slice(bytes).ok()?;
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

fn valid_committed_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("agent-") else {
        return false;
    };
    suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
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
}
