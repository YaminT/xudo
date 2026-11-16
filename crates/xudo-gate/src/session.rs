//! The committed session-record format shared with the cgroup attestor.
//!
//! Only committed names are read: `pending-*` records describe an adoption in
//! progress and are never authority. Keeping this parser pure lets xudo-sys
//! refuse malformed or stale records without trusting a path name.

use serde::Deserialize;
use xudo_sys::{RecordIdentity, ScopeKind};

/// Which root-created scope a committed record describes.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    /// An agent session.
    Agent,
    /// A human approval watcher.
    Watch,
}

impl SessionKind {
    /// The exact scope-name prefix assigned by root.
    pub const fn name_prefix(self) -> &'static str {
        match self {
            Self::Agent => "agent-",
            Self::Watch => "watch-",
        }
    }
}

/// Parsed contents of `/run/xudo/sessions/<kind>-<n>`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionRecord {
    /// The root-assigned session kind.
    pub kind: SessionKind,
    /// The non-root uid that owns the peer.
    pub uid: u32,
    /// An audit hint; it carries no authority.
    pub label: String,
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
    if record_name(record.kind, name).is_none()
        || record.uid != uid
        || record.boot_id != boot_id
        || record.created_at_boottime_ms > now_boottime_ms
        || record.deadline <= now_boottime_ms
        || record.deadline <= record.created_at_boottime_ms
        || !valid_label(&record.label)
        || record.cgroup_id == 0
        || record.pid == 0
        || record.starttime == 0
    {
        return None;
    }
    Some(record)
}

fn valid_label(label: &str) -> bool {
    let mut bytes = label.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && label.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Adapter used by xudo-sys without making the privileged syscall crate depend
/// on this higher-level pure parser.
pub fn record_identity(
    bytes: &[u8],
    name: &str,
    uid: u32,
    boot_id: &str,
    now_boottime_ms: u64,
) -> Option<RecordIdentity> {
    let record = parse_session_record(bytes, name, uid, boot_id, now_boottime_ms)?;
    Some(RecordIdentity {
        kind: match record.kind {
            SessionKind::Agent => ScopeKind::Agent,
            SessionKind::Watch => ScopeKind::Watch,
        },
        uid: record.uid,
        current_boot: record.boot_id == boot_id,
        live: record.deadline > now_boottime_ms,
        process: (record.pid, record.starttime),
        cgroup_id: record.cgroup_id,
    })
}

fn valid_committed_name(name: &str) -> bool {
    if name.starts_with("pending-") {
        return false;
    }
    let Some((prefix, suffix)) = name.split_once('-') else {
        return false;
    };
    (prefix == "agent" || prefix == "watch")
        && suffix.len() == 32
        && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !name.starts_with("pending-")
}

fn record_name(kind: SessionKind, name: &str) -> Option<String> {
    let prefix = kind.name_prefix();
    let suffix = name.strip_prefix(prefix)?;
    (suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const NAME: &str = "agent-0123456789abcdef0123456789abcdef";
    const RECORD: &str = r#"{"kind":"agent","uid":1000,"label":"codex","boot_id":"boot-a","created_at_boottime_ms":20,"deadline":200,"pid":42,"starttime":71,"cgroup_id":9001}"#;

    #[test]
    fn parses_a_committed_record_bound_to_its_live_scope() {
        let record = parse_session_record(RECORD.as_bytes(), NAME, 1000, "boot-a", 199);
        assert_eq!(record.as_ref().map(|value| value.cgroup_id), Some(9001));
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
    fn a_pending_name_never_parses_as_authority() {
        let pending = "pending-agent-0123456789abcdef0123456789abcdef";
        assert!(parse_session_record(RECORD.as_bytes(), pending, 1000, "boot-a", 0).is_none());
    }

    #[test]
    fn a_record_never_accepts_a_missing_or_unknown_field() {
        let removed = [
            "\"kind\":\"agent\",",
            "\"uid\":1000,",
            "\"label\":\"codex\",",
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
    fn record_kind_must_match_the_committed_scope_name() {
        let watch = RECORD.replace("\"agent\"", "\"watch\"");
        assert!(parse_session_record(watch.as_bytes(), NAME, 1000, "boot-a", 0).is_none());
    }

    #[test]
    fn an_expired_or_foreign_record_is_refused() {
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 1000, "boot-a", 200).is_none());
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 1001, "boot-a", 0).is_none());
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 1000, "boot-b", 0).is_none());
        assert!(parse_session_record(RECORD.as_bytes(), NAME, 0, "boot-a", 0).is_none());
    }

    #[test]
    fn record_identity_preserves_kind_and_scope_binding_for_the_sys_seam() {
        let agent = record_identity(RECORD.as_bytes(), NAME, 1000, "boot-a", 199).unwrap();
        assert_eq!(agent.kind, ScopeKind::Agent);
        assert!(agent.current_boot && agent.live);
        assert_eq!(agent.process, (42, 71));
        assert_eq!(agent.cgroup_id, 9001);
        let watch = RECORD
            .replace("\"agent\"", "\"watch\"")
            .replace("agent-", "watch-");
        let watch_name = NAME.replace("agent-", "watch-");
        let identity = record_identity(watch.as_bytes(), &watch_name, 1000, "boot-a", 199).unwrap();
        assert_eq!(identity.kind, ScopeKind::Watch);
        assert!(record_identity(RECORD.as_bytes(), NAME, 1000, "boot-a", 200).is_none());
        assert!(record_identity(RECORD.as_bytes(), "not-a-record", 1000, "boot-a", 1).is_none());
        assert!(record_identity(RECORD.as_bytes(), "unseparated", 1000, "boot-a", 1).is_none());
    }

    #[test]
    fn malformed_label_or_impossible_boottime_order_is_refused() {
        let bad_label = RECORD.replace("codex", "Bad label");
        let bad_label_character = RECORD.replace("codex", "coDex");
        let long_label = RECORD.replace("codex", "abcdefghijklmnopqrstuvwxyz1234567");
        let future_created = RECORD.replace(
            "\"created_at_boottime_ms\":20",
            "\"created_at_boottime_ms\":201",
        );
        let backward_deadline = RECORD.replace(
            "\"created_at_boottime_ms\":20",
            "\"created_at_boottime_ms\":200",
        );
        assert!(parse_session_record(bad_label.as_bytes(), NAME, 1000, "boot-a", 199).is_none());
        assert!(
            parse_session_record(bad_label_character.as_bytes(), NAME, 1000, "boot-a", 199)
                .is_none()
        );
        assert!(parse_session_record(long_label.as_bytes(), NAME, 1000, "boot-a", 199).is_none());
        assert!(
            parse_session_record(future_created.as_bytes(), NAME, 1000, "boot-a", 199).is_none()
        );
        assert!(
            parse_session_record(backward_deadline.as_bytes(), NAME, 1000, "boot-a", 199).is_none()
        );
    }
}
