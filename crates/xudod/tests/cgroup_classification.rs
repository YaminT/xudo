//! Adversarial broker classification tests through the E1 kernel-call seams.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use proptest::prelude::*;
use rustix::io::Errno;
use xudo_policy::{Classification, HarnessRegistry};
use xudo_sys::{
    CgroupCalls, FakePeer, FakeSyscalls, PeerCred, PidfdInfo, ProcessIds, ScopeFacts, SysError,
};
use xudod::identify::{CgroupAttestation, identify_classified};
use xudod::policy::classify_with_registry;

const PID: u32 = 4242;
const UID: u32 = 1000;
const ID: u64 = 90;
const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";
const NAME: &str = "agent-0123456789abcdef0123456789abcdef";
const WATCH_NAME: &str = "watch-0123456789abcdef0123456789abcdef";

struct FakeCgroup {
    path: Vec<u8>,
    inode: u64,
    facts: Option<ScopeFacts>,
    names: Vec<String>,
    fail_peer_id: bool,
    fail_scope: bool,
}

impl FakeCgroup {
    fn outside() -> Self {
        Self {
            path: b"0::/user.slice/session-1.scope\n".to_vec(),
            inode: ID,
            facts: None,
            names: vec![],
            fail_peer_id: false,
            fail_scope: false,
        }
    }

    fn scoped(record: Option<Vec<u8>>) -> Self {
        Self {
            path: format!("0::/xudo.slice/{NAME}.scope\n").into_bytes(),
            inode: ID,
            facts: record.map(|record| ScopeFacts {
                cgroup2: true,
                inode: ID,
                owner: 0,
                mode: 0o40755,
                procs_owner: 0,
                procs_mode: 0o100_644,
                populated: true,
                record: Some(record),
                record_owner: 0,
                record_mode: 0o100_600,
                record_nlink: 1,
                processes: Vec::new(),
            }),
            names: vec![NAME.to_owned()],
            fail_peer_id: false,
            fail_scope: false,
        }
    }

    fn watch(record: Vec<u8>) -> Self {
        let mut cgroup = Self::scoped(Some(record));
        cgroup.path = format!("0::/xudo.slice/{WATCH_NAME}.scope\n").into_bytes();
        cgroup.names = vec![WATCH_NAME.to_owned()];
        if let Some(facts) = &mut cgroup.facts {
            facts.processes = vec![(PID, 998_877)];
        }
        cgroup
    }

    fn failing_peer_id(mut self) -> Self {
        self.fail_peer_id = true;
        self
    }

    fn failing_scope(mut self) -> Self {
        self.fail_scope = true;
        self
    }
}

impl CgroupCalls for FakeCgroup {
    fn require_cgroup2(&self) -> Result<(), SysError> {
        Ok(())
    }
    fn pidfd_cgroup_id(&self, _pidfd: std::os::fd::BorrowedFd<'_>) -> Result<u64, SysError> {
        if self.fail_peer_id {
            Err(SysError::unsupported("fake cgroup id"))
        } else {
            Ok(ID)
        }
    }
    fn proc_cgroup(&self, _pid: u32) -> Result<Vec<u8>, SysError> {
        Ok(self.path.clone())
    }
    fn cgroup_inode(&self, _path: &str) -> Result<u64, SysError> {
        Ok(self.inode)
    }
    fn peer_alive(&self, _pidfd: std::os::fd::BorrowedFd<'_>) -> Result<bool, SysError> {
        Ok(true)
    }
    fn scope_facts(
        &self,
        name: &str,
        _id: u64,
        _with_processes: bool,
    ) -> Result<Option<ScopeFacts>, SysError> {
        if self.fail_scope {
            return Err(SysError::unsupported("fake scope lookup"));
        }
        Ok(name
            .strip_suffix(".scope")
            .filter(|name| *name == NAME || *name == WATCH_NAME)
            .and(self.facts.clone()))
    }
    fn scope_names(&self) -> Result<Vec<String>, SysError> {
        Ok(self.names.clone())
    }
}

/// The empty-registry classification: no agent is enrolled, so a scope is
/// never attested. Test-only; the broker always classifies against its registry.
fn classify(identity: &xudod::identify::PeerIdentity) -> xudo_policy::CallerFacts {
    classify_with_registry(identity, &xudo_policy::HarnessRegistry::empty(), "")
}

fn stat(pid: u32, _uid: u32, _nested: bool) -> Vec<u8> {
    let mut fields = vec![
        "S".to_owned(),
        "1".to_owned(),
        "1".to_owned(),
        "1".to_owned(),
        "0".to_owned(),
        "-1".to_owned(),
    ];
    for _ in 0..13 {
        fields.push("0".to_owned());
    }
    fields.push("998877".to_owned());
    format!("{pid} (claude) {}", fields.join(" ")).into_bytes()
}

fn record(uid: u32, boot: &str, deadline: u64, kind: &str) -> Vec<u8> {
    let registry = registry();
    let entry_hash = registry.get("claude").unwrap().hash_hex();
    let way = if kind == "agent" {
        "service"
    } else {
        "session"
    };
    format!(r#"{{"uid":{uid},"label":"claude","way":"{way}","registry_entry_hash":"{entry_hash}","boot_id":"{boot}","created_at_boottime_ms":20,"deadline":{deadline},"pid":{PID},"starttime":998877,"cgroup_id":{ID}}}"#).into_bytes()
}

fn registry() -> HarnessRegistry {
    HarnessRegistry::from_files([(
        "claude.toml",
        "label = \"claude\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"root\"]\nmax-sessions = 4\n",
    )])
    .unwrap()
}

fn identify(
    uid: u32,
    cgroup: &FakeCgroup,
    nested: bool,
    socket_pidfd: bool,
) -> xudod::identify::PeerIdentity {
    identify_with_boot(uid, cgroup, nested, socket_pidfd, Ok(BOOT.to_owned()))
}

fn identify_with_boot(
    uid: u32,
    cgroup: &FakeCgroup,
    nested: bool,
    socket_pidfd: bool,
    boot: Result<String, SysError>,
) -> xudod::identify::PeerIdentity {
    let fd = UnixStream::pair().unwrap().0;
    let syscalls = FakeSyscalls::new()
        .with_boot_id(boot)
        .with_info(Ok(PidfdInfo::empty()
            .with_ids(ProcessIds {
                pid: PID,
                tgid: PID,
                ppid: 1,
            })
            .with_creds(xudo_sys::Creds {
                ruid: uid,
                rgid: 100,
                euid: uid,
                egid: 100,
                suid: uid,
                sgid: 100,
                fsuid: uid,
                fsgid: 100,
            })
            .with_cgroup_id(ID)));
    let (syscalls, opened_peer) = if socket_pidfd {
        (
            syscalls.with_peer(Ok(UnixStream::pair().unwrap().0.into())),
            FakePeer::new(),
        )
    } else {
        use std::os::fd::OwnedFd;
        let (a, _) = UnixStream::pair().unwrap();
        let error = SysError::os("SO_PEERPIDFD", &Errno::NOPROTOOPT.into());
        (
            syscalls.with_peer(Err(error)),
            FakePeer::new().with_open(Ok(OwnedFd::from(a))),
        )
    };
    let status = format!(
        "Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nNSpid:\t{}\n",
        if nested { "7 4242" } else { "4242" }
    )
    .into_bytes();
    let peer = opened_peer
        .with_cred(Ok(PeerCred {
            pid: PID,
            uid,
            gid: 100,
        }))
        .with_stat(Ok(stat(PID, uid, nested)))
        .with_status(Ok(status))
        .with_proc(
            PID,
            xudo_sys::ProcFile::UidMap,
            b"0 0 4294967295\n".to_vec(),
        )
        .with_exit(Ok(false));
    let clock = xudo_sys::FixedClock(100);
    identify_classified(fd.as_fd(), &syscalls, &peer, cgroup, &clock)
        .unwrap()
        .identity
}

#[test]
fn claudecode_env_and_agent_comm_without_a_scope_is_human() {
    let identity = identify(UID, &FakeCgroup::outside(), false, true);
    assert!(matches!(
        identity.cgroup_attestation,
        CgroupAttestation::Outside
    ));
    assert!(matches!(
        classify(&identity).classification,
        Classification::Human
    ));
}

#[test]
fn a_live_root_registered_agent_scope_is_classified_from_its_record() {
    let cgroup = FakeCgroup::scoped(Some(record(UID, BOOT, 200, "agent")));
    let identity = identify(UID, &cgroup, false, true);
    assert!(matches!(
        classify_with_registry(
            &identity,
            &registry(),
            "agent:x:1000:1000:Agent:/home/agent:/bin/sh\n"
        )
        .classification,
        Classification::EnrolledAgent { .. }
    ));
}

#[test]
fn a_diverged_peer_in_an_agent_scope_is_never_an_agent() {
    let cgroup = FakeCgroup::scoped(Some(record(UID, BOOT, 200, "agent")));
    let identity = identify(UID, &cgroup, true, true);
    assert!(!matches!(
        classify(&identity).classification,
        Classification::EnrolledAgent { .. }
    ));
}

#[test]
fn a_pidfd_open_rung_never_classifies_an_agent() {
    let cgroup = FakeCgroup::scoped(Some(record(UID, BOOT, 200, "agent")));
    let identity = identify(UID, &cgroup, false, false);
    assert_eq!(identity.rung, xudo_sys::Attestation::PidfdOpen);
    assert!(!matches!(
        classify(&identity).classification,
        Classification::EnrolledAgent { .. }
    ));
}

#[test]
fn a_uid_zero_peer_in_an_agent_scope_is_not_an_agent() {
    let cgroup = FakeCgroup::scoped(Some(record(0, BOOT, 200, "agent")));
    let identity = identify(0, &cgroup, false, true);
    assert!(!matches!(
        classify(&identity).classification,
        Classification::EnrolledAgent { .. }
    ));
}

#[test]
fn a_scope_record_for_another_uid_is_not_an_agent() {
    let cgroup = FakeCgroup::scoped(Some(record(UID + 1, BOOT, 200, "agent")));
    let identity = identify(UID, &cgroup, false, true);
    assert!(
        matches!(
            classify(&identity).classification,
            Classification::Unattested { .. }
        ),
        "identity={identity:?}"
    );
}

#[test]
fn a_scope_from_a_previous_boot_is_not_an_agent() {
    let cgroup = FakeCgroup::scoped(Some(record(
        UID,
        "00000000-0000-0000-0000-000000000000",
        200,
        "agent",
    )));
    let identity = identify(UID, &cgroup, false, true);
    assert!(matches!(
        classify(&identity).classification,
        Classification::Unattested { .. }
    ));
}

#[test]
fn a_scope_past_its_record_deadline_is_not_an_agent() {
    let cgroup = FakeCgroup::scoped(Some(record(UID, BOOT, 100, "agent")));
    let identity = identify(UID, &cgroup, false, true);
    assert!(matches!(
        classify(&identity).classification,
        Classification::Unattested { .. }
    ));
}

#[test]
fn a_peer_in_a_recordless_scope_under_the_slice_is_unattested() {
    let identity = identify(UID, &FakeCgroup::scoped(None), false, true);
    assert!(
        matches!(
            classify(&identity).classification,
            Classification::Unattested { .. }
        ),
        "identity={identity:?}"
    );
}

#[test]
fn an_ssh_login_as_the_agent_account_is_human() {
    let identity = identify(UID, &FakeCgroup::outside(), false, true);
    assert!(matches!(
        classify(&identity).classification,
        Classification::Human
    ));
}

#[test]
fn a_failed_cgroup_id_lookup_is_unattested() {
    let identity = identify(UID, &FakeCgroup::outside().failing_peer_id(), false, true);
    assert!(matches!(
        identity.cgroup_attestation,
        CgroupAttestation::Unattested
    ));
    assert!(matches!(
        classify(&identity).classification,
        Classification::Unattested { .. }
    ));
}

#[test]
fn a_failed_registered_scope_lookup_is_unattested() {
    let cgroup = FakeCgroup::scoped(Some(record(UID, BOOT, 200, "agent"))).failing_scope();
    let identity = identify(UID, &cgroup, false, true);
    assert!(matches!(
        identity.cgroup_attestation,
        CgroupAttestation::Unattested
    ));
    assert!(matches!(
        classify(&identity).classification,
        Classification::Unattested { .. }
    ));
}

#[test]
fn an_unavailable_or_malformed_boot_id_is_unattested() {
    let cgroup = FakeCgroup::scoped(Some(record(UID, BOOT, 200, "agent")));
    for boot in [
        Err(SysError::unsupported("boot id unavailable")),
        Ok("malformed".to_owned()),
    ] {
        let identity = identify_with_boot(UID, &cgroup, false, true, boot);
        assert!(matches!(
            identity.cgroup_attestation,
            CgroupAttestation::Unattested
        ));
        assert!(matches!(
            classify(&identity).classification,
            Classification::Unattested { .. }
        ));
    }
}

#[test]
fn a_watch_scope_record_is_not_a_harness() {
    let cgroup = FakeCgroup::watch(record(UID, BOOT, 200, "watch"));
    let identity = identify(UID, &cgroup, false, true);
    assert!(matches!(
        identity.cgroup_attestation,
        CgroupAttestation::Recordless
    ));
    assert!(matches!(
        classify(&identity).classification,
        Classification::Unattested { .. }
    ));
}

#[test]
fn an_agent_scope_without_its_cgroup_id_is_unattested() {
    let mut identity = identify(
        UID,
        &FakeCgroup::scoped(Some(record(UID, BOOT, 200, "agent"))),
        false,
        true,
    );
    identity.cgroup_id = None;
    assert!(matches!(
        classify(&identity).classification,
        Classification::Unattested { .. }
    ));
}

proptest! {
    #[test]
    fn no_identity_without_a_live_agent_scope_classifies_as_an_agent(
        uid in 0u32..=2000,
        deadline in 0u64..=100,
        boot_matches in any::<bool>(),
        has_record in any::<bool>(),
    ) {
        let bytes = has_record.then(|| record(uid, if boot_matches { BOOT } else { "00000000-0000-0000-0000-000000000000" }, deadline, "agent"));
        let cgroup = FakeCgroup::scoped(bytes);
        let identity = identify(UID, &cgroup, false, true);
        let classified = classify(&identity).classification;
        prop_assert!(
            !matches!(classified, Classification::EnrolledAgent { .. }),
            "identity without a live matching agent scope classified as agent"
        );
    }
}
