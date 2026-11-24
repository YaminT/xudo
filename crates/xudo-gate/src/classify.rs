//! The gate's independent classification from pinned kernel cgroup facts.

use std::os::fd::AsFd;

use xudo_policy::{CallerFacts, Classification, HarnessRegistry};
use xudo_sys::{
    CgroupCalls, PeerCalls, ProcFile, Scope, ScopeKind, Syscalls, peer_cgroup_id, scope_status,
    verify_parent_pid,
};

use crate::request::AttestedClass;

/// The class and binding the gate re-derived for the broker's caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveClass {
    /// Policy view used for the independent re-decision.
    pub facts: CallerFacts,
    /// Stored identity form used to compare with the broker's entry.
    pub attested_class: AttestedClass,
    /// Live cgroup id for an agent, otherwise absent.
    pub scope_id: Option<u64>,
    /// Current boot id for an agent, otherwise absent.
    pub boot_id: Option<String>,
}

/// The matched ancestor and immediate child pins used by the gate rung.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AncestorPin {
    /// The caller's `(pid, starttime)` from the lineage walk.
    pub caller: (u32, u64),
    /// The caller's uid from the broker-minted entry.
    pub uid: u32,
    /// The immediate child pin from the lineage walk.
    pub child: (u32, u64),
    /// The gate's own clock reading in milliseconds since boot.
    pub now_boottime_ms: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::items_after_test_module)]

    use std::ffi::CStr;
    use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
    use std::os::unix::net::UnixStream;

    use super::*;
    use xudo_sys::{FakePeer, FakeSyscalls, PeerCall, ScopeFacts, SysError};

    struct InvalidBootSyscalls(FakeSyscalls);

    impl Syscalls for InvalidBootSyscalls {
        fn boot_id(&self) -> Result<String, SysError> {
            Ok("not-a-boot-id".to_owned())
        }
        fn mark_cloexec_from(&self, first: u32) -> Result<(), SysError> {
            self.0.mark_cloexec_from(first)
        }
        fn peer_pidfd(&self, socket: BorrowedFd<'_>) -> Result<OwnedFd, SysError> {
            self.0.peer_pidfd(socket)
        }
        fn peer_cred(
            &self,
            socket: BorrowedFd<'_>,
        ) -> Result<xudo_sys::syscall::PeerCred, SysError> {
            self.0.peer_cred(socket)
        }
        fn pidfd_info(
            &self,
            pidfd: BorrowedFd<'_>,
            mask: u64,
        ) -> Result<xudo_sys::PidfdInfo, SysError> {
            self.0.pidfd_info(pidfd, mask)
        }
        fn exec_fd(&self, program: BorrowedFd<'_>, argv: &[&CStr], envp: &[&CStr]) -> SysError {
            self.0.exec_fd(program, argv, envp)
        }
    }

    const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";

    #[test]
    fn a_live_non_agent_scope_stays_on_the_human_path() {
        let live = registered_scope(
            Scope {
                kind: ScopeKind::Watch,
                name: "watch-0123456789abcdef0123456789abcdef.scope".to_owned(),
                record: Vec::new(),
            },
            90,
            BOOT.to_owned(),
            1000,
            &registry(),
            PASSWD,
        );
        assert_eq!(live.attested_class, AttestedClass::Human);
        assert_eq!(live.facts.classification, Classification::Human);
        assert_eq!(live.scope_id, None);
        assert_eq!(live.boot_id, None);
    }
    const NAME: &str = "agent-0123456789abcdef0123456789abcdef";
    const WATCH_NAME: &str = "watch-0123456789abcdef0123456789abcdef";

    struct Cgroup {
        path: Vec<u8>,
        facts: Option<ScopeFacts>,
        names: Vec<String>,
        fail_peer_id: bool,
        fail_scope: bool,
        fail_proc_read: bool,
    }

    impl Cgroup {
        fn outside() -> Self {
            Self {
                path: b"0::/user.slice/session.scope\n".to_vec(),
                facts: None,
                names: Vec::new(),
                fail_peer_id: false,
                fail_scope: false,
                fail_proc_read: false,
            }
        }

        fn agent(record: Vec<u8>) -> Self {
            Self {
                path: format!("0::/xudo.slice/{NAME}.scope\n").into_bytes(),
                facts: Some(ScopeFacts {
                    cgroup2: true,
                    inode: 90,
                    owner: 0,
                    mode: 0o40755,
                    procs_owner: 0,
                    procs_mode: 0o100_644,
                    populated: true,
                    record: Some(record),
                    record_owner: 0,
                    record_mode: 0o100_600,
                    record_nlink: 1,
                    processes: vec![(100, 500)],
                }),
                names: vec![NAME.to_owned()],
                fail_peer_id: false,
                fail_scope: false,
                fail_proc_read: false,
            }
        }

        fn other_registered_scope(record: Vec<u8>) -> Self {
            let mut cgroup = Self::agent(record);
            cgroup.path = format!("0::/xudo.slice/{WATCH_NAME}.scope\n").into_bytes();
            cgroup.names = vec![WATCH_NAME.to_owned()];
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

        fn failing_proc_cgroup(mut self) -> Self {
            self.fail_proc_read = true;
            self
        }
    }

    impl CgroupCalls for Cgroup {
        fn require_cgroup2(&self) -> Result<(), SysError> {
            Ok(())
        }
        fn pidfd_cgroup_id(&self, _pidfd: std::os::fd::BorrowedFd<'_>) -> Result<u64, SysError> {
            if self.fail_peer_id {
                Err(SysError::unsupported("fake cgroup id"))
            } else {
                Ok(90)
            }
        }
        fn proc_cgroup(&self, _pid: u32) -> Result<Vec<u8>, SysError> {
            if self.fail_proc_read {
                Err(SysError::read("/proc/<pid>/cgroup", "unreadable"))
            } else {
                Ok(self.path.clone())
            }
        }
        fn cgroup_inode(&self, _path: &str) -> Result<u64, SysError> {
            Ok(90)
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

    fn stat(pid: u32, parent: u32, starttime: u64) -> Vec<u8> {
        let mut fields = vec!["S".to_owned(), parent.to_string()];
        for _ in 0..17 {
            fields.push("0".to_owned());
        }
        fields.push(starttime.to_string());
        format!("{pid} (test) {}", fields.join(" ")).into_bytes()
    }

    fn fd() -> OwnedFd {
        OwnedFd::from(UnixStream::pair().unwrap().0)
    }

    #[test]
    fn invalid_boot_test_syscalls_delegate_non_boot_operations() {
        let syscalls = InvalidBootSyscalls(FakeSyscalls::new());
        let descriptor = fd();
        let _ = syscalls.mark_cloexec_from(3);
        let _ = syscalls.peer_pidfd(descriptor.as_fd());
        let _ = syscalls.peer_cred(descriptor.as_fd());
        let _ = syscalls.pidfd_info(descriptor.as_fd(), 0);
        let _ = syscalls.exec_fd(descriptor.as_fd(), &[], &[]);
    }

    #[test]
    fn the_gate_ancestor_rung_requires_the_ppid_recheck_after_pidfd_open() {
        let peers = FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, 100, 700))
            .with_proc(100, ProcFile::Stat, stat(100, 1, 500))
            .with_exit(Ok(false))
            .with_exit(Ok(false));
        let syscalls = FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned()));
        let result = classify(
            &Cgroup::outside(),
            &peers,
            &syscalls,
            AncestorPin {
                caller: (100, 500),
                uid: 1000,
                child: (200, 700),
                now_boottime_ms: 50,
            },
        );

        assert_eq!(result.attested_class, AttestedClass::Human);
        let calls = peers.calls();
        assert_eq!(calls.first(), Some(&PeerCall::PidfdOpen(100)));
        assert_eq!(calls.get(1), Some(&PeerCall::PidfdOpen(200)));
        assert_eq!(calls.get(2), Some(&PeerCall::ReadProc(200, ProcFile::Stat)));
    }

    const PASSWD: &str = "agent:x:1000:1000:agent:/home/agent:/bin/sh\n";

    fn registry() -> xudo_policy::HarnessRegistry {
        xudo_policy::HarnessRegistry::from_files([(
            "codex.toml",
            "label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 4\n",
        )])
        .unwrap()
    }

    fn record(uid: u32, boot: &str, deadline: u64) -> Vec<u8> {
        let hash = registry().get("codex").unwrap().hash_hex();
        format!(r#"{{"uid":{uid},"label":"codex","way":"service","registry_entry_hash":"{hash}","boot_id":"{boot}","created_at_boottime_ms":20,"deadline":{deadline},"pid":100,"starttime":500,"cgroup_id":90}}"#).into_bytes()
    }

    fn non_agent_record(uid: u32, boot: &str, deadline: u64) -> Vec<u8> {
        record(uid, boot, deadline)
    }

    fn fake_peers(child_parent: u32) -> FakePeer {
        FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, child_parent, 700))
            .with_proc(100, ProcFile::Stat, stat(100, 1, 500))
            .with_exit(Ok(false))
            .with_exit(Ok(false))
    }

    #[test]
    fn the_gate_accepts_only_a_live_registered_agent_scope() {
        let peers = fake_peers(100);
        let syscalls = FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned()));
        let result = classify_with_registry(
            &Cgroup::agent(record(1000, BOOT, 200)),
            &peers,
            &syscalls,
            &registry(),
            PASSWD,
            AncestorPin {
                caller: (100, 500),
                uid: 1000,
                child: (200, 700),
                now_boottime_ms: 50,
            },
        );
        assert_eq!(
            result.attested_class,
            AttestedClass::EnrolledAgent { scope_id: 90 }
        );
        assert_eq!(result.scope_id, Some(90));
        assert_eq!(result.boot_id.as_deref(), Some(BOOT));
        assert_eq!(
            result.facts.classification,
            Classification::EnrolledAgent {
                agent_id: "codex".to_owned(),
                session_id: format!("{NAME}.scope"),
                declared_yolo: false,
            }
        );
    }

    #[test]
    fn a_scope_without_a_registry_label_is_not_an_enrolled_agent() {
        let live = super::registered_scope(
            xudo_sys::Scope {
                kind: xudo_sys::ScopeKind::Agent,
                name: format!("{NAME}.scope"),
                record: b"{}".to_vec(),
            },
            90,
            BOOT.to_owned(),
            1000,
            &registry(),
            PASSWD,
        );
        assert_eq!(live.attested_class, AttestedClass::Unattested);
        assert_eq!(live.scope_id, None);
        assert_eq!(
            live.facts.classification,
            Classification::Unattested {
                reason: "agent scope record does not match the current harness registry".to_owned(),
            }
        );
    }

    #[test]
    fn a_watch_kind_scope_stays_on_the_human_path() {
        let live = super::registered_scope(
            xudo_sys::Scope {
                kind: xudo_sys::ScopeKind::Watch,
                name: format!("{WATCH_NAME}.scope"),
                record: record(1000, BOOT, 200),
            },
            90,
            BOOT.to_owned(),
            1000,
            &registry(),
            PASSWD,
        );
        assert_eq!(live.attested_class, AttestedClass::Human);
        assert_eq!(live.facts.classification, Classification::Human);
        assert_eq!(live.scope_id, None);
        assert_eq!(live.boot_id, None);
    }

    #[test]
    fn a_changed_parent_link_withholds_the_gate_agent_class() {
        let peers = fake_peers(101);
        let syscalls = FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned()));
        let result = classify_with_registry(
            &Cgroup::agent(record(1000, BOOT, 200)),
            &peers,
            &syscalls,
            &registry(),
            PASSWD,
            AncestorPin {
                caller: (100, 500),
                uid: 1000,
                child: (200, 700),
                now_boottime_ms: 50,
            },
        );
        assert_eq!(result.attested_class, AttestedClass::Unattested);
        assert_eq!(result.scope_id, None);
    }

    #[test]
    fn a_watch_scope_is_unattested_after_the_record_kind_was_removed() {
        let peers = fake_peers(100);
        let syscalls = FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned()));
        let result = classify(
            &Cgroup::other_registered_scope(non_agent_record(1000, BOOT, 200)),
            &peers,
            &syscalls,
            AncestorPin {
                caller: (100, 500),
                uid: 1000,
                child: (200, 700),
                now_boottime_ms: 50,
            },
        );
        assert_eq!(result.attested_class, AttestedClass::Unattested);
    }

    #[test]
    fn a_failed_cgroup_read_inside_the_slice_is_unattested() {
        let result = classify_case(
            &Cgroup::agent(record(1000, BOOT, 200)).failing_proc_cgroup(),
            &fake_peers(100),
            &FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned())),
            (100, 500),
            1000,
            (200, 700),
        );
        assert_eq!(result.attested_class, AttestedClass::Unattested);
    }

    #[test]
    fn another_uids_root_scope_record_cannot_attest_the_gate_ancestor() {
        let result = classify_case(
            &Cgroup::agent(record(1001, BOOT, 200)),
            &fake_peers(100),
            &FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned())),
            (100, 500),
            1000,
            (200, 700),
        );
        assert_eq!(result.attested_class, AttestedClass::Unattested);
    }

    #[test]
    fn a_previous_boot_scope_record_cannot_attest_the_gate_ancestor() {
        let result = classify_case(
            &Cgroup::agent(record(1000, "11111111-2222-3333-4444-555555555555", 200)),
            &fake_peers(100),
            &FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned())),
            (100, 500),
            1000,
            (200, 700),
        );
        assert_eq!(result.attested_class, AttestedClass::Unattested);
    }

    #[test]
    fn an_expired_scope_record_cannot_attest_the_gate_ancestor() {
        let result = classify_case(
            &Cgroup::agent(record(1000, BOOT, 50)),
            &fake_peers(100),
            &FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned())),
            (100, 500),
            1000,
            (200, 700),
        );
        assert_eq!(result.attested_class, AttestedClass::Unattested);
    }

    #[test]
    fn a_recreated_scope_name_with_a_different_inode_cannot_attest_the_gate_ancestor() {
        let mut recreated = Cgroup::agent(record(1000, BOOT, 200));
        recreated.facts.as_mut().unwrap().inode = 91;
        let result = classify_case(
            &recreated,
            &fake_peers(100),
            &FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned())),
            (100, 500),
            1000,
            (200, 700),
        );
        assert_eq!(result.attested_class, AttestedClass::Unattested);
    }

    #[test]
    fn a_user_manager_scope_named_like_an_agent_is_not_an_agent_scope() {
        let user_scope = Cgroup {
            path: format!("0::/user.slice/{NAME}.scope\n").into_bytes(),
            ..Cgroup::outside()
        };
        let result = classify_case(
            &user_scope,
            &fake_peers(100),
            &FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned())),
            (100, 500),
            1000,
            (200, 700),
        );
        assert_eq!(result.attested_class, AttestedClass::Human);
    }

    fn classify_case(
        cgroup: &dyn CgroupCalls,
        peers: &dyn PeerCalls,
        syscalls: &dyn Syscalls,
        caller: (u32, u64),
        uid: u32,
        child: (u32, u64),
    ) -> LiveClass {
        classify_with_registry(
            cgroup,
            peers,
            syscalls,
            &registry(),
            PASSWD,
            AncestorPin {
                caller,
                uid,
                child,
                now_boottime_ms: 50,
            },
        )
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn gate_classification_failures_withhold_the_agent_class() {
        let bad = SysError::unsupported("scripted failure");
        let outside = Cgroup::outside();
        let good_boot = FakeSyscalls::new().with_boot_id(Ok(BOOT.to_owned()));

        // Non-process pins are human and never opened.
        assert_eq!(
            classify_case(
                &outside,
                &FakePeer::new(),
                &good_boot,
                (0, 1),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Human
        );
        assert_eq!(
            classify_case(
                &outside,
                &FakePeer::new(),
                &good_boot,
                (100, 1),
                0,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Human
        );
        assert_eq!(
            classify_case(
                &outside,
                &FakePeer::new(),
                &good_boot,
                (100, 1),
                1000,
                (0, 700)
            )
            .attested_class,
            AttestedClass::Human
        );

        // Every failed rung yields Unattested.
        let open_failed = FakePeer::new().with_open(Err(bad.clone()));
        assert_eq!(
            classify_case(
                &outside,
                &open_failed,
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        assert_eq!(
            classify_case(
                &Cgroup::outside().failing_peer_id(),
                &fake_peers(100),
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        let no_boot = FakeSyscalls::new();
        assert_eq!(
            classify_case(
                &outside,
                &fake_peers(100),
                &no_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        let invalid_boot = InvalidBootSyscalls(FakeSyscalls::new());
        assert_eq!(
            classify_case(
                &outside,
                &fake_peers(100),
                &invalid_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );

        let wrong_child = FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, 100, 701))
            .with_exit(Ok(false));
        assert_eq!(
            classify_case(
                &outside,
                &wrong_child,
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        let missing_parent = FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, 100, 700))
            .with_exit(Ok(false));
        assert_eq!(
            classify_case(
                &outside,
                &missing_parent,
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        let malformed_parent = FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, 100, 700))
            .with_proc(100, ProcFile::Stat, b"invalid".to_vec())
            .with_exit(Ok(false));
        assert_eq!(
            classify_case(
                &outside,
                &malformed_parent,
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        let changed_parent = FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, 100, 700))
            .with_proc(100, ProcFile::Stat, stat(101, 1, 500))
            .with_exit(Ok(false));
        assert_eq!(
            classify_case(
                &outside,
                &changed_parent,
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        let exited = FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, 100, 700))
            .with_proc(100, ProcFile::Stat, stat(100, 1, 500))
            .with_exit(Ok(false))
            .with_exit(Ok(true));
        assert_eq!(
            classify_case(&outside, &exited, &good_boot, (100, 500), 1000, (200, 700))
                .attested_class,
            AttestedClass::Unattested
        );
        let poll_failed = FakePeer::new()
            .with_open(Ok(fd()))
            .with_open(Ok(fd()))
            .with_proc(200, ProcFile::Stat, stat(200, 100, 700))
            .with_proc(100, ProcFile::Stat, stat(100, 1, 500))
            .with_exit(Ok(false))
            .with_exit(Err(bad.clone()));
        assert_eq!(
            classify_case(
                &outside,
                &poll_failed,
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );

        // A recordless peer beneath the broker slice is Unattested; a regular
        // user session is Human. A failed record lookup is Unattested.
        let recordless = Cgroup {
            path: format!("0::/xudo.slice/{NAME}.scope\n").into_bytes(),
            ..Cgroup::outside()
        };
        assert_eq!(
            classify_case(
                &recordless,
                &fake_peers(100),
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
        assert_eq!(
            classify_case(
                &outside,
                &fake_peers(100),
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Human
        );
        assert_eq!(
            classify_case(
                &Cgroup::agent(record(1000, BOOT, 200)).failing_scope(),
                &fake_peers(100),
                &good_boot,
                (100, 500),
                1000,
                (200, 700)
            )
            .attested_class,
            AttestedClass::Unattested
        );
    }
}

#[cfg(test)]
/// Classifies one pinned ancestor. `child` is the process immediately below
/// it in the gate's lineage; rechecking that link after `pidfd_open` closes the
/// PID reuse gap in the ancestor rung.
pub fn classify(
    cgroups: &dyn CgroupCalls,
    peers: &dyn PeerCalls,
    syscalls: &dyn Syscalls,
    ancestor: AncestorPin,
) -> LiveClass {
    classify_with_registry(
        cgroups,
        peers,
        syscalls,
        &HarnessRegistry::empty(),
        "",
        ancestor,
    )
}

/// As [`classify`], requiring the record to match the current root registry
/// and the root-owned passwd mapping before treating the peer as a harness.
pub fn classify_with_registry(
    cgroups: &dyn CgroupCalls,
    peers: &dyn PeerCalls,
    syscalls: &dyn Syscalls,
    registry: &HarnessRegistry,
    passwd: &str,
    ancestor: AncestorPin,
) -> LiveClass {
    let (pid, starttime) = ancestor.caller;
    let uid = ancestor.uid;
    let child = ancestor.child;
    let now = ancestor.now_boottime_ms;
    let unattested = || LiveClass {
        facts: CallerFacts::new(
            Classification::Unattested {
                reason: "the gate could not attest the caller's cgroup".to_owned(),
            },
            uid,
        ),
        attested_class: AttestedClass::Unattested,
        scope_id: None,
        boot_id: None,
    };
    let human = || LiveClass {
        facts: CallerFacts::new(Classification::Human, uid),
        attested_class: AttestedClass::Human,
        scope_id: None,
        boot_id: None,
    };
    if pid == 0 || uid == 0 || child.0 == 0 {
        return human();
    }
    let Ok(pidfd) = peers.pidfd_open(pid) else {
        return unattested();
    };
    let Ok(cgroup) = peer_cgroup_id(cgroups, pid, pidfd.as_fd()) else {
        return unattested();
    };
    let Ok(boot_id) = syscalls.boot_id() else {
        return unattested();
    };
    if !crate::request::is_boot_id(&boot_id) {
        return unattested();
    }
    let Ok(child_stat) = verify_parent_pid(peers, child.0, pid) else {
        return unattested();
    };
    if child_stat.starttime != child.1 {
        return unattested();
    }
    let Ok(parent_bytes) = peers.read_proc(pid, ProcFile::Stat) else {
        return unattested();
    };
    let Ok(parent_stat) = xudo_sys::parse_stat("/proc/<ancestor>/stat", &parent_bytes) else {
        return unattested();
    };
    if parent_stat.pid != pid || parent_stat.starttime != starttime {
        return unattested();
    }
    if !matches!(peers.has_exited(pidfd.as_fd()), Ok(false)) {
        return unattested();
    }
    let parse = |bytes: &[u8], name: &str| {
        crate::record_identity_registered(bytes, name, uid, &boot_id, now, registry, passwd)
    };
    match scope_status(cgroups, cgroup.id, uid, &parse) {
        Ok(Some(scope)) => registered_scope(scope, cgroup.id, boot_id, uid, registry, passwd),
        Ok(None) => {
            let in_slice = std::path::Path::new(&cgroup.path).starts_with("/xudo.slice");
            if in_slice { unattested() } else { human() }
        }
        Err(_) => unattested(),
    }
}

fn registered_scope(
    scope: Scope,
    cgroup_id: u64,
    boot_id: String,
    uid: u32,
    registry: &HarnessRegistry,
    passwd: &str,
) -> LiveClass {
    if scope.kind == ScopeKind::Agent {
        let Some(label) =
            crate::session::attested_harness_label(&scope.record, uid, registry, passwd)
        else {
            return LiveClass {
                facts: CallerFacts::new(
                    Classification::Unattested {
                        reason: "agent scope record does not match the current harness registry"
                            .to_owned(),
                    },
                    uid,
                ),
                attested_class: AttestedClass::Unattested,
                scope_id: None,
                boot_id: None,
            };
        };
        LiveClass {
            facts: CallerFacts::new(
                Classification::EnrolledAgent {
                    agent_id: label,
                    session_id: scope.name,
                    declared_yolo: false,
                },
                uid,
            ),
            attested_class: AttestedClass::EnrolledAgent {
                scope_id: cgroup_id,
            },
            scope_id: Some(cgroup_id),
            boot_id: Some(boot_id),
        }
    } else {
        LiveClass {
            facts: CallerFacts::new(Classification::Human, uid),
            attested_class: AttestedClass::Human,
            scope_id: None,
            boot_id: None,
        }
    }
}
