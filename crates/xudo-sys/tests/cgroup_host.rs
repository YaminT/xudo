//! Exercise the non-test Linux host adapter against its pinned descriptors.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::cell::Cell;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use xudo_sys::cgroup::{
    CgroupCalls, CgroupIdentity, CgroupRung, HostCgroup, ProcessSecurityStatus, RecordIdentity,
    ScopeFacts, ScopeKind, parse_process_security_status, peer_cgroup_id, process_security_status,
    scope_status, verify_parent_pid,
};
use xudo_sys::peer::{PeerCalls, PeerCred, ProcFile};
use xudo_sys::{SysError, parse_stat};

#[derive(Clone)]
struct FakeCgroup {
    info: Result<u64, SysError>,
    proc: Result<Vec<u8>, SysError>,
    inode: Result<u64, SysError>,
    alive: bool,
    names: Vec<String>,
    facts: Option<ScopeFacts>,
}

impl CgroupCalls for FakeCgroup {
    fn require_cgroup2(&self) -> Result<(), SysError> {
        Ok(())
    }
    fn pidfd_cgroup_id(&self, _: BorrowedFd<'_>) -> Result<u64, SysError> {
        self.info.clone()
    }
    fn proc_cgroup(&self, _: u32) -> Result<Vec<u8>, SysError> {
        self.proc.clone()
    }
    fn cgroup_inode(&self, _: &str) -> Result<u64, SysError> {
        self.inode.clone()
    }
    fn peer_alive(&self, _: BorrowedFd<'_>) -> Result<bool, SysError> {
        Ok(self.alive)
    }
    fn scope_facts(&self, _: &str) -> Result<Option<ScopeFacts>, SysError> {
        Ok(self.facts.clone())
    }
    fn scope_names(&self) -> Result<Vec<String>, SysError> {
        Ok(self.names.clone())
    }
}

struct FakePeer {
    status: Vec<u8>,
    stat: Vec<u8>,
    exited: Cell<bool>,
}

impl PeerCalls for FakePeer {
    fn peer_cred(&self, _: BorrowedFd<'_>) -> Result<PeerCred, SysError> {
        Err(SysError::unsupported("fake peer credentials"))
    }
    fn pidfd_open(&self, _: u32) -> Result<OwnedFd, SysError> {
        rustix::fs::open(
            "/dev/null",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|errno| SysError::os("fake pidfd_open", &errno.into()))
    }
    fn read_proc(&self, _: u32, file: ProcFile) -> Result<Vec<u8>, SysError> {
        Ok(match file {
            ProcFile::Stat => self.stat.clone(),
            ProcFile::Status => self.status.clone(),
            ProcFile::UidMap => Vec::new(),
        })
    }
    fn has_exited(&self, _: BorrowedFd<'_>) -> Result<bool, SysError> {
        Ok(self.exited.get())
    }
}

#[test]
fn the_host_cgroup_adapter_reads_the_callers_live_kernel_identity() {
    let host = HostCgroup::open().expect("Linux test hosts provide cgroup2");
    host.require_cgroup2().unwrap();

    let pid = std::process::id();
    let raw_pid = i32::try_from(pid).unwrap();
    let pidfd = rustix::process::pidfd_open(
        rustix::process::Pid::from_raw(raw_pid).unwrap(),
        rustix::process::PidfdFlags::empty(),
    )
    .unwrap();
    let identity = peer_cgroup_id(&host, pid, pidfd.as_fd()).unwrap();
    assert!(host.peer_alive(pidfd.as_fd()).unwrap());

    let cgroup = host.proc_cgroup(pid).unwrap();
    let text = std::str::from_utf8(&cgroup).unwrap();
    let path = text
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap();
    assert_eq!(host.cgroup_inode(path).unwrap(), identity.id);

    let _ = host.scope_names();
    let _ = host.scope_facts("agent-0123456789abcdef0123456789abcdef.scope");
    let _ = scope_status(&host, identity.id, 1000, &|_, _| None);
}

#[test]
fn the_pure_cgroup_and_peer_decisions_run_through_the_external_fake_seams() {
    let (socket, _other) = UnixStream::pair().unwrap();
    let peer_fd = socket.as_fd();
    let agent_name = "agent-0123456789abcdef0123456789abcdef";
    let scope_record = b"committed".to_vec();
    let facts = ScopeFacts {
        cgroup2: true,
        inode: 42,
        owner: 0,
        mode: 0o40_755,
        procs_owner: 0,
        procs_mode: 0o100_644,
        populated: true,
        record: Some(scope_record.clone()),
        processes: Vec::new(),
    };
    let fake = FakeCgroup {
        info: Ok(42),
        proc: Ok(b"0::/xudo.slice/agent-a.scope\n".to_vec()),
        inode: Ok(42),
        alive: true,
        names: vec![agent_name.to_owned()],
        facts: Some(facts),
    };
    let identity = peer_cgroup_id(&fake, 7, peer_fd).unwrap();
    assert_eq!(
        identity,
        CgroupIdentity {
            id: 42,
            rung: CgroupRung::PidfdInfo,
            fallback_errno: None,
        }
    );
    let agent = scope_status(&fake, 42, 1000, &|bytes, _| {
        (bytes == scope_record).then_some(RecordIdentity {
            kind: ScopeKind::Agent,
            uid: 1000,
            current_boot: true,
            live: true,
            process: (7, 9),
            cgroup_id: 42,
        })
    })
    .unwrap();
    assert_eq!(agent.map(|scope| scope.kind), Some(ScopeKind::Agent));

    let fallback = FakeCgroup {
        info: Err(SysError::os(
            "PIDFD_GET_INFO",
            &std::io::Error::from_raw_os_error(25),
        )),
        proc: Ok(b"0::/xudo.slice/agent-a.scope\n".to_vec()),
        inode: Ok(42),
        alive: true,
        names: Vec::new(),
        facts: None,
    };
    assert_eq!(
        peer_cgroup_id(&fallback, 7, peer_fd).unwrap().rung,
        CgroupRung::ProcFstat
    );
    let disagree = FakeCgroup {
        info: Ok(1),
        inode: Ok(42),
        ..fallback.clone()
    };
    assert!(peer_cgroup_id(&disagree, 7, peer_fd).is_err());
    let dead = FakeCgroup {
        alive: false,
        ..fallback
    };
    assert!(peer_cgroup_id(&dead, 7, peer_fd).is_err());

    let process = FakePeer {
        status: b"TracerPid:\t0\nNoNewPrivs:\t1\n".to_vec(),
        stat: b"7 (child) S 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 900".to_vec(),
        exited: Cell::new(false),
    };
    assert_eq!(
        process_security_status(&process, 7, peer_fd).unwrap(),
        ProcessSecurityStatus {
            tracer_pid: 0,
            no_new_privs: true,
        }
    );
    let expected = parse_stat("stat", &process.stat).unwrap();
    assert_eq!(
        verify_parent_pid(&process, 7, expected.ppid).unwrap(),
        expected
    );
    assert!(parse_process_security_status(b"TracerPid: 1\n").is_err());
}

mod props {
    use proptest::prelude::*;

    use super::*;

    fn committed(name: &str) -> bool {
        name.split_once('-').is_some_and(|(kind, hex)| {
            (kind == "agent" || kind == "watch")
                && hex.len() == 32
                && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }

    proptest! {
        // Liveness is never granted to a name root did not commit, even when
        // every fact and the record parser say yes.
        #[test]
        fn a_name_that_is_not_committed_is_never_live(
            name in prop_oneof![
                "\\PC{0,48}",
                "(pending-)?(agent|watch)-[0-9a-fA-Fg-z]{0,40}",
            ],
        ) {
            prop_assume!(!committed(&name));
            let fake = FakeCgroup {
                info: Ok(42),
                proc: Ok(Vec::new()),
                inode: Ok(42),
                alive: true,
                names: vec![name],
                facts: Some(ScopeFacts {
                    cgroup2: true,
                    inode: 42,
                    owner: 0,
                    mode: 0o40_755,
                    procs_owner: 0,
                    procs_mode: 0o100_644,
                    populated: true,
                    record: Some(b"committed".to_vec()),
                    processes: Vec::new(),
                }),
            };
            let scope = scope_status(&fake, 42, 1000, &|_, record_name| {
                Some(RecordIdentity {
                    kind: if record_name.starts_with("agent-") {
                        ScopeKind::Agent
                    } else {
                        ScopeKind::Watch
                    },
                    uid: 1000,
                    current_boot: true,
                    live: true,
                    process: (7, 9),
                    cgroup_id: 42,
                })
            })
            .unwrap();
            prop_assert!(scope.is_none());
        }
    }
}
