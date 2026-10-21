//! The broker against a real kernel and a real second process.
//!
//! Every refusal in `identify` and `serve` is reached with fakes in the
//! library's own tests. These run the same code on the real seams —
//! `SO_PEERCRED`, `SO_PEERPIDFD`, `PIDFD_GET_INFO`, `/proc`, and a poll on the
//! pidfd — against a peer that is a separate process, because a socket pair's
//! "peer" is always the process that made it and so cannot tell a right answer
//! from a wrong one.
//!
//! Written without a branch on what the kernel supports: what each kernel
//! should answer is computed from the attestation ladder and compared, so the
//! same test passes on Docker's 6.12 and on CI's 6.17, and a ladder that
//! disagrees with the kernel fails it.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use aido_policy::{Decision, RuleFile, Verdict, load_rule_files};
use aido_sys::{
    Attestation, FakeSpool, HostClock, HostEntropy, HostPeer, HostSyscalls, KernelSupport,
    SysError, UnixConnection, parse_stat,
};
use aido_wire::{Answer, BrokerRequest, BrokerResponse, Minted};
use aidod::identify::EuidSource;
use aidod::policy::{LoadedPolicy, PolicyError, PolicySource};
use aidod::serve::{Platform, Served, serve};
use aidod::{Fault, IdentifyError, identify};
use rustix::io::Errno;
use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};

fn running_kernel() -> KernelSupport {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    KernelSupport::parse(release.trim())
}

/// A fresh directory for one test's socket, under the target directory.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("aidod-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A listener, and a separate process connected to it that runs `script`
/// with the socket in `$s` and `extra` as `$ARGV[1]`.
fn connected(name: &str, script: &str, extra: &str) -> (Child, UnixStream) {
    let path = scratch(name).join("peer.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let child = Command::new("/usr/bin/perl")
        .args([
            "-MSocket",
            "-e",
            &format!(
                "socket(my $s, AF_UNIX, SOCK_STREAM, 0) or die \"socket: $!\"; \
                 connect($s, pack_sockaddr_un($ARGV[0])) or die \"connect: $!\"; {script}"
            ),
        ])
        .arg(&path)
        .arg(extra)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let (stream, _) = listener.accept().unwrap();
    (child, stream)
}

/// A peer that holds its connection open until its stdin closes.
fn waiting_peer(name: &str) -> (Child, UnixStream) {
    connected(name, "sysread(STDIN, my $b, 1); exit 0;", "")
}

/// Waits until `child` has exited, without reaping it.
fn wait_for_exit_leaving_a_zombie(child: &Child) {
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
    )
    .unwrap();
}

fn starttime_of(pid: u32) -> u64 {
    let bytes = std::fs::read(format!("/proc/{pid}/stat")).unwrap();
    parse_stat("stat", &bytes).unwrap().starttime
}

#[test]
fn a_live_peer_is_named_on_the_rung_the_kernel_version_predicts() {
    let kernel = running_kernel();
    assert!(
        kernel.attestation >= Attestation::PeerPidfd,
        "the Linux tests need SO_PEERPIDFD, Linux 6.5 or later"
    );
    let (mut child, stream) = waiting_peer("live");
    let identity = identify(stream.as_fd(), &HostSyscalls, &HostPeer).unwrap();

    let with_record = kernel.attestation == Attestation::PeerPidfdInfo;
    assert_eq!(identity.rung, kernel.attestation);
    assert_eq!(identity.pid, child.id());
    assert_eq!(identity.uid, rustix::process::geteuid().as_raw());
    assert_eq!(identity.gid, rustix::process::getegid().as_raw());
    assert_eq!(identity.starttime, starttime_of(child.id()));
    assert!(identity.pinned);
    assert_eq!(identity.cgroup_id.is_some(), with_record);
    assert_eq!(
        identity.euid_source,
        [EuidSource::ProcStatus, EuidSource::PidfdInfo][usize::from(with_record)]
    );

    drop(child.stdin.take());
    assert!(child.wait().unwrap().success());
}

#[test]
fn a_peer_that_exited_mid_identification_is_refused_while_its_number_is_still_its_own() {
    // Exited, not yet reaped: every read by number still succeeds — the
    // zombie keeps its /proc entry — so only the re-check through the pidfd
    // can tell, and it does, on every kernel.
    let (mut child, stream) = connected("zombie", "exit 0;", "");
    wait_for_exit_leaving_a_zombie(&child);
    let error = identify(stream.as_fd(), &HostSyscalls, &HostPeer).unwrap_err();
    assert_eq!(error, IdentifyError::Exited);
    assert!(child.wait().unwrap().success());
}

#[test]
fn a_peer_reaped_before_identification_is_refused_and_never_looked_up_by_number() {
    // Until 6.16 the kernel refuses a pidfd for a reaped peer; from 6.16 it
    // hands one out and PIDFD_GET_INFO on it answers ESRCH. Both are
    // refusals, and neither falls to a lower rung that would look the
    // number up again.
    let (mut child, stream) = connected("reaped", "exit 0;", "");
    assert!(child.wait().unwrap().success());
    let stale = running_kernel().version.at_least(6, 16);
    let error = identify(stream.as_fd(), &HostSyscalls, &HostPeer).unwrap_err();
    let expected = [
        IdentifyError::PeerPidfd(SysError::os(
            "getsockopt(SO_PEERPIDFD)",
            &Errno::INVAL.into(),
        )),
        IdentifyError::PidfdInfo(SysError::os("ioctl(PIDFD_GET_INFO)", &Errno::SRCH.into())),
    ];
    assert_eq!(
        std::mem::discriminant(&error),
        std::mem::discriminant(&expected[usize::from(stale)]),
        "{error}"
    );
    assert_eq!(
        error.to_string().contains("No such process"),
        stale,
        "{error}"
    );
    // On every kernel, the peer leaving is the peer's doing: a client that
    // connects and exits cannot make the broker exit as broken.
    assert_eq!(error.fault(), Fault::Client, "{error}");
}

/// Root's policy, fixed: one rule that restarts a unit.
struct OneRule;

impl PolicySource for OneRule {
    fn load(&self) -> Result<LoadedPolicy, PolicyError> {
        let rules = load_rule_files(vec![RuleFile {
            name: b"10-services.toml".to_vec(),
            bytes: br#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#
            .to_vec(),
        }])
        .unwrap();
        Ok(LoadedPolicy {
            rules,
            settings: aido_policy::engine::Settings::default(),
        })
    }
}

/// The decision and entry an answer carries, if it carries a decision.
fn decided(answer: Answer) -> Option<(Decision, Option<Minted>)> {
    match answer {
        Answer::Decided { decision, minted } => Some((decision, minted)),
        Answer::Refused { .. } => None,
    }
}

#[test]
fn a_real_client_is_identified_decided_and_minted_for_end_to_end() {
    // A separate process sends a request over a real connection and reads
    // the answer; the broker runs on the real kernel seams, the real clock,
    // and the real random source. Only the spool is in memory: the real
    // writer must be root's, and its descriptor half is tested as this user
    // in aido-sys.
    let request = BrokerRequest::new(
        "/usr/bin/systemctl",
        vec!["restart".to_owned(), "nginx.service".to_owned()],
        "unattested",
    );
    let (mut child, stream) = connected(
        "end-to-end",
        "syswrite($s, $ARGV[1]) or die \"write: $!\"; shutdown($s, 1); \
         my $r = \"\"; while (sysread($s, my $b, 65536)) { $r .= $b } print $r; exit 0;",
        &request.to_json(),
    );
    let conn = UnixConnection::adopt(stream.as_fd(), aidod::IO_TIMEOUT).unwrap();
    let platform = Platform {
        syscalls: &HostSyscalls,
        peers: &HostPeer,
        clock: &HostClock,
        entropy: &HostEntropy,
        policy: &OneRule,
        trail: Ok(()),
    };
    let spool = FakeSpool::new();
    let mut log = Vec::new();
    let before = aido_sys::Clock::monotonic_secs(&HostClock);
    let served = serve(&conn, &platform, Ok(&spool), &mut log);
    assert_eq!(served, Served::Minted);
    drop(conn);
    drop(stream);

    let mut answer = Vec::new();
    let mut stdout = child.stdout.take().unwrap();
    stdout.read_to_end(&mut answer).unwrap();
    assert!(child.wait().unwrap().success());
    let (decision, minted) = decided(BrokerResponse::parse(&answer).unwrap().answer).unwrap();
    assert_eq!(decision.verdict, Verdict::Allow);
    let minted = minted.unwrap();
    assert!(aido_gate::request::is_nonce(&minted.nonce));
    assert!(minted.deadline >= before + aidod::mint::REQUEST_TTL_SECS);

    let files = spool.files();
    let entry = aido_gate::PendingRequest::parse(
        std::str::from_utf8(&files[minted.nonce.as_bytes()]).unwrap(),
    )
    .unwrap();
    assert_eq!(entry.caller_pid, child.id());
    assert_eq!(entry.deadline.0, minted.deadline);
    let records = String::from_utf8(log).unwrap();
    assert!(
        records.contains(&format!("peer_pid={}", child.id())),
        "{records}"
    );
    assert!(
        records.contains(&format!(
            "rung={}",
            running_kernel().attestation.mechanism()
        )),
        "{records}"
    );
}

#[test]
fn two_nonces_drawn_from_the_kernel_never_collide() {
    let first = aidod::mint::draw_nonce(&HostEntropy).unwrap();
    let second = aidod::mint::draw_nonce(&HostEntropy).unwrap();
    assert_ne!(first, second);
    assert!(aido_gate::request::is_nonce(&first));
}
