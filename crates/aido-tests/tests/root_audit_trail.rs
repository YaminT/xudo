//! The audit trail, end to end, as uid 0: the broker's records and the gate's on
//! one real chain, and what each does when the chain cannot be written.
//!
//! The libraries run here are the ones the shipped binaries are made of, against
//! the real trail (`AuditTrail::system`, a real `/var/lib/aido`, a datagram
//! socket where journald would be), the real spool, the real ruleset, and the
//! real program trust walk. What is faked is what would end or endanger the test
//! process, and only that: the kernel's word about who connected (the broker's
//! `Platform`), the process tree above the gate, and the `execveat` itself,
//! whose replacement of the process is the one thing a test cannot survive. The
//! binaries are run for real by `aidod-bin/tests/root_trail.rs` and
//! `aido-gate-bin/tests/root_direct.rs`.
//!
//! What these tests show, each in the exit test's own words (plan item D1):
//!
//! * a successful root execution leaves both independent records;
//! * a direct hostile invocation of the gate, and a denial, leave theirs;
//! * a sink that cannot be written stops the mint and stops the execution;
//! * `aido_audit::verify_log` — what `aido audit --log` calls — passes the
//!   produced trail and fails after truncation, and what it cannot see is
//!   pinned as a test, so the limit is a fact and not a hope.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

#[path = "support/root_trail.rs"]
mod root_trail;

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use aido_audit::record::Decision;
use aido_gate::{GateHost, SystemHost, run};
use aido_sys::{
    Creds, FakeCall, FakeConnection, FakeHygiene, FakePeer, FakeSyscalls, HostClock, HostEntropy,
    MapSource, PeerCred, PidfdInfo, ProcSource, ProcessIds, SpoolDir,
};
use aido_wire::{Answer, BrokerRequest, BrokerResponse, RefusalCode};
use aidod::{HostPolicy, Platform, Served, serve};
use root_trail::{ACTION, FAULTS, Host, Mirrored, PROGRAM, SPOOL, root_or_skip};

const GATE_PID: u32 = 500;
const AIDO_PID: u32 = 200;
const AIDO_START: u64 = 7_000;
const UID: u32 = 1000;
const GID: u32 = 100;

/// The kernel's word about who connected, scripted: the `aido` of the process
/// tree below, running as an ordinary user.
fn kernel_says_aido_asked() -> (FakeSyscalls, FakePeer) {
    let creds = Creds {
        ruid: UID,
        rgid: GID,
        euid: UID,
        egid: GID,
        suid: UID,
        sgid: GID,
        fsuid: UID,
        fsgid: GID,
    };
    let record = PidfdInfo::empty()
        .with_ids(ProcessIds {
            pid: AIDO_PID,
            tgid: AIDO_PID,
            ppid: 1,
        })
        .with_creds(creds);
    let owned = || OwnedFd::from(UnixStream::pair().unwrap().0);
    (
        FakeSyscalls::new()
            .with_peer(Ok(owned()))
            .with_info(Ok(record)),
        FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: AIDO_PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat(AIDO_PID, "aido", 100, AIDO_START).into_bytes()))
            .with_exit(Ok(false)),
    )
}

fn stat(pid: u32, comm: &str, parent: u32, starttime: u64) -> String {
    let mut tail: Vec<String> = vec!["S".into(), parent.to_string()];
    tail.extend(std::iter::repeat_n("0".to_owned(), 17));
    tail.push(starttime.to_string());
    format!("{pid} ({comm}) {}", tail.join(" "))
}

/// The gate under sudo, under `aido`, under a shell.
fn process_tree() -> MapSource {
    MapSource::new()
        .with("500/stat", stat(500, "aido-gate-auth", 400, 9_000))
        .with("400/stat", stat(400, "sudo", 300, 8_500))
        .with("300/stat", stat(300, "sudo", 200, 8_000))
        .with("200/stat", stat(200, "aido", 100, AIDO_START))
        .with("100/stat", stat(100, "bash", 1, 5_000))
        .with("1/stat", stat(1, "systemd", 0, 1))
}

/// What the broker answered, and how its connection ended.
struct Brokered {
    served: Served,
    response: BrokerResponse,
}

/// Serves one request with the real trail, spool, ruleset, and clock.
fn broker(program: &str, argv: &[&str]) -> Brokered {
    let (syscalls, peers) = kernel_says_aido_asked();
    let request = BrokerRequest::new(
        program,
        argv.iter().map(|a| (*a).to_owned()).collect(),
        "unattested",
    );
    let conn = FakeConnection::new(
        OwnedFd::from(UnixStream::pair().unwrap().0),
        Ok(request.to_json().into_bytes()),
    );
    let policy = HostPolicy::system();
    let platform = Platform {
        syscalls: &syscalls,
        peers: &peers,
        clock: &HostClock,
        entropy: &HostEntropy,
        policy: &policy,
    };
    let spool = SpoolDir::open(Path::new(SPOOL));
    let mut trail = aido_sys::AuditTrail::system("aidod");
    let served = serve(&conn, &platform, spool.as_ref(), &mut trail);
    Brokered {
        served,
        response: BrokerResponse::parse(&conn.written()).unwrap(),
    }
}

fn minted_nonce(brokered: &Brokered) -> String {
    match &brokered.response.answer {
        Answer::Decided {
            minted: Some(minted),
            ..
        } => minted.nonce.clone(),
        other => panic!("nothing minted: {other:?}"),
    }
}

fn refusal_of(brokered: &Brokered) -> Option<RefusalCode> {
    match &brokered.response.answer {
        Answer::Refused { code, .. } => Some(*code),
        Answer::Decided { .. } => None,
    }
}

/// The real gate host — real spool, ruleset, clock, program walk, and trail —
/// with the process tree scripted and the exec recorded instead of made.
struct TestGate {
    real: SystemHost,
    syscalls: FakeSyscalls,
    hygiene: FakeHygiene,
}

impl TestGate {
    fn new() -> Self {
        Self {
            real: SystemHost::new(),
            syscalls: FakeSyscalls::new().with_cloexec(Ok(())),
            hygiene: FakeHygiene::new(GATE_PID),
        }
    }

    fn execs(&self) -> usize {
        self.syscalls
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::Exec { .. }))
            .count()
    }
}

impl GateHost for TestGate {
    fn syscalls(&self) -> &dyn aido_sys::Syscalls {
        &self.syscalls
    }
    fn hygiene(&self) -> &dyn aido_sys::Hygiene {
        &self.hygiene
    }
    fn clock(&self) -> &dyn aido_sys::Clock {
        self.real.clock()
    }
    fn open_proc(&self) -> Result<Box<dyn ProcSource>, aido_sys::SysError> {
        Ok(Box::new(process_tree()))
    }
    fn load_rules(&self) -> Result<aido_policy::LoadedRuleSet, aido_sys::TrustedRulesError> {
        self.real.load_rules()
    }
    fn open_spool(
        &self,
    ) -> Result<Box<dyn aido_gate::run::RequestSpool>, aido_sys::SpoolError> {
        self.real.open_spool()
    }
    fn programs(&self) -> &dyn aido_sys::Programs {
        self.real.programs()
    }
    fn audit(&mut self) -> &mut dyn aido_sys::AuditSink {
        self.real.audit()
    }
}

fn gate_args() -> Vec<OsString> {
    vec![OsString::from("/usr/libexec/aido/aido-gate-auth")]
}

#[test]
fn a_successful_root_execution_leaves_the_brokers_record_and_the_gates_on_one_chain() {
    if !root_or_skip("a_successful_root_execution_leaves_both_records") {
        return;
    }
    let host = Host::fresh();

    let minted = broker(PROGRAM, &["probe"]);
    assert_eq!(minted.served, Served::Minted);
    let nonce = minted_nonce(&minted);
    assert_eq!(host.spool(), [nonce.clone()]);

    let mut gate = TestGate::new();
    let exit = run(&mut gate, &gate_args());

    // The fake exec returned, so the gate refused; a real one never returns.
    // What matters is that it was reached, once, and with the entry spent.
    assert!(
        exit.message.contains("gate_failed_exec"),
        "{}",
        exit.message
    );
    assert_eq!(gate.execs(), 1);
    assert!(host.spool().is_empty(), "the entry is consumed");

    // One chain: the broker's authorization, the gate's, the gate's failed exec.
    let chain = host.chain();
    assert_eq!(
        chain.iter().map(|r| r.seq.get()).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(chain[0].decision, Decision::Allowed);
    assert!(chain[0].evidence.contains(&"broker=aidod".to_owned()));
    assert!(chain[0].evidence.contains(&format!("nonce={nonce}")));
    assert_eq!(chain[1].decision, Decision::Allowed);
    assert!(
        chain[1]
            .evidence
            .iter()
            .any(|line| line.starts_with("lineage=aido-gate-auth(500)"))
    );
    assert_eq!(chain[2].outcome.kind(), "failed");
    assert!(chain[2].evidence.contains(&"authorization_seq=2".to_owned()));
    // The same command, under the same action, in the independent records.
    assert_eq!(chain[0].argv, [PROGRAM, "probe"]);
    assert_eq!(chain[0].argv, chain[1].argv);
    assert_eq!(chain[0].action.as_deref(), Some(ACTION));
    assert_eq!(chain[0].action, chain[1].action);

    // And every line of the file is in the journal, as the binary that wrote it.
    let identifiers = ["aidod", "aido-gate", "aido-gate"];
    let expected: Vec<Mirrored> = chain
        .iter()
        .zip(identifiers)
        .map(|(record, identifier)| Mirrored {
            identifier: identifier.to_owned(),
            seq: record.seq.get(),
            hash: record.hash.clone(),
        })
        .collect();
    assert_eq!(host.mirrored(), expected);
}

#[test]
fn a_denial_leaves_a_record_and_a_hostile_gate_invocation_leaves_another_on_the_same_chain() {
    if !root_or_skip("a_denial_and_a_hostile_gate_invocation_leave_theirs") {
        return;
    }
    let host = Host::fresh();

    let denied = broker("/bin/sh", &["-c", "id"]);
    assert_eq!(denied.served, Served::Decided);
    assert!(host.spool().is_empty());

    // The gate, started with nothing minted for it: no entry names its caller.
    let mut gate = TestGate::new();
    let exit = run(&mut gate, &gate_args());
    assert_eq!(exit.status, 19);
    assert_eq!(gate.execs(), 0);

    let chain = host.chain();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].decision, Decision::Denied);
    assert!(chain[0].evidence.contains(&"broker=aidod".to_owned()));
    assert_eq!(chain[1].decision, Decision::Denied);
    assert_eq!(chain[1].prev_hash, chain[0].hash);
    assert!(
        exit.message.contains(chain[1].denial.as_deref().unwrap()),
        "{}",
        exit.message
    );
    let identifiers: Vec<String> = host.mirrored().into_iter().map(|m| m.identifier).collect();
    assert_eq!(identifiers, ["aidod", "aido-gate"]);
}

#[test]
fn a_broker_whose_trail_cannot_be_written_mints_nothing() {
    if !root_or_skip("a_broker_whose_trail_cannot_be_written_mints_nothing") {
        return;
    }
    for fault in FAULTS {
        let host = Host::fresh();
        host.break_trail(fault);
        // Read after the fault: a log that is now a directory has no bytes.
        let before = host.log();

        let refused = broker(PROGRAM, &["probe"]);
        assert_eq!(
            refusal_of(&refused),
            Some(RefusalCode::AuditUnavailable),
            "{fault:?}"
        );
        assert_eq!(refused.served.exit_status(), 19, "{fault:?}");
        assert!(host.spool().is_empty(), "{fault:?}: no entry without a record");
        assert_eq!(host.log(), before, "{fault:?}");
        assert!(host.mirrored().is_empty(), "{fault:?}");

        // A denial is still answered.
        let denied = broker("/bin/sh", &["-c", "id"]);
        assert_eq!(denied.served, Served::Decided, "{fault:?}");
    }
}

#[test]
fn a_gate_whose_trail_cannot_be_written_executes_nothing() {
    if !root_or_skip("a_gate_whose_trail_cannot_be_written_executes_nothing") {
        return;
    }
    for fault in FAULTS {
        let host = Host::fresh();
        // A valid mint, on a trail that works.
        let minted = broker(PROGRAM, &["probe"]);
        assert_eq!(minted.served, Served::Minted, "{fault:?}");
        assert_eq!(host.spool().len(), 1);
        let _ = host.mirrored();

        // Then the trail breaks, and the gate is run with the entry waiting.
        host.break_trail(fault);
        let before = host.log();
        let mut gate = TestGate::new();
        let exit = run(&mut gate, &gate_args());

        assert_eq!(exit.status, 19, "{fault:?}");
        assert!(
            exit.message.contains("gate_failed_audit"),
            "{fault:?}: {}",
            exit.message
        );
        assert_eq!(gate.execs(), 0, "{fault:?}: nothing runs without a record");
        // The gate consumes the entry before it asks the trail to authorize
        // (`aido_gate::run`, step 10 then 11): a refused authorization still
        // spends it, so a hostile sink can deny service but cannot keep the
        // entry for a later, unrecorded run.
        assert!(host.spool().is_empty(), "{fault:?}: the entry is spent");
        assert_eq!(host.log(), before, "{fault:?}");
        assert!(host.mirrored().is_empty(), "{fault:?}");
    }
}

#[test]
fn verify_log_passes_the_produced_trail_and_fails_after_truncation() {
    if !root_or_skip("verify_log_passes_the_produced_trail_and_fails_after_truncation") {
        return;
    }
    let host = Host::fresh();
    assert_eq!(broker(PROGRAM, &["probe"]).served, Served::Minted);
    let mut gate = TestGate::new();
    let _ = run(&mut gate, &gate_args());
    assert_eq!(broker("/bin/sh", &["-c", "id"]).served, Served::Decided);
    let intact = host.log();
    assert_eq!(aido_audit::verify_log(&intact).unwrap().len(), 4);

    // `truncate -s -1` removes only the final newline: no part of any record is
    // lost, so by design (`aido_audit::tail`) the log still verifies.
    root_trail::replace_log(&intact[..intact.len() - 1]);
    assert_eq!(aido_audit::verify_log(&host.log()).unwrap().len(), 4);

    // A torn tail: one byte of the last record, and a cut in the middle of it.
    let lines: Vec<&[u8]> = intact.split_inclusive(|b| *b == b'\n').collect();
    assert_eq!(lines.len(), 4);
    let last_start = intact.len() - lines[3].len();
    for (name, cut) in [
        ("one byte of the record", intact.len() - 2),
        ("mid-line", last_start + lines[3].len() / 2),
        ("one byte into the last line", last_start + 1),
    ] {
        root_trail::replace_log(&intact[..cut]);
        assert!(
            aido_audit::verify_log(&host.log()).is_err(),
            "a log cut at {name} must not verify"
        );
    }

    // An edit in place breaks the chain at the edit.
    let edited = String::from_utf8(intact.clone())
        .unwrap()
        .replacen("\"allowed\"", "\"denied\"", 1);
    root_trail::replace_log(edited.as_bytes());
    assert!(aido_audit::verify_log(&host.log()).is_err());

    // The limit, pinned: whole trailing records dropped cleanly leave a chain
    // that verifies. Nothing in the file can show that a record is missing; the
    // journal copy is the witness, and it holds all four.
    root_trail::replace_log(&intact[..intact.len() - lines[3].len()]);
    assert_eq!(aido_audit::verify_log(&host.log()).unwrap().len(), 3);
    assert_eq!(host.mirrored().len(), 4, "the journal still has every record");
}
