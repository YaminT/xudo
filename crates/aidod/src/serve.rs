//! One connection, start to finish.
//!
//! ```text
//! identify the peer      kernel facts only; refuse if it cannot be pinned honestly
//! read the request       bounded in size and time; parsed as hostile
//! check the spool        root-owned, private, reached through trusted components
//! load root's policy     the trusted ruleset and settings, or refuse
//! classify               Unattested, always, in M2b
//! decide                 the function behind `aido explain`
//! mint                   permitted decisions only; recorded before it exists
//! answer                 one response, then close
//! ```
//!
//! Every step that fails answers with a refusal and an audit record, and the
//! steps run in this order so that a refusal never describes something that
//! was not established: the peer is known before its request is read, and the
//! request is known before anything is said about the spool or the policy.
//! Nothing after a failure runs.

use std::io::Write;

use aido_policy::{CallerFacts, Decision};
use aido_sys::{Clock, Connection, Entropy, PeerCalls, Spool, SpoolError, Syscalls};
use aido_wire::{BrokerRequest, BrokerResponse, MAX_REQUEST_BYTES, Minted, RefusalCode};

use crate::identify::{Fault, PeerIdentity, identify};
use crate::mint::{Minting, REQUEST_TTL_SECS, draw_nonce, entry_for, publish};
use crate::policy::{LoadedPolicy, PolicySource, classify, decide};
use crate::record::{decided, emit, refused};
use crate::refusal::Refusal;

/// The exit status of a broker that could not do its job: `aido`'s own
/// "unusable", 19.
pub const UNUSABLE: u8 = 19;

/// Everything the broker asks of its host, as seams.
pub struct Platform<'a> {
    /// The calls that need `unsafe` and that the ladder makes itself:
    /// `SO_PEERPIDFD` and `PIDFD_GET_INFO`.
    pub syscalls: &'a dyn Syscalls,
    /// `pidfd_open`, `/proc`, and the liveness poll, which are safe in rustix,
    /// and `SO_PEERCRED`, which is not and is carried here only as a seam: the
    /// host reads it through `Syscalls::peer_cred`, behind a check of the
    /// socket's kind, and never through rustix's own decode.
    pub peers: &'a dyn PeerCalls,
    /// `CLOCK_MONOTONIC`, for deadlines.
    pub clock: &'a dyn Clock,
    /// The random source nonces are drawn from.
    pub entropy: &'a dyn Entropy,
    /// Root's ruleset and settings.
    pub policy: &'a dyn PolicySource,
    /// Whether the audit trail is attested: `Ok` when standard error is a
    /// connection to the journal, or the reason it is not.
    ///
    /// systemd points standard error at `/dev/null` when it cannot reach the
    /// journal, and the runtime does the same for a closed descriptor, so a
    /// write to either succeeds and goes nowhere. Nothing is minted unless
    /// this is `Ok`; a refusal needs no trail and is answered either way.
    pub trail: Result<(), String>,
}

/// How a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Served {
    /// An entry was minted and the client told so.
    Minted,
    /// The policy decided against the request and the client was told.
    Decided,
    /// The broker refused and the client was told.
    Refused(Fault),
    /// The answer could not be delivered: the client went away, or stopped
    /// reading until the send timeout fired.
    Undelivered,
}

impl Served {
    /// The exit status for systemd.
    ///
    /// Zero whenever the broker did its job, whatever it decided — a denial,
    /// a client's malformed request, or a client that left before its answer
    /// is not the broker failing. Non-zero only when the broker or its host is
    /// broken, so that what systemd records as a failure is something an
    /// administrator must look at, and a client cannot manufacture one.
    pub fn exit_status(self) -> u8 {
        match self {
            Self::Minted | Self::Decided | Self::Refused(Fault::Client) | Self::Undelivered => 0,
            Self::Refused(Fault::Broker) => UNUSABLE,
        }
    }
}

/// What a permitted request has established by the time it is minted.
struct Evaluated {
    decision: Decision,
    caller: CallerFacts,
    identity: PeerIdentity,
    request: BrokerRequest,
    policy: LoadedPolicy,
}

/// Serves one connection: identifies, reads, decides, mints, answers.
///
/// `spool` is the result of opening the spool, opened before the connection
/// is served and refused only once the request is known.
pub fn serve<S: Spool>(
    conn: &dyn Connection,
    platform: &Platform<'_>,
    spool: Result<&S, &SpoolError>,
    log: &mut dyn Write,
) -> Served {
    let identity = match identify(conn.socket(), platform.syscalls, platform.peers) {
        Ok(identity) => identity,
        Err(error) => return refuse(conn, log, &Refusal::from(&error), None, None),
    };
    let request = match receive(conn) {
        Ok(request) => request,
        Err(refusal) => return refuse(conn, log, &refusal, Some(&identity), None),
    };
    let spool = match spool {
        Ok(spool) => spool,
        Err(error) => {
            return refuse(
                conn,
                log,
                &Refusal::from(error),
                Some(&identity),
                Some(&request),
            );
        }
    };
    let policy = match platform.policy.load() {
        Ok(policy) => policy,
        Err(error) => {
            return refuse(
                conn,
                log,
                &Refusal::from(&error),
                Some(&identity),
                Some(&request),
            );
        }
    };

    let caller = classify(&identity);
    let decision = decide(&policy, &caller, &request);
    if !decision.verdict.is_permitted() {
        // Nothing is enabled by this record, so a sink that cannot take it
        // does not change the answer.
        let _ = emit(
            &decided(
                &decision,
                &caller,
                &identity,
                &request,
                &policy.rules.generation,
                None,
            ),
            log,
        );
        return answer(
            conn,
            &BrokerResponse::decided(decision, None),
            Served::Decided,
        );
    }
    mint(
        conn,
        platform,
        spool,
        log,
        Evaluated {
            decision,
            caller,
            identity,
            request,
            policy,
        },
    )
}

/// Reads and parses the request.
fn receive(conn: &dyn Connection) -> Result<BrokerRequest, Refusal> {
    let bytes = conn
        .read_request(MAX_REQUEST_BYTES)
        .map_err(|error| Refusal::from(&error))?;
    BrokerRequest::parse(&bytes).map_err(|error| Refusal::from(&error))
}

/// Mints the entry for a permitted decision and answers with it.
fn mint<S: Spool>(
    conn: &dyn Connection,
    platform: &Platform<'_>,
    spool: &S,
    log: &mut dyn Write,
    evaluated: Evaluated,
) -> Served {
    let Evaluated {
        decision,
        caller,
        identity,
        request,
        policy,
    } = evaluated;
    let known = (Some(&identity), Some(&request));

    if let Err(why) = &platform.trail {
        let refusal = Refusal::broker(
            RefusalCode::BrokerUnusable,
            format!(
                "standard error is not a connection to the journal ({why}), so nothing was minted"
            ),
        );
        return refuse(conn, log, &refusal, known.0, known.1);
    }

    let nonce = match draw_nonce(platform.entropy) {
        Ok(nonce) => nonce,
        Err(error) => {
            let refusal = Refusal::broker(
                RefusalCode::BrokerUnusable,
                format!("cannot draw a nonce: {error}"),
            );
            return refuse(conn, log, &refusal, known.0, known.1);
        }
    };
    let now = platform.clock.monotonic_secs();
    let deadline = now.saturating_add(REQUEST_TTL_SECS);
    let entry = match entry_for(
        &decision,
        &identity,
        &request,
        policy.rules.generation.id(),
        deadline,
        nonce,
    ) {
        Ok(entry) => entry,
        Err(error) => return refuse(conn, log, &Refusal::from(&error), known.0, known.1),
    };

    // Recorded before the entry exists: nothing is minted that the trail does
    // not show.
    let record = decided(
        &decision,
        &caller,
        &identity,
        &request,
        &policy.rules.generation,
        Some(&entry),
    );
    if emit(&record, log).is_err() {
        let refusal = Refusal::broker(
            RefusalCode::BrokerUnusable,
            "the audit record could not be written, so nothing was minted",
        );
        return refuse(conn, log, &refusal, known.0, known.1);
    }
    let json = entry.to_json();
    let minting = Minting {
        entry: &entry,
        json: &json,
        uid: identity.uid,
        now,
    };
    if let Err(error) = publish(spool, platform.peers, &minting) {
        return refuse(conn, log, &Refusal::from(&error), known.0, known.1);
    }

    let minted = Minted {
        nonce: entry.nonce,
        deadline,
        ttl_secs: REQUEST_TTL_SECS,
        gate: aido_backend::snippet::GATE_AUTH.to_owned(),
    };
    answer(
        conn,
        &BrokerResponse::decided(decision, Some(minted)),
        Served::Minted,
    )
}

/// Records a refusal and sends it.
fn refuse(
    conn: &dyn Connection,
    log: &mut dyn Write,
    refusal: &Refusal,
    identity: Option<&PeerIdentity>,
    request: Option<&BrokerRequest>,
) -> Served {
    let _ = emit(&refused(refusal, identity, request), log);
    answer(
        conn,
        &BrokerResponse::refused(refusal.code),
        Served::Refused(refusal.fault),
    )
}

/// Sends the response, reporting `served` if it arrived.
///
/// A broker fault stays one whether or not the client heard about it: the
/// client leaving does not make a broken spool any less broken.
fn answer(conn: &dyn Connection, response: &BrokerResponse, served: Served) -> Served {
    match conn.write_response(response.to_json().as_bytes()) {
        Ok(()) => served,
        Err(_) if served == Served::Refused(Fault::Broker) => served,
        Err(_) => Served::Undelivered,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use std::cell::Cell;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use aido_audit::record::{Decision as AuditDecision, Record};
    use aido_gate::request::{MonotonicSecs, PendingRequest};
    use aido_policy::{DenialCode, RuleFile, Verdict, load_rule_files};
    use aido_sys::{
        Creds, FakeConnection, FakeEntropy, FakePeer, FakeSpool, FakeSyscalls, FixedClock,
        PeerCred, PidfdInfo, ProcFile, ProcessIds, ReadFailure, SpoolCall, SysError,
    };
    use aido_wire::{Answer, WIRE_SCHEMA_VERSION};

    use super::*;
    use crate::mint::{MAX_SPOOL_ENTRIES, MintError};
    use crate::policy::PolicyError;

    const PID: u32 = 4242;
    const UID: u32 = 1000;
    const GID: u32 = 100;
    const START: u64 = 998_877;
    const NOW: u64 = 10_000;

    /// Three rules: one that runs freely, one that always confirms, and one a
    /// careless operator wrote for a shell.
    const RULES: &str = r#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "aido.pkg.remove"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [
  { name = "assume-yes", matcher = { literal = "-y" } },
  { name = "verb", matcher = { literal = "remove" } },
  { name = "pkg", matcher = { one-of = ["gcc"] } },
]

[[action]]
id = "aido.oops.shell"
tier = "diag-read"
exe = "/bin/sh"
args = [{ name = "c", matcher = { literal = "-c" } }]
"#;

    fn policy() -> LoadedPolicy {
        LoadedPolicy {
            rules: load_rule_files(vec![RuleFile {
                name: b"10-test.toml".to_vec(),
                bytes: RULES.as_bytes().to_vec(),
            }])
            .unwrap(),
            settings: aido_policy::engine::Settings::default(),
        }
    }

    /// Root's policy, fixed, counting how often it was asked for.
    struct FixedPolicy {
        answer: Result<LoadedPolicy, PolicyError>,
        loads: Cell<u32>,
    }

    impl PolicySource for FixedPolicy {
        fn load(&self) -> Result<LoadedPolicy, PolicyError> {
            self.loads.set(self.loads.get() + 1);
            self.answer.clone()
        }
    }

    /// A log that refuses every write: a journal that has gone away.
    struct Refusing;

    impl Write for Refusing {
        fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("the journal is gone"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Everything the broker asks of its host, faked: by default a peer that
    /// identifies honestly on the top rung, a fixed clock, one scripted
    /// nonce, and the test ruleset.
    struct Host {
        syscalls: FakeSyscalls,
        peers: FakePeer,
        clock: FixedClock,
        entropy: FakeEntropy,
        policy: FixedPolicy,
        trail: Result<(), String>,
    }

    impl Host {
        fn honest() -> Self {
            let record = PidfdInfo::empty()
                .with_ids(ProcessIds {
                    pid: PID,
                    tgid: PID,
                    ppid: 1,
                })
                .with_creds(Creds {
                    ruid: UID,
                    rgid: GID,
                    euid: UID,
                    egid: GID,
                    suid: UID,
                    sgid: GID,
                    fsuid: UID,
                    fsgid: GID,
                });
            Self {
                syscalls: FakeSyscalls::new()
                    .with_peer(Ok(a_descriptor()))
                    .with_info(Ok(record)),
                peers: FakePeer::new()
                    .with_cred(Ok(PeerCred {
                        pid: PID,
                        uid: UID,
                        gid: GID,
                    }))
                    .with_stat(Ok(stat_line(PID, START)))
                    .with_exit(Ok(false)),
                clock: FixedClock(NOW),
                entropy: FakeEntropy::new().with(Ok(vec![0xab; 32])),
                policy: FixedPolicy {
                    answer: Ok(policy()),
                    loads: Cell::new(0),
                },
                trail: Ok(()),
            }
        }

        fn platform(&self) -> Platform<'_> {
            Platform {
                syscalls: &self.syscalls,
                peers: &self.peers,
                clock: &self.clock,
                entropy: &self.entropy,
                policy: &self.policy,
                trail: self.trail.clone(),
            }
        }
    }

    /// Any descriptor: the fakes are handed it and never look at it.
    fn a_descriptor() -> OwnedFd {
        OwnedFd::from(UnixStream::pair().unwrap().0)
    }

    fn stat_line(pid: u32, starttime: u64) -> Vec<u8> {
        let mut tail: Vec<String> = vec!["S".into(), "1".into()];
        tail.extend(std::iter::repeat_n("0".to_owned(), 17));
        tail.push(starttime.to_string());
        format!("{pid} (aido) {}", tail.join(" ")).into_bytes()
    }

    fn connection(request: Result<Vec<u8>, ReadFailure>) -> FakeConnection {
        FakeConnection::new(a_descriptor(), request)
    }

    fn asking(program: &str, argv: &[&str]) -> FakeConnection {
        let request = BrokerRequest::new(
            program,
            argv.iter().map(|a| (*a).to_owned()).collect(),
            "enrolled-agent-yolo",
        );
        connection(Ok(request.to_json().into_bytes()))
    }

    fn restart() -> FakeConnection {
        asking("/usr/bin/systemctl", &["restart", "nginx.service"])
    }

    const NONCE: &str = "abababababababababababababababababababababababababababababababab";

    /// What one connection produced: how it ended, the answer the client
    /// read, and the audit records, one per line.
    struct Outcome {
        served: Served,
        answer: Answer,
        records: Vec<Record>,
    }

    fn serve_with(
        host: &Host,
        conn: &FakeConnection,
        spool: Result<&FakeSpool, &SpoolError>,
    ) -> Outcome {
        let mut log = Vec::new();
        let served = serve(conn, &host.platform(), spool, &mut log);
        let response = BrokerResponse::parse(&conn.written()).unwrap();
        assert_eq!(response.schema_version, WIRE_SCHEMA_VERSION);
        let records = String::from_utf8(log)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        Outcome {
            served,
            answer: response.answer,
            records,
        }
    }

    fn refusal_of(answer: &Answer) -> Option<RefusalCode> {
        match answer {
            Answer::Refused { code, .. } => Some(*code),
            Answer::Decided { .. } => None,
        }
    }

    fn decision_of(answer: &Answer) -> Option<(&Decision, Option<&Minted>)> {
        match answer {
            Answer::Decided { decision, minted } => Some((decision, minted.as_ref())),
            Answer::Refused { .. } => None,
        }
    }

    fn entry_in(spool: &FakeSpool) -> PendingRequest {
        let files = spool.files();
        PendingRequest::parse(std::str::from_utf8(&files[NONCE.as_bytes()]).unwrap()).unwrap()
    }

    #[test]
    fn a_permitted_request_is_minted_for_the_peer_the_kernel_named() {
        let host = Host::honest();
        let spool = FakeSpool::new();
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Minted);
        assert_eq!(outcome.served.exit_status(), 0);
        assert_eq!(refusal_of(&outcome.answer), None);

        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(
            minted,
            Some(&Minted {
                nonce: NONCE.to_owned(),
                deadline: NOW + REQUEST_TTL_SECS,
                ttl_secs: REQUEST_TTL_SECS,
                gate: "/usr/libexec/aido/aido-gate-auth".to_owned(),
            })
        );

        // The entry the gate will read: bound to the pin from the kernel, the
        // question as asked, the generation of the rules decided under.
        let entry = entry_in(&spool);
        assert_eq!((entry.caller_pid, entry.caller_starttime), (PID, START));
        assert_eq!(entry.action, "aido.svc.restart");
        assert_eq!(entry.program, "/usr/bin/systemctl");
        assert_eq!(entry.argv, ["restart", "nginx.service"]);
        assert_eq!(entry.generation, policy().rules.generation.id());
        assert_eq!(entry.deadline, MonotonicSecs(NOW + REQUEST_TTL_SECS));
        assert!(!entry.confirmed);
        assert_eq!(
            spool.calls(),
            [
                SpoolCall::Lock,
                SpoolCall::Names,
                SpoolCall::Publish(NONCE.to_owned()),
                SpoolCall::Unlock
            ]
        );

        // One record, written before the entry existed, naming the nonce.
        assert_eq!(outcome.records.len(), 1);
        let record = &outcome.records[0];
        assert_eq!(record.decision, AuditDecision::Allowed);
        assert!(record.evidence.contains(&format!("nonce={NONCE}")));
        assert!(record.evidence.contains(&format!("peer_pid={PID}")));
    }

    #[test]
    fn the_claimed_classification_is_recorded_and_changes_nothing() {
        // Invariant 1 at the broker: the request claimed to be a yolo agent;
        // the broker classified it from kernel facts, as unattested, and
        // routed it to the password path regardless.
        let host = Host::honest();
        let spool = FakeSpool::new();
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        let entry = entry_in(&spool);
        assert_eq!(entry.claimed_classification, "enrolled-agent-yolo");
        let record = &outcome.records[0];
        assert_eq!(record.classification, "unattested");
        assert!(
            record
                .evidence
                .contains(&"claimed_classification=enrolled-agent-yolo".to_owned())
        );
        let (_, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(minted.unwrap().gate, aido_backend::snippet::GATE_AUTH);
    }

    #[test]
    fn a_rule_that_demands_confirmation_still_mints_and_the_password_confirms() {
        let host = Host::honest();
        let spool = FakeSpool::new();
        let outcome = serve_with(
            &host,
            &asking("/usr/bin/apt-get", &["-y", "remove", "gcc"]),
            Ok(&spool),
        );
        assert_eq!(outcome.served, Served::Minted);
        let (decision, minted) = decision_of(&outcome.answer).unwrap();
        assert_eq!(decision.verdict, Verdict::AllowWithConfirmation);
        assert!(minted.is_some());
        let entry = entry_in(&spool);
        assert!(
            !entry.confirmed,
            "no channel confirmed it; sudo's password will"
        );
        assert_eq!(entry.confirmed_by, None);
        assert_eq!(
            outcome.records[0].decision,
            AuditDecision::AwaitingConfirmation
        );
    }

    #[test]
    fn denied_requests_mint_nothing_and_never_touch_the_spool() {
        // A program no rule runs, an operand the rule rejects, and a shell a
        // rule allows but the compiled-in deny-list refuses.
        for (program, argv, denial) in [
            ("/usr/bin/rm", &["-rf", "/"][..], DenialCode::UnknownAction),
            (
                "/usr/bin/systemctl",
                &["restart", "../../evil"][..],
                DenialCode::ArgvRejected,
            ),
            ("/bin/sh", &["-c"][..], DenialCode::DenyListed),
        ] {
            let host = Host::honest();
            let spool = FakeSpool::new();
            let outcome = serve_with(&host, &asking(program, argv), Ok(&spool));
            assert_eq!(outcome.served, Served::Decided, "{program}");
            assert_eq!(outcome.served.exit_status(), 0);
            let (decision, minted) = decision_of(&outcome.answer).unwrap();
            assert_eq!(decision.denial, Some(denial), "{program}");
            assert_eq!(minted, None);
            assert_eq!(spool.calls(), [], "{program}");
            assert_eq!(outcome.records.len(), 1);
            assert_eq!(outcome.records[0].denial.as_deref(), Some(denial.as_str()));
        }
    }

    #[test]
    fn a_peer_that_cannot_be_identified_is_refused_before_its_request_is_read() {
        // No credentials at all: the host cannot say who asked.
        let mut host = Host::honest();
        host.peers = FakePeer::new();
        let spool = FakeSpool::new();
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(outcome.served.exit_status(), UNUSABLE);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PeerUnidentified)
        );
        assert_eq!(decision_of(&outcome.answer), None);
        assert_eq!(host.policy.loads.get(), 0);
        assert_eq!(spool.calls(), []);
        // The record carries no request: none was read.
        assert!(outcome.records[0].argv.is_empty());
    }

    #[test]
    fn a_peer_the_kernel_reports_as_pid_zero_is_never_minted_for() {
        // SO_PEERCRED names pid 0 for a peer outside the broker's pid
        // namespace. Every other answer is scripted to agree with it — a
        // pidfd, no kernel record to contradict it, a /proc entry for "pid 0"
        // — so that the refusal in `identify` is all that stands between this
        // peer and a request that is read, decided, and minted.
        let mut host = Host::honest();
        host.syscalls = FakeSyscalls::new()
            .with_peer(Ok(a_descriptor()))
            .with_info(Err(SysError::os(
                "ioctl(PIDFD_GET_INFO)",
                &rustix::io::Errno::NOTTY.into(),
            )));
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: 0,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(0, START)))
            .with_status(Ok(
                format!("Uid:\t{UID}\t{UID}\t{UID}\t{UID}\n").into_bytes()
            ))
            .with_exit(Ok(false));
        let spool = FakeSpool::new();
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PeerUnidentified)
        );
        assert_eq!(decision_of(&outcome.answer), None);
        // Nothing was read, decided, or written: the policy was never loaded
        // and the spool never touched, and the record carries no request.
        assert_eq!(host.policy.loads.get(), 0);
        assert_eq!(spool.calls(), []);
        assert!(outcome.records[0].argv.is_empty());
        assert_eq!(
            outcome.records[0].denial.as_deref(),
            Some("peer_unidentified")
        );
        let evidence = &outcome.records[0].evidence;
        assert!(
            evidence.iter().any(|e| e.contains("pid is 0")),
            "{evidence:?}"
        );
        assert!(!evidence.iter().any(|e| e.starts_with("peer_pid=")));
    }

    #[test]
    fn a_peer_that_exits_mid_identification_is_refused_as_its_own_doing() {
        let mut host = Host::honest();
        host.peers = FakePeer::new()
            .with_cred(Ok(PeerCred {
                pid: PID,
                uid: UID,
                gid: GID,
            }))
            .with_stat(Ok(stat_line(PID, START)))
            .with_exit(Ok(true));
        let outcome = serve_with(&host, &restart(), Ok(&FakeSpool::new()));
        assert_eq!(outcome.served, Served::Refused(Fault::Client));
        assert_eq!(outcome.served.exit_status(), 0);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PeerUnidentified)
        );
        let evidence = &outcome.records[0].evidence;
        assert!(
            evidence.iter().any(|e| e.contains("exited")),
            "{evidence:?}"
        );
    }

    #[test]
    fn a_request_that_cannot_be_read_is_refused_as_the_clients_fault() {
        for (failure, code) in [
            (
                ReadFailure::TooLarge { limit: 1 },
                RefusalCode::RequestTooLarge,
            ),
            (ReadFailure::TimedOut, RefusalCode::RequestTimedOut),
            (
                ReadFailure::Os(SysError::unsupported("reset")),
                RefusalCode::RequestUnreadable,
            ),
        ] {
            let host = Host::honest();
            let outcome = serve_with(&host, &connection(Err(failure)), Ok(&FakeSpool::new()));
            assert_eq!(outcome.served, Served::Refused(Fault::Client));
            assert_eq!(refusal_of(&outcome.answer), Some(code));
            assert_eq!(host.policy.loads.get(), 0);
            // The peer was identified, so the record says who it was.
            assert!(
                outcome.records[0]
                    .evidence
                    .contains(&format!("peer_pid={PID}"))
            );
        }
    }

    #[test]
    fn a_request_one_byte_over_the_limit_is_refused_without_being_parsed() {
        let host = Host::honest();
        let over = vec![b' '; MAX_REQUEST_BYTES + 1];
        let outcome = serve_with(&host, &connection(Ok(over)), Ok(&FakeSpool::new()));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::RequestTooLarge)
        );
    }

    #[test]
    fn a_malformed_request_is_refused_before_policy_or_spool_is_consulted() {
        let valid = BrokerRequest::new("/usr/bin/systemctl", vec!["restart".to_owned()], "x");
        let mut unknown: serde_json::Value = serde_json::from_str(&valid.to_json()).unwrap();
        unknown["skip_confirmation"] = serde_json::Value::Bool(true);
        let mut future = valid.clone();
        future.schema_version = WIRE_SCHEMA_VERSION + 1;
        let mut relative = valid.clone();
        relative.program = "systemctl".to_owned();
        let mut nul = valid.clone();
        nul.argv = vec!["restart\0--force".to_owned()];
        let mut not_utf8 =
            br#"{"schema_version":1,"program":"/usr/bin/systemctl","argv":[""#.to_vec();
        not_utf8.extend_from_slice(b"\xff\"],\"claimed_classification\":\"x\"}");

        for (bytes, code) in [
            (b"restart nginx".to_vec(), RefusalCode::RequestMalformed),
            (not_utf8, RefusalCode::RequestNotUtf8),
            (
                unknown.to_string().into_bytes(),
                RefusalCode::RequestMalformed,
            ),
            (
                future.to_json().into_bytes(),
                RefusalCode::RequestWrongSchema,
            ),
            (
                relative.to_json().into_bytes(),
                RefusalCode::ProgramNotAbsolute,
            ),
            (nul.to_json().into_bytes(), RefusalCode::InteriorNul),
        ] {
            let host = Host::honest();
            let spool = FakeSpool::new();
            let outcome = serve_with(&host, &connection(Ok(bytes)), Ok(&spool));
            assert_eq!(outcome.served, Served::Refused(Fault::Client), "{code:?}");
            assert_eq!(refusal_of(&outcome.answer), Some(code));
            assert_eq!(host.policy.loads.get(), 0, "{code:?}");
            assert_eq!(spool.calls(), [], "{code:?}");
        }
    }

    #[test]
    fn a_spool_that_failed_its_checks_refuses_every_request() {
        let host = Host::honest();
        let untrusted = SpoolError::NotOwned {
            at: "/run/aido/req".to_owned(),
            uid: 1000,
        };
        let outcome = serve_with(&host, &restart(), Err(&untrusted));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(outcome.served.exit_status(), UNUSABLE);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );
        assert_eq!(host.policy.loads.get(), 0);
        // The detail is root's to read, not the client's.
        let record = &outcome.records[0];
        assert!(record.evidence.iter().any(|e| e.contains("uid 1000")));
        assert_eq!(
            record.argv,
            ["/usr/bin/systemctl", "restart", "nginx.service"]
        );
    }

    #[test]
    fn a_policy_that_cannot_be_loaded_refuses_rather_than_deciding() {
        let mut host = Host::honest();
        host.policy.answer = Err(PolicyError::ConfigNotUtf8 {
            file: "/etc/aido/config.toml".to_owned(),
        });
        let spool = FakeSpool::new();
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::PolicyUnloadable)
        );
        assert_eq!(spool.calls(), []);
    }

    #[test]
    fn no_nonce_means_no_entry() {
        let mut host = Host::honest();
        host.entropy = FakeEntropy::new().with(Err(SysError::unsupported("getrandom")));
        let spool = FakeSpool::new();
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::BrokerUnusable)
        );
        assert_eq!(spool.calls(), []);
        assert!(
            outcome.records[0]
                .evidence
                .iter()
                .any(|e| e.contains("cannot draw a nonce"))
        );
    }

    /// A live entry for another caller, under [`NONCE`].
    fn someone_elses_entry() -> PendingRequest {
        PendingRequest {
            schema_version: aido_gate::request::REQUEST_SCHEMA_VERSION,
            nonce: NONCE.to_owned(),
            caller_pid: 7,
            caller_starttime: 7,
            action: "aido.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "cron.service".to_owned()],
            generation: 1,
            deadline: MonotonicSecs(NOW + 60),
            confirmed: false,
            confirmed_by: None,
            claimed_classification: "unattested".to_owned(),
        }
    }

    /// Makes `entry`'s caller a running process of uid `uid`.
    fn running(host: &mut Host, entry: &PendingRequest, uid: u32) {
        let (pid, start) = (entry.caller_pid, entry.caller_starttime);
        host.peers = std::mem::take(&mut host.peers)
            .with_proc(pid, ProcFile::Stat, stat_line(pid, start))
            .with_proc(
                pid,
                ProcFile::Status,
                format!("Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            );
    }

    #[test]
    fn nothing_is_minted_when_standard_error_does_not_reach_the_journal() {
        // systemd points a service at /dev/null when it cannot reach the
        // journal; every audit write then succeeds and records nothing.
        let mut host = Host::honest();
        host.trail = Err("not a socket".to_owned());
        let spool = FakeSpool::new();
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(outcome.served.exit_status(), UNUSABLE);
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::BrokerUnusable)
        );
        assert_eq!(spool.calls(), [], "no entry, and no lock taken for one");
        assert!(spool.files().is_empty());
        let detail = outcome.records.last().unwrap().evidence.join(" ");
        assert!(detail.contains("not a socket"), "{detail}");
    }

    #[test]
    fn a_denial_is_answered_even_when_there_is_no_trail_to_write() {
        let mut host = Host::honest();
        host.trail = Err("not a socket".to_owned());
        let outcome = serve_with(
            &host,
            &connection(Ok(BrokerRequest::new("/bin/sh", Vec::new(), "unattested")
                .to_json()
                .into_bytes())),
            Ok(&FakeSpool::new()),
        );
        assert_eq!(outcome.served, Served::Decided);
    }

    #[test]
    fn a_colliding_nonce_is_refused_and_never_overwrites_a_pending_request() {
        let theirs = someone_elses_entry();
        let mut host = Host::honest();
        running(&mut host, &theirs, UID + 1);
        let spool = FakeSpool::new().with_file(NONCE, theirs.to_json());
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Refused(Fault::Broker));
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::NonceCollision)
        );
        assert_eq!(entry_in(&spool), theirs);
        // The decision was recorded before minting was attempted, and the
        // refusal after it, so the trail shows both.
        assert_eq!(outcome.records.len(), 2);
        assert_eq!(
            outcome.records[1].denial.as_deref(),
            Some("nonce_collision")
        );
    }

    #[test]
    fn a_full_spool_refuses_instead_of_growing() {
        let mut spool = FakeSpool::new();
        let mut host = Host::honest();
        for index in 0..MAX_SPOOL_ENTRIES {
            let mut live = someone_elses_entry();
            live.nonce = format!("{:064x}", index + 1);
            live.caller_pid = 10_000 + u32::try_from(index).unwrap();
            spool = spool.with_file(live.nonce.clone(), live.to_json());
            // Eight callers a uid: the spool is full of everyone, not of one.
            running(
                &mut host,
                &live,
                UID + 1 + u32::try_from(index.div_euclid(8)).unwrap(),
            );
        }
        let outcome = serve_with(&host, &restart(), Ok(&spool));
        assert_eq!(refusal_of(&outcome.answer), Some(RefusalCode::SpoolFull));
        // Other clients filled it; the broker refusing to grow it is the
        // broker working, so systemd is not told it failed.
        assert_eq!(outcome.served, Served::Refused(Fault::Client));
        assert_eq!(outcome.served.exit_status(), 0);
    }

    #[test]
    fn sixty_four_clients_that_ran_and_exited_cannot_lock_another_user_out() {
        // The review's attack: one user runs 64 clients one after another,
        // each gone before the next starts. The host shows none of them.
        let mut spool = FakeSpool::new();
        for index in 0..MAX_SPOOL_ENTRIES {
            let mut gone = someone_elses_entry();
            gone.nonce = format!("{:064x}", index + 1);
            gone.caller_pid = 10_000 + u32::try_from(index).unwrap();
            spool = spool.with_file(gone.nonce.clone(), gone.to_json());
        }
        let outcome = serve_with(&Host::honest(), &restart(), Ok(&spool));
        assert_eq!(outcome.served, Served::Minted);
        assert_eq!(spool.files().len(), 1);
    }

    #[test]
    fn a_client_that_connects_and_exits_cannot_make_the_broker_report_itself_broken() {
        // A review connected and exited three times and got three instances
        // that exited 19 with fault=broker: SO_PEERPIDFD refuses a reaped peer
        // with EINVAL on 6.5 to 6.15; from 6.16 PIDFD_GET_INFO answers ESRCH;
        // on the pidfd_open rung, pidfd_open answers ESRCH. Each is the peer
        // leaving.
        let gone = |operation: &str, code: rustix::io::Errno| SysError::os(operation, &code.into());
        let reaped_before_so_peerpidfd = FakeSyscalls::new().with_peer(Err(gone(
            "getsockopt(SO_PEERPIDFD)",
            rustix::io::Errno::INVAL,
        )));
        let outlived_by_its_pidfd = FakeSyscalls::new()
            .with_peer(Ok(a_descriptor()))
            .with_info(Err(gone("ioctl(PIDFD_GET_INFO)", rustix::io::Errno::SRCH)));
        let gone_before_pidfd_open = FakeSyscalls::new().with_peer(Err(gone(
            "getsockopt(SO_PEERPIDFD)",
            rustix::io::Errno::NOPROTOOPT,
        )));
        for syscalls in [
            reaped_before_so_peerpidfd,
            outlived_by_its_pidfd,
            gone_before_pidfd_open,
        ] {
            let mut host = Host::honest();
            host.syscalls = syscalls;
            host.peers = FakePeer::new()
                .with_cred(Ok(PeerCred {
                    pid: PID,
                    uid: UID,
                    gid: GID,
                }))
                .with_open(Err(gone("pidfd_open", rustix::io::Errno::SRCH)));
            let outcome = serve_with(&host, &restart(), Ok(&FakeSpool::new()));
            assert_eq!(
                refusal_of(&outcome.answer),
                Some(RefusalCode::PeerUnidentified)
            );
            assert_eq!(outcome.served, Served::Refused(Fault::Client));
            assert_eq!(outcome.served.exit_status(), 0);
            assert!(
                outcome.records[0]
                    .evidence
                    .contains(&"fault=client".to_owned())
            );
        }
    }

    #[test]
    fn a_spool_that_fails_while_publishing_is_refused() {
        let host = Host::honest();
        let broken = SpoolError::Io {
            operation: "publish".to_owned(),
            at: "/run/aido/req".to_owned(),
            code: None,
            reason: "no space left on device".to_owned(),
        };
        let outcome = serve_with(
            &host,
            &restart(),
            Ok(&FakeSpool::new().failing_publish(broken)),
        );
        assert_eq!(
            refusal_of(&outcome.answer),
            Some(RefusalCode::SpoolUnusable)
        );
    }

    #[test]
    fn nothing_is_minted_whose_audit_record_cannot_be_written() {
        let host = Host::honest();
        let conn = restart();
        let spool = FakeSpool::new();
        let served = serve(&conn, &host.platform(), Ok(&spool), &mut Refusing);
        assert_eq!(served, Served::Refused(Fault::Broker));
        assert_eq!(spool.calls(), [], "no entry without its record");
        let answer = BrokerResponse::parse(&conn.written()).unwrap().answer;
        assert_eq!(refusal_of(&answer), Some(RefusalCode::BrokerUnusable));
        assert!(Refusing.flush().is_ok());
    }

    #[test]
    fn a_client_that_leaves_before_its_answer_cannot_make_the_broker_fail() {
        // Minted or refused for its own fault, a client that went away is not
        // the broker failing: if it were, any group member could fill
        // systemd's record of failed units by hanging up.
        for conn in [restart(), connection(Err(ReadFailure::TimedOut))] {
            let host = Host::honest();
            let conn = conn.with_write_error(SysError::unsupported("peer gone"));
            let mut log = Vec::new();
            let served = serve(&conn, &host.platform(), Ok(&FakeSpool::new()), &mut log);
            assert_eq!(served, Served::Undelivered);
            assert_eq!(served.exit_status(), 0);
            // It was still recorded.
            assert!(!log.is_empty());
        }
    }

    #[test]
    fn a_broken_broker_still_fails_when_its_client_has_left() {
        let host = Host::honest();
        let conn = restart().with_write_error(SysError::unsupported("peer gone"));
        let untrusted = SpoolError::NotADirectory {
            at: "/run/aido/req".to_owned(),
        };
        let mut log = Vec::new();
        let served = serve::<FakeSpool>(&conn, &host.platform(), Err(&untrusted), &mut log);
        assert_eq!(served, Served::Refused(Fault::Broker));
        assert_eq!(served.exit_status(), UNUSABLE);
    }

    #[test]
    fn a_permitted_decision_that_names_no_action_is_refused_not_minted() {
        // The engine never produces one; if it ever did, the gate would have
        // no action to look up, so the broker refuses rather than guessing.
        let host = Host::honest();
        let conn = restart();
        let spool = FakeSpool::new();
        let mut decision = Decision::deny(DenialCode::UnknownAction, Vec::new(), Vec::new());
        decision.verdict = Verdict::Allow;
        decision.denial = None;
        let request = BrokerRequest::new("/usr/bin/systemctl", Vec::new(), "x");
        let identity = identify(conn.socket(), &host.syscalls, &host.peers).unwrap();
        let evaluated = Evaluated {
            caller: crate::policy::classify(&identity),
            decision,
            identity,
            request,
            policy: policy(),
        };
        let mut log = Vec::new();
        let served = mint(&conn, &host.platform(), &spool, &mut log, evaluated);
        assert_eq!(served, Served::Refused(Fault::Broker));
        assert_eq!(spool.calls(), []);
        let answer = BrokerResponse::parse(&conn.written()).unwrap().answer;
        assert_eq!(refusal_of(&answer), Some(RefusalCode::BrokerUnusable));
        assert!(
            String::from_utf8(log)
                .unwrap()
                .contains(&MintError::NoAction.to_string())
        );
    }

    #[test]
    fn the_exit_status_separates_a_broken_broker_from_a_refused_client() {
        assert_eq!(Served::Minted.exit_status(), 0);
        assert_eq!(Served::Decided.exit_status(), 0);
        assert_eq!(Served::Refused(Fault::Client).exit_status(), 0);
        assert_eq!(Served::Refused(Fault::Broker).exit_status(), UNUSABLE);
        assert_eq!(Served::Undelivered.exit_status(), 0);
    }
}
