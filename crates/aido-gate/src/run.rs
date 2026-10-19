//! The gate's whole sequence, written against traits.
//!
//! `aido-gate-bin` is five lines: it collects `argv`, hands it to [`run`] with
//! the real host, and exits with the status that comes back. Everything the
//! gate does is here, in the order it does it, so that each step is a place a
//! test can make fail and see that nothing after it ran.
//!
//! # The order, and why each step is where it is
//!
//! 1. **`close_range(3, ~0, CLOEXEC)`.** First, before the gate opens anything
//!    of its own: whatever `sudo` or the caller leaked above descriptor 2 is
//!    marked to close at the exec, so the child inherits none of it. On a
//!    kernel before 5.11 the call is refused and so is the gate; marking each
//!    descriptor by hand would be another `unsafe` block, and a pre-5.11 host
//!    is not one the beta supports.
//! 2. **`/dev/null` for closed 0 to 2.** Before the first `open`, which would
//!    otherwise take a closed descriptor's number and make the audit log the
//!    gate's standard error.
//! 3. **`PR_SET_NO_NEW_PRIVS`.** Irreversible and inherited by the exec, so
//!    nothing the gate runs gains privilege from a set-user-ID or
//!    file-capability binary. Set before anything is consumed, so a host that
//!    refuses costs the caller nothing.
//! 4. **The invocation.** No arguments, and `argv[0]` is the `-auth` name.
//!    `aido-gate-nopass` is not shipped until M4, so any other name is refused.
//! 5. **`/proc` verified as procfs**, on the descriptor it is read through.
//! 6. **The lineage walk**: the gate, `sudo` or `sudo-rs` (with its `use_pty`
//!    monitor) or `doas`, and then the `aido` process that asked, each pinned
//!    by `(pid, starttime)`, bounded at [`LINEAGE_PROCESSES`] processes. The
//!    names the walk reads are hints and go in the audit record; nothing
//!    branches on them. What the walk yields is a set of pins, and the next
//!    step matches an entry to one of them.
//! 7. **The ruleset**, only through `aido_sys::load_trusted_rules`. The
//!    generation is [`aido_policy::Generation::id`] of what was loaded, the
//!    value the broker minted against.
//! 8. **The spool**, opened through the trust walk. Every entry named by a
//!    nonce is read on a descriptor of its own. Exactly one must be pinned to
//!    an ancestor: none is [`Refusal::NoPendingRequest`], more than one is
//!    refused.
//! 9. **`validate`, then [`decide`]**, then **consume**: the entry is unlinked
//!    through the verified directory descriptor before anything executes, and
//!    a failed unlink — `ENOENT` included, which means a second gate took it
//!    first — is a refusal. An entry is therefore used at most once.
//! 10. **The program**, opened through the trust walk and judged and hashed on
//!     that descriptor. A `#!` script is refused as a script.
//! 11. **The audit record**, through [`aido_sys::authorize`], before the exec.
//!     A gate that cannot write its record refuses, and the exec takes the
//!     [`Authorized`] that only a written record makes.
//! 12. **`execveat(fd, "", AT_EMPTY_PATH)`**, with the argument vector built
//!     from the canonical argv *bytes* and the environment from
//!     [`crate::child_environment`].
//!
//! # The process model: exec in place
//!
//! The gate replaces itself with the command. The alternative is to fork, wait,
//! and report the outcome, and it is rejected for three reasons. `fork` has no
//! safe wrapper, so it would be a further `unsafe` block in the one crate that
//! has a published budget for them. A waiting root parent holds every
//! descriptor it inherited, and `close_range` marks rather than closes. And
//! exec in place gives the faithful exit status and signal for free, since
//! `sudo`'s own parent is what reaps the command. What it costs is an outcome
//! record: the authorization is written before the exec, and nothing is left
//! to write after it. The one outcome the gate can still learn is an exec that
//! fails, which it records as a second entry naming the authorization.
//!
//! # What a refusal says, and to whom
//!
//! The gate writes its refusal to the audit trail (best effort: a refusal
//! stands without its record) and prints one line to standard error, the
//! stable code and severity only. Nothing from the spool, the ruleset or the
//! environment reaches that line.

use std::convert::Infallible;
use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use aido_audit::record::Record;
use aido_policy::{CallerFacts, Classification, LoadedRuleSet, engine};
use aido_sys::{
    AuditSink, Authorized, Clock, DirSpool, HostClock, HostHygiene, HostPrograms, HostSyscalls,
    Hygiene, ProcRef, ProcSource, Program, Programs, Spool, Syscalls, TrustedRulesError,
    VerifiedProc, authorize, lineage,
};

use crate::decide::{
    Approved, GateCaller, GateContext, Refusal, Stage, UNKNOWN_UID, authorization_record, decide,
    exec_failure_record, refusal_record,
};
use crate::request::{CallerPin, MonotonicSecs, PendingRequest, RequestError, SPOOL_DIR, is_nonce};

/// The first descriptor the gate marks close-on-exec: everything above the
/// three standard streams.
pub const FIRST_INHERITED_FD: u32 = 3;

/// How many processes the lineage walk reads: the gate and the eight above it.
///
/// The hop is at most three deep: the gate, `sudo`'s monitor, `sudo` itself,
/// then `aido`. The bound is wider than that so a wrapper between them does
/// not lock a legitimate caller out, and narrow enough that a deep process
/// tree is not work a caller can demand of the gate.
pub const LINEAGE_PROCESSES: usize = 9;

/// The one name the gate runs under: the hardlink `sudo` asks for a password
/// to reach.
pub const AUTH_NAME: &[u8] = b"aido-gate-auth";

/// Where the root-owned ruleset is read from.
pub const RULES_DIR: &str = "/etc/aido/rules.d";

/// Everything the gate touches outside itself.
///
/// One trait rather than eight parameters, so the real host is one value and a
/// test host is another, and so the gate cannot be handed a mix.
pub trait GateHost {
    /// The system calls that need `unsafe`.
    fn syscalls(&self) -> &dyn Syscalls;
    /// What the gate settles about its own process.
    fn hygiene(&self) -> &dyn Hygiene;
    /// The monotonic clock.
    fn clock(&self) -> &dyn Clock;
    /// Opens `/proc` and proves it is procfs.
    ///
    /// # Errors
    ///
    /// [`aido_sys::SysError`] when it cannot be opened or is not procfs.
    fn open_proc(&self) -> Result<Box<dyn ProcSource>, aido_sys::SysError>;
    /// Loads the root-owned ruleset through the trust walk.
    ///
    /// # Errors
    ///
    /// [`TrustedRulesError`] when any component or file is not root's, or the
    /// files are not a ruleset.
    fn load_rules(&self) -> Result<LoadedRuleSet, TrustedRulesError>;
    /// Opens the spool through the trust walk.
    ///
    /// # Errors
    ///
    /// [`aido_sys::SysError`] when it fails the walk or is not a directory.
    fn open_spool(&self) -> Result<Box<dyn Spool>, aido_sys::SysError>;
    /// Where programs are opened.
    fn programs(&self) -> &dyn Programs;
    /// The audit trail.
    fn audit(&mut self) -> &mut dyn AuditSink;
}

/// The real host: the running kernel, the real `/proc`, `/etc/aido/rules.d`,
/// `/run/aido/req`, and the system audit trail.
#[derive(Debug)]
pub struct SystemHost {
    audit: aido_sys::AuditTrail,
}

impl SystemHost {
    /// The host for this machine. Opens nothing: every file is opened by the
    /// step that needs it.
    pub fn new() -> Self {
        Self {
            audit: aido_sys::AuditTrail::system("aido-gate"),
        }
    }
}

impl Default for SystemHost {
    fn default() -> Self {
        Self::new()
    }
}

impl GateHost for SystemHost {
    fn syscalls(&self) -> &dyn Syscalls {
        &HostSyscalls
    }

    fn hygiene(&self) -> &dyn Hygiene {
        &HostHygiene
    }

    fn clock(&self) -> &dyn Clock {
        &HostClock
    }

    fn open_proc(&self) -> Result<Box<dyn ProcSource>, aido_sys::SysError> {
        VerifiedProc::open().map(into_source)
    }

    fn load_rules(&self) -> Result<LoadedRuleSet, TrustedRulesError> {
        aido_sys::load_trusted_rules(Path::new(RULES_DIR))
    }

    fn open_spool(&self) -> Result<Box<dyn Spool>, aido_sys::SysError> {
        DirSpool::open(Path::new(SPOOL_DIR)).map(into_spool)
    }

    fn programs(&self) -> &dyn Programs {
        &HostPrograms
    }

    fn audit(&mut self) -> &mut dyn AuditSink {
        &mut self.audit
    }
}

/// A `/proc` source as the trait object the host hands out.
///
/// Generic so that the real host's conversion is the one every platform's
/// tests run: the real `/proc` exists only on Linux, and a closure written at
/// the call site would be a function only Linux ever called.
fn into_source<S: ProcSource + 'static>(source: S) -> Box<dyn ProcSource> {
    Box::new(source)
}

/// A spool as the trait object the host hands out. See [`into_source`].
fn into_spool<S: Spool + 'static>(spool: S) -> Box<dyn Spool> {
    Box::new(spool)
}

/// How the gate ends when it did not exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateExit {
    /// The exit status: 17, 18 or 19, never the child's range.
    pub status: i32,
    /// One line for standard error: the code and severity, nothing else.
    pub message: String,
}

/// Which hardlink the gate was started as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    /// `aido-gate-auth`: `sudo` asked a human for a password to start it.
    Auth,
}

impl Entry {
    /// Whether this name proves a password was typed.
    fn password_confirms(self) -> bool {
        match self {
            Self::Auth => true,
        }
    }

    /// What the record says confirmed the request under this name.
    fn confirmation(self) -> &'static str {
        match self {
            Self::Auth => "confirmation=password (sudo's own prompt, on the -auth name)",
        }
    }
}

/// Accepts the one invocation `sudo` makes: no arguments, under the `-auth`
/// name.
///
/// The name is the last `/`-separated segment of `argv[0]`, compared as bytes
/// and exactly: no normalisation, so `aido-gate-auth/` and `aido-gate-auth/.`
/// are not it. `aido-gate-nopass` is refused with the rest until M4 ships it.
fn accept_invocation(args: &[OsString]) -> Result<Entry, Refusal> {
    let refuse = |reason: String| Refusal::Failed {
        stage: Stage::Invocation,
        reason,
    };
    let Some(name) = args.first() else {
        return Err(refuse("no argv[0]".to_owned()));
    };
    if args.len() > 1 {
        return Err(refuse(format!(
            "{} argument(s) given, and the gate takes none",
            args.len().saturating_sub(1)
        )));
    }
    let bytes = name.as_bytes();
    let last = bytes
        .rsplit(|byte| *byte == b'/')
        .next()
        .unwrap_or_default();
    if last == AUTH_NAME {
        Ok(Entry::Auth)
    } else {
        Err(refuse(format!(
            "started as {}, and only {} runs",
            bytes.escape_ascii(),
            AUTH_NAME.escape_ascii()
        )))
    }
}

/// Turns a failure of one step into the refusal that names it.
fn stage<T, E: std::fmt::Display>(stage: Stage, result: Result<T, E>) -> Result<T, Refusal> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(Refusal::Failed {
            stage,
            reason: error.to_string(),
        }),
    }
}

/// What the gate has learnt so far, for the record of however it ends.
#[derive(Default)]
struct Progress {
    gate_pid: u32,
    caller: Option<GateCaller>,
    pending: Option<PendingRequest>,
    /// The authorization, once it is written: its position in the chain and
    /// what it authorized.
    authorized: Option<(u64, Approved)>,
    /// Evidence beyond what the record builders add: the lineage, the name the
    /// gate ran under, the program's digest.
    evidence: Vec<String>,
}

/// Runs the gate.
///
/// Returns only when the gate did **not** exec: a successful exec replaces the
/// process, so what comes back is always a refusal, already written to the
/// audit trail where that was possible.
pub fn run(host: &mut dyn GateHost, args: &[OsString]) -> GateExit {
    let mut progress = Progress {
        gate_pid: host.hygiene().pid(),
        ..Progress::default()
    };
    let Err(refusal) = proceed(host, args, &mut progress);
    record(host, &refusal, &progress);
    GateExit {
        status: refusal.exit_code().as_i32(),
        message: format!(
            "aido-gate: refused ({}, severity {})",
            refusal.code(),
            refusal.severity().label()
        ),
    }
}

/// Writes the refusal to the audit trail, or the failure of an exec that was
/// already authorized. Best effort: a refusal stands whether or not it lands.
fn record(host: &mut dyn GateHost, refusal: &Refusal, progress: &Progress) {
    let caller = progress
        .caller
        .clone()
        .unwrap_or_else(|| GateCaller::unidentified(progress.gate_pid));
    let build = |previous: Option<&Record>| match &progress.authorized {
        Some((seq, approved)) => {
            exec_failure_record(previous, approved, &caller, *seq, &refusal.to_string())
        }
        None => annotate(
            refusal_record(previous, refusal, &caller, progress.pending.as_ref()),
            &progress.evidence,
        ),
    };
    let _ = host.audit().append(&build);
}

/// Adds evidence to a record the builders in [`crate::decide`] made.
fn annotate(record: Record, extra: &[String]) -> Record {
    let mut evidence = record.evidence.clone();
    evidence.extend(extra.iter().cloned());
    record.with_evidence(evidence)
}

/// The steps, in order. `Err` is how the gate ends; there is no `Ok`, because
/// a successful exec does not return.
fn proceed(
    host: &mut dyn GateHost,
    args: &[OsString],
    progress: &mut Progress,
) -> Result<Infallible, Refusal> {
    stage(
        Stage::Descriptors,
        host.syscalls().mark_cloexec_from(FIRST_INHERITED_FD),
    )?;
    stage(Stage::Streams, host.hygiene().ensure_std_streams())?;
    stage(Stage::Privileges, host.hygiene().forbid_new_privileges())?;
    let entry = accept_invocation(args)?;
    progress
        .evidence
        .push(format!("gate_argv0={}", args_first_escaped(args)));

    let proc = stage(Stage::Procfs, host.open_proc())?;
    let ancestors = stage(
        Stage::Lineage,
        lineage(&*proc, progress.gate_pid, LINEAGE_PROCESSES),
    )?;
    progress
        .evidence
        .push(format!("lineage={}", ancestors.describe()));

    let loaded = stage(Stage::Rules, host.load_rules())?;
    let spool = stage(Stage::Spool, host.open_spool())?;
    let now = stage(Stage::Clock, host.clock().monotonic_secs())?;

    let pending = find_entry(&*spool, ancestors.chain.get(1..).unwrap_or_default())?;
    let own = ancestors
        .chain
        .first()
        .map_or(CallerPin::new(progress.gate_pid, 0), pin_of);
    let caller = GateCaller {
        pin: pending.as_ref().map_or(own, |found| {
            CallerPin::new(found.caller_pid, found.caller_starttime)
        }),
        facts: CallerFacts::new(
            Classification::Unattested {
                reason: "the gate attests no caller: classification is the broker's, and the \
                         passwordless path is M4"
                    .to_owned(),
            },
            UNKNOWN_UID,
        ),
    };
    progress.caller = Some(caller.clone());
    progress.pending.clone_from(&pending);

    let context = GateContext {
        generation: loaded.generation.id(),
        now: MonotonicSecs(now),
        settings: engine::Settings::default(),
        password_confirms: entry.password_confirms(),
    };
    let approved = decide(&loaded.rules, &caller, pending.as_ref(), context)?;
    progress.evidence.push(entry.confirmation().to_owned());

    // Consumed before anything runs: the entry is used at most once, and a
    // second gate that read it too fails here, on the unlink, and runs nothing.
    stage(Stage::Spool, spool.consume(&approved.nonce))?;

    let program = stage(
        Stage::Program,
        host.programs().open(Path::new(&approved.program)),
    )?;
    progress.evidence.push(format!(
        "program_sha256={} program_size={} program_dev_ino={}:{}",
        program.sha256(),
        program.size(),
        program.identity().0,
        program.identity().1
    ));

    let confirmed_by = pending
        .as_ref()
        .and_then(|found| found.confirmed_by.clone());
    let evidence = progress.evidence.clone();
    let build = |previous: Option<&Record>, approval: &Approved| {
        annotate(
            authorization_record(previous, approval, &caller, confirmed_by.as_deref()),
            &evidence,
        )
    };
    let authorized = stage(Stage::Audit, authorize(host.audit(), approved, &build))?;
    progress.authorized = Some((
        authorized.receipt().seq().get(),
        authorized.approval().clone(),
    ));

    Err(execute(host, &authorized, &program))
}

/// `argv[0]`, escaped, or an empty string when there is none.
fn args_first_escaped(args: &[OsString]) -> String {
    args.first()
        .map(|first| first.as_bytes().escape_ascii().to_string())
        .unwrap_or_default()
}

/// A process's pin.
fn pin_of(process: &ProcRef) -> CallerPin {
    CallerPin::new(process.pid, process.starttime)
}

/// The spool entry pinned to one of the `ancestors`, if exactly one is.
///
/// Only names that are nonces are opened. An entry that cannot be read, is
/// not UTF-8, or does not parse cannot be matched to anyone and is passed
/// over: refusing on it would let one stray file lock every caller out, and
/// passing over it can only end in "no pending request".
fn find_entry(spool: &dyn Spool, ancestors: &[ProcRef]) -> Result<Option<PendingRequest>, Refusal> {
    let names = stage(Stage::Spool, spool.names())?;
    let matched: Vec<(String, PendingRequest)> = names
        .iter()
        .filter_map(|raw| std::str::from_utf8(raw).ok().filter(|name| is_nonce(name)))
        .filter_map(|name| read_entry(spool, name).map(|entry| (name.to_owned(), entry)))
        .filter(|(_, entry)| pinned_to(entry, ancestors))
        .collect();
    if let Some((name, _)) = matched.iter().find(|(name, entry)| entry.nonce != *name) {
        return Err(Refusal::Request(RequestError::ForgedNonce {
            name: name.clone(),
        }));
    }
    match matched.len() {
        0 => Ok(None),
        1 => Ok(matched.into_iter().next().map(|(_, entry)| entry)),
        count => Err(Refusal::Request(RequestError::Ambiguous { matches: count })),
    }
}

/// One entry, read on its own descriptor and parsed; `None` for anything that
/// is not a request.
fn read_entry(spool: &dyn Spool, name: &str) -> Option<PendingRequest> {
    spool.read(name).ok().and_then(|bytes| {
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| PendingRequest::parse(text).ok())
    })
}

/// Whether an entry was minted for one of these processes: the pid **and**
/// the start time, because a pid alone is a name the kernel reissues.
fn pinned_to(entry: &PendingRequest, ancestors: &[ProcRef]) -> bool {
    ancestors.iter().any(|ancestor| {
        ancestor.pid == entry.caller_pid && ancestor.starttime == entry.caller_starttime
    })
}

/// The argument vector and environment, as the C strings the kernel takes.
struct ExecVector {
    argv: Vec<CString>,
    envp: Vec<CString>,
}

/// Builds the exec vector from the approved command: the program as `argv[0]`,
/// then the canonical operand **bytes**, and the fixed environment.
fn exec_vector(approved: &Approved) -> Result<ExecVector, Refusal> {
    let program = std::iter::once(approved.program.as_bytes());
    let operands = approved.exec_argv.iter().map(Vec::as_slice);
    let argv = program
        .chain(operands)
        .map(c_string)
        .collect::<Result<Vec<_>, _>>()?;
    let envp = approved
        .environment
        .iter()
        .map(|entry| c_string(entry.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExecVector { argv, envp })
}

/// One C string, refusing an interior NUL, which would let the kernel see a
/// prefix of what was reviewed.
fn c_string(bytes: &[u8]) -> Result<CString, Refusal> {
    stage(Stage::Exec, CString::new(bytes))
}

/// Executes the authorized program, and returns only if it could not.
fn execute(host: &dyn GateHost, authorized: &Authorized<Approved>, program: &Program) -> Refusal {
    let vector = match exec_vector(authorized.approval()) {
        Ok(vector) => vector,
        Err(refusal) => return refusal,
    };
    let argv: Vec<&CStr> = vector.argv.iter().map(CString::as_c_str).collect();
    let envp: Vec<&CStr> = vector.envp.iter().map(CString::as_c_str).collect();
    let error = host.syscalls().exec_fd(program.fd(), &argv, &envp);
    Refusal::Failed {
        stage: Stage::Exec,
        reason: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::rc::Rc;

    use aido_audit::record::Decision as AuditDecision;
    use aido_policy::{RuleFile, load_rule_files};
    use aido_sys::{
        FakeAuditSink, FakeClock, FakeHygiene, FakePrograms, FakeSyscalls, HygieneCall, MapSource,
        ProgramError, SysError, TrustError,
    };

    use super::*;
    use crate::env::child_environment;
    use crate::request::REQUEST_SCHEMA_VERSION;

    const NONCE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GATE_PID: u32 = 500;
    const AIDO_PID: u32 = 200;
    const AIDO_START: u64 = 7_000;
    const NOW: u64 = 100;

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
id = "aido.reload"
tier = "svc-control"
exe = "/usr/bin/systemctl"
confirm = "always"
args = [
  { name = "verb", matcher = { literal = "daemon-reload" } },
]
"#;

    fn rules() -> LoadedRuleSet {
        load_rule_files(vec![RuleFile {
            name: b"10-test.toml".to_vec(),
            bytes: RULES.as_bytes().to_vec(),
        }])
        .unwrap()
    }

    fn stat(pid: u32, comm: &str, parent: u32, starttime: u64) -> String {
        let mut tail: Vec<String> = vec!["S".into(), parent.to_string()];
        for _ in 0..17 {
            tail.push("0".to_owned());
        }
        tail.push(starttime.to_string());
        format!("{pid} ({comm}) {}", tail.join(" "))
    }

    /// The gate under sudo with `use_pty`, under aido, under a shell:
    /// 500 gate, 400 sudo monitor, 300 sudo, 200 aido, 100 bash, 1 init.
    fn proc_tree() -> MapSource {
        MapSource::new()
            .with("500/stat", stat(500, "aido-gate-auth", 400, 9_000))
            .with("400/stat", stat(400, "sudo", 300, 8_500))
            .with("300/stat", stat(300, "sudo", 200, 8_000))
            .with("200/stat", stat(200, "aido", 100, AIDO_START))
            .with("100/stat", stat(100, "bash", 1, 5_000))
            .with("1/stat", stat(1, "systemd", 0, 1))
    }

    fn entry(nonce: &str, pid: u32, starttime: u64, argv: &[&str]) -> PendingRequest {
        PendingRequest {
            schema_version: REQUEST_SCHEMA_VERSION,
            nonce: nonce.to_owned(),
            caller_pid: pid,
            caller_starttime: starttime,
            action: "aido.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            generation: rules().generation.id(),
            deadline: MonotonicSecs(200),
            confirmed: false,
            confirmed_by: None,
            claimed_classification: "enrolled-agent".to_owned(),
        }
    }

    fn ours() -> PendingRequest {
        entry(NONCE_A, AIDO_PID, AIDO_START, &["restart", "nginx.service"])
    }

    /// A spool in memory that can also refuse.
    struct FakeSpool {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        consumed: RefCell<Vec<String>>,
        consume_fails: Option<SysError>,
        names_fail: Option<SysError>,
    }

    impl FakeSpool {
        fn holding(entries: &[(&str, PendingRequest)]) -> Self {
            let spool = Self {
                files: RefCell::new(BTreeMap::new()),
                consumed: RefCell::new(Vec::new()),
                consume_fails: None,
                names_fail: None,
            };
            for (name, request) in entries {
                spool
                    .files
                    .borrow_mut()
                    .insert((*name).to_owned(), request.to_json().into_bytes());
            }
            spool
        }

        fn raw(self, name: &str, bytes: &[u8]) -> Self {
            self.files
                .borrow_mut()
                .insert(name.to_owned(), bytes.to_vec());
            self
        }
    }

    impl Spool for FakeSpool {
        fn names(&self) -> Result<Vec<Vec<u8>>, SysError> {
            if let Some(error) = &self.names_fail {
                return Err(error.clone());
            }
            Ok(self
                .files
                .borrow()
                .keys()
                .map(|name| name.as_bytes().to_vec())
                .collect())
        }

        fn read(&self, name: &str) -> Result<Vec<u8>, SysError> {
            self.files
                .borrow()
                .get(name)
                .cloned()
                .ok_or_else(|| SysError::read(name, "no such entry"))
        }

        fn consume(&self, name: &str) -> Result<(), SysError> {
            if let Some(error) = &self.consume_fails {
                return Err(error.clone());
            }
            self.consumed.borrow_mut().push(name.to_owned());
            self.files
                .borrow_mut()
                .remove(name)
                .map(|_| ())
                .ok_or_else(|| SysError::read(name, "already consumed"))
        }
    }

    /// A spool the host hands out, shared with the one the test holds.
    struct SharedSpool(Rc<FakeSpool>);

    impl Spool for SharedSpool {
        fn names(&self) -> Result<Vec<Vec<u8>>, SysError> {
            self.0.names()
        }
        fn read(&self, name: &str) -> Result<Vec<u8>, SysError> {
            self.0.read(name)
        }
        fn consume(&self, name: &str) -> Result<(), SysError> {
            self.0.consume(name)
        }
    }

    /// A host a test scripts, step by step.
    struct FakeHost {
        syscalls: FakeSyscalls,
        hygiene: FakeHygiene,
        clock: FakeClock,
        proc: Result<MapSource, SysError>,
        rules: Result<LoadedRuleSet, TrustedRulesError>,
        spool: Result<Rc<FakeSpool>, SysError>,
        programs: FakePrograms,
        audit: FakeAuditSink,
        proc_opened: Cell<bool>,
        spool_opened: Cell<bool>,
    }

    /// An executable under `target/`, owned by whoever runs the tests, made
    /// once per name however many tests ask: tests run in parallel, and one
    /// rewriting a file another is hashing would be a flake.
    fn program_file(name: &'static str, body: &'static [u8]) -> (PathBuf, u32) {
        static MADE: std::sync::Mutex<Vec<(&'static str, PathBuf, u32)>> =
            std::sync::Mutex::new(Vec::new());
        let mut made = MADE.lock().unwrap();
        if let Some((_, path, owner)) = made.iter().find(|(known, _, _)| *known == name) {
            return (path.clone(), *owner);
        }
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join("gate-run");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let owner = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&path).unwrap());
        made.push((name, path.clone(), owner));
        (path, owner)
    }

    impl FakeHost {
        fn new(spool: &Rc<FakeSpool>) -> Self {
            let (path, owner) = program_file("tool", b"the program that would run as root");
            Self {
                syscalls: FakeSyscalls::new().with_cloexec(Ok(())),
                hygiene: FakeHygiene::new(GATE_PID),
                clock: FakeClock::at(NOW),
                proc: Ok(proc_tree()),
                rules: Ok(rules()),
                spool: Ok(Rc::clone(spool)),
                programs: FakePrograms::serving(path, owner),
                audit: FakeAuditSink::new(),
                proc_opened: Cell::new(false),
                spool_opened: Cell::new(false),
            }
        }
    }

    impl GateHost for FakeHost {
        fn syscalls(&self) -> &dyn Syscalls {
            &self.syscalls
        }
        fn hygiene(&self) -> &dyn Hygiene {
            &self.hygiene
        }
        fn clock(&self) -> &dyn Clock {
            &self.clock
        }
        fn open_proc(&self) -> Result<Box<dyn ProcSource>, SysError> {
            self.proc_opened.set(true);
            self.proc
                .clone()
                .map(|source| Box::new(source) as Box<dyn ProcSource>)
        }
        fn load_rules(&self) -> Result<LoadedRuleSet, TrustedRulesError> {
            self.rules.clone()
        }
        fn open_spool(&self) -> Result<Box<dyn Spool>, SysError> {
            self.spool_opened.set(true);
            self.spool
                .clone()
                .map(|spool| Box::new(SharedSpool(spool)) as Box<dyn Spool>)
        }
        fn programs(&self) -> &dyn Programs {
            &self.programs
        }
        fn audit(&mut self) -> &mut dyn AuditSink {
            &mut self.audit
        }
    }

    fn auth() -> Vec<OsString> {
        vec![OsString::from("/usr/libexec/aido/aido-gate-auth")]
    }

    fn exec_calls(host: &FakeHost) -> usize {
        host.syscalls
            .calls()
            .iter()
            .filter(|call| matches!(call, aido_sys::FakeCall::Exec { .. }))
            .count()
    }

    fn denial_codes(host: &FakeHost) -> Vec<Option<String>> {
        host.audit
            .records()
            .iter()
            .map(|record| record.denial.clone())
            .collect()
    }

    /// The gate ran nothing, consumed nothing, and left one refusal behind.
    fn assert_refused_with(host: &FakeHost, spool: &FakeSpool, exit: &GateExit, code: &str) {
        assert_eq!(exec_calls(host), 0, "nothing may run on a refusal");
        assert!(spool.consumed.borrow().is_empty(), "nothing consumed");
        assert_eq!(denial_codes(host), vec![Some(code.to_owned())]);
        assert_eq!(host.audit.records()[0].decision, AuditDecision::Denied);
        assert!(exit.message.contains(code), "{}", exit.message);
    }

    // ---- the happy path, and everything it must do in order --------------

    #[test]
    fn an_approved_entry_is_consumed_recorded_and_then_executed_from_the_validated_descriptor() {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());

        // The fake exec returns an error, so `run` ends, with a refusal that
        // names the exec: the one thing a real exec never does.
        assert_eq!(exit.status, 19);
        assert!(
            exit.message.contains("gate_failed_exec"),
            "{}",
            exit.message
        );

        // Marked first, from descriptor 3.
        assert_eq!(
            host.syscalls.calls().first(),
            Some(&aido_sys::FakeCall::MarkCloexecFrom(3))
        );
        assert_eq!(
            host.hygiene.calls(),
            [
                HygieneCall::EnsureStdStreams,
                HygieneCall::ForbidNewPrivileges
            ]
        );
        // Consumed exactly once.
        assert_eq!(*spool.consumed.borrow(), [NONCE_A.to_owned()]);

        // Exec'd the descriptor that was hashed, with the canonical operands
        // and the fixed environment.
        let (path, _) = program_file("tool", b"the program that would run as root");
        let meta = std::fs::metadata(&path).unwrap();
        let operands = ["/usr/bin/systemctl", "restart", "nginx.service"];
        assert_eq!(
            host.syscalls.calls().last(),
            Some(&aido_sys::FakeCall::Exec {
                program: Some((
                    std::os::unix::fs::MetadataExt::dev(&meta),
                    std::os::unix::fs::MetadataExt::ino(&meta)
                )),
                argv: operands
                    .iter()
                    .map(|arg| CString::new(*arg).unwrap())
                    .collect(),
                envp: child_environment()
                    .iter()
                    .map(|entry| CString::new(entry.as_str()).unwrap())
                    .collect(),
            })
        );

        // The authorization was written before the exec, naming the program's
        // digest, then the failed exec was written after it.
        let records = host.audit.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].decision, AuditDecision::Allowed);
        assert_eq!(records[0].action.as_deref(), Some("aido.svc.restart"));
        let evidence = &records[0].evidence;
        assert!(has_line(evidence, "program_sha256="), "{evidence:?}");
        assert!(
            has_line(evidence, "lineage=aido-gate-auth(500) <- sudo(400)"),
            "{evidence:?}"
        );
        assert!(has_line(evidence, "confirmation=password"), "{evidence:?}");
        assert!(
            has_line(evidence, "gate_argv0=/usr/libexec"),
            "{evidence:?}"
        );
        assert_eq!(records[1].outcome.kind(), "failed");
        let after = &records[1].evidence;
        assert!(has_line(after, "authorization_seq=1"), "{after:?}");
    }

    /// Whether some line of evidence begins with `prefix`.
    fn has_line(evidence: &[String], prefix: &str) -> bool {
        evidence.iter().any(|line| line.starts_with(prefix))
    }

    #[test]
    fn an_entry_is_consumed_exactly_once_so_a_second_gate_finds_nothing() {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
        let mut first = FakeHost::new(&spool);
        let first_exit = run(&mut first, &auth());
        assert!(first_exit.message.contains("gate_failed_exec"));
        assert_eq!(exec_calls(&first), 1);

        let mut second = FakeHost::new(&spool);
        let exit = run(&mut second, &auth());
        assert_eq!(exit.status, 19);
        assert_eq!(exec_calls(&second), 0);
        assert!(exit.message.contains("gate_no_pending_request"));
        assert_eq!(spool.consumed.borrow().len(), 1);
    }

    #[test]
    fn a_rule_that_confirms_is_satisfied_by_the_password_on_the_auth_name() {
        let mut request = ours();
        request.action = "aido.reload".to_owned();
        request.argv = vec!["daemon-reload".to_owned()];
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, request)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        // It reached the exec: not refused for want of a confirmation.
        assert!(
            exit.message.contains("gate_failed_exec"),
            "{}",
            exit.message
        );
        assert_eq!(exec_calls(&host), 1);
    }

    // ---- a hostile direct invocation -------------------------------------

    #[test]
    fn a_direct_hostile_invocation_with_no_entry_does_nothing_and_exits_unusable_at_high_severity()
    {
        let spool = Rc::new(FakeSpool::holding(&[]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19);
        assert!(exit.message.contains("severity high"), "{}", exit.message);
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
        assert!(
            host.audit.records()[0]
                .evidence
                .contains(&"severity=high".to_owned())
        );
        // Nothing was opened for a program that was never named.
        assert!(host.programs.opened().is_empty());
    }

    #[test]
    fn an_entry_minted_for_someone_else_is_not_this_callers() {
        // Pinned to a pid nothing above the gate has.
        let other = entry(NONCE_A, 999, AIDO_START, &["restart", "nginx.service"]);
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, other)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
    }

    #[test]
    fn a_reissued_pid_does_not_borrow_the_entry_of_the_process_that_had_it() {
        // The pid matches an ancestor; the start time does not. Pid reuse.
        let stale = entry(
            NONCE_A,
            AIDO_PID,
            AIDO_START + 1,
            &["restart", "nginx.service"],
        );
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, stale)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
    }

    #[test]
    fn an_entry_pinned_to_the_gate_itself_or_below_the_walk_is_not_matched() {
        // The gate's own pin is not a caller: nothing the broker minted is for
        // the process it is about to run.
        let own = entry(NONCE_A, GATE_PID, 9_000, &["restart", "nginx.service"]);
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, own)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
    }

    #[test]
    fn two_entries_pinned_to_one_lineage_are_refused_and_neither_is_consumed() {
        let spool = Rc::new(FakeSpool::holding(&[
            (NONCE_A, ours()),
            (
                NONCE_B,
                entry(NONCE_B, 300, 8_000, &["restart", "nginx.service"]),
            ),
        ]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_ambiguous");
    }

    #[test]
    fn an_entry_whose_content_disagrees_with_its_name_is_forged_and_refused() {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_B, ours())]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_forged_nonce");
    }

    #[test]
    fn an_expired_entry_is_refused_at_normal_severity() {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.clock = FakeClock::at(200);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_expired");
        assert!(exit.message.contains("severity normal"), "{}", exit.message);
    }

    #[test]
    fn an_entry_from_before_the_rules_changed_is_refused() {
        let mut stale = ours();
        stale.generation ^= 1;
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, stale)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_stale_generation");
    }

    #[test]
    fn an_action_the_ruleset_does_not_name_is_refused_by_policy_and_not_consumed() {
        let mut unknown = ours();
        unknown.action = "aido.nonexistent".to_owned();
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, unknown)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 17);
        assert_eq!(exec_calls(&host), 0);
        assert!(spool.consumed.borrow().is_empty());
        assert_eq!(denial_codes(&host).len(), 1);
    }

    #[test]
    fn operands_the_rule_does_not_accept_are_refused_by_policy() {
        let spool = Rc::new(FakeSpool::holding(&[(
            NONCE_A,
            entry(
                NONCE_A,
                AIDO_PID,
                AIDO_START,
                &["restart", "nginx.service", "--now"],
            ),
        )]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 17);
        assert_eq!(exec_calls(&host), 0);
        assert!(spool.consumed.borrow().is_empty());
    }

    #[test]
    fn names_that_are_not_nonces_and_entries_that_are_not_requests_are_passed_over() {
        let spool = Rc::new(
            FakeSpool::holding(&[(NONCE_A, ours())])
                .raw("not-a-nonce", b"{}")
                .raw(".hidden", b"")
                .raw(&"c".repeat(64), b"\xff\xfe not utf-8")
                .raw(&"d".repeat(64), b"{ not a request }")
                .raw(&"e".repeat(63), b"{}"),
        );
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        // The one real entry ran; the junk neither blocked it nor was opened
        // as a request.
        assert!(
            exit.message.contains("gate_failed_exec"),
            "{}",
            exit.message
        );
        assert_eq!(*spool.consumed.borrow(), [NONCE_A.to_owned()]);
    }

    #[test]
    fn the_fake_spool_refuses_what_it_does_not_hold() {
        let spool = FakeSpool::holding(&[]);
        assert!(spool.read(NONCE_A).is_err());
        assert!(spool.consume(NONCE_A).is_err());
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_passed_over_and_ends_in_no_pending_request() {
        // A listing that names a nonce the spool then refuses to read: the
        // entry cannot be matched to anyone, so it is never run.
        let listing = FakeListing(vec![NONCE_A.as_bytes().to_vec()]);
        assert!(find_entry(&listing, &[]).unwrap().is_none());
        // Its other two methods refuse too, which is all they are for.
        assert!(listing.consume(NONCE_A).is_err());
    }

    /// A spool that lists a name and then fails to read it.
    struct FakeListing(Vec<Vec<u8>>);

    impl Spool for FakeListing {
        fn names(&self) -> Result<Vec<Vec<u8>>, SysError> {
            Ok(self.0.clone())
        }
        fn read(&self, name: &str) -> Result<Vec<u8>, SysError> {
            Err(SysError::read(name, "refused"))
        }
        fn consume(&self, name: &str) -> Result<(), SysError> {
            Err(SysError::read(name, "refused"))
        }
    }

    // ---- consuming --------------------------------------------------------

    #[test]
    fn an_entry_that_was_already_gone_when_the_gate_consumed_it_runs_nothing() {
        // Another gate read the same entry and unlinked it first: ENOENT on
        // the unlink is a refusal, never a second run.
        let mut spool = FakeSpool::holding(&[(NONCE_A, ours())]);
        spool.consume_fails = Some(SysError::Os {
            operation: "unlinkat".to_owned(),
            code: Some(2),
            reason: "No such file or directory".to_owned(),
        });
        let spool = Rc::new(spool);
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19);
        assert_eq!(exec_calls(&host), 0);
        assert!(host.programs.opened().is_empty());
        assert_eq!(
            denial_codes(&host),
            vec![Some("gate_failed_spool".to_owned())]
        );
        assert!(exit.message.contains("severity high"));
    }

    // ---- the program ------------------------------------------------------

    #[test]
    fn a_program_that_fails_the_trust_walk_is_refused_and_nothing_is_recorded_as_authorized() {
        for error in [
            ProgramError::Untrusted(TrustError::Symlink {
                at: "/usr/bin/systemctl".to_owned(),
            }),
            ProgramError::Writable {
                at: "/usr/bin/systemctl".to_owned(),
                mode: 0o777,
            },
            ProgramError::Script {
                at: "/usr/bin/systemctl".to_owned(),
            },
        ] {
            let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
            let mut host = FakeHost::new(&spool);
            host.programs = FakePrograms::refusing(error);
            let exit = run(&mut host, &auth());
            assert_eq!(exit.status, 19);
            assert_eq!(exec_calls(&host), 0);
            // The entry was consumed before the program was opened: it is
            // gone, and the caller must ask again.
            assert_eq!(*spool.consumed.borrow(), [NONCE_A.to_owned()]);
            assert_eq!(
                denial_codes(&host),
                vec![Some("gate_failed_program".to_owned())]
            );
            assert!(exit.message.contains("severity high"));
        }
    }

    #[test]
    fn a_script_is_refused_with_the_reason_in_the_record() {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        let (script, owner) = program_file("script", b"#!/bin/sh\nid\n");
        host.programs = FakePrograms::serving(script, owner);
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 0);
        assert!(exit.message.contains("gate_failed_program"));
        // The reason is on the record, so the operator learns it was a script.
        let evidence = &host.audit.records()[0].evidence;
        assert!(
            evidence
                .iter()
                .any(|line| line.starts_with("detail=") && line.contains("is a script")),
            "{evidence:?}"
        );
    }

    // ---- the audit record -------------------------------------------------

    #[test]
    fn a_gate_that_cannot_write_its_record_refuses_and_executes_nothing() {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.audit = FakeAuditSink::failing("the disk is full");
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19);
        assert_eq!(exec_calls(&host), 0);
        assert!(
            exit.message.contains("gate_failed_audit"),
            "{}",
            exit.message
        );
        assert!(host.audit.records().is_empty());
    }

    // ---- exec -------------------------------------------------------------

    #[test]
    fn the_exec_vector_is_the_canonical_bytes_not_the_rendered_argv() {
        // A rendering escapes; the kernel must be handed the bytes.
        let approved = Approved {
            program: "/usr/bin/tool".to_owned(),
            argv: vec!["rendered \\xff".to_owned()],
            exec_argv: vec![vec![0xff, b'a'], Vec::new()],
            environment: child_environment(),
            action: "a".to_owned(),
            rule_source: "r:1".to_owned(),
            requested_action: "a".to_owned(),
            requested_rule_source: "r:1".to_owned(),
            nonce: NONCE_A.to_owned(),
        };
        let vector = exec_vector(&approved).unwrap();
        let argv: Vec<&[u8]> = vector.argv.iter().map(|arg| arg.to_bytes()).collect();
        assert_eq!(argv, [&b"/usr/bin/tool"[..], &[0xff, b'a'][..], &b""[..]]);
        assert_eq!(vector.envp.len(), child_environment().len());
    }

    #[test]
    fn an_interior_nul_in_the_vector_is_refused_rather_than_truncated() {
        let mut approved = Approved {
            program: "/usr/bin/tool".to_owned(),
            argv: Vec::new(),
            exec_argv: vec![b"a\0b".to_vec()],
            environment: Vec::new(),
            action: "a".to_owned(),
            rule_source: "r:1".to_owned(),
            requested_action: "a".to_owned(),
            requested_rule_source: "r:1".to_owned(),
            nonce: NONCE_A.to_owned(),
        };
        let refused = exec_vector(&approved).err().unwrap();
        assert_eq!(refused.code(), "gate_failed_exec");
        // And in the environment.
        approved.exec_argv = Vec::new();
        approved.environment = vec!["A=b\0c".to_owned()];
        assert!(exec_vector(&approved).is_err());
    }

    // ---- every step that can fail, in order -------------------------------

    /// Runs the gate on a host `break_it` has broken, and checks it stopped at
    /// `code` having done none of the later steps.
    fn stops_at(break_it: impl FnOnce(&mut FakeHost), code: &str) -> (GateExit, Vec<String>) {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        break_it(&mut host);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19, "{}", exit.message);
        assert!(exit.message.contains(code), "{}", exit.message);
        assert_eq!(exec_calls(&host), 0, "{code}: nothing may run");
        assert!(
            spool.consumed.borrow().is_empty(),
            "{code}: nothing consumed"
        );
        let seen = vec![
            format!("proc={}", host.proc_opened.get()),
            format!("spool={}", host.spool_opened.get()),
            format!("hygiene={}", host.hygiene.calls().len()),
            format!("programs={}", host.programs.opened().len()),
        ];
        (exit, seen)
    }

    #[test]
    fn a_kernel_that_refuses_close_range_stops_the_gate_before_it_opens_anything() {
        let (_, seen) = stops_at(
            |host| {
                host.syscalls = FakeSyscalls::new();
            },
            "gate_failed_descriptors",
        );
        // The unscripted fake answers like a pre-5.11 kernel (ENOSYS). Nothing
        // after it ran: not the streams, not /proc, not the spool.
        assert_eq!(
            seen,
            ["proc=false", "spool=false", "hygiene=0", "programs=0"]
        );
    }

    #[test]
    fn closed_standard_streams_that_cannot_be_replaced_stop_the_gate_before_any_open() {
        let (_, seen) = stops_at(
            |host| {
                host.hygiene =
                    FakeHygiene::new(GATE_PID).with_streams_error(SysError::unsupported("dup2"));
            },
            "gate_failed_streams",
        );
        assert_eq!(
            seen,
            ["proc=false", "spool=false", "hygiene=1", "programs=0"]
        );
    }

    #[test]
    fn a_kernel_that_refuses_no_new_privs_stops_the_gate_before_it_consumes_anything() {
        let (_, seen) = stops_at(
            |host| {
                host.hygiene = FakeHygiene::new(GATE_PID)
                    .with_privileges_error(SysError::unsupported("prctl"));
            },
            "gate_failed_privileges",
        );
        assert_eq!(
            seen,
            ["proc=false", "spool=false", "hygiene=2", "programs=0"]
        );
    }

    #[test]
    fn a_proc_that_is_not_procfs_stops_the_gate_before_any_lineage_is_read() {
        let (_, seen) = stops_at(
            |host| {
                host.proc = Err(SysError::read("/proc", "not on procfs"));
            },
            "gate_failed_procfs",
        );
        assert_eq!(seen[1], "spool=false");
    }

    #[test]
    fn a_lineage_that_cannot_be_walked_stops_the_gate_before_the_ruleset_is_read() {
        let (_, seen) = stops_at(
            |host| {
                host.proc = Ok(MapSource::new());
            },
            "gate_failed_lineage",
        );
        assert_eq!(seen[1], "spool=false");
    }

    #[test]
    fn a_ruleset_that_fails_the_trust_walk_stops_the_gate_before_the_spool_is_opened() {
        let (_, seen) = stops_at(
            |host| {
                host.rules = Err(TrustedRulesError::Trust(TrustError::NotRootOwned {
                    at: "/etc/aido".to_owned(),
                    uid: 1000,
                }));
            },
            "gate_failed_rules",
        );
        assert_eq!(seen[1], "spool=false");
    }

    #[test]
    fn a_spool_that_fails_the_trust_walk_stops_the_gate() {
        let (_, seen) = stops_at(
            |host| {
                host.spool = Err(SysError::read("/run/aido/req", "not root's"));
            },
            "gate_failed_spool",
        );
        assert_eq!(seen[1], "spool=true");
    }

    #[test]
    fn a_spool_that_cannot_be_listed_stops_the_gate() {
        let mut spool = FakeSpool::holding(&[(NONCE_A, ours())]);
        spool.names_fail = Some(SysError::read("spool", "more than 4096 entries"));
        let spool = Rc::new(spool);
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 0);
        assert!(
            exit.message.contains("gate_failed_spool"),
            "{}",
            exit.message
        );
    }

    #[test]
    fn a_clock_that_cannot_be_read_stops_the_gate_because_no_deadline_can_be_checked() {
        stops_at(
            |host| {
                host.clock = FakeClock::broken("no clock");
            },
            "gate_failed_clock",
        );
    }

    // ---- the invocation ---------------------------------------------------

    fn refused_invocation(args: &[&[u8]]) -> GateExit {
        let spool = Rc::new(FakeSpool::holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        let args: Vec<OsString> = args
            .iter()
            .map(|bytes| std::os::unix::ffi::OsStringExt::from_vec(bytes.to_vec()))
            .collect();
        let exit = run(&mut host, &args);
        assert_eq!(exit.status, 19);
        assert!(
            exit.message.contains("gate_failed_invocation"),
            "{}",
            exit.message
        );
        assert!(exit.message.contains("severity high"));
        assert_eq!(exec_calls(&host), 0);
        assert!(spool.consumed.borrow().is_empty());
        // Refused before /proc or the spool were touched.
        assert!(!host.proc_opened.get());
        assert!(!host.spool_opened.get());
        // And the refusal is on the trail, with argv[0] escaped.
        assert_eq!(
            denial_codes(&host),
            vec![Some("gate_failed_invocation".to_owned())]
        );
        exit
    }

    #[test]
    fn arguments_are_refused_because_the_sudoers_rule_grants_none() {
        refused_invocation(&[b"aido-gate-auth", b"--help"]);
        refused_invocation(&[b"/usr/libexec/aido/aido-gate-auth", b""]);
    }

    #[test]
    fn an_unexpected_argv0_is_refused() {
        for name in [
            &b"aido-gate"[..],
            b"aido-gate-nopass",
            b"/usr/libexec/aido/aido-gate",
            b"sh",
            b"",
            b"aido-gate-auth/",
            b"aido-gate-auth/.",
            b"xaido-gate-auth",
            b"aido-gate-auth ",
            b"aido-gate-auth\xff",
        ] {
            refused_invocation(&[name]);
        }
    }

    #[test]
    fn a_missing_argv0_is_refused() {
        refused_invocation(&[]);
    }

    #[test]
    fn the_auth_name_runs_bare_or_by_path() {
        for name in [
            "aido-gate-auth",
            "/usr/libexec/aido/aido-gate-auth",
            "./aido-gate-auth",
        ] {
            assert_eq!(
                accept_invocation(&[OsString::from(name)]).unwrap(),
                Entry::Auth,
                "{name}"
            );
        }
        assert!(Entry::Auth.password_confirms());
    }

    #[test]
    fn an_argv0_that_could_drive_a_terminal_reaches_the_record_escaped() {
        let spool = Rc::new(FakeSpool::holding(&[]));
        let mut host = FakeHost::new(&spool);
        let evil = std::os::unix::ffi::OsStringExt::from_vec(b"\x1b]0;pwned\x07".to_vec());
        let exit = run(&mut host, &[evil]);
        assert!(exit.message.contains("gate_failed_invocation"));
        // The record holds the escape as the four characters `\x1b`, not the
        // byte: `Debug` would hide a raw one, so the evidence is asserted on.
        let evidence = &host.audit.records()[0].evidence;
        assert!(
            evidence
                .iter()
                .any(|line| line.contains("\\x1b]0;pwned\\x07")),
            "{evidence:?}"
        );
        assert!(evidence.iter().all(|line| !line.contains('\x1b')));
        assert!(!exit.message.contains('\x1b'));
    }

    #[test]
    fn the_refusal_names_the_code_and_nothing_the_caller_controls() {
        let spool = Rc::new(FakeSpool::holding(&[]));
        let mut host = FakeHost::new(&spool);
        let exit = run(
            &mut host,
            &[
                OsString::from("aido-gate-auth"),
                OsString::from("secret-arg"),
            ],
        );
        assert!(!exit.message.contains("secret-arg"), "{}", exit.message);
        assert_eq!(
            exit.message,
            "aido-gate: refused (gate_failed_invocation, severity high)"
        );
    }

    // ---- pieces -----------------------------------------------------------

    #[test]
    fn the_rules_directory_is_the_one_the_configuration_names() {
        assert_eq!(
            PathBuf::from(RULES_DIR),
            aido_config::SystemPaths::default().rules_dir()
        );
        assert_eq!(
            PathBuf::from(SPOOL_DIR),
            aido_config::SystemPaths::default().runtime.join("req")
        );
        assert_eq!(SPOOL_DIR, "/run/aido/req");
        assert_eq!(AUTH_NAME, b"aido-gate-auth");
    }

    #[test]
    fn the_system_host_reaches_every_real_seam_and_refuses_what_this_host_is_not() {
        let mut host = SystemHost::default();
        // Constructed without opening anything.
        assert!(format!("{host:?}").contains("SystemHost"));
        assert!(host.hygiene().pid() > 0);
        assert!(host.clock().monotonic_secs().is_ok());
        // Nothing here is a ruleset, a spool, or a root-owned program.
        assert!(host.load_rules().is_err());
        assert!(host.open_spool().is_err());
        assert!(
            host.programs()
                .open(Path::new("/definitely/not/a/program"))
                .is_err()
        );
        // Handed out on every platform, called only where it refuses: on Linux
        // `close_range` would mark this test process's own descriptors.
        let _syscalls = host.syscalls();
        // Off Linux the real `/proc` and the real `close_range` refuse.
        #[cfg(not(target_os = "linux"))]
        {
            assert!(host.open_proc().is_err());
            assert!(host.syscalls().mark_cloexec_from(3).is_err());
        }
        #[cfg(target_os = "linux")]
        assert!(host.open_proc().is_ok());
        // The audit trail is the system's. Handed out, never written to: a
        // test must not leave a record in a real log if it is run as root.
        let _trail = host.audit();
    }

    #[test]
    fn the_real_hosts_trait_objects_are_what_the_gate_is_given() {
        let source = into_source(MapSource::new().with("1/stat", "x"));
        assert_eq!(source.read("1/stat").unwrap(), b"x");
        let spool = into_spool(FakeListing(vec![b"n".to_vec()]));
        assert_eq!(spool.names().unwrap(), vec![b"n".to_vec()]);
    }

    #[test]
    fn an_authorized_vector_that_cannot_be_built_is_refused_at_the_exec_and_nothing_runs() {
        // Unreachable through `run`, where the entry's NUL bytes are refused
        // long before: reached here by authorizing an approval that carries
        // one, to prove the exec itself still refuses to hand the kernel a
        // prefix.
        let spool = Rc::new(FakeSpool::holding(&[]));
        let mut host = FakeHost::new(&spool);
        let approved = Approved {
            program: "/usr/bin/tool".to_owned(),
            argv: Vec::new(),
            exec_argv: vec![b"a\0b".to_vec()],
            environment: Vec::new(),
            action: "aido.x".to_owned(),
            rule_source: "r:1".to_owned(),
            requested_action: "aido.x".to_owned(),
            requested_rule_source: "r:1".to_owned(),
            nonce: NONCE_A.to_owned(),
        };
        let caller = GateCaller::unidentified(GATE_PID);
        let build = |previous: Option<&Record>, approval: &Approved| {
            authorization_record(previous, approval, &caller, None)
        };
        let authorized = authorize(&mut host.audit, approved, &build).unwrap();
        let (path, owner) = program_file("tool", b"the program that would run as root");
        let program = FakePrograms::serving(path, owner)
            .open(Path::new("/usr/bin/tool"))
            .unwrap();
        let refusal = execute(&host, &authorized, &program);
        assert_eq!(refusal.code(), "gate_failed_exec");
        assert_eq!(exec_calls(&host), 0);
    }
}
