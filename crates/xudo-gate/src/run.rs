//! The gate's whole sequence, written against traits.
//!
//! `xudo-gate-bin` is five lines: it collects `argv`, hands it to [`run`] with
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
//! 2. **`/dev/null` for closed 0 to 2.** Before the rlimit read, umask and cwd
//!    reset, and before any other `open`. A closed standard stream would give
//!    the next opened descriptor number 0, 1 or 2.
//! 3. **PID 1's resource limits.** Read through a pinned descriptor verified
//!    as procfs, then set every limit before the gate opens policy, spool,
//!    program, or audit state. The soft open-file limit is capped at 1024 and
//!    core dumps are disabled. Any failure refuses.
//! 4. **Umask `022` and working directory `/`.** Before anything else is opened
//!    or written. A caller umask of `000` would make a file an apt hook or a
//!    maintainer script creates world-writable. Either failure refuses.
//! 5. **`PR_SET_NO_NEW_PRIVS`.** Irreversible and inherited by the exec, so
//!    nothing the gate runs gains privilege from a set-user-ID or
//!    file-capability binary. Set before anything is consumed, so a host that
//!    refuses costs the caller nothing.
//! 6. **The invocation.** No arguments, and `argv[0]` is one of the two gate
//!    names, `-auth` or `-nopass`. Any other name is refused.
//! 7. **`/proc` verified as procfs**, on the descriptor it is read through,
//!    and then **the mode from the executed file**: `/proc/self/exe` is
//!    compared with both gate files under `/usr/libexec/xudo`, each opened
//!    through the trust walk and each with one name only
//!    ([`xudo_sys::GateFiles`]). The match is the mode, and `argv[0]` must
//!    say the same: a caller can choose a name and cannot choose an inode.
//! 8. **The lineage walk**: the gate, `sudo` or `sudo-rs` (with its `use_pty`
//!    monitor) or `doas`, and then the `xudo` process that asked, each pinned
//!    by `(pid, starttime)`, bounded at [`LINEAGE_PROCESSES`] processes. The
//!    names the walk reads are hints and go in the audit record; nothing
//!    branches on them. What the walk yields is a set of pins, and the next
//!    step matches an entry to one of them.
//! 9. **The ruleset**, only through `xudo_sys::load_trusted_rules`. The
//!    generation is [`xudo_policy::Generation::id`] of what was loaded, the
//!    value the broker minted against.
//! 10. **The spool and the clock.** The broker's spool, opened through the trust
//!     walk and seen through [`RequestSpool`], which can list, read and consume
//!     and nothing else; at most [`MAX_SPOOL_NAMES`] names are walked, and the
//!     listing is cut off one name past that, so a crowded spool is refused
//!     without being read to its end. Every
//!     entry named by a nonce is read on a descriptor of its own. Exactly one
//!     must be pinned to an ancestor: none is [`Refusal::NoPendingRequest`],
//!     more than one is refused. The clock is the broker's, [`xudo_sys::HostClock`]:
//!     one `CLOCK_BOOTTIME` that a deadline is stamped and judged on, and a
//!     reading of zero is refused as no reading.
//! 11. **`validate`, then [`decide`]**, then **consume**: the entry is unlinked
//!     through the verified directory descriptor before anything executes, and
//!     a failed unlink — `ENOENT` included, which means a second gate took it
//!     first ([`xudo_sys::SpoolError::Gone`]) — is a refusal. An entry is
//!     therefore used at most once. This is the one place the broker's own
//!     `remove`, for which a missing name is success, must not be used.
//! 12. **The program**, opened through the trust walk and judged and hashed on
//!     that descriptor. A `#!` script is refused as a script.
//! 13. **The audit record**, through [`xudo_sys::authorize`], before the exec.
//!     A gate that cannot write its record refuses, and the exec takes the
//!     [`Authorized`] that only a written record makes.
//! 14. **`execveat(fd, "", AT_EMPTY_PATH)`**, with the argument vector built
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
//! stable code and severity only. When an append fails because the log is
//! damaged, or because cutting a torn tail back itself failed, it prints one
//! more line: move the log aside. That line is fixed. Nothing from the log,
//! the spool, the ruleset or the environment reaches either line.

use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use xudo_audit::record::Record;
#[cfg(test)]
use xudo_policy::{LoadedRuleSet, engine};
#[cfg(test)]
use xudo_sys::TrustedRulesError;
use xudo_sys::{
    AuditSink, Authorized, CgroupCalls, Clock, GateFiles, GateMode, HostClock, HostGateFiles,
    HostHygiene, HostPeer, HostPrograms, HostSyscalls, Hygiene, PeerCalls, ProcRef, ProcSource,
    Program, Programs, Spool, SpoolDir, SpoolError, Syscalls, VerifiedProc, authorize, lineage,
};

use crate::decide::{
    Approved, GateCaller, GateContext, Refusal, Stage, authorization_record, decide,
    exec_failure_record, refusal_record,
};
use crate::policy::{LoadedPolicy, PolicyError};
use crate::queue_claim::{self, QUEUE_DIR, QueueClaim};
use crate::request::{
    BoottimeMillis, CallerPin, PendingRequest, RequestError, SPOOL_DIR, is_nonce,
};

/// The first descriptor the gate marks close-on-exec: everything above the
/// three standard streams.
pub const FIRST_INHERITED_FD: u32 = 3;

/// How many processes the lineage walk reads: the gate and the eight above it.
///
/// The hop is at most three deep: the gate, `sudo`'s monitor, `sudo` itself,
/// then `xudo`. The bound is wider than that so a wrapper between them does
/// not lock a legitimate caller out, and narrow enough that a deep process
/// tree is not work a caller can demand of the gate.
pub const LINEAGE_PROCESSES: usize = 9;

/// The one name the gate runs under: the hardlink `sudo` asks for a password
/// to reach.
pub const AUTH_NAME: &[u8] = b"xudo-gate-auth";

/// The other name: the gate a harness grant reaches without a password. No
/// sudoers text names it until the grant ships, and nothing mints the `harness`
/// entry it requires, so it refuses every invocation today.
pub const NOPASS_NAME: &[u8] = b"xudo-gate-nopass";

/// Where the root-owned ruleset is read from.
pub const RULES_DIR: &str = "/etc/xudo/rules.d";
/// The root-owned settings file rechecked by the gate.
pub const CONFIG_FILE: &str = "/etc/xudo/config.toml";

/// The most bytes of one spool entry the gate reads on the strength of a name.
///
/// A request is a few hundred bytes, and what the broker writes is at most a
/// 16 KiB request plus fields of known size. This is a ceiling on what a name
/// can make the gate read, not a size anything legitimate approaches.
pub const MAX_ENTRY_BYTES: usize = 64 * 1024;

/// The most names the gate will walk, and so the most it reads of a listing.
///
/// The broker keeps at most 64 live entries and removes the rest, so a spool
/// holding more than this is a broker that is not reaping, or something
/// wrong. Either way the gate does not read it entry by entry, and does not
/// read the whole directory to find out: the listing is cut off one name past
/// this ([`LISTED_NAMES`]), which is all it takes to see the bound crossed.
pub const MAX_SPOOL_NAMES: usize = 4096;

/// How many names the gate asks the spool for: one more than it will walk, so
/// that a spool over the bound is seen to be over it without being read to the
/// end.
const LISTED_NAMES: usize = MAX_SPOOL_NAMES + 1;

/// Everything the gate touches outside itself.
///
/// One trait rather than eight parameters, so the real host is one value and a
/// test host is another, and so the gate cannot be handed a mix.
pub trait GateHost {
    /// The system calls that need `unsafe`.
    fn syscalls(&self) -> &dyn Syscalls;
    /// The safe process calls used by the ancestor recheck.
    fn peers(&self) -> &dyn PeerCalls;
    /// Opens the kernel cgroup view and its root-owned session records.
    ///
    /// # Errors
    ///
    /// Returns an error if `/sys/fs/cgroup` or the session-record directory
    /// cannot be opened and verified.
    fn cgroups(&self) -> Result<Box<dyn CgroupCalls>, xudo_sys::SysError>;
    /// What the gate settles about its own process.
    fn hygiene(&self) -> &dyn Hygiene;
    /// The boottime clock.
    fn clock(&self) -> &dyn Clock;
    /// Opens `/proc` and proves it is procfs.
    ///
    /// # Errors
    ///
    /// [`xudo_sys::SysError`] when it cannot be opened or is not procfs.
    fn open_proc(&self) -> Result<Box<dyn ProcSource>, xudo_sys::SysError>;
    /// Loads root's rules and settings through the trust walk.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] when either trusted input cannot be read or parsed.
    fn load_policy(&self) -> Result<LoadedPolicy, PolicyError>;
    /// Whether the freeze marker for `uid`'s own agents stands. A marker that
    /// cannot be read cleanly counts as standing: the gate fails closed.
    fn user_frozen(&self, uid: u32) -> bool;
    /// Opens the spool through the trust walk.
    ///
    /// # Errors
    ///
    /// [`SpoolError`] when it fails the walk or is not a private root-owned
    /// directory.
    fn open_spool(&self) -> Result<Box<dyn RequestSpool>, SpoolError>;
    /// Opens the root-owned queue through the trust walk.
    ///
    /// The gate reads one record and does not write. An open that fails the
    /// walk is a spool failure, distinct from a record that is not claimed.
    ///
    /// # Errors
    ///
    /// [`SpoolError`] when the directory fails the walk or is not a private
    /// root-owned directory.
    fn open_queue(&self) -> Result<Box<dyn QueueClaim>, SpoolError>;
    /// Which gate file this process is.
    fn gate_files(&self) -> &dyn GateFiles;
    /// Where programs are opened.
    fn programs(&self) -> &dyn Programs;
    /// The audit trail.
    fn audit(&mut self) -> &mut dyn AuditSink;
    /// Runs a typed remove-path. The host opens nothing until this is called.
    ///
    /// # Errors
    ///
    /// [`xudo_sys::RemoveError`] when the walk removes nothing. A partial walk
    /// is `Ok` with [`xudo_sys::RemoveReport::partial`] set.
    fn remove_path(
        &mut self,
        request: &xudo_sys::RemoveRequest,
    ) -> Result<xudo_sys::RemoveReport, xudo_sys::RemoveError>;
}

/// The real host: the running kernel, the real `/proc`, `/etc/xudo/rules.d`,
/// `/run/xudo/req`, and the system audit trail.
#[derive(Debug)]
pub struct SystemHost {
    audit: xudo_sys::AuditTrail,
}

impl SystemHost {
    /// The host for this machine. Opens nothing: every file is opened by the
    /// step that needs it.
    pub fn new() -> Self {
        Self {
            audit: xudo_sys::AuditTrail::system("xudo-gate"),
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

    fn peers(&self) -> &dyn PeerCalls {
        &HostPeer
    }

    fn cgroups(&self) -> Result<Box<dyn CgroupCalls>, xudo_sys::SysError> {
        boxed_cgroups(xudo_sys::HostCgroup::open())
    }

    fn hygiene(&self) -> &dyn Hygiene {
        &HostHygiene
    }

    fn clock(&self) -> &dyn Clock {
        &HostClock
    }

    fn open_proc(&self) -> Result<Box<dyn ProcSource>, xudo_sys::SysError> {
        VerifiedProc::open().map(into_source)
    }

    fn load_policy(&self) -> Result<LoadedPolicy, PolicyError> {
        crate::policy::load(Path::new(RULES_DIR), Path::new(CONFIG_FILE))
    }

    fn user_frozen(&self, uid: u32) -> bool {
        crate::policy::user_frozen(uid, &xudo_sys::read_trusted_file)
    }

    fn open_spool(&self) -> Result<Box<dyn RequestSpool>, SpoolError> {
        SpoolDir::open(Path::new(SPOOL_DIR)).map(into_spool)
    }

    fn open_queue(&self) -> Result<Box<dyn QueueClaim>, SpoolError> {
        SpoolDir::open_beneath(Path::new(QUEUE_DIR)).map(into_queue)
    }

    fn gate_files(&self) -> &dyn GateFiles {
        &HostGateFiles
    }

    fn programs(&self) -> &dyn Programs {
        &HostPrograms
    }

    fn audit(&mut self) -> &mut dyn AuditSink {
        &mut self.audit
    }

    fn remove_path(
        &mut self,
        request: &xudo_sys::RemoveRequest,
    ) -> Result<xudo_sys::RemoveReport, xudo_sys::RemoveError> {
        xudo_sys::remove_path_on_host(request)
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
fn into_spool<S: Spool + 'static>(spool: S) -> Box<dyn RequestSpool> {
    Box::new(SpoolEntries(spool))
}

/// A queue directory as the read-only view the host hands out. See [`into_source`].
fn into_queue<S: Spool + 'static>(spool: S) -> Box<dyn QueueClaim> {
    Box::new(QueueDir(spool))
}

/// A queue directory seen only through [`QueueClaim`].
struct QueueDir<S>(S);

impl<S: Spool> QueueClaim for QueueDir<S> {
    fn read(&self, name: &str) -> Result<Vec<u8>, SpoolError> {
        self.0.read(name.as_bytes(), MAX_ENTRY_BYTES)
    }
}

/// What the gate does to the spool, and nothing more: list it, read one entry,
/// and take one.
///
/// The broker's [`Spool`] can also lock, publish and remove. The gate never
/// has a reason to, so it is not handed a spool that can: a hostile entry
/// cannot make the gate write into the directory it reads, because the type
/// it holds has no way to say so.
pub trait RequestSpool {
    /// The names in the spool, as bytes: at most [`MAX_SPOOL_NAMES`] and one
    /// more, the one that shows the spool is over the bound. A listing that
    /// long is a spool the gate refuses; the rest of the directory is never
    /// read.
    ///
    /// # Errors
    ///
    /// [`SpoolError`] when the directory cannot be listed.
    fn names(&self) -> Result<Vec<Vec<u8>>, SpoolError>;

    /// One entry's bytes, read through a descriptor of its own, at most
    /// [`MAX_ENTRY_BYTES`] of them.
    ///
    /// # Errors
    ///
    /// [`SpoolError`] for anything that is not a regular, private,
    /// root-owned, singly linked file of that size, and for a name that is not
    /// one path component.
    fn read(&self, name: &str) -> Result<Vec<u8>, SpoolError>;

    /// Takes one entry: after this `Ok`, nobody else can.
    ///
    /// # Errors
    ///
    /// [`SpoolError::Gone`] when it was already taken, and any other failure
    /// to unlink it. Never `Ok` for an entry that was not there.
    fn consume(&self, name: &str) -> Result<(), SpoolError>;
}

/// A [`Spool`] seen through the gate's narrower [`RequestSpool`].
#[derive(Debug)]
struct SpoolEntries<S>(S);

impl<S: Spool> RequestSpool for SpoolEntries<S> {
    fn names(&self) -> Result<Vec<Vec<u8>>, SpoolError> {
        self.0.names_up_to(LISTED_NAMES)
    }

    fn read(&self, name: &str) -> Result<Vec<u8>, SpoolError> {
        self.0.read(name.as_bytes(), MAX_ENTRY_BYTES)
    }

    fn consume(&self, name: &str) -> Result<(), SpoolError> {
        self.0.consume(name.as_bytes())
    }
}

/// How the gate ends when it did not exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GateExit {
    /// The exit status: 17, 18 or 19. The gate execs in place, so a child can
    /// exit with the same numbers; the stderr refusal line tells them apart.
    pub status: i32,
    /// Standard error. The first line is the code and severity. A second line
    /// is present only when an audit append reported a damaged log, and it is
    /// a fixed recovery sentence with nothing from the log or the caller.
    pub message: String,
}

/// What the record says confirmed the request under this gate file.
fn confirmation_text(mode: GateMode) -> &'static str {
    match mode {
        GateMode::Auth => "confirmation=password (sudo's own prompt, on the -auth name)",
        GateMode::Nopass => "confirmation=none (the -nopass name asks no password)",
    }
}

/// Accepts the one invocation `sudo` makes: no arguments, under one of the two
/// gate names.
///
/// The name is the last `/`-separated segment of `argv[0]`, compared as bytes
/// and exactly: no normalisation, so `xudo-gate-auth/` and `xudo-gate-auth/.`
/// are not it. This is what the caller *claims*. [`proceed`] refuses unless
/// the executed file says the same.
fn accept_invocation(args: &[OsString]) -> Result<GateMode, Refusal> {
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
        Ok(GateMode::Auth)
    } else if last == NOPASS_NAME {
        Ok(GateMode::Nopass)
    } else {
        Err(refuse(format!(
            "started as {}, and only {} and {} run",
            bytes.escape_ascii(),
            AUTH_NAME.escape_ascii(),
            NOPASS_NAME.escape_ascii()
        )))
    }
}

/// The mode the executed file says, and refused unless it is the one `argv[0]`
/// claimed.
fn mode_of_executed_file(
    host: &dyn GateHost,
    proc: &dyn ProcSource,
    claimed: GateMode,
) -> Result<GateMode, Refusal> {
    let refuse = |reason: String| Refusal::Failed {
        stage: Stage::Invocation,
        reason,
    };
    let executed = host
        .gate_files()
        .executing(proc)
        .map_err(|error| refuse(error.to_string()))?;
    if executed == claimed {
        Ok(executed)
    } else {
        Err(refuse(
            "argv[0] names one gate file and the executed file is the other".to_owned(),
        ))
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
    /// Set when the authorization append reported a damaged log. The refusal
    /// record is a second append; either one is enough to warn the operator.
    /// The sentence is static.
    audit_notice: Option<&'static str>,
    /// Entries a remove-path walk already removed when its final audit
    /// record failed: the work is done, so the exit must not say "refused".
    removed_unrecorded: Option<usize>,
}

/// Runs the gate.
///
/// Returns when the gate did **not** exec. A successful exec replaces the
/// process. A finished remove-path returns here: the walk already wrote its
/// one audit record, and this function does not write another. A refusal is
/// written to the audit trail where that was possible.
pub fn run(host: &mut dyn GateHost, args: &[OsString]) -> GateExit {
    #[cfg(feature = "lane-short-ttl")]
    crate::keep_lane_short_ttl_marker_linked();

    let mut progress = Progress {
        gate_pid: host.hygiene().pid(),
        ..Progress::default()
    };
    match proceed(host, args, &mut progress) {
        Ok(report) => GateExit {
            status: crate::operate::operation_status(&report),
            message: crate::operate::operation_message(&report),
        },
        Err(refusal) => finish_refusal(host, &refusal, &progress),
    }
}

/// Writes the refusal and builds the exit line.
fn finish_refusal(host: &mut dyn GateHost, refusal: &Refusal, progress: &Progress) -> GateExit {
    // The authorization append and the refusal append are different calls.
    // Either one reporting damage is enough, and the sentence is the same,
    // so the operator sees it once.
    let notice = record(host, refusal, progress).or(progress.audit_notice);
    let mut message = match progress.removed_unrecorded {
        Some(count) => format!(
            "xudo-gate: removed {count} entries; the audit record failed ({}, severity {})",
            refusal.code(),
            refusal.severity().label()
        ),
        None => format!(
            "xudo-gate: refused ({}, severity {})",
            refusal.code(),
            refusal.severity().label()
        ),
    };
    if let Some(line) = notice {
        message.push('\n');
        message.push_str("xudo-gate: ");
        message.push_str(line);
    }
    GateExit {
        status: refusal.exit_code().as_i32(),
        message,
    }
}

/// Writes the refusal to the audit trail, or the failure of an exec that was
/// already authorized. Best effort: a refusal stands whether or not it lands.
///
/// Returns the fixed recovery sentence when the append says the log may be
/// damaged. The sentence contains nothing from the error.
fn record(host: &mut dyn GateHost, refusal: &Refusal, progress: &Progress) -> Option<&'static str> {
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
    host.audit()
        .append(&build)
        .err()
        .and_then(|error| error.damaged_log_notice())
}

/// Adds evidence to a record the builders in [`crate::decide`] made.
fn annotate(record: Record, extra: &[String]) -> Record {
    let mut evidence = record.evidence.clone();
    evidence.extend(extra.iter().cloned());
    record.with_evidence(evidence)
}

/// Refuses a queued run whose queue record is not claimed for this nonce.
///
/// An entry with no queue id is an ordinary human-path mint and is not looked
/// up. Opening the queue directory is a spool failure. A missing, unreadable,
/// or non-matching record is [`RequestError::QueueNotClaimed`]: the request
/// must not fall through and run as a normal human-path command.
fn require_queued_claim(
    host: &dyn GateHost,
    entry: &PendingRequest,
    caller: &GateCaller,
) -> Result<(), Refusal> {
    let Some(id) = entry.queue_id.as_deref() else {
        return Ok(());
    };
    // The queue is the human's. A caller the gate could only read as
    // unattested, or in other namespaces than the host's, never claims it.
    if caller.attested_class != crate::request::AttestedClass::Human {
        return Err(Refusal::Request(RequestError::QueueNeedsAttestedHuman));
    }
    let queue = stage(Stage::Spool, host.open_queue())?;
    let name = queue_claim::queue_file_name(id);
    let held = match queue.read(&name) {
        Ok(bytes) => queue_claim::queued_claim_holds(&bytes, &entry.nonce),
        Err(_) => false,
    };
    if held {
        Ok(())
    } else {
        Err(Refusal::Request(RequestError::QueueNotClaimed))
    }
}

/// The steps, in order. `Ok` is a finished remove-path. `Err` is every other
/// ending, including a successful exec, which does not return to the caller
/// of [`run`] on the real host and is a refusal here when the exec fails.
#[allow(clippy::too_many_lines)]
fn proceed(
    host: &mut dyn GateHost,
    args: &[OsString],
    progress: &mut Progress,
) -> Result<xudo_sys::RemoveReport, Refusal> {
    stage(
        Stage::Descriptors,
        host.syscalls().mark_cloexec_from(FIRST_INHERITED_FD),
    )?;
    // Streams before the reset. `reset_cwd` opens an `O_PATH` descriptor of
    // `/`, and a closed 0, 1 or 2 would give that descriptor the stream's
    // number. Nothing before the reset depends on the umask or the working
    // directory, so moving the reset earlier only reopens that hole.
    stage(Stage::Streams, host.hygiene().ensure_std_streams())?;
    stage(Stage::CallerState, host.hygiene().reset_rlimits_from_pid1())?;
    stage(Stage::CallerState, host.hygiene().reset_umask())?;
    stage(Stage::CallerState, host.hygiene().reset_cwd())?;
    stage(Stage::Privileges, host.hygiene().forbid_new_privileges())?;
    let claimed = accept_invocation(args)?;
    progress
        .evidence
        .push(format!("gate_argv0={}", args_first_escaped(args)));

    let proc = stage(Stage::Procfs, host.open_proc())?;
    // The mode is the executed file's, and `argv[0]` only has to agree.
    let mode = mode_of_executed_file(&*host, &*proc, claimed)?;
    let ancestors = stage(
        Stage::Lineage,
        lineage(&*proc, progress.gate_pid, LINEAGE_PROCESSES),
    )?;
    progress
        .evidence
        .push(format!("lineage={}", ancestors.describe()));

    let loaded = load_policy_or_refuse(host)?;
    progress.evidence.extend(loaded.fault_evidence());
    let spool = stage(Stage::Spool, host.open_spool())?;
    let now = read_clock(host.clock())?;

    let matched = find_entry(&*spool, ancestors.chain.get(1..).unwrap_or_default())?;
    let own = ancestors
        .chain
        .first()
        .map_or(CallerPin::new(progress.gate_pid, 0), pin_of);
    let passwd = loaded.passwd.as_str();
    let (caller, live_uid) = caller_for(
        host,
        &*proc,
        matched.as_ref(),
        own,
        &ancestors.chain,
        now,
        &loaded.rules.harnesses,
        passwd,
    );
    progress.caller = Some(caller.clone());
    let pending = matched.map(|found| found.entry);
    progress.pending.clone_from(&pending);

    // The uid read from the live ancestor's own `status` picks whose freeze
    // marker also applies, and must be the uid the broker minted the entry for.
    // The entry's uid is a claim and is never used for a decision. Root's
    // global marker is already in the loaded settings. With no entry there is
    // no uid, and `decide` refuses on the missing entry.
    let mut settings = loaded.settings;
    if let Some(found) = &pending {
        let Some(live) = live_uid.filter(|live| *live == found.caller_uid) else {
            return Err(Refusal::Request(RequestError::WrongCallerUid {
                expected: found.caller_uid,
                actual: live_uid,
            }));
        };
        settings.frozen |= host.user_frozen(live);
    }
    let context = GateContext {
        generation: loaded.rules.generation.id(),
        now: BoottimeMillis(now),
        settings,
        password_confirms: mode == GateMode::Auth,
        mode,
    };
    // A missing spool entry is refused here. `decide` refuses the same case,
    // and after it succeeds the entry is always present, so a later check
    // must not keep a branch that cannot run.
    let Some(pending_entry) = pending else {
        return Err(Refusal::NoPendingRequest {
            pid: caller.pin.pid,
        });
    };
    crate::decide::validate_pending_identity(&pending_entry, &caller, &context)?;
    // A typed operation never opens the marker program and never execs.
    // The password name was already required by `accept_invocation`.
    if let Some(requested) = pending_entry.operation.as_ref() {
        return run_typed_operation(
            host,
            &loaded,
            &caller,
            &pending_entry,
            requested,
            &context,
            &*spool,
            progress,
        );
    }
    let approved = decide(&loaded.rules.rules, &caller, Some(&pending_entry), context)?;
    progress.evidence.push(confirmation_text(mode).to_owned());
    progress.evidence.push(format!(
        "gate_mode={mode:?} via={}",
        pending_entry.via.label()
    ));
    require_queued_claim(host, &pending_entry, &caller)?;

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

    let confirmed_by = pending_entry
        .confirmed_by
        .as_ref()
        .map(crate::request::WatcherPin::audit_text);
    let evidence = progress.evidence.clone();
    let build = |previous: Option<&Record>, approval: &Approved| {
        annotate(
            authorization_record(previous, approval, &caller, confirmed_by.as_deref()),
            &evidence,
        )
    };
    let authorized = match authorize(host.audit(), approved, &build) {
        Ok(authorized) => authorized,
        Err(error) => {
            progress.audit_notice = error.damaged_log_notice();
            return Err(Refusal::Failed {
                stage: Stage::Audit,
                reason: error.to_string(),
            });
        }
    };
    progress.authorized = Some((
        authorized.receipt().seq().get(),
        authorized.approval().clone(),
    ));

    Err(execute(host, &authorized, &program))
}

/// Re-decides a remove-path, consumes the spool entry, walks, then writes the
/// one audit record. Policy and password failures do not consume. A walk
/// error after consume is a refusal: nothing was removed. An audit error
/// after a removal is also a refusal, and the names are already gone.
#[allow(clippy::too_many_arguments)]
fn run_typed_operation(
    host: &mut dyn GateHost,
    loaded: &LoadedPolicy,
    caller: &GateCaller,
    pending: &PendingRequest,
    requested: &crate::request::RequestedOp,
    context: &GateContext,
    spool: &dyn RequestSpool,
    progress: &mut Progress,
) -> Result<xudo_sys::RemoveReport, Refusal> {
    let passwd = loaded.passwd.as_str();
    let mut work = crate::operate::prepare_remove(
        &loaded.rules.rules,
        &caller.facts,
        pending,
        &requested.op,
        &requested.target,
        requested.dry_run,
        context.settings,
        passwd,
        context.password_confirms,
    )?;
    progress.evidence.push(format!(
        "op=remove-path target={}",
        requested.target.escape_ascii()
    ));
    stage(Stage::Spool, spool.consume(&pending.nonce))?;
    // Fatal signals may still terminate the gate between this record and an
    // unlink; no safe signal-deferral API is available in this crate. The
    // intent remains a durable trace of what the walk was about to do.
    let mut planned_request = work.request.clone();
    planned_request.dry_run = true;
    let planned = match host.remove_path(&planned_request) {
        Ok(report) => report,
        Err(error) => return Err(crate::operate::walk_refusal(&error)),
    };
    let intent = host
        .audit()
        .append(&|previous| crate::operate::intent_record(previous, caller, &work, &planned))
        .map_err(|error| {
            progress.audit_notice = error.damaged_log_notice();
            Refusal::Failed {
                stage: Stage::Audit,
                reason: error.to_string(),
            }
        })?;
    work.intent_sequence = Some(intent.seq().get());
    let report = match host.remove_path(&work.request) {
        Ok(report) => report,
        Err(error) => return Err(crate::operate::walk_refusal(&error)),
    };
    let recorded_caller = caller.clone();
    let recorded_work = work.clone();
    let recorded_report = report.clone();
    if let Err(error) = host.audit().append(&|previous| {
        crate::operate::remove_record(previous, &recorded_caller, &recorded_work, &recorded_report)
    }) {
        progress.audit_notice = error.damaged_log_notice();
        progress.removed_unrecorded = Some(report.removed.len());
        return Err(Refusal::Failed {
            stage: Stage::Audit,
            reason: error.to_string(),
        });
    }
    Ok(report)
}

fn load_policy_or_refuse(host: &dyn GateHost) -> Result<LoadedPolicy, Refusal> {
    match host.load_policy() {
        Ok(loaded) => Ok(loaded),
        Err(error @ PolicyError::Rules(_)) => Err(Refusal::Failed {
            stage: Stage::Rules,
            reason: error.to_string(),
        }),
        Err(error) => Err(Refusal::Failed {
            stage: Stage::Config,
            reason: error.to_string(),
        }),
    }
}

/// Reads boottime, refusing a reading that cannot be one.
///
/// The clock is the broker's: [`xudo_sys::HostClock`], the one `CLOCK_BOOTTIME`
/// a deadline is stamped and judged on. It cannot fail, and for a negative
/// reading it answers zero. Zero is the
/// fail-closed reading for the broker, which then stamps a deadline already
/// behind it, and the wrong direction here, where it would make every deadline
/// look still ahead. No host is up for less than a second with a caller
/// waiting on a request, so a zero is no reading, and the gate refuses it.
fn read_clock(clock: &dyn Clock) -> Result<u64, Refusal> {
    match clock.boottime_millis() {
        0 => Err(Refusal::Failed {
            stage: Stage::Clock,
            reason: "the boottime clock read zero milliseconds, which is no reading".to_owned(),
        }),
        secs => Ok(secs),
    }
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

/// A spool entry, and the process the walk matched it to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Matched {
    /// The entry: the one pinned to a process in the gate's lineage.
    entry: PendingRequest,
    /// That process, as the kernel's `/proc` reported it.
    ///
    /// Not the entry's own `caller_pid` and `caller_starttime`: those are the
    /// entry's claim, and [`PendingRequest::validate`] is asked whether the
    /// claim is true of *this*. A pin made from the claim would be checked
    /// against itself, and a match that was wrong would sail through.
    caller: CallerPin,
}

/// The caller `decide` judges the entry for, and the uid read from its live
/// process. Any class comes from a fresh kernel cgroup read and ancestor
/// recheck, and the uid from the ancestor's own `status`; the entry supplies
/// neither. A caller or a gate in namespaces other than PID 1's is unattested,
/// and the class is never stronger than the broker's.
#[allow(clippy::too_many_arguments)]
fn caller_for(
    host: &dyn GateHost,
    proc: &dyn ProcSource,
    matched: Option<&Matched>,
    own: CallerPin,
    ancestors: &[ProcRef],
    now: u64,
    registry: &xudo_policy::HarnessRegistry,
    passwd: &str,
) -> (GateCaller, Option<u32>) {
    let Some(found) = matched else {
        return (GateCaller::unidentified(own.pid), None);
    };
    let index = ancestors.iter().position(|ancestor| {
        ancestor.pid == found.caller.pid && ancestor.starttime == found.caller.starttime
    });
    let child = index
        .and_then(|at| at.checked_sub(1))
        .and_then(|at| ancestors.get(at))
        .map(|child| (child.pid, child.starttime));
    let gate_clean = ancestors
        .first()
        .is_some_and(|gate| crate::live::read(proc, gate).namespaces_match_init);
    let caller_facts = index
        .and_then(|at| ancestors.get(at))
        .map(|caller| crate::live::read(proc, caller));
    let live_uid = caller_facts.and_then(|facts| facts.uid);
    let live = match (host.cgroups(), child, live_uid, caller_facts) {
        (Ok(cgroups), Some(child), Some(uid), Some(facts))
            if gate_clean && facts.namespaces_match_init =>
        {
            let live = crate::classify::classify_with_registry(
                cgroups.as_ref(),
                host.peers(),
                host.syscalls(),
                registry,
                passwd,
                crate::classify::AncestorPin {
                    caller: (found.caller.pid, found.caller.starttime),
                    uid,
                    child,
                    now_boottime_ms: now,
                },
            );
            if found.entry.effective_class(&live.attested_class) == live.attested_class {
                // Agreement with the broker's record, or nothing.
                live
            } else {
                crate::classify::LiveClass::unattested(
                    uid,
                    "the broker could not attest this caller, and the gate never upgrades it",
                )
            }
        }
        _ => crate::classify::LiveClass::unattested(
            live_uid.unwrap_or(crate::decide::UNKNOWN_UID),
            "the gate could not recheck its caller's lineage, uid, and namespaces",
        ),
    };
    let caller = GateCaller {
        pin: found.caller,
        facts: live.facts,
        attested_class: live.attested_class,
        attested_scope_id: live.scope_id,
        boot_id: live.boot_id,
    };
    (caller, live_uid)
}

/// The spool entry pinned to one of the `ancestors`, if exactly one is, and
/// the ancestor it is pinned to.
///
/// Only names that are nonces are opened. An entry that cannot be read, is
/// not UTF-8, or does not parse cannot be matched to anyone and is passed
/// over: refusing on it would let one stray file lock every caller out, and
/// passing over it can only end in "no pending request".
fn find_entry(spool: &dyn RequestSpool, ancestors: &[ProcRef]) -> Result<Option<Matched>, Refusal> {
    let names = stage(Stage::Spool, spool.names())?;
    if names.len() > MAX_SPOOL_NAMES {
        // The listing stopped one name past the bound, so how many more there
        // are is not known, and not said.
        return Err(Refusal::Failed {
            stage: Stage::Spool,
            reason: format!(
                "the spool holds more than the {MAX_SPOOL_NAMES} names the gate will walk"
            ),
        });
    }
    let matched: Vec<(String, Matched)> = names
        .iter()
        .filter_map(|raw| std::str::from_utf8(raw).ok().filter(|name| is_nonce(name)))
        .filter_map(|name| read_entry(spool, name).map(|entry| (name, entry)))
        .filter_map(|(name, entry)| {
            pinned_to(&entry, ancestors).map(|caller| (name.to_owned(), Matched { entry, caller }))
        })
        .collect();
    if let Some((name, _)) = matched
        .iter()
        .find(|(name, found)| found.entry.nonce != *name)
    {
        return Err(Refusal::Request(RequestError::ForgedNonce {
            name: name.clone(),
        }));
    }
    match matched.len() {
        0 => Ok(None),
        1 => Ok(matched.into_iter().next().map(|(_, found)| found)),
        count => Err(Refusal::Request(RequestError::Ambiguous { matches: count })),
    }
}

/// One entry, read on its own descriptor and parsed; `None` for anything that
/// is not a request.
fn read_entry(spool: &dyn RequestSpool, name: &str) -> Option<PendingRequest> {
    spool.read(name).ok().and_then(|bytes| {
        std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| PendingRequest::parse(text).ok())
    })
}

/// The process an entry was minted for, if it is one of these: the pid **and**
/// the start time, because a pid alone is a name the kernel reissues. The pin
/// returned is made from the ancestor, not from the entry.
fn pinned_to(entry: &PendingRequest, ancestors: &[ProcRef]) -> Option<CallerPin> {
    ancestors
        .iter()
        .find(|ancestor| {
            ancestor.pid == entry.caller_pid && ancestor.starttime == entry.caller_starttime
        })
        .map(pin_of)
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

/// Boxes an opened cgroup seam. A function of its own so a test can run the
/// `Ok` path on a host where the real seam never opens (macOS).
fn boxed_cgroups<T: CgroupCalls + 'static>(
    opened: Result<T, xudo_sys::SysError>,
) -> Result<Box<dyn CgroupCalls>, xudo_sys::SysError> {
    opened.map(|calls| Box::new(calls) as Box<dyn CgroupCalls>)
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

    use std::cell::Cell;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::rc::Rc;

    use xudo_audit::TailError;
    use xudo_audit::record::Decision as AuditDecision;
    use xudo_policy::{HarnessFile, RuleFile, load_policy, load_rule_files};
    use xudo_sys::{
        AuditError, FakeAuditSink, FakeHygiene, FakePeer, FakePrograms, FakeSpool, FakeSyscalls,
        FixedClock, HygieneCall, MapSource, ProcFile, ProgramError, ScopeFacts, SpoolCall,
        SysError, TrustError,
    };

    use super::*;
    use crate::env::child_environment;
    use crate::request::REQUEST_SCHEMA_VERSION;

    const NONCE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NONCE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const GATE_PID: u32 = 500;
    const XUDO_PID: u32 = 200;
    const XUDO_START: u64 = 7_000;
    const NOW: u64 = 100;

    const RULES: &str = r#"
[[action]]
id = "xudo.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "xudo.reload"
tier = "svc-control"
exe = "/usr/bin/systemctl"
confirm = "always"
args = [
  { name = "verb", matcher = { literal = "daemon-reload" } },
]
"#;

    fn rules() -> LoadedRuleSet {
        load_policy(
            vec![RuleFile {
                name: b"10-test.toml".to_vec(),
                bytes: RULES.as_bytes().to_vec(),
            }],
            &[HarnessFile {
                name: b"codex.toml".to_vec(),
                bytes: b"label = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 4\n".to_vec(),
            }],
        )
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

    fn agent_record() -> Vec<u8> {
        let hash = rules().harnesses.get("codex").unwrap().hash_hex();
        format!(
            r#"{{"uid":1000,"label":"codex","way":"service","registry_entry_hash":"{hash}","boot_id":"abcdef01-2345-6789-abcd-ef0123456789","created_at_boottime_ms":20,"deadline":200,"pid":200,"starttime":7000,"cgroup_id":90}}"#
        )
        .into_bytes()
    }

    fn a_descriptor() -> OwnedFd {
        OwnedFd::from(UnixStream::pair().unwrap().0)
    }

    fn agent_parent_peers() -> FakePeer {
        FakePeer::new()
            .with_open(Ok(a_descriptor()))
            .with_open(Ok(a_descriptor()))
            .with_proc(
                300,
                ProcFile::Stat,
                stat(300, "sudo", 200, 8_000).into_bytes(),
            )
            .with_proc(
                200,
                ProcFile::Stat,
                stat(200, "xudo", 100, XUDO_START).into_bytes(),
            )
            .with_exit(Ok(false))
            .with_exit(Ok(false))
    }

    /// The gate under sudo with `use_pty`, under xudo, under a shell:
    /// 500 gate, 400 sudo monitor, 300 sudo, 200 xudo, 100 bash, 1 init.
    fn proc_tree() -> MapSource {
        let source = MapSource::new()
            .with("500/stat", stat(500, "xudo-gate-auth", 400, 9_000))
            .with("400/stat", stat(400, "sudo", 300, 8_500))
            .with("300/stat", stat(300, "sudo", 200, 8_000))
            .with("200/stat", stat(200, "xudo", 100, XUDO_START))
            .with("100/stat", stat(100, "bash", 1, 5_000))
            .with("1/stat", stat(1, "systemd", 0, 1));
        // Every process in PID 1's namespaces, as an ordinary host has it; the
        // gate (500) as root, the rest as the user the entries are for.
        [500_u32, 400, 300, 200, 100, 1]
            .into_iter()
            .fold(source, |source, pid| {
                let uid = if (300..=500).contains(&pid) || pid == 1 {
                    0
                } else {
                    1000
                };
                in_init_namespaces(source, pid, uid)
            })
    }

    /// `pid`'s status, `uid_map` and namespace links, all as PID 1's.
    fn in_init_namespaces(source: MapSource, pid: u32, uid: u32) -> MapSource {
        ["user", "pid", "cgroup", "mnt"].iter().enumerate().fold(
            source
                .with(
                    format!("{pid}/status"),
                    format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nNSpid:\t{pid}\n"),
                )
                .with(format!("{pid}/uid_map"), "0 0 4294967295\n"),
            |source, (at, kind)| {
                let inode = 4_026_531_800 + u64::try_from(at).unwrap();
                source
                    .with_inode(format!("{pid}/ns/{kind}"), inode)
                    .with_inode(format!("1/ns/{kind}"), inode)
            },
        )
    }

    fn entry(nonce: &str, pid: u32, starttime: u64, argv: &[&str]) -> PendingRequest {
        PendingRequest {
            schema_version: REQUEST_SCHEMA_VERSION,
            nonce: nonce.to_owned(),
            caller_pid: pid,
            caller_starttime: starttime,
            action: "xudo.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: argv.iter().map(|a| (*a).to_owned()).collect(),
            generation: rules().generation.id(),
            deadline: BoottimeMillis(200),
            confirmed: false,
            confirmed_by: None,
            state: crate::request::ConfirmationState::Pending,
            caller_uid: 1000,
            caller_sid: 10,
            caller_tty: 20,
            needs_watch: false,
            shown_at_ms: None,
            shown_to: None,
            fingerprint: "0".repeat(64),
            claimed_classification: "enrolled-agent".to_owned(),
            attested_class: crate::request::AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
            attested_harness: None,
            via: crate::request::Via::Auth,
            queue_id: None,
            operation: None,
        }
    }

    fn ours() -> PendingRequest {
        entry(NONCE_A, XUDO_PID, XUDO_START, &["restart", "nginx.service"])
    }

    /// A spool holding these requests, each under the name it is given.
    fn holding(entries: &[(&str, PendingRequest)]) -> FakeSpool {
        entries
            .iter()
            .fold(FakeSpool::new(), |spool, (name, request)| {
                spool.with_file(*name, request.to_json())
            })
    }

    /// The names the gate (or a rival) consumed, in order.
    fn consumed(spool: &FakeSpool) -> Vec<String> {
        spool
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                SpoolCall::Consume(name) => Some(String::from_utf8(name).unwrap()),
                _ => None,
            })
            .collect()
    }

    /// The spool a host hands the gate: the test's own [`FakeSpool`], shared so
    /// the test can look at it afterwards, behind the gate's narrow view of it.
    struct SharedSpool {
        spool: Rc<FakeSpool>,
        /// Whether a second gate takes each entry the moment this one has read
        /// it, so that this one's own consume is the loser's.
        rival: bool,
    }

    struct SharedQueue {
        spool: Rc<FakeSpool>,
    }

    impl QueueClaim for SharedQueue {
        fn read(&self, name: &str) -> Result<Vec<u8>, SpoolError> {
            self.spool.read(name.as_bytes(), MAX_ENTRY_BYTES)
        }
    }

    impl RequestSpool for SharedSpool {
        fn names(&self) -> Result<Vec<Vec<u8>>, SpoolError> {
            // As the real adapter lists: cut off one name past the bound.
            self.spool.names_up_to(LISTED_NAMES)
        }

        fn read(&self, name: &str) -> Result<Vec<u8>, SpoolError> {
            let bytes = self.spool.read(name.as_bytes(), MAX_ENTRY_BYTES);
            if self.rival {
                // The other gate's unlink, which this gate cannot see coming.
                let _ = self.spool.consume(name.as_bytes());
            }
            bytes
        }

        fn consume(&self, name: &str) -> Result<(), SpoolError> {
            self.spool.consume(name.as_bytes())
        }
    }

    /// A host a test scripts, step by step.
    #[derive(Clone, Copy, Default)]
    enum FakeCgroupMode {
        #[default]
        Host,
        Agent,
        MissingAgentFacts,
        /// A caller outside `xudo.slice`, in an ordinary login session.
        Human,
        Unavailable,
    }

    struct FakeHost {
        syscalls: FakeSyscalls,
        peers: FakePeer,
        cgroup_mode: FakeCgroupMode,
        hygiene: FakeHygiene,
        clock: FixedClock,
        proc: Result<MapSource, SysError>,
        policy: Result<LoadedPolicy, PolicyError>,
        spool: Result<Rc<FakeSpool>, SpoolError>,
        /// The root-owned queue, separate from the request spool.
        queue: Result<Rc<FakeSpool>, SpoolError>,
        rival: bool,
        gate_files: xudo_sys::FakeGateFiles,
        programs: FakePrograms,
        audit: FakeAuditSink,
        proc_opened: Cell<bool>,
        spool_opened: Cell<bool>,
        /// The uids whose own freeze marker stands.
        user_freezes: Vec<u32>,
        /// The uids the gate asked about.
        freeze_asked: std::cell::RefCell<Vec<u32>>,
        /// The in-memory tree a remove-path walks.
        remove: xudo_sys::FakeRemoveFs,
        /// Make the fake unlink seam assert that a durable intent exists.
        assert_intent_before_unlink: bool,
    }

    #[test]
    fn an_opened_cgroup_seam_is_boxed_and_a_failed_open_stays_an_error() {
        assert!(
            boxed_cgroups(Ok(AgentCgroup {
                missing_facts: false
            }))
            .is_ok()
        );
        assert!(boxed_cgroups::<AgentCgroup>(Err(SysError::unsupported("x"))).is_err());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_real_seam_type_is_boxed_off_linux_where_it_never_opens() {
        let boxed = boxed_cgroups(Ok(xudo_sys::HostCgroup::inert())).unwrap();
        assert!(boxed.require_cgroup2().is_err());
    }

    #[test]
    fn the_agent_cgroup_double_answers_every_read() {
        use std::os::fd::AsFd as _;

        let fd = std::os::unix::net::UnixStream::pair().unwrap().0;
        for missing_facts in [false, true] {
            let seam = AgentCgroup { missing_facts };
            assert!(seam.require_cgroup2().is_ok());
            assert_eq!(seam.pidfd_cgroup_id(fd.as_fd()).unwrap(), 90);
            assert!(seam.proc_cgroup(1).is_ok());
            assert_eq!(seam.cgroup_inode("x").unwrap(), 90);
            assert!(seam.peer_alive(fd.as_fd()).unwrap());
            assert!(seam.scope_facts("other", 90, false).unwrap().is_none());
            assert!(
                seam.scope_facts("agent-0123456789abcdef0123456789abcdef.scope", 90, false)
                    .unwrap()
                    .is_some()
            );
            assert_eq!(seam.scope_names().unwrap().len(), 1);
        }
    }

    struct AgentCgroup {
        missing_facts: bool,
    }

    /// A cgroup tree in which every process is in a login session.
    struct HumanCgroup;

    impl CgroupCalls for HumanCgroup {
        fn require_cgroup2(&self) -> Result<(), SysError> {
            Ok(())
        }
        fn pidfd_cgroup_id(&self, _pidfd: std::os::fd::BorrowedFd<'_>) -> Result<u64, SysError> {
            Ok(90)
        }
        fn proc_cgroup(&self, _pid: u32) -> Result<Vec<u8>, SysError> {
            Ok(b"0::/user.slice/session-1.scope\n".to_vec())
        }
        fn cgroup_inode(&self, _path: &str) -> Result<u64, SysError> {
            Ok(90)
        }
        fn peer_alive(&self, _pidfd: std::os::fd::BorrowedFd<'_>) -> Result<bool, SysError> {
            Ok(true)
        }
        fn scope_facts(
            &self,
            _name: &str,
            _id: u64,
            _with_processes: bool,
        ) -> Result<Option<ScopeFacts>, SysError> {
            Ok(None)
        }
        fn scope_names(&self) -> Result<Vec<String>, SysError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn the_human_cgroup_double_answers_every_read() {
        use std::os::fd::AsFd as _;

        let fd = std::os::unix::net::UnixStream::pair().unwrap().0;
        let seam = HumanCgroup;
        assert!(seam.require_cgroup2().is_ok());
        assert_eq!(seam.pidfd_cgroup_id(fd.as_fd()).unwrap(), 90);
        assert!(seam.proc_cgroup(1).is_ok());
        assert_eq!(seam.cgroup_inode("x").unwrap(), 90);
        assert!(seam.peer_alive(fd.as_fd()).unwrap());
        assert!(seam.scope_facts("x", 90, false).unwrap().is_none());
        assert!(seam.scope_names().unwrap().is_empty());
    }

    impl CgroupCalls for AgentCgroup {
        fn require_cgroup2(&self) -> Result<(), SysError> {
            Ok(())
        }
        fn pidfd_cgroup_id(&self, _pidfd: std::os::fd::BorrowedFd<'_>) -> Result<u64, SysError> {
            Ok(90)
        }
        fn proc_cgroup(&self, _pid: u32) -> Result<Vec<u8>, SysError> {
            Ok(b"0::/xudo.slice/agent-0123456789abcdef0123456789abcdef.scope\n".to_vec())
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
            if name != "agent-0123456789abcdef0123456789abcdef.scope" {
                return Ok(None);
            }
            Ok(Some(ScopeFacts {
                cgroup2: true,
                inode: 90,
                owner: 0,
                mode: 0o40755,
                procs_owner: 0,
                procs_mode: 0o100_644,
                populated: true,
                record: Some(agent_record()),
                record_owner: 0,
                record_mode: 0o100_600,
                record_nlink: 1,
                processes: Vec::new(),
            }))
        }
        fn scope_names(&self) -> Result<Vec<String>, SysError> {
            let name = if self.missing_facts {
                "agent-ffffffffffffffffffffffffffffffff"
            } else {
                "agent-0123456789abcdef0123456789abcdef"
            };
            Ok(vec![name.to_owned()])
        }
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
                peers: FakePeer::new(),
                cgroup_mode: FakeCgroupMode::Host,
                hygiene: FakeHygiene::new(GATE_PID),
                clock: FixedClock(NOW),
                proc: Ok(proc_tree()),
                policy: Ok(LoadedPolicy {
                    rules: rules(),
                    settings: engine::Settings::default(),
                    queue_ttl_secs: 24 * 60 * 60,
                    passwd: "agent:x:1000:1000:agent:/home/agent:/bin/sh\n".to_owned(),
                    passwd_fault: None,
                }),
                spool: Ok(Rc::clone(spool)),
                queue: Ok(Rc::new(FakeSpool::new())),
                rival: false,
                gate_files: xudo_sys::FakeGateFiles::running_as(GateMode::Auth),
                programs: FakePrograms::serving(path, owner),
                audit: FakeAuditSink::new(),
                proc_opened: Cell::new(false),
                spool_opened: Cell::new(false),
                user_freezes: Vec::new(),
                freeze_asked: std::cell::RefCell::new(Vec::new()),
                remove: xudo_sys::FakeRemoveFs::new(),
                assert_intent_before_unlink: false,
            }
        }
    }

    impl GateHost for FakeHost {
        fn syscalls(&self) -> &dyn Syscalls {
            &self.syscalls
        }
        fn peers(&self) -> &dyn PeerCalls {
            &self.peers
        }
        fn cgroups(&self) -> Result<Box<dyn CgroupCalls>, SysError> {
            match self.cgroup_mode {
                FakeCgroupMode::Unavailable => {
                    return Err(SysError::unsupported("fake cgroup host unavailable"));
                }
                FakeCgroupMode::Agent => {
                    return Ok(Box::new(AgentCgroup {
                        missing_facts: false,
                    }));
                }
                FakeCgroupMode::MissingAgentFacts => {
                    return Ok(Box::new(AgentCgroup {
                        missing_facts: true,
                    }));
                }
                FakeCgroupMode::Human => return Ok(Box::new(HumanCgroup)),
                FakeCgroupMode::Host => {}
            }
            boxed_cgroups(xudo_sys::HostCgroup::open())
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
        fn load_policy(&self) -> Result<LoadedPolicy, PolicyError> {
            self.policy.clone()
        }
        fn user_frozen(&self, uid: u32) -> bool {
            self.freeze_asked.borrow_mut().push(uid);
            self.user_freezes.contains(&uid)
        }
        fn open_spool(&self) -> Result<Box<dyn RequestSpool>, SpoolError> {
            self.spool_opened.set(true);
            self.spool.clone().map(|spool| {
                Box::new(SharedSpool {
                    spool,
                    rival: self.rival,
                }) as Box<dyn RequestSpool>
            })
        }
        fn open_queue(&self) -> Result<Box<dyn QueueClaim>, SpoolError> {
            self.queue
                .clone()
                .map(|spool| Box::new(SharedQueue { spool }) as Box<dyn QueueClaim>)
        }
        fn gate_files(&self) -> &dyn GateFiles {
            &self.gate_files
        }
        fn programs(&self) -> &dyn Programs {
            &self.programs
        }
        fn audit(&mut self) -> &mut dyn AuditSink {
            &mut self.audit
        }
        fn remove_path(
            &mut self,
            request: &xudo_sys::RemoveRequest,
        ) -> Result<xudo_sys::RemoveReport, xudo_sys::RemoveError> {
            if self.assert_intent_before_unlink && !request.dry_run {
                assert!(
                    self.audit
                        .records()
                        .iter()
                        .any(|record| { has_line(&record.evidence, "op=remove-path-intent") })
                );
            }
            xudo_sys::remove_path(&mut self.remove, request)
        }
    }

    /// Makes the gate read this entry's caller as a human: the entry says
    /// `Human`, the pinned ancestors are scripted, and no cgroup is the slice.
    fn human_caller(host: &mut FakeHost, entry: &mut PendingRequest) {
        entry.attested_class = crate::request::AttestedClass::Human;
        host.cgroup_mode = FakeCgroupMode::Human;
        script_human(host);
    }

    /// The scripted reads one gate run consumes; script again before each run.
    fn script_human(host: &mut FakeHost) {
        host.peers = agent_parent_peers();
        host.syscalls = FakeSyscalls::new()
            .with_cloexec(Ok(()))
            .with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456789".to_owned()));
    }

    fn auth() -> Vec<OsString> {
        vec![OsString::from("/usr/libexec/xudo/xudo-gate-auth")]
    }

    fn exec_calls(host: &FakeHost) -> usize {
        host.syscalls
            .calls()
            .iter()
            .filter(|call| matches!(call, xudo_sys::FakeCall::Exec { .. }))
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
        assert!(consumed(spool).is_empty(), "nothing consumed");
        assert_eq!(denial_codes(host), vec![Some(code.to_owned())]);
        assert_eq!(host.audit.records()[0].decision, AuditDecision::Denied);
        assert!(exit.message.contains(code), "{}", exit.message);
    }

    // ---- the happy path, and everything it must do in order --------------

    #[test]
    fn the_gate_refuses_a_queued_run_whose_entry_is_not_claimed() {
        let id = "c".repeat(64);
        let mut entry = ours();
        entry.queue_id = Some(id.clone());
        let mut host = FakeHost::new(&Rc::new(FakeSpool::new()));
        human_caller(&mut host, &mut entry);
        let spool = Rc::new(holding(&[(NONCE_A, entry)]));
        host.spool = Ok(Rc::clone(&spool));
        script_human(&mut host);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_queue_not_claimed");

        host.queue = Ok(Rc::new(FakeSpool::new().with_file(
            format!("{id}.json"),
            format!(r#"{{"state":"pending","run_nonce":"{NONCE_A}"}}"#),
        )));
        host.audit = FakeAuditSink::new();
        script_human(&mut host);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_queue_not_claimed");

        host.queue = Ok(Rc::new(FakeSpool::new().with_file(
            format!("{id}.json"),
            format!(r#"{{"state":"claimed","run_nonce":"{NONCE_B}"}}"#),
        )));
        host.audit = FakeAuditSink::new();
        script_human(&mut host);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_queue_not_claimed");

        host.queue = Ok(Rc::new(
            FakeSpool::new().with_file(format!("{id}.json"), b"no".to_vec()),
        ));
        host.audit = FakeAuditSink::new();
        script_human(&mut host);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_queue_not_claimed");

        host.queue = Err(SpoolError::NotADirectory {
            at: "queue".to_owned(),
        });
        host.audit = FakeAuditSink::new();
        script_human(&mut host);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_failed_spool");
    }

    #[test]
    fn a_queued_run_whose_entry_is_claimed_for_this_nonce_reaches_exec() {
        let id = "c".repeat(64);
        let mut entry = ours();
        entry.queue_id = Some(id.clone());
        let mut host = FakeHost::new(&Rc::new(FakeSpool::new()));
        human_caller(&mut host, &mut entry);
        let spool = Rc::new(holding(&[(NONCE_A, entry)]));
        host.spool = Ok(Rc::clone(&spool));
        host.queue = Ok(Rc::new(FakeSpool::new().with_file(
            format!("{id}.json"),
            format!(r#"{{"state":"claimed","run_nonce":"{NONCE_A}","argv":[]}}"#),
        )));
        script_human(&mut host);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19);
        assert!(
            exit.message.contains("gate_failed_exec"),
            "{}",
            exit.message
        );
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
    }

    #[test]
    fn an_approved_entry_is_consumed_recorded_and_then_executed_from_the_validated_descriptor() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
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
            Some(&xudo_sys::FakeCall::MarkCloexecFrom(3))
        );
        assert_eq!(
            host.hygiene.calls(),
            [
                HygieneCall::EnsureStdStreams,
                HygieneCall::ResetRlimitsFromPid1,
                HygieneCall::ResetUmask,
                HygieneCall::ResetCwd,
                HygieneCall::ForbidNewPrivileges
            ]
        );
        // Consumed exactly once.
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);

        // Exec'd the descriptor that was hashed, with the canonical operands
        // and the fixed environment.
        let (path, _) = program_file("tool", b"the program that would run as root");
        let meta = std::fs::metadata(&path).unwrap();
        let operands = ["/usr/bin/systemctl", "restart", "nginx.service"];
        assert_eq!(
            host.syscalls.calls().last(),
            Some(&xudo_sys::FakeCall::Exec {
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
        assert_eq!(records[0].action.as_deref(), Some("xudo.svc.restart"));
        let evidence = &records[0].evidence;
        assert!(has_line(evidence, "program_sha256="), "{evidence:?}");
        assert!(
            has_line(evidence, "lineage=xudo-gate-auth(500) <- sudo(400)"),
            "{evidence:?}"
        );
        assert!(has_line(evidence, "confirmation=password"), "{evidence:?}");
        assert!(
            has_line(evidence, "gate_mode=Auth via=auth"),
            "{evidence:?}"
        );
        assert!(
            has_line(evidence, "gate_argv0=/usr/libexec"),
            "{evidence:?}"
        );
        assert_eq!(records[1].outcome.kind(), "failed");
        let after = &records[1].evidence;
        assert!(has_line(after, "authorization_seq=1"), "{after:?}");
    }

    #[test]
    fn a_human_broker_class_and_an_unattested_gate_class_still_run_on_auth() {
        let mut human = ours();
        human.attested_class = crate::request::AttestedClass::Human;
        let spool = Rc::new(holding(&[(NONCE_A, human)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());

        assert_eq!(exec_calls(&host), 1);
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert!(exit.message.contains("gate_failed_exec"));
        let records = host.audit.records();
        assert_eq!(records[0].decision, AuditDecision::Allowed);
        assert!(has_line(&records[0].evidence, "confirmation=password"));
    }

    #[test]
    fn an_unavailable_gate_cgroup_seam_still_runs_the_auth_entry() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.cgroup_mode = FakeCgroupMode::Unavailable;
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 1);
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert!(exit.message.contains("gate_failed_exec"));
    }

    #[test]
    fn a_missing_root_registered_scope_record_cannot_attest_the_gate_ancestor() {
        let mut agent = ours();
        agent.attested_class = crate::request::AttestedClass::EnrolledAgent { scope_id: 90 };
        agent.attested_scope_id = Some(90);
        agent.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        agent.attested_harness = Some("codex".to_owned());
        let spool = Rc::new(holding(&[(NONCE_A, agent)]));
        let mut host = FakeHost::new(&spool);
        host.cgroup_mode = FakeCgroupMode::MissingAgentFacts;
        host.peers = agent_parent_peers();
        host.syscalls = FakeSyscalls::new()
            .with_cloexec(Ok(()))
            .with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456789".to_owned()));
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 0);
        assert!(exit.message.contains("request_wrong_attested_identity"));
    }

    #[test]
    fn a_missing_scope_facts_reply_is_unattested_at_the_gate_classifier() {
        let peers = agent_parent_peers();
        let syscalls =
            FakeSyscalls::new().with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456789".to_owned()));
        let live = crate::classify::classify(
            &AgentCgroup {
                missing_facts: true,
            },
            &peers,
            &syscalls,
            crate::classify::AncestorPin {
                caller: (200, XUDO_START),
                uid: 1000,
                child: (300, 8_000),
                now_boottime_ms: NOW,
            },
        );
        assert_eq!(
            live.attested_class,
            crate::request::AttestedClass::Unattested
        );
    }

    #[test]
    fn system_host_constructs_its_peer_and_cgroup_adapters() {
        let host = SystemHost::new();
        let _peers = host.peers();
        #[cfg(target_os = "linux")]
        assert!(host.cgroups().is_ok());
        #[cfg(not(target_os = "linux"))]
        assert!(host.cgroups().is_err());
        // No test host has the gate installed as the executed file.
        assert!(
            host.gate_files()
                .executing(&xudo_sys::MapSource::new())
                .is_err()
        );
    }

    #[test]
    fn the_record_says_how_each_gate_file_confirmed() {
        assert!(confirmation_text(GateMode::Auth).starts_with("confirmation=password"));
        assert!(confirmation_text(GateMode::Nopass).starts_with("confirmation=none"));
    }

    #[test]
    fn a_user_freeze_marker_denies_an_enrolled_entry_at_the_gate() {
        let mut agent = ours();
        agent.attested_class = crate::request::AttestedClass::EnrolledAgent { scope_id: 90 };
        agent.attested_scope_id = Some(90);
        agent.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        agent.attested_harness = Some("codex".to_owned());
        let spool = Rc::new(holding(&[(NONCE_A, agent)]));
        let mut host = FakeHost::new(&spool);
        host.cgroup_mode = FakeCgroupMode::Agent;
        host.peers = agent_parent_peers();
        host.syscalls = FakeSyscalls::new()
            .with_cloexec(Ok(()))
            .with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456789".to_owned()));
        host.user_freezes = vec![1000];

        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "frozen");
        assert_eq!(*host.freeze_asked.borrow(), [1000]);
    }

    /// Whether some line of evidence begins with `prefix`.
    fn has_line(evidence: &[String], prefix: &str) -> bool {
        evidence.iter().any(|line| line.starts_with(prefix))
    }

    #[test]
    fn the_gate_consults_only_the_matched_entrys_own_users_freeze_marker() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.user_freezes = vec![1001];
        let _ = run(&mut host, &auth());
        assert_eq!(*host.freeze_asked.borrow(), [1000]);

        // With no entry there is no uid to ask about.
        let empty = Rc::new(holding(&[]));
        let mut host = FakeHost::new(&empty);
        let _ = run(&mut host, &auth());
        assert!(host.freeze_asked.borrow().is_empty());
    }

    /// A queued, claimed run by a caller the broker called `stored`, in a
    /// proc tree that `tree` has altered, and what the gate did with it.
    fn queued_run(
        stored: crate::request::AttestedClass,
        tree: impl FnOnce(MapSource) -> MapSource,
    ) -> (FakeHost, Rc<FakeSpool>, GateExit) {
        queued_run_in(stored, FakeCgroupMode::Human, tree)
    }

    /// [`queued_run`] with the gate's own cgroup read set to `mode`.
    fn queued_run_in(
        stored: crate::request::AttestedClass,
        mode: FakeCgroupMode,
        tree: impl FnOnce(MapSource) -> MapSource,
    ) -> (FakeHost, Rc<FakeSpool>, GateExit) {
        let id = "c".repeat(64);
        let mut entry = ours();
        entry.queue_id = Some(id.clone());
        let mut host = FakeHost::new(&Rc::new(FakeSpool::new()));
        human_caller(&mut host, &mut entry);
        entry.attested_class = stored;
        host.cgroup_mode = mode;
        let spool = Rc::new(holding(&[(NONCE_A, entry)]));
        host.spool = Ok(Rc::clone(&spool));
        host.proc = Ok(tree(proc_tree()));
        host.queue = Ok(Rc::new(FakeSpool::new().with_file(
            format!("{id}.json"),
            format!(r#"{{"state":"claimed","run_nonce":"{NONCE_A}","argv":[]}}"#),
        )));
        let exit = run(&mut host, &auth());
        (host, spool, exit)
    }

    /// The same run, with the caller's `ns/<kind>` (or the gate's) altered.
    fn queued_run_with_namespace(pid: u32, kind: &str) -> (FakeHost, Rc<FakeSpool>, GateExit) {
        queued_run(crate::request::AttestedClass::Human, |tree| {
            tree.with_inode(format!("{pid}/ns/{kind}"), 4_026_539_999)
        })
    }

    #[test]
    fn a_clean_queued_human_run_is_the_baseline_the_namespace_tests_differ_from() {
        let (host, spool, exit) = queued_run(crate::request::AttestedClass::Human, |tree| tree);
        assert!(
            exit.message.contains("gate_failed_exec"),
            "{}",
            exit.message
        );
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert_eq!(exec_calls(&host), 1);
    }

    #[test]
    fn the_gate_refuses_an_ancestor_in_another_user_namespace() {
        let (host, spool, exit) = queued_run_with_namespace(XUDO_PID, "user");
        assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");
    }

    #[test]
    fn the_gate_refuses_an_ancestor_in_another_mount_namespace() {
        let (host, spool, exit) = queued_run_with_namespace(XUDO_PID, "mnt");
        assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");
    }

    #[test]
    fn the_gate_refuses_an_ancestor_in_another_pid_or_cgroup_namespace() {
        for kind in ["pid", "cgroup"] {
            let (host, spool, exit) = queued_run_with_namespace(XUDO_PID, kind);
            assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");
        }
    }

    #[test]
    fn the_gate_refuses_when_it_is_itself_in_another_mount_namespace() {
        // sudo runs the gate in its caller's mount namespace, so a caller that
        // unshared one reaches the gate in it.
        let (host, spool, exit) = queued_run_with_namespace(GATE_PID, "mnt");
        assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");
    }

    #[test]
    fn an_ancestor_with_a_nested_pid_or_mapped_uid_namespace_is_unattested() {
        let (host, spool, exit) = queued_run(crate::request::AttestedClass::Human, |tree| {
            tree.with(
                "200/status",
                "Uid:\t1000\t1000\t1000\t1000\nNSpid:\t200\t1\n",
            )
        });
        assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");
        let (host, spool, exit) = queued_run(crate::request::AttestedClass::Human, |tree| {
            tree.with("200/uid_map", "0 100000 65536\n")
        });
        assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");
    }

    #[test]
    fn the_gate_reads_the_uid_from_the_live_ancestor() {
        // The marker consulted is the live process's uid, which here is also
        // the entry's. Nothing the entry says is asked about on its own.
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.proc =
            Ok(proc_tree().with("200/status", "Uid:\t1001\t1001\t1001\t1001\nNSpid:\t200\n"));
        let exit = run(&mut host, &auth());
        // The live uid is 1001, the entry says 1000: nothing it says is used.
        assert_refused_with(&host, &spool, &exit, "request_wrong_caller_uid");
        assert!(host.freeze_asked.borrow().is_empty());
        assert!(exit.message.contains("request_wrong_caller_uid"));

        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        let _ = run(&mut host, &auth());
        assert_eq!(*host.freeze_asked.borrow(), [1000]);
    }

    #[test]
    fn a_spool_uid_that_differs_from_the_live_one_is_refused() {
        // An entry that claims another uid, including the one whose marker is
        // absent or whose registry entry would grant something.
        for claimed in [0, 1001, 4_294_967_294] {
            let mut forged = ours();
            forged.caller_uid = claimed;
            let spool = Rc::new(holding(&[(NONCE_A, forged)]));
            let mut host = FakeHost::new(&spool);
            let exit = run(&mut host, &auth());
            assert_refused_with(&host, &spool, &exit, "request_wrong_caller_uid");
            assert!(host.freeze_asked.borrow().is_empty());
        }
    }

    #[test]
    fn an_ancestor_whose_uid_cannot_be_read_is_refused_not_trusted_from_the_entry() {
        for status in ["Uid:\tx\t1000\t1000\t1000\nNSpid:\t200\n", "NSpid:\t200\n"] {
            let spool = Rc::new(holding(&[(NONCE_A, ours())]));
            let mut host = FakeHost::new(&spool);
            host.proc = Ok(proc_tree().with("200/status", status));
            let exit = run(&mut host, &auth());
            assert_refused_with(&host, &spool, &exit, "request_wrong_caller_uid");
        }
    }

    #[test]
    fn a_stored_unattested_entry_is_never_human_at_the_gate() {
        // The gate reads this caller as a human; the broker could not attest
        // it. The gate does not upgrade it: no queue claim, and the audit
        // record says unattested.
        let (host, spool, exit) =
            queued_run(crate::request::AttestedClass::Unattested, |tree| tree);
        assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");

        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.cgroup_mode = FakeCgroupMode::Human;
        script_human(&mut host);
        let _ = run(&mut host, &auth());
        assert_eq!(host.audit.records()[0].classification, "unattested");
    }

    #[test]
    fn a_live_unattested_read_downgrades_a_human_entry() {
        // Stored human, queue record claimed; the gate's own cgroup read
        // fails. The effective class is the weaker one, so the queue stays
        // closed to this run although its record would hold.
        let (host, spool, exit) = queued_run_in(
            crate::request::AttestedClass::Human,
            FakeCgroupMode::Unavailable,
            |tree| tree,
        );
        assert_refused_with(&host, &spool, &exit, "request_queue_needs_attested_human");
    }

    #[test]
    fn an_entry_is_consumed_exactly_once_so_a_second_gate_finds_nothing() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut first = FakeHost::new(&spool);
        let first_exit = run(&mut first, &auth());
        assert!(first_exit.message.contains("gate_failed_exec"));
        assert_eq!(exec_calls(&first), 1);

        let mut second = FakeHost::new(&spool);
        let exit = run(&mut second, &auth());
        assert_eq!(exit.status, 19);
        assert_eq!(exec_calls(&second), 0);
        assert!(exit.message.contains("gate_no_pending_request"));
        assert_eq!(consumed(&spool).len(), 1);
    }

    #[test]
    fn a_rule_that_confirms_is_satisfied_by_the_password_on_the_auth_name() {
        let mut request = ours();
        request.action = "xudo.reload".to_owned();
        request.argv = vec!["daemon-reload".to_owned()];
        let spool = Rc::new(holding(&[(NONCE_A, request)]));
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
        let spool = Rc::new(holding(&[]));
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
        let other = entry(NONCE_A, 999, XUDO_START, &["restart", "nginx.service"]);
        let spool = Rc::new(holding(&[(NONCE_A, other)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
    }

    #[test]
    fn a_reissued_pid_does_not_borrow_the_entry_of_the_process_that_had_it() {
        // The pid matches an ancestor; the start time does not. Pid reuse.
        let stale = entry(
            NONCE_A,
            XUDO_PID,
            XUDO_START + 1,
            &["restart", "nginx.service"],
        );
        let spool = Rc::new(holding(&[(NONCE_A, stale)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
    }

    #[test]
    fn a_matched_entry_is_judged_against_the_ancestor_not_its_own_claim() {
        // A match whose ancestor is a reused pid: same pid, later start time.
        // `validate` must be asked about that ancestor. A pin built from the
        // entry's own claim would equal the claim and pass.
        let claim = ours();
        let found = Matched {
            caller: CallerPin::new(claim.caller_pid, claim.caller_starttime + 1),
            entry: claim,
        };
        let spool = Rc::new(holding(&[]));
        let host = FakeHost::new(&spool);
        let (caller, _) = caller_for(
            &host,
            &MapSource::new(),
            Some(&found),
            CallerPin::new(500, 9_000),
            &[],
            100,
            &xudo_policy::HarnessRegistry::empty(),
            "",
        );
        let context = GateContext {
            generation: rules().generation.id(),
            now: BoottimeMillis(100),
            settings: engine::Settings::default(),
            password_confirms: true,
            mode: GateMode::Auth,
        };
        let refusal = decide(&rules().rules, &caller, Some(&found.entry), context).unwrap_err();
        assert!(
            matches!(
                refusal,
                Refusal::Request(RequestError::WrongCaller {
                    expected_starttime: XUDO_START,
                    actual_starttime,
                    ..
                }) if actual_starttime == XUDO_START + 1
            ),
            "{refusal:?}"
        );
    }

    #[test]
    fn an_entry_pinned_to_the_gate_itself_or_below_the_walk_is_not_matched() {
        // The gate's own pin is not a caller: nothing the broker minted is for
        // the process it is about to run.
        let own = entry(NONCE_A, GATE_PID, 9_000, &["restart", "nginx.service"]);
        let spool = Rc::new(holding(&[(NONCE_A, own)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
    }

    #[test]
    fn two_entries_pinned_to_one_lineage_are_refused_and_neither_is_consumed() {
        let spool = Rc::new(holding(&[
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
        let spool = Rc::new(holding(&[(NONCE_B, ours())]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_forged_nonce");
    }

    #[test]
    fn an_expired_entry_is_refused_at_normal_severity() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.clock = FixedClock(200);
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_expired");
        assert!(exit.message.contains("severity normal"), "{}", exit.message);
    }

    #[test]
    fn adding_a_deny_rule_changes_generation_and_refuses_an_old_spool_entry() {
        let stale = ours();
        let old_generation = rules().generation.id();
        assert_eq!(
            stale.generation, old_generation,
            "the spool entry uses the old ruleset"
        );
        let changed = load_rule_files(vec![
            RuleFile {
                name: b"10-test.toml".to_vec(),
                bytes: RULES.as_bytes().to_vec(),
            },
            RuleFile {
                name: b"20-protect.toml".to_vec(),
                bytes: br#"[[deny]]
id = "xudo.protect.restart"
reason = "restart is temporarily protected"
program = ["systemctl"]
all = [{ any-arg = ["restart"] }]
"#
                .to_vec(),
            },
        ])
        .unwrap();
        let current_generation = changed.generation.id();
        assert_ne!(
            current_generation, old_generation,
            "adding the deny rule must move the ruleset generation"
        );
        let spool = Rc::new(holding(&[(NONCE_A, stale)]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(LoadedPolicy {
            rules: changed,
            settings: engine::Settings::default(),
            queue_ttl_secs: 24 * 60 * 60,
            passwd: String::new(),
            passwd_fault: None,
        });
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "request_stale_generation");
    }

    #[test]
    fn an_action_the_ruleset_does_not_name_is_refused_by_policy_and_not_consumed() {
        let mut unknown = ours();
        unknown.action = "xudo.nonexistent".to_owned();
        let spool = Rc::new(holding(&[(NONCE_A, unknown)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 17);
        assert_eq!(exec_calls(&host), 0);
        assert!(consumed(&spool).is_empty());
        assert_eq!(denial_codes(&host).len(), 1);
    }

    #[test]
    fn operands_the_rule_does_not_accept_are_refused_by_policy() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            entry(
                NONCE_A,
                XUDO_PID,
                XUDO_START,
                &["restart", "nginx.service", "--now"],
            ),
        )]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 17);
        assert_eq!(exec_calls(&host), 0);
        assert!(consumed(&spool).is_empty());
    }

    #[test]
    fn names_that_are_not_nonces_and_entries_that_are_not_requests_are_passed_over() {
        let spool = Rc::new(
            holding(&[(NONCE_A, ours())])
                .with_file("not-a-nonce", "{}")
                .with_file(".hidden", "")
                .with_file("c".repeat(64), b"\xff\xfe not utf-8")
                .with_file("d".repeat(64), "{ not a request }")
                .with_file("e".repeat(63), "{}"),
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
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_passed_over_and_ends_in_no_pending_request() {
        // A listing that names a nonce the spool then refuses to read: the
        // entry cannot be matched to anyone, so it is never run.
        let spool = SpoolEntries(
            FakeSpool::new()
                .with_file(NONCE_A, ours().to_json())
                .failing_read(NONCE_A),
        );
        assert!(find_entry(&spool, &[]).unwrap().is_none());
    }

    #[test]
    fn the_gates_view_of_the_spool_lists_one_name_past_the_bound_and_reads_no_further() {
        // A spool far fuller than the gate will walk. The directory is not
        // read to its end to find that out: the listing stops one name past
        // the bound, which is enough to refuse the spool. A listing that
        // stopped at the bound could not tell a full spool from a crowded one.
        let flooded = (0..MAX_SPOOL_NAMES + 100).fold(FakeSpool::new(), |spool, index| {
            spool.with_file(format!("{index:05}"), "")
        });
        let listed = into_spool(flooded).names().unwrap();
        assert_eq!(listed.len(), MAX_SPOOL_NAMES + 1);
        // At the bound exactly, the whole spool.
        let full = (0..MAX_SPOOL_NAMES).fold(FakeSpool::new(), |spool, index| {
            spool.with_file(format!("{index:05}"), "")
        });
        assert_eq!(into_spool(full).names().unwrap().len(), MAX_SPOOL_NAMES);
        // And what the gate asks for is the constant the refusal compares with.
        assert_eq!(LISTED_NAMES, MAX_SPOOL_NAMES + 1);
    }

    #[test]
    fn the_gates_view_of_the_spool_reads_within_a_bound_and_takes_an_entry_once() {
        let at_limit = vec![b'x'; MAX_ENTRY_BYTES];
        let view = into_spool(
            FakeSpool::new()
                .with_file("at", at_limit.clone())
                .with_file("past", vec![b'y'; MAX_ENTRY_BYTES + 1]),
        );
        assert_eq!(
            view.names().unwrap(),
            vec![b"at".to_vec(), b"past".to_vec()]
        );
        assert_eq!(view.read("at").unwrap(), at_limit);
        // One byte more than a request can be is refused, not truncated.
        assert_eq!(
            view.read("past").unwrap_err(),
            SpoolError::TooLarge {
                name: "past".to_owned(),
                limit: MAX_ENTRY_BYTES
            }
        );
        view.consume("at").unwrap();
        assert_eq!(
            view.consume("at").unwrap_err(),
            SpoolError::Gone {
                name: "at".to_owned()
            }
        );
    }

    // ---- consuming --------------------------------------------------------

    #[test]
    fn a_remove_path_entry_taken_by_a_rival_gate_removes_nothing() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        host.rival = true;
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19, "{exit:?}");
        assert!(host.remove.unlinked().is_empty());
        assert!(host.remove.exists(&[b"srv", b"app", b"build", b"cache"]));
        assert_eq!(
            denial_codes(&host),
            vec![Some("gate_failed_spool".to_owned())]
        );
    }

    #[test]
    fn an_entry_that_was_already_gone_when_the_gate_consumed_it_runs_nothing() {
        // Another gate read the same entry and unlinked it first. The loser's
        // unlink finds nothing, and "already gone" is a refusal, never a
        // second run: the one-use guarantee is that exactly one gate wins.
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.rival = true;
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19);
        assert_eq!(exec_calls(&host), 0);
        assert!(host.programs.opened().is_empty());
        assert_eq!(
            denial_codes(&host),
            vec![Some("gate_failed_spool".to_owned())]
        );
        assert!(exit.message.contains("severity high"));
        // Both unlinks were made, the rival's first. Only the rival's won.
        assert_eq!(consumed(&spool), [NONCE_A.to_owned(), NONCE_A.to_owned()]);
        let evidence = &host.audit.records()[0].evidence;
        assert!(
            evidence
                .iter()
                .any(|line| line.starts_with("detail=") && line.contains("already gone")),
            "{evidence:?}"
        );
        // Not authorized: nothing was recorded as allowed.
        assert_eq!(host.audit.records()[0].decision, AuditDecision::Denied);
    }

    #[test]
    fn a_registry_fault_is_in_the_evidence_of_every_gate_record() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.rival = true;
        let mut loaded = host.policy.clone().unwrap();
        loaded.rules.registry_fault = Some("harnesses.d is writable".to_owned());
        loaded.passwd_fault = Some("1 unusable and 0 non-UTF-8 line(s)".to_owned());
        host.policy = Ok(loaded);
        let _ = run(&mut host, &auth());
        let evidence = &host.audit.records()[0].evidence;
        assert!(
            evidence.contains(&"registry_fault=harnesses.d is writable".to_owned()),
            "{evidence:?}"
        );
        assert!(
            evidence
                .iter()
                .any(|line| line.starts_with("passwd_fault=1 unusable")),
            "{evidence:?}"
        );
    }

    #[test]
    fn an_entry_that_cannot_be_unlinked_runs_nothing() {
        // An unlink that fails for any other reason is not a claim either.
        let spool = Rc::new(
            holding(&[(NONCE_A, ours())]).failing_consume(SpoolError::Io {
                operation: "unlinkat".to_owned(),
                at: "/run/xudo/req".to_owned(),
                code: Some(5),
                reason: "Input/output error".to_owned(),
            }),
        );
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19);
        assert_eq!(exec_calls(&host), 0);
        assert!(host.programs.opened().is_empty());
        assert!(
            exit.message.contains("gate_failed_spool"),
            "{}",
            exit.message
        );
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
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
            let spool = Rc::new(holding(&[(NONCE_A, ours())]));
            let mut host = FakeHost::new(&spool);
            host.programs = FakePrograms::refusing(error);
            let exit = run(&mut host, &auth());
            assert_eq!(exit.status, 19);
            assert_eq!(exec_calls(&host), 0);
            // The entry was consumed before the program was opened: it is
            // gone, and the caller must ask again.
            assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
            assert_eq!(
                denial_codes(&host),
                vec![Some("gate_failed_program".to_owned())]
            );
            assert!(exit.message.contains("severity high"));
        }
    }

    #[test]
    fn a_script_is_refused_with_the_reason_in_the_record() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
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
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
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
        assert_eq!(exit.message.lines().count(), 1, "{}", exit.message);
        assert!(
            !exit.message.contains("move the log aside"),
            "{}",
            exit.message
        );
        assert!(host.audit.records().is_empty());
    }

    /// Bytes that must never reach stderr. They sit in the audit error, which
    /// is where a damaged tail quotes the log.
    const CALLER_BYTES: &str = "caller-bytes-9f3a";

    fn damaged_tail() -> AuditError {
        AuditError::DamagedTail {
            path: "/var/lib/xudo/audit.jsonl".to_owned(),
            reason: TailError::NotARecord {
                reason: CALLER_BYTES.to_owned(),
            },
        }
    }

    fn cut_back_failed() -> AuditError {
        AuditError::Io {
            op: "repair",
            path: format!("/tmp/{CALLER_BYTES}"),
            reason: format!("cutting the log back failed ({CALLER_BYTES})"),
        }
    }

    fn assert_fixed_recovery(exit: &GateExit, code: &str) {
        assert_eq!(exit.status, 19, "{}", exit.message);
        assert!(exit.message.contains(code), "{}", exit.message);
        assert!(
            exit.message
                .contains("xudo-gate: the audit log may be damaged; move the log aside to recover"),
            "{}",
            exit.message
        );
        assert!(!exit.message.contains(CALLER_BYTES), "{}", exit.message);
        assert_eq!(exit.message.lines().count(), 2, "{}", exit.message);
    }

    #[test]
    fn a_damaged_log_on_the_refusal_record_prints_a_fixed_recovery_line() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.audit = FakeAuditSink::failing_with(damaged_tail());
        let exit = run(
            &mut host,
            &[OsString::from("xudo-gate-auth"), OsString::from("--help")],
        );
        assert_fixed_recovery(&exit, "gate_failed_invocation");
        assert!(host.audit.records().is_empty());
        assert_eq!(exec_calls(&host), 0);
        assert!(consumed(&spool).is_empty());
    }

    #[test]
    fn a_cut_back_that_fails_on_the_authorization_prints_the_same_line() {
        // The authorization append fails and the refusal append lands. The
        // notice still comes from the authorization, once.
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.audit = FakeAuditSink::failing_times(1, cut_back_failed());
        let exit = run(&mut host, &auth());
        assert_fixed_recovery(&exit, "gate_failed_audit");
        assert_eq!(exec_calls(&host), 0);
        assert_eq!(
            denial_codes(&host),
            vec![Some("gate_failed_audit".to_owned())]
        );
    }

    #[test]
    fn both_appends_failing_on_a_damaged_log_prints_the_recovery_once() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.audit = FakeAuditSink::failing_with(damaged_tail());
        let exit = run(&mut host, &auth());
        assert_fixed_recovery(&exit, "gate_failed_audit");
        assert_eq!(exec_calls(&host), 0);
        assert!(host.audit.records().is_empty());
    }

    /// The gate attests no class, so an entry minted for any other class is
    /// refused through the real `caller_for`, in the real sequence, and runs
    /// nothing.
    fn refused_for_class(mut request: PendingRequest) {
        request.claimed_classification = "enrolled-agent".to_owned();
        let spool = Rc::new(holding(&[(NONCE_A, request)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19, "{}", exit.message);
        assert!(
            exit.message.contains("request_wrong_attested_identity"),
            "{}",
            exit.message
        );
        assert_eq!(exec_calls(&host), 0);
    }

    #[test]
    fn the_gate_refuses_an_enrolled_entry_until_it_can_attest_a_scope() {
        let mut request = ours();
        request.attested_class = crate::request::AttestedClass::EnrolledAgent { scope_id: 44 };
        request.attested_scope_id = Some(44);
        request.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        request.attested_harness = Some("codex".to_owned());
        refused_for_class(request);
    }

    #[test]
    fn a_human_entry_keeps_running_through_the_auth_gate() {
        let mut request = ours();
        request.attested_class = crate::request::AttestedClass::Human;
        let spool = Rc::new(holding(&[(NONCE_A, request)]));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 1);
        assert!(exit.message.contains("gate_failed_exec"));
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
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        break_it(&mut host);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19, "{}", exit.message);
        assert!(exit.message.contains(code), "{}", exit.message);
        assert_eq!(exec_calls(&host), 0, "{code}: nothing may run");
        assert!(consumed(&spool).is_empty(), "{code}: nothing consumed");
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
            ["proc=false", "spool=false", "hygiene=5", "programs=0"]
        );
    }

    #[test]
    fn the_gate_resets_cwd_and_umask() {
        // Both calls happen after the streams are filled and before anything
        // is opened. A failure of either refuses, and the later one is not
        // attempted when the earlier one failed.
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut umask_host = FakeHost::new(&spool);
        umask_host.hygiene =
            FakeHygiene::new(GATE_PID).with_umask_error(SysError::unsupported("umask"));
        let umask_exit = run(&mut umask_host, &auth());
        assert!(
            umask_exit.message.contains("gate_failed_caller_state"),
            "{}",
            umask_exit.message
        );
        assert_eq!(
            umask_host.hygiene.calls(),
            [
                HygieneCall::EnsureStdStreams,
                HygieneCall::ResetRlimitsFromPid1,
                HygieneCall::ResetUmask
            ]
        );
        assert!(!umask_host.proc_opened.get());
        assert!(umask_host.programs.opened().is_empty());

        let mut cwd_host = FakeHost::new(&spool);
        cwd_host.hygiene = FakeHygiene::new(GATE_PID).with_cwd_error(SysError::unsupported("cwd"));
        let cwd_exit = run(&mut cwd_host, &auth());
        assert!(
            cwd_exit.message.contains("gate_failed_caller_state"),
            "{}",
            cwd_exit.message
        );
        assert_eq!(
            cwd_host.hygiene.calls(),
            [
                HygieneCall::EnsureStdStreams,
                HygieneCall::ResetRlimitsFromPid1,
                HygieneCall::ResetUmask,
                HygieneCall::ResetCwd
            ]
        );
        assert!(!cwd_host.proc_opened.get());
        assert!(cwd_host.programs.opened().is_empty());
        assert_eq!(exec_calls(&cwd_host), 0);
    }

    #[test]
    fn the_gate_resets_limits_before_it_opens_policy_or_executes() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        let _ = run(&mut host, &auth());
        assert_eq!(
            host.hygiene.calls().get(0..2),
            Some(
                &[
                    HygieneCall::EnsureStdStreams,
                    HygieneCall::ResetRlimitsFromPid1
                ][..]
            )
        );
        assert!(host.proc_opened.get());
        assert_eq!(exec_calls(&host), 1);
    }

    #[test]
    fn a_failed_rlimit_reset_refuses_before_any_action() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.hygiene = FakeHygiene::new(GATE_PID)
            .with_rlimits_error(SysError::unsupported("PID 1 resource limits"));
        let exit = run(&mut host, &auth());
        assert!(
            exit.message.contains("gate_failed_caller_state"),
            "{}",
            exit.message
        );
        assert_eq!(
            host.hygiene.calls(),
            [
                HygieneCall::EnsureStdStreams,
                HygieneCall::ResetRlimitsFromPid1
            ]
        );
        assert!(!host.proc_opened.get());
        assert!(!host.spool_opened.get());
        assert_eq!(host.audit.records().len(), 1, "the refusal is audited");
        assert_eq!(
            host.audit.records()[0].denial.as_deref(),
            Some("gate_failed_caller_state")
        );
        assert!(host.programs.opened().is_empty());
        assert_eq!(exec_calls(&host), 0);
        assert!(consumed(&spool).is_empty());
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
                host.policy = Err(PolicyError::Rules(TrustedRulesError::Trust(
                    TrustError::NotRootOwned {
                        at: "/etc/xudo".to_owned(),
                        uid: 1000,
                    },
                )));
            },
            "gate_failed_rules",
        );
        assert_eq!(seen[1], "spool=false");
    }

    #[test]
    fn gate_refuses_a_config_on_a_user_writable_path() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
        let mut host = FakeHost::new(&spool);
        host.policy = Err(PolicyError::ConfigUntrusted(TrustError::Writable {
            at: "/etc/xudo/config.toml".to_owned(),
            mode: 0o666,
        }));
        let exit = run(&mut host, &auth());
        assert!(
            exit.message.contains("gate_failed_config"),
            "{}",
            exit.message
        );
        assert!(consumed(&spool).is_empty());
        assert_eq!(exec_calls(&host), 0);
        assert_eq!(host.audit.records().len(), 1);
        assert_eq!(
            host.audit.records()[0].denial.as_deref(),
            Some("gate_failed_config")
        );
    }

    #[test]
    fn a_spool_that_fails_the_trust_walk_stops_the_gate() {
        let (_, seen) = stops_at(
            |host| {
                host.spool = Err(SpoolError::NotOwned {
                    at: "/run/xudo/req".to_owned(),
                    uid: 1000,
                });
            },
            "gate_failed_spool",
        );
        assert_eq!(seen[1], "spool=true");
    }

    #[test]
    fn a_spool_that_cannot_be_listed_stops_the_gate() {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]).failing_names(SpoolError::Io {
            operation: "read the directory".to_owned(),
            at: "/run/xudo/req".to_owned(),
            code: Some(5),
            reason: "Input/output error".to_owned(),
        }));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 0);
        assert!(
            exit.message.contains("gate_failed_spool"),
            "{}",
            exit.message
        );
        // Nothing was read on the strength of a listing that never came.
        assert!(
            !spool
                .calls()
                .iter()
                .any(|call| matches!(call, SpoolCall::Read(_)))
        );
    }

    #[test]
    fn a_spool_holding_more_names_than_the_gate_will_walk_is_refused_not_walked() {
        // Not the broker's doing: it keeps at most 64. A spool this full is
        // something wrong, and the gate does not read it entry by entry.
        let crowded = (0..=MAX_SPOOL_NAMES).fold(FakeSpool::new(), |spool, index| {
            spool.with_file(format!("{index:05}"), "")
        });
        let spool = Rc::new(crowded.with_file(NONCE_A, ours().to_json()));
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 19);
        assert_eq!(exec_calls(&host), 0);
        assert!(
            exit.message.contains("gate_failed_spool"),
            "{}",
            exit.message
        );
        assert!(exit.message.contains("severity high"), "{}", exit.message);
        assert!(consumed(&spool).is_empty());
        assert!(
            !spool
                .calls()
                .iter()
                .any(|call| matches!(call, SpoolCall::Read(_))),
            "no entry may be read from a spool that is not walked"
        );
        let evidence = &host.audit.records()[0].evidence;
        assert!(
            evidence
                .iter()
                .any(|line| line.contains("more than the 4096 names the gate will walk")),
            "{evidence:?}"
        );
    }

    #[test]
    fn a_spool_with_exactly_as_many_names_as_the_gate_will_walk_is_walked() {
        // The bound is on more than, not on at: a full spool of junk with one
        // real entry in it still finds the entry.
        let crowded = (1..MAX_SPOOL_NAMES).fold(FakeSpool::new(), |spool, index| {
            spool.with_file(format!("{index:05}"), "")
        });
        let spool = Rc::new(crowded.with_file(NONCE_A, ours().to_json()));
        assert_eq!(spool.names().unwrap().len(), MAX_SPOOL_NAMES);
        let mut host = FakeHost::new(&spool);
        let exit = run(&mut host, &auth());
        assert!(
            exit.message.contains("gate_failed_exec"),
            "{}",
            exit.message
        );
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
    }

    #[test]
    fn a_clock_that_reads_zero_stops_the_gate_because_no_deadline_can_be_judged() {
        // `HostClock` answers zero for a negative clock reading. That
        // is the fail-closed reading for the broker, which then stamps a
        // deadline already behind it, and it would be the fail-open one here:
        // every deadline would look still ahead. Zero is no reading.
        let (exit, _) = stops_at(
            |host| {
                host.clock = FixedClock(0);
            },
            "gate_failed_clock",
        );
        assert!(exit.message.contains("severity normal"), "{}", exit.message);
        // And a clock that reads one millisecond is a clock.
        assert_eq!(read_clock(&FixedClock(1)), Ok(1));
        assert!(read_clock(&FixedClock(0)).is_err());
    }

    #[test]
    fn a_fake_boottime_reading_after_suspend_expires_the_deadline() {
        let mut pending = ours();
        pending.deadline = BoottimeMillis(900_000);
        let now_after_suspend = FixedClock(900_001).boottime_millis();
        assert_eq!(
            pending.validate(
                CallerPin::new(pending.caller_pid, pending.caller_starttime),
                pending.generation,
                BoottimeMillis(now_after_suspend),
            ),
            Err(crate::request::RequestError::Expired {
                deadline: 900_000,
                now: 900_001,
            })
        );
    }

    // ---- the invocation ---------------------------------------------------

    fn refused_invocation(args: &[&[u8]]) -> GateExit {
        let spool = Rc::new(holding(&[(NONCE_A, ours())]));
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
        assert!(consumed(&spool).is_empty());
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
        refused_invocation(&[b"xudo-gate-auth", b"--help"]);
        refused_invocation(&[b"/usr/libexec/xudo/xudo-gate-auth", b""]);
    }

    #[test]
    fn an_unexpected_argv0_is_refused() {
        for name in [
            &b"xudo-gate"[..],
            b"/usr/libexec/xudo/xudo-gate",
            b"sh",
            b"",
            b"xudo-gate-auth/",
            b"xudo-gate-auth/.",
            b"xxudo-gate-auth",
            b"xudo-gate-auth ",
            b"xudo-gate-auth\xff",
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
            "xudo-gate-auth",
            "/usr/libexec/xudo/xudo-gate-auth",
            "./xudo-gate-auth",
        ] {
            assert_eq!(
                accept_invocation(&[OsString::from(name)]).unwrap(),
                GateMode::Auth,
                "{name}"
            );
        }
        for name in ["xudo-gate-nopass", "/usr/libexec/xudo/xudo-gate-nopass"] {
            assert_eq!(
                accept_invocation(&[OsString::from(name)]).unwrap(),
                GateMode::Nopass,
                "{name}"
            );
        }
    }

    #[test]
    fn an_argv0_that_could_drive_a_terminal_reaches_the_record_escaped() {
        let spool = Rc::new(holding(&[]));
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
        let spool = Rc::new(holding(&[]));
        let mut host = FakeHost::new(&spool);
        let exit = run(
            &mut host,
            &[
                OsString::from("xudo-gate-auth"),
                OsString::from("secret-arg"),
            ],
        );
        assert!(!exit.message.contains("secret-arg"), "{}", exit.message);
        assert_eq!(
            exit.message,
            "xudo-gate: refused (gate_failed_invocation, severity high)"
        );
    }

    // ---- pieces -----------------------------------------------------------

    #[test]
    fn the_rules_directory_is_the_one_the_configuration_names() {
        assert_eq!(
            PathBuf::from(RULES_DIR),
            xudo_config::SystemPaths::default().rules_dir()
        );
        assert_eq!(
            PathBuf::from(CONFIG_FILE),
            xudo_config::SystemPaths::default().config()
        );
        assert_eq!(
            PathBuf::from(SPOOL_DIR),
            xudo_config::SystemPaths::default().runtime.join("req")
        );
        assert_eq!(SPOOL_DIR, "/run/xudo/req");
        assert_eq!(AUTH_NAME, b"xudo-gate-auth");
    }

    #[test]
    fn the_system_host_reaches_every_real_seam_and_refuses_what_this_host_is_not() {
        let mut host = SystemHost::default();
        // Constructed without opening anything.
        assert!(format!("{host:?}").contains("SystemHost"));
        assert!(host.hygiene().pid() > 0);
        #[cfg(target_os = "linux")]
        assert!(host.clock().boottime_millis() > 0);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(host.clock().boottime_millis(), 0);
        // Nothing here is a ruleset, a spool, or a root-owned program.
        assert!(host.load_policy().is_err());
        // Whatever this host holds at the marker, the answer is a bool and
        // never a panic: unreadable counts as frozen.
        let _ = host.user_frozen(u32::MAX);
        assert!(host.open_spool().is_err());
        assert!(host.open_queue().is_err());
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
        // The real cgroup view opens on a cgroup2 Linux host and refuses elsewhere;
        // either answer is fine here, a panic is not.
        let _cgroups = host.cgroups();
        // The audit trail is the system's. Handed out, never written to: a
        // test must not leave a record in a real log if it is run as root.
        let _trail = host.audit();
        let missing = xudo_sys::RemoveRequest {
            under: b"/no/such/xudo-t1-remove".to_vec(),
            relative: b"cache".to_vec(),
            recursive: false,
            max_depth: 2,
            max_entries: 1,
            owners: xudo_sys::RemoveOwnerPolicy::AnyButRoot,
            dry_run: true,
        };
        let error = host.remove_path(&missing).unwrap_err();
        #[cfg(target_os = "linux")]
        assert_eq!(error, xudo_sys::RemoveError::AncestorRefused);
        #[cfg(not(target_os = "linux"))]
        assert_eq!(error, xudo_sys::RemoveError::Unsupported);
    }

    #[test]
    fn the_real_hosts_trait_objects_are_what_the_gate_is_given() {
        let source = into_source(MapSource::new().with("1/stat", "x"));
        assert_eq!(source.read("1/stat").unwrap(), b"x");
        let spool = into_spool(FakeSpool::new().with_file("n", "x"));
        assert_eq!(spool.names().unwrap(), vec![b"n".to_vec()]);
        assert_eq!(spool.read("n").unwrap(), b"x");
        let queue = into_queue(FakeSpool::new().with_file("n.json", "x"));
        assert_eq!(queue.read("n.json").unwrap(), b"x");
        assert!(queue.read("missing").is_err());
    }

    #[test]
    fn an_authorized_vector_that_cannot_be_built_is_refused_at_the_exec_and_nothing_runs() {
        // Unreachable through `run`, where the entry's NUL bytes are refused
        // long before: reached here by authorizing an approval that carries
        // one, to prove the exec itself still refuses to hand the kernel a
        // prefix.
        let spool = Rc::new(holding(&[]));
        let mut host = FakeHost::new(&spool);
        let approved = Approved {
            program: "/usr/bin/tool".to_owned(),
            argv: Vec::new(),
            exec_argv: vec![b"a\0b".to_vec()],
            environment: Vec::new(),
            action: "xudo.x".to_owned(),
            rule_source: "r:1".to_owned(),
            requested_action: "xudo.x".to_owned(),
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

    const REMOVE_RULE: &str = r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 4
max-entries = 10
"#;

    fn remove_policy(text: &str) -> LoadedPolicy {
        LoadedPolicy {
            rules: load_policy(
                vec![RuleFile {
                    name: b"50-remove.toml".to_vec(),
                    bytes: text.as_bytes().to_vec(),
                }],
                &[],
            )
            .unwrap(),
            settings: engine::Settings::default(),
            queue_ttl_secs: 24 * 60 * 60,
            passwd: "agent:x:1000:1000:agent:/home/agent:/bin/sh\n".to_owned(),
            passwd_fault: None,
        }
    }

    fn remove_entry(text: &str, target: &[u8], dry_run: bool) -> PendingRequest {
        let mut entry = ours();
        entry.program = xudo_wire::OPERATION_PROGRAM.to_owned();
        entry.argv = vec![target.escape_ascii().to_string()];
        entry.action = "web.clean-build".to_owned();
        entry.generation = remove_policy(text).rules.generation.id();
        entry.operation = Some(crate::request::RequestedOp {
            op: "remove-path".to_owned(),
            target: target.to_vec(),
            dry_run,
        });
        entry
    }

    fn plant_tree(host: &mut FakeHost) {
        use xudo_sys::remove::NodeKind;
        let fs = &mut host.remove;
        fs.add(&[], b"srv", NodeKind::Dir, 0, 0o755, 0);
        fs.add(&[b"srv"], b"app", NodeKind::Dir, 0, 0o755, 0);
        fs.add(&[b"srv", b"app"], b"build", NodeKind::Dir, 0, 0o755, 0);
        fs.add(
            &[b"srv", b"app", b"build"],
            b"cache",
            NodeKind::File,
            1000,
            0o644,
            4,
        );
    }

    fn assert_remove_entry_refused(entry: PendingRequest) {
        let spool = Rc::new(holding(&[(NONCE_A, entry)]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        let exit = run(&mut host, &auth());
        assert_ne!(exit.status, 0, "{exit:?}");
        assert!(host.remove.unlinked().is_empty());
        assert!(host.remove.exists(&[b"srv", b"app", b"build", b"cache"]));
    }

    #[test]
    fn an_expired_remove_path_entry_is_refused_by_the_gate() {
        let mut entry = remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false);
        entry.deadline = crate::request::BoottimeMillis(NOW);
        assert_remove_entry_refused(entry);
    }

    #[test]
    fn a_stale_generation_remove_path_entry_is_refused() {
        let mut entry = remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false);
        entry.generation = entry.generation.saturating_add(1);
        assert_remove_entry_refused(entry);
    }

    #[test]
    fn an_entry_minted_under_another_operation_rule_is_refused() {
        let mut entry = remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false);
        entry.action = "other.clean-build".to_owned();
        assert_remove_entry_refused(entry);
    }

    #[test]
    fn a_remove_path_entry_for_another_attested_identity_is_refused() {
        let mut entry = remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false);
        entry.attested_class = crate::request::AttestedClass::EnrolledAgent { scope_id: 91 };
        entry.attested_scope_id = Some(91);
        entry.boot_id = Some("01234567-89ab-cdef-0123-456789abcdef".to_owned());
        entry.attested_harness = Some("codex".to_owned());
        assert_remove_entry_refused(entry);
    }

    #[test]
    fn a_password_gate_removes_a_path_and_does_not_exec() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 0);
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert_eq!(exit.status, 0, "{exit:?}");
        assert!(exit.message.contains("removed 1"));
        assert!(!host.remove.exists(&[b"srv", b"app", b"build", b"cache"]));
        let records = host.audit.records();
        assert_eq!(records.len(), 2);
        assert!(has_line(&records[0].evidence, "op=remove-path-intent"));
        assert!(has_line(&records[0].evidence, "planned_count=1"));
        assert_eq!(records[1].decision, AuditDecision::Allowed);
        assert!(has_line(&records[1].evidence, "op=remove-path"));
        assert!(has_line(&records[1].evidence, "intent_seq=1"));
        assert!(has_line(&records[1].evidence, "severity=normal"));
        assert_eq!(records[1].outcome.kind(), "exited");
    }

    #[test]
    fn a_killed_walk_leaves_an_intent_record() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        host.remove.fail_at("unlinkat", 0, 5);
        host.assert_intent_before_unlink = true;
        let _ = run(&mut host, &auth());
        assert!(host.audit.records().iter().any(|record| {
            has_line(&record.evidence, "op=remove-path-intent")
                && has_line(&record.evidence, "planned_count=1")
        }));
        assert!(host.remove.unlinked().is_empty());
    }

    #[test]
    fn dry_run_removes_nothing() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/srv/app/build/cache", true),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 0, "{exit:?}");
        assert_eq!(exec_calls(&host), 0);
        assert!(host.remove.exists(&[b"srv", b"app", b"build", b"cache"]));
        assert!(host.remove.unlinked().is_empty());
        let records = host.audit.records();
        assert_eq!(records.len(), 2);
        assert!(has_line(&records[0].evidence, "op=remove-path-intent"));
        assert!(has_line(&records[0].evidence, "planned_count=1"));
        assert!(has_line(&records[1].evidence, "severity=low"));
        assert!(has_line(&records[1].evidence, "dry_run=true"));
        assert!(has_line(&records[1].evidence, "intent_seq=1"));
        assert_eq!(records[1].outcome.kind(), "not_executed");
    }

    #[test]
    fn a_target_outside_the_tree_is_not_consumed() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/etc/passwd", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 0);
        assert!(consumed(&spool).is_empty());
        assert!(host.remove.exists(&[b"srv", b"app", b"build", b"cache"]));
        assert!(exit.message.contains("operation_refused"), "{exit:?}");
        assert_eq!(
            denial_codes(&host),
            vec![Some("operation_refused".to_owned())]
        );
    }

    #[test]
    fn stops_at_max_entries_and_reports_partial() {
        use xudo_sys::remove::NodeKind;
        let rule = REMOVE_RULE.replace("max-entries = 10", "max-entries = 1");
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(&rule, b"/srv/app/build/box", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(&rule));
        plant_tree(&mut host);
        host.remove.add(
            &[b"srv", b"app", b"build"],
            b"box",
            NodeKind::Dir,
            1000,
            0o755,
            0,
        );
        host.remove.add(
            &[b"srv", b"app", b"build", b"box"],
            b"a",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        host.remove.add(
            &[b"srv", b"app", b"build", b"box"],
            b"b",
            NodeKind::File,
            1000,
            0o644,
            1,
        );
        let exit = run(&mut host, &auth());
        assert_eq!(exit.status, 1, "{exit:?}");
        assert_eq!(exec_calls(&host), 0);
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert!(exit.message.contains("partial"));
        let records = host.audit.records();
        assert_eq!(records.len(), 2);
        assert!(has_line(&records[0].evidence, "op=remove-path-intent"));
        assert_eq!(records[1].decision, AuditDecision::Allowed);
        assert!(has_line(&records[1].evidence, "partial=true"));
        let left = [&b"a"[..], &b"b"[..]]
            .iter()
            .filter(|name| {
                host.remove
                    .exists(&[b"srv", b"app", b"build", b"box", name])
            })
            .count();
        assert_eq!(left, 1);
    }

    #[test]
    fn a_walk_that_cannot_start_is_a_refusal_after_the_entry_is_consumed() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        // No tree is planted: the walk cannot open its first component.
        let exit = run(&mut host, &auth());
        assert_ne!(exit.status, 0, "{exit:?}");
        assert_eq!(exec_calls(&host), 0);
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert!(exit.message.contains("refused"), "{exit:?}");
    }

    #[test]
    fn an_audit_failure_before_intent_stops_before_unlink() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        host.audit = FakeAuditSink::failing("sink closed");
        let exit = run(&mut host, &auth());
        assert_eq!(exec_calls(&host), 0);
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert!(host.remove.exists(&[b"srv", b"app", b"build", b"cache"]));
        assert!(exit.message.contains("refused"), "{exit:?}");
        assert_ne!(exit.status, 0);
    }

    #[test]
    fn a_final_audit_failure_after_the_walk_preserves_the_intent_record() {
        let spool = Rc::new(holding(&[(
            NONCE_A,
            remove_entry(REMOVE_RULE, b"/srv/app/build/cache", false),
        )]));
        let mut host = FakeHost::new(&spool);
        host.policy = Ok(remove_policy(REMOVE_RULE));
        plant_tree(&mut host);
        host.audit = FakeAuditSink::failing_after(
            1,
            AuditError::Unavailable {
                reason: "sink closed after walk".into(),
            },
        );
        let exit = run(&mut host, &auth());
        assert_ne!(exit.status, 0, "{exit:?}");
        assert!(!exit.message.contains("refused"), "{exit:?}");
        assert!(
            exit.message
                .contains("removed 1 entries; the audit record failed"),
            "{exit:?}"
        );
        assert_eq!(consumed(&spool), [NONCE_A.to_owned()]);
        assert!(!host.remove.exists(&[b"srv", b"app", b"build", b"cache"]));
        let records = host.audit.records();
        assert_eq!(records.len(), 1);
        assert!(has_line(&records[0].evidence, "op=remove-path-intent"));
    }

    // ---- the gate's mode comes from the executed file ---------------------

    fn nopass() -> Vec<OsString> {
        vec![OsString::from("/usr/libexec/xudo/xudo-gate-nopass")]
    }

    /// A host whose spool holds one entry and whose executed file is `file`.
    fn host_running(
        file: xudo_sys::FakeGateFiles,
        entry: PendingRequest,
    ) -> (FakeHost, Rc<FakeSpool>) {
        let spool = Rc::new(holding(&[(NONCE_A, entry)]));
        let mut host = FakeHost::new(&spool);
        host.gate_files = file;
        (host, spool)
    }

    #[test]
    fn the_mode_comes_from_the_executed_file_not_argv0() {
        // The file is the `-nopass` gate and the caller named it `-auth`: a
        // name the caller chose does not select the mode.
        let (mut host, spool) = host_running(
            xudo_sys::FakeGateFiles::running_as(GateMode::Nopass),
            ours(),
        );
        let exit = run(&mut host, &auth());
        assert_refused_with(&host, &spool, &exit, "gate_failed_invocation");
        assert!(exit.message.contains("severity high"));
        // Refused before the ruleset, the spool or the lineage were read.
        assert!(!host.spool_opened.get());
    }

    #[test]
    fn argv0_and_the_executed_file_disagreeing_is_refused() {
        // The other direction: a password-less name over the `-auth` file.
        let (mut host, spool) =
            host_running(xudo_sys::FakeGateFiles::running_as(GateMode::Auth), ours());
        let exit = run(&mut host, &nopass());
        assert_refused_with(&host, &spool, &exit, "gate_failed_invocation");
        let detail = &host.audit.records()[0].evidence;
        assert!(
            has_line(detail, "detail=argv[0] names one gate file"),
            "{detail:?}"
        );
    }

    #[test]
    fn a_hardlinked_or_replaced_gate_file_is_refused() {
        for error in [
            xudo_sys::GateFilesError::HardLinked {
                at: "/usr/libexec/xudo/xudo-gate-auth".to_owned(),
                nlink: 2,
            },
            xudo_sys::GateFilesError::NotAGateFile,
        ] {
            for name in [auth(), nopass()] {
                let (mut host, spool) =
                    host_running(xudo_sys::FakeGateFiles::refusing(error.clone()), ours());
                let exit = run(&mut host, &name);
                assert_refused_with(&host, &spool, &exit, "gate_failed_invocation");
                assert!(!host.spool_opened.get());
            }
        }
    }

    #[test]
    fn direct_nopass_invocation_with_no_entry_does_nothing() {
        // A hostile user starts the file with nothing minted for them.
        let spool = Rc::new(holding(&[]));
        let mut host = FakeHost::new(&spool);
        host.gate_files = xudo_sys::FakeGateFiles::running_as(GateMode::Nopass);
        let exit = run(&mut host, &nopass());
        assert_refused_with(&host, &spool, &exit, "gate_no_pending_request");
        assert!(exit.message.contains("severity high"));
    }

    #[test]
    fn nopass_refuses_an_auth_entry_the_broker_minted_today() {
        // The broker writes only `auth`, so under `-nopass` every real entry
        // is refused, and none is consumed.
        let (mut host, spool) = host_running(
            xudo_sys::FakeGateFiles::running_as(GateMode::Nopass),
            ours(),
        );
        let exit = run(&mut host, &nopass());
        assert_refused_with(&host, &spool, &exit, "gate_mode_wrong_via");
    }

    #[test]
    fn nopass_refuses_when_the_caller_left_its_scope() {
        // A harness entry for a stored scope whose caller now reads as a human.
        let mut entry = ours();
        entry.via = crate::request::Via::Harness;
        entry.attested_class = crate::request::AttestedClass::EnrolledAgent { scope_id: 90 };
        entry.attested_scope_id = Some(90);
        entry.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        entry.attested_harness = Some("codex".to_owned());
        let (mut host, spool) =
            host_running(xudo_sys::FakeGateFiles::running_as(GateMode::Nopass), entry);
        host.cgroup_mode = FakeCgroupMode::Human;
        script_human(&mut host);
        let exit = run(&mut host, &nopass());
        assert_refused_with(&host, &spool, &exit, "gate_mode_not_an_enrolled_agent");
    }

    #[test]
    fn nopass_refuses_a_live_enrolled_agent_no_rule_grants() {
        // Every fact about the caller holds, and no rule grants it.
        let mut entry = ours();
        entry.via = crate::request::Via::Harness;
        entry.attested_class = crate::request::AttestedClass::EnrolledAgent { scope_id: 90 };
        entry.attested_scope_id = Some(90);
        entry.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        entry.attested_harness = Some("codex".to_owned());
        let (mut host, spool) =
            host_running(xudo_sys::FakeGateFiles::running_as(GateMode::Nopass), entry);
        host.cgroup_mode = FakeCgroupMode::Agent;
        host.peers = agent_parent_peers();
        host.syscalls = FakeSyscalls::new()
            .with_cloexec(Ok(()))
            .with_boot_id(Ok("abcdef01-2345-6789-abcd-ef0123456789".to_owned()));
        let exit = run(&mut host, &nopass());
        assert_refused_with(&host, &spool, &exit, "gate_mode_not_granted");
    }
}
