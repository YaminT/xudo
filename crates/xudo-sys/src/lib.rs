//! Platform abstraction for `xudo`.
//!
//! `xudo-policy` decides; this crate is the only place allowed to *look at the
//! machine*. Everything the system can tell us sits behind a trait with an
//! in-memory fake, so the logic on top is testable without Linux, without root,
//! and without a `/proc` at all.
//!
//! # What this crate is allowed to be trusted for
//!
//! Almost nothing, and that is deliberate.
//!
//! Everything read here — `comm`, `cmdline`, `environ`, the resolved `exe`, the
//! ancestry chain — is produced by the caller or by a process the caller
//! controls. So this crate's output is [`Hint`]s and an
//! [`Classification`], and at this milestone the classification is *always*
//! [`Classification::Unattested`]: there is no broker yet, no `SO_PEERPIDFD`,
//! and no cgroup scope to check against. Per the project's second invariant,
//! unattested routes to the human path with a password, so a machine with only
//! this crate installed can misclassify in exactly one direction — it can ask
//! for a password it did not strictly need, never skip one it did.
//!
//! That is why the `/proc` reader here does **not** carry the `openat2`
//! hardening that the M2 exec path will. A lie in a hint cannot escalate,
//! because a hint cannot authorize. The hardening belongs on the path that
//! opens and executes a file, and it arrives with that path.
//!
//! # Platform posture
//!
//! [`MacOsStub`] answers `Unsupported` to every privileged question and
//! `Unattested` to every classification, so a developer on macOS cannot
//! accidentally validate a Linux-only assumption: every decision path they
//! exercise is the fail-closed one.
//!
//! # `unsafe`
//!
//! None here, and the compiler holds that: this crate forbids `unsafe_code`
//! like every other. The five system calls that cannot be made without it
//! live in `xudo-sys-raw`, behind a published block budget, and the rest of
//! the workspace reaches them only through [`Syscalls`], where a fake can stand
//! in for the kernel.

#![forbid(unsafe_code)]

pub mod audit;
pub mod cgroup;
pub mod clock;
pub mod connection;
pub mod entropy;
pub mod envfile;
pub mod error;
pub mod exec;
pub mod gate_files;
pub mod hygiene;
pub mod install;
pub mod kernel;
pub mod live;
mod mounts;
pub mod own;
pub mod peer;
pub mod platform;
pub mod probe;
pub mod proc;
pub mod procfs;
pub mod program;
pub mod provenance;
pub mod remove;
pub mod source;
pub mod spool;
pub mod syscall;
pub mod trust;
pub mod trusted_file;

#[cfg(any(test, feature = "fake"))]
pub use audit::FakeAuditSink;
pub use audit::{
    AUDIT_DIR, AUDIT_FILE_NAME, Approval, AuditError, AuditMirror, AuditReceipt, AuditSink,
    AuditTrail, Authorized, JOURNAL_SOCKET, JournaldSink, JsonlLog, authorize,
};
pub use cgroup::{
    CgroupCalls, CgroupIdentity, CgroupRung, HostCgroup, ProcessSecurityStatus, RecordIdentity,
    SERVICE_RECORD_PREFIX, Scope, ScopeFacts, ScopeKind, is_record_name,
    parse_process_security_status, peer_cgroup_id, process_cgroup, process_security_status,
    scope_status, service_record_name, unit_dir_name, verify_parent_pid,
};
#[cfg(target_os = "linux")]
pub use clock::DEADLINE_CLOCK;
pub use clock::{Clock, FixedClock, HostClock};
pub use connection::{
    AdoptError, Connection, FakeConnection, ReadFailure, UnixConnection, connected_unix_stream,
};
pub use entropy::{Entropy, FakeEntropy, HostEntropy};
#[cfg(any(test, feature = "fake"))]
pub use envfile::FakeEnvFiles;
pub use envfile::{AGENT_ENV_DIR, EnvFileProbe, EnvFiles, HostEnvFiles};
pub use error::SysError;
pub use exec::{HostRunner, Output, Runner, run_capture};
#[cfg(any(test, feature = "fake"))]
pub use gate_files::FakeGateFiles;
pub use gate_files::{
    AUTH_FILE, FileId, GATE_DIR, GateFiles, GateFilesError, GateMode, HostGateFiles, NOPASS_FILE,
};
pub use hygiene::{FakeHygiene, HostHygiene, Hygiene, HygieneCall};
pub use install::{
    Effect, HostInstallOps, HostInstaller, InstallError, InstallOps, InstallProbe, InstallReport,
    Installer, ProbeResult, RefusingInstaller, Verification, check_effect, execute,
};
pub use kernel::{Attestation, KernelSupport, KernelVersion, Resolution};
pub use live::LiveHost;
pub use mounts::MountRefusal;
#[cfg(any(test, feature = "fake"))]
pub use own::FakeOwn;
pub use own::{HostOwn, OwnFacts};
pub use peer::{
    FakePeer, HostPeer, PeerCall, PeerCalls, PeerCred, ProcFile, StatusUids, lacks_peer_pidfd,
    lacks_pidfd_info, lacks_pidfd_open, parse_status_euid, parse_status_uids, peer_was_reaped,
    process_is_gone,
};
pub use platform::{LinuxOps, MacOsStub, PrivilegedOps, host_ops};
pub use probe::HostProbe;
pub use proc::{
    CgroupPath, MountEntry, ProcStat, is_identity_uid_map, parse_cgroup, parse_mountinfo,
    parse_nspid_count, parse_stat,
};
pub use procfs::VerifiedProc;
pub use program::{FakePrograms, HostPrograms, Program, ProgramError, Programs};
pub use provenance::{Ancestry, ProcRef, ancestry, hints, lineage};
#[cfg(any(test, feature = "fake"))]
pub use remove::FakeRemoveFs;
pub use remove::{
    OwnerPolicy as RemoveOwnerPolicy, RemoveError, RemoveReport, RemoveRequest, removal_digest,
    remove_path, remove_path_on_host,
};
pub use source::{DirSource, MapSource, ProcSource};
#[cfg(any(test, feature = "fake"))]
pub use spool::{FakeSpool, SpoolCall};
pub use spool::{Spool, SpoolDir, SpoolError, TEMP_PREFIX, as_seam};
pub use syscall::{Creds, FakeCall, FakeSyscalls, HostSyscalls, PidfdInfo, ProcessIds, Syscalls};
pub use trust::{
    PathFacts, TrustError, TrustedFile, TrustedRulesError, load_trusted_policy, load_trusted_rules,
    open_trusted, read_trusted_dir, verify_path,
};
pub use trusted_file::read_trusted_file;

// Re-exported so a consumer does not need to depend on xudo-policy just to
// name the types this crate returns.
pub use xudo_policy::{CallerFacts, Classification, Hint, HintSource};
