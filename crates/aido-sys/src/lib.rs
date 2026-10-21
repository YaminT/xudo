//! Platform abstraction for `aido`.
//!
//! `aido-policy` decides; this crate is the only place allowed to *look at the
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
//! live in `aido-sys-raw`, behind a published block budget, and the rest of
//! the workspace reaches them only through [`Syscalls`], where a fake can stand
//! in for the kernel.

#![forbid(unsafe_code)]

pub mod audit;
pub mod clock;
pub mod connection;
pub mod entropy;
pub mod error;
pub mod exec;
pub mod kernel;
mod mounts;
pub mod peer;
pub mod platform;
pub mod probe;
pub mod proc;
pub mod provenance;
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
pub use clock::{Clock, FixedClock, HostClock};
pub use connection::{
    AdoptError, Connection, FakeConnection, ReadFailure, UnixConnection, connected_unix_stream,
};
pub use entropy::{Entropy, FakeEntropy, HostEntropy};
pub use error::SysError;
pub use exec::{HostRunner, Output, Runner, run_capture};
pub use kernel::{Attestation, KernelSupport, KernelVersion, Resolution};
pub use mounts::MountRefusal;
pub use peer::{
    FakePeer, HostPeer, PeerCall, PeerCalls, PeerCred, ProcFile, StatusUids, lacks_peer_pidfd,
    lacks_pidfd_info, lacks_pidfd_open, parse_status_euid, parse_status_uids, peer_was_reaped,
    process_is_gone,
};
pub use platform::{LinuxOps, MacOsStub, PrivilegedOps, host_ops};
pub use probe::HostProbe;
pub use proc::{CgroupPath, MountEntry, ProcStat, parse_cgroup, parse_mountinfo, parse_stat};
pub use provenance::{Ancestry, ProcRef, ancestry, hints};
pub use source::{DirSource, MapSource, ProcSource};
pub use spool::{FakeSpool, Spool, SpoolCall, SpoolDir, SpoolError, TEMP_PREFIX};
pub use syscall::{Creds, FakeCall, FakeSyscalls, HostSyscalls, PidfdInfo, ProcessIds, Syscalls};
pub use trust::{
    PathFacts, TrustError, TrustedFile, TrustedRulesError, load_trusted_rules, open_trusted,
    read_trusted_dir, verify_path,
};
pub use trusted_file::read_trusted_file;

// Re-exported so a consumer does not need to depend on aido-policy just to
// name the types this crate returns.
pub use aido_policy::{CallerFacts, Classification, Hint, HintSource};
