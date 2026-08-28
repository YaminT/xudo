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

#![forbid(unsafe_code)]

pub mod error;
pub mod exec;
pub mod platform;
pub mod probe;
pub mod proc;
pub mod provenance;
pub mod source;

pub use error::SysError;
pub use exec::{HostRunner, Output, Runner, run_capture};
pub use platform::{LinuxOps, MacOsStub, PrivilegedOps, host_ops};
pub use probe::HostProbe;
pub use proc::{CgroupPath, MountEntry, ProcStat, parse_cgroup, parse_mountinfo, parse_stat};
pub use provenance::{Ancestry, ProcRef, ancestry, hints};
pub use source::{DirSource, MapSource, ProcSource};

// Re-exported so a consumer does not need to depend on aido-policy just to
// name the types this crate returns.
pub use aido_policy::{CallerFacts, Classification, Hint, HintSource};
