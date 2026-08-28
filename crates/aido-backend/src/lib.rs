//! What `aido` asks `sudo`, `sudo-rs`, or `doas` to do — and what it must not
//! assume about them.
//!
//! This crate is pure. It takes facts that were gathered elsewhere (a version
//! banner, a probe result) and decides what to write, which command validates
//! it, and what to check afterwards. It never runs a process and never touches
//! a file, so all of it is unit-tested on any platform while the Linux-only
//! half — actually invoking the backend, actually renaming into `/etc` — lives
//! behind `aido-sys` and needs a real kernel.
//!
//! # The snippet is the entire security boundary
//!
//! Everything `aido` promises rests on one root-owned file granting exactly one
//! zero-argument command. If that file is wrong, or silently ignored, or
//! quietly stripped of a directive by a backend that does not implement it,
//! then the guarantees above it are decoration. So this crate is mostly a
//! collection of specific, historically-earned refusals:
//!
//! * A drop-in whose name contains a dot or ends in `~` is **silently ignored**
//!   by sudo. `/etc/sudoers.d/aido.conf` installs cleanly and does nothing.
//!   [`SudoersSnippet::path`] cannot produce such a name.
//! * `sudo-rs`'s `visudo` validates only `/etc/sudoers`, not the drop-in
//!   directory, so validation must name aido's own file explicitly.
//! * `sudo-rs` **ignores directives it does not support**, logging a warning.
//!   A rule aido wrote may therefore not mean what it says, which is why
//!   [`InstallPlan`] ends in a functional probe rather than a file check.
//! * `doas` has no drop-in directory on most ports, so its integration is a
//!   sentinel-delimited block appended under a lock — and it must be removable
//!   exactly.
//! * `OpenDoas` disables `persist` unless built `--with-timestamp`, so aido never
//!   depends on backend credential caching in either direction.

#![forbid(unsafe_code)]

pub mod capability;
pub mod detect;
pub mod plan;
pub mod snippet;

pub use capability::{Capability, CapabilityMatrix};
pub use detect::{Backend, BackendKind, DetectError, Probe, detect};
pub use plan::{InstallPlan, PlanStep, uninstall_plan};
pub use snippet::{DoasSnippet, SnippetError, SudoersSnippet};
