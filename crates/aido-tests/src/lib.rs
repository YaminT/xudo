//! Tests that belong to the workspace as a whole rather than to any one crate.
//!
//! Today that is `tests/crate_inventory.rs`: the crate tables in `CLAUDE.md`,
//! `docs/design-plan.md`, and `docs/todo/README.md` must name exactly the
//! members of the workspace's `Cargo.toml`, with a crate that is built but not
//! yet merged marked as in review. It reads those files with the standard
//! library alone, so this package has no dependencies.
//!
//! Reserved for the differential compliance matrix once there is something to
//! execute: the same ruleset run *through* sudo, sudo-rs, and `OpenDoas`, in
//! containers and VMs, asserting identical outcomes.
//!
//! The half that exists today is not Rust. `ci/differential/run.sh` drives the
//! static `aido` binary inside real distributions against each backend's own
//! parser — detection, the probed capability matrix, the install plan, the
//! generated snippet, and every verdict — and `just differential` runs it. It
//! stays a shell harness because its whole job is to start containers, which
//! this workspace's lint rules forbid a crate from doing for good reason.
//!
//! The `aido` binary's own process-level tests live in `aido-bin/tests`, the
//! only package Cargo builds that binary for.

#![forbid(unsafe_code)]
