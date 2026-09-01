//! The gate's decision core.
//!
//! `/usr/libexec/aido/aido-gate-auth` is the only thing in `aido` that runs as
//! root with the power to exec. It is reached through `sudo`, and the sudoers
//! rule grants it **with no arguments at all**, so this crate is written to one
//! assumption:
//!
//! > A hostile local user in the `aido` group runs the gate directly, right now,
//! > with an empty argv, a hand-built environment, and a spool entry they wrote
//! > themselves.
//!
//! Everything below follows from that. The gate is safe to invoke because the
//! gate is *itself the policy engine* — it re-decides from root-owned state
//! rather than trusting anything it was handed.
//!
//! # Why a second engine at all
//!
//! The front-end already evaluated the request. Re-evaluating here is not
//! belt-and-braces duplication; the front-end's verdict has **no standing**. It
//! ran unprivileged, in a process the caller controls, and its answer reaches
//! the gate only as a claim inside a spool entry. If the gate deferred to that
//! claim, the front-end would be the authorization boundary — and the front-end
//! is the thing the attacker already owns.
//!
//! So the same [`aido_policy::evaluate`] runs again, on a ruleset the gate
//! verified is root's, and the spool entry contributes only the *question*:
//! which action, which program, which operands.
//!
//! # What the spool entry is allowed to influence
//!
//! Nothing that widens a decision. Concretely, a caller who forges an entry can
//! ask for a different allowlisted action — and gets exactly what the ruleset
//! already permits, with the password `sudo` demands on the human path. What
//! they cannot do is ask for something the ruleset does not name, ride a stale
//! request, replay a consumed one, or borrow another process's pending entry:
//! [`request::PendingRequest::validate`] refuses each of those before the
//! ruleset is ever consulted.
//!
//! # Layout
//!
//! | Module | Answers |
//! |---|---|
//! | [`request`] | Is this spool entry a live request from *this* caller? |
//! | [`mod@decide`] | Does root's ruleset permit it, and what exactly may run? |
//! | [`mod@env`] | What environment does the child get? (a fixed one, built here) |
//! | [`status`] | How is the child's fate reported back faithfully? |
//!
//! All four are pure. The syscalls that surround them — `close_range`, the
//! `statfs` check on `/proc`, the `openat2` walk, `execveat` — live in
//! `aido-sys` behind its trait, which is what lets every refusal below be
//! reached by a test on a developer's laptop without root.

pub mod decide;
pub mod env;
pub mod request;
pub mod status;

pub use decide::{
    Approved, GateCaller, GateContext, Refusal, Severity, authorization_record, decide,
    demanded_confirmation, refusal_record,
};
pub use env::child_environment;
pub use request::{PendingRequest, RequestError, SPOOL_DIR};
pub use status::Termination;
