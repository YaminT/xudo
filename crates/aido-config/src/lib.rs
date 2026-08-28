//! Layered configuration for `aido` and `ido`.
//!
//! Pure. It is handed values and told which layer they came from; it never reads
//! a file, a flag, or the environment. That is what makes the two rules below
//! testable against the cases that matter rather than against whatever happens
//! to be set on the machine.
//!
//! # One precedence order
//!
//! ```text
//! compiled-in  (not configuration; the program)
//!   -> built-in default
//!   -> system      (/etc/aido, root-owned)
//!   -> user        (ido only — aido has no user layer)
//!   -> project     (narrowing only)
//!   -> environment (presentation settings only)
//!   -> flag        (always wins)
//! ```
//!
//! # The two rules that are enforced, not documented
//!
//! **Security-relevant settings are not settable from the environment.** The
//! caller controls the environment, so a safety default readable from it is one
//! `export` away from off — and the agent controls the export. Checked at merge
//! time by [`settings::Setting::is_security_relevant`].
//!
//! **A project layer may only narrow.** A checked-in file is writable by anyone
//! who can open a pull request, so it may tighten a limit or add a confirmation
//! and may never remove one. "Narrower" has no generic meaning, so each setting
//! defines it: see [`settings::Setting::narrows`].
//!
//! # Why `aido` has no user layer at all
//!
//! A file the user can write is a file the agent can write. `~/.config/aido`
//! does not exist and must never be read. `ido` is the opposite case — it
//! crosses no privilege boundary, so a user may configure their own picker
//! freely, with one exception that is absolute: **no setting, and no combination
//! of settings, may cause a queued command to run without the human selecting
//! it.**

#![forbid(unsafe_code)]

pub mod layer;
pub mod load;
pub mod paths;
pub mod settings;

pub use layer::{Layer, Origin, Tracked};
pub use load::{LoadError, apply_file};
pub use paths::{SystemPaths, XdgPaths};
pub use settings::{MergeError, SchemaEntry, Setting, Settings, Value};
