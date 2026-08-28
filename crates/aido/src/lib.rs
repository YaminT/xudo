//! The unprivileged `aido` front-end.
//!

//!
//! This crate parses a request, loads the root-owned ruleset, asks
//! `aido-policy` for a decision, and renders it. It **decides nothing**, holds
//! no secret, and at this milestone executes nothing at all: there is no
//! privileged path yet, so every subcommand here is introspection.
//!
//! # Why the entry point lives in a different package
//!
//! Every module here is driven directly by unit tests, because a decision path
//! that can only be reached by spawning a process is a decision path that gets
//! tested less carefully than it deserves. The five-line `main` sits in
//! `aido-bin`, and `aido-tests` asserts the exit status a shell actually
//! receives.
//!
//! The split is also what makes coverage honest: a package that is both a
//! library and a binary compiles every module twice, so each file is measured
//! twice and covered once.
//!
//! # `clap` without the `env` feature
//!
//! Declared in `Cargo.toml`, and load-bearing. If a flag could be set from the
//! environment, then a safety default would be one `export` away from off — and
//! in the case this project exists for, the agent controls the export.

#![forbid(unsafe_code)]

pub mod agentdoc;
pub mod cli;
pub mod render;
pub mod rules;

pub use cli::{Cli, Command, Format, run, run_with};
pub use rules::{LoadError, LoadedRules};
