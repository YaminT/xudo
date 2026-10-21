//! The `aido-gate` entry point.
//!
//! Deliberately the whole of it. The sequence — descriptors, `/dev/null`,
//! `/proc`, lineage, rules, spool, program, audit, exec — is `aido_gate::run`,
//! written against traits and tested at 100% in the library; what remains is
//! to hand it the real host, print the one line it returns, and leave with its
//! status. `tests/binary.rs` asserts that through a real process.
//!
//! It reads no environment. `args_os`, not `args`: `argv` is bytes, and one
//! that is not UTF-8 must be refused as what it is rather than abort here.
//! A successful exec never returns, so this returns only to refuse.

#![forbid(unsafe_code)]

use std::io::Write;

fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let mut host = aido_gate::SystemHost::new();
    let exit = aido_gate::run(&mut host, &args);
    // Ignored on purpose: the refusal stands whether or not anyone can read
    // the line, and a failed write must not turn into a panic.
    let _ = writeln!(std::io::stderr(), "{}", exit.message);
    // Falls back to "aido is unusable" rather than 0 if the status ever
    // exceeds a u8, so an unexpected value can never be read as success.
    std::process::ExitCode::from(u8::try_from(exit.status).unwrap_or(19))
}
