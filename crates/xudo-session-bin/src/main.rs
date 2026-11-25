//! The `xudo-session` entry point.
//!
//! Deliberately the whole of it: `xudod::unit_record::run` reads the host,
//! decides, and writes or removes one record. What remains is to print the
//! line it returns and leave with its status. It reads no environment;
//! `args_os`, not `args`, because argv is bytes and one that is not UTF-8
//! must be refused as what it is, not abort here. `tests/binary.rs` asserts
//! all of this through a real process.

#![forbid(unsafe_code)]

use std::io::Write;

fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let exit = xudod::unit_record::run(&args);
    // Ignored on purpose: the refusal stands whether or not anyone can read it.
    let _ = writeln!(std::io::stderr(), "{}", exit.message);
    std::process::ExitCode::from(exit.status)
}
