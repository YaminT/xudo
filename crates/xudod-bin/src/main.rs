//! The `xudod` entry point.
//!
//! systemd starts one of these per accepted connection with the connection as
//! standard input (`StandardInput=socket`), so descriptor 0 is borrowed from
//! `std::io::stdin()`: no `LISTEN_FDS` to read from an environment a privileged
//! process must not trust. Everything else is the `xudod` library;
//! `tests/broker.rs` runs this binary as a process.

#![forbid(unsafe_code)]

use std::os::fd::AsFd as _;

fn main() -> std::process::ExitCode {
    let mut trail = xudo_sys::AuditTrail::system("xudod");
    std::process::ExitCode::from(xudod::run(std::io::stdin().as_fd(), &mut trail))
}
