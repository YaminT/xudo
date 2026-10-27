//! The `aidod` entry point.
//!
//! Deliberately the whole of it. systemd starts one of these per accepted
//! connection with the connection as standard input (`StandardInput=socket`),
//! so descriptor 0 is borrowed from `std::io::stdin()` — no `LISTEN_FDS` to
//! read from an environment a privileged process must not trust, and no
//! descriptor adopted by number. The audit trail is the system's,
//! `AuditTrail::system("aidod")`, and nothing here can choose another: no
//! argument, no feature, no environment variable says where a root process
//! writes its record. Everything else is the `aidod` library, covered by its
//! own tests; `tests/broker.rs` runs this binary as a process and
//! `tests/root_trail.rs` runs it as root against the real trail.

#![forbid(unsafe_code)]

use std::os::fd::AsFd as _;

fn main() -> std::process::ExitCode {
    let stdin = std::io::stdin();
    let mut trail = aido_sys::AuditTrail::system("aidod");
    std::process::ExitCode::from(aidod::run(stdin.as_fd(), &mut trail))
}
