//! The `aidod` entry point.
//!
//! Deliberately the whole of it. systemd starts one of these per accepted
//! connection with the connection as standard input (`StandardInput=socket`),
//! so descriptor 0 is borrowed from `std::io::stdin()` — no `LISTEN_FDS` to
//! read from an environment a privileged process must not trust, and no
//! descriptor adopted by number. Everything else is the `aidod` library,
//! covered by its own tests; `tests/broker.rs` runs this binary as a process.

#![forbid(unsafe_code)]

use std::os::fd::AsFd as _;

fn main() -> std::process::ExitCode {
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    let trail = aidod::trail_of(stderr.as_fd());
    let mut log = stderr.lock();
    std::process::ExitCode::from(aidod::run(stdin.as_fd(), trail, &mut log))
}
