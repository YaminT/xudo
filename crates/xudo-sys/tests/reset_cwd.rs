//! The working directory the gate resets, in a process of its own.
//!
//! `chdir` is process-global. The library unit tests share one process and
//! run in parallel threads, so proving `fchdir` to `/` there would move every
//! other test for the window. This binary is that proof, and nothing else.
//! The root-lane probe also runs the gate's command and reads `/` back; this
//! one covers `HostRoot` inside `xudo-sys`, which that probe does not.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use xudo_sys::{HostHygiene, Hygiene};

#[cfg(target_os = "linux")]
#[test]
fn the_host_enters_slash_from_a_caller_chosen_directory() {
    rustix::process::chdir("/tmp").unwrap();
    HostHygiene.reset_cwd().unwrap();
    let cwd = rustix::process::getcwd(Vec::new()).unwrap();
    assert_eq!(cwd.as_bytes(), b"/");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn off_linux_the_host_refuses_to_enter_slash() {
    let err = HostHygiene.reset_cwd().unwrap_err();
    assert!(err.to_string().contains("not supported"), "{err}");
}
