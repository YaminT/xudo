//! The one place `aido` starts a child process.
//!
//! Isolated into its own file because it is the only code in the workspace whose
//! failure paths cannot be reached from a test: they need the kernel to fail a
//! `fork` or a pipe read on a descriptor we own. Every *decision* built on a
//! probe result lives behind [`crate::exec::Runner`] and is fully covered
//! against a fake, so what is excluded here is process plumbing and nothing
//! else. The exclusion is recorded in the `justfile` next to the other two.
//!
//! # Why `Command::new` is used here despite being banned
//!
//! `clippy.toml` disallows `std::process::Command::new` project-wide, because
//! resolving an executable through `PATH` means the caller chooses the binary.
//! The ban is lifted for exactly this function, under exactly these conditions:
//!
//! * the path must be **absolute**, checked at run time and not by convention;
//! * the environment is **cleared and rebuilt**, so no `LD_PRELOAD`,
//!   `GLIBC_TUNABLES`, `BASH_ENV`, or proxy variable reaches the child;
//! * the argv is fixed by the caller in code, never assembled from a request;
//! * stdin is either closed or a fixed byte string this crate wrote.
//!
//! This is **not** the privileged exec path. That one needs `openat2` resolution
//! from a pinned directory descriptor, an ancestor ownership walk, and
//! `execveat` on the descriptor that was validated rather than the path that was
//! checked. Do not grow this file into that one.

use std::io::Write as _;
use std::process::{Command, Stdio};

use crate::error::SysError;
use crate::exec::{CHILD_ENV, Output};

/// Runs `absolute_exe` with `args`, optionally feeding `stdin`, and captures the
/// result.
///
/// # Errors
///
/// Returns [`SysError::Read`] when the path is not absolute, and
/// [`SysError::Unsupported`] when the process cannot be started or its output
/// cannot be collected. Both are refusals: a probe that did not run answers
/// "no", never "probably yes".
pub fn run_capture(
    absolute_exe: &str,
    args: &[&str],
    stdin: Option<&[u8]>,
) -> Result<Output, SysError> {
    if !absolute_exe.starts_with('/') {
        return Err(SysError::read(
            absolute_exe,
            "a probe target must be an absolute path; PATH resolution lets the caller \
             choose the binary",
        ));
    }

    // The one place in this project permitted to construct a Command. See the
    // module documentation for the conditions this relies on.
    #[allow(clippy::disallowed_methods)]
    let mut command = Command::new(absolute_exe);
    command
        .args(args)
        .env_clear()
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in CHILD_ENV {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .map_err(|e| SysError::unsupported(format!("cannot run {absolute_exe}: {e}")))?;

    if let Some(bytes) = stdin {
        // A closed pipe means the child exited early, which the exit status
        // below reports. It is not a separate failure.
        if let Some(pipe) = child.stdin.as_mut() {
            let _ = pipe.write_all(bytes);
        }
        // Dropped so the child sees end-of-input rather than waiting for more.
        drop(child.stdin.take());
    }

    let finished = child
        .wait_with_output()
        .map_err(|e| collect_failed(absolute_exe, &e))?;

    Ok(Output {
        success: finished.status.success(),
        code: finished.status.code(),
        stdout: String::from_utf8_lossy(&finished.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&finished.stderr).into_owned(),
    })
}

/// The refusal used when a child ran but its output could not be collected.
pub(crate) fn collect_failed(absolute_exe: &str, error: &std::io::Error) -> SysError {
    SysError::unsupported(format!(
        "cannot collect output from {absolute_exe}: {error}"
    ))
}
