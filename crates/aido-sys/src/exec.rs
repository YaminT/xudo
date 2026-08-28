//! Asking an unprivileged helper a question, and believing the answer.
//!
//! The [`Runner`] trait is the seam: every decision built on a probe result is
//! testable against a fake, on a platform that has no `doas` to ask. The real
//! process plumbing lives in [`host`], which is the only file in the workspace
//! excluded from coverage, because its failure paths need the kernel to fail a
//! `fork`.

pub mod host;

use crate::error::SysError;

pub use host::run_capture;

/// The environment a probe child receives. Nothing else.
///
/// Rebuilt from scratch rather than filtered. `aido` is not setuid, so `ld.so`
/// does not scrub `LD_*` on its behalf — that is this crate's problem, and an
/// allowlist is the only way to be sure of what is absent.
pub(crate) const CHILD_ENV: [(&str, &str); 3] = [
    ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
    // C locale so a version banner or a parser error is not translated out from
    // under the string matching that reads it.
    ("LC_ALL", "C"),
    ("LANG", "C"),
];

/// What a probe child did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    /// Whether it exited zero.
    pub success: bool,
    /// Its exit code, when it exited normally rather than on a signal.
    pub code: Option<i32>,
    /// Standard output, lossily decoded — this is text for matching, never a
    /// path or an argv.
    pub stdout: String,
    /// Standard error, same.
    pub stderr: String,
}

/// Something that can run a probe.
///
/// A trait so the *decisions* built on probe results — which directive text to
/// send, how to read a refusal — are testable on a platform that has no `doas`
/// to ask. Without it, half of `probe.rs` would be coverable only on Linux, and
/// a branch that can only be exercised on one platform is a branch that gets
/// exercised on one platform.
pub trait Runner {
    /// Runs `absolute_exe` with `args`, optionally feeding `stdin`.
    ///
    /// # Errors
    ///
    /// Whatever prevented the process from running or being collected.
    fn run(
        &self,
        absolute_exe: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<Output, SysError>;
}

/// Runs probes as real child processes.
#[derive(Clone, Copy, Debug)]
pub struct HostRunner;

impl Runner for HostRunner {
    fn run(
        &self,
        absolute_exe: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<Output, SysError> {
        run_capture(absolute_exe, args, stdin)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    /// `/bin/echo` and `/bin/cat` exist on macOS and every Linux this targets.
    const ECHO: &str = "/bin/echo";
    const CAT: &str = "/bin/cat";

    #[test]
    fn a_relative_path_is_refused_rather_than_resolved_through_path() {
        // The whole reason the ban exists: PATH resolution lets the caller pick
        // the binary.
        for relative in ["echo", "./echo", "../bin/echo", ""] {
            let err = run_capture(relative, &[], None).unwrap_err();
            assert!(
                err.to_string().contains("absolute path"),
                "{relative:?} was accepted: {err}"
            );
        }
    }

    #[test]
    fn a_successful_probe_reports_its_output_and_status() {
        let out = run_capture(ECHO, &["hello"], None).unwrap();
        assert!(out.success);
        assert_eq!(out.code, Some(0));
        assert_eq!(out.stdout.trim(), "hello");
        assert!(out.stderr.is_empty());
        assert!(format!("{out:?}").contains("hello"));
    }

    #[test]
    fn stdin_is_delivered_and_then_closed() {
        // `cat` returns only when it sees end-of-input, so this also proves the
        // pipe is dropped rather than left open.
        let out = run_capture(CAT, &[], Some(b"fed via stdin")).unwrap();
        assert!(out.success);
        assert_eq!(out.stdout, "fed via stdin");
    }

    #[test]
    fn a_child_with_no_stdin_sees_end_of_input_immediately() {
        let out = run_capture(CAT, &[], None).unwrap();
        assert!(out.success);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn a_failing_child_is_reported_as_a_failure_not_an_error() {
        // A non-zero exit is information, not a malfunction: it is exactly how
        // `visudo -cf` says "this directive is not honoured".
        let out = run_capture(CAT, &["/definitely/not/here"], None).unwrap();
        assert!(!out.success);
        assert_eq!(out.code, Some(1));
        assert!(!out.stderr.is_empty());
    }

    #[test]
    fn a_missing_executable_is_a_refusal() {
        let err = run_capture("/definitely/not/an/executable", &[], None).unwrap_err();
        assert!(err.to_string().contains("cannot run"), "{err}");
    }

    #[test]
    fn a_collection_failure_is_a_refusal_naming_the_executable() {
        let err =
            host::collect_failed("/usr/sbin/visudo", &std::io::Error::other("pipe went away"));
        assert!(err.to_string().contains("cannot collect output"), "{err}");
        assert!(err.to_string().contains("/usr/sbin/visudo"), "{err}");
    }

    #[test]
    fn the_child_environment_is_rebuilt_and_carries_no_injection_variables() {
        // The property that matters. `aido` is not setuid, so ld.so does not
        // scrub LD_* for it; an allowlist is the only way to be sure.
        let out = run_capture("/usr/bin/env", &[], None).unwrap();
        assert!(out.success);
        let vars: Vec<&str> = out.stdout.lines().collect();
        assert!(
            vars.iter().any(|v| v.starts_with("PATH=/usr/sbin:")),
            "{vars:?}"
        );
        assert!(vars.contains(&"LC_ALL=C"), "{vars:?}");
        for banned in [
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "GLIBC_TUNABLES",
            "BASH_ENV",
            "PYTHONSTARTUP",
            "NODE_OPTIONS",
            "http_proxy",
            "SUDO_ASKPASS",
            "HOME",
        ] {
            assert!(
                !vars.iter().any(|v| v.starts_with(&format!("{banned}="))),
                "{banned} reached the child: {vars:?}"
            );
        }
        // Exactly the three that were allowed, and nothing else.
        assert_eq!(vars.len(), CHILD_ENV.len(), "{vars:?}");
    }
}
