//! The child's environment, built here rather than inherited.
//!
//! `sudo` already resets the environment, and the gate builds it again from
//! scratch anyway. Not distrust of `sudo` — a second construction costs nothing
//! and means the guarantee does not depend on a directive in a file someone can
//! edit, on a backend that might ignore that directive (sudo-rs warns and
//! continues on directives it does not implement), or on the gate having been
//! reached through `sudo` at all. A direct invocation gets the same environment.
//!
//! # Why nothing is passed through, not even `TERM`
//!
//! Every inherited variable is an input from the caller to a program running as
//! root. `TERM` looks harmless and is not: it selects a terminfo entry, and
//! terminfo parsing has its own CVE record. The same reasoning removes `LANG`
//! (locale files select message catalogs and collation), and it is why there is
//! no allowlist-with-passthrough here at all. The environment is a **constant**.
//! A program that needs more must be given it by a rule, explicitly, where an
//! operator can read it.
//!
//! # The three entries that are hardening, not plumbing
//!
//! * `SHELL=/usr/sbin/nologin` — a program that helpfully "drops you to a
//!   shell" gets a program that refuses to be one. `systemctl`, `git`, and
//!   `less` all consult `SHELL`.
//! * `PAGER=cat` and `SYSTEMD_PAGER=cat` — `less` accepts `!cmd` and runs it.
//!   `systemctl status` pipes to a pager by default, so without this, an
//!   allowlisted status command is a root shell one keystroke away. `cat`
//!   cannot execute anything.
//! * `LESSSECURE=1` — belt for the case where something invokes `less`
//!   regardless of `PAGER`; it disables the escape.

/// The complete environment handed to a privileged child.
///
/// A constant, in a fixed order, so two invocations of the same action produce
/// byte-identical `envp`. Reproducibility here is a review property: an operator
/// comparing two audit records should not have to wonder whether a difference
/// came from the environment.
pub const CHILD_ENVIRONMENT: &[(&str, &str)] = &[
    // No `PATH` search ever happens — the gate execs a validated fd — but a
    // child that itself spawns a helper searches this, so it must not be the
    // caller's.
    ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
    ("HOME", "/root"),
    ("USER", "root"),
    ("LOGNAME", "root"),
    ("SHELL", "/usr/sbin/nologin"),
    ("PAGER", "cat"),
    ("SYSTEMD_PAGER", "cat"),
    ("LESSSECURE", "1"),
];

/// Variables that must never reach a privileged child, whatever the source.
///
/// Each one turns "run this program" into "run this program *and* code I chose":
/// the dynamic loader ones inject a library, the interpreter ones inject a
/// startup file. Listed explicitly so that the assertion in
/// [`plan_carries_no_injection_vector`] is a real check rather than a
/// restatement of how [`CHILD_ENVIRONMENT`] happens to be written today.
///
/// [`plan_carries_no_injection_vector`]: #
pub const NEVER_INHERITED: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "GCONV_PATH",
    "GIT_CONFIG_GLOBAL",
    "GIT_EXTERNAL_DIFF",
    "IFS",
    "LOCPATH",
    "NODE_OPTIONS",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYOPT",
];

/// The environment as `KEY=VALUE` strings, ready for `execveat`.
pub fn child_environment() -> Vec<String> {
    CHILD_ENVIRONMENT
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

/// Whether `name` is a variable that must never be inherited.
///
/// Prefix-matches the dynamic loader's whole namespace rather than listing its
/// members: `LD_PRELOAD` and `LD_AUDIT` are the famous two, `LD_LIBRARY_PATH`
/// and `LD_DYNAMIC_WEAK` are the ones people forget, and glibc keeps adding
/// more. A prefix rule stays correct as that list grows.
pub fn is_forbidden(name: &str) -> bool {
    name.starts_with("LD_") || NEVER_INHERITED.contains(&name)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    #[test]
    fn plan_carries_no_injection_vector() {
        for (key, _) in CHILD_ENVIRONMENT {
            assert!(!is_forbidden(key), "{key} is in the plan and forbidden");
        }
    }

    #[test]
    fn the_loader_namespace_is_refused_by_prefix_not_by_enumeration() {
        // The point of the prefix rule: a variable glibc adds next year is
        // already refused.
        for name in [
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_LIBRARY_PATH",
            "LD_NOT_YET_INVENTED",
        ] {
            assert!(is_forbidden(name), "{name}");
        }
        assert!(!is_forbidden("LDFLAGS"));
        assert!(!is_forbidden("PATH"));
    }

    #[test]
    fn interpreter_startup_hooks_are_refused() {
        for name in [
            "BASH_ENV",
            "PYTHONSTARTUP",
            "NODE_OPTIONS",
            "PERL5OPT",
            "IFS",
        ] {
            assert!(is_forbidden(name), "{name}");
        }
    }

    #[test]
    fn a_shell_spawned_from_the_environment_is_not_a_shell() {
        let plan = child_environment();
        assert!(
            plan.contains(&"SHELL=/usr/sbin/nologin".to_owned()),
            "{plan:?}"
        );
    }

    #[test]
    fn no_pager_can_escape_to_a_command() {
        // GTFOBins' `less` entry is `!/bin/sh`, reached through any allowlisted
        // command that pages its output. `cat` has no escape, and LESSSECURE
        // closes the case where less runs anyway.
        let plan = child_environment();
        for expected in ["PAGER=cat", "SYSTEMD_PAGER=cat", "LESSSECURE=1"] {
            assert!(
                plan.contains(&expected.to_owned()),
                "{expected} missing from {plan:?}"
            );
        }
    }

    #[test]
    fn nothing_is_passed_through_so_the_plan_is_the_same_every_time() {
        assert_eq!(child_environment(), child_environment());
        assert_eq!(child_environment().len(), CHILD_ENVIRONMENT.len());
    }

    #[test]
    fn every_entry_is_a_key_equals_value_pair_with_no_empty_key() {
        for entry in child_environment() {
            let (key, _) = entry.split_once('=').expect("rendered as KEY=VALUE");
            assert!(!key.is_empty(), "{entry}");
            assert!(!key.contains(' '), "{entry}");
        }
    }
}
