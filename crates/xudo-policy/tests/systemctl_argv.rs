//! Option values must not hide a `systemctl` verb.
//!
//! systemctl parses options with getopt. Many options take the next argument
//! as their value, so the first token that does not start with `-` is not the
//! verb. This file is the matrix. It stays out of the library tests because
//! each `evaluate_deny_list` is most of a second under miri.

#![allow(clippy::unwrap_used, clippy::panic)]

use xudo_policy::{Argv, CapabilityClass, evaluate_deny_list};

/// Options that take a separate value. The stock Debian and Ubuntu images do
/// not ship `systemctl`, so this is the conservative getopt set: the review's
/// list, and the other options whose value is the next argument.
const OPTIONS_WITH_VALUES: &[&str] = &[
    "-p",
    "-t",
    "-s",
    "-H",
    "-M",
    "-n",
    "-o",
    "--property",
    "--type",
    "--signal",
    "--host",
    "--machine",
    "--lines",
    "--output",
    "--message",
    "--when",
    "--job-mode",
    "--root",
    "--kill-whom",
    "--kill-who",
    "--reboot-argument",
    "--boot-loader-menu",
    "--boot-loader-entry",
    "--check-inhibitors",
    "--what",
    "--state",
    "--timestamp",
    "--preset-mode",
    "--image",
    "--image-policy",
];

const POWER_SUBCOMMANDS: &[&str] = &[
    "poweroff",
    "reboot",
    "halt",
    "kexec",
    "suspend",
    "hibernate",
    "hybrid-sleep",
    "suspend-then-hibernate",
    "soft-reboot",
    "sleep",
    "rescue",
    "emergency",
    "default",
    "exit",
    "isolate",
];

const ACTING_VERBS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "try-restart",
    "reload",
    "reload-or-restart",
    "try-reload-or-restart",
    "kill",
    "clean",
    "freeze",
    "thaw",
    "condrestart",
    "force-reload",
    "reload-or-try-restart",
    "condreload",
    "condstop",
];

fn classes(args: &[&str]) -> Vec<CapabilityClass> {
    evaluate_deny_list(b"/usr/bin/systemctl", &Argv::new(args.to_vec()))
        .into_iter()
        .map(|finding| finding.class)
        .collect()
}

#[test]
fn an_option_value_cannot_hide_a_power_or_acting_verb() {
    for option in OPTIONS_WITH_VALUES {
        for verb in POWER_SUBCOMMANDS {
            let argv = [*option, "x", *verb];
            assert!(
                classes(&argv).contains(&CapabilityClass::PowerState),
                "{argv:?}"
            );
        }
        for verb in ACTING_VERBS {
            let argv = [*option, "status", *verb, "debug-shell.service"];
            assert!(
                classes(&argv).contains(&CapabilityClass::SpawnsShell),
                "{argv:?}"
            );
            let socket = [*option, "status", *verb, "xudod.socket"];
            assert!(
                classes(&socket).contains(&CapabilityClass::SelfModification),
                "{socket:?}"
            );
        }
    }
}

#[test]
fn the_review_argvs_are_denied_and_plain_status_is_not() {
    for argv in [
        &["-p", "x", "poweroff"][..],
        &["-M", ".host", "poweroff"],
        &["--message", "x", "reboot"],
        &["--when", "now", "poweroff"],
        &["-p", "x", "isolate", "multi-user.target"],
        &["-p", "status", "stop", "debug-shell.service"],
        &["-p", "status", "stop", "xudod.socket"],
        &["start", "--job-mode=isolate", "multi-user.target"],
        &["start", "--job-mode=isolate", "nginx.service"],
        &["start", "--job-mode", "isolate", "nginx.service"],
        &["start", "--j=isolate", "example.service"],
        &["status", "rescue"],
    ] {
        assert!(!classes(argv).is_empty(), "{argv:?}");
    }
    for prefix in [
        "--j",
        "--jo",
        "--job",
        "--job-",
        "--job-m",
        "--job-mo",
        "--job-mod",
        "--job-mode",
    ] {
        let joined = format!("{prefix}=isolate");
        let argv = ["start", joined.as_str(), "multi-user.target"];
        assert!(
            classes(&argv).contains(&CapabilityClass::PowerState),
            "{argv:?}"
        );
    }
    assert!(classes(&["status", "xudod.socket"]).is_empty());
    assert!(classes(&["--no-pager", "--full", "status", "journald"]).is_empty());
    assert!(classes(&["-p", "ActiveState", "status", "xudod.socket"]).is_empty());
    assert!(classes(&["start", "--job-mode=replace", "nginx.service"]).is_empty());
    assert!(classes(&["start", "--json=isolate", "nginx.service"]).is_empty());
}
