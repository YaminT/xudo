//! Option values must not hide a `systemctl` verb.
//!
//! systemctl parses options with getopt. Many options take the next argument
//! as their value, so the first token that does not start with `-` is not the
//! verb. This file is the matrix. It stays out of the library tests because
//! each `evaluate_deny_list` is most of a second under miri.

#![allow(clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
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
    // A separate option value is not the plain shape any more.
    assert!(!classes(&["-p", "ActiveState", "status", "xudod.socket"]).is_empty());
    assert!(classes(&["start", "--job-mode=replace", "nginx.service"]).is_empty());
    assert!(classes(&["start", "--json=isolate", "nginx.service"]).is_empty());
}

/// Every verb of systemctl that is not read-only (systemd 257 verb table, not
/// verified against a binary). A copy of the library set on purpose: a verb
/// added there without a finding here fails this file.
const NON_READ_ONLY_VERBS: &[&str] = &[
    "start",
    "stop",
    "restart",
    "try-restart",
    "reload",
    "reload-or-restart",
    "try-reload-or-restart",
    "reload-or-try-restart",
    "condrestart",
    "condreload",
    "condstop",
    "force-reload",
    "kill",
    "clean",
    "freeze",
    "thaw",
    "isolate",
    "set-property",
    "bind",
    "mount-image",
    "service-log-level",
    "service-log-target",
    "reset-failed",
    "whoami",
    "help",
    "enable",
    "disable",
    "reenable",
    "preset",
    "preset-all",
    "mask",
    "unmask",
    "link",
    "revert",
    "add-wants",
    "add-requires",
    "edit",
    "set-default",
    "cancel",
    "set-environment",
    "unset-environment",
    "import-environment",
    "daemon-reload",
    "daemon-reexec",
    "log-level",
    "log-target",
    "service-watchdogs",
    "switch-root",
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
];

const READ_ONLY_VERBS: &[&str] = &[
    "status",
    "show",
    "is-active",
    "is-failed",
    "is-enabled",
    "cat",
    "list-units",
    "list-unit-files",
    "list-dependencies",
    "list-sockets",
    "list-timers",
    "list-jobs",
];

const NO_VALUE_FLAGS: &[&str] = &[
    "--no-pager",
    "--full",
    "--no-ask-password",
    "-l",
    "--no-legend",
    "--plain",
    "--value",
    "--all",
];

#[test]
fn non_read_only_verbs_never_overlap_the_read_only_set() {
    for verb in NON_READ_ONLY_VERBS {
        assert!(!READ_ONLY_VERBS.contains(verb), "{verb}");
    }
}

#[test]
fn a_reenable_cannot_hide_behind_a_read_only_looking_option() {
    for verb in NON_READ_ONLY_VERBS {
        // The review's shape, for every verb that is not read-only: the
        // value of `-p` takes the place of the verb, and the real verb and
        // a tripwire unit follow.
        let argv = ["-p", "status", *verb, "xudod.socket"];
        assert!(!classes(&argv).is_empty(), "{argv:?}");
        let shell = ["-p", "status", *verb, "debug-shell.service"];
        assert!(!classes(&shell).is_empty(), "{shell:?}");
    }
    assert!(
        classes(&["reenable", "ssh.service"]).contains(&CapabilityClass::UnitDefinitionMutation)
    );
    assert!(
        classes(&["-p", "status", "reenable", "ssh.service"])
            .contains(&CapabilityClass::UnitDefinitionMutation)
    );
    assert!(
        classes(&[
            "-p",
            "status",
            "service-log-target",
            "systemd-journald.service",
            "null"
        ])
        .contains(&CapabilityClass::SelfModification)
    );
}

#[test]
fn p_status_reenable_debug_shell_is_denied() {
    let found = classes(&["-p", "status", "reenable", "debug-shell.service"]);
    assert!(found.contains(&CapabilityClass::SpawnsShell), "{found:?}");
    assert!(
        found.contains(&CapabilityClass::UnitDefinitionMutation),
        "{found:?}"
    );
}

#[test]
fn p_status_reset_failed_broker_socket_is_denied() {
    let found = classes(&["-p", "status", "reset-failed", "xudod.socket"]);
    assert!(
        found.contains(&CapabilityClass::SelfModification),
        "{found:?}"
    );
}

#[test]
fn plain_status_of_a_tripwire_unit_stays_allowed() {
    assert!(classes(&["--no-pager", "--full", "status", "xudod.socket"]).is_empty());
    assert!(classes(&["show", "systemd-journald.service"]).is_empty());
    assert!(
        classes(&[
            "--no-pager",
            "show",
            "debug-shell.service",
            "--property=ActiveState"
        ])
        .is_empty()
    );
    for flag in NO_VALUE_FLAGS {
        for verb in READ_ONLY_VERBS {
            let argv = [*flag, *verb, "xudod.socket"];
            assert!(classes(&argv).is_empty(), "{argv:?}");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Any option outside the fixed no-value set, in front of an otherwise
    /// plain read-only command, takes it out of the exemption.
    #[test]
    fn the_exemption_applies_only_to_the_plain_shape(
        option in "-(-[a-z][a-z-]{0,12}(=[a-zA-Z]{0,6})?|[a-zA-Z]{1,3})",
        later in any::<bool>(),
    ) {
        prop_assume!(!NO_VALUE_FLAGS.contains(&option.as_str()));
        let argv: Vec<&str> = if later {
            vec!["status", "xudod.socket", option.as_str()]
        } else {
            vec![option.as_str(), "status", "xudod.socket"]
        };
        // A later `--property=` is the one joined flag the shape allows.
        prop_assume!(!(later && option.starts_with("--property=")));
        prop_assert!(!classes(&argv).is_empty(), "{argv:?}");
    }
}

#[test]
fn a_glob_in_a_unit_position_is_refused() {
    for argv in [
        &["stop", "*"][..],
        &["stop", "xudo[d].socket"],
        &["kill", "xud?d.socket"],
        &["start", "shutdow?.target"],
        &["stop", "apparmo*.service"],
        &["status", "*"],
        &["--no-pager", "status", "xud?d.socket"],
    ] {
        assert!(!classes(argv).is_empty(), "{argv:?}");
    }
}

#[test]
fn denies_systemctl_host_and_machine_options() {
    for option in [
        "-H",
        "-Hroot@host",
        "--host",
        "--host=root@host",
        "--h",
        "--ho",
        "--hos",
        "-M",
        "-Mroot@",
        "--machine",
        "--machine=root@",
        "--m",
        "--ma",
        "--machin",
        "-lH",
    ] {
        for rest in [
            &["status", "nginx.service"][..],
            &["--no-pager", "show", "nginx.service"],
            &["daemon-reload"],
        ] {
            let mut argv = vec![option];
            argv.extend_from_slice(rest);
            assert!(!classes(&argv).is_empty(), "{argv:?}");
        }
    }
    assert!(classes(&["-H", "h", "status", "x"]).contains(&CapabilityClass::ExecProxy));
    assert!(classes(&["-M", "m", "status", "x"]).contains(&CapabilityClass::PrivilegeTool));
}

#[test]
fn the_nit_units_are_refused() {
    for unit in [
        "init.scope",
        "-.slice",
        "-.mount",
        "xudo.slice",
        "ntpd.service",
        "ntpsec.service",
        "agent-1.scope",
        "watch-2.scope",
    ] {
        assert!(!classes(&["stop", unit]).is_empty(), "{unit}");
    }
    assert!(!evaluate_deny_list(b"/usr/sbin/rtcwake", &Argv::default()).is_empty());
}
