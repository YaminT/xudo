//! The unit files and the tmpfiles line that ship with the broker, tested as
//! code.
//!
//! Each file is compiled in with `include_str!`, so the files asserted here are
//! the files in the repository, byte for byte. systemd is forgiving in exactly
//! the way a privilege broker cannot afford: a misspelled directive is a
//! warning in the journal and the unit runs without it. So every key in every
//! file must be one this test knows, and every security-relevant line is
//! asserted by value, against the constants the code itself uses.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::time::Duration;

const SOCKET: &str = include_str!("../../../packaging/systemd/aidod.socket");
const SERVICE: &str = include_str!("../../../packaging/systemd/aidod@.service");
const TMPFILES: &str = include_str!("../../../packaging/tmpfiles.d/aido.conf");

/// One `Key=Value` line, with the section it is in.
#[derive(Debug)]
struct Line {
    section: String,
    key: String,
    value: String,
}

/// Parses a unit file the way systemd reads one: sections, `Key=Value`
/// lines, `#` and `;` comments. A line that is none of those fails the test.
fn parse(unit: &str) -> Vec<Line> {
    let mut section = String::new();
    let mut lines = Vec::new();
    for raw in unit.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            name.clone_into(&mut section);
            continue;
        }
        let (key, value) = line.split_once('=').unwrap();
        assert!(!section.is_empty(), "{line:?} is outside any section");
        lines.push(Line {
            section: section.clone(),
            key: key.trim().to_owned(),
            value: value.trim().to_owned(),
        });
    }
    lines
}

/// Every value `key` has in `section`, in order.
fn values<'a>(lines: &'a [Line], section: &str, key: &str) -> Vec<&'a str> {
    lines
        .iter()
        .filter(|line| line.section == section && line.key == key)
        .map(|line| line.value.as_str())
        .collect()
}

/// The one value `key` has in `section`; set twice or not at all fails.
fn value<'a>(lines: &'a [Line], section: &str, key: &str) -> &'a str {
    let found = values(lines, section, key);
    assert_eq!(
        found.len(),
        1,
        "[{section}] {key}= is set {} times",
        found.len()
    );
    found[0]
}

/// Fails on any key not listed for its section.
fn only_known_keys(lines: &[Line], known: &[(&str, &[&str])]) {
    for line in lines {
        let allowed = known
            .iter()
            .find(|(section, _)| *section == line.section)
            .map_or(&[][..], |(_, keys)| *keys);
        assert!(
            allowed.contains(&line.key.as_str()),
            "[{}] {}= is not a key this test knows; a misspelled directive is one systemd \
             ignores",
            line.section,
            line.key
        );
    }
}

#[test]
fn the_socket_is_the_one_the_front_end_dials_and_only_the_aido_group_can_reach() {
    let socket = parse(SOCKET);
    only_known_keys(
        &socket,
        &[
            ("Unit", &["Description", "Documentation"]),
            (
                "Socket",
                &[
                    "ListenStream",
                    "Accept",
                    "SocketUser",
                    "SocketGroup",
                    "SocketMode",
                    "DirectoryMode",
                    "MaxConnections",
                    "MaxConnectionsPerSource",
                    "TriggerLimitIntervalSec",
                ],
            ),
            ("Install", &["WantedBy"]),
        ],
    );
    assert_eq!(
        value(&socket, "Socket", "ListenStream"),
        aido_wire::BROKER_SOCKET
    );
    // One process per connection, with the connection as its stdin.
    assert_eq!(value(&socket, "Socket", "Accept"), "yes");
    assert_eq!(value(&socket, "Socket", "SocketUser"), "root");
    assert_eq!(value(&socket, "Socket", "SocketGroup"), "aido");
    assert_eq!(value(&socket, "Socket", "SocketMode"), "0660");
    assert_eq!(value(&socket, "Socket", "DirectoryMode"), "0755");
    assert_eq!(value(&socket, "Install", "WantedBy"), "sockets.target");
}

#[test]
fn the_number_of_root_processes_a_caller_can_hold_open_is_bounded() {
    let socket = parse(SOCKET);
    let total: u32 = value(&socket, "Socket", "MaxConnections").parse().unwrap();
    let per_uid: u32 = value(&socket, "Socket", "MaxConnectionsPerSource")
        .parse()
        .unwrap();
    assert!((1..=64).contains(&total), "{total}");
    // Zero would mean unlimited, and one uid must not be able to take them all.
    assert!(per_uid >= 1 && per_uid < total, "{per_uid} of {total}");
}

/// What the note above the connection limits must say, in the unit's own
/// words: the measured cost, and then the rule that cost makes for an
/// operator. Both are one sentence each, so that neither can be dropped while
/// the other keeps the check green.
const NOTE_SAYS: [&str; 2] = [
    "fail this whole socket",
    "/run/aido must never be reachable from a pid namespace",
];

/// Whether the `#` comment directly above the `MaxConnections=` and
/// `MaxConnectionsPerSource=` pair says everything in [`NOTE_SAYS`], or why not.
///
/// Only that one block counts: the lines of `#` comment that touch the pair,
/// with no blank line or directive between, read as one text with every wrapped
/// sentence joined. The words of the note also appear elsewhere in the unit
/// (the socket's own path is under `/run/aido`, and another comment mentions
/// the pid namespace), so searching the whole file above the limit would stay
/// green after the rule itself was deleted, or moved to somewhere nobody reads
/// it beside the setting. The two limits must be adjacent lines, in either
/// order, because a note above one says nothing about a second that something
/// else separates from it.
fn the_note_beside_the_limits(unit: &str) -> Result<(), String> {
    let lines: Vec<&str> = unit.lines().map(str::trim).collect();
    let at = |key: &str| lines.iter().position(|line| line.starts_with(key));
    let (Some(total), Some(per_source)) = (at("MaxConnections="), at("MaxConnectionsPerSource="))
    else {
        return Err("the unit does not set both connection limits".to_owned());
    };
    if total.abs_diff(per_source) != 1 {
        return Err(
            "MaxConnections= and MaxConnectionsPerSource= are not adjacent lines, so a note \
             above the first does not state the cost of the second"
                .to_owned(),
        );
    }
    let mut above: Vec<&str> = lines[..total.min(per_source)]
        .iter()
        .rev()
        .take_while(|line| line.starts_with('#'))
        .map(|line| line.trim_start_matches('#'))
        .collect();
    above.reverse();
    let note = above
        .iter()
        .flat_map(|line| line.split_whitespace())
        .collect::<Vec<_>>()
        .join(" ");
    for phrase in NOTE_SAYS {
        if !note.contains(phrase) {
            return Err(format!(
                "{phrase:?} is not in the comment directly above the limits, which reads: {note:?}"
            ));
        }
    }
    Ok(())
}

#[test]
fn the_per_source_limit_states_what_it_costs_beside_the_limit() {
    // Measured on systemd 257.13: with MaxConnectionsPerSource= set, one
    // connection from a peer outside systemd's pid namespace (SO_PEERCRED
    // pid 0) fails the whole socket ("Failed to get peer credentials of
    // socket: No data available", Result: resources), and the broker never
    // starts. The limit stays, because one uid must not hold every slot, and
    // the rule an operator must keep (/run/aido is never shared with a pid
    // namespace systemd cannot see into) is written directly above it, so that
    // neither is changed without the other (docs/CONCERNS.md, the broker
    // entry, open item 8).
    if let Err(why) = the_note_beside_the_limits(SOCKET) {
        panic!("{why}");
    }
}

#[test]
fn a_note_that_was_deleted_moved_or_cut_off_from_the_limits_fails_the_check() {
    // The ways the sentence the test above protects can be lost, each a change
    // that leaves the words the first version of that test looked for
    // somewhere in the file: the socket's own path is under /run/aido, and the
    // cost sentence mentions the pid namespace.
    let cost =
        "# A peer outside systemd's pid namespace makes systemd\n# fail this whole socket.\n";
    let rule = "# So /run/aido must never be reachable from a pid\n# namespace that systemd cannot see into.\n";
    let limits = "MaxConnections=32\nMaxConnectionsPerSource=8\n";
    let socket = |above: &str, between: &str| {
        format!("[Socket]\nListenStream=/run/aido/broker.sock\n{above}{between}{limits}")
    };
    let both = format!("{cost}{rule}");

    assert_eq!(the_note_beside_the_limits(&socket(&both, "")), Ok(()));
    // The wrapped sentence is read whole, and the limits in the other order
    // are still one pair.
    assert_eq!(
        the_note_beside_the_limits(&format!(
            "{both}MaxConnectionsPerSource=8\nMaxConnections=32\n"
        )),
        Ok(())
    );

    // The rule deleted, the measurement left.
    assert!(the_note_beside_the_limits(&socket(cost, "")).is_err());
    // The measurement deleted, the rule left.
    assert!(the_note_beside_the_limits(&socket(rule, "")).is_err());
    // No note at all.
    assert!(the_note_beside_the_limits(&socket("", "")).is_err());
    // The note moved to the top of the section, away from the limits.
    assert!(
        the_note_beside_the_limits(&format!(
            "[Socket]\n{both}ListenStream=/run/aido/broker.sock\n{limits}"
        ))
        .is_err()
    );
    // A blank line, or a directive, between the note and the limits.
    assert!(the_note_beside_the_limits(&socket(&both, "\n")).is_err());
    assert!(the_note_beside_the_limits(&socket(&both, "Accept=yes\n")).is_err());
    // The note below the limits instead of above them.
    assert!(the_note_beside_the_limits(&format!("[Socket]\n{limits}{both}Accept=yes\n")).is_err());
    // The two limits parted by another directive, or one of them gone.
    assert!(
        the_note_beside_the_limits(&format!(
            "{both}MaxConnections=32\nAccept=yes\nMaxConnectionsPerSource=8\n"
        ))
        .is_err()
    );
    assert!(the_note_beside_the_limits(&format!("{both}MaxConnections=32\n")).is_err());
    assert!(the_note_beside_the_limits(&format!("{both}MaxConnectionsPerSource=8\n")).is_err());
}

#[test]
fn a_group_member_cannot_fail_the_socket_for_everyone_with_a_burst_of_connections() {
    // systemd's default trigger limit for an Accept=yes socket is 200
    // activations in 2 seconds. Before systemd 255, hitting it puts the socket
    // into a failed state until an administrator restarts it: a review on
    // systemd 252 opened 600 connections as one group member, the journal
    // said "Trigger limit hit, refusing further activation", and the next
    // client got "Connection refused". Zero turns the limit off; concurrency
    // stays bounded by MaxConnections and MaxConnectionsPerSource.
    let socket = parse(SOCKET);
    assert_eq!(value(&socket, "Socket", "TriggerLimitIntervalSec"), "0");
    let total: u32 = value(&socket, "Socket", "MaxConnections").parse().unwrap();
    assert!(total > 0, "zero would leave concurrency unbounded");
}

const SERVICE_KEYS: &[(&str, &[&str])] = &[
    ("Unit", &["Description", "Documentation", "CollectMode"]),
    (
        "Service",
        &[
            "ExecStart",
            "StandardInput",
            "StandardOutput",
            "StandardError",
            "RuntimeMaxSec",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "NoNewPrivileges",
            "UMask",
            "ProtectSystem",
            "ReadWritePaths",
            "ProtectHome",
            "PrivateTmp",
            "PrivateDevices",
            "ProcSubset",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectControlGroups",
            "ProtectClock",
            "ProtectHostname",
            "PrivateNetwork",
            "RestrictAddressFamilies",
            "RestrictNamespaces",
            "RestrictRealtime",
            "RestrictSUIDSGID",
            "LockPersonality",
            "MemoryDenyWriteExecute",
            "SystemCallArchitectures",
            "SystemCallFilter",
            "SystemCallErrorNumber",
            "TasksMax",
            "LimitNOFILE",
        ],
    ),
];

#[test]
fn the_service_runs_the_installed_broker_with_the_connection_on_descriptor_zero() {
    let service = parse(SERVICE);
    only_known_keys(&service, SERVICE_KEYS);
    // The installed path, with no arguments: nothing on a command line for
    // the broker to parse.
    assert_eq!(
        value(&service, "Service", "ExecStart"),
        aidod::INSTALLED_PATH
    );
    assert_eq!(value(&service, "Service", "StandardInput"), "socket");
    // Left unset, standard output would be the socket too.
    assert_eq!(value(&service, "Service", "StandardOutput"), "journal");
    assert_eq!(value(&service, "Service", "StandardError"), "journal");
    assert_eq!(value(&service, "Unit", "CollectMode"), "inactive-or-failed");
}

#[test]
fn the_broker_is_root_without_a_single_capability() {
    let service = parse(SERVICE);
    // No User=: root, so the files it trusts are files it owns. Never a user
    // namespace, where "root-owned" stops meaning root.
    assert!(values(&service, "Service", "User").is_empty());
    assert!(values(&service, "Service", "PrivateUsers").is_empty());
    assert_eq!(value(&service, "Service", "CapabilityBoundingSet"), "");
    assert_eq!(value(&service, "Service", "AmbientCapabilities"), "");
    assert_eq!(value(&service, "Service", "NoNewPrivileges"), "yes");
    assert_eq!(value(&service, "Service", "UMask"), "0077");
}

#[test]
fn the_only_writable_path_is_the_spool() {
    let service = parse(SERVICE);
    assert_eq!(value(&service, "Service", "ProtectSystem"), "strict");
    // "-" lets the broker start, and refuse with a reason, when the spool
    // is missing; it widens nothing.
    assert_eq!(
        value(&service, "Service", "ReadWritePaths"),
        format!("-{}", aido_gate::SPOOL_DIR)
    );
    for key in [
        "ProtectHome",
        "PrivateTmp",
        "PrivateDevices",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "ProtectClock",
        "ProtectHostname",
    ] {
        assert_eq!(value(&service, "Service", key), "yes", "{key}");
    }
    assert_eq!(value(&service, "Service", "ProcSubset"), "pid");
}

#[test]
fn the_broker_has_no_network_and_no_socket_but_a_unix_one() {
    let service = parse(SERVICE);
    assert_eq!(value(&service, "Service", "PrivateNetwork"), "yes");
    assert_eq!(
        value(&service, "Service", "RestrictAddressFamilies"),
        "AF_UNIX"
    );
}

#[test]
fn the_unit_never_puts_the_broker_in_a_pid_namespace_of_its_own() {
    // SO_PEERCRED reports pid 0 for a peer outside the receiver's pid
    // namespace. That is a clean refusal now (the safe decode, no undefined
    // behaviour), but a private pid namespace would make every caller such a
    // peer and every request a refusal, and the broker reads callers' /proc
    // entries by number, which it can do only from a namespace its callers
    // are visible in. This holds the unit, not the host: a peer the broker
    // cannot see is refused as PeerNotVisible, and whether systemd lets it
    // that far is a matter of where /run/aido is shared, which no unit can
    // say (the socket unit's comment above MaxConnectionsPerSource=).
    let service = parse(SERVICE);
    assert!(values(&service, "Service", "PrivatePIDs").is_empty());
    // Nor may it hide other users' processes: the broker reads their /proc
    // entries by number.
    assert!(values(&service, "Service", "ProtectProc").is_empty());
}

#[test]
fn the_system_calls_are_filtered_and_a_filtered_call_fails_closed() {
    let service = parse(SERVICE);
    assert_eq!(
        values(&service, "Service", "SystemCallFilter"),
        ["@system-service", "~@privileged @resources"]
    );
    assert_eq!(value(&service, "Service", "SystemCallErrorNumber"), "EPERM");
    assert_eq!(
        value(&service, "Service", "SystemCallArchitectures"),
        "native"
    );
    for key in [
        "RestrictNamespaces",
        "RestrictRealtime",
        "RestrictSUIDSGID",
        "LockPersonality",
        "MemoryDenyWriteExecute",
    ] {
        assert_eq!(value(&service, "Service", key), "yes", "{key}");
    }
}

#[test]
fn a_connection_ends_on_its_own_timeouts_before_the_unit_kills_it() {
    let service = parse(SERVICE);
    let runtime: u64 = value(&service, "Service", "RuntimeMaxSec").parse().unwrap();
    // One read and one write, each bounded by the socket timeout, fit with
    // room to spare, so a slow client is refused rather than killed.
    let io = aidod::IO_TIMEOUT.saturating_mul(2);
    assert!(Duration::from_secs(runtime) > io, "{runtime}s");
    assert!(runtime <= 60, "{runtime}s");
    let tasks: u32 = value(&service, "Service", "TasksMax").parse().unwrap();
    assert!((1..=8).contains(&tasks), "{tasks}");
}

#[test]
fn the_service_takes_nothing_from_an_environment() {
    // The broker reads no environment; a unit that set one would be
    // configuration nobody reviews.
    let service = parse(SERVICE);
    for key in ["Environment", "EnvironmentFile", "PassEnvironment"] {
        assert!(values(&service, "Service", key).is_empty(), "{key}");
    }
}

#[test]
fn tmpfiles_creates_a_reachable_run_dir_and_a_private_spool() {
    let lines: Vec<Vec<&str>> = TMPFILES
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(
        lines,
        [
            ["d", "/run/aido", "0755", "root", "root", "-", "-"],
            ["d", aido_gate::SPOOL_DIR, "0700", "root", "root", "-", "-"],
        ]
    );
    assert_eq!(
        std::path::Path::new(aido_wire::BROKER_SOCKET).parent(),
        Some(std::path::Path::new("/run/aido"))
    );
}

#[test]
fn the_parser_this_test_relies_on_refuses_what_it_cannot_read() {
    // A test that parsed nothing would pass everything.
    assert!(parse(SOCKET).len() > 8);
    assert!(parse(SERVICE).len() > 30);
    let parsed = parse("# comment\n; also\n[A]\nKey = value\n");
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        (
            parsed[0].section.as_str(),
            parsed[0].key.as_str(),
            parsed[0].value.as_str()
        ),
        ("A", "Key", "value")
    );
    let outside = std::panic::catch_unwind(|| parse("Key=value\n"));
    assert!(outside.is_err());
    let garbage = std::panic::catch_unwind(|| parse("[A]\nnot a directive\n"));
    assert!(garbage.is_err());
    let unknown = std::panic::catch_unwind(|| {
        only_known_keys(&parse("[Service]\nNoNewPrivilege=yes\n"), SERVICE_KEYS);
    });
    assert!(
        unknown.is_err(),
        "a misspelled directive must fail the test"
    );
}
