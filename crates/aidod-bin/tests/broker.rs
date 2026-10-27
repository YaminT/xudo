//! The broker binary, run as a process, the way systemd runs it: one accepted
//! connection on standard input and an exit status systemd reads.
//!
//! The binary writes its audit record to the system trail
//! (`/var/lib/aido/audit.jsonl`, copied to journald) and to nothing else, and
//! offers no way to point it elsewhere: no argument, no feature, no
//! environment variable. So these tests, which run as an ordinary user, can see
//! what an unprivileged run does — every refusal is still answered, the exit
//! status is still the right one, and standard error carries no record. That
//! the trail is written, chained, and required is proven by
//! `tests/root_trail.rs`, which runs this same binary as uid 0.
//!
//! Everything the broker decides is tested in the `aidod` library. These tests
//! exist for what only a real process has: descriptor 0 as the connection, an
//! environment it must ignore, and the status a service manager receives. They
//! run as whoever runs the suite — never root — so on every host the spool is
//! not root's and the broker refuses; what differs by platform is only how far
//! it gets before refusing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use aido_wire::{Answer, BrokerRequest, BrokerResponse, RefusalCode};

/// The binary under test, by the absolute path Cargo built it at.
const AIDOD: &str = env!("CARGO_BIN_EXE_aidod");

/// `aido`'s "unusable": the broker or its host is broken.
const UNUSABLE: i32 = 19;

/// How a well-formed request is refused here. On Linux the kernel names the
/// peer — the test process, which created the socket pair — and the broker
/// then finds no root-owned spool. Anywhere else no peer can be named at all.
#[cfg(target_os = "linux")]
const REFUSED_WITH: RefusalCode = RefusalCode::SpoolUnusable;
#[cfg(not(target_os = "linux"))]
const REFUSED_WITH: RefusalCode = RefusalCode::PeerUnidentified;

/// How a malformed request is refused here: on Linux it is read, and refused
/// as the client's fault; anywhere else the peer is refused before it is read.
#[cfg(target_os = "linux")]
const MALFORMED_REFUSED_WITH: (RefusalCode, i32) = (RefusalCode::RequestMalformed, 0);
#[cfg(not(target_os = "linux"))]
const MALFORMED_REFUSED_WITH: (RefusalCode, i32) = (RefusalCode::PeerUnidentified, UNUSABLE);

fn refusal_of(answer: &Answer) -> Option<RefusalCode> {
    match answer {
        Answer::Refused { code, .. } => Some(*code),
        Answer::Decided { .. } => None,
    }
}

/// Runs the broker with `stdin` as descriptor 0 and `env` as its whole
/// environment.
fn broker(stdin: Stdio, env: &[(&str, &str)]) -> std::process::Child {
    Command::new(AIDOD)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Sends `request` to a broker serving one end of a socket pair, and returns
/// what it answered and how it exited.
fn exchange(request: &[u8], env: &[(&str, &str)]) -> (BrokerResponse, Output) {
    let (served, mut client) = UnixStream::pair().unwrap();
    // A broker that hangs must fail the test, not hang it.
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let child = broker(Stdio::from(OwnedFd::from(served)), env);
    client.write_all(request).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    (
        BrokerResponse::parse(&answer).unwrap(),
        child.wait_with_output().unwrap(),
    )
}

fn restart() -> Vec<u8> {
    BrokerRequest::new(
        "/usr/bin/systemctl",
        vec!["restart".to_owned(), "nginx.service".to_owned()],
        "enrolled-agent-yolo",
    )
    .to_json()
    .into_bytes()
}

/// Asserts that standard error carries no audit record. A record there is
/// diagnostics at best: nothing is minted on the strength of one, so a binary
/// that wrote its trail to standard error again would be a regression.
fn assert_no_record_on_stderr(output: &Output) {
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        !text.lines().any(|line| line.contains("\"prev_hash\"")),
        "an audit record on standard error: {text}"
    );
}

#[test]
fn a_connection_on_descriptor_zero_is_answered_and_refused_without_a_root_owned_spool() {
    let (response, output) = exchange(&restart(), &[]);
    assert_eq!(refusal_of(&response.answer), Some(REFUSED_WITH));
    assert_eq!(output.status.code(), Some(UNUSABLE));
    assert_no_record_on_stderr(&output);
}

#[test]
fn a_socket_activation_environment_it_never_asked_for_changes_nothing() {
    // The connection is descriptor 0 because the unit says so. LISTEN_FDS
    // and friends are the caller's to set when the binary is run by hand,
    // so the broker reads none of them — nor anything else from its
    // environment.
    let hostile = [
        ("LISTEN_FDS", "3"),
        ("LISTEN_PID", "1"),
        ("LISTEN_FDNAMES", "broker"),
        ("AIDO_SPOOL", "/home/attacker/spool"),
        ("RUST_BACKTRACE", "full"),
    ];
    let (clean, clean_output) = exchange(&restart(), &[]);
    let (dirty, dirty_output) = exchange(&restart(), &hostile);
    assert_eq!(dirty, clean);
    assert_eq!(dirty_output.status.code(), clean_output.status.code());
}

#[test]
fn a_malformed_request_is_refused_and_the_broker_exits_by_whose_fault_it_was() {
    let (response, output) = exchange(b"{\"skip_confirmation\":true}", &[]);
    let (code, status) = MALFORMED_REFUSED_WITH;
    assert_eq!(refusal_of(&response.answer), Some(code));
    assert_eq!(output.status.code(), Some(status));
    assert_no_record_on_stderr(&output);
}

#[cfg(target_os = "linux")]
#[test]
fn a_client_that_connects_and_exits_cannot_make_the_broker_exit_as_broken() {
    // A review ran connect-and-exit clients against the shipped units and got
    // one failed instance each: status 19, fault=broker. Here the peer is a
    // separate process that connects and exits, reaped before the broker
    // starts, as systemd hands such a connection over. On every kernel it is
    // refused as the client's doing and the broker exits 0.
    use std::os::unix::net::UnixListener;

    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("aidod-bin-gone");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("peer.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut client = Command::new("/usr/bin/perl")
        .args([
            "-MSocket",
            "-e",
            "socket(my $s, AF_UNIX, SOCK_STREAM, 0) or die \"socket: $!\"; \
             connect($s, pack_sockaddr_un($ARGV[0])) or die \"connect: $!\"; exit 0;",
        ])
        .arg(&path)
        .env_clear()
        .spawn()
        .unwrap();
    let (accepted, _) = listener.accept().unwrap();
    assert!(client.wait().unwrap().success());

    let output = broker(Stdio::from(OwnedFd::from(accepted)), &[])
        .wait_with_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_no_record_on_stderr(&output);
}

#[test]
fn a_descriptor_zero_that_is_not_a_stream_socket_is_refused_and_fails_the_unit() {
    // A file, and a socket of the wrong type: nobody to answer, so nothing is
    // written back, and systemd sees a failure. (The record that says why is
    // the root lane's to read.)
    let (datagram, _other) = UnixDatagram::pair().unwrap();
    for (stdin, why) in [
        (Stdio::null(), "not a socket"),
        (Stdio::from(OwnedFd::from(datagram)), "not a stream socket"),
    ] {
        let output = broker(stdin, &[]).wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(UNUSABLE), "{why}");
        assert!(output.stdout.is_empty(), "{why}");
        assert_no_record_on_stderr(&output);
    }
}
