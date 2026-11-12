//! `xudo exec --queue`, the real binary, against a fake broker, as real root.
//!
//! The binary reads the broker at the fixed `/run/xudo/broker.sock`, which only
//! root may create, so the process-level proof of `queue_host()` (the
//! environment it reads, the uid it takes, the queue it writes) lives in the
//! root lane. The broker here only ever says "a human must run this". See
//! `xudo-sys/tests/root_lane.rs` for the lane.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use xudo::watch::{Answer, BrokerResponse, WIRE_SCHEMA_VERSION};
use xudo_policy::{Decision, DenialCode};
use xudo_tests::root_lane::root_guard;

const XUDO: &str = env!("CARGO_BIN_EXE_xudo");
const SOCKET: &str = "/run/xudo/broker.sock";

fn begin_root_test(test: &str) -> bool {
    root_guard(test)
}

/// A scratch home under the target dir, never `/tmp`.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A broker that answers one request with a human-path denial, then goes away.
fn denying_broker() -> std::thread::JoinHandle<()> {
    std::fs::create_dir_all("/run/xudo").unwrap();
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        let reply = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: Decision::deny(DenialCode::HumanPathOnly, Vec::new(), Vec::new()),
                minted: None,
            },
        };
        stream.write_all(reply.to_json().as_bytes()).unwrap();
    })
}

/// The real binary with an empty environment but the scratch home.
fn xudo(home: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(XUDO);
    cmd.env_clear()
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .args(args);
    let broker = denying_broker();
    let out = cmd.output().unwrap();
    broker.join().unwrap();
    let _ = std::fs::remove_file(SOCKET);
    out
}

fn queue_lines(home: &Path) -> Vec<serde_json::Value> {
    let file = home.join("state").join("ido").join("queue.jsonl");
    std::fs::read_to_string(file)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn exec_queue_writes_the_denied_command_to_the_callers_queue_and_runs_nothing() {
    if !begin_root_test(
        "exec_queue_writes_the_denied_command_to_the_callers_queue_and_runs_nothing",
    ) {
        return;
    }
    let home = scratch("bin-queue-on");
    let marker = home.join("ran");
    let marker_text = marker.to_str().unwrap();
    let out = xudo(
        &home,
        &[
            "exec",
            "--queue",
            "--",
            "/usr/bin/touch",
            marker_text,
            "a b",
        ],
    );
    assert_eq!(out.status.code(), Some(17), "{out:?}");
    assert!(!marker.exists(), "the denied command ran");
    let entries = queue_lines(&home);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["queued_by"], "xudo", "{entries:?}");
    assert_eq!(
        entries[0]["argv"],
        serde_json::json!(["/usr/bin/touch", marker_text, "a b"]),
        "{entries:?}"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("queued"),
        "{out:?}"
    );
}

#[test]
fn exec_without_queue_leaves_the_queue_untouched() {
    if !begin_root_test("exec_without_queue_leaves_the_queue_untouched") {
        return;
    }
    let home = scratch("bin-queue-off");
    let marker = home.join("ran");
    let out = xudo(
        &home,
        &["exec", "--", "/usr/bin/touch", marker.to_str().unwrap()],
    );
    assert_eq!(out.status.code(), Some(17), "{out:?}");
    assert!(!marker.exists(), "the denied command ran");
    assert!(queue_lines(&home).is_empty());
    assert!(
        !home.join("state").exists(),
        "the queue location was created"
    );
}
