//! Real-terminal tests for the watcher entry point.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustix::fs::{OFlags, fcntl_setfl};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use xudo::watch::{
    Answer, BrokerRequest, BrokerResponse, ExitCode, Question, RefusalCode, RuleSet, StdTerminal,
    WIRE_SCHEMA_VERSION, WatchPrompt, watch_with,
};

fn fixture_rules() -> RuleSet {
    RuleSet::from_toml(
        "20-packages.toml",
        r#"[[action]]
id = "xudo.pkg.remove"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "remove" } }]
"#,
    )
    .unwrap()
}

fn test_dir() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = root.join(format!(
        "watch-pty-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn pty_watch_child_entry() {
    let Some(socket) = std::env::args().next_back().filter(|arg| {
        Path::new(arg)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sock"))
    }) else {
        return;
    };
    rustix::process::setsid().unwrap();
    rustix::process::ioctl_tiocsctty(std::io::stdin()).unwrap();
    let mut terminal = StdTerminal::new();
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let status = watch_with(
        Path::new(&socket),
        &fixture_rules(),
        &mut terminal,
        &mut out,
        &mut err,
        &mut xudo::watch::ask_live,
    );
    assert_eq!(status, ExitCode::Unusable);
}

#[test]
fn real_pty_watcher_approves_on_its_terminal() {
    exercise_real_pty("remove\n", true, "remove", None);
}

#[test]
fn real_pty_watcher_denies_on_its_terminal() {
    exercise_real_pty("n\n", false, "n", None);
}

#[test]
fn input_written_before_the_prompt_is_flushed_from_a_real_terminal() {
    exercise_real_pty("n\n", false, "n", Some("remove\n"));
}

fn exercise_real_pty(input: &str, approve: bool, expected_token: &str, pre_input: Option<&str>) {
    let dir = test_dir();
    let socket = dir.join("broker.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let response_token = Arc::new(Mutex::new(None));
    let response_seen = Arc::clone(&response_token);
    let server = std::thread::spawn(move || {
        let mut watches = 0;
        loop {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            let request = BrokerRequest::parse(&bytes).unwrap();
            let answer = match request.question {
                Question::Watch => {
                    watches += 1;
                    if watches == 1 {
                        Answer::Watching {
                            prompts: vec![watch_prompt()],
                            omitted: 0,
                        }
                    } else {
                        Answer::Refused {
                            code: RefusalCode::ChannelUntrusted,
                            remediation: "stop test watcher".to_owned(),
                            detail: Some("pty test finished".to_owned()),
                        }
                    }
                }
                Question::Answer {
                    approve: got_approve,
                    token,
                    ..
                } => {
                    *response_seen.lock().unwrap() = Some((got_approve, token));
                    Answer::Done
                }
                _ => panic!("unexpected broker question"),
            };
            let reply = BrokerResponse {
                schema_version: WIRE_SCHEMA_VERSION,
                answer,
            };
            stream.write_all(reply.to_json().as_bytes()).unwrap();
            if watches > 1 {
                break;
            }
        }
    });

    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(i32::try_from(OFlags::NOCTTY.bits()).unwrap())
        .open(name.to_str().unwrap())
        .unwrap();
    if let Some(pre_input) = pre_input {
        rustix::io::write(&master, pre_input.as_bytes()).unwrap();
    }
    let child = ProcessCommand::new(std::env::current_exe().unwrap())
        .args(["--exact", "pty_watch_child_entry", "--nocapture"])
        .arg("--")
        .arg(&socket)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .unwrap();
    fcntl_setfl(&master, OFlags::NONBLOCK).unwrap();
    let (mut child, mut transcript) = wait_prompt_and_answer(child, &master, input);
    read_until_marker(&master, &mut transcript, "pty test finished");
    let status = child.wait().unwrap();
    let mut tail = [0_u8; 4096];
    while let Ok(count) = rustix::io::read(&master, &mut tail) {
        if count == 0 {
            break;
        }
        transcript.extend_from_slice(&tail[..count]);
    }
    server.join().unwrap();
    assert!(status.success(), "{}", String::from_utf8_lossy(&transcript));
    assert!(String::from_utf8_lossy(&transcript).contains("PENDING"));
    assert!(String::from_utf8_lossy(&transcript).contains("pty test finished"));
    assert_eq!(
        *response_token.lock().unwrap(),
        Some((approve, expected_token.to_owned()))
    );
    std::fs::remove_dir_all(dir).unwrap();
}

fn read_until_marker(master: &OwnedFd, transcript: &mut Vec<u8>, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut buffer = [0_u8; 4096];
    while !String::from_utf8_lossy(transcript).contains(marker) && Instant::now() < deadline {
        match rustix::io::read(master, &mut buffer) {
            Ok(count) if count > 0 => transcript.extend_from_slice(&buffer[..count]),
            Ok(_) => break,
            Err(error) if error == rustix::io::Errno::AGAIN => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("pty read failed: {error}"),
        }
    }
}

fn wait_prompt_and_answer(
    mut child: std::process::Child,
    master: &OwnedFd,
    input: &str,
) -> (std::process::Child, Vec<u8>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut transcript = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match rustix::io::read(master, &mut buffer) {
            Ok(count) => transcript.extend_from_slice(&buffer[..count]),
            Err(error) if error == rustix::io::Errno::AGAIN => {}
            Err(error) => panic!("pty read failed: {error}"),
        }
        if String::from_utf8_lossy(&transcript).contains("type 'remove'") {
            rustix::io::write(master, input.as_bytes()).unwrap();
            return (child, transcript);
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "watcher exited before prompting ({status}): {}",
                String::from_utf8_lossy(&transcript)
            );
        }
        assert!(
            Instant::now() < deadline,
            "watcher did not prompt: {}",
            String::from_utf8_lossy(&transcript)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn watch_prompt() -> WatchPrompt {
    WatchPrompt {
        id: "ab".repeat(32),
        action: "xudo.pkg.remove".to_owned(),
        program: "/usr/bin/apt-get".to_owned(),
        argv: vec!["remove".to_owned(), "nginx".to_owned()],
        classification: "unattested".to_owned(),
        evidence: "watch approval is pending; the password remains required".to_owned(),
        expires_in_ms: 60_000,
    }
}
