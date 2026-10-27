//! `aido exec`, end to end, as the human it is for: a password typed at a real
//! terminal, a real broker, a real `sudo`, the real gate, and a command that
//! ran as uid 0.
//!
//! Everything else about `exec` is tested without any of that, against fakes.
//! This is the one place that shows the pieces fit: that the gate finds the
//! request the broker minted for *this* `aido` through `sudo`'s own process
//! tree (gate, `sudo`'s `use_pty` monitor, `sudo`, `aido`), that the password
//! prompt is the backend's and reachable on a pty, and that the command's exit
//! status comes back as the status `aido` exits with.
//!
//! Only `ci/root-test.sh` (`just root-test`) runs it, as uid 0 in a throwaway
//! container, and refuses anywhere else (`support/root_lane.rs`): it creates an
//! account, installs a sudoers rule, and binds the broker's socket.
//!
//! No systemd in the container, so the test is the socket activator: it binds
//! `/run/aido/broker.sock` and starts one `aidod` per connection with the
//! connection as its standard input, as `aidod-bin/tests/broker.rs` does.

#![cfg(all(feature = "root-tests", target_os = "linux"))]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

use std::fs;
use std::io::{Read as _, Write as _};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::SystemTime;

use rexpect::process::wait::WaitStatus;
use rexpect::session::{PtySession, spawn_command};

#[path = "../../aido-sys/tests/support/root_lane.rs"]
mod lane;

use lane::root_or_skip;

/// The unprivileged account the human is.
const USER: &str = "aidotest";
const PASSWORD: &str = "correct horse battery staple";
/// The group the installed rule grants, and the broker's socket is open to.
const GROUP: &str = "aido";

const GATE_DIR: &str = "/usr/libexec/aido";
const PROGRAM_DIR: &str = "/usr/local/libexec/aido-test";
const PROGRAM: &str = "/usr/local/libexec/aido-test/whoami-exit";
/// Written by the program when it runs, holding the uid it ran as.
const MARKER: &str = "/run/aido-test-ran";
const SPOOL: &str = "/run/aido/req";
const SOCKET: &str = "/run/aido/broker.sock";

/// How long a test waits for anything before it fails instead of hanging.
const PATIENCE_MS: u64 = 90_000;

const PROGRAM_SOURCE: &str = r#"
fn main() {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    std::fs::write("/run/aido-test-ran", &uid).unwrap();
    println!("{uid}");
    let code = match std::env::args().nth(1).as_deref() {
        Some("eighteen") => 18,
        _ => 7,
    };
    std::process::exit(code);
}
"#;

const RULES: &str = r#"
[[action]]
id = "aido.test.whoami-exit"
tier = "diag-read"
exe = "/usr/local/libexec/aido-test/whoami-exit"
args = [{ name = "verb", matcher = { one-of = ["go", "eighteen"] } }]
"#;

/// Runs a tool as root and fails the test, with its output, if it fails.
fn tool(program: &str, args: &[&str]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {args:?}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn mkdir(path: &str, mode: u32) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    chown(path, Some(0), Some(0)).unwrap();
}

fn install_file(path: &Path, bytes: &[u8], mode: u32) {
    let _ = fs::remove_file(path);
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    chown(path, Some(0), Some(0)).unwrap();
}

fn modified(path: &Path) -> SystemTime {
    fs::metadata(path).unwrap().modified().unwrap()
}

/// What `aido exec` is run against, set up once for the whole lane.
struct Machine {
    aido: PathBuf,
}

/// Builds the machine: the sibling binaries installed where the rule says they
/// are, an account with a password, a ruleset, the sudoers rule, and the
/// broker's socket with something accepting on it.
fn machine() -> &'static Machine {
    static MACHINE: OnceLock<Machine> = OnceLock::new();
    MACHINE.get_or_init(|| {
        let aido = PathBuf::from(env!("CARGO_BIN_EXE_aido"));
        let built = aido.parent().unwrap();
        let (aidod, gate) = (built.join("aidod"), built.join("aido-gate"));

        // The lane builds the siblings before it runs this. One that is missing,
        // or older than the checkout it is tested against, is a stale build of
        // some other revision, and a pass against it would prove nothing.
        let checkout = modified(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml"));
        for sibling in [&aidod, &gate] {
            assert!(
                sibling.is_file(),
                "{} is missing: build it with `cargo build -p aidod-bin -p aido-gate-bin`",
                sibling.display()
            );
            assert!(
                modified(sibling) >= checkout,
                "{} is older than the checkout; rebuild it",
                sibling.display()
            );
        }

        // The account, in the group the rule grants, with a password.
        let _ = Command::new("/usr/sbin/groupadd").arg(GROUP).output();
        if !Command::new("/usr/bin/id")
            .args(["-u", USER])
            .output()
            .unwrap()
            .status
            .success()
        {
            tool(
                "/usr/sbin/useradd",
                &["-m", "-G", GROUP, "-s", "/bin/sh", USER],
            );
        }
        let mut chpasswd = Command::new("/usr/sbin/chpasswd")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(chpasswd.stdin.take().unwrap(), "{USER}:{PASSWORD}").unwrap();
        assert!(chpasswd.wait().unwrap().success());

        // The gate, and its `-auth` name as a hardlink, in a root-owned
        // directory under root-owned ancestors.
        mkdir("/usr/libexec", 0o755);
        mkdir(GATE_DIR, 0o755);
        let installed = Path::new(GATE_DIR).join("aido-gate");
        let _ = fs::remove_file(&installed);
        fs::copy(&gate, &installed).unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
        chown(&installed, Some(0), Some(0)).unwrap();
        let auth = Path::new(aido_backend::snippet::GATE_AUTH);
        let _ = fs::remove_file(auth);
        fs::hard_link(&installed, auth).unwrap();

        // The command the rule permits: a real executable, not a script, because
        // the gate executes the descriptor it validated and a script run that
        // way cannot find its interpreter through a close-on-exec descriptor.
        mkdir("/usr/local", 0o755);
        mkdir("/usr/local/libexec", 0o755);
        mkdir(PROGRAM_DIR, 0o755);
        let source = Path::new(env!("CARGO_TARGET_TMPDIR")).join("whoami-exit.rs");
        fs::write(&source, PROGRAM_SOURCE).unwrap();
        let _ = fs::remove_file(PROGRAM);
        tool(
            "/usr/local/cargo/bin/rustc",
            &["-O", "-o", PROGRAM, source.to_str().unwrap()],
        );
        fs::set_permissions(PROGRAM, fs::Permissions::from_mode(0o755)).unwrap();
        chown(PROGRAM, Some(0), Some(0)).unwrap();

        // The ruleset, as the broker and the gate both read it.
        mkdir("/etc/aido", 0o755);
        mkdir("/etc/aido/rules.d", 0o755);
        install_file(
            Path::new("/etc/aido/rules.d/10-test.toml"),
            RULES.as_bytes(),
            0o644,
        );

        // The sudoers rule `aido install` would write, validated by sudo's own
        // parser before it is trusted.
        let backend = aido_backend::detect(&aido_sys::HostProbe).unwrap();
        let snippet = aido_backend::SudoersSnippet::human_only(&backend).unwrap();
        install_file(
            Path::new(aido_backend::SudoersSnippet::path()),
            snippet.contents.as_bytes(),
            aido_backend::SudoersSnippet::mode(),
        );
        tool(
            "/usr/sbin/visudo",
            &["-cf", aido_backend::SudoersSnippet::path()],
        );

        // What the gate writes its decision to before it acts: the chain under
        // /var/lib/aido, and a mirror to journald's native socket. No journald
        // here, so something listens on that path, or the gate would (rightly)
        // refuse every request for want of a record.
        mkdir("/var/lib/aido", 0o700);
        mkdir("/run/systemd", 0o755);
        mkdir("/run/systemd/journal", 0o755);
        let journald = "/run/systemd/journal/socket";
        let _ = fs::remove_file(journald);
        let mirror = UnixDatagram::bind(journald).unwrap();
        std::thread::spawn(move || {
            let mut datagram = vec![0_u8; 256 * 1024];
            while mirror.recv(&mut datagram).is_ok() {}
        });

        // The broker's directory and spool, as tmpfiles.d makes them, and the
        // socket systemd would hold: root:aido 0660.
        mkdir("/run/aido", 0o755);
        mkdir(SPOOL, 0o700);
        let _ = fs::remove_file(SOCKET);
        let listener = UnixListener::bind(SOCKET).unwrap();
        tool("/usr/bin/chgrp", &[GROUP, SOCKET]);
        fs::set_permissions(SOCKET, fs::Permissions::from_mode(0o660)).unwrap();
        std::thread::spawn(move || {
            for connection in listener.incoming() {
                let connection = connection.unwrap();
                // The broker mints only if its standard error is a connected
                // stream socket, as the journal's is. No journald here, so the
                // other end of one is read by this thread and shown.
                let (journal, records) = UnixStream::pair().unwrap();
                std::thread::spawn(move || {
                    let mut text = String::new();
                    let _ = { records }.read_to_string(&mut text);
                    eprint!("broker record: {text}");
                });
                // One broker process per connection, the connection as its
                // standard input, an empty environment: what the unit does.
                let mut broker = Command::new(&aidod)
                    .env_clear()
                    .stdin(Stdio::from(OwnedFd::from(connection)))
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(OwnedFd::from(journal)))
                    .spawn()
                    .unwrap();
                std::thread::spawn(move || {
                    let _ = broker.wait();
                });
            }
        });

        Machine { aido }
    })
}

/// A clean slate: no request pending, nothing recorded as having run.
fn reset() {
    for entry in fs::read_dir(SPOOL).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let _ = fs::remove_file(MARKER);
}

fn pending() -> usize {
    fs::read_dir(SPOOL).unwrap().count()
}

/// `aido exec -- <program> <verb>` as the unprivileged account, on a real pty.
fn exec_as_the_human(machine: &Machine, verb: &str) -> PtySession {
    let mut command = Command::new("/usr/sbin/runuser");
    command
        .args(["-u", USER, "--"])
        .arg(&machine.aido)
        .args(["exec", "--", PROGRAM, verb]);
    spawn_command(command, Some(PATIENCE_MS)).unwrap()
}

fn status_of(session: &PtySession) -> i32 {
    match session.process.wait().unwrap() {
        WaitStatus::Exited(_, code) => code,
        other => panic!("not a normal exit: {other:?}"),
    }
}

const PROMPT: &str = "password for aidotest";

#[test]
fn a_human_types_the_password_and_the_command_runs_as_root_with_its_status_back() {
    if !root_or_skip("a_human_types_the_password_and_the_command_runs_as_root") {
        return;
    }
    let machine = machine();
    reset();

    let mut session = exec_as_the_human(machine, "go");
    session.exp_string(PROMPT).unwrap();
    // Typed promptly: the broker's request lives fifteen minutes, but nothing
    // here should depend on that.
    session.send_line(PASSWORD).unwrap();
    session.exp_string("0\r\n").unwrap();
    let rest = session.exp_eof().unwrap();

    // The command's own status, unchanged: 7 is neither sudo's 1 nor any of
    // aido's own, and it came through the gate, sudo, and aido.
    assert_eq!(status_of(&session), 7, "{rest}");
    assert_eq!(fs::read_to_string(MARKER).unwrap(), "0", "it ran as uid 0");
    assert!(!rest.contains("the gate refused"), "{rest}");
    assert_eq!(pending(), 0, "the entry was consumed by the gate");
}

#[test]
fn three_wrong_passwords_run_nothing_and_give_back_the_backends_own_status() {
    if !root_or_skip("three_wrong_passwords_run_nothing") {
        return;
    }
    let machine = machine();
    reset();

    let mut session = exec_as_the_human(machine, "go");
    for _ in 0..3 {
        session.exp_string(PROMPT).unwrap();
        session.send_line("not the password").unwrap();
    }
    let rest = session.exp_eof().unwrap();

    assert_eq!(status_of(&session), 1, "{rest}");
    assert!(!Path::new(MARKER).exists(), "the command must not have run");
    assert!(!rest.contains("the gate refused"), "{rest}");
    // The request is still there for the gate that was never reached: it
    // expires, and the broker prunes it.
    assert_eq!(pending(), 1);
}

#[test]
fn a_command_that_exits_eighteen_is_reported_as_its_own_and_not_as_a_refusal() {
    if !root_or_skip("a_command_that_exits_eighteen_is_its_own") {
        return;
    }
    let machine = machine();
    reset();

    let mut session = exec_as_the_human(machine, "eighteen");
    session.exp_string(PROMPT).unwrap();
    session.send_line(PASSWORD).unwrap();
    let rest = session.exp_eof().unwrap();

    // 18 is aido's "not confirmed", and here it is the command's: the gate
    // wrote no refusal line, so no note says otherwise.
    assert_eq!(status_of(&session), 18, "{rest}");
    assert_eq!(fs::read_to_string(MARKER).unwrap(), "0");
    assert!(!rest.contains("the gate refused"), "{rest}");
}

#[test]
fn a_gate_refusal_is_named_as_the_gates_and_runs_nothing() {
    if !root_or_skip("a_gate_refusal_is_named_as_the_gates") {
        return;
    }
    let machine = machine();
    reset();

    let mut session = exec_as_the_human(machine, "go");
    session.exp_string(PROMPT).unwrap();
    // The prompt is shown after the broker minted, so the entry exists now.
    // Taking it away is what a slow human and an expiry would do to it: the
    // gate has nothing to act on and must say so rather than run.
    assert_eq!(pending(), 1);
    reset();
    session.send_line(PASSWORD).unwrap();
    let rest = session.exp_eof().unwrap();

    let status = status_of(&session);
    assert!((17..=19).contains(&status), "{status}: {rest}");
    assert!(
        rest.contains("aido: the gate refused (gate_no_pending_request); see the audit trail"),
        "{rest}"
    );
    assert!(!Path::new(MARKER).exists(), "the command must not have run");
}
