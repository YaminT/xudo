//! The installed rule reaches the gate, and the gate runs a command as uid 0.
//!
//! This is what `xudo install`'s functional probe is for, done by hand where a
//! request can be written without the broker: the real snippet is installed by
//! the product's own executor into the real `/etc/sudoers.d`, the real gate
//! binary stands at the path the snippet names, and an unprivileged account
//! runs it through real `sudo` with a password. The entry the gate waits for is
//! written the way the broker writes one (a root-owned `0600` file in a root-owned
//! `0700` directory), pinned to this test's own process, and the gate finds it
//! because this process is an ancestor of the `sudo` that runs it.
//!
//! The first tests write the entry by hand; the last ones use the real broker,
//! the real `xudo exec` on a pseudo-terminal, and the real `xudo install` probe.
//!
//! The password is typed by this harness, on `sudo`'s own prompt: nothing in
//! `xudo` reads a confirmation from a stream the requester owns (invariant 3).
//!
//! # What a container lacks, and what stands in for it
//!
//! * **`journald`.** The gate's trail is the audit file *and* the journal, and a
//!   host without one refuses every decision (that is the gate's design, not
//!   something to switch off). A datagram socket at the journal's real path
//!   plays the receiving end of the real protocol, and the test reads back what
//!   the gate sent it: the record of the authorization.
//! * **`sudo`, the unprivileged account, the group.** `ci/root-test.sh` and the
//!   installer provide them.
//!
//! See `xudo-sys/tests/root_lane.rs` for how the lane works and what a root test
//! must do first.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods,
    clippy::arithmetic_side_effects
)]

use xudo_tests::root_lane::root_guard;

use std::fs::{self, File, Permissions};
use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use xudo_backend::{InstallPlan, detect};
use xudo_gate::SPOOL_DIR;
use xudo_gate::request::{MonotonicSecs, PendingRequest, REQUEST_SCHEMA_VERSION};
use xudo_sys::{
    Clock, HostClock, HostInstallOps, HostProbe, InstallProbe, ProbeResult, VerifiedProc, execute,
    lineage, load_trusted_rules, run_capture,
};
use xudo_wire::{Answer, BrokerRequest, BrokerResponse};

/// A probe that does not run: these tests look at files, not at the gate.
struct NoProbe;

impl InstallProbe for NoProbe {
    fn verify(&self, _argv: &[String]) -> ProbeResult {
        ProbeResult::Unavailable {
            reason: "not probed here".to_owned(),
        }
    }
}

const GATE: &str = env!("CARGO_BIN_EXE_xudo-gate");
const GATE_AUTH: &str = "/usr/libexec/xudo/xudo-gate-auth";
const RULES_DIR: &str = "/etc/xudo/rules.d";
const AUDIT_DIR: &str = "/var/lib/xudo";
const JOURNAL_DIR: &str = "/run/systemd/journal";
const USER: &str = "xudotest";
/// The lane's account's password. Worth nothing: see `ci/root-test.sh`.
const PASSWORD: &str = "xudotest-fixed-password";
const ACTION: &str = "xudo.probe.id";

/// The rule that ships, so the broker is tested against the file operators get.
const RULES: &str = include_str!("../../../rules/05-probe.toml");

fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    true
}

fn root_dir(path: &str, mode: u32) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    chown(path, Some(0), Some(0)).unwrap();
}

fn root_file(path: &str, contents: &[u8], mode: u32) {
    let mut file = File::create(path).unwrap();
    file.write_all(contents).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    chown(path, Some(0), Some(0)).unwrap();
}

/// A journald that is only a socket, and what the gate sent it.
struct StandInJournal {
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    _reader: JoinHandle<()>,
}

impl StandInJournal {
    fn open() -> Self {
        root_dir("/run/systemd", 0o755);
        root_dir(JOURNAL_DIR, 0o755);
        let socket = format!("{JOURNAL_DIR}/socket");
        let _ = fs::remove_file(&socket);
        let datagrams = UnixDatagram::bind(&socket).unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&received);
        let reader = thread::spawn(move || {
            let mut buf = vec![0_u8; 256 * 1024];
            while let Ok(count) = datagrams.recv(&mut buf) {
                sink.lock().unwrap().push(buf[..count].to_vec());
            }
        });
        Self {
            received,
            _reader: reader,
        }
    }

    fn text(&self) -> String {
        let all = self.received.lock().unwrap();
        all.iter()
            .map(|datagram| String::from_utf8_lossy(datagram).into_owned())
            .collect()
    }
}

/// Everything the gate reads, as root's, and the snippet installed through the
/// product's own executor. Returns the journal stand-in.
fn install_everything() -> StandInJournal {
    // The gate, at the path the snippet grants, under the name that runs.
    root_dir("/usr/libexec", 0o755);
    root_dir("/usr/libexec/xudo", 0o755);
    let _ = fs::remove_file(GATE_AUTH);
    fs::copy(GATE, GATE_AUTH).unwrap();
    fs::set_permissions(GATE_AUTH, Permissions::from_mode(0o755)).unwrap();
    chown(GATE_AUTH, Some(0), Some(0)).unwrap();

    root_dir("/etc/xudo", 0o755);
    root_dir(RULES_DIR, 0o755);
    root_file(
        &format!("{RULES_DIR}/05-probe.toml"),
        RULES.as_bytes(),
        0o644,
    );
    root_dir("/var/lib", 0o755);
    root_dir(AUDIT_DIR, 0o700);
    let _ = fs::remove_file(format!("{AUDIT_DIR}/audit.jsonl"));
    root_dir("/run/xudo", 0o700);
    root_dir(SPOOL_DIR, 0o700);
    clear_spool();

    // The rule, exactly as `xudo install` writes it.
    let backend = detect(&HostProbe).expect("the lane installs sudo before it runs");
    let plan = InstallPlan::human_only(&backend).unwrap();
    execute(&plan, &HostInstallOps::system(), &NoProbe).unwrap();
    let _ = run_capture("/usr/sbin/groupadd", &["--system", "xudo"], None);
    let added = run_capture("/usr/sbin/usermod", &["-aG", "xudo", USER], None).unwrap();
    assert!(
        added.success,
        "the lane's account is missing: {}",
        added.stderr
    );
    StandInJournal::open()
}

fn clear_spool() {
    for entry in fs::read_dir(SPOOL_DIR).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
}

fn remove_snippet() {
    let _ = fs::remove_file("/etc/sudoers.d/xudo");
}

/// This process, as the kernel's `/proc` names it: the pin an entry carries.
fn own_pin() -> (u32, u64) {
    let proc = VerifiedProc::open().unwrap();
    let chain = lineage(&proc, std::process::id(), 1).unwrap().chain;
    (chain[0].pid, chain[0].starttime)
}

static SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// A request the broker could have minted for `pin`, written where it writes.
fn write_entry(pin: (u32, u64), generation_offset: u64) -> String {
    let nonce = format!(
        "{:064x}",
        (u128::from(std::process::id()) << 64)
            | u128::from(SEQUENCE.fetch_add(1, Ordering::Relaxed))
    );
    let generation = load_trusted_rules(Path::new(RULES_DIR))
        .unwrap()
        .generation
        .id();
    let entry = PendingRequest {
        schema_version: REQUEST_SCHEMA_VERSION,
        nonce: nonce.clone(),
        caller_pid: pin.0,
        caller_starttime: pin.1,
        action: ACTION.to_owned(),
        program: "/usr/bin/id".to_owned(),
        argv: vec!["-u".to_owned()],
        generation: generation.saturating_add(generation_offset),
        deadline: MonotonicSecs(HostClock.monotonic_secs().saturating_add(120)),
        confirmed: false,
        confirmed_by: None,
        claimed_classification: "human".to_owned(),
    };
    let path = format!("{SPOOL_DIR}/{nonce}");
    root_file(&path, entry.to_json().as_bytes(), 0o600);
    nonce
}

/// Runs the installed gate the way a user does: `sudo` as the unprivileged
/// account, the password on `sudo`'s own prompt.
fn through_sudo() -> xudo_sys::Output {
    run_capture(
        "/usr/sbin/runuser",
        &["-u", USER, "--", "/usr/bin/sudo", "-S", GATE_AUTH],
        Some(format!("{PASSWORD}\n").as_bytes()),
    )
    .unwrap()
}

fn entry_exists(nonce: &str) -> bool {
    fs::symlink_metadata(format!("{SPOOL_DIR}/{nonce}")).is_ok()
}

#[test]
fn the_installed_snippet_reaches_the_gate_and_runs_as_uid_0() {
    if !begin_root_test("the_installed_snippet_reaches_the_gate_and_runs_as_uid_0") {
        return;
    }
    let journal = install_everything();
    let nonce = write_entry(own_pin(), 0);

    let output = through_sudo();

    assert!(output.success, "{output:?}");
    // `use_pty` makes sudo's relay end lines with CR LF.
    assert_eq!(
        output.stdout.trim(),
        "0",
        "id -u did not run as root: {output:?}"
    );
    assert!(!entry_exists(&nonce), "the entry was not consumed");

    // The gate recorded the authorization before it ran anything: in the audit
    // file, and in what it sent the journal.
    let log = fs::read_to_string(format!("{AUDIT_DIR}/audit.jsonl")).unwrap();
    assert!(log.contains(ACTION), "{log}");
    assert!(log.contains("/usr/bin/id"), "{log}");
    assert!(
        journal.text().contains(ACTION),
        "the journal was sent nothing"
    );
    remove_snippet();
}

#[test]
fn a_minted_request_leaves_the_brokers_and_the_gates_records_in_one_chain() {
    if !begin_root_test("a_minted_request_leaves_the_brokers_and_the_gates_records_in_one_chain") {
        return;
    }
    let _journal = install_everything();

    // The real broker, in this process, on a real socket: it pins this process.
    let (server, mut client) = UnixStream::pair().unwrap();
    let request = BrokerRequest::new("/usr/bin/id", vec!["-u".to_owned()], "human");
    client.write_all(request.to_json().as_bytes()).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut trail = xudo_sys::AuditTrail::system("xudod");
    assert_eq!(xudod::run(server.as_fd(), &mut trail), 0);
    drop(server);
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    let Answer::Decided {
        minted: Some(minted),
        ..
    } = BrokerResponse::parse(&answer).unwrap().answer
    else {
        panic!("not minted: {}", String::from_utf8_lossy(&answer));
    };

    let output = through_sudo();
    assert!(output.success, "{output:?}");
    assert_eq!(output.stdout.trim(), "0");
    assert!(!entry_exists(&minted.nonce));

    // One chain holds both records, in order, and it verifies.
    let path = format!("{AUDIT_DIR}/audit.jsonl");
    let log = fs::read(&path).unwrap();
    let chain = xudo_audit::verify_log(&log).unwrap();
    let evidence: Vec<String> = chain
        .records()
        .iter()
        .map(|record| record.evidence.join(" "))
        .collect();
    assert_eq!(evidence.len(), 2, "{evidence:?}");
    assert!(evidence[0].contains("broker=xudod"), "{evidence:?}");
    assert!(
        evidence[0].contains(&format!("nonce={}", minted.nonce)),
        "{evidence:?}"
    );
    assert!(!evidence[1].contains("broker=xudod"), "{evidence:?}");

    // Cutting the log is seen: through the last record, and from the front.
    assert!(xudo_audit::verify_log(&log[..log.len() - 20]).is_err());
    let first_line = log.iter().position(|b| *b == b'\n').unwrap() + 1;
    assert!(xudo_audit::verify_log(&log[first_line..]).is_err());
    remove_snippet();
}

#[test]
fn a_consumed_entry_is_not_replayed() {
    if !begin_root_test("a_consumed_entry_is_not_replayed") {
        return;
    }
    let _journal = install_everything();
    let nonce = write_entry(own_pin(), 0);
    assert!(through_sudo().success);
    assert!(!entry_exists(&nonce));

    // The same request again, nothing minted for it.
    let again = through_sudo();
    assert!(!again.success, "a consumed request ran twice: {again:?}");
    assert!(
        again.stderr.contains("gate_no_pending_request"),
        "refused for some other reason: {again:?}"
    );
    assert_ne!(again.stdout.trim(), "0");
    remove_snippet();
}

#[test]
fn an_entry_pinned_to_a_reissued_pid_is_refused() {
    if !begin_root_test("an_entry_pinned_to_a_reissued_pid_is_refused") {
        return;
    }
    let _journal = install_everything();
    // This process's pid with another process's start time: what a pid the
    // kernel reissued looks like to a pin that was minted for its first owner.
    let (pid, starttime) = own_pin();
    let nonce = write_entry((pid, starttime + 1), 0);

    let output = through_sudo();

    assert!(!output.success, "{output:?}");
    assert!(
        output.stderr.contains("gate_no_pending_request"),
        "{output:?}"
    );
    assert!(entry_exists(&nonce), "a refused entry was consumed");
    remove_snippet();
}

#[test]
fn an_entry_minted_under_other_rules_is_refused() {
    if !begin_root_test("an_entry_minted_under_other_rules_is_refused") {
        return;
    }
    let _journal = install_everything();
    let nonce = write_entry(own_pin(), 1);

    let output = through_sudo();

    assert!(!output.success, "{output:?}");
    assert!(
        output.stderr.contains("request_stale_generation"),
        "{output:?}"
    );
    assert!(entry_exists(&nonce), "a refused entry was consumed");
    remove_snippet();
}

#[test]
fn a_wrong_password_never_reaches_the_gate() {
    if !begin_root_test("a_wrong_password_never_reaches_the_gate") {
        return;
    }
    let _journal = install_everything();
    let nonce = write_entry(own_pin(), 0);

    let output = run_capture(
        "/usr/sbin/runuser",
        &["-u", USER, "--", "/usr/bin/sudo", "-S", GATE_AUTH],
        Some(b"not-the-password\n"),
    )
    .unwrap();

    assert!(!output.success, "{output:?}");
    assert_ne!(output.stdout.trim(), "0");
    assert!(entry_exists(&nonce), "the gate ran without a password");
    remove_snippet();
}

// --- the product's own path: broker, `xudo exec`, `xudo install` ------------

use rustix::fs::{OFlags, fcntl_setfl};
use rustix::io::Errno;
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const SOCKET: &str = "/run/xudo/broker.sock";
const AUDIT_LOG: &str = "/var/lib/xudo/audit.jsonl";

/// The `xudo` the lane just built, next to the gate: `ci/root-test.sh` builds
/// it first, because Cargo only sets `CARGO_BIN_EXE_` for this package's binary.
fn xudo_binary() -> std::path::PathBuf {
    let path = Path::new(GATE).with_file_name("xudo");
    assert!(
        path.exists(),
        "{} is missing: run via ci/root-test.sh",
        path.display()
    );
    path
}

/// The real broker on its real socket (`root:xudo 0660`, as the unit makes it),
/// one `xudod::run` per connection, the way the socket unit does.
fn start_broker() {
    root_dir("/run/xudo", 0o755);
    let _ = fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET).unwrap();
    let group = fs::read_to_string("/etc/group").unwrap();
    let gid: u32 = group
        .lines()
        .find_map(|l| l.strip_prefix("xudo:x:")?.split(':').next()?.parse().ok())
        .expect("no xudo group");
    chown(SOCKET, Some(0), Some(gid)).unwrap();
    fs::set_permissions(SOCKET, Permissions::from_mode(0o660)).unwrap();
    thread::spawn(move || {
        let mut trail = xudo_sys::AuditTrail::system("xudod");
        while let Ok((stream, _)) = listener.accept() {
            xudod::run(stream.as_fd(), &mut trail);
        }
    });
}

/// A child on a real pseudo-terminal that is its controlling one.
struct Pty {
    master: OwnedFd,
    child: Child,
    seen: String,
}

impl Pty {
    /// `argv` as `USER`, in its own session with the pty as controlling terminal.
    fn spawn(argv: &[&str]) -> Self {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = File::options()
            .read(true)
            .write(true)
            .open(name.to_str().unwrap())
            .unwrap();
        // `setsid -c` takes the terminal on stdin; no `unsafe` needed here.
        let child = Command::new("/usr/bin/setsid")
            .args(["-w", "-c", "/usr/sbin/runuser", "-u", USER, "--"])
            .args(argv)
            .env_clear()
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap();
        fcntl_setfl(&master, OFlags::NONBLOCK).unwrap();
        Self {
            master,
            child,
            seen: String::new(),
        }
    }

    /// Reads until `needle` shows up; the text up to it is dropped.
    fn expect(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut buf = [0_u8; 4096];
        while Instant::now() < deadline {
            if let Some(at) = self.seen.find(needle) {
                self.seen.drain(..at + needle.len());
                return;
            }
            match rustix::io::read(&self.master, &mut buf) {
                Ok(0) | Err(Errno::IO) => break,
                Ok(n) => self.seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
        let _ = self.child.kill();
        panic!("never saw {needle:?}; saw {:?}", self.seen);
    }

    fn type_line(&self, line: &str) {
        rustix::io::write(&self.master, format!("{line}\r").as_bytes()).unwrap();
    }

    /// Everything the child still says, and how it ended.
    fn finish(mut self) -> (std::process::ExitStatus, String) {
        let status = self.child.wait().unwrap();
        let mut buf = [0_u8; 4096];
        while let Ok(n @ 1..) = rustix::io::read(&self.master, &mut buf) {
            self.seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
        (status, self.seen)
    }
}

fn audit_records() -> usize {
    let log = fs::read(AUDIT_LOG).unwrap();
    xudo_audit::verify_log(&log).unwrap().records().len()
}

fn spool_entries() -> usize {
    fs::read_dir(SPOOL_DIR).unwrap().count()
}

fn exec_probe() -> Pty {
    let xudo = xudo_binary();
    Pty::spawn(&[xudo.to_str().unwrap(), "exec", "--", "/usr/bin/id", "-u"])
}

#[test]
fn xudo_exec_asks_for_a_password_and_then_runs_as_uid_0() {
    if !begin_root_test("xudo_exec_asks_for_a_password_and_then_runs_as_uid_0") {
        return;
    }
    let _journal = install_everything();
    start_broker();

    let mut pty = exec_probe();
    pty.expect("assword");
    pty.type_line(PASSWORD);
    let (status, said) = pty.finish();

    assert!(status.success(), "{said:?}");
    assert!(said.lines().any(|l| l.trim() == "0"), "{said:?}");
    // The broker's record and the gate's, one chain; the entry was consumed.
    assert_eq!(audit_records(), 2);
    assert_eq!(spool_entries(), 0);
    remove_snippet();
}

#[test]
fn xudo_exec_with_a_wrong_password_runs_nothing() {
    if !begin_root_test("xudo_exec_with_a_wrong_password_runs_nothing") {
        return;
    }
    let _journal = install_everything();
    start_broker();

    let mut pty = exec_probe();
    // `sudo` asks three times before it gives up.
    for _ in 0..3 {
        pty.expect("assword");
        pty.type_line("not-the-password");
    }
    let (status, said) = pty.finish();

    assert!(!status.success(), "{said:?}");
    assert!(!said.lines().any(|l| l.trim() == "0"), "{said:?}");
    // The broker minted and recorded; the gate never ran, so it recorded
    // nothing and left the entry for the expiry to remove.
    assert_eq!(audit_records(), 1);
    assert_eq!(spool_entries(), 1);
    remove_snippet();
}

#[test]
fn xudo_install_is_verified_by_the_gate_printing_zero_and_uninstalls_again() {
    if !begin_root_test("xudo_install_is_verified_by_the_gate_printing_zero_and_uninstalls_again") {
        return;
    }
    let _journal = install_everything();
    remove_snippet();
    start_broker();
    let xudo = xudo_binary();

    let installed = Command::new(&xudo).arg("install").output().unwrap();
    let out = String::from_utf8_lossy(&installed.stdout);
    let err = String::from_utf8_lossy(&installed.stderr);
    assert!(installed.status.success(), "{out}\n{err}");
    assert!(
        out.contains("verified     the functional probe passed"),
        "{out}"
    );
    assert!(!err.contains("NOT VERIFIED"), "{err}");
    assert!(Path::new("/etc/sudoers.d/xudo").exists());
    // The gate the probe ran left its record beside the broker's.
    assert_eq!(audit_records(), 2);

    let removed = Command::new(&xudo)
        .args(["install", "--uninstall"])
        .output()
        .unwrap();
    assert!(removed.status.success(), "{removed:?}");
    assert!(!Path::new("/etc/sudoers.d/xudo").exists());
}
