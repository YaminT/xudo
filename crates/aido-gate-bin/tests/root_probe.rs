//! The installed rule reaches the gate, and the gate runs a command as uid 0.
//!
//! This is what `aido install`'s functional probe is for, done by hand where a
//! request can be written without the broker: the real snippet is installed by
//! the product's own executor into the real `/etc/sudoers.d`, the real gate
//! binary stands at the path the snippet names, and an unprivileged account
//! runs it through real `sudo` with a password. The entry the gate waits for is
//! written the way the broker writes one (a root-owned `0600` file in a root-owned
//! `0700` directory), pinned to this test's own process, and the gate finds it
//! because this process is an ancestor of the `sudo` that runs it.
//!
//! It is **not** the product's probe. `aido install` cannot mint an entry until
//! the front-end has a broker client (M2b plan item C1), so its own probe stays
//! `NOT VERIFIED`. What this file proves is the path that probe will use.
//!
//! The password is typed by this harness, on `sudo`'s own prompt: nothing in
//! `aido` reads a confirmation from a stream the requester owns (invariant 3).
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
//! See `aido-sys/tests/root_lane.rs` for how the lane works and what a root test
//! must do first.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use aido_tests::root_lane::root_guard;

use std::fs::{self, File, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use aido_backend::{InstallPlan, detect};
use aido_gate::SPOOL_DIR;
use aido_gate::request::{MonotonicSecs, PendingRequest, REQUEST_SCHEMA_VERSION};
use aido_sys::{
    Clock, HostClock, HostInstallOps, HostProbe, PendingGateProbe, VerifiedProc, execute, lineage,
    load_trusted_rules, run_capture,
};

const GATE: &str = env!("CARGO_BIN_EXE_aido-gate");
const GATE_AUTH: &str = "/usr/libexec/aido/aido-gate-auth";
const RULES_DIR: &str = "/etc/aido/rules.d";
const AUDIT_DIR: &str = "/var/lib/aido";
const JOURNAL_DIR: &str = "/run/systemd/journal";
const USER: &str = "aidotest";
/// The lane's account's password. Worth nothing: see `ci/root-test.sh`.
const PASSWORD: &str = "aidotest-fixed-password";
const ACTION: &str = "aido.probe.id";

/// The one action in the ruleset the gate loads here: print the caller's
/// effective uid, which is the whole of the proof that it ran as root.
const RULES: &str = r#"
[[action]]
id = "aido.probe.id"
tier = "diag-read"
exe = "/usr/bin/id"
args = [
  { name = "effective-uid", matcher = { literal = "-u" } },
]
"#;

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
    root_dir("/usr/libexec/aido", 0o755);
    let _ = fs::remove_file(GATE_AUTH);
    fs::copy(GATE, GATE_AUTH).unwrap();
    fs::set_permissions(GATE_AUTH, Permissions::from_mode(0o755)).unwrap();
    chown(GATE_AUTH, Some(0), Some(0)).unwrap();

    root_dir("/etc/aido", 0o755);
    root_dir(RULES_DIR, 0o755);
    root_file(
        &format!("{RULES_DIR}/10-probe.toml"),
        RULES.as_bytes(),
        0o644,
    );
    root_dir("/var/lib", 0o755);
    root_dir(AUDIT_DIR, 0o700);
    let _ = fs::remove_file(format!("{AUDIT_DIR}/audit.jsonl"));
    root_dir("/run/aido", 0o700);
    root_dir(SPOOL_DIR, 0o700);
    clear_spool();

    // The rule, exactly as `aido install` writes it.
    let backend = detect(&HostProbe).expect("the lane installs sudo before it runs");
    let plan = InstallPlan::human_only(&backend).unwrap();
    execute(&plan, &HostInstallOps::system(), &PendingGateProbe).unwrap();
    let _ = run_capture("/usr/sbin/groupadd", &["--system", "aido"], None);
    let added = run_capture("/usr/sbin/usermod", &["-aG", "aido", USER], None).unwrap();
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
    let _ = fs::remove_file("/etc/sudoers.d/aido");
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
fn through_sudo() -> aido_sys::Output {
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
