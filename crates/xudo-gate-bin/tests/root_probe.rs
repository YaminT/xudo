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
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

struct FreezeMarkerGuard(std::path::PathBuf);

impl Drop for FreezeMarkerGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

use xudo_backend::{InstallPlan, detect};
use xudo_gate::request::{BoottimeMillis, PendingRequest, REQUEST_SCHEMA_VERSION};
use xudo_gate::{CONFIG_FILE as GATE_CONFIG_FILE, SPOOL_DIR};
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
const CONFIG_FILE: &str = "/etc/xudo/config.toml";
const AUDIT_DIR: &str = "/var/lib/xudo";
const JOURNAL_DIR: &str = "/run/systemd/journal";
const CONFIRM_DIR: &str = "/run/xudo/confirm";
const USER: &str = "xudotest";
/// The lane's account's password. Worth nothing: see `ci/root-test.sh`.
const PASSWORD: &str = "xudotest-fixed-password";
const ACTION: &str = "xudo.probe.id";
const ENV_ACTION: &str = "xudo.test.environment";

/// The rule that ships, so the broker is tested against the file operators get.
const RULES: &str = include_str!("../../../rules/05-probe.toml");

fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    true
}

#[test]
fn gate_reads_the_root_owned_config_from_etc() {
    if !begin_root_test("gate_reads_the_root_owned_config_from_etc") {
        return;
    }
    let _journal = install_everything();
    let loaded = xudo_gate::policy::load(Path::new(RULES_DIR), Path::new(CONFIG_FILE)).unwrap();
    assert!(loaded.settings.confirm_human_path);
}

#[test]
fn gate_refuses_bad_configs_through_the_real_trust_walk() {
    if !begin_root_test("gate_refuses_bad_configs_through_the_real_trust_walk") {
        return;
    }
    let _journal = install_everything();
    let paths = xudo_config::SystemPaths::default();
    assert_eq!(Path::new(GATE_CONFIG_FILE), paths.config());

    root_file(CONFIG_FILE, b"confirm_human_path = true\n", 0o666);
    assert!(
        xudo_gate::policy::load(Path::new(RULES_DIR), Path::new(CONFIG_FILE)).is_err(),
        "world-writable config passed the gate trust walk"
    );

    root_file(CONFIG_FILE, b"confirm_human_path = true\n", 0o644);
    let target = "/etc/xudo/config-target.toml";
    root_file(target, b"confirm_human_path = true\n", 0o644);
    fs::remove_file(CONFIG_FILE).unwrap();
    std::os::unix::fs::symlink(target, CONFIG_FILE).unwrap();
    assert!(
        xudo_gate::policy::load(Path::new(RULES_DIR), Path::new(CONFIG_FILE)).is_err(),
        "symlinked config passed the gate trust walk"
    );

    fs::remove_file(CONFIG_FILE).unwrap();
    root_file(CONFIG_FILE, b"unknown_m3_setting = true\n", 0o644);
    assert!(
        xudo_gate::policy::load(Path::new(RULES_DIR), Path::new(CONFIG_FILE)).is_err(),
        "unknown config key passed the gate parser"
    );
    fs::remove_file(target).unwrap();
    root_file(CONFIG_FILE, b"confirm_human_path = true\n", 0o644);
}

/// Sends one question to the real broker on its real socket, as this process.
fn ask_broker(question: xudo_wire::Question) -> BrokerResponse {
    let mut client = UnixStream::connect(SOCKET).unwrap();
    let request = BrokerRequest {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        question,
    };
    client.write_all(request.to_json().as_bytes()).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).unwrap();
    BrokerResponse::parse(&answer).unwrap()
}

/// The real broker publishes the freeze file into the real `/var/lib/xudo`
/// (over a stale temporary a killed broker left), the policy both the broker
/// and the gate load reads it as frozen, only root can thaw, and the human path
/// keeps working while frozen.
///
/// A real gate run cannot be agent-classified before M4, so what the frozen
/// flag changes for the agent path is asserted on the policy load result, the
/// one value the gate's engine takes it from; the engine's own use of it is in
/// `xudo-policy`'s tests.
#[test]
fn the_root_lane_writes_reads_the_real_freeze_file_and_runs_the_gate() {
    if !begin_root_test("the_root_lane_writes_reads_the_real_freeze_file_and_runs_the_gate") {
        return;
    }
    let _journal = install_everything();
    start_broker();
    let dir = Path::new("/var/lib/xudo");
    let marker = dir.join("frozen");
    let stale = dir.join(format!("{}frozen", xudo_sys::TEMP_PREFIX));
    let _ = fs::remove_file(&marker);
    let _marker_guard = FreezeMarkerGuard(marker.clone());
    assert_eq!(fs::metadata(dir).unwrap().uid(), 0);
    assert_eq!(
        fs::metadata(dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let load = || xudo_gate::policy::load(Path::new(RULES_DIR), Path::new(CONFIG_FILE)).unwrap();
    assert!(!load().settings.frozen);

    fs::write(&stale, b"half a record").unwrap();
    let answer = ask_broker(xudo_wire::Question::Freeze {
        reason: "root lane test".to_owned(),
    });
    assert_eq!(answer.answer, Answer::Done);
    assert!(!stale.exists(), "the stale temporary disabled freeze");
    let meta = fs::metadata(&marker).unwrap();
    assert_eq!((meta.uid(), meta.permissions().mode() & 0o777), (0, 0o600));
    let record = fs::read_to_string(&marker).unwrap();
    assert!(record.contains(r#""reason":"root lane test""#), "{record}");
    assert!(load().settings.frozen);

    // A second freeze reports success rather than failing on the first.
    let again = ask_broker(xudo_wire::Question::Freeze {
        reason: "again".to_owned(),
    });
    assert_eq!(again.answer, Answer::Done);

    // The human path: the entry is written, the password typed, the gate runs.
    let nonce = write_entry(own_pin(), 0);
    let output = through_sudo();
    assert!(output.success, "{output:?}");
    assert_eq!(output.stdout.trim(), "0");
    assert!(!entry_exists(&nonce));

    // An ordinary user cannot thaw, and is told it is a matter of trust.
    let refused = Command::new("/usr/sbin/runuser")
        .args(["-u", USER, "--"])
        .arg(xudo_binary())
        .args(["--output", "json", "thaw"])
        .output()
        .unwrap();
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("ChannelUntrusted"),
        "{refused:?}"
    );
    assert!(marker.exists());

    assert_eq!(ask_broker(xudo_wire::Question::Thaw).answer, Answer::Done);
    assert!(!marker.exists());
    assert!(!load().settings.frozen);
    remove_snippet();
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
    root_file(CONFIG_FILE, b"confirm_human_path = true\n", 0o644);
    root_dir("/var/lib", 0o755);
    root_dir(AUDIT_DIR, 0o700);
    let _ = fs::remove_file(format!("{AUDIT_DIR}/audit.jsonl"));
    root_dir("/run/xudo", 0o700);
    root_dir(SPOOL_DIR, 0o700);
    clear_spool();
    root_dir(CONFIRM_DIR, 0o700);
    let _ = fs::remove_file(format!("{CONFIRM_DIR}/1000.json"));

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
    write_entry_for(
        pin,
        generation_offset,
        ACTION,
        "/usr/bin/id",
        vec!["-u".to_owned()],
    )
}

fn write_entry_for(
    pin: (u32, u64),
    generation_offset: u64,
    action: &str,
    program: &str,
    argv: Vec<String>,
) -> String {
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
        action: action.to_owned(),
        program: program.to_owned(),
        argv,
        generation: generation.saturating_add(generation_offset),
        deadline: BoottimeMillis(HostClock.boottime_millis().saturating_add(120_000)),
        confirmed: false,
        confirmed_by: None,
        state: xudo_gate::request::ConfirmationState::Pending,
        caller_uid: 1000,
        caller_sid: 10,
        caller_tty: 20,
        needs_watch: false,
        shown_at_ms: None,
        shown_to: None,
        fingerprint: "0".repeat(64),
        claimed_classification: "human".to_owned(),
        attested_class: xudo_gate::request::AttestedClass::Unattested,
        attested_scope_id: None,
        boot_id: None,
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
fn real_injection_payloads_never_reach_the_child_environment() {
    if !begin_root_test("real_injection_payloads_never_reach_the_child_environment") {
        return;
    }
    let _journal = install_everything();
    let marker = format!("{AUDIT_DIR}/environment-payload-ran-{}", std::process::id());
    let _ = fs::remove_file(&marker);
    let _marker_guard = FreezeMarkerGuard(marker.clone().into());
    let (preload_source, preload_library) = compile_environment_payload(&marker);
    let _source_guard = FreezeMarkerGuard(preload_source.into());
    let _library_guard = FreezeMarkerGuard(preload_library.clone().into());

    let vars = [
        ("LD_PRELOAD", preload_library.as_str()),
        ("BASH_ENV", marker.as_str()),
        ("NODE_OPTIONS", "--require=/nonexistent-xudo-test-module"),
        ("http_proxy", "http://xudo-test.invalid/"),
        ("LESSOPEN", "|/bin/touch /tmp/xudo-test-lessopen"),
        ("GCONV_PATH", "/nonexistent-xudo-test-gconv"),
    ];
    let test_rule = format!("{RULES_DIR}/90-test-environment.toml");
    let sudoers = "/etc/sudoers.d/xudo-env-test";
    let _sudoers_guard = FreezeMarkerGuard(sudoers.into());
    let _rule_guard = FreezeMarkerGuard(test_rule.clone().into());

    // Prove the payload itself works in an ordinary child. LD_PRELOAD is set
    // only for cat, never for runuser (which is itself running as root here).
    let payload_control = Command::new("/usr/bin/cat")
        .arg("/proc/self/environ")
        .env("LD_PRELOAD", &preload_library)
        .output()
        .unwrap();
    assert!(
        payload_control.status.success(),
        "payload control failed: {payload_control:?}"
    );
    assert!(
        Path::new(&marker).exists(),
        "LD_PRELOAD control payload did not run"
    );
    fs::remove_file(&marker).unwrap();

    // sudo's setuid loader strips LD_PRELOAD and GCONV_PATH before sudo can
    // apply env_keep. Prove the other four names reach a plain child through
    // the same sudo environment path used by the installed gate.
    assert_sudo_environment_delivery(sudoers, &[vars[1], vars[2], vars[3], vars[4]]);

    // Direct start keeps the complete environment intact until the gate,
    // including loader variables glibc deliberately removes from setuid sudo.
    root_file(
        &test_rule,
        format!(
            "[[action]]\nid = \"{ENV_ACTION}\"\ntier = \"diag-read\"\nexe = \"/usr/bin/cat\"\nargs = [{{ name = \"environment\", matcher = {{ literal = \"/proc/self/environ\" }} }}]\n"
        )
        .as_bytes(),
        0o644,
    );
    let nonce = write_entry_for(
        own_pin(),
        0,
        ENV_ACTION,
        "/usr/bin/cat",
        vec!["/proc/self/environ".to_owned()],
    );

    let child = Command::new(GATE_AUTH)
        .env_clear()
        .envs(vars.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let actual = output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| String::from_utf8(entry.to_vec()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actual, xudo_gate::child_environment(), "{output:?}");
    assert!(
        !Path::new(&marker).exists(),
        "an environment payload created its marker"
    );
    assert!(!entry_exists(&nonce), "the request was not consumed");
    remove_snippet();
}

fn compile_environment_payload(marker: &str) -> (String, String) {
    let payload_source = format!(
        r#"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void mark_cat_load(void) {{
    char executable[4096];
    ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    if (length <= 0) return;
    executable[length] = '\0';
    if (strcmp(executable, "/usr/bin/cat") != 0) return;
    int marker = open("{marker}", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (marker >= 0) close(marker);
}}
"#
    );
    let preload_source = format!("{AUDIT_DIR}/environment-payload-{}.c", std::process::id());
    let preload_library = format!("{AUDIT_DIR}/environment-payload-{}.so", std::process::id());
    fs::write(&preload_source, payload_source).unwrap();
    let compiled = Command::new("cc")
        .args(["-shared", "-fPIC", "-o", &preload_library, &preload_source])
        .output()
        .unwrap();
    assert!(compiled.status.success(), "cc failed: {compiled:?}");
    (preload_source, preload_library)
}

fn assert_sudo_environment_delivery(sudoers: &str, vars: &[(&str, &str)]) {
    root_file(
        sudoers,
        b"Defaults env_keep += \"BASH_ENV NODE_OPTIONS http_proxy LESSOPEN\"\nxudotest ALL=(root) NOPASSWD: /usr/bin/cat /proc/self/environ\n",
        0o440,
    );
    let mut control_command = Command::new("/usr/sbin/runuser");
    control_command.args(["-u", USER, "--", "/usr/bin/env"]);
    control_command.args(vars.iter().map(|(name, value)| format!("{name}={value}")));
    control_command.args(["/usr/bin/sudo", "-n", "/usr/bin/cat", "/proc/self/environ"]);
    let control = control_command.output().unwrap();
    assert!(
        control.status.success(),
        "sudo environment control failed: {control:?}"
    );
    for (name, value) in vars {
        let entry = format!("{name}={value}");
        assert!(
            control
                .stdout
                .split(|byte| *byte == 0)
                .any(|part| part == entry.as_bytes()),
            "control did not receive {name}: {control:?}"
        );
    }
}

#[test]
fn the_real_gate_requires_watch_approval_in_addition_to_the_password() {
    if !begin_root_test("the_real_gate_requires_watch_approval_in_addition_to_the_password") {
        return;
    }
    let _journal = install_everything();
    let confirm_rule = rules_with_id_confirmation();
    root_file(
        &format!("{RULES_DIR}/05-probe.toml"),
        confirm_rule.as_bytes(),
        0o644,
    );
    root_file(CONFIG_FILE, b"confirm_human_path = true\n", 0o644);
    let nonce = write_entry(own_pin(), 0);

    let output = through_sudo();

    assert!(
        !output.success,
        "gate ran a confirm-tier command without watch approval: {output:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "unexpected command output: {output:?}"
    );
    assert!(
        output.stderr.contains("gate_confirmation_missing"),
        "gate did not refuse after the password: {output:?}"
    );
    assert!(
        entry_exists(&nonce),
        "refused request should remain unconsumed"
    );
    clear_spool();
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
    assert_eq!(
        thread::spawn(move || {
            let mut trail = xudo_sys::AuditTrail::system("xudod");
            xudod::run(server.as_fd(), &mut trail)
        })
        .join()
        .unwrap(),
        0
    );
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

/// Seeds the same root-owned heartbeat file the watch request maintains, tied
/// to a live xudotest process on a distinct controlling terminal.
fn live_test_watcher() -> Pty {
    let watcher = Pty::spawn(&["/usr/bin/sleep", "60"]);
    // setsid may fork before it can create a session. Find its live descendant
    // that actually owns the controlling terminal, rather than pinning wrapper.
    let root_pid = watcher.child.id();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let (pid, stat) = loop {
        let found = fs::read_dir("/proc")
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .find_map(|pid| {
                let bytes = fs::read(format!("/proc/{pid}/stat")).ok()?;
                let stat = xudo_sys::parse_stat("watcher", &bytes).ok()?;
                if !xudo_gate::request::is_watch_terminal(stat.tty_nr) {
                    return None;
                }
                let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
                if !status
                    .lines()
                    .any(|line| line.starts_with("Uid:\t1000\t1000"))
                {
                    return None;
                }
                let mut parent = stat.ppid;
                for _ in 0..8 {
                    if parent == root_pid {
                        return Some((pid, stat));
                    }
                    let bytes = fs::read(format!("/proc/{parent}/stat")).ok()?;
                    parent = xudo_sys::parse_stat("watcher parent", &bytes).ok()?.ppid;
                }
                None
            });
        if let Some(found) = found {
            break found;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "watcher never acquired a valid pty"
        );
        thread::sleep(Duration::from_millis(10));
    };
    let now = HostClock.boottime_millis();
    root_file(
        &format!("{CONFIRM_DIR}/1000.json"),
        format!(
            "{{\"h\":{{\"p\":{pid},\"s\":{},\"t\":{},\"d\":{},\"a\":{}}},\"b\":[],\"o\":[]}}",
            stat.starttime, stat.tty_nr, stat.session, now
        )
        .as_bytes(),
        0o600,
    );
    watcher
}

fn rules_with_id_confirmation() -> String {
    // Keep `confirm` inside the id action. Appending it to the whole rules
    // string would now attach it to gnuid, the last `[[action]]` table.
    let marker = "\n[[action]]\nid = \"xudo.probe.gnuid\"";
    let (id_rule, gnuid_rule) = RULES
        .split_once(marker)
        .expect("the shipped probe rules keep id before gnuid");
    format!("{id_rule}\nconfirm = \"always\"{marker}{gnuid_rule}")
}

fn require_watch_confirmation() {
    let confirm_rule = rules_with_id_confirmation();
    root_file(
        &format!("{RULES_DIR}/05-probe.toml"),
        confirm_rule.as_bytes(),
        0o644,
    );
}

fn stdin_yes_exec(timeout: u64) -> std::process::Output {
    root_file(
        CONFIG_FILE,
        format!("confirm_human_path = true\nconfirmation_timeout_secs = {timeout}\n").as_bytes(),
        0o644,
    );
    let xudo = xudo_binary();
    let mut child = Command::new("/usr/sbin/runuser")
        .args(["-u", USER, "--"])
        .arg(xudo)
        .args(["--output", "json", "exec", "--", "/usr/bin/id", "-u"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    child.wait_with_output().unwrap()
}

fn assert_run_is_still_pending(output: &std::process::Output) {
    assert_eq!(output.status.code(), Some(18), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("\"verdict\":\"pending\""), "{stdout}");
    assert!(
        stderr.contains("pending approval") || stderr.contains("waiting for approval"),
        "{stderr}"
    );
    assert!(
        !stdout.contains("yes"),
        "stdin leaked into output: {stdout}"
    );
    let entries = fs::read_dir(SPOOL_DIR)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1, "pending spool entries: {entries:?}");
    let bytes = fs::read(entries[0].path()).unwrap();
    let request = PendingRequest::parse(std::str::from_utf8(&bytes).unwrap()).unwrap();
    assert_eq!(
        request.state,
        xudo_gate::request::ConfirmationState::Pending
    );
    let log = fs::read(AUDIT_LOG).unwrap();
    let chain = xudo_audit::verify_log(&log).unwrap();
    let runs = chain
        .records()
        .iter()
        .filter(|record| {
            record.decision == xudo_audit::record::Decision::AwaitingConfirmation
                && record.action.as_deref() == Some(ACTION)
        })
        .count();
    assert_eq!(runs, 1, "the run was repeated: {:#?}", chain.records());
}

#[test]
fn yes_on_stdin_cannot_answer_a_pending_run_with_zero_wait() {
    if !begin_root_test("yes_on_stdin_cannot_answer_a_pending_run_with_zero_wait") {
        return;
    }
    let _journal = install_everything();
    require_watch_confirmation();
    let _watcher = live_test_watcher();
    start_broker();
    let output = stdin_yes_exec(0);
    assert_run_is_still_pending(&output);
    clear_spool();
}

#[test]
fn yes_on_stdin_cannot_answer_a_pending_run_while_waiting() {
    if !begin_root_test("yes_on_stdin_cannot_answer_a_pending_run_while_waiting") {
        return;
    }
    let _journal = install_everything();
    require_watch_confirmation();
    let _watcher = live_test_watcher();
    start_broker();
    let output = stdin_yes_exec(1);
    assert_run_is_still_pending(&output);
    clear_spool();
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
