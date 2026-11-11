//! Two real sudo invocations racing to consume one real gate entry.

#![cfg(feature = "root-tests")]
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods,
    clippy::arithmetic_side_effects
)]

use std::fs::{self, File, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Child, ChildStderr, Command, ExitStatus, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use xudo_gate::SPOOL_DIR;
use xudo_gate::request::{BoottimeMillis, PendingRequest, REQUEST_SCHEMA_VERSION};
use xudo_sys::{Clock, HostClock, VerifiedProc, lineage, load_trusted_rules};
use xudo_tests::root_lane::root_guard;

const GATE: &str = env!("CARGO_BIN_EXE_xudo-gate");
const GATE_AUTH: &str = "/usr/libexec/xudo/xudo-gate-auth";
const USER: &str = "xudotest";
const PASSWORD: &str = "xudotest-fixed-password";
const RULES: &str = include_str!("../../../rules/05-probe.toml");
const RULES_DIR: &str = "/etc/xudo/rules.d";
const ACTION: &str = "xudo.probe.id";
const AUDIT_LOG: &str = "/var/lib/xudo/audit.jsonl";
const GONE_DETAIL: &str = "already gone from the spool: another consumer took it first";

fn begin_root_test(test: &str) -> bool {
    root_guard(test)
}

struct Journal {
    socket: UnixDatagram,
    reader: Option<thread::JoinHandle<()>>,
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.socket.send_to(b"stop", "/run/systemd/journal/socket");
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
        let _ = fs::remove_file("/run/systemd/journal/socket");
    }
}

fn root_dir(path: &str, mode: u32) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    chown(path, Some(0), Some(0)).unwrap();
}

fn root_file(path: &str, bytes: &[u8], mode: u32) {
    let mut file = File::create(path).unwrap();
    file.write_all(bytes).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    chown(path, Some(0), Some(0)).unwrap();
}

fn install_gate() -> Journal {
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
    root_file(
        "/etc/xudo/config.toml",
        b"confirm_human_path = true\n",
        0o644,
    );
    root_dir("/var/lib/xudo", 0o700);
    let _ = fs::remove_file("/var/lib/xudo/audit.jsonl");
    root_dir("/run/xudo", 0o700);
    root_dir(SPOOL_DIR, 0o700);
    for entry in fs::read_dir(SPOOL_DIR).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    fs::create_dir_all("/run/systemd/journal").unwrap();
    let _ = fs::remove_file("/run/systemd/journal/socket");
    let journal = UnixDatagram::bind("/run/systemd/journal/socket").unwrap();
    let reader_socket = journal.try_clone().unwrap();
    let reader = thread::spawn(move || {
        let mut buffer = vec![0_u8; 256 * 1024];
        while let Ok(count) = reader_socket.recv(&mut buffer) {
            if &buffer[..count] == b"stop" {
                break;
            }
        }
    });
    let rules = xudo_backend::detect(&xudo_sys::HostProbe).unwrap();
    let plan = xudo_backend::InstallPlan::human_only(&rules).unwrap();
    xudo_sys::execute(&plan, &xudo_sys::HostInstallOps::system(), &NoProbe).unwrap();
    let _ = xudo_sys::run_capture("/usr/sbin/groupadd", &["--system", "xudo"], None);
    let added = xudo_sys::run_capture("/usr/sbin/usermod", &["-aG", "xudo", USER], None).unwrap();
    assert!(
        added.success,
        "could not add {USER} to xudo: {}",
        added.stderr
    );
    Journal {
        socket: journal,
        reader: Some(reader),
    }
}

struct FifoGuard(Vec<String>);

impl Drop for FifoGuard {
    fn drop(&mut self) {
        for fifo in &self.0 {
            let _ = fs::remove_file(fifo);
        }
    }
}

struct PromptedChild {
    child: Child,
    stderr: ChildStderr,
    captured_stderr: Vec<u8>,
}

impl PromptedChild {
    fn wait_for_prompt(mut child: Child, prompt: &str) -> Self {
        let mut stderr = child.stderr.take().unwrap();
        let mut captured_stderr = Vec::new();
        let mut buffer = [0_u8; 128];
        while !captured_stderr
            .windows(prompt.len())
            .any(|window| window == prompt.as_bytes())
        {
            let count = stderr.read(&mut buffer).unwrap();
            assert!(count > 0, "sudo exited before prompt {prompt:?}");
            captured_stderr.extend_from_slice(&buffer[..count]);
        }
        Self {
            child,
            stderr,
            captured_stderr,
        }
    }

    fn finish(mut self) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        let status = self.child.wait().unwrap();
        let mut stdout = Vec::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut stdout)
            .unwrap();
        self.stderr.read_to_end(&mut self.captured_stderr).unwrap();
        (status, stdout, self.captured_stderr)
    }
}

struct NoProbe;

impl xudo_sys::InstallProbe for NoProbe {
    fn verify(&self, _argv: &[String]) -> xudo_sys::ProbeResult {
        xudo_sys::ProbeResult::Unavailable {
            reason: "not used".to_owned(),
        }
    }
}

fn write_entry(round: u64) -> String {
    let proc = VerifiedProc::open().unwrap();
    let chain = lineage(&proc, std::process::id(), 1).unwrap();
    let pin = &chain.chain[0];
    let nonce = format!(
        "{:064x}",
        u128::from(std::process::id()) << 64 | u128::from(round + 1)
    );
    let generation = load_trusted_rules(Path::new(RULES_DIR))
        .unwrap()
        .generation
        .id();
    let entry = PendingRequest {
        schema_version: REQUEST_SCHEMA_VERSION,
        nonce: nonce.clone(),
        caller_pid: pin.pid,
        caller_starttime: pin.starttime,
        action: ACTION.to_owned(),
        program: "/usr/bin/id".to_owned(),
        argv: vec!["-u".to_owned()],
        generation,
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
    root_file(
        &format!("{SPOOL_DIR}/{nonce}"),
        entry.to_json().as_bytes(),
        0o600,
    );
    nonce
}

fn make_fifo_pair(round: u64) -> (String, String, FifoGuard) {
    let base = format!("/run/xudo/race-{round}");
    let fifo_a = format!("{base}-a");
    let fifo_b = format!("{base}-b");
    let guard = FifoGuard(vec![fifo_a.clone(), fifo_b.clone()]);
    for fifo in [&fifo_a, &fifo_b] {
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            fifo.as_str(),
            rustix::fs::Mode::from_bits_truncate(0o666),
        )
        .unwrap();
        fs::set_permissions(fifo, Permissions::from_mode(0o600)).unwrap();
    }
    (fifo_a, fifo_b, guard)
}

fn spawn_sudo(fifo: &str, round: u64, lane: &str) -> (Child, String) {
    let prompt = format!("XUDO_RACE_{round}_{lane}:");
    let child = Command::new("/usr/sbin/runuser")
        .args([
            "-u",
            USER,
            "--",
            "/usr/bin/sudo",
            "-S",
            "-p",
            &prompt,
            GATE_AUTH,
        ])
        .stdin(Stdio::from(File::open(fifo).unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (child, prompt)
}

fn assert_round_outputs(
    round: u64,
    nonce: &str,
    a: &(ExitStatus, Vec<u8>, Vec<u8>),
    b: &(ExitStatus, Vec<u8>, Vec<u8>),
) -> bool {
    let outputs = [a, b];
    let successes = outputs
        .iter()
        .filter(|(status, stdout, _)| {
            status.success() && String::from_utf8_lossy(stdout).trim() == "0"
        })
        .count();
    assert_eq!(successes, 1, "round {round}: {a:?} {b:?}");
    let refusals = outputs
        .iter()
        .filter(|(status, _, _)| !status.success())
        .count();
    assert_eq!(refusals, 1, "round {round}: {a:?} {b:?}");
    assert!(
        !Path::new(&format!("{SPOOL_DIR}/{nonce}")).exists(),
        "round {round}: entry survived"
    );

    let audit = fs::read_to_string(AUDIT_LOG).unwrap();
    outputs
        .iter()
        .filter(|(status, _, _)| !status.success())
        .any(|(_, _, stderr_bytes)| {
            let stderr = String::from_utf8_lossy(stderr_bytes);
            assert!(
                stderr.contains("xudo-gate: refused (gate_failed_spool")
                    || stderr.contains("xudo-gate: refused (gate_no_pending_request"),
                "round {round}: loser did not fail closed: {stderr}"
            );
            if stderr.contains("xudo-gate: refused (gate_failed_spool") {
                let audit_line = audit
                    .lines()
                    .find(|line| {
                        line.contains(&format!("nonce={nonce}"))
                            && line.contains("\"denial\":\"gate_failed_spool\"")
                    })
                    .unwrap_or_else(|| {
                        panic!("round {round}: no audit record for {nonce}: {audit}")
                    });
                assert!(
                    audit_line.contains(GONE_DETAIL),
                    "round {round}: spool failure was not Gone: {audit_line}"
                );
                true
            } else {
                false
            }
        })
}

fn run_race_round(round: u64) -> bool {
    let nonce = write_entry(round);
    let (fifo_a, fifo_b, _fifo_guard) = make_fifo_pair(round);
    let barrier = Arc::new(Barrier::new(3));
    let writers: Vec<_> = [fifo_a.clone(), fifo_b.clone()]
        .into_iter()
        .map(|fifo| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut writer = File::options().write(true).open(fifo).unwrap();
                barrier.wait();
                writer
                    .write_all(format!("{PASSWORD}\n").as_bytes())
                    .unwrap();
            })
        })
        .collect();

    let (a_child, a_prompt) = spawn_sudo(&fifo_a, round, "a");
    let (b_child, b_prompt) = spawn_sudo(&fifo_b, round, "b");
    let a = PromptedChild::wait_for_prompt(a_child, &a_prompt);
    let b = PromptedChild::wait_for_prompt(b_child, &b_prompt);
    barrier.wait();
    let a = a.finish();
    let b = b.finish();
    for writer in writers {
        writer.join().unwrap();
    }
    assert_round_outputs(round, &nonce, &a, &b)
}

#[test]
fn two_gates_racing_one_entry_run_it_exactly_once() {
    if !begin_root_test("two_gates_racing_one_entry_run_it_exactly_once") {
        return;
    }
    let _journal = install_gate();
    let mut gone_refusals = 0;
    for round in 0..50_u64 {
        gone_refusals += usize::from(run_race_round(round));
    }
    assert!(
        gone_refusals > 0,
        "50 simultaneous releases never exercised Gone at unlink"
    );
    eprintln!("root_race: {gone_refusals} of 50 rounds produced Gone");
}
