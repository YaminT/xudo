//! Two real sudo invocations racing to consume one real gate entry.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods,
    clippy::arithmetic_side_effects
)]

use std::fs::{self, File, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{PermissionsExt, chown};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{Command, Stdio};
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
    Journal {
        socket: journal,
        reader: Some(reader),
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
    };
    root_file(
        &format!("{SPOOL_DIR}/{nonce}"),
        entry.to_json().as_bytes(),
        0o600,
    );
    nonce
}

#[test]
fn two_gates_racing_one_entry_run_it_exactly_once() {
    if !begin_root_test("two_gates_racing_one_entry_run_it_exactly_once") {
        return;
    }
    let _journal = install_gate();
    let mut gone_refusals = 0;
    for round in 0..50_u64 {
        let nonce = write_entry(round);
        let base = format!("/run/xudo/race-{round}");
        let fifo_a = format!("{base}-a");
        let fifo_b = format!("{base}-b");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            fifo_a.as_str(),
            rustix::fs::Mode::from_bits_truncate(0o666),
        )
        .unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            fifo_b.as_str(),
            rustix::fs::Mode::from_bits_truncate(0o666),
        )
        .unwrap();
        chown(&fifo_a, Some(1000), Some(1000)).unwrap();
        chown(&fifo_b, Some(1000), Some(1000)).unwrap();
        fs::set_permissions(&fifo_a, Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&fifo_b, Permissions::from_mode(0o600)).unwrap();
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
        let child = |fifo: &str| {
            Command::new("/usr/sbin/runuser")
                .args(["-u", USER, "--", "/usr/bin/sudo", "-S", GATE_AUTH])
                .stdin(Stdio::from(File::open(fifo).unwrap()))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let a = child(&fifo_a);
        let b = child(&fifo_b);
        barrier.wait();
        let a = a.wait_with_output().unwrap();
        let b = b.wait_with_output().unwrap();
        for writer in writers {
            writer.join().unwrap();
        }
        let successes = [&a, &b]
            .into_iter()
            .filter(|output| {
                output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "0"
            })
            .count();
        assert_eq!(successes, 1, "round {round}: {a:?} {b:?}");
        let refusals = [&a, &b]
            .into_iter()
            .filter(|output| !output.status.success())
            .count();
        assert_eq!(refusals, 1, "round {round}: {a:?} {b:?}");
        assert!(
            !Path::new(&format!("{SPOOL_DIR}/{nonce}")).exists(),
            "round {round}: entry survived"
        );
        fs::remove_file(fifo_a).unwrap();
        fs::remove_file(fifo_b).unwrap();
        for output in [&a, &b] {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains("xudo-gate: refused (gate_failed_spool")
                        || stderr.contains("xudo-gate: refused (gate_no_pending_request"),
                    "round {round}: loser did not fail closed on the consumed entry: {output:?}"
                );
                if stderr.contains("xudo-gate: refused (gate_failed_spool") {
                    gone_refusals += 1;
                }
            }
        }
    }
    assert!(
        gone_refusals > 0,
        "50 simultaneous releases never exercised Gone at unlink"
    );
}
