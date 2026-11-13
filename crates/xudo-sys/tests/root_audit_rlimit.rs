//! `RLIMIT_FSIZE` must not leave a torn audit record.
//!
//! A short `write` is the kernel's answer when the file is under the limit but
//! the record would pass it: no signal, a short count. The writer treats that
//! count as a failure and cuts the log back while it is still alive. A write
//! that starts already at the limit is `SIGXFSZ`, and the log is untouched
//! because nothing was written. Either way the bytes left behind are the
//! previous log, or that log plus one whole record.
//!
//! The child is this test binary again, so the signal cannot kill the parent
//! that checks the log afterwards.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use xudo_tests::root_lane::root_guard;

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use xudo_audit::{Decision, Record, verify_log};
use xudo_sys::{AUDIT_FILE_NAME, AuditSink, JsonlLog};

const DIR: &str = "/var/lib/xudo-a0b-rlimit";

fn begin_root_test(test: &str) -> bool {
    root_guard(test)
}

fn build_record(previous: Option<&Record>) -> Record {
    Record::after(
        previous,
        Decision::Denied,
        vec!["a0b-rlimit".to_owned()],
        "unattested",
    )
    .with_denial("rlimit_fsize")
}

/// `Some` when this process is the re-invoked child. The marker rides after
/// `--`, which the test harness does not read, so the role is not an
/// environment variable.
fn child_request() -> Option<(u64, PathBuf)> {
    let mut args = std::env::args();
    args.find(|arg| arg == "--")?;
    if args.next().as_deref() != Some("a0b-child") {
        return None;
    }
    let k = args.next()?.parse().ok()?;
    Some((k, PathBuf::from(args.next()?)))
}

#[test]
fn rlimit_fsize_cannot_tear_an_audit_record() {
    if !begin_root_test("rlimit_fsize_cannot_tear_an_audit_record") {
        return;
    }
    if let Some((k, dir)) = child_request() {
        child(k, &dir);
    } else {
        parent();
    }
}

fn child(k: u64, dir: &Path) -> ! {
    let path = dir.join(AUDIT_FILE_NAME);
    let len = fs::metadata(&path).unwrap().len();
    let limit = len.saturating_add(k);
    eprintln!("CHILD_BEGIN len={len} k={k} limit={limit}");
    rustix::process::setrlimit(
        rustix::process::Resource::Fsize,
        rustix::process::Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        },
    )
    .unwrap();
    let mut log = JsonlLog::in_dir(dir);
    match log.append(&build_record) {
        Ok(_receipt) => {
            eprintln!("CHILD_WROTE");
            std::process::exit(0);
        }
        Err(error) => {
            eprintln!("CHILD_ERR {error}");
            std::process::exit(1);
        }
    }
}

fn parent() {
    note_sudo_rlimit();
    let dir = PathBuf::from(DIR);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

    let mut log = JsonlLog::in_dir(&dir);
    let _ = log.append(&build_record).unwrap();
    let path = dir.join(AUDIT_FILE_NAME);
    let seed = fs::read(&path).unwrap();
    let chain = verify_log(&seed).unwrap();
    let record_len = build_record(chain.records().last())
        .to_jsonl()
        .len()
        .saturating_add(1);
    assert!(record_len > 5, "record is {record_len} bytes");

    let half = record_len.saturating_div(2);
    let ks = [1_usize, 5, half, record_len.saturating_sub(1)];
    for k in ks {
        restore(&path, &seed);
        let output = run_child(&dir, k);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let status = output.status.code();
        let signal = output.status.signal();
        let reported =
            stderr.contains("CHILD_ERR") || stderr.contains("CHILD_WROTE") || signal.is_some();
        assert!(
            stderr.contains("CHILD_BEGIN") && reported,
            "k={k} status={status:?} signal={signal:?}\n{stderr}\n{stdout}"
        );
        let after = fs::read(&path).unwrap();
        assert!(
            intact(&seed, &after),
            "k={k} tore the log (before {before}, after {after_len}, signal {signal:?})\n{stderr}",
            before = seed.len(),
            after_len = after.len()
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// The log is the seed, or the seed plus one whole extra record. Either way
/// the verifier accepts it.
fn intact(before: &[u8], after: &[u8]) -> bool {
    if verify_log(after).is_err() {
        return false;
    }
    if after == before {
        return true;
    }
    if !after.starts_with(before) {
        return false;
    }
    let extra = &after[before.len()..];
    let Some(line) = extra.strip_suffix(b"\n") else {
        return false;
    };
    if line.is_empty() || line.contains(&b'\n') {
        return false;
    }
    let before_len = verify_log(before).map_or(0, |chain| chain.len());
    verify_log(after).map(|chain| chain.len()) == Ok(before_len.saturating_add(1))
}

fn restore(path: &Path, seed: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(seed).unwrap();
    file.sync_all().unwrap();
}

/// Re-invokes this test binary. `Command` is banned in privileged code; this
/// is the test harness spawning itself so `SIGXFSZ` stays in the child.
#[allow(clippy::disallowed_methods)]
fn run_child(dir: &Path, k: usize) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("rlimit_fsize_cannot_tear_an_audit_record")
        .arg("--test-threads=1")
        .arg("--")
        .arg("a0b-child")
        .arg(k.to_string())
        .arg(dir)
        .output()
        .unwrap()
}

/// Whether `sudo -n` keeps the caller's `RLIMIT_FSIZE`. Recorded, not
/// asserted: a reset is a fact for the orchestrator. The absolute paths avoid
/// a `PATH` search. `Command` is allowed here only to observe that fact.
#[allow(clippy::disallowed_methods)]
fn note_sudo_rlimit() {
    match Command::new("/usr/bin/prlimit")
        .args([
            "--fsize=1048576",
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/prlimit",
            "--fsize",
        ])
        .output()
    {
        Ok(output) => {
            let status = output.status.code();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("A0B_SUDO_RLIMIT status={status:?} stdout={stdout} stderr={stderr}");
        }
        Err(error) => eprintln!("A0B_SUDO_RLIMIT spawn-failed {error}"),
    }
}
