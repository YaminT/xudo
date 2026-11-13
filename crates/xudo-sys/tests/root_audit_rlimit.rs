//! `RLIMIT_FSIZE` must not leave a torn audit record.
//!
//! A short `write` is the kernel's answer when the file is under the limit but
//! the record would pass it: no signal, a short count. The writer treats that
//! count as a failure and cuts the log back while it is still alive. A write
//! that starts already at the limit is `SIGXFSZ`, and the log is untouched
//! because nothing was written.
//!
//! `k = 0` must die by `SIGXFSZ`. That is what proves the lane left the signal
//! at its default action: an inherited ignore would let the old `write_all`
//! see `EFBIG`, cut the log back, and pass. For `k >= 1` the child must stay
//! alive, exit 1, and leave the seed log. The child is started through
//! `sh -c 'trap - XFSZ'` so a shell that arrived with the signal ignored is
//! put back to the default before this binary runs.
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
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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
    note_escalator_rlimits();
    note_signal_tear();
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
    // `0` is the write that starts already at the limit: default `SIGXFSZ`
    // kills the child and nothing is written. The rest are short counts.
    let ks = [0_usize, 1, 5, half, record_len.saturating_sub(1)];
    let xfsz = rustix::process::Signal::XFSZ.as_raw();
    for k in ks {
        restore(&path, &seed);
        let output = run_child(&dir, k);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let status = output.status.code();
        let signal = output.status.signal();
        assert!(
            stderr.contains("CHILD_BEGIN"),
            "k={k} never reached setrlimit status={status:?} signal={signal:?}\n{stderr}\n{stdout}"
        );
        if k == 0 {
            assert_eq!(
                signal,
                Some(xfsz),
                "k=0 must die by SIGXFSZ. An inherited ignore would let the old write_all pass. \
                 status={status:?} signal={signal:?}\n{stderr}\n{stdout}"
            );
            assert!(
                status.is_none(),
                "k=0 exited {status:?} instead of dying by SIGXFSZ\n{stderr}"
            );
            assert!(
                !stderr.contains("CHILD_ERR") && !stderr.contains("CHILD_WROTE"),
                "k=0 handled SIGXFSZ instead of dying by it\n{stderr}"
            );
        } else {
            assert!(
                signal.is_none(),
                "k={k} died by signal {signal:?}; the writer must cut the short write back and exit 1\n{stderr}\n{stdout}"
            );
            assert_eq!(
                status,
                Some(1),
                "k={k} status={status:?}\n{stderr}\n{stdout}"
            );
            assert!(
                stderr.contains("CHILD_ERR"),
                "k={k} did not refuse the short write\n{stderr}"
            );
            assert!(
                !stderr.contains("CHILD_WROTE"),
                "k={k} reported a successful write\n{stderr}"
            );
        }
        let after = fs::read(&path).unwrap();
        assert!(
            intact(&seed, &after),
            "k={k} tore the log (before {before}, after {after_len}, signal {signal:?})\n{stderr}",
            before = seed.len(),
            after_len = after.len()
        );
        assert_eq!(
            after, seed,
            "k={k} left bytes beyond the seed; the cut-back must restore it"
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

/// Re-invokes this test binary with `SIGXFSZ` at its default action.
///
/// `Command` is banned in privileged code; this is the test harness. The
/// shell's `trap - XFSZ` clears an inherited ignore, and `exec` keeps that
/// default. A missing shell is a loud failure, not a pass.
#[allow(clippy::disallowed_methods)]
fn run_child(dir: &Path, k: usize) -> Output {
    let exe = std::env::current_exe().unwrap();
    Command::new("/bin/sh")
        .arg("-c")
        .arg("trap - XFSZ; exec \"$0\" \"$@\"")
        .arg(&exe)
        .arg("--exact")
        .arg("rlimit_fsize_cannot_tear_an_audit_record")
        .arg("--test-threads=1")
        .arg("--")
        .arg("a0b-child")
        .arg(k.to_string())
        .arg(dir)
        .output()
        .unwrap_or_else(|error| panic!("cannot reset SIGXFSZ through /bin/sh: {error}"))
}

/// Whether each installed escalator keeps the caller's `RLIMIT_FSIZE`.
///
/// Recorded, not asserted: a reset is a fact for the orchestrator. Absent
/// tools are skipped with a message. `timeout` stops a password prompt.
/// Absolute paths avoid a `PATH` search. `Command` is allowed here only to
/// observe that fact.
#[allow(clippy::disallowed_methods)]
fn note_escalator_rlimits() {
    note_one_rlimit("sudo", "/usr/bin/sudo", &["-n"]);
    note_one_rlimit("sudo-rs", "/usr/bin/sudo-rs", &["-n"]);
    let doas_paths = ["/usr/bin/doas", "/usr/sbin/doas", "/bin/doas"];
    if let Some(path) = doas_paths
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
    {
        note_one_rlimit("doas", path, &[]);
    } else {
        eprintln!("A0E_RLIMIT doas absent (/usr/bin/doas, /usr/sbin/doas, /bin/doas)");
    }
}

#[allow(clippy::disallowed_methods)]
fn note_one_rlimit(label: &str, path: &str, prefix: &[&str]) {
    if !Path::new(path).is_file() {
        eprintln!("A0E_RLIMIT {label} absent ({path})");
        return;
    }
    if !Path::new("/usr/bin/prlimit").is_file() || !Path::new("/usr/bin/timeout").is_file() {
        eprintln!("A0E_RLIMIT {label} skipped: /usr/bin/prlimit or /usr/bin/timeout absent");
        return;
    }
    let mut command = Command::new("/usr/bin/timeout");
    command.args([
        "--signal=KILL",
        "3",
        "/usr/bin/prlimit",
        "--fsize=1048576",
        path,
    ]);
    command.args(prefix);
    command.args(["/usr/bin/prlimit", "--fsize"]);
    match command.output() {
        Ok(output) => {
            eprintln!(
                "A0E_RLIMIT {label} path={path} status={:?} signal={:?} stdout={} stderr={}",
                output.status.code(),
                output.status.signal(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(error) => eprintln!("A0E_RLIMIT {label} spawn-failed {error}"),
    }
}

/// A non-failing note of whether `SIGTERM` during one multi-page `write` can
/// leave a short file. The suite does not depend on reproducing it: page-cache
/// writes are often faster than the signal. Recorded either way.
#[allow(clippy::disallowed_methods)]
fn note_signal_tear() {
    const EXPECTED: u64 = 1024 * 1024;
    let gcc = "/usr/bin/gcc";
    let src = "/tmp/xudo-a0e-tear.c";
    let bin = "/tmp/xudo-a0e-tear";
    let out = "/tmp/xudo-a0e-tear.out";
    if !Path::new(gcc).is_file() {
        eprintln!("A0E_SIGNAL_TEAR skipped: {gcc} absent");
        return;
    }
    let source = r#"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void) {
    int fd = open("/tmp/xudo-a0e-tear.out", O_CREAT | O_TRUNC | O_WRONLY | O_SYNC, 0600);
    if (fd < 0) return 2;
    enum { N = 1024 * 1024 };
    static char buf[N];
    memset(buf, 'A', N);
    ssize_t n = write(fd, buf, N);
    fprintf(stderr, "A0E_TEAR_CHILD n=%zd\n", n);
    return n == (ssize_t)N ? 0 : 3;
}
"#;
    if fs::write(src, source).is_err() {
        eprintln!("A0E_SIGNAL_TEAR skipped: cannot write {src}");
        return;
    }
    let compiled = Command::new(gcc).args(["-O2", "-o", bin, src]).output();
    let Ok(compiled) = compiled else {
        eprintln!("A0E_SIGNAL_TEAR skipped: cannot spawn {gcc}");
        let _ = fs::remove_file(src);
        return;
    };
    if !compiled.status.success() {
        eprintln!(
            "A0E_SIGNAL_TEAR skipped: gcc failed {}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let _ = fs::remove_file(src);
        return;
    }
    let _ = fs::remove_file(out);
    let mut child = match Command::new(bin).stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("A0E_SIGNAL_TEAR skipped: spawn {error}");
            let _ = fs::remove_file(src);
            let _ = fs::remove_file(bin);
            return;
        }
    };
    let pid = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw);
    thread::sleep(Duration::from_millis(20));
    if let Some(pid) = pid {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() > Duration::from_secs(3) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                eprintln!("A0E_SIGNAL_TEAR wait-failed {error}");
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let size = fs::metadata(out).map_or(0, |meta| meta.len());
    let reproduced = size > 0 && size < EXPECTED;
    eprintln!(
        "A0E_SIGNAL_TEAR size={size} expected={EXPECTED} reproduced={reproduced} status={status:?}"
    );
    let _ = fs::remove_file(src);
    let _ = fs::remove_file(bin);
    let _ = fs::remove_file(out);
}
