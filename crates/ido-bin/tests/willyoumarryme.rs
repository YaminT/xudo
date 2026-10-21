//! The full loop, through real processes: an agent queues, a human runs, the
//! celebration confirms.
//!
//! Everything here runs the `ido` binary Cargo just built for this package —
//! never a stale one from `target/` — with a cleared environment and a private
//! home, so nothing on the developer's machine leaks in. The last test drives
//! the picker on a real pseudo-terminal, since every other test bypasses it.
//!
//! # Why a run of this suite once failed with no message, and what changed
//!
//! **An `ido` killed at exec, on macOS.** About one run in thirty, a test saw
//! its first `ido` call die from SIGKILL within two milliseconds, with nothing
//! on stdout or stderr, and the assertion that caught it printed nothing
//! either. Every test used to hard-link the binary as `willyoumarryme` and run
//! it, eight tests at a time. Looped with the kernel log captured alongside,
//! that suite lost a child in 8 of 220 runs, ten children in all, always a
//! test's first call, and the log holds a denial for every one of them, within
//! milliseconds: `AppleSystemPolicy: Security policy would not allow process`,
//! naming a path that exists nowhere. It was `target/debug/willyoumarryme`, or
//! `target/tmp/ido-second-name/bin/ido`: the directory of one name of the file
//! with the file name of another. Several names of one executable, made and
//! run in the same instant, hand Gatekeeper a path that is not there, and it
//! refuses the exec. Load alone did not do it: 60 runs under CPU, fsync and
//! process-spawn storms lost nothing. With the second name a symlink, which
//! adds no name to the file, 330 runs lost nothing and the log held no denial.
//! `the_suite_never_hard_links_the_binary_it_runs` keeps it so. The package
//! installs a hard link (`docs/todo/phase-3-packaging-and-publish.md`);
//! checking that layout is the package's job, on the platform that ships it.
//! What this suite tests is that `argv[0]` picks the celebration. To see the
//! denial yourself, loop the suite and watch
//! `log stream --predicate 'process == "kernel"'` for "would not allow".
//!
//! **Two runs at once.** `just verify` and a reviewer's `cargo test` in one
//! checkout used to remove each other's homes mid-test, and every failure that
//! caused read as `ido` failing for no reason. Each run has its own homes now.
//!
//! And every step a test stands on says how it ended, signal included, when it
//! fails: a child killed by a signal has no stderr, and a message made only of
//! stderr is how the first failure said nothing.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::disallowed_methods
)]

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const IDO: &str = env!("CARGO_BIN_EXE_ido");

/// An isolated home with `willyoumarryme` on its `PATH`.
struct TempHome {
    root: PathBuf,
}

impl TempHome {
    fn new(name: &str) -> Self {
        // Under the target directory, never /tmp, and named for this process so
        // that two runs of the suite never share a home.
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("ido-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["home", "bin", "work"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        // The second name for the binary. A symlink and never a hard link; the
        // module docs say why.
        std::os::unix::fs::symlink(IDO, root.join("bin").join("willyoumarryme")).unwrap();
        Self { root }
    }

    fn ido(&self) -> Command {
        let mut command = Command::new(IDO);
        command
            .env_clear()
            .env("HOME", self.root.join("home"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            )
            .current_dir(self.root.join("work"))
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.ido().args(args).output().unwrap()
    }

    /// Runs `ido` and requires it to succeed: for the steps a test stands on,
    /// where a silent failure would only surface as some later, unrelated
    /// assertion.
    fn run_ok(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(out.status.success(), "ido {args:?}: {}", why(&out));
        out
    }

    fn queue_file(&self) -> PathBuf {
        self.root.join("state").join("ido").join("queue.jsonl")
    }

    fn read_queue(&self) -> Vec<serde_json::Value> {
        let listed = self.run_ok(&["list", "--json"]);
        serde_json::from_slice::<Vec<serde_json::Value>>(&listed.stdout).unwrap()
    }

    fn read_log(&self) -> Vec<aido_audit::Record> {
        let text =
            std::fs::read_to_string(self.root.join("state").join("ido").join("log.jsonl")).unwrap();
        aido_audit::Chain::from_jsonl(&text)
            .unwrap()
            .records()
            .to_vec()
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        // A failing test keeps its home, for whoever reads the failure.
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// How a run ended, and what it said. The status comes first: a child killed
/// by a signal wrote nothing, and a message made only of stderr is empty.
fn why(out: &Output) -> String {
    format!("{}; stderr: {:?}", out.status, text(&out.stderr))
}

#[test]
fn an_agent_queues_and_the_human_runs_it() {
    let home = TempHome::new("acceptance");

    // 1. The agent queues it and does not block.
    let queued = home.run_ok(&["queue", "-m", "she said yes", "--", "willyoumarryme"]);
    assert!(text(&queued.stdout).contains("Run `ido` to execute it."));

    // 2. Exactly one entry is buffered, argv stored as a vector.
    let queue = home.read_queue();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0]["argv"], serde_json::json!(["willyoumarryme"]));
    assert_eq!(queue[0]["status"], "ready");

    // 3. The human runs it. --yes only because there is no tty here; the
    //    interactive path is the pseudo-terminal test below.
    let run = home.run_ok(&["run", "--all", "--yes", "--no-animation"]);
    assert!(
        text(&run.stdout).contains("ido works."),
        "{}",
        text(&run.stdout)
    );

    // 4. The queue is now empty and the run is in the log.
    assert!(home.read_queue().is_empty());
    let log = home.read_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].outcome, aido_audit::Outcome::Exited { code: 0 });
    assert_eq!(log[0].argv, ["willyoumarryme"]);
}

#[test]
fn the_second_name_is_the_celebration() {
    let home = TempHome::new("second-name");
    let out = Command::new(home.root.join("bin").join("willyoumarryme"))
        .arg("--no-animation")
        .env_clear()
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", why(&out));
    assert_eq!(text(&out.stdout), "ido works.\n");
}

#[test]
fn the_suite_never_hard_links_the_binary_it_runs() {
    // Each new name for the file under test is another chance for the kernel
    // to refuse an exec of it, at random, with a SIGKILL and nothing said. A
    // symlink adds none; a hard link adds one. The module docs have the log.
    let links = || std::fs::metadata(IDO).unwrap().nlink();
    let before = links();
    let home = TempHome::new("links");
    assert_eq!(
        links(),
        before,
        "the second name must be a symlink: a hard link to the binary under test is \
         how this suite once had its children killed at exec on macOS"
    );
    assert!(
        std::fs::symlink_metadata(home.root.join("bin").join("willyoumarryme"))
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn a_child_killed_by_a_signal_is_reported_by_its_signal() {
    // The first failure of this suite said nothing, because its only message
    // was the child's stderr, and a child killed at exec has written none.
    let out = Command::new("/bin/sh")
        .args(["-c", "kill -9 $$"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stderr.is_empty());
    assert!(why(&out).contains("signal: 9"), "{}", why(&out));
}

#[test]
fn a_home_belongs_to_the_run_that_made_it() {
    // The attack: a second `cargo test` in the same checkout, whose first act
    // is to delete the homes it is about to make. Named for the test alone,
    // those are the first run's, mid-test.
    let home = TempHome::new("belongs");
    let name = home.root.file_name().unwrap().to_str().unwrap().to_owned();
    assert!(name.contains(&std::process::id().to_string()), "{name}");
}

#[test]
fn argv_is_never_passed_through_a_shell() {
    let home = TempHome::new("no-shell");
    home.run_ok(&["queue", "--", "/bin/echo", "$(id)", "a;b", "`id`", "*"]);
    let run = home.run_ok(&["run", "--all", "--yes"]);
    // Every token arrives literally: no substitution, no splitting, no glob.
    assert!(
        text(&run.stdout).contains("$(id) a;b `id` *\n"),
        "{}",
        text(&run.stdout)
    );
}

#[test]
fn no_tty_falls_back_to_list_and_runs_nothing() {
    let home = TempHome::new("no-tty");
    home.run_ok(&["queue", "--", "touch", "should-not-exist"]);
    let bare = home.run_ok(&[]);
    assert!(
        text(&bare.stdout).contains("#1 ready"),
        "{}",
        text(&bare.stdout)
    );
    assert!(!home.root.join("work").join("should-not-exist").exists());
    assert_eq!(home.read_queue().len(), 1);
}

#[test]
fn another_users_queue_is_unreachable() {
    let home = TempHome::new("private");
    home.run_ok(&["queue", "--", "true"]);
    let file = std::fs::metadata(home.queue_file()).unwrap();
    let dir = std::fs::metadata(home.queue_file().parent().unwrap()).unwrap();
    assert_eq!(file.mode() & 0o777, 0o600);
    assert_eq!(dir.mode() & 0o777, 0o700);

    // A queue someone else can write is refused, not read.
    std::fs::set_permissions(
        home.queue_file(),
        std::os::unix::fs::PermissionsExt::from_mode(0o620),
    )
    .unwrap();
    let refused = home.run(&["list"]);
    assert_eq!(refused.status.code(), Some(2), "{}", why(&refused));
    assert!(text(&refused.stderr).contains("writable by group or world"));
}

#[test]
fn a_dependency_cycle_is_refused_at_queue_time() {
    let home = TempHome::new("cycle");
    let out = home.run(&["queue", "--needs", "1", "--", "true"]);
    assert_eq!(out.status.code(), Some(2), "{}", why(&out));
    assert!(text(&out.stderr).contains("already exists"));
    assert!(home.read_queue().is_empty());
}

#[test]
fn exit_statuses_say_what_happened() {
    let home = TempHome::new("exits");
    let usage = home.run(&["frobnicate"]);
    assert_eq!(usage.status.code(), Some(2), "usage: {}", why(&usage));
    home.run_ok(&["queue", "--", "false"]);
    let failed = home.run(&["run", "1", "--yes"]);
    assert_eq!(
        failed.status.code(),
        Some(1),
        "a command failed: {}",
        why(&failed)
    );
    let version = home.run(&["--version"]);
    assert_eq!(version.status.code(), Some(0), "{}", why(&version));
}

/// The picker on a real pseudo-terminal: list, select with space, run with
/// enter, see the celebration. The one test that exercises raw mode.
#[test]
fn the_picker_runs_the_selection_on_a_real_terminal() {
    use rustix::fs::{OFlags, fcntl_setfl};
    use rustix::io::Errno;
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    let home = TempHome::new("pty");
    home.run_ok(&["queue", "-m", "she said yes", "--", "willyoumarryme"]);

    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&master).unwrap();
    unlockpt(&master).unwrap();
    let name = ptsname(&master, Vec::new()).unwrap();
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(name.to_str().unwrap())
        .unwrap();
    rustix::termios::tcsetwinsize(
        &slave,
        rustix::termios::Winsize {
            ws_row: 30,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .unwrap();

    let mut child = home
        .ido()
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .spawn()
        .unwrap();
    drop(slave);
    fcntl_setfl(&master, OFlags::NONBLOCK).unwrap();

    let mut transcript = Vec::new();
    let mut wait_for = |needle: &str| -> bool {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut buffer = [0_u8; 4096];
        while Instant::now() < deadline {
            match rustix::io::read(&master, &mut buffer) {
                Ok(0) | Err(Errno::IO) => break,
                Ok(n) => transcript.extend_from_slice(&buffer[..n]),
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
            if text(&transcript).contains(needle) {
                return true;
            }
        }
        text(&transcript).contains(needle)
    };

    assert!(
        wait_for("willyoumarryme"),
        "the picker never listed the entry"
    );
    assert!(wait_for("space select"), "the picker never drew its footer");
    rustix::io::write(&master, b" ").unwrap();
    std::thread::sleep(Duration::from_millis(100));
    rustix::io::write(&master, b"\r").unwrap();
    let celebrated = wait_for("ido works.");
    if !celebrated {
        // A picker that is still waiting for a key must fail this test, not
        // hang the whole suite in the wait below.
        let _ = child.kill();
    }
    let status = child.wait().unwrap();
    assert!(celebrated, "no celebration: {:?}", text(&transcript));
    assert!(status.success());
    assert!(home.read_queue().is_empty());
}
