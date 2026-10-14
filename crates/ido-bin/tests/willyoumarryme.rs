//! The full loop, through real processes: an agent queues, a human runs, the
//! celebration confirms.
//!
//! Everything here runs the `ido` binary Cargo just built for this package —
//! never a stale one from `target/` — with a cleared environment and a private
//! home, so nothing on the developer's machine leaks in. The last test drives
//! the picker on a real pseudo-terminal, since every other test bypasses it.

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
        // Under the target directory, never /tmp.
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("ido-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["home", "bin", "work"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        // The second name for the same inode, as the package installs it.
        std::fs::hard_link(IDO, root.join("bin").join("willyoumarryme")).unwrap();
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

    fn queue_file(&self) -> PathBuf {
        self.root.join("state").join("ido").join("queue.jsonl")
    }

    fn read_queue(&self) -> Vec<serde_json::Value> {
        let listed = self.run(&["list", "--json"]);
        assert!(listed.status.success());
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

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn an_agent_queues_and_the_human_runs_it() {
    let home = TempHome::new("acceptance");

    // 1. The agent queues it and does not block.
    let queued = home.run(&["queue", "-m", "she said yes", "--", "willyoumarryme"]);
    assert!(queued.status.success(), "{}", text(&queued.stderr));
    assert!(text(&queued.stdout).contains("Run `ido` to execute it."));

    // 2. Exactly one entry is buffered, argv stored as a vector.
    let queue = home.read_queue();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0]["argv"], serde_json::json!(["willyoumarryme"]));
    assert_eq!(queue[0]["status"], "ready");

    // 3. The human runs it. --yes only because there is no tty here; the
    //    interactive path is the pseudo-terminal test below.
    let run = home.run(&["run", "--all", "--yes", "--no-animation"]);
    assert!(run.status.success(), "{}", text(&run.stderr));
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
    assert!(out.status.success());
    assert_eq!(text(&out.stdout), "ido works.\n");
}

#[test]
fn argv_is_never_passed_through_a_shell() {
    let home = TempHome::new("no-shell");
    let queued = home.run(&["queue", "--", "/bin/echo", "$(id)", "a;b", "`id`", "*"]);
    assert!(queued.status.success());
    let run = home.run(&["run", "--all", "--yes"]);
    assert!(run.status.success(), "{}", text(&run.stderr));
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
    home.run(&["queue", "--", "touch", "should-not-exist"]);
    let bare = home.run(&[]);
    assert!(bare.status.success());
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
    home.run(&["queue", "--", "true"]);
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
    assert_eq!(refused.status.code(), Some(2));
    assert!(text(&refused.stderr).contains("writable by group or world"));
}

#[test]
fn a_dependency_cycle_is_refused_at_queue_time() {
    let home = TempHome::new("cycle");
    let out = home.run(&["queue", "--needs", "1", "--", "true"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("already exists"));
    assert!(home.read_queue().is_empty());
}

#[test]
fn exit_statuses_say_what_happened() {
    let home = TempHome::new("exits");
    assert_eq!(home.run(&["frobnicate"]).status.code(), Some(2), "usage");
    home.run(&["queue", "--", "false"]);
    assert_eq!(
        home.run(&["run", "1", "--yes"]).status.code(),
        Some(1),
        "a command failed"
    );
    assert_eq!(home.run(&["--version"]).status.code(), Some(0));
}

/// The picker on a real pseudo-terminal: list, select with space, run with
/// enter, see the celebration. The one test that exercises raw mode.
#[test]
fn the_picker_runs_the_selection_on_a_real_terminal() {
    use rustix::fs::{OFlags, fcntl_setfl};
    use rustix::io::Errno;
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};

    let home = TempHome::new("pty");
    home.run(&["queue", "-m", "she said yes", "--", "willyoumarryme"]);

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
    let status = child.wait().unwrap();
    assert!(celebrated, "no celebration: {:?}", text(&transcript));
    assert!(status.success());
    assert!(home.read_queue().is_empty());
}
