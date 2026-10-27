//! The real trail's scaffolding for the root lane: what a root test needs
//! around `/var/lib/aido`, `/run/aido`, `/etc/aido`, and journald, shared by
//! every `tests/root_*.rs` that reads or breaks the audit trail.
//!
//! One file, included by each of them with `#[path]`, because a test target is
//! its own crate and a shared helper crate would be one more thing to keep out
//! of a shipped binary. It sits in a subdirectory of `tests/` so cargo does not
//! build it as a target of its own.
//!
//! The trail under test is the **real** one: `AuditTrail::system(..)`, whose
//! log is `/var/lib/aido/audit.jsonl` behind the trust walk and whose mirror is
//! the datagram socket at `/run/systemd/journal/socket`. The only fake is the
//! far end of that socket, bound here by the test, because a container has no
//! journald: it collects what is sent, so a test can match every line of the
//! file with the datagram that mirrored it.
//!
//! Everything is root-only and rewrites the container's real filesystem. Tests
//! run one at a time (`ci/root-test.sh`); each begins with [`Host::fresh`],
//! which leaves nothing of the one before.

#![allow(dead_code, unreachable_pub)]

use std::fs::{self, File, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, chown};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};

/// The trail's directory.
pub const AUDIT_DIR: &str = "/var/lib/aido";
/// The trail's file.
pub const AUDIT_FILE: &str = "/var/lib/aido/audit.jsonl";
/// The spool the broker mints into and the gate reads.
pub const SPOOL: &str = "/run/aido/req";
/// The ruleset the broker and the gate both read.
pub const RULES_DIR: &str = "/etc/aido/rules.d";
/// journald's native-protocol socket.
pub const JOURNAL: &str = "/run/systemd/journal/socket";

/// The one rule the tests allow: `true probe`, a program every image has and
/// that no test ever really runs.
pub const PROGRAM: &str = "/usr/bin/true";
/// What the rule is called.
pub const ACTION: &str = "aido.d1.probe";

const RULES: &str = r#"
[[action]]
id = "aido.d1.probe"
tier = "diag-read"
exe = "/usr/bin/true"
args = [{ name = "verb", matcher = { literal = "probe" } }]
"#;

/// An owner no test account has, for the directory a hostile owner holds.
const NOT_ROOT: u32 = 1000;

/// `true` when the calling test should go on; otherwise says `SKIPPED` on
/// standard error, which `ci/root-test.sh` turns into a failure.
///
/// Root is judged by the files this process makes: the standard library has no
/// `geteuid`, and `unsafe` is forbidden.
pub fn root_or_skip(test: &str) -> bool {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(&dir).unwrap();
    let probe = dir.join(format!("identity-{test}"));
    File::create(&probe).unwrap();
    if fs::metadata(&probe).unwrap().uid() == 0 {
        return true;
    }
    eprintln!("SKIPPED: {test} needs uid 0; ci/root-test.sh runs it for real");
    false
}

/// The three ways the trail can be made unwritable that root cannot ignore.
/// (A mode does not: root writes through `chmod 000`.)
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// `audit.jsonl` is a directory.
    LogIsADirectory,
    /// `/var/lib/aido` belongs to a user, so the trust walk refuses it.
    DirectoryNotRoots,
    /// Nothing listens at journald's socket, so the mirror refuses.
    NoJournal,
}

/// Every fault, for a test that must hold under each.
pub const FAULTS: [Fault; 3] = [
    Fault::LogIsADirectory,
    Fault::DirectoryNotRoots,
    Fault::NoJournal,
];

/// One datagram journald was sent, reduced to what a test matches on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mirrored {
    /// `SYSLOG_IDENTIFIER`: the binary that wrote it.
    pub identifier: String,
    /// `AIDO_SEQ`.
    pub seq: u64,
    /// `AIDO_HASH`.
    pub hash: String,
}

/// The container as the trail's tests find it: a fresh trail directory, spool,
/// ruleset, and a listener where journald would be.
pub struct Host {
    journal: UnixDatagram,
}

impl Host {
    /// Resets `/var/lib/aido`, `/run/aido`, `/etc/aido`, and the journal
    /// socket to what a correctly installed host has, with the one rule.
    pub fn fresh() -> Self {
        reset_dir(AUDIT_DIR, 0o700);
        let _ = fs::remove_dir_all("/run/aido");
        make_dir("/run/aido", 0o755);
        make_dir(SPOOL, 0o700);
        let _ = fs::remove_dir_all("/etc/aido");
        make_dir("/etc/aido", 0o755);
        make_dir(RULES_DIR, 0o755);
        let rules = Path::new(RULES_DIR).join("10-d1.toml");
        fs::write(&rules, RULES).unwrap();
        fs::set_permissions(&rules, Permissions::from_mode(0o644)).unwrap();
        make_dir("/run/systemd", 0o755);
        make_dir("/run/systemd/journal", 0o755);
        let _ = fs::remove_file(JOURNAL);
        let journal = UnixDatagram::bind(JOURNAL).unwrap();
        journal.set_nonblocking(true).unwrap();
        Self { journal }
    }

    /// The log's bytes, or nothing when there is no file.
    pub fn log(&self) -> Vec<u8> {
        fs::read(AUDIT_FILE).unwrap_or_default()
    }

    /// The log's records, which must verify as one chain.
    pub fn chain(&self) -> Vec<aido_audit::Record> {
        aido_audit::verify_log(&self.log())
            .unwrap()
            .records()
            .to_vec()
    }

    /// Everything journald has been sent since the last call.
    pub fn mirrored(&self) -> Vec<Mirrored> {
        let mut seen = Vec::new();
        let mut buffer = vec![0u8; 256 * 1024];
        while let Ok(count) = self.journal.recv(&mut buffer) {
            let text = String::from_utf8_lossy(&buffer[..count]).into_owned();
            let field = |name: &str| {
                text.lines()
                    .find_map(|line| line.strip_prefix(&format!("{name}=")))
                    .unwrap_or_default()
                    .to_owned()
            };
            seen.push(Mirrored {
                identifier: field("SYSLOG_IDENTIFIER"),
                seq: field("AIDO_SEQ").parse().unwrap(),
                hash: field("AIDO_HASH"),
            });
        }
        seen
    }

    /// The names in the spool.
    pub fn spool(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(SPOOL)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// Makes the trail unwritable, one way.
    pub fn break_trail(&self, fault: Fault) {
        match fault {
            Fault::LogIsADirectory => {
                let _ = fs::remove_file(AUDIT_FILE);
                fs::create_dir(AUDIT_FILE).unwrap();
            }
            Fault::DirectoryNotRoots => chown(AUDIT_DIR, Some(NOT_ROOT), Some(NOT_ROOT)).unwrap(),
            Fault::NoJournal => fs::remove_file(JOURNAL).unwrap(),
        }
    }
}

/// Appends raw bytes to the log, as an attacker with root would.
pub fn append_to_log(bytes: &[u8]) {
    let mut file = fs::OpenOptions::new().append(true).open(AUDIT_FILE).unwrap();
    file.write_all(bytes).unwrap();
}

/// Rewrites the log to these bytes, keeping its mode.
pub fn replace_log(bytes: &[u8]) {
    fs::write(AUDIT_FILE, bytes).unwrap();
}

fn make_dir(path: &str, mode: u32) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn reset_dir(path: &str, mode: u32) {
    let _ = fs::remove_dir_all(path);
    make_dir(path, mode);
}
