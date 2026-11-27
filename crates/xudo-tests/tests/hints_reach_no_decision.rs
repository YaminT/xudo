//! No decision reads a caller hint (invariant 1).
//!
//! A caller chooses its `comm`, `exe`, command line and environment, so the
//! hints read from them are recorded in the audit trail and nowhere else. This
//! reads every library source in the workspace, outside its test module, and
//! fails on a hint token in any file but the few that read, carry or record
//! hints. Each of those is listed with the reason it may.
//!
//! Standard library alone, like the crate inventory.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// What names a hint in code.
const TOKENS: &[&str] = &[
    "CallerHints",
    "pinned_hints",
    "requester_hints",
    "peer_hints",
    ".hints",
    "hint_exe",
    "hint_cmdline",
    "hint_claudecode",
    "hint_comm",
    "ProcFile::Exe",
    "ProcFile::Cmdline",
    "ProcFile::Environ",
];

/// The files that may name a hint, and why.
const ALLOWED: &[(&str, &str)] = &[
    (
        "crates/xudo-sys/src/caller_hints.rs",
        "defines the hints; they render to audit lines only",
    ),
    ("crates/xudo-sys/src/lib.rs", "re-exports them"),
    (
        "crates/xudo-sys/src/peer.rs",
        "the /proc reads behind the broker's seam",
    ),
    (
        "crates/xudo-policy/src/caller.rs",
        "defines CallerFacts::hints, which the engine never reads",
    ),
    (
        "crates/xudo/src/doctor.rs",
        "counts the front end's hints for the operator",
    ),
    (
        "crates/xudod/src/identify.rs",
        "reads the peer's hints while the pidfd holds it",
    ),
    (
        "crates/xudod/src/record.rs",
        "writes them into the audit record",
    ),
    (
        "crates/xudo-gate/src/run.rs",
        "reads the requester's hints into the audit evidence",
    ),
];

fn repo() -> PathBuf {
    Path::new(MANIFEST_DIR).join("../..")
}

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            found.push(path);
        }
    }
}

/// Every library source, as a path relative to the repository.
fn library_sources() -> Vec<String> {
    let mut found = Vec::new();
    for krate in fs::read_dir(repo().join("crates")).unwrap() {
        let src = krate.unwrap().path().join("src");
        if src.is_dir() {
            sources(&src, &mut found);
        }
    }
    let root = repo().canonicalize().unwrap();
    let mut relative: Vec<String> = found
        .iter()
        .map(|path| {
            let path = path.canonicalize().unwrap();
            path.strip_prefix(&root).unwrap().display().to_string()
        })
        .collect();
    relative.sort();
    relative
}

/// The source before its test module: tests may build any hint they like.
fn without_tests(source: &str) -> &str {
    source
        .find("#[cfg(test)]\nmod ")
        .map_or(source, |at| source.get(..at).unwrap_or(source))
}

/// The hint tokens `source` names outside its tests, if `name` may not.
fn problems(name: &str, source: &str) -> Vec<String> {
    if ALLOWED.iter().any(|(allowed, _)| *allowed == name) {
        return Vec::new();
    }
    let code = without_tests(source);
    TOKENS
        .iter()
        .filter(|token| code.contains(**token))
        .map(|token| format!("{name}: names `{token}` outside its tests"))
        .collect()
}

#[test]
fn no_decision_code_reads_a_caller_hint() {
    let files = library_sources();
    assert!(files.len() > 50, "found only {} sources", files.len());
    let found: Vec<String> = files
        .iter()
        .flat_map(|name| problems(name, &fs::read_to_string(repo().join(name)).unwrap()))
        .collect();
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn every_allowed_file_exists_and_names_a_hint() {
    // A stale entry would let a new file of the same name in unread.
    for (name, why) in ALLOWED {
        let source = fs::read_to_string(repo().join(name)).unwrap();
        let code = without_tests(&source);
        assert!(
            TOKENS.iter().any(|token| code.contains(token)),
            "{name} ({why}) names no hint any more: drop it from ALLOWED"
        );
    }
}

#[test]
fn the_hints_type_has_no_accessor_a_decision_could_read() {
    // Only constructors and the audit rendering: no field is public and no
    // method hands out a single value to branch on.
    let source = fs::read_to_string(repo().join("crates/xudo-sys/src/caller_hints.rs")).unwrap();
    let code = without_tests(&source);
    let public: Vec<&str> = code
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .filter(|line| !line.starts_with("pub const") && !line.starts_with("pub struct"))
        .map(|line| {
            let name = line.strip_prefix("pub fn ").unwrap_or(line);
            name.split(['(', '<']).next().unwrap_or(name)
        })
        .collect();
    assert_eq!(
        public,
        ["unavailable", "from_reads", "evidence", "pinned_hints"]
    );
    // And the struct's fields are private.
    assert!(
        code.contains("pub struct CallerHints {\n    exe: String,"),
        "{code}"
    );
}

#[test]
fn the_scan_catches_a_decision_that_branches_on_a_hint() {
    let decision = "fn decide(identity: &PeerIdentity) -> bool {\n    \
                    identity.hints.evidence()[2] == \"hint_claudecode=\\\"1\\\"\"\n}\n";
    assert_eq!(
        problems("crates/xudod/src/policy.rs", decision),
        [
            "crates/xudod/src/policy.rs: names `.hints` outside its tests",
            "crates/xudod/src/policy.rs: names `hint_claudecode` outside its tests",
        ]
    );
    // The same text in a test module, or in an allowed file, is fine.
    let tested = format!("fn x() {{}}\n#[cfg(test)]\nmod tests {{\n{decision}}}\n");
    assert!(problems("crates/xudod/src/policy.rs", &tested).is_empty());
    assert!(problems("crates/xudod/src/record.rs", decision).is_empty());
}
