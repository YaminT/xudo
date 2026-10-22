//! No root test can run as root outside the lane's container.
//!
//! A root test writes the real `/etc`, replaces the installed gate and deletes
//! the audit log. `just test` enables every feature, so on a real machine run
//! as root those tests would do it to the machine. Each begins with the shared
//! guard (`crates/aido-tests/src/root_lane.rs`), which panics as root without the sentinel
//! `ci/root-test.sh` creates. A guard one test forgot is a test that runs
//! unguarded, so this reads every root test file and holds it to the rule:
//!
//! * the file includes the one shared guard, and defines no guard of its own;
//! * every `#[test]` function's first statement is `begin_root_test(`, so
//!   nothing touches the filesystem before the guard has spoken;
//! * the lane script writes exactly the sentinel the guard looks for.
//!
//! Standard library alone, like the crate inventory.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
const INCLUDE: &str = "use aido_tests::root_lane::";

fn repo() -> PathBuf {
    Path::new(MANIFEST_DIR).join("../..")
}

fn root_test_files() -> Vec<PathBuf> {
    let mut found = Vec::new();
    for krate in fs::read_dir(repo().join("crates")).unwrap() {
        let tests = krate.unwrap().path().join("tests");
        let Ok(entries) = fs::read_dir(&tests) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().as_encoded_bytes();
            if name.starts_with(b"root_") && path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// What is wrong with one root test file, one finding per line.
fn problems(name: &str, source: &str) -> Vec<String> {
    let mut found = Vec::new();
    if !source.contains(INCLUDE) {
        found.push(format!("{name}: does not use the shared guard"));
    }
    if source.contains("fn root_or_skip") || source.contains("fn root_guard") {
        found.push(format!("{name}: defines a guard of its own"));
    }
    let lines: Vec<&str> = source.lines().collect();
    for (at, line) in lines
        .iter()
        .enumerate()
        .map(|(at, line)| (at.saturating_add(1), line))
    {
        if line.trim() != "#[test]" {
            continue;
        }
        // The function's body opens on the first line that ends in `{`, and its
        // first statement is the first non-comment line after that.
        let mut rest = lines.iter().skip(at);
        let header = rest.by_ref().find(|l| l.trim_end().ends_with('{'));
        let first = rest
            .map(|l| l.trim())
            .find(|l| !l.is_empty() && !l.starts_with("//"));
        let ok = header.is_some() && first.is_some_and(|l| l.contains("begin_root_test("));
        if !ok {
            found.push(format!(
                "{name}:{at}: a #[test] whose first statement is not begin_root_test(..), \
                 so it runs unguarded"
            ));
        }
    }
    found
}

#[test]
fn every_root_test_begins_with_the_shared_guard() {
    let files = root_test_files();
    assert!(files.len() >= 5, "found only {files:?}");
    let mut all = Vec::new();
    for path in &files {
        let name = path.strip_prefix(repo()).unwrap().display().to_string();
        all.extend(problems(&name, &fs::read_to_string(path).unwrap()));
    }
    assert!(all.is_empty(), "{}", all.join("\n"));
}

#[test]
fn the_check_catches_a_test_that_forgot_the_guard() {
    let source = format!(
        "{INCLUDE}root_guard;\n#[test]\nfn a() {{\n    if !begin_root_test(\"a\") {{ return; }}\n}}\n\
         #[test]\nfn b() {{\n    fs::remove_file(\"/etc/doas.conf\").unwrap();\n}}\n"
    );
    let found = problems("x.rs", &source);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found.iter().all(|f| f.contains("unguarded")), "{found:?}");
    // Nor does a file that carries its own, weaker, guard pass.
    let own = "#[test]\nfn a() {\n    begin_root_test(\"a\");\n}\nfn root_or_skip() {}\n";
    assert_eq!(problems("y.rs", own).len(), 2);
}

/// The value of `const <name>: &str = "...";` in the guard, which may continue
/// on the next line.
fn guard_constant(name: &str) -> String {
    let source = fs::read_to_string(repo().join("crates/aido-tests/src/root_lane.rs")).unwrap();
    let statement = source
        .split(&format!("const {name}: &str"))
        .nth(1)
        .unwrap_or_else(|| panic!("no {name} in the guard"))
        .split(';')
        .next()
        .unwrap();
    statement.split('"').nth(1).unwrap().replace("\\n", "\n")
}

#[test]
fn the_lane_script_writes_the_sentinel_the_guard_looks_for() {
    let script = fs::read_to_string(repo().join("ci/root-test.sh")).unwrap();
    let path = guard_constant("SENTINEL");
    let content = guard_constant("SENTINEL_CONTENT");
    let line = content.trim_end_matches('\n');
    assert!(
        script.contains(&format!("'{line}'")),
        "ci/root-test.sh does not write {line:?}"
    );
    assert!(script.contains(&format!(">{path}")), "wrong path: {path}");
    assert!(script.contains(&format!("chown 0:0 {path}")));
    assert!(script.contains(&format!("chmod 0400 {path}")));
    // Made before the first cargo command, or the first root test refuses.
    let made = script.find(&format!(">{path}")).unwrap();
    let first_cargo = script.find("run cargo test").unwrap();
    assert!(
        made < first_cargo,
        "the sentinel is made after the tests run"
    );
}
