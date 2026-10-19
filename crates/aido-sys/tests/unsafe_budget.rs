//! `unsafe` lives in `aido-sys::raw`, within its published budget, and nowhere
//! else.
//!
//! The compiler enforces most of this already: every other crate forbids
//! `unsafe_code`, and this one denies it outside `raw`. What the compiler
//! cannot see is the *configuration* that makes that true. A crate that stops
//! inheriting the workspace lints, a second module that allows `unsafe_code`,
//! or a sixth block in `raw` all compile cleanly. These tests are the review
//! that does not get tired.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn workspace_root() -> PathBuf {
    Path::new(MANIFEST_DIR)
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read_toml(path: &Path) -> toml::Table {
    fs::read_to_string(path).unwrap().parse().unwrap()
}

/// Source lines with whole-line comments removed, so prose about `unsafe`
/// does not count as `unsafe`.
fn code_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .map(str::to_owned)
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let is_dir = path.is_dir();
        let is_rust = path.extension().is_some_and(|e| e == "rs");
        is_dir.then(|| rust_files(&path, out));
        (is_rust && !is_dir).then(|| out.push(path.clone()));
    }
}

const MARKERS: [&str; 5] = [
    "unsafe {",
    "unsafe fn",
    "unsafe impl",
    "unsafe extern",
    "allow(unsafe_code)",
];

fn raw_rs() -> PathBuf {
    Path::new(MANIFEST_DIR).join("src/raw.rs")
}

#[test]
fn no_unsafe_appears_outside_raw_anywhere_in_the_workspace() {
    let root = workspace_root();
    let raw = raw_rs().canonicalize().unwrap();
    let mut files = Vec::new();
    for crate_dir in fs::read_dir(root.join("crates")).unwrap() {
        let src = crate_dir.unwrap().path().join("src");
        src.is_dir().then(|| rust_files(&src, &mut files));
    }
    assert!(
        files.len() > 20,
        "the scan found too little to be looking in the right place"
    );

    let offenders: Vec<String> = files
        .iter()
        .filter(|f| f.canonicalize().unwrap() != raw)
        .flat_map(|f| {
            code_lines(f)
                .into_iter()
                .filter(|l| MARKERS.iter().any(|m| l.contains(m)))
                .map(move |l| format!("{}: {}", f.display(), l.trim()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "unsafe outside aido-sys::raw:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn raw_stays_within_the_budget_its_docs_publish() {
    let text = fs::read_to_string(raw_rs()).unwrap();
    let budget: usize = text
        .split("**Budget: ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse().ok())
        .expect("raw.rs must publish `**Budget: N `unsafe` blocks.**` in its module docs");

    let code = code_lines(&raw_rs());
    let blocks = code.iter().filter(|l| l.contains("unsafe {")).count();
    assert_eq!(
        blocks, budget,
        "raw.rs has {blocks} unsafe blocks against a published budget of {budget}; \
         a change to either is a reviewed change to both"
    );
    for forbidden in ["unsafe fn", "unsafe impl", "unsafe extern"] {
        assert!(
            !code.iter().any(|l| l.contains(forbidden)),
            "raw.rs must not contain `{forbidden}`: it exports safe functions only"
        );
    }
}

#[test]
fn only_raw_may_allow_unsafe_and_it_is_not_public() {
    let lib = code_lines(&Path::new(MANIFEST_DIR).join("src/lib.rs"));
    assert!(lib.iter().any(|l| l.trim() == "#![deny(unsafe_code)]"));
    assert!(
        lib.iter().any(|l| l.trim() == "mod raw;"),
        "raw must stay private to aido-sys"
    );
    assert!(
        !lib.iter()
            .any(|l| l.contains("pub mod raw") || l.contains("pub(crate) mod raw"))
    );
    assert!(
        code_lines(&raw_rs())
            .iter()
            .any(|l| l.trim() == "#![allow(unsafe_code)]")
    );
}

#[test]
fn this_crates_lints_are_the_workspaces_but_for_unsafe_code() {
    let root = workspace_root();
    let mut expected = read_toml(&root.join("Cargo.toml"))["workspace"]["lints"].clone();
    expected["rust"]["unsafe_code"] = toml::Value::from("deny");
    assert_eq!(
        read_toml(&Path::new(MANIFEST_DIR).join("Cargo.toml"))["lints"],
        expected,
        "aido-sys's [lints] must equal [workspace.lints] with only unsafe_code lowered to deny"
    );
    assert_eq!(
        read_toml(&root.join("Cargo.toml"))["workspace"]["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid"),
        "the workspace default must stay forbid"
    );
}

#[test]
fn every_other_crate_inherits_the_workspace_lints() {
    let root = workspace_root();
    let manifest = read_toml(&root.join("Cargo.toml"));
    let members = manifest["workspace"]["members"].as_array().unwrap();
    assert!(members.len() > 5);
    let strays: Vec<&str> = members
        .iter()
        .map(|m| m.as_str().unwrap())
        .filter(|m| *m != "crates/aido-sys")
        .filter(|m| {
            let lints = read_toml(&root.join(m).join("Cargo.toml"));
            lints
                .get("lints")
                .and_then(|l| l.get("workspace"))
                .and_then(toml::Value::as_bool)
                != Some(true)
        })
        .collect();
    assert!(
        strays.is_empty(),
        "these crates do not inherit the workspace lints: {strays:?}"
    );
}
