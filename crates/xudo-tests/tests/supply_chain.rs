//! The `cargo vet` gate is wired and its files are committed.
//!
//! Standard library alone, like the other checks in this package.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn the_supply_chain_recipe_runs_cargo_vet_after_deny_and_audit() {
    let justfile = std::fs::read_to_string(repo().join("justfile")).unwrap();
    let body = justfile.split("\nsupply-chain:").nth(1).unwrap();
    let body = body.split("\n\n").next().unwrap();
    let at = |needle: &str| {
        body.find(needle)
            .unwrap_or_else(|| panic!("missing {needle}"))
    };
    assert!(at("cargo deny check") < at("cargo audit --deny warnings"));
    assert!(at("cargo audit --deny warnings") < at("cargo vet --locked"));
}

#[test]
fn the_vet_files_exist_and_are_tracked() {
    for file in ["config.toml", "audits.toml", "imports.lock"] {
        let path = format!("supply-chain/{file}");
        assert!(repo().join(&path).is_file(), "{path} is missing");
        // The index lists tracked paths verbatim. No index (a source
        // tarball): the existence check above stands.
        if let Ok(index) = std::fs::read(repo().join(".git/index")) {
            assert!(
                index.windows(path.len()).any(|w| w == path.as_bytes()),
                "{path} is not tracked"
            );
        }
    }
}

#[test]
fn ci_installs_cargo_vet() {
    let ci = std::fs::read_to_string(repo().join(".github/workflows/ci.yml")).unwrap();
    assert!(ci.contains("cargo-vet@"));
}
