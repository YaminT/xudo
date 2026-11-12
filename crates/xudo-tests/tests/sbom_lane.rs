//! The release embeds each binary's dependency list, ships a signed `CycloneDX`
//! SBOM, and a lane proves the two agree.
//!
//! Standard library alone, like the other checks in this package.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    fs::read_to_string(repo().join(path)).unwrap()
}

fn recipe(justfile: &str, name: &str) -> String {
    let body = justfile
        .split(&format!("\n{name}"))
        .nth(1)
        .unwrap_or_else(|| panic!("no recipe {name}"));
    body.split("\n\n").next().unwrap().to_owned()
}

#[test]
fn the_deb_recipe_builds_with_cargo_auditable() {
    let deb = recipe(&read("justfile"), "deb:");
    assert!(deb.contains("cargo auditable build"), "{deb}");
    assert!(
        !deb.contains("    cargo build"),
        "a plain cargo build would ship binaries with no audit data"
    );
}

#[test]
fn every_job_that_runs_the_deb_recipe_installs_cargo_auditable() {
    // `deb-test`, `systemd-test` and `repro` all run `just deb`; so does the release.
    for file in [".github/workflows/ci.yml", ".github/workflows/release.yml"] {
        let text = read(file);
        for needle in ["just deb-test", "just systemd-test", "just repro"] {
            for (at, _) in text.match_indices(needle) {
                let before = &text[..at];
                let install = before.rfind("tool: ").unwrap();
                assert!(
                    before[install..]
                        .lines()
                        .next()
                        .unwrap()
                        .contains("cargo-auditable@"),
                    "{file}: the job running `{needle}` does not install a pinned cargo-auditable"
                );
            }
        }
    }
}

#[test]
fn the_release_signs_and_publishes_the_sbom() {
    let release = read(".github/workflows/release.yml");
    assert!(
        release.contains("just sbom "),
        "the build job generates the SBOM"
    );
    assert!(release.contains("sha256sum -- *.deb *.cdx.json > SHA256SUMS"));
    assert!(release.contains("for file in *.deb *.cdx.json SHA256SUMS;"));
    assert!(release.contains("cosign sign-blob --yes --bundle"));
    let create = release
        .lines()
        .find(|l| l.contains("gh release create"))
        .unwrap();
    assert!(create.contains("./*.cdx.json"), "{create}");
    // The bundle for the SBOM is published by the existing glob.
    assert!(create.contains("./*.cosign.bundle"), "{create}");
    // The sign job stays minimal: it downloads the SBOM, it does not build it.
    let sign = release.split("\n  sign:").nth(1).unwrap();
    let sign = sign.split("\n  release:").next().unwrap();
    assert!(!sign.contains("just "), "the sign job builds nothing");
}

#[test]
fn the_sbom_check_recipe_exists_and_is_wired_into_ci() {
    let justfile = read("justfile");
    let check = recipe(&justfile, "sbom-check");
    assert!(check.contains("ci/sbom/check.sh"), "{check}");
    assert!(
        justfile
            .lines()
            .any(|l| l.starts_with("ci:") && l.contains("sbom-check"))
    );
    assert!(read(".github/workflows/ci.yml").contains("run: just sbom-check"));
    for file in ["check.sh", "generate.sh", "sbom.py"] {
        assert!(repo().join("ci/sbom").join(file).is_file(), "{file}");
    }
}

#[test]
fn the_sbom_is_deterministic_by_construction() {
    let script = read("ci/sbom/sbom.py");
    assert!(!script.contains("serialNumber") && !script.contains("timestamp"));
    assert!(script.contains("sort_keys=True") && script.contains("sorted("));
}
