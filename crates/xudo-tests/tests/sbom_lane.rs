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

/// The body of one workflow job: from its `  <key>:` line to the next job key.
fn job(workflow: &str, key: &str) -> String {
    let header = format!("  {key}:");
    let mut lines = workflow.lines().skip_while(|l| *l != header);
    let mut out: Vec<&str> = lines.by_ref().take(1).collect();
    out.extend(lines.take_while(|l| l.is_empty() || l.starts_with("   ")));
    out.join("\n")
}

/// Every top-level job key of a workflow.
fn job_keys(workflow: &str) -> Vec<String> {
    let jobs = workflow.split("\njobs:\n").nth(1).unwrap();
    jobs.lines()
        .filter(|l| {
            l.starts_with("  ")
                && !l.starts_with("   ")
                && !l.trim_start().starts_with('#')
                && l.trim_end().ends_with(':')
        })
        .map(|l| l.trim().trim_end_matches(':').to_owned())
        .collect()
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
    let mut checked = 0;
    for file in [".github/workflows/ci.yml", ".github/workflows/release.yml"] {
        let text = read(file);
        for key in job_keys(&text) {
            let body = job(&text, &key);
            if !["just deb-test", "just systemd-test", "just repro"]
                .iter()
                .any(|n| body.contains(n))
            {
                continue;
            }
            checked += 1;
            let tool = body
                .lines()
                .find(|l| l.trim_start().starts_with("tool: "))
                .unwrap_or_else(|| panic!("{file}: job {key} installs no tools"));
            assert!(
                tool.contains("cargo-auditable@"),
                "{file}: job {key} runs the deb recipe without a pinned cargo-auditable"
            );
            assert!(
                body.contains("fallback: none"),
                "{file}: job {key} may fall back to an unpinned cargo-auditable"
            );
        }
    }
    assert_eq!(checked, 4, "the build, repro, deb and systemd jobs");
}

#[test]
fn every_cargo_auditable_pin_is_the_same_one_the_deb_recipe_expects() {
    let mut pins = Vec::new();
    for file in [".github/workflows/ci.yml", ".github/workflows/release.yml"] {
        for (at, _) in read(file).match_indices("cargo-auditable@") {
            let text = read(file);
            let rest = &text[at + "cargo-auditable@".len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_digit() || c == '.'))
                .unwrap();
            pins.push(rest[..end].to_owned());
        }
    }
    assert_eq!(pins.len(), 4, "{pins:?}");
    let justfile = read("justfile");
    let recipe_pin = justfile
        .lines()
        .find_map(|l| l.strip_prefix("auditable_version := \""))
        .unwrap()
        .trim_end_matches('"');
    assert!(
        pins.iter().all(|p| p == recipe_pin),
        "{pins:?} vs {recipe_pin}"
    );
    assert!(recipe(&justfile, "deb:").contains("{{auditable_version}}"));
    assert!(read("ci/repro/run.sh").contains(&format!("cargo-auditable {recipe_pin}")));
}

#[test]
fn the_release_signs_and_publishes_the_sbom() {
    let release = read(".github/workflows/release.yml");
    assert!(
        release.contains("just sbom "),
        "the sbom job generates the SBOM"
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
    // Only the sign job may mint an OIDC token.
    for key in job_keys(&release) {
        assert_eq!(
            job(&release, &key).contains("id-token: write"),
            key == "sign",
            "id-token: write belongs to the sign job alone, not {key}"
        );
    }
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
    // The real proof is the `cmp` of two generations in check.sh; this only
    // keeps the sources of nondeterminism out of the generator.
    let script = read("ci/sbom/sbom.py");
    assert!(!script.contains("serialNumber") && !script.contains("timestamp"));
    assert!(read("ci/sbom/check.sh").contains("cmp \"$tmp/sbom.json\" \"$tmp/again.json\""));
}

#[test]
fn the_sbom_check_runs_its_adversarial_self_tests() {
    let check = read("ci/sbom/check.sh");
    assert!(check.contains("objcopy --remove-section .dep-v0"));
    assert!(check.contains("sbom.py drop"));
    assert!(check.contains("SELFTEST PASS"));
    assert!(check.contains("ALLOW_AUDIT_ONLY=errno"));
}
