//! What `just ci` runs is what CI runs.
//!
//! The `ci` recipe says it is "what CI runs on a pull request", and a developer
//! who runs it before pushing believes that. A lane added to
//! `.github/workflows/ci.yml` and not to the recipe makes the claim false
//! without anyone deciding it should be: the `install-root` job was exactly
//! that. So every `just <recipe>` that a workflow step runs must be reachable
//! from `ci`, directly or through `verify`, or be named below with its reason.
//!
//! Standard library alone, like the other checks in this package.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Recipes a job runs that `just ci` deliberately does not, each with why.
const NOT_IN_CI: [(&str, &str); 2] = [
    (
        "fuzz",
        "the long nightly run, on a schedule; needs the nightly toolchain and cargo-fuzz",
    ),
    (
        "fuzz-smoke",
        "a sixty-second run per push; needs the nightly toolchain and cargo-fuzz",
    ),
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The recipe names after `just ` in the `run:` lines of a workflow, where
/// `a && just b` names both.
fn recipes_run(workflow: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in workflow.lines() {
        let Some(command) = line
            .trim()
            .strip_prefix("- run:")
            .or_else(|| line.trim().strip_prefix("run:"))
        else {
            continue;
        };
        for part in command.split("&&") {
            if let Some(rest) = part.trim().strip_prefix("just ") {
                if let Some(name) = rest.split_whitespace().next() {
                    found.insert(name.to_owned());
                }
            }
        }
    }
    found
}

/// The dependencies a justfile recipe lists on its header line.
fn dependencies(justfile: &str, recipe: &str) -> Vec<String> {
    let header = justfile
        .lines()
        .find(|l| l.starts_with(&format!("{recipe}:")))
        .unwrap_or_else(|| panic!("no recipe {recipe} in the justfile"));
    header
        .split_once(':')
        .unwrap()
        .1
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// What `ci` reaches: its dependencies, and what `verify` pulls in.
fn reached(justfile: &str) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    for dep in dependencies(justfile, "ci") {
        if dep == "verify" {
            all.extend(dependencies(justfile, "verify"));
        }
        all.insert(dep);
    }
    all
}

/// The recipes `run` names that `reached` lacks and the allow-list does not
/// excuse.
fn missing(run: &BTreeSet<String>, reached: &BTreeSet<String>) -> Vec<String> {
    run.iter()
        .filter(|r| !reached.contains(*r) && !NOT_IN_CI.iter().any(|(n, _)| n == r))
        .cloned()
        .collect()
}

#[test]
fn every_lane_a_ci_job_runs_is_in_the_ci_recipe() {
    let workflow = fs::read_to_string(repo().join(".github/workflows/ci.yml")).unwrap();
    let justfile = fs::read_to_string(repo().join("justfile")).unwrap();
    let run = recipes_run(&workflow);
    assert!(
        run.contains("root-test") && run.contains("install-root"),
        "{run:?}"
    );
    let absent = missing(&run, &reached(&justfile));
    assert!(
        absent.is_empty(),
        "CI runs `just {}` but the `ci` recipe does not; add it to the recipe, or to \
         NOT_IN_CI here with a reason",
        absent.join("`, `just ")
    );
}

#[test]
fn the_check_notices_a_lane_missing_from_the_recipe() {
    let workflow = "      - run: just units\n      - name: x\n        run: just a && just b c\n";
    let run = recipes_run(workflow);
    assert_eq!(
        run.iter().map(String::as_str).collect::<Vec<_>>(),
        ["a", "b", "units"]
    );
    let justfile = "verify: fmt\nci: verify units\n";
    let got = reached(justfile);
    assert_eq!(missing(&run, &got), ["a", "b"]);
    // The excused ones are not missing.
    let excused: BTreeSet<String> = ["fuzz".to_owned()].into();
    assert!(missing(&excused, &got).is_empty());
}

/// Job-level `needs` edges in the small, regular job maps used by our workflows.
fn workflow_needs(workflow: &str, job: &str) -> Vec<String> {
    let mut in_job = false;
    let mut section = Vec::new();
    for line in workflow.lines() {
        if in_job && line.starts_with("  ") && !line.starts_with("    ") {
            break;
        }
        if line.trim() == format!("{job}:") {
            in_job = true;
        }
        if in_job {
            section.push(line);
        }
    }
    assert!(in_job, "no job {job}");
    let Some(needs) = section
        .iter()
        .find_map(|line| line.trim().strip_prefix("needs:"))
    else {
        return Vec::new();
    };
    needs
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn release_signing_waits_for_the_reusable_ci_workflow() {
    let ci = fs::read_to_string(repo().join(".github/workflows/ci.yml")).unwrap();
    let release = fs::read_to_string(repo().join(".github/workflows/release.yml")).unwrap();
    assert!(ci.lines().any(|line| line.trim() == "workflow_call:"));
    assert!(release.contains("uses: ./.github/workflows/ci.yml"));

    let build_needs = workflow_needs(&release, "build");
    assert!(build_needs.iter().any(|job| job == "ci"), "{build_needs:?}");
    let sign_needs = workflow_needs(&release, "sign");
    assert!(
        sign_needs.iter().any(|job| job == "build"),
        "{sign_needs:?}"
    );

    // Follow needs edges from sign; the reusable CI call must be an ancestor.
    let mut pending = sign_needs;
    let mut visited = BTreeSet::new();
    while let Some(job) = pending.pop() {
        if visited.insert(job.clone()) {
            pending.extend(workflow_needs(&release, &job));
        }
    }
    assert!(visited.contains("ci"), "sign ancestors: {visited:?}");
}

/// `uses:` values that are not a local `./` workflow and not
/// `action@<40 hex> # vX.Y.Z`.
fn unpinned_actions(workflow: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in workflow.lines() {
        let Some(value) = uses_value(line) else {
            continue;
        };
        if value.starts_with("./") || is_sha_pin(value) {
            continue;
        }
        found.push(value.to_owned());
    }
    found
}

/// The value of a step or job `uses:` key, ignoring commented lines.
fn uses_value(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("- uses:") {
        return Some(rest.trim());
    }
    if let Some(rest) = trimmed.strip_prefix("uses:") {
        return Some(rest.trim());
    }
    None
}

/// A third-party action pinned the way `release.yml` pins one.
fn is_sha_pin(value: &str) -> bool {
    let Some((action, revision)) = value.split_once('@') else {
        return false;
    };
    if action.is_empty() {
        return false;
    }
    let Some((sha, comment)) = revision.split_once(' ') else {
        return false;
    };
    is_commit_sha(sha) && is_version_comment(comment.trim())
}

fn is_commit_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// `# vX.Y.Z`, the trailing comment on every pin in `release.yml`.
fn is_version_comment(comment: &str) -> bool {
    let Some(version) = comment.strip_prefix("# v") else {
        return false;
    };
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 3 && parts.iter().all(|part| is_numeric(part))
}

fn is_numeric(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
}

fn workflow_files() -> Vec<PathBuf> {
    let dir = repo().join(".github/workflows");
    let mut paths = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        paths.push(entry.unwrap().path());
    }
    paths.sort();
    assert!(!paths.is_empty(), "no workflows under {}", dir.display());
    paths
}

#[test]
fn every_action_in_every_workflow_is_pinned_to_a_sha() {
    let mut saw_local = false;
    let mut saw_pin = false;
    for path in workflow_files() {
        let text = fs::read_to_string(&path).unwrap();
        let unpinned = unpinned_actions(&text);
        assert!(
            unpinned.is_empty(),
            "{} uses an action that is not pinned to a 40-hex commit SHA: {}",
            path.display(),
            unpinned.join(", ")
        );
        for line in text.lines() {
            let Some(value) = uses_value(line) else {
                continue;
            };
            if value.starts_with("./") {
                saw_local = true;
            } else {
                saw_pin = true;
            }
        }
    }
    assert!(
        saw_local,
        "a local ./ workflow call is exempt and must stay"
    );
    assert!(saw_pin, "expected at least one SHA-pinned action");
}

#[test]
fn the_pin_check_catches_an_unpinned_uses() {
    let sha = "11bd71901bbe5b1630ceea73d27597364c9af683";
    let workflow = format!(
        "\
# uses: actions/checkout@v4
jobs:
  ci:
    uses: ./.github/workflows/ci.yml
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/checkout@{sha} # v4.2.2
      - name: Install gate tools
        uses: taiki-e/install-action@v2
      - uses: actions/checkout@{sha}
      - uses: actions/checkout@11bd719 # v4.2.2
      - uses: actions/checkout@{sha} # v4
      - uses: actions/checkout@{sha} # release
      - uses: actions/checkout@{sha} # v4.2.x
      - uses: actions/checkout@{sha} # v4..2
      - uses: actions/checkout@gggggggggggggggggggggggggggggggggggggggg # v4.2.2
      - uses: @{sha} # v4.2.2
      - uses: not-an-action
"
    );
    assert_eq!(
        unpinned_actions(&workflow),
        vec![
            "actions/checkout@v4".to_owned(),
            "taiki-e/install-action@v2".to_owned(),
            format!("actions/checkout@{sha}"),
            "actions/checkout@11bd719 # v4.2.2".to_owned(),
            format!("actions/checkout@{sha} # v4"),
            format!("actions/checkout@{sha} # release"),
            format!("actions/checkout@{sha} # v4.2.x"),
            format!("actions/checkout@{sha} # v4..2"),
            "actions/checkout@gggggggggggggggggggggggggggggggggggggggg # v4.2.2".to_owned(),
            format!("@{sha} # v4.2.2"),
            "not-an-action".to_owned(),
        ]
    );
}

/// A file's text without its comment lines, so a needle must be in the code.
fn uncommented(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The lines of the recipe body (indented lines after its header).
fn recipe_body(justfile: &str, recipe: &str) -> String {
    let mut lines = justfile.lines();
    lines
        .by_ref()
        .find(|l| l.starts_with(&format!("{recipe}:")))
        .unwrap();
    let body: Vec<&str> = lines
        .take_while(|l| l.is_empty() || l.starts_with(' '))
        .collect();
    uncommented(&body.join("\n"))
}

/// The text of the job `key` in a workflow: from its key to the next job key.
fn job(workflow: &str, key: &str) -> String {
    let header = format!("  {key}:");
    let mut lines = workflow.lines().skip_while(|l| *l != header);
    let mut out: Vec<&str> = lines.by_ref().take(1).collect();
    out.extend(
        lines.take_while(|l| {
            l.is_empty() || l.starts_with("   ") || l.trim_start().starts_with('#')
        }),
    );
    out.join("\n")
}

#[test]
fn a_ci_job_builds_the_deb_twice_and_compares_the_bytes() {
    let workflow = fs::read_to_string(repo().join(".github/workflows/ci.yml")).unwrap();
    let justfile = fs::read_to_string(repo().join("justfile")).unwrap();
    let script = fs::read_to_string(repo().join("ci/repro/run.sh")).unwrap();
    let code = uncommented(&script);
    assert!(recipes_run(&workflow).contains("repro"));
    assert!(justfile.lines().any(|l| l.starts_with("repro")));
    assert!(reached(&justfile).contains("repro"));
    // The recipe is tied to the job, which is a hard gate.
    let repro = job(&workflow, "reproducible-build");
    assert!(repro.contains("name: reproducible build"));
    assert!(repro.contains("run: just repro "), "{repro}");
    assert!(!repro.contains("continue-on-error"), "{repro}");
    assert!(!repro.contains("\n    if:"), "{repro}");
    assert!(!repro.contains("rust-cache"), "{repro}");
    assert!(repro.contains("ubuntu-24.04-arm"), "{repro}");
    assert!(repro.contains("persist-credentials: false"), "{repro}");
    assert!(
        !repro.lines().any(|l| l.trim_start().starts_with("if:")),
        "{repro}"
    );
    // The release reaches the job through its call to this workflow.
    assert!(workflow.lines().any(|l| l.trim() == "workflow_call:"));
    // The script runs the very recipe the release signs, in each checkout.
    assert!(code.contains("just deb"), "run.sh must call `just deb`");
    assert!(code.contains("archive HEAD"));
    assert!(code.contains("sha256sum"));
    assert!(code.contains("CARGO_HOME"));
    assert!(
        !code.contains("cargo build"),
        "run.sh must not build itself"
    );
    // The shipped bytes are decided in the recipe, whatever the caller sets.
    let deb = recipe_body(&justfile, "deb");
    for needle in [
        "--remap-path-prefix={{justfile_directory()}}",
        "CARGO_HOME",
        "rustc --print sysroot",
        "SOURCE_DATE_EPOCH",
        "LC_ALL=C",
        "TZ=UTC",
        "CARGO_INCREMENTAL=0",
        "export RUSTFLAGS=\"--remap",
    ] {
        assert!(deb.contains(needle), "the deb recipe lacks {needle}");
    }
    assert!(
        !deb.contains("RUSTFLAGS:-"),
        "RUSTFLAGS must be set outright"
    );
    assert!(
        !deb.contains("$RUSTFLAGS"),
        "RUSTFLAGS must be set outright"
    );
    let build = uncommented(&fs::read_to_string(repo().join("packaging/deb/build.sh")).unwrap());
    assert!(build.contains("export LC_ALL=C"));
    assert!(unpinned_actions(&workflow).is_empty());
}

#[test]
fn the_release_build_fails_if_its_deb_differs_from_the_independent_rebuild() {
    let release = fs::read_to_string(repo().join(".github/workflows/release.yml")).unwrap();
    let build = job(&release, "build");
    assert!(build.contains("repro-sha256-${{ matrix.arch }}"), "{build}");
    assert!(build.contains("sha256sum target/deb/xudo_*.deb"), "{build}");
    assert!(build.contains("\"$expected\" = \"$actual\""), "{build}");
    assert!(!build.contains("rust-cache"), "{build}");
    assert!(!build.contains("continue-on-error"), "{build}");
    assert!(release.contains("uses: ./.github/workflows/ci.yml"));
    assert!(build.contains("needs: ci"));
}
