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
