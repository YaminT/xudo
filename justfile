# aido development gate.
#
# `just verify` is the pre-commit gate and is byte-for-byte what CI runs. If it
# passes locally and fails in CI, that is a bug in this file, not in CI.

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Coverage floor. 100 unless a written waiver exists — see CLAUDE.md.
cov_lines := "100"
cov_regions := "100"
cov_functions := "100"

default: verify

# The full gate. Run before every commit.
verify: fmt-check toml-check lint test doc-test coverage-clean coverage supply-chain gtfobins
    @echo "gate: all checks passed"

# --- formatting -------------------------------------------------------------

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

# TOML formatting. Scoped by .taplo.toml, which excludes target/ — generated
# test fixtures there include a deliberately non-UTF-8 file and a directory
# named `10-a.toml`, both of which exist to prove the rule loader refuses them.
toml-check:
    taplo fmt --check

# --- linting ----------------------------------------------------------------

# Zero warnings. The disallowed-methods list in clippy.toml is a list of
# documented root-exploit vectors, not a style opinion.
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Type-check the Linux targets from a macOS host, so a Linux-only mistake is
# caught before it reaches CI.
check-linux:
    cargo check --workspace --target x86_64-unknown-linux-gnu
    cargo check --workspace --target aarch64-unknown-linux-gnu

# --- tests ------------------------------------------------------------------

test:
    cargo test --workspace --all-features
    just no-ignored-passes

doc-test:
    cargo test --doc --workspace

# An adversarial test that is #[ignore]d and passes means the attack it encodes
# now works. That must fail the build, not sit quietly in the output.
no-ignored-passes:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(cargo test --workspace -- --ignored 2>&1 || true)
    if grep -qE '^test .* \.\.\. ok$' <<<"$out"; then
        echo "FAIL: an #[ignore]d test passed — the attack it encodes may now work:" >&2
        grep -E '^test .* \.\.\. ok$' <<<"$out" >&2
        exit 1
    fi
    echo "no-ignored-passes: clean"

# --- coverage ---------------------------------------------------------------

# Two packages are excluded, and both exclusions are load-bearing rather than
# convenient:
#
#   aido-tests  spawns the built `aido` binary, which the coverage harness
#               relocates, so `cargo_bin` cannot find it. It is a correctness
#               gate (`just test` runs it), not a coverage source.
#   exec/host.rs is the only file that starts a child process. Its failure paths
#               need the kernel to fail a `fork` or a pipe read on a descriptor
#               we own, which a test cannot arrange. Every decision built on a
#               probe result sits behind the `Runner` trait and is fully covered
#               against a fake, so what is excluded is process plumbing only.
#   aido-bin    is the five-line entry point. `aido-tests` asserts its exit
#               statuses through a real process — 0, 17, and 19 — which is the
#               only place that behaviour exists. Excluding one tiny package is
#               honest; a line-level waiver inside a shared file is not.
#
# Everything else is 100% with no waivers. Do not add a third exclusion without
# writing down why here.
coverage:
    cargo llvm-cov --workspace --exclude aido-tests --exclude aido-bin --all-features \
        --ignore-filename-regex 'crates/aido-sys/src/exec/host\.rs$' \
        --fail-under-lines {{cov_lines}} \
        --fail-under-regions {{cov_regions}} \
        --fail-under-functions {{cov_functions}}

# Human-readable report, for finding the gap rather than gating on it.
# Coverage data is cached per target dir and goes stale across a refactor,
# which reads as a sudden unexplained drop. Purge first, always.
coverage-clean:
    rm -rf target/llvm-cov target/llvm-cov-target

coverage-report: coverage-clean
    cargo llvm-cov --workspace --exclude aido-tests --exclude aido-bin --all-features --ignore-filename-regex 'crates/aido-sys/src/exec/host\.rs$' --html
    @echo "open target/llvm-cov/html/index.html"

coverage-lcov: coverage-clean
    cargo llvm-cov --workspace --exclude aido-tests --exclude aido-bin --all-features --lcov --output-path lcov.info

# --- undefined behaviour ----------------------------------------------------

# Scoped to `--lib` deliberately. The pure engine is what miri is for, and its
# unit tests cover it completely; the proptest integration test cannot run under
# miri because the harness calls `getcwd` for failure persistence and miri's
# isolation blocks it. Disabling isolation to get it running would weaken the
# check rather than widen it.
miri:
    cargo +nightly miri test -p aido-policy --lib

# --- fuzzing ----------------------------------------------------------------

# Smoke run for CI. Nightly runs these for hours instead of seconds.
fuzz-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    for target in $(cargo +nightly fuzz list); do
        echo "fuzzing $target"
        cargo +nightly fuzz run "$target" -- -max_total_time=60
    done

# --- supply chain -----------------------------------------------------------

# `cargo audit` alone exits 0 on unmaintained crates; the informational
# categories do not fail a plain run, so warnings are denied explicitly.
supply-chain:
    cargo deny check
    cargo audit --deny warnings

# --- GTFOBins gate ----------------------------------------------------------

# Every executable an action allowlists is checked against the vendored
# GTFOBins list. A hit fails the build: the binary can be turned into a shell,
# so allowlisting it defeats the whole design.
gtfobins:
    #!/usr/bin/env bash
    set -euo pipefail
    list="ci/gtfobins.txt"
    waivers="ci/gtfobins-waivers.txt"
    for f in "$list" "$waivers"; do
        if [[ ! -f "$f" ]]; then
            echo "FAIL: $f is missing; the GTFOBins gate cannot run" >&2
            exit 1
        fi
    done

    # Every executable any shipped rule allowlists. A while-read loop rather
    # than `mapfile`, because macOS ships bash 3.2 and a developer gate that
    # only runs on the CI image is a gate nobody runs.
    exes=()
    while IFS= read -r found; do
        [[ -n "$found" ]] && exes+=("$found")
    done < <(grep -rhoE 'exe[[:space:]]*=[[:space:]]*"[^"]+"' rules/ \
        | sed -E 's/.*"([^"]+)".*/\1/' | sort -u)
    if (( ${#exes[@]} == 0 )); then
        echo "FAIL: no allowlisted executables found under rules/ — is the gate looking in the right place?" >&2
        exit 1
    fi

    fail=0
    for exe in "${exes[@]}"; do
        base="${exe##*/}"
        grep -qxF "$base" "$list" || continue

        # Listed by GTFOBins. A waiver must exist, name the technique, and
        # explain why the rule makes it unreachable.
        line=$(grep -F "${exe}|" "$waivers" || true)
        if [[ -z "$line" ]]; then
            echo "FAIL: rule allowlists '$exe', which GTFOBins lists as shell-capable, and no waiver explains why that is safe." >&2
            echo "      Add an entry to $waivers, or narrow the rule until the binary is not needed." >&2
            fail=1
            continue
        fi
        technique=$(cut -d'|' -f2 <<<"$line")
        rationale=$(cut -d'|' -f3- <<<"$line")
        if (( ${#technique} < 20 )) || (( ${#rationale} < 80 )); then
            echo "FAIL: the waiver for '$exe' does not actually argue the case (technique ${#technique} chars, rationale ${#rationale} chars)." >&2
            fail=1
        fi
    done

    # A waiver for a binary no rule allowlists is stale and must not accumulate.
    while IFS='|' read -r exe _rest; do
        [[ -z "$exe" || "$exe" == \#* ]] && continue
        if ! printf '%s\n' "${exes[@]}" | grep -qxF "$exe"; then
            echo "FAIL: stale waiver for '$exe' — no rule allowlists it any more. Remove it." >&2
            fail=1
        fi
    done < "$waivers"

    if (( fail )); then exit 1; fi
    echo "gtfobins: every allowlisted shell-capable binary has a reviewed waiver"

# --- developer setup --------------------------------------------------------

# Point git at the tracked hooks directory, so the gate runs before every
# commit. Tracked in-repo rather than copied into .git/hooks, so an update to
# the hook reaches everyone.
install-hooks:
    git config core.hooksPath .githooks
    @echo "hooks: core.hooksPath -> .githooks"

# One-time setup for a new checkout.
setup: install-hooks
    rustup show active-toolchain || rustup toolchain install
    @echo "setup: run 'just verify' to confirm the gate is green"

# --- convenience ------------------------------------------------------------

# What CI runs on a pull request, including the slow lanes.
ci: verify check-linux miri

clean:
    cargo clean
    rm -f lcov.info
