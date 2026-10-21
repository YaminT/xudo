# aido development gate.
#
# `just verify` is the pre-commit gate and is byte-for-byte what CI runs. If it
# passes locally and fails in CI, that is a bug in this file, not in CI.

set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

# Coverage floor. 100 unless a written waiver exists — see CLAUDE.md.
cov_lines := "100"
cov_regions := "100"
cov_functions := "100"

# The most `systemd-analyze security` may score any service under packaging/,
# where 0.0 is nothing left open and 10.0 is everything. The broker's service
# scores 1.1; the ceiling leaves 0.1 for systemd re-weighting a check, and sits
# below what dropping any one of its network, namespace, capability, or
# system-call restrictions costs. Like the coverage floor, it is changed only by
# a reviewed change that says why: fix the unit, or argue that the exposure is
# the price of what the service must do. The lane's self-test drops
# `PrivateNetwork=` from a control that scores 1.1 and requires the 1.5 that
# results to be refused, so a ceiling of 1.5 or more fails the self-test until
# the self-test is changed on purpose (ci/units/check.sh).
unit_exposure_max := "1.2"

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

# Three packages and one file are excluded, and every exclusion is load-bearing
# rather than convenient:
#
#   exec/host.rs is the only file that starts a child process. Its failure paths
#               need the kernel to fail a `fork` or a pipe read on a descriptor
#               we own, which a test cannot arrange. Every decision built on a
#               probe result sits behind the `Runner` trait and is fully covered
#               against a fake, so what is excluded is process plumbing only.
#   aido-bin    is the five-line entry point. Its own `tests/binary.rs` asserts
#               its exit statuses through a real process — 0, 17, and 19 — which
#               is the only place that behaviour exists. It is a correctness gate
#               (`just test` runs it), not a coverage source. Excluding one tiny
#               package is honest; a line-level waiver inside a shared file is
#               not.
#   ido-bin     is the same shape for `ido`, plus the raw terminal: reading the
#               environment once, termios raw mode, and the alternate screen.
#               None of that can run without a real terminal, so its
#               `tests/willyoumarryme.rs` drives it through real processes and a
#               real pseudo-terminal instead. The picker's logic is not here; it
#               is in the `ido` library, at 100% like everything else.
#   aidod-bin   is the same shape for the root broker: it borrows descriptor 0
#               from standard input, where systemd puts the accepted connection,
#               hands it and standard error to `aidod::run`, and exits with what
#               that returns. Its `tests/broker.rs` runs the real binary with a
#               real socket, a file, and nothing at all on descriptor 0. Every
#               decision is in the `aidod` library, at 100%.
#
# Everything else is 100% with no waivers. Do not add another exclusion without
# writing down why here.
coverage:
    cargo llvm-cov --workspace --exclude aido-bin --exclude ido-bin --exclude aidod-bin --all-features \
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
    cargo llvm-cov --workspace --exclude aido-bin --exclude ido-bin --exclude aidod-bin --all-features --ignore-filename-regex 'crates/aido-sys/src/exec/host\.rs$' --html
    @echo "open target/llvm-cov/html/index.html"

coverage-lcov: coverage-clean
    cargo llvm-cov --workspace --exclude aido-bin --exclude ido-bin --exclude aidod-bin --all-features --lcov --output-path lcov.info

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
fuzz-smoke: (fuzz "60")

# `--target` is the host triple, stated explicitly. cargo-fuzz otherwise
# defaults to the triple it was itself compiled for, and the prebuilt CI
# binary is static musl — a target AddressSanitizer refuses outright.
fuzz seconds:
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc +nightly -vV | sed -n 's/^host: //p')
    for target in $(cargo +nightly fuzz list); do
        echo "fuzzing $target"
        cargo +nightly fuzz run --target "$host" "$target" -- -max_total_time={{seconds}}
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

# --- linux -----------------------------------------------------------------

# The workspace's tests on a real Linux kernel, through Docker, as a non-root
# user, on a copy of the checkout rather than the bind mount. Run it before
# committing anything that touches a syscall: `cargo check --target` proves
# only that Linux code compiles. Arguments go to `cargo test`, e.g.
# `just linux-test -p aido-sys`.
linux-test *args:
    ci/linux-test.sh {{args}}

# The mirror of `linux-test`: the tests that must run as uid 0 (every
# `tests/root_*.rs`, behind the `root-tests` feature), as real root in a
# throwaway container, on a copy of the checkout, and nothing else. The rest of
# the suite assumes an unprivileged user and is not run as root. Shares
# `linux-test`'s lock and cache volumes. Needs Docker. Arguments go to
# `cargo test`. In CI it does not yet block: see the `root-tests` job.
root-test *args:
    ci/root-test.sh {{args}}

# --- systemd units ----------------------------------------------------------

# Every unit file under packaging/, by systemd's own tools in a Debian trixie
# container: `systemd-analyze verify` must say nothing, and `systemd-analyze
# security --offline` must score each service no worse than `unit_exposure_max`.
# The lane first shows it can fail, against a control unit it damages one way at
# a time. Skips, and says so, while packaging/ holds no unit. Needs Docker and
# the network. ci/units/check.sh says what each check is for.
units:
    ci/units/run.sh {{unit_exposure_max}}

# --- differential compliance ------------------------------------------------

# The static Linux binary the matrix drives: musl, for whichever architecture
# Docker on this host runs natively. Linked with rustc's bundled rust-lld (see
# .cargo/config.toml) so the same build works from a Mac and from the runner.
musl_triple := if arch() == "aarch64" { "aarch64-unknown-linux-musl" } else { "x86_64-unknown-linux-musl" }

# One binary and the shipped ruleset, driven inside real distributions against
# the real sudo, sudo-rs (the version Ubuntu 24.04 ships and the one 26.04
# does), OpenDoas, and a container with no escalator at all. Every backend's
# detection and probed capabilities are pinned, its own parser is asked to
# accept the snippet aido would write, and every verdict must be identical in
# every row. Needs Docker. ci/differential/run.sh says what is compared and
# what is deliberately not yet.
differential:
    cargo build -p aido-bin --release --target {{musl_triple}}
    ci/differential/run.sh target/{{musl_triple}}/release/aido

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

# What CI runs on a pull request, including the slow lanes. `root-test` joins it
# when its CI job stops being non-blocking (see the `root-tests` job).
ci: verify check-linux miri units differential

clean:
    cargo clean
    rm -f lcov.info
