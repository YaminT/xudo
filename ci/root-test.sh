#!/usr/bin/env bash
# The tests that must run as root, run as root, on a real Linux kernel, from any
# host with Docker.
#
#   ci/root-test.sh [cargo test arguments]        (or: just root-test ...)
#
# The mirror of ci/linux-test.sh. The same hazards decide its shape, with the
# middle one turned around (docs/CONCERNS.md, 2026-10-14, 2026-10-15, and
# 2026-10-21):
#
# * Never on the bind mount. Docker Desktop's mount misreports the checkout as
#   root-owned to a root process, and intermittently reports a directory
#   created a moment earlier as missing. So the checkout is copied onto the
#   container's own filesystem first, and the mount is read-only.
# * Always as root, and only the tests that need it. ci/linux-test.sh refuses to
#   run as root because root ignores file modes, so every "a writable file is
#   refused" test passes vacuously. This lane exists for what only root can
#   observe: a file handed to root:root and moded 0440, a rename inside a
#   directory only root may write. The rest of the workspace is written for an
#   unprivileged user and assumes it (a checkout that is not root's, a mode that
#   refuses the caller), so it is not run here: as root it fails, or passes for
#   the wrong reason. What runs is every `tests/root_*.rs`, behind the
#   `root-tests` feature, and the script refuses to continue if it turns out
#   not to be root. A cargo feature selects the tests and nothing in a
#   privileged crate reads the environment to decide to run them.
# * Never with the checkout's own mtimes. Every checkout is copied to the same
#   /work and builds into the same target volume, and cargo decides freshness
#   by comparing mtimes. A worktree whose files are older than the last build
#   from a different worktree would be tested against that other worktree's
#   code, silently. So the copy is extracted with the current time on every
#   file, and every run rebuilds the workspace's own crates; the registry
#   crates, which are the slow part, stay cached.
#
# Root in a container is root in the container, and nothing here pretends
# otherwise: the tests may write anywhere in it. The checkout is mounted
# read-only and the copy is thrown away with the container, so what they write
# never leaves it.
#
# Two ways this lane could pass without proving anything are closed, because
# both are one careless edit away:
#
# * A root test that is not root returns early and says SKIPPED, so that the
#   suites that enable every feature (`just test`, `just linux-test`) can still
#   build and run them as an ordinary user. Here that is a failure: the output is
#   read, and any SKIPPED fails the run.
# * A lane that runs no tests is not a lane. The passing tests are counted from
#   cargo's own summaries, and none is a failure.
#
# Tests run one at a time, with their output shown: they change the container's
# real filesystem, which parallel tests would race, and the SKIPPED check above
# needs the output.
#
# The toolchain is the one rust-toolchain.toml pins. Registry and target caches
# are the named volumes ci/linux-test.sh uses, so a second run does not rebuild
# the world; the lock below keeps the two from using them at once.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")
if [[ -z $channel ]]; then
    echo "FAIL: no channel in rust-toolchain.toml" >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker is required" >&2
    exit 1
fi

image="rust:${channel}-slim"

# One run at a time per machine, from any checkout, and shared with
# ci/linux-test.sh: the two use the same cache volumes. Why, and how, is in the
# library.
# shellcheck source=lib/machine-lock.sh
. "$root/ci/lib/machine-lock.sh"
take_machine_lock root-test

# Arguments are passed to `cargo test` as separate words, never re-parsed. They
# come after the fixed ones, so they can add to what runs (`-p aido-sys`, or a
# test name after `--`) and cannot remove the selection that keeps the
# unprivileged suite out of a root run.
docker run --rm -i \
    -v "$root:/src:ro" \
    -v aido-linux-cargo:/cache/cargo \
    -v aido-linux-target:/cache/target \
    "$image" bash -s -- "$@" <<'INNER'
set -euo pipefail
mkdir -p /work
(cd /src && tar --exclude=./target --exclude=./fuzz/target -cf - .) | tar -xmf - --no-same-owner -C /work

# The image's own toolchain, which is the pinned one, asked from outside the
# checkout: asked from inside it, rustup reads rust-toolchain.toml and downloads
# the cross targets and tools the file lists, which no test here needs, on every
# run of a container that forgets them.
toolchain=$(cd / && rustup show active-toolchain | cut -d' ' -f1)

# RUST_TEST_THREADS and RUST_TEST_NOCAPTURE are libtest's own settings: the
# environment of the tests, not a switch in any aido crate.
run() {
    env -i PATH=/usr/local/cargo/bin:/usr/bin:/bin HOME=/work \
        CARGO_HOME=/cache/cargo CARGO_TARGET_DIR=/cache/target \
        RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN="$toolchain" \
        RUST_TEST_THREADS=1 RUST_TEST_NOCAPTURE=1 \
        "$@"
}

if [[ $(run id -u) != 0 ]]; then
    echo "FAIL: the root tests would run as uid $(run id -u), not root" >&2
    exit 1
fi
echo "root-test: $(uname -sr) $(uname -m), as uid $(run id -u), on the container's own filesystem"
cd /work

out=$(mktemp)
run cargo test --workspace --features root-tests --test 'root_*' "$@" 2>&1 | tee "$out"

if grep -q 'SKIPPED:' "$out"; then
    echo "FAIL: a root test skipped itself, so it did not run as root:" >&2
    grep 'SKIPPED:' "$out" >&2
    exit 1
fi
passed=$(awk '/^test result: ok\./ { n += $4 } END { print n + 0 }' "$out")
if [[ $passed == 0 ]]; then
    echo "FAIL: no root test ran, so nothing was shown to work as root" >&2
    exit 1
fi
echo "root-test: $passed root tests passed as uid 0, none skipped"
INNER
