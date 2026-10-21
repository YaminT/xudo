#!/usr/bin/env bash
# The test suite on a real Linux kernel, from any host with Docker.
#
#   ci/linux-test.sh [cargo test arguments]        (or: just linux-test ...)
#
# Three hazards decide the shape, all found the hard way (docs/CONCERNS.md,
# 2026-10-14 and 2026-10-19):
#
# * Never on the bind mount. Docker Desktop's mount misreports the checkout as
#   root-owned to a root process, and intermittently reports a directory
#   created a moment earlier as missing. So the checkout is copied onto the
#   container's own filesystem first, and the mount is read-only.
# * Never as root. Root ignores file modes, so every "a writable file is
#   refused" test passes vacuously. The copy and the caches are prepared as
#   root, then the suite runs as an unprivileged user, and the script refuses to
#   continue if that user turns out to be root.
# * Never with the checkout's own mtimes. Every checkout is copied to the same
#   /work and builds into the same target volume, and cargo decides freshness
#   by comparing mtimes. A worktree whose files are older than the last build
#   from a different worktree would be tested against that other worktree's
#   code, silently. So the copy is extracted with the current time on every
#   file, and every run rebuilds the workspace's own crates; the registry
#   crates, which are the slow part, stay cached.
#
# The toolchain is the one rust-toolchain.toml pins. Registry and target caches
# live in named volumes so a second run does not rebuild the world.
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
uid=1000

# One run at a time per machine, from any checkout, and shared with
# ci/root-test.sh: the two use the same cache volumes. Why, and how, is in the
# library.
# shellcheck source=lib/machine-lock.sh
. "$root/ci/lib/machine-lock.sh"
take_machine_lock linux-test

# Arguments are passed to `cargo test` as separate words, never re-parsed.
docker run --rm -i \
    -v "$root:/src:ro" \
    -v aido-linux-cargo:/cache/cargo \
    -v aido-linux-target:/cache/target \
    -e TEST_UID="$uid" \
    "$image" bash -s -- "$@" <<'INNER'
set -euo pipefail
mkdir -p /work
(cd /src && tar --exclude=./target --exclude=./fuzz/target -cf - .) | tar -xmf - -C /work
chown -R "$TEST_UID:$TEST_UID" /work /cache/cargo /cache/target

run() {
    setpriv --reuid="$TEST_UID" --regid="$TEST_UID" --clear-groups \
        env -i PATH=/usr/local/cargo/bin:/usr/bin:/bin HOME=/work \
        CARGO_HOME=/cache/cargo CARGO_TARGET_DIR=/cache/target \
        RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN="$(rustup show active-toolchain | cut -d' ' -f1)" \
        "$@"
}

if [[ $(run id -u) == 0 ]]; then
    echo "FAIL: the suite would run as root, under which mode checks pass vacuously" >&2
    exit 1
fi
echo "linux-test: $(uname -sr) $(uname -m), as uid $(run id -u), on the container's own filesystem"
cd /work
run cargo test --workspace --all-features "$@"
INNER
