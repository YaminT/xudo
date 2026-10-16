#!/usr/bin/env bash
# The test suite on a real Linux kernel, from any host with Docker.
#
#   ci/linux-test.sh [cargo test arguments]        (or: just linux-test ...)
#
# Two hazards decide the shape, both found the hard way (docs/CONCERNS.md,
# 2026-10-14):
#
# * Never on the bind mount. Docker Desktop's mount misreports the checkout as
#   root-owned to a root process, and intermittently reports a directory
#   created a moment earlier as missing. So the checkout is copied onto the
#   container's own filesystem first, and the mount is read-only.
# * Never as root. Root ignores file modes, so every "a writable file is
#   refused" test passes vacuously. The copy and the caches are prepared as
#   root, then the suite runs as an unprivileged user, and the script refuses to
#   continue if that user turns out to be root.
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

# One run at a time per machine, from any checkout. Every worktree shares the
# two cache volumes and the Docker VM's memory, and parallel agents working in
# separate worktrees would otherwise race both: the target volume rebuilt from
# under each other, and enough concurrent rustc processes to get one killed
# with no message. A directory is the lock because mkdir is atomic everywhere
# and macOS ships no flock(1); a lock whose holder has died is taken over.
lock="${TMPDIR:-/tmp}/aido-linux-test.lock"
announced=0
until mkdir "$lock" 2>/dev/null; do
    holder=$(cat "$lock/pid" 2>/dev/null || true)
    if [[ -n $holder ]] && ! kill -0 "$holder" 2>/dev/null; then
        rm -rf "$lock"
        continue
    fi
    if [[ $announced == 0 ]]; then
        echo "linux-test: waiting for another run (pid ${holder:-starting})" >&2
        announced=1
    fi
    sleep 2
done
echo $$ >"$lock/pid"
trap 'rm -rf "$lock"' EXIT

# Arguments are passed to `cargo test` as separate words, never re-parsed.
docker run --rm -i \
    -v "$root:/src:ro" \
    -v aido-linux-cargo:/cache/cargo \
    -v aido-linux-target:/cache/target \
    -e TEST_UID="$uid" \
    "$image" bash -s -- "$@" <<'INNER'
set -euo pipefail
mkdir -p /work
(cd /src && tar --exclude=./target --exclude=./fuzz/target -cf - .) | tar -xf - -C /work
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
