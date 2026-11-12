#!/usr/bin/env bash
# two_builds_of_the_same_commit_are_byte_identical
#
# Runs `just deb` (the recipe the release signs) twice on HEAD, each in a clean
# `git archive` checkout under a different absolute path, with a different
# CARGO_HOME and its own target directory under the checkout, then compares the
# .deb and the four binaries byte for byte.
#
#   ci/repro/run.sh <musl triple> [file for the .deb sha256]    (or: just repro)
#
# The determinism (SOURCE_DATE_EPOCH, --remap-path-prefix of the checkout,
# CARGO_HOME and the sysroot, LC_ALL=C, TZ=UTC, CARGO_INCREMENTAL=0, RUSTFLAGS
# set outright) is in the `deb` recipe, not here. This script only supplies the
# commit time, because a git archive has no history.
#
# Reference rebuild environment: the GitHub ubuntu-24.04 runner image (amd64 and
# arm64), its stock dpkg-deb and xz-utils (from the image; `dpkg-deb --version`
# and `xz --version` are printed below), and the toolchain pinned in
# rust-toolchain.toml (1.98.0). The release build job compares its own .deb
# sha256 with the one this script records.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 <musl triple> [sha256 output file]" >&2
    exit 2
fi
triple=$1
sha_out=${2:-}
[[ -z $sha_out ]] || sha_out=$(realpath -m "$sha_out")
root=$(cd "$(dirname "$0")/../.." && pwd)
epoch=$(git -C "$root" log -1 --format=%ct)
export RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}
home_a=${CARGO_HOME:-$HOME/.cargo}
home_b=$root/target/repro-b/cargo-home-other
dpkg-deb --version | head -n 1
xz --version | head -n 1

build() { # <name> <checkout dir> <cargo home>
    local name=$1 src=$2 chome=$3
    rm -rf "$src"
    mkdir -p "$src"
    git -C "$root" archive HEAD | tar -x -C "$src"
    (
        cd "$src"
        export SOURCE_DATE_EPOCH=$epoch CARGO_HOME=$chome
        just deb >/dev/null
    )
    # Only the output is compared; free the intermediate build before the next.
    rm -rf "$root/target/repro-$name/out"
    mv "$src/target/deb" "$root/target/repro-$name/out"
    rm -rf "$src/target" "$root/target/repro-$name/cargo-home-other"
}

rm -rf "$root/target/repro-a" "$root/target/repro-b"
mkdir -p "$root/target/repro-a" "$root/target/repro-b"
build a "$root/target/repro-a/xudo-one" "$home_a"
build b "$root/target/repro-b/another/xudo-two-longer" "$home_b"

sums() { # <out dir> : sha256 of the deb and the files it ships
    local out=$1 deb
    deb=$(ls "$out"/xudo_*.deb)
    sha256sum "$deb" | sed "s|$out/||"
    (cd "$out/stage" && sha256sum usr/bin/xudo usr/bin/ido usr/libexec/xudo/xudod usr/libexec/xudo/xudo-gate-auth)
}
sums "$root/target/repro-a/out" >"$root/target/repro-a/sums"
sums "$root/target/repro-b/out" >"$root/target/repro-b/sums"
cat "$root/target/repro-a/sums"
if diff "$root/target/repro-a/sums" "$root/target/repro-b/sums"; then
    echo "OK: two builds of $(git -C "$root" rev-parse --short HEAD) are byte-identical"
    [[ -z $sha_out ]] || head -n 1 "$root/target/repro-a/sums" >"$sha_out"
    rm -rf "$root/target/repro-a" "$root/target/repro-b"
    exit 0
fi
echo "FAIL: the two builds differ" >&2
a=$root/target/repro-a/out
b=$root/target/repro-b/out
if command -v diffoscope >/dev/null; then
    diffoscope "$a"/xudo_*.deb "$b"/xudo_*.deb || true
else
    for f in usr/bin/xudo usr/bin/ido usr/libexec/xudo/xudod usr/libexec/xudo/xudo-gate-auth; do
        n=$(cmp -l "$a/stage/$f" "$b/stage/$f" | wc -l || true)
        echo "$f: $n differing bytes" >&2
    done
    cmp -l "$a"/xudo_*.deb "$b"/xudo_*.deb | wc -l | sed 's/$/ differing bytes in the .deb/' >&2 || true
fi
exit 1
