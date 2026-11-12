#!/usr/bin/env bash
# two_builds_of_the_same_commit_are_byte_identical
#
# Builds the .deb twice from HEAD, each from a clean `git archive` extracted
# under a different absolute path with its own empty target directory, then
# compares the .deb and the four binaries byte for byte.
#
#   ci/repro/run.sh <musl triple>          (or: just repro)
#
# What makes the output independent of the machine and the path:
#   SOURCE_DATE_EPOCH  the commit time; build.sh uses it for every mtime and the changelog date
#   --remap-path-prefix  the checkout, CARGO_HOME and the rustc sysroot, so no path is embedded
#   CARGO_INCREMENTAL=0, TZ=UTC, LC_ALL=C, --locked
# Existing RUSTFLAGS (CI sets -D warnings) are kept and the remaps appended.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <musl triple>" >&2
    exit 2
fi
triple=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$root/target/repro
epoch=$(git -C "$root" log -1 --format=%ct)
cargo_home=${CARGO_HOME:-$HOME/.cargo}
sysroot=$(rustc --print sysroot)

build() { # <name> <checkout dir>
    local name=$1 src=$2
    rm -rf "$src"
    mkdir -p "$src"
    git -C "$root" archive HEAD | tar -x -C "$src"
    (
        cd "$src"
        export SOURCE_DATE_EPOCH=$epoch TZ=UTC LC_ALL=C CARGO_INCREMENTAL=0
        export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$src=/build --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rustc"
        cargo build -p xudo-bin -p xudod-bin -p xudo-gate-bin -p ido-bin \
            --release --locked --target "$triple" --target-dir "$work/$name-target"
        XUDO_BUILD_BIN_DIR=$work/$name-target/$triple/release \
            packaging/deb/build.sh "$triple" "$work/$name-out" >/dev/null
    )
    # Only the output is compared; free the intermediate build before the next.
    rm -rf "${work:?}/$name-target"
}

rm -rf "$work"
mkdir -p "$work"
build a "$work/a/xudo-one"
build b "$work/b/another/xudo-two-longer"

sums() { # <out dir> : sha256 of the deb and the files it ships
    local out=$1 deb
    deb=$(ls "$out"/xudo_*.deb)
    sha256sum "$deb" | sed "s|$out/||"
    (cd "$out/stage" && sha256sum usr/bin/xudo usr/bin/ido usr/libexec/xudo/xudod usr/libexec/xudo/xudo-gate-auth)
}
sums "$work/a-out" >"$work/a.sums"
sums "$work/b-out" >"$work/b.sums"
cat "$work/a.sums"
if diff "$work/a.sums" "$work/b.sums"; then
    echo "OK: two builds of $(git -C "$root" rev-parse --short HEAD) are byte-identical"
    rm -rf "$work"
    exit 0
fi
echo "FAIL: the two builds differ" >&2
if command -v diffoscope >/dev/null; then
    diffoscope "$work"/a-out/xudo_*.deb "$work"/b-out/xudo_*.deb || true
else
    for f in usr/bin/xudo usr/bin/ido usr/libexec/xudo/xudod usr/libexec/xudo/xudo-gate-auth; do
        n=$(cmp -l "$work/a-out/stage/$f" "$work/b-out/stage/$f" | wc -l || true)
        echo "$f: $n differing bytes" >&2
    done
    cmp -l "$work"/a-out/xudo_*.deb "$work"/b-out/xudo_*.deb | wc -l | sed 's/$/ differing bytes in the .deb/' >&2 || true
fi
exit 1
