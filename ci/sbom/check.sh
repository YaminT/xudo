#!/usr/bin/env bash
# The binaries inside the .deb embed the dependency list cargo-auditable wrote,
# and it agrees with `cargo tree` and with the SBOM, in both directions, per binary.
# Then two attacks that MUST be caught: a binary stripped of its audit data, and an
# SBOM missing a crate.
#
#   ci/sbom/check.sh <musl triple>        (or: just sbom-check; builds with `just deb`)
#
# Needs the crates already fetched (cargo tree may download them), and objcopy.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
triple=${1:?usage: check.sh <musl triple>}
cd "$root"
command -v objcopy >/dev/null || { echo "FAIL: objcopy (binutils) is required" >&2; exit 1; }

# cargo-auditable's data lists a crate that is not linked: it reads
# `cargo metadata --filter-platform`, which keeps rustix's linux-only optional
# `libc_errno` edge without checking that the feature is on. `cargo tree` applies
# the features and leaves `errno` out. Named here so every other difference fails.
ALLOW_AUDIT_ONLY=errno

shopt -s nullglob
debs=(target/deb/*.deb)
[[ ${#debs[@]} -eq 1 ]] || { echo "FAIL: want one target/deb/*.deb, found ${#debs[@]}" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dpkg-deb -x "${debs[0]}" "$tmp/deb"
bins=("$tmp/deb/usr/bin/xudo" "$tmp/deb/usr/bin/ido" "$tmp/deb/usr/libexec/xudo/xudod" "$tmp/deb/usr/libexec/xudo/xudo-gate-auth")
pkgs=(xudo-bin ido-bin xudod-bin xudo-gate-bin)

ci/sbom/generate.sh "$tmp/sbom.json" >/dev/null
for p in "${pkgs[@]}"; do
    cargo tree --locked -e normal,build --target "$triple" -p "$p" --prefix none >"$tmp/tree-$p.txt"
done
for t in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    cargo tree --locked -e normal,build --target "$t" \
        -p xudo-bin -p xudod-bin -p xudo-gate-bin -p ido-bin --prefix none >>"$tmp/both.txt"
done

verify() { # <sbom> <binary>...
    local sbom=$1 pairs=() i
    shift
    for i in "${!pkgs[@]}"; do pairs+=("$tmp/tree-${pkgs[$i]}.txt" "${@:$((i + 1)):1}"); done
    python3 -I ci/sbom/sbom.py check Cargo.lock "$sbom" "$tmp/both.txt" "$ALLOW_AUDIT_ONLY" "${pairs[@]}"
}

verify "$tmp/sbom.json" "${bins[@]}"
# The same file twice must be the same bytes.
ci/sbom/generate.sh "$tmp/again.json" >/dev/null
cmp "$tmp/sbom.json" "$tmp/again.json"

# Self-test (a): a binary with no audit data must fail.
cp "${bins[0]}" "$tmp/stripped"
objcopy --remove-section .dep-v0 "$tmp/stripped"
if out=$(verify "$tmp/sbom.json" "$tmp/stripped" "${bins[@]:1}" 2>&1); then
    echo "SELFTEST FAIL: a binary without .dep-v0 passed" >&2
    exit 1
fi
grep -q "no embedded audit data" <<<"$out" || { echo "SELFTEST FAIL: wrong reason: $out" >&2; exit 1; }
echo "SELFTEST PASS: a binary without audit data is rejected"

# Self-test (b): an SBOM missing a component must fail.
python3 -I ci/sbom/sbom.py drop "$tmp/sbom.json" serde >"$tmp/short.json"
if out=$(verify "$tmp/short.json" "${bins[@]}" 2>&1); then
    echo "SELFTEST FAIL: an SBOM without serde passed" >&2
    exit 1
fi
grep -q "serde .* is missing from the SBOM" <<<"$out" || { echo "SELFTEST FAIL: wrong reason: $out" >&2; exit 1; }
echo "SELFTEST PASS: an SBOM missing a crate is rejected"
