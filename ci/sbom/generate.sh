#!/usr/bin/env bash
# CycloneDX SBOM of the four shipped binaries, from Cargo.lock.
#
#   ci/sbom/generate.sh <output file>      (or: just sbom)
#
# One SBOM for both shipped architectures: the component set is the union of
# `cargo tree -e normal,build` for the four binary packages on the two musl
# targets, so it is the same on any host and carries nothing that only
# cfg(windows) pulls in. Crates only build scripts and proc macros need are
# marked "scope": "excluded". Versions and sha256 checksums come from Cargo.lock.
# Deterministic: no serialNumber, no timestamp, components sorted, no paths.
# Needs the crates already fetched (cargo tree may download them).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
out=$(realpath -m "${1:?usage: generate.sh <output file>}")
cd "$root"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
pkgs=(-p xudo-bin -p xudod-bin -p xudo-gate-bin -p ido-bin)
for triple in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
    # Every crate that is built; then the ones that end up linked (normal edges
    # only, not through a proc macro, whose subtree runs at build time).
    cargo tree --locked -e normal,build --target "$triple" "${pkgs[@]}" --prefix none >>"$tmp/all.txt"
    cargo tree --locked -e normal --no-dedupe --target "$triple" "${pkgs[@]}" --prefix depth >>"$tmp/linked.txt"
done
mkdir -p "$(dirname "$out")"
python3 -I "$root/ci/sbom/sbom.py" generate "$root/Cargo.lock" "$tmp/all.txt" "$tmp/linked.txt" "$root/Cargo.toml" >"$out"
echo "wrote $out"
