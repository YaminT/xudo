#!/usr/bin/env bash
# CycloneDX SBOM of the four shipped binaries, from Cargo.lock.
#
#   ci/sbom/generate.sh <musl triple> <output file>      (or: just sbom)
#
# The component set is `cargo tree -e normal,build` for the four binary packages
# on every target platform, the same set `cargo auditable` embeds. Versions and sha256
# checksums come from Cargo.lock. Deterministic: no serialNumber, no timestamp,
# components sorted, no paths.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
triple=${1:?usage: generate.sh <musl triple> <output file>}
out=$(realpath -m "${2:?usage: generate.sh <musl triple> <output file>}")
cd "$root"
tree=$(mktemp)
trap 'rm -f "$tree"' EXIT
cargo tree --locked -e normal,build --target all \
    -p xudo-bin -p xudod-bin -p xudo-gate-bin -p ido-bin --prefix none >"$tree"
mkdir -p "$(dirname "$out")"
python3 -I "$root/ci/sbom/sbom.py" generate "$root/Cargo.lock" "$tree" "$root/Cargo.toml" >"$out"
echo "wrote $out"
