#!/usr/bin/env bash
# Each shipped binary embeds a non-empty dependency list, and the SBOM lists every
# crate in it and every crate of `cargo tree -e normal`, at the Cargo.lock version.
#
#   ci/sbom/check.sh <musl triple>        (or: just sbom-check; builds with `just deb`)
#
# No network: it reads target/<triple>/release, Cargo.lock and the local registry.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
triple=${1:?usage: check.sh <musl triple>}
cd "$root"
command -v objcopy >/dev/null || { echo "FAIL: objcopy (binutils) is required" >&2; exit 1; }
bin=target/$triple/release
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
ci/sbom/generate.sh "$triple" "$tmp/sbom.json" >/dev/null
cargo tree --locked -e normal --target "$triple" \
    -p xudo-bin -p xudod-bin -p xudo-gate-bin -p ido-bin --prefix none >"$tmp/tree.txt"
python3 -I ci/sbom/sbom.py check Cargo.lock "$tmp/tree.txt" "$tmp/sbom.json" \
    "$bin/xudo" "$bin/ido" "$bin/xudod" "$bin/xudo-gate"
# The same file twice must be the same bytes.
ci/sbom/generate.sh "$triple" "$tmp/again.json" >/dev/null
cmp "$tmp/sbom.json" "$tmp/again.json"
