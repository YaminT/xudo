#!/usr/bin/env bash
# The differential compliance matrix: one static `aido` binary and the shipped
# ruleset, driven inside real distributions against the real sudo, sudo-rs, and
# OpenDoas parsers, plus a container with no escalator at all.
#
#   ci/differential/run.sh <static linux aido binary>      (or: just differential)
#
# Each row below names an image and how to install its backend. Inside the
# container, row.sh records two things:
#
#   report.txt    what is backend-specific and must match expected/<row>.txt
#                 exactly: which backend was found, every capability it was
#                 probed to have, whether the install plan is offered or refused,
#                 and whether the snippet aido would write is accepted by that
#                 backend's own parser. Versions are normalized out, so a
#                 package update may not break this but a capability change
#                 must.
#   verdicts.txt  what is policy and must be identical in every row *and* match
#                 expected/verdicts.txt: the engine's answer for every argv in
#                 invocations.txt. No backend may change a verdict.
#
# What this does not do yet: execute anything. `aido doctor` reports the exec
# path as absent, and row.sh fails the moment that stops being true, because at
# that point the comparison that matters — the same ruleset *executed* through
# each backend, with identical outcomes — is due and has to be written here.
#
# Images are moving tags on purpose. Detection is runtime, and the point is to
# notice when a distribution's package changes what its backend can do.
#
# Bless a reviewed change with: cp target/differential.*/<row>/report.txt
# ci/differential/expected/<row>.txt (and likewise verdicts.txt), then commit
# the diff as the policy or backend change it is.
set -euo pipefail

# row | image | setup, run as root inside the container before anything else
rows=(
    "sudo|ubuntu:24.04|apt-get update -qq && apt-get install -y -qq sudo"
    "sudo-rs-0.2|ubuntu:24.04|apt-get update -qq && apt-get install -y -qq sudo-rs"
    "sudo-rs|ubuntu:26.04|apt-get update -qq && apt-get install -y -qq sudo-rs"
    "doas|alpine:3.22|apk add -q doas"
    "none|alpine:3.22|true"
)

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <static linux aido binary>" >&2
    exit 2
fi
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

if [[ ! -x $bin ]]; then
    echo "FAIL: $bin is not an executable" >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker is required to run the matrix" >&2
    exit 1
fi

# Under target/, never /tmp. The container writes here as root.
mkdir -p "$root/target"
out=$(mktemp -d "$root/target/differential.XXXXXX")
echo "differential: transcripts in $out"

fail=0
for spec in "${rows[@]}"; do
    IFS='|' read -r row image setup <<<"$spec"
    echo "== $row  ($image)"
    if ! docker run --rm \
        -v "$bin:/usr/local/bin/aido:ro" \
        -v "$root/rules:/rules:ro" \
        -v "$here:/harness:ro" \
        -v "$out:/out" \
        "$image" sh /harness/row.sh "$row" "$setup"; then
        echo "FAIL: row $row did not complete" >&2
        fail=1
        continue
    fi
    if ! diff -u "$here/expected/$row.txt" "$out/$row/report.txt"; then
        echo "FAIL: row $row: the backend report differs from expected/$row.txt" >&2
        fail=1
    fi
    if ! diff -u "$here/expected/verdicts.txt" "$out/$row/verdicts.txt"; then
        echo "FAIL: row $row: a verdict depends on the backend, or policy changed without its snapshot" >&2
        fail=1
    fi
done

if (( fail )); then
    exit 1
fi
echo "differential: ${#rows[@]} rows, identical verdicts, every backend report as expected"
