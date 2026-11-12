#!/usr/bin/env bash
# The .deb this job built must be byte-identical to the one the reproducible-build
# job built on another runner VM.
#
#   ci/repro/compare.sh <sha file from the repro job> <the built .deb>
#
# Fails closed: a missing or empty sha file, no .deb, more than one .deb, or a
# differing hash all exit 1. The <deb> argument may be a glob; quote it or not.
set -u

if [ $# -ne 2 ]; then
    echo "usage: $0 <sha file> <deb>" >&2
    exit 2
fi
sha_file=$1
shift
echo "runner: ${ImageOS:-unknown} ${ImageVersion:-unknown}"

if [ ! -s "$sha_file" ]; then
    echo "missing or empty sha file: $sha_file" >&2
    exit 1
fi
expected=$(cut -d' ' -f1 "$sha_file" | head -n 1)
if [ -z "$expected" ]; then
    echo "no hash in $sha_file" >&2
    exit 1
fi

debs=()
for f in "$@"; do
    if [ -f "$f" ]; then
        debs+=("$f")
    fi
done
if [ "${#debs[@]}" -ne 1 ]; then
    echo "expected exactly one .deb, found ${#debs[@]}" >&2
    exit 1
fi
if [ ! -s "${debs[0]}" ]; then
    echo "empty .deb: ${debs[0]}" >&2
    exit 1
fi
actual=$(sha256sum "${debs[0]}" | cut -d' ' -f1)
echo "rebuild $expected"
echo "shipped $actual"
if [ "$expected" != "$actual" ]; then
    echo "the .deb differs from the independent rebuild" >&2
    exit 1
fi
