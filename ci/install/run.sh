#!/usr/bin/env bash
# `aido install` and `aido install --uninstall`, run for real as root inside a
# container of its own, against real sudo, sudo-rs, and OpenDoas.
#
#   ci/install/run.sh <static linux aido binary>          (or: just install-root)
#
# Why this is not part of `just linux-test`: that suite runs as an unprivileged
# user on purpose, because root ignores file modes and every "a writable file is
# refused" test would pass vacuously. The install writes under /etc as root, so
# it has to be exercised somewhere that really is root and really is disposable.
# Each row below is a fresh container, started here, thrown away after.
#
# What each row proves is in row.sh. In short: the install refuses anyone but
# root; it lays down exactly the file the plan names, 0440 or 0400 root:root,
# validated by the backend's own parser; it never replaces or removes a file it
# did not write; a backend that rejects the candidate leaves the old state as it
# was; and uninstall removes exactly what install wrote and nothing else.
#
# The one thing it does NOT prove is that the gate runs as root through the rule:
# `aido install` cannot yet ask the broker for a request (M2b plan item C1), so
# its functional probe is missing. row.sh asserts the install says so, loudly,
# rather than claiming to have verified. The root lane (`just root-test`, job
# `root-tests`) proves that path with a hand-written request, for sudo. This
# harness overlaps it for sudo's install and uninstall and stays for sudo-rs and
# OpenDoas, which the root lane does not install.
set -euo pipefail

# row | image | setup, run as root inside the container before anything else
rows=(
    "sudo|ubuntu:24.04|apt-get update -qq && apt-get install -y -qq sudo"
    "sudo-rs-0.2|ubuntu:24.04|apt-get update -qq && apt-get install -y -qq sudo-rs"
    "sudo-rs|ubuntu:26.04|apt-get update -qq && apt-get install -y -qq sudo-rs"
    "doas|alpine:3.22|apk add -q doas"
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
    echo "FAIL: docker is required" >&2
    exit 1
fi

# Under target/, never /tmp. The container writes here as root.
mkdir -p "$root/target"
out=$(mktemp -d "$root/target/install-root.XXXXXX")
echo "install-root: transcripts in $out"

fail=0
for spec in "${rows[@]}"; do
    IFS='|' read -r row image setup <<<"$spec"
    echo "== $row  ($image)"
    if ! docker run --rm \
        -v "$bin:/usr/local/bin/aido:ro" \
        -v "$here:/harness:ro" \
        -v "$out:/out" \
        "$image" sh /harness/row.sh "$row" "$setup"; then
        echo "FAIL: row $row" >&2
        fail=1
    fi
done

if ((fail)); then
    exit 1
fi
echo "install-root: ${#rows[@]} rows, install and uninstall behaved as the plan says"
