#!/usr/bin/env bash
# systemd's own checks on every unit file under packaging/, in a Debian trixie
# container.
#
#   ci/units/run.sh <exposure ceiling, e.g. 1.2>      (or: just units)
#
# `systemd-analyze verify` and `systemd-analyze security --offline` need systemd
# and a Linux kernel to read units against, and the current stable Debian's
# systemd is the one the package's own users will have. So the lane is a
# container, as ci/differential is, and the same moving tag on purpose:
# trixie is a stable release, so what moves is point-release fixes, and a fix
# that changes how a unit is judged is a change worth seeing. The same unit was
# scored 1.1 on arm64 and on amd64.
#
# ci/units/check.sh does the work inside the container and says what each check
# is for. This script only decides whether there is anything to check.
#
# The ceiling is an exposure level as `systemd-analyze security` prints it
# (0.0 to 10.0, lower is tighter), set in the justfile. It is the one number
# here that can only go up by being changed, and a change to it is a reviewed
# one: fix the unit, or say why the exposure is the price of what it does.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <exposure ceiling, e.g. 1.2>" >&2
    exit 2
fi
if [[ ! $1 =~ ^[0-9]+\.[0-9]$ ]]; then
    echo "FAIL: '$1' is not an exposure level like 1.2" >&2
    exit 2
fi
# systemd-analyze takes a whole number of tenths. The base is stated so that a
# ceiling of 0.8 is not read as a bad octal number.
tenths=$((10#${1/./}))

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
packaging="$root/packaging"

# Nothing to check yet is not a failure, and not silent either: a lane that skips
# without saying so reads as a lane that passed. Once packaging/ exists, check.sh
# decides what an empty one means.
if [[ ! -d $packaging ]]; then
    echo "units: SKIPPED: there is no packaging/ directory yet, so there is no unit to check"
    exit 0
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker is required" >&2
    exit 1
fi

docker run --rm \
    -v "$packaging:/packaging:ro" \
    -v "$here:/harness:ro" \
    debian:trixie-slim sh /harness/check.sh "$tenths"
