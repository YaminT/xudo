#!/bin/sh
# systemd's own checks on every unit file under packaging/, inside a Debian
# trixie container, as root.
#
#   sh /harness/check.sh <exposure ceiling, in tenths>
#
# Expects the repository's packaging/ at /packaging and this directory at
# /harness, both read-only; ci/units/run.sh starts it. POSIX sh only. Two
# checks, each by systemd's own tool, and what each is for:
#
#   verify    `systemd-analyze verify`: the unit loads, what it names exists, and
#             systemd had nothing to say about any line of it. It must be
#             silent, not merely exit 0. For a misspelled directive or a value
#             it cannot parse it prints one warning, ignores the line, and exits
#             0 (measured on systemd 257.13), and a hardening line that is
#             ignored is a unit that starts without the protection. Applies to
#             every unit type.
#   exposure  `systemd-analyze security --offline`: systemd's own score for how
#             much a service's sandbox leaves open, held under a ceiling. It is
#             the net under crates/aidod/tests/units.rs, which asserts each line
#             by name and knows only the lines its author thought of. Applies to
#             services only: given a socket it scores everything a socket does
#             not declare, 9.6 UNSAFE, which means nothing.
#
# The programs the units run are not in the repository, so each absolute path a
# unit names is stubbed with an executable file before verify looks. That keeps
# a unit checkable on its own; it does not check that the package installs the
# program there, which is phase 3's test of the package.
#
# The lane also tests itself, because an exit status that looks like a verdict is
# the thing most worth distrusting here. See self_test.
set -eu
set -f # a path is never a glob

ceiling=$1
export DEBIAN_FRONTEND=noninteractive

# The unit files, by suffix, as regular files only: a symlink in a .wants
# directory points at a unit that is already on this list.
units=$(find /packaging -type f \( -name '*.service' -o -name '*.socket' -o -name '*.timer' \
    -o -name '*.target' -o -name '*.path' -o -name '*.slice' -o -name '*.mount' \
    -o -name '*.automount' -o -name '*.swap' \) | sort)
if [ -z "$units" ]; then
    echo "units: SKIPPED: packaging/ holds no systemd unit files, so there is nothing to check"
    exit 0
fi

log=$(mktemp)
if ! { apt-get -o Acquire::Retries=3 update -qq &&
    apt-get -o Acquire::Retries=3 install -y -qq --no-install-recommends systemd; } >"$log" 2>&1; then
    echo "FAIL: could not install systemd in the container (this lane needs the network):" >&2
    tail -n 20 "$log" >&2
    exit 1
fi
echo "units: $(systemd-analyze --version | sed -n 1p)"

# 12 -> 1.2, the way systemd-analyze prints a level.
tenths() {
    echo "$(($1 / 10)).$(($1 % 10))"
}

# An executable file at every absolute path a unit (or a drop-in for one) runs.
# The modifiers that may precede a program (`-`, `@`, `:`, `+`, `!`) are not
# part of its name; an empty value resets the list and names nothing.
stub_executables() {
    for file in "$@" $(find /packaging -type f -path '*.d/*.conf'); do
        sed -n -E 's/^[[:space:]]*Exec[A-Za-z]*[[:space:]]*=[[:space:]]*[-@:+!]*//p' "$file" |
            while read -r program _; do
                case $program in
                    /*)
                        if [ ! -e "$program" ]; then
                            mkdir -p "$(dirname "$program")"
                            cp /bin/true "$program"
                        fi
                        ;;
                esac
            done
    done
}

# check_units <unit file>...: one FAIL line per finding on standard error, each
# naming the check that made it, and a return status of 1 if there was any.
check_units() {
    bad=0
    stub_executables "$@"

    out=$(systemd-analyze verify --man=no "$@" 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ] || [ -n "$out" ]; then
        echo "FAIL: verify: systemd-analyze verify exited $rc, and it must exit 0 and say nothing:" >&2
        printf '%s\n' "$out" >&2
        bad=1
    fi

    for unit in "$@"; do
        case $unit in
            *.service) ;;
            *) continue ;;
        esac
        out=$(systemd-analyze security --offline=true --no-pager --threshold="$ceiling" "$unit" 2>&1) && rc=0 || rc=$?
        overall=$(printf '%s\n' "$out" | sed -n 's/^.*\(Overall exposure level for .*\)$/\1/p')
        if [ "$rc" -ne 0 ]; then
            if [ -n "$overall" ]; then
                echo "FAIL: exposure: $unit: $overall, ceiling $(tenths "$ceiling"); the lines that cost it:" >&2
                printf '%s\n' "$out" | grep '^✗' >&2 || true
            else
                echo "FAIL: exposure: $unit: systemd-analyze security exited $rc without an exposure level; what it printed:" >&2
                printf '%s\n' "$out" >&2
            fi
            bad=1
        else
            echo "units: $unit: $overall, ceiling $(tenths "$ceiling")"
        fi
    done
    return "$bad"
}

# refuses <what is wrong> <check that must refuse it> <file> <sed script>
#
# Damages the control pair in exactly one way and requires the check named, and
# not merely some check, to refuse it. A change that alters nothing is itself a
# failure, so a control that drifts away from its own mutations cannot turn the
# test into one that passes for want of anything to test.
refuses() {
    what=$1 check=$2 target=$3 script=$4
    dir=$(mktemp -d)
    cp /harness/control/control.socket /harness/control/control.service "$dir/"
    sed -i -e "$script" "$dir/$target"
    if cmp -s "$dir/$target" "/harness/control/$target"; then
        echo "FAIL: self-test: the change for '$what' altered nothing, so it proves nothing" >&2
        return 1
    fi
    if out=$(check_units "$dir/control.socket" "$dir/control.service" 2>&1); then
        echo "FAIL: self-test: '$what' was accepted" >&2
        return 1
    fi
    case $out in
        *"FAIL: $check:"*) echo "units: self-test: $what: refused by $check" ;;
        *)
            echo "FAIL: self-test: '$what' was refused, but not by $check:" >&2
            printf '%s\n' "$out" >&2
            return 1
            ;;
    esac
}

# The control pair in ci/units/control/ must be accepted, and each damage below
# must be refused by the check that exists for it. If systemd-analyze changes how
# it reports one of these, or a later edit to this file stops looking, this is
# where the lane fails, instead of passing for the units that happen to be
# clean today.
self_test() {
    dir=$(mktemp -d)
    cp /harness/control/control.socket /harness/control/control.service "$dir/"
    if ! out=$(check_units "$dir/control.socket" "$dir/control.service" 2>&1); then
        echo "FAIL: self-test: the control pair was refused, so every refusal below would prove nothing:" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi
    echo "units: self-test: the control pair is accepted"

    failed=0
    refuses "a hardening directive misspelled" verify control.service \
        's/^NoNewPrivileges=/NoNewPrivilegs=/' || failed=1
    refuses "a value systemd cannot parse" verify control.service \
        's/^RuntimeMaxSec=30$/RuntimeMaxSec=banana/' || failed=1
    refuses "a hardening directive under the wrong heading" verify control.service \
        '/^ProtectKernelLogs=yes$/d;/^\[Unit\]$/a ProtectKernelLogs=yes' || failed=1
    refuses "a dependency no unit provides" verify control.service \
        '/^\[Unit\]$/a Requires=aido-units-lane-missing.service' || failed=1
    refuses "a socket directive misspelled" verify control.socket \
        's/^SocketMode=/SocketModee=/' || failed=1
    refuses "a sandbox directive removed" exposure control.service \
        '/^PrivateNetwork=yes$/d' || failed=1
    return "$failed"
}

self_test

# shellcheck disable=SC2086 # the list is newline-separated paths, split on purpose
set -- $units
echo "units: checking $# unit file(s)"
check_units "$@"
echo "units: every unit file is accepted by systemd-analyze verify, and every service is within the exposure ceiling"
