#!/bin/sh
# One row of the differential matrix, run inside that row's container as root.
#
#   sh /harness/row.sh <row> <setup command>
#
# Expects the static xudo binary at /usr/local/bin/xudo, its siblings in /bins, the
# shipped rules at /rules, this directory at /harness, and a writable /out. POSIX sh only: the
# Alpine rows have busybox, the Ubuntu rows have dash.
#
# Writes /out/<row>/report.txt (the backend-specific facts, normalized) and
# /out/<row>/verdicts.txt (the policy answers, which must not be backend-specific
# at all), with the raw transcripts beside them. run.sh does the comparing.
set -eu
set -f # an invocation token is never a glob

row=$1
setup=$2
xudo=/usr/local/bin/xudo
rules=/rules
harness=/harness
out=/out/$row
mkdir -p "$out"
export DEBIAN_FRONTEND=noninteractive

if ! sh -c "$setup" >"$out/setup.log" 2>&1; then
    echo "row $row: setup failed:" >&2
    cat "$out/setup.log" >&2
    exit 1
fi

# xudo must not consult its environment, but the harness still hands it a
# known one so that a difference between rows cannot come from here.
run_xudo() {
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$xudo" --rules "$rules" "$@"
}

report=$out/report.txt
: >"$report"

# 1. Which backend was found and what it was probed to support. The version is
#    normalized away: the distribution's package moves, the capability matrix
#    must not.
run_xudo doctor >"$out/doctor.txt" 2>&1 || true
sed -nE \
    -e 's/^(backend      (sudo|sudo-rs|doas)) \(.*\)$/\1 (<version>)/p' \
    -e 's/^(backend      UNUSABLE: [a-z-]+) .* (is missing a required control .*)$/\1 <version> \2/p' \
    -e '/^backend      NONE/p' \
    -e '/^backend caps /p' \
    -e '/^ +absent: /p' \
    "$out/doctor.txt" >>"$report"

# 2. The install plan: refused with exit 19 where nothing usable exists,
#    printed in full where something does — and then the one file xudo would
#    write is handed to that backend's own parser.
set +e
run_xudo install --dry-run --show-contents >"$out/install.txt" 2>&1
rc=$?
set -e
echo "install      exit $rc" >>"$report"
if [ "$rc" -eq 0 ]; then
    kind=$(sed -nE 's/^plan for     (.*)$/\1/p' "$out/install.txt")
    echo "plan for     $kind" >>"$report"
    # The contents of the step that writes xudo's rule, exactly as it would land.
    awk '/^   [0-9]+\. (write candidate|append xudo.s block)/ { grab = 1; next }
         /^   [0-9]+\. / { grab = 0 }
         grab && sub(/^      \| ?/, "")' "$out/install.txt" >"$out/snippet.txt"
    # The validator the plan itself names, pointed at stdin instead of the
    # candidate file. The plan's own argv, not one chosen here: if the plan
    # names a validator that does not exist on this distribution, or passes it
    # an argument that changes the question, this is where it shows.
    validator=$(sed -nE 's/^   [0-9]+\. validate: (.*) \{candidate\}$/\1/p' "$out/install.txt")
    if [ -z "$validator" ]; then
        echo "row $row: the plan for $kind names no validate step ending in {candidate}" >&2
        exit 1
    fi
    validator="$validator /dev/stdin"
    if $validator <"$out/snippet.txt" >"$out/validate.log" 2>&1; then
        echo "snippet      accepted by $validator" >>"$report"
    else
        echo "snippet      REJECTED by $validator" >>"$report"
        cat "$out/validate.log" >>"$report"
    fi
else
    sed -nE \
        -e 's/^xudo: no usable backend: no privilege backend found.*$/refused      no privilege backend found/p' \
        -e 's/^xudo: no usable backend: ([a-z-]+) .* is missing a required control.*$/refused      \1 <version> is missing a required control/p' \
        "$out/install.txt" >>"$report"
fi

# 3. The ruleset itself is accepted. Its generation hash is not pinned here;
#    the verdicts below are what a rule change must answer for.
set +e
run_xudo check >"$out/check.txt" 2>&1
rc=$?
set -e
echo "check        exit $rc" >>"$report"

# 4. The policy answers. Every line of invocations.txt is one argv, split on
#    whitespace. Only the fields that are a decision are recorded: a backend
#    cannot be allowed to change any of them, and a rule change must change them
#    in every row at once.
verdicts=$out/verdicts.txt
: >"$verdicts"
while IFS= read -r line; do
    case $line in '' | '#'*) continue ;; esac
    # shellcheck disable=SC2086
    set -- $line
    echo "# $line" >>"$verdicts"
    set +e
    run_xudo --output json explain -- "$@" >"$out/explain.json" 2>"$out/explain.err"
    rc=$?
    set -e
    grep -E '^  "(verdict|denial|action)":' "$out/explain.json" >>"$verdicts" || true
    echo "exit $rc" >>"$verdicts"
    echo >>"$verdicts"
done <"$harness/invocations.txt"

# 5. The same ruleset executed through the backend (exec.sh): exec.txt, which
#    must be identical in every row with a backend. With none, `xudo exec` has
#    nothing to run through and says so with exit 19.
sh "$harness/exec.sh" "$row"
