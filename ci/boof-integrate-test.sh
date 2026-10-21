#!/usr/bin/env bash
# Proof for ci/boof-integrate.sh, the boof onApproved hook.
#
#   /bin/bash ci/boof-integrate-test.sh
#
# Every case builds its own world in a temporary directory: a bare "origin", a
# clone of it that holds the script (the "main checkout"), and a task worktree.
# `gh` and `just` are fakes first on PATH, and the origin remote's URL is a
# GitHub one that git rewrites (insteadOf) to the bare repository, so the
# script's URL parsing runs for real and nothing here can reach GitHub.
#
# Runs under /bin/bash, as the hook does: bash 3.2 on macOS.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
tmp=$(cd "$(mktemp -d)" && pwd -P)
trap 'rm -rf "$tmp"' EXIT

# TMPDIR isolates the hook's lock from any real run.
export TMPDIR=$tmp
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=$tmp/gitconfig
export PATH=$tmp/bin:$PATH
export BOOF_INTEGRATE_POLL=0
export BOOF_INTEGRATE_APPEAR_TIMEOUT=3
export BOOF_INTEGRATE_MAIN_TIMEOUT=10

git config --global user.name "Boof Test"
git config --global user.email "boof-test@example.invalid"
git config --global init.defaultBranch main
git config --global commit.gpgsign false
git config --global core.hooksPath /dev/null

mkdir "$tmp/bin"
cat >"$tmp/bin/gh" <<'EOF'
#!/bin/bash
# Fake gh: logs argv, answers `run list --commit SHA` from $FAKE/runs.
echo "$*" >>"$FAKE/gh.log"
repo="" sha=""
while [ $# -gt 0 ]; do
    case $1 in
    -R) repo=$2; shift ;;
    --commit) sha=$2; shift ;;
    esac
    shift
done
if [ "$repo" != test/aido ]; then
    echo "fake gh: unexpected repository '$repo'" >&2
    exit 2
fi
if [ -f "$FAKE/runs/$sha" ]; then
    cat "$FAKE/runs/$sha"
else
    cat "$FAKE/runs/default"
fi
EOF
cat >"$tmp/bin/just" <<'EOF'
#!/bin/bash
# Fake just: logs start and end, optionally sleeps and runs a hook, and exits
# with $FAKE/exit-<recipe>.
echo "start $1" >>"$FAKE/just.log"
if [ -f "$FAKE/sleep" ]; then
    sleep "$(cat "$FAKE/sleep")"
fi
if [ -f "$FAKE/hook-$1" ]; then
    bash "$FAKE/hook-$1"
fi
echo "GATE-MARKER-$1"
code=0
if [ -f "$FAKE/exit-$1" ]; then
    code=$(cat "$FAKE/exit-$1")
fi
if [ "$code" -eq 0 ]; then
    echo "end $1" >>"$FAKE/just.log"
fi
exit "$code"
EOF
chmod +x "$tmp/bin/gh" "$tmp/bin/just"

# ---- world ---------------------------------------------------------------
dir="" # the current case's directory
failures=0
problems=""

commit_file() { # commit_file CHECKOUT FILE CONTENT SUBJECT
    printf '%s\n' "$3" >"$1/$2"
    git -C "$1" add "$2"
    git -C "$1" commit -q -m "$4"
}

# fixture NAME: origin, main checkout, and a task worktree with one commit.
fixture() {
    dir=$tmp/$1
    mkdir -p "$dir/fake/runs"
    printf 'completed\tsuccess\thttps://example.invalid/run/1\n' >"$dir/fake/runs/default"
    git init -q --bare "$dir/origin.git"
    git clone -q "$dir/origin.git" "$dir/main" 2>/dev/null
    mkdir "$dir/main/ci"
    cp "$here/boof-integrate.sh" "$dir/main/ci/boof-integrate.sh"
    printf 'line one\n' >"$dir/main/README"
    printf '/target\n' >"$dir/main/.gitignore"
    git -C "$dir/main" add -A
    git -C "$dir/main" commit -q -m "chore: seed"
    git -C "$dir/main" push -q origin HEAD:main
    git -C "$dir/main" remote set-url origin git@github.com:test/aido.git
    git -C "$dir/main" config "url.$dir/origin.git.insteadOf" git@github.com:test/aido.git
    git -C "$dir/main" fetch -q origin
    git -C "$dir/main" branch -q --set-upstream-to=origin/main main
    add_worktree wt "boof-runner/$1" thing
    git clone -q "$dir/origin.git" "$dir/side" 2>/dev/null
}

# add_worktree DIRNAME BRANCH FILE: a worktree with one good commit.
add_worktree() {
    git -C "$dir/main" worktree add -q "$dir/$1" -b "$2"
    commit_file "$dir/$1" "$3" "$3" "feat: add $3"
}

origin_head() { git -C "$dir/origin.git" rev-parse main; }

# hook_env WORKTREE BRANCH [BASE]: the variables boof sets. BOOF_BASE is a
# commit sha, as boof passes it; by default the seed commit on origin.
hook_env() {
    local base=${3:-$(git -C "$dir/origin.git" rev-parse "$(git -C "$dir/origin.git" rev-list --max-parents=0 main)")}
    printf 'FAKE=%s BOOF_TASK_ID=%s BOOF_TASK_TITLE=title BOOF_BRANCH=%s BOOF_BASE=%s BOOF_WORKTREE=%s BOOF_WORKING_DIRECTORY=%s BOOF_DATA_ROOT=%s' \
        "$dir/fake" "${2##*/}" "$2" "$base" "$1" "$1" "$dir/data"
}

# run_hook OUTFILE [WORKTREE BRANCH SCRIPT [ARG...]]: sets RC; output is in OUTFILE.
run_hook() {
    local out=$1 wt=${2:-$dir/wt} branch=${3:-boof-runner/${dir##*/}} script=${4:-$dir/main/ci/boof-integrate.sh}
    local extra=()
    if [[ $# -gt 4 ]]; then
        extra=("${@:5}")
    fi
    RC=0
    (
        cd "$wt"
        # shellcheck disable=SC2046 # the words are KEY=value pairs by construction
        env $(hook_env "$wt" "$branch" "${BASE_OVERRIDE:-}") /bin/bash "$script" ${extra[@]+"${extra[@]}"}
    ) >"$out" 2>&1 || RC=$?
}

# ---- expectations --------------------------------------------------------
begin() {
    problems=""
    echo "--- $1"
}
expect() { # expect DESCRIPTION CONDITION-EXIT-STATUS
    if [[ $2 -ne 0 ]]; then
        problems="$problems
    expected: $1"
    fi
}
expect_fail() { expect "the hook exits non-zero (got $RC)" "$((RC == 0))"; }
expect_out() { # expect_out OUTFILE PATTERN
    local s=0
    grep -Eq -- "$2" "$1" || s=1
    expect "output matches /$2/" "$s"
}
expect_same() { expect "$3" "$([[ $1 == "$2" ]] && echo 0 || echo 1)"; }
expect_absent() { expect "$1 does not exist" "$([[ ! -e $1 ]] && echo 0 || echo 1)"; }
finish() { # finish OUTFILE
    if [[ -z $problems ]]; then
        echo "PASS $1"
    else
        echo "FAIL $1$problems"
        echo "    output was:"
        sed 's/^/    | /' "$2"
        failures=$((failures + 1))
    fi
}

# ---- cases ---------------------------------------------------------------
case_bad_subject() {
    begin "a bad subject is refused at step d"
    fixture bad-subject
    commit_file "$dir/wt" other other "WIP stuff"
    local bad before
    bad=$(git -C "$dir/wt" rev-parse --short HEAD)
    before=$(origin_head)
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'step d'
    expect_out "$dir/out" "$bad WIP stuff"
    expect_absent "$dir/fake/just.log"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish bad-subject "$dir/out"
}

case_conflict() {
    begin "a conflict aborts at step f and pushes nothing"
    fixture conflict
    commit_file "$dir/wt" README "task change" "feat: edit readme"
    commit_file "$dir/side" README "origin change" "fix: edit readme"
    git -C "$dir/side" push -q origin HEAD:main
    local before head
    before=$(origin_head)
    head=$(git -C "$dir/wt" rev-parse HEAD)
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'step f'
    expect_absent "$(git -C "$dir/wt" rev-parse --git-path rebase-merge)"
    expect_absent "$(git -C "$dir/wt" rev-parse --git-path rebase-apply)"
    expect_same "$(git -C "$dir/wt" rev-parse HEAD)" "$head" "the worktree is back at its own HEAD"
    expect_same "$(git -C "$dir/wt" status --porcelain)" "" "the worktree is clean"
    expect_absent "$dir/fake/just.log"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish conflict "$dir/out"
}

case_red_main() {
    begin "a red CI on main refuses at step e"
    fixture red-main
    local before
    before=$(origin_head)
    printf 'completed\tfailure\thttps://example.invalid/run/red\n' >"$dir/fake/runs/$before"
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'step e: main is not green'
    expect_out "$dir/out" 'https://example.invalid/run/red'
    expect_absent "$dir/fake/just.log"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish red-main "$dir/out"
}

case_pending_then_missing() {
    begin "main with no run at all is refused at step e, not assumed green"
    fixture no-runs
    local before
    before=$(origin_head)
    : >"$dir/fake/runs/$before"
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'step e: main is not green: no Actions run appeared'
    expect_absent "$dir/fake/just.log"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish no-runs "$dir/out"
}

case_gate_fails() {
    begin "a failing gate refuses at step g"
    fixture gate-fails
    local before
    before=$(origin_head)
    echo 1 >"$dir/fake/exit-verify"
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'step g: just verify failed'
    expect_out "$dir/out" 'GATE-MARKER-verify'
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish gate-fails "$dir/out"
}

case_push_rejected() {
    begin "a rejected push is retried and then fails"
    fixture push-rejected
    cat >"$dir/fake/hook-verify" <<EOF
set -e
cd "$dir/side"
git pull -q origin main
echo "\$RANDOM \$\$ \$(date +%s)" >>moved
git add moved
git commit -q -m "chore: move main"
git push -q origin HEAD:main
EOF
    local task
    task=$(git -C "$dir/wt" rev-parse HEAD)
    run_hook "$dir/out"
    expect_fail
    expect_same "$(grep -c '^start verify' "$dir/fake/just.log")" 3 "the gate ran exactly 3 times"
    expect_out "$dir/out" 'push rejected 3 times'
    expect "origin main does not hold the task commit" \
        "$(git -C "$dir/origin.git" merge-base --is-ancestor "$task" main 2>/dev/null && echo 1 || echo 0)"
    finish push-rejected "$dir/out"
}

case_worktree_copy() {
    begin "the copy inside the worktree refuses to run at step a"
    fixture worktree-copy
    local before
    before=$(origin_head)
    run_hook "$dir/out" "$dir/wt" "boof-runner/worktree-copy" "$dir/wt/ci/boof-integrate.sh"
    expect_fail
    expect_out "$dir/out" 'step a: refusing to run the copy inside the task worktree'
    expect_absent "$dir/fake/gh.log"
    expect_absent "$dir/fake/just.log"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish worktree-copy "$dir/out"
}

case_missing_variable() {
    begin "a missing BOOF_* variable refuses at step a"
    fixture missing-var
    RC=0
    (cd "$dir/wt" && env FAKE="$dir/fake" BOOF_BASE=main BOOF_BRANCH=boof-runner/missing-var \
        /bin/bash "$dir/main/ci/boof-integrate.sh") >"$dir/out" 2>&1 || RC=$?
    expect_fail
    expect_out "$dir/out" 'step a: BOOF_TASK_ID is not set'
    expect_absent "$dir/fake/just.log"
    finish missing-var "$dir/out"
}

case_dirty_worktree() {
    begin "a dirty worktree refuses at step b"
    fixture dirty
    printf 'stray\n' >"$dir/wt/stray"
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'step b: the worktree is not clean'
    expect_absent "$dir/fake/just.log"
    finish dirty "$dir/out"
}

case_concurrency() {
    begin "two concurrent runs are serialized by the lock"
    fixture concurrent
    add_worktree wt2 boof-runner/concurrent-2 thing2
    echo 2 >"$dir/fake/sleep"
    local rc1 rc2 pid1 pid2 alternates=0
    (
        cd "$dir/wt"
        # shellcheck disable=SC2046
        env $(hook_env "$dir/wt" boof-runner/concurrent) /bin/bash "$dir/main/ci/boof-integrate.sh"
    ) >"$dir/out1" 2>&1 &
    pid1=$!
    (
        cd "$dir/wt2"
        # shellcheck disable=SC2046
        env $(hook_env "$dir/wt2" boof-runner/concurrent-2) /bin/bash "$dir/main/ci/boof-integrate.sh"
    ) >"$dir/out2" 2>&1 &
    pid2=$!
    rc1=0 rc2=0
    wait "$pid1" || rc1=$?
    wait "$pid2" || rc2=$?
    expect_same "$rc1" 0 "the first run exits 0"
    expect_same "$rc2" 0 "the second run exits 0"
    expect "one run printed 'waiting for another integration'" \
        "$(cat "$dir/out1" "$dir/out2" | grep -q 'waiting for another integration' && echo 0 || echo 1)"
    awk '
        $1 == "start" { if (open) bad = 1; open = 1; starts++ }
        $1 == "end"   { if (!open) bad = 1; open = 0 }
        END { exit (bad || open || starts != 4) }
    ' "$dir/fake/just.log" && alternates=1
    expect "gate steps strictly alternate start/end, 4 of them" "$((alternates == 1 ? 0 : 1))"
    git -C "$dir/origin.git" cat-file -e "main:thing" 2>/dev/null || expect "origin main holds 'thing'" 1
    git -C "$dir/origin.git" cat-file -e "main:thing2" 2>/dev/null || expect "origin main holds 'thing2'" 1
    expect_absent "$tmp/aido-boof-integrate.lock"
    local combined="$dir/out"
    cat "$dir/out1" "$dir/out2" >"$combined"
    finish concurrent "$combined"
}

case_happy_path() {
    begin "the happy path pushes and fast-forwards the main checkout"
    fixture happy
    run_hook "$dir/out"
    expect_same "$RC" 0 "the hook exits 0"
    expect_same "$(origin_head)" "$(git -C "$dir/wt" rev-parse HEAD)" "origin main is the worktree HEAD"
    expect_same "$(git -C "$dir/main" rev-parse HEAD)" "$(origin_head)" "the main checkout was fast-forwarded"
    expect_out "$dir/out" 'boof-integrate: landed [0-9a-f]{40} on main; base [0-9a-f]{40}; CI success; https://example.invalid/run/1'
    expect_same "$(grep -c '^start' "$dir/fake/just.log")" 2 "the gate ran verify and linux-test once each"
    expect_absent "$tmp/aido-boof-integrate.lock"
    expect "no GATE FILES CHANGED block" "$(grep -q 'GATE FILES CHANGED' "$dir/out" && echo 1 || echo 0)"
    finish happy "$dir/out"
}

case_base_sha_not_on_main() {
    begin "a BOOF_BASE sha that is not on main still integrates"
    fixture base-sha
    local lane
    git -C "$dir/main" worktree remove --force "$dir/wt"
    git -C "$dir/main" branch -q -D boof-runner/base-sha
    git -C "$dir/main" worktree add -q "$dir/wt" -b boof-runner/base-sha
    commit_file "$dir/wt" lane lane "feat: lane work"
    lane=$(git -C "$dir/wt" rev-parse HEAD)
    commit_file "$dir/wt" task task "feat: task work"
    BASE_OVERRIDE=$lane run_hook "$dir/out"
    expect_same "$RC" 0 "the hook exits 0"
    expect_same "$(origin_head)" "$(git -C "$dir/wt" rev-parse HEAD)" "origin main holds the task commit"
    expect_out "$dir/out" "base $lane"
    finish base-sha "$dir/out"
}

case_gate_files_changed() {
    begin "a change to a gate file is flagged, not refused"
    fixture gate-files
    mkdir -p "$dir/wt/ci"
    commit_file "$dir/wt" ci/foo.sh foo "ci: add foo"
    run_hook "$dir/out"
    expect_same "$RC" 0 "the hook exits 0"
    expect_out "$dir/out" 'GATE FILES CHANGED'
    expect_out "$dir/out" '  ci/foo\.sh'
    expect_same "$(origin_head)" "$(git -C "$dir/wt" rev-parse HEAD)" "origin main holds the task commit"
    finish gate-files "$dir/out"
}

case_allow_red_main() {
    begin "--allow-red-main skips step e only"
    fixture allow-red
    local before
    before=$(origin_head)
    printf 'completed\tfailure\thttps://example.invalid/run/red\n' >"$dir/fake/runs/$before"
    run_hook "$dir/out" "$dir/wt" "boof-runner/allow-red" "$dir/main/ci/boof-integrate.sh" --allow-red-main
    expect_same "$RC" 0 "the hook exits 0"
    expect_out "$dir/out" 'skipping step e'
    expect_same "$(origin_head)" "$(git -C "$dir/wt" rev-parse HEAD)" "origin main holds the task commit"
    finish allow-red "$dir/out"
}

case_unknown_argument() {
    begin "an unknown argument is refused at step a"
    fixture bogus-arg
    local before
    before=$(origin_head)
    run_hook "$dir/out" "$dir/wt" "boof-runner/bogus-arg" "$dir/main/ci/boof-integrate.sh" --bogus
    expect_fail
    expect_out "$dir/out" "step a: unknown argument '--bogus'"
    expect_absent "$dir/fake/gh.log"
    expect_absent "$dir/fake/just.log"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish bogus-arg "$dir/out"
}

case_symlink_to_worktree_copy() {
    begin "a symlink to the worktree copy refuses at step a"
    fixture symlink
    local before
    before=$(origin_head)
    mkdir -p "$dir/wt/ci"
    cp "$here/boof-integrate.sh" "$dir/wt/ci/boof-integrate.sh"
    ln -s "$dir/wt/ci/boof-integrate.sh" "$dir/main/ci/x.sh"
    run_hook "$dir/out" "$dir/wt" "boof-runner/symlink" "$dir/main/ci/x.sh"
    expect_fail
    expect_out "$dir/out" 'step a: refusing to run the copy inside the task worktree'
    expect_absent "$dir/fake/gh.log"
    expect_absent "$dir/fake/just.log"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    finish symlink "$dir/out"
}

case_push_refused_not_moved() {
    begin "a push refused while main did not move fails at step h without a retry"
    fixture refused
    local before
    before=$(origin_head)
    printf '#!/bin/sh\necho "refused by test" >&2\nexit 1\n' >"$dir/origin.git/hooks/pre-receive"
    chmod +x "$dir/origin.git/hooks/pre-receive"
    git -C "$dir/origin.git" config core.hooksPath "$dir/origin.git/hooks"
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'step h: git push failed \(main did not move\)'
    expect_same "$(grep -c '^start verify' "$dir/fake/just.log")" 1 "the gate ran once"
    expect "no retry message" "$(grep -q 'push rejected 3 times' "$dir/out" && echo 1 || echo 0)"
    expect_same "$(origin_head)" "$before" "origin main is unchanged"
    expect_absent "$tmp/aido-boof-integrate.lock"
    finish refused "$dir/out"
}

case_red_after_push() {
    begin "a red CI on the pushed commit fails loudly"
    fixture red-after
    local seed
    seed=$(origin_head)
    printf 'completed\tsuccess\thttps://example.invalid/run/seed\n' >"$dir/fake/runs/$seed"
    printf 'completed\tfailure\thttps://example.invalid/run/boom\n' >"$dir/fake/runs/default"
    run_hook "$dir/out"
    expect_fail
    expect_out "$dir/out" 'MAIN IS NOW RED'
    expect_out "$dir/out" 'https://example.invalid/run/boom'
    expect_same "$(origin_head)" "$(git -C "$dir/wt" rev-parse HEAD)" "origin main holds the task commit"
    expect_absent "$tmp/aido-boof-integrate.lock"
    expect_same "$(git -C "$dir/main" rev-parse HEAD)" "$seed" "the main checkout is not fast-forwarded"
    finish red-after "$dir/out"
}

case_bad_subject
case_conflict
case_red_main
case_pending_then_missing
case_gate_fails
case_push_rejected
case_worktree_copy
case_missing_variable
case_dirty_worktree
case_concurrency
case_happy_path
case_base_sha_not_on_main
case_gate_files_changed
case_allow_red_main
case_unknown_argument
case_symlink_to_worktree_copy
case_push_refused_not_moved
case_red_after_push

echo
if [[ $failures -ne 0 ]]; then
    echo "boof-integrate-test: $failures case(s) FAILED"
    exit 1
fi
echo "boof-integrate-test: all cases passed"
