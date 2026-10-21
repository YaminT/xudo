#!/usr/bin/env bash
# The boof `settings.hooks.onApproved` hook: lands an approved task on main.
#
#   /bin/bash <main checkout>/ci/boof-integrate.sh [--allow-red-main]
#
# boof runs it from the task worktree with BOOF_TASK_ID, BOOF_BRANCH,
# BOOF_BASE and BOOF_WORKTREE set. Exit 0 marks the task done; anything else
# fails it and keeps its branch and worktree. BOOF_BASE is the task's base
# commit sha: informational only, compared with nothing, because the hook
# always lands on origin/main whatever the task was based on.
#
# --allow-red-main skips step e only, so a fix-forward task can land while main
# is red. It is for a dedicated hotfix data root whose onApproved argv includes
# it; normal lanes never pass it. It is argv, never an environment variable.
#
# Trust model. The hook must be invoked as the MAIN checkout's copy, never the
# copy inside the task worktree, so a branch cannot weaken the hook itself.
# Step a refuses to run from the worktree, symlinks resolved. That is all it
# protects. On a push, GitHub Actions runs the workflow files of the pushed
# commit, so a branch that edits .github/workflows/ changes the CI that judges
# it; likewise `just verify` and `just linux-test` run the branch's own
# justfile, ci/ and .githooks/. The hook does not make those files trusted. It
# makes a change to them loud (the GATE FILES CHANGED block, before step g),
# and review of the diff is the control. The listing uses --no-renames, so a
# file moved out of a gate path shows under its old name too, and it matches
# case-insensitively: `just` finds justfile in any case and also .justfile, and
# loads *.just and <module>/justfile through mod and import. A deleted justfile
# makes `just` search the parent directories; the deletion is listed as well.
# Also flagged, here and nested: .cargo/config(.toml), whose `runner` entry
# changes what `cargo test` runs, and which cargo reads upward from the working
# directory; rustfmt.toml and .rustfmt.toml, which rustfmt finds upward from
# each file; clippy.toml and .clippy.toml, read from each crate's directory; and
# the legacy rust-toolchain file, which picks the compiler. The names come from
# a NUL-separated listing, so git never quotes them, and are printed with %q, so
# a control byte in a file name cannot fake a line in the task log.
#
# Steps, in order. Nothing is pushed before step h.
#   a  refuse to run from the wrong place or with a variable missing
#   b  the worktree is clean and on BOOF_BRANCH
#   c  take the integration lock
#   d  commit hygiene on origin/main..HEAD
#   e  wait until every Actions run on origin/main's head succeeded
#   f  rebase onto origin/main
#      (then list any changed gate files, a warning, never a refusal)
#   g  `just verify`, then `just linux-test`
#   h  push without force; if main moved, back to d, at most 3 attempts
#   i  watch every Actions run on the pushed commit
#   j  fast-forward the main checkout
#   k  one summary line
#
# A missing or invalid `gh` login refuses at once, at step e with "could not be
# confirmed" and at step i as NOT CONFIRMED, rather than holding the lock while
# it retries; network errors are still retried with backoff.
#
# The BOOF_INTEGRATE_* tunables only shorten waits, for the test harness
# (ci/boof-integrate-test.sh). No environment variable can skip a check; only
# the --allow-red-main argument skips step e.
#
# Runs under /bin/bash, which on macOS is 3.2: no mapfile, no associative
# arrays, no `wait -n`, and an empty array is expanded as ${a[@]+"${a[@]}"}.
set -euo pipefail

die() {
    echo "boof-integrate: step $1: $2" >&2
    exit 1
}
warn() {
    echo "boof-integrate: step $1: $2" >&2
}

allow_red=0
while [[ $# -gt 0 ]]; do
    case $1 in
    --allow-red-main) allow_red=1 ;;
    *) die a "unknown argument '$1'" ;;
    esac
    shift
done

numeric() {
    local name=$1 value=$2
    [[ $value =~ ^[0-9]+$ ]] || die a "$name must be a number of seconds, got '$value'"
}
POLL=${BOOF_INTEGRATE_POLL:-30}
MAIN_TIMEOUT=${BOOF_INTEGRATE_MAIN_TIMEOUT:-5400}
APPEAR_TIMEOUT=${BOOF_INTEGRATE_APPEAR_TIMEOUT:-300}
RETRY=${BOOF_INTEGRATE_RETRY:-5}
numeric BOOF_INTEGRATE_POLL "$POLL"
numeric BOOF_INTEGRATE_MAIN_TIMEOUT "$MAIN_TIMEOUT"
numeric BOOF_INTEGRATE_APPEAR_TIMEOUT "$APPEAR_TIMEOUT"
numeric BOOF_INTEGRATE_RETRY "$RETRY"

# ---- a. the right place --------------------------------------------------
for var in BOOF_TASK_ID BOOF_BRANCH BOOF_BASE BOOF_WORKTREE; do
    [[ -n ${!var:-} ]] || die a "$var is not set"
done

# Resolve the script's own path through symlinks (bash 3.2: no readlink -f).
self=${BASH_SOURCE[0]}
hops=0
while [[ -L $self ]]; do
    hops=$((hops + 1))
    [[ $hops -le 40 ]] || die a "too many symlinks resolving this script"
    link=$(readlink "$self") || die a "cannot read the link $self"
    case $link in
    /*) self=$link ;;
    *) self="$(dirname "$self")/$link" ;;
    esac
done
self_dir=$(cd "$(dirname "$self")" && pwd -P) || die a "cannot resolve this script's directory"
wt=$(cd "$BOOF_WORKTREE" && pwd -P) || die a "BOOF_WORKTREE '$BOOF_WORKTREE' is not a directory"
if [[ $self_dir == "$wt" || $self_dir/ == "$wt"/* ]]; then
    die a "refusing to run the copy inside the task worktree ($self_dir); run the main checkout's copy"
fi
main_repo=$(git -C "$self_dir" rev-parse --show-toplevel) || die a "this script is not inside a git checkout"
wt_top=$(git -C "$wt" rev-parse --show-toplevel) || die a "BOOF_WORKTREE is not a git checkout"
[[ $main_repo != "$wt_top" ]] || die a "this script and BOOF_WORKTREE are the same checkout"

g() { git -C "$wt" "$@"; }

# ---- b. the worktree -----------------------------------------------------
on_branch=$(g symbolic-ref --short HEAD) || die b "the worktree is on a detached HEAD"
[[ $on_branch == "$BOOF_BRANCH" ]] || die b "the worktree is on '$on_branch', not '$BOOF_BRANCH'"
dirty=$(g status --porcelain --untracked-files=all)
[[ -z $dirty ]] || die b "the worktree is not clean:
$dirty"

# ---- the repository, from the origin remote ------------------------------
# `config`, not `remote get-url`: the latter applies insteadOf rewrites.
origin_url=$(g config --get remote.origin.url) || die c "no origin remote"
url_re='^(git@github\.com:|https://github\.com/|ssh://git@github\.com/)(.+)$'
[[ $origin_url =~ $url_re ]] || die c "origin '$origin_url' is not a GitHub URL"
repo=${BASH_REMATCH[2]}
repo=${repo%.git}
repo_re='^[^/]+/[^/]+$'
[[ $repo =~ $repo_re ]] || die c "cannot read owner/name from origin '$origin_url'"

# ---- c. the lock ---------------------------------------------------------
# Not the machine lock of ci/lib/machine-lock.sh: `just linux-test` takes that
# one itself, and holding it here would deadlock the gate.
lock="${TMPDIR:-/tmp}/aido-boof-integrate.lock"
have_lock=0
scratch=""

gitpath() {
    local p
    p=$(g rev-parse --git-path "$1")
    case $p in
    /*) echo "$p" ;;
    *) echo "$wt/$p" ;;
    esac
}

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -d $(gitpath rebase-merge) || -d $(gitpath rebase-apply) ]]; then
        g rebase --abort >/dev/null 2>&1 || true
    fi
    if [[ -n $scratch ]]; then
        rm -rf "$scratch"
    fi
    if [[ $have_lock == 1 ]]; then
        rm -rf "$lock"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

announced=0
until mkdir "$lock" 2>/dev/null; do
    holder=$(cat "$lock/pid" 2>/dev/null || true)
    if [[ -n $holder ]] && ! kill -0 "$holder" 2>/dev/null; then
        rm -rf "$lock"
        continue
    fi
    if [[ $announced == 0 ]]; then
        echo "boof-integrate: waiting for another integration (pid ${holder:-starting})" >&2
        announced=1
    fi
    sleep 1
done
have_lock=1
echo $$ >"$lock/pid"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/boof-integrate.XXXXXX")

# ---- CI helpers ----------------------------------------------------------
ci_urls=""
ci_msg=""

# wait_ci SHA APPEAR TOTAL STEP: wait for every Actions run on SHA to complete.
# Returns 0 when at least one run exists and every conclusion is exactly
# `success`. Returns 1 when that is settled the other way: every run completed
# and one did not succeed, or no run appeared in time. Returns 2 when it could
# not be settled: the total time ran out with runs still going, or `gh` kept
# failing. Only a call that succeeded can say "red" or "no runs"; a failed call
# keeps the last observation and is retried with backoff until TOTAL. Leaves the
# run URLs in ci_urls and the reason in ci_msg.
wait_ci() {
    local sha=$1 appear=$2 total=$3 step=$4
    local start=$SECONDS out last_err="" n=0 pending=0 bad=0 st co url elapsed
    local k=0 delay i gh_rc
    ci_urls=""
    ci_msg=""
    while :; do
        delay=$POLL
        if out=$(gh run list -R "$repo" --commit "$sha" --limit 100 \
            --json status,conclusion,url \
            --jq '.[] | [.status, (if (.conclusion // "") == "" then "-" else .conclusion end), .url] | @tsv' 2>"$scratch/gh.err"); then
            k=0
            last_err=""
            n=0 pending=0 bad=0 ci_urls=""
            while IFS=$'\t' read -r st co url; do
                [[ -n $st ]] || continue
                n=$((n + 1))
                ci_urls="$ci_urls $url"
                if [[ $st != completed ]]; then
                    pending=$((pending + 1))
                elif [[ $co != success ]]; then
                    bad=$((bad + 1))
                fi
            done <<EOF
$out
EOF
            ci_urls=${ci_urls# }
            if [[ $n -gt 0 && $pending -eq 0 ]]; then
                if [[ $bad -eq 0 ]]; then
                    return 0
                fi
                ci_msg="$bad of $n runs on ${sha:0:12} did not succeed"
                return 1
            fi
            elapsed=$((SECONDS - start))
            if [[ $n -eq 0 && $elapsed -ge $appear ]]; then
                ci_msg="no Actions run appeared for ${sha:0:12} within ${appear}s"
                return 1
            fi
        else
            gh_rc=$?
            last_err=$(cat "$scratch/gh.err")
            # A lasting auth fault is not worth the lock: refuse at once. The
            # match is loose on purpose; a false hit only refuses sooner.
            if [[ $gh_rc -eq 4 ]] || printf '%s' "$last_err" | grep -Eqi 'gh auth login|HTTP 401|bad credentials|authentication required'; then
                ci_msg="gh is not authenticated; run 'gh auth login' (gh: $last_err)"
                return 2
            fi
            k=$((k + 1))
            # RETRY * 2^(k-1), at most 60s and at most the time left.
            delay=$RETRY
            i=1
            while [[ $i -lt $k && $delay -lt 60 ]]; do
                delay=$((delay * 2))
                i=$((i + 1))
            done
            [[ $delay -le 60 ]] || delay=60
            elapsed=$((SECONDS - start))
            if [[ $total -gt $elapsed && $delay -gt $((total - elapsed)) ]]; then
                delay=$((total - elapsed))
            fi
            if [[ $elapsed -ge $total ]]; then
                warn "$step" "gh run list failed (try $k), giving up: $last_err"
            else
                warn "$step" "gh run list failed (try $k), retrying in ${delay}s: $last_err"
            fi
        fi
        if [[ $elapsed -ge $total ]]; then
            ci_msg="could not confirm CI on ${sha:0:12} within ${total}s${last_err:+ (gh: $last_err)}"
            return 2
        fi
        sleep "$delay"
    done
}

run_gate() {
    local name=$1
    echo "boof-integrate: step g: just $name" >&2
    if ! (cd "$wt" && just "$name") >"$wt/target/boof-integrate/$name.log" 2>&1; then
        echo "boof-integrate: last 80 lines of $wt/target/boof-integrate/$name.log:" >&2
        tail -n 80 "$wt/target/boof-integrate/$name.log" >&2 || true
        die g "just $name failed"
    fi
}

subject_re='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9._/-]+\))?!?: [^ ]'

pushed=""
attempt=1
while [[ $attempt -le 3 ]]; do
    # ---- d. commit hygiene -----------------------------------------------
    g fetch origin main >&2 || die d "git fetch origin main failed"
    commits=$(g log --format='%h%x09%s' origin/main..HEAD)
    [[ -n $commits ]] || die d "no commits on top of origin/main"
    offenders=""
    while IFS=$'\t' read -r h s; do
        why=""
        if ! [[ $s =~ $subject_re ]]; then
            why="not a Conventional Commit (type(scope)?: subject)"
        fi
        len=$(printf %s "$s" | LC_ALL=en_US.UTF-8 wc -m | tr -d ' ')
        if [[ $len -gt 50 ]]; then
            why="${why:+$why; }subject is $len characters, the limit is 50"
        fi
        lower=$(printf %s "$s" | tr '[:upper:]' '[:lower:]')
        case $lower in
        wip* | fixup!* | squash!* | boof-runner:*)
            why="${why:+$why; }subject starts with a banned prefix (wip, fixup!, squash!, boof-runner:)"
            ;;
        esac
        if [[ -n $why ]]; then
            offenders="$offenders  $h $s -- $why
"
        fi
    done <<EOF
$commits
EOF
    if [[ -n $offenders ]]; then
        printf '%s' "$offenders" >&2
        die d "commits that fail the hygiene check are listed above"
    fi

    # ---- e. main is green ------------------------------------------------
    main_sha=$(g rev-parse origin/main)
    if [[ $allow_red == 1 ]]; then
        warn e "skipping step e: --allow-red-main (main's CI not checked)"
    else
        rc=0
        wait_ci "$main_sha" "$APPEAR_TIMEOUT" "$MAIN_TIMEOUT" e || rc=$?
        case $rc in
        0) ;;
        1) die e "main is not green: $ci_msg ${ci_urls}" ;;
        *) die e "main's CI could not be confirmed green: $ci_msg ${ci_urls}" ;;
        esac
    fi

    # ---- f. rebase -------------------------------------------------------
    if ! g rebase origin/main >&2; then
        g rebase --abort >/dev/null 2>&1 || true
        die f "conflict rebasing onto origin/main"
    fi

    # ---- gate files: loud, never a refusal -------------------------------
    gate_changed=""
    g diff -z --name-only --no-renames origin/main...HEAD >"$scratch/changed" ||
        die f "cannot list the changed files"
    while IFS= read -r -d '' f; do
        lc=$(printf '%s' "$f" | LC_ALL=C tr '[:upper:]' '[:lower:]')
        case $lc in
        justfile | .justfile | */justfile | */.justfile | *.just | ci/* | .github/* | .githooks/* | deny.toml | clippy.toml | rust-toolchain.toml | .taplo.toml | \
            .cargo/config.toml | .cargo/config | */.cargo/config.toml | */.cargo/config | \
            rust-toolchain | rustfmt.toml | .rustfmt.toml | */rustfmt.toml | */.rustfmt.toml | \
            .clippy.toml | */clippy.toml | */.clippy.toml)
            gate_changed="$gate_changed  $(printf '%q' "$f")
"
            ;;
        esac
    done <"$scratch/changed"
    if [[ -n $gate_changed ]]; then
        {
            echo "boof-integrate: ==== GATE FILES CHANGED ===="
            printf '%s' "$gate_changed"
            echo "boof-integrate: these define the CI and local gate that judge this branch; review the diff"
            echo "boof-integrate: ============================="
        } >&2
    fi

    # ---- g. the gate -----------------------------------------------------
    before=$(g rev-parse HEAD)
    mkdir -p "$wt/target/boof-integrate"
    run_gate verify
    run_gate linux-test
    after=$(g rev-parse HEAD)
    [[ $after == "$before" ]] || die g "the gate moved HEAD from $before to $after"
    dirty=$(g status --porcelain --untracked-files=all)
    [[ -z $dirty ]] || die g "the gate left the worktree dirty:
$dirty"

    # ---- h. push ---------------------------------------------------------
    if g push origin HEAD:refs/heads/main 2>"$scratch/push.err"; then
        pushed=$before
        break
    fi
    cat "$scratch/push.err" >&2
    remote_main=$(g ls-remote origin refs/heads/main | cut -f1) || die h "git push failed and origin could not be read"
    if [[ -n $remote_main && $remote_main != "$main_sha" ]]; then
        warn h "push rejected, main moved (attempt $attempt of 3)"
        attempt=$((attempt + 1))
        continue
    fi
    die h "git push failed (main did not move)"
done
[[ -n $pushed ]] || die h "push rejected 3 times"

# ---- i. watch CI on the pushed commit ------------------------------------
rc=0
wait_ci "$pushed" "$APPEAR_TIMEOUT" "$MAIN_TIMEOUT" i || rc=$?
if [[ $rc -eq 1 ]]; then
    {
        echo "boof-integrate: MAIN IS NOW RED at $pushed: $ci_msg"
        echo "boof-integrate: runs: ${ci_urls:-none}"
    } >&2
    exit 1
elif [[ $rc -ne 0 ]]; then
    {
        echo "boof-integrate: CI on $pushed NOT CONFIRMED (the commit is on main): $ci_msg"
        echo "boof-integrate: runs: ${ci_urls:-none}"
    } >&2
    exit 1
fi

# ---- j. fast-forward the main checkout -----------------------------------
if git -C "$main_repo" fetch origin main >/dev/null 2>&1; then
    main_branch=$(git -C "$main_repo" symbolic-ref --short -q HEAD || true)
    main_dirty=$(git -C "$main_repo" status --porcelain --untracked-files=no)
    if [[ $main_branch == main && -z $main_dirty ]]; then
        git -C "$main_repo" merge --ff-only origin/main >&2 ||
            warn j "could not fast-forward $main_repo"
    else
        warn j "$main_repo is not on a clean main; not fast-forwarded"
    fi
else
    warn j "could not fetch origin in $main_repo"
fi

# ---- k. summary ----------------------------------------------------------
echo "boof-integrate: landed $pushed on main; base $BOOF_BASE; CI success; $ci_urls"
