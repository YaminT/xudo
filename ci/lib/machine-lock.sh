# shellcheck shell=bash
# One Docker run at a time per machine, from any checkout and from any script
# that shares the caches.
#
#   . "$root/ci/lib/machine-lock.sh"
#   take_machine_lock <name, for the message printed while waiting>
#
# ci/linux-test.sh and ci/root-test.sh both take this lock, at this path, so a
# run of one waits for a run of the other. They share the two cache volumes
# (aido-linux-cargo and aido-linux-target) and the Docker VM's memory, and
# parallel agents working in separate worktrees would otherwise race both: the
# target volume rebuilt from under each other, and enough concurrent rustc
# processes to get one killed with no message. The root run also leaves
# root-owned files in the volumes, which the next linux-test run takes back with
# a chown that must not race another run's compile.
#
# A directory is the lock because mkdir is atomic everywhere and macOS ships no
# flock(1); a lock whose holder has died is taken over. It is released when the
# shell that took it exits.
take_machine_lock() {
    local who=$1 holder announced=0
    machine_lock="${TMPDIR:-/tmp}/aido-linux-test.lock"
    until mkdir "$machine_lock" 2>/dev/null; do
        holder=$(cat "$machine_lock/pid" 2>/dev/null || true)
        if [[ -n $holder ]] && ! kill -0 "$holder" 2>/dev/null; then
            rm -rf "$machine_lock"
            continue
        fi
        if [[ $announced == 0 ]]; then
            echo "$who: waiting for another run (pid ${holder:-starting})" >&2
            announced=1
        fi
        sleep 2
    done
    echo $$ >"$machine_lock/pid"
    trap 'rm -rf "$machine_lock"' EXIT
}
