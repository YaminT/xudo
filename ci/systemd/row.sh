#!/bin/sh
# Inside a container whose PID 1 is systemd. Installs /opt/xudo.deb, drives
# xudo exec on a pty (ci/differential/exec.exp, user xudotest), and removes it.
# The unit files are the ones the package shipped. This script does not edit them.
set -eu
export DEBIAN_FRONTEND=noninteractive

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }
good() { echo "PASS: $*"; }

. /etc/os-release
echo "-- ${PRETTY_NAME} / $(systemctl --version | awk 'NR==1{print}') / system $(systemctl is-system-running || true)"

apt-get update -qq
cd /opt
# Ubuntu 26.04 ships uutils `id` as a symlink, which the gate refuses; replace
# it with the regular GNU coreutils binary at the path in the shipped ruleset.
if [ -L /usr/bin/id ]; then
    apt-get install -y -qq --allow-remove-essential coreutils-from-gnu coreutils-from-uutils-
    install -m 0755 /usr/bin/gnuid /var/tmp/xudo-id
    mv /var/tmp/xudo-id /usr/bin/id
    echo "NOTE: replaced uutils id with GNU id"
fi
if ! apt-get install -y ./xudo.deb >/var/tmp/xudo-install.log 2>&1; then
    cat /var/tmp/xudo-install.log >&2
    echo "FAIL: apt install" >&2
    exit 1
fi

en=$(systemctl is-enabled xudod.socket 2>&1 || true)
if [ "$en" = enabled ]; then good "xudod.socket enabled"; else bad "xudod.socket enabled (is $en)"; fi
ac=$(systemctl is-active xudod.socket 2>&1 || true)
if [ "$ac" = active ]; then good "xudod.socket active"; else bad "xudod.socket active (is $ac)"; fi
ten=$(systemctl is-enabled xudo-pasban.timer 2>&1 || true)
if [ "$ten" = enabled ]; then good "xudo-pasban.timer enabled"; else bad "xudo-pasban.timer enabled (is $ten)"; fi
tac=$(systemctl is-active xudo-pasban.timer 2>&1 || true)
if [ "$tac" = active ]; then good "xudo-pasban.timer active"; else bad "xudo-pasban.timer active (is $tac)"; fi
mode=$(stat -c '%a %U:%G' /run/xudo/broker.sock 2>/dev/null || echo missing)
if [ "$mode" = "660 root:xudo" ]; then good "broker.sock 0660 root:xudo"; else bad "broker.sock is $mode, wanted 0660 root:xudo"; fi

# postinst runs `xudo install` and prints its verdict. NOT VERIFIED is a finding.
if grep -q '^xudo: installed, but NOT VERIFIED:' /var/tmp/xudo-install.log; then
    bad "xudo install reported verified"
    grep '^xudo: installed, but NOT VERIFIED:' /var/tmp/xudo-install.log >&2 || true
elif grep -q 'the functional probe passed' /var/tmp/xudo-install.log; then
    good "xudo install reported verified"
else
    bad "xudo install printed neither verified nor NOT VERIFIED"
    cat /var/tmp/xudo-install.log >&2
fi

apt-get install -y -qq expect python3 procps >/dev/null
id xudotest >/dev/null 2>&1 || useradd --create-home --user-group xudotest
echo 'xudotest:pw' | chpasswd
usermod -aG xudo xudotest

# Hold one activated broker in its five-second read window while checking its
# kernel attribute; the unit intentionally leaves NoNewPrivileges unset.
python3 - <<'PY' >/var/tmp/held-broker.log 2>&1 &
import socket
import time

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect("/run/xudo/broker.sock")
time.sleep(4)
PY
held=$!
sleep 1
instance=$(systemctl list-units --type=service --state=running --no-legend --plain 'xudod@*' | awk 'NR==1 {print $1}')
if [ -n "$instance" ]; then
    pid=$(systemctl show "$instance" --property=MainPID --value)
    if [ -r "/proc/$pid/status" ] && grep -Eq '^NoNewPrivs:[[:space:]]+1$' "/proc/$pid/status"; then
        good "running broker has NoNewPrivs: 1"
    else
        bad "running broker has NoNewPrivs: 1 (unit=$instance pid=$pid)"
    fi
else
    bad "running broker has NoNewPrivs: 1 (no active xudod@ instance)"
fi
wait "$held" || true

# exec.exp's first argument is the su binary; it types $1 at a password prompt.
# Leaves a CR-stripped transcript in /var/tmp/case.out and prints the status.
pty() {
    pw=$1
    shift
    set +e
    expect /opt/exec.exp "su --pty" "$pw" "/usr/bin/xudo exec -- $*" >/var/tmp/case.raw 2>&1
    rc=$?
    set -e
    # Drop CR and the session markers systemd 259 writes onto the pty.
    tr -d '\r' </var/tmp/case.raw |
        sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\x1b\][^\x1b]*\x1b\\//g' >/var/tmp/case.out
    echo "$rc"
}

rc=$(pty pw /usr/bin/id -u)
if [ "$rc" -eq 0 ] && grep -qi password /var/tmp/case.out && grep -qx 0 /var/tmp/case.out; then
    good "id -u prompts, prints 0, exits 0"
else
    bad "id -u prompts, prints 0, exits 0 (rc=$rc)"
    cat /var/tmp/case.out >&2
fi

rc=$(pty pw /usr/bin/id -G)
if [ "$rc" -eq 17 ]; then
    good "id -G exits 17"
else
    bad "id -G exits 17 (rc=$rc)"
    cat /var/tmp/case.out >&2
fi

rc=$(pty wrong /usr/bin/id -u)
if [ "$rc" -ne 0 ] && grep -qi password /var/tmp/case.out && ! grep -qx 0 /var/tmp/case.out; then
    good "wrong password is nonzero and runs nothing"
else
    bad "wrong password is nonzero and runs nothing (rc=$rc)"
    cat /var/tmp/case.out >&2
fi

# Enable the real human confirmation path only in this disposable container.
cat >/etc/xudo/config.toml <<'EOF'
confirm_human_path = true
confirmation_timeout_secs = 0
EOF
cat >/etc/xudo/rules.d/99-systemd-confirm.toml <<'EOF'
[[action]]
id = "harness.u"
tier = "diag-read"
confirm = "always"
exe = "/usr/bin/id"
args = [{ name = "effective-uid", matcher = { literal = "-u" } }]
EOF
chmod 0644 /etc/xudo/config.toml
chmod 0644 /etc/xudo/rules.d/99-systemd-confirm.toml

pending=$(su --pty -s /bin/sh -c 'xudo pending' xudotest 2>&1 || true)
if [ -z "$pending" ]; then
    start=$(date +%s%3N)
    rc=$(pty pw /usr/bin/id -u)
    elapsed=$(($(date +%s%3N) - start))
    if [ "$rc" -eq 18 ] && grep -qi no_confirmation_channel /var/tmp/case.out && [ "$elapsed" -le 5000 ]; then
        good "no_watcher_denies_at_once"
    else
        bad "no_watcher_denies_at_once (rc=$rc elapsed=${elapsed}ms)"
        cat /var/tmp/case.out >&2
    fi
    pending=$(su --pty -s /bin/sh -c 'xudo pending' xudotest 2>&1 || true)
    if [ -z "$pending" ]; then
        good "no_watcher_mints_nothing"
    else
        bad "no_watcher_mints_nothing"
        printf '%s\n' "$pending" >&2
    fi
else
    bad "no_watcher_denies_at_once (unexpected pre-existing pending entry)"
fi

clear_confirm() {
    rm -f /run/xudo/confirm/*.json /run/xudo/req/*
}
pending=
if expect /harness/confirm.exp pending >/var/tmp/confirm-pending.log 2>&1; then
    pending=$(su --pty -s /bin/sh -c 'xudo pending' xudotest 2>&1 || true)
    if [ -n "$pending" ]; then
        good "timeout_zero_returns_pending_and_the_entry_stays_until_ttl"
    else
        bad "timeout_zero_returns_pending_and_the_entry_stays_until_ttl (entry missing)"
    fi
else
    bad "timeout_zero_returns_pending_and_the_entry_stays_until_ttl"
    cat /var/tmp/confirm-pending.log >&2
fi
if [ -n "$pending" ]; then
    sleep 2
    still=$(su --pty -s /bin/sh -c 'xudo pending' xudotest 2>&1 || true)
    if [ -n "$still" ]; then
        good "pending_entry_survives_until_ttl_check"
    else
        bad "pending_entry_survives_until_ttl_check (entry disappeared)"
    fi
fi
clear_confirm

# The positive timeout is tested against a live pending request; the watcher
# leaves it unanswered so the wait itself can be measured.
cat >/etc/xudo/config.toml <<'EOF'
confirm_human_path = true
confirmation_timeout_secs = 2
EOF
starts_before=$(journalctl -b -u 'xudod@*' --no-pager -o cat 2>/dev/null | grep -c 'Started xudod@' || true)
start=$(date +%s%3N)
if expect /harness/confirm.exp timeout >/var/tmp/confirm-timeout.log 2>&1; then rc=18; else rc=1; fi
elapsed=$(($(date +%s%3N) - start))
starts_after=$(journalctl -b -u 'xudod@*' --no-pager -o cat 2>/dev/null | grep -c 'Started xudod@' || true)
poll_starts=$((starts_after - starts_before))
wait_ms=$(sed -n 's/^WAIT_MS=//p' /var/tmp/confirm-timeout.log)
if [ "$rc" -eq 18 ] && [ -n "$wait_ms" ] && [ "$wait_ms" -ge 1500 ] && [ "$wait_ms" -le 7000 ]; then
    good "a_positive_timeout_returns_pending_or_denied_within_the_bound (${wait_ms}ms)"
else
    bad "a_positive_timeout_returns_pending_or_denied_within_the_bound (rc=$rc elapsed=${elapsed}ms)"
    cat /var/tmp/confirm-timeout.log >&2
    cat /var/tmp/watch-session.out >&2 || true
fi
clear_confirm
if [ "$poll_starts" -gt 0 ]; then
    if [ -n "$wait_ms" ]; then
        cost=$((wait_ms / poll_starts))
        echo "MEASURE: positive-timeout polls started $poll_starts brokers in ${wait_ms}ms (${cost}ms/start)"
    else
        echo "FAIL: per-poll broker start cost could not be measured (missing WAIT_MS)"
        fail=1
    fi
else
    echo "FAIL: per-poll broker start cost could not be measured (starts=$poll_starts)"
    fail=1
fi
cat >/etc/xudo/config.toml <<'EOF'
confirm_human_path = true
confirmation_timeout_secs = 0
EOF

# A fresh pending request is answered by a second user session on another pty.
if expect /harness/confirm.exp approve >/var/tmp/confirm-approve.log 2>&1; then
    roundtrip=$(sed -n 's/^ROUNDTRIP_MS=//p' /var/tmp/confirm-approve.log)
    good "approve_then_rerun_then_password_runs_as_root (watch round-trip ${roundtrip}ms)"
else
    bad "approve_then_rerun_then_password_runs_as_root"
    cat /var/tmp/confirm-approve.log >&2
    cat /var/tmp/watch-session.out >&2 || true
fi
clear_confirm

if expect /harness/confirm.exp deny >/var/tmp/confirm-deny.log 2>&1; then
    good "deny_runs_nothing_and_exits_18"
else
    bad "deny_runs_nothing_and_exits_18"
    cat /var/tmp/confirm-deny.log >&2
fi
clear_confirm

# The requester stdin is a pipe containing the expected word. It cannot answer
# the broker's separate watch question.
if expect /harness/confirm.exp self-stdin >/var/tmp/self-stdin.out 2>&1; then
    good "self_approval_from_the_requesters_stdin_fails"
else
    bad "self_approval_from_the_requesters_stdin_fails"
    cat /var/tmp/self-stdin.out >&2
fi
clear_confirm

cat >/etc/xudo/config.toml <<'EOF'
confirm_human_path = true
confirmation_timeout_secs = 3
EOF
if expect /harness/confirm.exp self-tty >/var/tmp/self-tty.out 2>&1; then
    good "self_approval_through_dev_tty_fails"
else
    bad "self_approval_through_dev_tty_fails"
    cat /var/tmp/self-tty.out >&2
fi
clear_confirm
cat >/etc/xudo/config.toml <<'EOF'
confirm_human_path = true
confirmation_timeout_secs = 0
EOF

# A watcher in the requester's own session and terminal is refused.
if expect /harness/confirm.exp same-session >/var/tmp/same-session.out 2>&1; then
    good "watch_started_in_the_requesters_session_is_refused"
else
    bad "watch_started_in_the_requesters_session_is_refused"
    cat /var/tmp/same-session.out >&2
fi
clear_confirm

# Some container runtimes disable user namespaces. Distinguish that fixture
# limitation explicitly; never turn it into a silent pass.
set +e
timeout 8 su --pty -s /bin/sh -c 'unshare -Ur /usr/bin/xudo watch' xudotest >/var/tmp/userns-watch.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 124 ] && grep -qiE 'channel|namespace|terminal' /var/tmp/userns-watch.out; then
    good "watch_in_a_user_namespace_is_refused"
elif [ "$rc" -ne 124 ] && grep -qiE 'operation not permitted|not permitted|permission denied' /var/tmp/userns-watch.out; then
    echo "PASS: watch_in_a_user_namespace_is_refused (unshare unavailable; covered by fixture tests)"
else
    bad "watch_in_a_user_namespace_is_refused (rc=$rc; unexpected unshare failure)"
    cat /var/tmp/userns-watch.out >&2
fi

# Freeze is global in this harness: the approved human path must still prompt
# for and accept the password. Thaw is root-only.
test_uid=$(id -u xudotest)
pkill -TERM -u "$test_uid" -x xudo 2>/dev/null || true
sleep 1
clear_confirm
if xudo freeze --reason 'systemd M3 proof' >/var/tmp/freeze.out 2>&1; then
    if expect /harness/confirm.exp approve >/var/tmp/frozen-approve.log 2>&1; then
        good "freeze_then_human_password_path_runs"
    else
        bad "freeze_then_human_password_path_runs"
        cat /var/tmp/frozen-approve.log /var/tmp/case.out >&2 || true
    fi
else
    bad "freeze_then_human_password_path_runs"
    cat /var/tmp/freeze.out >&2
fi
clear_confirm
set +e
su --pty -s /bin/sh -c 'sudo -n /usr/bin/xudo thaw' xudotest >/var/tmp/nonroot-thaw.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    good "sudo_xudo_thaw_is_refused_for_unprivileged_user"
else
    bad "sudo_xudo_thaw_is_refused_for_unprivileged_user"
fi
if sudo /usr/bin/xudo thaw >/var/tmp/root-thaw.out 2>&1; then
    good "sudo_xudo_thaw_works_as_root"
else
    bad "sudo_xudo_thaw_works_as_root"
    cat /var/tmp/root-thaw.out >&2
fi

mid=a06b36c755dd4b85815d6af790559b5e
unitj=$(journalctl -u 'xudod@*' --no-pager -o short-iso 2>/dev/null || true)
bro=$(journalctl _UID=0 MESSAGE_ID=$mid SYSLOG_IDENTIFIER=xudod -o cat --no-pager 2>/dev/null || true)
gate=$(journalctl _UID=0 MESSAGE_ID=$mid SYSLOG_IDENTIFIER=xudo-gate -o cat --no-pager 2>/dev/null || true)
if printf '%s\n' "$unitj" | grep -q 'Started xudod@'; then
    good "broker started under xudod@"
else
    bad "broker started under xudod@"
fi
if [ -n "$bro" ]; then good "journal has the broker's audit records"; else bad "journal has the broker's audit records"; fi
if [ -n "$gate" ]; then good "journal has the gate's audit records"; else bad "journal has the gate's audit records"; fi

am=$(stat -c '%a %U:%G' /var/lib/xudo/audit.jsonl 2>/dev/null || echo missing)
if [ "$am" = "600 root:root" ]; then good "audit.jsonl 0600 root:root"; else bad "audit.jsonl is $am, wanted 0600 root:root"; fi
if xudo audit --log /var/lib/xudo/audit.jsonl 2>/var/tmp/audit.err | grep -q 'chain intact'; then
    good "audit chain verifies"
else
    bad "audit chain verifies"
    cat /var/tmp/audit.err >&2
fi

# pasban_case <what> <ok, or a phrase the failure must have at priority <= 2>
pasban_case() {
    what=$1
    want=$2
    systemctl reset-failed xudo-pasban.service >/dev/null 2>&1 || true
    set +e
    systemctl start xudo-pasban.service >/var/tmp/pasban-start.out 2>&1
    rc=$?
    set -e
    invocation=$(systemctl show --property=InvocationID --value xudo-pasban.service)
    loud=$(journalctl -u xudo-pasban _SYSTEMD_INVOCATION_ID="$invocation" -p 2 --no-pager -o cat 2>/dev/null || true)
    if [ "$want" = ok ]; then
        if [ "$rc" -eq 0 ]; then
            good "$what"
        else
            bad "$what (rc=$rc)"
            cat /var/tmp/pasban-start.out >&2 || true
            journalctl -u xudo-pasban --no-pager -n 50 >&2 || true
        fi
        if [ -z "$loud" ]; then
            good "$what is not priority <= 2"
        else
            bad "$what is not priority <= 2"
            printf '%s\n' "$loud" >&2
        fi
        return
    fi
    if [ "$rc" -ne 0 ]; then
        good "$what: service fails"
    else
        bad "$what: service fails (rc=0)"
    fi
    state=$(systemctl is-failed xudo-pasban.service 2>&1 || true)
    if [ "$state" = failed ]; then
        good "$what: unit is failed"
    else
        bad "$what: unit is failed (is $state)"
    fi
    if printf '%s\n' "$loud" | grep -q -- "$want"; then
        good "$what: journal priority <= 2"
    else
        bad "$what: journal priority <= 2"
        printf '%s\n' "$loud" >&2
        journalctl -u xudo-pasban _SYSTEMD_INVOCATION_ID="$invocation" --no-pager -o verbose >&2 || true
    fi
}

cp -a /var/lib/xudo/audit.jsonl /var/tmp/audit.intact
pasban_case "intact log" ok

python3 - <<'PY'
from pathlib import Path
src = Path("/var/tmp/audit.intact").read_bytes()
if not src.endswith(b"\n") or len(src) < 32:
    raise SystemExit(f"audit log is too short to cut ({len(src)} bytes)")
Path("/var/lib/xudo/audit.jsonl").write_bytes(src[:-8])
PY
pasban_case "last line truncated" "is not intact"

cp -a /var/tmp/audit.intact /var/lib/xudo/audit.jsonl
python3 - <<'PY'
from pathlib import Path
data = bytearray(Path("/var/tmp/audit.intact").read_bytes())
data[len(data) // 2] ^= 1
Path("/var/lib/xudo/audit.jsonl").write_bytes(data)
PY
pasban_case "a byte edited in the middle" "is not intact"

cp -a /var/tmp/audit.intact /var/lib/xudo/audit.jsonl
python3 - <<'PY'
from pathlib import Path
data = Path("/var/tmp/audit.intact").read_bytes()
body = data[:-1] if data.endswith(b"\n") else data
head, sep, _last = body.rpartition(b"\n")
Path("/var/lib/xudo/audit.jsonl").write_bytes(head + b"\n" if sep else b"")
PY
if xudo audit --log /var/lib/xudo/audit.jsonl 2>/var/tmp/audit-tail.err | grep -q 'chain intact'; then
    good "file chain misses a removed tail"
else
    bad "file chain misses a removed tail"
    cat /var/tmp/audit-tail.err >&2 || true
fi
pasban_case "last record removed" "removed from the end"

mv /usr/bin/xudo /var/tmp/xudo.pasban-missing
pasban_case "missing xudo binary" "pasban:"
mv /var/tmp/xudo.pasban-missing /usr/bin/xudo

cp -a /var/tmp/audit.intact /var/lib/xudo/audit.jsonl
systemctl reset-failed xudo-pasban.service >/dev/null 2>&1 || true

# CollectMode=inactive-or-failed drops a failed instance, so --failed can be
# empty while the journal still recorded the failure. Both are checked.
listed=$(systemctl --failed --no-legend --plain 2>/dev/null | grep xudod || true)
if [ -z "$listed" ]; then good "systemctl --failed lists no xudod"; else bad "systemctl --failed lists xudod"; printf '%s\n' "$listed" >&2; fi
jf=$(printf '%s\n' "$unitj" | grep 'Failed with result' || true)
if [ -z "$jf" ]; then
    good "journal shows no failed xudod@"
else
    bad "journal shows no failed xudod@"
    printf '%s\n' "$jf" >&2
fi
sec=$(printf '%s\n' "$unitj" | grep -Ei 'seccomp|EPERM|Operation not permitted' || true)
if [ -z "$sec" ]; then good "no seccomp or EPERM complaint from xudod"; else bad "seccomp or EPERM complaint from xudod"; printf '%s\n' "$sec" >&2; fi

echo "-- journal: xudod@"
printf '%s\n' "$unitj"
# The short journal line names the refusal; the mount reason is in the record.
if [ -f /var/lib/xudo/audit.jsonl ]; then
    echo "-- audit details"
    sed -n 's/.*\(detail=[^"]*\).*/\1/p' /var/lib/xudo/audit.jsonl
fi

if ! apt-get remove -y xudo >/var/tmp/xudo-remove.log 2>&1; then
    cat /var/tmp/xudo-remove.log >&2
    bad "apt remove"
fi
en=$(systemctl is-enabled xudod.socket 2>&1 || true)
case $en in
enabled | static | indirect | generated | alias) bad "socket still enabled ($en)" ;;
*) good "socket not enabled ($en)" ;;
esac
ac=$(systemctl is-active xudod.socket 2>&1 || true)
case $ac in
active | activating) bad "socket still active ($ac)" ;;
*) good "socket not active ($ac)" ;;
esac
ten=$(systemctl is-enabled xudo-pasban.timer 2>&1 || true)
case $ten in
enabled | static | indirect | generated | alias) bad "pasban timer still enabled ($ten)" ;;
*) good "pasban timer not enabled ($ten)" ;;
esac
tac=$(systemctl is-active xudo-pasban.timer 2>&1 || true)
case $tac in
active | activating) bad "pasban timer still active ($tac)" ;;
*) good "pasban timer not active ($tac)" ;;
esac
if [ ! -e /etc/sudoers.d/xudo ] && [ ! -L /etc/sudoers.d/xudo ]; then
    good "no sudoers rule left"
else
    bad "sudoers rule still present"
fi

if [ "$fail" -ne 0 ]; then
    echo "row: FAILED"
    exit 1
fi
echo "row: ok"
