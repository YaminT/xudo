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
# The gate refuses a symlink. Same order as rules/05-probe.toml: the first
# path that is a regular non-symlink file is the one every later case runs.
# The package's own install probe makes this choice; this only follows it.
regular_file() { [ -e "$1" ] && [ ! -L "$1" ] && [ -f "$1" ]; }
gate_exe=
for candidate in /usr/bin/id /usr/bin/gnuid; do
    if regular_file "$candidate"; then
        gate_exe=$candidate
        break
    fi
done
case $gate_exe in
/usr/bin/id) probe_action=xudo.probe.id ;;
/usr/bin/gnuid) probe_action=xudo.probe.gnuid ;;
*)
    echo "FAIL: no regular probe program" >&2
    exit 1
    ;;
esac
export XUDO_GATE_EXE=$gate_exe
export XUDO_PROBE_ACTION=$probe_action
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

apt-get install -y -qq expect python3 procps uidmap >/dev/null
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

rc=$(pty pw "$gate_exe" -u)
if [ "$rc" -eq 0 ] && grep -qi password /var/tmp/case.out && grep -qx 0 /var/tmp/case.out; then
    good "id -u prompts, prints 0, exits 0"
else
    bad "id -u prompts, prints 0, exits 0 (rc=$rc)"
    cat /var/tmp/case.out >&2
fi

rc=$(pty pw "$gate_exe" -G)
if [ "$rc" -eq 17 ]; then
    good "id -G exits 17"
else
    bad "id -G exits 17 (rc=$rc)"
    cat /var/tmp/case.out >&2
fi

rc=$(pty wrong "$gate_exe" -u)
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
cat >/etc/xudo/rules.d/99-systemd-confirm.toml <<EOF
[[action]]
id = "harness.u"
tier = "diag-read"
confirm = "always"
exe = "$gate_exe"
args = [{ name = "effective-uid", matcher = { literal = "-u" } }]
EOF
chmod 0644 /etc/xudo/config.toml
chmod 0644 /etc/xudo/rules.d/99-systemd-confirm.toml

# clear_confirm <case> <none|some|none_left>: assert what the spool holds (none_left: already checked by the caller), then empty it.
clear_confirm() {
    n=$(spool_entries)
    case $2 in
    none) [ "$n" -eq 0 ] || bad "$1: spool holds $n entries after the case, wanted none ($(ls /run/xudo/req | tr '\n' ' '))" ;;
    none_left) ;;
    some) [ "$n" -gt 0 ] || bad "$1: spool is empty after the case, wanted the pending entry" ;;
    esac
    rm -f /run/xudo/confirm/*.json /run/xudo/req/*
}
# What xudotest sees from `xudo pending`, with terminal noise removed.
pending_out() {
    su --pty -s /bin/sh -c 'xudo pending' xudotest 2>&1 |
        tr -d '\r' | sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\x1b\][^\x1b]*\x1b\\//g' || true
}
# True when `xudo pending` lists a request for harness.u, id -u.
lists_the_request() {
    printf '%s\n' "$1" | grep -Eq '^PENDING [0-9a-f]{64}$' &&
        printf '%s\n' "$1" | grep -q 'harness\.u' &&
        printf '%s\n' "$1" | grep -Eq "^[[:space:]]+command[[:space:]]+${gate_exe} -u\$"
}
spool_entries() { find /run/xudo/req -mindepth 1 2>/dev/null | wc -l; }

# The wrong-password case leaves exactly one entry: the broker minted it, sudo
# refused all three passwords, so the gate never ran to consume it; it stays
# until its deadline. Check it is that entry, then empty the spool.
n=$(spool_entries)
if [ "$n" -eq 1 ] && python3 -c '
import json, os, sys
d = json.load(open(sys.argv[1]))
sys.exit(0 if d.get("action") == os.environ["XUDO_PROBE_ACTION"] and d.get("argv") == ["-u"] else 1)
' /run/xudo/req/*; then
    good "password_cases_leave_only_the_wrong_password_entry"
else
    bad "password_cases_leave_only_the_wrong_password_entry ($n entries: $(ls /run/xudo/req | tr '\n' ' '))"
    cat /run/xudo/req/* >&2 || true
fi
clear_confirm password_cases none_left
pending=$(pending_out)
pre_spool=$(spool_entries)
if [ -z "$pending" ] && [ "$pre_spool" -eq 0 ]; then
    start=$(date +%s%3N)
    rc=$(pty pw "$gate_exe" -u)
    elapsed=$(($(date +%s%3N) - start))
    if [ "$rc" -eq 18 ] && grep -qi no_confirmation_channel /var/tmp/case.out && [ "$elapsed" -le 5000 ]; then
        good "no_watcher_denies_at_once"
    else
        bad "no_watcher_denies_at_once (rc=$rc elapsed=${elapsed}ms)"
        cat /var/tmp/case.out >&2
    fi
    pending=$(pending_out)
    post_spool=$(spool_entries)
    if [ -z "$pending" ] && [ "$post_spool" -eq 0 ]; then
        good "no_watcher_mints_nothing"
    else
        bad "no_watcher_mints_nothing (spool entries: $post_spool)"
        printf '%s\n' "$pending" >&2
        ls -la /run/xudo/req >&2
    fi
else
    bad "no_watcher_denies_at_once (unexpected pre-existing pending entry or spool entry)"
    printf '%s\n' "$pending" >&2
    ls -la /run/xudo/req >&2
fi

# This timeout-zero case proves the request returns immediately and leaves a
# pending entry for `xudo pending` to display.
pending=
name=timeout_zero_returns_pending_and_the_entry_stays
if expect /harness/confirm.exp pending >/var/tmp/confirm-pending.log 2>&1; then
    rc=$(sed -n 's/^REQUESTER_RC=//p' /var/tmp/confirm-pending.log)
    pending=$(pending_out)
    if [ "$rc" = 18 ] && lists_the_request "$pending" && [ "$(spool_entries)" -gt 0 ]; then
        good "$name (rc=$rc)"
    else
        bad "$name (rc=$rc, entry missing)"
        printf '%s\n' "$pending" >&2
    fi
else
    bad "$name"
    cat /var/tmp/confirm-pending.log >&2
fi
if [ -n "$pending" ]; then
    sleep 2
    still=$(pending_out)
    if lists_the_request "$still"; then
        good "pending_entry_survives_two_more_seconds"
    else
        bad "pending_entry_survives_two_more_seconds (entry disappeared)"
    fi
fi
clear_confirm "$name" some

# The positive timeout is tested against a live pending request; the watcher
# leaves it unanswered so the wait itself can be measured.
cat >/etc/xudo/config.toml <<'EOF'
confirm_human_path = true
confirmation_timeout_secs = 2
EOF
starts_before=$(journalctl -b -u 'xudod@*' --no-pager -o cat 2>/dev/null | grep -c 'Started xudod@' || true)
start=$(date +%s%3N)
if expect /harness/confirm.exp timeout >/var/tmp/confirm-timeout.log 2>&1; then
    rc=$(sed -n 's/^REQUESTER_RC=//p' /var/tmp/confirm-timeout.log)
else
    rc=expect-failed
fi
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
clear_confirm timeout_positive some
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
# confirm.exp fails unless the re-run asked for the password.
if expect /harness/confirm.exp approve >/var/tmp/confirm-approve.log 2>&1; then
    roundtrip=$(sed -n 's/^ROUNDTRIP_MS=//p' /var/tmp/confirm-approve.log)
    good "approve_then_rerun_then_password_runs_as_root (watch round-trip ${roundtrip}ms)"
else
    bad "approve_then_rerun_then_password_runs_as_root"
    cat /var/tmp/confirm-approve.log >&2
    cat /var/tmp/watch-session.out >&2 || true
fi
clear_confirm approve none

if expect /harness/confirm.exp deny >/var/tmp/confirm-deny.log 2>&1; then
    good "deny_runs_nothing_and_exits_18"
else
    bad "deny_runs_nothing_and_exits_18"
    cat /var/tmp/confirm-deny.log >&2
fi
clear_confirm deny none

# The requester's stdin is a pipe holding the expected word. It cannot answer
# the broker's separate watch question. A positive timeout makes the requester
# wait, so an approval would be seen; confirm.exp then checks the entry is still
# pending and a re-run is not approved.
cat >/etc/xudo/config.toml <<'EOF'
confirm_human_path = true
confirmation_timeout_secs = 3
EOF
if expect /harness/confirm.exp self-stdin >/var/tmp/self-stdin.out 2>&1; then
    good "self_approval_from_the_requesters_stdin_fails"
else
    bad "self_approval_from_the_requesters_stdin_fails"
    cat /var/tmp/self-stdin.out >&2
fi
clear_confirm self-stdin some

if expect /harness/confirm.exp self-tty >/var/tmp/self-tty.out 2>&1; then
    good "self_approval_through_dev_tty_fails"
else
    bad "self_approval_through_dev_tty_fails"
    cat /var/tmp/self-tty.out >&2
fi
clear_confirm self-tty some
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
clear_confirm same-session none

# A watcher in a user namespace with a non-identity uid map is not live. Root
# makes the namespace, so the host's restriction on unprivileged ones (AppArmor)
# does not apply, and no sysctl is changed. Needs util-linux >= 2.39 for
# --map-users. A missing prerequisite is a hard failure; the case is never
# skipped.
userns=watch_in_a_user_namespace_is_refused
skip_reason=
unshare_ver=$(unshare --version 2>/dev/null | sed -n 's/.* \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
if [ -z "$unshare_ver" ]; then
    skip_reason="cannot read the unshare version"
elif [ "$(printf '%s\n2.39\n' "$unshare_ver" | sort -V | head -1)" != 2.39 ]; then
    skip_reason="util-linux $unshare_ver has no --map-users"
fi
if [ -z "$skip_reason" ]; then
    xg=$(getent group xudo | cut -d: -f3)
    tu=$(id -u xudotest)
    # util-linux 2.39 maps through newuidmap, which wants a subuid/subgid grant
    # for exactly these ids (disposable container; the range is one id each).
    echo "root:$tu:1" >>/etc/subuid
    echo "root:$xg:1" >>/etc/subgid
    if ! unshare --user --map-users="$tu:$tu:1" --map-groups="$xg:$xg:1" true >/var/tmp/userns-probe.out 2>&1; then
        skip_reason="root cannot create a user namespace here: $(tr '\n' ' ' </var/tmp/userns-probe.out)"
    fi
fi
if [ -n "$skip_reason" ]; then
    bad "$userns cannot run: $skip_reason"
elif expect /harness/confirm.exp userns >/var/tmp/userns.out 2>&1; then
    good "$userns (rc=$(sed -n 's/^REQUESTER_RC=//p' /var/tmp/userns.out))"
else
    bad "$userns"
    cat /var/tmp/userns.out >&2
fi
clear_confirm userns none

# Root's freeze is global; the approved human path must still prompt for and
# accept the password. A user's freeze and thaw reach only that user's own
# marker, so a user's thaw cannot lift root's freeze.
frozen=/var/lib/xudo/frozen
test_uid=$(id -u xudotest)
pkill -TERM -u "$test_uid" -x xudo 2>/dev/null || true
sleep 1
clear_confirm before_freeze none
if xudo freeze --reason 'systemd M3 proof' >/var/tmp/freeze.out 2>&1 && [ -f "$frozen" ]; then
    good "freeze_creates_the_frozen_file"
    if expect /harness/confirm.exp approve >/var/tmp/frozen-approve.log 2>&1; then
        good "freeze_then_human_password_path_runs"
    else
        bad "freeze_then_human_password_path_runs"
        cat /var/tmp/frozen-approve.log /var/tmp/case.out >&2 || true
    fi
else
    bad "freeze_creates_the_frozen_file"
    cat /var/tmp/freeze.out >&2
fi
clear_confirm freeze_approve none
set +e
su -s /bin/sh -c '/usr/bin/xudo thaw' xudotest >/var/tmp/nonroot-thaw.out 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ] && [ -f "$frozen" ]; then
    good "a_users_thaw_cannot_lift_roots_global_freeze (rc=$rc)"
else
    bad "a_users_thaw_cannot_lift_roots_global_freeze (rc=$rc, frozen file: $([ -f "$frozen" ] && echo present || echo gone))"
    cat /var/tmp/nonroot-thaw.out >&2
fi
user_frozen=/var/lib/xudo/frozen-$test_uid
set +e
su -s /bin/sh -c '/usr/bin/xudo freeze --reason "user scope"' xudotest >/var/tmp/user-freeze.out 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ] && [ -f "$user_frozen" ]; then
    good "a_users_freeze_writes_only_their_own_marker"
else
    bad "a_users_freeze_writes_only_their_own_marker (rc=$rc)"
    cat /var/tmp/user-freeze.out >&2
fi
set +e
su -s /bin/sh -c '/usr/bin/xudo thaw' xudotest >/var/tmp/user-thaw.out 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ] && [ ! -e "$user_frozen" ] && [ -f "$frozen" ]; then
    good "a_users_thaw_removes_only_their_own_marker"
else
    bad "a_users_thaw_removes_only_their_own_marker (rc=$rc)"
    cat /var/tmp/user-thaw.out >&2
fi
su -s /bin/sh -c '/usr/bin/xudo freeze --reason "user scope"' xudotest >/dev/null 2>&1 || true
if xudo thaw >/var/tmp/root-thaw.out 2>&1 && [ ! -e "$frozen" ] && [ ! -e "$user_frozen" ]; then
    good "xudo_thaw_works_as_root_and_removes_every_freeze_marker"
else
    bad "xudo_thaw_works_as_root_and_removes_every_freeze_marker"
    cat /var/tmp/root-thaw.out >&2
fi

# Install the short-TTL package only for its expiry proof. Restore the normal
# package before journal, audit, pasban and remove checks below.
if ! dpkg -i /opt/xudo-short-ttl.deb >/var/tmp/xudo-short-ttl-install.log 2>&1; then
    cat /var/tmp/xudo-short-ttl-install.log >&2
    bad "install short-TTL test package"
else
    marker=xudo-lane-short-ttl-20-seconds
    if grep -aFq "$marker" /usr/libexec/xudo/xudod &&
        grep -aFq "$marker" /usr/libexec/xudo/xudo-gate-auth; then
        good "short-TTL marker is present in installed broker and gate"
    else
        bad "short-TTL marker is present in installed broker and gate"
    fi
    name=short_ttl_expires_a_pending_entry
    if expect /harness/confirm.exp pending >/var/tmp/confirm-short-ttl.log 2>&1; then
        pending=$(pending_out)
        if [ "$(sed -n 's/^REQUESTER_RC=//p' /var/tmp/confirm-short-ttl.log)" = 18 ] &&
            [ -n "$pending" ] && lists_the_request "$pending"; then
            sleep 5
            still=$(pending_out)
            if lists_the_request "$still"; then
                good "$name (entry remains before its 20-second expiry)"
            else
                bad "$name (entry expired before the 5-second lower bound)"
                printf '%s\n' "$still" >&2
            fi
            sleep 17
            expired=$(pending_out)
            if ! lists_the_request "$expired"; then
                if grep -q 'confirmation_expired' /var/lib/xudo/audit.jsonl; then
                    good "$name (expired entry removed and audited)"
                else
                    bad "$name (expiry audit record missing)"
                fi
            else
                bad "$name (entry remained visible past 20 seconds)"
                printf '%s\n' "$expired" >&2
            fi
        else
            bad "$name (request was not pending initially)"
            cat /var/tmp/confirm-short-ttl.log >&2
        fi
    else
        bad "$name"
        cat /var/tmp/confirm-short-ttl.log >&2
    fi
    clear_confirm "$name" none

    if ! dpkg -i /opt/xudo.deb >/var/tmp/xudo-normal-restore.log 2>&1; then
        cat /var/tmp/xudo-normal-restore.log >&2
        bad "restore normal package after short-TTL expiry case"
    else
        if ! grep -aFq "$marker" /usr/libexec/xudo/xudod &&
            ! grep -aFq "$marker" /usr/libexec/xudo/xudo-gate-auth; then
            good "normal package restored without short-TTL marker"
        else
            bad "normal package restored without short-TTL marker"
        fi
    fi
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
