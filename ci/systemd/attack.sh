# Sourced by grant.sh under real systemd (E7), after G1f's rows and before
# its flood, with the lane-only NOPASSWD line in place: the attack rows E8's
# opt-in install waits for. Each row tries to get a passwordless root run, or
# root's hand on a path the rule does not cover, and asserts the exact
# refusal. Uses grant.sh's driver (submit, collect, as_harness), trail_len,
# spool_vias, has_root_line, show, its tree and rule, and row.sh's good, bad.
#
# What it adds, all inside the disposable container: a home, linger and a key
# for sshd for the `lane` account (its user manager is the leave route, ssh a
# login), a rule file, and two bind mounts. row.sh's EXIT trap unmounts them
# and restores the PAM file if this aborts first; the rows undo the rest.
#
# Not here: rule packs (`xudo rules add`, P1) are not on main yet. The walk's
# refusals on a real kernel without systemd (a planted link, a tmpfs mount)
# are root tests in crates/xudo-sys/tests/root_remove_path.rs (just root-test).

# Never outside the throwaway container: this mounts, starts sshd, and
# deletes a home.
systemd-detect-virt --container -q || {
    bad "e7: not inside a container; refusing to run the attack rows"
    return 1
}

e7=/usr/local/lib/xudo-e7
victim=/var/lib/xudo-e7-victim
attack_rules=/etc/xudo/rules.d/91-e7-attack.toml
account=xudograntee
home=/home/$account
uid=$(id -u "$account")
slice=/sys/fs/cgroup/xudo.slice
scope=$slice/xudo-agent@lane.service

echo "-- e7: kernel $(uname -r), $(systemctl --version | head -n 1)"
apt-get install -y -qq dbus dbus-user-session openssh-server openssh-client expect >/var/tmp/e7-install.log 2>&1 ||
    bad "e7: install dbus-user-session and openssh: $(tail -n 3 /var/tmp/e7-install.log)"
mkdir -p "$e7"
install -d -m 0700 -o "$account" -g "$account" "$home"

# cg <write|mkdir> <path> [pid]: the errno name the kernel answers, or ok.
cat >"$e7/cg" <<'EOF'
import errno, os, sys
op, path = sys.argv[1], sys.argv[2]
try:
    if op == "write":
        fd = os.open(path, os.O_WRONLY)
        try:
            os.write(fd, (sys.argv[3] if len(sys.argv) > 3 else str(os.getpid())).encode())
        finally:
            os.close(fd)
    else:
        os.mkdir(path)
    print("ok")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)))
EOF
# leave <how> <command...>: move this shell out of the harness unit through
# the account's own user manager, print the cgroup it landed in, run the rest.
cat >"$e7/leave" <<'EOF'
how=$1
shift
M="org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
case $how in
scope) exec systemd-run --user --scope --quiet sh /usr/local/lib/xudo-e7/after "$@" ;;
transient)
    busctl --user call $M StartTransientUnit 'ssa(sv)a(sa(sv))' "e7-leave-$$.scope" fail \
        1 PIDs au 1 $$ 0 >/dev/null || echo "call=$?"
    ;;
delegated | plain)
    unit=e7-$how-$$.service
    if [ "$how" = delegated ]; then
        systemd-run --user --quiet --unit="$unit" -p Delegate=yes sleep 600
    else
        systemd-run --user --quiet --unit="$unit" sleep 600
    fi
    busctl --user call $M AttachProcessesToUnit ssau "$unit" "" 1 $$ 2>&1 || echo "call=$?"
    ;;
esac
# The move is asynchronous: give systemd thirty seconds to make it.
i=0
while grep -q '^0::/xudo.slice/' /proc/$$/cgroup && [ "$i" -lt 300 ]; do
    sleep 0.1
    i=$((i + 1))
done
exec sh /usr/local/lib/xudo-e7/after "$@"
EOF
cat >"$e7/after" <<'EOF'
echo "cgroup=$(sed -n 's/^0:://p' /proc/self/cgroup)"
[ "$#" -eq 0 ] || exec "$@"
EOF
# prompt.exp <command...>: run it on a pty until it asks a password, then
# hang up. Gives sudo a terminal, so its PAM auth stack runs.
cat >"$e7/prompt.exp" <<'EOF'
set timeout 60
spawn -noecho {*}$argv
expect {
    -re {[Pp]assword} {}
    eof {}
    timeout { puts "prompt.exp: no password prompt"; exit 124 }
}
catch {close}
exit [lindex [wait] 3]
EOF
chmod 0644 "$e7/cg" "$e7/leave" "$e7/after" "$e7/prompt.exp"

# The account outside its unit: same uid, its own groups, its user manager.
loginctl enable-linger "$account"
for _ in $(seq 1 50); do
    [ -S "/run/user/$uid/bus" ] && break
    sleep 0.2
done
as_account() {
    setpriv --reuid="$account" --regid="$account" --init-groups \
        env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$home" XDG_RUNTIME_DIR="/run/user/$uid" "$@"
}
# outsider <command...>: run as the account in a user-manager unit of its
# own, outside xudo.slice, and wait for it.
outsider() { as_account timeout 120 systemd-run --user --quiet --wait --pipe --collect "$@"; }

# e7_trail <mark>: classification, decision, denial, action and the door
# evidence of every record since line <mark>.
e7_trail() {
    tail -n +"$(($1 + 1))" "$audit" | python3 -c '
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    ev = " ".join(e for e in r["evidence"] if e.startswith(("via=", "gate_mode=", "refused=", "partial=", "count=")))
    print(r["classification"], r["decision"], r.get("denial") or "-", r.get("action") or "-", ev)
'
}
# human_path <case> <class>: the request since $mark took the password path:
# one <class> decision with a password entry, never the harness door, and
# sudo (or 26.04's sudo-rs), with no terminal and no password, ran nothing.
human_path() {
    trail=$(e7_trail "$mark")
    if [ "$hrc" != 0 ] && ! has_root_line "$hout" &&
        printf '%s\n' "$hout" | grep -Eq '^sudo: (a password is required|A terminal is required to authenticate)$' &&
        [ "$(printf '%s\n' "$trail" | grep -c "^$2 allowed - g1f.whoami via=auth\$")" = 1 ] &&
        ! printf '%s\n' "$trail" | grep -q 'via=harness\|gate_mode=' &&
        [ "$(spool_vias)" = auth ]; then
        good "$1"
    else
        bad "$1"
        show "$1"
        printf '%s\n' "$trail" >&2
    fi
    rm -f /run/xudo/req/*
}
# door_refused <case> <code> <class>: a direct call of the passwordless door
# since $mark was refused with <code> after sudo let it start.
door_refused() {
    if printf '%s\n' "$hout" | grep -qx "door=19" &&
        printf '%s\n' "$hout" | grep -q "xudo-gate: refused ($2, severity high)" &&
        e7_trail "$mark" | grep -q "^$3 denied $2 " &&
        ! e7_trail "$mark" | grep -q '^[a-z-]* allowed .*gate_mode='; then
        good "$1"
    else
        bad "$1"
        show "$1"
    fi
}
# capture <command...>: its output (both streams) in hout and status in hrc,
# without row.sh's `set -e` ending the row on a refusal.
capture() {
    set +e
    hout=$("$@" </dev/null 2>&1)
    hrc=$?
    set -e
}
whoami_cmd="/usr/bin/xudo exec -- $gate_exe -un"
door_cmd="/usr/bin/sudo -n $nopass; echo door=\$?"

# --- Enter: nothing the account or a human can do puts a process in a
# harness unit or the slice. Each answer is the kernel's or systemd's.
for who in harness human outsider; do
    probe=
    for target in "$scope" "$slice/xudo-agent@other.service" "$slice" /sys/fs/cgroup; do
        probe="$probe
python3 -I $e7/cg write $target/cgroup.procs"
    done
    probe="$probe
python3 -I $e7/cg mkdir $scope/e7
python3 -I $e7/cg mkdir $slice/e7.scope
cat /proc/self/cgroup"
    case $who in
    harness) as_harness lane enter "$probe" ;;
    human)
        capture su -s /bin/sh -c "$probe" xudotest
        ;;
    outsider)
        printf '%s\n' "$probe" >"$e7/probe"
        chmod 0644 "$e7/probe"
        capture outsider sh "$e7/probe"
        ;;
    esac
    case_name="a_${who}_cannot_write_or_make_a_cgroup_under_the_slice"
    if [ "$hrc" = 0 ] && [ "$(printf '%s\n' "$hout" | grep -cx EACCES)" = 6 ] &&
        [ "$(printf '%s\n' "$hout" | grep -c .)" = 7 ]; then
        good "$case_name"
    else
        bad "$case_name (rc=$hrc)"
        printf '%s\n' "$hout" >&2
    fi
done

# systemd's own routes in: the system manager will not attach a process to a
# unit that is not delegated (the harness's is Delegate=no), whoever asks and
# whichever pid, and an unprivileged caller may not start a scope there.
as_account systemd-run --user --quiet --unit=e7-sleeper sleep 600
sleeper=$(as_account systemctl --user show -P MainPID e7-sleeper.service)
attach="busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager AttachProcessesToUnit ssau xudo-agent@lane.service"
as_harness lane attach "$attach '' 1 $sleeper; echo pull=\$?
$attach /e7 1 $sleeper; echo pull_sub=\$?
systemd-run --scope --slice=xudo.slice true; echo scope=\$?
if command -v run0 >/dev/null; then run0 --no-ask-password true; echo run0=\$?; else echo run0=absent; fi"
printf '%s\n' "$attach '' 1 \$\$; echo push=\$?" "systemd-run --scope --slice=xudo.slice true; echo outscope=\$?" >"$e7/push"
chmod 0644 "$e7/push"
pulled=$hout
capture outsider sh "$e7/push"
hout="$pulled
$hout"
case_name=systemd_will_not_move_a_process_into_a_harness_unit
if [ "$(printf '%s\n' "$hout" | grep -c 'Process migration not available on non-delegated units')" = 3 ] &&
    printf '%s\n' "$hout" | grep -qx 'pull=1' && printf '%s\n' "$hout" | grep -qx 'pull_sub=1' &&
    printf '%s\n' "$hout" | grep -qx 'push=1' &&
    grep -q '^0::/user.slice/' "/proc/$sleeper/cgroup"; then
    good "$case_name"
else
    bad "$case_name"
    printf '%s\n' "$hout" >&2
    cat "/proc/$sleeper/cgroup" >&2 || true
fi
case_name=an_unprivileged_caller_cannot_start_a_scope_under_the_slice
# run0 (systemd 256 and later): absent, or refused by systemd for want of
# polkit, exactly; any other failure is not this refusal.
run0_refused=
case $(printf '%s\n' "$hout" | grep '^run0=') in
run0=absent) run0_refused=1 ;;
run0=1)
    if printf '%s\n' "$hout" | grep -qx 'Failed to start transient service unit: Access denied'; then
        run0_refused=1
    fi
    ;;
esac
if [ "$(printf '%s\n' "$hout" | grep -c 'Failed to start transient scope unit: Access denied')" = 2 ] &&
    printf '%s\n' "$hout" | grep -qx 'scope=1' && printf '%s\n' "$hout" | grep -qx 'outscope=1' &&
    [ -n "$run0_refused" ]; then
    good "$case_name ($(printf '%s\n' "$hout" | grep '^run0='))"
else
    bad "$case_name"
    printf '%s\n' "$hout" >&2
fi
as_account systemctl --user stop e7-sleeper.service

# --- Leave: the harness can leave its unit through its own user manager (the
# measured cells: a user scope, a user transient unit, a delegated user unit;
# a plain one is refused). It is then a human: a password entry, never the door.
# Ubuntu 24.04's StartTransientUnit cell is not pinned yet: there the call may
# also be refused, and the process must then still be the harness (VERSION_ID
# is row.sh's, from /etc/os-release).
left="^cgroup=/user.slice/user-$uid.slice/user@$uid.service/"
for how in scope transient delegated; do
    mark=$(trail_len)
    as_harness lane "leave-$how" "sh $e7/leave $how $whoami_cmd"
    case_name="a_harness_that_leaves_by_a_user_${how}_unit_is_human"
    if printf '%s\n' "$hout" | grep -q "$left"; then
        human_path "$case_name" human
    elif [ "$how" = transient ] && [ "${VERSION_ID:-}" = 24.04 ] &&
        printf '%s\n' "$hout" | grep -q '^call=' &&
        printf '%s\n' "$hout" | grep -qx 'cgroup=/xudo.slice/xudo-agent@lane.service' &&
        [ "$hrc" = 0 ] && has_root_line "$hout" &&
        e7_trail "$mark" | grep -q '^enrolled-agent allowed - g1f.whoami gate_mode=Nopass via=harness'; then
        good "$case_name (24.04: the call was refused, the process stayed the harness)"
        rm -f /run/xudo/req/*
    else
        bad "$case_name (did not leave)"
        show "$case_name"
        rm -f /run/xudo/req/*
    fi
done
mark=$(trail_len)
as_harness lane leave-plain "sh $e7/leave plain $whoami_cmd"
case_name=a_harness_cannot_leave_by_a_plain_user_unit
if printf '%s\n' "$hout" | grep -q 'Process migration not available on non-delegated units' &&
    printf '%s\n' "$hout" | grep -qx 'cgroup=/xudo.slice/xudo-agent@lane.service' &&
    [ "$hrc" = 0 ] && has_root_line "$hout" &&
    e7_trail "$mark" | grep -q '^enrolled-agent allowed - g1f.whoami gate_mode=Nopass via=harness'; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi

# Leave, then try to come back: the way in is shut, and the leaver stays human.
# A file, not `sh -c`: systemd-run 259 expands `$$` in its arguments.
printf '%s\n' "python3 -I $e7/cg write $scope/cgroup.procs" "$attach '' 1 \$\$; echo back=\$?" \
    "$whoami_cmd" >"$e7/return"
chmod 0644 "$e7/return"
mark=$(trail_len)
as_harness lane return "sh $e7/leave scope sh $e7/return"
case_name=a_leaver_cannot_move_back_into_the_harness_unit
if printf '%s\n' "$hout" | grep -q "$left" &&
    printf '%s\n' "$hout" | grep -qx EACCES && printf '%s\n' "$hout" | grep -qx 'back=1' &&
    printf '%s\n' "$hout" | grep -q 'Process migration not available on non-delegated units'; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi
human_path a_leaver_that_tried_to_return_is_still_human human

# A leaver going straight to the door: sudo lets it start (the lane-only line
# names the account's group), the gate finds no entry for it. That it left is
# asserted: from inside, a door call with no entry gets the same refusal.
mark=$(trail_len)
as_harness lane leave-door "sh $e7/leave scope sh -c '$door_cmd'"
if printf '%s\n' "$hout" | grep -q "$left"; then
    door_refused a_scope_leaver_asking_the_passwordless_door_is_refused gate_no_pending_request unattested
else
    bad "a_scope_leaver_asking_the_passwordless_door_is_refused (did not leave)"
    show leave-door
fi

# A lookalike unit in the account's user manager: the harness's own name and
# slice, under user@ instead of the system's xudo.slice.
mark=$(trail_len)
as_harness lane lookalike "XDG_RUNTIME_DIR=/run/user/$uid timeout 120 systemd-run --user --quiet --wait --pipe --collect \
--unit=xudo-agent@lane.service --slice=xudo.slice sh $e7/after $whoami_cmd"
case_name=a_user_manager_unit_named_like_the_harness_is_not_one
if printf '%s\n' "$hout" | grep -qx "cgroup=/user.slice/user-$uid.slice/user@$uid.service/xudo.slice/xudo-agent@lane.service"; then
    human_path "$case_name" human
else
    bad "$case_name (cgroup)"
    show "$case_name"
fi

# Unregistered units under the real slice, made by root (standing in for a
# human who authenticated to polkit): no record, so unattested, password path.
hex=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
mark=$(trail_len)
capture systemd-run --quiet --scope --slice=xudo.slice --unit="agent-$hex.scope" \
    setpriv --reuid="$account" --regid="$account" --init-groups sh "$e7/after" $whoami_cmd
if printf '%s\n' "$hout" | grep -qx "cgroup=/xudo.slice/agent-$hex.scope"; then
    human_path a_root_made_scope_under_the_slice_without_a_record_is_unattested unattested
else
    bad "a_root_made_scope_under_the_slice_without_a_record_is_unattested (cgroup)"
    printf '%s\n' "$hout" >&2
fi
mark=$(trail_len)
capture timeout 120 systemd-run --quiet --wait --pipe --collect --unit=xudo-agent-lane.service --slice=xudo.slice \
    --uid="$account" sh "$e7/after" $whoami_cmd
if printf '%s\n' "$hout" | grep -qx 'cgroup=/xudo.slice/xudo-agent-lane.service'; then
    human_path a_root_made_service_under_the_slice_without_a_record_is_unattested unattested
else
    bad "a_root_made_service_under_the_slice_without_a_record_is_unattested (cgroup)"
    printf '%s\n' "$hout" >&2
fi

# Impersonation: a copy of the driver, bound over the real one's path so its
# command line is the harness's to the byte (`/bin/sh .../driver lane`), run
# as the account with CLAUDECODE=1 in a system unit of its own. It stays the
# parent of each request it runs, so the broker sees a live lookalike
# ancestor, not an exec trick. Only its box differs. Hints are recorded,
# never trusted.
sed 's|^box=/var/lib/xudo-g1f/\$1$|box=/var/lib/xudo-g1f/e7-$1|' /usr/local/lib/xudo-g1f/driver >"$e7/driver"
chmod 0644 "$e7/driver"
install -d -m 0700 -o "$account" -g "$account" /var/lib/xudo-g1f/e7-lane
systemd-run --quiet --unit=e7-impostor.service --uid="$account" -E CLAUDECODE=1 \
    -p BindReadOnlyPaths="$e7/driver:/usr/local/lib/xudo-g1f/driver" \
    /bin/sh /usr/local/lib/xudo-g1f/driver lane
impostor=$(systemctl show -P MainPID e7-impostor.service)
mark=$(trail_len)
as_harness e7-lane impersonate "sh $e7/after $whoami_cmd"
case_name=an_unregistered_process_of_the_agent_uid_is_human
if printf '%s\n' "$hout" | grep -qx 'cgroup=/system.slice/e7-impostor.service' &&
    [ "$(tr '\0' ' ' <"/proc/$impostor/cmdline")" = "/bin/sh /usr/local/lib/xudo-g1f/driver lane " ] &&
    tr '\0' '\n' <"/proc/$impostor/environ" | grep -qx CLAUDECODE=1 &&
    grep -q '^box=/var/lib/xudo-g1f/e7-' "/proc/$impostor/root/usr/local/lib/xudo-g1f/driver"; then
    human_path "$case_name" human
else
    bad "$case_name (impostor)"
    show "$case_name"
    cat "/proc/$impostor/cmdline" >&2 || true
fi
# Where the hint is recorded: `xudo doctor` counts it and trusts none. It
# counts one more hint with CLAUDECODE than without (comm, cmdline and exe
# are hints too).
as_harness e7-lane hints '/usr/bin/xudo doctor 2>&1 | sed -n "s/^hints  *\([0-9]*\) recorded, 0 trusted$/with=\1/p"
env -u CLAUDECODE /usr/bin/xudo doctor 2>&1 | sed -n "s/^hints  *\([0-9]*\) recorded, 0 trusted$/without=\1/p"'
with=$(printf '%s\n' "$hout" | sed -n 's/^with=//p')
without=$(printf '%s\n' "$hout" | sed -n 's/^without=//p')
case_name=the_impostors_claudecode_hint_is_recorded_and_not_trusted
if [ -n "$with" ] && [ -n "$without" ] && [ "$with" = "$((without + 1))" ]; then
    good "$case_name"
else
    bad "$case_name"
    printf '%s\n' "$hout" >&2
fi
systemctl stop e7-impostor.service
rm -rf /var/lib/xudo-g1f/e7-lane

# An SSH login as the agent account: a session scope, so human; the door
# refuses it too (below, with an entry minted for the login).
install -d -m 0700 -o "$account" -g "$account" "$home/.ssh"
rm -f /var/tmp/e7-key /var/tmp/e7-key.pub
ssh-keygen -q -t ed25519 -N '' -f /var/tmp/e7-key
install -m 0600 -o "$account" -g "$account" /var/tmp/e7-key.pub "$home/.ssh/authorized_keys"
started_ssh=
if ! systemctl is-active -q ssh.socket && ! systemctl is-active -q ssh.service; then
    systemctl start ssh.service
    started_ssh=1
fi
ssh_as() {
    timeout 120 ssh -i /var/tmp/e7-key -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o LogLevel=ERROR "$account@127.0.0.1" "$1"
}
mark=$(trail_len)
capture ssh_as "sh $e7/after $whoami_cmd"
if printf '%s\n' "$hout" | grep -Eq "^cgroup=/user.slice/user-$uid.slice/session-[^/]*.scope\$"; then
    human_path an_ssh_login_as_the_agent_account_is_human human
else
    bad "an_ssh_login_as_the_agent_account_is_human (rc=$hrc)"
    printf '%s\n' "$hout" >&2
    journalctl -u ssh --no-pager -n 20 >&2 || true
fi

# Between mint and gate (sudo's PAM runs the armed text as root, once, in
# its auth stack on the password path and its account stack on the door):
# another process of the account, outside the unit, calls the door while the
# harness's entry waits; then the requester itself is moved out through the
# account's user manager. Neither runs anything. row.sh's EXIT trap restores
# the PAM file if this aborts.
hook_on() {
    cp -a /etc/pam.d/sudo /var/tmp/g1f-pam-sudo
    {
        echo 'auth optional pam_exec.so seteuid quiet /usr/local/lib/xudo-g1f/between'
        echo 'account optional pam_exec.so seteuid quiet /usr/local/lib/xudo-g1f/between'
        cat /var/tmp/g1f-pam-sudo
    } >/etc/pam.d/sudo
}
hook_off() {
    cp -a /var/tmp/g1f-pam-sudo /etc/pam.d/sudo
    rm -f /var/tmp/g1f-pam-sudo "$g1f/once" /run/xudo/req/*
}
hook_on
arm "timeout 120 systemd-run --quiet --wait --pipe --collect --uid=$account sh -c '$door_cmd'"
mark=$(trail_len)
as_harness lane steal "$whoami_cmd"
trail=$(e7_trail "$mark")
case_name=a_same_uid_process_outside_the_unit_cannot_consume_a_harness_entry
if grep -qx 'door=19' "$g1f/ran.out" &&
    grep -q 'xudo-gate: refused (gate_no_pending_request, severity high)' "$g1f/ran.out" &&
    printf '%s\n' "$trail" | grep -q '^unattested denied gate_no_pending_request ' &&
    [ "$(printf '%s\n' "$trail" | grep -c 'gate_mode=')" = 1 ] &&
    [ "$hrc" = 0 ] && has_root_line "$hout"; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
    cat "$g1f/ran.out" >&2 || true
fi
as_account systemd-run --user --quiet --unit=e7-adopt -p Delegate=yes sleep 600
arm "pid=\$(pgrep -u $account -x xudo)
setpriv --reuid=$account --regid=$account --init-groups env XDG_RUNTIME_DIR=/run/user/$uid \
busctl --user call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
AttachProcessesToUnit ssau e7-adopt.service '' 1 \$pid
sed -n 's/^0::/moved=/p' /proc/\$pid/cgroup"
mark=$(trail_len)
as_harness lane adopt "$whoami_cmd"
case_name=a_requester_moved_out_through_its_user_manager_after_the_mint_is_refused
if grep -qx "moved=/user.slice/user-$uid.slice/user@$uid.service/app.slice/e7-adopt.service" "$g1f/ran.out" &&
    [ "$hrc" = 19 ] && ! has_root_line "$hout" &&
    printf '%s\n' "$hout" | grep -q 'xudo-gate: refused (gate_mode_not_an_enrolled_agent, severity high)' &&
    e7_trail "$mark" | grep -q '^unattested denied gate_mode_not_an_enrolled_agent ' &&
    ! e7_trail "$mark" | grep -q '^[a-z-]* allowed .*gate_mode='; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
    cat "$g1f/ran.out" >&2 || true
fi
as_account systemctl --user stop e7-adopt.service
rm -f /run/xudo/req/*

# A human's entry at the passwordless door: a caller that is not the harness
# (a leaver, an SSH login) gets a real `auth` entry from `xudo exec`, and
# while sudo asks its password, the hook runs the door as the account from
# inside that caller's own process tree, so the gate finds the entry. The
# entry is for the other gate file: refused, and nothing runs.
# wrong_via <case> <cgroup pattern>: the request since $mark, run on a pty.
wrong_via() {
    if printf '%s\n' "$hout" | grep -Eq "$2" &&
        printf '%s\n' "$hout" | grep -q '[Pp]assword' && ! has_root_line "$hout" &&
        [ -e "$g1f/ran" ] && grep -qx 'door=19' "$g1f/ran.out" && ! grep -qx root "$g1f/ran.out" &&
        grep -q 'xudo-gate: refused (gate_mode_wrong_via, severity high)' "$g1f/ran.out" &&
        [ "$(e7_trail "$mark" | grep -c '^human allowed - g1f.whoami via=auth$')" = 1 ] &&
        e7_trail "$mark" | grep -q '^[a-z-]* denied gate_mode_wrong_via ' &&
        ! e7_trail "$mark" | grep -q '^[a-z-]* allowed .*gate_mode=' &&
        [ "$(spool_vias)" = auth ]; then
        good "$1"
    else
        bad "$1"
        show "$1"
        cat "$g1f/ran.out" >&2 || true
    fi
    rm -f /run/xudo/req/*
}
door_as_account="setpriv --reuid=$account --regid=$account --init-groups env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin sh -c '$door_cmd'"
arm "$door_as_account"
mark=$(trail_len)
as_harness lane leave-mint "sh $e7/leave scope expect -f $e7/prompt.exp $whoami_cmd"
wrong_via a_leaver_with_a_password_entry_is_refused_at_the_passwordless_door "$left"
arm "$door_as_account"
mark=$(trail_len)
capture ssh_as "sh $e7/after expect -f $e7/prompt.exp $whoami_cmd"
wrong_via an_ssh_login_as_the_agent_account_cannot_use_the_door \
    "^cgroup=/user.slice/user-$uid.slice/session-[^/]*.scope\$"
hook_off

# --- Rule escapes. A value rule beside G1f's literal one, then every
# spelling an injected option could take. Matching is byte-exact on the argv
# the kernel delivers, so each is "no rule allows this": exit 17, no entry.
cat >"$attack_rules" <<EOF
[[action]]
id = "e7.user"
tier = "diag-read"
exe = "$gate_exe"
args = [
    { name = "flag", matcher = { literal = "-u" } },
    { name = "user", matcher = { one-of = ["xudotest"] } },
]
harness = ["lane"]
outcome = "allow"
EOF
chmod 0644 "$attack_rules"
mark=$(trail_len)
as_harness lane value "/usr/bin/xudo exec -- $gate_exe -u xudotest"
case_name=the_value_rule_grants_its_exact_argv
if [ "$hrc" = 0 ] && printf '%s\n' "$hout" | grep -qx "$(id -u xudotest)" &&
    e7_trail "$mark" | grep -q '^enrolled-agent allowed - e7.user gate_mode=Nopass via=harness'; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi
injected=0
for argv in "-un -rf" "-- -un" "-un -- --" "-u -n" "-nu" "-un root" "--name --user" "-un=x" \
    "-u -r" "-u --help" "-u -- xudotest" "-u xudotest -- --" "-u xudotest -r" "-u=xudotest" \
    "--user=xudotest" "--user xudotest" "-uxudotest" "-u xudotest xudotest" "-u root"; do
    mark=$(trail_len)
    as_harness lane inject "/usr/bin/xudo exec -- $gate_exe $argv"
    if [ "$hrc" = 17 ] && [ -z "$(spool_vias)" ] &&
        [ "$(e7_trail "$mark")" = "enrolled-agent denied argv_rejected - " ]; then
        injected=$((injected + 1))
    else
        bad "an_injected_option_is_never_granted: $gate_exe $argv (rc=$hrc)"
        show inject
        rm -f /run/xudo/req/*
    fi
done
if [ "$injected" = 19 ]; then good "an_injected_option_is_never_granted (19 spellings)"; fi
# A separator with nothing after it is dropped by canonicalization
# (Argv::canonicalize), and what the gate runs is the argv that matched.
for argv in "-un --" "-u xudotest --"; do
    mark=$(trail_len)
    as_harness lane separator "/usr/bin/xudo exec -- $gate_exe $argv"
    ran=$(tail -n +"$((mark + 1))" "$audit" | python3 -c '
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    if any(e.startswith("gate_mode=Nopass") for e in r["evidence"]):
        print(" ".join(r["argv"]))
')
    case_name="a_trailing_separator_runs_the_argv_that_matched: $argv"
    if [ "$hrc" = 0 ] && [ "$ran" = "$gate_exe ${argv% --}" ]; then
        good "$case_name"
    else
        bad "$case_name (ran: $ran)"
        show "$case_name"
    fi
done
rm -f "$attack_rules"

# remove-path: links in the account's home, `..`, absolute and malformed
# targets are refused by the broker before anything is minted; a link inside
# the tree and a bind mount are refused by the gate's walk. Nothing outside
# the tree changes.
rm -rf "$tree" "$outside"
install -d -m 0755 "$tree"
install -d -m 0755 -o "$account" -g "$account" "$tree/cache" "$tree/cache/deep" "$tree/cache/deep/m2" "$tree/mnt" "$victim"
for f in "$victim/v.o" "$tree/cache/c.o" "$outside"; do
    printf 'keep\n' >"$f"
    chown "$account:$account" "$f"
done
as_account ln -s "$outside" "$home/out"
as_account ln -s "$tree/cache" "$home/in"
as_account ln -s "$victim" "$tree/cache/hop"
mount --bind "$victim" "$tree/mnt"
mount --bind "$victim" "$tree/cache/deep/m2"
# broker <case> <target> <reason in the trace>
broker_refuses() {
    mark=$(trail_len)
    as_harness lane escape "/usr/bin/xudo op remove-path '$2'"
    if [ "$hrc" = 17 ] && printf '%s\n' "$hout" | grep -q "skipped remove-path: $3\$" &&
        [ "$(e7_trail "$mark")" = "enrolled-agent denied operation_refused - " ] &&
        [ -z "$(spool_vias)" ]; then
        good "$1"
    else
        bad "$1"
        show "$1"
        rm -f /run/xudo/req/*
    fi
}
outside_rule='no remove-path rule covers this target'
unclean='target is not a clean absolute path'
broker_refuses a_link_in_the_home_to_a_file_outside_the_tree_is_refused "$home/out" "$outside_rule"
broker_refuses a_link_in_the_home_into_the_tree_is_refused "$home/in" "$outside_rule"
broker_refuses a_dotdot_out_of_the_tree_is_refused "$tree/../xudo-g1f-outside" "$unclean"
broker_refuses a_dotdot_inside_a_deeper_target_is_refused "$tree/cache/../../xudo-g1f-outside" "$unclean"
broker_refuses an_absolute_target_outside_the_tree_is_refused /etc/passwd "$outside_rule"
broker_refuses the_filesystem_root_is_refused / "$unclean"
broker_refuses the_tree_root_is_refused "$tree" 'the tree root is never removed'
broker_refuses a_doubled_slash_is_refused "$tree//cache" "$unclean"
broker_refuses a_dot_component_is_refused "$tree/./cache" "$unclean"
broker_refuses a_trailing_slash_is_refused "$tree/cache/" "$unclean"
mark=$(trail_len)
as_harness lane relative "cd $tree && /usr/bin/xudo op remove-path cache"
case_name=a_relative_target_is_refused_before_the_broker
if [ "$hrc" = 19 ] && printf '%s\n' "$hout" | grep -qx 'xudo: target must be an absolute path without NUL' &&
    [ "$(trail_len)" = "$mark" ]; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi
mark=$(trail_len)
as_harness lane flag "/usr/bin/xudo op remove-path -rf $tree/cache"
case_name=an_option_before_a_remove_path_target_is_refused_before_the_broker
if [ "$hrc" = 2 ] && [ "$(trail_len)" = "$mark" ] && [ -f "$tree/cache/c.o" ]; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi
# The gate's walk: a link or a mount it would cross is an escape. The gate
# refuses it loudly (gate_walk_escape, severity high, with what it met) and
# removes nothing, not even what the walk would have reached first (c.o).
# walk_escape <case> <what the walk met>: the request since $mark.
walk_escape() {
    if [ "$hrc" = 19 ] && printf '%s\n' "$hout" | grep -q 'xudo-gate: refused (gate_walk_escape, severity high)' &&
        e7_trail "$mark" | grep -q '^enrolled-agent denied gate_walk_escape ' &&
        tail -n +"$((mark + 1))" "$audit" | grep -qF "\"detail=$2\"" &&
        ! e7_trail "$mark" | grep -q 'count=' &&
        [ "$(cat "$victim/v.o")" = keep ] && [ -f "$tree/cache/c.o" ]; then
        good "$1"
    else
        bad "$1"
        show "$1"
        e7_trail "$mark" >&2
    fi
}
link_met='a directory on the way to the target is a symbolic link'
mount_met='the walk would cross a mount'
mark=$(trail_len)
as_harness lane hop "/usr/bin/xudo op remove-path $tree/cache/hop/v.o"
walk_escape a_link_inside_the_tree_is_never_followed_to_a_directory_outside "$link_met"
# A bind mount: as the target, as a parent, and inside a recursive removal.
for target in "$tree/mnt" "$tree/mnt/v.o" "$tree/cache"; do
    mark=$(trail_len)
    as_harness lane mount "/usr/bin/xudo op remove-path $target"
    walk_escape "a_bind_mount_in_the_tree_is_never_crossed: ${target#"$tree"/}" "$mount_met"
done
# Mint, then swap: the broker mints a removal of x/v.o while x is a real
# directory; between the mint and the gate, the account swaps x for a link to
# the victim. The gate re-walks the tree itself and meets the link.
install -d -m 0755 -o "$account" -g "$account" "$tree/cache/x"
printf 'keep\n' >"$tree/cache/x/v.o"
chown "$account:$account" "$tree/cache/x/v.o"
hook_on
arm "cd $tree/cache && setpriv --reuid=$account --regid=$account --init-groups sh -c 'mv x x.gone && ln -s $victim x'"
mark=$(trail_len)
as_harness lane swap "/usr/bin/xudo op remove-path $tree/cache/x/v.o"
if [ -e "$g1f/ran" ] && [ -L "$tree/cache/x" ] && [ "$(cat "$tree/cache/x.gone/v.o")" = keep ]; then
    walk_escape a_link_swapped_in_after_the_mint_is_never_followed "$link_met"
else
    bad "a_link_swapped_in_after_the_mint_is_never_followed (no swap)"
    show swap
    cat "$g1f/ran.out" >&2 || true
fi
hook_off
umount "$tree/cache/deep/m2" "$tree/mnt"
case_name=remove_path_escapes_leave_everything_outside_the_tree
if [ "$(cat "$outside")" = keep ] && [ "$(cat "$victim/v.o")" = keep ] &&
    [ -L "$home/out" ] && [ -L "$home/in" ] && [ -d "$tree" ]; then
    good "$case_name"
else
    bad "$case_name"
    find "$victim" "$outside" "$home" -printf '%u %p\n' >&2 || true
fi
rm -rf "$tree" "$outside" "$victim" "$home/out" "$home/in"

# --- Freeze under load. Root's global freeze, then the harness's own marker:
# ten concurrent requests, every one denied at the broker or, past the
# socket's MaxConnectionsPerSource=8 for one uid, never served; the harness
# cannot thaw either, from its unit or from a login; the human path still runs.
concurrent='i=0
while [ "$i" -lt 10 ]; do
    ( '"$whoami_cmd"' >"/var/tmp/e7-c-$i.out" 2>&1; echo "rc=$?" >>"/var/tmp/e7-c-$i.out" ) &
    i=$((i + 1))
done
wait
cat /var/tmp/e7-c-*.out
rm -f /var/tmp/e7-c-*.out
/usr/bin/xudo thaw; echo thaw=$?'
for kind in global harness; do
    case $kind in
    global) /usr/bin/xudo freeze --reason 'e7 load' >/dev/null ;;
    harness) printf '{"reason":"e7 load","uid":0,"time":0}' >/var/lib/xudo/frozen-h-lane ;;
    esac
    mark=$(trail_len)
    as_harness lane "frozen-$kind" "$concurrent"
    harness_out=$hout
    capture ssh_as '/usr/bin/xudo thaw; echo thaw=$?'
    ssh_thaw=$hout
    hout=$harness_out
    case_name="a_${kind}_freeze_holds_under_ten_concurrent_requests"
    denied=$(printf '%s\n' "$hout" | grep -cx 'rc=17' || true)
    unserved=$(printf '%s\n' "$hout" |
        grep -Ec '^xudo: the broker is unreachable \((Connection reset by peer|Broken pipe|Connection refused)' || true)
    if [ "$denied" -ge 8 ] && [ "$((denied + unserved))" = 10 ] &&
        [ "$(printf '%s\n' "$hout" | grep -cx 'rc=19')" = "$unserved" ] && ! has_root_line "$hout" &&
        [ "$(e7_trail "$mark" | grep -c '^enrolled-agent denied frozen - ')" = "$denied" ] &&
        ! e7_trail "$mark" | grep -q '^[a-z-]* allowed ' && [ -z "$(spool_vias)" ]; then
        good "$case_name (denied=$denied unserved=$unserved)"
    else
        bad "$case_name (denied=$denied unserved=$unserved)"
        show "$case_name"
    fi
    case $kind in
    global) marker=/var/lib/xudo/frozen ;;
    harness) marker=/var/lib/xudo/frozen-h-lane ;;
    esac
    case_name="neither_the_harness_nor_a_login_lifts_a_${kind}_freeze"
    if printf '%s\n' "$hout" | grep -qx 'thaw=17' && [ -f "$marker" ] &&
        printf '%s\n' "$ssh_thaw" | grep -qx 'thaw=17' &&
        printf '%s\n' "$hout" | grep -q 'this account runs an agent harness: use `sudo xudo thaw`'; then
        good "$case_name (login: $(printf '%s\n' "$ssh_thaw" | tail -n 1))"
    else
        bad "$case_name"
        show "$case_name"
        printf '%s\n' "$ssh_thaw" >&2
    fi
    # Root's freeze covers the second harness too; lane's own does not. After
    # the rows above, whose trail its record would otherwise join.
    other_mark=$(trail_len)
    as_harness other "frozen-other-$kind" "$whoami_cmd"
    other_trail=$(e7_trail "$other_mark")
    case_name="a_${kind}_freeze_reaches_the_other_harness_as_it_should"
    case $kind in
    global) other_want='^enrolled-agent denied frozen ' ;;
    harness) other_want='refused=harness_not_granted' ;;
    esac
    if [ "$hrc" = 17 ] && ! has_root_line "$hout" && printf '%s\n' "$other_trail" | grep -q "$other_want" &&
        { [ "$kind" = global ] || ! printf '%s\n' "$other_trail" | grep -q ' denied frozen '; }; then
        good "$case_name"
    else
        bad "$case_name"
        show "$case_name"
        printf '%s\n' "$other_trail" >&2
    fi
    rc=$(pty pw "$gate_exe" -u)
    case_name="the_human_password_path_runs_under_a_${kind}_freeze"
    if [ "$rc" -eq 0 ] && grep -qi password /var/tmp/case.out && grep -qx 0 /var/tmp/case.out; then
        good "$case_name"
    else
        bad "$case_name (rc=$rc)"
        cat /var/tmp/case.out >&2
    fi
    /usr/bin/xudo thaw >/dev/null
    rm -f /var/lib/xudo/frozen-h-lane
done
as_harness lane thawed "$whoami_cmd"
if [ "$hrc" = 0 ] && has_root_line "$hout"; then
    good "the_grant_returns_after_root_thaws"
else
    bad "the_grant_returns_after_root_thaws"
    show the_grant_returns_after_root_thaws
fi

# --- The ceiling on grants themselves: G1f's flood is calls with no entry,
# which the gate counts by uid alone; this one is real grants, counted by uid
# and label. Runs until the gate refuses one; at most 60 in any minute ran.
# A runner whose calls take a second or more never fills a minute; then the
# hour's 600 stops it, so it gets 700 tries and fifteen minutes.
mark=$(trail_len)
started=$(date +%s)
submit lane ceiling 'i=0
while [ "$i" -lt 700 ]; do
    out=$('"$whoami_cmd"' 2>&1)
    rc=$?
    echo "$rc $(printf "%s\n" "$out" | grep -o "gate_rate_ceiling\|^root$" | head -n 1)"
    [ "$rc" = 0 ] || break
    i=$((i + 1))
done'
i=0
while [ ! -e /var/lib/xudo-g1f/lane/ceiling.rc ] && [ "$i" -lt 900 ]; do
    sleep 1
    i=$((i + 1))
done
collect lane ceiling
minutes=$((($(date +%s) - started) / 60 + 1))
ran=$(printf '%s\n' "$hout" | grep -cx '0 root' || true)
case_name=a_granted_command_over_the_ceiling_is_refused_and_runs_nothing
if [ "$(printf '%s\n' "$hout" | tail -n 1)" = '19 gate_rate_ceiling' ] &&
    [ "$ran" -ge 1 ] && [ "$ran" -le $((60 * minutes)) ] &&
    [ "$(e7_trail "$mark" | grep -c '^enrolled-agent allowed - g1f.whoami gate_mode=Nopass via=harness')" = "$ran" ] &&
    e7_trail "$mark" | grep -q '^[a-z-]* denied gate_rate_ceiling '; then
    good "$case_name (ran=$ran minutes=$minutes)"
else
    bad "$case_name (ran=$ran minutes=$minutes)"
    printf '%s\n' "$hout" | sort | uniq -c >&2
fi
rm -f /run/xudo/req/*

# What the rows started, so the flood and the lane's teardown see none of it.
as_account systemctl --user stop 'e7-*' 2>/dev/null || true
if [ -n "$started_ssh" ]; then
    systemctl stop ssh.service ssh.socket 2>/dev/null || true
fi
rm -f /var/tmp/e7-key /var/tmp/e7-key.pub /var/tmp/e7-install.log
rm -rf "$home" "$e7"
loginctl disable-linger "$account"
