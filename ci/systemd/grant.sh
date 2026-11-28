# Sourced by row.sh, under real systemd with the package installed: the
# passwordless grant end to end (G1f). Two enrolled service harnesses run a
# small driver as their own accounts, in their own units; a rule grants the
# first, `lane`, and lists nobody else. Uses row.sh's good, bad, pty and gate_exe.
#
# The NOPASSWD line below is LANE ONLY: this script writes it inside the
# disposable container, after both enrolments, and deletes it before it ends.
# The package ships no such line and no install code writes one (E8, not built).
#
# A PAM hook lets a case act between the broker's mint and the gate: sudo
# runs it (account and session, as root) after xudo has its entry and before
# sudo execs the gate. It does nothing unless a case armed it, and runs once.
#
# Both edits to the system (the NOPASSWD line and /etc/pam.d/sudo) are undone
# by g1f_cleanup, which row.sh runs on EXIT, if this script aborts first.
# attack.sh, sourced before the flood, holds E7's attack rows.

# Never outside the throwaway container: this writes a NOPASSWD line.
lane_sentinel=/xudo-systemd-lane
[ -f "$lane_sentinel" ] && [ ! -L "$lane_sentinel" ] && [ "$(stat -c %u "$lane_sentinel")" = 0 ] &&
    [ "$(cat "$lane_sentinel")" = "xudo systemd lane: a throwaway container made by ci/systemd/run.sh" ] &&
    systemd-detect-virt --container -q || {
    bad "g1f: not inside the systemd lane's container (no run.sh sentinel); refusing to write a NOPASSWD line"
    return 1
}

g1f=/run/xudo-g1f
tree=/var/lib/xudo-g1f-tree
outside=/var/lib/xudo-g1f-outside
lane_sudoers=/etc/sudoers.d/xudo-g1f-lane-only
grant_rules=/etc/xudo/rules.d/90-g1f-grant.toml
audit=/var/lib/xudo/audit.jsonl
nopass=/usr/libexec/xudo/xudo-gate-nopass

# The confirmation cases above leave a rule on `id -u` and the watch setting.
rm -f /etc/xudo/rules.d/99-systemd-confirm.toml /run/xudo/req/*
: >/etc/xudo/config.toml

mkdir -p /usr/local/lib/xudo-g1f /var/lib/xudo-g1f
chmod 0755 /var/lib/xudo-g1f
install -d -m 0700 "$g1f"
# The harness: runs each request root leaves in its box, one at a time, as the
# unit's account and in the unit's cgroup.
cat >/usr/local/lib/xudo-g1f/driver <<'EOF'
#!/bin/sh
box=/var/lib/xudo-g1f/$1
while :; do
    for req in "$box"/*.req; do
        [ -e "$req" ] || continue
        tag=${req%.req}
        sh "$req" >"$tag.out" 2>&1 </dev/null
        echo $? >"$tag.part"
        rm -f "$req"
        mv "$tag.part" "$tag.rc"
    done
    sleep 0.1
done
EOF
cat >/usr/local/lib/xudo-g1f/between <<'EOF'
#!/bin/sh
once=/run/xudo-g1f/once
[ -f "$once" ] || exit 0
mv "$once" /run/xudo-g1f/ran
sh /run/xudo-g1f/ran >/run/xudo-g1f/ran.out 2>&1
exit 0
EOF
chmod 0755 /usr/local/lib/xudo-g1f/driver /usr/local/lib/xudo-g1f/between

for pair in lane:xudograntee other:xudoother; do
    label=${pair%%:*}
    account=${pair#*:}
    id "$account" >/dev/null 2>&1 || useradd --system --no-create-home "$account"
    install -d -m 0700 -o "$account" -g "$account" "/var/lib/xudo-g1f/$label"
    if /usr/bin/xudo agent enrol "$label" --account "$account" --reviewer xudotest \
        -- /bin/sh /usr/local/lib/xudo-g1f/driver "$label" >/var/tmp/g1f-enrol.log 2>&1; then
        good "g1f: enrol $label as $account"
    else
        bad "g1f: enrol $label as $account"
        cat /var/tmp/g1f-enrol.log >&2
    fi
done
for label in lane other; do
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -e "/run/xudo/sessions/svc-$label" ] && break
        sleep 1
    done
    if [ -e "/run/xudo/sessions/svc-$label" ] &&
        [ "$(systemctl is-active "xudo-agent@$label.service")" = active ]; then
        good "g1f: xudo-agent@$label running with its record"
    else
        bad "g1f: xudo-agent@$label running with its record"
        journalctl -u "xudo-agent@$label" --no-pager -n 20 >&2 || true
    fi
done

cat >"$grant_rules" <<EOF
[[action]]
id = "g1f.whoami"
tier = "diag-read"
exe = "$gate_exe"
args = [{ name = "name", matcher = { literal = "-un" } }]
harness = ["lane"]
outcome = "allow"

[[action]]
id = "g1f.ask"
tier = "diag-read"
exe = "$gate_exe"
args = [{ name = "group", matcher = { literal = "-g" } }]
harness = ["lane"]
outcome = "ask-human"

[[operation]]
id = "g1f.clean"
op = "remove-path"
under = "$tree"
recursive = true
max-depth = 3
max-entries = 16
owners = ["xudograntee"]
harness = ["lane"]
outcome = "allow"
EOF
chmod 0644 "$grant_rules"

# submit <label> <tag> <shell text>: hand the text to that harness's driver.
submit() {
    rm -f "/var/lib/xudo-g1f/$1/$2".*
    printf '%s\n' "$3" >"/var/lib/xudo-g1f/$1/.$2"
    chmod 0644 "/var/lib/xudo-g1f/$1/.$2"
    mv "/var/lib/xudo-g1f/$1/.$2" "/var/lib/xudo-g1f/$1/$2.req"
}
# collect <label> <tag>: wait (up to 3 minutes: the flood is 200 calls) for
# the request, then set hrc and hout.
collect() {
    i=0
    while [ ! -e "/var/lib/xudo-g1f/$1/$2.rc" ] && [ "$i" -lt 1800 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    hrc=$(cat "/var/lib/xudo-g1f/$1/$2.rc" 2>/dev/null || echo timeout)
    hout=$(cat "/var/lib/xudo-g1f/$1/$2.out" 2>/dev/null || true)
}
# as_harness <label> <tag> <shell text>: both, in one step.
as_harness() {
    submit "$1" "$2" "$3"
    collect "$1" "$2"
}
# Records appended since line $1: decision, denial, action, and the evidence
# that names the door (via=, gate_mode=, refused=).
trail_since() {
    tail -n +"$(($1 + 1))" "$audit" | python3 -c '
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    ev = " ".join(e for e in r["evidence"] if e.startswith(("via=", "gate_mode=", "refused=")))
    print(r["decision"], r.get("denial") or "-", r.get("action") or "-", ev)
'
}
trail_len() { wc -l <"$audit"; }
# The via of every spool entry, one per line.
spool_vias() {
    for entry in /run/xudo/req/*; do
        [ -e "$entry" ] || continue
        python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("via"))' "$entry"
    done
}
has_root_line() { printf '%s\n' "$1" | grep -qx root; }
# show <case>: everything a failed case needs to be read.
show() {
    echo "--- $1: rc=$hrc" >&2
    printf '%s\n' "$hout" >&2
    trail_since "$mark" >&2 || true
    ls -la /run/xudo/req >&2 || true
}
run_whoami='/usr/bin/xudo exec -- '"$gate_exe"' -un'

# (9) The default install: a granted harness, and no sudoers line names the
# -nopass file. sudo -n refuses before the gate, and xudo says why.
mark=$(trail_len)
as_harness lane default "$run_whoami"
case_name=the_default_install_refuses_nopass_with_a_password_required
if [ "$hrc" = 1 ] && ! has_root_line "$hout" &&
    ! grep -rqs xudo-gate-nopass /etc/sudoers /etc/sudoers.d &&
    printf '%s\n' "$hout" | grep -q 'passwordless agent path is not installed' &&
    [ "$(spool_vias)" = harness ] &&
    ! trail_since "$mark" | grep -q 'gate_mode='; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi
rm -f /run/xudo/req/*

# The lane-only line: the managed snippet's agent rule, word for word, in a
# file of its own. Written only now: enrol refuses an account a hand-written
# line names, which is the point of H2d.
cat >"$lane_sudoers" <<EOF
# LANE ONLY: ci/systemd/grant.sh writes this in a throwaway container and removes it.
Cmnd_Alias XUDO_NOPASS = $nopass ""
Defaults!XUDO_NOPASS env_reset, !setenv, secure_path="/usr/sbin:/usr/bin:/sbin:/bin", timestamp_timeout=0, use_pty, !visiblepw
%xudo-agent ALL=(root) NOPASSWD: XUDO_NOPASS
EOF
chmod 0440 "$lane_sudoers"
if visudo -cf "$lane_sudoers" >/var/tmp/g1f-visudo.out 2>&1; then
    good "g1f: the lane-only line parses"
else
    bad "g1f: the lane-only line parses"
    cat /var/tmp/g1f-visudo.out >&2
fi

# (1) The grant: the command runs as root, with no password, and the gate's
# record says it came through the passwordless door for a harness.
mark=$(trail_len)
as_harness lane grant "$run_whoami"
case_name=a_granted_command_runs_as_root_through_a_live_harness_scope
trail=$(trail_since "$mark")
if [ "$hrc" = 0 ] && has_root_line "$hout" &&
    printf '%s\n' "$trail" | grep -q '^allowed - g1f.whoami .*via=harness' &&
    printf '%s\n' "$trail" | grep -q '^allowed - g1f.whoami .*gate_mode=Nopass via=harness' &&
    [ -z "$(spool_vias)" ]; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi

# (7) A granted remove-path, run as root: the account's own files under the
# tree go, a symlink is removed and never followed, and nothing the account
# does not own, and nothing outside the tree, is touched. The tree root is
# root's, so the account could not unlink `cache` itself.
rm -rf "$tree" "$outside"
install -d -m 0755 "$tree"
install -d -m 0755 -o xudograntee -g xudograntee "$tree/cache" "$tree/cache/obj" "$tree/sibling"
for f in cache/a.o cache/obj/b.o sibling/keep.o; do
    printf 'build\n' >"$tree/$f"
    chown xudograntee:xudograntee "$tree/$f"
done
printf 'secret\n' >"$outside"
chown xudograntee:xudograntee "$outside"
ln -s "$outside" "$tree/cache/link"
chown -h xudograntee:xudograntee "$tree/cache/link"
mark=$(trail_len)
as_harness lane remove "/usr/bin/xudo op remove-path $tree/cache"
case_name=granted_remove_path_runs_as_root_through_a_live_harness_scope
trail=$(trail_since "$mark")
if [ "$hrc" = 0 ] && [ ! -e "$tree/cache" ] && [ ! -L "$tree/cache/link" ] &&
    [ "$(cat "$outside")" = secret ] && [ -f "$tree/sibling/keep.o" ] && [ -d "$tree" ] &&
    printf '%s\n' "$trail" | grep -q '^allowed - g1f.clean .*via=harness'; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
    find "$tree" "$outside" -printf '%u %p\n' >&2 || true
fi
# The same rule never removes what another account owns: xudotest's file in
# the account's directory stays, and so does the directory that holds it.
install -d -m 0755 -o xudograntee -g xudograntee "$tree/mixed"
printf 'mine\n' >"$tree/mixed/mine.o"
chown xudograntee:xudograntee "$tree/mixed/mine.o"
printf 'theirs\n' >"$tree/mixed/theirs.o"
chown xudotest:xudotest "$tree/mixed/theirs.o"
printf 'roots\n' >"$tree/mixed/roots.o"
mark=$(trail_len)
as_harness lane mixed "/usr/bin/xudo op remove-path $tree/mixed"
case_name=a_granted_remove_path_leaves_what_the_account_does_not_own
if [ "$hrc" = 0 ] && [ ! -e "$tree/mixed/mine.o" ] &&
    [ "$(cat "$tree/mixed/theirs.o" 2>/dev/null)" = theirs ] &&
    [ "$(cat "$tree/mixed/roots.o" 2>/dev/null)" = roots ] &&
    trail_since "$mark" | grep -q '^allowed - g1f.clean .*via=harness'; then
    good "$case_name (rc=$hrc)"
else
    bad "$case_name"
    show "$case_name"
    find "$tree" -printf '%u %p\n' >&2 || true
fi
rm -rf "$tree" "$outside"

# (4) A command no rule allows is denied, and nothing is minted.
mark=$(trail_len)
as_harness lane unruled '/usr/bin/xudo exec -- '"$gate_exe"' -G'
case_name=a_command_no_rule_allows_is_denied_for_a_harness
if [ "$hrc" = 17 ] && ! printf '%s\n' "$hout" | grep -Eq '^[0-9 ]+$' &&
    [ -z "$(spool_vias)" ] && ! trail_since "$mark" | grep -q 'gate_mode='; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi

# (5) An enrolled harness the rule does not list: harness_not_granted, no entry.
mark=$(trail_len)
as_harness other unlisted "$run_whoami"
case_name=an_unlisted_harness_is_refused_and_nothing_is_minted
if [ "$hrc" = 17 ] && ! has_root_line "$hout" &&
    printf '%s\n' "$hout" | grep -q '^xudo: not granted (action g1f.whoami)' &&
    trail_since "$mark" | grep -q 'refused=harness_not_granted' &&
    [ -z "$(spool_vias)" ] && ! trail_since "$mark" | grep -q 'gate_mode='; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi

# (10) The broker's root-held queue, under the shipped unit: an ask-human
# rule queues the harness's request (the unit's RestrictSUIDSGID= answers the
# queue's openat2 with ENOSYS, which once refused every entry), its reviewer
# lists it with ido, and claims and runs it with the password.
root_held() {
    su -s /bin/sh -c 'ido list --json' xudotest 2>/dev/null | python3 -c '
import json, sys
for entry in json.load(sys.stdin)["root_held"]:
    print(entry["id"], entry["state"], entry["harness"], " ".join(entry["argv"]))
'
}
mark=$(trail_len)
as_harness lane ask '/usr/bin/xudo exec -- '"$gate_exe"' -g'
queued=$(find /var/lib/xudo/queue -maxdepth 1 -type f -name '*.json' | wc -l)
held=$(root_held || true)
qid=$(printf '%s\n' "$held" |
    awk -v exe="$gate_exe" '$2 == "pending" && $3 == "lane" && $4 == exe && $5 == "-g" && NF == 5 { print $1 }')
case_name=an_ask_human_request_is_queued_under_the_shipped_unit
if [ "$hrc" != 0 ] && ! printf '%s\n' "$hout" | grep -qx 0 &&
    printf '%s\n' "$hout" | grep -q 'root-held queue' && [ "$queued" -eq 1 ] &&
    ! trail_since "$mark" | grep -q 'gate_mode='; then
    good "$case_name"
else
    bad "$case_name (queued=$queued)"
    show "$case_name"
    journalctl -u 'xudod@*' --no-pager -n 20 >&2 || true
fi
case_name=the_reviewer_lists_the_queued_entry
if printf '%s\n' "$qid" | grep -Eqx '[0-9a-f]{64}'; then
    good "$case_name"
else
    bad "$case_name"
    printf '%s\n' "$held" >&2
fi
set +e
XUDO_G1F_ID=$qid expect -c '
set timeout 60
spawn su --pty -s /bin/sh -c "/usr/bin/xudo exec --queued $env(XUDO_G1F_ID)" xudotest
expect {
    "press enter: " { send "run\r"; exp_continue }
    -nocase "password" { send "pw\r"; exp_continue }
    timeout { exit 124 }
    eof
}
catch wait result
exit [lindex $result 3]
' >/var/tmp/g1f-claim.raw 2>&1
hrc=$?
set -e
hout=$(tr -d '\r' </var/tmp/g1f-claim.raw |
    sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\x1b\][^\x1b]*\x1b\\//g')
case_name=the_reviewer_claims_and_runs_the_queued_entry_with_the_password
if [ "$hrc" = 0 ] && printf '%s\n' "$hout" | grep -qx 0 &&
    trail_since "$mark" | grep -q '^allowed - g1f.ask .*gate_mode=Auth via=auth' &&
    ! root_held | grep -q "^$qid pending"; then
    good "$case_name"
else
    bad "$case_name (rc=$hrc)"
    show "$case_name"
    root_held >&2 || true
fi
rm -f /run/xudo/req/*

# A reviewer's own thaw lifts their marker and leaves a harness's freeze,
# which only root lifts.
printf '{"reason":"g1f lane","uid":0,"time":0}' >/var/lib/xudo/frozen-h-lane
reviewer_frozen=/var/lib/xudo/frozen-$(id -u xudotest)
set +e
su -s /bin/sh -c '/usr/bin/xudo freeze --reason "g1f reviewer"' xudotest >/var/tmp/g1f-thaw.out 2>&1
su -s /bin/sh -c '/usr/bin/xudo thaw' xudotest >>/var/tmp/g1f-thaw.out 2>&1
rc=$?
set -e
case_name=a_reviewers_thaw_leaves_a_harness_freeze_in_place
if [ "$rc" -eq 0 ] && [ ! -e "$reviewer_frozen" ] && [ -f /var/lib/xudo/frozen-h-lane ]; then
    good "$case_name"
else
    bad "$case_name (rc=$rc, harness: $([ -f /var/lib/xudo/frozen-h-lane ] && echo present || echo gone))"
    cat /var/tmp/g1f-thaw.out >&2
fi
rm -f /var/lib/xudo/frozen-h-lane "$reviewer_frozen"

# (2) A process that left the scope is not the harness: the broker mints a
# password entry, and sudo asks a password nobody here can type. First a
# process of the unit that root moves out of xudo.slice; then a login as the
# account (what ssh would give it), on a pty, with a wrong password typed.
mkdir -p /sys/fs/cgroup/xudo-g1f-leaver
mark=$(trail_len)
submit lane leaver 'echo $$ >/var/lib/xudo-g1f/lane/leaver.pid
i=0
while [ ! -e /var/lib/xudo-g1f/lane/leaver.go ] && [ "$i" -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
cat /proc/self/cgroup
'"$run_whoami"
i=0
while [ ! -s /var/lib/xudo-g1f/lane/leaver.pid ] && [ "$i" -lt 100 ]; do
    sleep 0.1
    i=$((i + 1))
done
leaver=$(cat /var/lib/xudo-g1f/lane/leaver.pid 2>/dev/null || echo none)
moved=no
if echo "$leaver" >/sys/fs/cgroup/xudo-g1f-leaver/cgroup.procs 2>/var/tmp/g1f-move.err; then
    moved=yes
fi
touch /var/lib/xudo-g1f/lane/leaver.go
collect lane leaver
case_name=a_process_moved_out_of_its_scope_is_not_the_harness
if [ "$moved" = yes ] && printf '%s\n' "$hout" | grep -q '^0::/xudo-g1f-leaver$' &&
    [ "$hrc" != 0 ] && ! has_root_line "$hout" && [ "$(spool_vias)" = auth ] &&
    ! trail_since "$mark" | grep -q 'via=harness'; then
    good "$case_name"
else
    bad "$case_name (moved=$moved pid=$leaver)"
    cat /var/tmp/g1f-move.err >&2 || true
    show "$case_name"
fi
rm -f /run/xudo/req/*
rmdir /sys/fs/cgroup/xudo-g1f-leaver 2>/dev/null || true

mark=$(trail_len)
set +e
XUDO_G1F_RUN=$run_whoami expect -c '
set timeout 30
set prompts 0
spawn su --pty -s /bin/sh -c $env(XUDO_G1F_RUN) xudograntee
expect {
    -nocase "password" { incr prompts; send "wrong\r"; exp_continue }
    timeout { exit 124 }
    eof
}
catch wait result
puts "PROMPTS=$prompts"
exit [lindex $result 3]
' >/var/tmp/g1f-login.raw 2>&1
hrc=$?
set -e
# Without CR and the session markers systemd 259 writes onto the pty.
hout=$(tr -d '\r' </var/tmp/g1f-login.raw |
    sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\x1b\][^\x1b]*\x1b\\//g')
case_name=a_login_as_the_agent_account_is_asked_the_password
if [ "$hrc" != 0 ] && ! has_root_line "$hout" &&
    printf '%s\n' "$hout" | grep -Eq '^PROMPTS=[1-9]' &&
    [ "$(spool_vias)" = auth ] && ! trail_since "$mark" | grep -q 'via=harness'; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi
rm -f /run/xudo/req/*

# Between mint and gate: sudo's PAM stack runs `between`, which runs what the
# case armed in $g1f/once, as root, exactly once.
cp -a /etc/pam.d/sudo /var/tmp/g1f-pam-sudo
{
    echo 'account optional pam_exec.so seteuid quiet /usr/local/lib/xudo-g1f/between'
    echo 'session optional pam_exec.so seteuid quiet /usr/local/lib/xudo-g1f/between'
    cat /var/tmp/g1f-pam-sudo
} >/etc/pam.d/sudo
# arm <shell text>: what runs between the next mint and its gate.
arm() {
    rm -f "$g1f/ran" "$g1f/ran.out"
    printf '%s\n' "$1" >"$g1f/once"
}

# (8) Frozen after the mint: the entry is the harness's own and still refused.
mark=$(trail_len)
arm 'printf "{\"reason\":\"g1f lane\",\"uid\":0,\"time\":0}" >/var/lib/xudo/frozen-h-lane'
as_harness lane frozen "$run_whoami"
case_name=a_frozen_harness_is_refused_with_a_minted_entry
if [ -e "$g1f/ran" ] && [ -e /var/lib/xudo/frozen-h-lane ] &&
    [ "$hrc" != 0 ] && ! has_root_line "$hout" && printf '%s\n' "$hout" | grep -q frozen &&
    [ "$(spool_vias)" = harness ] && ! trail_since "$mark" | grep -q '^allowed .*gate_mode='; then
    good "$case_name"
else
    bad "$case_name (hook ran: $([ -e "$g1f/ran" ] && echo yes || echo no))"
    show "$case_name"
    cat "$g1f/ran.out" >&2 || true
fi
rm -f /var/lib/xudo/frozen-h-lane /run/xudo/req/* "$g1f/once"

# (3) The registry file removed after the mint: the minted entry is refused,
# and the very next request from the same unit is a human's.
mark=$(trail_len)
arm 'mv /etc/xudo/harnesses.d/lane.toml /var/tmp/g1f-lane.toml'
as_harness lane unregistered "$run_whoami"
case_name=a_registry_file_removed_after_the_mint_refuses_the_entry
if [ -e "$g1f/ran" ] && [ ! -e /etc/xudo/harnesses.d/lane.toml ] &&
    [ "$hrc" != 0 ] && ! has_root_line "$hout" &&
    printf '%s\n' "$hout" | grep -q request_stale_generation &&
    [ "$(spool_vias)" = harness ] && ! trail_since "$mark" | grep -q '^allowed .*gate_mode='; then
    good "$case_name"
else
    bad "$case_name (hook ran: $([ -e "$g1f/ran" ] && echo yes || echo no))"
    show "$case_name"
    cat "$g1f/ran.out" >&2 || true
fi
rm -f /run/xudo/req/* "$g1f/once"
mark=$(trail_len)
as_harness lane human "$run_whoami"
case_name=a_removed_harness_is_human_at_once
trail=$(trail_since "$mark")
if [ "$hrc" != 0 ] && ! has_root_line "$hout" && [ "$(spool_vias)" = auth ] &&
    printf '%s\n' "$trail" | grep -q 'via=auth' &&
    ! printf '%s\n' "$trail" | grep -q 'via=harness'; then
    good "$case_name (rc=$hrc)"
else
    bad "$case_name"
    show "$case_name"
fi
rm -f /run/xudo/req/*
# The same bytes back: the grant returns, so the refusals above were the registry's.
if [ -e /var/tmp/g1f-lane.toml ]; then
    mv /var/tmp/g1f-lane.toml /etc/xudo/harnesses.d/lane.toml
fi
as_harness lane restored "$run_whoami"
case_name=the_restored_registry_file_grants_again
if [ "$hrc" = 0 ] && has_root_line "$hout"; then
    good "$case_name"
else
    bad "$case_name"
    show "$case_name"
fi
cp -a /var/tmp/g1f-pam-sudo /etc/pam.d/sudo
rm -f "$g1f/once" /var/tmp/g1f-pam-sudo

# E7's attack rows, with the lane-only line still in place and before the
# flood below fills the account's uid-only ledger.
. /harness/attack.sh

# (6) The ceiling under load: 200 calls of the passwordless door with nothing
# minted. The trail grows by at most the ceiling (60 in any minute) plus one
# coalesced record a minute, the chain stays intact, and a human's password
# run still works afterwards. Each call prints its exit status and the gate's
# refusal code. The bound scales with the minutes the flood took, so a slow
# runner whose calls span more than one window does not fail the row.
mark=$(trail_len)
started=$(date +%s)
as_harness lane flood 'i=0
while [ "$i" -lt 200 ]; do
    out=$(/usr/bin/sudo -n '"$nopass"' 2>&1)
    echo "$? $(printf "%s\n" "$out" | grep -o "gate_[a-z_]*" | head -n 1)"
    i=$((i + 1))
done'
added=$(($(trail_len) - mark))
minutes=$((($(date +%s) - started) / 60 + 1))
record_limit=$((63 * minutes))
throttle_floor=$((200 - 70 * minutes))
[ "$throttle_floor" -gt 0 ] || throttle_floor=1
calls=$(printf '%s\n' "$hout" | grep -c . || true)
throttled=$(printf '%s\n' "$hout" | grep -cx '19 gate_rate_ceiling' || true)
unentered=$(printf '%s\n' "$hout" | grep -cx '19 gate_no_pending_request' || true)
case_name=two_hundred_nopass_refusals_leave_a_bounded_trail
if [ "$calls" -eq 200 ] && [ "$((throttled + unentered))" -eq 200 ] &&
    [ "$throttled" -ge "$throttle_floor" ] && [ "$added" -le "$record_limit" ] &&
    xudo audit --log "$audit" 2>/dev/null | grep -q 'chain intact'; then
    good "$case_name (records=$added throttled=$throttled minutes=$minutes)"
else
    bad "$case_name (calls=$calls records=$added throttled=$throttled minutes=$minutes)"
    printf '%s\n' "$hout" | sort | uniq -c >&2
fi
rc=$(pty pw "$gate_exe" -u)
case_name=the_human_password_path_runs_after_an_agent_flood
if [ "$rc" -eq 0 ] && grep -qi password /var/tmp/case.out && grep -qx 0 /var/tmp/case.out; then
    good "$case_name"
else
    bad "$case_name (rc=$rc)"
    cat /var/tmp/case.out >&2
fi

# The lane-only line goes, and the negative control proves it is gone: the
# same door is refused by sudo itself, before any gate runs.
rm -f "$lane_sudoers"
as_harness other gone "/usr/bin/sudo -n $nopass"
case_name=the_lane_only_nopasswd_line_is_gone_after_the_row
if [ ! -e "$lane_sudoers" ] && ! grep -rqs xudo-gate-nopass /etc/sudoers /etc/sudoers.d &&
    [ "$hrc" = 1 ] && ! printf '%s\n' "$hout" | grep -q 'gate_'; then
    good "$case_name"
else
    bad "$case_name (rc=$hrc)"
    printf '%s\n' "$hout" >&2
fi

for label in lane other; do
    /usr/bin/xudo agent remove "$label" >/var/tmp/g1f-remove.log 2>&1 ||
        bad "g1f: xudo agent remove $label: $(cat /var/tmp/g1f-remove.log)"
done
rm -f "$grant_rules" /run/xudo/req/*
rm -rf /var/lib/xudo-g1f /usr/local/lib/xudo-g1f "$g1f"
