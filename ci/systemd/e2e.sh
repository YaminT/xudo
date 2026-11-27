# Sourced by row.sh last, under real systemd, after the package was removed
# (E9): the operator's whole journey, with the real installer and no
# lane-only sudoers line. Install the package (its postinst runs `xudo
# install`, the human path only), enrol a service harness with `sudo xudo
# agent enrol`, install a reviewed rule pack with `sudo xudo rules add
# --reviewed`, see the agent path off, turn it on with `sudo xudo install
# --agent-path`, then allow, remove-path, deny, ask-human through `ido`,
# freeze, the human path, `sudo xudo install --uninstall`, the pack's and the
# harness's removal, and a host with no xudo line, registry entry or pack
# left. Every root step is a human's: e2eadmin, in the image's own `%sudo`
# rule, typing the password on a pty. Uses row.sh's good, bad and gate_exe.
#
# Ubuntu 26.04's sudo is sudo-rs (asserted below), so the three images cover
# sudo and sudo-rs.

# Never outside the throwaway container: this purges the package, deletes
# accounts and turns the passwordless agent path on.
systemd-detect-virt --container -q || {
    bad "e2e: not inside a container; refusing to run the journey"
    return 1
}

e2e=/usr/local/lib/xudo-e2e
state=/var/lib/xudo-e2e
box=$state/box
tree=$state/tree
outside=$state/outside
packs=$state/packs
audit=/var/lib/xudo/audit.jsonl
dest=/etc/sudoers.d/xudo
installed=/etc/xudo/rules.d/pack-e2e-ops.toml
registry=/etc/xudo/harnesses.d/e2e.toml
env_file=/etc/xudo/agents/e2e.env
unit=xudo-agent@e2e.service
admin=e2eadmin
reviewer=e2ereviewer
agent=e2eagent

# If the journey aborts: stop its harness and drop its files. The container
# is thrown away after the row, so nothing else needs undoing.
e2e_cleanup() {
    systemctl stop "$unit" >/dev/null 2>&1 || true
    rm -rf "$e2e" "$state"
}
trap 'g1f_cleanup; e2e_cleanup' EXIT

# The image's sudo: sudo-rs on Ubuntu 26.04, sudo everywhere else.
sudo_line=$(sudo --version 2>/dev/null | head -n 1)
case $(. /etc/os-release && echo "$ID:$VERSION_ID") in
ubuntu:26.04) sudo_kind=sudo-rs want_sudo='sudo-rs ' ;;
*) sudo_kind=sudo want_sudo='Sudo version ' ;;
esac
case $sudo_line in
"$want_sudo"*) good "e2e_the_image_runs_$sudo_kind ($sudo_line)" ;;
*) bad "e2e_the_image_runs_$sudo_kind (got: $sudo_line)" ;;
esac
# sudo_refused <user>: sudo -n refused <user>'s call of the passwordless door
# in sudo's own words. sudo says it wants a password; sudo-rs, whose rules
# name nothing for the door, says no rule allows it.
sudo_refused() {
    case $sudo_kind in
    sudo-rs) want="sudo: I'm sorry $1. I'm afraid I can't do that" ;;
    *) want='sudo: a password is required' ;;
    esac
    printf '%s\n' "$hout" | grep -Fqx "$want"
}
# /etc/pam.d/sudo as its package shipped it: no lane PAM hook, no backup of
# one, and the package's own checksum.
pam_pristine() {
    pam_pkg=$(dpkg-query -S /etc/pam.d/sudo | head -n 1 | cut -d: -f1)
    pam_md5=$(dpkg-query -W -f='${Conffiles}\n' "$pam_pkg" | awk '$1 == "/etc/pam.d/sudo" { print $2 }')
    ! grep -q pam_exec /etc/pam.d/sudo && [ ! -e /var/tmp/g1f-pam-sudo ] && [ -n "$pam_md5" ] &&
        [ "$(md5sum </etc/pam.d/sudo | cut -d' ' -f1)" = "$pam_md5" ]
}
wants=/etc/systemd/system/multi-user.target.wants/xudo-agent@e2e.service

# --- A clean host. The rows above removed the package but left `t` enrolled
# (its drop-in, its enablement, its account in the agent groups) and their
# configuration. Purge that, so the journey starts where an operator would.
for d in /etc/systemd/system/xudo-agent@*.service.d; do
    if [ -d "$d" ]; then rm -rf "$d"; fi
done
rm -f /etc/systemd/system/multi-user.target.wants/xudo-agent@*.service
systemctl daemon-reload
if ! apt-get purge -y xudo >/var/tmp/e2e-purge.log 2>&1; then
    cat /var/tmp/e2e-purge.log >&2
    bad "e2e: purge the package left by the rows"
fi
! id xudoagent >/dev/null 2>&1 || userdel xudoagent
members=$(getent group xudo-agent | cut -d: -f4)
if [ -z "$members" ] && [ ! -e /etc/xudo ] &&
    ! grep -rqs xudo /etc/sudoers /etc/sudoers.d && pam_pristine; then
    good "e2e: the host starts with no xudo line, configuration, agent or PAM hook"
else
    bad "e2e: the host starts with no xudo line, configuration, agent or PAM hook (xudo-agent: $members)"
    grep -rls xudo /etc/sudoers /etc/sudoers.d >&2 || true
    cat /etc/pam.d/sudo >&2 || true
fi
sudoers_now() {
    sha256sum /etc/sudoers
    find /etc/sudoers.d -mindepth 1 -printf '%f %U:%G %m\n' | sort
    find /etc/sudoers.d -type f -exec sha256sum {} + | sort
}
sudoers_before=$(sudoers_now)

# --- Helpers.
install -d -m 0755 "$e2e" "$state" "$packs"
# as.exp <user> <password> <command>: <command> as <user> on a pty, typing
# the password at each sudo prompt and `run` at xudo's queued-run prompt.
# Prints PROMPTS=<password prompts>; exits with the command's status.
cat >"$e2e/as.exp" <<'EOF'
set timeout 120
set prompts 0
spawn su --pty -s /bin/sh -c [lindex $argv 2] [lindex $argv 0]
expect {
    -nocase -re {password( for [^:\r\n]*)?: ?$} { incr prompts; send "[lindex $argv 1]\r"; exp_continue }
    "and press enter: " { send "run\r"; exp_continue }
    timeout { puts "PROMPTS=$prompts"; exit 124 }
    eof
}
puts "PROMPTS=$prompts"
catch wait result
exit [lindex $result 3]
EOF
# ido.exp <user> <password> <id>: the reviewer's `ido` picker on a pty. Waits
# for the root-held entry, presses enter, types `run` at the picker's prompt,
# then at `xudo exec --queued`'s, then the password at sudo's. The second's
# pause lets `su --pty` pass on the last bytes before it exits.
cat >"$e2e/ido.exp" <<'EOF'
set timeout 60
set stty_init "rows 50 columns 250"
set id [lindex $argv 2]
set prompts 0
spawn su --pty -s /bin/sh -c {/usr/bin/ido; rc=$?; sleep 1; exit $rc} [lindex $argv 0]
expect {
    "root $id" {}
    timeout { puts "STEP=list"; exit 124 }
    eof { puts "STEP=list"; exit 125 }
}
send "\r"
expect {
    "root-held $id" {}
    timeout { puts "STEP=confirm"; exit 124 }
    eof { puts "STEP=confirm"; exit 125 }
}
send "run\r"
expect {
    "and press enter: " { send "run\r"; exp_continue }
    -nocase -re {password( for [^:\r\n]*)?: ?$} { incr prompts; send "[lindex $argv 1]\r"; exp_continue }
    timeout { puts "STEP=run"; exit 124 }
    eof
}
puts "PROMPTS=$prompts"
catch wait result
exit [lindex $result 3]
EOF
chmod 0644 "$e2e/as.exp" "$e2e/ido.exp"
# The transcript without CR and terminal sequences.
clean() { tr -d '\r' | sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\x1b\][^\x1b]*\x1b\\//g'; }
# as_user <user> <command>: on a pty, with the password `pw`. Its standard
# output and status go to files; standard error stays on the terminal (a
# queued run needs one) and gets a second to drain before `su --pty` exits.
# Sets hout, hrc.
as_user() {
    printf '%s >%s; echo "$?" >%s; sleep 1\n' "$2" "$e2e/user.out" "$e2e/user.rc" >"$e2e/user"
    chmod 0644 "$e2e/user"
    for f in user.rc user.out; do
        install -m 0644 -o "$1" -g "$1" /dev/null "$e2e/$f"
    done
    set +e
    expect "$e2e/as.exp" "$1" pw "sh $e2e/user" </dev/null >/var/tmp/e2e-user.raw 2>&1
    set -e
    hout="$(clean </var/tmp/e2e-user.raw)
$(cat "$e2e/user.out")"
    hrc=$(cat "$e2e/user.rc")
}
# as_admin <command>: e2eadmin on a pty, typing the password, in a system
# unit of its own so root's ancestor walk ends at pid 1 and not at this
# script's `docker exec`. The command's output and status also go to files,
# because `su --pty` can drop the last bytes of its pty when it exits. The
# unit dies before `timeout` gives up, so a hung step writes no stale status
# into the next one.
as_admin() {
    printf '{ %s; echo "$?" >%s; } 2>&1 | tee %s\n' "$1" "$e2e/admin.rc" "$e2e/admin.out" >"$e2e/admin"
    chmod 0644 "$e2e/admin"
    for f in admin.rc admin.out; do
        install -m 0644 -o "$admin" -g "$admin" /dev/null "$e2e/$f"
    done
    set +e
    timeout 300 systemd-run --quiet --wait --pipe --collect --property=RuntimeMaxSec=290 \
        expect "$e2e/as.exp" "$admin" pw "sh $e2e/admin" </dev/null >/var/tmp/e2e-admin.raw 2>&1
    set -e
    hout="$(clean </var/tmp/e2e-admin.raw)
$(cat "$e2e/admin.out")"
    hrc=$(cat "$e2e/admin.rc")
}
# as_plain <user> <command>: no terminal. Sets hout, hrc.
as_plain() {
    set +e
    hout=$(su -s /bin/sh -c "$2" "$1" </dev/null 2>&1)
    hrc=$?
    set -e
}
asked_password() { printf '%s\n' "$hout" | grep -Eq '^PROMPTS=[1-9]'; }
# The harness: runs each request root leaves in its box, one at a time, as
# the unit's account and in the unit's cgroup.
cat >"$e2e/driver" <<EOF
#!/bin/sh
while :; do
    for req in $box/*.req; do
        [ -e "\$req" ] || continue
        tag=\${req%.req}
        sh "\$req" >"\$tag.out" 2>&1 </dev/null
        echo \$? >"\$tag.part"
        rm -f "\$req"
        mv "\$tag.part" "\$tag.rc"
    done
    sleep 0.1
done
EOF
chmod 0755 "$e2e/driver"
# as_harness <tag> <shell text>: the harness runs it. Sets hout, hrc.
as_harness() {
    rm -f "$box/$1".*
    printf '%s\n' "$2" >"$box/.$1"
    chmod 0644 "$box/.$1"
    mv "$box/.$1" "$box/$1.req"
    i=0
    while [ ! -e "$box/$1.rc" ] && [ "$i" -lt 600 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    hrc=$(cat "$box/$1.rc" 2>/dev/null || echo timeout)
    hout=$(cat "$box/$1.out" 2>/dev/null || true)
}
trail_len() { if [ -f "$audit" ]; then wc -l <"$audit"; else echo 0; fi; }
# Records since line $1: classification, decision, denial, action, and the
# evidence that names the door (and, for remove-path, what it removed).
trail() {
    [ -f "$audit" ] || return 0
    tail -n +"$(($1 + 1))" "$audit" | python3 -c '
import json, sys
for line in sys.stdin:
    r = json.loads(line)
    ev = " ".join(e for e in r["evidence"] if e.startswith(("op=", "via=", "gate_mode=", "refused=", "count=")))
    print(r["classification"], r["decision"], r.get("denial") or "-", r.get("action") or "-", ev)
'
}
spool_count() { find /run/xudo/req -mindepth 1 2>/dev/null | wc -l; }
# The `via` of every entry in the spool, one per line.
spool_vias() {
    for entry in /run/xudo/req/*; do
        [ -e "$entry" ] || continue
        python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("via"))' "$entry"
    done
}
# A line that is uid 0 and nothing else: `id --user` (or `-ru`) as root.
has_uid0() { printf '%s\n' "$hout" | grep -qx 0; }
# `xudo doctor`'s agent path, as root reads it.
doctor_agent_path() {
    timeout 60 /usr/bin/xudo doctor --json 2>/dev/null |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["agent_path"]["state"])' 2>/dev/null ||
        echo unreadable
}
show() {
    echo "--- $1: rc=$hrc" >&2
    printf '%s\n' "$hout" >&2
    trail "$mark" >&2 || true
    ls -la /run/xudo/req >&2 || true
}
# check <case> <condition...>: one row.
check() {
    case_name=$1
    shift
    if "$@"; then good "$case_name"; else bad "$case_name"; show "$case_name"; fi
}
token_of() { printf '%s\n' "$1" | sed -n 's/^  sudo xudo rules [a-z]*.* --reviewed \([0-9a-f]*\) .*/\1/p'; }
uid_cmd="/usr/bin/xudo exec -- $gate_exe --user"
clean_cmd="/usr/bin/xudo op remove-path $tree/cache"
# The agent path is off: the broker mints the harness's entry, sudo -n
# refuses the passwordless door in its own words, and the entry is still in
# the spool, the one entry there, unconsumed. Nothing runs and no gate starts.
agent_path_off() {
    [ "$hrc" = 1 ] && ! has_uid0 && sudo_refused "$agent" &&
        printf '%s\n' "$hout" | grep -q 'passwordless agent path is not installed' &&
        [ "$(spool_count)" = 1 ] && [ "$(spool_vias)" = harness ] &&
        trail "$mark" | grep -q '^enrolled-agent allowed - pack\.e2e\.[a-z]* via=harness$' &&
        ! trail "$mark" | grep -q 'gate_mode='
}

# --- 1. The package. Its postinst runs `xudo install`: the human path only.
if ! apt-get install -y /opt/xudo.deb >/var/tmp/e2e-install.log 2>&1; then
    cat /var/tmp/e2e-install.log >&2
    bad "e2e: apt install"
fi
if grep -q 'the functional probe passed' /var/tmp/e2e-install.log &&
    [ "$(stat -c '%a %U:%G' "$dest")" = '440 root:root' ] && grep -q 'PASSWD:' "$dest" &&
    ! grep -rqsE '^[^#]*(NOPASSWD|xudo-gate-nopass)' /etc/sudoers /etc/sudoers.d; then
    good "e2e_the_package_installs_the_human_path_only"
else
    bad "e2e_the_package_installs_the_human_path_only"
    cat /var/tmp/e2e-install.log "$dest" >&2 || true
fi
rules_installed=$(find /etc/xudo/rules.d -type f -printf '%f %U:%G %m\n' | sort)
# The people: an administrator in the image's own `%sudo ALL` rule, a
# reviewer in the xudo group, and the harness's account, which has no
# password and no rule.
grep -Eq '^%sudo[[:space:]]+ALL' /etc/sudoers || bad "e2e: the image's /etc/sudoers has no %sudo ALL rule"
id "$admin" >/dev/null 2>&1 || useradd --create-home --user-group --groups sudo "$admin"
id "$reviewer" >/dev/null 2>&1 || useradd --create-home --user-group --groups xudo "$reviewer"
id "$agent" >/dev/null 2>&1 || useradd --system --no-create-home "$agent"
printf '%s:pw\n%s:pw\n' "$admin" "$reviewer" | chpasswd

# --- 2. Enrol the harness, through sudo.
install -d -m 0700 -o "$agent" -g "$agent" "$box"
mark=$(trail_len)
as_admin "/usr/bin/sudo /usr/bin/xudo agent enrol e2e --account $agent --reviewer $reviewer -- /bin/sh $e2e/driver"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -e /run/xudo/sessions/svc-e2e ] && break
    sleep 1
done
groups=$(id -nG "$agent" | tr ' ' '\n' | grep -x 'xudo\|xudo-agent' | sort | tr '\n' ' ')
check e2e_the_operator_enrols_a_harness_through_sudo eval '
    [ "$hrc" = 0 ] && asked_password && [ -f "$registry" ] &&
    [ "$(systemctl is-active "$unit")" = active ] && [ -e /run/xudo/sessions/svc-e2e ] && [ -L "$wants" ] &&
    [ "$groups" = "xudo xudo-agent " ] && ! grep -rqsE "^[^#]*(NOPASSWD|xudo-gate-nopass)" /etc/sudoers /etc/sudoers.d'

# --- 3. The rule pack: `id --user` for the harness with no password, `id -ru`
# only after a human approves it, and remove-path under the tree for what
# the harness's account owns. Reviewed as the administrator, then installed
# with the token through sudo. Not `id -u`: the shipped probe rule accepts
# that for the password path, and the strictest accepting rule wins.
cat >"$packs/ops.toml" <<EOF
[pack]
name = "e2e-ops"
version = "1.0.0"
for = ["e2e"]

[[action]]
id = "pack.e2e.uid"
tier = "diag-read"
exe = "$gate_exe"
args = [{ name = "effective-uid", matcher = { literal = "--user" } }]
outcome = "allow"

[[action]]
id = "pack.e2e.ask"
tier = "diag-read"
exe = "$gate_exe"
args = [{ name = "real-uid", matcher = { literal = "-ru" } }]
outcome = "ask-human"

[[operation]]
id = "pack.e2e.clean"
op = "remove-path"
under = "$tree"
recursive = true
max-depth = 3
max-entries = 16
owners = ["$agent"]
outcome = "allow"

[[test]]
argv = ["$gate_exe", "--user"]
expect = "allow"
action = "pack.e2e.uid"

[[test]]
argv = ["$gate_exe", "--group"]
expect = "deny"
action = "pack.e2e.uid"
reason = "near miss: one operand off the allow test"

[[test]]
argv = ["$gate_exe", "-ru"]
expect = "allow"
action = "pack.e2e.ask"

[[test]]
argv = ["$gate_exe", "-rg"]
expect = "deny"
action = "pack.e2e.ask"
reason = "near miss: one operand off the allow test"
EOF
chmod 0644 "$packs/ops.toml"
as_plain "$admin" "/usr/bin/xudo rules add $packs/ops.toml"
review=$hout
token=$(token_of "$review")
check e2e_the_review_names_the_harness_gain_and_prints_a_token eval '
    [ "$hrc" = 0 ] && printf "%s\n" "$token" | grep -Eqx "[0-9a-f]{64}" &&
    printf "%s\n" "$review" | grep -q "^  e2e gains (no password): " && [ ! -e "$installed" ]'
as_admin "/usr/bin/sudo /usr/bin/xudo rules add --reviewed $token $packs/ops.toml"
check e2e_the_operator_installs_the_reviewed_pack_through_sudo eval '
    [ "$hrc" = 0 ] && asked_password && printf "%s\n" "$hout" | grep -qx "installed $installed" &&
    [ "$(stat -c "%U:%G %a" "$installed")" = "root:root 644" ]'

# The tree remove-path works on: root's, with the account's build output in
# it, a link to a file outside it, and a file of the reviewer's. The two
# directories are the account's but read-only, so only root's override of
# the permissions can unlink what is in them: the account cannot fake a
# removal by doing it itself.
rm -rf "$tree" "$outside"
install -d -m 0755 "$tree"
install -d -m 0755 -o "$agent" -g "$agent" "$tree/cache" "$tree/cache/obj"
for f in cache/a.o cache/obj/b.o; do
    printf 'build\n' >"$tree/$f"
    chown "$agent:$agent" "$tree/$f"
done
printf 'theirs\n' >"$tree/cache/theirs.o"
chown "$reviewer:$reviewer" "$tree/cache/theirs.o"
printf 'secret\n' >"$outside"
chown "$agent:$agent" "$outside"
ln -s "$outside" "$tree/cache/link"
chown -h "$agent:$agent" "$tree/cache/link"
chmod 0555 "$tree/cache/obj" "$tree/cache"
tree_intact() {
    [ -f "$tree/cache/a.o" ] && [ -f "$tree/cache/obj/b.o" ] && [ -L "$tree/cache/link" ] &&
        [ "$(cat "$outside")" = secret ]
}

# --- 4. Before --agent-path: the rule grants, the door is shut.
check e2e_doctor_says_the_agent_path_is_off eval '[ "$(doctor_agent_path)" = off ]'
mark=$(trail_len)
as_harness off-uid "$uid_cmd"
check e2e_before_the_agent_path_sudo_refuses_a_granted_command agent_path_off
rm -f /run/xudo/req/*
mark=$(trail_len)
as_harness off-clean "$clean_cmd"
check e2e_before_the_agent_path_sudo_refuses_a_granted_remove_path eval 'agent_path_off && tree_intact'
rm -f /run/xudo/req/*

# --- 5. The real installer turns the agent path on.
as_admin "/usr/bin/sudo /usr/bin/xudo install --agent-path"
check e2e_the_operator_turns_the_agent_path_on_through_sudo eval '
    [ "$hrc" = 0 ] && asked_password &&
    printf "%s\n" "$hout" | grep -q "the backend parsed its whole configuration" &&
    printf "%s\n" "$hout" | grep -q "verified: the backend lists the passwordless helper for root" &&
    printf "%s\n" "$hout" | grep -q "the passwordless helper refused a caller it cannot attest" &&
    [ "$(stat -c "%a %U:%G" "$dest")" = "440 root:root" ] &&
    [ "$(grep -c NOPASSWD "$dest")" = 1 ] &&
    grep -qx "%xudo-agent ALL=(root) NOPASSWD: XUDO_NOPASS" "$dest" &&
    [ "$(grep -rlsE "^[^#]*NOPASSWD" /etc/sudoers /etc/sudoers.d)" = "$dest" ] && visudo -c >/dev/null'
check e2e_doctor_says_the_agent_path_is_on eval '[ "$(doctor_agent_path)" = on ]'
# Run twice, it is the same file.
agent_path_file() { sha256sum "$dest" && stat -c '%a %U:%G' "$dest"; }
agent_path_before=$(agent_path_file)
as_admin "/usr/bin/sudo /usr/bin/xudo install --agent-path"
check e2e_a_second_agent_path_install_leaves_the_same_bytes eval '
    [ "$hrc" = 0 ] && asked_password && [ "$(agent_path_file)" = "$agent_path_before" ] &&
    [ "$(doctor_agent_path)" = on ]'

# --- 6. The grant runs as root with no password; the gate says which door.
mark=$(trail_len)
as_harness on-uid "$uid_cmd"
check e2e_the_harness_runs_its_granted_command_as_root_with_no_password eval '
    [ "$hrc" = 0 ] && has_uid0 &&
    trail "$mark" | grep -q "^enrolled-agent allowed - pack\.e2e\.uid via=harness$" &&
    trail "$mark" | grep -q "^enrolled-agent allowed - pack\.e2e\.uid gate_mode=Nopass via=harness$" &&
    [ "$(spool_count)" = 0 ]'
# The gate's two remove-path records (the intent before any unlink, the
# result after) carry no `gate_mode=`. They name the entry's door instead:
# the gate refuses a `via=harness` entry on any door but -nopass
# (`gate_mode_wrong_via`), so `via=harness` in the gate's own records is the
# passwordless door.
mark=$(trail_len)
as_harness on-clean "$clean_cmd"
check e2e_the_harness_removes_its_own_files_as_root_with_no_password eval '
    [ "$hrc" = 0 ] && [ ! -e "$tree/cache/a.o" ] && [ ! -e "$tree/cache/obj" ] &&
    [ ! -L "$tree/cache/link" ] && [ "$(cat "$outside")" = secret ] &&
    [ "$(cat "$tree/cache/theirs.o")" = theirs ] && [ -d "$tree" ] &&
    [ "$(stat -c "%U %a" "$tree/cache")" = "$agent 555" ] &&
    trail "$mark" | grep -q "^enrolled-agent allowed - pack\.e2e\.clean op=remove-path-intent via=harness$" &&
    trail "$mark" | grep -q "^enrolled-agent allowed - pack\.e2e\.clean op=remove-path via=harness count=4$" &&
    [ "$(spool_count)" = 0 ]'

# --- 7. A command no rule allows: denied at the broker, nothing minted.
mark=$(trail_len)
as_harness deny "/usr/bin/xudo exec -- $gate_exe -G"
check e2e_a_command_no_rule_allows_is_denied_for_the_harness eval '
    [ "$hrc" = 17 ] && ! printf "%s\n" "$hout" | grep -Eq "^[0-9 ]+$" &&
    trail "$mark" | grep -q "^enrolled-agent denied argv_rejected " &&
    ! trail "$mark" | grep -q "gate_mode=" && [ "$(spool_count)" = 0 ]'

# --- 8. Ask-human: queued, listed to the reviewer, approved in `ido` with the
# reviewer's password, run once as root.
root_held() {
    su -s /bin/sh -c 'ido list --json' "$reviewer" 2>/dev/null | python3 -c '
import json, sys
for entry in json.load(sys.stdin)["root_held"]:
    print(entry["id"], entry["state"], entry["harness"], " ".join(entry["argv"]))
'
}
mark=$(trail_len)
as_harness ask "/usr/bin/xudo exec -- $gate_exe -ru"
queued=$(find /var/lib/xudo/queue -maxdepth 1 -type f -name '*.json' | wc -l)
qid=$(root_held | awk -v exe="$gate_exe" '$2 == "pending" && $3 == "e2e" && $4 == exe && $5 == "-ru" && NF == 5 { print $1 }')
check e2e_an_ask_human_request_waits_in_the_root_held_queue eval '
    [ "$hrc" = 17 ] && ! has_uid0 &&
    printf "%s\n" "$hout" | grep -q "root-held queue" && [ "$queued" = 1 ] &&
    printf "%s\n" "$qid" | grep -Eqx "[0-9a-f]{64}" &&
    trail "$mark" | grep -q "^enrolled-agent denied ask_human pack\.e2e\.ask " &&
    ! trail "$mark" | grep -q "gate_mode="'
mark=$(trail_len)
set +e
expect "$e2e/ido.exp" "$reviewer" pw "$qid" </dev/null >/var/tmp/e2e-ido.raw 2>&1
hrc=$?
set -e
hout=$(clean </var/tmp/e2e-ido.raw)
check e2e_the_reviewer_approves_it_in_ido_and_it_runs_as_root eval '
    [ "$hrc" = 0 ] && asked_password && has_uid0 &&
    printf "%s\n" "$hout" | grep -q "^ido: xudo exec --queued $qid exited 0" &&
    [ "$(trail "$mark" | grep -c " allowed - pack\.e2e\.ask .*gate_mode=Auth via=auth$")" = 1 ] &&
    ! root_held | grep -q "^$qid pending"'
mark=$(trail_len)
as_user "$reviewer" "/usr/bin/xudo exec --queued $qid"
check e2e_an_approved_entry_runs_once eval '
    [ "$hrc" = 19 ] && ! has_uid0 && ! asked_password &&
    printf "%s\n" "$hout" | grep -Fqx "xudo: the broker refused (RequestUnknown): the request is unknown or this question is not implemented yet" &&
    ! trail "$mark" | grep -q " allowed .*gate_mode="'
rm -f /run/xudo/req/*

# --- 9. Freeze: the reviewer's brake stops the harness, which cannot lift
# it; the reviewer's thaw lifts only their own marker; root's thaw, through
# sudo, lifts it.
harness_marker=/var/lib/xudo/frozen-h-e2e
reviewer_marker=/var/lib/xudo/frozen-$(id -u "$reviewer")
as_plain "$reviewer" "/usr/bin/xudo freeze --reason 'e2e brake'"
check e2e_the_reviewer_freezes_the_harness eval '
    [ "$hrc" = 0 ] && [ -f "$harness_marker" ] && [ -f "$reviewer_marker" ]'
mark=$(trail_len)
as_harness frozen "$uid_cmd"
check e2e_a_frozen_harness_runs_nothing eval '
    [ "$hrc" = 17 ] && ! has_uid0 && printf "%s\n" "$hout" | grep -q frozen &&
    trail "$mark" | grep -q "^enrolled-agent denied frozen " &&
    ! trail "$mark" | grep -q "gate_mode=" && [ "$(spool_count)" = 0 ]'
# The broker's refusal of a thaw from a harness's account, as `xudo thaw`
# prints it.
thaw_refused='xudo: Refused { code: ChannelUntrusted, remediation: "the peer is not trusted for this broker channel", detail: Some("this account runs an agent harness: use `sudo xudo thaw`, which lifts ALL freezes (the global one and every user'"'"'s)") }'
as_harness self-thaw "/usr/bin/xudo thaw"
check e2e_the_harness_cannot_thaw_itself eval '
    [ "$hrc" = 17 ] && [ -f "$harness_marker" ] &&
    printf "%s\n" "$hout" | grep -Fqx "$thaw_refused"'
as_plain "$reviewer" "/usr/bin/xudo thaw"
check e2e_the_reviewers_thaw_leaves_the_harness_frozen eval '
    [ "$hrc" = 0 ] && [ ! -e "$reviewer_marker" ] && [ -f "$harness_marker" ]'
as_admin "/usr/bin/sudo /usr/bin/xudo thaw"
check e2e_root_thaws_through_sudo eval '[ "$hrc" = 0 ] && asked_password && [ ! -e "$harness_marker" ]'
mark=$(trail_len)
as_harness thawed "$uid_cmd"
check e2e_the_thawed_harness_runs_again eval '
    [ "$hrc" = 0 ] && has_uid0 &&
    trail "$mark" | grep -q "^enrolled-agent allowed - pack\.e2e\.uid gate_mode=Nopass via=harness$"'

# --- 10. The human path, beside the agent path: the reviewer's password.
mark=$(trail_len)
as_user "$reviewer" "/usr/bin/xudo exec -- $gate_exe -u"
check e2e_the_human_path_still_asks_the_password eval '
    [ "$hrc" = 0 ] && asked_password && has_uid0 &&
    trail "$mark" | grep -q "^human allowed - $probe_action .*gate_mode=Auth via=auth$" &&
    ! trail "$mark" | grep -q "via=harness"'
as_user "$reviewer" "/usr/bin/sudo -n /usr/libexec/xudo/xudo-gate-nopass"
check e2e_a_human_cannot_use_the_passwordless_door eval '
    [ "$hrc" = 1 ] && ! asked_password && sudo_refused "$reviewer" &&
    ! printf "%s\n" "$hout" | grep -q "xudo-gate:"'

# --- 11. Uninstall: the agent path and the human path go; enrol's groups stay.
as_admin "/usr/bin/sudo /usr/bin/xudo install --uninstall"
groups=$(id -nG "$agent" | tr ' ' '\n' | grep -x 'xudo\|xudo-agent' | sort | tr '\n' ' ')
check e2e_uninstall_removes_every_xudo_sudoers_line eval '
    [ "$hrc" = 0 ] && asked_password && [ ! -e "$dest" ] && [ ! -L "$dest" ] &&
    ! grep -rqs "xudo" /etc/sudoers /etc/sudoers.d && visudo -c >/dev/null &&
    [ "$groups" = "xudo xudo-agent " ]'
check e2e_doctor_says_the_agent_path_is_off_after_uninstall eval '[ "$(doctor_agent_path)" = off ]'
mark=$(trail_len)
as_harness gone "$uid_cmd"
check e2e_after_uninstall_sudo_refuses_the_harness_again agent_path_off
rm -f /run/xudo/req/*

# --- 12. The pack and the harness go, through sudo.
as_plain "$admin" "/usr/bin/xudo rules remove e2e-ops"
review=$hout
token=$(token_of "$review")
check e2e_the_removal_review_names_the_harness_loss eval '
    [ "$hrc" = 0 ] && [ -n "$token" ] && printf "%s\n" "$review" | grep -q "^  e2e loses (no password): "'
as_admin "/usr/bin/sudo /usr/bin/xudo rules remove --reviewed $token e2e-ops"
check e2e_the_operator_removes_the_pack_through_sudo eval '
    [ "$hrc" = 0 ] && asked_password && printf "%s\n" "$hout" | grep -qx "removed $installed" &&
    [ ! -e "$installed" ]'
as_admin "/usr/bin/sudo /usr/bin/xudo agent remove e2e"
check e2e_the_operator_removes_the_harness_through_sudo eval '
    [ "$hrc" = 0 ] && asked_password &&
    printf "%s\n" "$hout" | grep -qx "removed $agent from group xudo-agent" &&
    printf "%s\n" "$hout" | grep -qx "removed $agent from group xudo"'

# --- 13. The host as it was: no xudo sudoers line, no registry entry, no
# pack, no unit, no record, the account in no xudo group. The environment
# file stays on purpose (it may hold credentials).
groups=$(id -nG "$agent" | tr ' ' '\n' | grep -x 'xudo\|xudo-agent' || true)
case $(systemctl is-active "$unit" 2>&1 || true) in
active | activating) unit_state=running ;;
*) unit_state=stopped ;;
esac
check e2e_the_host_is_as_it_was_before_the_journey eval '
    [ "$(sudoers_now)" = "$sudoers_before" ] && ! grep -rqs xudo /etc/sudoers /etc/sudoers.d &&
    [ ! -e "$registry" ] && [ ! -e "$installed" ] &&
    [ "$(find /etc/xudo/rules.d -type f -printf "%f %U:%G %m\n" | sort)" = "$rules_installed" ] &&
    [ "$unit_state" = stopped ] && [ ! -e /run/xudo/sessions/svc-e2e ] &&
    [ ! -e /etc/systemd/system/xudo-agent@e2e.service.d ] && [ -z "$groups" ] &&
    [ ! -e "$wants" ] && [ ! -L "$wants" ] && pam_pristine &&
    [ ! -e /etc/sysctl.d/05-xudo-ptrace-scope.conf ] && [ -f "$env_file" ]'

if ! apt-get remove -y xudo >/var/tmp/e2e-remove.log 2>&1; then
    cat /var/tmp/e2e-remove.log >&2
    bad "e2e: apt remove after the journey"
fi
rm -f "$env_file"
userdel -r "$admin" >/dev/null 2>&1 || true
userdel -r "$reviewer" >/dev/null 2>&1 || true
userdel "$agent" >/dev/null 2>&1 || true
rm -rf "$e2e" "$state" "$outside"
