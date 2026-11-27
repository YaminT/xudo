#!/bin/sh
# One row of the install matrix, run inside that row's container as root.
#
#   sh /harness/row.sh <row> <setup command>
#
# Expects the static xudo binary at /usr/local/bin/xudo, this directory at
# /harness, and a writable /out. POSIX sh only: the Alpine row has busybox, the
# Ubuntu rows have dash. Every check that fails prints what it was checking and
# exits non-zero; there is no "warn".
set -eu
set -f

row=$1
setup=$2
xudo=/usr/local/bin/xudo
out=/out/$row
mkdir -p "$out"
export DEBIAN_FRONTEND=noninteractive

fail() {
    echo "row $row: FAIL: $*" >&2
    for f in "$out"/*.err; do
        [ -f "$f" ] && { echo "--- $f" >&2; cat "$f" >&2; }
    done
    exit 1
}

if ! sh -c "$setup" >"$out/setup.log" 2>&1; then
    cat "$out/setup.log" >&2
    fail "setup failed"
fi

# xudo must not consult its environment, but the harness still hands it a known
# one so that nothing here can come from it.
run_xudo() {
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$xudo" "$@"
}

# try <name> <args...>: runs xudo as root, keeping stdout, stderr, and the status.
try() {
    name=$1
    shift
    set +e
    run_xudo "$@" >"$out/$name.out" 2>"$out/$name.err"
    rc=$?
    set -e
}

# has <file> <text>: the file contains the text, literally.
has() { grep -qF -- "$2" "$1"; }

expect_rc() { [ "$rc" -eq "$1" ] || fail "$2: exit $rc, wanted $1"; }
expect_err() { has "$out/$1.err" "$2" || fail "$1: stderr lacks '$2'"; }
expect_out() { has "$out/$1.out" "$2" || fail "$1: stdout lacks '$2'"; }
expect_absent() { [ ! -e "$1" ] && [ ! -L "$1" ] || fail "$1 exists, and must not"; }
expect_meta() { [ "$(stat -c '%a %U:%G' "$1")" = "$2" ] || fail "$1 is $(stat -c '%a %U:%G' "$1"), wanted $2"; }
sum() { cksum <"$1"; }

# The install is unverified in this build, and must say so with a failing status:
# the functional probe needs a request minted through the broker (plan item C1).
expect_unverified() {
    expect_rc 19 "$1"
    expect_err "$1" "NOT VERIFIED"
    if has "$out/$1.out" "verified     "; then fail "$1: claimed to be verified"; fi
}

# 1. Anyone but root is refused before anything is touched.
as_nobody() {
    set +e
    su -s /bin/sh nobody -c "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin $xudo $*" \
        >"$out/nobody.out" 2>"$out/nobody.err"
    rc=$?
    set -e
}

refuses_non_root() {
    as_nobody install
    expect_rc 19 "non-root install"
    expect_err nobody "requires root"
    if getent group xudo >/dev/null; then fail "a non-root install created the group"; fi
}

# A doas that rejects any command line matching the pattern, and is otherwise
# the real one: how a backend that refuses the candidate is made to happen.
reject_doas() {
    mv /usr/bin/doas /usr/bin/doas.orig
    cat >/usr/bin/doas <<EOF
#!/bin/sh
# Stands in for a doas that reads /etc/doas.d: xudo finds that by the name in
# the executable, so the wrapper has to carry it as the real binary does.
case "\$*" in $1) echo "rejected by the test" >&2; exit 1 ;; esac
exec /usr/bin/doas.orig "\$@"
EOF
    chmod 755 /usr/bin/doas
}

restore_doas() { mv /usr/bin/doas.orig /usr/bin/doas; }

# An agent-path install that wrote its line and passed every check that could
# run: exit 0, the whole configuration parsed, the helper listed for root (the
# control) and not for nobody, and the functional probe either passed or said why it could not run.
expect_agent_ok() {
    expect_rc 0 "$1"
    expect_out "$1" "the backend parsed its whole configuration"
    expect_out "$1" "verified: the backend lists the passwordless helper for root"
    expect_out "$1" "verified: the backend does not list the passwordless helper for nobody"
    has "$out/$1.out" "could not verify: " || has "$out/$1.out" "verified     the functional probe passed" ||
        fail "$1: neither verified nor said what it could not verify"
}

# The opt-in agent path (E8), on a sudo or sudo-rs row after the install rows.
agent_path() {
    dest=/etc/sudoers.d/xudo
    helper=/usr/libexec/xudo/xudo-gate-nopass
    drop_in=/etc/sysctl.d/05-xudo-ptrace-scope.conf
    sudo_exe=$(command -v sudo || command -v sudo-rs)
    install -d -m 755 /usr/libexec/xudo
    expect_absent "$dest"
    # Yama is not namespaced: a container sees the host's value, and setting
    # it here would change the host. --agent-path refuses at 0 or unreadable,
    # so every row below needs the host at 1 or more.
    scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo none)
    case $scope in
    1 | 2 | 3) ;;
    *) fail "the host's kernel.yama.ptrace_scope is $scope: the agent-path rows need 1 or more; set it on the host (sudo sysctl -w kernel.yama.ptrace_scope=1)" ;;
    esac

    # 9. No helper on the machine: nothing to trust, so nothing is written,
    #    not even the group.
    try nohelper install --agent-path
    expect_rc 19 "agent path with no helper"
    expect_err nohelper "the passwordless helper cannot be trusted: $helper is missing"
    expect_absent "$dest"
    if getent group xudo-agent >/dev/null; then fail "a refused agent path created xudo-agent"; fi

    # 10. A helper that runs something instead of refusing: nothing is written.
    printf '#!/bin/sh
echo 0
' >"$helper"
    chmod 755 "$helper"
    try runs install --agent-path
    expect_rc 19 "agent path with a helper that does not refuse"
    expect_err runs "was not shown to refuse"
    expect_absent "$dest"

    # The real gate, as the package ships it: two copies, never a hardlink.
    install -m 755 /harness-bin/xudo-gate /usr/libexec/xudo/xudo-gate-auth
    install -m 755 /harness-bin/xudo-gate "$helper"

    # 10b. A helper someone else could replace: group-writable, or with a
    #      second name. Refused before anything is run or written.
    chmod 775 "$helper"
    try gwritable install --agent-path
    chmod 755 "$helper"
    expect_rc 19 "agent path with a group-writable helper"
    expect_err gwritable "cannot be trusted: $helper is writable by its group"
    ln "$helper" /usr/libexec/xudo/second-name
    try linked2 install --agent-path
    rm /usr/libexec/xudo/second-name
    expect_rc 19 "agent path with a hard-linked helper"
    expect_err linked2 "has 2 names"
    expect_absent "$dest"

    # 11. Another line for the agent group, or the helper given to %xudo:
    #     refused and named, in either include order.
    #     So is an alias named like xudo's, defined first (visudo -cf passes
    #     xudo's file alone), and a wildcard Defaults line reaching the helper.
    for line in '%xudo-agent ALL=(ALL) NOPASSWD: ALL' \
        '%xudo ALL=(root) NOPASSWD: /usr/libexec/xudo/xudo-gate-nopass' \
        'Cmnd_Alias XUDO_NOPASS = ALL' \
        'Defaults!/usr/libexec/*/* env_keep+=LD_PRELOAD'; do
        # Not `name`: try() sets that.
        for ops_file in 00-ops zz-ops; do
            printf '%s\n' "$line" >/etc/sudoers.d/$ops_file
            chmod 440 /etc/sudoers.d/$ops_file
            try ops install --agent-path
            expect_rc 19 "agent path beside an operator's line in $ops_file"
            expect_err ops "/etc/sudoers.d/$ops_file line 1"
            expect_absent "$dest"
            rm -f /etc/sudoers.d/$ops_file
        done
    done

    # 12. A symlinked sudoers.d is not written through.
    mv /etc/sudoers.d /etc/sudoers.d.real
    ln -s /etc/sudoers.d.real /etc/sudoers.d
    try linked install --agent-path
    rm /etc/sudoers.d
    mv /etc/sudoers.d.real /etc/sudoers.d
    expect_rc 19 "agent path through a symlinked sudoers.d"
    expect_absent "$dest"

    # 12b. A broken file xudo's checks do not name: the candidate parses
    #      alone, the whole configuration does not, and the rename is undone.
    printf 'this is not sudoers\n' >/etc/sudoers.d/zz-broken
    chmod 440 /etc/sudoers.d/zz-broken
    try whole install --agent-path
    rm -f /etc/sudoers.d/zz-broken
    expect_rc 19 "agent path beside a broken sudoers file"
    expect_err whole "was restored to what it was before"
    expect_absent "$dest"

    # 13. The agent path itself.
    try agent install --agent-path
    expect_agent_ok agent
    expect_out agent "the passwordless helper refused a caller it cannot attest"
    expect_meta "$dest" "440 root:root"
    [ "$(grep -c NOPASSWD "$dest")" -eq 1 ] || fail "not exactly one NOPASSWD line"
    grep -qx '%xudo-agent ALL=(root) NOPASSWD: XUDO_NOPASS' "$dest" || fail "the passwordless line is not xudo's"
    grep -qx 'Cmnd_Alias XUDO_NOPASS = /usr/libexec/xudo/xudo-gate-nopass ""' "$dest" || fail "the helper alias is not exactly the helper with no arguments"
    grep -qx '%xudo ALL=(root) PASSWD:   XUDO_AUTH' "$dest" || fail "the auth rule changed"
    visudo -c >/dev/null || fail "the configuration is invalid with the agent path"
    members=$(getent group xudo-agent | cut -d: -f4)
    [ -z "$members" ] || fail "the xudo-agent group is not empty: $members"

    # A member reaches the helper with no password, and nothing else.
    useradd -M -s /bin/sh -G xudo-agent e8agent
    as_agent() {
        set +e
        su -s /bin/sh e8agent -c "$sudo_exe -n $*" >"$out/agent-sudo.out" 2>"$out/agent-sudo.err"
        rc=$?
        set -e
    }
    as_agent "$helper"
    [ "$rc" -ne 0 ] || fail "the helper ran something for an unattested member"
    has "$out/agent-sudo.err" "xudo-gate: refused (" || fail "the member did not reach the helper with no password"
    [ ! -s "$out/agent-sudo.out" ] || fail "the helper printed for an unattested member"
    for refused in "$helper extra" "/usr/libexec/xudo/xudo-gate-auth" "/bin/true"; do
        as_agent "$refused"
        [ "$rc" -ne 0 ] || fail "a member ran '$refused' with no password"
        if has "$out/agent-sudo.err" "xudo-gate:"; then fail "a member reached the gate with '$refused'"; fi
    done

    # 13b. That member was added by hand, not by enrol, and no harness names
    #      it: the next install refuses and names it.
    try unnamed install --agent-path
    expect_rc 19 "agent path with an unregistered member of xudo-agent"
    expect_err unnamed "refusing --agent-path: e8agent is in xudo-agent"
    userdel e8agent

    # 14. A second agent-path install changes nothing.
    before=$(sum "$dest")
    try again install --agent-path
    expect_agent_ok again
    [ "$(sum "$dest")" = "$before" ] || fail "a second agent-path install changed the file"
    [ "$(ls /etc/sudoers.d | grep -c '^xudo')" -eq 1 ] || fail "more than one xudo file"

    # 15. --raise-ptrace-scope never lowers: at the host's 1 or more (checked
    #     above) it writes nothing. What it does at 0 (the drop-in alone, the
    #     agent path left off) is the unit tests' raise_flag_writes_dropin_but_
    #     install_waits_for_live_value: this lane cannot set the host to 0.
    mkdir -p /etc/sysctl.d
    try raise install --agent-path --raise-ptrace-scope
    expect_agent_ok raise
    expect_out raise "is already $scope"
    expect_absent "$drop_in"

    # 16. An operator's edit is never replaced or removed, and is named.
    cp "$dest" "$out/agent.saved"
    printf '%%xudo-agent ALL=(ALL) NOPASSWD: ALL\n' >>"$dest"
    edited=$(sum "$dest")
    try edited install --uninstall
    expect_rc 19 "uninstall of an edited agent file"
    expect_err edited "was edited"
    try edited2 install --agent-path
    expect_rc 19 "agent path over an edited agent file"
    expect_err edited2 "was edited"
    [ "$(sum "$dest")" = "$edited" ] || fail "an edited agent file was changed"
    cat "$out/agent.saved" >"$dest"

    # 17. A plain install turns the agent path off, and says so.
    try off install
    expect_unverified off
    expect_err off "turns it off"
    if has "$dest" "NOPASSWD"; then fail "a plain install kept the passwordless line"; fi

    # 18. Uninstall removes the agent path and nothing else.
    try on install --agent-path
    expect_agent_ok on
    printf '# operator\n' >/etc/sudoers.d/other
    chmod 440 /etc/sudoers.d/other
    before=$(sum /etc/sudoers.d/other)
    # An edited drop-in is left, with a warning, and never keeps the line.
    if [ -e "$drop_in" ]; then
        printf 'kernel.yama.ptrace_scope = 0\n' >>"$drop_in"
    else
        printf '# Managed by xudo.\nkernel.yama.ptrace_scope = 0\n' >"$drop_in"
        chmod 440 "$drop_in"
    fi
    try agentuninstall install --uninstall
    expect_rc 0 "uninstall of the agent path beside an edited drop-in"
    expect_out agentuninstall "$drop_in was left in place"
    expect_absent "$dest"
    [ -e "$drop_in" ] || fail "uninstall removed an edited drop-in"
    rm -f "$drop_in"
    [ "$(sum /etc/sudoers.d/other)" = "$before" ] || fail "uninstall touched another file"
    getent group xudo-agent >/dev/null || fail "uninstall removed the xudo-agent group"
    visudo -c >/dev/null || fail "the configuration is invalid after removing the agent path"
    rm -f /etc/sudoers.d/other
}

case $row in
sudo-rs-0.2)
    # sudo-rs 0.2 cannot scope `Defaults!command`, which xudo's rule depends on.
    # Installing anyway would write a rule that does not mean what it says, so
    # the install refuses, as root and as anyone, before it writes a byte. The
    # uninstall does not need a usable backend: it removes what xudo wrote.
    try install install
    expect_rc 19 "install on an unusable backend"
    expect_err install "no usable backend"
    expect_absent /etc/sudoers.d/xudo
    expect_absent /etc/sudoers.d/xudo.candidate
    if getent group xudo >/dev/null; then fail "a refused install created the group"; fi
    try uninstall install --uninstall
    expect_rc 0 "uninstall with nothing installed"
    try agentpath install --agent-path
    expect_rc 19 "agent path on an unusable backend"
    expect_err agentpath "no usable backend"
    expect_absent /etc/sudoers.d/xudo
    ;;

sudo | sudo-rs)
    # The image ships /etc/sudoers 0644, which both visudo and sudo-rs's refuse.
    chmod 440 /etc/sudoers
    dest=/etc/sudoers.d/xudo
    cand=/etc/sudoers.d/xudo.candidate
    refuses_non_root
    expect_absent "$dest"
    expect_absent "$cand"

    # 2. A file an operator made at the destination is never replaced.
    printf '# my own rule\n' >"$dest"
    chmod 440 "$dest"
    before=$(sum "$dest")
    try operator install
    expect_rc 19 "install over an operator's file"
    expect_err operator "not a file xudo wrote"
    [ "$(sum "$dest")" = "$before" ] || fail "an operator's file was changed"
    expect_absent "$cand"
    rm -f "$dest"

    # 3. A stale candidate is somebody's file: refused, not overwritten.
    printf '# left here\n' >"$cand"
    before=$(sum "$cand")
    try stale install
    expect_rc 19 "install with a stale candidate"
    [ "$(sum "$cand")" = "$before" ] || fail "a stale candidate was overwritten"
    expect_absent "$dest"
    rm -f "$cand"

    # 4. The install itself.
    try install install
    expect_unverified install
    expect_out install "installed $dest"
    expect_meta "$dest" "440 root:root"
    expect_absent "$cand"
    [ "$(head -c 18 "$dest")" = "# Managed by xudo." ] || fail "the file lacks xudo's marker"
    has "$dest" "PASSWD:" || fail "no PASSWD rule"
    if has "$dest" "NOPASSWD"; then fail "a passwordless rule was installed"; fi
    visudo -cf "$dest" >/dev/null || fail "the backend's validator rejects the installed file"
    visudo -c >/dev/null || fail "the whole sudoers configuration is no longer valid"
    members=$(getent group xudo | cut -d: -f4)
    [ -z "$members" ] || fail "the xudo group is not empty: $members"
    inode=$(stat -c %i "$dest")

    # 5. A reinstall replaces the file atomically, still one file.
    try reinstall install
    expect_unverified reinstall
    [ "$(stat -c %i "$dest")" != "$inode" ] || fail "the reinstall did not replace the file"
    expect_meta "$dest" "440 root:root"
    [ "$(ls /etc/sudoers.d | grep -c '^xudo')" -eq 1 ] || fail "more than one xudo file"

    # 6. A backend that rejects the candidate leaves the old state as it was.
    real=$(readlink -f /usr/sbin/visudo)
    mv /usr/sbin/visudo /usr/sbin/visudo.orig
    # A regular file moved aside is run from where it went; a link keeps pointing
    # at the same place it always did.
    [ "$real" != /usr/sbin/visudo ] || real=/usr/sbin/visudo.orig
    cat >/usr/sbin/visudo <<EOF
#!/bin/sh
case "\$*" in *xudo.candidate*) echo "rejected by the test" >&2; exit 1 ;; esac
exec $real "\$@"
EOF
    chmod 755 /usr/sbin/visudo
    before=$(sum "$dest")
    inode=$(stat -c %i "$dest")
    try rejected install
    mv /usr/sbin/visudo.orig /usr/sbin/visudo
    expect_rc 19 "install the backend rejects"
    expect_err rejected "rejected the candidate"
    [ "$(sum "$dest")" = "$before" ] || fail "a rejected install changed the old file"
    [ "$(stat -c %i "$dest")" = "$inode" ] || fail "a rejected install replaced the old file"
    expect_absent "$cand"

    # 7. Uninstall removes xudo's file, and nothing else, and not the group.
    printf '# operator\n' >/etc/sudoers.d/other
    chmod 440 /etc/sudoers.d/other
    before=$(sum /etc/sudoers.d/other)
    try uninstall install --uninstall
    expect_rc 0 "uninstall"
    expect_absent "$dest"
    [ "$(sum /etc/sudoers.d/other)" = "$before" ] || fail "uninstall touched another file"
    getent group xudo >/dev/null || fail "uninstall removed the group"
    try again install --uninstall
    expect_rc 0 "a second uninstall"
    visudo -c >/dev/null || fail "the configuration is invalid after uninstall"

    # 8. Uninstall never removes what is not provably xudo's.
    printf '# mine\n' >"$dest"
    chmod 440 "$dest"
    try theirs install --uninstall
    expect_rc 19 "uninstall of an operator's file"
    expect_err theirs "not a file xudo wrote"
    [ -f "$dest" ] || fail "an operator's file was removed"
    rm -f "$dest"
    printf 'precious\n' >/etc/hostname-xudo-test
    ln -s /etc/hostname-xudo-test "$dest"
    try link install --uninstall
    expect_rc 19 "uninstall of a symlink"
    [ -L "$dest" ] || fail "the symlink was removed or replaced"
    [ "$(cat /etc/hostname-xudo-test)" = precious ] || fail "the link's target was changed"
    rm -f "$dest" /etc/hostname-xudo-test /etc/sudoers.d/other

    agent_path
    ;;

doas)
    dropin=/etc/doas.d/60-xudo.conf
    cand=/etc/doas.d/60-xudo.conf.candidate
    conf=/etc/doas.conf
    cp "$conf" "$out/doas.conf.orig"
    refuses_non_root

    # 2. The drop-in install (Alpine ships /etc/doas.d).
    try install install
    expect_unverified install
    expect_out install "installed $dropin"
    expect_meta "$dropin" "400 root:root"
    expect_absent "$cand"
    [ "$(head -c 18 "$dropin")" = "# Managed by xudo." ] || fail "the drop-in lacks xudo's marker"
    doas -C "$dropin" || fail "doas rejects the installed drop-in"
    doas -C "$conf" || fail "doas rejects its configuration after the install"
    cmp -s "$conf" "$out/doas.conf.orig" || fail "the drop-in install changed doas.conf"
    members=$(getent group xudo | cut -d: -f4)
    [ -z "$members" ] || fail "the xudo group is not empty: $members"

    # 3. An operator's file at the drop-in's name is never replaced.
    mv "$dropin" "$out/dropin.saved"
    printf '# mine\n' >"$dropin"
    before=$(sum "$dropin")
    try operator install
    expect_rc 19 "install over an operator's drop-in"
    expect_err operator "not a file xudo wrote"
    [ "$(sum "$dropin")" = "$before" ] || fail "an operator's drop-in was changed"
    expect_absent "$cand"
    try theirs install --uninstall
    expect_rc 19 "uninstall of an operator's drop-in"
    [ -f "$dropin" ] || fail "an operator's drop-in was removed"
    rm -f "$dropin"
    mv "$out/dropin.saved" "$dropin"

    # 4. A backend that rejects the candidate leaves the old state as it was.
    reject_doas '*candidate*'
    before=$(sum "$dropin")
    try rejected install
    restore_doas
    expect_rc 19 "install the backend rejects"
    expect_err rejected "rejected the candidate"
    [ "$(sum "$dropin")" = "$before" ] || fail "a rejected install changed the old drop-in"
    expect_absent "$cand"

    # 5. Uninstall removes the drop-in and leaves doas.conf as it was.
    try uninstall install --uninstall
    expect_rc 0 "uninstall"
    expect_absent "$dropin"
    cmp -s "$conf" "$out/doas.conf.orig" || fail "uninstall changed doas.conf"
    getent group xudo >/dev/null || fail "uninstall removed the group"

    # 6. Without a drop-in directory the rule is a sentinel-delimited block in
    #    the operator's own file.
    rmdir /etc/doas.d
    printf 'permit persist :wheel\n# kept\n' >>"$conf"
    # root:wheel 0640, as a distribution may ship it: the edit must hand back
    # exactly that, not root:root 0400.
    chgrp wheel "$conf"
    chmod 640 "$conf"
    cp "$conf" "$out/doas.conf.operator"
    try block install
    expect_unverified block
    expect_out block "set xudo's block in $conf"
    [ "$(grep -c '^### xudo:begin' "$conf")" -eq 1 ] || fail "not exactly one begin sentinel"
    [ "$(grep -c '^### xudo:end$' "$conf")" -eq 1 ] || fail "not exactly one end sentinel"
    has "$conf" "permit persist :wheel" || fail "an operator's line was lost"
    expect_meta "$conf" "640 root:wheel"
    doas -C "$conf" || fail "doas rejects its configuration with the block"
    expect_absent "$conf.xudo-new"

    # 7. A reinstall replaces the block, it does not add a second.
    try reblock install
    expect_unverified reblock
    [ "$(grep -c '^### xudo:begin' "$conf")" -eq 1 ] || fail "a reinstall added a second block"

    # 8. A backend that rejects the merged copy leaves doas.conf as it was.
    before=$(sum "$conf")
    reject_doas '*xudo-new*'
    try blockrejected install
    restore_doas
    expect_rc 19 "block install the backend rejects"
    expect_err blockrejected "rejected the candidate"
    [ "$(sum "$conf")" = "$before" ] || fail "a rejected block install changed doas.conf"
    expect_absent "$conf.xudo-new"

    # 9. Uninstall removes exactly the block: the file is the operator's again.
    try blockagain install
    expect_unverified blockagain
    try unblock install --uninstall
    expect_rc 0 "uninstall of the block"
    cmp -s "$conf" "$out/doas.conf.operator" || fail "uninstall did not restore the operator's file byte for byte"
    expect_meta "$conf" "640 root:wheel"

    # 10. Sentinels that do not pair are not guessed at.
    printf '### xudo:begin — do not edit between the markers\n' >>"$conf"
    cp "$conf" "$out/doas.conf.ambiguous"
    try ambiguous install --uninstall
    expect_rc 19 "uninstall with an unpaired sentinel"
    cmp -s "$conf" "$out/doas.conf.ambiguous" || fail "an ambiguous file was edited"
    ;;

*)
    fail "unknown row"
    ;;
esac

echo "row $row: ok"
