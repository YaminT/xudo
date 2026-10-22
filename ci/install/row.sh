#!/bin/sh
# One row of the install matrix, run inside that row's container as root.
#
#   sh /harness/row.sh <row> <setup command>
#
# Expects the static aido binary at /usr/local/bin/aido, this directory at
# /harness, and a writable /out. POSIX sh only: the Alpine row has busybox, the
# Ubuntu rows have dash. Every check that fails prints what it was checking and
# exits non-zero; there is no "warn".
set -eu
set -f

row=$1
setup=$2
aido=/usr/local/bin/aido
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

# aido must not consult its environment, but the harness still hands it a known
# one so that nothing here can come from it.
run_aido() {
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$aido" "$@"
}

# try <name> <args...>: runs aido as root, keeping stdout, stderr, and the status.
try() {
    name=$1
    shift
    set +e
    run_aido "$@" >"$out/$name.out" 2>"$out/$name.err"
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
    su -s /bin/sh nobody -c "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin $aido $*" \
        >"$out/nobody.out" 2>"$out/nobody.err"
    rc=$?
    set -e
}

refuses_non_root() {
    as_nobody install
    expect_rc 19 "non-root install"
    expect_err nobody "requires root"
    if getent group aido >/dev/null; then fail "a non-root install created the group"; fi
}

# A doas that rejects any command line matching the pattern, and is otherwise
# the real one: how a backend that refuses the candidate is made to happen.
reject_doas() {
    mv /usr/bin/doas /usr/bin/doas.orig
    cat >/usr/bin/doas <<EOF
#!/bin/sh
case "\$*" in $1) echo "rejected by the test" >&2; exit 1 ;; esac
exec /usr/bin/doas.orig "\$@"
EOF
    chmod 755 /usr/bin/doas
}

restore_doas() { mv /usr/bin/doas.orig /usr/bin/doas; }

case $row in
sudo-rs-0.2)
    # sudo-rs 0.2 cannot scope `Defaults!command`, which aido's rule depends on.
    # Installing anyway would write a rule that does not mean what it says, so
    # the install refuses, as root and as anyone, before it writes a byte. The
    # uninstall does not need a usable backend: it removes what aido wrote.
    try install install
    expect_rc 19 "install on an unusable backend"
    expect_err install "no usable backend"
    expect_absent /etc/sudoers.d/aido
    expect_absent /etc/sudoers.d/aido.candidate
    if getent group aido >/dev/null; then fail "a refused install created the group"; fi
    try uninstall install --uninstall
    expect_rc 0 "uninstall with nothing installed"
    ;;

sudo | sudo-rs)
    # The image ships /etc/sudoers 0644, which both visudo and sudo-rs's refuse.
    chmod 440 /etc/sudoers
    dest=/etc/sudoers.d/aido
    cand=/etc/sudoers.d/aido.candidate
    refuses_non_root
    expect_absent "$dest"
    expect_absent "$cand"

    # 2. A file an operator made at the destination is never replaced.
    printf '# my own rule\n' >"$dest"
    chmod 440 "$dest"
    before=$(sum "$dest")
    try operator install
    expect_rc 19 "install over an operator's file"
    expect_err operator "not a file aido wrote"
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
    [ "$(head -c 18 "$dest")" = "# Managed by aido." ] || fail "the file lacks aido's marker"
    has "$dest" "PASSWD:" || fail "no PASSWD rule"
    if has "$dest" "NOPASSWD"; then fail "a passwordless rule was installed"; fi
    visudo -cf "$dest" >/dev/null || fail "the backend's validator rejects the installed file"
    visudo -c >/dev/null || fail "the whole sudoers configuration is no longer valid"
    members=$(getent group aido | cut -d: -f4)
    [ -z "$members" ] || fail "the aido group is not empty: $members"
    inode=$(stat -c %i "$dest")

    # 5. A reinstall replaces the file atomically, still one file.
    try reinstall install
    expect_unverified reinstall
    [ "$(stat -c %i "$dest")" != "$inode" ] || fail "the reinstall did not replace the file"
    expect_meta "$dest" "440 root:root"
    [ "$(ls /etc/sudoers.d | grep -c '^aido')" -eq 1 ] || fail "more than one aido file"

    # 6. A backend that rejects the candidate leaves the old state as it was.
    real=$(readlink -f /usr/sbin/visudo)
    mv /usr/sbin/visudo /usr/sbin/visudo.orig
    # A regular file moved aside is run from where it went; a link keeps pointing
    # at the same place it always did.
    [ "$real" != /usr/sbin/visudo ] || real=/usr/sbin/visudo.orig
    cat >/usr/sbin/visudo <<EOF
#!/bin/sh
case "\$*" in *aido.candidate*) echo "rejected by the test" >&2; exit 1 ;; esac
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

    # 7. Uninstall removes aido's file, and nothing else, and not the group.
    printf '# operator\n' >/etc/sudoers.d/other
    chmod 440 /etc/sudoers.d/other
    before=$(sum /etc/sudoers.d/other)
    try uninstall install --uninstall
    expect_rc 0 "uninstall"
    expect_absent "$dest"
    [ "$(sum /etc/sudoers.d/other)" = "$before" ] || fail "uninstall touched another file"
    getent group aido >/dev/null || fail "uninstall removed the group"
    try again install --uninstall
    expect_rc 0 "a second uninstall"
    visudo -c >/dev/null || fail "the configuration is invalid after uninstall"

    # 8. Uninstall never removes what is not provably aido's.
    printf '# mine\n' >"$dest"
    chmod 440 "$dest"
    try theirs install --uninstall
    expect_rc 19 "uninstall of an operator's file"
    expect_err theirs "not a file aido wrote"
    [ -f "$dest" ] || fail "an operator's file was removed"
    rm -f "$dest"
    printf 'precious\n' >/etc/hostname-aido-test
    ln -s /etc/hostname-aido-test "$dest"
    try link install --uninstall
    expect_rc 19 "uninstall of a symlink"
    [ -L "$dest" ] || fail "the symlink was removed or replaced"
    [ "$(cat /etc/hostname-aido-test)" = precious ] || fail "the link's target was changed"
    rm -f "$dest" /etc/hostname-aido-test /etc/sudoers.d/other
    ;;

doas)
    dropin=/etc/doas.d/60-aido.conf
    cand=/etc/doas.d/60-aido.conf.candidate
    conf=/etc/doas.conf
    cp "$conf" "$out/doas.conf.orig"
    refuses_non_root

    # 2. The drop-in install (Alpine ships /etc/doas.d).
    try install install
    expect_unverified install
    expect_out install "installed $dropin"
    expect_meta "$dropin" "400 root:root"
    expect_absent "$cand"
    [ "$(head -c 18 "$dropin")" = "# Managed by aido." ] || fail "the drop-in lacks aido's marker"
    doas -C "$dropin" || fail "doas rejects the installed drop-in"
    doas -C "$conf" || fail "doas rejects its configuration after the install"
    cmp -s "$conf" "$out/doas.conf.orig" || fail "the drop-in install changed doas.conf"
    members=$(getent group aido | cut -d: -f4)
    [ -z "$members" ] || fail "the aido group is not empty: $members"

    # 3. An operator's file at the drop-in's name is never replaced.
    mv "$dropin" "$out/dropin.saved"
    printf '# mine\n' >"$dropin"
    before=$(sum "$dropin")
    try operator install
    expect_rc 19 "install over an operator's drop-in"
    expect_err operator "not a file aido wrote"
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
    getent group aido >/dev/null || fail "uninstall removed the group"

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
    expect_out block "set aido's block in $conf"
    [ "$(grep -c '^### aido:begin' "$conf")" -eq 1 ] || fail "not exactly one begin sentinel"
    [ "$(grep -c '^### aido:end$' "$conf")" -eq 1 ] || fail "not exactly one end sentinel"
    has "$conf" "permit persist :wheel" || fail "an operator's line was lost"
    expect_meta "$conf" "640 root:wheel"
    doas -C "$conf" || fail "doas rejects its configuration with the block"
    expect_absent "$conf.aido-new"

    # 7. A reinstall replaces the block, it does not add a second.
    try reblock install
    expect_unverified reblock
    [ "$(grep -c '^### aido:begin' "$conf")" -eq 1 ] || fail "a reinstall added a second block"

    # 8. A backend that rejects the merged copy leaves doas.conf as it was.
    before=$(sum "$conf")
    reject_doas '*aido-new*'
    try blockrejected install
    restore_doas
    expect_rc 19 "block install the backend rejects"
    expect_err blockrejected "rejected the candidate"
    [ "$(sum "$conf")" = "$before" ] || fail "a rejected block install changed doas.conf"
    expect_absent "$conf.aido-new"

    # 9. Uninstall removes exactly the block: the file is the operator's again.
    try blockagain install
    expect_unverified blockagain
    try unblock install --uninstall
    expect_rc 0 "uninstall of the block"
    cmp -s "$conf" "$out/doas.conf.operator" || fail "uninstall did not restore the operator's file byte for byte"
    expect_meta "$conf" "640 root:wheel"

    # 10. Sentinels that do not pair are not guessed at.
    printf '### aido:begin — do not edit between the markers\n' >>"$conf"
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
