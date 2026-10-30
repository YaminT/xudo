#!/bin/sh
# The executing half of a row: the real broker, gate, and install, then
# `xudo exec` as an unprivileged user through the real backend.
#
#   sh /harness/exec.sh <row>      (called by row.sh, as root, after setup)
#
# Writes /out/<row>/exec.txt, which must be identical in every row with a
# backend, and adds the install outcome to report.txt. POSIX sh: Alpine has busybox.
set -eu

row=$1
out=/out/$row
bins=/bins
res=$out/exec.txt

if [ "$row" = none ]; then
    # No backend: nothing to exec through.
    set +e
    /usr/local/bin/xudo exec -- /usr/bin/id -u >"$out/exec-none.log" 2>&1
    echo "exec         exit $?" >>"$out/report.txt"
    exit 0
fi

: >"$res"
if command -v apk >/dev/null; then apk add -q socat expect coreutils; else apt-get install -y -qq socat expect >/dev/null; fi

# The product's files, where the product looks for them.
install -d -m755 /usr/libexec/xudo /etc/xudo /etc/xudo/rules.d
install -m755 "$bins/xudod" "$bins/xudo-gate" /usr/libexec/xudo/
ln -f /usr/libexec/xudo/xudo-gate /usr/libexec/xudo/xudo-gate-auth
install -m644 /rules/*.toml /harness/harness-rules.toml /etc/xudo/rules.d/
install -d -m700 /var/lib/xudo
install -d -m755 /run/xudo
install -d -m700 /run/xudo/req

# A user with a password, in the group that may reach the broker.
if command -v useradd >/dev/null; then
    groupadd --system xudo
    useradd -m -G xudo xudotest
    SU="su --pty" # su -c drops the controlling tty, and sudo wants one
else
    addgroup -S xudo
    adduser -D -G xudo xudotest
    SU=su
fi
echo xudotest:pw | chpasswd 2>/dev/null

# No journald in a container: a datagram socket where the journal would be.
install -d /run/systemd/journal
socat -u UNIX-RECV:/run/systemd/journal/socket /dev/null &

# systemd's Accept=yes, by hand: each connection is the broker's descriptor 0
# (nofork), so it sees the real peer and not socat.
broker() {
    socat UNIX-LISTEN:/run/xudo/broker.sock,fork,mode=0660,group=xudo EXEC:/usr/libexec/xudo/xudod,nofork &
    sleep 1
}

# Finding: the gate refuses a symlinked program, and /usr/bin/id (the install
# probe's) and expr are symlinks to multicall binaries on Ubuntu 26.04 (uutils)
# and Alpine (busybox), which also want their own name in argv[0]. Real GNU
# ones stand in so the rows can run; reported, not fixed.
for tool in id expr; do
    # Alpine has no gnu$tool; its coreutils package is one multicall binary.
    real=/usr/bin/gnu$tool
    [ -x $real ] || real=/bin/coreutils
    if [ -L /usr/bin/$tool ] && [ -x $real ]; then
        rm /usr/bin/$tool
        cp $real /usr/bin/$tool
    fi
done

# `xudo install` for real, with its own probe through the broker. doas asks root
# for a password, so its probe cannot run: installed, NOT VERIFIED.
broker
set +e
/usr/local/bin/xudo install >"$out/install-real.log" 2>&1
set -e
sed -nE -e 's/^verified +(.*)$/install real  verified: \1/p' \
    -e 's/^.*(installed, but NOT VERIFIED).*$/install real  \1/p' \
    "$out/install-real.log" | sort -u >>"$out/report.txt"
# A backend xudo refuses to install on has nothing to execute through.
if grep -q '^xudo: no usable backend' "$out/install-real.log"; then
    echo "install real  refused: no usable backend" >>"$out/report.txt"
    rm -f "$res"
    exit 0
fi
[ -e /etc/sudoers.d/xudo ] || [ -e /etc/doas.d/60-xudo.conf ] || { cat "$out/install-real.log" >&2; exit 1; }

# One case: xudo exec as xudotest on a pty, the password typed at the prompt.
# Records xudo's exit status and what the command printed, minus the prompt
# and the pty's CRs.
case_() {
    pw=$1
    shift
    echo "== $*" >>"$res"
    set +e
    expect /harness/exec.exp "$SU" "$pw" "/usr/local/bin/xudo exec -- $*" >"$out/case.raw" 2>&1
    rc=$?
    set -e
    tr -d '\r' <"$out/case.raw" | sed -e 's|^/usr/bin/||' -e "s/[‘’]/'/g" | grep -vi -e '^spawn ' -e password -e '^$' >"$out/case.out" || true
    cat "$out/case.out" >>"$res"
    echo "exit $rc" >>"$res"
}

case_ pw /usr/bin/id -u
case_ pw /usr/bin/expr 1 +
case_ pw /usr/bin/id -G
case_ pw /bin/sh -c id
# A wrong password may fail differently per backend (sudo exits 1, doas too,
# sudo-rs may differ); only "failed and ran nothing" is compared.
echo "== wrong password" >>"$res"
set +e
expect /harness/exec.exp "$SU" wrong "/usr/local/bin/xudo exec -- /usr/bin/id -u" >"$out/wrong.raw" 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ] && ! tr -d '\r' <"$out/wrong.raw" | grep -qx 0; then echo "failed, ran nothing" >>"$res"; else echo "UNEXPECTED rc=$rc" >>"$res"; fi
