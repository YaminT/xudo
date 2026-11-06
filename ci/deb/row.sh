#!/bin/sh
# One row of the .deb matrix, run as root in a fresh container with the old
# package at /debs/old.deb and a higher version at /debs/new.deb.
# APT_NO_RECOMMENDS, when set, is passed to every package install (Debian).
set -eu
export DEBIAN_FRONTEND=noninteractive
fail() { echo "FAIL: $*" >&2; exit 1; }
meta() { [ "$(stat -c '%a %U:%G' "$1")" = "$2" ] || fail "$1 is $(stat -c '%a %U:%G' "$1"), wanted $2"; }
gone() { [ ! -e "$1" ] && [ ! -L "$1" ] || fail "$1 exists, and must not"; }
rule=/etc/sudoers.d/xudo
socket=/etc/systemd/system/sockets.target.wants/xudod.socket
norec=${APT_NO_RECOMMENDS:-}
apt() { apt-get "$@" -y -qq >/tmp/apt.log 2>&1 || { cat /tmp/apt.log >&2; fail "apt-get $*"; }; }
deb_install() {
    if [ -n "$norec" ]; then
        apt-get install -y -qq "$norec" "$@" >/tmp/apt.log 2>&1 || { cat /tmp/apt.log >&2; fail "apt-get install $*"; }
    else
        apt-get install -y -qq "$@" >/tmp/apt.log 2>&1 || { cat /tmp/apt.log >&2; fail "apt-get install $*"; }
    fi
}

apt-get update -qq >/dev/null
cp /debs/old.deb /debs/new.deb /tmp/ && cd /tmp

# Install: pulls sudo, writes the rule, creates an empty group.
deb_install ./old.deb
dpkg -s xudo | grep -q '^Status: install ok installed' || fail "not installed"
if command -v debsums >/dev/null 2>&1; then debsums -s xudo || fail "debsums"; else dpkg --verify xudo || fail "dpkg --verify"; fi
meta $rule "440 root:root"
! grep -qs NOPASSWD "$rule" || fail "NOPASSWD found in generated sudoers rule"
! dpkg -L xudo | grep -q xudo-gate-nopass || fail "passwordless gate listed"
getent group xudo >/dev/null || fail "no xudo group"
[ -z "$(getent group xudo | cut -d: -f4)" ] || fail "xudo group is not empty"
meta /var/lib/xudo "700 root:root"
meta /run/xudo "755 root:root"
meta /run/xudo/req "700 root:root"
[ -L "$socket" ] || fail "socket was not enabled"
gone /usr/libexec/xudo/xudo-gate-nopass
gone /usr/libexec/xudo/xudo-gate
[ -x /usr/libexec/xudo/xudo-gate-auth ] || fail "auth gate missing"
[ "$(stat -c %i /usr/bin/ido)" = "$(stat -c %i /usr/bin/willyoumarryme)" ] || fail "ido names are not one inode"
files=$(dpkg -L xudo | while read -r f; do if [ -f "$f" ]; then echo "$f"; fi; done)
[ -n "$files" ] || fail "no files listed"
bad=$(for f in $files; do find "$f" \( -perm -4000 -o -perm -2000 \); done)
[ -z "$bad" ] || fail "setuid or setgid file in the package"
conf=$(dpkg-query -W -f='${Conffiles}' xudo)
for r in /etc/xudo/rules.d/*.toml; do echo "$conf" | grep -qF "$r" || fail "$r is not a conffile"; done
[ "$(echo "$conf" | grep -c rules.d)" -ge 5 ] || fail "conffiles missing"
xudo list >/dev/null || fail "xudo list does not run"
shipped=$(find /etc/sudoers.d -mindepth 1 -maxdepth 1 ! -name xudo | sort)
[ -n "$shipped" ] || fail "distro shipped nothing under /etc/sudoers.d"

# Upgrade keeps the rule, a group member, and an operator's edit to a shipped rule.
echo '# mine' >>/etc/xudo/rules.d/05-probe.toml
useradd --no-create-home xudomember
usermod -aG xudo xudomember
deb_install -o Dpkg::Options::=--force-confold ./new.deb
[ "$(dpkg-query -W -f='${Version}' xudo)" != "$(dpkg-deb -f /tmp/old.deb Version)" ] || fail "version did not change"
meta $rule "440 root:root"
grep -q '^# mine' /etc/xudo/rules.d/05-probe.toml || fail "upgrade lost the operator's edit"
members=$(getent group xudo | cut -d: -f4)
printf '%s\n' ",$members," | grep -q ',xudomember,' || fail "upgrade dropped the group member"
[ -L "$socket" ] || fail "upgrade dropped the socket enablement"
if grep -q 'no xudo rule installed' /tmp/apt.log; then
    fail "upgrade with a rule said there was none"
fi

# Remove leaves config-files. Purge from that state, and leave the distro's sudoers.d files.
apt remove xudo
gone $rule
gone /usr/bin/xudo
[ -d /etc/xudo/rules.d ] || fail "remove deleted the conffiles"
getent group xudo >/dev/null || fail "remove deleted the group"
dpkg -s xudo | grep -q '^Status: deinstall ok config-files' || fail "remove did not leave config-files"
[ ! -e "$socket" ] && [ ! -L "$socket" ] || fail "remove left the socket enabled"
apt purge xudo
gone $rule
gone /etc/xudo
gone /var/lib/xudo
! getent group xudo >/dev/null || fail "purge left the group"
for f in $shipped; do [ -e "$f" ] || fail "purge removed $f"; done

# A rule the operator removed is not put back by an upgrade.
deb_install ./old.deb
meta $rule "440 root:root"
xudo install --uninstall
gone $rule
deb_install -o Dpkg::Options::=--force-confold ./new.deb
gone $rule
grep -q 'no xudo rule installed' /tmp/apt.log || fail "upgrade did not report the missing rule"
echo "row ok"
