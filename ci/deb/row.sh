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
timer=/etc/systemd/system/timers.target.wants/xudo-pasban.timer
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
# Plain Docker does not start the broker, so the probe is unverified here for
# that reason on every image. A symlink or a missing probe program is a
# different failure: the package must not have fallen through to it.
if grep -q 'no probe program is a regular file' /tmp/apt.log; then
    cat /tmp/apt.log >&2
    fail "install probe found no regular program"
fi
grep -Fq 'every privileged request asks for a password' /tmp/apt.log || fail "first install notice missing"
grep -Fq 'There is no' /tmp/apt.log || fail "first install notice omitted agent-path status"
grep -Fq '/usr/share/doc/xudo/SECURITY.md' /tmp/apt.log || fail "first install notice omitted local SECURITY.md path"
grep -Fq 'https://github.com/YaminT/xudo/blob/main/SECURITY.md' /tmp/apt.log || fail "first install notice omitted SECURITY.md URL"
grep -Fq 'Agent detection is not a security boundary' /tmp/apt.log || fail "first install notice omitted detection boundary"
grep -Fq 'sudo usermod -aG xudo <you>' /tmp/apt.log || fail "first install notice omitted group instructions"
grep -Fq 'xudo doctor --fix' /tmp/apt.log || fail "first install notice omitted doctor instructions"
grep -Fq 'Without systemd' /tmp/apt.log || fail "first install notice omitted systemd/journald requirement"
dpkg -s xudo | grep -q '^Status: install ok installed' || fail "not installed"
doctor_out=$(xudo doctor)
printf '%s\n' "$doctor_out" | grep -Fq 'sudoers xudo managed rule at /etc/sudoers.d/xudo' || fail "doctor did not report xudo's installed sudoers rule"
# Ubuntu's official images set path-exclude=/usr/share/doc/*, so dpkg never
# unpacks the example there. Debian 13 does not, and the file is present.
# ci/deb/run.sh is what checks the .deb itself contains the example.
example=/usr/share/doc/xudo/examples/20-services-lifecycle.toml
if [ ! -f "$example" ]; then
    if [ ! -d /etc/dpkg/dpkg.cfg.d ] \
        || ! grep -Rqs '^path-exclude=/usr/share/doc/\*' /etc/dpkg/dpkg.cfg.d
    then
        fail "lifecycle example not installed"
    fi
fi
[ ! -e /etc/xudo/rules.d/20-services-lifecycle.toml ] || fail "lifecycle example installed as a rule"
printf '%s\n' "$doctor_out" | grep -Fq 'no service lifecycle rule: copy /usr/share/doc/xudo/examples/20-services-lifecycle.toml to /etc/xudo/rules.d/ and list your units' || fail "doctor omitted the lifecycle note"
rules_count=$(find /etc/xudo/rules.d -maxdepth 1 -type f -name '*.toml' | wc -l)
matching_count=$(printf '%s\n' "$doctor_out" | grep -c 'rule package .*: matches shipped' || true)
[ "$matching_count" -eq "$rules_count" ] || fail "doctor did not report every shipped rule as matches shipped"
cp "$rule" /etc/sudoers.d/xudo.conf
doctor_out=$(xudo doctor)
printf '%s\n' "$doctor_out" | grep -Fq '/etc/sudoers.d/xudo.conf is not in effect:' || fail "doctor missed dotted xudo snippet"
rm /etc/sudoers.d/xudo.conf
if command -v debsums >/dev/null 2>&1; then debsums -s xudo || fail "debsums"; else dpkg --verify xudo || fail "dpkg --verify"; fi
meta $rule "440 root:root"
! grep -qs NOPASSWD "$rule" || fail "NOPASSWD found in generated sudoers rule"
! dpkg -L xudo | grep -q xudo-gate-nopass || fail "passwordless gate listed"
getent group xudo >/dev/null || fail "no xudo group"
[ -z "$(getent group xudo | cut -d: -f4)" ] || fail "xudo group is not empty"
meta /var/lib/xudo "700 root:root"
grep -Eq '^f[[:space:]]+/var/lib/xudo/audit.jsonl[[:space:]]+0600[[:space:]]+root[[:space:]]+root([[:space:]]|$)' /usr/lib/tmpfiles.d/xudo.conf || fail "tmpfiles audit-log rule missing"
grep -Eq '^d[[:space:]]+/run/xudo/confirm[[:space:]]+0700[[:space:]]+root[[:space:]]+root([[:space:]]|$)' /usr/lib/tmpfiles.d/xudo.conf || fail "tmpfiles confirm rule missing"
# postinst creates these. Creating them here would pass when postinst did not.
meta /var/lib/xudo/audit.jsonl "600 root:root"
[ ! -s /var/lib/xudo/audit.jsonl ] || fail "new audit log is not empty"
meta /run/xudo "755 root:root"
meta /run/xudo/req "700 root:root"
meta /run/xudo/confirm "700 root:root"
[ -L "$socket" ] || fail "socket was not enabled"
[ -f /usr/lib/systemd/system/xudo-pasban.service ] || fail "pasban service not in the package"
[ -f /usr/lib/systemd/system/xudo-pasban.timer ] || fail "pasban timer not in the package"
[ -L "$timer" ] || fail "timer was not enabled"
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
# A comment keeps the file valid. The upgrade notice matches the id string.
printf '\n# kept beta.1 rule id = "xudo.svc.lifecycle"\n' >>/etc/xudo/rules.d/20-services.toml
doctor_out=$(xudo doctor)
printf '%s\n' "$doctor_out" | grep -Fq '/etc/xudo/rules.d/05-probe.toml: changed locally' || fail "doctor missed local rule edit"
useradd --no-create-home xudomember
usermod -aG xudo xudomember
printf '%s\n' '{"h":null,"b":[["fingerprint",3,123]],"o":[]}' >/run/xudo/confirm/legacy.json
printf '%s\n' 'keep target' >/run/xudo/confirm/target-data
ln -s target-data /run/xudo/confirm/link.json
printf '%s\n' 'keep non-json' >/run/xudo/confirm/preserve.txt
mkdir /run/xudo/confirm/nested
printf '%s\n' 'keep nested' >/run/xudo/confirm/nested/legacy.json
deb_install -o Dpkg::Options::=--force-confold ./new.deb
grep -q 'xudo.svc.lifecycle' /etc/xudo/rules.d/20-services.toml || fail "upgrade did not keep the beta.1 lifecycle rule"
grep -Fq 'replace its unit-name with a one-of list of your units' /tmp/apt.log || fail "upgrade did not warn about the kept lifecycle rule"
gone /run/xudo/confirm/legacy.json
[ -L /run/xudo/confirm/link.json ] || fail "confirm cleanup removed a symlink"
[ "$(cat /run/xudo/confirm/target-data)" = 'keep target' ] || fail "confirm cleanup changed a symlink target"
[ "$(cat /run/xudo/confirm/preserve.txt)" = 'keep non-json' ] || fail "confirm cleanup removed a non-json file"
[ -d /run/xudo/confirm/nested ] || fail "confirm cleanup removed a subdirectory"
[ "$(cat /run/xudo/confirm/nested/legacy.json)" = 'keep nested' ] || fail "confirm cleanup changed a nested file"
if grep -Fq 'every privileged request asks for a password' /tmp/apt.log; then
    fail "upgrade printed the first install notice"
fi
[ "$(dpkg-query -W -f='${Version}' xudo)" != "$(dpkg-deb -f /tmp/old.deb Version)" ] || fail "version did not change"
meta $rule "440 root:root"
grep -q '^# mine' /etc/xudo/rules.d/05-probe.toml || fail "upgrade lost the operator's edit"
members=$(getent group xudo | cut -d: -f4)
printf '%s\n' ",$members," | grep -q ',xudomember,' || fail "upgrade dropped the group member"
[ -L "$socket" ] || fail "upgrade dropped the socket enablement"
[ -L "$timer" ] || fail "upgrade dropped the timer enablement"
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
[ ! -e "$timer" ] && [ ! -L "$timer" ] || fail "remove left the timer enabled"
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
# An operator who disabled the timer keeps it disabled across an upgrade.
# Enablement is a first install only, same as the socket.
rm -f "$timer"
deb_install -o Dpkg::Options::=--force-confold ./new.deb
gone $rule
[ ! -e "$timer" ] && [ ! -L "$timer" ] || fail "upgrade re-enabled a timer the operator disabled"
grep -q 'no xudo rule installed' /tmp/apt.log || fail "upgrade did not report the missing rule"
echo "row ok"
