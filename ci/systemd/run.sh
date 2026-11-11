#!/bin/sh
# The installed .deb with the broker under real systemd, one container per
# distribution. systemd is PID 1: the image installs systemd and systemd-sysv,
# then execs /sbin/init. Privileged lets it manage its own private cgroup namespace.
# Nothing else on the host is changed. ci/systemd/row.sh asserts inside.
#
#   ci/systemd/run.sh <musl triple>       (or: just systemd-test)
#
# Every case must run and pass. The user-namespace case needs util-linux >=
# 2.39 and root able to create a user namespace; if it cannot run, the lane
# fails. Nothing is skippable.
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <musl triple>" >&2
    exit 2
fi
triple=$1
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
command -v docker >/dev/null || { echo "FAIL: docker is required" >&2; exit 1; }

case $triple in
x86_64-*) arch=amd64 ;;
aarch64-*) arch=arm64 ;;
*) echo "unsupported triple $triple" >&2; exit 1 ;;
esac
raw=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -1)
[ -n "$raw" ] || { echo "FAIL: no version in Cargo.toml" >&2; exit 1; }
deb_ver=$(printf '%s\n' "$raw" | tr '-' '~')
deb="$root/target/deb/xudo_${deb_ver}_${arch}.deb"
short_ttl_deb="$root/target/systemd-short-ttl/deb/xudo_${deb_ver}_${arch}.deb"
[ -f "$deb" ] || { echo "FAIL: built package not at $deb" >&2; exit 1; }
[ -f "$short_ttl_deb" ] || { echo "FAIL: short-TTL test package not at $short_ttl_deb" >&2; exit 1; }

# Debian 13, Ubuntu 24.04, and Ubuntu 26.04, each as the image ships it.
# 26.04's /usr/bin/id is a uutils symlink; the install probe uses gnuid.
images="debian:13 ubuntu:24.04 ubuntu:26.04"
name=
cleanup() {
    if [ -n "$name" ]; then
        docker rm -f "$name" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Official images ship policy-rc.d that refuses service starts. A machine does
# not, and this lane is about the package starting its socket.
#
# apt-get -qq prints nothing until dpkg starts. A stalled Ubuntu mirror used to
# sit there for the whole 240s wait, with an empty `docker logs`, and this
# script reported that systemd had not become running. The acquire timeout
# makes a stall fail the container instead. Once systemd is PID 1, the units
# below are oneshots with no start timeout, or a getty restart loop. A
# container never needs them. logind stays: without it, pam_systemd blocks
# `su` and `xudo watch` never publishes a heartbeat. Masking is a symlink to
# /dev/null, which does not need a running systemd.
boot='
set -eu
export DEBIAN_FRONTEND=noninteractive
cat >/etc/apt/apt.conf.d/99xudo-boot <<EOF
Acquire::http::Timeout "30";
Acquire::https::Timeout "30";
Acquire::Retries "2";
EOF
echo "boot: apt-get update"
apt-get update -qq
echo "boot: apt-get install systemd"
apt-get install -y -qq systemd systemd-sysv
rm -f /usr/sbin/policy-rc.d
mkdir -p /etc/systemd/system
for unit in \
    systemd-networkd-wait-online.service \
    apt-daily.timer \
    apt-daily-upgrade.timer \
    apt-daily.service \
    apt-daily-upgrade.service \
    getty@.service
do
    ln -sfn /dev/null "/etc/systemd/system/$unit"
done
echo "boot: exec /sbin/init"
exec /sbin/init
'

# What the container was doing when the boot wait gave up. Printed before the
# container is removed. Each query is bounded: a wedged bus must not add
# another 240s.
dump_boot() {
    echo "---- $image boot diagnostics ----" >&2
    hostpid=$(docker inspect -f '{{.State.Pid}}' "$name" 2>/dev/null || echo 0)
    ps -p "$hostpid" -o args= >&2 || true
    timeout 20 docker exec "$name" systemctl list-jobs --no-pager >&2 2>&1 || true
    timeout 20 docker exec "$name" systemctl --failed --no-pager >&2 2>&1 || true
    timeout 20 docker exec "$name" systemd-analyze blame --no-pager >&2 2>&1 || true
    timeout 20 docker exec "$name" journalctl -b --no-pager -n 80 >&2 2>&1 || true
    docker logs "$name" 2>&1 | tail -40 >&2 || true
}

# One boot. 120 * 2s is the 240s bound. Returns 0 once systemd reports
# running or degraded. Leaves the container in place so a failure can be
# diagnosed. Called from `if`, where `set -e` does not apply.
boot_once() {
    state=missing
    got=
    docker rm -f "$name" >/dev/null 2>&1 || true
    if ! docker run -d --name "$name" \
        --privileged \
        --cgroupns=private \
        --tmpfs /run:rw,nosuid,nodev \
        --tmpfs /run/lock:rw,nosuid,nodev,noexec \
        -v "$deb:/opt/xudo.deb:ro" \
        -v "$short_ttl_deb:/opt/xudo-short-ttl.deb:ro" \
        -v "$root/ci/differential/exec.exp:/opt/exec.exp:ro" \
        -v "$here:/harness:ro" \
        "$image" \
        sh -c "$boot" >/dev/null; then
        echo "boot: $image container did not start" >&2
        return 1
    fi
    i=0
    while [ "$i" -lt 120 ]; do
        state=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)
        if [ "$state" != running ]; then
            echo "boot: $image container is $state" >&2
            return 1
        fi
        got=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
        case $got in
        running | degraded)
            echo "   systemd is $got"
            return 0
            ;;
        esac
        i=$((i + 1))
        sleep 2
    done
    echo "boot: $image systemd did not become running or degraded (last: ${got:-none})" >&2
    return 1
}

fail=0
n=0
for image in $images; do
    n=$((n + 1))
    echo "== $image"
    name=xudo-systemd-$(printf '%s' "$image" | tr ':/' '--')-$$
    booted=
    try=1
    while :; do
        if boot_once; then
            booted=1
            break
        fi
        dump_boot
        docker rm -f "$name" >/dev/null 2>&1 || true
        if [ "$try" -ge 2 ]; then
            if [ "$state" != running ]; then
                echo "FAIL: $image container is $state" >&2
            else
                echo "FAIL: $image systemd did not become running or degraded" >&2
            fi
            fail=1
            name=
            break
        fi
        # The container, not the test case. A failed row is never run again.
        echo "retry: booting $image again" >&2
        try=2
    done
    if [ -z "$booted" ]; then
        continue
    fi

    # Line-buffer: without a tty the row's stdout would arrive in one lump.
    if ! docker exec "$name" stdbuf -oL -eL sh /harness/row.sh; then
        echo "FAIL: row $image" >&2
        fail=1
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    name=
done

if [ "$fail" -ne 0 ]; then
    echo "systemd-test: FAILED ($n images)" >&2
    exit 1
fi
echo "systemd-test: $n images ok"
