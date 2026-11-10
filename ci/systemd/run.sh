#!/bin/sh
# The installed .deb with the broker under real systemd, one container per
# distribution. systemd is PID 1: the image installs systemd and systemd-sysv,
# then execs /sbin/init. Privileged lets it manage its own private cgroup namespace.
# Nothing else on the host is changed. ci/systemd/row.sh asserts inside.
#
#   ci/systemd/run.sh <musl triple>       (or: just systemd-test)
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
[ -f "$deb" ] || { echo "FAIL: built package not at $deb" >&2; exit 1; }

# Debian 13, Ubuntu 24.04, and Ubuntu 26.04. 26.04 stays while it boots the
# same way; row.sh reports a distro that cannot verify.
images=${XUDO_SYSTEMD_IMAGES:-"debian:13 ubuntu:24.04 ubuntu:26.04"}
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
boot='
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq systemd systemd-sysv
rm -f /usr/sbin/policy-rc.d
exec /sbin/init
'

fail=0
n=0
for image in $images; do
    n=$((n + 1))
    echo "== $image"
    name=xudo-systemd-$(printf '%s' "$image" | tr ':/' '--')-$$
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" \
        --privileged \
        --cgroupns=private \
        --tmpfs /run:rw,nosuid,nodev \
        --tmpfs /run/lock:rw,nosuid,nodev,noexec \
        -v "$deb:/opt/xudo.deb:ro" \
        -v "$root/ci/differential/exec.exp:/opt/exec.exp:ro" \
        -v "$here:/harness:ro" \
        "$image" \
        sh -c "$boot" >/dev/null

    ready=
    i=0
    while [ "$i" -lt 120 ]; do
        state=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)
        if [ "$state" != running ]; then
            echo "FAIL: $image container is $state" >&2
            docker logs "$name" 2>&1 | tail -40 >&2 || true
            fail=1
            break
        fi
        got=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
        case $got in
        running | degraded)
            echo "   systemd is $got"
            ready=1
            break
            ;;
        esac
        i=$((i + 1))
        sleep 2
    done
    if [ -z "$ready" ]; then
        if [ "$fail" -eq 0 ] || [ "$state" = running ]; then
            echo "FAIL: $image systemd did not become running or degraded" >&2
            docker logs "$name" 2>&1 | tail -40 >&2 || true
            fail=1
        fi
        docker rm -f "$name" >/dev/null 2>&1 || true
        name=
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
