#!/usr/bin/env bash
# Installs the built .deb in real Debian and Ubuntu containers and walks it
# through install, upgrade, remove and purge. What each row asserts is in row.sh.
#
#   ci/deb/run.sh <musl triple>          (or: just deb-test, which builds first)
#
# Plain Docker has no running systemd. postinst still enables the socket
# through deb-systemd-helper; deb-systemd-invoke does not start it here.
set -euo pipefail

rows=(ubuntu:24.04 ubuntu:26.04 debian:13)

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <musl triple>" >&2
    exit 2
fi
triple=$1
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
command -v docker >/dev/null || { echo "FAIL: docker is required" >&2; exit 1; }

# The path build.sh prints: xudo_<debian version>_<arch>.deb. Cargo's
# 0.1.0-beta.1 is Debian 0.1.0~beta.1, same mapping as build.sh.
case $triple in
x86_64-*) arch=amd64 ;;
aarch64-*) arch=arm64 ;;
*) echo "unsupported triple $triple" >&2; exit 1 ;;
esac
raw=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$root/Cargo.toml" | head -1)
[ -n "$raw" ] || { echo "FAIL: no version in Cargo.toml" >&2; exit 1; }
deb_ver=$(printf '%s\n' "$raw" | tr '-' '~')
numeric=$(printf '%s\n' "$raw" | sed 's/[-+].*//')
case $numeric in
*.*.*) ;;
*) echo "FAIL: cannot parse version $raw" >&2; exit 1 ;;
esac
patch=${numeric##*.}
case $patch in
'' | *[!0-9]*) echo "FAIL: bad patch in $raw" >&2; exit 1 ;;
esac
dir="$root/target/deb"
deb="$dir/xudo_${deb_ver}_${arch}.deb"
[ -f "$deb" ] || { echo "FAIL: built package not at $deb" >&2; exit 1; }

marker=xudo-lane-short-ttl-20-seconds
command -v dpkg-deb >/dev/null || { echo "FAIL: dpkg-deb is required" >&2; exit 1; }
command -v grep >/dev/null || { echo "FAIL: grep is required" >&2; exit 1; }
package_root=$(mktemp -d "$root/target/deb-check.XXXXXX")
trap 'rm -rf "$package_root"' EXIT
dpkg-deb -x "$deb" "$package_root"
for binary in usr/bin/xudo usr/bin/ido usr/libexec/xudo/xudod usr/libexec/xudo/xudo-gate-auth; do
    f="$package_root/$binary"
    if [ ! -f "$f" ]; then
        echo "FAIL: normal_package_contains_all_binaries (missing $binary)" >&2
        exit 1
    fi
    if grep -aFq "$marker" "$f"; then
        echo "FAIL: normal_package_uses_the_shipped_ttl ($binary contains the short-TTL marker)" >&2
        exit 1
    fi
done
echo "PASS: normal_package_does_not_contain_the_short_ttl_feature"
example="$package_root/usr/share/xudo/examples/20-services-lifecycle.toml"
if [ ! -f "$example" ]; then
    echo "FAIL: lifecycle example missing from /usr/share/xudo/examples" >&2
    exit 1
fi
if [ -e "$package_root/etc/xudo/rules.d/20-services-lifecycle.toml" ]; then
    echo "FAIL: lifecycle example installed into /etc/xudo/rules.d" >&2
    exit 1
fi
if find "$package_root/etc/xudo/rules.d" -name '*lifecycle*' | grep -q .; then
    echo "FAIL: a lifecycle file landed in rules.d" >&2
    exit 1
fi
echo "PASS: lifecycle example is documentation, not a shipped rule"

# old.deb is stamped 0.1.0-beta.1 (Debian 0.1.0~beta.1), whatever Cargo
# says now. postinst warns only when the previous version is below
# 0.1.0~beta.2, so a later version bump must not skip that gate. The
# binaries are the ones just built. new.deb is the next patch, which stays
# newer than 0.1.0~beta.1 after that bump.
rm -rf "$root/target/deb-old"
old=$(VERSION=0.1.0-beta.1 "$root/packaging/deb/build.sh" "$triple" "$root/target/deb-old")
[ -f "$old" ] || { echo "FAIL: beta.1 package not at $old" >&2; exit 1; }
rm -rf "$root/target/deb-upgrade"
up=$(VERSION="${numeric%.*}.$((patch + 1))" "$root/packaging/deb/build.sh" "$triple" "$root/target/deb-upgrade")
[ -f "$up" ] || { echo "FAIL: upgrade package not at $up" >&2; exit 1; }
mkdir -p "$root/target/deb-mount"
rm -f "$root"/target/deb-mount/*
cp "$old" "$root/target/deb-mount/old.deb"
cp "$up" "$root/target/deb-mount/new.deb"

fail=0
for image in "${rows[@]}"; do
    echo "== $image"
    # Debian without Recommends has no systemd-tmpfiles. The others install normally.
    norec=()
    if [[ $image == debian:13 ]]; then
        norec=(-e APT_NO_RECOMMENDS=--no-install-recommends)
        echo "   --no-install-recommends"
    fi
    docker run --rm "${norec[@]}" -v "$root/target/deb-mount:/debs:ro" -v "$here:/harness:ro" \
        "$image" sh /harness/row.sh || { echo "FAIL: row $image" >&2; fail=1; }
done

# lintian runs in Debian, on the built package.
echo "== lintian"
docker run --rm -e DEBIAN_FRONTEND=noninteractive -v "$root/target/deb-mount:/debs:ro" -v "$here:/harness:ro" debian:13 sh -c '
    apt-get update -qq && apt-get install -y -qq lintian >/dev/null &&
    lintian --fail-on warning,error /debs/old.deb' ||
    { echo "FAIL: lintian" >&2; fail=1; }

((fail == 0)) || exit 1
echo "deb-test: ${#rows[@]} rows + lintian clean"
