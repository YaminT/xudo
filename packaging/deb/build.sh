#!/bin/sh
# Builds xudo_<version>_<arch>.deb from the static musl binaries.
#
#   packaging/deb/build.sh <musl triple> [outdir]      (or: just deb)
#
# VERSION overrides the workspace version (the upgrade test builds a second one).
# Run `cargo build --release --target <triple>` for the four binaries first.
set -eu
umask 022
# conffiles and md5sums are sorted: the order must not depend on the locale.
export LC_ALL=C
triple=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
out=${2:-$root/target/deb}
case $triple in
x86_64-*) arch=amd64 ;;
aarch64-*) arch=arm64 ;;
*) echo "unsupported triple $triple" >&2; exit 1 ;;
esac
# Cargo's spelling, hyphen included. CHANGELOG headings use this text.
# The rewrite below is only for the Debian version, so match the notes first.
cargo_version=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)}
# A hyphen starts a Debian revision, so 0.1.0-beta.1 would sort above 0.1.0.
# Tilde stays in the upstream version and sorts before the final release.
version=$(printf '%s\n' "$cargo_version" | tr '-' '~')
bin=${XUDO_BUILD_BIN_DIR:-$root/target/$triple/release}
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 0)}
export SOURCE_DATE_EPOCH=$epoch

stage=$out/stage
rm -rf "$stage"
mkdir -p "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/libexec/xudo" \
    "$stage/usr/lib/systemd/system" "$stage/usr/lib/tmpfiles.d" \
    "$stage/etc/xudo/rules.d" \
    "$stage/usr/share/doc/xudo" "$stage/usr/share/man/man1" "$stage/usr/share/man/man5"
mkdir -p "$stage/usr/share/xudo"

install -m 0755 "$bin/xudo" "$bin/ido" "$stage/usr/bin/"
ln "$stage/usr/bin/ido" "$stage/usr/bin/willyoumarryme"
printf '.so man1/ido.1\n' | gzip -9n >"$stage/usr/share/man/man1/willyoumarryme.1.gz"
install -m 0755 "$bin/xudod" "$stage/usr/libexec/xudo/"
# Only the -auth name: the passwordless gate is not in this package at all.
install -m 0755 "$bin/xudo-gate" "$stage/usr/libexec/xudo/xudo-gate-auth"
install -m 0644 "$root"/packaging/systemd/* "$stage/usr/lib/systemd/system/"
install -m 0644 "$root/packaging/tmpfiles.d/xudo.conf" "$stage/usr/lib/tmpfiles.d/"
install -m 0644 "$root"/rules/*.toml "$stage/etc/xudo/rules.d/"
# The lifecycle example is documentation. `rules/*.toml` does not match
# `rules/examples/*.toml.example`, and this name is what an operator copies
# into rules.d. It is not a conffile.
mkdir -p "$stage/usr/share/doc/xudo/examples"
install -m 0644 "$root/rules/examples/20-services-lifecycle.toml.example" \
    "$stage/usr/share/doc/xudo/examples/20-services-lifecycle.toml"
mkdir -p "$stage/usr/share/lintian/overrides"
install -m 0644 "$root/packaging/deb/lintian-overrides" "$stage/usr/share/lintian/overrides/xudo"
install -m 0644 "$root/README.md" "$root/SECURITY.md" "$root/packaging/deb/copyright" \
    "$stage/usr/share/doc/xudo/"
install -m 0644 "$root/packaging/deb/first-install-notice" "$stage/usr/share/xudo/first-install-notice"
{
    printf 'xudo (%s) unstable; urgency=low\n\n' "$version"
    # A VERSION override (the upgrade package) has no changelog section.
    awk -v ver="$cargo_version" '
        function heading(line, prefix, rest) {
            prefix = "## " ver
            if (index(line, prefix) != 1) return 0
            rest = substr(line, length(prefix) + 1)
            return rest == "" || substr(rest, 1, 1) == " "
        }
        function wrap(prefix, text, width, cut, part) {
            width = 78 - length(prefix)
            while (length(text) > width) {
                cut = width
                while (cut > 1 && substr(text, cut, 1) != " ") cut--
                if (cut == 1) cut = width
                part = substr(text, 1, cut)
                sub(/[[:space:]]+$/, "", part)
                print prefix part
                text = substr(text, cut + 1)
                sub(/^[[:space:]]+/, "", text)
                prefix = sprintf("%*s", length(prefix), "")
                width = 78 - length(prefix)
            }
            print prefix text
        }
        heading($0) { active = 1; found = 1; next }
        /^## / && active { exit }
        !active { next }
        /^### / { wrap("  * ", substr($0, 5)); next }
        /^- / { wrap("    - ", substr($0, 3)); next }
        /^  / { sub(/^[[:space:]]+/, ""); wrap("      ", $0); next }
        END { if (!found) print "  * Release of this version." }
    ' "$root/CHANGELOG.md"
    printf '\n -- YaminT <YaminT@users.noreply.github.com>  %s\n' \
        "$(date -u -d "@$epoch" '+%a, %d %b %Y %H:%M:%S +0000')"
} | gzip -9n >"$stage/usr/share/doc/xudo/changelog.gz"
for m in "$root"/docs/man/*.1; do gzip -9n <"$m" >"$stage/usr/share/man/man1/$(basename "$m").gz"; done
for m in "$root"/docs/man/*.5; do gzip -9n <"$m" >"$stage/usr/share/man/man5/$(basename "$m").gz"; done

sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" "$root/packaging/deb/control" >"$stage/DEBIAN/control"
install -m 0755 "$root/packaging/deb/postinst" "$root/packaging/deb/prerm" \
    "$root/packaging/deb/postrm" "$stage/DEBIAN/"
(cd "$stage" && find etc -type f | sed 's|^|/|' | sort) >"$stage/DEBIAN/conffiles"
(cd "$stage" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z | xargs -0 md5sum >DEBIAN/md5sums)

# Normalise mtimes so two builds of one commit match.
find "$stage" -exec touch -h -d "@$epoch" {} +
# Drop older builds so a caller cannot pick a stale .deb by listing the directory.
rm -f "$out"/xudo_*.deb
deb=$out/xudo_${version}_${arch}.deb
dpkg-deb --build --root-owner-group -Zxz "$stage" "$deb" >/dev/null
echo "$deb"
