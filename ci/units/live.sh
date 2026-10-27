#!/usr/bin/env bash
# The broker's unit, run for real: systemd as PID 1 in a container, the socket
# and the service started, connections driven through the socket, and the audit
# trail read back.
#
#   ci/units/live.sh <directory holding the static aidod and aido>   (or: just units-live)
#
# `just units` shows a unit loads and scores well; it cannot show the sandbox
# lets the broker do its job. A `ReadWritePaths=` that misses the trail, a
# system-call filter that refuses `flock`, a trust walk that fails inside the
# namespace systemd builds: each leaves a unit that verifies, scores 1.1, and
# refuses every request. docs/CONCERNS.md (2026-10-21, B1, open items 6 and 10)
# left all three argued rather than measured. This lane measures them.
#
# What is measured, and by what:
#
#   * the sandbox reaches the trail: a permitted request is answered with a
#     minted entry, which the broker answers only after its record is on the
#     trail (aidod::serve), so the answer is the measurement of the log's open,
#     trust walk, lock, write and sync, and of the journal send, all under
#     ProtectSystem=strict and the shipped system-call filter, with
#     SystemCallErrorNumber=EPERM making a filtered call a failed append;
#   * the file is /var/lib/aido/audit.jsonl, 0600 root, in a 0700 root
#     directory tmpfiles made;
#   * the journal holds the same sequence number and hash as each line of the
#     file, from the aidod identifier;
#   * no instance logged EPERM, an untrusted directory, or an unavailable trail,
#     and each exited cleanly;
#   * `aido audit --log` passes on the file, and fails on a copy cut into its
#     last record;
#   * the system-call filter, statically: every call the log writer and the
#     journal sender make is in @system-service and in neither @privileged nor
#     @resources;
#   * the negative control: with /var/lib/aido gone, the same request is
#     answered broker_audit_unavailable and the file is not created, so the
#     "-" on ReadWritePaths is not quietly skipping the trail.
#
# What is not measured: the attested path. M2b classifies every caller
# Unattested (no cgroup classification until M4), so a request from a plain
# process takes the same mint path an enrolled agent will; what a root-created
# aido.slice scope adds is M4's to show.
#
# The container is privileged, because systemd as PID 1 needs to mount and to
# own its cgroup. It is thrown away. Needs Docker and the network.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <directory holding the static aidod and aido>" >&2
    exit 2
fi
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
bins=$(cd "$1" && pwd)
for binary in aidod aido; do
    [[ -x $bins/$binary ]] || { echo "FAIL: $bins/$binary is not built" >&2; exit 2; }
done
if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker is required" >&2
    exit 1
fi

image=aido-units-live:trixie
name="aido-units-live-$$"
stage=$(mktemp -d)
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf "$stage"
}
trap cleanup EXIT

# systemd, and what a client and the checks need, in an image of its own so the
# download happens once. Perl is the client: its Socket module is in the base.
docker build -q -t "$image" - >/dev/null <<'DOCKERFILE'
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::Retries=3 update -qq \
 && apt-get -o Acquire::Retries=3 install -y -qq --no-install-recommends systemd systemd-sysv \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
DOCKERFILE

# What is installed, laid out as the package will lay it out.
install -d "$stage/usr/libexec/aido" "$stage/usr/local/bin" "$stage/etc/systemd/system" \
    "$stage/usr/lib/tmpfiles.d" "$stage/etc/aido/rules.d"
install -m 0755 "$bins/aidod" "$stage/usr/libexec/aido/aidod"
install -m 0755 "$bins/aido" "$stage/usr/local/bin/aido"
install -m 0644 "$root/packaging/systemd/aidod.socket" "$stage/etc/systemd/system/aidod.socket"
install -m 0644 "$root/packaging/systemd/aidod@.service" "$stage/etc/systemd/system/aidod@.service"
install -m 0644 "$root/packaging/tmpfiles.d/aido.conf" "$stage/usr/lib/tmpfiles.d/aido.conf"
cat >"$stage/etc/aido/rules.d/10-live.toml" <<'RULES'
[[action]]
id = "aido.live.probe"
tier = "diag-read"
exe = "/usr/bin/true"
args = [{ name = "verb", matcher = { literal = "probe" } }]
RULES
# The client: one request on the socket, the whole answer on standard output.
cat >"$stage/usr/local/bin/aido-ask" <<'CLIENT'
#!/usr/bin/perl
use strict;
use warnings;
use Socket;
socket(my $s, AF_UNIX, SOCK_STREAM, 0) or die "socket: $!\n";
connect($s, pack_sockaddr_un("/run/aido/broker.sock")) or die "connect: $!\n";
syswrite($s, $ARGV[0]) or die "write: $!\n";
shutdown($s, 1);
local $/;
my $answer = <$s>;
print defined $answer ? $answer : "";
CLIENT
chmod 0755 "$stage/usr/local/bin/aido-ask"
chmod 0755 "$stage/etc/aido" "$stage/etc/aido/rules.d"
chmod 0644 "$stage/etc/aido/rules.d/10-live.toml"

docker run -d --name "$name" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock -e container=docker \
    "$image" /lib/systemd/systemd >/dev/null
# Named top-level directories, never `.`: extracting a `.` entry would hand `/`
# the staging directory's owner, and the broker's trust walk would rightly
# refuse every path under a root directory a user owns.
tar -C "$stage" -cf - usr etc | docker exec -i "$name" tar -xf - -C / --no-same-owner

x() { docker exec "$name" "$@"; }
sh_() { docker exec "$name" sh -c "$1"; }

# Booted means systemd says so; "degraded" is a container with units that cannot
# start in one, and is as booted as this needs.
booted=
for _ in $(seq 1 60); do
    state=$(x systemctl is-system-running 2>/dev/null || true)
    if [[ $state == running || $state == degraded ]]; then booted=$state; break; fi
    sleep 1
done
if [[ -z $booted ]]; then
    echo "FAIL: systemd did not boot as PID 1 in the container" >&2
    docker logs "$name" 2>&1 | tail -n 20 >&2
    exit 1
fi
echo "units-live: $(x systemctl --version | sed -n 1p), system $booted"

fail=0
check() {
    local what=$1
    shift
    if "$@"; then
        echo "  ok    $what"
    else
        echo "  FAIL  $what" >&2
        fail=1
    fi
}

x groupadd --system aido
x useradd --create-home --groups aido aidotest
x systemd-tmpfiles --create
x systemctl daemon-reload
x systemctl start aidod.socket

ask() { x runuser -u aidotest -- /usr/local/bin/aido-ask "$1"; }
PERMITTED='{"schema_version":1,"program":"/usr/bin/true","argv":["probe"],"claimed_classification":"unattested"}'
DENIED='{"schema_version":1,"program":"/bin/sh","argv":["-c","id"],"claimed_classification":"unattested"}'

echo "units-live: the install, as tmpfiles made it"
check "/var/lib/aido is 0700 root" \
    sh_ '[ "$(stat -c "%a %U:%G" /var/lib/aido)" = "700 root:root" ]'
check "the socket is up" x systemctl is-active --quiet aidod.socket

echo "units-live: a permitted request, under the shipped sandbox"
answer=$(ask "$PERMITTED")
echo "$answer"
check "the answer carries a minted nonce" grep -q '"nonce"' <<<"$answer"
check "the entry is in the spool" sh_ '[ "$(ls /run/aido/req | wc -l)" -eq 1 ]'
check "audit.jsonl is 0600 root" \
    sh_ '[ "$(stat -c "%a %U:%G" /var/lib/aido/audit.jsonl)" = "600 root:root" ]'

echo "units-live: a denial"
answer=$(ask "$DENIED")
check "the denial is answered" grep -q '"verdict"' <<<"$answer"
check "a denial mints nothing more" sh_ '[ "$(ls /run/aido/req | wc -l)" -eq 1 ]'

echo "units-live: the file and the journal hold the same records"
x journalctl --sync >/dev/null 2>&1 || true
sleep 1
sh_ "grep -o '\"hash\":\"[0-9a-f]*\"' /var/lib/aido/audit.jsonl | cut -d'\"' -f4 | sort" >"$stage/file-hashes"
sh_ "journalctl -t aidod -o json --no-pager | grep -o '\"AIDO_HASH\":\"[0-9a-f]*\"' | cut -d'\"' -f4 | sort" >"$stage/journal-hashes"
check "two records in the file" [ "$(wc -l <"$stage/file-hashes")" -eq 2 ]
check "every record in the file is in the journal, and nothing else" \
    cmp -s "$stage/file-hashes" "$stage/journal-hashes"

echo "units-live: the instances ran clean"
sh_ "journalctl -u 'aidod@*' --no-pager" >"$stage/instances"
check "each instance exited cleanly" \
    [ "$(grep -c 'Deactivated successfully' "$stage/instances")" -ge 2 ]
check "no EPERM, untrusted directory, or unavailable trail" \
    bash -c "! grep -Eqi 'operation not permitted|EPERM|cannot be trusted|audit_unavailable|AuditUnavailable|Failed with result' '$stage/instances'"
check "no failed unit" bash -c "! docker exec $name systemctl --failed --no-legend | grep -q aidod"

echo "units-live: aido audit --log on the produced trail"
check "passes on the produced trail" x aido audit --log /var/lib/aido/audit.jsonl
sh_ 'cp /var/lib/aido/audit.jsonl /root/cut.jsonl && truncate -s -2 /root/cut.jsonl'
check "fails on a trail cut into its last record" \
    bash -c "! docker exec $name aido audit --log /root/cut.jsonl"

echo "units-live: the system-call filter, statically"
allowed=$(x systemd-analyze syscall-filter @system-service)
privileged=$(x systemd-analyze syscall-filter @privileged)
resources=$(x systemd-analyze syscall-filter @resources)
# The calls the log writer (openat, fstat, newfstatat, flock, write, fsync or
# fdatasync, ftruncate) and the journal sender (socket, setsockopt, sendto) make.
# A name differs by architecture, so each is any of its spellings.
for want in 'openat' 'fstat' 'newfstatat|fstatat64|statx' 'flock' 'write' \
    'fsync' 'fdatasync' 'ftruncate' 'socket' 'setsockopt' 'sendto'; do
    check "$want is allowed" grep -Eqw "$want" <<<"$allowed"
    check "$want is not privileged or resource-limited" \
        bash -c "! grep -Eqw '$want' <<<'$privileged$resources'"
done

echo "units-live: the negative control, with the trail's directory gone"
x rm -rf /var/lib/aido
answer=$(ask "$PERMITTED")
echo "$answer"
check "the same request is refused as broker_audit_unavailable" \
    grep -q 'broker_audit_unavailable' <<<"$answer"
check "the directory was not recreated" sh_ '[ ! -e /var/lib/aido ]'
check "nothing new was minted" sh_ '[ "$(ls /run/aido/req | wc -l)" -eq 1 ]'

if ((fail)); then
    echo "units-live: FAILED" >&2
    exit 1
fi
echo "units-live: the broker's unit reaches the trail under systemd, and fails closed without it"
