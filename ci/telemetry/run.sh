#!/usr/bin/env bash
# Check shipped release binaries under strace and their normal dependency graph.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
triple=${1:?usage: run.sh <musl-triple>}
channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$root/rust-toolchain.toml")
[[ -n $channel ]] || { echo "FAIL: no channel in rust-toolchain.toml" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "FAIL: docker is required" >&2; exit 1; }

# shellcheck source=../lib/machine-lock.sh
. "$root/ci/lib/machine-lock.sh"
take_machine_lock telemetry

docker run --rm -i -v "$root:/src:ro" -v xudo-linux-cargo:/cache/cargo -v xudo-linux-target:/cache/target "rust:${channel}-slim" bash -s -- "$triple" <<'INNER'
set -euo pipefail
triple=$1
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends strace python3 >/dev/null
mkdir -p /work
(cd /src && tar --exclude=./target --exclude=./fuzz/target -cf - .) | tar -xmf - -C /work
chown -R 1000:1000 /work /cache/cargo /cache/target
mkdir -p /work/home /work/tmp
chown -R 1000:1000 /work/home /work/tmp
# xudo's backend plan checks that sudo exists before it contacts the broker.
touch /usr/bin/sudo
chmod 0755 /usr/bin/sudo
run() {
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/local/cargo/bin:/usr/bin:/bin HOME=/work/home \
        CARGO_HOME=/cache/cargo CARGO_TARGET_DIR=/cache/target \
        RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN="$(rustup show active-toolchain | cut -d' ' -f1)" "$@"
}
cd /work
run rustup target add "$triple" >/dev/null
run cargo build --locked --release --target "$triple" -p xudo-bin -p ido-bin -p xudo-gate-bin -p xudod-bin
run cargo tree --locked -e normal --target "$triple" -p xudo-bin -p xudod-bin -p xudo-gate-bin -p ido-bin --prefix none > /work/tree.txt
grep -Eq '^xudo-wire v' /work/tree.txt || { echo "FAIL: shipped dependency tree lacks xudo-wire" >&2; exit 1; }
for crate in reqwest hyper h2 ureq curl isahc attohttpc tokio mio socket2 rustls native-tls openssl quinn tonic; do
    if grep -Eq "^${crate} v" /work/tree.txt; then echo "FAIL: networking crate in shipped dependency tree: $crate" >&2; exit 1; fi
done

trace_one() {
    name=$1 expected=$2
    shift 2
    trace="/work/${name}.trace"
    : > "$trace"
    chmod 666 "$trace"
    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        env -i PATH=/usr/local/cargo/bin:/usr/bin:/bin HOME=/work/home \
        CARGO_HOME=/cache/cargo CARGO_TARGET_DIR=/cache/target \
        RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN="$(rustup show active-toolchain | cut -d' ' -f1)" \
        strace -f -e trace=execve,socket,socketpair,connect -o "$trace" -qq "$@"
    rc=$?
    set -e
    [[ $rc -ne 126 && $rc -ne 127 ]] || { echo "FAIL: $name did not execute (exit $rc)" >&2; exit 1; }
    grep -Fq "execve(\"$1\"" "$trace" && grep -Eq "execve\(\"$1\".*= 0" "$trace" || { echo "FAIL: $name target was not executed" >&2; cat "$trace" >&2; exit 1; }
    if [[ -n $expected ]]; then
        [[ $rc -eq $expected ]] || { echo "FAIL: $name expected exit $expected, got $rc" >&2; exit 1; }
    fi
    families=$(sed -nE 's/.*(socket|socketpair)\((AF_[A-Z0-9_]+|PF_LOCAL|AF_LOCAL),.*/\2/p; s/.*connect\([^,]+, \{sa_family=(AF_[A-Z0-9_]+).*/\1/p' "$trace" | sort -u | tr '\n' ' ')
    echo "telemetry: $name socket families: ${families:-none} (exit $rc)"
}

xudo=/cache/target/$triple/release/xudo
index=0
for args in "--help" "--version" "explain -- /usr/bin/id -u" "why-not --action nope -- /usr/bin/id -u" \
    "check" "list" "doctor" "doctor --json" "config" "config --schema" "agentdoc" "install --dry-run"; do
    index=$((index + 1))
    read -r -a argv <<< "$args"
    trace_one "xudo-$index" "" "$xudo" "${argv[@]}"
done
touch /work/tmp/audit.jsonl
chown 1000:1000 /work/tmp/audit.jsonl
trace_one xudo-audit "" "$xudo" audit --log /work/tmp/audit.jsonl
trace_one xudo-exec 19 "$xudo" exec -- /usr/bin/id -u 2>/work/xudo-exec.stderr
grep -Fq 'broker is unreachable' /work/xudo-exec.stderr || { echo "FAIL: xudo exec did not refuse because the broker is unreachable" >&2; cat /work/xudo-exec.stderr >&2; exit 1; }
grep -Eq 'connect\([^,]+, \{sa_family=AF_UNIX, sun_path="/run/xudo/broker.sock"' /work/xudo-exec.trace || { echo "FAIL: xudo exec did not connect to broker.sock" >&2; cat /work/xudo-exec.trace >&2; exit 1; }

ido=/cache/target/$triple/release/ido
for args in "--help" "queue -- /usr/bin/true" "list" "drop --all"; do
    index=$((index + 1))
    read -r -a argv <<< "$args"
    trace_one "ido-$index" "" "$ido" "${argv[@]}"
done

# Positive control: the exact bad-family filter used below must detect AF_INET.
trace_one inet-control "" /usr/bin/python3 -c 'import socket; socket.socket()'
bad_filter='(^|[[:space:]])(socket|socketpair)\(|connect\('
local_filter='\((AF_UNIX|PF_LOCAL|AF_LOCAL),|sa_family=(AF_UNIX|PF_LOCAL|AF_LOCAL)([ ,}]|$)'
bad=$(grep -E "$bad_filter" /work/inet-control.trace | grep -Ev "$local_filter" || true)
[[ -n $bad ]] || { echo "FAIL: non-local filter missed AF_INET control" >&2; exit 1; }
echo "telemetry: AF_INET control caught by non-local filter"

gate=/cache/target/$triple/release/xudo-gate
cp "$gate" /work/home/xudo-gate-auth
chown 1000:1000 /work/home/xudo-gate-auth
trace_one xudo-gate 19 /work/home/xudo-gate-auth

# Feed xudod a real socketpair on descriptor 0; its expected refusal is fine.
TRIPLE="$triple" python3 - <<'PY'
import json, os, re, socket, subprocess
trace = "/work/xudod.trace"
left, right = socket.socketpair()
proc = subprocess.Popen(
    ["setpriv", "--reuid=1000", "--regid=1000", "--clear-groups",
     "env", "-i", "PATH=/usr/bin:/bin", "HOME=/work/home",
     "strace", "-f", "-e", "trace=execve,socket,socketpair,connect", "-o", trace, "-qq",
     "/cache/target/" + os.environ.get("TRIPLE", "") + "/release/xudod"],
    stdin=right, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
right.close()
request = {
    "schema_version": 1,
    "program": "/usr/bin/id",
    "argv": ["-u"],
    "claimed_classification": "telemetry",
}
left.sendall((json.dumps(request) + "\n").encode())
left.shutdown(socket.SHUT_WR)
left.settimeout(30)
reply = left.recv(4096)
left.close()
out, err = proc.communicate(timeout=15)
if proc.returncode in (126, 127):
    raise SystemExit("FAIL: xudod was not executed")
text = open(trace, encoding="utf-8").read()
if not re.search(r'execve\("/cache/target/[^"]+/release/xudod".*= 0', text):
    raise SystemExit("FAIL: xudod execve missing from trace\n" + text)
if any(f"{call}(AF_INET" in text for call in ("socketpair", "socket")):
    raise SystemExit("FAIL: xudod used AF_INET\n" + text)
families = set(re.findall(r'(?:socket|socketpair)\((AF_[A-Z0-9_]+|PF_LOCAL|AF_LOCAL),', text))
families.update(re.findall(r'connect\([^,]+, \{sa_family=(AF_[A-Z0-9_]+)', text))
print("telemetry: xudod socket families: %s (exit %d)" % (" ".join(sorted(families)) or "none", proc.returncode))
if reply:
    print(reply.decode("utf-8", "replace").strip())
PY
for trace in /work/*.trace; do
    bad=$(grep -E "$bad_filter" "$trace" | grep -Ev "$local_filter" || true)
    if [[ -n $bad && $trace != /work/inet-control.trace ]]; then echo "FAIL: non-local socket family detected in $trace:" >&2; printf '%s\n' "$bad" >&2; exit 1; fi
done
echo "telemetry: no non-local socket families; shipped dependency tree clean"
INNER
