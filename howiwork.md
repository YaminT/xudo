# howiwork.md — the source of truth

This file describes the product that ships in xudo `0.1.0-beta.2`. The README,
site, man pages, and generated harness instructions derive from it. Keep their
claims consistent with this file and with the implementation.

## What xudo does

xudo is a Linux privilege broker for AI harnesses. A harness calls `xudo exec`
with a program and its exact argument vector. xudo checks the request against
root-owned rules and a compiled-in deny-list, then either runs it, queues it for
a human, or refuses it. The host's `sudo`, `sudo-rs`, or `doas` performs the
uid transition. xudo has no setuid binary.

The default install grants no passwordless execution. A verified, registered
harness can run a rule-allowed command without a password only when an operator
also enables the opt-in agent path. A normal human request uses the host's
password-authenticated path. An `ask-human` harness request enters a root-held
queue; a separate reviewer uses `ido` to review it and run it through the
password-authenticated path.

## The three invariants

1. **Agent detection is not a security boundary.** Authorization comes only from kernel-attested facts (`SO_PEERPIDFD` + a root-created cgroup scope under `xudo.slice`). `CLAUDECODE`, `argv[0]`, `comm`, `cmdline`, `/proc/<pid>/exe`, and process ancestry are *unauthenticated hints*: record them in the audit trail, never branch authorization on them. A **verified harness** means exactly two things together: the kernel attests the caller is inside a live root-created scope, and a root-written registry entry names that scope's harness. Never a program name, an environment variable, or anything the caller sends.
2. **No caller gets passwordless root by mistake or by default.** A command runs without a password only when the kernel attests the caller is inside a root-registered harness scope **and** a root-written rule allows that exact command for that harness. Everything else (a human, an unattested caller, a process that left its scope, a command no rule allows) takes the human path, where the machine's own `sudo` asks the password, or is denied. Misclassification may only withhold. Nothing the agent may run is closed to the human path.
3. **A human decision is made where the requester cannot answer it.** Anything that needs a human (an `ido` entry, or the optional `xudo watch` check on the human path) is decided by the human on a channel the requesting process tree cannot answer: never from its stdin, stdout, or `/dev/tty`. "Needs a human" never resolves by itself; with no human, it does not run.

## Components and trust

- `xudo` is the unprivileged CLI used by people and harnesses.
- `xudod` is the root broker. It authenticates the connected process from
  kernel facts, checks root-owned policy, writes the audit trail, and manages
  the root-held review queue.
- `xudo-gate` is the separately invoked root executor. It independently checks
  the request and current policy, consumes the one-use request, and executes
  the validated file descriptor.
- The host privilege backend performs the uid transition. The `-auth` gate
  always follows the password path. The `-nopass` gate works only for an
  attested harness with a matching rule and only if root has explicitly
  installed its backend rule.
- `ido` reads the broker queue through the broker and lets a reviewer claim and
  run an entry. The requester cannot answer or edit this root-held queue.

Authorization relies on a connected Unix socket peer and the kernel's
pidfd/cgroup evidence, plus a root-owned harness registry. User-controlled
names, environment, process ancestry, and command-line hints do not authorize.
The broker and gate both make decisions; any mismatch, stale generation,
missing state, or error fails closed.

## Harness enrollment and passwordless execution

The shipped enrollment path is the **service way**. An operator runs
`sudo xudo agent enrol LABEL --account ACCOUNT --reviewer USER -- PROGRAM ARGS`
for an existing dedicated account. Enrollment checks the account and its
privilege paths, then creates a root-owned registry record, a systemd service
drop-in, and a private environment file, adds the account to xudo's groups, and
enables `xudo-agent@LABEL.service`. Credentials for the harness may be stored
in the root-only environment file. Enrollment itself authorizes no command.

Only a process running inside the live scope created by that root-managed unit,
with a matching registry record, is a verified harness. A similarly named
process or an SSH login as the service account is not enough. Root-created
cgroups and registry state are the authentication basis; display names are not.

Session start and attach for a harness running as a logged-in human are not
implemented. There is no laptop/session enrollment path in this beta.

The package and plain `xudo install` install only the password-authenticated
backend rule. After enrollment and after installing rules that grant the
harness, an operator may opt in on sudo or sudo-rs hosts with
`sudo xudo install --agent-path`. This writes the narrowly scoped passwordless
rule for the agent group and the no-argument helper. The helper still rejects
unattested callers. OpenDoas does not support this agent-path installation.
An upgrade or plain `xudo install` turns the agent path off. `--uninstall`
removes only exact files xudo manages; an edited ptrace-scope file is left in
place with a warning.

## Rules and outcomes

Rules are TOML files owned by root under `/etc/xudo/rules.d`. Each action names
one absolute executable and constrains its arguments position by position
using typed matchers. A harness allow requires both an exact command match and
the harness label in the rule. The compiled-in deny-list is evaluated after
allow matching and cannot be overridden by rules. `path-under` is lexical
only; it does not enforce filesystem containment for programs that open paths
as root.

There are three outcomes:

1. **Allow.** A matching rule may run for a verified harness. It runs without
   a password only if the opt-in agent path is installed. Everyone else takes
   the human path or is refused.
2. **Ask human.** A matching `outcome = "ask-human"` rule for a verified,
   listed harness places the request in the broker's root-held queue. A
   configured reviewer sees it in `ido`, reviews it, and runs it with
   `xudo exec --queued ID`. The broker rechecks the saved request against the
   current rules, then the host asks for the reviewer's password. Queue entries
   are bounded, expire, and are invalidated when relevant policy changes.
   The requester cannot list, edit, claim, approve, or answer its own entry.
3. **Deny.** A deny rule, the compiled-in deny-list, a missing match, a failed
   check, or a required human decision with no available human stops the
   request. Denied commands never run.

Human requests that match ordinary allow rules use the password-authenticated
gate. The optional `xudo watch` flow can provide an extra human confirmation
where policy requires it; it is not required for the passwordless harness
path. No agent can answer a human confirmation from its own terminal or
process tree.

### Typed `remove-path`

The `remove-path` operation is performed by xudo itself, not by running `rm`.
The rule fixes the allowed tree. The implementation enforces ownership and
trust of the path's ancestors, refuses mount boundaries, and bounds the walk
by depth and entry count; it does not follow symlinks. Harness rules can grant this typed operation with
the same verified-harness and optional passwordless gates. The shipped example
is `rules/examples/50-remove-path.toml.example`.

## Rule packs

A rule pack is a local TOML file with a `[pack]` header. `xudo rules add FILE`
previews the policy and effects without writing. The preview returns a token
bound to the reviewed pack bytes, the current rule set and registry generation,
and the selected waiver setting. A reviewer installs it by passing that token
back with `sudo xudo rules add FILE --reviewed TOKEN`; the root side recomputes
the review and refuses if anything changed. Packs are not downloaded or
updated automatically. Removal uses the same preview and review token flow.

## G1 rate ledger, freeze, and audit limits

The passwordless gate keeps a root-owned rate ledger keyed by account and
harness under `/run/xudo/rate`. Every invocation counts, including a refusal.
It allows at most 60 invocations in a minute and 600 retained stamps in an
hour; reaching a ceiling refuses the request and records the refusal with
bounded coalescing. A missing, corrupt, unreadable, or busy ledger also
refuses the request. Root can freeze all harnesses; a user can freeze that
user's own harness. Harnesses cannot freeze or thaw. The broker, gate, queue,
freeze controls, and decision records use bounded root-owned state.

The audit trail is hash-chained and the system journal receives root-written
records. `xudo audit --against-journal` can compare the local file to the
journal records it can read. This is tamper evidence, not an external audit or
a guarantee against a malicious root user. Audit hints are bounded and
audit-only: xudo does not store raw arguments or a digest of them. Hints may be
unavailable for processes the broker cannot inspect.

## Install and supported hosts

The supported package targets are Debian 13, Ubuntu 24.04 LTS, and Ubuntu
26.04 LTS, on amd64 and arm64. The service broker uses systemd and journald.
Other distributions and releases are not supported.

Download the `.deb`, `SHA256SUMS`, and its `.cosign.bundle` from the matching
GitHub Release. Check the checksum and verify the package signature against the
release workflow identity before installation. GitHub renders `~` as `.` in
the Debian package filename; use this checksum command:

```sh
sed 's/~/./' SHA256SUMS | sha256sum -c --ignore-missing
cosign verify-blob --bundle xudo_<ver>_<arch>.deb.cosign.bundle \
  --certificate-identity https://github.com/YaminT/xudo/.github/workflows/release.yml@refs/tags/<tag> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  xudo_<ver>_<arch>.deb
sudo apt install ./xudo_<ver>_<arch>.deb
```

Replace `<ver>`, `<arch>`, and `<tag>` with the package version, `amd64` or
`arm64`, and Git tag shown by the release. xudo has no `curl | sh` installer.

## Limits

This is beta software and has not had an external security audit. xudo protects
only commands routed through xudo; it does not remove other ways to obtain
root. `xudo doctor` reports paths it can inspect, but cannot prove that no
other root path exists. The deny-list is defense in depth; narrow root-owned
rules are the policy boundary. `path-under` does not provide filesystem
containment. Landlock confinement and an external audit are not implemented.

For the security reporting route and details of the limits, see
[`SECURITY.md`](SECURITY.md).
