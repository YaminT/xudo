# Security

## Status

**Beta. Not externally audited.** Do not deploy xudo where compromise would
have unacceptable consequences. The CLI, rule format, and service enrollment
may change before 1.0.

The package and plain `xudo install` install only the password-authenticated
gate rule. The passwordless agent path is off until an operator enrolls a
service harness, grants it an exact rule, and explicitly runs
`sudo xudo install --agent-path` on sudo or sudo-rs. OpenDoas does not support
that opt-in path. Enrollment alone grants no command. The session way (a
harness running in the human's own account) is parsed and loaded but has no
start command. A session harness shares the human's uid: at
`kernel.yama.ptrace_scope = 0`, a process of that uid can read a typed
password, `xudo watch` accepts a same-uid watcher on another tty, and a
registry entry can name the human's account. Run harnesses as separate service
accounts. `--raise-ptrace-scope` takes effect only after `sudo sysctl --system`
or reboot.

## Security boundary

The policy boundary is the root-owned rules and their argument matchers. The
compiled-in deny-list is defense in depth; the broker and gate both check
policy. A
passwordless run additionally requires kernel-attested membership in a live
root-created cgroup scope, a matching root-owned harness registry entry, an
exact rule for that harness, and the installed opt-in backend rule. Caller
names, environment variables, command-line text, and process ancestry are
audit hints only. Any missing, stale, unreadable, or mismatched state fails
closed.

The deny-list is defense in depth; it cannot enumerate every program or
configuration that can become a root shell. Keep rules narrow and review every
argument matcher. `path-under` is a lexical comparison, not filesystem
containment, and must not be used for a program that opens an argument path as
root. The `remove-path` operation is separate: it walks a fixed configured
tree with ownership checks and depth and entry-count bounds.

The service account and its systemd scope authenticate the harness; they do not
confine malicious code inside the account. Do not give that account unrelated
privileges or credentials it should not use. xudo does not provide Landlock
confinement. The account's access to files, networks, and services remains a
host configuration responsibility.

## Limits

- xudo controls only requests routed through xudo. `sudo`, root shells,
  privileged groups, daemons, containers, and other host mechanisms remain
  separate paths to root. `xudo doctor` reports paths it can inspect but
  cannot prove that no other path exists.
- A root user or compromised kernel can alter xudo, its rules, registry, queue,
  service, or audit state. The hash-chained audit file and journal copies can
  expose some edits; they are not an external trust anchor or protection from
  malicious root.
- Audit hints include a bounded, caller-controlled `argv[0]`, argument count,
  and argument length, but no later arguments and no digest. A process can
  rewrite its title, and a failed read is recorded as `unavailable`. Hints
  never change an authorization decision.
- A reviewer must make human decisions outside the requesting process tree.
  Root-held `ask-human` entries are written by the broker and read through it;
  the requester can see its own entry but cannot edit, claim, release, or
  answer it. `ido` asks the broker to release or run an entry; it does not
  rewrite queue files. The reviewer rechecks policy and enters the host
  backend's password before a queued command runs.
- Root's thaw lifts every freeze marker. A reviewer's thaw removes only their
  uid marker, not `frozen-h-<label>`. An attested harness cannot freeze or thaw;
  a harness account outside its scope can freeze its own uid marker. Only
  `sudo xudo thaw` lifts a harness marker.
- A broad rule can grant broad root access. Rule packs are previewed and bound
  to the reviewed bytes and policy generation; installation still requires a
  root reviewer. Read the preview, especially any GTFOBins waiver.
- The system uses systemd and journald on Debian 13, Ubuntu 24.04, and Ubuntu
  26.04, amd64 and arm64. Other releases and distributions are not supported.

The broker and gate both fail closed on policy, registry, queue, or audit
errors. That can make xudo unavailable until an operator fixes the host; it
does not grant a fallback command.

## Reporting a vulnerability

Open a **private security advisory** in the GitHub repository. Do not open a
public issue for anything that could be exploited. Include the affected
version, host and backend, the exact rule and request shape, and a minimal
reproduction that does not expose real credentials or customer data.

Design feedback is welcome as well. The product invariants are in
[`howiwork.md`](howiwork.md); a report that identifies a violation of one of
them is especially useful.
