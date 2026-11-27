# Security

## Status

**Beta. Not externally audited.** Do not deploy xudo where compromise would
have unacceptable consequences. The CLI, rule format, and service enrollment
may change before 1.0.

The package and plain `xudo install` install only the password-authenticated
gate rule. The passwordless agent path is off until an operator enrolls a
service harness, grants it an exact rule, and explicitly runs
`sudo xudo install --agent-path` on sudo or sudo-rs. OpenDoas does not support
that opt-in path. Enrollment alone grants no command. Session start and attach
for a harness running as a logged-in user's account are not implemented.

## Security boundary

The authorization boundary is the combination of root-owned rules, the
compiled-in deny-list, and the broker and gate's independent checks. A
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
- Audit hints are bounded and do not contain raw command arguments or a digest
  of them. Some process details are unavailable to the unprivileged broker.
  Hints never change an authorization decision.
- A reviewer must make human decisions outside the requesting process tree.
  Root-held `ask-human` entries are written by the broker and read through it;
  the requester cannot answer or edit them. The reviewer rechecks policy and
  enters the host backend's password before a queued command runs.
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
