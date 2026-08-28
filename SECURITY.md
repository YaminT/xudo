# Security

## Status

**Beta. Not externally audited.** An external security audit is a stated
precondition for 1.0. Until then, do not deploy this where a compromise would
matter.

**This build has no privileged path.** Nothing it contains can execute a command
as root. `classify()` returns `Unattested` for every caller on every platform, so
every request routes to the password path.

## Reporting

Open a private security advisory on the GitHub repository. Please do not open a
public issue for anything that could be exploited.

If you are reporting a design flaw rather than a bug, that is welcome and useful
— the threat model is in `docs/design-plan.md` and the reasoning behind each
control is in `docs/CONCERNS.md`.

## What this does not protect against

Stated plainly, because a control you believe in and do not have is worse than
one you know you lack.

- **Agent detection is not a security boundary.** A same-uid process can forge
  every cheap signal, and a human can ask a genuinely-enrolled agent to run a
  command. Impersonation buys only a skipped password on an already-allowlisted
  action.
- **The deny-list is defence in depth.** The set of programs that can be turned
  into a root shell is not enumerable. It catches a mistake in a rule; it is not
  the boundary.
- **One overbroad allowlist entry voids the design.** A single allowlisted shell,
  interpreter, pager, exec proxy, or `apt-get -o DPkg::Pre-Invoke::=` is
  unrestricted root regardless of how the arguments are written.
- **`aido` cannot protect a host that already has other paths to root.** Run
  `aido doctor`: it reports pre-existing `NOPASSWD` entries, `wheel` / `sudo` /
  `docker` / `lxd` membership, writable unit directories, writable `PATH`
  entries, and writable shell rc files. Any one of them makes `aido` decorative.
- **Rule-file ownership and mode are not yet verified.** Survivable only because
  nothing can execute: a tampered ruleset currently makes `aido explain` print a
  wrong answer to a human who asked a question. This is a stated precondition of
  the privileged path, not a nice-to-have.

## No telemetry

The default build contains no network code. Verifying that mechanically —
a seccomp filter denying `AF_INET` socket creation and a CI job under `strace`
asserting no non-`AF_UNIX` socket — is planned and not yet done.
