# Changelog

All notable changes to xudo are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

- The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a regular file, so stock Ubuntu 26.04 verifies.

## 0.1.0-beta.1 - 2026-11-10

### Added

- M3 out-of-band confirmation through `xudo watch`, including pending
  requests, freeze and thaw controls, and per-user and global watch quotas.
- Strict wire-message parsing and a journald-only `audit_sink` setting.
- Linux command-line policy inspection, rule checking, configuration schema,
  host diagnostics, audit verification, and agent documentation generation.
- A root broker, a password-authenticated gate, a one-use request flow, and a
  tamper-evident authorization audit trail.
- A single Debian package for xudo and ido, with a systemd socket-activated
  broker and password-only sudo integration.
- Container coverage for package install, upgrade, removal, purge, and the
  installed password and gate path on Debian 13, Ubuntu 24.04, and Ubuntu 26.04.
- Pasban's daily root timer verifies the audit chain and compares the file with
  journald copies by hash. It detects removed tails, cut-and-continued files,
  and forged chains the journal did not observe. It does not prevent root from
  changing both sources or record command outcomes.

### Security

- Human confirmation is disabled by default (`confirm_human_path=false`); every
  request continues to use the host password path.
- `just telemetry` runs the strace no-telemetry check, also run by the CI job
  "no telemetry".
- Every request uses the human password path. Out-of-band confirmation through
  `xudo watch` is built and off by default. The passwordless agent path and
  Landlock confinement are not in this beta.
- No release has been published. The release workflow signs the package with
  cosign keyless signing when a version tag is pushed.
- Install probe reports `installed, but NOT VERIFIED` on doas and on
  multicall-coreutils systems such as stock Ubuntu 26.04 and Alpine. The
  Ubuntu 26.04 systemd and differential lanes install GNU `id`. Those passes
  do not show probe support for uutils `/usr/bin/id`.
- The audit trail records authorization, not outcomes.
