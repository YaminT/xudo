# Changelog

All notable changes to xudo are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

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

- Every request uses the human password path. The passwordless agent path,
  out-of-band confirmation, and Landlock confinement are not in this beta.
- The package and beta release have not been published; release signing is not
  yet available.
- Install probe reports `installed, but NOT VERIFIED` on doas and on
  multicall-coreutils systems such as stock Ubuntu 26.04 and Alpine. The
  Ubuntu 26.04 systemd and differential lanes install GNU `id`. Those passes
  do not show probe support for uutils `/usr/bin/id`.
- The audit trail records authorization, not outcomes.
