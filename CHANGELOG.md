# Changelog

All notable changes to xudo are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Security

- v0.1.0-beta.1 accepted `systemctl` start, stop, and restart of power,
  reboot, rescue, kernel-module, filesystem-template, and broker-socket
  units for any caller who could pass the password gate. The filesystem
  templates on the deny-list are `systemd-fsck@`, `systemd-growfs@`,
  `systemd-makefs@`, and `mdadm*@`. A `.mount` unit is not on that list, and
  `unit-name` accepts it. The tripwire is a name list: an alias or a unit
  that is not enumerated gets past, and the enumeration is the boundary.
  The shipped rule set no longer contains a service lifecycle rule. Copy
  `/usr/share/xudo/examples/20-services-lifecycle.toml` to
  `/etc/xudo/rules.d/` and list the units that host should expose.
  `xudo check` and `xudo doctor` note the omission. The compiled-in deny-list
  still refuses those names, plus the systemd power and sleep services,
  `debug-shell`, runlevel aliases, firewall and time-sync units, and the
  journal units, on a verb that starts, stops, signals, or otherwise acts,
  including when an operator's rule names one of them. A read-only verb is
  not refused because of the unit name.
  If dpkg asked about `/etc/xudo/rules.d/20-services.toml` during the
  upgrade and you kept your version, you still have the beta.1 rule: run
  `xudo check`, and replace its `unit-name` with a `one-of` list of your
  units. `xudo check` exits 21 for that rule, and `xudo doctor` prints the
  same sentence. The package upgrade prints it when the kept file still
  contains `xudo.svc.lifecycle`.
- `systemctl poweroff`, `reboot`, `halt`, `kexec`, `suspend`, `hibernate`,
  `hybrid-sleep`, `suspend-then-hibernate`, `soft-reboot`, `rescue`,
  `emergency`, `default`, and `exit` are refused with any arguments.
  `isolate` is refused for every target. `systemd-exit.service` is refused
  with the other power services: its unit file sets `SuccessAction=exit-force`.
- `systemd-journald` followed by `-`, `.`, or `@` is the journal for any
  continuation. `systemd-journald-audit.socket` was not refused.
- Read-only `systemctl` verbs (`status`, `show`, `is-active`, `is-failed`,
  `is-enabled`, `cat`, and the `list-*` queries) are not refused just
  because the unit is on the tripwire. Nothing changed for diagnostics:
  `xudo.svc.status` and `xudo.svc.show` of `xudod`, the journal, chrony,
  nftables, apparmor, and auditd still run. A verb that starts, stops, or
  signals the unit is still refused, and a power subcommand is still refused.
- The unit name list also refuses `umount.target`, `final.target`,
  `rescue.service`, `emergency.service`, `syslog.socket`, the timesyncd
  alias `dbus-org.freedesktop.timesync1.service`, `systemd-repart.service`,
  and `systemd-sysctl.service`. Each of those exists on Debian 13, Ubuntu
  24.04, or Ubuntu 26.04 (`systemd-repart` only on Ubuntu 24.04).
  `systemd-sysctl` applies sysctl files at boot and uses the same class as
  a file-driven sysctl flag. `systemd-tmpfiles-*` and `logrotate.service`
  were left off: they run programs whose names are already refused.
  `syslog.service`, `ntp.service`, `ntpsec.service`, `iptables.service`,
  `systemd-mkswap@`, and `systemd-cryptsetup@` had no unit file on those
  three images.
- Package-manager config redirects are matched per tool. apt long options
  are case-insensitive and a short cluster is scanned for `c` or `o`.
  sysctl also refuses `-f` and a prefix of `--load` or `--system`. dnf,
  yum, zypper, pacman, and dpkg use their own option names. This is defence
  in depth: the shipped rules still only name apt-get, and their positions
  are literals.
- The install rule accepted a package name ending in `-` (`apparmor-`),
  which `apt-get install` reads as a request to remove that package, skipping
  the confirmation the remove rule demands. `deb-name` and `apk-name` now
  reject a trailing `-`. The install rule also requires `--no-remove`, so an
  install that would remove a conflicting package is refused; the operator
  removes that package with the remove rule. A trailing `+` stays accepted
  by `deb-name`: `g++` and `libstdc++6` are real names, and `pkg+` on
  `apt-get install` is harmless.
- apt-get reads a package name containing `.` or `+` that is not an exact
  cache hit as an unanchored regular expression. On install that can select
  many packages and cannot remove one, because the install rule requires
  `--no-remove`, so `deb-name` is unchanged there. On remove one confirmed
  token such as `lib.` could remove hundreds of packages, and a trailing
  `+` installs. The remove rule now uses `deb-name-literal` (`deb-name`, and
  no `.` and no `+` anywhere). A package whose name contains either
  (`python3.12`, `g++`, `libstdc++6`) can no longer be removed through xudo.
  Remove it with the host's own tools, or add an operator rule that lists
  that name with `one-of`. The ruleset generation changes, so an approval
  already minted is no longer valid.
- The audit appender wrote a record with `write_all`. A caller who set
  `RLIMIT_FSIZE` just past the log made the first `write` return a short
  count and the next one raise `SIGXFSZ`, which killed the gate before the
  torn tail could be cut back. The broker and every later gate then refused
  the damaged log. An append is now one `write`. On this `RLIMIT_FSIZE`
  route a short count is a failure and the existing cut-back runs, so the
  request is denied and the log stays intact. `EINTR` (which writes nothing)
  is tried once more; a second interrupt is a failure too. This holds for
  `RLIMIT_FSIZE` only. `SIGXFSZ` and `SIGXCPU` are core-dump signals and are
  not delivered between the pages of one `write`, so they do not tear a
  record. `SIGTERM`, `SIGHUP` and `SIGINT` still can, when the record crosses
  a page boundary; the caller can steer that length through argv, and sudo
  relaying a signal (or the pty hanging up) can deliver it. That route
  predates this fix. xudo stays down until an operator moves the log aside.
  Blocking signals around the write is a later change.

### Added

- Executable `[[test]]` tables in rule files, run by `xudo check` and by the
  build. A test never changes a decision and is not part of the ruleset
  generation.
- `xudo check --fuzz [--fuzz-budget N] [--fuzz-seed S]`: a bounded,
  deterministic differential fuzz of the loaded ruleset that cross-checks the
  overlap report and the standing invariants; a finding is a lint error (21).

### Changed

- **Breaking:** `xudo check` exit codes. Overlapping actions now exit 20 (was
  0), the shell-allowlist lint exits 21 (was 17), and a failing rule test exits
  22. A failing test ranks above a lint error when one run finds both.
- The ruleset generation is hashed from a canonical encoding of each action
  (framing v2), and a rule file with no actions is no longer part of it. Every
  approval in flight when xudo is upgraded is invalidated once; retry the
  request.
- A rule file may carry at most 4096 `[[test]]` tables, and a ruleset at most
  16384 in all; more fails to load.

### Compatibility

- The shipped rules carry `[[test]]` tables, which a 0.1.0-beta.1 binary
  rejects as an unknown key. Downgrading xudo below this version while keeping
  the new rules denies everything until the rules are downgraded with it.

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
- Install probe reports `installed, but NOT VERIFIED` on doas and on a
  multicall-coreutils system with no regular probe program, such as Alpine.
- The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a
  regular file, so stock Ubuntu 26.04 verifies.
- The audit trail records authorization, not outcomes.
