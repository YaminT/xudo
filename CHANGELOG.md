# Changelog

All notable changes to xudo are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

### Added

- `xudo op remove-path <target>` removes a path under an `[[operation]]` rule
  through the password-authenticated gate. `--dry-run` lists the paths and
  removes nothing. A `harness` label on the rule is parsed and checked against
  the registry and is not a grant. Harness use of this operation is planned.
  The passwordless gate is not in this release.

### Changed

- Ask-human rules now use denial code `ask_human` and send a verified, explicitly listed harness request to the broker's root-held queue by default. The queue stores byte-exact argv and cwd, enforces per-uid and global bounds, uses boottime expiry, and returns entries only to their owner for status or to a Human-classified configured reviewer. Human-path denials are no longer written into the caller-owned `ido` queue. A human reviewer runs a queued entry with `xudo exec --queued ID`: the broker re-decides the stored argv, the password gate runs it in `/`, and the entry is completed only from that gate's audit record. `ido` lists the root-held queue separately from the agent-editable user queue. The passwordless gate is not in this release.
- `ido list --json` always prints one JSON object with `user` (the previous user-queue array), `root_held`, and `root_queue_unavailable`, including when the root-held list is empty.

### Security

- A harness registry whose reviewer is the account or a user of any harness (its own or another's) now fails to load. Such a reviewer could approve what its own agent queued. Tests `a_reviewer_that_is_a_harness_account_fails_to_load`, `a_reviewer_that_is_a_harness_user_fails_to_load`, `a_reviewer_overlapping_another_harness_fails_to_load`, `disjoint_reviewers_load_across_harnesses`. The error names the harness that owns the clashing account. The queue also compares uids at request time, so a reviewer who shares a uid with a harness account under another name is refused (`an_alias_reviewer_with_a_harness_accounts_uid_is_refused`, `a_reviewer_with_a_distinct_uid_is_still_allowed`).
- `xudo freeze` and `xudo thaw` now classify the caller against the real harness registry. They used an empty one, so an enrolled agent counted as unattested and could lift its owner's freeze. Tests `an_enrolled_agent_cannot_thaw_its_owners_freeze_through_the_broker`, `an_enrolled_agent_cannot_freeze_or_thaw_others`.
- A non-root `xudo thaw` is now refused for an unattested caller and for any caller whose uid is the account or a user of any registered harness (`ChannelUntrusted`, "use `sudo xudo thaw`"). "Outside any agent scope" is not "a human": an agent can start a process outside its scope as its own uid, so only root, or `sudo xudo thaw` (uid 0, which the password already proved), lifts a harness uid's freeze. A user who is not a harness uid still thaws only their own marker. A password-proof thaw for ordinary users arrives with the passwordless-gate work. Tests `an_outside_caller_with_a_session_harness_uid_cannot_thaw`, `a_service_harness_account_cannot_thaw_even_outside_its_scope`, `a_harness_uid_alias_cannot_thaw`, `a_user_who_is_not_a_harness_uid_still_thaws_their_own_marker`, `root_can_thaw_any_marker`, `an_unattested_caller_cannot_thaw`. Freeze is unchanged (it only withholds). Freeze and thaw refuse when `/etc/passwd` is missing, empty or not UTF-8, and the policy load fails closed the same way: a single non-UTF-8 byte in `/etc/passwd` stops every xudo request, which only withholds, and root can still `touch /var/lib/xudo/frozen` (`an_unusable_passwd_refuses_freeze_and_thaw`, `an_empty_or_non_utf8_passwd_fails_the_load_closed`). A broken registry also locks the human out of freeze; that is acceptable because nothing runs while the policy fails to load.
- The doas rule `xudo install` writes no longer says `persist`: an OpenDoas built with timestamp support cached the password for later runs of `xudo exec`. Test `doas_snippet_never_enables_credential_persistence`.
- A queued claim records the reviewer uid and a claim token. Another reviewer cannot release, fail, or complete a fresh claim; after 15 minutes they may recover a stale claim, and only if the audit trail has no gate record for that nonce. A release or failure revokes the minted spool entry. The gate refuses a queued run whose queue record is not currently claimed for that nonce. Completion searches a bounded tail of the audit log under the log lock.
- Let the broker read `/proc/sys/kernel/random/boot_id` by removing
  `ProcSubset=pid` from its unit. Keep `ProtectKernelTunables=yes`; the unit
  remains at the configured 1.2 systemd exposure ceiling. Use the same strict
  lowercase boot-id validator in the syscall seam and broker paths.

- Reset every resource limit from PID 1 before the gate reads policy, consumes
  a request, writes an audit record, or runs a command. Cap the soft open-file
  limit at 1024 and disable core dumps. In a container or PID namespace, PID 1
  is that namespace's init, and using its limits is acceptable. The refusal
  record after a failed reset is still written under caller limits; CPU time or
  signals can tear that one record. Blocking signals around audit append and
  cut-back remains unavailable through a safe API.
- Bound the macOS `cross` and `gate` CI jobs to eight minutes; Ubuntu gate
  jobs retain their existing timeout and no retries were added.
- Ship active `00-protect.toml` rules that refuse removal of xudo, sudo,
  sudo-rs, AppArmor, audit, firewall, logging, time-sync, and SSH server
  packages through the shipped `apt-get remove` action. Its other clauses are
  tripwires for broader operator actions. The policy loader still rejects deny
  rules for programs with no loaded action, so apt and dpkg tripwires are tested
  with broad test-only operator actions until those executables have shipped actions.
- Protect `/usr/bin/xudo`, `/usr/bin/ido`, and `/usr/libexec/xudo/xudod` from
  xudo-mediated writes; bump the compiled deny-list version to 7.

- `path-under` is lexical only. Nothing in xudo enforces containment for
  argument paths. Never use it for a program that opens the path as root.
  A rule that allowlists `rm` of a home directory accepts a path the agent
  planted as a symlink and deletes whatever that symlink points at. The
  compiled-in deny-list now refuses that class of tool
  (`ChangesPathMetadataOrExistence`, deny-list version 7): `rm`, `rmdir`,
  `unlink`, `chmod`, `chown`, `chgrp`, `chattr`, `setfacl`, `setfattr`,
  `touch`, `mkdir`, `mkfifo`, `rename`, and `prename`, including a copy or
  hardlink that keeps the name and a `busybox` applet. `mknod` joins
  `DeviceOrFilesystem`. `setcap` was already `PrivilegeTool`. `mount` and
  `umount` are not named on the list. `xudo check` warns on every
  `path-under` matcher and exits 20. A rule that allowlists one of these
  tools is a lint error, as with any other deny-listed executable.

## 0.1.0-beta.2 - 2026-11-16

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
  same sentence. On an upgrade from a version below `0.1.0~beta.2` the
  package says to check that file with `xudo check`. It does not decide
  whether the host is exposed. `xudo check` and `xudo doctor` both report
  those rows as `open_unit_lints` (`check` nests the array under `lint`).
- `systemctl poweroff`, `reboot`, `halt`, `kexec`, `suspend`, `hibernate`,
  `hybrid-sleep`, `suspend-then-hibernate`, `soft-reboot`, `sleep`, `rescue`,
  `emergency`, `default`, and `exit` are refused with any arguments.
  `isolate` is refused for every target, including `start --job-mode=isolate`,
  the split form `--job-mode isolate`, and a getopt prefix such as
  `--j=isolate`. `systemd-exit.service` is refused
  with the other power services: its unit file sets `SuccessAction=exit-force`.
  An option value cannot hide the verb: `-p`, `-M`, `--when`, `--message`,
  and the other options that take the next argument are scanned like every
  other token. The read-only exemption is a whitelist of one shape: optional
  no-value flags (`--no-pager`, `--full`, `--no-ask-password`, `-l`,
  `--no-legend`, `--plain`, `--value`, `--all`), a read-only verb, then only
  unit names or joined `--property=` flags. Any other option, or any verb of
  the non-read-only set (including `reenable`, `reset-failed`), removes it
  and the full check applies to every token. `*`, `?` and `[` in a token
  outside that shape, and `-H`, `--host`, `-M`, `--machine` and their
  prefixes, are refused. `status rescue` is refused,
  because `rescue` is a power subcommand. `status rescue.service` still reads.
- The acting verbs also include `kill`, `clean`, `freeze`, `thaw`, and the
  compatibility names `condrestart`, `force-reload`, `reload-or-try-restart`,
  `condreload`, and `condstop`. Stock Debian 13 and Ubuntu images used for
  the check do not ship `systemctl`, so those names were not confirmed with
  `--help`. A verb systemd would reject is still refused.
- The tripwire is best effort for operator rules and covers the `systemctl`
  program only. A rule whose exe is not exactly `systemctl` gets no checks
  and no lint. `service`, `invoke-rc.d`, `busctl`, and a unit alias such as
  firewalld's `dbus-org.fedoraproject.FirewallD1.service` get around it. The
  enumeration is the boundary. `xudo check` also reports an enumerated unit
  list that names a refused unit or a glob. The set of non-read-only verbs
  is from the systemd 257 verb table and was not checked against a binary.
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
  sysctl also refuses `-f` and a prefix of `--load` or `--system`. dnf
  and yum refuse `-c` (their short form of `--config`) and a prefix of
  `--config`, `--setopt`, `--installroot`, or `--repofrompath`. pacman
  refuses a prefix of `--config`, `--hookdir`, `--root`, `--dbpath`, or
  `--sysroot`, and the short options `-c`, `-r`, and `-b`. pacman's `-c`
  is `--clean` or `--cascade`, not a config file; refusing it is harmless.
  zypper refuses `--root` and `--plus-repo`. dpkg refuses a prefix of
  `--status-logger` (it runs a command) and `--log`. dnf, yum, pacman, and
  zypper were not installed on the images used for the check. This is
  defence in depth: the shipped rules still only name apt-get, and their
  positions are literals.
- The install rule accepted a package name ending in `-` (`apparmor-`),
  which `apt-get install` reads as a request to remove that package, skipping
  the confirmation the remove rule demands when `confirm_human_path` is on. `deb-name` and `apk-name` now
  reject a trailing `-`. The install rule also requires `--no-remove`, so an
  install that would remove a conflicting package is refused; the operator
  removes that package with the remove rule. A trailing `+` stays accepted
  by `deb-name`: `g++` and `libstdc++6` are real names, and `pkg+` on
  `apt-get install` is harmless.
- apt-get reads a package name containing `.` or `+` that is not an exact
  cache hit as an unanchored regular expression. On install that can select
  many packages and cannot remove one, because the install rule requires
  `--no-remove`, so `deb-name` is unchanged there.
  `APT::Cmd::Pattern-Only=true` would turn that regular expression off, but
  the deny-list refuses `-o` and apt ignores an unknown key, so it is only
  a possible later defence in depth. On remove one confirmed
  token such as `lib.` or `libstdc++` could remove hundreds of packages
  (`+` is a regular expression character too), and a trailing `+` on remove
  installs. The remove rule now uses `deb-name-literal` (`deb-name`, and
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
  Blocking signals around the write is a later change. When the gate's own
  append fails because the log is damaged or the cut-back did not land, it
  prints one fixed line on stderr telling the operator to move the log
  aside. The line has no path and no bytes from the log. The exit status
  is unchanged. The broker's refusal message still carries the error text.
- sudo-rs 0.2.5 and OpenDoas pass a caller umask of `000` through to the
  root command. Classic sudo applies `022`. Measured. A file an apt hook or
  a maintainer script creates would then be world-writable. The gate now
  always sets umask `022`, and the command starts in `/`. sudo's own rule
  is the caller's umask combined with `022`, so a caller's `077` is now
  loosened to `022`. `027` would make files root writes under `/etc` and
  `/usr` unreadable to non-root daemons, and keeping sudo's combined rule
  would let a tight caller umask under sudo-rs or doas do the same to other
  users' services. A fixed `022` is deterministic and matches what classic
  sudo gives.
- In the default configuration (`confirm_human_path` off),
  `xudo.pkg.remove`'s `confirm = "always"` is satisfied by the password
  alone. A member of the `xudo` group who passes the password can remove
  packages through it, including xudo, sudo, apparmor, auditd, nftables, ufw
  and rsyslog. This was already true in beta.1 and is not changed here; a
  package-name tripwire for those is a later change.
- The shipped `timedatectl set-ntp false` has the same effect as stopping
  the time-sync unit, which the tripwire refuses for operator rules.

### Added

- Executable `[[test]]` tables in rule files, run by `xudo check` and by the
  build. A test never changes a decision and is not part of the ruleset
  generation.
- `xudo check --fuzz [--fuzz-budget N] [--fuzz-seed S]`: a bounded,
  deterministic differential fuzz of the loaded ruleset that cross-checks the
  overlap report and the standing invariants; a finding is a lint error (21).
- `xudo config` (`get`, `list`, `schema`) shows the effective configuration
  and the file and line each value came from. `ido config list` shows ido's
  user layer.
- `xudo exec --queue`: a request refused only because it needs the human path
  goes into the caller's `ido` queue. It runs nothing and keeps the denial's
  exit status.
- `ido queue --root` marks an entry to run through `xudo exec`, with policy,
  audit and the password prompt, and so does every entry `xudo exec --queue`
  writes. `ido run --yes` refuses a root-marked entry. The queue format and
  the `AGENTS.md` / `xudo agentdoc` block are now version 2.
- Release engineering: the binaries embed their dependency list
  (cargo-auditable), each release ships a signed CycloneDX SBOM, CI rebuilds
  each package on a second runner and requires matching bytes before signing,
  and cargo-vet is part of the supply-chain checks.

### Changed

- **Breaking:** the shipped argv and rules changed. The service-lifecycle
  rule no longer ships: copy `/usr/share/xudo/examples/20-services-lifecycle.toml`
  to `/etc/xudo/rules.d/` and list your units. `xudo.pkg.install` now
  requires `--no-remove` before the verb, and the old argv is denied.
  `xudo.pkg.remove` refuses names containing `.` or `+`. `reset-failed` takes
  only a plain `.service` and is refused for the tripwire units (journald,
  apparmor, chrony and others). The gate now starts the root command with
  umask 022 and cwd `/`. Re-run `xudo agentdoc`, and drop queued `ido`
  entries that use the old argv.
- A kept or edited beta.1 `/etc/xudo/rules.d/30-packages.toml` still has the
  old rule text. The compiled-in refusal of a trailing `-` applies to it, but
  `--no-remove` and the literal-name rule do not, and no lint catches it.
  Compare it with the new file (`xudo doctor` shows it as changed locally).
- **Breaking:** `xudo check` exit codes. Overlapping actions now exit 20 (was
  0), the shell-allowlist lint exits 21 (was 17), and a failing rule test exits
  22. A failing test ranks above a lint error when one run finds both.
- The ruleset generation is hashed from a canonical encoding of each action
  (framing v2), and a rule file with no actions is no longer part of it. Every
  approval in flight when xudo is upgraded is invalidated once; retry the
  request.
- A rule file may carry at most 4096 `[[test]]` tables, and a ruleset at most
  16384 in all; more fails to load.
- The doas rule `xudo install` writes uses `permit persist`. On an OpenDoas
  built with timestamp support, one password then covers about five minutes
  of `xudo exec`, unlike the sudo rule, which sets `timestamp_timeout=0`. The
  package depends on sudo.

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
