# Security

## Status

**Beta. Not externally audited.** An external security audit is a stated
precondition for 1.0. Until then, do not deploy this where a compromise would
matter.

The broker and the password-authenticated gate are built. Both can recognise a
caller inside a scope that root made for a registered agent, but nothing in
this release creates one, so every request takes the password path. The
package installs no `NOPASSWD` rule. Passwordless runs, agent enrolment,
Landlock confinement and a separate agent account are not in this release. An
optional confirmation through `xudo watch` is built and off by default; it is
an extra on the human path and the agent path never depends on it. Every path
still requires the password. Session and terminal checks do not prove a human:
a same-uid agent can run `script -qc 'xudo watch'`. This limits only that
extra.

The doas rule `xudo install` writes has no `persist`, so every run prompts even on an OpenDoas built
with timestamp support. doas does not give its command a new pty, so a command that uses the
terminal can reach the parent's tty. The package depends on sudo.

`v0.1.0-beta.1` had three issues that `v0.1.0-beta.2` fixed. The shipped
service rule accepted `systemctl` start, stop, and restart of power, reboot,
rescue, and similar units. A package name ending in `-` could remove a
package, including a security package. On remove, a name containing `.` or
`+` was read as a regular expression and could select many packages. The
fixes, and what an operator who kept an old rule file should do, are in
[CHANGELOG.md](CHANGELOG.md).

No shipped rule starts or stops a service. To allow it, copy
`/usr/share/xudo/examples/20-services-lifecycle.toml` into
`/etc/xudo/rules.d/` and list your units with `one-of`. The built-in list
refuses power, rescue, firewall, time-sync, journal and xudo's own units on any
verb that acts, but it is a list of names: an alias it does not name gets past.
If you kept a beta.1 `20-services.toml` during an upgrade, run `xudo check`.

With `confirm_human_path` off, the default, `xudo.pkg.remove`'s
`confirm = "always"` is satisfied by the password alone. The shipped active
`00-protect.toml` deny rules refuse removal of xudo, sudo, sudo-rs, AppArmor,
auditd, firewall, logging, time-sync, and openssh-server packages through the
shipped `apt-get remove` action. Its purge, autoremove, autopurge,
`install pkg-`, and dpkg clauses are tripwires for operator actions that accept
those spellings. These
checks protect xudo-mediated paths only. They cannot prevent a host-side apt or
dpkg command, a root shell, or an indirect transaction such as installing
`sudo-ldap` that removes a conflicting package. Removing `openssh-client` can
remove `openssh-server`; removing `libip4tc2` or `libxtables12` can remove
`iptables`; removing `libnftables1` can remove `nftables`; removing `python3`
can remove `ufw` or `firewalld`; and removing `init-system-helpers` can remove
xudo. `xudo doctor` warns when a shipped deny-rule id is missing or inert.
Rules for programs with no loaded action load as inactive and cannot allow
anything; `xudo check` and `doctor` say "inert today" until an operator action
names that program. The apt and dpkg package protections are tested against
later operator actions as well as the shipped apt-get action.

The shipped `xudo.time.set-ntp` rule accepts `timedatectl set-ntp false`,
which has the same effect as stopping the time-sync unit. The tripwire
refuses that stop for operator rules; it does not apply to this shipped
action.

The published `v0.1.0-beta.1` audit appender wrote each record with
`write_all`. A caller who set `RLIMIT_FSIZE` to the log's size plus a few
bytes made the first `write` return a short count and the next one raise
`SIGXFSZ`, killing the `-auth` gate before it could cut the torn line back.
The broker and every later gate then refused the damaged tail, so xudo stayed
down until an operator moved the log aside. An append is now one `write` of
the whole record. On this `RLIMIT_FSIZE` route a short count is a failure
and the cut-back runs, denying the request and leaving the log as it was.
`EINTR` wrote nothing, so it is tried once; a second interrupt fails the same
way. A core-dump signal (`SIGXFSZ`, `SIGXCPU`) is not turned into a pending
group-exit between the pages of one `write`, so it does not tear a record
this way. A fatal signal that is not a core-dump signal (`SIGTERM`,
`SIGHUP`, `SIGINT`) still can: the kernel marks the kill and checks for it
between page-sized chunks, so a record that crosses a page boundary can be
left half-written. The caller can steer that length through argv. A signal
sudo relays, or the pty hanging up when the user kills sudo, is enough to
deliver it. That route predates this fix. The impact is availability: xudo
stays down until an operator moves the log aside. Blocking signals around
the write and the cut-back remains unavailable through a safe API: rustix's
signal-mask call is `unsafe`, and the published unsafe-block budget was not
changed. A record crossing a page boundary therefore remains vulnerable to
a fatal non-core-dump signal. The gate now resets every Linux resource limit
from PID 1's values before it handles a request, caps the soft open-file limit
at 1024, and disables core dumps. It reads `/proc/1/limits` through a pinned
descriptor verified as procfs and refuses if the file, any value, or any
`setrlimit` call fails. In a container or PID namespace, PID 1 is that
namespace's init; copying its limits is acceptable because those limits are
the baseline the namespace provides. If the resource-limit reset fails, the
refusal audit record is written under the caller's limits. A caller's CPU-time
limit or a delivered signal can still tear that one record. When the gate's
own append fails because the log is damaged or the cut-back did not land,
stderr gains one fixed line
telling the operator to move the log aside. The line has no path and no
bytes from the log. The exit status is unchanged. The broker's refusal
message still carries the error text.

sudo-rs 0.2.5 and OpenDoas pass a caller umask of `000` through to the root
command. Classic sudo applies `022`. Measured. A file an apt hook or a
maintainer script creates would then be world-writable. The gate now always
sets umask `022`, and the command starts in `/`. sudo's own rule is the
caller's umask combined with `022`, so a caller's `077` is loosened to
`022`. `027` would make files root writes under `/etc` and `/usr` unreadable
to non-root daemons, and keeping sudo's combined rule would let a tight
caller umask under sudo-rs or doas do the same to other users' services. A
fixed `022` is deterministic and matches what classic sudo gives.

## Verifying a release

Each release carries a CycloneDX SBOM, `xudo-<version>.cdx.json` (`<version>` is Cargo's spelling, for example `0.1.0-beta.1`), listing every crate the shipped binaries link, as resolved for the two musl targets, with its `Cargo.lock` version and checksum. It is signed like the package; verify it with the same identity the package uses:

```sh
cosign verify-blob --bundle xudo-<version>.cdx.json.cosign.bundle --certificate-identity https://github.com/YaminT/xudo/.github/workflows/release.yml@refs/tags/<tag> --certificate-oidc-issuer https://token.actions.githubusercontent.com xudo-<version>.cdx.json
```

The four binaries also embed that dependency list (`cargo-auditable`). Read it from an installed binary with `cargo audit bin /usr/bin/xudo`. That embedded list may name a crate the binary does not link (`errno`); the SBOM does not. Building the package (`just deb`) needs `cargo-auditable` 0.7.7.

## Reporting

Open a private security advisory on the GitHub repository. Please do not open a
public issue for anything that could be exploited.

If you are reporting a design flaw rather than a bug, that is welcome and useful.
The limits of the design are the rest of this file. The product invariants are
in `howiwork.md`: agent detection is not a security boundary; no caller gets
passwordless root by mistake or by default; and a decision that needs a person
is made where the requester cannot answer it. Passwordless runs are not built
yet, so today nothing runs without a password.

## What this does not protect against

Stated plainly, because a control you believe in and do not have is worse than
one you know you lack.

- **Agent detection is not a security boundary.** A same-uid process can forge
  every cheap signal, and a person can ask a verified harness to run a command.
  In the design, a process inside a verified harness's scope runs, without a
  password, exactly what root's rules allow that harness: no live approval
  stands in between, so the rules must be sized for that. In this release no
  caller is a verified harness and impersonation buys nothing.
- **The deny-list is defence in depth.** The set of programs that can be turned
  into a root shell is not enumerable. It catches a mistake in a rule; it is not
  the boundary.
- **`path-under` is lexical only.** Nothing in xudo enforces containment for
  argument paths. Never use it for a program that opens the path as root.
  A symlink inside the prefix is a path the rule never named. `rm`, `rmdir`,
  `unlink`, `chmod`, `chown`, `chgrp`, `chattr`, `setfacl`, `setfattr`,
  `touch`, `mkdir`, `mkfifo`, `rename`, and `prename` are the compiled-in
  class `ChangesPathMetadataOrExistence` (deny-list version 7), including a
  copy or hardlink that keeps the name and a `busybox` applet. `mknod` is
  `DeviceOrFilesystem`. `setcap` is `PrivilegeTool`. `xudo check` warns on
  every `path-under` use and exits 20.
- **One overbroad allowlist entry voids the design.** A single allowlisted shell,
  interpreter, pager, exec proxy, or `apt-get -o DPkg::Pre-Invoke::=` is
  unrestricted root regardless of how the arguments are written.
- **`xudo` cannot protect a host that already has other paths to root.**
  Pre-existing `NOPASSWD` entries, `wheel` / `sudo` / `docker` / `lxd`
  membership, writable unit directories, writable `PATH` entries, writable shell
  rc files: any one of them makes `xudo` decorative. `xudo doctor` reports them
  (`--json` for a program, `--fix` for what to change); see below for what that
  report can and cannot see.
- **`xudo explain` does not verify the rules it reads.** It reads them by path,
  so that it works on a checkout; a tampered ruleset makes it print a wrong
  answer to the human who asked. `exec` does not use the front-end's rule path. The broker and gate load through a trusted loader, which refuses a ruleset with
  any component that is not root's, is writable by group or world, is a
  symbolic link, or is on a mount a non-root user could have made — checked on
  the descriptors the rules are read through — and `xudo doctor` reports
  through it. The broker and gate use this trusted loader for privileged
  requests; `explain` itself remains an unprivileged inspection command.
- **The review queue shows text the agent wrote.** A queued entry's reason is
  agent-written and shown sanitised. Judge the exact argv, which is re-checked
  against the current rules when you run it, in `/`. Only a person classified
  as human and listed in the harness's `reviewers` may claim an entry, never
  the account that queued it. The queue holds at most 32 entries per account
  and 1024 in total, and an entry expires after `queue_ttl_secs` (at most one
  day). A harness label names a scope root made, not a program: whatever runs
  in that scope gets that label's rules. Nothing in this release creates such
  a scope, so the queue stays empty.
- **Not every user-writable filesystem is refused yet.** A mount that root made
  from a block device or loop file a user can write passes, and so does an
  overlay whose upper layer a user can write: what is checked is who made the
  mount and the marks it carries, not what backs it.

## What `xudo doctor` reports about other paths to root

It runs as you, unprivileged, and reports what it can read. **What it cannot
read is "unverified", never "clean"**: `/etc/sudoers` is `0440` and `/root` is
`0700` on every normal host, so run it a second time with `sudo` to read those,
and keep the first run for the checks that only mean something as you.

It reports:

- **Passwordless rules**: `NOPASSWD`, `!authenticate`, and doas `nopass`, in
  `/etc/sudoers`, `/etc/sudoers-rs`, every file they include, `/etc/doas.conf`,
  and `/etc/doas.d`. When `/etc/sudoers` cannot be read, `/etc/sudoers.d` is read
  anyway. The reader is deliberately not sudo's parser, and it is not trusted to
  be a faithful one: four rounds of review each found another way sudo's or
  OpenDoas's lexer joins lines differently from it, so it **does not model line
  continuation at all**. Every physical line whose last byte (past trailing
  whitespace) is a backslash, whatever precedes it and in either dialect, makes
  the line it may join unmodelled: a passwordless rule on it or on a line it may
  join "may name you" (never "does not"), a tag split across the join still
  counts, and the file is listed as unverified, so the check is never clean (it
  reads "found" where a rule was found and "unverified" where none was). An
  include that starts any of those lines is still followed, by **both of its
  paths**: sudo reads `@include /p\` as the path `p\`, backslash included, and
  the line after it as a rule of its own, and `@include /p \` as `/p` and a
  continuation, so `/p` and `/p\` are both read, for `@include`, `#include`,
  `@includedir`, and `#includedir`, on the first line of the join or a later
  one; a path that is not there is unverified. Those paths are hints, not the
  file sudo opens: a backslash-newline inside the quotes of an include path is
  dropped, and a path may start on the continuation line of its directive, and
  neither reaches a file any of them names. So a line that is not settled and
  holds the word `include` is also reported as an include (`"grant":
  "include"`, "may name you"), whatever else is found, and the check is never
  clean. It is a containment. Plan item D3 is done: as root, doctor asks
  `sudo -n -l -U`. Within a line the scan is left to right with escape semantics,
  and **only three escapes are modelled**: a backslash before a backslash,
  before a `#`, and before a blank. Any other backslash escape (`\q`, `\xHH`,
  `\"`), and a double quote on a line that also has a backslash or a later `#`,
  makes the file unverified, and a rule on a line it is part of "may name you";
  for doas, which drops the backslash of an escape, `nopass` is also looked for
  with its backslashes removed. Sudoers include paths are unescaped, and the
  tokens are looked for on every line that is not a whole-line comment. An
  alias, a netgroup, a host or command scope, or a user or group name that
  `/etc/passwd` and `/etc/group` do not hold makes a rule "may name you" rather
  than "does not", and an include whose target is missing or unreadable is
  unverified. Root's `PATH` is unverified too, and says which of two causes:
  a sudoers file that could set `secure_path` could not be read, or one was read
  and has a line xudo does not model, which may set it (the `secure_path` it did
  find is examined either way). A file with a continuation line therefore says
  "may name you" and "unverified" where a faithful parser would say yes or no;
  the fix is to ask the program itself: as root, doctor runs `sudo -n -l -U`;
  unprivileged, it runs `doas -C` for each configuration file.
- **Group membership** that is root by another name: `sudo`, `wheel`, `admin`,
  `docker`, `lxd`, `incus-admin`, `libvirt`, `disk`, `input` — both the groups
  `/etc/group` lists you in and the ones this session holds.
- **Writable systemd unit and generator directories**, their entries, drop-ins,
  and the files their links name.
- **Writable entries of root's `PATH`** (the `secure_path` sudoers sets, and
  the stock directories) and of **your `PATH`** ahead of the backend, where a
  program named `sudo` would capture the password you type next; and relative
  entries there.
- **Writable files root's shells read**: the system profile and rc files of
  bash, sh, zsh, and fish, their drop-in directories, `/etc/environment`, and
  the rc files in root's home.

"Writable" means anyone but root can change it or create it, judged on every
directory the kernel passes through on the way, links followed one at a time —
the owner, a writable group or everyone, or you where `access(2)` says so. In a
sticky directory such as `/tmp`, whoever owns a link, or a file where a
directory should be, may replace it, and counts. A character device
(`/dev/null`) holds nothing and is judged by its owner alone; a fifo, a socket,
or a block device is judged like a file. Symlinked drop-in directories are read.

It does not check, and does not list as unverified: accounts, groups, and sudo
rules kept in a directory service (LDAP, SSSD), polkit rules, file
capabilities, set-user-ID programs, cron, the dynamic loader's configuration,
kernel modules, `/etc/pam.d`, `/etc/sudo.conf` (which can load plugins), whether
`/etc/sudoers*`, `/etc/sudoers.d`, `/etc/doas.conf`, and the files they include
are themselves writable by someone else, whether `/etc/passwd`, `/etc/shadow`,
or `/etc/group` are, `/root/.ssh`, systemd's `system-shutdown`, `system-sleep`,
and `system.conf.d` directories, udev rules, *your own* shell's rc files (an
alias or function named `sudo` there captures the password exactly as a
writable `PATH` entry does), and an ACL that lets someone *else* write (visible
only through the group bits it sets). "Every other path to root" in the
design means the ones listed above; this is the list of the ones it is not. `xudo doctor --fix`
prints each proposed change, what it means, and the exact command for a human
to run; it applies nothing, because a confirmation read from your own terminal
is one an agent driving that terminal could type.

## Other known limits

The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a regular file, so stock Ubuntu 26.04 verifies. It reports `installed, but NOT VERIFIED` on doas and on a multicall-coreutils system with no regular probe program, such as Alpine. The audit trail records authorization, not command outcomes. Pasban runs daily as root to verify the chain and compare file records with journald copies by hash. It detects a removed tail, a cut followed by continued writes, and a forged chain journald never saw. It cannot prevent privileged tampering or prove a command completed.

## No telemetry

The shipped release-musl binaries are checked under `strace` across selected commands, failing on socket families outside `AF_UNIX`/`AF_LOCAL`. CI also checks their normal Cargo dependency tree for known networking crates.
