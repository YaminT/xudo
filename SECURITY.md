# Security

## Status

**Beta. Not externally audited.** An external security audit is a stated
precondition for 1.0. Until then, do not deploy this where a compromise would
matter.

The broker and password-authenticated gate are built. Every caller is currently
classified as `Unattested`, so every request uses the password path. The
package does not install a `NOPASSWD` rule. The passwordless agent path,
Landlock confinement, and same-uid watcher separation are not in this release.
Out-of-band confirmation through `xudo watch` is built but off by default; every
path still requires the password. Session and terminal checks do not prove a
human: a same-uid agent can run `script -qc 'xudo watch'`. M4's cgroup scope is
needed to separate the agent from the human.

The published `v0.1.0-beta.1` package ships `xudo.svc.lifecycle` accepting
`systemctl` start, stop, and restart of power, reboot, rescue, kernel-module,
device, and broker-socket units for any caller who passes the password gate.
The shipped rule set no longer contains a service lifecycle rule. Copy
`/usr/share/xudo/examples/20-services-lifecycle.toml` to
`/etc/xudo/rules.d/` and list the units that host should expose. `reset-failed`
still ships, and accepts only a plain `.service` name. The compiled-in
deny-list refuses the units above, the systemd power and sleep services,
`debug-shell`, the runlevel aliases, firewall and time-sync units, and the
journal units, on `systemctl` for every verb, including a unit an operator
listed by mistake. If dpkg asked about `/etc/xudo/rules.d/20-services.toml`
during the upgrade and you kept your version, you still have the beta.1
rule: run `xudo check`, and replace its `unit-name` with a `one-of` list of
your units.

The published `v0.1.0-beta.1` install rule accepted a package name ending in
`-`. `apt-get install apparmor-` removes `apparmor`, so that command skipped
the confirmation `xudo.pkg.remove` demands and could remove a security
package or xudo itself. `deb-name` and `apk-name` now reject a trailing `-`.
The install rule also requires `--no-remove`: an install that would remove a
conflicting package is refused, and the operator removes that package with
the remove rule. A trailing `+` stays accepted. `g++` is a real package name,
`pkg+` on `apt-get install` asks apt to install the package, and on `remove`
it merely installs.

The published `v0.1.0-beta.1` audit appender wrote each record with
`write_all`. A caller who set `RLIMIT_FSIZE` to the log's size plus a few
bytes made the first `write` return a short count and the next one raise
`SIGXFSZ`, killing the `-auth` gate before it could cut the torn line back.
The broker and every later gate then refused the damaged tail, so xudo stayed
down until an operator moved the log aside. An append is now one `write` of
the whole record. A short count is a failure and the cut-back runs, denying
the request and leaving the log as it was. `EINTR` wrote nothing, so it is
tried once; a second interrupt fails the same way. This does not reset the
caller's resource limits. That stays a later change.

## Reporting

Open a private security advisory on the GitHub repository. Please do not open a
public issue for anything that could be exploited.

If you are reporting a design flaw rather than a bug, that is welcome and useful.
The limits of the design are the rest of this file. The product invariants are
in `howiwork.md`: agent detection is not a security boundary, the agent path is
never broader than the human path, and confirmation lives outside the
requester's process tree.

## What this does not protect against

Stated plainly, because a control you believe in and do not have is worse than
one you know you lack.

- **Agent detection is not a security boundary.** A same-uid process can forge
  every cheap signal, and a human can ask a genuinely-enrolled agent to run a
  command. Once the passwordless path exists, impersonation would skip the password on
  an already-allowlisted action; today it buys nothing.
- **The deny-list is defence in depth.** The set of programs that can be turned
  into a root shell is not enumerable. It catches a mistake in a rule; it is not
  the boundary.
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
  answer to the human who asked. `exec` does not use the front-end's rule path. The broker and gate load through the privileged loader `xudo_sys::load_trusted_rules`, which refuses a ruleset with
  any component that is not root's, is writable by group or world, is a
  symbolic link, or is on a mount a non-root user could have made — checked on
  the descriptors the rules are read through — and `xudo doctor` reports
  through it. The broker and gate use this trusted loader for privileged
  requests; `explain` itself remains an unprivileged inspection command.
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
