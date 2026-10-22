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
- **`aido` cannot protect a host that already has other paths to root.**
  Pre-existing `NOPASSWD` entries, `wheel` / `sudo` / `docker` / `lxd`
  membership, writable unit directories, writable `PATH` entries, writable shell
  rc files: any one of them makes `aido` decorative. `aido doctor` reports them
  (`--json` for a program, `--fix` for what to change); see below for what that
  report can and cannot see.
- **`aido explain` does not verify the rules it reads.** It reads them by path,
  so that it works on a checkout; a tampered ruleset makes it print a wrong
  answer to the human who asked. Survivable only because nothing can execute.
  The privileged loader, `aido_sys::load_trusted_rules`, refuses a ruleset with
  any component that is not root's, is writable by group or world, is a
  symbolic link, or is on a mount a non-root user could have made — checked on
  the descriptors the rules are read through — and `aido doctor` reports
  through it. The broker and the gate are not written yet; loading through it,
  and nothing else, is a stated precondition of the privileged path.
- **Not every user-writable filesystem is refused yet.** A mount that root made
  from a block device or loop file a user can write passes, and so does an
  overlay whose upper layer a user can write: what is checked is who made the
  mount and the marks it carries, not what backs it (`docs/CONCERNS.md`,
  2026-10-19).

## What `aido doctor` reports about other paths to root

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
  clean. It is a containment: only asking sudo itself (plan item D3) turns it
  into an answer. Within a line the scan is left to right with escape semantics,
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
  and has a line aido does not model, which may set it (the `secure_path` it did
  find is examined either way). A file with a continuation line therefore says
  "may name you" and "unverified" where a faithful parser would say yes or no;
  the fix for that is to ask the program itself (`doas -C`, `sudo -l -U`), which
  is planned (`docs/todo/m2b-finish-plan.md`, item D3).
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
design means the ones listed above; this is the list of the ones it is not. `aido doctor --fix`
prints each proposed change, what it means, and the exact command for a human
to run; it applies nothing, because a confirmation read from your own terminal
is one an agent driving that terminal could type.

## No telemetry

The default build contains no network code. Verifying that mechanically —
a seccomp filter denying `AF_INET` socket creation and a CI job under `strace`
asserting no non-`AF_UNIX` socket — is planned and not yet done.
