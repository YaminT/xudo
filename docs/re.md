# Blockers

Only things that stop work. Full inventory in `todo/` and `CONCERNS.md`.

## None

Nothing stops M2b. Docker on this machine gives a real Linux kernel, with
`sudo`, `sudo-rs`, and `OpenDoas` installable in it, which is enough for every
M2b and M3 item. Run the suite there as a non-root user on a copy of the
checkout, never on the bind mount and never as root; `todo/README.md` § M2b
step 0 says why.

Still wanted later, not now: a VM for the kernel-version matrix and for M4's
systemd scopes.

## Answered — closed

- **Host.** Local Docker. The remote hosts recorded earlier are no longer
  needed for anything.
- **Kernel 5.** Attestation is a ladder, not a floor: 6.13 / 6.5 / 5.3 / older,
  reported by `doctor`. `SO_PEERCRED` alone withholds passwordless operation
  rather than authorising a race.
- **The gate without a broker** cannot execute, so the broker's minting half is
  M2b. See `todo/README.md` open decision 5.
- **`ido add` collision** — `ido add` writes `AGENTS.md`, `ido queue` buffers.
- **Packaging** — one package; `ido` is not separately installable.
- **Distribution** — signed `.deb` on GitHub Releases, no apt repo yet.
- **Queue file** — `$XDG_STATE_HOME`.

## macOS

`explain`, `check`, `list`, `config`, `audit`, `doctor`, and all of `ido` work.
The human path could work: macOS has `sudo` and `/etc/sudoers.d`. The agent
path cannot: it rests on a root-created cgroup scope, and macOS has no cgroups,
no `/proc`, no `openat2`, no `execveat`, no pidfds. Planned, not built.
