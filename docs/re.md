# Blockers

Only things that stop work. Full inventory in `todo/` and `CONCERNS.md`.

## Answered — closed

1. **Linux environment.** `yamin@yamin.lol` reachable. Ubuntu 24.04.4, kernel
   6.8.0, sudo 1.9.15p5, Docker 29.5.1 usable unprivileged, cgroup v2, `sudo-rs
   0.2.2` in apt. Plan in `CONCERNS.md`. Two caveats below.
2. **`ido add` collision** — decided: `ido add` writes `AGENTS.md`, `ido queue`
   buffers a command.
3. **Packaging** — one package. `ido` ships with `aido` and is not separately
   installable.
4. **Distribution** — signed `.deb` on GitHub Releases. No apt repo yet.
5. **Queue file** — `$XDG_STATE_HOME`, as already implemented.
6. **`CLAUDE.md` stale guidance** — fixed.
7. **`aido-config` not wired to the engine** — fixed. A settings file now changes
   a decision, and a broken one fails closed on the deciding path too.

## Still blocking

**A. Disk and RAM on yamin.lol.** 3.3 GB free of 38 GB (91% used), 3 GB RAM with
~0 available. A Rust toolchain plus target dir is 2–4 GB, and containers for the
distro matrix need more. Either free ~10 GB, or confirm the alternative:
cross-compile on the Mac and ship only the binary over. I will take the
cross-compile route unless you free space.

**B. Whether I may write `/etc/sudoers.d` on yamin.lol.** Blocks M2b's install
path. My plan avoids it: run privileged tests in Docker containers on that host,
which also gives the sudo / sudo-rs / doas matrix. Say so if you want it on the
host itself.

**C. `PIDFD_GET_INFO` needs kernel 6.13; yamin.lol has 6.8.** `SO_PEERPIDFD`
works. Not a blocker — the `SO_PEERCRED` + `(pid, starttime)` fallback exists for
this — but it means the primary attestation path cannot be tested there. A
newer-kernel container will not help; this needs a VM or a newer host eventually.

## macOS support

You asked. Short answer: **partial is easy, full is not possible as designed.**
`aido explain`/`check`/`list`/`config` already work. The human path could work —
macOS has `sudo` and `/etc/sudoers.d`. The **agent path cannot**: it rests on a
root-created cgroup scope under `aido.slice`, and macOS has no cgroups, no
`/proc`, no `openat2`, no `execveat`, no pidfds. Attesting a caller there needs a
different mechanism entirely (Endpoint Security, or audit tokens over XPC), which
is its own design. Planned, not built. Written up in `CONCERNS.md`.
