# Blockers

Only things that stop work. Full inventory in `todo/` and `CONCERNS.md`.

## None

Nothing stops phase 2 today.

The last blocker — a host where I can be root — is resolved by Docker on
`yamin@yamin.lol`: `docker run` there gives uid 0 in a container, which is
enough to write `/etc/sudoers.d`, execute the install plan, and run the
sudo / sudo-rs / OpenDoas matrix.

The `rustix` question is not a blocker either. `openat2` and `execveat` have no
`std` wrapper, but `rustix` exposes both through a **safe** API, so
`#![forbid(unsafe_code)]` stays intact workspace-wide and no waiver is needed.
`docs/design-plan.md` already names `rustix` as the syscall dependency.

## One correction, for the record

`49.13.25.232` still has **no podman** (`podman: command not found`, checked
2026-08-31), and its `sudo` still wants a password I do not have. It is
therefore a build-and-run host only, not a privileged test host. Nothing needs
it — the matrix lives on `yamin.lol`. If you want the bigger host in the matrix
later, `sudo apt-get install -y podman` there is all it takes.

## Answered — closed

- **Host.** Build/run on `batman@49.13.25.232` (Ubuntu 24.04.3, kernel 6.8.0-90).
  Privileged tests in Docker on `yamin@yamin.lol`. Cross-compiled from the Mac
  with `cargo-zigbuild`: a 2.1 MB static musl binary, no toolchain on the host.
- **Kernel 5.** Done. Attestation is a ladder, not a floor: 6.13 / 6.5 / 5.3 /
  older, reported by `doctor`. 5.4, 5.10 and 5.14 all keep the agent path.
  `SO_PEERCRED` alone does **not** — a pid can be recycled, so it withholds
  passwordless operation rather than authorising a race. `openat2` degrades to a
  per-component `O_NOFOLLOW` walk and loses nothing.
- **`ido add` collision** — `ido add` writes `AGENTS.md`, `ido queue` buffers.
- **Packaging** — one package; `ido` is not separately installable.
- **Distribution** — signed `.deb` on GitHub Releases, no apt repo yet.
- **Queue file** — `$XDG_STATE_HOME`.
- **`CLAUDE.md` stale guidance**, **`aido-config` not wired to the engine** —
  both fixed.

## macOS

Partial is easy and already works (`explain`, `check`, `list`, `config`, `audit`).
The human path could work: macOS has `sudo` and `/etc/sudoers.d`. The **agent
path cannot** — it rests on a root-created cgroup scope, and macOS has no
cgroups, no `/proc`, no `openat2`, no `execveat`, no pidfds. Attesting a caller
there needs Endpoint Security or audit tokens over XPC, which is its own design.
Planned, not built.
