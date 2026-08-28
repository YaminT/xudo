# Blockers

Only things that stop work. Full inventory in `todo/` and `CONCERNS.md`.

## One blocker

**Root on `49.13.25.232`.** You said I may write `/etc/sudoers.d` there. I cannot:
`batman` is in the `sudo` group but every `sudo` call wants a password I do not
have, `/etc/sudoers.d` is unreadable, there is no `docker` or `podman`, and user
namespaces are disabled (`unshare --user` → `Operation not permitted`), so there
is no unprivileged fallback either.

Any one of these unblocks it. Run it yourself with `! <command>`:

```sh
# simplest: let this one account run without a password
echo 'batman ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/batman-nopasswd
sudo chmod 0440 /etc/sudoers.d/batman-nopasswd

# or install a container runtime, which also gives the sudo/sudo-rs/doas matrix
sudo apt-get install -y podman

# or just tell me the password for batman
```

Blocks: executing the install plan, `aido-gate`, and the differential compliance
matrix — everything left in phase 2.

## Answered — closed

- **Host.** Moved to `batman@49.13.25.232` (Ubuntu 24.04.3, kernel 6.8.0-90,
  4 CPUs, 7.6 GB RAM, 57 GB free). The old disk pressure is gone. Still
  cross-compiling from the Mac with `cargo-zigbuild` — a 2.1 MB static musl
  binary, no toolchain on the host, and it already runs there.
- **Kernel 5.** Done. Attestation is a ladder, not a floor: 6.13 / 6.5 / 5.3 /
  older, reported by `doctor`. 5.4, 5.10 and 5.14 all keep the agent path.
  `SO_PEERCRED` alone does **not** — a pid can be recycled, so it withholds
  passwordless operation rather than authorising a race. `openat2` degrades to a
  per-component `O_NOFOLLOW` walk and loses nothing. Written up in `CONCERNS.md`.
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
