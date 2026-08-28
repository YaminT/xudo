# aido — Agent-Aware Privilege Broker for Linux

**Plan only. No code in this phase.**

## Context

AI coding agents (Claude Code, Codex CLI, Gemini CLI, Aider) constantly hit commands that need root: package installs, service restarts, `/etc/hosts` edits, sysctl tweaks. Today there are two options and both are bad. Either a human babysits every `sudo` password prompt — which destroys unattended agent work — or the user grants blanket `NOPASSWD: ALL`, which is a standing root backdoor available to *any* process running as that user.

`aido` is the middle path: a sudo-like front door backed by a **root-owned allowlist of named actions**. Enrolled agent sessions execute allowlisted actions without a password. A human invoking `aido` directly is always prompted. A catastrophic-command deny-list is compiled into the binary and cannot be edited by config. Every decision is audited.

Target: Linux. Dev host is macOS, so the policy engine must build and unit-test natively on darwin while all privileged paths are Linux-only and fail closed elsewhere.

### Requirements traceability

| # | Requirement | Where it is satisfied |
|---|---|---|
| 1 | sudo-like CLI, delegates to `sudo` or `doas` | Backend adapter, M2 |
| 2 | Root-owned rule set allowlisting actions | `/etc/aido/rules.d/`, `aido-policy` crate, M1 |
| 3 | Known agents run allowlisted actions with no password | `aido-gate-nopass` + `NOPASSWD` rule, M4 |
| 4 | Human invoking `aido` is prompted | `aido-gate-auth` + `PASSWD` rule, M2 |
| 5 | Predefined agent list, user-extensible, root required to extend | `/etc/aido/agents.d/`, `aido agent add` via password path, M4 |
| 6 | Confirm even in yolo mode; user-disableable | `confirm_agent_actions = true` default + `trust.d` narrowing, M3/M5 |
| 7 | Best tooling | Rust workspace, see Stack |
| 8 | No development yet | This document |

---

## The three invariants that shape everything

Everything below follows from three facts. Getting these wrong produces a tool that *looks* secure and is a passwordless-root installer.

**(A) Agent detection is not a security boundary — and `aido` must say so in its own SECURITY.md.**
The requirement "agents get no prompt, humans do" inverts the normal trust model: the *absence* of proof-of-humanity becomes the thing that grants a privilege. Every cheap signal (`CLAUDECODE=1`, `argv[0]`, `comm`, `/proc/<pid>/exe`, ancestry names) is caller-controlled and trivially forged by a same-uid process. Even with unforgeable enrollment, a human can simply *ask a real enrolled agent* to run the command — "consent laundering" — which is indistinguishable at the syscall layer.

Therefore: a successful impersonation buys exactly one thing — skipping the password on an action **that is already allowlisted** — and buys no new capability. The real boundary is the root-owned allowlist, the non-overridable deny-list, and out-of-band confirmation. **Size the allowlist assuming every entry will be run passwordless by a process you cannot authenticate.**

**(B) The agent path is strictly narrower than the human path, never broader in authentication.**
Misclassification can only withhold capability, never grant it. An unattested caller falls to the human flow with a password — never a silent downgrade to passwordless.

**(C) Confirmation lives outside the agent's process tree and off its stdin.**
The agent is `aido`'s *parent*. It owns `aido`'s stdin, stdout, and any pty it allocated. A confirmation read from stdin — or even from `/dev/tty` — is a confirmation the agent answers with `--yes`. Measured fact driving this: inside Claude Code's bash tool the child shell has **no controlling terminal** (`tty` → "not a tty", `open("/dev/tty")` → ENXIO) while the parent `claude` keeps its pty. So `aido` adopts polkit's authority/agent split: the root broker prompts on a channel the requester does not own. No live channel → **DENY**, never skip.

---

## Architecture

Four binaries, **no setuid bit anywhere**, one uid transition performed by sudo/doas.

```
  agent or human
        │  aido pkg install ripgrep
        ▼
  /usr/bin/aido ────────── unix socket ────────►  aidod (root)
  (unprivileged,                                  ├ SO_PEERPIDFD → PIDFD_GET_INFO
   decides nothing)                               ├ classify: enrolled-agent | human | unattested
        │                                         ├ evaluate policy + deny-list + rate limits
        │  exec via backend                       ├ own the confirmation state machine
        ▼                                         └ mint one-use request record
  sudo / doas  ──►  aido-gate-{nopass,auth} (root)
                    zero argv, zero env input
                    ├ calls back to broker, walks its own lineage
                    ├ consumes the nonce (one use)
                    ├ RE-DECIDES independently (second policy engine)
                    └ execveat(validated_fd, "", AT_EMPTY_PATH)
```

| Binary | Priv | Responsibility |
|---|---|---|
| `/usr/bin/aido` | user | Normalize verb + argv into a named action and typed argv vector (byte-exact `OsStr`, never `to_string_lossy`). Talk to the broker. Render the decision. Holds no secret, makes no decision. `clap` compiled **without** the `env` feature so no flag is ever settable from the environment. |
| `/usr/libexec/aido/aidod` | root | The authority. Socket-activated on `/run/aido/broker.sock`. Identifies peers, classifies, evaluates, rate-limits, owns confirmation, mints one-use request records, writes the audit chain. |
| `/usr/libexec/aido/aido-gate-{nopass,auth}` | root | Two hardlinks to one inode, branching on `argv[0]`. Exec'd only by sudo/doas. **A second, independent policy engine**, written on the assumption any local user can invoke it directly. |
| `/usr/libexec/aido/aido-session` | root | Enrollment launcher — the *only* way an agent identity comes into existence. Reached through the password path. |

### Caller classification — the one thing that carries authorization weight

A caller is an **agent** if and only if its cgroup id equals a live, root-created transient scope under `aido.slice/`. The user provably cannot write a pid into that cgroup: the kernel requires write access to both the destination and the common-ancestor `cgroup.procs`, and `aido.slice` sits outside systemd's delegated user subtree, so the attempt fails `EACCES`.

- Peer identity: `SO_PEERPIDFD` → `ioctl(PIDFD_GET_INFO, PIDFD_INFO_CREDS|PIDFD_INFO_CGROUPID)`. Race-free by construction.
- Kernels < 6.5: `SO_PEERCRED` + `(pid, starttime)` pinning, documented as the weaker fallback.
- Namespace-divergence guard runs **first**: if the caller or any ancestor is in a different mnt/pid/user namespace than the broker, all path-derived evidence is discarded and the request continues as *unattested*.
- Everything else — `CLAUDECODE`, `comm`, `cmdline`, `exe`, ancestry — is recorded as an **unauthenticated hint** in the audit record and carries **zero** authorization weight.

The scope-bound HMAC session token is bookkeeping — non-repudiation, expiry, revocation, and an authenticated channel for the agent to *declare* yolo mode — not a boundary. A token exfiltrated into the human's own shell fails the scope check.

### Crate layout (5 crates, trust boundary drawn on day one)

- `aido-policy` — pure function `(ruleset, caller_facts, action) → Decision{verdict, rule_id, rule_source file:line, resolved_argv, env_plan, trace}`. **Zero syscalls.** Builds and tests natively on macOS. Deny-list compiled in here.
- `aido-sys` — every Linux syscall behind a trait. Three impls: `LinuxProcFs` (injectable procfs root so fixture trees drive unit tests), `LinuxKernel` (`openat2`, `execveat`, `close_range`, `pidfd_open`, `SO_PEERPIDFD`, cgroup writes, `statfs`), `MacOsStub` (always returns `Unknown`/`Unsupported`, so a macOS dev cannot accidentally validate a Linux-only assumption).
- `aido` — front-end.
- `aido-gate` + `aidod` — privileged. Dependency budget capped at sudo-rs's bar: rustix/libc + one audited serialization crate.
- `aido-tests` — container/VM matrix.

`#![forbid(unsafe_code)]` everywhere except one audited syscall module with a published unsafe-line budget.

---

## Config layout

All of `/etc/aido` is `root:root` and **refuses to load** if any path *component* is group/world-writable, is a symlink, or lives on a filesystem mounted by a non-root user (checked against `/proc/self/mountinfo`). Verification is on the **opened fd** via `fstat`, never on the path string.

```
/etc/aido/config.toml            0644  confirm_agent_actions = true (default), confirmation_timeout,
                                       use_pty, audit_sink, rate limits, novelty signals.
                                       There is NO global confirmation off-switch key.
/etc/aido/rules.d/*.toml         0644  Named actions + typed argv matchers. Lexical basename order.
                                       A missing include is a HARD ERROR, never a silent skip.
/etc/aido/deny.d/00-catastrophic.toml  Shipped copy FOR OPERATOR READING ONLY. The authoritative
                                       deny-list is compiled into aido-policy and cannot be edited,
                                       shadowed, or disabled by any file.
/etc/aido/agents.d/*.toml        0644  Enrollment registry: id, launch command, target pinned by
                                       (st_dev, st_ino), provenance (who/when/why).
/etc/aido/trust.d/*.toml         0644  The ONLY thing that can narrow the confirmation requirement.
                                       Triple (agent × project root × action class) + mandatory
                                       reason + expiry.
/etc/aido/projects.d/*.toml      0644  Project root → profile, grant ceiling, repo_policy_sha256.
/etc/aido/backend.toml           0644  Detected backend + probed capability matrix.
/etc/aido/attest.key             0600  HMAC-SHA256 key, regenerated per boot_id.
/etc/aido/policy.generation      0644  Monotonic counter + hash of the committed generation.

<project>/.aido/policy.toml            NARROWING ONLY. The loader structurally rejects any construct
                                       that adds a rule, widens a matcher, removes a confirm
                                       requirement, raises a rate limit, or extends a TTL. Ignored
                                       unless projects.d records its sha256. There is deliberately
                                       NO user-home layer that can widen policy.

/etc/sudoers.d/aido              0440  NO DOT, NO trailing ~ — sudo silently ignores such files.
/etc/doas.d/60-aido.conf         0400  Or a sentinel-delimited block in /etc/doas.conf under flock.

/run/aido/                       0700  broker.sock, sessions/<id>, req/<id> (0600, O_EXCL)
/var/lib/aido/                   0700  grants, rate buckets, novelty baselines, nonce ledger,
                                       policy generations + rollback copies
/var/log/aido/audit.jsonl        0600  hash-chained secondary sink (journald is primary)
```

Rate buckets and grant counters **must** live on disk, not in-process: each `aido` invocation is a fresh short-lived process. Grant TTLs are monotonic-clock-anchored so a clock change cannot extend a window.

---

## Backend integration

Detection is **runtime, never build-time**, recorded in `backend.toml` and in every audit record. Probe `/usr/bin/sudo` and `/usr/bin/doas` by absolute path. Detect sudo vs **sudo-rs** (default sudo in Ubuntu 26.04 LTS — it *ignores* unsupported directives with a warning, so a rule aido wrote may silently not do what it says). For doas, detect whether the build has `--with-timestamp` (OpenDoas disables `persist` by default on Linux). **aido never depends on backend credential caching.**

Refuse to operate — exit 19, fail closed, no silent downgrade — when neither backend exists, when the ruleset is not root-owned, when `/etc/aido` sits on a `nosuid`/`noexec`/user-writable mount, or when "root" is a namespaced root that does not mean what the operator thinks.

**Post-install verification is functional, not file-existence:** run the gate with a no-op probe and assert it actually executed as uid 0.

```sudoers
# /etc/sudoers.d/aido — 0440 root:root
Cmnd_Alias AIDO_NOPASS = /usr/libexec/aido/aido-gate-nopass ""
Cmnd_Alias AIDO_AUTH   = /usr/libexec/aido/aido-gate-auth   ""
Defaults!AIDO_NOPASS env_reset, !setenv, secure_path="/usr/sbin:/usr/bin:/sbin:/bin", timestamp_timeout=0, use_pty, !visiblepw
Defaults!AIDO_AUTH   env_reset, !setenv, secure_path="/usr/sbin:/usr/bin:/sbin:/bin", timestamp_timeout=0, use_pty, !visiblepw
%aido ALL=(root) NOPASSWD: AIDO_NOPASS
%aido ALL=(root) PASSWD:   AIDO_AUTH
```

Line by line:
- `""` after each path = **the command may be run with zero arguments only**. This removes sudo's `fnmatch`/glob layer from the trust path entirely and makes the whole sudoers-wildcard argument-injection class structurally unreachable.
- `timestamp_timeout=0` is **essential**: without it the agent path can ride a credential the human cached with an earlier unrelated `sudo` — the exact residual-timeout side channel used in a published Codex CLI sandbox escape.
- `use_pty` is the remedy for the TIOCSTI/TIOCLINUX tty-hijack class (CVE-2005-4890 `su`, CVE-2016-2779 `runuser`, still-open OpenDoas #106). Blocking individual ioctls is a losing game — TIOCLINUX has no equivalent of Linux 6.2's `dev.tty.legacy_tiocsti` knob.
- Two hardlinks, two rules: `NOPASSWD` only ever attaches to the agent-path name.
- Validate with `visudo -cf` on aido's own temp copy before atomic rename. **sudo-rs's `visudo` validates only `/etc/sudoers`, not `sudoers.d`** — aido must run the check explicitly on its own file.

### Why zero arguments and not a request id on argv

sudo closes all fds ≥ 3 before exec (`closefrom`), so an fd-passed request channel does not survive the backend hop. And sudoers cannot constrain argument *arity* — only "no arguments" or a trailing wildcard. Rather than accept a wildcard or a bearer token in argv (visible in `/proc`, and caller-controlled), the gate takes **nothing**: it calls back to the broker, the broker identifies the *gate* via `SO_PEERPIDFD`, walks `gate → sudo/doas → aido` with pidfds pinned by `(pid, starttime)`, matches the pending record it minted for that exact `aido` process, and atomically consumes the nonce. Nothing to spoof, no lookup to race.

**The gate is directly invocable by any member of the `aido` group, and that is designed for, not wished away.** A hostile direct invocation gets: empty argv (the rule enforces it), an environment reset by sudo *and* rebuilt from scratch by the gate, no pending request record → no nonce to consume → nothing to execute. It exits non-zero having done nothing privileged, and emits a high-severity audit record. The gate is safe to invoke by anyone **because the gate is the policy engine** and derives every input from kernel-attested facts and root-owned state, never from what it was handed.

---

## Flows

**Human (password required).** `aido svc restart nginx` → broker classifies HUMAN (cgroup does not match a live scope) → evaluate allowlist → deny-list → rate limits → freeze state → mint one-use request → front-end execs `sudo /usr/libexec/aido/aido-gate-auth` → sudo runs its own PAM conversation on the fresh pty it allocated. **aido never sees, handles, or caches the password** — the entire credential-handling bug class stays out of scope. Gate re-decides independently, then execs.

**Agent (enrolled, passwordless, still confirmed).** Same, except the cgroup id matches a live root-created scope → ENROLLED AGENT. Pre-flight runs the dry-run (`apt-get -s install`) and, for removals, intersects the resolved set against the protected-package set and count cap. `confirm_agent_actions = true` by default, so it goes to the confirmation flow — **not** to a password prompt. Then `sudo /usr/libexec/aido/aido-gate-nopass`.

**Yolo confirmation (the default-on safety setting).** aido learns yolo state **only** from the agent's self-declaration over the authenticated channel, never inferred from ancestor argv (an attacker who wants the prompt skipped simply omits `--dangerously-skip-permissions`, and an in-session toggle never appears in argv at all). The declaration affects logging and wording, never authorization. The broker creates a pending request with an absolute monotonic deadline and returns a request id **immediately** — the front-end blocks on the broker socket, not on a terminal read, so the agent gets a resumable structured "pending approval" state rather than a wedged tool call. Prompt is rendered on, in strict priority order: (1) an `aido watch` session — the trusted-by-construction default; (2) the session TTY captured at enrollment, after re-verifying ownership; (3) `aido approve <req-id>` from any other authorized terminal.

The prompt shows post-canonicalization resolved argv, matched rule id + `file:line`, digest result, caller classification *and its evidence*, declared reversibility and write scope, and the cached dry-run preview. Every agent-supplied string is stripped of ANSI/C0/C1, bidi overrides (U+202A–202E, U+2066–2069), and confusable/homoglyph path characters — the approval prompt is itself an attack surface. Responses require a **typed token** (the action name, not `y`) and are rejected if they arrive faster than a human reaction floor. Requests are de-duplicated by fingerprint with exponential backoff so a looping agent cannot induce prompt fatigue. Timeout → **DENY**.

**Agent registration.** `aido agent add claude-code --exec ...` is root-only through the password path. Registration mints an identity, which is exactly why root is the right requirement. It writes `/etc/aido/agents.d/<name>.toml` with `(st_dev, st_ino)` pinning and provenance, and **prints every time** that the registry is an availability control, not a security control. Content-hash pinning of agent binaries is deliberately *not* a boundary: real installs live in user-writable, self-updating `$HOME` paths (measured: `CLAUDE_CODE_EXECPATH` under `~/.local/share/claude/versions/`), so a hash registry over an attacker-writable file is decoration.

**Enrollment** — the part that actually creates capability — happens per session: `aido session start --agent claude-code --project /srv/app -- --dangerously-skip-permissions`. Through the password path, so the human authenticates once. `aido-session` then creates the root-owned transient scope under `aido.slice`, captures and validates the human's controlling TTY as the confirmation channel, mints the scope-bound HMAC token, passes one end of a socketpair as an inherited fd (possession of the fd *is* the proof of lineage), and execs the registry-pinned harness with a scrubbed environment — refusing to launch if the exec-time environment carries `LD_PRELOAD`/`LD_AUDIT`/`LD_LIBRARY_PATH`/`NODE_OPTIONS`/`PYTHONSTARTUP`.

**Policy install (two-phase, semantically diffed).** Parse with `deny_unknown_fields` on every struct — an unrecognized key in a root-owned rule file is a **hard fail**. Run `aido check`. Then compute a **semantic capability diff**, not a text diff: for each rule, the set of `(binary, argv-shape, path-prefix, confirm-requirement, write-scope, network-flag)` tuples, reported in plain language — *"now permits writes anywhere under /etc, previously only /etc/nginx"* — including reachability changes caused by ordering. A textual diff hides a capability change made by loosening a regex by one character. Confirm on a trusted channel, commit atomically (staging → fsync file → fsync dir → rename → fsync dir), bump the monotonic generation, hash it into the audit chain. The bump invalidates outstanding grants, cached decisions, repo-policy trust hashes, and generated agent docs.

---

## Rule matching semantics

The single most important design choice after the broker. **Named actions, not command strings.**

The ruleset allowlists root-authored action IDs that expand **internally** to a fixed argv, so no agent-supplied token ever reaches a mount/volume/exec/config/hook flag. Convergent evidence that this is right: polkit action IDs and Gemini CLI's `ShellTool(git status)` arrived at the same shape independently.

- **No intra-argument globs anywhere, ever.** sudoers-style argument globbing is an argument-injection engine: arguments are matched as one concatenated `fnmatch` string, so `*` crosses whitespace *and* matches `/`. `/usr/bin/python3 /opt/utils/*.py` is a root shell; `cat /var/log/messages*` is an arbitrary-file reader.
- **Typed matchers only:** literal · enum-of-literals · anchored regex (anchors injected by the parser, `size_limit` and `dfa_size_limit` set) · path-under-dirfd · int-range · unit-name · package-name.
- **"No args specified" means zero arguments permitted**, not any. (doas's default is the permissive one; take the strict half.)
- **Flags are deny-by-default per binary** — no blocklist of flag *values* can be complete when the value space is an entire configuration namespace.
- **Last-match-wins with explicit negation** as a backstop, documented loudly.
- **Deny-list is compiled into the binary**, evaluated *after* allow matching on the canonicalized tuple, non-overridable by any config layer, and enumerated by **capability** (spawns a shell / reads arbitrary files / writes arbitrary paths / executes a config-specified program / has network egress) rather than by binary name — because name-based denial is defeated by a copy, a hardlink, or a busybox multicall applet.

### Default rule tiers

| Tier | Risk | Default | Examples |
|---|---|---|---|
| **T0 diag-read** | low | on | `journalctl --no-pager -u <unit-allowlist>`, `dmesg --nopager`, `systemctl status\|show\|cat\|is-active`, `ss -tulpnH`, `lsof -nP -Dr -i`, `iptables -S/-L` |
| **T1 svc-control** | medium | on | `systemctl <start\|stop\|restart\|reload\|try-restart> <unit-allowlist>`, `daemon-reload`, `reset-failed`, `kill --signal=<enum> --kill-whom=main`. `enable`/`disable` **off** by default |
| **T2 pkg-install** | high | on | `apt-get -y --no-install-recommends install -- <deb-name>{1,20}`, `apt-get update`, `dnf -y install`, `pacman -S --needed --noconfirm`, `apk add --no-cache`. snap/flatpak **off** |
| **T3 pkg-remove/upgrade** | high | on, capped | `apt-get -y remove -- <deb-name>{1,10}`, `apt-get -y upgrade`. `full-upgrade` **off**. Removals cascade — resolved set is intersected against a protected-package set and a count cap |
| **T4 sys-tunable** | high | narrow | `sysctl -w` on an **enum of keys with per-key value ranges** (`vm.max_map_count`, `fs.inotify.max_user_watches`, `net.core.somaxconn`), `timedatectl set-ntp\|set-timezone`, in-process `/etc/hosts` and `/etc/sysctl.d` writers |
| **T5 net-filter-write** | high | via verbs | `aido net fw-allow <port>/<proto>` renders a fixed per-backend template *after* snapshotting the ruleset to a root-owned 0600 backup. Rollback restores from aido's own snapshot, never via `iptables-restore` |
| **T6 fs-mount** | critical | **off** | Only `mount <target>` where target is an exact member of the fstab `user`/`noauto` set. `mount` with caller-influenced options is unconditionally equivalent to full root |
| **T7 container-daemon** | critical | **off** | No safe subset exists — `docker run -v /:/host` rewrites root's password hash. Default action *prints rootless podman/Docker guidance*. Never `usermod -aG docker` |
| **T8 lang-global-install** | critical | **off** | npm/pip install-time code execution is documented normal behavior. Default action *routes to userspace*: pipx, `uv tool install`, `npm prefix ~/.local`, venv |
| **T9 priv-file-ops** | high | very narrow | Only `mkdir`-then-`chown`-to-caller under an enumerated prefix. **No generic privileged-write primitive of any shape** |

**The T9 theorem, stated once and applied everywhere: arbitrary root write implies root code execution.** `/etc/ld.so.preload`, `/etc/cron.d`, `/etc/sudoers.d`, and `/root/.ssh/authorized_keys` each suffice on their own. So `tee`, `dd`, `cp`, `mv`, `install`, `ln`, `sed -i` with a caller-nameable destination are *equivalent to full root* and are permanently denied.

Highest-leverage entries in the default set are the ones that **execute nothing**: T7 and T8 convert the most common agent privilege request into *no privilege at all*. Same for T0 — `journalctl(1)` states members of `systemd-journal`, `adm`, and `wheel` can read all journal files, so group membership beats a rule.

### Compiled-in deny-list (by capability class)

Shells · interpreters (`python*`, `perl`, `ruby`, `node`, `awk`, `lua`, `php`, `expect`) · exec proxies (`env`, `nice`, `nohup`, `timeout`, `setsid`, `stdbuf`, `taskset`, `chrt`) · namespace/priv tools (`unshare`, `nsenter`, `chroot`, `systemd-run`, `systemd-nspawn`, `machinectl shell`, `setpriv`) · `find` with `-exec*`/`-delete`/`-fprintf` · `xargs`/`parallel` (argv from attacker-controlled stdin) · editors and `sed -i` · **pagers** (`less`/`more`/`man`/`bat` honor `LESSOPEN` and `!cmd`) · debuggers (`gdb`, `strace`, `perf`, `bpftrace`) · **`git` as root in any form** (`-c core.pager=`, `-c core.sshCommand=`, `alias.*=!`, repo-local `.git/hooks/*`) · `ssh`/`scp`/`socat`/`nc` (ProxyCommand, LocalCommand) · `tar --to-command`/`--checkpoint-action=exec`/`-I` · all generic write primitives · `dd` to any device · `mkfs*`/`wipefs`/`fdisk`/`parted` · `rm -rf` on system paths · recursive `chmod`/`chown`/`setfacl` on system paths, any setuid/setgid/`o+w` mode outside a workspace · `setcap` and any file-capability grant · all user/group/password tools · **anything that writes the thing that decides** (`/etc/sudoers*`, `/etc/doas.conf`, `/etc/polkit-1/**`, `/etc/pam.d/*`, `/etc/nsswitch.conf`, **`/etc/aido/**`**, aido's own binaries and audit log) · `/etc/ld.so.preload` and `ldconfig` with a caller path · `/etc/environment`, `/etc/profile*`, `/etc/default/*` · kernel modules and `kexec` · dangerous sysctl keys (`kernel.core_pattern`, `kernel.modprobe`, `kernel.sysrq`, `kernel.unprivileged_*`) and **all file-driven sysctl forms** (`-p`, `--load`, `--system`) · shutdown/reboot/kexec · `systemctl enable|disable|mask|link|revert|edit|set-property|set-environment` and unit-file writes · `iptables-restore`/`nft -f`/`nft flush ruleset` · `mount --bind`/`--move`/`-o suid,dev,exec`/`mount -a` · `docker run|build|exec|cp|commit|load`, `podman --privileged` · any network-fetch-piped-to-interpreter · cron/at/`run-parts`/`logrotate -f` with a caller config · audit and SELinux/AppArmor disabling · **any write to package-manager config, keyrings, or sources** · any package op naming a local file, path, URL, or VCS ref (`dpkg -i`, `rpm -i`, `apt install ./x.deb`) · any package-manager flag that redirects config or hooks (`apt -o DPkg::Pre-Invoke::='...'` **is** a `/bin/sh`-as-root injection through a rule that only meant to install a package).

**Enforce with a CI gate** that greps every allowlisted binary against a vendored GTFOBins list and fails the build.

---

## CLI surface

```
aido [-n|--non-interactive] [--output human|json] [--explain] [-k] [--unattended] <subcommand>
aido -- <argv>...                    # shorthand for `aido exec --`

EXECUTION
  aido exec -- <argv>...             # escape hatch; same matching, no looser
  aido pkg     install|remove|update|upgrade|dry-run|search|info
  aido svc     start|stop|restart|reload|status|logs|reload-units
  aido net     listeners|who-holds|fw-list|fw-allow|fw-revoke|fw-rollback
  aido hosts   add|remove|list
  aido sysctl  get|set [--persist]
  aido time    set-ntp|set-tz
  aido dir     claim <path>
  aido mount|umount <fstab-target>
  aido global-install|container      # execute NOTHING by default; print the unprivileged equivalent

INTROSPECTION
  aido explain [--json] -- <argv>    # full trace: every rule considered, per-position matcher
                                     # outcome, matched rule file:line, resolved binary + digest,
                                     # the exact environment, the classification AND its evidence
  aido explain --why-not <rule-id> -- <argv>
  aido list | aido -l [--as <agent>] # effective policy. Listing ANOTHER agent's effective
                                     # permissions is itself a privileged action (polkit precedent)
  aido check [--fuzz]                # linter + executable [[test]] blocks; distinct exit codes for
                                     # lint-warning / lint-error / test-failure so CI gates each
  aido doctor [--json] [--fix]       # backend/kernel/env report + EVERY OTHER PATH TO ROOT that
                                     # makes aido decorative (pre-existing NOPASSWD, wheel/docker
                                     # membership, writable unit dirs, writable PATH, writable rc)

CONFIRMATION
  aido watch                         # hold a terminal as the trusted confirmation channel (default)
  aido pending | aido approve <id> | aido deny <id>
  aido freeze [--session <id>] [--for <dur>] --reason <text>   # instantly deny every agent path;
                                                               # human path stays available
  aido thaw                          # human path only

SESSIONS / GRANTS / AGENTS / POLICY  (all root-authored, all through the password path)
  aido session start --agent <a> --project <p> -- <harness-args>
  aido grant <dur> --profile <p> --project <p> --max <n> | aido grants | aido revoke <id>
  aido agent add|list|remove
  aido policy install <path> | aido policy rollback | aido project trust
  aido audit tail|query|verify
  aido agentdoc --format claude|agents|codex
  aido mcp                           # stdio MCP server: aido_run/explain/list_rules/request_grant
```

Contradictory safety flags (`--unattended` with `--confirm`, `-n` with `--explain-interactive`) are a **hard parse-time error**, never a silent precedence choice.

---

## Stack

**Rust**, 2024 edition, MSRV 1.85, stable toolchain.

Why: the trust boundary in aido is almost entirely **parsing and matching** — TOML rules, argv canonicalization, deny-list evaluation, `/proc` text. That is precisely the code shape that produced sudo's CVE record (CVE-2021-3156 Baron Samedit heap overflow in argv unescaping; CVE-2023-22809 sudoedit; CVE-2025-32462/32463). Rust removes that bug class at the boundary and makes the rule engine a pure, fuzzable, proptest-able function. Precedent has moved: **sudo-rs** (Trifecta Tech / ISRG Prossimo, two external audits) is the default sudo in Ubuntu 26.04 LTS and packaged in Debian 13+, Fedora, Arch, Alpine, NixOS — distro security teams now accept Rust in exactly this niche. And `rustix` gives `openat2`, `execveat`, `close_range`, `pidfd_open`, `SO_PEERPIDFD` with `OwnedFd`/`AsFd` types that make **fd lifetime a compile-time property**; Rust's runtime spawns no threads before `main`.

Rejected: **Go** — PAM needs cgo (destroying the static/cross advantage exactly where you need it), the runtime is multi-threaded before `main` while Linux `setuid`/`setresuid` are per-thread, and `SysProcAttr` is a fixed struct with no `pre_exec` hook, so `close_range`/`PR_SET_NO_NEW_PRIVS` are awkward. **C** — writing a new rule-language parser, argv matcher, and deny-list evaluator in C is volunteering for sudo's exact bug class.

| Purpose | Crate |
|---|---|
| Syscalls (both binaries) | `rustix` (fs, process, procfs, termios) + `rustix-linux-procfs` — verifies `/proc` fstype/ownership so a bind-mounted `/proc` makes reads **fail**, not lie |
| `/proc` parsing (front-end only) | `procfs` 0.18 |
| FFI escape hatch | `libc` (`initgroups`, `getpwnam_r`, `prctl`) |
| CLI | `clap` 4 derive, **`env` feature OFF** |
| Config | `serde` + `toml` 0.9+, `#[serde(deny_unknown_fields)]` on **every** struct |
| Wire + audit | `serde_json` (fixed schema, size-capped) |
| Patterns | `regex` (linear-time hybrid NFA/DFA — no ReDoS from an admin-added pattern) |
| Byte-exact argv | `bstr` + `std::ffi::OsStr` — one `to_string_lossy()` in the matcher is a policy bypass |
| Errors | `thiserror` everywhere; `anyhow` **banned** from the gate and any decision path (its context strings leak paths) |
| Audit sinks | `systemd-journal-logger` primary; `syslog` (AF_UNIX `/dev/log`) fallback for Alpine/OpenRC — a **socket**, not a symlinkable path |
| Secrets | `zeroize` + `secrecy` |
| Digest pinning | `sha2`, verified on the already-open `O_PATH` fd immediately before exec |
| Capabilities | `caps` |
| Human-facing quoting | `shlex` **one-way only** — never `shlex::split` |
| Dev | `assert_cmd`, `predicates`, `assert_fs`, `rexpect` (the only way to test "human IS prompted" and "yolo agent still gets a confirmation"), `insta`, `proptest`, `trycmd`, `cargo-fuzz` |
| Supply chain | `cargo-deny`, `cargo-audit --deny warnings` (plain `cargo audit` goes green on unmaintained crates), `cargo-auditable`, `cargo-vet` |
| Cross-build | `cargo-zigbuild` for the macOS→Linux dev loop; release artifacts built natively on `ubuntu-24.04` and `ubuntu-24.04-arm` runners — **no QEMU in the release path** |
| Packaging | `cargo-deb`, `cargo-generate-rpm`, APKBUILD, PKGBUILD, Nix module |

### Testing

- **Native on macOS:** `aido-policy` unit tests, `proptest` invariants, `insta` snapshots, `cargo-fuzz` targets. Fast inner loop, no VM.
- **Proptest invariants** (not examples): deny always wins · canonicalization is idempotent · appending an argument never flips deny→allow · rule load order never changes a deny · no generated argv escapes the declared matcher set.
- **Fuzz three parsers separately:** TOML rule deserializer, argv canonicalizer/matcher, deny-list evaluator.
- **Differential compliance harness** (the centerpiece): the same ruleset and invocation driven against `sudo`, `sudo-rs`, and `OpenDoas` asserting **identical** allow/deny outcomes, across Ubuntu 24.04 / Ubuntu 26.04 (sudo-rs default) / Debian 13 / Fedora+SELinux-enforcing / Alpine-musl-OpenDoas / Arch, × {x86_64, aarch64} natively, × kernels 5.15 / 6.1 / 6.6+, × cgroup v1 and v2, × `ptrace_scope` 0 and 1. Plus a no-escalator row asserting clean fail-closed.
- **Every spoof and attack from the threat model ships as a named adversarial test** asserting DENY + an audit record. **CI fails if an `#[ignore]`d test passes.**
- Environment scrubbing is regression-tested with a **real payload asserted absent** in the child's `/proc/self/environ`.
- Lints: `clippy` with `disallowed_methods` banning `to_string_lossy`, non-absolute `Command::new`, `shlex::split`, and `std::env::var` **inside the privileged crates** — otherwise the default-on safety setting is one `export` away from off and the agent controls the export.

---

## Milestones

Each is independently shippable.

**M1 — Policy core, matcher, `explain`.** *No privilege, no Linux required.* The 5-crate workspace with the trust boundary drawn on day one. `aido-policy` as a pure function. Typed matchers, no globs. Compiled-in deny-list. `aido-sys` trait layer with `MacOsStub`. Ships as a standalone auditor: `aido explain`, `aido check --fuzz`, `aido rule list|test`, the versioned JSON envelope with a stable append-only exit-code and denial-code taxonomy, `aido agentdoc`. Test discipline established here and enforced forever. **Deliberately absent: any ability to execute anything.**

**M2 — Human path end to end.** *A hardened, always-prompting sudo front-end.* Complete without any agent concept. Backend adapter with runtime capability probing across sudo/sudo-rs/OpenDoas; snippet generation with `visudo -cf`/`doas -C` validation, inode verification, atomic rename, and a **functional** post-install probe. `aido-gate` as the second independent policy engine with the full hardening set (`close_range` first, `/dev/null` substitution, `statfs` `/proc` check, ancestor ownership walk from a pinned dirfd, `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)`, `O_PATH` + `fstat` + digest pin + `execveat(fd, "", AT_EMPTY_PATH)`, env from a fixed allowlist, `PR_SET_NO_NEW_PRIVS`, faithful exit-status and signal propagation). Audit subsystem with hash chain + journald. `aido doctor`. Distro packages. **Every invocation prompts** — exactly what a cautious operator wants to deploy first, and it already delivers the allowlist, the deny-list, and the audit trail.

**M3 — Broker and out-of-band confirmation.** *Still no passwordless path.* `aidod` socket-activated, `SO_PEERPIDFD` + `PIDFD_GET_INFO` peer identification with the documented fallback, namespace-divergence guard, gate-lineage walking. One-use nonce records with monotonic deadlines. The confirmation channel layer: `aido watch`, ownership-verified session TTY, `aido approve|deny|pending`, liveness pings, **DENY when no channel is live**. Full prompt-integrity work (ANSI/bidi/homoglyph stripping, typed tokens, reaction-time floor, de-dup with backoff, resumable pending envelope). `aido freeze`/`thaw`. Confirmation is purely **additive** here — every path still requires a password — so it ships as a safety upgrade with no new attack surface, and it proves the hardest architectural claim (that confirmation can live outside the agent's process tree) before anything depends on it.

**M4 — Agent enrollment and the passwordless path.** *The milestone the product exists for — deliberately last among the load-bearing ones.* `aido-session` through the password path: root-owned transient scope under `aido.slice`, TTY capture and validation, scope-bound HMAC token with a replay ledger and per-agent revocation, socketpair fd as proof of lineage, registry-pinned harness exec with a scrubbed environment. `aido agent add|list|remove` with `(st_dev, st_ino)` pinning, provenance, expiry, and the mandatory printed disclaimer. Broker classification by cgroup identity, activation of the `aido-gate-nopass` hardlink, `confirm_agent_actions` defaulting to true. Agent-declared yolo state over the authenticated channel. **Non-delegable one-use grants** so a sub-agent, Task subagent, or MCP hop is a fresh decision. `SECURITY.md` published with the plain statement that agent detection is a UX mechanism, not a security boundary. **All eight requirements now met.**

**M5 — Narrowing the confirmation, bounded grants, volume controls.** The "users can turn it off" requirement, implemented as a **narrowing rather than a switch**: `trust.d` records over (agent × project × action class) with mandatory reason and expiry, gating `confirm = "never"` and the per-invocation non-persistable `--unattended`; a persistent banner and a distinct high-severity audit record on every use. `aido grant <dur> --profile --project --max` with monotonic TTLs, use counters persisted *before* exec, and the invariant that an agent-path invocation can never mint or extend a grant. Persistent token buckets with three escalating thresholds (annotate → force confirmation even under a grant → deny + notify + optional auto-freeze), plus a separate **rule-novelty** bucket because breadth is a better anomaly signal than depth. **This is the milestone that prevents the realistic failure mode — someone disabling the safety default to unstick a workflow.**

**M6 — Ergonomics, named-action profiles, harness integration.** *All explicitly non-load-bearing.* The curated verb surface with per-backend argv rendering, mandatory dry-run pre-flight for installs, protected-package intersection for removals, in-process schema-aware writers for `/etc/hosts` and `/etc/sysctl.d`, firewall verbs with snapshots and rollback by aido's own rule ids. Dry-run previews rendered into the confirmation prompt (`apt-get -s`, `nft -c`, `systemd-analyze verify`), output-capped and cached against the request fingerprint. `aido init` wizard composing from profiles. `aido agentdoc` hook packs, `aido shell-init` EPERM hints verified against policy before printing, `aido mcp`, `aido audit tail|query` with session replay. Documented throughout: **the hook is a convenience; the guarantee is that the action is impossible without aido.**

**M7 — Confinement, supply chain, external audit.** Hardening to 1.0. The full differential compliance matrix. Per-rule least privilege: capability bounding sets instead of full uid 0 where one or two caps suffice, Landlock rulesets derived from declared write scope (explicit audit record on kernel-version degradation, policy option to deny-on-degrade), seccomp filters. Two-phase installs with semantic capability diffs and `aido policy rollback`. Signed rule bundles (minisign/cosign, no insecure-skip path), `min_aido_version`, unknown-matcher-kind as a hard parse error rather than match-anything. Provably telemetry-free default build (networking behind a non-default cargo feature, seccomp denying `AF_INET` socket creation, a CI job under `strace` asserting no non-`AF_UNIX` socket), reproducible builds, SBOM, `aido verify-self`. **Then an external security audit on the sudo-rs precedent** — without which distro security teams will not package a privilege broker.

---

## Top 5 risks

**1. The trust model is inverted.** "Agents get no prompt, humans do" makes the *absence* of proof-of-humanity the grant condition, and every cheap signal is caller-controlled.
→ Root all authorization in kernel-attested facts only (`SO_PEERPIDFD` + root-created cgroup scope). Demote every env var, `comm`, `cmdline`, and ancestry name to an audited hint with zero weight. Make misclassification able only to *withhold* capability. State in SECURITY.md that detection is a UX mechanism, and **size the allowlist so that a full impersonation is survivable.**

**2. The NOPASSWD gate is directly invocable.** Any design that says "only the front-end calls the helper" has already lost.
→ Zero-argv rule, no env input, gate re-decides independently from root-owned state, one-use nonce bound to a specific `aido` pid via broker-walked lineage. Direct invocation does nothing and logs at high severity. `timestamp_timeout=0` so the agent path can never ride a cached human credential.

**3. The confirmation is self-approvable by the agent.** The agent owns aido's stdin, stdout, and pty.
→ Confirmation leaves the agent's process tree entirely: `aido watch`, the ownership-verified session TTY, or `aido approve` from another terminal. Never a channel the requester supplied. Typed-token responses, human reaction-time floor, ANSI/bidi/homoglyph stripping, bounded deadlines that **fail closed**, de-dup with backoff to prevent prompt fatigue. The off switch is a narrowing (`trust.d` + per-rule `confirm = "never"` + per-invocation `--unattended`), never a global boolean — because **the most likely real failure is that a noisy prompt gets turned off.**

**4. One overbroad allowlist entry voids the whole design.** One allowlisted shell, interpreter, pager, editor, exec proxy, container runtime, or `apt -o DPkg::Pre-Invoke::=` is unrestricted root regardless of how the arguments are written.
→ Named actions expanding to fixed argv · no intra-argument globs anywhere · flags deny-by-default per binary · deny-list compiled in and enumerated by capability class · **feature omission as the primary security property**, written down as a refusal list · CI gate against a vendored GTFOBins list.

**5. Self-widening writes and TOCTOU/symlink races.** CVE-2021-3156's exploitation raced sudo's `ts_mkdirs()` with a symlink; sudo-rs's own audit found a path traversal (GHSA-2r3c-m6v7-9354). And because aido is deliberately **not** setuid, `ld.so` never sees `AT_SECURE` and does **no** `LD_*` scrubbing for it — that is entirely aido's problem.
→ Enforce paths by **resolution, never by string prefix**: `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` from a pinned dirfd, reject `..`, reject any symlink or non-root-owned component, reject `st_nlink>1` on write targets, verify ownership/mode **after** opening via `fstat`, and walk **every ancestor** (one writable ancestor defeats all per-file checks). **Exec the fd you validated, not the path you validated.** Audit to a socket, not a path. Build the child environment from an **allowlist**, never a denylist, and regression-test each hazard's removal with a real payload.

---

## Suggestions — TL;DR

Beyond the eight stated requirements. Ranked by value-to-effort; explanations follow.

| # | Suggestion | Effort | TL;DR |
|---|---|---|---|
| 1 | JSON decision envelope + denial taxonomy | S | Versioned JSON verdict with a stable error code and a concrete next step, so the agent reacts correctly instead of guessing from exit 1. |
| 2 | `aido explain` decision trace | S | Prints which rule matched at which `file:line`, the resolved binary, normalized argv, and the environment — without executing. |
| 3 | Fail-closed confirmation + request de-dup | S | Confirmations time out into a **deny**, never a hang; an identical request inside a short window reuses the prior verdict instead of re-prompting. |
| 4 | Per-rule env allowlist | S | Child environment built from scratch; loader and interpreter injection variables hard-refused. |
| 5 | Rate limiting with escalating friction | S | Token buckets per (session, rule, project) escalate allow → forced confirmation → deny + notify. A runaway agent is throttled before it is catastrophic. |
| 6 | `aido freeze` / `thaw` kill switch | S | One root-owned flag instantly denies every agent path; human path stays available for recovery. |
| 7 | `aido agentdoc` generator | S | Emits a policy-derived CLAUDE.md / AGENTS.md block stamped with the policy hash so CI detects drift. |
| 8 | Shell EPERM hint | S | A command that just failed on permissions prints one line — `try: aido <same command>` — verified against policy before suggesting. |
| 9 | Typed argv matchers | M | Per-position matchers instead of globbing a flattened command string. **This one is load-bearing, not optional.** |
| 10 | `aido check` linter + policy unit tests | M | Type-checks the ruleset, flags dangerous constructs, runs `[[test]]` blocks in CI and pre-commit. |
| 11 | Hash-chained audit log | M | Each JSONL record carries its predecessor's hash, mirrored to journald, so gaps and edits are detectable. |
| 12 | Time-boxed revocable grants | M | `aido grant 15m --profile docker-dev --max 20` mints a root-held grant that expires hard and cannot be renewed by the agent. |
| 13 | Attested caller identity | L | Root broker identifies the caller race-free from the socket peer and enrolled cgroup lineage. **Also load-bearing.** |
| 14 | Two-phase policy install + semantic diff | M | Stages the change, renders a **capability-level** diff, confirms, commits atomically, bumps a generation counter. |
| 15 | MCP server | M | `aido_run` / `aido_explain` / `aido_list_rules` / `aido_request_grant` with elicitation-based confirmation. |
| 16 | `aido log` forensic TUI | M | Filter the audit chain by agent, session, project, rule, decision, time; session replay; export. |
| 17 | Dry-run preview in the prompt | M | Rules declare a no-side-effect preview whose output is shown at confirmation time, so approval is informed rather than reflexive. |
| 18 | Binary identity pinning | M | A rule pins its target by resolved path + content hash or owning package; a replaced or shadowed binary fails closed. |
| 19 | Per-project narrowing-only scoping | M | A checked-in `.aido/policy.toml` can only further restrict, and only if root recorded its hash. |
| 20 | Anomaly / novelty escalation | M | Escalate on statistical surprise: a rule never used this session, unusual breadth, off-hours burst. |
| 21 | Signed rule bundles + curated profiles | M | Shareable versioned profiles (`docker-dev`, `web-dev`, `k8s-dev`, `embedded`) verified offline before install. |
| 22 | Telemetry-free build, verifiable at runtime | S | No network code in the default build, enforced by seccomp and a CI test asserting zero outbound syscalls. |
| 23 | `aido doctor` | S | Reports the backend, unavailable features, kernel probes, live confirmation channels — **and every other path to root.** |
| 24 | `aido init` wizard | M | Detects backend, distro, and installed agents; proposes a starter policy; previews the diff; installs atomically. |
| 25 | Landlock + capability-bounded children | L | Even allowed commands run with only the caps and filesystem access the rule declares, not full uid 0. |
| 26 | I/O session recording with redaction | M | Rules can capture the child's stdout/stderr or a full pty transcript, size-capped and redacted. |
| 27 | Off-box audit shipping | M | Optionally stream records to a remote collector so a compromised host cannot erase its own history. |
| 28 | `aido undo` | L | Rules declare an inverse and/or a pre-snapshot hook, so recent actions can be reversed under the same policy checks. |
| 29 | `aido shell --record` | M | A sanctioned escape hatch: a time-limited, fully recorded root shell, so humans stop reaching for raw `sudo`. |
| 30 | Two-person approval for a critical class | M | Rules tagged critical need approvals from two distinct humans on independent channels. |

---

## Suggestions — explained

**1–2. Machine-readable envelope and `explain`.** The primary consumer of aido is a language model, and `exit 1` with a prose message is the worst possible interface for one: the model guesses, retries with a mangled command, or gives up and asks the human to run raw `sudo` — defeating the tool. A versioned envelope (`schema_version`, `decision`, `rule_id`, `rule_source`, `resolved_exe`, `resolved_exe_sha256`, `argv_normalized`, `session_id`, `grant_id`, `audit_id`, `remediation`) with a **stable, append-only** denial code taxonomy lets the agent branch correctly: "this needs a grant" → request one; "this is permanently denied" → stop asking; "this needs confirmation" → surface it to the human and wait. `explain` is the same engine with execution removed, which is also how a human answers *"how do I know my ruleset does what I think it does?"* — the question every allowlist system eventually fails to answer.

**3. Fail-closed confirmation and de-dup.** Two failure modes, both fatal in practice. A confirmation that blocks forever wedges the agent's tool call and gets the feature disabled by an annoyed operator; a confirmation that times out into *allow* is not a confirmation. So: absolute monotonic deadlines, timeout → deny, and a resumable structured "pending" state so the agent's session survives an arbitrary approval delay. De-dup matters because a looping agent that re-requests the same action 40 times induces **prompt fatigue** — after the fifth identical prompt a human stops reading, which is a worse security state than no prompt at all.

**4. Per-rule env allowlist.** Because aido is not setuid, `ld.so` does not scrub `LD_*` for it. `LD_PRELOAD`, `LD_AUDIT`, `GLIBC_TUNABLES`, `GCONV_PATH`, `BASH_ENV`, `PYTHONSTARTUP`, `NODE_OPTIONS`, `PERL5OPT`, `LESSOPEN`, `GIT_*`, `http_proxy` (a caller-supplied proxy on `apt-get update` is an invisible machine-in-the-middle), `SUDO_ASKPASS` — none of these appear in argv, so argv matching cannot see them. Allowlist, never denylist, and assert absence in the child's `/proc/self/environ` with a real payload in tests.

**5. Rate limiting with escalating friction.** The distinctive agent failure mode is not one malicious command; it is a loop. Fifty `apt-get install` calls in ninety seconds is not a decision, it is a bug, and the right response is friction rather than a binary allow/deny. Three thresholds — annotate the audit record, then force confirmation *even under an active grant*, then deny + notify + optionally auto-freeze. Track a **separate novelty bucket**, because an agent suddenly touching twelve rules it has never used is a better anomaly signal than depth on one.

**6. Kill switch.** When something is going wrong, the operator needs one command that stops it *now*, and they need it to not lock them out of fixing the problem. `aido freeze` denies every agent-path invocation and leaves the human path working. Pair it with the dead-man default (no live confirmation channel → deny) so the system fails safe without anyone typing anything.

**7. `agentdoc`.** Agents behave far better when told what they may do than when made to discover it by failing. Generate the CLAUDE.md/AGENTS.md block *from the policy*, stamped with the policy generation hash, and let `aido check --agentdoc-fresh` fail CI when the doc has drifted. This closes the loop where documentation says one thing and the ruleset does another.

**8. EPERM hint.** Pure adoption. Someone types `systemctl restart nginx`, gets a permission error, and — because the shell hook checked the policy first and only suggests when the answer is yes — sees `try: aido svc restart nginx`. Without something like this, users learn the tool by hitting walls, and a tool learned by hitting walls gets replaced by `sudo -i`.

**9 & 13. Typed matchers and attested identity are not really suggestions.** They are listed here because they arrived as feature findings, but the design cannot ship without them — a glob-based matcher is an argument-injection engine, and env-var-based identity is trivially forged. Treat them as requirements.

**10. `aido check`.** A security policy nobody can test is a security policy nobody trusts. Executable `[[test]]` blocks inside the ruleset — `argv X must be allowed by rule Y`, `argv Z must be denied` — turn policy edits into a CI-gated change like any other code. Distinct exit codes for lint-warning vs lint-error vs test-failure so a pipeline can gate each independently. Include the shadowing lint: rules unreachable because an earlier deny matched, and rules that *shadow a later deny*, which is the ordering bug everyone makes with last-match-wins semantics.

**11. Hash-chained audit.** Two sinks, both independent: journald for structured querying, and a hash-chained JSONL file where each record carries `seq`/`prev_hash`/`hash` so a deletion or an edit is detectable rather than invisible. `fdatasync` before returning the exec result — an audit record written after the action completes is an audit record that a crash loses. Both the broker *and* the gate emit independently, so a direct gate invocation that bypasses the front-end still leaves a trace.

**12. Time-boxed grants.** The real workflow need: "I'm about to let the agent do twenty minutes of Docker work, stop asking me." A grant scoped to a profile, a project, a max use count, and a hard monotonic expiry gives that without becoming permanent. Two invariants make it safe: the counter is decremented and persisted *before* exec, and an **agent-path invocation can never mint or extend a grant** — only the human path can.

**14. Semantic policy diff.** A text diff of a rule file hides the thing that matters. Loosening a regex by one character can convert "writes under /etc/nginx" into "writes anywhere under /etc", and the diff shows one changed byte. Diff the **capability set** — `(binary, argv-shape, path-prefix, confirm-requirement, write-scope, network-flag)` — and render it in plain language, including reachability changes caused purely by reordering.

**15. MCP server.** The agent-native interface: `aido_run`, `aido_explain`, `aido_list_rules`, `aido_request_grant` as first-class tools rather than shell strings the model has to construct. MCP elicitation can route confirmation through the agent's own client UI, which is a *nicer* channel — but note it is the agent's client, so it never replaces the out-of-band channel for high-tier actions; it forwards to the broker, which still decides.

**16–17. Forensic review and dry-run previews.** Both are about the human's decision quality. `aido log` answers "what did the agent actually do last Tuesday" in one place. Dry-run previews answer the harder question at the moment it matters: an `apt-get remove` prompt that says "this will remove 47 packages including build-essential" produces a different decision than one that says `apt-get -y remove foo`. Run the preview under the same argv validation and scrubbed environment, cap the output, cache it against the request fingerprint.

**18. Binary pinning.** A rule for `/usr/bin/systemctl` should not be satisfiable by a replaced `/usr/bin/systemctl`. Pin by resolved absolute path plus content hash *or* owning package, verify on the already-open `O_PATH` fd immediately before `execveat` — which closes the swap window a path-based check cannot.

**19. Per-project narrowing.** Different repos need different capability. Bind a project root to a profile in root-owned config, and let a checked-in `.aido/policy.toml` **only further restrict** — never add a rule, widen a matcher, drop a confirm requirement, raise a limit, or extend a TTL — and only when root has recorded its sha256. Copies Claude Code's managed-settings property verbatim, for the same reason.

**20. Novelty escalation.** Fixed rate limits catch volume; they miss the single surprising action. Escalate on interpretable, individually-toggleable signals — first use of a rule (on by default), first use in this project, rule-breadth spike, off-hours, novel path prefix — and **always state the reason in both the prompt and the record**. An unexplained "this looked unusual" prompt trains people to click through.

**21. Signed profiles.** Nobody should hand-write a `docker-dev` ruleset. Curated, versioned, signature-bundled profiles verified offline (minisign, or cosign with a stapled inclusion proof) with `min_aido_version`, and **unknown matcher kinds as a hard parse error rather than match-anything** — the fail-open default that has bitten every policy format that allowed it.

**22–23. Telemetry-free and `doctor`.** A privilege broker that phones home will not be installed. Make it *provable*: no network code in the default build, networking behind a non-default cargo feature, a seccomp filter denying `AF_INET`/`AF_INET6` socket creation, and a CI job running the suite under `strace` asserting no non-`AF_UNIX` socket. `doctor`'s most valuable output is the part that undermines aido itself: **every other path to root** — pre-existing `NOPASSWD` entries, `wheel`/`sudo`/`docker`/`lxd` membership, writable unit directories, writable `PATH` entries, writable shell rc files. Any one of them makes aido decorative, and the operator deserves to know before they trust it.

**24. `aido init`.** First-run experience determines whether the starter policy is minimal or `ALL`. Detect the backend, distro, and installed agents, propose a small policy composed **from profiles rather than bespoke matchers**, preview the capability diff, run the linter, install atomically.

**25. Landlock and capability bounding.** The deepest hardening available: even for an allowed command, run the child with only the capabilities and filesystem access the rule declares instead of full uid 0. `systemctl restart nginx` does not need write access to `/home`. Two operational requirements: an explicit audit record when kernel support degrades the confinement, and a policy option to **deny on degrade** rather than silently running unconfined.

**26–27. Recording and off-box audit.** Optional, for teams. A size-capped redacted transcript makes "what did that command print" answerable after the fact. Streaming records off-box means a compromised host cannot erase its own history — the standard reason audit lives elsewhere.

**28. `aido undo`.** The feature users will ask for immediately and that is hardest to do honestly. Only rules that *declare* an inverse or a pre-snapshot hook can be undone, the undo runs through the same policy checks, and the ones that genuinely cannot be reversed must say so rather than pretending. Firewall changes and `/etc/hosts` edits are the natural first candidates because aido already snapshots them.

**29. `aido shell --record`.** The pressure-release valve. Policy will never cover everything, and when it does not, the human's alternative is `sudo -i` — which is unaudited, unbounded, and outside aido entirely. A time-limited, fully recorded root shell keeps that case inside the system. Deliberately human-path only.

**30. Two-person approval.** For the small class of rules where one person's judgment is not enough. Two distinct human principals on independent channels. Only worth building once an org actually asks.

---

## Verification

**M1, natively on macOS:** `cargo test -p aido-policy` · `cargo test --workspace` · `cargo fuzz run rules_toml`, `argv_canon`, `denylist_eval` (60s each in CI, longer nightly) · `cargo clippy -- -D warnings` with the `disallowed_methods` list · `cargo insta test` · `cargo miri test -p aido-policy` · `cargo deny check` + `cargo audit --deny warnings`. Sanity: `aido explain -- apt-get install ripgrep` prints a matched rule with `file:line`; `aido explain -- /bin/sh -c id` prints a deny naming the compiled-in capability class; `aido check --fuzz` exits 0 on the shipped ruleset.

**M2 onward, on Linux (Lima VM locally, containers in CI):**
1. `aido doctor --json` reports the backend, its implementation (sudo vs sudo-rs vs doas), the probed capability matrix, and every other path to root.
2. **Human path prompts.** Under `rexpect`: a plain invocation from a real pty must produce a password prompt. Test asserts the prompt string, not just the exit code.
3. **Snippet is functionally in effect** — not that the file exists. Run the gate with a no-op probe and assert it executed as uid 0. Regression test: install the snippet as `aido.conf` and assert `doctor` reports it as **not in effect** (sudo silently ignores dotted filenames).
4. **Hostile direct gate invocation.** `sudo /usr/libexec/aido/aido-gate-nopass` with no pending request must exit non-zero, perform nothing privileged, and emit a high-severity audit record.
5. **Nonce is one-use.** Replay a consumed request record; second attempt must fail.
6. **Enrolled agent path is passwordless but confirmed.** Start a session, run an allowlisted action from inside the scope, assert no password prompt *and* a pending confirmation appearing on the `aido watch` channel — never on the agent's stdin.
7. **Yolo does not bypass confirmation.** Same, with `--dangerously-skip-permissions` declared. Then assert that *omitting* the declaration also confirms (the declaration must not be the gate).
8. **Confirmation is not self-approvable.** From inside the agent's process tree, attempt to answer the prompt on stdin, on `/dev/tty`, and by writing to the parent's `/dev/pts/N`. All three must fail to approve.
9. **Timeout denies.** No answer within the deadline → deny, with the agent receiving a structured pending-then-denied envelope rather than a hang.
10. **Cgroup spoofing fails.** From the user's own shell, attempt to write a pid into `aido.slice/agent-N.scope/cgroup.procs` — must fail `EACCES`. Then attempt classification with `CLAUDECODE=1` set and assert the request is classified **human** and prompted.
11. **Env scrubbing.** Invoke with `LD_PRELOAD`, `BASH_ENV`, `NODE_OPTIONS`, `http_proxy`, `LESSOPEN` set to real payloads; assert each is absent from the child's `/proc/self/environ` and that the payload did not execute.
12. **Symlink and TOCTOU resistance.** Plant a symlink mid-path on the ruleset path, on the exec target, and on the audit log; each must be refused. Swap the target binary between validation and exec; the digest pin on the `O_PATH` fd must catch it.
13. **Deny-list is non-overridable.** Author a rule file that allows `/bin/sh`; assert it is denied and that `aido check` refuses the ruleset at lint time.
14. **Differential compliance.** Same ruleset, same invocations, against sudo / sudo-rs / OpenDoas across the distro × arch × kernel matrix; assert **identical** allow/deny outcomes. Plus a no-escalator row asserting clean fail-closed with exit 19.
15. **Audit chain verifies.** `aido audit verify` passes; then truncate a record and assert it fails.
16. `aido freeze` → every agent-path invocation denied, human path still works, `aido thaw` restores.

CI gates: the GTFOBins grep over every allowlisted binary · `agentdoc` freshness · **fail the build if any `#[ignore]`d adversarial test passes** · the `strace` no-network assertion.
