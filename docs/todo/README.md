# todo — everything not yet built

Written 2026-08-26. Read this first; it is the index and the sequencing argument.

Design plan: `../design-plan.md`. Project rules: `../CLAUDE.md`. Enhancement backlog: `../SUGGESTIONS.md`.

---

## Where the project actually stands

> **Status, 2026-08-28.** M1 complete. M2 split: **M2a done**, M2b blocked on a Linux VM. **Phase 5 part 1 done** (`aido-config`). Next unblocked item is **phase 4, `ido`**. Read `../CONCERNS.md` first — it carries the blocker, the decisions, and what is still open.

**Done.** Six crates, and a working executable.

| Crate | What it is |
|---|---|
| `aido-policy` | The pure decision engine: typed per-position matchers with no globs anywhere, the compiled-in deny-list enumerated by capability class, the rule model and TOML loader, the versioned decision envelope with an append-only denial taxonomy |
| `aido-sys` | Syscalls behind traits, `/proc` parsers, ancestry walking, and the `MacOsStub` that forces every fail-closed branch on a non-Linux host |
| `aido-backend` | The backend capability matrix, runtime detection, snippet generation, and the ordered install plan (M2a) |
| `aido-config` | Layered configuration: precedence, origin tracking, the narrowing-only project layer, and XDG path resolution (phase 5 part 1) |
| `aido` | The unprivileged front-end library |
| `aido-bin` | The five-line `aido` entry point, in its own package so the library is measured exactly once |
| `aido-tests` | The real binary run as a process; the future differential matrix |

`aido explain`, `why-not`, `check`, `list`, `doctor`, and `agentdoc` all work. Four starter rule files ship and are tested as code.

**The gate:** 373 tests, 100% coverage on lines, regions, and functions with **zero line-level waivers**, zero clippy warnings, `cargo deny` clean, miri clean, three fuzz targets clean, a GTFOBins waiver gate, and a pre-commit hook. Nightly and `cargo-fuzz` are installed, so the fuzz and miri lanes have actually run — and fuzzing found a real bug on its first execution (see `../CONCERNS.md`).

**Not done.** Everything with a syscall in it. There is still **no privileged path**: nothing this project builds can execute a command as root, and `classify()` returns `Unattested` for every caller on every platform, so every request routes to the password path.

---

## Two numbering schemes, one project

The design plan numbers **milestones M1–M7** (technical layers). The user numbers **phases** (delivery stages): phase 1 was planning, phase 2 was the first development pass, and phases 3–5 are specified in the sibling files here. They are different axes and both are kept.

| File | Covers |
|---|---|
| `phase-3-packaging-and-publish.md` | Debian/Ubuntu `.deb`, apt repository, one-line install, GitHub publication, SEO and AI-crawler discoverability, security disclosures, beta labelling |
| `phase-4-ido.md` | `ido` — the buffered human-run command queue, its TUI, `AGENTS.md` integration, and the `willyoumarryme` acceptance test |
| `phase-5-configuration.md` | Configuration layering and precedence for every binary, plus shipped predefined profiles |

Milestones M1(remainder)–M7 are listed below rather than in separate files, because each is already specified in the design plan; what follows is the delta and the ordering.

---

## Remaining milestone work

### M1 remainder — make it runnable

Nothing here needs Linux or privilege, so it all runs on the macOS dev host.

- **`crates/aido-sys`** — every syscall behind a `ProvenanceSource` / `PrivilegedOps` trait. Three implementations: `LinuxProcFs` with an injectable procfs root so fixture trees drive unit tests, `LinuxKernel` (`openat2`, `execveat`, `close_range`, `pidfd_open`, `SO_PEERPIDFD`, `PIDFD_GET_INFO`, `statfs`), and `MacOsStub` returning `Unsupported` for everything so a macOS developer cannot accidentally validate a Linux-only assumption. This is the only crate permitted `unsafe`, confined to a `raw` module with a published line budget.
- **`crates/aido` front-end** — `aido explain [--json]`, `aido explain --why-not <rule-id>`, `aido check [--fuzz]`, `aido rule list|test`, `aido agentdoc --format claude|agents|codex`. `clap` compiled **without** the `env` feature. `main` stays a thin shim over a fully-tested library so the 100% floor holds; if a waiver is ever needed, `main.rs` is the honest place for the first one.
- **Exit-code taxonomy wired to a real process exit** — the `ExitCode` enum exists and is tested, but nothing calls `std::process::exit` yet.
- **`insta` snapshots** — of every decision record and every rendered explain output. Cannot be written until there is a renderer; `CLAUDE.md` already flags this as not-yet-wired.
- **Install nightly + `cargo-fuzz`** and actually run the three fuzz targets. They have only ever been compile-checked.

Exit criterion: `aido explain -- apt-get install ripgrep` prints a matched rule with `file:line`; `aido explain -- /bin/sh -c id` prints a deny naming the capability class; `aido check` exits 0 on the shipped ruleset. Still executes nothing.

### M2 — human path end to end

**Split, because half of it cannot run on the dev host.** See `../CONCERNS.md` § "M2 cannot be finished or verified on this machine".

**M2a — done.** `crates/aido-backend`: the capability matrix, runtime backend detection, sudoers and doas snippet generation, and the ordered install/uninstall plan. All pure, all 100% covered. `aido doctor` now reports the backend, and correctly reports it as *unusable* on a host where a required directive cannot be confirmed.

**M2b — needs a Linux VM.** Everything below.

A hardened, always-prompting sudo front-end, complete without any agent concept. Backend adapter with runtime capability probing across sudo / sudo-rs / OpenDoas; snippet generation with `visudo -cf` on aido's own temp copy, inode verification, atomic rename, and a **functional** post-install probe rather than a file-existence check. `aido-gate` as the second independent policy engine with the full hardening set (`close_range` first, `/dev/null` substitution for closed fds, `statfs` `/proc` check, ancestor ownership walk from a pinned dirfd, `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)`, `O_PATH` + `fstat` + digest pin + `execveat(fd, "", AT_EMPTY_PATH)`, environment rebuilt from an allowlist, `PR_SET_NO_NEW_PRIVS`, faithful exit-status and signal propagation). Audit subsystem: journald primary, `AF_UNIX /dev/log` fallback, hash-chained JSONL secondary with `fdatasync` before returning. `aido doctor [--json] [--fix]` including the every-other-path-to-root report.

Needs a Linux VM in the loop for the first time (Lima locally, containers in CI).

### M3 — broker and out-of-band confirmation

Still no passwordless path. `aidod` socket-activated, `SO_PEERPIDFD` + `PIDFD_GET_INFO` peer identification with the `SO_PEERCRED` + `(pid, starttime)` fallback, namespace-divergence guard, gate-lineage walking. One-use nonce records with absolute monotonic deadlines. The confirmation channel layer: `aido watch`, the ownership-verified session TTY, `aido approve|deny|pending`, and **DENY when no channel is live**. Full prompt-integrity work: ANSI/C0/C1 and bidi-override stripping, typed-token responses, a human reaction-time floor, request de-duplication with exponential backoff. `aido freeze`/`thaw`.

Confirmation is purely additive here — every path still needs a password — so this ships as a safety upgrade with no new authentication surface, and it proves the hardest architectural claim before anything depends on it.

### M4 — agent enrollment and the passwordless path

The milestone the product exists for, deliberately last among the load-bearing ones. `aido-session` through the password path: root-owned transient cgroup scope under `aido.slice`, TTY capture and ownership validation, scope-bound HMAC token with a replay ledger and per-agent revocation, socketpair fd as proof of lineage, registry-pinned harness exec with a scrubbed environment. `aido agent add|list|remove` with `(st_dev, st_ino)` pinning and the mandatory printed disclaimer that the registry is an availability control. Broker classification by cgroup identity, activation of the `aido-gate-nopass` hardlink, `confirm_agent_actions` defaulting true, non-delegable one-use grants. `SECURITY.md` published.

### M5 — narrowing, bounded grants, volume controls

`trust.d` records over (agent × project × action class) with mandatory reason and expiry; `--unattended` as a non-persistable per-invocation flag; a banner and a high-severity audit record on every use. Time-boxed grants with counters persisted before exec. Token buckets escalating annotate → force confirmation even under a grant → deny and notify, plus a separate rule-novelty bucket.

### M6 — ergonomics, profiles, harness integration

The verb surface (`aido pkg|svc|net|hosts|sysctl|time|dir|mount`), dry-run previews rendered into the confirmation prompt, `aido init`, `aido mcp`, EPERM shell hints, audit query with session replay.

### M7 — confinement, supply chain, external audit

Differential compliance matrix across sudo / sudo-rs / OpenDoas × distro × arch × kernel. Landlock and capability bounding per rule. Two-phase policy installs with semantic capability diffs. Signed rule bundles. Provably telemetry-free build. Then an external security audit.

---

## Recommended sequence

Strict numerical order is the wrong order. Two changes are worth making deliberately.

```
1. M1 remainder        DONE — aido-sys + the explain CLI. Makes it runnable.
2. M2a                 DONE — backend model, snippets, install plan. No syscalls.
3. Phase 5 (part 1)    DONE — aido-config: precedence, origins, narrowing-only
                       project layer, XDG paths, `aido config [--schema]`.
4. Phase 4             ido. No privilege at all. Highest value per unit of risk.
5. M2b                 BLOCKED ON A VM — the gate's syscalls, the real sudo hop,
                       the functional probe, the differential matrix.
6. Phase 3             beta .deb + publish, human path only, no NOPASSWD shipped.
7. M3                  broker + out-of-band confirmation.
8. M4                  enrollment + the passwordless path.
9. M5, M6              narrowing, grants, verbs, harness integration.
10. Phase 5 (part 2)   predefined profiles, config introspection.
11. M7                 confinement, signing, external audit.
```

M2b moved down the list on purpose: writing syscall code that has never executed
is the one thing most likely to produce a root exploit in this project, and
`cargo check --target` is not evidence it works. The reasoning is in
`../CONCERNS.md`.

**Config layering moved earlier, and is now done.** The reasoning below is kept because it is why:

**Why config layering moves earlier.** Precedence is the thing that is painful to retrofit: once three binaries each read config their own way, unifying them is a rewrite. The *foundation* (layer order, `deny_unknown_fields`, which keys are env-settable) should land with M2 while there are only two consumers. The *profiles* half genuinely belongs late, once there are enough rules to bundle.

**Why `ido` moves before the passwordless path.** `ido` needs no root, no cgroups, no broker, and no policy engine. It delivers the entire "the agent cannot run this, so a human runs it" story with none of M4's risk, and it makes the product useful to someone who would never enable a `NOPASSWD` rule. It is also the natural landing place for `aido`'s `HumanPathOnly` and `NoConfirmationChannel` denials — see phase 4.

**Why phase 3 ships before M3/M4.** The earliest defensible publication point is right after M2, when the tool is a hardened always-prompting sudo front-end. The beta `.deb` must **not** install the `NOPASSWD` hardlink or its sudoers rule at all; that arrives with M4 behind an explicit opt-in. Publishing a passwordless-root mechanism before an external audit, with no reviewed enrollment path, would be indefensible.

---

## Open decisions needing an answer before implementation

1. ~~**`ido add` is specified twice.**~~ **DECIDED:** `ido add` writes
   `AGENTS.md`, `ido queue` buffers. Original text: The phase 4 brief uses `ido add` both for "add these instructions to AGENTS.md" and, implicitly, for "add a command to the buffer". One has to move. Recommendation and reasoning in `phase-4-ido.md` § Command surface.
2. ~~**Where the queue file lives**~~ **DECIDED:** `$XDG_STATE_HOME`, as
   implemented. Original text: — `$XDG_STATE_HOME` (survives reboot, the useful behaviour) versus `$XDG_RUNTIME_DIR` (a real temp file, cleared on logout, matches the word "temp" in the brief). Recommendation: state, with a documented retention cap.
3. ~~**Whether phase 3 publishes a real signed apt repository**~~ **DECIDED:**
   signed `.deb` on Releases, no apt repo yet. Original text: or only signed `.deb` artifacts on GitHub Releases. The one-line install reads very differently in each case.
4. ~~**Whether `ido` and `aido` are one package or two.**~~ **DECIDED:** one
   package; `ido` is not separately installable. Original text: They share the audit and config crates but have completely different privilege stories, and `ido` is installable by someone who does not want `aido` at all.
