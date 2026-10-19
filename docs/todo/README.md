# todo — everything not yet built

Written 2026-08-26. Read this first; it is the index and the sequencing argument.

Design plan: `../design-plan.md`. Project rules: `../CLAUDE.md`. Enhancement backlog: `../SUGGESTIONS.md`.

---

## Where the project actually stands

> **Status, 2026-10-19.** M1 complete. M2 split: **M2a done**, M2b in progress (steps 0, 1, 2b, and 7 done: the Linux harness, the `aido-sys-raw` syscalls, strictest overlapping-rule enforcement, and the refusal of a ruleset on a mount a non-root user could have made; the privileged execution path is not built). **Phase 5 part 1 done** (`aido-config`). **Phase 4 done** (`ido`, `ido-bin`, `term-sanitize`). The differential matrix runs in CI and trips the day an exec path appears. Next is **M2b**: Docker now gives a real Linux kernel to run privileged tests in, so the old "blocked on a VM" no longer holds for most of it. Read `../CONCERNS.md` first — it carries the decisions and what is still open.

**Done.** Six crates, and a working executable.

| Crate | What it is |
|---|---|
| `aido-policy` | The pure decision engine: typed per-position matchers with no globs anywhere, the compiled-in deny-list enumerated by capability class, the rule model and TOML loader, the versioned decision envelope with an append-only denial taxonomy |
| `aido-sys` | Syscalls behind traits, `/proc` parsers, ancestry walking, and the `MacOsStub` that forces every fail-closed branch on a non-Linux host |
| `aido-backend` | The backend capability matrix, runtime detection, snippet generation, and the ordered install plan (M2a) |
| `aido-config` | Layered configuration: precedence, origin tracking, the narrowing-only project layer, and XDG path resolution (phase 5 part 1) |
| `aido` | The unprivileged front-end library |
| `aido-bin` | The five-line `aido` entry point, in its own package so the library is measured exactly once |
| `ido` | The buffered human-run command queue: queue file, derived status, picker state machine, runner, `AGENTS.md` splicer (phase 4) |
| `ido-bin` | The `ido` executable and its raw terminal, tested through real processes and a pseudo-terminal |
| `term-sanitize` | Display-only sanitizer for agent-written terminal text, shared by `ido` and the future `aido` prompt |
| `aido-tests` | Reserved for the executing half of the differential matrix; the unprivileged half is `ci/differential/`, run by `just differential` (binary process tests live in `aido-bin/tests`) |

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

- ~~**`crates/aido-sys`**~~ **DONE.** `PrivilegedOps` with `LinuxOps` and `MacOsStub`, procfs parsing from fixture trees, the attestation ladder, the backend probe, and now the descriptor-verified ruleset walk. No `unsafe` yet; `raw` arrives with M2b.
- ~~**`crates/aido` front-end**~~ **DONE, with three gaps:** `explain`, `why-not`, `check`, `list`, `doctor`, `config`, `install --dry-run`, `audit`, `agentdoc` exist. Not built: `check --fuzz`, `rule list|test` (the `[[test]]` blocks of SUGGESTIONS #10), and `doctor --json`. The first two are M6; `doctor --json` is M2b, because verification item 1 needs it.
- ~~**Exit-code taxonomy wired to a real process exit**~~ **DONE.** `aido-bin/tests/binary.rs` asserts 0, 17, 18, and 19 through a real process.
- ~~**Install nightly + `cargo-fuzz`**~~ **DONE.** Three targets run on every push and for thirty minutes nightly.

Exit criterion: `aido explain -- apt-get install ripgrep` prints a matched rule with `file:line`; `aido explain -- /bin/sh -c id` prints a deny naming the capability class; `aido check` exits 0 on the shipped ruleset. Still executes nothing.

### M2 — human path end to end

**Split, because half of it cannot run on the dev host.** See `../CONCERNS.md` § "M2 cannot be finished or verified on this machine".

**M2a — done.** `crates/aido-backend`: the capability matrix, runtime backend detection, sudoers and doas snippet generation, and the ordered install/uninstall plan. All pure, all 100% covered. `aido doctor` now reports the backend, and correctly reports it as *unusable* on a host where a required directive cannot be confirmed.

**M2b — in progress.** The first slice landed 2026-10-14: the ruleset is read through verified descriptors (`aido_sys::read_trusted_dir`), and `aido doctor` reports through it. What is left, in the order to build it:

0. ~~**A Linux test harness, before any syscall code.**~~ **DONE 2026-10-15.** `just linux-test [cargo test args]`, in `ci/linux-test.sh`: the workspace copied into a Docker container and the suite run there as a non-root user. Not on the bind mount, which misreports the checkout as root-owned and intermittently loses a directory created a moment earlier; and not as root, under which file modes are not enforced and every refusal test passes vacuously. Containers give a real kernel for everything in M2b and M3. A VM is needed only for the kernel-version matrix and for M4's systemd scopes.
1. ~~**`aido-sys::raw`**~~ **DONE 2026-10-19, as the crate `aido-sys-raw`.** `close_range` (CLOEXEC-only), `SO_PEERPIDFD`, `PIDFD_GET_INFO`, and `execveat`, in five blocks (six, with `SO_PEERCRED` added the same day), behind `aido_sys::Syscalls` with `HostSyscalls` and a scripted `FakeSyscalls`. A crate rather than a module so that `aido-sys` keeps `forbid(unsafe_code)` and the compiler, not a scan, confines the unsafe code; `aido-sys-raw/tests/unsafe_budget.rs` is the backstop. Open for step 4: the gate's process model (exec in place, or fork and wait, which needs `fork` in the budget) and what it does on a pre-5.11 kernel where `CLOSE_RANGE_CLOEXEC` is refused. `SO_PEERCRED` now has its seam, `Syscalls::peer_cred`; open for step 2: `pidfd_open` and the liveness check need one of their own. See `../CONCERNS.md`.
2. **A minimal `aidod`, pulled forward from M3.** The gate as built refuses with `NoPendingRequest` unless a root-minted entry exists under `/run/aido/req`, and only a root daemon can mint one, so the human path cannot work without a broker. M2b's `aidod` does exactly this: accept a connection on `/run/aido/broker.sock` (systemd socket activation), identify the peer by the attestation ladder in `kernel.rs`, classify it `Unattested` (no cgroup lookup until M4), evaluate, mint the entry, return the nonce. No confirmation channel, no `freeze`, no cgroup classification. Load the rules with `aido_sys::load_trusted_rules` and mint with its `generation.id()`: the gate will compute the same value from the same bytes, through the same `aido_policy::load_rule_files` the front-end uses. `/run/aido` is `0755` with the socket `0660 root:aido` and `req/` `0700`, as the design plan's file table now says.
2b. ~~**Overlapping rules resolve to the strictest, and `check` says when they overlap.**~~ **DONE 2026-10-19.** Every action that accepts a command — the same program byte for byte, an argument list that accepts the canonical operands — now contributes its requirement: any human-only one refuses an agent, and the confirmation is the strictest any of them demands (critical tier, then `confirm = "always"`, then the agent setting). That holds in `aido_policy::evaluate`, so a caller naming a permissive duplicate gains nothing and the gate inherits it, and in the new `aido_policy::evaluate_command`, which replaces the front-end's `best_match` so the broker and `aido exec` search the ruleset through the engine rather than beside it. A decision cites the action whose requirement it carries; a tie cites the action asked for, or the first declared. `RuleSet::overlaps` reports every pair of actions that can accept one command — decided exactly for literal, enumeration, range, path, and name positions, reported as *possible* where a pattern or a search too large to finish leaves it open, never silent — and `aido check` prints it, each certain overlap with a command the engine accepts under both. The shipped rules are disjoint and `tests/shipped_rules.rs` keeps them so. Standing property: adding a rule never removes a confirmation, and rule order never changes one. No last-match-wins, no negation. See `../CONCERNS.md`.
3. **`aido exec -- <argv>`** in the front-end: the same matching as `explain`, then the broker round-trip, then exec of `sudo /usr/libexec/aido/aido-gate-auth` (or `doas`), with the backend's exit status passed through. A denial whose remediation is "a human must run this" prints the exact `ido queue` line to run instead. That is phase 4 § 8, first half; the second half (`ido` running an entry through `aido exec`) is M6.
4. **`aido-gate-bin`**: the executable, in its own package like `aido-bin`, installed as `/usr/libexec/aido/aido-gate` with `aido-gate-auth` as a hardlink; `aido-gate-nopass` is not shipped until M4. `close_range` first, `/dev/null` substitution for closed standard descriptors, the `statfs` check on `/proc`, the lineage walk gate → sudo/doas → `aido` pinned by `(pid, starttime)`, the ruleset through `read_trusted_dir`, `O_PATH` + `fstat` + digest pin, `execveat(fd, "", AT_EMPTY_PATH)`, the environment from `aido_gate::child_environment`, `PR_SET_NO_NEW_PRIVS`, faithful exit-status and signal propagation.
4b. **`aido doctor --json`, `--fix`, and the every-other-path-to-root report**, dropped from this list by mistake on 2026-10-14. The report names pre-existing `NOPASSWD` entries, `wheel` / `sudo` / `docker` / `lxd` membership, writable unit directories, writable `PATH` entries, and writable shell rc files; `SECURITY.md` says plainly that it does not exist yet. `--fix` is what the generated sudoers comment and the install notice already tell operators to run, so it has to exist before `install` does.
5. **Executing the install plan**: `aido install` without `--dry-run`. `visudo -cf` on the candidate, inode check, atomic rename, and the functional post-install probe the plan already describes.
6. ~~**Audit sinks**~~ **DONE 2026-10-19.** `aido-sys::audit`: the contract both privileged binaries write through, and the two sinks, not yet wired to either. `AuditSink::append` builds each record from the chain's last record while the log is locked and returns an `AuditReceipt` only a sink can make; `authorize` hands an approval back as `Authorized<T>` only with that receipt, for a record carrying the approval's command and governing action, and drops it otherwise; the broker's mint and the gate's exec, by taking an `Authorized<_>`, are what will keep an unrecorded approval from being acted on. `JsonlLog` is the chain's authority at `/var/lib/aido/audit.jsonl` (not `/var/log`, which is `root:syslog 0775` on Ubuntu): directory by the descriptor walk, file `O_APPEND|O_NOFOLLOW|O_CLOEXEC|O_CREAT` at `0600`, refused unless root's, private, and singly linked, an exclusive `flock` with a bounded wait and the file re-checked once it is held, the tail read from the end, `fdatasync` (plus a directory `fsync` for the first record) and the journald send under the lock before the receipt, any failure from the write on cut back, and a log ending in damage refused rather than continued or restarted, damage `aido audit --log` reports too. `JournaldSink` mirrors each record as one native-protocol datagram through rustix's safe socket API, `AIDO_RECORD` carrying the file line byte for byte, and fails closed where there is no journald; only entries with `_UID=0` count (`aido_audit::journal::query`). `AuditTrail::system` is both; `FakeAuditSink` sits behind a `fake` feature only test builds enable. Decisions and what is open: `../CONCERNS.md`, 2026-10-19.
7. ~~**The one trust check still missing**: a ruleset on a filesystem mounted by a non-root user.~~ **DONE 2026-10-19.** `open_trusted`, `read_trusted_dir`, and `load_trusted_rules` now match every descriptor they open — each component and each rule file — to its mount by the `mnt_id` in `/proc/thread-self/fdinfo/<fd>`, and judge that mount in `/proc/thread-self/mountinfo`, both read only through descriptors `fstatfs` proves are on procfs. Refused to every reader: a FUSE mount (`fuse`, `fuseblk`, `fuse.*`) unless it names exactly one `user_id` and that is `0`; an `idmapped` mount; a mount the table does not list; a table that cannot be read or does not parse, now refused whole on any malformed line; and everything when the thread is outside the initial user namespace. The two ruleset readers also refuse `nosuid` and `noexec`; `open_trusted` does not, because systemd mounts `/run`, the gate's spool, `nosuid`. Each component is opened `O_PATH`, which asks its filesystem nothing, and its mount is judged before its owner and mode are read and before anything beneath it is looked up, so a user's FUSE daemon is never consulted; what is read is reopened and refused unless it is the inode that passed. A directory's mount is judged before it is listed, and every rule file's before any is read. Matched by mount id, not by `st_dev` as first proposed, because on btrfs no file's `st_dev` appears in mountinfo at all (measured). `aido doctor` names the component, the filesystem, its mount point, and the reason, with the mount's bytes escaped: a FUSE daemon names its own subtype. Off Linux there is no mount table, so the three refuse everything there. See `../CONCERNS.md`.
8. **The executing half of the differential matrix**, in `aido-tests`: the same ruleset run *through* sudo, sudo-rs, and OpenDoas with identical outcomes. `ci/differential/row.sh` fails the build demanding it the moment `doctor` stops reporting the exec path as absent.

Where the password lives, per `howiwork.md` (2026-10-19): an **approved** request from an attested agent takes the `NOPASSWD` hardlink and needs no human password (M4); a **Run with ido** entry, or a human running `aido` directly, takes the `PASSWD` hardlink and is prompted once. The `sudo`/`doas` hop is kept for the uid transition only, because aido ships no setuid bit; it is not the password mechanism. M2b builds the `PASSWD` side of that split, and the beta ships only that side.

One decision, recorded here because the gate's code depends on it: **on the password path, the password is the confirmation.** A rule with `confirm = "always"` yields `allow_with_confirmation`. On the agent path that goes to the out-of-band channel (M3). On the human path it is satisfied by sudo's PAM conversation on the fresh pty, a channel the requesting process tree cannot answer without the secret. The gate knows which path it is on from `argv[0]`: `aido-gate-auth` means a password was typed, so `aido_gate::demanded_confirmation` bites on the `-nopass` name only.


### M3 — out-of-band confirmation

Still no passwordless path: every outcome still goes through the `PASSWD` hardlink. The broker and its one-use nonce records arrive with M2b; this milestone adds the confirmation state machine to it, which is what will later let an approved agent request need no password at all. The namespace-divergence guard. The channel layer: `aido watch`, the ownership-verified session TTY, `aido approve|deny|pending`, and **DENY when no channel is live**. Prompt integrity: every agent-written string through `term-sanitize` (built, shared with `ido`), typed-token responses, a human reaction-time floor, request de-duplication with exponential backoff. Absolute monotonic deadlines; timeout → deny, with the front-end receiving a structured pending-then-denied envelope rather than a hang. `aido freeze`/`thaw`.

Confirmation is purely additive here — every path still needs a password — so this ships as a safety upgrade with no new authentication surface, and it proves the hardest architectural claim before anything depends on it.

### M4 — agent enrollment and the passwordless path

The milestone the product exists for, deliberately last among the load-bearing ones. `aido-session` through the password path: root-owned transient cgroup scope under `aido.slice`, TTY capture and ownership validation, scope-bound HMAC token with a replay ledger and per-agent revocation, socketpair fd as proof of lineage, registry-pinned harness exec with a scrubbed environment. `aido agent add|list|remove` with `(st_dev, st_ino)` pinning and the mandatory printed disclaimer that the registry is an availability control. Broker classification by cgroup identity, activation of the `aido-gate-nopass` hardlink (the `NOPASSWD` rule attaches to that name and only that name), `confirm_agent_actions` defaulting true, non-delegable one-use grants. **This is the milestone where "approved means no human password" becomes true**: an attested agent's approved request runs through the `NOPASSWD` hop; a human, or any unattested caller, keeps the `PASSWD` hop (invariant 2). `SECURITY.md` published.

### M5 — narrowing, bounded grants, volume controls

`trust.d` records over (agent × project × action class) with mandatory reason and expiry; `--unattended` as a non-persistable per-invocation flag; a banner and a high-severity audit record on every use. Time-boxed grants with counters persisted before exec. Token buckets escalating annotate → force confirmation even under a grant → deny and notify, plus a separate rule-novelty bucket.

### M6 — ergonomics, profiles, harness integration

The verb surface (`aido pkg|svc|net|hosts|sysctl|time|dir|mount`), dry-run previews rendered into the confirmation prompt, `aido init`, `aido mcp`, EPERM shell hints, audit query with session replay, `check --fuzz`, `rule list|test`, and `ido` running a queued entry through `aido exec` (phase 4 § 8, second half). The `AGENTS.md` block becomes v2 and gains one line: *never run `ido run` or `ido drop`*. An agent that runs them gains nothing it could not do by running the command itself — `ido` holds no privilege, and a queued `sudo` has no terminal to prompt on — but the block should say so rather than rely on it.

### Verification checklist, against `../design-plan.md` § Verification

| # | Item | State |
|---|---|---|
| M1 | Everything listed | Done; `just verify` is the gate |
| 1 | `doctor --json` with backend, implementation, capabilities, other paths to root | Backend and capabilities yes; `--json` and other paths no (M2b 4b) |
| 2 | Human path prompts, under `rexpect` on a real pty | M2b |
| 3 | Snippet functionally in effect; dotted-filename regression | M2b 5 |
| 4 | Hostile direct gate invocation does nothing privileged | Decision core tested (`aido-gate`); binary M2b 4 |
| 5 | Nonce is one-use | Validation tested; consumption needs the broker (M2b 2) |
| 6–10 | Enrolled agent path, yolo, self-approval, timeout, cgroup spoofing | M3 and M4 |
| 11 | Env scrubbing with real payloads in the child's `/proc/self/environ` | Allowlist built and tested in `aido-gate::env`; child assertion M2b 4 |
| 12 | Symlink and TOCTOU resistance on ruleset, exec target, audit log | Ruleset done 2026-10-14; audit log done 2026-10-19 (sink built, not yet wired); exec target M2b 4 |
| 13 | Deny-list non-overridable; `check` refuses a rule naming a shell | Done |
| 14 | Differential compliance | Unprivileged half done and in CI; executing half M2b 8 |
| 15 | Audit chain verifies and detects truncation | Done |
| 16 | `freeze` / `thaw` | Engine honours `frozen`; the commands are M3 |

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
4. Phase 4             DONE 2026-10-14 — ido: queue, picker, runner, `ido add`,
                       the willyoumarryme acceptance test, man pages.
5. M2b                 STARTED 2026-10-14 — the ruleset is read through verified
                       descriptors; `just linux-test` runs the suite on Linux.
                       Left, in order: aido-sys::raw, a minimal aidod (minting only), `aido exec`,
                       aido-gate-bin, executing the install plan, the audit
                       sinks, the executing half of the differential matrix.
6. Phase 3             beta .deb + publish, human path only, no NOPASSWD shipped.
                       Ships aidod too: without the nopass hardlink it grants
                       nothing a password did not.
7. M3                  out-of-band confirmation on the broker from M2b.
8. M4                  enrollment + the passwordless path.
9. M5, M6              narrowing, grants, verbs, harness integration.
10. Phase 5 (part 2)   predefined profiles, config introspection.
11. M7                 confinement, signing, external audit.
```

M2b moved down the list on purpose: writing syscall code that has never executed
is the one thing most likely to produce a root exploit in this project, and
`cargo check --target` is not evidence it works. That is why the Linux test
harness is M2b's step 0 and not an afterthought. The reasoning is in
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
5. **DECIDED 2026-10-14: the broker's minting half is M2b, not M3.** The gate acts only on a root-minted request, so a human path with no broker is a human path that cannot execute. M3 keeps the confirmation channels, `freeze`, and the namespace guard.
6. **DECIDED 2026-10-14, restated 2026-10-19: on the password path, the password is the confirmation.** `confirm = "always"` reaches the out-of-band channel only on the passwordless path. The password itself lives next to `ido` and direct human runs, never on an approved agent request; the `sudo`/`doas` hop is the uid transition, kept because aido has no setuid bit. See M2b above and `howiwork.md` mismatch 5.
7. **DECIDED 2026-10-14: the gate executable is `aido-gate-bin`**, the same shape as `aido-bin` and `ido-bin`, so the pure `aido-gate` library stays measured at 100% and the binary is tested through real processes.
8. **DECIDED 2026-10-14: Linux tests run in Docker, as a non-root user, on a copy of the checkout.** A VM is for the kernel-version matrix and for M4's systemd scopes only. The old "blocked on a VM" was true of the machine, not of the work.
9. **DECIDED 2026-10-14, amended 2026-10-19: the `aido-sys-raw` crate holds the five syscalls that need `unsafe`** — `execveat`, `close_range`, `SO_PEERPIDFD`, `SO_PEERCRED`, `PIDFD_GET_INFO` — because rustix 1.1 wraps the rest of what the gate and broker are known to need without `unsafe`, and decodes `SO_PEERCRED` unsoundly (budget 6, decided 2026-10-19; see `../CONCERNS.md`). Two foreseeable additions are not in it: `fork`, if the gate outlives the command it runs, and a per-descriptor `fcntl` fallback below 5.11. Each is a budget change decided with the gate.
