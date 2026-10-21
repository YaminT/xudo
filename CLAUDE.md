# aido — project rules

`aido` is a privilege broker: it decides whether a privileged command runs as root. A bug here is a root exploit, not a crash. Every rule below exists because of a specific historical CVE or a specific documented escape. Follow them exactly.

Product source of truth: `howiwork.md` — what the system is and how it behaves; derived views (README, diagrams) follow it. This file owns the engineering and security rules below; the three invariants appear in both and may be weakened by neither.

Design plan: `docs/design-plan.md`. Enhancement backlog: `docs/SUGGESTIONS.md`. Decision log: `docs/CONCERNS.md`.

---

## The three invariants

These are not style preferences. A change that weakens any of them must be rejected in review, no matter how convenient.

1. **Agent detection is not a security boundary.** Authorization comes only from kernel-attested facts (`SO_PEERPIDFD` + a root-created cgroup scope under `aido.slice`). `CLAUDECODE`, `argv[0]`, `comm`, `cmdline`, `/proc/<pid>/exe`, and process ancestry are *unauthenticated hints*: record them in the audit trail, never branch authorization on them.
2. **The agent path is never broader than the human path in authentication.** Misclassification may only withhold capability. An unattested caller falls through to the human flow with a password — never a silent downgrade to passwordless.
3. **Confirmation lives outside the requester's process tree.** Never read a confirmation from stdin, stdout, or `/dev/tty`. No live out-of-band channel means **deny**.

---

## Commit rules

Every commit must satisfy all of the following. `just verify` runs the whole gate locally; CI runs the same commands.

### Coverage: 100%, line and region

**Default is 100% coverage. It is enforced, and the build fails below it.** The only way to land less is an explicit, written waiver from the programmer.

- A waiver is a `#[cfg_attr(coverage_nightly, coverage(off))]` attribute (or a `llvm-cov` exclusion) **plus** a `// COVERAGE-WAIVER(<who>): <why>` comment on the same item naming a concrete reason — not "hard to test".
- `just coverage` fails under the thresholds declared at the top of the `justfile` (`cov_lines`, `cov_regions`, `cov_functions`). Do not lower one to make a build pass; either write the test or write the waiver.
- Untestable-by-construction code (a syscall that cannot be faked) is the reason `aido-sys` exists: put the syscall behind the trait, fake the trait, and test the logic. If you are reaching for a waiver in `aido-policy`, you have put logic in the wrong crate.
- **Two packages are excluded from the measurement, both entry points.** `aido-bin` is the five-line entry point whose exit statuses its own `tests/binary.rs` asserts through a real process. `ido-bin` is the same shape plus the raw terminal, which only a real terminal can exercise, so its `tests/willyoumarryme.rs` drives it through real processes and a real pseudo-terminal. Both are recorded in the `justfile` with their reasons, alongside the one excluded file. Adding another exclusion means writing down why, in the same place.
- **Process-level tests of a binary live in the package that owns it.** Cargo sets `CARGO_BIN_EXE_<name>`, and guarantees a fresh build, only for that package's integration tests. From anywhere else `cargo_bin` silently picks up whatever stale binary sits in `target/` — or nothing, on a clean CI runner.
- **Purge coverage data before measuring** (`just coverage-clean`, already part of `just verify`). Stale profile data from a previous layout reads as a sudden unexplained drop, and the temptation is then to lower a threshold rather than to clean.
- **Prefer deleting an unreachable branch to waiving it.** Three were removed while building M1 — two `ok_or_else` arms on slice ranges that always exist, and a `split().next()` that can never be `None`. A fourth, a serializer error on a plain data struct, became reachable by making the fallback a *denial envelope* and testing it through a generic helper. A branch that cannot be tested usually cannot be reasoned about either.

### Tests are adversarial, not illustrative

- Every security claim gets a test that tries to **break** it, named for the attack: `denies_shell_via_busybox_hardlink`, not `test_deny_list_3`.
- **Property tests over example tests** for the matcher. The standing invariants, which must never be deleted: deny always wins · canonicalization is idempotent · appending an argument never flips deny→allow · rule load order never changes a deny · no generated argv escapes its declared matcher · adding a rule never removes a confirmation · rule order never changes whether a confirmation is demanded.
- **A test that is `#[ignore]`d and passes fails the build.** An adversarial test that starts passing means the attack it encodes now works.
- Snapshot every decision record and every confirmation-prompt string (`insta`) once there is a rendered surface to snapshot. A diff in either is a policy or UX change and must be reviewed as one. *(Done for the surfaces that exist: `aido-policy/tests/contract_snapshots.rs` pins the denial-code wire contract and every prompt string; `aido/tests/render_snapshots.rs` pins every verdict shape through both renderers. Both are exhaustive by construction — adding a denial code or a confirm reason fails compilation until it has a snapshot. Accept a deliberate change with `cargo insta review` or `INSTA_UPDATE=always cargo test`, and commit the `.snap` diff. The M3 confirmation prompt joins them when it exists.)*
- Fuzz the three trust-boundary parsers separately: the TOML rule deserializer, the argv canonicalizer, and the deny-list evaluator.

### Banned in privileged code

`aido-policy`, `aido-sys`, `aido-sys-raw`, `aido-gate`, and `aidod` are privileged crates. Clippy enforces most of this; the rest is on review.

| Banned | Why |
|---|---|
| `to_string_lossy`, `to_str().unwrap()` on argv or paths | Linux argv is arbitrary bytes. One lossy conversion in the matcher is a policy bypass. Compare byte-exact on `OsStr`/`&[u8]`. **One exception, narrowly:** `Path::display()` is permitted for text shown to a human — a message, or the provenance in a trace — because that text is never compared against anything. If a value can reach a comparison, it stays bytes. |
| `std::env::var` / `env::vars` | The caller controls the environment. Reading it in a decision path means the safety default is one `export` away from off. `clap` is compiled without the `env` feature for the same reason. |
| `shlex::split` (splitting a string into argv) | Re-parsing a rendered command string is how you reintroduce injection. `shlex` is for one-way *display* quoting only. |
| `Command::new` with a non-absolute path | No `PATH` search, ever. Resolve absolutely, then exec the fd you validated. |
| `anyhow` | Context strings leak paths into output. Use `thiserror` enums so every failure mode is exhaustively matchable. |
| `unsafe` | `#![forbid(unsafe_code)]` everywhere except the `aido-sys-raw` crate, which denies it at its root and allows it only in its `sys` module, under an unsafe-block budget published in that module's docs. `aido-sys-raw/tests/unsafe_budget.rs` lexes every Rust file in the workspace and fails on any `unsafe` token or lift of `unsafe_code` outside `sys`, on a block count other than the budget, and on any second crate depending on `aido-sys-raw`. Raising the budget is a reviewed change. |
| `unwrap` / `expect` / panicking indexing in a decision path | A panic in the broker is a denial of service; a panic in the gate is undefined policy. Return a typed error and fail closed. |
| Reading policy from any non-root-owned path | Verify ownership and mode on the **opened fd** via `fstat`, never on the path string. |

### Fail closed, always

Every error path denies. There is no "log and continue" in a decision path, no `unwrap_or(true)`, no `Default` impl on a verdict that means allow. `serde(deny_unknown_fields)` goes on **every** config struct: an unrecognized key in a root-owned rule file is a hard parse failure, because silently ignoring a security-relevant directive is the exact sudo-rs-on-Ubuntu footgun this project exists to avoid.

### Paths and exec

- Resolve by **resolution, never string prefix**: `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` from a pinned dirfd.
- Reject `..`, any symlinked component, any non-root-owned component, and `st_nlink > 1` on a write target.
- Walk **every ancestor** — one writable ancestor defeats all per-file checks.
- **Exec the fd you validated, not the path you validated**: `O_PATH` + `fstat` + digest check + `execveat(fd, "", AT_EMPTY_PATH)`. A path-based check has a swap window; an fd does not.
- Never create files in `/tmp`. Root-owned `0700` directories under `/run/aido` and `/var/lib/aido`, `O_EXCL`.

### Deny-list

The deny-list is **compiled into `aido-policy`**, evaluated *after* allow matching on the canonicalized tuple, and structurally non-overridable by any config file. It is enumerated by **capability class** (spawns a shell / reads arbitrary paths / writes arbitrary paths / executes a config-named program / has network egress), never by binary name — name matching is defeated by a copy, a hardlink, or a busybox multicall applet.

Adding any binary to an allowlist requires checking it against the vendored GTFOBins list (`ci/gtfobins.txt`). A hit does not automatically fail the build — `systemctl` is on that list and is also the single most useful thing to allowlist — but it does require an entry in `ci/gtfobins-waivers.txt` naming **the specific technique** and **why the rule makes it unreachable**. The gate rejects a thin rationale and rejects a stale waiver for a binary no rule allowlists any more, so waivers cannot accumulate unread. Widening a rule that owns a waiver means re-checking that waiver's reasoning.

`RuleSet::self_denying_actions` is the in-process half of the same check and runs against the shipped ruleset in the test suite, so it cannot be forgotten.

### Commit messages

Conventional Commits. Subject ≤ 50 chars, imperative. A body only when the *why* is not obvious from the diff. Security-relevant changes name the threat in the body and reference the test that proves the fix.

```
fix(policy): reject argv globs spanning a path separator

sudoers matches arguments as one concatenated fnmatch string, so `*`
crossed both whitespace and `/`. Adds denies_glob_crossing_separator.
```

---

## Toolchain gate

`just verify` — run before every commit; identical to CI.

| Step | Command | Gate |
|---|---|---|
| Format | `cargo fmt --all --check` | no diff |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` | zero warnings |
| Type-check both platforms | `cargo check --workspace` + Linux target | both clean |
| Test | `cargo test --workspace --all-features` | all pass, **no ignored test passes** |
| Doc tests | `cargo test --doc --workspace` | all pass |
| Coverage | `cargo llvm-cov --workspace --all-features --fail-under-{lines,regions,functions} 100` | 100% or a written waiver |
| Undefined behaviour | `cargo +nightly miri test -p aido-policy --lib` | clean. `--lib` only: the proptest harness calls `getcwd`, which miri's isolation blocks, and disabling isolation would weaken the check |
| Supply chain | `cargo deny check` | advisories, bans, licenses, sources all pass |
| Fuzz smoke | `cargo fuzz run <target> -- -max_total_time=60` | no crash |
| TOML format | `taplo fmt --check` | no diff |
| GTFOBins gate | `just gtfobins` | every allowlisted shell-capable binary has a reviewed waiver |
| Linux tests | `just linux-test` | the whole suite on a real Linux kernel in Docker, as a non-root user, on a copy of the checkout. Required before committing syscall code; not in `verify` because it needs Docker |
| Root tests | `just root-test` | the `tests/root_*.rs` targets behind the `root-tests` feature, as real uid 0 in a throwaway container on a copy of the checkout, and nothing else: the rest of the suite assumes an unprivileged user and is not run as root. The mirror of `just linux-test`, sharing its lock; a root test that skipped itself fails the lane. Needs Docker; runs in CI, not in `verify`, and does not yet block (the switch is written in the `root-tests` job) |
| Units | `just units` | every unit file under `packaging/` through `systemd-analyze verify`, which must say nothing and not merely exit 0, and `systemd-analyze security --offline`, which must score no service above `unit_exposure_max`, in a Debian trixie container; the lane first fails a damaged control unit on purpose. Skips, with a message, while `packaging/` holds no unit. Needs Docker and the network; runs in CI, not in `verify` |
| Differential | `just differential` | the static binary inside real distributions: every backend report matches `ci/differential/expected/`, every verdict identical in every row. Needs Docker; runs in CI, not in `verify` |

`rust-toolchain.toml` pins the toolchain; MSRV is declared in the workspace manifest and checked in CI. Nightly is used **only** for `cargo fuzz`, `cargo miri`, and region coverage — never for a shipped build.

## Platform

macOS is a **development and unit-test platform only**. `aido-sys::MacOsStub` returns `Unsupported` for every syscall so a macOS developer cannot accidentally validate a Linux-only assumption; every privileged path must fail closed there. The differential matrix (`just differential`, `ci/differential/`) drives the static binary in Linux containers across sudo / sudo-rs / OpenDoas and a host with no escalator; the executing half, once a gate binary exists, belongs in `aido-tests` and the matrix fails loudly until it is written.

## Rule files

Rule files under `rules/` are code and are tested like it: `tests/shipped_rules.rs` compiles each one in with `include_str!`, so the policy crate stays pure while the files that actually ship are parsed, validated, and attacked on every run. Adding a rule means adding its coverage there; `a_yolo_agent_is_confirmed_on_every_shipped_action` fails loudly on an action with no test.

Two things to know before writing one:

- **The vocabulary is kebab-case throughout** — `one-of`, `int-range`, `path-under`, `deb-name`, `unit-name`.
- **A rule matches the argv byte-for-byte as the kernel delivers it.** Canonicalization does **not** split `--key=value`; that behaviour existed briefly in M1 and fuzzing killed it, because the value of a split can itself look like a long flag and the function had no fixed point. So a rule that accepts both the joined and the split spelling must **list both** — the engine will not unify them. Prefer the joined spelling in an enum, since that is what people type. Enforced by `a_rule_matches_the_argv_the_kernel_delivers_and_not_a_normalized_form`.
- A rule file **cannot declare its own provenance**. `source` is assigned by the loader from the file it parsed, because provenance a rule can set is provenance an operator cannot trust.

## Developer setup

`just setup` points git at `.githooks` (so the gate runs pre-commit) and installs the pinned toolchain. Fuzzing and miri need nightly: `rustup toolchain install nightly --component miri` and `cargo install cargo-fuzz`.

## Crate layout

One row per member of `Cargo.toml`'s `[workspace]`, plus the crates still in review: a crate built in a lane's worktree and not yet a member, whose row opens with `**in review (M2b).**` and loses it when the crate merges. `crates/aido-tests/tests/crate_inventory.rs` fails the build when this table and the manifest disagree in either direction, and holds the tables in `docs/design-plan.md` and `docs/todo/README.md` to the same.

| Crate | Role and rule |
|---|---|
| `aido-policy` | The pure policy engine: `(ruleset, caller facts, request) → Decision`, with the deny-list compiled in. **Zero syscalls, zero I/O.** If it needs the filesystem, it belongs in `aido-sys`. Builds and tests natively on macOS. |
| `aido-backend` | What `aido` asks `sudo`, `sudo-rs`, or `doas` to do: the capability matrix, runtime detection, snippet generation, and the install plan. Pure; running a backend or renaming into `/etc` lives behind `aido-sys`. |
| `aido-config` | Layered configuration for `aido` and `ido`: one precedence order, nothing security-relevant from the environment, a project layer that may only narrow. Pure: it is handed values and never reads a file, a flag, or the environment. |
| `aido-audit` | Tamper-evident audit records: builds them, chains them, verifies a chain. Pure: opening the file and writing the journald mirror is `aido-sys`'s job. |
| `aido-sys` | Every syscall behind a trait, with an in-memory fake for tests. Forbids `unsafe` like every other crate; the five calls that need it come from `aido-sys-raw`. |
| `aido-sys-raw` | The five system calls that cannot be made safely — `close_range`, `SO_PEERPIDFD`, `SO_PEERCRED`, `PIDFD_GET_INFO`, `execveat` — and the kernel-written `PidfdInfo` and `PeerCred`. The only crate that does not forbid `unsafe_code`: it is allowed only in `sys`, within a published block budget. Only `aido-sys` may depend on it. |
| `aido` | The unprivileged front-end **library**: parses a request, loads the root-owned ruleset, asks `aido-policy`, renders the decision. Holds no secret, makes no decision. |
| `aido-bin` | The `aido` executable: argument parsing and an exit code, nothing else. Its own package so the library is compiled, and therefore measured, exactly once. Its `tests/` run the real binary as a process. Excluded from coverage, never from `just test`. |
| `aido-wire` | **in review (M2b).** The wire protocol between `aido` and `aidod`: the messages and the parser for them. |
| `aidod` | **in review (M2b).** The root broker, the authority on classification and confirmation: identifies its peer from kernel-attested facts, decides with the engine `aido explain` uses, and mints bounded one-use requests. |
| `aidod-bin` | **in review (M2b).** The `aidod` executable, socket-activated on `/run/aido/broker.sock`. Its own package, like `aido-bin`. |
| `aido-gate` | The gate's decision core: a *second independent policy engine* that re-decides from root-owned state and trusts nothing it was handed. Pure. Assume a hostile local user invokes the gate directly with no arguments. |
| `aido-gate-bin` | **in review (M2b).** The gate executable, installed as `aido-gate` with `aido-gate-auth` as a hardlink. Its own package, like `aido-bin`, so `aido-gate` stays pure and measured. |
| `ido` | The buffered human-run command queue, as a library: queue, picker state machine, runner, `AGENTS.md` splicer. **Unprivileged** — it holds nothing to leak, so it runs commands with the human's own `PATH` — but every field it renders is agent-written and goes through `term-sanitize`, and argv is executed as stored, never through a shell. Reads no environment; the binary passes it in. |
| `ido-bin` | The `ido` executable: collects the environment once and owns the raw terminal (via `rustix`, no `unsafe`). Excluded from coverage like `aido-bin`; its `tests/` run real processes and a real pseudo-terminal. |
| `term-sanitize` | Display-only sanitizer for agent-written text bound for a terminal. Shared by `ido` and, later, `aido`'s confirmation prompt, so the two cannot drift. Its output is never compared or executed. |
| `aido-tests` | Tests that belong to the workspace as a whole. Today that is `tests/crate_inventory.rs`, the check on this table. Reserved for the executing half of the differential matrix; the half that exists today is `ci/differential/`, a shell harness, because its job is to start containers. |
