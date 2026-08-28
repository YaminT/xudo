# aido — project rules

`aido` is a privilege broker: it decides whether a privileged command runs as root. A bug here is a root exploit, not a crash. Every rule below exists because of a specific historical CVE or a specific documented escape. Follow them exactly.

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
- **Two packages are excluded from the measurement, and no lines are.** `aido-tests` spawns the built binary, which the coverage harness relocates out from under `cargo_bin`; `aido-bin` is the five-line entry point whose exit statuses `aido-tests` asserts through a real process. Both are recorded in the `justfile` with their reasons. Adding a third exclusion means writing down why, in the same place.
- **Purge coverage data before measuring** (`just coverage-clean`, already part of `just verify`). Stale profile data from a previous layout reads as a sudden unexplained drop, and the temptation is then to lower a threshold rather than to clean.
- **Prefer deleting an unreachable branch to waiving it.** Three were removed while building M1 — two `ok_or_else` arms on slice ranges that always exist, and a `split().next()` that can never be `None`. A fourth, a serializer error on a plain data struct, became reachable by making the fallback a *denial envelope* and testing it through a generic helper. A branch that cannot be tested usually cannot be reasoned about either.

### Tests are adversarial, not illustrative

- Every security claim gets a test that tries to **break** it, named for the attack: `denies_shell_via_busybox_hardlink`, not `test_deny_list_3`.
- **Property tests over example tests** for the matcher. The standing invariants, which must never be deleted: deny always wins · canonicalization is idempotent · appending an argument never flips deny→allow · rule load order never changes a deny · no generated argv escapes its declared matcher.
- **A test that is `#[ignore]`d and passes fails the build.** An adversarial test that starts passing means the attack it encodes now works.
- Snapshot every decision record and every confirmation-prompt string (`insta`) once there is a rendered surface to snapshot. A diff in either is a policy or UX change and must be reviewed as one. *(Still unwritten. The blocker named here is gone: `render.rs` exists and `insta` is already a dev-dependency with zero uses.)*
- Fuzz the three trust-boundary parsers separately: the TOML rule deserializer, the argv canonicalizer, and the deny-list evaluator.

### Banned in privileged code

`aido-policy`, `aido-sys`, `aido-gate`, and `aidod` are privileged crates. Clippy enforces most of this; the rest is on review.

| Banned | Why |
|---|---|
| `to_string_lossy`, `to_str().unwrap()` on argv or paths | Linux argv is arbitrary bytes. One lossy conversion in the matcher is a policy bypass. Compare byte-exact on `OsStr`/`&[u8]`. **One exception, narrowly:** `Path::display()` is permitted for text shown to a human — a message, or the provenance in a trace — because that text is never compared against anything. If a value can reach a comparison, it stays bytes. |
| `std::env::var` / `env::vars` | The caller controls the environment. Reading it in a decision path means the safety default is one `export` away from off. `clap` is compiled without the `env` feature for the same reason. |
| `shlex::split` (splitting a string into argv) | Re-parsing a rendered command string is how you reintroduce injection. `shlex` is for one-way *display* quoting only. |
| `Command::new` with a non-absolute path | No `PATH` search, ever. Resolve absolutely, then exec the fd you validated. |
| `anyhow` | Context strings leak paths into output. Use `thiserror` enums so every failure mode is exhaustively matchable. |
| `unsafe` | `#![forbid(unsafe_code)]` everywhere except `aido-sys::raw`, which has a published unsafe-line budget in its module docs. Raising the budget is a reviewed change. |
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

`rust-toolchain.toml` pins the toolchain; MSRV is declared in the workspace manifest and checked in CI. Nightly is used **only** for `cargo fuzz`, `cargo miri`, and region coverage — never for a shipped build.

## Platform

macOS is a **development and unit-test platform only**. `aido-sys::MacOsStub` returns `Unsupported` for every syscall so a macOS developer cannot accidentally validate a Linux-only assumption; every privileged path must fail closed there. Privileged integration tests run in Linux containers and VMs (`aido-tests`), across sudo / sudo-rs / OpenDoas.

## Rule files

Rule files under `rules/` are code and are tested like it: `tests/shipped_rules.rs` compiles each one in with `include_str!`, so the policy crate stays pure while the files that actually ship are parsed, validated, and attacked on every run. Adding a rule means adding its coverage there; `a_yolo_agent_is_confirmed_on_every_shipped_action` fails loudly on an action with no test.

Two things to know before writing one:

- **The vocabulary is kebab-case throughout** — `one-of`, `int-range`, `path-under`, `deb-name`, `unit-name`.
- **A rule matches the argv byte-for-byte as the kernel delivers it.** Canonicalization does **not** split `--key=value`; that behaviour existed briefly in M1 and fuzzing killed it, because the value of a split can itself look like a long flag and the function had no fixed point. So a rule that accepts both the joined and the split spelling must **list both** — the engine will not unify them. Prefer the joined spelling in an enum, since that is what people type. Enforced by `a_rule_matches_the_argv_the_kernel_delivers_and_not_a_normalized_form`.
- A rule file **cannot declare its own provenance**. `source` is assigned by the loader from the file it parsed, because provenance a rule can set is provenance an operator cannot trust.

## Developer setup

`just setup` points git at `.githooks` (so the gate runs pre-commit) and installs the pinned toolchain. Fuzzing and miri need nightly: `rustup toolchain install nightly --component miri` and `cargo install cargo-fuzz`.

## Crate layout

| Crate | Rule |
|---|---|
| `aido-policy` | Pure. **Zero syscalls, zero I/O.** If it needs the filesystem, it belongs in `aido-sys`. Builds and tests natively on macOS. |
| `aido-sys` | Every syscall behind a trait, with an in-memory fake for tests. The only crate allowed `unsafe`, confined to `raw`. |
| `aido` | Unprivileged front-end **library**. Holds no secret, makes no decision. |
| `aido-bin` | The `aido` executable: argument parsing and an exit code, nothing else. Its own package so the library is compiled, and therefore measured, exactly once. |
| `aido-gate` | Privileged executor and *second independent policy engine*. Assume a hostile local user invokes it directly with no arguments. |
| `aidod` | Root broker. The authority on classification and confirmation. |
| `aido-tests` | Runs the real binary as a process, and the future container/VM matrix. Excluded from coverage, never from `just test`. |
