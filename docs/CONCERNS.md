# Concerns, decisions, and things you need to know

Running log. Newest section first. This is where commentary lives instead of a chat transcript, so it should be readable cold, months later, by someone who was not here.

---

## 2026-08-28 — phase 2, part two: probing verified on Linux, and the audit crate

### Verified on a real kernel for the first time

```
$ ssh yamin.lol '/tmp/aido-test --rules /tmp/aido-rules doctor'
platform     linux
hints        4 recorded, 0 trusted
backend      sudo (Sudo version 1.9.15p5)
backend caps 6 of 7 supported
             absent: rejects argument wildcards
```

`platform linux` and four collected hints mean `aido-sys`'s `/proc` ancestry walk
and hint collection ran against a real kernel rather than a fixture tree. The
backend line means the probe genuinely asked `sudo`.

**Toolchain.** `cargo-zigbuild` cross-compiles a 2.1 MB static musl binary on the
Mac, so nothing needs installing on yamin.lol — which is the answer to its 3.3 GB
of free disk and 3 GB of RAM. `brew install zig` plus `cargo install
cargo-zigbuild`; the target was already in `rust-toolchain.toml`.

### The probe is functional, not a version check

This is the piece that turns `aido doctor` from UNUSABLE into a real answer, and
the technique matters more than the code.

`sudo-rs` accepts directives it has not implemented and silently ignores them. So
asking "does this backend honour `timestamp_timeout=0`?" cannot be answered by
reading a version number. The probe feeds a minimal sudoers fragment to the
backend's **own parser** and reads the exit status:

```
$ printf 'Defaults!T timestamp_timeout=0\n...' | visudo -cf /dev/stdin ; echo $?
/dev/stdin: parsed OK
0
$ printf 'Defaults!T nope_not_real=1\n...'     | visudo -cf /dev/stdin ; echo $?
/dev/stdin:1:26: unknown defaults entry "nope_not_real"
1
```

Three decisions inside that:

- **Through `/dev/stdin`, not a temp file.** A predictable path in a
  world-writable directory is a symlink race; this way there is no path to race.
  Verified on the host before writing any code.
- **The fragment grants nothing.** It names `/bin/true` with no arguments, so even
  if it were somehow installed it would authorise a no-op. A test asserts the
  fragment can never contain a `NOPASSWD`.
- **The caller passes the exact directive text, value included.** My first
  version passed the bare option name, and `timestamp_timeout` without a value is
  a syntax error — so the probe reported the control missing on a backend that
  honours it perfectly. Caught by running it on the host, not by a test.

Only `/usr/bin/sudo` and `/usr/bin/doas` are ever interrogated. Anything else
answers `false`, so a caller cannot substitute a cooperative "backend" that
agrees to everything.

### Platform-dependent coverage arrived, and was designed around rather than waived

Predicted for M2b and it happened immediately: the `doas` branches cannot execute
on macOS. Rather than accept a platform-specific hole, the process runner went
behind a `Runner` trait with a fake, so every *decision* built on a probe result —
which directive text to send, how to read a refusal, which paths to interrogate —
is covered on any platform.

What is left is `crates/aido-sys/src/exec/host.rs`: the actual `fork` and pipe
plumbing, whose failure paths need the kernel to fail a read on a descriptor we
own. That one file is excluded by regex, recorded in the `justfile` beside the two
package exclusions. Coverage is still 100% with **no line-level waivers**.

### `crates/aido-audit` — built before the gate, deliberately

A gate that executes before there is a record of what it executed is a gate whose
first incident is unreconstructable. Pure: it builds records, chains them, and
verifies a chain; it does not open a file or talk to journald.

The chain detects an edit, a deletion, a reordering, and a **front truncation** —
that last one matters because without the check, dropping the first N records
produces a log that verifies cleanly and hides everything before it. Two subtler
properties are tested:

- **Resealing an edited record does not help.** Fix a record's own hash and the
  break simply moves one position later, to the record whose `prev_hash` no longer
  matches.
- **Hash fields are length-prefixed**, so text cannot be moved across a field
  boundary to produce the same digest — the classic concatenation ambiguity where
  `("ab","c")` and `("a","bc")` hash alike.

And the limits are written into the crate docs rather than left to be inferred:
this is **not a signature**. An attacker with write access can truncate the log
and rebuild a consistent chain from any point, because the hash input is entirely
in the log. Detecting that needs an off-box copy or a key the attacker does not
hold, both later work. An audit log people over-trust is worse than one whose
limits are stated.

Rendering is **infallible by construction**: a writer that can refuse to render
loses the record it was about to write. If serialization ever failed, the fallback
line still carries the sequence and hash, so the chain stays verifiable across the
gap.

### Still not done in phase 2

`aido-gate` itself, `openat2` resolution with the ancestor ownership walk,
`execveat`, executing the install plan, and the journald sink. `aido doctor` still
reports `exec path absent in this build`, and that remains accurate.

Also: **the answers I asked for in `re.md` did not land.** The file was unchanged
and git was clean; the edit was probably made to the root `re.md` in the window
before it moved to `docs/`. I proceeded on the two defaults that file already
stated — cross-compile rather than free disk, and containers rather than the
host's own `/etc/sudoers.d`. Neither has been exercised yet, because there is no
install path to exercise.

---

## 2026-08-28 — decisions answered, two blockers fixed, host surveyed

### Decisions, now settled

| Question | Answer | Consequence |
|---|---|---|
| Linux environment | `yamin@yamin.lol`, SSH working | See host survey below |
| `ido add` collision | `ido add` writes `AGENTS.md`; `ido queue` buffers a command | Update `todo/phase-4-ido.md` § Command surface, which listed this as unresolved |
| One package or two | **One.** `ido` ships with `aido`, not separately installable | Simplifies phase 3: one `debian/`, one postinst. `ido` cannot be offered to someone who wants nothing to do with `aido`, which was the argument for two — overridden deliberately |
| Distribution | Signed `.deb` on GitHub Releases; no apt repo yet | Phase 3 § 4 shrinks: no `aptly`/`reprepro`, no `aido-keyring`, no `gh-pages`. The checksum-verified one-liner becomes the documented install |
| Queue file location | `$XDG_STATE_HOME` — "do whatever", so the existing behaviour stands | No change; `paths.rs` already does this and explains why |

### Host survey: yamin.lol

```
Ubuntu 24.04.4 LTS   kernel 6.8.0-124-generic   x86_64
sudo 1.9.15p5 (the C sudo, not sudo-rs)
Docker 29.5.1, usable unprivileged (yamin is in the docker group)
cgroup v2 present
sudo-rs 0.2.2 available in apt
yamin: uid 1000, groups include sudo, docker, dev
no Rust toolchain
disk: 3.3 GB free of 38 GB (91% used)
RAM: 3 GB total, ~0 available
```

Three consequences worth knowing:

1. **Do not build Rust on that host.** 3.3 GB free and 3 GB RAM will not
   comfortably hold a toolchain plus a target directory, and a parallel codegen
   run risks the OOM killer. Plan: cross-compile on the Mac with
   `cargo-zigbuild` — the Linux targets are already installed — and ship only the
   binary. Alternative is freeing ~10 GB.
2. **Run privileged tests in Docker containers on that host, not on the host.**
   That avoids writing `/etc/sudoers.d` on a machine the user actually uses, and
   it is also how the sudo / sudo-rs / OpenDoas matrix gets built. Note the
   `docker` group is root-equivalent, so this is a convenience, not a sandbox.
3. **`PIDFD_GET_INFO` needs kernel 6.13; this is 6.8.** `SO_PEERPIDFD` (6.5+)
   works. So the design's documented fallback — `SO_PEERCRED` plus a
   `(pid, starttime)` pin — is the path that will actually run there, and the
   primary path stays untested until there is a newer kernel. Good validation
   that the fallback was worth designing; a real limitation for M3.

### macOS support: partial is cheap, full is a different design

Asked, and worth writing down rather than answering once in chat.

Already works on macOS: `explain`, `why-not`, `check`, `list`, `config`,
`agentdoc`, `doctor`. The whole policy engine is pure and platform-independent.

The **human path** could work with moderate effort: macOS ships `sudo` and honours
`/etc/sudoers.d`, so backend detection, snippet generation, and the install plan
mostly transfer. `use_pty` and `timestamp_timeout` exist there.

The **agent path cannot**, as designed. It rests on a root-created cgroup scope
under `aido.slice` that a same-uid process provably cannot write into. macOS has
no cgroups, no `/proc`, no `openat2`, no `execveat`, and no pidfds. Attesting a
caller would need an entirely different mechanism — Endpoint Security, or audit
tokens over XPC — and that is its own threat model, not a port. Planned, not
built, and it should not be attempted before the Linux path is audited.

### Two blockers fixed in this pass

**`CLAUDE.md` was telling rule authors the opposite of the truth.** It said
`--key=value` is split during canonicalization, so a rule written against the
joined spelling never matches. M1 removed the splitting; the joined spelling is
now the one that matches. Anyone following that guidance wrote a rule that never
fired. Corrected, along with a stale comment in `shipped_rules.rs` and the
now-obsolete "M1 has no renderer" blocker on the `insta` snapshots.

**The layered configuration reached `aido config` and nothing else.** `cli.rs`
passed `engine::Settings::default()` into every `evaluate`, so
`confirm_agent_actions` and `frozen` were configurable on paper and fixed in
practice — an operator would set a value, be shown it in `aido config`, and get
the default behaviour. Now `engine_settings()` loads the file and derives the
engine's view, and a broken file fails closed on the deciding path rather than
falling back silently to the defaults. The defaults are the *safe* values, so
falling back would have been safe — but silent, and a settings file that does not
mean what it says is the condition this project exists to refuse.

Two smaller things fell out of that:

- **`best_match` reported a freeze as "unknown action".** It kept only denials it
  considered informative, and `Frozen` was not on the list, so a frozen agent
  running `aido explain` was told no rule defines the action — sending an
  operator hunting for a missing rule when the real cause was their own freeze.
  Now a freeze short-circuits, and the informative-code list is gone entirely:
  the first refusal is kept whatever it is, so a denial code added later cannot
  be silently swallowed the same way.
- **`taplo fmt --check` was failing and was not in `just verify`.** It walked into
  `target/test-tmp`, where the rule-loader tests deliberately generate a
  non-UTF-8 file and a directory named `10-a.toml`. Added `.taplo.toml` excluding
  `target/**`, and wired `toml-check` into the gate, where CI had it but the
  local gate did not.

---

## 2026-08-28 — phase 5 part 1 done: the config layering foundation

`crates/aido-config` now exists. 430 tests across the workspace, 100% coverage on
lines, regions, and functions, zero line-level waivers, gate green. `aido config`
and `aido config --schema` work.

This landed before `ido` and before M2b on purpose: precedence is the thing that
is painful to retrofit, and doing it while there are only two consumers is much
cheaper than unifying three that each grew their own.

### The two rules are enforced by the type system and the merge, not by convention

**Security-relevant settings are not settable from the environment.** Checked at
merge time against `Setting::is_security_relevant`, so a new setting is covered
by default rather than by somebody remembering. Only presentation (`color`) is
exempt. A test walks every setting and asserts the refusal.

**A project layer may only narrow.** `Setting::narrows` defines what that means
per setting, because there is no generic answer:

| Setting | Narrower means |
|---|---|
| `confirm_agent_actions` | turning it **on** |
| `frozen` | turning it **on** |
| `confirmation_timeout_secs` | getting **shorter** — a shorter wait denies sooner |
| `audit_sink`, `color` | no ordering exists, so a project layer may not change them at all |

The `_` arm of `narrows` falls back to equality, so a **type mismatch cannot be
used as an escape hatch** by a lower layer. There is a test for exactly that.

### Three smaller decisions worth knowing

- **`Layer`'s derived `Ord` *is* the precedence order.** Not a comparison
  function somebody can implement backwards. A lower layer applied out of order
  is inert rather than surprising, so callers cannot corrupt the result by
  applying files in the wrong sequence.
- **Compiled-in values are reported, not omitted.** `use_pty` appears in
  `aido config` marked `<compiled-in>`, and setting it produces "compiled in and
  cannot be configured" rather than "unknown key". An operator who tries deserves
  the real reason.
- **`7 of 7` has an analogue here too**: an unrecognised key fails the *whole
  file*. A typo in `confirm_agent_actions` that reads as "no such setting, carry
  on" is the same failure as silently ignoring a directive, wearing a friendlier
  face.

### A path choice I got wrong and fixed

My first version derived the settings file from the rules directory's parent. Test
isolation caught it: every fixture then shared one `config.toml` under
`target/test-tmp`, so one test's file changed another test's result. That is a
test smell revealing a real design smell — an implicit path relationship nobody
asked for. Replaced with an explicit `--config-file`, defaulting to
`/etc/aido/config.toml`.

### `ido` paths are settled, ahead of building `ido`

`paths.rs` resolves the XDG layout from **injected values**, never by reading the
environment — `std::env::var` is banned in this project's privileged crates, and
a resolver that reads its own inputs cannot be tested against the cases that
matter. Decisions made, with tests:

- **The queue lives under state, not runtime.** A queue that vanishes on logout
  loses exactly the work the human meant to come back to. The *lock* is ephemeral
  and does live in runtime.
- **`$XDG_RUNTIME_DIR` unset falls back under state and says so.** It is routinely
  unset over SSH, and `runtime_is_fallback` is reported rather than hidden so an
  operator chasing a stale lock knows which directory is in use.
- **Nothing resolves into `/tmp`**, and `touches_tmp()` exists to be asserted
  rather than trusted. A test also confirms the guard detects the thing it guards
  against.
- **An empty or relative XDG value is treated as unset**, per the specification,
  which stops a relative `XDG_STATE_HOME` resolving against whatever directory
  the process happens to be in.
- **`aido` has no user layer at all**, and a test walks every system path
  asserting none of them mentions a home directory or `.config`.

### Not done in this pass

The `trust.d` records that actually gate `confirm = "never"` are modelled as a
path but not implemented — they belong with M5, and they need the broker to
enforce them. `SystemPaths::trust_dir()` exists so the ownership check has the
path in its list.

---

## 2026-08-28 — M2a done. What it is, and one design change worth knowing

`crates/aido-backend` now exists: 373 tests across the workspace, 100% coverage on
lines, regions, and functions, zero line-level waivers, full gate green.

Four modules, all pure — they decide what to write and never write it:

| Module | What it settles |
|---|---|
| `capability` | What a backend can be *relied on* to do, and which two controls have no substitute |
| `detect` | Which implementation is installed, probed at runtime, never at build time |
| `snippet` | The sudoers and doas text, with every historically-earned constraint encoded |
| `plan` | The ordered install and uninstall steps, so the *ordering* is reviewable |

### The design change: capabilities are probed, not inferred from the name

My first version hardcoded "sudo and sudo-rs both honour `timestamp_timeout` and
`use_pty`". The coverage gate caught it as dead code — the "unusable backend"
branch was unreachable — and chasing that revealed the version was **wrong**, not
merely untested.

`sudo-rs` *accepts directives it has not implemented and silently ignores them*,
logging a warning. So a config file containing `timestamp_timeout=0` proves
nothing about whether the credential cache is off. Inferring a capability from an
implementation's name is exactly the mistake that produces a working-looking
install with a missing control.

`Probe` therefore gained `honours_directive(exe, directive)`, and both required
capabilities are now asked about rather than assumed. That made the refusal path
reachable, and there are now tests for a backend that accepts `use_pty` into its
config and ignores it.

**Consequence you will see immediately.** `HostProbe::honours_directive` answers
`false` for everything, because confirming a directive means writing a probe
config and observing the result, which needs the process handling that lands with
M2b. So on this machine `aido doctor` reports:

```
backend      UNUSABLE: sudo-rs  is missing a required control (…)
```

That is correct and deliberate. `aido` will not claim a control nobody has
verified, and the consequence of the gap is that it declines to install rather
than installing something weaker than it advertises. It will start reporting a
usable backend when the probe can actually run — in the VM.

Note also that the unreadable banner makes it guess `sudo-rs` rather than `sudo`,
which is the conservative direction: `sudo-rs` supports the smaller set of
directives, so guessing it means probing for each one instead of assuming it is
honoured.

### Smaller things decided in this pass

- **`7 of 7` capabilities is unreachable, so there is no branch for it.** The C
  `sudo` does not reject argument wildcards; `sudo-rs` cannot validate a named
  file. A "everything present" special case would have been dead code pretending
  to be thoroughness, so `doctor` prints a count and then one line per absent
  capability, with no conditional at all.
- **Uninstall never removes the `aido` group.** An operator may have granted
  membership for their own reasons, and revoking it on a package removal is a
  surprise in the other direction. It *does* remove the sudoers file and any
  stale candidate, because leaving a rule behind is a security defect.
- **The candidate file sits beside its destination**, not in `/tmp`: same
  filesystem so the rename is atomic, and no predictable path in a
  world-writable directory.
- **`with_agent_path` exists but is unreachable from the CLI.** The passwordless
  snippet shape is written and tested now so the diff that eventually enables it
  is small and obvious rather than sprawling. `human_only` is the only
  constructor anything calls, and it does not mention the agent helper at all.

### Still open from M1, not yet done

The deny-list's exact-token checks for `-o` / `--option` / `-c` /
`--config-file` do not also match their `--flag=value` forms. Since
canonicalization no longer splits on `=`, that is a real gap — narrow, because
substring matching on the whole argument still catches the known
`DPkg::Pre-Invoke` case, but it should be closed. It is the first thing I would
pick up in a follow-up pass.

---

## 2026-08-28 — starting M2, and the blocker you need to decide about

### The blocker: M2 cannot be finished or verified on this machine

M2 is the first milestone with a privileged path, and essentially all of it is Linux-only:

| M2 component | Runs on macOS? |
|---|---|
| `sudo` / `sudo-rs` / `doas` detection and capability probing | No — no such binaries, and the version banners differ |
| Writing and validating `/etc/sudoers.d/aido` | No — no `visudo`, no sudoers |
| `aido-gate` hardening: `close_range`, `openat2(RESOLVE_*)`, `execveat`, `PR_SET_NO_NEW_PRIVS`, `statfs` on `/proc` | No — none of these syscalls exist |
| journald audit sink | No |
| The functional post-install probe (did the gate really run as uid 0?) | No |
| The differential matrix across sudo / sudo-rs / OpenDoas | No |

**What I did about it.** I split M2 in two and built the half that is genuinely testable here:

- **M2a — done in this pass.** Everything that is a *decision* rather than a syscall: the backend model, the capability matrix, sudoers and doas snippet generation, the install plan, and the validation commands. All pure functions over injected facts, so they are unit-tested to 100% on macOS and behave identically on Linux.
- **M2b — needs a Linux VM.** The syscalls, the real `sudo` invocation, the functional probe, the audit sinks, and the matrix.

### What I need from you before M2b

One of:

1. **Approval to install Lima** (`brew install lima`, then `limactl start`). Roughly 2 GB of disk and a few minutes. This gets a real Ubuntu with `sudo`, and later a second VM with `sudo-rs` and one Alpine with OpenDoas.
2. **A Linux host** you already have — an SSH target works, and I can drive `cargo` there.
3. **Docker/Colima**, which covers most of the matrix. Note the gap: containers share the host kernel and cannot exercise the kernel-version matrix (5.15 / 6.1 / 6.6+) or `SO_PEERPIDFD` availability differences, so a VM is still needed eventually.

I did not install any of these, because a VM is a large, slow, and easily-unwanted change to your machine.

### The thing I most want you to not let me do

**Write Linux code I cannot run, and let it accumulate.**

`cargo check --target x86_64-unknown-linux-gnu` passes on code that would fail instantly on a real kernel: a wrong `openat2` flag combination, a `close_range` that closes a descriptor still in use, an `execveat` with the wrong `AT_` flags. "Compiles for Linux" is not evidence of anything. The gate is also the one component where a bug is a root exploit rather than a wrong answer.

So my recommendation is: **do not let M2b's syscall code get written before there is a VM to run it in.** If you want progress without a VM, the honest order is
M2a (done) → phase 4 `ido` (no privilege at all, no VM needed) → phase 5 config layering → then M2b once a VM exists.

`todo/README.md` already recommends `ido` before the passwordless path for a different reason; the VM constraint makes that ordering stronger.

### Security notes from the M2a work

The sudoers snippet is the entire security boundary, and every one of these is a trap I encoded because it has bitten someone:

- **The filename cannot contain a dot or end in `~`.** `sudo` silently ignores such files, which produces a working-looking install with no rule in effect. `/etc/sudoers.d/aido.conf` is the mistake.
- **`visudo -cf` must be run on aido's own file explicitly.** `sudo-rs`'s `visudo` validates only `/etc/sudoers`, not the drop-in directory.
- **sudo-rs ignores directives it does not support, with a warning.** So the install check must be *functional* — run the gate and confirm it executed as uid 0 — not a file-existence check. Ubuntu 26.04 ships sudo-rs by default, so this is the common case, not an edge case.
- **`timestamp_timeout=0` is load-bearing.** Without it the agent path can ride a credential a human cached with an unrelated earlier `sudo`. That residual-timeout channel was used in a published Codex CLI sandbox escape.
- **`use_pty`** is the fix for the TIOCSTI/TIOCLINUX tty-hijack class. Blocking individual ioctls is a losing game; TIOCLINUX has no equivalent of Linux 6.2's `dev.tty.legacy_tiocsti` knob.
- **The gate takes zero arguments.** `sudo` closes fds ≥ 3, so a request channel cannot survive the hop, and sudoers cannot constrain argument *arity* — only "no arguments" or a trailing wildcard. Zero argv removes the entire sudoers-glob injection class from the trust path.
- **The beta must not install the `NOPASSWD` rule or the `aido-gate-nopass` hardlink at all.** See `todo/phase-3-packaging-and-publish.md` § 1.

### Open hole that becomes real in M2b

`crates/aido/src/rules.rs` does **not** yet verify ownership and mode of the rule files. Today that is survivable: nothing can execute, so a tampered ruleset only makes `aido explain` print a wrong answer to a human who asked a question. **The moment an exec path exists, this is a privilege escalation.** It is a stated precondition of M2b, not a nice-to-have, and it needs `openat2` plus the ancestor walk — so it lands with the rest of the syscall work, in the VM.

### Suggestions, ranked

1. **Get a VM before writing gate syscalls.** Above.
2. **Build `ido` next if you want progress today.** Zero privilege, zero VM, and it is the piece that makes the project useful to someone who would never enable a `NOPASSWD` rule.
3. **Add the audit crate before the gate, not after.** A gate that executes before there is a tamper-evident record of what it executed is a gate whose first incident is unreconstructable. It is also pure enough to be fully testable here.
4. **Decide the packaging question in `todo/README.md` § Open decisions** — one package or two for `aido`/`ido` — before phase 3, because it changes the maintainer scripts.

---

## 2026-08-27 — M1 completed

### A real bug, found by fuzzing on the target's first run

`Argv::canonicalize` split `--key=value` into two arguments, so a deny rule on a flag could not be evaded by joining its value with `=`. Input `["---=---=-_"]` broke it: the *value* of a split can itself look like a long flag, so it split again on the next pass and the function had no fixed point.

Splitting recursively would fix idempotence and make the real problem worse — the matcher would see three arguments where the program sees one, which is precisely the matcher-versus-kernel divergence CVE-2021-3156 exploited.

**Resolution: the splitting was removed.** A rule now matches the argv byte-for-byte as the kernel delivers it. Two consequences, both deliberate and both documented in `argv.rs`:

- A rule that accepts both spellings must list both, with an enum or an anchored pattern. The engine will not unify them.
- The deny-list must match a joined flag by prefix as well as by exact token, because there is no normalization step to lean on. **This is not fully done** — `deny.rs` catches `--option=DPkg::Pre-Invoke::=…` through substring matching on the whole argument, which covers the known case, but the exact-token checks for `-o` / `--option` / `-c` / `--config-file` do not yet also match their `--flag=value` forms. Worth closing in M2a's follow-up; noted here so it is not lost.

The crash input is now a permanent regression test (`canonicalize_never_splits_a_joined_flag`).

### I misdiagnosed the coverage problem twice — read this before trusting the crate layout

Getting coverage from 99% to 100% took an embarrassing number of attempts, and my first two diagnoses were wrong.

I concluded that the `aido` package being both a library and a binary was double-counting coverage, and restructured into three packages on that basis. **The actual cause was stale `llvm-cov` profile data surviving a refactor.** `rm -rf target/llvm-cov target/llvm-cov-target` fixed it instantly.

I kept the restructure, because it is independently justified — `aido-tests` is in the plan for M2's differential matrix, and it genuinely cannot run under the coverage harness since `cargo_bin` cannot find the relocated binary — but it was **not** the fix, and nobody should infer from the layout that lib+bin coverage is broken.

`just verify` now purges coverage data first, and `CLAUDE.md` records why: a stale drop invites lowering a threshold instead of cleaning.

### Coverage is 100% with zero line-level waivers

Four unreachable branches were **deleted rather than waived**:

- two `ok_or_else` arms on slice ranges that always exist (`parse_stat`),
- a `split().next()` that can never return `None` (`parse_mountinfo`),
- a serializer error on a plain data struct — made *reachable* instead, by turning the fallback into a fail-closed denial envelope and testing it through a generic helper.

`PrivilegedOps` is injected into the CLI so "the platform cannot observe this caller" is exercised by a test rather than only on a broken machine.

Two package-level exclusions remain, both recorded in the `justfile` with reasons: `aido-tests` and `aido-bin`.

### Tooling facts worth remembering

- **Nightly is required** for `cargo fuzz` and `cargo miri`. Both are installed now and both are green.
- **Miri is scoped to `--lib`.** The proptest integration test calls `getcwd` for failure persistence, which miri's isolation blocks. Disabling isolation would weaken the check rather than widen it.
- **`fuzz/` is outside the workspace** (`exclude = ["fuzz"]`), because cargo-fuzz needs nightly, its own release profile, and sanitizer flags — none of which should reach the pinned stable build that ships.
- Clippy caught me violating this project's own `to_string_lossy` ban twice. One I fixed properly; the other produced a narrow documented exception — `Path::display()` is permitted for human-facing provenance that is never compared against anything.

### The property that makes M1 safe to have shipped

`classify()` returns `Unattested` for every caller, on every platform, because there is no broker yet. Unattested requires a password, so the gap fails in the only acceptable direction. A test asserts that a forged `CLAUDECODE=1` is recorded as a hint and changes nothing.
