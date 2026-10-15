# Concerns, decisions, and things you need to know

Running log. Newest section first. This is where commentary lives instead of a chat transcript, so it should be readable cold, months later, by someone who was not here.

---

## 2026-10-15 — second review: the code against the goal

Yesterday's pass compared the plan with the code at milestone level. This one
read the code against the goal and the three invariants, and ran the
documentation's own examples. Findings, worst first.

**Overlapping rules resolve by file order, and order can skip a human.**
`best_match` returns the first permitted action in declaration order. Two
actions that accept the same argv with different `confirm` settings therefore
let the sort order of two rule files decide whether anyone is asked. No test
covers it and `check` does not report it. Harmless today, because nothing
executes, and the plan's own answer — sudoers-style last-match-wins with
negation — would make it worse: negation is a way to widen by reordering. The
fix goes before `aido exec` in M2b: strictest confirmation across every
matching action, an overlap report in `check`, and a new standing property,
*adding a rule never removes a confirmation*.

**`doctor` was credited with a report it does not produce.** `README.md`,
`SECURITY.md`, and the design plan all said `doctor` lists every other path to
root — `NOPASSWD` entries, group memberships, writable unit directories and
`PATH` entries. It lists none of them, and yesterday's rewrite of M2b dropped
the item that would build them. Both documents now say so, and the item is
back as M2b 4b together with `--json` and `--fix`, the latter already named by
the generated sudoers comment as the thing to run.

**Two of the three `README` examples could not work.** They omitted the
program, so `explain` reported no matching action for a command the ruleset
allows. Replaced with the lines that were actually run. The `--help` text named
a `rule` subcommand that does not exist; it now names the ones that do.

**What held.** All five standing invariants from `CLAUDE.md` exist as property
tests in `aido-policy/tests/invariants.rs`, plus five more (hints never change
a verdict; the agent path is never broader than the human path; declared yolo
never removes a confirmation; every denial is actionable; evaluation never
panics). No `#[ignore]`d test. A rule with no `args` permits zero arguments.
`check` refuses a ruleset that names a shell. The gate's child environment is
a fixed allowlist and `LD_*`, `GCONV_PATH`, `PYTHONPATH` are refused by name.
The audit chain detects an edit and a truncation. Hints are recorded and
compared nowhere.

**`ido run --yes` from an agent.** Reachable: no terminal, so `--yes` is
accepted. It grants nothing — `ido` holds no privilege, the agent could run
the command directly, and a queued `sudo` has no terminal to prompt on — but
the `AGENTS.md` block should forbid it in words. Planned as its v2, in M6.

A verification tracker now sits in `todo/README.md`, one row per item of the
design plan's checklist, so the next review starts from a table rather than
from memory.

---

## 2026-10-14 — plan review against the goal, and four corrections

The eight requirements in `design-plan.md` were checked against the code. Two
are met in full (the root-owned rule set; the tooling). Two — the sudo-like
CLI that delegates to the backend, and the human being prompted — are M2b and
are now the whole of the project's critical path; everything agent-related sits
behind them. `ido` is outside the eight and done. The review found four places
where the plan and the code had quietly parted, and the plan was wrong each
time.

**The gate cannot act without the broker, and the broker was a milestone
later.** `aido-gate::decide` refuses with `NoPendingRequest` unless a
root-minted entry exists under `/run/aido/req`, and only root can mint one.
M2 was defined as "complete without any agent concept" with `aidod` in M3, so
M2 as written could not execute anything. The minting half of the broker is
now M2b; M3 keeps the confirmation channels. The alternative — the gate reading
the question from its parent's `/proc/<pid>/cmdline` — was rejected: it would
replace the one-use, generation-pinned record the gate was built and tested
against with a caller-rewritable string, to save writing a daemon that the
passwordless path needs anyway.

**`confirm = "always"` on the human path had no answer.** The gate refuses an
unconfirmed action under a confirming rule, and the only thing that can set
`confirmed` is the broker after an out-of-band approval. For a human who just
typed a password that is a second prompt with no channel to appear on.
Decided: the password is the confirmation on the password path, known to the
gate from `argv[0]`. The out-of-band channel is for the path where no secret
was typed.

**"Blocked on a VM" was true of the machine, not the work.** Docker gives a
real kernel with real `sudo`, `sudo-rs`, and `OpenDoas`; the differential
matrix already runs in it. Recorded with the two hazards found this week: the
bind mount misreports ownership and loses fresh directories, and root does not
enforce file modes. So: a copy, a non-root user.

**The unsafe budget had no contents list.** Checked against rustix 1.1.4:
`openat2`, `pidfd_open`, `fstatfs`, and `PR_SET_NO_NEW_PRIVS` are safe
wrappers; `close_range`, `SO_PEERPIDFD`, and `PIDFD_GET_INFO` are absent and
`execveat` is `unsafe`. `aido-sys::raw` therefore holds exactly those four, and
the claim "no `unsafe` outside `raw`" stays checkable.

Smaller corrections in the same pass: the gate executable gets its own package
(`aido-gate-bin`) like the other two entry points; phase 3's deliverables
claimed an apt repository that open decision 3 had already deferred; phase 4
§ 8 (the `ido` ↔ `aido` integration) had no milestone and now splits between
M2b's `aido exec` and M6; `re.md` still pointed at remote hosts nobody needs;
and `design-plan.md` carries a dated deviations block so a reader meets the
differences before the text that predates them.

---

## 2026-10-14 — M2b, first slice: the ruleset is checked on the descriptors it is read through

### The hole this closes

`trust.rs` verified the rules path by `lstat`-ing each component, and the loader
then read the files by name. Between the two, any component could be swapped.
`aido doctor` also checked only the *directory*, so a group-writable rule file
inside a root-owned directory was reported trusted. CONCERNS has called this "a
stated precondition of M2b" since 2026-08-28.

`aido_sys::open_trusted` walks from `/` one component at a time, each opened
relative to its parent's descriptor with `O_NOFOLLOW` (and `O_DIRECTORY` for
ancestors), and runs the existing check on what `fstat` reports for the
descriptor just opened. `aido_sys::read_trusted_dir` does that for the rules
directory and then for every `*.toml` file in it, and reads the bytes through
the same descriptor that was checked. The thing checked is the thing read.
When an open fails, the component is examined with `fstatat` and no follow, so
a link is still reported as a link and a file where a directory must be as
that, rather than as a bare `ELOOP` or `ENOTDIR`.

`aido doctor` reports through it now. The gate must load through it and nothing
else; the front-end loader still reads by path so `aido explain` works on a
checkout, and says so in its module documentation.

### How it is tested without root

The per-component check is now one pure function that `verify` and the
descriptor walk share. The directory half takes an already-open descriptor and
an owner, so a test can point it at a directory it created and name its own
uid; the public functions always pass `TRUSTED_UID`, which stays a constant. The
walk itself is tested against paths every supported host has: `/usr/bin/true`
for the trusted case, `/bin` (merged-`/usr` Linux) or `/tmp` (macOS) for a link,
`/root` or `/private/var/root` for a directory the caller may not search.

`openat2` with `RESOLVE_NO_SYMLINKS` would do the walk in one call where the
kernel has it. The per-component walk loses nothing without it and runs on
every kernel this supports, so it is the only path for now.

### Two test-environment facts worth knowing

- **Docker Desktop's bind mount is not a faithful filesystem.** Run as root in a
  container, the checkout appears root-owned, which breaks every "a checkout is
  not root's" test, including one that predates this change. Run as a normal
  user, a directory created a moment earlier can read as missing while sibling
  directories are created and deleted in parallel: 1 run in 3 failed that way.
  Copied onto the container's own filesystem, the same tests passed 15 times out
  of 15. Run Linux tests as a non-root user, on a copy, not on the mount.
- **One unexplained failure on macOS.** During one `just verify`, the `ido`
  acceptance test saw `ido queue` exit non-zero with nothing on stderr. It did
  not recur in five isolated runs or in two later full gates. A process killed
  by a signal leaves no stderr, which fits a Docker build writing to the same
  checkout at that moment, but that is unproven. If it recurs, look there first.

### Not done in M2b

The gate binary, the sudo hop, the functional post-install probe, `close_range`,
`execveat` on a pinned descriptor, `PR_SET_NO_NEW_PRIVS`, the journald sink,
executing the install plan, and the check for a filesystem mounted by a
non-root user. Docker on this machine gives a real kernel for all of them.

---

## 2026-10-14 — phase 4 done: `ido`

### What exists

`ido` is the queue an agent writes and a human reads. `crates/ido` is the
library, at 100% lines, regions, and functions with no waivers; `crates/ido-bin`
is the executable, excluded from coverage like `aido-bin` and tested through
real processes instead. Every command in `todo/phase-4-ido.md` § 2 exists:
`queue`, `add`, `list`, `run`, `drop`, `log`, `celebrate`, and the bare picker.
`willyoumarryme` is the same binary under a second name. Every row of the
adversarial table in § 7 is a test, the acceptance test is
`an_agent_queues_and_the_human_runs_it`, and
`the_picker_runs_the_selection_on_a_real_terminal` types into the real picker on
a pseudo-terminal, on macOS and in a Linux container. `ido(1)` and
`ido-queue(5)` are in `docs/man/`, and a test fails if a subcommand is missing
from the page.

### The half-built crate had never compiled

`crates/ido` had sat untracked since 2026-09-04 with `lib.rs` naming two modules
that did not exist. Two of its tests were wrong in ways a compiler run would
have shown at once: one asserted that the two-character message `no` was longer
than five characters, and the queue was described as safe from other users
without anything checking. Both are fixed; the second is now a real check.

### Decisions worth knowing

- **No `ratatui`, no `crossterm`.** `deny.toml` forbids a second version of any
  crate, and those two bring a large tree. Raw mode needs three calls, and
  `rustix` — already in the lockfile through `tempfile` and `terminal_size` —
  exposes them safely, so `forbid(unsafe_code)` holds in `ido-bin` too. The
  picker itself is a pure state machine in the library: keys in, actions and a
  text frame out.
- **The lock is never held while a command runs.** A `terraform apply` can take
  twenty minutes, and an agent's `ido queue` in that window must not fail. So
  each entry is re-read and re-checked under the lock immediately before it
  starts, and the result is recorded under the lock afterwards. A step whose
  predecessor just failed, or an entry dropped from another terminal, is skipped
  rather than run on a decision made before the facts changed.
- **Another user's queue is refused, not read.** A queue directory or file owned
  by someone else, or writable by group or world, is refused, checked on the
  opened descriptor. Whoever can write the queue chooses what the human runs
  next. The uid comes from the binary, so the refusal is testable.
- **A `--dry-run-of` preview is shown, never run automatically.** The spec asked
  for its cached output at selection time. But the preview is a command the
  agent wrote, and running it when the human merely highlights an entry is
  executing agent input without consent. The picker shows it, labelled.
- **"Unblock and continue" is dropping the failed step.** The spec asked for an
  explicit override. Dropping is already explicit, already confirmed with `y`,
  and leaves no flag that skips a dependency silently. `run --all` leaves
  failed entries alone; retrying one is `ido run <id>`.
- **Typed confirmation** — the word `run` — is required for more than one entry
  and for anything that elevates, drives a cloud CLI, or has a lookalike
  command name. A single low-consequence entry runs on space then enter.
  `ido run` outside the picker asks for the same word on a terminal; `--yes` is
  refused there and required without one.
- **What is refused rather than altered:** argv that is not UTF-8, an identical
  command already queued (it answers with the existing id), and a relative
  `ido add` path that leaves the current directory.
- **`ido list --json` is pure ASCII.** The argv is exact, but every non-ASCII
  character is a `\u` escape, so the JSON cannot carry a bidi override to the
  terminal it is printed on.
- **The splicer is a module, not an `ido-doc` crate.** It has one consumer.

### Not done

- § 8, the integration with `aido`: denials that queue themselves, and queued
  entries run through `aido exec`. `aido exec` does not exist yet.
- Cloud profiles that come from the environment (`AWS_PROFILE`) are not shown;
  only the ones in the argv are. Showing them means reading the human's
  environment at render time, which the library deliberately does not do.
- `queued_by` recognises only `CLAUDECODE`. It is a hint, shown as unverified.
- Packaging the second name as a hardlink is phase 3's job.

---

## 2026-10-13 — the differential matrix is wired, and it found two more bugs of one kind

### The tripwire fired, as designed, and is now a job

`differential compliance (M2)` had been the only red job since `fc878d0`
pushed `crates/aido-gate`: it exited 1 the moment a gate crate existed, so the
matrix could not be forgotten. It is now real. `just differential` builds a
static musl `aido` and `ci/differential/run.sh` drives it in Docker through
five rows — Ubuntu 24.04 with sudo, Ubuntu 24.04 with sudo-rs 0.2.2, Ubuntu
26.04 with sudo-rs 0.2.13, Alpine 3.22 with OpenDoas 6.8.2, and Alpine with no
escalator at all. Each row pins which backend was found and every capability
it was probed to have (`expected/<row>.txt`, versions normalized out), feeds
the snippet aido would write to that backend's own parser, and records the
verdict for nineteen invocations over the shipped rules
(`expected/verdicts.txt`). Every row must produce that file byte for byte: a
backend is not a policy input.

What it does not do: execute. The binary has no exec path, and `row.sh` fails
the moment `aido doctor` stops saying so, because then the comparison that
matters — the same ruleset *executed* through each backend, identical
outcomes — is due. The tripwire moved from "does a gate crate exist" to "does
the binary say it can exec", which is the question that actually decides when
the second half must be written. `aido-tests` stays reserved for that half.

### Two defects, both "is root permitted?" where the question was "does this parse?"

**The OpenDoas probe.** `doas -C <file>` parses a config and exits 0 or 1.
`doas -C <file> <command>` additionally evaluates whether the *invoking* user
is permitted and prints `deny`, exit 1, otherwise. The probe passed `/bin/true`
as a command; the probe rule names group `aido`; root is not in it; so every
real OpenDoas answered no to every probe, and detection reported it UNUSABLE
with an empty version. That is the "open, not fixed" item from 2026-08-28,
explained. No unit test could see it because the fake runner did not model the
difference. It does now, and
`a_doas_probe_asks_the_parser_not_whether_the_probing_user_is_permitted` fails
against the old code. The doas row is usable: 5 of 7 capabilities, absent only
wildcard rejection (a sudo-family question doas is never asked) and the
persistent credential cache (which OpenDoas has only when built
`--with-timestamp`).

**The doas install plan's validate step** had the same shape:
`doas -C {candidate} /usr/libexec/aido/aido-gate-auth`. The installer is root,
root is not in `aido`, so on a perfectly valid file the step would have printed
`deny`, exited 1, and — correctly, every non-notice step is fatal — aborted the
install. The command is gone;
`the_doas_validation_command_asks_the_parser_only` pins it. `row.sh` takes the
validator argv from the plan's own output rather than choosing one, so a plan
that names a validator the distribution lacks, or hands it an argument that
changes the question, fails in the row that has that distribution.

The version banner was never the problem: OpenDoas has no version flag at all,
and `doctor` now says `no version banner` rather than the stale
`version not probed yet`.

### sudo-rs on Ubuntu 26.04 is usable, and lives at `/usr/bin/sudo`

Measured, not assumed: sudo-rs 0.2.13 accepts `Defaults!ALIAS
timestamp_timeout=0`, and its `visudo` accepts `-cf /dev/stdin`. The 26.04
package installs `/usr/bin/sudo` and `/usr/sbin/visudo` through alternatives,
so detection finds it at the C sudo's path, classifies it from its banner, and
probes it through `/usr/sbin/visudo` — which is visudo-rs there, and works. The
24.04 package (0.2.2) still installs only `/usr/bin/sudo-rs`, still lacks the
per-command scope, and is still refused by name with that reason; that row
pins the refusal and will say so the day the package changes.

Two things the matrix pins that are not pretty: the UNUSABLE line reads
`sudo-rs sudo-rs 0.2.2`, because the banner already carries the name, and the
doas snippet header says `doas ()`. Both are cosmetic and both are now
snapshots, so fixing either is a reviewed diff rather than a drift.

### Reproducing it on a Mac

Static musl, linked with rustc's own `rust-lld` (`.cargo/config.toml`), so
nothing beyond the pinned toolchain is needed; `aarch64-unknown-linux-musl`
joined the pinned targets for Apple Silicon, and `just` picks the triple from
the host architecture so Docker runs the image natively. `cargo-zigbuild` was
not installed on this machine any more and is not needed.

---

## 2026-09-23 — CI had been red since 2026-08-28, for two reasons

Every run on `main` failed from `ec666f5` onward. Neither cause was a code
defect; both were test infrastructure lying about what it was testing.

### The binary tests were running whatever `aido` happened to be lying around

`aido-tests/tests/binary.rs` called `Command::cargo_bin("aido")`, but the
`aido` binary belongs to `aido-bin`. Cargo sets `CARGO_BIN_EXE_aido`, and
builds the binary at all, only for the integration tests of the package that
owns it. From `aido-tests`, `assert_cmd` fell back to probing `target/debug/aido`:

- **on a clean CI runner** nothing was there, and all nine tests panicked with
  `` `CARGO_BIN_EXE_aido` is unset ``;
- **on a developer machine** a binary from some earlier `cargo build` usually
  was there, so the tests passed — against a stale build. Deleting it locally
  reproduced the CI failure exactly.

The second is the worse of the two: an exit-code test that asserts an old
binary proves nothing about the current one. The tests now live in
`aido-bin/tests/binary.rs`, where Cargo guarantees a fresh build and sets the
variable. `aido-bin` was already excluded from coverage, so measurement is
unchanged, and `aido-tests` no longer needs an exclusion. It stays as an empty
package reserved for the M2 differential matrix. This also corrects the
2026-08-27 note below: `cargo_bin` failing "under the coverage harness" was the
same cross-package problem, not something llvm-cov did.

### cargo-fuzz was building for musl

A cargo-fuzz installed as a prebuilt binary (`taiki-e/install-action`) is
statically linked against musl, and cargo-fuzz defaults `--target` to the
triple it was compiled for. AddressSanitizer refuses a static libc:
`sanitizer is incompatible with statically linked libc`. `just fuzz` now passes
the host triple from `rustc +nightly -vV` explicitly, and the nightly long run
calls the same recipe (`just fuzz 1800`) instead of its own copy of the loop.

### Coverage in `term-sanitize` was passing by luck

Found while verifying the two fixes above. Three branches of the escape
stripper — a bare C0 control other than ESC, an escape with more than one
intermediate byte, and an intermediate followed by a non-final character —
were reached only when proptest happened to generate them, so `just coverage`
came out anywhere from 99.46% to 100% run to run. Each now has a deterministic
test named for what it stops, starting with
`a_carriage_return_cannot_overwrite_what_was_shown`: `rm -rf /\rls` renders as
`ls` on a raw terminal. The unit tests alone now cover the crate fully; the
property tests are back to checking invariants rather than carrying coverage.

### Heads-up: the differential job will fail on the next push, on purpose

`crates/aido-gate` landed locally in `fc878d0` but was never pushed. The
`differential compliance (M2)` job exits 1 the moment a gate crate exists, so
the sudo / sudo-rs / doas matrix cannot be forgotten. That failure is the
tripwire working, not a regression.

---

## 2026-09-03 — every rendered decision is now a snapshot

### The commit-rule debt is paid

`CLAUDE.md` has required snapshot tests of every decision record and every
confirmation-prompt string since M1, flagged *(Still unwritten)* once the
blocker (no renderer) was gone. They exist now, in two files:

- **`aido-policy/tests/contract_snapshots.rs`** pins the strings a caller acts
  on independent of any renderer: the denial-code wire contract (numeric code,
  string code, remediation — all three append-only) and every
  `ConfirmReason::explain()` prompt sentence.
- **`aido/tests/render_snapshots.rs`** pins every verdict shape through both
  rendered surfaces, `render::human` and `render::json`: the allow, all three
  confirmation reasons, and all eight denial codes — 24 snapshots.

Both are **exhaustive by construction**, not by discipline: each file carries a
wildcard-free `match` over the enum, so adding a `DenialCode` or a
`ConfirmReason` is a compile failure until it has a fixture, and a fixture is a
snapshot. The fixtures produce each decision the way the real producer does —
through `evaluate` with a realistic ruleset — except `policy_unloadable` and
`no_confirmation_channel`, which no layer produces yet (the loader's failure
envelope and M3's channel check); those two are pinned through
`Decision::deny`, the constructor their eventual producers will use, so the
producer inherits a pinned record rather than inventing one.

Accepting a deliberate change: `cargo insta review`, or
`INSTA_UPDATE=always cargo test`, then commit the `.snap` diff — which is the
point, because that diff is where review sees a policy or UX surface move.

### The first snapshot found a defect the existing tests could not see

`DenialCode::ExeMismatch`'s remediation contained an eighteen-space run from a
mis-wrapped string literal (a line break without the `\` continuation every
neighbouring arm uses). Every existing test asserted `contains(...)` on
substrings, which is exactly the assertion shape that cannot notice broken
whitespace between two valid fragments. A snapshot cannot miss it. Fixed in the
same change, and it is a fair one-line argument for why exact-surface pinning
earns its maintenance cost.

### Writing the critical-tier fixture ran into the deny-list twice, correctly

The fixture needed a critical-tier action that *reaches* the confirmation
decision. The first two attempts — `/usr/sbin/poweroff`, then
`systemctl mask` — both came back `deny_listed` (`PowerState` and
`UnitDefinitionMutation`), because the deny-list evaluates before confirmation
and both verbs sit on it by capability class. That is the engine's ordering
working as designed — a deny-listed command must never get as far as asking a
human — and it is worth recording that the natural examples of "critical" are
mostly things the deny-list refuses outright. The fixture that works is
`apt-get dist-upgrade`: unbounded scope, so honestly critical, and a plain verb
the deny-list has no reason to touch.

---

## 2026-09-01 — phase 2, part three: the gate decides for itself

### `aido-gate` is the second policy engine, and it reads the ruleset itself

The gate is reached through `sudo` with **no arguments**, so it is written to
one assumption: a hostile local user in the `aido` group runs it right now, with
an empty argv, a hand-built environment, and a spool entry they wrote
themselves. Four pure modules — `request` (is this a live entry from *this*
caller?), `decide` (does root's ruleset permit it?), `env` (a constant child
environment, nothing inherited), `status` (report the child's fate unsoftened).

One design change happened while writing it, and it matters more than it looks.
`decide()` originally read the authorized program and the rule provenance off
the `Decision` the engine returned, where both are `Option`. That left an arm no
test could reach — a permitted decision always carries them — and per this
project's own rule ("prefer deleting an unreachable branch to waiving it") the
fix was to restructure rather than waive. `decide()` now does its own
`rules.get(&action_id)` **before** evaluating, so:

- the `None` arm is reachable and tested (`unknown_action`), and
- the program that gets exec'd comes from the ruleset the gate loaded, not from
  a field on a decision object. That is what "second independent policy engine"
  is supposed to mean, and the first version quietly was not it.

Three refusals exist only in the gate: no pending request, an unconfirmed action
under a confirming rule (`gate_confirmation_missing` — invariant 3 forbids the
gate reading an approval from a terminal in the requester's process tree, so it
refuses instead of prompting), and a program that is not the rule's program
(`exe_mismatch`, kept distinct from an argument complaint because it is the
shape of a bypass, not a typo).

### Two documentation defects found in already-committed code

Neither is exploitable. Both are the kind of wrongness that misleads the next
reader, which in a privilege broker is its own cost.

1. **`aido-policy/src/decision.rs` claimed exit codes 17, 18 and 19 "sit above
   the range shells use for signals so they cannot be confused with a killed
   child".** Backwards: the shell convention is `128 + signal`, i.e. 129–192,
   which is *above* aido's codes. The codes themselves are fine — above the
   `0`/`1`/`2` band a program uses for its own failures and below 128 — so the
   fix is the sentence, not the numbers. **Fixed**, along with the test that
   encoded the same error in its name and asserted only `> 16`; it now pins both
   bounds and is called
   `a_refusal_cannot_be_read_as_a_child_that_ran_or_was_killed`.
2. **`Action`'s TOML keys `agent_allowed` and `env_allow` were snake_case, while
   `CLAUDE.md` states "the vocabulary is kebab-case throughout"** (`one-of`,
   `int-range`, `path-under`, `deb-name`, `unit-name`). No shipped rule file
   under `rules/` used either key, so the rename was free that day and would not
   have been free once an operator wrote a rule file against the old spelling.
   **Fixed** with `rename_all = "kebab-case"` on the struct rather than a
   `rename` per field, so a field added later cannot reintroduce a snake_case
   key. With `deny_unknown_fields` the old spelling is now a hard parse failure,
   which is the whole point — `agent_allowed = false` silently ignored would
   publish a human-only action to agents. Pinned by
   `denies_the_snake_case_spelling_of_a_human_only_rule`.

   Note for whoever reads this next: the JSON envelopes (`Decision`, `Record`,
   `PendingRequest`) are snake_case **deliberately**, and so are the keys in
   `aido-config`'s settings file. Kebab-case is the *rule-file* vocabulary, not a
   workspace-wide serialization style. Do not "fix" the others to match.

### A `matches!` with one arm is an uncovered region

Worth writing down because it cost time twice. `assert!(matches!(x, Pat))` in a
test expands to a `match` whose `_ => false` arm never runs, and `llvm-cov`
counts it. Same for `let Pat = x else { panic!() }` — the panic arm is dead by
construction if the test passes. Both patterns read as normal test code and both
put the crate under 100%.

The fix that keeps the assertion honest is a small helper returning `Option`,
called with a matching *and* a non-matching value, so both arms execute and the
test asserts something extra while it is there — `refused_decision()` in
`decide.rs` and `malformed_reason()` in `request.rs`. Where a variant is
identified by a stable string code, comparing the code is simpler still, since
codes are one-to-one with variants.

`PendingRequest::to_json` got the treatment `Record::to_jsonl` already had: the
`{}` fallback is a value handed to a free function, not a closure, so a test can
hand it a genuine `serde_json` error and exercise the arm.

### `cargo deny` rejects a path dependency with no version

A new crate declaring `aido-policy = { path = "../aido-policy" }` fails
`cargo deny check bans` as a **wildcard dependency**, which is not obvious from
the error's wording. Every in-workspace dependency needs
`{ path = "...", version = "0.0.1" }`, exactly as the older crates already do.

### The Mac's Rust toolchain was broken, and I repaired it

Not a project concern, but it happened inside this repo and the next person on
this machine should know. `cargo` was not on `PATH` at all: `~/.cargo/bin` held
only cargo *subcommands* (no `cargo` proxy), and `/opt/homebrew/bin` had only
`rustup`. Symlinking homebrew's `rustup` as `cargo` does not work — it resolves
its proxy identity from its real path, not `argv[0]`, so it prints its own
version banner.

What works, and what is now in place: symlinks in `~/.local/bin` (already on
`PATH`) pointing at the real per-tool wrappers in
`/opt/homebrew/Cellar/rustup/1.29.0_2/bin/` — `cargo`, `rustc`, `rustdoc`,
`rustfmt`, `cargo-fmt`, `cargo-clippy`, `clippy-driver`, `cargo-miri`. A
homebrew upgrade of rustup will move that Cellar path and break the symlinks;
the honest long-term fix is a rustup-managed install owning `~/.cargo/bin`.


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

### `aido audit verify` — the crate now has a consumer

A crate with no caller is a crate whose interface has never been used in anger,
so `aido audit <--log PATH>` landed with it. Four choices in it are deliberate:

- **It reads, it never repairs.** A tool that can rewrite the evidence is a tool
  an attacker can use to launder it. There is no `--fix`.
- **A missing log exits 19 (unusable), not 0.** "Nothing to check" and "I could
  not check" must not print the same reassurance. Only a log that was read and
  verified exits 0; a broken chain exits 17.
- **The limit prints with the good news.** The success line is followed by a note
  that an unbroken chain proves nothing was edited *in place* and cannot prove
  the log was never truncated and rebuilt. Burying that in a man page is how
  people come to over-trust it.
- **The default path ignores the environment.** `std::env::var` is on this
  project's disallowed list because a privileged binary must not take a path from
  its environment, and carving an exception for the convenient case is how that
  rule stops meaning anything. So the default is `$HOME/.local/state/ido/log.jsonl`
  and `XDG_STATE_HOME` is *not* consulted — `--help` says so, and a test asserts
  the resolved default, so the day someone "fixes" it for convenience it fails.

The coverage work here is worth recording because it repeated a pattern. Five of
the last uncovered regions in the whole workspace were not missing tests at all —
they were **branches nothing can reach**: a lazily-built fallback for a
serializer that cannot fail, a `home_dir()` returning `None` on a machine that
has one, and `assert!` panic-message arguments on assertions that pass. Each was
fixed by changing the code so the branch does not exist: compute the fallback
eagerly and hand it over as a value, take the resolved path as a parameter,
bind the message before asserting. That is the project rule working as intended —
prefer deleting an unreachable branch to waiving it — and it left 100% with no
line-level waivers.

### `aido-sys/trust.rs` — the precondition every other guarantee rests on

The policy engine is a pure function of the ruleset. So whoever can edit the
ruleset decides what an agent may run, and checking the file's own owner and mode
is not enough:

- A **symlink** anywhere on the path redirects the load. `/etc/aido` owned by root
  but *reachable* through a directory a user can write is a directory a user can
  replace.
- A **writable ancestor** is the same attack one level up. If `/etc/aido` is
  immaculate but `/etc` is group-writable, that group renames `aido` aside and
  puts its own there. Nothing about the final file looks wrong afterwards.
- A **group- or world-writable** file needs no attack at all.

So the check walks from `/` down to the target and demands all three of every
component. Four details are deliberate:

- **A symlink is refused, not followed.** Following it means the path that was
  checked and the path that gets read are different paths, which is the entire
  trick. Kind is checked *before* uid, and a separate test asserts a root-owned
  symlink is still refused, so nobody reorders it as an optimisation.
- **`.` and `..` are refused rather than normalised**, for the same reason.
  `Path::components` silently drops `.`, so that one is caught on the raw bytes
  before `components()` is consulted; `..` survives and is refused there.
- **The outermost failure is the one reported.** Fixing the inner problem while
  the outer one stands fixes nothing, and an error naming the rule file sends an
  operator to inspect the wrong thing.
- **The sticky and setuid bits are ignored.** Only `0o022` matters. Refusing
  `1755` would reject paths that are perfectly safe to read through.

`doctor` now prints a `rules trust` line, and in a development checkout it reads
`UNTRUSTED: … is owned by uid 501, not root`, which is the honest answer. It
**reports** rather than enforces on purpose: the enforcement point is the
executor, and a check the unprivileged front-end "passes" is a check an attacker
races — nothing stops the ruleset changing between that stat and a later read.

Two coverage notes worth keeping, both the same lesson as the audit crate. A
`let … else { return None }` leaves a region llvm-cov never marks covered even
when the branch runs, because the diverging value is its own region; moving the
refusal into a small helper returning `Option` fixed it. And `Kind::Other` was
dead until a test made a **real** socket with `UnixListener::bind` — dead code in
a trust check is a branch nobody has ever seen behave, so it was worth the four
lines rather than a waiver.

### Kernel 5 support: a ladder, not a floor

Requested, and it forced a decision that was going to have to be made anyway.
`aido` cannot require a 2025 kernel — Ubuntu 20.04 ships 5.4, Debian 11 ships
5.10, RHEL 9 ships 5.14, and all three are still in service. So attestation is a
**ladder** (`aido-sys/kernel.rs`), and the rung is reported by `doctor`:

| Rung | Since | What the broker learns |
|---|---|---|
| `PeerPidfdInfo` | 6.13 | pidfd + creds + cgroup id in one race-free `PIDFD_GET_INFO` |
| `PeerPidfd` | 6.5 | pidfd straight from the socket (`SO_PEERPIDFD`) |
| `PidfdOpen` | 5.3 | pid from `SO_PEERCRED`, then `pidfd_open`, then re-read and compare |
| `PeerCredOnly` | 2.2 | a pid, and no way to stop it being reused |

The line that matters is not convenience, it is whether the peer can be
**pinned**. A pid is a name that can be recycled: the process that connected may
have exited and its number been reissued before the broker reads `/proc`. A pidfd
is a handle to that specific process.

So `PeerCredOnly` **cannot carry the agent path** — it withholds passwordless
operation rather than authorising a race. That is invariant 2 applied to the
kernel, and it is asserted directly rather than left to be inferred. An old kernel
does not lose `aido`; a human typing a password is not relying on the broker
knowing which process asked.

`openat2` (5.6) degrades to one `openat(O_PATH|O_NOFOLLOW|O_DIRECTORY)` per
component, and that loses **nothing** here, because the ruleset walk refuses a
symlinked component rather than resolving it and refuses `..` outright. So the
resolution rung does not gate the agent path; only attestation does. Verified:
5.4, 5.10 and 5.14 all keep the agent path and all require the post-pin re-read.

An unparseable version is `UNKNOWN`, which sits below every threshold — a kernel
we cannot identify is treated as the oldest we support, never the newest.

### A real bypass, found by running the binary on a Linux host

The first host run of `aido explain -- /usr/bin/systemctl restart nginx.service`
came back `DENY … argument 0 ("/usr/bin/systemctl") does not satisfy no-pager`.
The front-end was handing the **whole command** to the argument matcher, so:

- the program was consumed as operand 0, and
- a rule's `exe` was never compared against anything at all.

Which means `aido explain -- restart nginx.service` — naming **no program** —
was ALLOWED by a rule for `/usr/bin/systemctl`. Not exploitable today, because
nothing executes yet. It would have been the day the gate landed, and it is
exactly the class of bug that is invisible in unit tests written against the same
wrong assumption. Nine existing tests encoded it.

Fixed in the **engine**, not the CLI: `Request::for_program` carries the program,
and `evaluate` compares it to the rule's `exe` byte-exactly *before* the argument
list is consulted. Four decisions in that:

- **Its own denial code** (`exe_mismatch`, 8). "Tried to run `/bin/sh` under a
  rule for `systemctl`" is the shape of an attempted bypass, and folding it into
  `argv_rejected` would bury it among ordinary typos. The two also send a caller
  to different places: fix the arguments, versus you want a different action.
- **Byte-exact, no normalisation.** `/usr/bin/./systemctl`, `/usr/bin//systemctl`,
  `systemctl`, and `/usr/bin/Systemctl` are all refused. The engine performs no
  I/O so it cannot know what a path resolves to, and normalising is how two
  different paths start comparing equal.
- **Checked in the engine, not the front-end.** A front-end that decides which
  program an action may run is a front-end making a decision.
- **Two new standing proptest invariants**: naming a program never turns a deny
  into an allow (the check is provably subtractive), and only the rule's own
  program is ever accepted.

`best_match` skips an `exe_mismatch` when scanning every action, because that
refusal says nothing about the argv — reporting it would name whichever rule
sorted first and send an operator to an unrelated action.

Then a second, smaller defect from the same change: the rendered `command` line
showed operands **without** the program. A decision record listing `restart
nginx.service` describes a command nobody can reconstruct. `Decision` now carries
`resolved_exe` and every surface renders through `resolved_command()`, so none of
them can drift back. On an allow it records the **rule's** copy of the path, not
the caller's spelling — identical by then, but it means the record shows what
policy authorised.

Confirmed on the host: program named plus permitted argv → ALLOW; same argv with
`/bin/sh` substituted → `exe_mismatch`; no program named → `unknown_action`.

### The container matrix ran, and it falsified three things in the code

Docker on `yamin.lol` runs as root without a password (that user is in the
`docker` group), so the sudo / sudo-rs / doas matrix finally ran against real
parsers. Three assumptions in `aido-backend` were wrong, and all three were the
same mistake: a property inferred from an implementation's *name* instead of
asked.

**1. sudo-rs was invisible.** Ubuntu's `sudo-rs` package installs
`/usr/bin/sudo-rs` and `/usr/bin/visudo-rs`, and does **not** provide
`/usr/bin/sudo`. `detect` probed only `/usr/bin/sudo`, so on a host whose one
privilege tool was the stricter of the two implementations aido exists to
support, `aido doctor` said *"no backend found — aido cannot operate on this
machine."* Fail-closed, so not a hole; useless, though, on exactly the
configuration the probe was written for. `BackendKind::SUDO_CANDIDATES` now lists
both paths, `Backend` records the one it was found at, and every probe is asked
of that path — because a probe that guesses the path interrogates a binary that
is not installed and gets "no" to everything.

**2. Every sudo-rs probe was failing for an invisible reason.** The probe
fragment used `Defaults!AIDO_PROBE <directive>`, and sudo-rs 0.2.2 supports
**only global `Defaults`**. Measured, one directive at a time:

```
Defaults timestamp_timeout=0        ACCEPTED
Defaults use_pty                    ACCEPTED
Defaults!ALIAS timestamp_timeout=0  REJECTED: unknown setting: 'ALIAS'
Defaults:%aido timestamp_timeout=0  REJECTED: expected parameter
Defaults>root  timestamp_timeout=0  REJECTED: expected parameter
Defaults@ALL   timestamp_timeout=0  REJECTED: expected parameter
Defaults !setenv                    REJECTED: unknown setting: 'setenv'
```

So the scope question and the setting question had been asked in one fragment
that fails for two independent reasons, and nothing could tell them apart. They
are now separate: `honours_directive` asks the global form, and
`honours_scoped_directive` asks the scoped one.

That splits out the real finding. **`PerCommandDefaults` is now a required
capability**, because without a scope the only way to apply `timestamp_timeout=0`
and `use_pty` is to apply them to *every sudo user on the host* — and an
installer that silently changes unrelated sudo behaviour is doing something the
operator did not ask for. sudo-rs 0.2.2 is therefore refused, by name, with that
reason. It is not weaker at enforcement; it cannot scope the directives aido
depends on.

Making it required immediately broke the doas path, which was the useful part:
doas carries its options **on the rule itself**, so it has the property more
directly than sudo does. That proved the capability is a *property, not a
syntax* — `Defaults!ALIAS` is one way to have it, and doas's shape is the better
one. Both satisfy it; only sudo-rs fails.

**3. Two capabilities were recorded backwards.** `sudo-rs`'s
`visudo -c -f <file>` validates any named file (the code said it could not), and
sudo-rs *accepts* an argument wildcard (the code said it refuses them). Both are
now probed. The lesson is the one this crate was built around and still got
wrong in two places: **ask the backend.**

`aido install --dry-run` exists so any of this could be checked at all — the plan
and the generated snippet had no way out of the process. It refuses without
`--dry-run`, because a subcommand named `install` that silently did nothing would
be worse than no subcommand. `--show-contents` prints the file. Verified with the
real `visudo`: the generated snippet is `parsed OK`, and `/etc/sudoers` still
parses after it is installed.

**Open, not fixed:** OpenDoas reports `UNUSABLE` in the container with an empty
version string, which means `version_banner` came back empty and the doas probes
answered no. OpenDoas prints its banner to stderr and exits non-zero, so this is
probably the banner read rather than a capability. Not investigated further, and
not guessed at.

### Still not done in phase 2

`aido-gate` itself, `openat2` resolution (the ancestor ownership walk it needs
now exists in `trust.rs`, but `openat2`'s `RESOLVE_NO_SYMLINKS` is what closes the
race between checking and opening),
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
