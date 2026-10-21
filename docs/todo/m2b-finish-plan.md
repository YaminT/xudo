# M2b — the plan to finish it

Written 2026-10-21 after a Fable review of the milestone against main at
`829f41d`. Supersedes nothing: `README.md` in this directory stays the index
and the step definitions; this file is the *sequence and exit test* for what is
left. When the two disagree, fix this one, it is newer.

## Where main stands (`829f41d`, CI green)

| Merged | Not merged, in a worktree | Not started |
|---|---|---|
| 0 Linux harness · 1 `aido-sys-raw` · 2b strictest rules · 6 audit sinks (unwired) · 7 mount trust · `SO_PEERCRED` safe decode (sixth `unsafe` block) · `howiwork.md` and its derived views | 2 broker (review fixes applied, awaiting the decode switch) · 4b doctor (round 5: any line continuation → unverified) · 4 gate executor (built, awaiting its observer) · 5 install executor (mid-build) | 3 `aido exec` · 8 executing differential · audit integration (D1) |

## How work moves

Every code step runs the same chain, and the roles are fixed: **Sonnet
develops, Opus observes, Fable reviews.** A step merges only after the Fable
review approves it as matching its request, only onto a main head whose CI
finished green, and the push is watched to completion. Review findings are
reproduced before they are fixed, and every fix lands with a test named for the
attack it closes. Each lane keeps a `RECOVERY-*.txt` in its worktree so an
interrupted run resumes from its last checkpoint.

## What "M2b done" means

The review's reading of `design-plan.md` § M2 and the verification table, which
this file adopts as the exit test. All of these true, with Linux evidence:

1. Rules and the spool are loaded only through the trust walk, mount check
   included. *(done)*
2. A socket-activated root broker identifies its peer by the kernel, classifies,
   decides with the same engine `explain` uses, and mints bounded one-use
   requests. *(B1)*
3. `aido exec` makes the broker round-trip, execs the backend's `PASSWD` hop,
   and passes the backend's exit status through; a human is prompted on a real
   pty. *(C1, verification row 2)*
4. The auth-only gate re-decides from root-owned state, consumes the nonce
   before anything runs, execs the validated descriptor with the hardening list,
   and propagates status and signals faithfully. *(B3)*
5. The doctor reports the backend, capabilities, trust, and every other path to
   root it can check, never printing clean for what it could not read. *(B2)*
6. Install writes a validated snippet atomically and a **functional** probe
   proves the gate executed as root; the dotted-filename regression is tested.
   *(B4, row 3)*
7. The broker and the gate each write their own audit record through the
   step-6 contract; a sink that cannot be written prevents mint and execution;
   `aido audit` verifies the produced trail and fails after truncation. *(D1,
   row 15)*
8. The differential matrix executes the same ruleset through sudo, sudo-rs, and
   OpenDoas with identical verdicts. *(C2, row 14)*

Rows 6–10 and 16 of the verification table are M3/M4 and are not part of this
exit. Packaging stays in phase 3.

## The sequence

### A. Resume *(mechanical)*

- A1. Main's head CI green; worktrees clean; each lane's agent reads its
  `RECOVERY-*.txt` and `git log` before touching anything. *(done 2026-10-21)*

### B. Merge queue, strict order

- **B1. Broker final** (`wf_87180089-132-1`, HEAD `7dcc41a`). Switch
  `SO_PEERCRED` to `Syscalls::peer_cred` (pid 0 is its own refusal, tested);
  close CONCERNS open item 8; revisit the "`/run/aido` not shared across pid
  namespaces" note and keep it only with a reason; wire the audit contract if
  contained, else record D1 as the explicit next item with the stderr record
  kept. One squashed commit; gates; merge.
- **B2. Doctor round 5** (`wf_87180089-132-3`, HEAD `002230e`). Any line
  continuation, both dialects, → `Unverified`/`Maybe`, never `Clean`/`No`;
  tests for every real-sudo/doas case found in rounds 2–4 plus a generated
  property test; observer re-runs the real programs; merge. The oracle (D3) is
  the real fix for this class, and is recorded as such.
- **B3. Gate** (`wf_2a8abc38-d83-3`, HEAD `8e6152a`). Resume at the observer.
  Rebase onto the merged broker and reconcile three contracts before merging:
  consuming a spool entry that is already gone (`ENOENT`) is a refusal; one
  monotonic clock seam shared with the broker; the exec path takes
  `Authorized<_>` from the step-6 contract. Merge.
- **B4. Install** (`wf_2a8abc38-d83-4`, HEAD `9ce866e`). Finish the executor;
  make the post-install probe real against the merged gate (a safe no-op
  request that must execute as uid 0); dotted-filename regression; merge. Its
  real-file tests that need uid 0 join the root lane (`tests/root_*.rs`, run
  by `just root-test`), and that lane stops being non-blocking in the same
  commit: the three-step switch is written in the `root-tests` job in `ci.yml`.

### C. New builds *(after B; C1 before C2)*

- **C1. Step 3, `aido exec`.** Front-end round-trip over `aido-wire`; exec of
  the backend's `PASSWD` hop; backend exit status passed through byte for byte;
  a denial whose remediation is "a human must run this" prints the exact
  `ido queue` line; `rexpect` test of the password prompt on a real pty. This is
  the first user-visible outcome of the milestone.
- **C2. Step 8, executing differential.** `aido-tests` drives the static binary
  through sudo, sudo-rs, and OpenDoas in `ci/differential`'s containers, every
  verdict identical in every row; `row.sh` stops reporting the exec path as
  absent.

### D. Debts to clear before closeout *(parallel with C)*

- **D1. Audit integration, end to end.** Broker mint and gate exec take
  `Authorized<_>`; a successful root execution leaves both independent records;
  a direct hostile invocation and a denial leave theirs; a failing sink stops
  mint and execution; `aido audit --log` passes on the produced trail and fails
  after truncation. Decide and record how a post-execution outcome is obtained
  with an exec-in-place gate. The broker's half was examined at B1 and left
  whole, not half-wired: `CONCERNS.md`, the M2b step 2 entry, open item 6,
  lists what it touches and the order to do it in (the unit's sandbox first,
  measured under systemd).
- **D2. Fuzz target** for the `aido-wire` request parser, a trust-boundary
  parser `CLAUDE.md` requires fuzzing; wire it into `just fuzz`.
- **D3. Doctor oracle.** Ask the programs themselves — `sudo -l -U <user>` when
  run as root, `doas -C <file> <cmd>` unprivileged — as the authoritative
  passwordless check, demoting the hand parser to a hint. Four review rounds
  each found a new lexer mismatch; the parser cannot win that race.
- **D4. Flaky tests, owned.** `ido-bin` PTY `argv_is_never_passed_through_a_shell`
  (failed once under load); the `trust.rs` socket tests that hit `SUN_LEN` on a
  long checkout path. Fix, or pin with the reason written beside the test.
- **D5. CI gaps.** The systemd unit assertions (`aidod/tests/units.rs`) and a
  root-in-container lane for the install tests join `just verify`/CI.
- **D6. Inventories.** The crate tables in `CLAUDE.md`, `design-plan.md`, and
  `README.md` (this directory) name the real workspace members, with `aidod`
  marked in review until B1 lands.

### E. Closeout and decisions *(user sign-off)*

- **E1. M2b closeout.** Sweep the verification table against the exit test
  above; `howiwork.md` "Where the build stands" and the FigJam card re-stamped;
  a dated `CONCERNS.md` entry.
- **E2. Phase 3 beta `.deb`** — human path only, no `NOPASSWD` shipped. *Decision:
  release timing.*
- **E3. Schedule the `howiwork.md` promises with no milestone:** vision-mode
  providers, YAML/JSON permission-set import, pasban's schedule and log
  verification, `airead`. *Decision: proposed homes M5/M6/phase 5.*

## Estimates

Measured burn this cycle: about 2M agent tokens and 2–2.5 hours per completed
step (build, review, fix, merge, green CI); gateway failures roughly doubled it
at their worst. From that: B ≈ 3–5M tokens, C ≈ 4–6M, D ≈ 2–3M; about 12–17
hours of agent time to E1, more if the gate's review finds what gates usually
do. The whole roadmap after M2b (phase 3, M3–M7) is an order of magnitude
larger and includes work no agent can do: an external audit and a VM for the
kernel-version and systemd-scope matrix.
