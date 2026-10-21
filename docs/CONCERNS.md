# Concerns, decisions, and things you need to know

Running log. Newest section first. This is where commentary lives instead of a chat transcript, so it should be readable cold, months later, by someone who was not here.

---

## 2026-10-21 — M2b step 4 (B3): `aido-gate-bin`, the root executor, reconciled with the broker

Built 2026-10-19 on `aebfd15`, before the broker was on main. Finished
2026-10-21 at the rebase onto the merged broker (`1851c9a`), where the three
contracts the finish plan names for B3 were reconciled; they are the first
section below.

**What exists.** The `aido-gate` executable, in its own package (`aido-gate-bin`,
the shape of `aido-bin`, `ido-bin` and `aidod-bin`: five lines of `main`,
excluded from coverage with its reason in the `justfile`, `tests/binary.rs`
running the real binary), to be installed as `/usr/libexec/aido/aido-gate` with
`aido-gate-auth` as a hardlink. Only the `-auth` name runs. The sequence it hands
off to is `aido_gate::run`, a module of the `aido-gate` library written against
traits (`GateHost`) with no syscall of its own, and fully covered. It refuses
with `NoPendingRequest` until a root-minted entry exists, and the broker is what
mints one; with the broker on main the two halves now meet at the spool, and
neither has yet run as root through `sudo` (nothing asks the broker, step 3, and
nothing installs the rule that reaches the gate, step 5).

**The order, each step refusing and stopping everything after it.**

1. `close_range(3, ~0, CLOEXEC)`. 2. `/dev/null` for closed 0 to 2. 3.
`PR_SET_NO_NEW_PRIVS`. 4. The invocation: no arguments, `argv[0]` named
`aido-gate-auth`. 5. `/proc` opened and proved procfs on that descriptor. 6.
The lineage walk. 7. The ruleset through `load_trusted_rules`, the generation
`generation.id()`. 8. The broker's spool through `SpoolDir::open`, and the
broker's clock. 9. Exactly one entry matching an ancestor's pin; `validate`;
`decide`; **consume**. 10. The program opened, judged, hashed. 11. The
authorization recorded through `authorize`. 12. `execveat` on the validated
descriptor. `run` returns only when it did not exec, always with a refusal,
already on the trail where it could be written, and prints one line to standard
error: the stable code and the severity, nothing the caller supplied.

**Reconciled with the broker (B1).** Three contracts, as the plan named them,
and two things the merge showed.

1. **An entry already gone when the gate consumes it is a refusal, never a
   success.** The broker's `Spool::remove` says the opposite, on purpose: for
   the broker's tidying, "already gone" is the outcome it wanted, and the gate
   "may have consumed it a moment ago". For the gate the unlink *is* the claim.
   Two gates that read the same entry both reach it, exactly one wins, and the
   one that finds the name gone lost and must run nothing. A gate that took the
   broker's `remove` would run the command twice. The seam now has both:
   `Spool::consume` and `SpoolError::Gone`, over one `unlink_entry` that
   `remove` and `consume` share, so they differ in nothing but what to make of
   "was not there". `FakeSpool::consume` mirrors it, and
   `FakeSpool::failing_consume` scripts any other failure. The gate does not
   hold the whole `Spool`: `GateHost::open_spool` hands it a `RequestSpool`
   (list, read, consume) over it, so a hostile entry cannot make the gate
   publish, lock or remove, because the type it holds has no way to say so.
   Tests, each shown to fail with its protection removed:
   `consuming_an_entry_takes_it_and_the_second_consumer_is_told_it_is_gone`
   (aido-sys, on a real directory),
   `an_entry_that_was_already_gone_when_the_gate_consumed_it_runs_nothing` (a
   second gate takes the entry the moment the first has read it, through the
   seam, so the loser's consume is the real answer and not a scripted one),
   `an_entry_that_cannot_be_unlinked_runs_nothing`.
2. **One monotonic clock, the broker's.** The gate's own `Clock`, `HostClock`
   and `FakeClock` were deleted; `aido_sys::{Clock, HostClock, FixedClock}` is
   what both read, so a deadline is stamped and judged on one `CLOCK_MONOTONIC`
   in whole seconds. The broker's `Clock` cannot fail, so the gate's step
   "could not read the clock" and its `FakeClock::broken` test went with the
   fallibility, not by choice. What replaced it is `read_clock`, which refuses
   a reading of zero (`gate_failed_clock`, `a_clock_that_reads_zero_stops_the_gate_because_no_deadline_can_be_judged`):
   `HostClock` answers zero for a negative `tv_sec`, which the kernel never
   reports. Zero is the fail-closed reading for the broker, which then stamps a
   deadline already behind it, and it would be the fail-open one at the gate,
   where every deadline would look still ahead. The gate's own check that its
   `HostClock` is the monotonic clock and not the wall clock
   (`the_host_clock_is_seconds_since_boot_and_not_the_wall_clock`) moved to the
   shared `clock.rs`: the broker's two tests would not have noticed a swap to
   `ClockId::Realtime`. **B1's open item 1 asked step 4 to confirm the two
   read the same clock rather than assume it.** Confirmed by construction: it
   is one function. The one way two processes on one host could read different
   `CLOCK_MONOTONIC`s is a time namespace, and the premise that closes it is
   that creating one takes `CAP_SYS_ADMIN` in its owning user namespace, and the
   set-user-ID bit on `sudo` does nothing inside a user namespace where root is
   not mapped, so a caller cannot run the gate inside a namespace it made. That
   premise is the kernel's documented behaviour and is **not measured here**:
   Docker's default seccomp profile refuses `unshare`. A time namespace root
   made on purpose, with `/run/aido` reachable from it, is the same kind of
   configuration as the pid-namespace case B1 recorded (open item 8) and is
   outside the model.
3. **The exec path takes `Authorized<_>`, and B1 did not wire the broker's
   half.** B1 deferred the audit trail to plan item D1 (its open item 6) and
   kept the stderr record, so there is no broker-side contract to take. The
   gate's exec already takes an `Authorized<Approved>` that only
   `aido_sys::authorize` makes, with `AuditTrail::system("aido-gate")`, so it
   keeps its pre-exec record. **D1 owns what is left:** the end-to-end check
   (both independent records on a successful execution, a failing sink stopping
   mint *and* execution, `aido audit --log` passing on the produced trail and
   failing after truncation), and the decision recorded in decision 1 below, how
   a post-execution outcome is obtained from an exec-in-place gate. Until D1
   the trail the gate writes holds the gate's records alone, and a host
   without journald refuses every gate decision that needs a record
   (`gate_failed_audit`), which is the fail-closed direction.
4. **One spool implementation.** The gate had written its own, `DirSpool`, at the
   same path as the broker's `SpoolDir`; the two were not the same code. The
   broker's is kept (reviewed, merged), and what the gate's had that it lacked
   moved into it: an entry with a second name is refused (`st_nlink != 1`, since
   the unlink that consumes removes one name), for the broker's reader as well.
   What the broker's has that the gate's lacked now holds for the gate: the
   spool must be a root-owned directory private to root, not any directory the
   walk accepts, and an entry may not give group or other *any* access, where
   the gate's refused only write bits. The gate's old `DirSpool` tests were
   each carried over or superseded: the write-bit modes are
   `an_entry_anyone_else_can_write_is_unreadable`, the second name is
   `an_entry_that_is_known_by_a_second_name_is_unreadable`, the bound on how
   many names are walked is now the gate's own
   (`a_spool_holding_more_names_than_the_gate_will_walk_is_refused_not_walked`
   and its at-the-bound twin), and the rest are the broker's tests of the same
   reader. The two bounds the gate reads by, `MAX_SPOOL_NAMES` and
   `MAX_ENTRY_BYTES`, are pinned against the broker's own ceilings by two
   compile-time assertions in `aidod::mint`: a spool kept within the broker's
   limits (64 live entries, 32 KiB an entry) is always one the gate will walk
   and read, so the gate's bounds can only bite on a spool the broker did not
   keep. The listing itself is bounded too: `Spool::names_up_to(MAX_SPOOL_NAMES
   + 1)` pulls entries lazily, so a spool someone filled is never read whole to
   be refused. Tests: `a_listing_with_a_limit_reads_no_further_than_the_limit`,
   `a_listing_with_a_limit_pulls_no_more_entries_than_the_limit_takes`,
   `the_fake_lists_up_to_a_limit_as_the_directory_does`,
   `the_gates_view_of_the_spool_lists_one_name_past_the_bound_and_reads_no_further`.
   Mutations L1 to L10 were killed.
5. **The settings the gate decides with.** Decision 12 below said the gate and
   the broker "must agree" on the settings file once either reads it. The
   broker now does (`aidod::policy`, `read_trusted_file` and `settings_from`);
   the gate still decides with `Settings::default()`. That is safe today for the
   reason it was: `frozen` and `confirm_agent_actions` bite only an enrolled
   agent (`engine::Settings`), and the gate attests no one, so no decision
   differs. It stops being safe the day M3's `aido freeze` or M4's enrolment
   exists. **Open item 8.**

**Decisions** (the step-1 "open for step 4" items, and the rest this step had
to make):

1. **Process model: exec in place.** The alternative, fork and wait, was
   rejected for three reasons. `fork` has no safe wrapper, so it would be a
   further `unsafe` block in the one crate with a published budget, for a
   benefit that is only a record the gate then has nothing to write. A waiting
   root parent keeps every descriptor it inherited, and `close_range` marks
   rather than closes. And exec in place gives the faithful exit status and
   signal for free: `sudo`'s own parent reaps the command. The cost is an outcome
   record. The authorization is written before the exec, nothing follows it, and
   the one outcome the gate can learn, an exec that fails, is a second record
   (`exec_failure_record`) naming the first by `authorization_seq=` in its
   evidence, because the log is append-only and `Record` has no field to name
   it with (step 6, open item 2). A second cost: the exit status. 17, 18 and 19
   are `aido`'s refusal codes, and a child exec'd in place can exit with them,
   so status alone cannot tell a refusal from a child; the stderr refusal line
   is the signal, and C1's front-end must read it.
2. **Before 5.11 the gate refuses.** `CLOSE_RANGE_CLOEXEC` is the whole of step
   1, and the per-descriptor `fcntl` fallback is another `unsafe` block in the
   budget for a kernel older than the beta supports. The refusal is
   `gate_failed_descriptors`, at normal severity, exit 19. The unscripted
   `FakeSyscalls` answers `ENOSYS` exactly as such a kernel does, so the test
   needs no special case.
3. **The exec vector is the canonical argv bytes.** `Approved::exec_argv` holds
   `Argv::canonicalize()`'s operands as bytes and `execute` builds the vector
   from them; `Approved::argv`, which came through the renderer, is for the
   record. `exec_vector` refuses an interior NUL rather than hand the kernel a
   prefix; the entry's own NULs are refused much earlier by `validate`.
4. **`PR_SET_NO_NEW_PRIVS` is set early, not at the exec.** It is irreversible,
   inherited, and nothing the gate does before the exec depends on it being
   unset, so setting it before anything is consumed means a host that refuses
   costs the caller nothing. A test pins that a refusal there leaves the spool
   and the program untouched.
5. **On `-auth` the password is the confirmation**, as the plan decided on
   2026-10-14: `GateContext::password_confirms`, true only for that name,
   satisfies `AllowWithConfirmation` in `decide`, and the record says so
   (`confirmation=password ...`). It widens nothing else: an expired, stale,
   or policy-refused entry is refused with the flag set
   (`a_rule_that_confirms_is_satisfied_by_the_password_and_by_nothing_else_the_caller_can_say`).
6. **The caller is identified by a pin match, never by a name.** `lineage`
   (in `aido-sys`) reads the gate and up to eight processes above it,
   quietly stopping at the bound where `ancestry` refuses a deep tree, because
   a deep session is ordinary here. The ancestors' `(pid, starttime)` pairs are
   what a spool entry must match; the names go in the record as
   `lineage=` and are branched on nowhere. This is shape-agnostic on purpose:
   `sudo` and `sudo-rs` with `use_pty` put a monitor between the gate and
   `aido`, and OpenDoas execs without a fork, so the distance is one to three
   and the walk does not need to know which. **Not measured** against the real
   three here: the lineage is tested against the tree those programs are
   documented to make, and the matrix's executing half (step 8) is where it
   becomes a fact.
7. **Zero matches is `NoPendingRequest`; more than one is refused**
   (`request_ambiguous`); an entry that matches the pin but whose content nonce
   disagrees with its name is refused (`request_forged_nonce`). Entries that
   are not named by a nonce, cannot be read, are not UTF-8, or do not parse are
   passed over: they cannot be matched to anyone, and refusing on one would let
   a stray file in a root-only directory lock every caller out. The only way a
   passed-over entry changes the outcome is by being the one that should have
   matched, and then the outcome is `NoPendingRequest`, which refuses. The
   broker's temporary files (`.tmp.<nonce>`) are such names: no nonce starts
   with a dot.
8. **Consume after `decide`, before the program is touched.** An entry is
   unlinked only when the gate would otherwise go on to run it. A refusal by
   policy, expiry or a stale generation leaves the entry for the broker's
   reaper; a refusal after the consume (a program that fails the walk, a record
   that cannot be written) burns it, and the caller must ask again. That is the
   fail-closed direction, and `an_entry_is_consumed_exactly_once_so_a_second_gate_finds_nothing`
   and `an_entry_that_was_already_gone_when_the_gate_consumed_it_runs_nothing`
   pin both ends: the second gate to unlink gets `Gone` and runs nothing.
9. **The program is opened by `open_trusted`, not as a bare `O_PATH`
   descriptor.** The walk opens every component `O_PATH` and the target
   `O_PATH`, then reopens the target read-only and refuses it unless it is the
   inode that passed; SHA-256 needs the contents, which `O_PATH` cannot give. The
   one descriptor is then `fstat`ed (regular, owner, no group or world write,
   an execute bit), hashed with `pread`, and the same descriptor is what
   `execveat` runs. `Program::from_fd` asks the descriptor the owner and mode
   questions again, so a program is never run on a check made on something
   else. A `#!` is refused first, as `Script`, with the reason in the record:
   through a close-on-exec descriptor the kernel could not have run it anyway.
10. **A refusal for "could not do a step" is a `Refusal::Failed`, not a new
    `DenialCode`.** Step 6 open item 1 (a refusal for "the record could not be
    written") is `Stage::Audit`, code `gate_failed_audit`; `Stage` names every
    step that can fail without the request being at fault, with a stable code
    each, and `Invocation`, `Spool` and `Program` report at high severity
    because they fail only when somebody is making them. The pinned denial
    contract in `aido-policy` is untouched. The record of a `Failed` refusal
    carries `detail=`, the step's own words bounded to 200 characters.
11. **No new crate, no new `unsafe`.** `aido-gate` depends on `aido-sys` (and
    `aido-sys` dev-depends on `aido-gate` for its contract test, which Cargo
    allows); `aido-sys` takes the workspace's `sha2` and two more rustix
    features beside the broker's (`stdio`, `thread`). `Cargo.lock` gains edges,
    not packages. The unsafe budget is untouched: six blocks, enforced by
    `aido-sys-raw/tests/unsafe_budget.rs`.
12. **The gate reads no `config.toml` yet**, so `engine::Settings::default()`
    is what it decides with (`confirm_agent_actions` on, `frozen` off). See
    reconciliation 5 and open item 8.

**Found while building it.** A filled standard stream was left close-on-exec:
`dup2(x, x)` does nothing, so a descriptor that was already open as 0, 1 or 2
and had `FD_CLOEXEC` set stayed so, and the child saw the stream closed.
`install` now clears `FD_CLOEXEC` by name after the `dup2`, and
`crates/aido-sys/tests/std_streams.rs` tests it in its own process. Mutations
H1 to H4 on `install` were each killed. An earlier version of this entry said
the closed-descriptor path was not mutation-checked; it now is.

Rust's runtime already replaces closed standard
descriptors before `main` on Unix, so step 2 is the second line of defence, not
the first. It is kept: the guarantee must not rest on a runtime detail, the gate
must hold it for whatever builds it, and it is cheap. That also means the
process test for closed descriptors can show only that the gate behaves the
same with 0, 1 and 2 closed; the ordering ("before any open") is pinned by the
library tests, where the fake table records it.

The first `just linux-test` of the rebased tree failed one test it had no part
in: `exec_runs_the_descriptor_it_is_handed_not_the_working_directory` got
`ETXTBSY` where it expected `ENOEXEC`. It is the race the script test beside it
already records (89f7029): the kernel looks for open writers before it looks at
a file's format, and a fork in another test thread holds a copy of the write
descriptor `std::fs::write` just closed until the child execs. The broker's new
Linux tests start processes, which made the window wider. The test now accepts
`ETXTBSY` as well, which keeps what it discriminates (`EACCES` is what executing
the working directory would give, and still fails it) and drops the flake. It
is the second instance of one class, so the retry is not the fix for the class:
plan item D4 still owns it.

**Tests, named for the attack.** In `aido-gate::run`:
`a_direct_hostile_invocation_with_no_entry_does_nothing_and_exits_unusable_at_high_severity`,
`arguments_are_refused_because_the_sudoers_rule_grants_none`,
`an_unexpected_argv0_is_refused` (ten spellings, `aido-gate-nopass` and
`aido-gate-auth/` among them),
`an_argv0_that_could_drive_a_terminal_reaches_the_record_escaped`,
`an_entry_minted_for_someone_else_is_not_this_callers`,
`a_reissued_pid_does_not_borrow_the_entry_of_the_process_that_had_it`,
`two_entries_pinned_to_one_lineage_are_refused_and_neither_is_consumed`,
`an_entry_whose_content_disagrees_with_its_name_is_forged_and_refused`,
`an_expired_entry_is_refused_at_normal_severity`,
`an_entry_from_before_the_rules_changed_is_refused`,
`a_program_that_fails_the_trust_walk_is_refused_and_nothing_is_recorded_as_authorized`
(symlink, writable, script), `a_gate_that_cannot_write_its_record_refuses_and_executes_nothing`,
and one `stops_at` test per step proving nothing after it ran (a kernel without
`close_range`, streams that cannot be replaced, `no_new_privs` refused, a `/proc`
that is not procfs, a lineage that cannot be walked, a ruleset or spool that fails
the trust walk, a spool too crowded to walk, a clock that reads zero). In `aido-sys`:
the seam's three tests above, `a_script_is_refused_with_that_reason_and_never_hashed`,
`a_program_anyone_else_can_write_is_refused`, `a_symlinked_program_is_refused_by_the_walk`,
`a_read_that_fails_after_the_first_bytes_is_a_refusal_not_a_short_hash`,
`a_file_that_is_not_on_procfs_is_refused_wherever_it_sits_under_proc`. In
`aido-gate-bin/tests/binary.rs`, through real processes and hardlinks: the same
refusals by exit status and the one line, closed and leaked descriptors, and
that the environment is never read.

**Each protection was removed to see that a test notices.** Twenty-nine
mutations of the gate and its seams, one at a time, each restored: the
no-entry refusal at normal severity and with the wrong exit, arguments and any
`argv[0]` accepted, the forged-nonce and ambiguity checks, the pin matched on
pid alone and on start time alone, the gate's own pin matched as a caller, the
deadline boundary, a stale generation, a wrong caller, a failed consume
ignored, consume skipped, consume moved after the program is opened, the exec
vector built from the rendering and with an emptied environment,
`no_new_privs`, the standard streams, and `close_range` each dropped, the
streams moved after the first open, a script, a writable program and a program
someone else owns accepted, `consume` succeeding on a missing name (the real
directory and the fake), and a second name accepted; and, in Docker, the procfs
check made always true and `no_new_privs` set to false. Every one fails at least
one test, named above (three, for the last two). The real `/dev/null` fill of a
closed standard stream is not one of them: it is held by a fake table that
records the order, because Rust's own runtime fills a closed descriptor before
`main` and a process test cannot tell.

**Open.**

1. **The root-run half.** Everything above runs unprivileged, as the hostile
   user does, and `exec_fd` is a fake in the library tests: the gate has not
   yet exec'd anything for real, as root, through a real `sudo`. That is the
   executing half of the differential matrix (`aido-tests`, step 8), and
   checklist items 4 and 11 stay half-open until it exists (the child's own
   `/proc/self/environ`, the real lineage under sudo, sudo-rs and OpenDoas).
   A root-lane test of the binary (`just root-test`) is not built here, for a
   reason worth knowing: the gate's audit trail mirrors every record to
   journald's socket and refuses without it, a container has none, so a real
   exec in the lane needs a stand-in for that socket. Whoever builds the first
   root-run test of the gate has to make it; B4's post-install probe is the first
   that will need to.
2. **`argv[0]` is the name, not `/proc/self/exe`.** `sudo` sets `argv[0]` to
   the command it was asked for, so the `-auth` name is as trustworthy as the
   sudoers rule that attaches the password to that path, and no more. When M4
   ships `-nopass`, where the name decides whether a password was typed in the
   other direction, the name should be read from the kernel's record of which
   dentry was exec'd instead.
3. **The caller's uid is recorded as unknown** (`u32::MAX`, not 0, which would
   read as root). The decision does not use it. `SO_PEERCRED` at the broker is
   where it is known; the entry does not carry it.
4. **The program's digest is recorded, not compared.** There is nothing to
   compare it with until a rule can pin one.
5. **A refusal record over 64 KiB goes unwritten** (step 6, open item 3): an
   entry may be 64 KiB, and its argv is echoed into the refusal's `argv`. The
   refusal stands and the gate still exits; only the record is lost. The broker
   writes at most a 16 KiB request, so this needs an entry the broker did not
   write. A bounded fallback record belongs with the broker's, which has the
   same problem.
6. **`Approved` is still `Clone` with public fields**, so the guarantee that
   nothing runs unrecorded rests on `execute` taking an `Authorized<Approved>`,
   which it does and nothing else can make (step 6, open item 9).
7. **A policy refusal leaves the entry in the spool.** The broker prunes
   expired, superseded and unusable entries at each mint, so the spool no longer
   grows without bound, and an entry that is never consumed lives at most its
   fifteen minutes or until its caller exits; the gate's own ceiling of
   `MAX_SPOOL_NAMES` (4096, against the broker's 64) is a bound on what a
   spool someone else filled can make it read, and the listing stops one name
   past it (`Spool::names_up_to`, reconciliation 4).
8. **The gate does not read `/etc/aido/config.toml`.** Before M3's `freeze` or
   M4's enrolment can make `frozen` or `confirm_agent_actions` bite, the gate
   must read the same file through the same walk and derive the same settings
   as the broker, and the two must be one function: `settings_from` is in
   `aidod::policy` today, which `aido-gate` cannot depend on (the dependency
   runs the other way), so it belongs in `aido-gate` (or lower) and the broker
   should call it from there.
9. **The audit trail is the gate's alone until D1** (reconciliation 3), and the
   post-execution outcome of an exec-in-place gate is D1's to decide.
10. **A time namespace** is argued, not measured (reconciliation 2).

**Measured**, on the commit that carries this entry: `just verify` green
through the pre-commit hook (100% lines, regions and functions on macOS, no
waiver, no threshold moved); `just check-linux` clean for both Linux triples,
and clippy `-D warnings` clean for both, which `just verify` does not run;
`just linux-test` green on Linux 6.12.76 (linuxkit, aarch64) in Docker as uid
1000, with the gate binary's seven process tests and the rebased broker's suite
in it, after the flake above. The Linux half of the coverage was measured by
hand, with the command `just coverage` runs, in that container: 100% on every
file this change adds or touches except the two environment-bound ones B1
recorded, `probe.rs` (needs `sudo` or `doas` installed, which the runners have)
and one closure in `syscall.rs` that runs only from kernel 6.16 (the runners
have 6.17). Not yet seen on the CI runners, nor on x86_64.

---

## 2026-10-21 — M2b step 2 (B1): `aidod`, the broker that mints, final

Built 2026-10-19; this entry was finished when it landed, after the review
fixes, the safe `SO_PEERCRED` decode (open item 8, resolved), and the decision
to leave the audit trail unwired (open item 6, which is plan item D1).

**Why it exists.** The gate refuses with `NoPendingRequest` unless a
root-minted entry exists under `/run/aido/req`, so until now the human path
could not have executed anything even with a gate binary. The broker is the
only thing that writes there. It grants nothing a password does not: every
caller is `Unattested` until M4, and an entry only lets the gate run, through
`sudo`, what root's ruleset already permits that caller.

**What exists now.**

- **`aidod`** (library, privileged, 100% covered) and **`aidod-bin`** (the
  entry point, `/usr/libexec/aido/aidod`, excluded from coverage like
  `aido-bin` and run as a process by `tests/broker.rs`). One connection per
  process: `serve` identifies the peer, reads one request, checks the spool,
  loads root's policy, classifies, decides, mints, answers, in that order, so a
  refusal never describes something not yet established. Every step that fails
  answers with a refusal and writes an audit record.
- **`aido-wire`**, a new pure crate (`aido-policy`, `serde`, `thiserror`, no
  I/O) holding the protocol, so `aido exec` (step 3) links it without linking
  the broker. A request is `schema_version`, an absolute `program`, `argv` as
  strings, and `claimed_classification` — a hint the broker records and never
  reads. At most 16 KiB; not UTF-8, an unknown or missing key, another schema,
  a relative program, or a NUL anywhere is refused before anything is decided.
  The answer is either the engine's own versioned `Decision` envelope plus, when
  minted, `{nonce, deadline, ttl_secs, gate}`, or a `RefusalCode` — fourteen,
  append-only, numbered like the denial taxonomy — with a fixed remediation
  sentence. The client never sees a path or an errno; the detail goes to the
  audit record. `BrokerResponse::parse` also refuses a decision whose envelope
  version is not this build's.
- **Peer identification** (`aidod::identify`) asks the kernel down the ladder
  and never reads its version: `SO_PEERCRED` on every rung, a pid of 0 refused
  before anything takes a pid; `SO_PEERPIDFD`, and
  on `ENOPROTOOPT` only, `pidfd_open` on the connect-time pid, and on `ENOSYS`
  only, no pidfd (`PeerCredOnly`); `PIDFD_GET_INFO` where it answers, dropped on
  `ENOTTY`/`EINVAL` only, its thread-group id required to equal the connecting
  pid; the start time from `/proc/<pid>/stat`, which must name that pid; and
  after the last `/proc` read, a zero-timeout poll on the pidfd, refusing a
  peer that has exited. Every other errno is a refusal and never a lower rung.
- **A seam for the rest of the peer calls**, `aido_sys::PeerCalls`
  (`SO_PEERCRED`, `pidfd_open`, `/proc/<pid>/{stat,status}`, the pidfd poll)
  with `HostPeer` and a `FakePeer` that scripts a *sequence* per call and
  records the order, so tests assert that the liveness check follows the last
  `/proc` read. The
  `Syscalls` trait stays the calls that need `unsafe`, and `SO_PEERCRED` is one
  of them: `HostPeer::peer_cred` reads it through `Syscalls::peer_cred`, after
  its own check of the socket's kind (open item 8). Also new in
  `aido-sys`, each with a host implementation and a fake: `Connection`
  (descriptor 0 adopted only if it is a connected `AF_UNIX` `SOCK_STREAM`
  socket, duplicated rather than taken, `SO_RCVTIMEO` and `SO_SNDTIMEO` of five
  seconds through rustix, one bounded read, one write), `Spool`, `Clock`
  (`CLOCK_MONOTONIC` in whole seconds, for the gate to read too), `Entropy`
  (`getrandom`, a short read refused), and `read_trusted_file` for the
  optional settings file.
- **Minting** (`aidod::mint`). Only a permitted decision mints, confirming ones
  included with `confirmed = false`: on the password path the password is the
  confirmation. The entry is `aido_gate::PendingRequest` with the generation of
  the ruleset `load_trusted_rules` returned, the request's program and operands
  as asked, the pin from the kernel, a 32-byte `getrandom` nonce in lowercase
  hex, and a deadline `REQUEST_TTL_SECS` (fifteen minutes) past
  `CLOCK_MONOTONIC`. Under the spool's `flock`: temporary files and unreadable,
  misnamed, expired, or superseded entries are removed, an older entry for the
  same `(pid, starttime)` included, so the gate finds one entry per caller;
  so is an entry whose caller `/proc/<pid>/stat` no longer shows as the pinned
  `(pid, starttime)` (it can never be consumed, since the gate checks its own
  caller against the pin); then at most 64 live entries and 1 MiB, and 8 whose
  live caller runs as the asking uid, or `spool_full`; then
  `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` under `.tmp.<nonce>` (no nonce starts
  with a dot), `fchmod 0600`, and `renameat2(RENAME_NOREPLACE)`, so a colliding
  nonce is `nonce_collision`, never an overwrite. The spool is opened through
  the trust walk and must be a root-owned directory giving group and other
  nothing; the descriptor half takes its owner as a parameter, so the real
  writer runs in the suite as uid 1000 on Linux.
- **Root's policy** (`aidod::policy`): the ruleset only through
  `load_trusted_rules`, settings from `/etc/aido/config.toml` through the same
  walk or the documented defaults when it is absent — absence decided inside
  the verified parent directory, where nobody else could have created it — and
  the decision from `aido_policy::evaluate_command`, the function `explain`
  calls, so the broker inherits step 2b's strictest-rule resolution instead of
  searching beside it. A settings file that is present and broken refuses.
- **Units** in `packaging/`: `aidod.socket` (`Accept=yes`, `0660 root:aido`,
  `MaxConnections=32`, `MaxConnectionsPerSource=8`, which systemd keys by peer
  uid on `AF_UNIX`), `aidod@.service` (`StandardInput=socket`; root with an
  empty `CapabilityBoundingSet`; `NoNewPrivileges`, `ProtectSystem=strict` with
  `ReadWritePaths=-/run/aido/req` alone, `PrivateTmp`, `PrivateDevices`,
  `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX`, `ProcSubset=pid`, the
  kernel and clock protections, `SystemCallFilter=@system-service` minus
  `@privileged @resources`, `RuntimeMaxSec=30`, `TasksMax=4`, `LimitNOFILE=64`,
  `CollectMode=inactive-or-failed`), and `tmpfiles.d/aido.conf` (`/run/aido`
  `0755`, `/run/aido/req` `0700`). `aidod/tests/units.rs` includes all three
  and asserts every security-relevant line against the constants the code
  uses, and refuses any key it does not know, because systemd ignores a
  misspelled directive with a warning. Checked against systemd 257 in
  Docker: `systemd-analyze verify` is silent on both units and an instance,
  `systemd-analyze security` rates the service 1.1 (both now run on every pull
  request by the D5 lane, `just units`, which was run against these units and
  passed), and `systemd-tmpfiles` creates both directories with those modes,
  by hand. The phase-3 layout table lists them.
- **Audit**: one `aido_audit::Record` per connection as a JSON line on
  standard error, which the unit sends to the journal, each the first of a
  chain of one. It is **not** routed through step 6's `AuditTrail` and
  `authorize`: that is plan item D1 (`docs/todo/m2b-finish-plan.md`), left
  whole rather than half-wired (open item 6). A minted decision is recorded
  *before* the entry exists, and if the record cannot be written, or standard
  error is not a connected socket (open item 9), nothing is minted.

**Decisions worth knowing.**

1. **Recovered work.** The first agent on this step died mid-build. Its move of
   the front-end's `best_match` into `aido-policy` was superseded at the rebase
   by step 2b's `evaluate_command`, which the broker now calls; nothing else of
   it was discarded.
2. **The euid is compared on every rung, not only where `PIDFD_GET_INFO`
   answers.** Without the record it comes from `/proc/<pid>/status`, confirmed
   by the same re-check. A peer that connected and then exec'd a set-user-ID
   program is refused either way. Stricter than the brief.
3. **`PeerCredOnly` (no pidfd at all) still serves the human path**, recorded
   `pinned=false`, as `kernel.rs` already argued: the password is the
   authority there. Nothing on that rung, or on `PidfdOpen`, can become an
   agent path.
4. **The peer is identified before its request is read**, so a refusal for a
   malformed request can name who sent it, and a peer that cannot be named is
   never read at all.
5. **Exit status is by fault.** 0 when the broker did its job, whatever it
   decided — including a malformed request and a client that hung up before
   its answer; 19 only when the broker or its host is broken (no spool, an
   unloadable policy, no randomness, an unwritable record, a peer the host
   cannot name). Otherwise any group member could fill systemd's list of
   failed units by hanging up, which is also why the instances are collected.
6. **A filtered system call fails with `EPERM` instead of killing the
   broker**, so the client still receives a refusal and the journal a record.
7. **`ReadWritePaths=-/run/aido/req`**: with the dash, a missing spool lets the
   broker start and answer `spool_unusable` with the remediation, rather than
   systemd failing the instance before anything can say why. It widens
   nothing.
8. **Standard output is the journal, not left to default**: with
   `StandardInput=socket` it would default to the socket itself.
9. **The fifteen-minute TTL** is `sudo`'s `passwd_timeout` times
   `passwd_tries` at their defaults. The entry is bound to one process and
   consumed on use, so the TTL is not the window in which it can be abused.
10. **Shaped for coverage, not waived:** `HostPolicy::load` and
    `SpoolDir::names` map their last fallible call instead of using `?`,
    because a root-owned broken settings file and a failing `readdir` cannot
    be produced without root; every failure of those calls is tested where it
    is made (`settings_from`, `SpoolDir::checked`).

**Tests**, named for the attack. On the wire:
`denies_a_request_that_tries_to_name_its_own_caller`,
`denies_non_utf8_bytes_instead_of_replacing_them`,
`denies_a_lone_surrogate_escape_rather_than_decoding_it`,
`denies_an_interior_nul_in_the_program_or_any_operand`,
`denies_a_program_that_would_be_resolved_against_a_path_or_a_cwd`,
`a_decision_in_an_envelope_of_another_version_is_refused`. Identification, on
fakes: `denies_a_peer_reaped_before_so_peerpidfd_rather_than_dropping_a_rung`,
`denies_a_peer_whose_pidfd_outlived_it_from_six_sixteen`,
`denies_a_kernel_record_nobody_answered`,
`denies_a_pidfd_that_names_a_different_process`,
`denies_a_peer_that_exec_d_a_set_user_id_program_after_connecting`,
`denies_a_peer_that_exited_between_the_proc_read_and_the_re_check`,
`a_peer_with_pid_zero_is_refused_and_never_looked_up_as_a_process`, and
`denies_pid_zero_even_when_every_later_answer_would_agree` (every answer past
`SO_PEERCRED` scripted to agree, so that only the refusal stops it: without
the refusal `identify` returns an identity pinned to pid 0), every other errno
of each call, and each rung. Serving:
`a_peer_the_kernel_reports_as_pid_zero_is_never_minted_for` (without the
refusal the broker mints),
`the_claimed_classification_is_recorded_and_changes_nothing`,
`denied_requests_mint_nothing_and_never_touch_the_spool` (unknown action,
rejected operand, deny-list hit through a rule that allows a shell),
`a_colliding_nonce_is_refused_and_never_overwrites_a_pending_request`,
`nothing_is_minted_whose_audit_record_cannot_be_written`,
`a_client_that_leaves_before_its_answer_cannot_make_the_broker_fail`. The
spool: `a_planted_temporary_file_or_link_is_never_written_through`,
`publishing_over_a_taken_name_is_refused_and_leaves_both_files_alone`,
`a_spool_reached_through_a_symbolic_link_is_refused_even_a_root_owned_one`.
On a real kernel with a separate peer process (`aidod/tests/linux.rs`,
without a branch on the kernel: the expected answer is computed from the
version): `a_live_peer_is_named_on_the_rung_the_kernel_version_predicts`,
`a_peer_that_exited_mid_identification_is_refused_while_its_number_is_still_its_own`
(a zombie, held with `waitid(WNOWAIT)`: every read by number succeeds and only
the pidfd re-check can tell),
`a_peer_reaped_before_identification_is_refused_and_never_looked_up_by_number`,
and `a_real_client_is_identified_decided_and_minted_for_end_to_end`. The
binary: `a_socket_activation_environment_it_never_asked_for_changes_nothing`
and `a_descriptor_zero_that_is_not_a_stream_socket_is_refused_with_a_record`.
The socket-kind check in front of `SO_PEERCRED`, on a real kernel in
`aido-sys`: `peer_credentials_of_a_connected_datagram_socket_are_refused_rather_than_decoded`,
`peer_credentials_of_a_tcp_connection_are_refused_rather_than_decoded`, and
`peer_credentials_of_a_socket_with_no_peer_are_refused_rather_than_decoded`.
The units: `the_unit_never_puts_the_broker_in_a_pid_namespace_of_its_own` and
the unknown-directive refusal.

**Outside the step.** `justfile` and CI exclude `aidod-bin` from coverage with
its reason, and `CLAUDE.md` says three entry points are excluded and lists the
two new crates. `rustix` in `aido-sys` gains the `net`, `process`, `event`,
`time`, and `rand` features of the crate already in the tree; no new crate.

**Review fixes.** The independent review found seven things. The socket unit
gains `TriggerLimitIntervalSec=0`, because systemd before 255 fails an
`Accept=yes` socket for good at 200 activations in two seconds, which any group
member could cause (`a_group_member_cannot_fail_the_socket_for_everyone_with_a_burst_of_connections`);
concurrency stays bounded by `MaxConnections=` and `MaxConnectionsPerSource=`.
A client that connects and exits is the client's fault, not the broker's:
`SO_PEERPIDFD` `EINVAL` (6.5 to 6.15), `PIDFD_GET_INFO` and `pidfd_open` `ESRCH`,
and a full spool exit 0 (`a_client_that_connects_and_exits_cannot_make_the_broker_exit_as_broken`).
The rest are open items 2, 8, 9 and 10 below, and snapshots for the refusal
codes, their remediation sentences, and the audit records
(`aido-wire/tests/contract_snapshots.rs`, `aidod/tests/record_snapshots.rs`;
`renaming_a_refusal_code_breaks_the_wire_contract_and_this_test`).

**Open.**

1. **The gate's half (step 4).** It must find the entry by its caller's pin,
   validate it, and remove it, which is what makes the nonce one-use; the
   broker's "one live entry per caller" relies on that removal. It must read
   the clock through `aido_sys::HostClock`. `CLOCK_MONOTONIC` is per time
   namespace; an unprivileged caller cannot be root inside one it created, so
   the broker and the gate should always read the same clock, but step 4
   should confirm it rather than assume it.
2. **Per-uid fairness in the spool: narrowed, not closed.** The review showed
   the first version of this item was too kind: 64 clients run one after
   another, each gone before the next, filled the spool for fifteen minutes
   with nothing alive (`sixty_four_exited_callers_cannot_lock_everyone_else_out`,
   and through `serve`,
   `sixty_four_clients_that_ran_and_exited_cannot_lock_another_user_out`). Now
   an entry counts only while its caller is still the pinned process, and no
   schema change was needed: the cap of 8 per uid (`MAX_ENTRIES_PER_UID`)
   reads the uids of each live caller from `/proc/<pid>/status`, real and
   effective both, so a caller that exec'd a set-user-ID program after minting
   stays on its user's share (`a_set_uid_caller_stays_on_its_real_users_share`).
   What remains: eight members of the group, each holding eight live callers,
   still fill the spool; and a caller that stays alive keeps its entry for the
   whole fifteen minutes. A real per-user quota would need the uid in the
   entry (a schema change the gate must accept).
3. **Run outside systemd**, the broker bounds each read by `SO_RCVTIMEO` but
   not the whole request, so a client trickling one byte per four seconds holds
   it for hours; under the unit, `RuntimeMaxSec=30` ends it. As designed, and
   the binary is never meant to be run by hand.
4. **A systemd whose `@system-service` predates `pidfd_open`** filters it
   to `EPERM`, which is a refusal, reachable only on the `PidfdOpen` rung
   (kernels 5.3 to 6.4). Not checked against old systemd versions.
5. **Only the units' text is checked by systemd, not the broker under them.**
   `just units` (D5, `ci/units/`) puts `systemd-analyze verify` and
   `security --offline` on every unit under `packaging/` in CI, outside
   `just verify` because it needs Docker and the network. Nothing starts the
   broker under its own sandbox: phase 3's container tests are where that
   belongs (see item 10).
6. **The audit trail is not wired: plan item D1 is the explicit next step
   (decided 2026-10-21, at B1, not to half-wire it).** Step 7 is wired. Step
   6, `aido_sys::audit::{AuditTrail, authorize}`, is not: the broker's half of
   it is not a contained change, which is the finish plan's test for doing it
   now, and its parts are one piece. The broker keeps its stderr record and
   mints under the stopgap of open item 9.
   * **No receipt without the real trail.** `AuditReceipt` and `Authorized`
     can be made only inside `aido_sys::audit`, so the mint cannot take "an
     authorization whose record went to standard error" unless a weaker sink
     is added to that module, and a receipt that sometimes means "the chain
     holds the record" and sometimes "a line was written" would say less than
     the type says now. The only honest source of one is
     `AuditTrail::system("aidod")`.
   * **The unit must reach the trail**, a sandbox change that cannot be
     tested here: `/var/lib/aido` writable (`ReadWritePaths=` and a
     `tmpfiles.d` line making it `0700 root`; the only writable path today is
     `-/run/aido/req`), the journal socket reachable under
     `ProtectSystem=strict` (connecting to a socket is not a write to the
     filesystem, but nothing here has run it), the system-call filter checked
     against the calls the log and the journal sender make, and the trust walk
     of `open_trusted` run inside that sandbox, which open item 10 already
     calls argued, not measured.
   * `Platform` gains a sink seam (`&mut dyn AuditSink`) and `serve` threads it
     through every refusal, so every `serve` test that reads the stderr
     record changes with it.
   * The record is built from the chain's last record (`Record::after`), not
     `Record::first`, so `record.rs` and its snapshots change.
   * The mint takes an `Authorized<MintApproval>` (`impl Approval`: command
     and governing action), which changes `publish` and `Minting`.
   * Open item 9's stderr attestation is replaced by the trail itself, and its
     test with it; the `aidod-bin` process tests, which run unprivileged and
     read the records from standard error, then need a trail they can reach
     through a seam the binary does not have.
   * Whether "the record could not be written" gets a refusal code of its own
     (today `broker_unusable`, the reason in the record) changes the pinned
     wire contract, so it is a reviewed snapshot change (step 6, open item 1).

   The order for whoever does it (D1, which also covers the gate): the unit
   and `tmpfiles` first, measured under systemd in Docker; then the seam; then
   `authorize` around the mint. Until then no record of the broker is chained
   or hash-linked, and `aido audit --log` has nothing of the broker to verify.
7. Seen, not changed: the front-end reads `/etc/aido/config.toml` by path and
   the broker through the trust walk. They parse it identically; only the
   broker's reading is trusted, which is as it should be.
8. **RESOLVED 2026-10-21 (B1). Decision, the user's, 2026-10-19: a sixth
   `unsafe` block.** rustix's `UCred` holds the pid as a `Pid`, which cannot
   be zero, filled by `assume_init` from whatever the kernel wrote, and the
   kernel writes 0 for a socket with no peer, for a socket type that records
   none (a connected datagram socket, TCP), and for a peer outside the
   caller's pid namespace: undefined behaviour in 1.1.4 and 1.1.5 alike. The
   user chose to decode `SO_PEERCRED` into plain integers in `aido-sys-raw`
   (commit `829f41d`, `Syscalls::peer_cred`; see "the sixth `unsafe` block" at
   the end of this file), and the broker now reads the record through it:
   `HostPeer::peer_cred` is the socket-kind check (a connected `AF_UNIX`
   stream or seqpacket, kept as defence in depth; `UnixConnection::adopt`
   refuses the same on the broker's descriptor) followed by
   `HostSyscalls.peer_cred`. rustix's `socket_peercred` is called nowhere in
   the workspace, and two guards keep it so (below).

   A pid of 0 is its own refusal, `IdentifyError::PeerNotVisible`, raised
   before any call that takes a pid; a pid that is negative decodes to 0 and
   is refused the same way. It counts as the broker's fault (exit 19): the
   broker cannot see its caller, which no unprivileged client can arrange by
   itself. Four tests fail if the refusal is removed, which was checked by
   removing it (`identify` then returns an identity pinned to pid 0, and
   `serve` mints an entry for it):
   `denies_when_the_socket_has_no_credentials_or_a_peer_outside_the_namespace`,
   `a_peer_with_pid_zero_is_refused_and_never_looked_up_as_a_process`,
   `denies_pid_zero_even_when_every_later_answer_would_agree`, and
   `a_peer_the_kernel_reports_as_pid_zero_is_never_minted_for`. The last two
   script every later answer to agree with pid 0, so they fail on the
   consequence and not only on the missing error. The decode is pinned by
   `a_peer_outside_the_pid_namespace_decodes_as_pid_zero_never_an_identity`.

   **The switch itself needed a guard of its own**, which no test of the
   decode can be. The review put rustix's call back into
   `HostPeer::peer_cred` and the whole Linux suite passed: rustix decodes every
   peer a test can make correctly and goes wrong only on the one it was
   dropped for. Two guards hold it now, one of which runs on every host.
   * **`clippy.toml` bans `rustix::net::sockopt::socket_peercred`**
     (`disallowed-methods`, denied across the workspace), and its reason names
     `Syscalls::peer_cred` as the replacement. The function exists in rustix
     only on Linux, so the entry carries `allow-invalid = true`; without it
     every lint run on a Mac warns that the path names nothing. It bites where
     clippy sees `HostPeer`'s Linux half, which is the two Linux runners'
     `just lint`; a Mac's `just verify` never compiles that half. Checked by
     putting the call back: clippy for `x86_64-unknown-linux-gnu` reports "use
     of a disallowed method".
   * **`nothing_reads_so_peercred_through_rustix_anywhere_in_the_workspace`**
     (`aido-sys-raw/tests/unsafe_budget.rs`) looks for the name as a token,
     comments and strings aside, in every Rust file of every crate and of the
     fuzz crate, on every host. Checked by putting the call back: it fails and
     names `peer.rs`. Beside it,
     `the_lint_that_bans_rustix_socket_peercred_is_still_in_clippy_toml` fails
     if the ban leaves the file or stops naming what to use instead, and
     `the_peercred_scan_finds_every_spelling_of_the_call_and_nothing_that_is_not_one`
     tests the scanner.

   **The unit-file note that `/run/aido` must not be shared across pid
   namespaces is kept, for a different reason.** It no longer guards against
   undefined behaviour: a peer the broker cannot see is a clean refusal.
   What it guards against is systemd's own behaviour, measured on systemd
   257.13 (Debian trixie, in Docker, with a second container sharing the
   socket's volume as the peer). With `MaxConnectionsPerSource=` set, as
   `aidod.socket` has it, one connection from a peer outside systemd's pid
   namespace made systemd log "Failed to get peer credentials of socket: No
   data available" and fail the whole socket (`Result: resources`) until an
   administrator restarts it, and the broker was never started. Without that
   setting systemd started an instance, `…@0-unknown.service`, and the
   broker's own refusal was the only guard. So the broker is safe either way,
   and the cost of the per-uid bound is stated rather than left to be found:
   `/run/aido` must never be reachable from a pid namespace that systemd
   cannot see into (a sibling container sharing it, or systemd itself in a
   container with a peer outside it). A container whose pid namespace is a
   descendant of systemd's is visible to it, by how the kernel nests pid
   namespaces (not measured here), and unaffected. The shipped socket unit
   says so in the comment directly above the setting, and a test keeps it
   there: `the_per_source_limit_states_what_it_costs_beside_the_limit` reads
   only that block of comment, its wrapped lines joined, and requires the
   measured cost and the rule's own sentence (`/run/aido must never be
   reachable from a pid namespace`), so that deleting the rule or moving the
   note away from the limits fails it (checked by deleting the rule). Its
   first version searched the whole file above the limit, where those words
   also occur for other reasons, and stayed green with the rule deleted;
   `a_note_that_was_deleted_moved_or_cut_off_from_the_limits_fails_the_check`
   tests the check. The other half of the old note stays as its own
   test, `the_unit_never_puts_the_broker_in_a_pid_namespace_of_its_own`: a
   private pid namespace for the broker would make every caller pid 0 and
   every request a refusal, and the broker reads callers' `/proc` entries by
   number, which works only from a namespace its callers are visible in.
9. **The audit trail is attested by its descriptor, not by the journal.**
   "Nothing is minted whose record cannot be written" held only for a
   `write()` that fails. systemd points standard error at `/dev/null` when it
   cannot connect a service to the journal ("Failed to connect stderr to the
   journal socket, ignoring"), and Rust reopens a closed descriptor 2 on
   `/dev/null`: every write then succeeds and records nothing. The broker now
   requires standard error to be a connected `AF_UNIX` stream socket before it
   mints (`Platform::trail`, `aidod::trail_of`;
   `nothing_is_minted_when_standard_error_does_not_reach_the_journal`); a
   denial is answered regardless
   (`a_denial_is_answered_even_when_there_is_no_trail_to_write`). That is what
   holds, no more: a socket, not proof that it reaches the journal or that
   something else did not take the other end. The hash-chained sink of step 6
   is the real answer.
10. **Step 7's mount-trust check and the unit's sandbox.** Inside the broker's
   unit, `ReadWritePaths=-/run/aido/req` makes the spool a separate bind mount
   (mountinfo shows `/aido/req /run/aido/req rw ... tmpfs`) on top of a
   read-only `/run`, because `ProtectSystem=strict` marks every mount
   read-only; and `ProcSubset=pid` gives the broker its own `/proc` instance.
   The gate runs unsandboxed and sees a plain directory. The review's worry was
   that a mount-layout rule would judge the same spool differently in the
   broker and the gate, and the broker would refuse every request as
   `spool_unusable`; and the earlier note that step 7 "applies automatically"
   was not shown. Read against what step 7 became, it composes, for these
   reasons and no others. It judges a descriptor by the mount `fdinfo` names,
   in the mount namespace of the thread that walked, so the broker's walk and
   the broker's table agree whatever the unit rearranged. It judges a mount by
   what the filesystem is: FUSE and its `user_id`, `idmapped`, a user
   namespace. It does not judge by flags or bind roots under a root-owned
   path (`MountPolicy::RootPath` ignores `nosuid`/`noexec`/`ro`, because
   `/run` itself is `nosuid`), so the read-only `/run` and the tmpfs bind on
   it pass; and `tmpfs` is accepted as anything else root mounted is. It reads
   the table only through a descriptor `fstatfs` shows to be procfs, which the
   unit's `/proc` instance is, and `/proc/thread-self/{fdinfo,mountinfo}`
   remain under `ProcSubset=pid`. **What is not shown:** all of that is read
   from the code and its tests, run outside the unit. No test starts the broker
   under its own sandbox and walks the spool there; until one does (phase 3's
   container tests, with open item 5), treat the composition as argued, not
   measured. Any later tightening of `RootPath` that looks at flags, bind
   roots, or sources must be tested under the unit first. The unit is not
   changed here, and no `NoExecPaths=`/`ExecPaths=` is in it.

Measured, on the commit that carries this entry: `just verify` green (100%
lines, regions, and functions on macOS, through the pre-commit hook);
`just check-linux` clean for both Linux triples; `just linux-test` green on
Linux 6.12.76 in Docker as uid 1000, the new Linux tests included; `just units`
(the D5 lane, added to main while this was in review) green against the two
units, `verify` silent and the service at 1.1 of the 1.2 ceiling. The same
`cargo llvm-cov` command `just coverage` runs, run in that container as uid
1000, is 100% on every file this change adds or touches. It was not before:
a Linux-only test used `matches!`, whose non-matching arm is a region no test
reaches, which would have failed the Linux runners' coverage gate and no macOS
run could show (`spool.rs`, now an `assert_eq!`). Two files this change does
not touch are below 100% in the container and are left to the runners: `probe.rs`
(needs `sudo` or `doas` installed, which the container lacks) and `syscall.rs`
(one test's closure runs only from kernel 6.16, and the container has 6.12; the
runners have 6.17).

---

## 2026-10-21 — D5: the unit checks and the root tests are CI lanes now

Finish-plan item D5. Two checks that had been done by hand in a Docker session
now run on every pull request: systemd's own verdict on the unit files, and the
tests that must be uid 0. Neither is in `just verify`, which has to run on a
machine without Docker; both need it.

**The unit lane: `just units`, `ci/units/`.** Every unit file under `packaging/`,
in a `debian:trixie-slim` container (systemd 257.13), through `systemd-analyze
verify` and `systemd-analyze security --offline`. It blocks from the start.
Until B1 lands there is no `packaging/`; the lane says so and skips, so it
merges first. Run against the broker's `aidod.socket` and `aidod@.service` as
they stand on its branch (`7dcc41a`; its `tmpfiles.d/aido.conf` is not a unit
and is ignored) it passes, and that closes the broker's open item "The unit
check is manual": its merge should replace that item with a pointer here. What
building it measured, which is why it is built the way it is:

1. **`verify` exits 0 for a misspelled directive and for a value it cannot
   parse.** `NoNewPrivilegs=yes` and `RuntimeMaxSec=banana` each print one
   warning, are ignored, and leave the exit status 0. A hardening line that is
   ignored is a unit that starts without it, which is the case
   `aidod/tests/units.rs` guards by refusing keys it does not know. So the check
   is that `verify` exits 0 *and says nothing*. It does exit 1 for a dependency no
   unit provides and for a missing section header.
2. **`security` applies to services only.** Given a socket it scores what the
   socket does not declare: `aidod.socket` came out 9.6 UNSAFE. A socket's keys
   are held by `verify` and by `units.rs`, and by nothing else.
3. **The ceiling is 1.2** (`unit_exposure_max`, at the top of the justfile;
   `--threshold` takes whole tenths). The broker's service scores 1.1, on arm64
   and, under emulation, on amd64. Measured, dropping one line from it costs:
   `CapabilityBoundingSet=` 2.9; `RestrictAddressFamilies=` and
   `RestrictNamespaces=` 1.8; `PrivateNetwork=` 1.5; the two `SystemCallFilter=`
   lines 1.4 and 1.3; `PrivateDevices=` 1.3. All are over the ceiling. The small
   ones (`NoNewPrivileges=`, `ProtectSystem=`, `ProtectHome=`, and the like, 1.2
   or 1.1) are not, and stay `units.rs`'s to catch line by line: the score is a
   net under that test, not a replacement for it. Raising the ceiling is a
   reviewed change that says why, and a ceiling of 1.5 or more fails the
   self-test below until that is changed on purpose.
4. **The lane tests itself first.** `ci/units/control/` is a service and a socket
   it must accept. Six edits to them, one each, must each be refused *by the
   check named for it*: a misspelled directive, an unparsable value, a hardening
   directive under the wrong heading, a dependency nobody provides, a misspelled
   socket directive (all `verify`), and `PrivateNetwork=` removed (exposure). An
   edit that alters nothing fails the self-test, so a control that drifts from
   its own mutations cannot make it pass for want of anything to test. On the
   broker's real service, a typo fails `verify` with systemd's own warning, and
   dropping `PrivateNetwork=` fails the ceiling at 1.5 with the costly lines
   listed.
5. **The programs are stubbed.** `verify` refuses a unit whose `ExecStart=` is
   not an executable file, and the programs are not in the repository, so each
   absolute path a unit names gets a stand-in. What is checked is the unit, not
   that the package installs `/usr/libexec/aido/aidod` there; that is phase 3's
   test of the package. A template is verified under systemd's dummy instance
   (`aidod@test_instance.service`), which is the "and an instance" the by-hand
   check did separately.

Not covered, and still by hand: `systemd-tmpfiles` creating the two directories
with their modes from `tmpfiles.d/aido.conf` (the textual lines are
`units.rs`'s), and anything about `sysusers.d` once it exists.

**The root lane: `just root-test`, `ci/root-test.sh`.** The mirror of
`linux-test`: real root in a throwaway container, on a copy of the checkout
with the checkout mounted read-only, for what only root can observe.

1. **Only `root_*` test targets, not the whole workspace.** D5 as written named
   `cargo test --workspace --features root-tests`, which would run the existing
   suite as root. Measured: five `aido-sys` unit tests fail there
   (`a_checkout_is_not_root_owned_on_the_walk`,
   `a_real_directory_owned_by_the_test_user_is_refused`,
   `an_untrusted_ruleset_is_refused_before_it_is_parsed`,
   `the_directory_must_pass_the_walk_from_the_root`,
   `a_log_that_refuses_reaches_no_mirror`), every one because it takes the
   checkout or the caller to be someone other than root, and the rest passing as
   root says nothing about the mode checks root ignores (2026-10-15). So the
   lane runs `cargo test --workspace --features root-tests --test 'root_*'`, one
   test at a time, with their output shown.
2. **A cargo feature selects the tests; nothing reads the environment.** The
   feature is `root-tests`, declared in `aido-sys`, which the install executor
   lives in. The suites that enable every feature (`just test`, `just
   linux-test`, coverage) build the root tests and run them as an ordinary user,
   where they return early and print `SKIPPED:`, the idiom of the `nix` crate.
   Root tests are integration tests under `tests/`, which `cargo llvm-cov` leaves
   out of its report, so a skip path costs no coverage (checked: the report is
   100% and lists no file under `tests/`). The lane makes a skip a failure: it
   reads the output for `SKIPPED:`, and counts passing tests from cargo's own
   summaries, so a lane that ran none fails too. A `[[test]]` entry with
   `required-features` means a run that forgot the feature errors ("requires the
   features") rather than running an empty binary and passing.
3. **What it holds today is its own tripwire**, `aido-sys/tests/root_lane.rs`:
   real, effective, saved, and filesystem uid and gid all 0; a mode-0000 file
   readable, which is the reason `linux-test` never runs as root; a file given to
   another owner and moded 0440, then handed back (`CAP_CHOWN` and `CAP_FOWNER`,
   which an install depends on). Measured to fail where it should: run as uid
   1000, the lane fails listing the three skips; with a filter matching nothing,
   "no root test ran"; in a container without `CAP_CHOWN`, `give a file to
   another owner: Operation not permitted`.
4. **The lock is shared by construction.** It moved from `linux-test.sh` into
   `ci/lib/machine-lock.sh`, which both scripts source; the protocol and the
   path are unchanged, so a run from another worktree's older copy still takes
   turns with it (measured: turn-taking, and a dead holder's lock taken over).
   The two share the cache volumes, and the root run leaves root-owned files in
   them that `linux-test`'s opening `chown` takes back. The lane asks rustup for
   the toolchain from outside the checkout, because asked from inside it rustup
   reads `rust-toolchain.toml` and downloads the cross targets and tools the
   file lists, on every run of a container that forgets them. It has no cache on
   a runner, so each job builds what its tests need from nothing: little while it
   holds three tests, worth revisiting when B4's make it slow.

**It does not block yet, and when it does.** Until the install executor's own
root tests land, a red lane would be about the lane, so the `root-tests` job
carries `continue-on-error: true`. **The switch, in the commit that merges B4's
root tests:** delete that line; add `root-test` to the `ci` recipe in the
justfile; and, if branch protection lists required checks, add the job's name.
It is written in the job's comment and in the finish plan's B4 item. B4's tests
are `tests/root_<name>.rs` in the crate that owns the code, behind
`#![cfg(feature = "root-tests")]`, each beginning by asking `root_or_skip` and
returning if it says no; the header of `root_lane.rs` says so.

**No longer manual, and what still is.** The unit checks are no longer manual.
The root tests are no longer manual as a mechanism: a test that must be root is
a file and a lane, not a Docker session. What the lane does not yet hold is the
install executor's tests (B4) and the audit production path, which step 6's open
item 11 records as run by hand as root; that is the next thing to move in.
Neither lane has run on a GitHub runner yet (amd64, Ubuntu 24.04, a fresh
Docker). The units lane is a skip there until B1; the root lane is non-blocking,
which is the second reason it is.

Measured, on this host: `just verify` green at 100% lines, regions, and
functions; `just check-linux`, and clippy over every target for both Linux
triples, clean; `just linux-test` green on Linux 6.12.76 aarch64 as uid 1000
(1076 tests, the lock library in use); `just root-test` green as uid 0 (three
root tests, none skipped); `just units` against the broker branch's units green,
and the failing cases above shown failing.

---

## 2026-10-21 — Temporary permissions, planned for M5

Requested: time-limited permissions that let a harness run something for a
while without asking each time, default 30 minutes, for a single permission or
a whole permission set (`aido set-temp nginx-reload 30m`, `... 24h`). Folded
into the time-boxed grants M5 already planned, instead of a second mechanism,
and specified in `howiwork.md` § Temporary permissions, spelled
`aido grant <name> [duration]` to match the existing `grants`/`revoke` verbs.

The decisions that keep it inside the invariants: a grant can only activate
what root's rules already define (a permission, a set, or a `grant-only`
dormant action), never invent or widen one; it is minted by a human on the
password path, never by an agent and never from inside a grant; it lifts only
the per-call confirmation, never the deny-list, a human-only action, the
critical tier's confirmation, or the rate limits; a duration over the ceiling
is refused rather than shortened; expiry is checked at every use, not left to
pasban's sweep. It needs M4 to mean anything and needs permission sets to
become a rule-file construct first, so it lands as the first part of M5, with
five new standing properties listed in `docs/todo/README.md`.

A Fable review of the spec found it met the request and returned four gaps,
all closed before commit: the grantee is an M4 registry identity matched to
the requester's kernel-attested scope at every use, never a name-based hint
(invariant 1), and a bare grant's default grantee is written down; the spec
now argues invariant 3 explicitly (the password-gated grant *is* the
out-of-band confirmation, given in advance and time-boxed); a grant records
the policy generation it was minted under and dies when the rules change; and
a design-plan deviation now says which old CLI text it supersedes. It also
made "live" mean both decision points, broker at mint and gate at exec.

---

## 2026-10-21 — M2b reviewed; the plan to finish it is written down

A Fable review of the milestone against main at `829f41d` (three of four
lanes; the fourth timed out and its ground is covered by the others). Its
substance: the four in-flight lanes — broker, doctor, gate, install — do not
close M2b when they merge. `aido exec` (step 3), the executing differential
(step 8), and the broker-plus-gate audit integration are separate exit
blockers, and verification row 15 was marked done too early: the chain and the
sinks are done, the end-to-end trail is not. Three documentation drifts were
corrected in the same commit: a sentence in the design plan's deviations block
that read as the opposite of the strictest-wins invariant, a status block that
still said "no unsafe yet" beside a step marked done, and crate inventories
that no longer matched the workspace.

`docs/todo/m2b-finish-plan.md` now carries the exit test and the sequence —
B merge queue in strict order, C new builds, D debts, E decisions — with the
fixed roles (Sonnet develops, Opus observes, Fable reviews) and the measured
estimates. One lesson is promoted to a plan item: four review rounds on the
doctor each found a new way its reading of sudoers/doas differed from the real
programs, so the real fix is to ask the programs (`sudo -l -U`, `doas -C`)
rather than re-implement their lexers.

---

## 2026-10-19 — M2b step 6: the audit sinks

**What exists.** `aido-sys::audit`: the contract the broker and the gate will
write through, and the two sinks behind it. Wired to neither binary; that is
steps 2 and 4.

- **The contract carries the rule.** `AuditSink::append` takes a function that
  builds the record from the chain's last record, calls it while the sink holds
  the log, and checks the result with `aido_audit::follows` — the verifier's
  own rule for one position, now shared by `verify` and every writer — before
  a byte is written. It returns an `AuditReceipt`, which only a sink in
  `aido-sys` can make. `authorize(sink, approval, build)` moves the approval in
  and hands it back as `Authorized<T>` only with that receipt, and only for a
  record that describes it — its command and governing action
  (`aido_audit::Approval`), checked before the write (review finding 6). On
  any error the approval given is dropped, and a record that says `denied`
  authorizes nothing (`RecordedAsRefusal`). The drop is not the guarantee —
  `Approved` is `Clone` — the types are: the broker's mint and the gate's exec
  are to take an `Authorized<_>`, so acting on an unrecorded approval is a
  type error rather than a review comment. A refusal needs no receipt: it is
  appended best-effort and stands either way.
- **`JsonlLog`, the chain's authority, at `/var/lib/aido/audit.jsonl`.** The
  directory through `open_trusted` (root-owned and not group- or
  world-writable from `/` down, no link); the file by `openat` on that
  descriptor, `O_RDWR|O_APPEND|O_CREAT|O_NOFOLLOW|O_CLOEXEC` at `0600`; `fstat`
  on the descriptor must show a regular file owned by root with no group or
  other bits and `st_nlink == 1`; an exclusive `flock`, waited for at most 5 s;
  the last record found in the last 128 KiB (`aido_audit::continuation`); the
  new record built, checked, and refused over 64 KiB; one write, `fdatasync`,
  an `fsync` of the directory with a log's first record, and the record sent
  to the trail's mirrors — all under the lock. Any failure from the write on
  cuts the log back to where it ended, and syncs the cut, before the lock is
  released.
- **`JournaldSink`**: one native-protocol datagram per record to
  `/run/systemd/journal/socket`, through rustix's safe `socket_with` and
  `sendto`, with a 2 s send timeout. `MESSAGE` is one escaped,
  `term-sanitize`d, bounded line; `PRIORITY` is 5 for an authorization, 4 for a
  refusal, 1 for a refusal carrying the gate's `severity=high`;
  `SYSLOG_FACILITY=10`, a fixed `MESSAGE_ID`, `AIDO_*` index fields, and
  `AIDO_RECORD`, the file's line byte for byte, so the entries root sent can be
  compared with the file record by record. The encoder is pure
  (`aido-audit::journal`), snapshot-tested, and checked by a decoder written
  from the protocol description. Every query of it starts from
  `aido_audit::journal::query`, which matches `_UID=0` (review finding 1,
  below).
- `AuditTrail::system(identifier)` is the log, then journald, both required.
  `FakeAuditSink` exists only under the `fake` feature, which only test builds
  enable.

**Decisions.**

1. **`/var/lib/aido`, not `/var/log/aido`.** The design plan's file table and
   `todo/README.md` disagreed. On Ubuntu `/var/log` is `root:syslog 0775`, so
   nothing beneath it passes the ancestor walk — rightly, since the `syslog`
   group can rename `/var/log/aido` aside. `/var/log` is also where rotation
   truncates and where log2ram keeps files that never reach a disk. `aido-config`
   names the path (`SystemPaths::audit_log`) and its unused `log` field is
   gone; the design-plan table and deviations block and the phase 3 packaging
   notes say the same. The deny-list already protected `/var/lib/aido`
   (`writing_anything_that_decides_is_denied` now lists the file) and keeps
   `/var/log/aido` as a former location.
2. **The file is the authority and journald a required mirror**, the reverse of
   the plan's "journald primary". Only a file has a last record to continue
   from, and journald rate-limits without telling the sender. The send happens
   while the log is still locked, and a failed one cuts the record back out of
   the log (review finding 2): an append lands on the whole trail or on none
   of it, so a host without journald records nothing, refusals included.
3. **A cap, not `memfd`, for oversized entries.** The writer refuses a record
   over 64 KiB before writing anything, so an entry stays near 70 KiB at most,
   under `PAYLOAD_MAX` (96 KiB) and the stock ~208 KiB socket send buffer. A
   host tuned below that gets `EMSGSIZE`, which fails closed. Replayed into a
   real `systemd-journald` (Debian stable, in Docker): all three snapshotted
   payloads were stored with every field, and each `AIDO_RECORD` parsed back.
4. **No `systemd-journal-logger` and no `/dev/log` fallback**, against the
   plan's dependency table: the protocol is a few dozen lines over rustix,
   already a dependency. The cost is open item 4.
5. **Damage stops the writer.** A torn, edited, foreign-schema, or overlong
   last line is refused (`TailError`): never continued past, never answered
   with a fresh `seq 1`. The one tolerated irregularity is a complete record
   missing its final newline. Repair is a person's: move the log aside, which
   starts a new chain deliberately and keeps the evidence. `aido audit --log`
   reports the same damage, or the first damage before it (review finding 4);
   the refusal names that command, because the front-end has no `verify`
   subcommand whatever older text calls it.
6. Found by the snapshot: a newline in a quoted value ended `MESSAGE` there and
   dropped the outcome. Every quoted value is now escaped.

**Review, and how each finding was resolved.** An independent review of the
step found no fail-open path — every error it could cause came back `Err`, and
no receipt preceded `fdatasync` — and eight defects, resolved before merge
below (its journald-mirror defect is resolved by the same change as the
durability one, item 2), and two hardening notes (item 8, and open item 10):

1. **Anyone could forge an entry the documented query returned.** Any local
   user can send journald a datagram with aido's `MESSAGE_ID`, `PRIORITY=1`,
   and every `AIDO_*` field; reproduced against a real journald, where
   `journalctl MESSAGE_ID=… AIDO_DECISION=denied` returned uid 1000's entry.
   *Fixed:* `aido_audit::journal::query` renders the one query every alert
   rule and comparison starts from, `journalctl _UID=0 MESSAGE_ID=…`, and it
   excludes that entry (re-run: root's entry returned, uid 1000's not).
   `_UID` is the field journald takes from the kernel's credentials on the
   datagram. Only entries passing it count, and the journal is never the
   authority — root, which it still admits, can rewrite the file as easily.
   Pinned by `a_forged_entry_from_an_unprivileged_sender_fails_every_documented_query`,
   `the_query_in_the_module_docs_is_the_one_the_code_renders`, and the
   `trusted_query` snapshot. **Not** narrowed by `_EXE` or `_SYSTEMD_UNIT`, as
   the review suggested: journald reads those from `/proc` after the datagram
   arrives. Measured against systemd 257's journald, from root: of 300 entries
   whose sender exited at once, 299 had no `_EXE`; of 300 whose sender exec'd
   at once, 86 carried the exec'd program's. The gate exits as soon as it
   refuses and will exec as soon as it records, so that filter would drop its
   alerts — the entries it exists for. `_SYSTEMD_UNIT` is read the same way,
   and the gate runs in its caller's scope besides.
2. **A record that failed after its write stayed in the log, and the next
   writer chained onto it.** Only a failed write was cut back. After a failed
   `fdatasync` the "allowed" line stayed, and Linux reports a writeback error
   once, so the next writer's own `fdatasync` could succeed over a page that
   never landed; after a failed directory `fsync` the next writer saw a record,
   never synced the directory, and issued receipts a crash could erase with
   the file; and a failed journald send left an "allowed" record that nothing
   distinguished from one that ran. *Fixed:* the mirrors are sent to inside
   the log's write, under its lock, and any failure from the write on cuts the
   log back to its size before the write and `fdatasync`s the cut. For a first
   record that means no record at all, so the next writer syncs the directory
   itself. The review's two reproductions are kept, inverted:
   `a_record_whose_fdatasync_fails_is_cut_back_before_any_writer_chains_on_it`
   and `a_first_record_whose_directory_sync_fails_is_cut_back_so_the_next_writer_syncs_it`;
   also `a_mirror_that_refuses_gets_the_record_cut_back_under_the_lock`,
   `a_mirror_that_refuses_leaves_no_record_for_the_next_writer_to_chain_onto`,
   and `the_record_reaches_the_mirrors_while_the_log_is_still_locked`. What
   cannot be closed: if the cut itself fails, the next writer finds what is
   left — a torn tail it refuses, or a whole record it continues from.
3. **The log was checked before the lock and not after it.** A writer waiting
   up to 5 s for the lock while root moved the log aside (as the damaged-tail
   refusal says to) or deleted it went on to lock the old file and return a
   receipt for a record in a file that was no longer the chain, or in none —
   reproduced on macOS and Linux. *Fixed:* once the lock is held, `fstat`
   again (one name) and `statat` the name without following it (same device
   and inode); otherwise close and reopen, within the same bound, and refuse
   if the log is still changing when it runs out. The review's two races are
   kept as regressions with honest names,
   `a_log_deleted_while_a_writer_waits_never_takes_the_record_with_it` and
   `a_log_moved_aside_while_a_writer_waits_keeps_its_evidence_untouched`, with
   `a_log_replaced_while_a_writer_waits_is_written_in_its_replacement` and
   `a_log_that_keeps_changing_under_the_writer_is_refused_once_the_wait_runs_out`;
   all three races fail with the check removed. A rename or delete *after* the
   check, while the lock is held, still lands the record in the moved file or
   in none — root's to do at any time, receipt or not.
4. **The writer refused endings the verifier called intact, and the refusal
   promised the verifier would name the line.** Past 128 KiB of blank space,
   or a last line longer than the window, the writer refused every decision
   while `aido audit --log` printed "chain intact"; a non-UTF-8 tail it
   reported as an unreadable file, with no line. *Fixed:* one shared check.
   `aido_audit::verify_log` — what `aido audit` now runs, on the file's bytes —
   verifies every record and then asks `continuation_of` about the end: the
   writer's function, on the window `window_start` gives both of them. So
   every ending the writer refuses is reported, as the line when the damage
   is a line and as the writer's own refusal when it is not, and a non-UTF-8
   line is named by number (`Chain::from_jsonl_bytes`). The refusal now says
   `aido audit --log` "reports it, or the first damage before it", which is
   what it does. The review's reproduction, inverted:
   `a_blank_tail_the_writer_refuses_is_reported_by_the_verifier_too`; with
   `the_writer_and_the_verifier_agree_on_every_ending` (eleven endings, both
   answers), `audit_reports_an_ending_the_privileged_writer_refuses_instead_of_calling_it_intact`,
   and `audit_names_the_line_of_a_tail_that_is_not_text`. A consequence to
   know: `aido audit` applies the privileged writer's end rule to whatever log
   it reads, so an `ido` log whose last record runs past 128 KiB — `ido` caps
   none — is reported, though `ido` itself would continue it.
5. **`FakeAuditSink` did not enforce `MAX_RECORD_BYTES`.** A builder padded
   past 64 KiB passed every test against the fake and failed with `TooLarge`
   only in production. *Fixed:* every sink builds, chains, and sizes its record
   through one function, `next_record`, so the fake refuses exactly what the
   log refuses. `the_fake_sink_refuses_exactly_the_records_too_long_for_the_real_log`
   pins it at the byte: a line of exactly 64 KiB is accepted by both, one more
   byte refused by both with the same error.
6. **`authorize` did not tie the record to the approval.** It checked only
   that the record was not `denied`, so a builder that recorded another argv
   or action still produced `Authorized<T>`; and "the approval is dropped" was
   claimed as a guarantee though `Approved` is `Clone` with public fields.
   *Fixed, minimally:* `authorize` takes `T: aido_audit::Approval` — the
   command and the governing action an approval must be recorded with,
   implemented by `aido_gate::Approved` and used by its own
   `authorization_record` for `argv` — and passes `AuditSink::append_checked`
   a check that the built record carries exactly those, run after the record
   chains and before anything is written (`AuditError::Misrecorded`). The
   docs now say the drop is not the guarantee; executors taking
   `Authorized<_>` is. Tests: `an_authorization_recorded_for_another_command_authorizes_nothing`,
   `an_authorization_recorded_under_another_action_authorizes_nothing`,
   `a_misrecorded_authorization_never_reaches_the_log_or_a_mirror`,
   `a_gate_record_built_for_another_approval_authorizes_nothing`, and
   `a_record_for_another_command_or_action_does_not_describe_the_approval`.
   The deeper design is open item 9.
7. **Documents still disagreed.** The design plan's dependency table still
   said `systemd-journal-logger` primary with a `/dev/log` fallback, its
   rationale "two sinks, both independent", and its TOCTOU section "audit to a
   socket, not a path"; `Chain::replace_tail` still called editing an outcome
   in place "the one legitimate mutation". *Fixed:* the plan (and the same
   paragraph in `SUGGESTIONS.md`) now says one authority, journald a required
   mirror written under the file's lock, only `_UID=0` entries counting, and
   a log opened through the descriptor walk. `replace_tail` is deleted —
   nothing called it, on any branch, and its only purpose contradicted the
   append-only log — and
   `an_outcome_is_a_record_of_its_own_and_filling_one_in_is_tampering` pins
   the rule instead. The two cuts the file cannot show — truncation to zero,
   which restarts the chain at `seq 1`, and a cut at a record boundary, which
   is continued — are stated as open item 5, and in `aido_audit::tail`.
8. The `open_trusted` `O_DIRECTORY` hardening note is left to step 7, whose
   branch changes that function.

**How the broker and the gate are to call it** (the module docs carry the same
sketch): open `AuditTrail::system("aidod")` or `("aido-gate")`. On a refusal,
`append` the record `refusal_record` builds and refuse whatever comes back. On
an approval, `authorize` with `authorization_record`, act only through the
`Authorized<_>`, and refuse when it errs. The receipt's `seq` is the audit id a
spool entry or a decision envelope can cite.

**Tests**, named for the attack: on a real file, the symlink, dangling-symlink,
second-name, foreign-owner, and readable-mode refusals
(`a_dangling_symlink_cannot_make_the_writer_create_a_file_elsewhere`,
`a_log_with_a_second_name_is_refused`); a torn and an edited tail on disk, each
refused by the writer and named by the verifier
(`an_edited_last_record_on_disk_stops_the_writer_and_the_verifier_names_it`);
`concurrent_writers_never_fork_the_chain`; through a fake file, the order write
→ `fdatasync` → directory `fsync` and each failure among them
(`the_first_record_starts_the_chain_and_reaches_the_disk`,
`a_record_whose_fdatasync_fails_is_cut_back_before_any_writer_chains_on_it`,
`a_write_that_fails_part_way_is_cut_back_to_where_the_log_ended`);
`an_approval_that_cannot_be_recorded_leaves_nothing_to_act_on`;
`an_argv_cannot_forge_a_log_line_or_drive_the_terminal_through_the_message`;
and on Linux, the transport against datagram sockets bound under `target/`:
delivered whole, refused by a dead or a stalled receiver within the timeout,
and `the_journal_receives_the_line_the_log_holds_byte_for_byte` through the
real trail. Where there is no journald, as in the container,
`the_system_sink_reaches_journald_exactly_when_the_host_has_one` asserts the
refusal; on a CI runner, the delivery.

**Open.**

1. **Wiring (steps 2 and 4).** Neither binary has a refusal for "the record
   could not be written": no `DenialCode`, no gate `Refusal` variant. Adding
   one changes the pinned denial contract, so it is a reviewed snapshot change.
2. **Outcomes.** An outcome learnt after exec is a second record naming the
   authorization (`authorization_record`'s doc said the record is "updated";
   it now says append-only). `Record` has no field to name it with yet, and
   whether the gate learns an outcome at all is step 4's process-model call.
3. **A refusal over 64 KiB goes unrecorded.** A caller can pad an argv until
   its refusal record is too large to write. The broker should cap a request's
   size, and both callers should fall back to a bounded refusal (argv elided,
   its length as evidence); there is no helper for that yet.
4. **No `audit_sink` setting.** A host or container without journald —
   including the devcontainers agents often run in — refuses every privileged
   request. Phase 3 still says `Recommends: systemd`; decide before the beta
   `.deb` whether that becomes `Depends`, or the setting comes first.
5. **Two cuts the file cannot show, and nothing cross-checks it against the
   journal.** A log truncated to zero bytes — or to nothing but blank lines —
   holds no record, so the next writer silently starts a fresh chain at
   `seq 1`: it cannot tell an emptied log from a new one. A log cut back at a
   record boundary ends in a good record, so the next writer silently
   continues from it, and the verifier calls it intact. Both need root or a
   disk fault, and neither is detected today. The `AIDO_SEQ` and `AIDO_HASH`
   of the journal entries the trusted query finds would show both, but no tool
   compares them; pasban is where that comparison belongs. `aido audit`
   checks one file, defaults to `ido`'s per-user log, and needs
   `--log /var/lib/aido/audit.jsonl` and root for the chain.
6. **The directory's own mode.** The walk demands root-owned and not group- or
   world-writable, not the table's `0700`. Loosened to `0755` on a host with
   `fs.protected_hardlinks=0`, a local user can hard-link the log and so make
   the writer refuse every decision: fail closed, availability only. Step 7's
   mount check should cover `/var/lib/aido` as well as the ruleset.
7. On a host with journald, the suite leaves one `SYSLOG_IDENTIFIER=aido-test`
   entry per run, under the real `MESSAGE_ID`. It carries the runner's `_UID`,
   so the trusted query excludes it; only a suite run as root, which
   `just linux-test` and CI never do, would leave one the query counts.
8. `ido`'s per-user run log keeps its whole-log read and verify on every
   append. It shares `Record` and `Chain::from_jsonl` with the privileged
   writer and has no need of a tail window.
9. **The approval-to-record binding is minimal.** `authorize` checks the
   command and the governing action only; the rule source, the caller's
   classification, the confirmation channel, and the nonce are the builder's
   to get right. The fuller shape is for the approval to build its own record
   (`authorize<T: Recordable>`), or for the receipt to carry a digest the
   executor compares. And while `Approved` is `Clone` with public fields, the
   guarantee rests entirely on every executor taking `Authorized<_>`; a
   constructor-only `Approved` is step 4's call, when the executor exists.
10. **`0600` keeps the file from other users, not the records.** The same
    record, argv and all, goes to the system journal, which members of `adm`
    and `systemd-journal` can read. The mode is what keeps everyone else from
    writing — or reading — the file; it is not confidentiality from those
    groups. Found by the review, as were two quirks of the record hash outside
    this step, left for a schema bump: `None` and `Some("")` hash alike, and an
    `Outcome` is hashed through its `Debug` output, which no toolchain
    promises to keep stable.
11. **The production path has no committed test as root.** Every real-file
    test opens its directory itself (`LogDir::Opened`), because the suite runs
    unprivileged by design. The production path was run by hand as root in
    Docker instead — by the review, and again after these fixes (see
    "Measured").

Measured, after the review fixes: `just verify` at 100% lines, regions, and
functions on macOS; `just check-linux` and clippy over every target for both
Linux triples clean; `just linux-test` green on Linux 6.12 aarch64 as uid
1000, the three lock races, the create race, and the socket tests included.
The production path by hand as root in the same container, with no journald:
`JsonlLog::system()` created `/var/lib/aido/audit.jsonl` `0600`, root's, one
name; `AuditTrail::system` refused and left the log's size as it was; the
next append was `seq 2`, and `verify_log` read two records. Not yet seen on
the CI runners' 6.17.

---

## 2026-10-19 — M2b step 7: a ruleset on a mount a non-root user made

### The hole this closes

The trust walk checked each component's owner and mode on the descriptor it
opened, and believed what the filesystem reported. A FUSE filesystem reports
whatever its daemon says, and any user can mount one through the set-user-ID
`fusermount3`. So: a directory on the path to the rules is the user's by
mistake; the user mounts sshfs over it; the daemon answers every `stat` with
`root:root 0755`; the walk passes and the daemon serves the rules. The ownership
checks cannot see this. Only the mount table can.

`open_trusted`, `read_trusted_dir`, and `load_trusted_rules` now match every
descriptor they open — each path component and each rule file — to its mount,
and judge the mount (`crates/aido-sys/src/mounts.rs`) before anything else the
filesystem says about the component is believed. Each component is opened
`O_PATH`, which asks its filesystem nothing — crossing into the root of a FUSE
mount does not reach the daemon — then its mount is judged, and only then are
its kind, owner, and mode read from that descriptor; nothing beneath a
component is looked up until it has passed. So a user's daemon is never asked
anything. It cannot choose the refusal the operator sees, by answering `stat`
with an owner of its choosing or, without `allow_other`, by refusing root
outright; and it cannot stall the walk. The refusal names the outermost
component at fault, and where one component fails both ways its mount is what
is reported (`the_owner_a_daemon_reports_is_never_asked_for_before_its_mount_is_refused`,
and on Linux `on_linux_a_component_nobody_may_open_is_still_refused_for_its_mount`).
The directory's mount is judged before the directory is listed, so a FUSE
daemon chooses neither the names read from it nor, through a file it reports
as writable, which refusal is shown
(`a_directory_on_a_refused_mount_is_not_listed_so_its_daemon_cannot_pick_the_refusal`).
Rule files are opened `O_PATH` and their mounts judged together — a file can be
a mount point of its own — before any is checked or read:
`a_rule_file_on_a_refused_mount_is_refused_before_any_file_is_read` proves it
with a directory named `20-b.toml`, whose read would fail with `EISDIR` and
does not get the chance. Nothing can be read through `O_PATH`, so the target
and each rule file are opened once more, by name, in a directory that has
passed, and refused (`TrustError::Replaced`) unless the device and inode are
the probe's; the probe stays open meanwhile, so its inode cannot be freed and
reused (`a_rule_file_replaced_after_it_passed_is_refused_rather_than_read`,
`a_target_swapped_after_it_passed_is_refused_rather_than_opened`). A file named
as the rules directory passes as the walk's last component and is refused by
that reopen, which asks for a directory.

### Deviation: matched by mount id, not by `st_dev`

The step was proposed as "match each component by `st_dev`, and where that is
ambiguous take the longest matching mount point". Measured on Linux 6.12 in a
throwaway privileged container (a loop-backed btrfs with one subvolume, mounted
twice): mountinfo listed both mounts as `0:72`, while `stat` reported `0:73`
for the top-level subvolume and `0:74` for the other. btrfs gives every
subvolume an anonymous device of its own, and none of them appears in
mountinfo, so on a btrfs root — Fedora's default — an `st_dev` match finds
nothing at all and would refuse every install. overlayfs also reports
per-layer devices for some files. And two mounts of one filesystem share a
device while differing in exactly the per-mount options that matter.

What is exact is `mnt_id` in `/proc/thread-self/fdinfo/<fd>`, present since
Linux 3.15 and equal to mountinfo's first field. In the same container it told
the two mounts of device `0:74` apart (`198` and `199`). An open descriptor
keeps its mount alive, so the id cannot be reissued to another mount while the
walk holds it; a mount detached after the open is simply no longer listed, and
an unlisted mount is refused. `devices_that_mountinfo_cannot_tell_apart_the_mount_id_can`
pins the btrfs case.

### What is refused, and why

The kernel does not record who asked for a mount. In the initial user
namespace every mount needs `CAP_SYS_ADMIN`, so a non-root user mounts only
through something running as root for them, and each leaves a mark:

- **FUSE** (`fuse`, `fuseblk`, `fuse.<subtype>`) unless it names exactly one
  `user_id` and that is `0`. `fusermount3` writes the invoking user's uid
  there. Missing, duplicated, or non-numeric is refused too: who serves the
  mount cannot be told. The daemon chooses only what follows the dot in the
  type; the kernel writes `fuse` before it. A FUSE mount that root made is then
  judged like any other mount: a stick a desktop automounts through a root-run
  `ntfs-3g` (`fuseblk … user_id=0`) is still refused for the ruleset by the
  `nosuid` udisks2 gave it
  (`a_root_mounted_fuse_still_carries_the_marks_of_a_user_mount`).
- **`nosuid` or `noexec`, for the ruleset only**: on every component of the
  path to the rules and every rule file, as the design plan asks of
  `/etc/aido` (`MountPolicy::Ruleset`, used by `read_trusted_dir` and
  `load_trusted_rules`). `fusermount3` and udisks2 mount `nosuid`; fstab's
  `user` and `users` imply `nosuid,noexec`, `owner` and `group` imply
  `nosuid`. The real user FUSE mount in the probe read
  `rw,nosuid,nodev,noatime - fuse.fuse-overlayfs ... user_id=1000`, so it is
  refused on two independent counts. `nodev` alone is not refused: half the
  mounts on a normal host carry it. `open_trusted`, which any other root-owned
  path goes through, does not refuse these two (`MountPolicy::RootPath`):
  root's own mounts carry them — systemd mounts `/run` `nosuid,nodev` on every
  host, the gate's spool is `/run/aido/req`, and `/var`, with `/var/lib/aido`,
  is `nosuid` on some — so there they say nothing about who made the mount
  (`a_spool_on_a_nosuid_mount_opens_while_rules_there_are_refused`; on Linux,
  `procfs_is_refused_as_a_home_for_rules_by_its_mount` opens `/proc/sys`
  through `open_trusted` and refuses it to `read_trusted_dir`).
- **`idmapped`**, to every reader: the owners it reports are a mapping chosen
  at mount time, not what is on disk.
- **A mount the table does not list**, and **a table that cannot be read or
  does not parse**, to every reader.
- **Everything, when the thread is outside the initial user namespace**, read
  as the `ns/user` link and compared with the kernel's fixed
  `PROC_USER_INIT_INO` (`user:[4026531837]`). There, uid 0 means the
  namespace's owner; and the kernel prints a FUSE mount's `user_id` relative
  to the user namespace the mount was made in, which mountinfo does not name.
  In the initial namespace, a mount owned by another can only arrive by root's
  hand (propagation out of a less privileged mount namespace is one-way, and
  `move_mount` needs `CAP_SYS_ADMIN` over the target). A kernel built without
  `CONFIG_USER_NS` lists no `user` entry in `ns/` and has no namespace but the
  initial one, so `ENOENT` for that entry, in an `ns` directory already proven
  to be procfs, is read as the initial namespace; any other failure is refused
  (`a_kernel_without_user_namespaces_is_not_refused_as_unreadable`). This is
  also the design plan's "namespaced root" refusal, for the trust walk only;
  the broker and the gate should still check their own identity (steps 2 and
  4).

### What is accepted, and why

Anything else root mounted, because root chose to put the rules there:
root-mounted FUSE (`user_id=0`, e.g. `lxcfs`); network and virtual
filesystems (NFS, CIFS, 9p, virtiofs), which delegate trust to a server or a
hypervisor that root picked — and refusing them would refuse every diskless
NFS-root host outright; filesystems with no ownership model (vfat, exfat)
mounted by root, whose owner comes from mount options root wrote. A user's
mount of the same media carries `nosuid` from udisks2 or from fstab's `user`.
An allowlist of filesystem types was considered and rejected: it would refuse
bcachefs, erofs, nilfs2, ZFS and every type added later, and the plan's
criterion is who made the mount, not what it is.

### The table, and how it is believed

Read from `/proc/thread-self/` — `mountinfo`, `fdinfo/<fd>`, and the `ns`
directory — every file through a descriptor `fstatfs` reports as procfs, so a
mount over `/proc` cannot hand back a table of its choosing
(`a_forged_proc_is_refused_before_its_table_is_read`). `thread-self`, not
`self`: the walk resolved its paths in this thread's mount namespace, and the
descriptors are in this thread's table. Opening through `thread-self` follows
procfs's own link; the `fstatfs` on the final descriptor is the check.
`openat2(RESOLVE_NO_XDEV)` would pin the read to the verified mount itself, and
needs 5.6. `mnt_id` is in fdinfo since 3.15 and `thread-self` exists since
3.17; on an older kernel the read fails, and refuses.

The table is read once per component, after that component's `O_PATH` open
and while it is held, and once more for all the rule files together: five
reads for `/etc/aido/rules.d` with no rule file in it. Never once up front: a
mount id is handed to a new mount as soon as its old one is gone, and only an
open descriptor keeps the mount it names alive, so a table read before the
descriptor was opened could describe a different mount under the same id.

`parse_mountinfo` reverses an M1 decision. It used to skip lines it did not
understand, which suited discovery; as evidence in a trust decision a skipped
line is a mount nobody looked at, so any malformed line now refuses the whole
table, as does a table that ends mid-line. Fields are split on spaces before
the kernel's octal escapes are decoded, so a directory named `a - b` cannot
move a field; decoding is byte-exact, and a backslash the kernel's escaper did
not write is kept as written. `aido-sys/tests/mountinfo.rs` renders arbitrary
bytes exactly as `show_mountinfo` does and requires them back unchanged, and
requires that no input can panic the parser.

### Decisions worth knowing

- **Off Linux, nothing is trusted.** There is no mount table, so the three
  functions refuse everything on macOS, at `/`, and `aido doctor` there says
  the mount table cannot be checked. The walk and the judgement are tested on
  every platform through a scripted table (`mounts::fake`); the real `/proc` is
  tested on Linux. macOS has no `O_PATH` either, so its probe is a read-only,
  non-blocking open: a link or a socket there is refused as something that
  cannot be opened rather than for what it is, and the tests expect each
  platform's wording. The kind check itself is exercised on both
  (`the_stat_of_a_link_or_a_socket_is_never_taken_for_a_file`).
- **The target is reopened by name, not through `/proc/thread-self/fd/<n>`.**
  Both give a descriptor that can be read; the name needs no procfs and runs
  the same on macOS, and the device-and-inode comparison against the held
  probe closes the window the second lookup opens. The directory is one that
  passed, so only root can rename within it, and the comparison holds even
  against root.
- **The host reader is written as `and_then` chains, not `?`.** Each failure is
  still propagated, and each is reached by a test of the function that produces
  it, which a `?` after an infallible-in-practice read would not be.
- **A refusal shows the mount's bytes escaped.** A FUSE daemon names its own
  subtype, the kernel escapes only space, tab, newline, and backslash in it,
  and the parser decodes those back. `TrustError::UntrustedMount` keeps the
  decoded bytes for anything that compares them and renders the type and the
  mount point through `escape_ascii`, so an escape sequence, or a newline
  forging a line of `aido doctor`'s report, reaches the terminal as visible
  text (`a_fuse_subtype_cannot_write_to_the_terminal_that_shows_its_refusal`).
  The component path is rendered as before: it comes from the operator's path,
  or from a listing on a mount that has already passed.
- **Mutants run against the tests**, each killed: judging only a mount's first
  listing; mount-checking the directory but not its rule files; skipping the
  user-namespace check; taking the first `user_id` rather than demanding
  exactly one; decoding escapes before splitting the line; listing the
  directory before judging its mount; rendering the type unescaped. Another,
  reading the files before the check, does not compile: the read consumes the
  descriptors the check borrows. Two more that review found surviving every
  test are now killed — accepting a root-made FUSE mount without judging its
  marks, and not judging the mount of the target itself — and, after the
  review fixes, so are: `fstat` before the mount is judged; dropping the
  device-and-inode comparison; not judging the mounts above the target, or
  the rule files' mounts, or the target's; judging the rules directory or its
  ancestors, or the rule files, without `nosuid`/`noexec`; holding
  `open_trusted` to them; and refusing them to every root-owned path, or
  `idmapped` to none.
- **Recovered work.** The first implementation was interrupted by an API
  outage before it was committed. It was rebased onto step 2b (only this log
  conflicted), and a review pass then added three things above: the escaped
  rendering, the directory judged before it is listed, and `O_DIRECTORY` on a
  directory reader's target (now on the reopen it is listed through). Step 2b
  had meanwhile fixed the macOS socket-path test in its own way, so this
  step's workaround for it was dropped. An independent review then found the
  five things below; it was rebased onto `howiwork.md` first, again with only
  this log in conflict.

### What review should look at

1. Accepting root-mounted FUSE and network filesystems. Stricter is a one-line
   change in `mounts::refusal`; the cost is NFS-root hosts and lxcfs users.
2. `nosuid` and `noexec` judged on every component of the path to the rules,
   not only on the directory holding them: if `/` or `/etc` is ever `nosuid`
   — a host that layers `/etc` from `systemd-confext` images may be one —
   nothing loads. And not judged at all on other root-owned paths, which is
   where a future caller that opens a rule file through `open_trusted` would
   lose them.
3. The user-namespace refusal living inside the trust walk.
4. Strict parsing: a kernel that prints a line this parser does not expect
   refuses every ruleset on that host, loudly, until the parser learns it.
5. The table is read once per component and once for the rule files, five
   times for `/etc/aido/rules.d`, rather than once; see above for why it
   cannot be read up front.

### Still open

- **Overlay layers are not walked.** A root-built overlay whose upper directory
  a user can write lets that user rearrange root's files in the merged view.
  Only root can build one in the initial namespace, and the layer paths are in
  root's mount namespace, not necessarily this one.
- **fstab `user` semantics are seen only through `nosuid`/`noexec`.** libmount
  records the mounting user in `/run/mount/utab`, a private format the kernel
  does not attest; an fstab line that re-enables `exec,suid` for a user mount
  is invisible here, and is root's own choice.
- **Before Linux 5.8 a mountinfo read is not atomic** across `read` calls while
  mounts change: a mount can be listed twice (every listing must pass) or not
  at all (refused). Transient, and fail-closed.
- **No fuzz target** for `parse_mountinfo`; the property tests cover panics and
  round trips. Adding one costs a minute of every CI run.
- `verify_path`, the path-based report, has no mount check; nothing calls it.
- **A root-made mount of a writable device is accepted.** The design plan
  refuses `/etc/aido` on a "user-writable mount" (its line 161), and nothing
  here checks what backs a mount: a root-made mount of a block device a user
  can write, or of a loop device whose backing file is the user's, passes,
  and that user can rewrite the filesystem under the kernel. mountinfo names
  the source (`/dev/sdb1`, `/dev/loop0`); checking it means resolving the
  device to its node and, for a loop device, to
  `/sys/block/loopN/loop/backing_file`, and walking that file's ownership. A
  block device's own node is `root:disk 0660` on most distributions, so
  "group-writable" cannot be the test. New design; recorded, not built.
- **`aidod`'s unit must not add `nosuid` or `noexec` to the path to the
  rules** — systemd's `NoExecPaths=` would, for one — or nothing loads. To be
  recorded where the unit is written (step 2).
- ~~**A user's FUSE daemon can stall the walk.**~~ Closed by the review fix
  below: no component's filesystem is asked anything before its mount has
  passed.

### What review found, and how each was resolved

An independent review of the recovered commit found no path that fails open,
confirmed the core claim against real mounts, and found five things. Each was
confirmed here before it was fixed: by a test or a mutant the old code fails,
by a real-kernel probe, or, for the kernel without user namespaces, by the
code and the kernel's own table of `ns` entries.

1. **`open_trusted` refused every path under `/run`.** `nosuid` and `noexec`
   were refused to every caller, and systemd mounts `/run` `nosuid,nodev`: the
   gate's spool, `/run/aido/req`, would have been refused on every real host
   while `just linux-test` passed, Docker's `/run` being a directory on the
   container's root. **Fixed**: a `MountPolicy` — the ruleset readers refuse
   the two marks, `open_trusted` keeps every other refusal and not those.
   `a_spool_on_a_nosuid_mount_opens_while_rules_there_are_refused` pins both
   halves, the rules directory refused above and at itself;
   `a_rule_file_bound_nosuid_over_the_ruleset_is_refused` pins the files.
2. **Two behaviours no test pinned**, each mutant passing every test and
   clippy. **Fixed**: `a_root_mounted_fuse_still_carries_the_marks_of_a_user_mount`
   (a root-run FUSE stick with `nosuid`, `noexec`, `idmapped`) and
   `a_user_mount_over_the_target_file_itself_is_refused` (only the target on
   the user's mount). Both mutants were re-run and are killed, and the claim
   above that every mutant was killed now lists what was tried.
3. **The walk asked a user's FUSE daemon before judging its mount**, so the
   daemon picked the refusal shown — "Permission denied" without
   `allow_other`, an owner of its choosing with it — contradicting this
   entry's claim, and a stopped daemon stalled the walk. **Fixed** by the
   reorder described at the top of this entry: `O_PATH`, the mount, then
   `fstat`, and a reopen checked against the probe. Measured in a throwaway
   privileged container on Linux 6.12, `fuse-overlayfs` mounted by uid 1000
   on a root-owned `/opt/aido` and probed as root, before and after: without
   `allow_other` the old walk said "cannot be inspected: Permission denied",
   with it "is owned by uid 1000", and with the daemon stopped by `SIGSTOP` it
   hung until killed; the new walk reported the user's FUSE mount in all
   three, the last at once. Tests:
   `the_owner_a_daemon_reports_is_never_asked_for_before_its_mount_is_refused`,
   `on_linux_a_component_nobody_may_open_is_still_refused_for_its_mount`, and
   the two `Replaced` tests.
4. **A kernel without `CONFIG_USER_NS` refused everything**, its missing
   `ns/user` read as "(unreadable)". **Fixed** as described above:
   `ENOENT` there is the initial namespace, every other failure still refuses;
   `a_kernel_without_user_namespaces_is_not_refused_as_unreadable` feeds the
   decision every answer and checks a real procfs `ns` directory answers
   `ENOENT` for an entry it does not list.
5. **Documentation.** `SECURITY.md` still said rule-file ownership and mode
   were not verified; it now says what `aido explain` does not check, what the
   privileged loader does, and what no check covers yet. `mounts.rs` now says
   `/proc/thread-self` needs 3.17, and that a FUSE `user_id` is relative to the
   namespace the mount was made in. The design plan's "user-writable mount"
   criterion — a backing device a user can write — is an open item above, not
   built. `howiwork.md` lists this check as in review, which it is, and is
   unchanged.

Measured after the review fixes, on `howiwork.md` (113ed0f): `just verify`
passes on macOS with 100% lines, regions, and functions; `just check-linux`
is clean; `just linux-test` passes on Linux 6.12 (aarch64) as uid 1000, where
`/proc/sys` opens through `open_trusted` and is refused to
`read_trusted_dir` for its `nosuid` procfs mount, and `/usr/bin/true` is
trusted on the overlay root. CI's coverage command, run the same way in
Docker, measures `mounts.rs`, `trust.rs`, `proc.rs`, and `aido/src/cli.rs` at
100% on Linux; the only gaps in that container are in files this step does
not touch and belong to the container, not the code — `probe.rs`'s sudo
probes (the image has no sudo) and one `PIDFD_GET_INFO` path in `syscall.rs`
(Linux 6.12 lacks the call; CI's kernel has it).

---

## 2026-10-19 — `howiwork.md`: the product source of truth, and the merged vision

A product vision document arrived (permission sets and PRS, `airead`,
vision/blind mode, `pasban`, ido's three outcomes, a distro ambition) and was
merged with the existing design into `howiwork.md`, now the authoritative
statement of product behaviour. README and every diagram derive from it. Four
parts of the vision collided with the invariants and were reconciled rather
than adopted, each recorded in that file's "Mismatches resolved" section — the
load-bearing one: in vision mode an AI may reject, defer, or annotate, never
approve, because a component that can be prompt-injected must not be a
component that can grant root. Engineering rules stay in `CLAUDE.md`.

---

## 2026-10-19 — M2b step 2b: overlapping rules resolve to the strictest

**The hole.** `best_match`, in the front-end, returned the first permitting
action in declaration order. Two actions that accept one command with
different requirements therefore let the sort order of two rule files decide
whether a human is asked; and since a request names its action, a caller could
also just name the permissive one. Nothing executed, so it was a wrong answer
from `explain`, but the broker and the gate were about to inherit it.

**What exists now.**

- **A requirement belongs to the command, not to the name it is asked under.**
  `aido_policy::evaluate` gathers every action that runs the same program,
  byte for byte, and accepts the canonical operands, the named one included.
  If any of them is human-only, an enrolled agent is refused; otherwise the
  confirmation is the strictest any of them demands. Because `evaluate` itself
  does this, the gate, which re-decides the action a spool entry names,
  inherits it with no change of its own, and naming a permissive duplicate
  gains nothing (`an_entry_naming_a_permissive_duplicate_still_needs_the_stricter_confirmation`).
- **`aido_policy::evaluate_command`** asks the same question of a command that
  names no action, and replaces `best_match`, so the front-end no longer
  decides which rule governs a command. **The broker (step 2) and `aido exec`
  (step 3) must call it, or `evaluate` with the named action, and never iterate
  the actions themselves**: a second search is a second chance to get this
  wrong.
- **Strictness is a total order**, ranked by what it takes to lift:
  critical tier, then `confirm = "always"`, then the agent setting, then none
  (`ConfirmReason::strictness`). Two different reasons never tie, so the
  requirement *and its reason* are independent of declaration order; only the
  cited action can differ between equally strict ones.
- **Which action a decision cites:** the one whose requirement it carries.
  Among equals, the action asked for, or, when none was, the first declared.
  The brief said declaration order breaks ties; for a request that names an
  action, the named one wins instead, so a decision only cites something other
  than what was asked when another rule is strictly stricter. Denials still
  cite no action, as before; the trace names every accepting action, and for a
  human-only refusal reached through an overlap it names the rule that
  reserved the command.
- **`RuleSet::overlaps`** (new module `aido-policy::overlap`) lists every pair
  of actions that can accept one command, and `aido check` prints it. Each pair
  of positions is intersected by probing: candidate arguments from both
  matchers, tried through the engine's own `Matcher::accepts`. A shared probe
  is a certain meet. No shared probe is *disjoint* only where an argument
  proves the probes complete — any literal or enumeration, two ranges, a range
  against a name kind or a path, two path prefixes, a path against a name kind
  (`matcher::exhausts`, one argument per arm, and
  `name_kinds_hold_what_overlap_detection_relies_on` pins the three facts about
  name kinds those arguments use). Anything else — a pattern, two name kinds
  that share no representative — is *undecided* and reported as a possible
  overlap. The argument lists are then run as two automata in step, a
  breadth-first search over pairs of states; a pair with more than 2^18 states
  is reported as possible rather than searched. A certain overlap carries a
  witness, re-checked with `match_argv` and in canonical form; a witness that
  is not canonical (it ends in a bare `--`) downgrades to possible.
- **`check` reports overlaps and still exits 0**: the engine resolves them
  safely, and an operator's broad-plus-narrow pair can be deliberate. The
  shipped rules have none, decided exactly (they use no pattern), and
  `the_shipped_rules_overlap_only_where_a_reason_is_written_down` fails on any
  undeclared one; `DELIBERATE_OVERLAPS` beside it is empty and refuses a thin
  or stale entry, the way the GTFOBins waivers do.
- No last-match-wins and no negation. The design plan's line saying otherwise
  now has a deviation entry.

**Standing properties**, in `tests/invariants.rs`, never to be deleted:
`adding_a_rule_never_removes_a_confirmation` (nor lifts a human-only
reservation or a deny-list hit, searched or asked under every name, with the
new rule inserted anywhere in declaration order) and its twin
`rule_order_never_changes_whether_a_confirmation_is_demanded`; with them,
`naming_an_overlapping_action_never_weakens_the_decision`,
`deny_list_always_wins_over_every_overlapping_rule`, and three for the report
having no false negatives. Adversarial examples through real rule files:
`a_later_permissive_duplicate_cannot_weaken_an_earlier_confirming_rule`, its
mirror, `reordering_rule_files_cannot_drop_a_confirmation`,
`naming_the_permissive_duplicate_cannot_skip_the_confirmation`,
`a_permissive_duplicate_cannot_hand_a_human_only_command_to_an_agent`.

**The tests were mutated to prove they bite.** Five mutants, each killed:
first-match citation, human-only checked on the named action only, patterns
called disjoint, the path-beneath-prefix probe removed, and the range floor at
the unparseable `i64::MIN`. Two of them first survived. The adding-a-rule
property appended the new rule at the end, where first-match never lets it
win, so it now inserts anywhere; and the report properties' vocabulary rarely
paired matchers that overlap without sharing a probe, so it gained such
patterns, a single-position property, and a parametric one over awkward range
bounds and path prefixes. The minimal counterexamples are kept in
`invariants.proptest-regressions`, so those regressions fail deterministically.

**Contract snapshots.** No existing decision record or rendering changed: all
24 render snapshots and both contract snapshots are byte-identical. New pinned
surfaces: the two shapes overlaps add (a confirmation decided by a stricter
action than the one named; an agent refused through an overlapping human-only
action), the overlap report, and `check` with overlaps. Three things `explain`
without `--action` now says differently, none pinned before: a refusal lists
every same-program rule's reason, not the first; a command no rule runs gets a
full record naming the program, where the front-end printed an empty one; and
a frozen agent with an empty ruleset reads `frozen`, not `unknown_action`.
`ci/differential/expected/verdicts.txt` is unaffected: every verdict, denial,
and action field is the same.

**Outside the step, needed to run the gate here.**
`a_rule_file_that_is_a_link_a_directory_or_a_socket_is_refused` bound a socket
at a path spelled through `crates/aido-sys/../..`, 128 bytes in a git worktree
against macOS's 104-byte `sun_path`. It now binds the same file by a path
relative to the package directory. Every worktree hits this.

**What review should look at.** The `exhausts` arms, since a wrong `true`
there is an overlap `check` stays silent about. The decision to extend
"strictest" from confirmation to human-only. Whether CI should be able to fail
on overlaps (`check --deny-overlaps`), which is not built.

**Open.**

1. **One program, two names.** The engine compares a rule's program byte for
   byte, so rules for `/bin/systemctl` and `/usr/bin/systemctl` never overlap
   in its terms — yet on merged-`/usr` they are one file, and the caller picks
   the spelling and so the rule. The pure crate cannot see it; `check` or the
   gate could compare `(st_dev, st_ino)` of every rule's program.
2. **`env_allow` is parsed and used nowhere.** When the gate builds a child
   environment from it, overlapping actions must intersect their lists, or a
   caller names the duplicate with the widest one.
3. ~~The gate's `Approved` and its authorization record cite the action the
   entry named.~~ Fixed after review, below.
4. Resolution is per command. A broad rule still grants commands a narrow one
   never accepts — removing `gcc make` together, when the narrow rule accepts
   one package (`the_strictest_rule_binds_the_commands_it_accepts_and_no_others`).
   That is what an allowlist is; the overlap report is how an operator finds it.
5. A pattern against a pattern is always *possible*. Exact would need
   automaton intersection; not worth it until a shipped rule uses a pattern.
6. ~~`CLAUDE.md`'s list of standing invariants should name the new one.~~
   Added at the merge, with its order twin.
7. Seen, not changed: a denial after the program check (`argv_rejected`,
   `human_path_only`, `deny_listed`) carries no `resolved_exe`, so its rendered
   command omits the program, against what `Decision::resolved_exe` promises.
   The existing snapshots pin it that way; changing it is a deliberate
   snapshot change of its own.

**What review found** (an independent pass over the recovered branch, both
reproduced before fixing):

- **A critical rule could lose its critical rank.** The engine asked "does the
  rule say `always`?" before "is it critical?", so a critical action that also
  said `always` reported an ordinary rule requirement, tied with an ordinary
  always-confirming duplicate, and was cited in its place. Confirmation was
  still demanded, but with the wrong reason and the wrong rule. The tier is now
  checked first. `a_critical_rule_outranks_an_ordinary_always_rule_whatever_its_own_confirm_says`
  covers critical with and without `always`, four declaration orders, both
  callers, searched and named — including naming the duplicate that never asks
  — and fails on the old order.
- **The gate's record cited the permissive rule.** `Approved` took its action
  and provenance from the entry's named action, so an authorization that a
  stricter rule's confirmation had made necessary was recorded against the
  rule that asks for nothing. `Approved` now carries the governing action (the
  one the decision cites) and the requested one; the authorization record cites
  the governing rule and records the requested one as evidence when they
  differ.

Accepted as a deliberate deviation from the brief: on equal strictness a named
request keeps the action it named, rather than the earliest in declaration
order. It changes which rule is cited, never what is demanded.

---

## 2026-10-19 — M2b step 1: `aido-sys-raw`, and what review found

The workspace's only `unsafe`: four system calls, five blocks (a fifth call and sixth block, `SO_PEERCRED`, followed the same day; see the entry at the end of this file), in a crate of
their own, reached through a `Syscalls` trait in `aido-sys` with a real
implementation and a scripted fake.

| Call | Purpose | Kernel |
|---|---|---|
| `close_range(first, ~0, CLOSE_RANGE_CLOEXEC)` | the gate's first act | 5.11 |
| `getsockopt(SO_PEERPIDFD)` | which process is on the other end of the broker's socket | 6.5 |
| `ioctl(PIDFD_GET_INFO)` | that process's ids, credentials, and cgroup in one call | 6.13 |
| `execveat(fd, "", AT_EMPTY_PATH)` | exec the descriptor that was validated | 3.19 |

The first version put these in a module, `aido-sys::raw`, lowered the whole of
`aido-sys` from `forbid` to `deny` to allow it, and guarded the rest with a
test that matched substrings. A five-lens adversarial review (FFI soundness,
kernel facts against kernel source, enforcement bypass, test adequacy, fit for
steps 2 and 4) took it apart, and every finding below was checked against
kernel source or by mutation before it was acted on. The review's own verifier
stage failed on infrastructure errors, so nothing here rests on its votes.

**The enforcement was beatable five ways.** `unsafe{`, `#[expect(unsafe_code)]`,
`#[allow(dead_code, unsafe_code)]`, `#[unsafe(no_mangle)]`, and two blocks on
one line all passed, as did `unsafe` in `aido-sys/tests/` and in a `build.rs`,
which inherited the liftable `deny`. Each was proven with a compiling PoC.
Now: the calls live in the crate `aido-sys-raw`, `aido-sys` forbids `unsafe`
again, and the compiler confines it. The test that remains,
`aido-sys-raw/tests/unsafe_budget.rs`, is the backstop: it lexes every Rust file
of every workspace member plus `fuzz/` — comments, raw strings, byte and C
strings, and character literals understood, so text cannot hide code and code
cannot hide behind text — and fails on any `unsafe` token or lift of
`unsafe_code` outside `sys.rs`, on `include!` or `#[path]`, on a block count
other than the published budget, and on any crate but `aido-sys` depending on
`aido-sys-raw`. The four PoCs that beat the old test all fail the new one.

**Five gaps in the tests, each proven by a surviving mutant:** a `close_range`
that ignored its floor, or stopped at it; an exec of the working directory
instead of the descriptor; a pidfd with close-on-exec cleared; and a pidfd for
the wrong process. The peer tests used a socketpair, whose "peer" is always the
test process itself, so they could not tell a right answer from a wrong one.
Now the floor test checks below, at, above, and far above; the exec tests
expect `ENOEXEC` and `ENOENT` that only the handed descriptor can produce; and
the peer tests connect a separate process. All five mutants are killed.

**Kernel facts that were wrong or missing**, all now documented on the trait
where step 2 will read them, and the version-dependent ones pinned by tests that
predict the answer from the version without a branch:

- A pidfd pins the process, **not its pid number**: the number is released at
  reap and can be reissued while the pidfd is held. Every rung that reads
  `/proc/<pid>` by number must re-check through the pidfd afterwards; the ladder
  said only the `pidfd_open` rung needed to.
- `PIDFD_GET_INFO` reports credentials and cgroup **at the moment of the
  call**. A peer that connects and then execs a set-user-ID program reports that
  program's ids. Connect-time identity comes from `SO_PEERCRED`, on every rung.
- The **5.3 `pidfd_open` rung cannot bind its pin to the connection**:
  `SO_PEERCRED` reports the connector's pid number even after the connector is
  reaped and the number reissued, and nothing else is left to compare. So it no
  longer carries the agent path; passwordless operation needs 6.5. A re-check
  through `sock_diag` that finds the socket in the pinned process could restore
  it, and is M4's to build or not. The human path is unaffected.
- A missing `PIDFD_GET_INFO` answers `ENOTTY` before 6.11 and **`EINVAL` on 6.11
  and 6.12** (found on the first Linux run). RHEL 9 and 10 carry the call below
  6.13, so the broker should ask the kernel once rather than trust the version.
- `SO_PEERPIDFD` on a reaped peer is `EINVAL` before 6.16; **from 6.16 it hands
  out a pidfd for the dead process**, and `PIDFD_GET_INFO` on it answers `ESRCH`.
- From 6.12 the `PIDFD_GET_INFO` request number is also `NS_MNT_GET_NEXT` to a
  mount-namespace descriptor, which answers success and, with `CAP_SYS_ADMIN`,
  installs a new descriptor. `HostSyscalls::pidfd_info` now refuses anything not
  on pidfs before the ioctl is sent.
- `PIDFD_INFO_CGROUPID` is reported whether or not the unified hierarchy is
  mounted; its presence says nothing about whether a host can attest.

**Results that must never read as root.** A call reported successful that never
ran — a syscall filter returning 0 — left the request record, every requested
bit set and every field zero, to be read as root's credentials, and left `-1` in
`SO_PEERPIDFD`'s output for `OwnedFd` to panic on. `PidfdInfo::is_answer` refuses
the first in the real and the fake implementation alike, and `peer_pidfd`
refuses the second without adopting it.

**The CI runners are on 6.17**, not older than Docker's 6.12 as first written.
So every CI run executes the `PIDFD_GET_INFO` success path and the 6.16 stale
pidfd path, and the success test checks every field — ids, all eight
credentials, and the cgroup id against the inode of this process's cgroup — so
a field declared out of order fails there. Each field's offset is also asserted
against libc's `pidfd_info` at compile time.

**The harness was testing the wrong code.** `just linux-test` copies each
checkout to the same `/work` and shares one target volume, and cargo judges
freshness by mtime: a worktree with older files than the last build from another
tree ran that other tree's code. Found when an unmutated tree failed with a
mutant's symptoms. The copy is now extracted with fresh mtimes.

Decisions worth knowing before building on it:

- **`close_range` marks, it does not close.** A safe wrapper around a real close
  would be unsound: it can close a descriptor an `OwnedFd` still holds. Marked
  descriptors close at the next exec; sudo and doas already `closefrom(3)`
  before the gate runs.
- **Open for step 4: the gate's process model.** Exec in place gives faithful
  exit status for free and leaves no root parent holding inherited
  descriptors, but no outcome to record afterwards; fork and wait needs `fork`,
  which has no safe API and would be a sixth block. Also open: a kernel before
  5.11 refuses `CLOSE_RANGE_CLOEXEC`; whether the gate refuses there or marks
  descriptors one by one (another block) is the gate's call. And the gate's
  exec vector should be built from the canonical argv bytes, not from
  `Decision::resolved_argv`, which comes from a display renderer.
- **Open for step 2:** `SO_PEERCRED`, `pidfd_open`, and the liveness check are
  safe in rustix and need a seam of their own; this trait stays the list of
  calls that need `unsafe`. Socket activation with `Accept=yes` and
  `StandardInput=socket` puts the connection on fd 0, reachable safely, with no
  `LISTEN_FDS` to parse.

Measured: 100% on macOS (`just verify`); the whole suite passes on Linux 6.12 in
Docker as uid 1000 on fresh builds; `aido-sys-raw` compiles for 64-bit Linux
only, and says so in words on anything else.

---

## 2026-10-16 — One generation for every reader, and a reachable broker socket

Two things found while reading for M2b step 2, fixed before the broker is
built so that the broker and the gate are written against them rather than
around them.

**Three readers, three chances to disagree.** The front-end computed the
policy generation itself, in `crates/aido/src/rules.rs`; nothing else did. The
broker is about to write a generation into every spool entry and the gate to
refuse an entry whose generation is not current, so each of them would have
grown its own copy of the hash and its own idea of which directory entries are
rule files. Two copies that drift make every request look stale, or worse,
make two different rulesets look like one. Now there is one function,
`aido_policy::load_rule_files`, pure, which takes the files as read and owns
the selection predicate (`is_rule_file_name`: `<name>.toml`, so a bare `.toml`
is no longer a rule file to the descriptor-verified reader either), the order
(byte order of names), the UTF-8 refusals, and the hash. The front-end reads
by path and calls it; `aido_sys::load_trusted_rules` reads through verified
descriptors and calls it. The broker and the gate use the second and compare
`Generation::id()`, the first eight bytes of the digest.

**The old hash could not tell two rulesets apart.** It fed each file's name
and contents to SHA-256 back to back, so `1.toml` holding `#a2.toml#b` hashed
the same as `1.toml` holding `#a` beside `2.toml` holding `#b`. Only root can
write the rules, so this was not an attack, but it was a generation check that
could pass across a real policy change. The new hash is domain-separated
(`aido.ruleset.generation.v1`) and length-prefixes every field.
`two_rulesets_that_concatenate_alike_have_different_generations` pins it, a
digest of a fixed ruleset is asserted exactly, and
`the_generation_depends_on_the_files_not_on_their_read_order` joins the
standing properties. The front-end's printed generation changes value once;
nothing persisted the old one.

**The socket was unreachable as designed.** The design plan's file table put
`broker.sock` in a `0700` `/run/aido`, a directory no user can traverse, so no
user could ever have connected. Now `/run/aido` is `0755`, the socket `0660
root:aido` (the same group the sudoers rule names), and `req/` and `sessions/`
are the `0700` directories. The gate's `SPOOL_DIR` already described `req/` as
root-owned `0700`, so no code changes.

---

## 2026-10-15 — M2b step 0: `just linux-test`

The suite now runs on a real Linux kernel from the Mac in one command, with the
two hazards found on 2026-10-14 designed out rather than remembered:

- **A copy, not the mount.** The checkout is mounted read-only and copied onto
  the container's own filesystem before anything runs, so ownership is real and
  no directory goes missing under parallel tests.
- **Not root.** The copy and the caches are prepared as root, then the suite
  runs as uid 1000 through `setpriv`, and the script refuses to start if that
  user is root, because under root every mode check passes vacuously.

The image is `rust:<channel>-slim` with the channel read from
`rust-toolchain.toml`, so it cannot drift from the pinned toolchain. Registry
and target caches are named volumes: the first run builds everything, a rerun
of one package took 11 seconds. Arguments go straight to `cargo test` as
separate words. First full run: every test in the workspace passed on Linux
6.12 aarch64 as uid 1000, including the `ido` pseudo-terminal test.

It is not part of `just verify`, because `verify` must run on a machine without
Docker and CI already runs the suite natively on two Linux architectures. It is
the required local check for syscall code, and `CLAUDE.md`'s gate table says so.

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

---

## 2026-10-19 — the sixth `unsafe` block: `SO_PEERCRED`

**Decided by the user.** `aido-sys-raw` gains `getsockopt(SO_PEERCRED)` as its fifth call and sixth block, and the published budget in `sys.rs` goes from 5 to 6 in the same commit.

**Why.** rustix 1.1.x decodes `SO_PEERCRED` with `assume_init` into a `UCred` whose `pid` is a `Pid(NonZeroI32)`. The kernel reports pid 0 for a datagram socket and for a peer outside the caller's pid namespace, so a safe rustix call is undefined behaviour on an answer the broker can be handed (verified against rustix 1.1.4 and 1.1.5 source in an earlier review). A broker that decodes a hostile peer's credentials must not have UB on the answer "nobody". The new call reads into a `#[repr(C)]` `PeerCred { pid: i32, uid: u32, gid: u32 }` (size and offsets asserted against `libc::ucred`, length checked after the call, a record the kernel never wrote refused), so zero is a value, not a trap. It is exposed as `Syscalls::peer_cred`; it does not decide what pid 0 means, which is the broker's call (step 2 switches to it). **Switched 2026-10-21:** the broker reads `SO_PEERCRED` only through it and refuses pid 0 as `PeerNotVisible`; rustix's `socket_peercred` is called nowhere, and is banned in `clippy.toml` and by a scan of every Rust file. See open item 8 of the M2b step 2 entry.

**Tests.** `a_peer_cred_pid_of_zero_is_reported_as_zero_never_a_panic`, `a_peer_cred_is_refused_on_something_that_is_not_a_socket`, `a_peer_cred_is_refused_on_a_directory_and_on_a_device`, and a fake-driven pid-0 test on every platform. Measured on a 6.12 kernel: a datagram socket is not refused, it answers success with pid 0 and uid and gid `u32::MAX`, which is the real-kernel pid-0 case the test pins; only a non-socket is an errno (`ENOTSOCK`).
