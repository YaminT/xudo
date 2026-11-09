# M3 — out-of-band confirmation: the plan

Written 2026-11-07 against `phase-3-finish` (`2c62481`). `README.md` in this
directory stays the index; this file is the design, the sequence and the exit
test for M3. When the two disagree, fix this one, it is newer.

Work moves as in `m2b-finish-plan.md`: a developer and an Opus reviewer per
step, then `ci/boof-integrate.sh`. Every fix lands with a test named for the
attack it closes.

**In one paragraph.** A request whose rule demands confirmation becomes a
pending entry in the spool. A human approves or denies it on `xudo watch`, a
terminal the broker has checked is not the requester's. `confirm_human_path`
is off by default and on in the test lanes. `confirmation_timeout_secs`
defaults to 0: `xudo exec` returns at once with a pending answer (exit 18,
NotConfirmed) and the entry stays until a human answers or the entry TTL
passes. A positive timeout makes `exec` wait up to that many seconds. After
approval the agent re-runs the same command; that re-run consumes the
approval once. No live watcher: deny, at once. M3 now, then M4. M3 removes no
password; M4 is where an approval replaces it for an attested agent.

## What "M3 done" means

All true, with Linux evidence. Rows are `design-plan.md` § Verification.

1. The gate and the broker decide with the same settings, read from the same
   root-owned file by one function. *(CONCERNS 2026-10-21, gate open item 8)*
2. With `confirm_human_path` on, a `confirm = "always"` request creates a
   pending entry. Approving it on `xudo watch` lets a later matching re-run
   take the password path. Denying it, or letting the entry TTL pass, runs
   nothing. Timeout 0 (the default): `xudo exec` returns at once with a
   pending envelope, exit 18 (NotConfirmed), and the entry stays pending.
   A positive `confirmation_timeout_secs`: `exec` waits up to that many
   seconds, polling, then returns pending or denied, and never waits longer
   than that bound. *(row 9)*
3. No live watcher: denied `no_confirmation_channel` at once, nothing minted.
4. The requester cannot approve itself through its stdin, its `/dev/tty`, or a
   `xudo watch` started in its own session or on its own terminal. *(row 8, the
   half M3 can prove; see Risks)* The out-of-process-tree guarantee against a
   same-user agent is complete only with M4's cgroup scope. M3 stays safe
   because the password is still required.
5. Every agent-written string on the prompt goes through `term-sanitize`. The
   human types the action's last word (for example `remove`). An answer faster
   than the 2 s floor is refused. Identical requests do not prompt twice and
   back off after a refusal. The line prompt is pinned by `insta` snapshots.
   Approving happens only inside `xudo watch`. `xudo pending` is read-only.
   There is no `xudo approve` or `xudo deny` in M3.
6. A peer in a nested pid namespace or a mapped user namespace is never a
   watcher.
7. `xudo freeze` denies the agent path at the broker and at the gate; `thaw`
   needs root; the human path keeps working. *(row 16; the agent half is
   proven with a faked classification until M4)*
8. `just verify`, `linux-test`, `root-test`, `units`, `systemd-test` green.

## The design, minimal

### Who needs the channel in M3

Today every caller is `Unattested`, takes the `PASSWD` hop, and the password is
the confirmation (decision 6, `README.md`). So without a change nothing would
ever reach `xudo watch`. M3 adds one root setting, `confirm_human_path`
(`/etc/xudo/config.toml`, a bool; turning it on narrows, so a project layer may
turn it on and never off). When it is on, a decision of
`allow_with_confirmation` needs a watch approval **and** the password. The
setting is off by default. The test lanes turn it on. M4 reuses the same
machinery for the `-nopass` path, where the approval is the only confirmation.

### Where pending state lives

In the spool, in the entry the gate already reads. `PendingRequest` has
`confirmed` and `confirmed_by`; it gains `fingerprint`, `caller_sid`,
`caller_tty`, `shown_at_ms`, `needs_watch` (entry schema bump). No daemon: the
broker stays one process per connection (`Accept=yes`, `RuntimeMaxSec=30`),
so state that outlives a connection is a file. One new directory,
`/run/xudo/confirm` (`0700 root`), holds one JSON file per uid: the watcher's
heartbeat and the backoff table. Not `req/`: the gate parses every name there.

### The state machine

```
          mint (needs_watch)                 watcher types the action's last word
 Run ─────────────────────────► PENDING ─────────────────────────► APPROVED
                                   │                                    │
                                   │  watcher answers "deny"            │ matching re-run
                                   ├──────────────────────────► DENIED  │ (same user, same argv,
                                   │  entry TTL passes                 │  within the entry TTL)
                                   └──────────────────────────► EXPIRED └─► consumed once, then gone
```

- PENDING is `confirmed = false`; APPROVED is `confirmed = true` with
  `confirmed_by` (watcher uid, pid, starttime, tty, sid). The approval sits
  until one matching `run` consumes it: same user, same argv, within the
  entry TTL. A different argv or a different user does not match. A second
  match finds nothing. DENIED and EXPIRED are an audit record and no file.
  Nothing leaves DENIED or EXPIRED. The entry TTL is the expiry, not
  `confirmation_timeout_secs`. That setting only bounds how long `xudo exec`
  polls.
- Each transition happens under the spool lock, record first: the approval
  rewrite takes an `Authorized<_>`, like mint. It is a replacing rename,
  refused unless the name still holds the inode just read, so approving a
  consumed entry never recreates it.
- The first broker to see an expired entry records the expiry and the strike.

### Deadlines

- The shared `Clock` seam moves to `CLOCK_BOOTTIME` in ms. `CLOCK_MONOTONIC`
  stops in suspend: a laptop closed overnight would wake with the prompt live.
- PENDING lasts until deny or `minted_at + REQUEST_TTL_SECS`. It does not
  end because `xudo exec` returned.
- `confirmation_timeout_secs` (default 0) is only the `xudo exec` wait. 0
  means do not wait. A positive value is the poll bound in seconds.
- APPROVED lasts until consumed or until `minted_at + REQUEST_TTL_SECS`. The
  gate already refuses a passed deadline. The 120 s password-typing window
  still caps how long a consumed run may sit at the password prompt:
  `min(consumed_at + 120 s, minted_at + REQUEST_TTL_SECS)`.

### Who may watch, and how the broker checks it

The broker decides; `xudo watch` only renders. On every `watch` and `answer`
the broker identifies the peer as today, then requires, from kernel facts:

Session id and terminal do not prove a human is watching: any same-user
process can call `setsid`, open a new pty, and make it the controlling
terminal, giving it a session and terminal different from the requester's.
M3's safety therefore rests on the password (decision 7). Step 7 must
re-read session and terminal on every `watch` and `answer`.

- **A terminal**: `tty_nr` in `/proc/<pid>/stat` non-zero, a pts or vt major.
  Ownership follows: a terminal becomes controlling only when opened
  read-write, and a pts is `0620` owner. No fd passing.
- **Not the requester's**: watcher `sid` ≠ the entry's `caller_sid`, watcher
  `tty_nr` ≠ `caller_tty` (both read at mint), watcher ≠ the requester's pin.
- **Same user**: watcher uid is the entry's caller uid, or 0. It sees and
  answers only those entries.
- **Same namespaces**: the guard below passes.
- **One live watcher per uid**: a second `watch` is refused and told the
  first one's pid and tty, so a squatter is visible.

Live: a heartbeat in the last 3 s from a pid whose starttime still matches.

### The namespace-divergence guard

`identify` reads two world-readable facts: `NSpid` in `/proc/<pid>/status`
(more than one level: nested pid namespace) and `/proc/<pid>/uid_map` (not the
identity map: user namespace). Either marks the peer `diverged`, on every
record. A diverged peer still gets the password path but is never a watcher;
M4 must also never classify one as an agent. The mount namespace needs
`CAP_SYS_PTRACE`, which the broker does not get; it is recorded as unknown.

### The wire (`xudo-wire`, schema 2)

`BrokerRequest` becomes `{ schema_version: 2, question }`:

| Question | Who | Answer |
|---|---|---|
| `run { program, argv, claimed_classification }` | anyone | `decided` as today, or `pending { id, expires_in_ms }` |
| `status { id }` | the requester's own pin only | `pending`, or `decided` (minted on approval, denial otherwise) |
| `watch` | a checked watcher | `watching { prompts }`: the heartbeat and the list |
| `answer { id, token, approve }` | a checked watcher | `done`, or a refusal |
| `freeze { reason }` | any group member | `done` |
| `thaw` | peer uid 0 only | `done` |

Still one question per connection. `id` is the nonce. Appended codes, never
renumbered: `DenialCode::{ConfirmationRefused, ConfirmationExpired,
ConfirmationThrottled}` (exit 18), and `RefusalCode::{ChannelUntrusted,
RequestUnknown, AnswerRejected}`. A v1 request is `request_wrong_schema`. The
fuzz targets cover the new shapes.

### What `xudo exec` sees

`confirmation_timeout_secs` defaults to 0.

- **0.** Do not wait. `exec` returns at once. Stderr is one line (`xudo:
  pending approval on xudo watch, request 3f9a…`). With `--output json` it
  prints a pending envelope. Exit 18 (NotConfirmed). The entry stays pending
  until a human approves or denies it in `xudo watch`, or the entry TTL
  passes. `exec` does not poll and does not read stdin.
- **Positive.** `exec` prints `xudo: waiting for approval on xudo watch,
  request 3f9a…, <n> s` and the same pending envelope, then asks `status`
  every 500 ms. It stops at `n` seconds, or `n + 5 s` if the broker goes
  silent. Approved during the wait: this call consumes the approval and the
  backend and gate run as today, so the pin is still `xudo` and the password
  is still typed. Denied or expired during the wait: the denied envelope,
  exit 18. Still pending when `n` seconds pass: the pending envelope, exit
  18, and the entry stays. Broker silent: exit 19. It reads no input while
  waiting.

After a timeout-0 return, the agent re-runs the same command once a human has
approved. That re-run consumes the approval. Same user, same argv, within the
entry TTL, one use. A different argv or user does not match, and the approval
is never reused after that one run. A re-run while the entry is still PENDING
is `confirmation_throttled`, not a second prompt.

### Dedup and backoff

`fingerprint = sha256(uid ‖ program ‖ argv)`, length-framed.

- A `run` whose fingerprint already has a PENDING entry is denied
  `confirmation_throttled` ("an identical request is waiting, id …"). No second
  prompt.
- A refusal or an expiry adds a strike: no prompt for that fingerprint for
  30 s × 2^(strikes−1), capped at 15 min. An approval clears it. The table is
  bounded (64 fingerprints per uid, oldest dropped) and lives in the uid's file
  in `/run/xudo/confirm`.
- An approval is consumed by one matching re-run: same user, same argv,
  within the entry TTL. It cannot satisfy a different argv or a different
  user, and it is never reused after that one run. (design-plan suggestion 3
  says "reuses the prior verdict"; reusing an approval would be a replay.)

### The prompt

A line prompt: canonical program and argv, governing action and `file:line`,
classification and evidence, time left, and the word to type. The word is the
action's last word (for example `remove`). Every field goes through
`term_sanitize::display_str` (single line), the program also through
`flag_command_name`; any finding prints a warning above the prompt. `watch`
flushes type-ahead (`tcflush(TCIFLUSH)`) before reading. The word and the 2 s
floor are checked **by the broker**: `shown_at_ms` is set the first time a
`watch` answer carries the entry; an answer before `shown_at_ms + 2 s`, or
with the wrong word, is `answer_rejected` and the entry stays pending. `n`
denies. Approval is typed only inside `xudo watch`. `xudo pending` lists and
answers nothing. `xudo approve` and `xudo deny` are not in M3.

### Freeze and thaw

A file, `/var/lib/xudo/frozen` (reason, uid, time), written by the broker:
`/etc/xudo` is read-only to it, so the config key `frozen` stays the
operator's static switch and the engine's `frozen` is the OR of both. Broker
and gate read the file through the trust walk; one that exists but fails the
walk or the parse means frozen. `freeze` denies every PENDING entry. `thaw` is
accepted only from uid 0, so it is `sudo xudo thaw`, with a password. No
`--session` (M4), no `--for` (a timed thaw is a thaw no human typed).

### Why this holds the invariants

1. Every check is a kernel fact (`SO_PEERCRED`, pidfd, `/proc` stat, `NSpid`,
   `uid_map`); `claimed_classification` and names stay hints.
2. An approval is added to the password, never substituted for it, until M4.
3. The approval is read only on a terminal checked not to be the requester's
   session or tty; `exec` reads no input; no live watcher means deny.

## Steps

One task and one squashed commit each, in order: 1 and 2 are foundations, 3
to 5 are pure or faked, 6 to 9 touch real systems.

### 1. The gate reads the settings; the new key

Done 2026-11-07: the gate and broker share settings parsing and the gate loads the trusted config.

- **Goal.** Close gate open item 8 before anything makes `frozen` or a
  confirmation bite. Move `xudod::policy::settings_from` into `xudo-gate`; the
  broker calls it there. The gate reads `/etc/xudo/config.toml` through the
  trust walk. Add `confirm_human_path` (`xudo-config`, narrows by turning on;
  one `engine::Settings` field). `password_confirms` records the password fact
  unchanged; when this key is on, the gate requires both password and watch
  approval. *Touches* `xudo-config`, `xudo-policy`, `xudo-gate`,
  `xudod::policy`.
- **Exit.** Same bytes, same `Settings` in broker and gate; a broken or
  user-writable config refuses at the gate.
- **Tests.** `shared_loader_handles_absent_and_present_settings` (proptest),
  `gate_refuses_a_config_on_a_user_writable_path`,
  `the_password_alone_does_not_satisfy_a_rule_when_the_watch_is_required`,
  `a_project_layer_cannot_turn_confirm_human_path_off`.
- **Lane.** `just verify`; `just root-test` for the real file.

### 2. Kernel facts: clock, session, terminal, namespaces

- **Goal.** `Clock` on `CLOCK_BOOTTIME` in ms, one seam for broker and gate.
  `ProcStat` exposes `session` and `tty_nr`; `identify` records `sid`, `tty`,
  `diverged`. *Touches* `xudo-sys` (`clock`, `proc`, `peer`),
  `xudod::identify`, `xudo-gate` (`validate`).
- **Exit.** Real readings right on a real pty and with no terminal.
- **Tests.** `a_process_without_a_controlling_terminal_reads_tty_zero`,
  `a_peer_in_a_nested_pid_namespace_is_diverged`,
  `a_peer_with_a_non_identity_uid_map_is_diverged`,
  `an_unreadable_uid_map_is_diverged_not_clean`,
  `a_deadline_is_not_extended_by_suspend` (fake clock),
  `stat_parsing_survives_a_comm_with_parens_and_spaces`.
- **Lane.** `just verify`; `just linux-test` (real `openpty`; `unshare` where
  the container allows it, fixtures where not).
- **Status (2026-11-07):** done.

### 3. Wire schema 2

- **Goal.** The questions, answers and appended codes above. *Touches*
  `xudo-wire`, `xudo-policy` (`DenialCode`), both wire fuzz targets,
  `contract_snapshots.rs`, `render_snapshots.rs`.
- **Exit.** Every new code snapshotted (exhaustive by construction); fuzz
  60 s clean.
- **Tests.** `a_schema_1_request_is_refused_wrong_schema`,
  `an_unknown_question_is_malformed`, `an_answer_without_a_token_is_malformed`,
  `a_status_id_that_is_not_a_nonce_is_malformed`.
- **Lane.** `just verify`, `just fuzz`.
- **Status (2026-11-07):** done. `run` is ported end to end; other questions
  currently receive `request_unknown` until step 5 implements the state machine.

### 4. The state machine, pure

- **Goal.** A `confirm` module in `xudod`: pure functions over (entry,
  watcher facts, now, settings) for each transition, watcher eligibility,
  fingerprint, backoff, the 2 s floor, and the last-word check. Matching a
  later `run` to an APPROVED entry: one use, same user, same argv, within
  the entry TTL. New entry fields and entry schema bump in
  `xudo-gate::request`.
- **Exit.** 100% coverage; the properties hold.
- **Tests.** Properties: `no_transition_leaves_denied_or_expired`,
  `an_approval_never_outlives_the_entry_ttl`,
  `appending_an_argument_changes_the_fingerprint`,
  `take_approval_never_consumes_non_approved_entries`. Attacks:
  `a_watcher_in_the_requesters_session_cannot_approve`,
  `a_watcher_on_the_requesters_tty_cannot_approve`,
  `a_watcher_without_a_terminal_cannot_approve`,
  `a_diverged_watcher_cannot_approve`,
  `another_users_watcher_cannot_see_or_answer`,
  `an_answer_before_the_two_second_floor_is_refused_and_stays_pending`,
  `a_wrong_last_word_is_refused_and_stays_pending`,
  `an_approval_after_the_entry_ttl_is_refused`,
  `an_approval_is_consumed_once_and_cannot_satisfy_a_different_argv_or_user`,
  `an_approval_cannot_match_shorter_reordered_or_empty_argv_or_survive_any_late_time`,
  `an_approval_does_not_survive_a_policy_reload`,
  `an_approval_for_a_different_governing_action_stays_unconsumed`,
  `a_duplicate_request_does_not_prompt_twice`,
  `request_fingerprint_frames_each_boundary_and_identity_field`,
  `a_second_watcher_cannot_answer_immediately_after_their_first_view`,
  `a_watcher_who_did_not_see_the_current_prompt_cannot_answer`, and gate
  attacks `an_approval_without_needs_watch_is_refused`,
  `an_approval_without_a_shown_timestamp_is_refused`,
  `a_pending_entry_cannot_carry_an_approver`,
  `a_shown_timestamp_requires_needs_watch`,
  `a_shown_timestamp_at_or_after_the_deadline_is_refused`,
  `a_watcher_in_the_requesters_session_is_refused`,
  `a_watcher_on_the_requesters_tty_is_refused`,
  `a_zero_tty_watcher_is_refused`, `a_zero_pid_watcher_is_refused`,
  `an_unknown_confirmation_state_is_rejected_by_the_parser`,
  `only_virtual_console_and_pts_terminals_are_watchable`,
  `backoff_doubles_and_caps_at_fifteen_minutes`.
- **Lane.** `just verify`.
- **Status (2026-11-08):** done. `take_approval` binds uid, exact argv, current
  policy generation, governing action, and deadline. Broker and gate share
  `WatcherPin` eligibility and terminal decoding; watcher uid must equal the
  requester uid, and only pts and virtual consoles are accepted. `shown_at_ms`
  is tied to its watcher. Minting respects `confirm_human_path`. The broker
  does not dispatch confirmation questions until step 5.

### 5. The broker serves it

- **Goal.** `serve` dispatches every question. `run` that needs a watch: no
  live watcher → `no_confirmation_channel`; a PENDING duplicate or backoff →
  `confirmation_throttled`; an APPROVED entry for the same user and the same
  argv, still inside the entry TTL, is consumed once and the run continues
  to the password; a different argv or user does not consume it; otherwise
  mint PENDING, record first. `status`,
  `watch`, `answer` per the state machine. `Spool::replace` (replacing rename
  under the lock, inode checked); a `ConfirmDir` on the same walk as
  `SpoolDir`, bounded per uid. *Touches* `xudod::{serve, mint, record}`,
  `xudo-sys::spool`.
- **Exit.** Every refusal reached with fakes; the real spool under
  `linux-test`.
- **Tests.** `no_live_watcher_denies_and_mints_nothing`,
  `a_stale_heartbeat_is_not_a_live_channel`,
  `a_reused_pid_is_not_the_live_watcher`,
  `a_second_watcher_is_refused_and_told_the_first`,
  `status_from_another_process_is_refused`,
  `approving_a_consumed_entry_does_not_recreate_it`,
  `an_approval_the_audit_sink_refuses_is_not_applied`,
  `every_transition_leaves_one_record`,
  `a_full_confirm_directory_refuses_and_overwrites_nothing`.
- **Lane.** `just verify`, `just linux-test`.
- **Status (2026-11-09):** done. `just verify` passes at 100%; Linux, root, units, and systemd gates pass.

### 6. `xudo exec` returns pending, or waits when asked

- **Goal.** Timeout 0 returns at once with the pending envelope, exit 18
  (NotConfirmed), and leaves the entry pending. A positive
  `confirmation_timeout_secs` runs the bounded poll above, in both
  renderers, then returns pending or denied. A re-run after approval
  consumes that approval once. *Touches* `xudo::{exec, render}`,
  `xudo-bin/tests`.
- **Exit.** Timeout 0 never polls. A positive timeout never waits past
  `n + 5 s`. A matching re-run runs today's plan through the password.
  Denied or expired exits 18. A different argv or user does not consume
  the approval.
- **Tests.** `exec_with_timeout_zero_returns_pending_at_once_and_leaves_the_entry`,
  `exec_never_waits_past_the_configured_timeout`,
  `exec_prints_a_pending_envelope_then_a_denied_one_when_denied_during_the_wait`,
  `a_rerun_consumes_one_approval_for_the_same_user_and_argv`,
  `a_yes_on_stdin_while_pending_changes_nothing`,
  `a_broker_that_goes_silent_while_pending_is_exit_19`,
  `an_approved_status_naming_another_gate_is_refused`; snapshots of the
  pending envelope.
- **Lane.** `just verify`.
- **Status (2026-11-09):** done. Timeout 0 returns a snapshotted pending
  envelope without polling; positive timeouts poll status every 500 ms and
  return pending, denied, or unusable after the documented bounds. A positive
  wait consumes approval with the same run request before handing off to the
  installed gate. The front-end reads `confirmation_timeout_secs` (default 0,
  maximum 600) and never reads confirmation input.

### 7. `xudo watch` and `xudo pending`

- **Goal.** The line prompt. The human types the action's last word. The
  floor is 2 s. `pending` lists with the same checks and answers nothing.
  There is no `approve` or `deny` subcommand. `watch` refuses to start
  without a terminal on stdin. *Touches*
  `xudo::cli`, a small `xudo::watch`, `xudo-bin/tests` (real pty).
- **Exit.** Every prompt string pinned by `insta`; a real pty session approves
  and denies.
- **Tests.** `ansi_in_argv_is_not_rendered`, `bidi_override_in_argv_is_flagged`,
  `a_homoglyph_program_is_flagged`,
  `a_newline_in_argv_cannot_draw_a_second_prompt`,
  `type_ahead_before_the_prompt_is_flushed`,
  `watch_refuses_to_start_without_a_terminal`.
- **Lane.** `just verify`, `just linux-test`.
- **Status (2026-11-09):** done. `watch` heartbeats once per second, flushes
  terminal input before each prompt, and delegates the last-word and 2 s checks
  to the broker. `pending` is read-only and does not require a terminal. Every
  line prompt and message is covered by `insta`; a pseudo-terminal drives both
  approval and denial.

### 8. Freeze and thaw

- **Goal.** As above; the file's `frozen` reaches the engine at both decision
  points. *Touches* `xudod`, `xudo-gate`, `xudo::cli`, `packaging/tmpfiles.d`.
- **Exit.** Row 16 with a faked enrolled classification; the human path runs
  while frozen.
- **Tests.** `thaw_from_a_non_root_peer_is_refused`,
  `an_entry_minted_before_freeze_is_refused_by_the_gate_for_an_agent`,
  `freeze_denies_every_pending_entry`, `an_unreadable_freeze_file_means_frozen`,
  `a_freeze_file_failing_the_trust_walk_means_frozen`,
  `the_human_path_runs_while_frozen`.
- **Lane.** `just verify`, `just root-test`.

### 9. Packaging and the end-to-end proof

- **Goal.** `/run/xudo/confirm` in tmpfiles and `ReadWritePaths`, `units.rs`
  updated, and the acceptance under real systemd with `confirm_human_path =
  true`, one user on two ptys. Measure a `watch` round-trip and record it.
- **Exit.** "M3 done" items 2–4 and 7 on Debian 13, Ubuntu 24.04 and 26.04.
- **Tests.** `approve_then_rerun_then_password_runs_as_root`,
  `deny_runs_nothing_and_exits_18`,
  `timeout_zero_returns_pending_and_the_entry_stays_until_ttl`,
  `a_positive_timeout_returns_pending_or_denied_within_the_bound`,
  `no_watcher_denies_at_once`, `self_approval_from_the_requesters_stdin_fails`,
  `self_approval_through_dev_tty_fails`,
  `watch_started_in_the_requesters_session_is_refused`,
  `watch_in_a_user_namespace_is_refused`.
- **Lane.** `just units`, `just systemd-test`, `just root-test`.

### 10. Closeout

A dated `CONCERNS.md` entry; this directory's `README.md` (status, rows 8, 9,
16); `howiwork.md` "Where the build stands"; one `SECURITY.md` paragraph on
the same-uid limit below.

## Decisions (owner, 2026-11-07)

1. **Channel default: off.** `confirm_human_path` exists. It is off by
   default. The test lanes turn it on.
2. **Timeout: configurable, default 0.** 0 means do not wait. `xudo exec`
   returns at once with a structured pending answer (exit 18, NotConfirmed).
   The request stays pending until a human approves or denies it in
   `xudo watch`, or it expires after the entry TTL. The agent re-runs the
   command after approval. That re-run consumes the approval once: one use,
   same user, same argv, within the TTL. It is never reused. A positive value
   means `xudo exec` waits up to that many seconds, polling as this plan
   describes, then returns pending or denied.
3. **Approve UX.** The human types the action's last word (for example
   `remove`). The reaction floor is 2 s.
4. **`xudo approve|deny <id>`: dropped from M3.** Approving happens only
   inside `xudo watch`. `xudo pending` is read-only.
5. **`watch` UI: line prompt.**
6. **`freeze` / `thaw`: in M3** (step 8).
7. **Order: M3 now, then M4.** The out-of-process-tree guarantee against a
   same-user agent is complete only with M4's cgroup scope. M3 stays safe
   because the password is still required.

## Risks

- **A same-uid agent can run its own watcher**: `setsid` plus a pty gives it
  a new session and terminal, and the M3 checks pass. Before M4 no kernel fact
  separates its tree from the human's. The out-of-process-tree guarantee
  against a same-user agent is complete only with M4's cgroup scope. M3 stays
  safe because the password is still required. M4 closes it: a watcher must
  not be in any live agent scope (cgroup). Row 8 is fully provable only then.
  Order is M3 now, then M4.
- **Polling cost.** The default timeout is 0, so `xudo exec` does not poll.
  A positive timeout does. Each poll starts one sandboxed broker: about 1/s
  per watcher, 2/s per waiting `exec`, inside `MaxConnectionsPerSource=8`.
  Step 9 measures it; a long-poll `watch` is the fallback.
- **Whoever owns the requester's pty draws the password prompt**, and can
  mislabel it or read the password. `watch` shows the real command first; it
  does not stop the reading. Worth a `SECURITY.md` line; not fixed here.
- **Mount namespace unchecked** (no `CAP_SYS_PTRACE`); recorded as unknown.
- **Squatting.** A watcher started first holds the uid's slot; the human's
  `watch` is refused and shown its pid and tty.

## Out of scope

M4: enrollment, cgroup classification, the session TTY captured at
enrollment, `-nopass` and its `NOPASSWD` rule, yolo declarations, the approval
replacing the password. M5: grants, `trust.d`, `--unattended`, rate and
novelty buckets. M6: dry-run previews in the prompt, MCP elicitation. Also
out: `freeze --session|--for`, two-person approval, desktop notifications.
