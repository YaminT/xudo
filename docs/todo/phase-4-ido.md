# Phase 4 — `ido`, the buffered human-run command queue

An agent queues the commands it cannot or should not run. The human runs `ido`, sees the queue in a full-screen picker, chooses what to run, and runs it in their own terminal.

---

## 1. Why this is a better trust story than `aido`, not a weaker one

`aido` fights a hard problem: the agent is the parent process, so it owns `aido`'s stdin, stdout, and pty, and a confirmation read from any of them is a confirmation the agent can answer. That is why `aido` needs a root broker, an out-of-band channel, cgroup attestation, and a reaction-time floor.

`ido` sidesteps all of it. The human is already the one running the program, in their own shell, on their own terminal. There is no impersonation to detect because nothing executes without a keystroke from a person who went looking for the queue. **`ido` needs no root, no cgroups, no broker, and no policy engine**, which is why the sequencing note in `README.md` recommends building it before the passwordless path.

The division of labour:

| | `aido` | `ido` |
|---|---|---|
| Who executes | The agent, under root-owned policy | The human, after selecting |
| Gates on | **Privilege** — does this need uid 0 | **Consequence** — how bad is this if wrong |
| Needs root | Yes | No |
| Failure mode | A policy hole becomes a root exploit | A queued command sits unrun |

### Consequence, not uid

The brief's example is the point: `gcloud` and `aws` with write permissions need no root at all, yet they hold long-lived cloud credentials and can delete production. `sudo` cannot help, because there is no privilege boundary to cross — the user's own credentials are already sufficient. So `ido`'s scope is *anything the human should personally decide*, and uid is not the criterion.

Worth surfacing in the UI for exactly these commands: the **resolved account, project, profile, and region** a cloud command would use. `aws s3 rm --recursive` against `--profile dev` and `--profile prod` are the same command and different events, and the profile is often implicit in the environment rather than in the argv.

---

## 2. Command surface — and the name collision to resolve first

> **DECIDED 2026-08-28.** `ido add` writes the `AGENTS.md` block; `ido queue`
> buffers a command. The surface below is now the specification, not a proposal.

**The brief specifies `ido add` twice.** It is the natural name for "add a command to the buffer", and it is explicitly specified as the command that writes instructions into `AGENTS.md`. One has to move.

Recommendation: keep `ido add` for the documentation action exactly as specified, because that is the one a human types once and needs to remember, and give the agent-facing verb its own name.

```
ido                                  Open the picker (the default, no subcommand).

ido queue -- <argv>...               Buffer a command. The agent-facing verb.
  -m, --reason <text>                Why. Shown to the human. Untrusted text.
  --group <name>                     Group with other commands.
  --step <n>                         Order within the group; enforces one-by-one.
  --needs <id>                       Depend on a specific queued entry.
  --cwd <path>                        Working directory to run in.
  --dry-run-of <argv>...             A no-side-effect preview to show at selection time.

ido add [path]                       Write the agent instructions into AGENTS.md.
                                     Bare: ./AGENTS.md. With a path: that file.
                                     Also accepts CLAUDE.md, GEMINI.md, and others.

ido list [--json]                    Print the queue without a TUI. For scripts and CI.
ido run <id>... | --group <name>      Run without the TUI. Requires --yes to be
                                     non-interactive, and refuses --yes on a tty.
ido drop <id>... | --all             Discard entries.
ido log [-n N]                        What was run, when, and what it exited with.
ido celebrate                        See § 7.
```

`ido queue` never blocks and never waits for the human. It prints the entry id and exits 0, so an agent's tool call completes immediately.

---

## 3. The queue file

### Location

Recommend `$XDG_STATE_HOME/ido/queue.jsonl` (default `~/.local/state/ido/queue.jsonl`), **not** `$XDG_RUNTIME_DIR`. The brief says "temp file", but a queue that vanishes on logout loses exactly the work the human meant to come back to. Directory `0700`, file `0600`, created `O_EXCL`, append-only JSONL with a monotonic id per line. Retention: entries older than a configurable window (default 7 days) are marked stale and shown greyed rather than deleted, and `ido drop --stale` clears them.

One queue per user. No shared queue, ever — a shared queue is a way for one user to get another user to run their command.

### Every field in it is untrusted input

This is the security core of phase 4, and it is the same lesson as `aido`'s confirmation prompt.

The agent writes this file. The human reads it in a terminal and then executes what it says. So the command, the reason, the cwd, and the group name are all **attacker-controlled text destined for a terminal and then for execution.** Concretely required:

- **Strip ANSI/C0/C1 escape sequences** before rendering. Otherwise a queued "reason" can redraw the screen, hide a line, or fake a prompt.
- **Strip bidirectional overrides** (U+202A–202E, U+2066–2069). These reorder displayed text without changing bytes, so the human reads one command and executes another. This is the Trojan Source class and it is directly applicable here.
- **Flag confusable and homoglyph characters** in the command path — a Cyrillic `а` in `аws` is a different binary.
- **Clamp width and line count** per field, so one entry cannot push the rest of the queue off screen.
- **Render the argv as a quoted vector**, not as a reconstructed shell string, so the human sees exactly the tokens that will be passed.

### Store argv, never a shell string

`ido queue -- <argv>` takes a real argument vector and stores it as a vector. `ido` execs it directly with no shell involved, which makes the entire quoting-and-injection class unreachable — the same reason `aido` bans `shlex::split` and resolves executables absolutely.

An agent that needs a pipeline must queue a **script file** it has written, so the human can read the script before running it. A one-line convenience that accepts a shell string is the obvious request and should be refused; if it is ever added, it must be a distinct entry kind, rendered with a visibly different marker, and the docs must say a shell will interpret it.

---

## 4. Grouping and dependencies

Two shapes, both needed by the brief.

**Independent entries** — the default. Any order, any subset.

**A group with steps** — `--group deploy --step 1|2|3`. The UX has to make one-by-one unmistakable rather than merely possible:

- Steps render as an indented, numbered block under the group name, not as flat list items.
- Step *n+1* shows as **blocked** with the literal reason — `blocked: step 1 has not run` — and cannot be selected until step *n* has exited 0.
- If a step exits non-zero, the rest of the group moves to **halted**, and the human has to explicitly choose *retry step n* or *unblock and continue*, with the latter labelled as overriding a dependency.
- Running the whole group is one action: `Run all 3 in order, stopping on the first failure`. The stopping rule is in the label, not in the manual.

`--needs <id>` handles a cross-group dependency and forms a DAG. Reject a cycle at queue time with a clear error rather than at run time.

---

## 5. The picker

Model the interaction on `claude --resume`: a full-screen list, newest first, keyboard-driven, with a preview of the highlighted entry.

Build with `ratatui` + `crossterm`.

```
┌─ ido ─ 4 queued ─────────────────────────────────────────────────────┐
│                                                                      │
│   ▸ ▣ apt-get install -y ripgrep                          2 min ago │
│       needs sudo · claude-code · "install ripgrep for search"        │
│                                                                      │
│     ▢ deploy                                          3 groups ─ 12m │
│        1. terraform plan -out=tf.plan                     ready      │
│        2. terraform apply tf.plan            blocked: step 1 not run  │
│                                                                      │
│     ▢ aws s3 sync ./dist s3://assets-prod                  14 min ago │
│       no sudo · profile=prod · region=eu-west-1 · ⚠ writes prod      │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│ ↑↓ move · space select · enter run · d drop · p preview · q quit      │
└──────────────────────────────────────────────────────────────────────┘
```

Per-entry, the list shows: the argv, whether it needs sudo, who queued it and in which session, when, the agent's reason, group and dependency state, and — for cloud CLIs — the resolved profile/project/region.

The preview pane shows the full argv one token per line, the cwd, the exact environment the child will get, and the cached output of any `--dry-run-of` command.

Non-negotiables:

- **Nothing runs on a single keystroke by accident.** Enter runs the *selected* set; with more than one selected, or with anything marked high-consequence, require a typed confirmation rather than a keypress.
- **Respect `NO_COLOR`**, and detect a non-tty: `ido` with no tty must not attempt a TUI, it must behave as `ido list`.
- Every rendered field passes through the sanitizer from § 3.
- Output of a run streams to the terminal live, and the exit status is recorded.

---

## 6. `ido add` — writing the agent instructions

`ido add` writes a block into `AGENTS.md` in the current directory. `ido add ./path/to/AGENTS.md` writes to that file. `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and `.github/copilot-instructions.md` are recognised by filename and get the same block.

Mechanics that matter:

- **Sentinel markers** so a second run updates rather than duplicates:
  `<!-- ido:begin v1 -->` … `<!-- ido:end -->`.
- **Never clobber.** Read the file, splice between sentinels, write to a temp file in the same directory, `fsync`, `rename`. If no sentinels exist, append. Back up to `<file>.ido-backup` on first modification.
- **Refuse to write outside the current tree** without an explicit absolute path, so a stray `ido add` cannot rewrite a home-directory config.
- Package install prints how to run it; it does **not** run it. Writing into a user's project files at install time is not the package manager's business.

### The block itself

The brief asks for "simple strict and short English", which is the right instinct: this text is parsed by a model, and hedging produces exactly the ambiguity that gets misread. Short imperative sentences, one instruction per line, no adverbs, no alternatives offered.

Draft:

```markdown
<!-- ido:begin v1 -->
## Privileged and high-consequence commands

Do not run commands that need sudo. Do not run cloud CLI commands that write.

Queue them for the user instead:

    ido queue -m "<why>" -- <command> <args>

Example:

    ido queue -m "install ripgrep for code search" -- apt-get install -y ripgrep

The user runs `ido` later and picks what to run. Do not wait for it. Do not ask
the user to run the command by hand.

If two commands must run in order, put them in one group:

    ido queue --group deploy --step 1 -- terraform plan -out=tf.plan
    ido queue --group deploy --step 2 -- terraform apply tf.plan

Rules:
- Queue one command per call.
- Write a real argument list after `--`. Do not write a shell string.
- Do not queue the same command twice.
- Say what you queued. Then say: "Run `ido` to execute it."
<!-- ido:end -->
```

Keep the block under 30 lines. A long block gets summarised away by the harness.

---

## 7. The `willyoumarryme` acceptance test

From the brief: the agent queues `willyoumarryme`; when the user runs `ido`, a small CLI celebration plays and says `ido works.`

### Shape

Ship the celebration as `ido celebrate`, and install `willyoumarryme` as a **second name for the same inode** — the same hardlink-with-two-names trick `aido-gate` uses, so there is one binary and one code path. The literal string from the brief then works as a queued command, and there is no separate script to keep in sync.

The celebration has **no people in it**: no names, no couple, no pronouns, no figures. Abstract only — confetti glyphs, rings, a bell, colour. It ends by printing exactly:

```
ido works.
```

Honour `NO_COLOR`, skip the animation when stdout is not a tty or `--no-animation` is passed, and finish in well under two seconds. Exit 0.

### The test, end to end

```rust
// tests/willyoumarryme.rs
// The full loop: an agent queues, a human runs, the celebration confirms.

#[test]
fn an_agent_queues_and_the_human_runs_it() {
    let home = TempHome::new();                    // isolated XDG_STATE_HOME

    // 1. The agent queues it and does not block.
    let queued = ido(&home).args(["queue", "-m", "she said yes", "--", "willyoumarryme"]).output();
    assert!(queued.status.success());

    // 2. Exactly one entry is buffered, argv stored as a vector.
    let queue = home.read_queue();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].argv, vec!["willyoumarryme"]);
    assert_eq!(queue[0].state, "ready");

    // 3. The human runs it. --yes only because there is no tty in CI; the
    //    interactive path is covered by the rexpect test below.
    let run = ido(&home).args(["run", "--all", "--yes", "--no-animation"]).output();
    assert!(run.status.success());
    assert!(String::from_utf8_lossy(&run.stdout).contains("ido works."));

    // 4. The queue is now empty and the run is in the log.
    assert!(home.read_queue().is_empty());
    assert!(home.read_log()[0].exit_code == 0);
}
```

Plus, under `rexpect` on a real pty, the interactive path: launch `ido`, assert the entry is listed, send space and Enter, assert `ido works.` appears. That test is what proves the picker actually works, since everything else bypasses it.

Adversarial tests in the same file, because the queue is untrusted input:

| Test | Asserts |
|---|---|
| `ansi_escapes_in_a_reason_cannot_redraw_the_screen` | Escape sequences stripped before render |
| `bidi_overrides_in_a_command_cannot_reorder_the_display` | U+202A–202E and U+2066–2069 stripped; rendered order equals byte order |
| `a_homoglyph_binary_name_is_flagged` | Cyrillic `а` in `аws` marked as confusable |
| `argv_is_never_passed_through_a_shell` | Queue `echo $(id)`; assert the literal string is passed and no substitution happened |
| `a_blocked_step_cannot_be_selected` | Step 2 unselectable until step 1 exits 0 |
| `a_failed_step_halts_its_group` | Step 2 not run after step 1 exits non-zero |
| `a_dependency_cycle_is_refused_at_queue_time` | `--needs` cycle errors on queue, not on run |
| `another_users_queue_is_unreachable` | Queue path is per-user and mode 0600 |
| `no_tty_falls_back_to_list_and_runs_nothing` | `ido` with stdout redirected prints the queue and exits 0 |
| `ido_add_is_idempotent` | Two runs produce one block, not two |
| `ido_add_preserves_surrounding_content` | Text before and after the sentinels is byte-identical |

---

## 8. Integration with `aido`

Two connections worth building, because they make each tool better rather than merely adjacent.

**`aido` denials offer the queue.** When `aido` denies with `HumanPathOnly` or `NoConfirmationChannel`, the remediation string in the decision envelope already tells the agent to hand the action to a person. Make it concrete: `aido` can queue the request into `ido` and return the entry id, so the agent's next message is *"queued as #7, run `ido` to execute"* instead of a dead end. The denial taxonomy already has the codes; this is a renderer change plus one call.

**`ido` can run through `aido`.** A queued entry that needs root can be executed as `aido exec -- <argv>` rather than `sudo <argv>`, so it still gets policy matching, the deny-list, and the audit record — with the human's password prompt, which they are present to answer. The human keeps the decision; the machine keeps the guardrails.

Shared crates: the audit sink (hash-chained JSONL plus journald) and the config layering from phase 5. The terminal-text sanitizer belongs in a shared crate too, since both the `aido` confirmation prompt and the `ido` picker need exactly the same thing.

---

## 9. Packaging note

`ido` is installable by someone who wants nothing to do with `aido` — it needs no root and grants no privilege. That argues for `ido` as its own package with `aido` as a `Suggests:`, and it is one of the open decisions in `README.md`. If they ship as one package, `ido` must still work fully with no sudoers snippet installed and no `aido` group membership.

---

## Deliverables

- `crates/ido` — queue, picker, runner, log.
- `crates/ido-doc` — the `AGENTS.md` splicer with sentinel handling and backups.
- `crates/term-sanitize` — shared ANSI/bidi/homoglyph sanitizer, used by both `ido` and `aido`.
- `ido celebrate` plus the `willyoumarryme` second name.
- The acceptance test, the `rexpect` interactive test, and the adversarial table above.
- Man pages `ido(1)` and `ido-queue(5)`.
- The `AGENTS.md` block, version-stamped so `ido add` can update an older one.
