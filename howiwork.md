# howiwork.md — the source of truth

This file is the authoritative statement of what aido is and how the system
behaves. **Every other description derives from it**: the README, the FigJam
overview, generated agent documentation, and marketing text of any kind. When
any of them disagrees with this file, this file is right and the other document
is the bug. Changes to product behaviour are made *here first*, then propagated.

Division of labour with the other load-bearing documents:

| Document | Owns |
|---|---|
| `howiwork.md` (this file) | What the product is, which components exist, how a request flows, what each mode and outcome means |
| `CLAUDE.md` | Engineering and security rules for writing the code (coverage, banned constructs, test discipline) |
| `docs/design-plan.md` | The detailed architecture and threat model behind this file |
| `docs/CONCERNS.md` | Why decisions were made, dated, newest first |
| `docs/todo/README.md` | Sequencing and current state |

The three invariants below are part of this file. Nothing written here or
anywhere else may weaken them; a future edit to this file that contradicts them
is an error in the edit, not a new truth.

---

## What aido is

aido lives beside `sudo`. Its job is to let AI agents run the privileged
commands a task genuinely needs — in the safest way achievable — while a human
invoking the same commands is always prompted, and everything either of them
does is recorded in a tamper-evident trail.

The long-term shape is a system where aido is part of the installed path of a
machine built for agent work (ultimately a Linux distribution that ships it
preconfigured). The near-term shape is a signed `.deb` an operator installs
beside the escalator they already have (`sudo`, `sudo-rs`, or `doas`).

## The three invariants

1. **Agent detection is not a security boundary.** Authorization comes only
   from kernel-attested facts (`SO_PEERPIDFD` + a root-created cgroup scope
   under `aido.slice`). Environment variables, process names, `/proc` paths,
   and process ancestry are *unauthenticated hints*: recorded in the audit
   trail, never used to authorize.
2. **The agent path is never broader than the human path in authentication.**
   Misclassification may only withhold capability. An unattested caller falls
   through to the human flow with a password — never a silent downgrade to
   passwordless.
3. **Confirmation lives outside the requester's process tree.** A confirmation
   that the requesting process (or anything it controls) can answer is not a
   confirmation. No live out-of-band channel means **deny**.

## The permission model: action X, situation Y, requester Z

A permission answers: *may requester Z perform action X in situation Y?*

- **Action X** — a *named action*: one fixed executable plus an argument list
  constrained position by position with typed matchers. No globs anywhere.
  Actions cover what the invoking user cannot already do: installing packages,
  restarting services, writing under `/var/www`, running `certbot` as root.
- **Situation Y** — the context the decision is made in: the project the
  request is scoped to, global settings (frozen, agent confirmation), whether
  a rule demands human confirmation, rate and novelty limits, and conflicts
  the doctor can see (for the nginx example: Apache already holding port 80 is
  reported, not silently fought). Context can only *narrow* what an action
  grants — a project layer that tries to widen policy is structurally
  rejected.
- **Requester Z** — who is asking, established by the kernel, not by names.
  The broker identifies its peer through the socket (`SO_PEERPIDFD`,
  credentials at connect time via `SO_PEERCRED`) and classifies it:
  *enrolled agent* (its cgroup is a live root-created scope), *human*, or
  *unattested*. "Claude Code requested this" is recorded as a hint for the
  audit record; it never authorizes. Prompt injection and malicious scripts
  are contained by this design rather than detected: whatever a hijacked agent
  claims to be, it can reach only the allowlist, minus the deny-list, through
  the confirmation rules.

### Permission sets

A **permission set** groups named actions into something an admin can reason
about — e.g. *web admin*: install from the web-server list (nginx, apache),
write under `/var/www`, run `certbot` as root. **Predefined permission sets
(PRS)** are shipped, reviewed sets the operator selects or imports.

The engine's native, tested format is TOML under root-owned
`/etc/aido/rules.d/` (this is what ships today). YAML and JSON are accepted as
*import formats* for permission sets: converted to the native rules, shown to
the operator as a capability-level diff, and installed only after review.
Every shipped set is tested as code and checked against the GTFOBins gate —
a set that allowlists something shell-capable needs a written waiver naming
why the rule makes the technique unreachable.

## The components

| Component | Privilege | Role |
|---|---|---|
| `aido` | user | The front-end agents and humans call. Explains, checks, asks the broker. Decides nothing. |
| `aidod` | root | The authority. Identifies the peer, classifies, evaluates policy, mints one-use requests, owns confirmation. |
| `aido-gate` | root (via sudo/doas) | The executor, and a **second independent policy engine**: re-decides from root-owned state, consumes the one-use nonce, execs the validated descriptor. Safe to invoke directly because it trusts nothing it is handed. |
| `sudo` / `doas` (the hop) | root | The machine's own escalator, used only as the **uid transition**: aido ships no setuid bit anywhere. Two rules point at two hardlinks of the gate: `aido-gate-nopass` (`NOPASSWD`, the approved agent path) and `aido-gate-auth` (`PASSWD`, the human path). The password lives on the second and only the second. |
| `ido` | user | The buffered human-run queue (below). Where the human's password is entered. |
| `airead` | user | The read-only surface (below). |
| `pasban` | root (scheduled) | The watchman (below). |

## The three outcomes

Every request resolves to exactly one of:

1. **Rejected** — the deny-list matched, no rule accepts the command, the
   context forbids it, or a required confirmation has no live channel. Every
   error path lands here: aido fails closed.
2. **Approved** — an enrolled agent, attested by the kernel, asks for
   something a rule accepts, and every requirement is met, including whatever
   out-of-band confirmation the strictest matching rule demands. **An approved
   request needs no human password: the approval is the authorization.** It
   runs through the `NOPASSWD` hop. A caller the kernel cannot attest is never
   approved this way (invariant 2): it takes the human path below.
   *Not built yet:* the passwordless hop and enrollment are M4. The beta ships
   only the `PASSWD` hop, so today nothing runs without a password.
3. **Run with ido** — aido cannot or should not run it now, so it is handed to
   a human as reviewable work instead of being silently dropped. **This is
   where the human password lives**: the human runs the entry, and the
   privileged step goes through the `PASSWD` hop, which asks for it once.

A human who runs `aido` directly is on the same human path: always prompted,
because a human is exactly what the kernel cannot attest as an enrolled agent.

When several rules accept the same command, the **strictest requirement wins**
— file order can never decide whether a human is asked.

### ido

`ido` keeps a queue of commands an agent wanted but could not run. Each entry
stores the exact argv (never re-parsed through a shell), the agent's stated
reason, and an identifier; `ido {id}` runs one entry, `ido` opens the picker.
The admin is told when unfinished tasks exist.

Running an entry is a *human* act: it executes with the human's own authority,
and anything privileged goes through aido's human path, where the `PASSWD` hop
(`aido-gate-auth`) prompts for the password once. ido itself holds no privilege and never will —
"running ido is equivalent to sudo" is achieved by routing through the same
gate as everything else, not by making ido a second sudo. Every rendered field
of an entry is sanitized for the terminal (agent text cannot forge the UI), and
every run lands in the audit chain.

### airead

`airead` is aido's read-only twin: the same engine, the same attestation, the
same audit trail, but it can only ever grant actions whose capability class is
*reads* — no file writes, no database writes, no cloud-CLI mutations, no
network egress that changes state. The separation is structural, not
cosmetic: read-only-ness is decided by the action's declared capability class
and the compiled-in deny-list (which classifies by what a binary *can do*,
never by its name), so a write cannot be disguised as a read by renaming or
copying a binary. A rule whose action could write is simply not expressible in
airead's rule set.

### Vision mode and blind mode

**Blind mode is the authorization engine and it is always on.** Strictly
defined rules, compiled-in deny-list, fail closed; only known actions pass.
This is not a degraded state — it is the only thing that ever authorizes.

**Vision mode** adds AI assistance on top, using a configured provider
(Anthropic-, OpenAI-, or Gemini-compatible, by key or subscription). Where no
strict rule decides, a model may: explain a denial, triage a request into the
ido queue with a drafted script and rationale, flag a suspicious context, or
propose a new rule *for the operator to review*. A model's output can reject,
defer, or annotate — **it can never approve**. That is the merge of the
original idea with invariant 2: an AI decision may only withhold capability,
because a component that can be prompt-injected must not be a component that
can grant root.

When the provider is unreachable or the quota is exhausted, the operator's
configured fallback applies: continue in blind mode (default), queue
everything unmatched to ido, or reject everything unmatched. There is no
configuration in which the absence of AI widens what passes.

### Pasban

Pasban is the watchman: a root-owned scheduled job (daily by default, period
operator-configurable) that

- **revokes** every temporarily-gained permission past its expiry — time-boxed
  grants die on schedule even if nothing else runs;
- **verifies** the audit trail end to end and **escalates** suspicious
  patterns found in it;
- treats any third-party write, truncation, or deletion of the security log as
  an **immediate threat** and reports it loudly.

The security log is the hash-chained audit trail: root-owned, mode 0600,
append-only in practice and tamper-evident by construction. aido (broker and
gate) writes it and can read it; pasban reads and verifies it; nothing else has
access. "Hard written" is implemented as a hash chain — every record seals the
one before it — plus the journald copy, so a modification cannot be hidden
even from an attacker who gains the file: the chain stops verifying, and
pasban's next run reports exactly where.

## How a request flows

```
enrolled agent ── aido ──► aidod (root broker)
                             ├ who is asking? (kernel-attested)
                             ├ which rules accept it? strictest wins
                             ├ deny-list (compiled in, non-overridable)
                             ├ confirmation needed? channel live? (else deny)
                             └ outcome: Reject │ Approve │ ido-queue

  Approve ─► mint one-use record ─► sudo/doas, NOPASSWD ─► aido-gate-nopass
                                    (uid transition only,       │
                                     no password)               │
  Run with ido ─► human reviews, runs entry ─► aido (human path)│
                  ─► sudo/doas, PASSWD ─────► aido-gate-auth    │
                  (the human types the password here)           │
                                                                ▼
                                        aido-gate (root, the same binary)
                                          ├ re-decides from root-owned state
                                          ├ consumes the nonce (one use, ever)
                                          └ execs the validated file descriptor
                                              └ audit record before and after
```

Why the hop exists at all when approval needs no password: it is the only
place a uid transition happens, because aido has no setuid bit. It also gives
the gate a real pty (`use_pty`, the TIOCSTI defence), faithful exit status, and
the operator's existing sudo/doas logging. Take it away and the choice is a
setuid binary, which this project refuses, or having the root daemon execute
commands itself, which makes the broker, the parser, and the executor one
process. Two hardlinks keep the password rule and the passwordless rule from
ever naming the same command: `NOPASSWD` attaches only to the agent-path name.

## Mismatches resolved (pasted vision → merged truth)

Recorded so the reconciliation is visible, not silent:

1. *"Check if Claude Code is added as an actor"* → actor identity is
   kernel-attested (invariant 1). The actor's *name* is an audited hint. The
   registry of enrolled agents is an availability control, not a boundary.
2. *"AI takes decisions where no strict rule is defined"* → AI may reject,
   defer to ido, or annotate — never approve (invariants 2 and 3). Blind mode
   is the engine, not a fallback.
3. *"Running ido is equivalent of sudo without sudo"* → ido stays
   unprivileged; privileged entries run through aido's human path with its
   password prompt. Same user experience, no second privilege boundary.
4. *"Permission sets in YAML and JSON"* → native engine format stays TOML
   (tested, shipped); YAML/JSON are import formats converted and reviewed
   before install.
5. *"If something is approved, no human password is needed"* → true for an
   approved, attested agent request, which takes the `NOPASSWD` hop. The
   password moved next to ido: it belongs to the human path (the human running
   an ido entry, or running `aido` directly), because an unattested caller,
   including a human, is never silently downgraded to passwordless
   (invariant 2). The `sudo`/`doas` hop itself stays: it is the uid transition,
   not the password mechanism.
6. *"airead as a separate app"* → same engine, structurally restricted to
   read-class capabilities, so the read/write separation cannot drift between
   two codebases.

## Derived views

Everything below is generated from this file and must never be edited as if it
were the source:

| View | Where | How it stays true |
|---|---|---|
| README | `README.md` | Opens by naming this file as the source; its product claims are copied from here, never extended |
| FigJam overview | FigJam board `zfZBwQ4rf9rks1sUl50XEd` (private to the owner's account; drafts folder) | A banner on the board stamps the `howiwork.md` commit it was built from. A board whose stamp differs from the current commit of this file is stale |

The rule: **edit this file first, then bring the views up to date, in the same
change where possible.** When a view and this file disagree, this file is right
and the view is the bug. Agents and humans reading a view should open this
file before acting on it.

---

## Where the build stands

M1 (policy core, explain) done. M2a (backend model) done. M2b in progress:
the Linux harness, the audited unsafe syscall layer, and strictest
overlapping-rule resolution are on main; the broker (`aidod`), the gate
binary, the doctor report, the audit sinks, and the mount-trust check are in
review. Nothing can execute as root yet. Then: M3 out-of-band confirmation,
M4 enrollment and the passwordless path, M5 narrowing and bounded grants
(pasban's revocation substrate), M6 ergonomics (`airead` surfaces here),
M7 confinement and external audit.
