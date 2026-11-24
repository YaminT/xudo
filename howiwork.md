# howiwork.md — the source of truth

This file is the authoritative statement of what xudo is and how the system
behaves. **Every other description derives from it**: the README, the FigJam
overview, generated agent documentation, and marketing text of any kind. When
any of them disagrees with this file, this file is right and the other document
is the bug. Changes to product behaviour are made *here first*, then propagated.

Division of labour:

| Document | Owns |
|---|---|
| `howiwork.md` (this file) | What the product is, which components exist, how a request flows, what each mode and outcome means |
| `docs/crates.md` | The workspace crate list, checked against `Cargo.toml` |

Contributor rules and the design history are maintainer notes and are not part
of the published tree. The three invariants below are part of this file.
Nothing written here or anywhere else may weaken them; a future edit to this
file that contradicts them is an error in the edit, not a new truth.

---

## What xudo is

xudo is `sudo` for AI agents. An agent (Claude Code, Codex, Grok…) calls
`xudo` where it would call `sudo`. xudo first checks that the caller is a
harness root has verified on this machine, then checks the command **and its
arguments** against rules root wrote. The answer is one of three: **allowed**
(it runs as root, with no password), **denied**, or **needs a human** (it waits
in the `ido` queue until a person reviews and runs it). xudo itself never asks
for or handles a password. Anyone who is not a verified harness, a human
included, gets the machine's normal `sudo` password prompt. Every decision is
recorded in a tamper-evident trail.

Today's beta builds the password half only: every request, from anyone, asks
for a password. The verified-harness half is not built yet: the registry, the
rule keys and the root-held queue exist in the code, but nothing in this
release creates an agent scope, so no caller counts as a registered agent.

The long-term shape is a system where xudo is part of the installed path of a
machine built for agent work (ultimately a Linux distribution that ships it
preconfigured). The near-term shape is a signed `.deb` an operator installs
beside the escalator they already have (`sudo`, `sudo-rs`, or `doas`).

## The three invariants

1. **Agent detection is not a security boundary.** Authorization comes only
   from kernel-attested facts (`SO_PEERPIDFD` + a root-created cgroup scope
   under `xudo.slice`). Environment variables, process names, `/proc` paths,
   and process ancestry are *unauthenticated hints*: recorded in the audit
   trail, never used to authorize. A *verified harness* is a caller the kernel
   shows is inside a live root-created scope that a root-written registry
   entry names; never a name or anything the caller sends.
2. **No caller gets passwordless root by mistake or by default.** A command
   runs without a password only when the kernel attests the caller is inside a
   root-registered harness scope **and** a root-written rule allows that exact
   command for that harness. Everything else (a human, an unattested caller, a
   process that left its scope, a command no rule allows) takes the human
   path, where the machine's own `sudo` asks the password, or is denied.
   Misclassification may only withhold. Nothing the agent may run is closed to
   the human path.
3. **A human decision is made where the requester cannot answer it.**
   Anything that needs a human is decided by the human on a channel the
   requesting process (or anything it controls) cannot answer: never from its
   stdin, stdout, or `/dev/tty`. "Needs a human"
   never resolves by itself; with no human, it does not run.

## The permission model: action X, situation Y, requester Z

A permission answers: *may requester Z perform action X in situation Y?*

- **Action X** — a *named action*: one fixed executable plus an argument list
  constrained position by position with typed matchers. No globs anywhere.
  Actions cover what the invoking user cannot already do: installing packages,
  restarting services, writing under `/var/www`, running `certbot` as root.
- **Situation Y** — the context the decision is made in: the project the
  request is scoped to, global settings (frozen: a freeze is global when root sets it and covers only the caller's own agents when a user does), whether
  a rule sends the command to a human, rate and novelty limits, and conflicts
  the doctor can see (for the nginx example: Apache already holding port 80 is
  reported, not silently fought). Context can only *narrow* what an action
  grants — a project layer that tries to widen policy is structurally
  rejected.
- **Requester Z** — who is asking, established by the kernel, not by names.
  The broker identifies its peer through the socket (`SO_PEERPIDFD`,
  credentials at connect time via `SO_PEERCRED`) and classifies it:
  *verified harness* (its cgroup is a live root-created scope that root's
  harness registry names), *human*, or *unattested*. "Claude Code requested
  this" is recorded as a hint for the audit record; it never authorizes.
  Prompt injection and malicious scripts are contained by this design rather
  than detected: whatever a hijacked agent claims to be, it can reach only
  what root's rules allow its harness, minus the deny-list. Because no person
  approves an allowed command, the rules are the boundary: each must be
  narrow enough to run unattended.

### Permission sets

A **permission set** would group named actions into something an admin can
reason about, for example *web admin*: install from the web-server list (nginx,
apache), write under `/var/www`, run `certbot` as root. **Predefined permission
sets** (rule packs) are not built yet. Today the shipped rules are the files in
`/etc/xudo/rules.d/`.

The engine's native, tested format is TOML under root-owned
`/etc/xudo/rules.d/` (this is what ships today). YAML and JSON import,
converted to native rules and shown as a capability diff before install, is not
built yet. Every shipped rule is tested as code and checked against the
GTFOBins gate: a rule that allowlists something shell-capable needs a written
waiver naming why the rule makes the technique unreachable.

### Operator deny rules, protect rules, the registry and the queue

These exist in the code today.

- **`[[deny]]` tables.** A rule file may refuse a command an action would
  accept: `id` (unique across actions and deny rules), `reason`, `program` (a
  list of executable basenames) and `all` (a list of clauses, each holding
  exactly one of `any-arg` or `any-deb-name`; every clause must match). A deny
  rule only narrows. One whose program no loaded action runs loads inert, and
  `xudo check` and `xudo doctor` say so.
- **Protect rules.** `rules/00-protect.toml` ships active. Through xudo it
  refuses removal of xudo, sudo, sudo-rs, AppArmor, auditd, firewall, logging,
  time-sync and SSH server packages. It cannot stop the host's own `apt` or
  `dpkg`.
- **The harness registry.** Root-written `/etc/xudo/harnesses.d/<label>.toml`
  files (`label`, `way`, `account` or `users`, `reviewers`, `max-sessions`;
  the package ships the directory empty). An action may name labels with
  `harness` and set `outcome` to `allow` or `ask-human`. Nothing in this
  release creates an agent scope, so none of this can trigger yet.
- **The root-held queue.** An `ask-human` request from a registered agent
  would be stored in `/var/lib/xudo/queue`, which the agent cannot edit. A
  person classified as human, named in the harness's `reviewers` and not the
  entry's owner, runs it with `xudo exec --queued ID`.

### Temporary permissions

*Not built yet.* None of the commands below exist.

A **temporary permission** lets a harness use a defined permission, or a whole
permission set, without asking the human each time, for a bounded window that
ends on its own.

```
xudo grant nginx-reload              # 30 minutes, the default
xudo grant web-admin 24h             # a whole permission set
xudo grant nginx-reload 2h --agent claude-code --project /srv/site --max 20
xudo grants                          # what is live, who granted it, when it ends
xudo revoke <grant-id>               # end one early
```

What makes it safe:

- **Only what root already defined.** A grant names an action or a set that
  exists in root's rules. It cannot invent a permission or widen a matcher,
  and the compiled-in deny-list is evaluated after it exactly as without it.
- **Minted by a human, never by an agent.** Granting runs through the human
  path: the `PASSWD` hop, where the human types the password, with the prompt
  saying exactly what is granted, to whom, and until when. That password
  prompt is the human's decision for the whole window, made in advance on a
  channel the requesting process tree cannot answer (invariant 3), time-boxed
  and recorded. An agent may *ask* for a grant (the request is shown to the
  human, who mints it on the password path or declines); an attested agent
  trying to mint or extend one itself is refused. The real boundary is that
  minting always needs the human-path password; refusing a mint from inside a
  live grant is a second guard, not the boundary.
- **What it changes during the window**, for the named harness (and project,
  if given). The harness is a verified harness from root's registry, and at
  every use the broker matches it to the requester's kernel-attested scope:
  the name is how the human picks the grantee, never how a requester is
  identified. A grant without `--agent` covers the sole registered harness,
  and `--agent` is required when more than one is registered. During the
  window, actions marked `grant-only` (defined and reviewed, but dormant)
  become usable, and granted actions that are marked to need a human (not the human-only
  ones) run without waiting for one. It does **not** lift a human-only action, the
  critical tier, or rate limits: a burst still sends the command to a human,
  then denies.
- **Bounded.** The default is 30 minutes. Each permission or set may declare
  a ceiling (`max-grant = "24h"`), a global ceiling caps all of them, and a
  request above a ceiling is refused, not silently shortened. Deadlines are
  monotonic, so moving the clock cannot extend one. An optional use count is
  persisted before each execution.
- **Expiry is enforced twice:** at every use — at both decision points, the
  broker when it mints a request and the gate when it re-decides before
  executing, so a request minted under a grant that expires before the gate
  runs it is refused — and by pasban, which removes expired grants and reports
  any grant it finds that should not exist.
- **A grant never outlives the rules it named.** Each grant records the policy
  generation it was minted under; a policy change bumps the generation
  and invalidates every outstanding grant (comments, positions and tests
  do not).
- **Visible and recorded.** Granting, every use under a grant, expiry, and
  revocation each write an audit record, and while any grant is live, xudo
  shows a banner naming it.

Grants are stored root-owned under `/var/lib/xudo/grants` and read only
through the trust walk. Standing, reviewed narrowing over days or weeks stays
in `trust.d`; a grant is its time-boxed sibling, the short window an operator
opens from the command line. Grants only mean something once verified
harnesses exist; in today's beta every request asks for a password anyway.
Grants are not built yet. Permission sets become a construct in the rule
files first.

## The components

| Component | Privilege | Role |
|---|---|---|
| `xudo` | user | The front-end agents and humans call. Explains, checks, asks the broker. Decides nothing. |
| `xudod` | root | The authority. Identifies the peer, classifies, evaluates policy, mints one-use requests, and runs the optional human-path confirmation. |
| `xudo-gate` | root (via sudo/doas) | The executor, and a **second independent policy engine**: re-decides from root-owned state, consumes the one-use nonce, execs the validated descriptor. Safe to invoke directly because it trusts nothing it is handed. |
| `sudo` / `doas` (the hop) | root | The machine's own escalator, used only as the **uid transition**: xudo ships no setuid bit anywhere. Two rules point at two hardlinks of the gate: `xudo-gate-nopass` (`NOPASSWD`, for a verified harness; not shipped yet) and `xudo-gate-auth` (`PASSWD`, the human path). The password lives on the second and only the second. |
| `ido` | user | The buffered human-run queue (below). Where the human's password is entered. |
| `airead` | user | Not built yet. The read-only surface (below). |
| `pasban` | root (scheduled) | The watchman (below). |

## The three outcomes

Every request resolves to exactly one of:

1. **Denied** — the deny-list or a deny rule matched, no rule allows the
   command, or the context forbids it. A command no rule mentions is denied.
   Every error path lands here: xudo fails closed.
2. **Allowed** — a verified harness asks for a command that a root-written
   rule allows for that harness. It runs as root with **no password and no
   prompt**: the rule is the authorization. It goes through the `NOPASSWD`
   hop. A caller the kernel cannot place in a registered harness scope is
   never allowed this way (invariant 2): it takes the human path.
   *Not built yet:* harness verification and the passwordless hop. Today's
   beta ships only the `PASSWD` hop, so nothing runs without a password.
3. **Needs a human** — a rule with `outcome = "ask-human"` that lists the
   caller's registered harness label. The broker denies the request and stores
   its exact argv and the agent's reason in a root-held queue
   (`/var/lib/xudo/queue`) that the agent cannot edit. A person classified as
   human, named in that harness's `reviewers`, and not the entry's owner sees
   it in `ido` and runs it with `xudo exec --queued ID`. The broker re-decides
   it against the current rules, `sudo` asks for the password, and the command
   runs in `/`. It never resolves by itself. A request from anyone else that a
   rule refuses is denied, never queued. *Not built yet:* nothing in this
   release creates an agent scope, so this queue stays empty until enrolment
   ships. Separately, an agent can always hand work to a person with
   `ido queue --root`, in the person's own editable queue.

A human who runs `xudo` directly is on the same human path: `sudo` asks the
password. An administrator who wants a second check there can turn on
`confirm_human_path`: a rule that requires confirmation then also needs an
approval typed into `xudo watch`, a window the requester cannot answer. It is
off by default and is never part of the agent path.

When several rules accept the same command, the **strictest requirement wins**
— file order can never decide whether a human is asked.

### ido

`ido` keeps a queue of commands an agent wanted but could not run. Each entry
stores the exact argv (never re-parsed through a shell), the agent's stated
reason, and an identifier; `ido run <id>` runs one entry, `ido` opens the picker.
The admin is told when unfinished tasks exist.

`ido` shows two lists: the user's own queue, which the agent writes and can
edit, and the broker's root-held review queue, which only root writes and
which `ido` reads through the broker. The root-held queue is empty until
agents can be registered.

Running an entry is a *human* act: it executes with the human's own authority,
and anything privileged goes through xudo's human path, where the `PASSWD` hop
(`xudo-gate-auth`) prompts for the password once. ido itself holds no privilege and never will —
"running ido is equivalent to sudo" is achieved by routing through the same
gate as everything else, not by making ido a second sudo. Every rendered field
of an entry is sanitized for the terminal (agent text cannot forge the UI), and
every run lands in the audit chain.

### airead

*Not built yet.* `airead` would be xudo's read-only twin: the same engine, the same attestation, the
same audit trail, but it can only ever grant actions whose capability class is
*reads* — no file writes, no database writes, no cloud-CLI mutations, no
network egress that changes state. The separation is structural, not
cosmetic: read-only-ness is decided by the action's declared capability class
and the compiled-in deny-list (which classifies by what a binary *can do*,
never by its name), so a write cannot be disguised as a read by renaming or
copying a binary. A rule whose action could write is simply not expressible in
airead's rule set.

### Vision mode and blind mode

*Not built yet.* Blind mode below is what runs today; vision mode is the design.

**Blind mode is the authorization engine and it is always on.** Strictly
defined rules, compiled-in deny-list, fail closed; only known actions pass.
This is not a degraded state — it is the only thing that ever authorizes.

**Vision mode** adds AI assistance on top, using a configured provider
(Anthropic-, OpenAI-, or Gemini-compatible, by key or subscription). Where no
strict rule decides, a model may: explain a denial, triage a request into the
ido queue with a drafted script and rationale, flag a suspicious context, or
propose a new rule *for the operator to review*. A model's output can reject,
defer, or annotate — **it can never approve**. Only a root-written rule can
let a command run (invariant 2), so an AI decision may only withhold
capability: a component that can be prompt-injected must not be a component
that can grant root.

When the provider is unreachable or the quota is exhausted, the operator's
configured fallback applies: continue in blind mode (default), or send
every request that needs a human decision to the human path with no AI
opinion. A command no rule allows stays denied either way. There is no
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
append-only in practice and tamper-evident by construction. xudo (broker and
gate) writes it and can read it; pasban reads and verifies it; nothing else has
access except root, which the chain detects only through the journal copy.
"Hard written" is implemented as a hash chain — every record seals the
one before it — plus the journald copy, so a modification cannot be hidden
even from an attacker who gains the file: the chain stops verifying, and
pasban's next run reports exactly where.

## How a request flows

```
caller ── xudo exec ──► xudod (root service)
                           ├ who is asking? (from the kernel; names are hints)
                           ├ a verified harness? (root-created scope + root's registry)
                           ├ which rules accept this command and its arguments?
                           ├ deny-list (built in, cannot be switched off)
                           └ outcome: Denied │ Allowed │ ask-human queue

  Allowed ─► one-use record ─► sudo/doas, NOPASSWD ─► xudo-gate-nopass (not built yet)
                               (identity switch only,       │
                                no password)                │
  ask-human queue ─► reviewer runs xudo exec --queued ID    │
                 ─► xudo (human path)                       │
                 ─► sudo/doas, PASSWD ─────► xudo-gate-auth │
                    (the person types the password here)    │
                                                            ▼
                                    xudo-gate (root, the same binary)
                                      ├ decides again from root-owned files
                                      ├ uses the one-use record (once, ever)
                                      └ runs the checked program
                                          └ audit record before and after
```

Today only the human half is built: every request takes the `PASSWD` hop.

Why the hop exists at all when an allowed command needs no password (today
only the `PASSWD` hop ships): it is
the only place a uid transition happens, because xudo has no setuid bit. It
also gives the gate a real pty (`use_pty`, the TIOCSTI defence), faithful exit
status, and the operator's existing sudo/doas logging. Take it away and the
choice is a setuid binary, which this project refuses, or having the root
daemon execute commands itself, which makes the broker, the parser, and the
executor one process. Two hardlinks keep the password rule and the
passwordless rule from ever naming the same command: `NOPASSWD` attaches only
to the verified-harness name.

## Mismatches resolved (pasted vision → merged truth)

Recorded so the reconciliation is visible, not silent:

1. *"Check if Claude Code is added as an actor"* → a harness is verified by
   the kernel-attested scope it runs in plus root's registry entry for that
   scope (invariant 1). The name a program gives itself is an audited hint.
   The registry is root-written: an agent cannot add itself.
2. *"AI takes decisions where no strict rule is defined"* → AI may reject,
   defer to ido, or annotate — never approve (invariant 2: only a root-written rule lets a command run). Blind mode
   is the engine, not a fallback.
3. *"Running ido is equivalent of sudo without sudo"* → ido stays
   unprivileged; privileged entries run through xudo's human path with its
   password prompt. Same user experience, no second privilege boundary.
4. *"Permission sets in YAML and JSON"* → native engine format stays TOML
   (tested, shipped); YAML/JSON import, converted and reviewed before
   install, is not built yet.
5. *"If something is approved, no human password is needed"* → true for a
   command a root-written rule allows for a verified harness, which takes the
   `NOPASSWD` hop. The password belongs to the human path (a person running an
   ido entry, or running `xudo` directly), because a caller that is not a
   verified harness, a human included, never gets passwordless root by mistake
   or by default (invariant 2). The `sudo`/`doas` hop itself stays: it is the
   uid transition, not the password mechanism.
6. *"airead as a separate app"* (not built yet) → same engine, structurally restricted to
   read-class capabilities, so the read/write separation cannot drift between
   two codebases.
7. *"Temp permissions: `xudo set-temp nginx-reload 30m`, `xudo set-temp
   nginx-perm-set 24h`, default 30 minutes"* → adopted as temporary
   permissions, spelled `xudo grant <name> [duration]` to match the existing
   `grants`/`revoke` verbs, default 30 minutes. A grant activates something
   root already defined, for a named harness, minted by a human on the
   password path; it lets granted actions run without waiting for a human, and
   never lifts the deny-list, a human-only action, the critical tier, or rate
   limits (invariants 2 and 3).

8. *"The application does not require a password; rules decide; commands
   that need a user go to ido"* (2026-11-16) → adopted. Rules alone decide
   what a verified harness may run: allowed, denied, or needs a human. No
   agent request waits for a live approval window. A harness is verified once:
   on a server the administrator registers it to run as its own account; on a
   laptop the person types the sudo password once per session in sudo's own
   prompt. xudo never sees a password. "`rm` only inside home" is xudo's own
   safe file operation, not a rule over the real `rm`. A command no rule
   mentions is denied.

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

Built: the policy engine with `[[test]]` tables and `xudo check`; the broker
and the password-authenticated gate, both deciding independently; `xudo exec`,
`xudo install` and `xudo doctor`; the hash-chained audit log, verified daily by
Pasban; `[[deny]]` rules and the shipped protect rules; the safe `remove-path`
operation (`xudo op remove-path`, on the password path); classification of each
caller from its cgroup; the harness registry and the rule keys `harness` and
`outcome`; the root-held ask-human queue with `xudo exec --queued` and its
listing in `ido`; the optional `xudo watch` check on the password path (off by
default). The same rules behave the same through sudo, sudo-rs and OpenDoas.
The doas install probe remains NOT VERIFIED.

Not built yet: agent enrolment, so no caller can be a registered agent and the
queue stays empty; passwordless runs; rule packs; temporary permissions;
`xudo setup` and an apt repository; `airead`; vision mode; Landlock
confinement; an external audit. In this release every privileged request asks
for a password.
