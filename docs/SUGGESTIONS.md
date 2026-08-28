# aido — Enhancement Suggestions

Beyond the eight stated requirements. Ranked by value-to-effort. Each row is the TL;DR; the reasoning for every entry follows in the second half of this document.

Two entries below (#9 typed matchers, #13 attested identity) are marked **REQUIRED** — they arrived as feature findings but the design cannot ship without them. Treat them as requirements, not options.

Source: `docs/design-plan.md`.

---

## TL;DR

| # | Suggestion | Effort | TL;DR |
|---|---|---|---|
| 1 | JSON decision envelope + denial taxonomy | S | Versioned JSON verdict with a stable error code and a concrete next step, so the agent reacts correctly instead of guessing from exit 1. |
| 2 | `aido explain` decision trace | S | Prints which rule matched at which `file:line`, the resolved binary, normalized argv, and the environment — without executing. |
| 3 | Fail-closed confirmation + request de-dup | S | Confirmations time out into a **deny**, never a hang; an identical request inside a short window reuses the prior verdict instead of re-prompting. |
| 4 | Per-rule env allowlist | S | Child environment built from scratch; loader and interpreter injection variables hard-refused. |
| 5 | Rate limiting with escalating friction | S | Token buckets per (session, rule, project) escalate allow → forced confirmation → deny + notify. A runaway agent is throttled before it is catastrophic. |
| 6 | `aido freeze` / `thaw` kill switch | S | One root-owned flag instantly denies every agent-path invocation; human path stays available for recovery. |
| 7 | `aido agentdoc` generator | S | Emits a policy-derived CLAUDE.md / AGENTS.md block stamped with the policy hash so CI detects drift. |
| 8 | Shell EPERM hint | S | A command that just failed on permissions prints one line — `try: aido <the same command>` — verified against policy before suggesting. |
| 9 | Typed argv matchers · **REQUIRED** | M | Per-position matchers instead of globbing a flattened command string. |
| 10 | `aido check` linter + policy unit tests | M | Type-checks the ruleset, flags dangerous constructs, runs `[[test]]` blocks in CI and pre-commit. |
| 11 | Hash-chained append-only audit log | M | Each JSONL record carries its predecessor's hash, mirrored to journald, so gaps and edits are detectable. |
| 12 | Time-boxed revocable grants | M | `aido grant 15m --profile docker-dev --max 20 --project /srv/app` mints a root-held grant that expires hard and cannot be renewed by the agent. |
| 13 | Attested caller identity · **REQUIRED** | L | Root broker identifies the caller race-free from the socket peer and enrolled cgroup lineage; env vars carry zero authorization weight. |
| 14 | Two-phase policy install + semantic diff | M | Stages the change, renders a **capability-level** diff, confirms, commits atomically, bumps a generation counter. |
| 15 | MCP server | M | `aido_run` / `aido_explain` / `aido_list_rules` / `aido_request_grant` with elicitation-based confirmation. |
| 16 | `aido log` forensic review | M | Filter the audit chain by agent, session, project, rule, decision, time; session replay; export. |
| 17 | Dry-run preview in the prompt | M | Rules declare a no-side-effect preview whose output is shown at confirmation time, so approval is informed rather than reflexive. |
| 18 | Binary identity pinning | M | A rule pins its target by resolved path + content hash or owning package; a replaced or shadowed binary fails closed. |
| 19 | Per-project narrowing-only scoping | M | A checked-in `.aido/policy.toml` can only further restrict, and only if root recorded its hash. |
| 20 | Anomaly / novelty escalation | M | Escalate on statistical surprise: a rule never used this session, unusual breadth, off-hours burst. |
| 21 | Signed rule bundles + curated profiles | M | Shareable versioned profiles (`docker-dev`, `web-dev`, `k8s-dev`, `embedded`) verified offline before install. |
| 22 | Telemetry-free build, verifiable at runtime | S | No network code in the default build, enforced by seccomp and a CI test asserting zero outbound syscalls. |
| 23 | `aido doctor` | S | Reports the backend, unavailable features, kernel probes, live confirmation channels — **and every other path to root.** |
| 24 | `aido init` wizard | M | Detects backend, distro, and installed agents; proposes a starter policy; previews the diff; installs atomically. |
| 25 | Landlock + capability-bounded children | L | Even allowed commands run with only the caps and filesystem access the rule declares, not full uid 0. |
| 26 | I/O session recording with redaction | M | Rules can capture the child's stdout/stderr or a full pty transcript, size-capped and redacted. |
| 27 | Off-box audit shipping | M | Optionally stream records to a remote collector so a compromised host cannot erase its own history. |
| 28 | `aido undo` | L | Rules declare an inverse and/or a pre-snapshot hook, so recent actions can be reversed under the same policy checks. |
| 29 | `aido shell --record` | M | A sanctioned escape hatch: a time-limited, fully recorded root shell, so humans stop reaching for raw `sudo`. |
| 30 | Two-person approval for a critical class | M | Rules tagged critical need approvals from two distinct humans on independent channels. |

---

## Explanations

**1–2. Machine-readable envelope and `explain`.** The primary consumer of aido is a language model, and `exit 1` with a prose message is the worst possible interface for one: the model guesses, retries with a mangled command, or gives up and asks the human to run raw `sudo` — defeating the tool. A versioned envelope (`schema_version`, `decision`, `rule_id`, `rule_source`, `resolved_exe`, `resolved_exe_sha256`, `argv_normalized`, `session_id`, `grant_id`, `audit_id`, `remediation`) with a **stable, append-only** denial code taxonomy lets the agent branch correctly: "this needs a grant" → request one; "this is permanently denied" → stop asking; "this needs confirmation" → surface it to the human and wait. `explain` is the same engine with execution removed, which is also how a human answers *"how do I know my ruleset does what I think it does?"* — the question every allowlist system eventually fails to answer.

**3. Fail-closed confirmation and de-dup.** Two failure modes, both fatal in practice. A confirmation that blocks forever wedges the agent's tool call and gets the feature disabled by an annoyed operator; a confirmation that times out into *allow* is not a confirmation. So: absolute monotonic deadlines, timeout → deny, and a resumable structured "pending" state so the agent's session survives an arbitrary approval delay. De-dup matters because a looping agent that re-requests the same action 40 times induces **prompt fatigue** — after the fifth identical prompt a human stops reading, which is a worse security state than no prompt at all.

**4. Per-rule env allowlist.** Because aido is not setuid, `ld.so` does not scrub `LD_*` for it. `LD_PRELOAD`, `LD_AUDIT`, `GLIBC_TUNABLES`, `GCONV_PATH`, `BASH_ENV`, `PYTHONSTARTUP`, `NODE_OPTIONS`, `PERL5OPT`, `LESSOPEN`, `GIT_*`, `http_proxy` (a caller-supplied proxy on `apt-get update` is an invisible machine-in-the-middle), `SUDO_ASKPASS` — none of these appear in argv, so argv matching cannot see them. Allowlist, never denylist, and assert absence in the child's `/proc/self/environ` with a real payload in tests.

**5. Rate limiting with escalating friction.** The distinctive agent failure mode is not one malicious command; it is a loop. Fifty `apt-get install` calls in ninety seconds is not a decision, it is a bug, and the right response is friction rather than a binary allow/deny. Three thresholds — annotate the audit record, then force confirmation *even under an active grant*, then deny + notify + optionally auto-freeze. Track a **separate novelty bucket**, because an agent suddenly touching twelve rules it has never used is a better anomaly signal than depth on one.

**6. Kill switch.** When something is going wrong, the operator needs one command that stops it *now*, and they need it to not lock them out of fixing the problem. `aido freeze` denies every agent-path invocation and leaves the human path working. Pair it with the dead-man default (no live confirmation channel → deny) so the system fails safe without anyone typing anything.

**7. `agentdoc`.** Agents behave far better when told what they may do than when made to discover it by failing. Generate the CLAUDE.md/AGENTS.md block *from the policy*, stamped with the policy generation hash, and let `aido check --agentdoc-fresh` fail CI when the doc has drifted. This closes the loop where documentation says one thing and the ruleset does another.

**8. EPERM hint.** Pure adoption. Someone types `systemctl restart nginx`, gets a permission error, and — because the shell hook checked the policy first and only suggests when the answer is yes — sees `try: aido svc restart nginx`. Without something like this, users learn the tool by hitting walls, and a tool learned by hitting walls gets replaced by `sudo -i`.

**9 & 13. Typed matchers and attested identity are not really suggestions.** They are listed because they arrived as feature findings, but the design cannot ship without them — a glob-based matcher is an argument-injection engine (sudoers matches arguments as one concatenated `fnmatch` string, so `*` crosses whitespace *and* matches `/`), and env-var-based identity is trivially forged by a same-uid process. Treat both as requirements.

**10. `aido check`.** A security policy nobody can test is a security policy nobody trusts. Executable `[[test]]` blocks inside the ruleset — `argv X must be allowed by rule Y`, `argv Z must be denied` — turn policy edits into a CI-gated change like any other code. Distinct exit codes for lint-warning vs lint-error vs test-failure so a pipeline can gate each independently. Include the shadowing lint: rules unreachable because an earlier deny matched, and rules that *shadow a later deny*, which is the ordering bug everyone makes with last-match-wins semantics.

**11. Hash-chained audit.** Two sinks, both independent: journald for structured querying, and a hash-chained JSONL file where each record carries `seq`/`prev_hash`/`hash` so a deletion or an edit is detectable rather than invisible. `fdatasync` before returning the exec result — an audit record written after the action completes is an audit record that a crash loses. Both the broker *and* the gate emit independently, so a direct gate invocation that bypasses the front-end still leaves a trace.

**12. Time-boxed grants.** The real workflow need: "I'm about to let the agent do twenty minutes of Docker work, stop asking me." A grant scoped to a profile, a project, a max use count, and a hard monotonic expiry gives that without becoming permanent. Two invariants make it safe: the counter is decremented and persisted *before* exec, and an **agent-path invocation can never mint or extend a grant** — only the human path can.

**14. Semantic policy diff.** A text diff of a rule file hides the thing that matters. Loosening a regex by one character can convert "writes under /etc/nginx" into "writes anywhere under /etc", and the diff shows one changed byte. Diff the **capability set** — `(binary, argv-shape, path-prefix, confirm-requirement, write-scope, network-flag)` — and render it in plain language, including reachability changes caused purely by reordering.

**15. MCP server.** The agent-native interface: `aido_run`, `aido_explain`, `aido_list_rules`, `aido_request_grant` as first-class tools rather than shell strings the model has to construct. MCP elicitation can route confirmation through the agent's own client UI, which is a *nicer* channel — but note it is the agent's client, so it never replaces the out-of-band channel for high-tier actions; it forwards to the broker, which still decides.

**16–17. Forensic review and dry-run previews.** Both are about the human's decision quality. `aido log` answers "what did the agent actually do last Tuesday" in one place. Dry-run previews answer the harder question at the moment it matters: an `apt-get remove` prompt that says "this will remove 47 packages including build-essential" produces a different decision than one that says `apt-get -y remove foo`. Run the preview under the same argv validation and scrubbed environment, cap the output, cache it against the request fingerprint.

**18. Binary pinning.** A rule for `/usr/bin/systemctl` should not be satisfiable by a replaced `/usr/bin/systemctl`. Pin by resolved absolute path plus content hash *or* owning package, verify on the already-open `O_PATH` fd immediately before `execveat` — which closes the swap window a path-based check cannot.

**19. Per-project narrowing.** Different repos need different capability. Bind a project root to a profile in root-owned config, and let a checked-in `.aido/policy.toml` **only further restrict** — never add a rule, widen a matcher, drop a confirm requirement, raise a limit, or extend a TTL — and only when root has recorded its sha256. Copies Claude Code's managed-settings property verbatim, for the same reason.

**20. Novelty escalation.** Fixed rate limits catch volume; they miss the single surprising action. Escalate on interpretable, individually-toggleable signals — first use of a rule (on by default), first use in this project, rule-breadth spike, off-hours, novel path prefix — and **always state the reason in both the prompt and the record**. An unexplained "this looked unusual" prompt trains people to click through.

**21. Signed profiles.** Nobody should hand-write a `docker-dev` ruleset. Curated, versioned, signature-bundled profiles verified offline (minisign, or cosign with a stapled inclusion proof) with `min_aido_version`, and **unknown matcher kinds as a hard parse error rather than match-anything** — the fail-open default that has bitten every policy format that allowed it.

**22–23. Telemetry-free and `doctor`.** A privilege broker that phones home will not be installed. Make it *provable*: no network code in the default build, networking behind a non-default cargo feature, a seccomp filter denying `AF_INET`/`AF_INET6` socket creation, and a CI job running the suite under `strace` asserting no non-`AF_UNIX` socket. `doctor`'s most valuable output is the part that undermines aido itself: **every other path to root** — pre-existing `NOPASSWD` entries, `wheel`/`sudo`/`docker`/`lxd` membership, writable unit directories, writable `PATH` entries, writable shell rc files. Any one of them makes aido decorative, and the operator deserves to know before they trust it.

**24. `aido init`.** First-run experience determines whether the starter policy is minimal or `ALL`. Detect the backend, distro, and installed agents, propose a small policy composed **from profiles rather than bespoke matchers**, preview the capability diff, run the linter, install atomically.

**25. Landlock and capability bounding.** The deepest hardening available: even for an allowed command, run the child with only the capabilities and filesystem access the rule declares instead of full uid 0. `systemctl restart nginx` does not need write access to `/home`. Two operational requirements: an explicit audit record when kernel support degrades the confinement, and a policy option to **deny on degrade** rather than silently running unconfined.

**26–27. Recording and off-box audit.** Optional, for teams. A size-capped redacted transcript makes "what did that command print" answerable after the fact. Streaming records off-box means a compromised host cannot erase its own history — the standard reason audit lives elsewhere.

**28. `aido undo`.** The feature users will ask for immediately and that is hardest to do honestly. Only rules that *declare* an inverse or a pre-snapshot hook can be undone, the undo runs through the same policy checks, and the ones that genuinely cannot be reversed must say so rather than pretending. Firewall changes and `/etc/hosts` edits are the natural first candidates because aido already snapshots them.

**29. `aido shell --record`.** The pressure-release valve. Policy will never cover everything, and when it does not, the human's alternative is `sudo -i` — which is unaudited, unbounded, and outside aido entirely. A time-limited, fully recorded root shell keeps that case inside the system. Deliberately human-path only.

**30. Two-person approval.** For the small class of rules where one person's judgment is not enough. Two distinct human principals on independent channels. Only worth building once an org actually asks.
