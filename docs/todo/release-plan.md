# Release plan: what is left, split into release work and improvements

Written 2026-11-10 against `m3` (`9964207`, draft PR #5, CI green). This is a
plan only: nothing here is fixed yet. Each item says what is wrong, where, and
how to fix and prove it. `README.md` in this directory stays the index.

Sources: every file in `docs/todo/`, `howiwork.md`, `docs/design-plan.md`,
`docs/SUGGESTIONS.md`, the newest `docs/CONCERNS.md` entries, a read-only audit
of the release path, and an independent security review of the M3 diff
(`main..m3`). Every finding below was checked against the code.

**The beta being planned:** `v0.1.0-beta.1`, a signed `.deb` on GitHub
Releases. Human path only, a password on every request, no `NOPASSWD`, and
`xudo watch` built but off by default (`confirm_human_path = false`).

---

## 0. Decisions the owner must make first

Each one changes what the release work is.

| # | Question | Options | Recommendation |
|---|---|---|---|
| D1 | Does the beta include M3? | (a) merge PR #5, then release; (b) release from `main` without M3 | (a). M3 is off by default, CI is green, and the docs already describe it |
| D2 | What does freeze cover? (CONCERNS 2026-11-09, still flagged) | (a) agent path only, as built and as the plan says; (b) humans too | (a). Freeze must leave the human path free for recovery (SUGGESTIONS #6). Record the answer in CONCERNS |
| D3 | What happens on stock Ubuntu 26.04, whose first install reports `NOT VERIFIED` (uutils `id` is a symlink the gate refuses)? | (a) ship as is and document it; (b) change the probe target to a program that is a regular file on every distro; (c) have the gate print the uid itself | (b) or (c) before tagging. A security tool whose first run says "unproven" on the newest LTS reads as broken. See R7 |
| D4 | Do reproducible builds, an SBOM and `cargo-auditable` gate this beta? (phase 3 deliverables) | (a) yes, now; (b) move them to the 1.0 / M7 list | (b), but edit the phase 3 deliverables to say so, so the plan stops promising them for this release |
| D5 | Should `/etc/xudo/config.toml` and `/etc/xudo/deny.d/00-catastrophic.toml` ship? (phase 3 § 2 lists them; `build.sh` ships neither) | (a) ship a fully commented default config and the read-only deny-list copy; (b) remove them from the layout | (a) for the config: it tells the operator `confirm_human_path` exists. (b) for `deny.d` until there is generated content to put in it |
| D6 | Which `.rpm`, `APKBUILD`, `PKGBUILD` and Nix packages ship? (phase 3 deliverables) | beta, or later | Later. Remove them from this release's deliverables |

---

## 1. Release blockers (must be done before the tag)

### R1. The version cannot be tagged
- **Problem:** `Cargo.toml:29` says `0.0.1`. `release.yml` requires the tag to be `v` plus that version, so `v0.1.0-beta.1` is rejected.
- **Fix:** bump the workspace version, and any internal version requirements, to `0.1.0-beta.1`. Bring `CITATION.cff`, the package changelog and the examples in line with it.
- **Proof:** `xudo --version` prints `0.1.0-beta.1 (beta, not externally audited)`. A local run of the tag check passes.

### R2. Signing does not wait for the security lanes
- **Problem:** in `release.yml`, `sign` needs only `build`, and `build` runs only `just deb-test`. Root tests, systemd, the differential, telemetry, units and install-as-root run in `ci.yml`, which the release workflow never waits for. A tag on a commit that never passed CI would still be signed.
- **Fix:** one of:
  - (a) Run the same lanes in `release.yml` before `sign`, by calling `ci.yml` as a reusable workflow (`workflow_call`) and adding `needs:`.
  - (b) Add a first job that fails unless the tagged SHA has a successful `ci.yml` run on `main`.

  (a) is simpler to reason about. Keep `id-token: write` on the `sign` job only, as it is today.
- **Proof:** a tag on a commit whose CI is red never reaches `sign`. Test it on a fork, or with a dry-run tag on a throwaway branch.

### R3. Public pages contradict the build
- **README.md:80:** the FAQ says out-of-band confirmation is not in this release, while line 39 of the same file says it is built and off by default.
- **site/index.html:19, site/security.html:5:** say out-of-band confirmation is not in this release.
- **site/faq.html:12, site/security.html:6:** say "the planned strace CI check does not exist yet". It exists (`just telemetry`, CI job "no telemetry").
- **docs/todo/phase-3-packaging-and-publish.md § 6:** "What is not in this release: … the broker, out-of-band confirmation". Phase 3 § 1 also says "Before M4 there is no … broker".
- **CHANGELOG.md:** says nothing about `xudo watch`, `pending`, `freeze` or `thaw`.
- **Fix:** take one sentence from `howiwork.md` § Where the build stands and use it in every place above. Add an M3 entry to `CHANGELOG.md`. Cut a dated `## 0.1.0-beta.1` section.
- **Proof:** add a test in `xudo-tests`, the same shape as `readme_no_pipe_to_shell.rs`. It fails if README, `site/` or `SECURITY.md` say "out-of-band confirmation" next to "not in this release", or say the strace check "does not exist". Stale claims have come back in every phase; a test stops it.

### R4. The first-install notice is missing
- **Problem:** phase 3 § 3 step 8 promises a notice on first install. It should say:
  - every request asks for a password;
  - there is no agent path in this release;
  - where `SECURITY.md` is;
  - agent detection is not a security boundary.

  `postinst` prints none of it. It also never says that the `xudo` group is empty by design, so `xudo exec` is refused for everyone until a human adds themselves. A new user's first command fails with nothing to explain why.
- **Fix:** on a first install only (`$2` empty), print a short notice to stderr. It covers the four points above, plus the next step: `sudo adduser <you> xudo`, and log in again. Also mention `xudo doctor --fix`, which proposes the same thing.
- **Proof:** `ci/deb/row.sh` checks the notice on a first install, and checks that an upgrade does not print it.

### R5. `audit_sink` is accepted and then ignored
- **Problem:** `xudo-config` accepts any text for `audit_sink` (`load.rs:58`), and `xudo config` shows the operator's value. But `xudo_gate::policy::settings_from` (`policy.rs:119`) never reads it, and nothing else does either. CLAUDE.md names this exact footgun: "silently ignoring a security-relevant directive". An operator who writes `audit_sink = "file"` to get past the journald requirement sees it reported as set, and it does nothing.
- **Fix:** until a second sink exists, accept only `"journald"`. Any other value is a hard parse error naming the one value allowed. Then check the other keys that are accepted but not acted on yet: `confirm_agent_actions` until M4, and the rate limits if any exist. Either reject them or have `xudo config` mark them "no effect until M4".
- **Proof:** `audit_sink_other_than_journald_is_refused`, and a broker or gate test showing that a config holding it refuses closed.

### R6. Watch entries can fill the spool for everyone (security review #1)
- **Problem:** since M3, a pending or approved watch entry counts as live until its deadline + 60 s, even after the requester exits (`xudod/src/mint.rs:384`). Limits are `MAX_ENTRIES_PER_UID = 8` and `MAX_SPOOL_ENTRIES = 64`. Eight group members can each send eight timeout-0 requests with different argv, run their own watcher (the known `setsid` trick), and walk away. For about 16 minutes every other user's `run` then fails with `Full`, plain password path included. It only works with `confirm_human_path` on, but it ships, and turning that setting on is what the docs suggest for safety.
- **Fix:** give watch entries their own limits, for example 2 per uid and 16 in total, kept out of the slots the password path needs. A watch entry beyond those limits is `confirmation_throttled`, never `Full` for someone else.
- **Proof:** `watch_entries_cannot_exhaust_the_spool_for_the_password_path` (fake spool), plus a property test: with any mix of watch entries, a non-watch mint for a fresh uid succeeds.

### R7. The probe on stock Ubuntu 26.04 (after D3)
- **Problem:** if D3 is (b) or (c), change `rules/05-probe.toml`, or the gate's probe mode, so the probe works where `/usr/bin/id` is a uutils symlink. Today the systemd and differential lanes pass only because they install GNU `id` first, so CI never tests what a real user gets.
- **Fix:** whatever D3 picks. Then delete the "install GNU coreutils" step from the 26.04 lanes, so they test the stock image.
- **Proof:** the 26.04 `deb-test` and `systemd-test` rows on a stock image print `installed` with no `NOT VERIFIED`.

---

## 2. Should be done before the tag (small, on shipped code)

These are not exploitable with the defaults. Each is a few lines on code that ships, so they are cheaper to fix now than to explain later.

| # | What | Where | Fix | Test |
|---|---|---|---|---|
| S1 | The wire check reads `schema_version` only from a top-level JSON object, and the serde derive also accepts the array form. So `[1, {"watch": …}]` parses with `schema_version = 1` and gets past `a_schema_1_request_is_refused_wrong_schema` | `xudo-wire/src/lib.rs:178-196` | After deserializing, refuse `schema_version != WIRE_SCHEMA_VERSION`, and refuse any top level that is not an object. Do the same for the response and the spool entry | `an_array_form_request_is_refused`; add the array form to the wire fuzz seeds |
| S2 | The gate accepts an `Approved` entry that was never consumed. The pinned requester can run the gate straight after `status` says approved, skipping the broker's `take_approval` checks and the 120 s cap on the password window. It is still one use, and the password is still needed | `xudo-gate/src/request.rs:425` | When `needs_watch` is set, accept only `Consumed` | `an_approved_but_unconsumed_entry_is_refused_by_the_gate` |
| S3 | When there is no systemd, the `postinst` fallback creates `/run/xudo/req` but not `/run/xudo/confirm` or `audit.jsonl`. It fails closed, but it is out of step with tmpfiles | `packaging/deb/postinst:20-24` | Mirror every tmpfiles line, or drop the fallback and say there is no broker without systemd | `units.rs` already reads tmpfiles; add a check that the fallback lists the same paths |
| S4 | Package metadata uses `noreply@xudo.invalid`, and the generated Debian changelog is generic | `packaging/deb/control:4`, `build.sh:46` | A real maintainer address, or the GitHub noreply address; build the Debian changelog from `CHANGELOG.md` | lintian is clean |
| S5 | `systemd` is only a `Recommends`, but without journald every privileged request is refused | `packaging/deb/control:7` | Say so in the README install section and in the first-install notice (R4); keep it a `Recommends` | none |
| S6 | GitHub settings: the About text, topics, social preview, and Pages are still served from the old `gh-pages` content | phase 3 § 5 | Apply `docs/github-metadata.md`; switch Pages to the main-only workflow | none (manual, owner) |

---

## 3. Security findings to fix before M4 (not a beta blocker)

These are safe in M3 because the password is still required. Each one becomes a hole the moment an approval replaces the password (M4). Write them into M4's plan as **entry criteria**, not follow-ups.

1. **An approval is not tied to who asked.** `take_approval` matches uid, argv, generation, action and deadline (`xudod/src/confirm.rs:261`). `mint_approved` re-pins the consumed entry to whichever process re-runs (`serve.rs:670`). In M4, any process of the same uid could consume a human's approval, including an agent in a different scope, and run it on `-nopass`. **Fix:** store the attested classification and cgroup scope id on the entry at mint; `take_approval` must match them; the gate re-checks them.
2. **Re-decisions use the wrong identity.** Approve, deny and freeze re-decide with the watcher's or freezer's `classify(identity)` plus the entry's *claimed* class (`serve.rs:1181`, `serve.rs:1667`). **Fix:** re-decide from the requester's attested class stored at mint (item 1). The claimed class stays a hint, as invariant 1 requires.
3. **Freeze picks entries by the claimed class, across all users, and any member can trigger it** (`serve.rs:1232`). In M4, any agent could freeze every user's agents until root thaws. **Fix:** pick entries by the stored attested class. Decide whether an attested agent may freeze at all, and whether a non-root freeze covers only the freezer's own uid.
4. **Any process of the same uid can use up an approval.** `publish_consumed_approval` (`serve.rs:731`) does not check the caller. A re-run is also denied `no_confirmation_channel` once the human has closed `xudo watch`, even though an approval is waiting (`serve.rs:135-155`: the live-watcher check runs before the approval lookup). **Fix:** check who the caller is before consuming; look for an approval before demanding a live channel.
5. **The watcher needs a separate process tree.** A watcher must not be in any live agent scope (the known M3 limit, m3-plan § Risks). Row 8 is proven only when this has a test.

---

## 4. Improvements (after the beta, by milestone)

### Before or alongside M4
- **I1.** The confirm directory's 4,096-uid bound is never pruned. File 4,097 is checked only before publishing, and after that every user's `watch` fails (`serve.rs:563`, `MAX_CONFIRM_UIDS`). Prune files with no live heartbeat, no backoff and no outcomes, and enforce the bound when publishing.
- **I2.** `UnixStream::connect` has no timeout (CONCERNS 2026-11-09). Use a non-blocking connect with the same deadline as the read and write.
- **I3.** Each `status` poll and each watch heartbeat starts a sandboxed broker, about 300 ms each. That is fine at the defaults. The m3-plan fallback is a long-poll `watch`, and it becomes worth building once M4 makes watch the common path.
- **I4.** Promised tests that are missing or narrower than the plan says:
  - `exec_with_timeout_zero_…_leaves_the_entry` became a render test that never checks the entry.
  - Expiry at the TTL is tested only in unit tests, not under systemd.
  - `watch_in_a_user_namespace_is_refused` can be skipped with an environment variable.
  - The other renames are fine.

  Add the missing check that the entry survives, and an expiry case with a short TTL under systemd (a test-only TTL override behind the lane's sentinel).
- **I5.** Verification row 5: two real gates racing one entry is untested. Row 11: no test reads the child's `/proc/self/environ` with a real payload. Both are design-plan promises. Do them in the root lane before M4 adds the passwordless gate.
- **I6.** doas has no oracle and no functional probe (`NOT VERIFIED`). Either build the `doas -C` oracle decided on 2026-10-30, or state in the README that doas is not supported for the beta.
- **I7.** The `ido-bin` pty flake (D4, 2026-10-30) was never diagnosed.
- **I9.** `a_stalled_journald_refuses_within_the_timeout_instead_of_hanging` (`xudo-sys/src/audit/journal.rs:297`) failed once under full `just verify` load with `EINTR` ("Interrupted system call"), then passed 5 out of 5 times alone (2026-11-10). Either the journald send treats `EINTR` as a refusal instead of retrying within its deadline (fail-closed, but a spurious denial on a real host), or the test races. Diagnose it before the release, because a flaky gate gets bypassed.
- **I8.** Wire leniency: serde accepts positional and array enum forms everywhere (CONCERNS 2026-11-07). S1 closes the schema hole; doing the same for every privileged parser (spool entry, confirm file) makes it total.

### M5, M6, phase 5 part 2
No change to the order in `README.md`. Three plan gaps to close when those milestones are planned:
- **Grants and `freeze`:** a live grant must not survive a freeze. Neither `howiwork.md` nor the README says so.
- **Grants and the M3 approval:** say whether a grant lifts the `confirm_human_path` watch requirement. Recommendation: no. Grants are for the agent path; the human path keeps its password.
- **`airead` (M6)** has no plan section beyond one paragraph. It needs a capability-class model in `xudo-policy` before it can be scheduled.

### Pre-1.0 (M7)
Reproducible builds with a two-build compare in CI, an SBOM per release, `cargo-auditable`, `cargo-vet`, the full differential matrix (Fedora/SELinux, Arch, kernels 5.15 / 6.1 / 6.6+, cgroup v1), `.rpm` / APK / PKGBUILD / Nix, an apt repository with a keyring package, then the external audit.

---

## 5. Flaws in the plan documents themselves

These cause wrong work or wrong expectations later. Fix them in one docs commit.

| # | Where | Problem | Fix |
|---|---|---|---|
| P1 | `design-plan.md:237` | Still says "last-match-wins with explicit negation". Line 16 of the same file and README 2b record the decision that replaced it: strictest wins, no negation | Replace the bullet with the decision and point to 2b |
| P2 | `design-plan.md` § CLI surface, § Flows, M3 | Still lists `xudo approve|deny <id>`, `freeze --session/--for`, and the session TTY as channel 2. M3 dropped all of these (m3-plan decisions 4 and 6) | Mark each one: dropped, or moved to M4 |
| P3 | `design-plan.md` § Caller classification | Says a diverged peer "continues as unattested". What was built: also never a watcher, and in M4 never an agent. Consistent, but not stated | Add that one line |
| P4 | `phase-3 … § 1, § 6` | Stale "no broker / no out-of-band confirmation" text (R3) | As R3 |
| P5 | `phase-3 … Deliverables` | Promises the rpm, APK, PKGBUILD and Nix packages, the SBOM, `cargo-auditable` and reproducibility for this phase, though none is planned for the beta | Move them per D4 and D6 |
| P6 | `phase-3 … § 7` table | The rows "sudo-rs directive regression" (the probe cannot catch it; the lane asserts `NOT VERIFIED`), "reproducible build" (absent) and "doas lane" (tests the install executor, not the `.deb` scripts) read as done | Give each row a status column |
| P7 | `docs/todo/README.md` verification table, row 16 | It and CONCERNS still carry the open freeze question | Close it after D2 |
| P8 | `design-plan.md` § Stack | Lists `rexpect`, `cargo-zigbuild`, `cargo-deb`, `caps`, `secrecy`, `procfs`, none of which is used (the pty tests are hand-driven; the package uses `dpkg-deb`) | Mark it "planned stack, see `Cargo.lock` for the real one", or prune it |
| P9 | `howiwork.md` § Pasban | "nothing else has access" to the log: root has access, and CONCERNS 2026-11-06 says pasban does not defend against root | Add "except root, which the chain only detects through the journal copy" |
| P10 | m3-plan § Who may watch | Says "watcher uid is the entry's caller uid, **or 0**". What was built deliberately drops the root watcher (CONCERNS 2026-11-08) | Edit the plan to match |

---

## Suggested order

1. Owner answers D1–D6.
2. One fix branch per group, each with an Opus review:
   - **Docs:** R3 and P1–P10, plus the stale-claims test.
   - **Config:** R5.
   - **Broker and wire:** R6, S1, S2.
   - **Packaging:** R4, S3–S5, R7.
   - **Release workflow:** R1, R2.
3. Merge PR #5 (D1), then the fix branches, then run `just ci` plus a dry-run tag on a fork.
4. The owner pushes `v0.1.0-beta.1` and publishes the draft release by hand (S6 at the same time).
5. Write section 3 into the M4 plan as its entry criteria before any M4 code.
