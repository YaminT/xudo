# Phase 5 — configuration layering and predefined profiles

Every binary needs configuration, and the question the brief asks — *where are the best configs here* — has a different answer for `aido` than for `ido`, because only one of them sits on a privilege boundary.

**Sequencing.** Split this phase. The *layering foundation* should land with M2, while there are only two consumers; precedence is the thing that is painful to retrofit once three binaries each read config their own way. The *profiles* half genuinely belongs late, once there are enough rules worth bundling.

---

## 1. The asymmetry that decides everything

`aido`'s configuration is a privilege grant. A user-writable file that can add a rule, widen a matcher, or drop a confirmation requirement is a user-writable path to root, which is why the design plan puts `/etc/aido/**` in the compiled-in deny-list's `SelfModification` class. So:

> **For `aido`, a lower layer may only narrow. For `ido`, a lower layer may configure freely.**

`ido` crosses no privilege boundary — it runs as the user, with the user's own credentials, and nothing executes without the user selecting it. There is no reason to restrict what a user may configure about their own picker. The one thing `ido`'s config must *never* be able to do is cause a queued command to run without selection. No `auto_run`, no `run_on_open`, no `trust_agent` key — not as a default, not as an option. That is the single invariant of `ido`'s config surface.

---

## 2. Where the files go

### `aido` — system-owned, following the systemd drop-in convention

Already specified in the design plan; restated here as the contract.

```
/etc/aido/config.toml            0644  global settings
/etc/aido/rules.d/*.toml         0644  actions; loaded in lexical BASENAME order
/etc/aido/deny.d/00-*.toml       0644  shipped copy, FOR OPERATOR READING ONLY
/etc/aido/agents.d/*.toml        0644  enrollment registry
/etc/aido/trust.d/*.toml         0644  the only thing that may narrow confirmation
/etc/aido/projects.d/*.toml      0644  project root -> profile binding
/etc/aido/backend.toml           0644  detected backend + probed capabilities
/etc/aido/attest.key             0600  HMAC key, regenerated per boot_id
/etc/aido/policy.generation      0644  monotonic counter + generation hash

<project>/.aido/policy.toml            NARROWING ONLY, and only when root has
                                       recorded its sha256 in projects.d
```

There is deliberately **no user-home layer for `aido`**. `~/.config/aido/` does not exist and must not be read, because a file the user can write is a file the agent can write.

Conventions worth copying exactly, each because someone got it wrong first:

- **`*.d` drop-in directories, lexical basename order, later wins** — systemd's and polkit's convention, and the one operators already know.
- **A missing include is a hard error, never a silent skip.**
- **`deny_unknown_fields` on every struct** — an unrecognised key in a root-owned rule file is a parse failure, not a warning.
- **Refuse to load if any path *component* is group- or world-writable, is a symlink, or sits on a filesystem mounted by a non-root user.** Verify on the opened fd via `fstat`, never on the path string.
- **Filenames**: no dots beyond the `.toml` suffix and no trailing tilde in anything adjacent to `sudoers.d`, since sudo silently ignores those.

### `ido` — XDG, per user

```
$XDG_CONFIG_HOME/ido/config.toml      ~/.config/ido/config.toml
$XDG_STATE_HOME/ido/queue.jsonl       ~/.local/state/ido/queue.jsonl   0600
$XDG_STATE_HOME/ido/log.jsonl         hash-chained run log
$XDG_RUNTIME_DIR/ido/lock             advisory lock; ephemeral by design
$XDG_CACHE_HOME/ido/previews/         cached --dry-run-of output, size-capped
<project>/.ido/config.toml            per-project picker preferences
```

Follow the XDG Base Directory specification with its documented fallbacks (`$HOME/.config`, `$HOME/.local/state`, `$HOME/.cache`), and respect the variables when set rather than hardcoding the defaults. Where `$XDG_RUNTIME_DIR` is unset — it often is over SSH — fall back to a `0700` directory under state and say so in `ido doctor` rather than silently choosing `/tmp`.

**Never `/tmp`** for anything in either tool. A predictable path in a world-writable directory is a symlink race, and `aido`'s own rules already forbid it.

---

## 3. Precedence

One order, documented once, identical in both tools:

```
built-in defaults
  -> system      (/etc/aido, or the OS package default for ido)
  -> user        (ido only — aido has no user layer)
  -> project     (narrowing-only for aido; free for ido)
  -> environment (NON-SECURITY KEYS ONLY)
  -> CLI flags   (highest)
```

### The environment rule

Security-relevant keys are **not settable from the environment, at any layer, in either tool.** The reason is specific: the caller controls the environment, so a safety default readable from an env var is a safety default one `export` away from off — and in `aido`'s case the agent controls the export. This is already enforced mechanically: `clap` is compiled without the `env` feature, and `clippy.toml` bans `std::env::var` in the privileged crates.

What the environment *may* set: `NO_COLOR`, `IDO_EDITOR`, the XDG variables themselves, and `AIDO_LOG` for developer diagnostics in non-release builds. Publish that list; anything not on it is ignored rather than honoured-but-undocumented.

### Contradictions are errors

`--unattended` together with `--confirm`, or `-n` with an interactive flag, is a hard parse-time error, never a silent precedence win. A user who wrote both had a wrong belief about one of them, and picking one for them preserves the wrong belief.

---

## 4. `config` introspection — the highest-value item here

Borrow from `git config --show-origin`, which solved this problem well.

```
aido config get confirm_agent_actions --origin
  true    /etc/aido/config.toml:12

aido config list --origin --effective
  confirm_agent_actions   true   /etc/aido/config.toml:12
  confirmation_timeout    60s    <built-in default>
  audit_sink              journald  /etc/aido/config.toml:19
  use_pty                 true   <compiled-in, not configurable>

aido config schema --json
  # machine-readable schema, so editors and agents can validate a file
  # before an operator installs it

ido config list --origin
```

Three properties make this worth building rather than nice-to-have:

- **Every effective value names the file and line that set it.** "Why is confirmation off?" has to have a one-command answer, or someone will answer it by guessing.
- **Compiled-in values are shown as compiled-in**, not omitted. A reader must be able to see that `use_pty` is not something they can turn off.
- **The JSON schema is exported**, so `aido check` and an editor and an agent all validate against the same definition instead of three drifting approximations.

---

## 5. Predefined profiles

"Predefined configs" from the brief. Nobody should hand-write a `docker-dev` ruleset; hand-written matchers are where the mistakes live.

| Profile | Contains | Notes |
|---|---|---|
| `minimal` | T0 diagnostics only | The default after `aido init` with no argument. Executes almost nothing. |
| `web-dev` | Service lifecycle for a named unit set, package install, `/etc/hosts` writes | The common case |
| `docker-dev` | Container **daemon lifecycle only** — start/restart `docker.service` | Explicitly *not* `docker run`; the profile's docs state that no safe subset of `docker run` exists and point at rootless podman |
| `k8s-dev` | `kubectl` context reads, no cluster writes | Cloud-consequence, routed to `ido` rather than `aido` |
| `cloud-ops` | Nothing privileged at all | Ships `ido` rules for `aws`/`gcloud` write commands. Demonstrates that the answer is often "queue it, do not allowlist it" |
| `embedded` | Serial device access, `dmesg`, specific `sysctl` keys | |
| `paranoid` | T0 only, `confirm = "always"` on every action, no grants | For evaluating the tool without trusting it yet |

Profile mechanics:

- **Composable**: `aido init --profile web-dev,docker-dev`, with the union computed and any conflict reported rather than silently resolved.
- **Signed and versioned**: `minisign` or `cosign` with a stapled inclusion proof for offline verification, plus a `min_aido_version` key. No insecure-skip path in the happy flow.
- **`schema_version` on every file**, and an **unknown matcher kind is a hard parse error, never match-anything** — the fail-open default that has bitten every policy format that permitted it.
- **Installed through the two-phase flow** from M7: stage, render a semantic *capability* diff in plain language, confirm, commit atomically, bump the generation.
- Profiles live in `/usr/share/aido/profiles/` as shipped read-only data, and installing one **copies** into `/etc/aido/rules.d/` rather than symlinking, so a package upgrade cannot silently change a policy an operator reviewed.

---

## 6. Where to look for prior art

The brief asks where the best configs are. These are the specific sources worth reading before writing the loader, and what each one contributes:

| Source | What to take |
|---|---|
| XDG Base Directory spec | The user-level directory layout and the fallback rules, for `ido` |
| systemd drop-ins | `*.d` directories, lexical basename ordering, later-wins, and the `10-`/`50-`/`99-` numbering habit |
| `sudoers.d` | The dotted-filename trap — sudo silently ignores those files. A warning, not a model |
| sudo `Defaults!Cmnd_Alias` | Per-command settings scoping, which is the shape `aido`'s per-rule `env_allow` follows |
| polkit | Action ids as the unit of authorization, and the rule that listing another principal's permissions is itself privileged |
| doas `setenv { }` | A declarative, per-rule environment clause — a better shape than a global defaults soup |
| Claude Code managed settings | The narrowing-only lower layer, copied verbatim for `<project>/.aido/policy.toml` |
| `git config --show-origin` | Origin reporting, the model for § 4 |
| Gemini CLI trusted folders | A globally-set auto-accept is *ignored* in an untrusted context rather than honoured |

---

## 7. Tests

| Test | Asserts |
|---|---|
| `precedence_is_exactly_the_documented_order` | Table-driven over every layer combination |
| `a_project_layer_cannot_widen_aido_policy` | Every widening construct — add a rule, loosen a matcher, drop a confirm, raise a limit, extend a TTL — is refused structurally, not by validation |
| `no_security_key_is_settable_from_the_environment` | Enumerate every key; assert the security subset ignores the environment |
| `an_unknown_key_fails_the_whole_file` | Both tools, every config struct |
| `an_unknown_matcher_kind_is_a_hard_error` | Never match-anything |
| `a_symlinked_path_component_refuses_to_load` | Plant a symlink at each level of `/etc/aido` |
| `a_group_writable_ancestor_refuses_to_load` | One writable ancestor defeats per-file checks |
| `origin_reporting_names_the_real_file_and_line` | For every layer, including compiled-in |
| `ido_config_cannot_enable_auto_run` | No key, no combination, produces execution without selection |
| `xdg_fallbacks_are_honoured` | With each XDG variable set, unset, and set to a relative path |
| `no_config_path_resolves_into_tmp` | Both tools, including the `$XDG_RUNTIME_DIR`-unset fallback |
| `profiles_compose_and_report_conflicts` | Union computed; conflicts surfaced |
| `an_unsigned_profile_is_refused` | And the refusal has no bypass flag |

---

## Deliverables

- `crates/aido-config` — layered loader, precedence, origin tracking, schema export. Pure, like `aido-policy`: string in, config out, no I/O.
- `aido config get|list|schema` and `ido config get|list`, all with `--origin`.
- Seven shipped profiles under `/usr/share/aido/profiles/`, signed and version-stamped.
- `aido init --profile <list>` composing from profiles rather than generating bespoke matchers.
- The precedence table documented once, in `aido-config`'s module docs, and referenced from both tools' man pages rather than restated.
