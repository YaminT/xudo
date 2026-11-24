# xudo

**xudo is `sudo` for AI agents.** Your agent (Claude Code, Codex, Grok…) calls `xudo` where it would call `sudo`. It checks two things: is this an agent harness you verified on this machine, and does a rule you wrote allow this exact command with these exact arguments? If yes, it runs as root with no password prompt. If a rule says a person must decide, the command waits in the `ido` queue until you review and run it. Anyone else gets the normal `sudo` password prompt, and a command no rule allows is refused. xudo itself never asks for or handles a password. Every decision goes into a tamper-evident log.

**What works today:** every request asks for your password. Agent enrolment and the passwordless path are not built yet, and nothing in this release creates an agent scope, so no caller counts as a registered agent. Until then an agent hands you privileged work with `ido queue --root -- <command>`; you run it from `ido`, and `sudo` asks for your password.

## How it works (the design; steps 2 and 4 are not built yet)

1. You install one package and choose rule files: what agents may run, down to each argument.
2. You verify a harness once: on a server the admin registers it; on a laptop you type your sudo password once per session.
3. The agent runs `xudo exec -- <command>`. A root service checks who is asking (from the kernel, not from names) and matches the command against the rules.
4. Allowed: runs as root now, with no password. Needs a person: waits in `ido`. Anyone else: the normal `sudo` password prompt. A command no rule allows: refused. A built-in deny-list refuses shells and other escapes whatever the rules say.
5. Everything is recorded in a log that shows any tampering.

> This README is a derived view of [howiwork.md](howiwork.md), the source of truth for product behavior.

## Install

v0.1.0-beta.2 is a pre-release. Download the `.deb`, `SHA256SUMS`, and its `.cosign.bundle` from the GitHub Release, then verify both the checksum and the exact GitHub Actions identity before installing. Replace `<ver>` with the Debian version, `<arch>` with `amd64` or `arm64`, and `<tag>` with the Git tag; for example, `<ver>` `0.1.0~beta.2` corresponds to `<tag>` `v0.1.0-beta.2`:

GitHub shows the `~` in the Debian version as `.` on the Release page, so the file you download is named with a `.`.

```sh
sed 's/~/./' SHA256SUMS | sha256sum -c --ignore-missing
cosign verify-blob --bundle xudo_<ver>_<arch>.deb.cosign.bundle --certificate-identity https://github.com/YaminT/xudo/.github/workflows/release.yml@refs/tags/<tag> --certificate-oidc-issuer https://token.actions.githubusercontent.com xudo_<ver>_<arch>.deb
sudo apt install ./xudo_<ver>_<arch>.deb
```

xudo has no `curl | sh` installer because a privileged shell script is difficult to inspect before execution.

The broker requires systemd and journald. Without them every privileged request is refused; `systemd` is recommended by the package and may be omitted by explicitly installing without recommendations.

## Supported platforms

Debian 13, Ubuntu 24.04 LTS and Ubuntu 26.04 LTS, on amd64 and arm64. Other releases and distributions are not supported for now. The agent path needs Linux 6.5 or later; it is not yet shipped.

## Example

From a checkout, inspect the shipped rules with `--rules ./rules`:

```sh
xudo --rules ./rules explain -- /usr/bin/systemctl --no-pager --full status nginx.service
xudo doctor
ido queue -m "show listeners after review" -- /usr/bin/ss -tulpnH
```

`explain` shows the policy decision and executes nothing. `exec` ignores `--rules`. The installed broker loads root's `/etc/xudo/rules.d`. The shipped rules do not start or stop a service. To allow that on one host, copy `/usr/share/xudo/examples/20-services-lifecycle.toml` to `/etc/xudo/rules.d/` and replace the placeholder unit names. After installing the package, add your user to the `xudo` group (`sudo usermod -aG xudo YOUR_USER`, then log out and back in). This is a deliberate privilege grant: the group can invoke the installed password-authenticated gate.

Then run `xudo exec -- /usr/bin/systemctl --no-pager --full status nginx.service`. `exec` asks the broker. If a rule permits the command, the host's privilege backend prompts for a password and the gate runs it. Until agent enrolment ships, an agent hands you privileged work with `ido queue --root -- <command>`. You run it from `ido`, `ido` calls `xudo exec`, and `sudo` asks for your password. The root-held review queue (`xudo exec --queued ID`) is in the code but stays empty until then: nothing in this release creates an agent scope. Human-path denials are not copied into the caller's editable `ido` queue.

`xudo op remove-path /srv/app/build/cache` removes that path when an `[[operation]]` rule names the tree. It does not run `rm`. `--dry-run` lists the paths and removes nothing. The example is `rules/examples/50-remove-path.toml.example`, installed as `/usr/share/xudo/examples/50-remove-path.toml`. Copy it into `/etc/xudo/rules.d/` and set `under` to a tree whose ancestors are root-owned and not writable by group or other. The rule's `harness` list is parsed and checked against the registry and is not a grant. Harness use of this operation is not built yet. This release runs it only on the password path.

## Status

**Beta (v0.1.0-beta.2). Not externally audited.** Do not deploy it where a compromise would matter. The rule format and command line may still change.

**Works today.** `xudo exec` sends your command to a root service, the broker. The broker checks it against the rules in `/etc/xudo/rules.d` and a built-in refusal list, and writes the decision to a hash-chained audit log. It then hands the command through `sudo` to a separate root program, the gate. `sudo` asks for the password, and the gate checks the rules again before it runs anything. Other tools: `xudo check` tests rule files, `xudo doctor` lists other ways to get root on the machine, `xudo op remove-path` removes a tree an `[[operation]]` rule names, and a daily job (Pasban) verifies the audit log. The same rules behave the same through sudo, sudo-rs and OpenDoas. An optional extra check typed into `xudo watch` exists on this password path and is off by default (`confirm_human_path = false`).

**In the code, not usable yet.** A harness registry (`/etc/xudo/harnesses.d`), the rule keys `harness` and `outcome = "ask-human"`, and a root-held review queue (`xudo exec --queued ID`, shown by `ido`). They act only for a caller that the kernel places in a scope root made for a registered agent. Nothing in this release creates such a scope.

**Not built yet.** Agent enrolment, passwordless runs for a registered agent, rule packs, temporary permissions, `xudo setup` and an apt repository. The passwordless agent path and Landlock confinement are not in this release.

The rules are the boundary; the deny-list is a safety net. `xudo doctor` reports some other paths to root but cannot prove there are none. The audit log records decisions, not whether a command finished. The doas install probe reports NOT VERIFIED.

Details and limits: [SECURITY.md](SECURITY.md). The default build has no network code or telemetry; CI checks that with a system-call trace (see the FAQ below).

The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a regular file, so stock Ubuntu 26.04 verifies. It reports `installed, but NOT VERIFIED` on doas and on a multicall-coreutils system with no regular probe program, such as Alpine.

The audit trail records authorization, not execution outcomes. Pasban runs daily as root. It verifies the audit chain and compares journal copies with the file by hash. It detects removed tails, cut-and-continued files, and forged chains the journal never saw. It does not prevent privileged tampering or prove that a command completed.

## Rule format

Rules are TOML files. An action fixes the executable and constrains each argument by position. `rules/20-services.toml` clears a failed service state and reloads unit files. It does not start or stop a service. A start/stop rule ships only as an example, `rules/examples/20-services-lifecycle.toml.example`: an operator copies it into `rules.d` and lists real unit names. An `[[operation]]` rule names work xudo performs itself. `remove-path` is the shipped operation, and it runs on the password path. The example at `rules/examples/50-remove-path.toml.example` is not loaded until an operator copies it into `rules.d`.

Agent registrations go in root-owned `/etc/xudo/harnesses.d/<label>.toml` files (keys `label`, `way`, `account` or `users`, `reviewers`, `max-sessions`; see xudo-rules(5)). An action may list labels with `harness = ["codex"]` and set `outcome = "ask-human"`. Such a request from that agent would wait in a root-held queue. A person named in `reviewers`, other than the agent's own account, runs it with `xudo exec --queued ID`, and `sudo` asks for the password. None of this can trigger yet, because nothing in this release creates an agent scope. `outcome = "allow"` grants nothing extra today. The package ships `/etc/xudo/harnesses.d` empty.

The root setting `queue_ttl_secs` controls how long an ask-human entry stays live. It defaults to 86400 seconds and is capped at one day; a project config may only shorten it. Shortening the setting also expires older entries at the new deadline.

```toml
[[action]]
id = "xudo.svc.reset-failed"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "verb", matcher = { literal = "reset-failed" } },
  { name = "unit", matcher = { name = "service-unit-name" } },
]
```

There are no argument globs. Each argument is constrained by position. The shipped rules are the TOML files under [rules/](rules/). The lifecycle example is not one of them.

A rule file can also hold `[[deny]]` tables, which refuse a command an action would accept: `id`, `reason`, `program` (executable names), and `all`, a list of clauses that use `any-arg` or `any-deb-name`. It can also hold `[[test]]` tables that state the expected decision. `xudo check` lints and tests the rules and exits 20 for a warning, 21 for an error and 22 for a failing test. See xudo-rules(5).

The package also installs `rules/00-protect.toml`, active by default. Through xudo it refuses to remove xudo, sudo, sudo-rs, AppArmor, auditd, firewalls, logging, time sync or the SSH server. It cannot stop the host's own `apt` or `dpkg`, and it cannot stop a removal that apt pulls in through dependencies (for example, removing `openssh-client` can remove `openssh-server`). `xudo doctor` warns when a protect rule is missing. xudo also refuses, through itself, to write to its own files and binaries, including `/usr/bin/xudo`, `/usr/bin/ido` and `/usr/bin/willyoumarryme`. [SECURITY.md](SECURITY.md) has the full list.

## FAQ

### What is the difference between `xudo` and `sudo`?

`sudo` is the host's privilege transition. `xudo` checks a named-action policy first, asks a root broker to authorize the request, and sends an approved request through a separate gate. Every command that runs goes through the human password path today.

### Can an AI agent run any command with `xudo`?

No. A command must match an action in the root-owned rules and pass the compiled-in deny-list. This release also asks for a password on each privileged request.

### Is this safe? What are the limits?

This is beta software and has not been externally audited. A broad rule can give broad root access; the built-in refusal list is a safety net, not a complete boundary; and other ways to root on the host are outside xudo's control. Agent detection is not a security boundary; the rules are. See [Status](#status) and [SECURITY.md](SECURITY.md).

### Does this work with Claude Code, Codex CLI, Gemini CLI, or Aider?

Yes. Any harness that can run a command can call `xudo exec`. The rules do not depend on a particular agent. This beta cannot register an agent, so it cannot tell an agent from you and has no passwordless mode. An agent can call `xudo exec`, and `sudo` then asks a human for the password. Or it can queue the command with `ido queue --root` for you to run.

### What happens if an agent lies about being an agent?

Nothing changes. Names and environment variables never grant anything. Only a harness root registered, running inside the scope the kernel tracks for it, could ever run commands without a password, and only what its rules allow. Nothing in this release creates such a scope, so lying gains nothing today: every request asks for a password.

### How is this different from `NOPASSWD: ALL`?

The package installs only the password-authenticated gate rule. It does not install a `NOPASSWD` rule. Rules name executables and constrain arguments; the gate checks the request again before execution.

### Does it work with `doas`? With `sudo-rs`?

The package depends on `sudo`, so package installs use sudo for both `xudo install` and `xudo exec`. doas works only with a hand install on a host without sudo; its install probe always reports NOT VERIFIED. Detection and execution prefer sudo. sudo-rs 0.2 is refused at detection; newer sudo-rs, including Ubuntu 26.04's version, works.

### Does it phone home?

The default build has no network code or telemetry. CI traces the shipped release-musl binaries (`xudo`, `ido`, and `xudo-gate-auth`) across selected commands, failing on socket families outside `AF_UNIX`/`AF_LOCAL`; it also checks their normal Cargo dependency tree for known networking crates.

## More documentation

- [howiwork.md](howiwork.md): source of truth for behavior
- [SECURITY.md](SECURITY.md): reporting route and security limits
- [docs/crates.md](docs/crates.md): workspace crates
- [docs/man/](docs/man/): available manual pages

## License

Apache-2.0. See [LICENSE](LICENSE).
