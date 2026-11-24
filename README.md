# xudo

**xudo is `sudo` for AI agents.** Your agent (Claude Code, Codex, Grok…) calls `xudo` where it would call `sudo`. It checks two things: is this an agent harness you verified on this machine, and does a rule you wrote allow this exact command with these exact arguments? If yes, it runs as root with no password prompt. If a rule says a person must decide, the command waits in the `ido` queue until you review and run it. Anyone else gets the normal `sudo` password prompt, and a command no rule allows is refused. xudo itself never asks for or handles a password. Every decision goes into a tamper-evident log.

Today's beta asks your password for every request. The passwordless path for verified agents is being built.

## How it works (the design; steps 2 and 4 are being built)

1. You install one package and choose rule files: what agents may run, down to each argument.
2. You verify a harness once: on a server the admin registers it; on a laptop you type your sudo password once per session.
3. The agent runs `xudo exec -- <command>`. A root service checks who is asking (from the kernel, not from names) and matches the command against the rules.
4. Allowed: runs as root now, with no password. Needs a person: waits in `ido`. Anyone else: the normal `sudo` password prompt. A command no rule allows: refused. A built-in deny-list refuses shells and other escapes whatever the rules say.
5. Everything is recorded in a log that shows any tampering.

> This README is a derived view of [howiwork.md](howiwork.md), the source of truth for product behavior.

## Install

v0.1.0-beta.2 is a pre-release. Download the `.deb`, `SHA256SUMS`, and its `.cosign.bundle` from the GitHub Release, then verify both the checksum and the exact GitHub Actions identity before installing. Replace `<ver>` with the Debian version, `<arch>` with `amd64` or `arm64`, and `<tag>` with the Git tag; for example, `<ver>` `0.1.0~beta.1` corresponds to `<tag>` `v0.1.0-beta.1`:

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

Then run `xudo exec -- /usr/bin/systemctl --no-pager --full status nginx.service`. `exec` asks the broker. If a rule permits the command, the host's privilege backend prompts for a password and the gate runs it. A verified harness request matching an `ask-human` action is stored in the broker's root-held queue. A human reviewer runs it with `xudo exec --queued ID`: the broker re-decides the stored argv, sudo asks for the password, and the command runs in `/`. `ido` lists that queue separately from the user-side queue, which stays labelled as written by the agent and editable by it. Human-path denials are not copied into the caller's editable `ido` queue. The passwordless gate is not in this release.

`xudo op remove-path /srv/app/build/cache` removes that path when an `[[operation]]` rule names the tree. It does not run `rm`. `--dry-run` lists the paths and removes nothing. The example is `rules/examples/50-remove-path.toml.example`, installed as `/usr/share/xudo/examples/50-remove-path.toml`. Copy it into `/etc/xudo/rules.d/` and set `under` to a tree whose ancestors are root-owned and not writable by group or other. The rule's `harness` list is parsed and checked against the registry and is not a grant. Harness use of this operation is planned. This release runs it only on the password path.

## Status

**Beta (v0.1.0-beta.2). Not externally audited.** Do not deploy it where a compromise would matter. The rule format and command line may still change.

- Built: the rules and built-in deny-list, the root service and gate, `xudo exec`, `xudo install`, `xudo doctor`, the `ido` queue, and the tamper-evident audit log, checked daily. The same rules behave the same through sudo, sudo-rs and OpenDoas.
- In this release every privileged request asks for a password. The passwordless agent path and Landlock confinement are not in this release.
- Being built: verified harnesses, rule-allowed commands without a password, and a root-held queue for commands that need a person.
- An optional extra confirmation for people (`xudo watch`, `confirm_human_path`) is built and off by default.
- The rules are the boundary; the deny-list is a safety net. `xudo doctor` reports some other paths to root but cannot prove there are none. The audit log records decisions, not whether a command finished. The doas install probe reports NOT VERIFIED.

Details and limits: [SECURITY.md](SECURITY.md). The default build has no network code; `just telemetry` runs the strace no-telemetry check in CI.

The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a regular file, so stock Ubuntu 26.04 verifies. It reports `installed, but NOT VERIFIED` on doas and on a multicall-coreutils system with no regular probe program, such as Alpine.

The audit trail records authorization, not execution outcomes. Pasban runs daily as root. It verifies the audit chain and compares journal copies with the file by hash. It detects removed tails, cut-and-continued files, and forged chains the journal never saw. It does not prevent privileged tampering or prove that a command completed.

## Rule format

Rules are TOML files. An action fixes the executable and constrains each argument by position. `rules/20-services.toml` clears a failed service state and reloads unit files. It does not start or stop a service. That rule is the example at `rules/examples/20-services-lifecycle.toml.example`: an operator copies it into `rules.d` and replaces the placeholder unit names. An `[[operation]]` rule names work xudo performs itself. `remove-path` is the shipped operation, and it runs on the password path. The example at `rules/examples/50-remove-path.toml.example` is not loaded until an operator copies it into `rules.d`.

Harness registrations live in root-owned `/etc/xudo/harnesses.d/<label>.toml` files. An action may name labels with `harness = ["codex"]` and set `outcome = "ask-human"`; a verified matching request is stored by the broker. A human reviewer, and not the entry's owner, claims it with `xudo exec --queued ID`. The broker re-decides the stored bytes against the current rules and, only if they still match, asks for the password through the `-auth` gate. `ido` shows that queue separately from the agent-editable list. `outcome = "allow"` does not create a passwordless grant in this release. The passwordless gate is not installed.

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

The package also ships `rules/00-protect.toml` as an active dpkg conffile. It refuses removal of `xudo`, `sudo`, `sudo-rs`, AppArmor, audit, firewall, logging, time-sync, and SSH server packages through the shipped `apt-get remove` action. Its purge, autoremove, auto-remove, autopurge, trailing-hyphen install, and dpkg clauses also protect later operator actions that name `apt`, `apt-get`, or `dpkg`; `xudo check` and `xudo doctor` report when one of those deny rules is inert because no loaded action runs its program. These rules protect xudo-mediated commands only. They cannot stop the host's own package tools or dependency/conflict transactions that indirectly remove packages. For example, removing `openssh-client` can remove `openssh-server`; removing `libip4tc2`, `libxtables12`, `libnftables1`, `python3`, or `init-system-helpers` can remove `iptables`, `nftables`, `ufw`, `firewalld`, or xudo. Installing `sudo-ldap` can also remove a conflicting package. `xudo doctor` reports if a shipped protect rule is missing or inert. The compiled-in path checks also protect `/usr/bin/xudo`, `/usr/bin/ido`, `/usr/bin/willyoumarryme`, and xudo's private files from xudo-mediated writes.

## FAQ

### What is the difference between `xudo` and `sudo`?

`sudo` is the host's privilege transition. `xudo` checks a named-action policy first, asks a root broker to authorize the request, and sends an approved request through a separate gate. Commands that run use the human password path. An `ask-human` harness request waits in the root-held queue until a human reviewer runs `xudo exec --queued ID`, which asks for the password again.

### Can an AI agent run any command with `xudo`?

No. A command must match an action in the root-owned rules and pass the compiled-in deny-list. This beta also requires the host's password prompt for each privileged request.

### Is this safe? What are the limits?

Beta, not externally audited. A broad rule gives broad root access, the deny-list is a safety net and not a complete boundary, and other paths to root on the machine are outside xudo's control. See [SECURITY.md](SECURITY.md).

### Does this work with Claude Code, Codex CLI, Gemini CLI, or Aider?

Yes. Any harness that can run a command can call `xudo exec`. xudo does not trust a program's name: a harness is verified by the machine, registered once by root. In this release no harness is verified yet, so every request asks for a password.

### What happens if an agent lies about being an agent?

Nothing changes. Names and environment variables never grant anything. Only a harness root registered, running inside the scope the kernel tracks for it, can run commands without a password, and only what its rules allow. In this release every request asks for a password.

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
