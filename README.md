# xudo

xudo is a Linux privilege broker. It checks commands against root-owned rules and uses the host's `sudo`, `sudo-rs`, or `doas` for privileged execution. Every command that runs still goes through the human password path.

> This README is a derived view of [howiwork.md](howiwork.md), the source of truth for product behavior.

## Install

v0.1.0-beta.2 is a pre-release. Download the `.deb`, `SHA256SUMS`, and its `.cosign.bundle` from the GitHub Release, then verify both the checksum and the exact GitHub Actions identity before installing. Replace `<ver>` with the Debian version, `<arch>` with `amd64` or `arm64`, and `<tag>` with the Git tag; for example, `<ver>` `0.1.0~beta.1` corresponds to `<tag>` `v0.1.0-beta.1`:

GitHub shows the `~` in the Debian version as `.` on the Release page, so the file you download is named with a `.`. Verify the checksum with `sed 's/~/./' SHA256SUMS | sha256sum -c --ignore-missing`.

```sh
sed 's/~/./' SHA256SUMS | sha256sum -c --ignore-missing
cosign verify-blob --bundle xudo_<ver>_<arch>.deb.cosign.bundle --certificate-identity https://github.com/YaminT/xudo/.github/workflows/release.yml@refs/tags/<tag> --certificate-oidc-issuer https://token.actions.githubusercontent.com xudo_<ver>_<arch>.deb
sudo apt install ./xudo_<ver>_<arch>.deb
```

Each release also carries a CycloneDX SBOM, `xudo-<version>.cdx.json` (`<version>` is Cargo's spelling, for example `0.1.0-beta.1`), listing every crate the shipped binaries link, as resolved for the two musl targets, with its `Cargo.lock` version and checksum. It is signed like the package; verify it with the same identity:

```sh
cosign verify-blob --bundle xudo-<version>.cdx.json.cosign.bundle --certificate-identity https://github.com/YaminT/xudo/.github/workflows/release.yml@refs/tags/<tag> --certificate-oidc-issuer https://token.actions.githubusercontent.com xudo-<version>.cdx.json
```

The four binaries also embed that dependency list (`cargo-auditable`). Read it from an installed binary with `cargo audit bin /usr/bin/xudo`. That embedded list may name a crate the binary does not link (`errno`); the SBOM does not. Building the package (`just deb`) needs `cargo-auditable` 0.7.7.

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

`xudo op remove-path /srv/app/build/cache` removes that path when an `[[operation]]` rule names the tree. It does not run `rm`. `--dry-run` lists the paths and removes nothing. The example is `rules/examples/50-remove-path.toml.example`, installed as `/usr/share/xudo/examples/50-remove-path.toml`. Copy it into `/etc/xudo/rules.d/` and set `under` to a tree whose ancestors are root-owned and not writable by group or other. With `harness` and `outcome = "allow"`, a live enrolled harness the rule lists runs it through the `-nopass` gate without a password, the same walk; everyone else uses the password path. The package installs no sudoers line for `-nopass`, so out of the box that path is refused.

## Security status

**Beta. Not externally audited.** The rule-file format and command-line interface may change, and an upgrade may require rule edits. Do not deploy this where a compromise would matter.

Agent detection is not a security boundary. The passwordless agent path is not in this release, so a successful impersonation cannot skip the password today. The allowlist is the boundary; the compiled-in deny-list is defense in depth because the set of programs that can become a root shell is not enumerable. `xudo doctor` reports some other paths to root, but cannot prove that a host has none.

The policy engine, the backend model, the broker, the gate and the audit trail are built and tested (2026-10-30): the broker mints entries, the gate consumes one and runs it as root, `xudo exec` and `xudo install` ask the broker, both write one hash-chained audit trail, and the same ruleset behaves the same through sudo, sudo-rs and OpenDoas. Out-of-band confirmation via `xudo watch` is off by default, and every path still requires the password. The broker runs under its real systemd sandbox, and Pasban verifies the audit chain daily. The doas install probe remains NOT VERIFIED. Not yet built: enrollment and the passwordless agent path, temporary permissions, narrowing and volume controls, more ergonomics, and confinement with an external audit. `confirm_human_path=false` by default. `just telemetry` runs the strace no-telemetry check, also run by the CI job “no telemetry”. The passwordless agent path and Landlock confinement are not in this release.

The install probe runs `/usr/bin/gnuid -u` when `/usr/bin/id` is not a regular file, so stock Ubuntu 26.04 verifies. It reports `installed, but NOT VERIFIED` on doas and on a multicall-coreutils system with no regular probe program, such as Alpine.

The audit trail records authorization, not execution outcomes. Pasban runs daily as root. It verifies the audit chain and compares journal copies with the file by hash. It detects removed tails, cut-and-continued files, and forged chains the journal never saw. It does not prevent privileged tampering or prove that a command completed.

## How it works

`xudo explain` loads the selected rules and reports what the policy would decide. For `xudo exec`, the front end sends the request to the root broker over a Unix socket. The broker identifies the connected peer from kernel-provided facts, checks the root-owned rules and deny-list, and records the authorization decision. If permitted, it creates a bounded one-use request. The host's `sudo`, `sudo-rs`, or `doas` performs the uid transition through the password-authenticated gate. The gate independently checks policy and the one-use request before executing the validated program. Errors fail closed.

The broker can classify a caller as a verified harness only from kernel-attested scope facts and the root-owned registry. No passwordless gate rule is installed by the package; human and unattested callers use the password path. An ask-human harness request waits in the broker queue until a human reviewer runs `xudo exec --queued ID`.

## Rule format

Rules are TOML files. An action fixes the executable and constrains each argument by position. `rules/20-services.toml` clears a failed service state and reloads unit files. It does not start or stop a service. That rule is the example at `rules/examples/20-services-lifecycle.toml.example`: an operator copies it into `rules.d` and replaces the placeholder unit names. An `[[operation]]` rule names work xudo performs itself. `remove-path` is the shipped operation, and it runs on the password path unless the rule grants a harness. The example at `rules/examples/50-remove-path.toml.example` is not loaded until an operator copies it into `rules.d`.

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

This is beta software and has not been externally audited. A broad rule can grant broad root access, the deny-list is not a complete boundary, and other host paths to root remain outside xudo's control. Agent detection is not a security boundary; the allowlist is. The policy engine, the backend model, the broker, the gate and the audit trail are built and tested (2026-10-30): the broker mints entries, the gate consumes one and runs it as root, `xudo exec` and `xudo install` ask the broker, both write one hash-chained audit trail, and the same ruleset behaves the same through sudo, sudo-rs and OpenDoas. Out-of-band confirmation via `xudo watch` is off by default, and every path still requires the password. The broker runs under its real systemd sandbox, and Pasban verifies the audit chain daily. The doas install probe remains NOT VERIFIED. Not yet built: enrollment and the passwordless agent path, temporary permissions, narrowing and volume controls, more ergonomics, and confinement with an external audit. `confirm_human_path=false` by default. `just telemetry` runs the strace no-telemetry check, also run by the CI job “no telemetry”. The passwordless agent path and Landlock confinement are not in this release.

### Does this work with Claude Code, Codex CLI, Gemini CLI, or Aider?

The policy engine does not depend on a particular agent. This beta does not enroll or authenticate agents, and it does not provide passwordless agent execution. Any caller that gets permission still follows the host password path.

### What happens if an agent lies about being an agent?

Agent names and environment variables do not authorize a request. The broker requires kernel-attested scope facts and a matching root-owned registry entry. This release does not install a passwordless gate rule.

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
