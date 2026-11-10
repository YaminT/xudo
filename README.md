# xudo

xudo is a Linux privilege broker. It checks commands against root-owned rules and uses the host's `sudo`, `sudo-rs`, or `doas` for privileged execution. This beta uses the human password path for every request.

> This README is a derived view of [howiwork.md](howiwork.md), the source of truth for product behavior.

## Install

No release has been published yet. When one is available, download the `.deb`, `SHA256SUMS`, and its `.cosign.bundle` from the GitHub Release, then verify both the checksum and the exact GitHub Actions identity before installing. Replace `<ver>` with the Debian version, `<arch>` with `amd64` or `arm64`, and `<tag>` with the Git tag; for example, `<ver>` `0.1.0~beta.1` corresponds to `<tag>` `v0.1.0-beta.1`:

```sh
sha256sum -c SHA256SUMS --ignore-missing
cosign verify-blob --bundle xudo_<ver>_<arch>.deb.cosign.bundle --certificate-identity https://github.com/YaminT/xudo/.github/workflows/release.yml@refs/tags/<tag> --certificate-oidc-issuer https://token.actions.githubusercontent.com xudo_<ver>_<arch>.deb
sudo apt install ./xudo_<ver>_<arch>.deb
```

xudo has no `curl | sh` installer because a privileged shell script is difficult to inspect before execution.

## Example

From a checkout, inspect the example rules with `--rules ./rules`:

```sh
xudo --rules ./rules explain -- /usr/bin/systemctl --no-pager --no-ask-password restart nginx.service
xudo doctor
ido queue -m "restart nginx after review" -- /usr/bin/systemctl restart nginx.service
```

`explain` shows the policy decision and executes nothing. `exec` ignores `--rules`. The installed broker loads root's `/etc/xudo/rules.d`. After installing the package, add your user to the `xudo` group (`sudo usermod -aG xudo YOUR_USER`, then log out and back in). This is a deliberate privilege grant: the group can invoke the installed password-authenticated gate.

Then run `xudo exec -- /usr/bin/systemctl --no-pager --no-ask-password restart nginx.service`. `exec` asks the broker. If a rule permits the command, the host's privilege backend prompts for a password and the gate runs it. `ido queue` stores exact arguments for a human to review and run with `ido`.

## Security status

**Beta. Not externally audited.** The rule-file format and command-line interface may change, and an upgrade may require rule edits. Do not deploy this where a compromise would matter.

Agent detection is not a security boundary. The passwordless agent path is not in this release, so a successful impersonation cannot skip the password today. The allowlist is the boundary; the compiled-in deny-list is defense in depth because the set of programs that can become a root shell is not enumerable. `xudo doctor` reports some other paths to root, but cannot prove that a host has none.

The broker and password-authenticated gate are built and packaged. Out-of-band confirmation through `xudo watch` is built but off by default; every path still requires the password. The passwordless agent path and Landlock confinement are not in this release. The default build has no network code or telemetry. CI traces the shipped release-musl binaries (`xudo`, `ido`, and `xudo-gate-auth`) across selected commands, failing on socket families outside `AF_UNIX`/`AF_LOCAL`; it also checks their normal Cargo dependency tree for known networking crates.

The install probe reports `installed, but NOT VERIFIED` on doas and multicall-coreutils systems. Examples include stock Ubuntu 26.04 and Alpine, where `/usr/bin/id` is uutils or a multicall applet. The Ubuntu 26.04 systemd and differential lanes pass because they install GNU `id`.

The audit trail records authorization, not execution outcomes. Pasban runs daily as root. It verifies the audit chain and compares journal copies with the file by hash. It detects removed tails, cut-and-continued files, and forged chains the journal never saw. It does not prevent privileged tampering or prove that a command completed.

## How it works

`xudo explain` loads the selected rules and reports what the policy would decide. For `xudo exec`, the front end sends the request to the root broker over a Unix socket. The broker identifies the connected peer from kernel-provided facts, checks the root-owned rules and deny-list, and records the authorization decision. If permitted, it creates a bounded one-use request. The host's `sudo`, `sudo-rs`, or `doas` performs the uid transition through the password-authenticated gate. The gate independently checks policy and the one-use request before executing the validated program. Errors fail closed.

Every caller is currently classified as unattested. The beta therefore uses the password path for every invocation; no `NOPASSWD` rule is installed by the package.

## Rule format

Rules are TOML files. An action fixes the executable and constrains each argument by position. For example, `rules/20-services.toml` allows a limited set of service lifecycle verbs:

```toml
[[action]]
id = "xudo.svc.lifecycle"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "no-ask", matcher = { literal = "--no-ask-password" } },
  { name = "verb", matcher = { one-of = ["start", "stop", "restart", "try-restart", "reload", "reload-or-restart", "try-reload-or-restart"] } },
  { name = "unit", matcher = { name = "unit-name" } },
]
```

There are no argument globs. The native format and matcher behavior are documented in [docs/design-plan.md](docs/design-plan.md) and the shipped TOML rules under [rules/](rules/).

## FAQ

### What is the difference between `xudo` and `sudo`?

`sudo` is the host's privilege transition. `xudo` checks a named-action policy first, asks a root broker to authorize the request, and sends an approved request through a separate gate. In this beta, every invocation uses the human password path.

### Can an AI agent run any command with `xudo`?

No. A command must match an action in the root-owned rules and pass the compiled-in deny-list. This beta also requires the host's password prompt for each privileged request.

### Is this safe? What are the limits?

This is beta software and has not been externally audited. A broad rule can grant broad root access, the deny-list is not a complete boundary, and other host paths to root remain outside xudo's control. Agent detection is not a security boundary; the allowlist is. The passwordless agent path, out-of-band confirmation, and Landlock confinement are not in this release.

### Does this work with Claude Code, Codex CLI, Gemini CLI, or Aider?

The policy engine does not depend on a particular agent. This beta does not enroll or authenticate agents, and it does not provide passwordless agent execution. Any caller that gets permission still follows the host password path.

### What happens if an agent lies about being an agent?

Agent names and environment variables do not authorize a request. Kernel-attested identity is required for the future passwordless path, which is not in this beta. Today every caller is unattested and uses the password path.

### How is this different from `NOPASSWD: ALL`?

The package installs only the password-authenticated gate rule. It does not install a `NOPASSWD` rule. Rules name executables and constrain arguments; the gate checks the request again before execution.

### Does it work with `doas`? With `sudo-rs`?

The package depends on `sudo`, so package installs use sudo for both `xudo install` and `xudo exec`. doas works only with a hand install on a host without sudo; its install probe always reports NOT VERIFIED. Detection and execution prefer sudo. sudo-rs 0.2 is refused at detection; newer sudo-rs, including Ubuntu 26.04's version, works.

### Does it phone home?

The default build has no network code or telemetry. CI traces the shipped release-musl binaries (`xudo`, `ido`, and `xudo-gate-auth`) across selected commands, failing on socket families outside `AF_UNIX`/`AF_LOCAL`; it also checks their normal Cargo dependency tree for known networking crates.

## More documentation

- [howiwork.md](howiwork.md): source of truth for behavior
- [SECURITY.md](SECURITY.md): reporting route and security limits
- [docs/design-plan.md](docs/design-plan.md): architecture and threat model
- [docs/man/](docs/man/): available manual pages
- [CLAUDE.md](CLAUDE.md): contributor and engineering rules

## License

Apache-2.0. See [LICENSE](LICENSE).
