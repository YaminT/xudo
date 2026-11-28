# xudo

**sudo for AI harnesses.** xudo checks each privileged command and its exact
arguments against root-owned rules. A verified harness may run an allowed
command without a password after the operator explicitly enables the agent
path. A human-required request waits in `ido`; a denied command never runs.

> Product behavior: [howiwork.md](howiwork.md). **Beta; not externally
> audited.** See [security limits](SECURITY.md).

## Install

Download the `.deb`, `SHA256SUMS`, and `.cosign.bundle` from the [GitHub Releases](https://github.com/YaminT/xudo/releases) page.
Verify the checksum and signature as described in [howiwork.md](howiwork.md),
then install:

```sh
sudo apt install ./xudo_<ver>_<arch>.deb
```

Supported: Debian 13, Ubuntu 24.04 and 26.04, amd64 and arm64. The package
installs no passwordless rule. Passwordless harness execution is off by
default and requires service enrollment, a matching root-owned rule, and the
explicit `sudo xudo install --agent-path` opt-in (sudo or sudo-rs only), which
refuses while `kernel.yama.ptrace_scope` is 0; the broker and the gate check
the live value again on every passwordless run.

## Example

```sh
xudo explain -- /usr/bin/systemctl --no-pager --full status nginx.service
xudo exec -- /usr/bin/systemctl --no-pager --full status nginx.service
```

`explain` shows the decision and runs nothing. For a human, `exec` uses the
host's password prompt. A harness request that a rule marks `ask-human` is
queued in root-owned state for its separate reviewer to inspect in `ido`; the
broker rechecks it before running it through the password path. Unmatched and
denied commands do not run.

## How it works

The broker authenticates a harness from kernel-attested facts and a root-owned
registry, then checks the command against rules and a compiled-in deny-list.
The gate checks the request again before executing it. Rules constrain
arguments position by position. `remove-path` is a bounded typed operation;
it does not run `rm`. Rule packs can be previewed and installed only with a
review token after a root password prompt.

- [How xudo works](howiwork.md)
- [Security and reporting](SECURITY.md)
- [xudo command manual](docs/man/xudo.1)
- [Rule file manual](docs/man/xudo-rules.5)
- [Human queue manual](docs/man/ido.1)
