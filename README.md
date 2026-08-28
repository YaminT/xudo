# aido

**A sudo alternative that lets AI coding agents run an allowlisted set of
privileged commands without a password, while always prompting humans.**
Root-owned rule set, compiled-in deny-list, full decision trace. Rust, Linux.

> ## Beta. Not externally audited. No privileged path yet.
>
> This build **cannot execute anything as root.** `aido explain`, `check`,
> `list`, `config`, `doctor`, and `agentdoc` inspect the policy and execute
> nothing. The passwordless agent path, the broker, and out-of-band confirmation
> are not in this release. See [docs/re.md](docs/re.md) for what is left.

## The problem

An agent hits a command needing root. Today you either answer every `sudo`
prompt yourself — which ends unattended work — or you grant `NOPASSWD: ALL`,
which is a standing root backdoor for **any** process running as that user.

`aido` is the middle path: a root-owned allowlist of *named actions*. Enrolled
agent sessions run allowlisted actions passwordless; a human invoking `aido` is
always prompted; a catastrophic-command deny-list is compiled into the binary and
cannot be edited by configuration.

## Agent detection is not a security boundary

Said here rather than left for a critic to find.

`aido`'s premise makes the *absence* of proof-of-humanity the thing that grants a
privilege, and every cheap signal that a caller is an agent is produced by the
caller: `CLAUDECODE=1` is an environment variable anyone can export, `argv[0]` is
chosen by whoever exec'd, `/proc/<pid>/exe` points into a user-writable `$HOME`.
Even with unforgeable enrollment, a human can ask a genuinely-enrolled agent to
run the command — indistinguishable at the syscall layer.

So a successful impersonation buys exactly one thing: **skipping the password on
an action that is already allowlisted.** It buys no new capability. The real
boundary is the allowlist, the deny-list, and out-of-band confirmation. Size the
allowlist on the assumption that every entry will eventually be run passwordless
by a process you cannot authenticate.

The compiled-in deny-list is **defence in depth, not the boundary** — the set of
programs that can be turned into a root shell is not enumerable.

## Try it

Nothing here touches privilege.

```
aido --rules ./rules explain -- --no-pager --no-ask-password restart nginx.service
aido --rules ./rules explain -- -c            # a rule allowlisting /bin/sh is still refused
aido --rules ./rules doctor                   # backend, capabilities, and every other path to root
aido --rules ./rules config --schema          # machine-readable settings schema
```

`explain` prints which rule matched at which `file:line`, the canonical argv, the
deny-list verdict, and a stable machine-readable envelope under
`--output json` — because the primary consumer is a language model, and `exit 1`
with a prose message is the worst possible interface for one.

## How rules work

A rule allowlists a **named action** whose executable is fixed and whose
arguments are constrained position by position. No globs, anywhere:

```toml
[[action]]
id = "aido.svc.lifecycle"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "no-pager", matcher = { literal = "--no-pager" } },
  { name = "verb", matcher = { one-of = ["start", "stop", "restart", "reload"] } },
  { name = "unit", matcher = { name = "unit-name" } },
]
```

`sudoers` matches arguments by joining them into one string and running
`fnmatch`, so `*` crosses whitespace *and* matches `/` — which makes
`/usr/bin/python3 /opt/utils/*.py` a root shell. There is no wildcard here at
any position.

## Building

Requires the pinned toolchain in `rust-toolchain.toml`.

```
just setup     # git hooks + toolchain
just verify    # the full gate; identical to CI
```

The gate is 100% line, region, and function coverage with no line-level waivers,
zero clippy warnings, `cargo deny`, miri, and three fuzz targets. Fuzzing found a
real bug in argv canonicalization on its first run; the story is in
[docs/CONCERNS.md](docs/CONCERNS.md).

## Documentation

| File | What it is |
|---|---|
| [docs/re.md](docs/re.md) | Current blockers |
| [docs/CONCERNS.md](docs/CONCERNS.md) | Running decision log — read this before changing anything |
| [docs/design-plan.md](docs/design-plan.md) | Full architecture and threat model |
| [docs/todo/](docs/todo/) | Remaining phases |
| [CLAUDE.md](CLAUDE.md) | Project rules; every one exists because of a specific CVE or escape |
| [SECURITY.md](SECURITY.md) | Reporting, and what is not yet protected |

## Licence

Apache-2.0. See [LICENSE](LICENSE).
