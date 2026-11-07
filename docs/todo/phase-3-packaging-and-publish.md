# Phase 3 — Debian/Ubuntu packaging, publication, and the beta release

Goal: someone on Ubuntu or Debian can install `xudo` with one command, understand what it does and what it does not protect them from before they trust it, and find the project when they or their coding agent go looking for it.

**Sequencing.** Do this after M2 and not before. See § The beta ships the human path only.

---

> **DECIDED 2026-08-28.** Two questions in this file are settled:
>
> * **One package.** `ido` ships alongside `xudo` and is deliberately *not*
>   separately installable. § 2's layout gains the `ido` binaries; the "one
>   package or two" open decision is closed in favour of one.
> * **Signed `.deb` on GitHub Releases, no apt repository yet.** § 4's `aptly` /
>   `reprepro` / `gh-pages` / `xudo-keyring` work is deferred, and the
>   checksum-verified download becomes the documented install. The reasoning for
>   why there is no `curl | sh` installer still applies and still belongs in the
>   README.

## 1. The beta ships the human path only

This is the load-bearing decision of the whole phase, so it comes first.

A `.deb` postinst runs as root. If it installs a `NOPASSWD` sudoers rule, then the single most dangerous moment in this product's life is an unattended `apt install` on a machine whose owner has read nothing. Before M4 there is no reviewed enrollment path, no broker, and no out-of-band confirmation, so a passwordless rule would be a standing root grant with no compensating control.

Therefore the beta package:

- installs `/usr/bin/xudo`, `/usr/bin/ido` (with `willyoumarryme` as a second name for the same inode), `/usr/libexec/xudo/xudo-gate` with `xudo-gate-auth` as its hardlink, and `/usr/libexec/xudo/xudod` with its socket unit — the broker mints requests and grants nothing a password did not;
- installs the `PASSWD:` sudoers rule only;
- does **not** install `xudo-gate-nopass`, its hardlink, or its `NOPASSWD:` rule — those files are not in the package at all, rather than present-but-unreferenced;
- does **not** add any user to the `xudo` group (see § 3);
- prints, on first install, that every invocation will prompt for a password and that the passwordless agent path is not in this release.

The passwordless path arrives in a later release, behind an explicit `xudo enable-agent-path` that requires reading a warning and authenticating. Shipping it as a package default would be indefensible.

---

## 2. Package layout

Build with `cargo-deb` for the ordinary paths, but the maintainer scripts need hand-writing: `cargo-deb`'s generated postinst is not adequate for a privilege broker.

```
/usr/bin/xudo                             0755 root:root   no setuid bit, ever
/usr/libexec/xudo/xudo-gate-auth          0755 root:root   no setuid bit, ever
/usr/libexec/xudo/xudod                   0755 root:root   the broker; started per connection, never by hand
/usr/lib/systemd/system/xudod.socket      0644 root:root   packaging/systemd/xudod.socket: /run/xudo/broker.sock, 0660 root:xudo
/usr/lib/systemd/system/xudod@.service    0644 root:root   packaging/systemd/xudod@.service: one sandboxed instance per connection
/usr/share/doc/xudo/                                       README, SECURITY, changelog, copyright
/usr/share/man/man1/xudo.1.gz
/usr/share/man/man5/xudo-rules.5.gz                        the rule-file format
/etc/xudo/config.toml                                      conffile
/etc/xudo/rules.d/*.toml                                   conffiles — see § 2.2
/etc/xudo/deny.d/00-catastrophic.toml                      conffile, FOR READING ONLY
/etc/sudoers.d/xudo                       0440 root:root   generated in postinst, never shipped
/usr/lib/tmpfiles.d/xudo.conf             0644 root:root   packaging/tmpfiles.d/xudo.conf: /run/xudo 0755, /run/xudo/req 0700
```

The three files under `packaging/` are tested as code by `crates/xudod/tests/units.rs`, which refuses any directive it does not know — systemd ignores a misspelled one with a warning — and asserts every security-relevant line against the constants the code uses. The postinst creates the `xudo` group before it enables `xudod.socket`, because `SocketGroup=xudo` fails without it.

Control fields:

| Field | Value | Why |
|---|---|---|
| `Package` | `xudo` | |
| `Section` | `admin` | |
| `Priority` | `optional` | |
| `Architecture` | `amd64`, `arm64` | Native runners for both; no QEMU in the release path |
| `Depends` | `sudo \| opendoas`, `${shlibs:Depends}`, `${misc:Depends}` | An alternation, because the doas lane is real |
| `Recommends` | `systemd` | journald mirrors every audit record and the mirror is required: a host or container without journald refuses every privileged request until an `audit_sink` setting exists to leave it out (`../CONCERNS.md`, 2026-10-19). No `/dev/log` fallback yet |
| `Conflicts` | — | Deliberately none; `xudo` does not replace `sudo` |

### 2.1 The `xudo` group

Create the group in postinst (`addgroup --system xudo`), and **add nobody to it**. Group membership is the privilege grant, so it is the user's explicit act: `xudo doctor --fix` proposes it, prints what it means, and requires confirmation. An `apt install` that silently grants a user access to a privileged helper is the behaviour this project exists to argue against.

### 2.2 Rule files as conffiles

Shipped rules under `/etc/xudo/rules.d/` are Debian conffiles, so dpkg prompts on local modification rather than overwriting. Consequence to test: an operator who narrows a shipped rule keeps their version across upgrades, which means an upgrade can leave a *stale* rule in place. `xudo doctor` must report the version of each rule file it loaded against the version the package shipped, so drift is visible rather than silent.

---

## 3. Maintainer scripts

The dangerous part. Each step exists because of a specific failure mode.

### postinst

1. `addgroup --system xudo` (idempotent).
2. Generate the sudoers snippet to a temp file inside `/etc/sudoers.d/` — same filesystem, so the later rename is atomic.
3. **Validate with `visudo -cf <tempfile>`.** Note that sudo-rs's `visudo` validates only `/etc/sudoers`, not files under `sudoers.d`, so the check must name xudo's own file explicitly. Abort the install on failure and remove the temp file.
4. `chmod 0440`, `chown root:root`, then `rename()` into `/etc/sudoers.d/xudo`.
   **The filename has no dot and no trailing tilde.** sudo silently ignores files in `sudoers.d` whose names contain a dot or end in `~`, which produces a working-looking install with no rule in effect. Test that this failure is detected rather than trusted (§ 7).
5. On a doas system: append a sentinel-delimited block to `/etc/doas.conf` under an `flock`, validate with `doas -C` on a temp copy first. Detect whether the build has `--with-timestamp`; xudo must never depend on backend credential caching either way.
6. **Functional probe, not a file check.** Invoke the gate with a no-op request and assert it actually executed as uid 0. Ubuntu 26.04 ships sudo-rs, which logs unsupported directives as warnings and *ignores* them, so a rule the postinst wrote may silently not mean what it says.
7. `systemd-tmpfiles --create` for `/run/xudo`.
8. Print the first-install notice: always prompts, no agent path in this release, `SECURITY.md` location, and the one-sentence honest statement that agent detection is not a security boundary.

### prerm / postrm

**An uninstall that leaves a sudoers rule behind is a security defect, not a cosmetic one.** `postrm remove` must delete `/etc/sudoers.d/xudo`; `postrm purge` must additionally remove `/etc/xudo`, `/var/lib/xudo` (which holds the audit chain, `audit.jsonl`), and the `xudo` group. The package creates `/var/lib/xudo` `0700 root:root`; the audit writer creates its log there and never creates the directory. The doas path must remove exactly its own sentinel-delimited block and nothing else. Both are asserted in the container matrix.

---

## 4. Distribution and the one-line install

### The one-line install must not be `curl | sudo sh`

`xudo`'s own compiled-in deny-list refuses "any network fetch piped to an interpreter as root". Publishing an install command that does exactly that would be self-refuting, and reviewers would be right to say so. It is also the specific pattern the project's threat model calls out.

### Recommended: signed apt repository on GitHub Pages

Build with `aptly` or `reprepro`, sign the `Release` file with a dedicated repository key, publish to `gh-pages`, and ship a small `xudo-keyring` package so the key can be rotated through the package manager rather than by asking users to re-run a shell command.

The install becomes three lines that a reader can audit, and the *documented* one-liner is the apt install itself:

```bash
# 1. keyring (verifiable, no piping to a shell)
sudo curl -fsSLo /usr/share/keyrings/xudo.gpg https://<org>.github.io/xudo/xudo.gpg
# 2. source
echo "deb [signed-by=/usr/share/keyrings/xudo.gpg] https://<org>.github.io/xudo stable main" \
  | sudo tee /etc/apt/sources.list.d/xudo.list
# 3. install
sudo apt update && sudo apt install xudo
```

If a genuine single command is required for the README headline, use the `.deb` path with a published checksum rather than a piped script:

```bash
curl -fsSLO https://github.com/<org>/xudo/releases/latest/download/xudo_amd64.deb \
  && sha256sum -c xudo_amd64.deb.sha256 \
  && sudo apt install ./xudo_amd64.deb
```

State plainly in the README why there is no `curl | sh` installer. That paragraph is itself a credibility signal for this particular product.

### Also worth doing

- **Launchpad PPA** for Ubuntu reach; it is what Ubuntu users look for first.
- `.rpm` via `cargo-generate-rpm`, `APKBUILD`, `PKGBUILD`, and a Nix module — cheap once the `.deb` maintainer scripts exist, and the Alpine/doas lane is already in the test matrix.
- `cargo-auditable` in the release build so the shipped binary carries its dependency list; publish an SBOM (CycloneDX or SPDX) per release.
- Reproducible builds, and sign release artifacts (`minisign` or `cosign`).

---

## 5. GitHub presence: SEO and AI-crawler discoverability

Two audiences, and they retrieve differently. A search engine wants crawlable structure and inbound relevance; a language model retrieves passages and answers questions, so it rewards prose that states the subject explicitly and headings shaped like questions.

### Repository metadata

- **About description**, under 350 characters, front-loading the concrete nouns rather than the pitch. Something like: *"A sudo alternative that lets AI coding agents run an allowlisted set of privileged commands without a password, while always prompting humans. Root-owned rule set, compiled-in deny-list, full audit trail. Rust, Linux."*
- **Topics**: `sudo`, `sudo-alternative`, `privilege-escalation`, `linux-security`, `ai-agents`, `claude-code`, `openai-codex`, `agentic-ai`, `rust`, `cli`, `devsecops`, `least-privilege`, `doas`, `polkit`, `allowlist`.
- **Social preview image** — it is what appears in every link unfurl, including Slack and Discord.
- `SECURITY.md` with a disclosure address, `CITATION.cff`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, a real `CHANGELOG.md`.
- `LICENSE` — Apache-2.0 OR MIT, matching the workspace manifest.

### README structure

The first paragraph must answer *what is this and who is it for* in plain sentences with no metaphor, because that paragraph is what gets retrieved and quoted. Then, in this order: the one-line install, a 30-second example, the honest security statement, how it works, the rule format, and an FAQ.

Write the FAQ headings as the questions people actually type, since heading-level question matching is how both search engines and retrieval systems find the answer:

- What is the difference between `xudo` and `sudo`?
- Can an AI agent run any command with `xudo`?
- Is this safe? What are the limits?
- Does this work with Claude Code, Codex CLI, Gemini CLI, or Aider?
- What happens if an agent lies about being an agent?
- How is this different from `NOPASSWD: ALL`?
- Does it work with `doas`? With `sudo-rs`?
- Does it phone home?

Answer the fourth-from-last one bluntly, in the README, above the fold: **agent detection is not a security boundary; the allowlist is.** A reader who learns that from a critic instead of from the README will not come back.

### Machine-readable discoverability

- **`AGENTS.md` at the repository root**, so a coding agent that clones the repo learns how to use `xudo` and `ido` without being told. Generated by `xudo agentdoc`, stamped with the policy generation hash.
- **`llms.txt`** at the repository root and on the docs site: a short, link-annotated map of the project for retrieval systems.
- A **GitHub Pages docs site** with JSON-LD (`SoftwareApplication` / `SoftwareSourceCode`), a `sitemap.xml`, and a `robots.txt` that permits crawlers. Do not gate documentation behind JavaScript rendering.
- Alt text on every diagram, and a text equivalent for anything that only exists as an image.

---

## 6. Beta labelling and the security statement

Version `0.y.z`, and say what that means: the rule-file format and the CLI surface may change, and an upgrade may require editing rules.

Every one of these appears in the README, the package description, and `xudo --version`:

- **Beta. Not externally audited.** The design plan makes an external audit a precondition for 1.0; until then, say so where people will see it.
- **Agent detection is not a security boundary.** A same-uid process can forge every cheap signal, and a human can ask a genuinely-enrolled agent to run a command, which is indistinguishable at the syscall layer. A successful impersonation buys exactly one thing: skipping the password on an action that is *already allowlisted*. Size the allowlist accordingly.
- **The deny-list is defence in depth, not the boundary.** The set of programs that can be turned into a root shell is not enumerable.
- **`xudo` cannot protect a host that already has other paths to root.** `xudo doctor` reports pre-existing `NOPASSWD` entries, `wheel`/`sudo`/`docker`/`lxd` membership, writable unit directories, writable `PATH` entries, and writable shell rc files — any one of which makes `xudo` decorative.
- **What is not in this release**: the passwordless agent path, the broker, out-of-band confirmation, Landlock confinement.
- **No telemetry**, and how to verify it: no network code in the default build, networking behind a non-default cargo feature, and a CI job running the suite under `strace` asserting no non-`AF_UNIX` socket.

---

## 7. Tests that gate the release

Run in containers, per distro, on both architectures.

| Test | Asserts |
|---|---|
| Install / upgrade / remove / purge on Ubuntu 24.04, Ubuntu 26.04, Debian 13 | Clean at every step; the sudoers snippet is **gone** after remove and after purge |
| Dotted-filename regression | Install the snippet as `xudo.conf` and assert `xudo doctor` reports the rule as **not in effect** — sudo ignores it silently |
| sudo-rs directive regression | On Ubuntu 26.04, assert the functional probe catches an ignored-but-warned directive |
| doas lane | Alpine + OpenDoas: block appended, `doas -C` validated, removed exactly on purge |
| No setuid anywhere | `find / -perm -4000` over the installed file set is empty |
| No `NOPASSWD` in the beta | `grep -r NOPASSWD /etc/sudoers.d/xudo` finds nothing, and `xudo-gate-nopass` is absent from the package |
| Nobody was added to a group | The `xudo` group exists and is empty after install |
| `lintian` | Clean, with any override justified in a comment |
| Reproducible build | Two builds from the same source produce identical artifacts |
| Install-command documentation | A CI check that the README contains no `curl … | …sh` pattern |

---

## Deliverables

- `debian/` packaging with hand-written maintainer scripts, or `cargo-deb` metadata plus script overrides.
- Signed `.deb` artifacts on GitHub Releases. The `xudo-keyring` package and the apt repository are deferred (open decision 3 in `README.md`); § 4's one-line install is written for the Releases form until then.
- `.rpm`, `APKBUILD`, `PKGBUILD`, Nix module.
- Signed release artifacts, SBOM, `cargo-auditable` build.
- README, `SECURITY.md`, `CITATION.cff`, `AGENTS.md`, `llms.txt`, docs site with JSON-LD.
- The container install/remove/purge matrix wired into CI.
- Man pages for `xudo(1)` and `xudo-rules(5)`; `ido(1)` and `ido-queue(5)` exist in `../man/` and a test keeps `ido(1)` in step with the command surface.
