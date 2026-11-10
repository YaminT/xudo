# Crates

One row per member of `Cargo.toml`'s `[workspace]`. A crate that is built but
not merged yet opens its row with `**in review (M2b).**` and loses that marker
when it joins the workspace. `crates/xudo-tests/tests/crate_inventory.rs`
fails the build when this table and the manifest disagree.

## Crate layout

| Crate | Role |
|---|---|
| `xudo-policy` | Pure policy engine: ruleset, caller facts, and request to a decision. No I/O. |
| `xudo-backend` | What to ask sudo, sudo-rs, or doas. Pure; execution is `xudo-sys`. |
| `xudo-config` | Layered configuration. Pure; handed values, reads nothing itself. |
| `xudo-audit` | Tamper-evident audit records. Pure; the file and journald mirror are `xudo-sys`. |
| `xudo-sys` | Syscalls behind a trait, with an in-memory fake. |
| `xudo-sys-raw` | The five unsafe syscalls, allowed only in its `sys` module. |
| `xudo` | Unprivileged front-end library. Holds no secret and makes no decision. |
| `xudo-bin` | The `xudo` executable. Excluded from coverage; tested as a process. |
| `xudo-wire` | Wire protocol between `xudo` and `xudod`. Pure data. |
| `xudod` | Root broker library. Identifies the peer, decides, mints. Executes nothing. |
| `xudod-bin` | The `xudod` executable. Excluded from coverage; tested as a process. |
| `xudo-gate` | Second policy engine. Re-decides from root-owned state. |
| `xudo-gate-bin` | The `xudo-gate` executable. Excluded from coverage; tested as a process. |
| `ido` | Unprivileged command queue. |
| `ido-bin` | The `ido` executable. Excluded from coverage; tested as a process. |
| `term-sanitize` | Display-only sanitizer for agent-written terminal text. |
| `xudo-tests` | Workspace tests, including the check on this table. |
