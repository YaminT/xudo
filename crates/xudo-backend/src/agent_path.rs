//! What must hold before `xudo install --agent-path` writes its one
//! passwordless line: no other line in any sudo or doas file names the agent
//! group, xudo's aliases or anything under `/usr/libexec/xudo`; the helper and
//! every directory above it are root's alone; and the agent group holds no
//! account the operator did not register.
//!
//! xudo's line grants `%xudo-agent` the `-nopass` helper with no arguments.
//! Every argument for why that is safe assumes it is the only line that does
//! anything for that group, those aliases or that helper. A line an operator
//! wrote, before xudo's or after it, in any include order, breaks that
//! assumption in a way xudo cannot reason about, so the install stops and
//! names it. Conservative, like enrol's scan: a comment is skipped, anything
//! else that mentions one counts, and a file or an include this cannot read
//! counts too.
//!
//! Pure: everything is read through a [`HostView`].

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::enrol::{
    RULE_DIRS, RULE_FILES, contains, group_gid, names_numeric_group, names_token, number,
    parse_passwd,
};
use crate::paths_to_root::{HostView, Kind, Lookup};
use crate::snippet::{GATE_NOPASS, SUDOERS_PATH, XUDO_AGENT_GROUP, doas_rule};

/// Where xudo's helpers live: any line that names a path under it is about
/// them.
const HELPERS_DIR: &[u8] = b"/usr/libexec/xudo";

/// The aliases xudo's file defines. One defined first elsewhere wins over
/// xudo's (`Cmnd_Alias XUDO_NOPASS = ALL`), or makes the whole file fail.
const ALIASES: [&str; 3] = ["XUDO_NOPASS", "XUDO_AUTH", "XUDO_SELF"];

/// Every reason the passwordless line must not be written: one per line that
/// names the agent group, one of xudo's aliases or a helper, or includes what
/// this cannot follow, and one per file or directory that could not be read.
/// Empty means go on.
///
/// xudo's own file and its candidate are skipped: the install replaces the
/// one, under its own edit check, and sudo never reads the other (a dot).
#[must_use]
pub fn conflicts(host: &dyn HostView) -> Vec<String> {
    let gid = group_gid(host, XUDO_AGENT_GROUP);
    let mut tokens = vec![
        format!("%{XUDO_AGENT_GROUP}"),
        format!(":{XUDO_AGENT_GROUP}"),
    ];
    tokens.extend(ALIASES.map(str::to_owned));
    tokens.extend(
        gid.iter()
            .flat_map(|gid| [format!("%#{gid}"), format!("%{gid}")]),
    );
    let mut files: Vec<PathBuf> = RULE_FILES.iter().map(PathBuf::from).collect();
    let mut out = Vec::new();
    for dir in RULE_DIRS {
        match host.list(Path::new(dir)) {
            Lookup::Found(names) => files.extend(names.iter().map(|n| Path::new(dir).join(n))),
            Lookup::Missing => {}
            Lookup::Unreadable(why) => out.push(format!("could not examine {dir}: {why}")),
        }
    }
    let candidate = PathBuf::from(format!("{SUDOERS_PATH}.candidate"));
    for file in files
        .iter()
        .filter(|file| file.as_path() != Path::new(SUDOERS_PATH) && **file != candidate)
    {
        match host.read(file) {
            Lookup::Found(bytes) => {
                out.extend(
                    conflicting_lines(&bytes, &tokens, gid.is_none())
                        .into_iter()
                        .map(|line| {
                            format!(
                                "{} line {line} names the agent group, an alias xudo defines \
                                 or a path under /usr/libexec/xudo, or includes a file this \
                                 cannot follow",
                                file.display()
                            )
                        }),
                );
            }
            Lookup::Missing => {}
            Lookup::Unreadable(why) => {
                out.push(format!("could not examine {}: {why}", file.display()));
            }
        }
    }
    out
}

/// The 1-based numbers of the lines in `bytes` that name a token, a path
/// under the helpers' directory or a pattern that reaches the helper, include
/// anything but the standard drop-in directory, or, while the group does not
/// exist yet (`numeric`), name any group by number: a leftover `%#996` would
/// name the group once `groupadd` hands it that gid. xudo's own doas rule,
/// byte for byte, is not a conflict.
fn conflicting_lines(bytes: &[u8], tokens: &[String], numeric: bool) -> Vec<usize> {
    let is_word = |byte: &u8| byte.is_ascii_alphanumeric() || b"_.-#".contains(byte);
    let ours = doas_rule();
    let mut found = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let trimmed = line.trim_ascii_start();
        let include = [&b"#include"[..], b"@include"]
            .iter()
            .any(|word| trimmed.starts_with(word));
        let hit = if include {
            let mut parts = trimmed.split(u8::is_ascii_whitespace);
            !matches!(
                (parts.next(), parts.next(), parts.next()),
                (
                    Some(b"#includedir" | b"@includedir"),
                    Some(b"/etc/sudoers.d"),
                    None
                )
            )
        } else if trimmed.first() == Some(&b'#') && !trimmed.get(1).is_some_and(u8::is_ascii_digit)
        {
            false
        } else {
            line.trim_ascii() != ours.as_bytes()
                && (contains(line, HELPERS_DIR)
                    || contains(line, b"xudo-gate")
                    || reaches_helper(line)
                    || tokens
                        .iter()
                        .any(|token| names_token(line, token.as_bytes(), &is_word))
                    || (numeric && names_numeric_group(line)))
        };
        if hit {
            found.push(index.saturating_add(1));
        }
    }
    found
}

/// Whether any absolute path pattern in `line` could match the helper, the
/// way sudo matches a command: one path component at a time, `*` and `?`
/// never crossing a `/`. A component holding `[` or `\` is taken to match.
/// `Defaults!/usr/libexec/*/* env_keep+=LD_PRELOAD` reaches the helper
/// without naming it.
fn reaches_helper(line: &[u8]) -> bool {
    let components = |path: &[u8]| -> Vec<Vec<u8>> {
        path.split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    };
    let helper = components(GATE_NOPASS.as_bytes());
    line.split(|byte| byte.is_ascii_whitespace() || b",=:!()\"".contains(byte))
        .filter(|token| token.first() == Some(&b'/'))
        .any(|token| {
            let pattern = components(token);
            pattern.len() == helper.len()
                && pattern
                    .iter()
                    .zip(&helper)
                    .all(|(pattern, name)| component_matches(pattern, name))
        })
}

/// Whether one glob component matches one name: `*`, `?` and literal bytes,
/// with the usual backtrack to the last `*` (linear in practice, never
/// exponential). `[` or `\` anywhere it is reached counts as a match.
fn component_matches(pattern: &[u8], name: &[u8]) -> bool {
    let (mut at, mut of) = (0_usize, 0_usize);
    let mut star: Option<(usize, usize)> = None;
    loop {
        match (pattern.get(at), name.get(of)) {
            // A bracket or an escape is taken to match; so is the end of both.
            (Some(b'[' | b'\\'), _) | (None, None) => return true,
            (Some(b'*'), _) => {
                star = Some((at, of));
                at = at.saturating_add(1);
                continue;
            }
            (Some(want), Some(got)) if *want == b'?' || want == got => {
                at = at.saturating_add(1);
                of = of.saturating_add(1);
                continue;
            }
            _ => {}
        }
        match star {
            Some((star_at, star_of)) if star_of < name.len() => {
                let next = star_of.saturating_add(1);
                star = Some((star_at, next));
                at = star_at.saturating_add(1);
                of = next;
            }
            _ => return false,
        }
    }
}

/// Why the passwordless helper's file cannot be trusted: one reason per
/// fault, empty when it and every directory above it are root's, written by
/// root alone, and not symbolic links, and the file has one name. Whoever can
/// replace that file decides what a member of the agent group runs as root.
#[must_use]
pub fn gate_faults(host: &dyn HostView) -> Vec<String> {
    let mut out = Vec::new();
    let path = Path::new(GATE_NOPASS);
    for at in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let (want, noun) = if at == path {
            (Kind::File, "regular file")
        } else {
            (Kind::Directory, "directory")
        };
        let shown = at.display();
        match host.stat(at) {
            Lookup::Found(meta) => {
                if meta.kind == Kind::Symlink {
                    out.push(format!("{shown} is a symbolic link"));
                } else if meta.kind != want {
                    out.push(format!("{shown} is not a {noun}"));
                }
                if meta.uid != 0 {
                    out.push(format!("{shown} belongs to uid {}, not root", meta.uid));
                }
                if meta.mode & 0o022 != 0 {
                    out.push(format!(
                        "{shown} is writable by its group or by everyone (mode {:04o})",
                        meta.mode
                    ));
                }
                if want == Kind::File && meta.nlink != 1 {
                    out.push(format!(
                        "{shown} has {} names: a second hard link is a way to change it",
                        meta.nlink
                    ));
                }
            }
            Lookup::Missing => out.push(format!("{shown} is missing")),
            Lookup::Unreadable(why) => out.push(format!("could not examine {shown}: {why}")),
        }
    }
    out
}

/// Every account in the agent group: listed in `/etc/group`, or with it as
/// the primary group in `/etc/passwd`. Sorted, each once. A name that is not
/// plain text is shown escaped, so it can never equal a registered one.
///
/// # Errors
///
/// A file that could not be read, or a group line with no numeric gid: the
/// members cannot be known, so nothing may be assumed about them.
pub fn agent_members(host: &dyn HostView) -> Result<Vec<String>, String> {
    let read = |path: &str| read_file(host, path);
    let group = read("/etc/group")?;
    let lines: Vec<Vec<&[u8]>> = group
        .split(|byte| *byte == b'\n')
        .map(|line| line.split(|byte| *byte == b':').collect())
        .filter(|fields: &Vec<&[u8]>| fields.first() == Some(&XUDO_AGENT_GROUP.as_bytes()))
        .collect();
    if lines.is_empty() {
        return Ok(Vec::new());
    }
    let shown = |name: &[u8]| name.escape_ascii().to_string();
    let mut names = BTreeSet::new();
    let mut gids = Vec::new();
    for fields in &lines {
        let gid = fields.get(2).and_then(|gid| number(gid)).ok_or_else(|| {
            format!("the {XUDO_AGENT_GROUP} line in /etc/group has no numeric gid")
        })?;
        gids.push(gid);
        names.extend(
            fields
                .get(3)
                .iter()
                .flat_map(|list| list.split(|byte| *byte == b','))
                .filter(|name| !name.is_empty())
                .map(shown),
        );
    }
    let passwd = read("/etc/passwd")?;
    names.extend(
        parse_passwd(&passwd)
            .iter()
            .filter(|entry| gids.contains(&entry.gid))
            .map(|entry| shown(entry.name)),
    );
    Ok(names.into_iter().collect())
}

/// Whether `/etc/passwd` holds an account named `name`: the listing checks
/// ask the backend about an account, and one that does not exist gets no
/// answer.
///
/// # Errors
///
/// `/etc/passwd` could not be read.
pub fn account_exists(host: &dyn HostView, name: &str) -> Result<bool, String> {
    let passwd = read_file(host, "/etc/passwd")?;
    Ok(parse_passwd(&passwd)
        .iter()
        .any(|entry| entry.name == name.as_bytes()))
}

/// The whole of `path`, or why not.
fn read_file(host: &dyn HostView, path: &str) -> Result<Vec<u8>, String> {
    match host.read(Path::new(path)) {
        Lookup::Found(bytes) => Ok(bytes),
        Lookup::Missing => Err(format!("{path} is missing")),
        Lookup::Unreadable(why) => Err(format!("could not examine {path}: {why}")),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::paths_to_root::{Caller, MemoryHost};

    const GROUPS: &[u8] = b"root:x:0:\nxudo:x:998:\nxudo-agent:x:997:agent\n";

    /// A root-run host with sudo's files, the agent group at gid 997, and
    /// `files` in `/etc/sudoers.d`.
    fn host(sudoers: &[u8], files: &[(&str, &[u8])]) -> MemoryHost {
        let mut host = MemoryHost::new(Caller {
            uid: 0,
            gid: 0,
            groups: Lookup::Found(vec![0]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file("/etc/group", 0, 0, 0o644, GROUPS)
        .file("/etc/sudoers", 0, 0, 0o440, sudoers)
        .dir("/etc/sudoers.d", 0, 0, 0o750);
        for (path, contents) in files {
            host = host.file(path, 0, 0, 0o440, contents);
        }
        host
    }

    const STOCK: &[u8] =
        b"Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n";

    #[test]
    fn a_stock_host_has_no_conflict() {
        assert_eq!(conflicts(&host(STOCK, &[])), Vec::<String>::new());
    }

    #[test]
    fn a_preexisting_agent_group_line_blocks_the_agent_path() {
        // An operator's own grant to the group, in a file sudo reads before
        // xudo's: with it, the agent account has root with no helper at all.
        let found = conflicts(&host(
            STOCK,
            &[(
                "/etc/sudoers.d/00-ops",
                b"# ours\n%xudo-agent ALL=(ALL) NOPASSWD: ALL\n",
            )],
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].starts_with("/etc/sudoers.d/00-ops line 2 "),
            "{found:?}"
        );
    }

    #[test]
    fn a_line_granting_the_nopass_helper_to_xudo_blocks_the_agent_path() {
        // `%xudo` instead of `%xudo-agent`: every human member would get the
        // helper with no password, and any argument. Named by the helper.
        let found = conflicts(&host(
            STOCK,
            &[(
                "/etc/sudoers.d/zz-late",
                b"%xudo ALL=(root) NOPASSWD: /usr/libexec/xudo/xudo-gate-nopass\n",
            )],
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("zz-late line 1"), "{found:?}");
    }

    #[test]
    fn a_line_after_the_operators_include_still_blocks() {
        // sudo takes the last match, so a line after the include beats xudo's.
        let late = b"@includedir /etc/sudoers.d\n%xudo-agent ALL=(ALL) ALL\n";
        let found = conflicts(&host(late, &[]));
        assert_eq!(
            found,
            [
                "/etc/sudoers line 2 names the agent group, an alias xudo defines or a path under \
                 /usr/libexec/xudo, or includes a file this cannot follow"
            ]
        );
    }

    #[test]
    fn the_agent_group_named_by_gid_or_in_doas_spelling_blocks() {
        for line in [
            &b"%#997 ALL=(ALL) NOPASSWD: ALL\n"[..],
            b"%997 ALL=(ALL) ALL\n",
            b"User_Alias A = %xudo-agent, bob\n",
            b"permit nopass :xudo-agent as root\n",
            b"Defaults!/usr/libexec/xudo//xudo-gate-nopass !use_pty\n",
        ] {
            let found = conflicts(&host(STOCK, &[("/etc/sudoers.d/ops", line)]));
            assert_eq!(found.len(), 1, "{line:?}");
        }
    }

    #[test]
    fn a_similar_name_or_a_comment_is_not_the_agent_group() {
        let lines =
            b"%xudo-agents ALL=(ALL) ALL\n# %xudo-agent ALL=(ALL) ALL\n%#9970 ALL=(ALL) ALL\n";
        assert!(conflicts(&host(STOCK, &[("/etc/sudoers.d/ops", lines)])).is_empty());
    }

    #[test]
    fn any_numeric_group_blocks_while_the_agent_group_does_not_exist() {
        let host = host(STOCK, &[("/etc/sudoers.d/ops", b"%#996 ALL=(ALL) ALL\n")]).file(
            "/etc/group",
            0,
            0,
            0o644,
            b"root:x:0:\n",
        );
        assert_eq!(conflicts(&host).len(), 1);
    }

    #[test]
    fn an_include_this_cannot_follow_blocks() {
        for include in [
            &b"@include /etc/sudoers.local\n"[..],
            b"#includedir /etc/sudoers.alt\n",
            b"@includedir /etc/sudoers.d extra\n",
        ] {
            let found = conflicts(&host(include, &[]));
            assert_eq!(found.len(), 1, "{include:?}");
        }
        assert!(conflicts(&host(b"#includedir /etc/sudoers.d\n", &[])).is_empty());
    }

    #[test]
    fn what_cannot_be_read_blocks() {
        let host = host(STOCK, &[])
            .unreadable_file("/etc/sudoers.d/secret", 0, 0, 0o400)
            .fault("/etc/doas.d", "scripted");
        let found = conflicts(&host);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("could not examine /etc/doas.d"))
        );
        assert!(
            found
                .iter()
                .any(|f| f.starts_with("could not examine /etc/sudoers.d/secret"))
        );
    }

    #[test]
    fn xudos_own_file_and_candidate_are_not_conflicts() {
        let agent = b"%xudo-agent ALL=(root) NOPASSWD: XUDO_NOPASS\n";
        let host = host(
            STOCK,
            &[
                ("/etc/sudoers.d/xudo", agent),
                ("/etc/sudoers.d/xudo.candidate", agent),
            ],
        );
        assert!(conflicts(&host).is_empty());
    }

    #[test]
    fn an_earlier_alias_named_like_xudos_is_refused_before_writing() {
        // `Cmnd_Alias XUDO_NOPASS = ALL` in a file sudo reads first: visudo -cf
        // passes xudo's candidate alone, and the joined configuration either
        // fails or keeps the operator's `ALL`.
        for line in [
            &b"Cmnd_Alias XUDO_NOPASS = ALL\n"[..],
            b"Cmnd_Alias XUDO_AUTH = /bin/sh\n",
            b"User_Alias XUDO_SELF = bob\n",
            b"Defaults!XUDO_NOPASS !use_pty\n",
        ] {
            let found = conflicts(&host(STOCK, &[("/etc/sudoers.d/00-ops", line)]));
            assert_eq!(found.len(), 1, "{line:?}");
            assert!(found[0].contains("an alias xudo defines"), "{found:?}");
        }
        // A longer name is another alias.
        let other = b"Cmnd_Alias XUDO_NOPASSWD_OK = /bin/true\n";
        assert!(conflicts(&host(STOCK, &[("/etc/sudoers.d/00-ops", other)])).is_empty());
    }

    #[test]
    fn a_wildcard_or_any_line_reaching_the_helpers_blocks() {
        for line in [
            &b"Defaults!/usr/libexec/xudo/* env_keep+=LD_PRELOAD\n"[..],
            b"Defaults!/usr/libexec/*/* env_keep+=LD_PRELOAD\n",
            b"Defaults!/usr/*/xudo/xudo-gate-?opass !use_pty\n",
            b"Defaults!/*/*/*/* !env_reset\n",
            b"Defaults!/usr/libexec/[x]udo/x* !use_pty\n",
            b"Defaults!/usr/lib\\exec/*/* !use_pty\n",
            b"%admin ALL=(ALL) NOPASSWD:/usr/libexec/*/*nopass\n",
            b"%admin ALL=(root) NOPASSWD: /usr/libexec/xudo/xudo-gate-auth\n",
        ] {
            let found = conflicts(&host(STOCK, &[("/etc/sudoers.d/ops", line)]));
            assert_eq!(found.len(), 1, "{line:?}");
        }
    }

    #[test]
    fn a_pattern_that_cannot_reach_the_helper_or_xudos_doas_rule_is_no_conflict() {
        let lines = b"Defaults!/usr/bin/* !lecture\n\
                      Defaults!/usr/libexec/* !lecture\n\
                      %ops ALL=(ALL) /usr/libexec/*/*/x\n\
                      %ops ALL=(ALL) /usr/libexec/*/nopasz\n\
                      %ops ALL=(ALL) /usr/libexec/xu*q/*\n\
                      %ops ALL=(ALL) relative/*/*/*\n";
        let host = host(STOCK, &[("/etc/sudoers.d/ops", lines)]).file(
            "/etc/doas.conf",
            0,
            0,
            0o400,
            format!("permit :wheel\n  {}\n", doas_rule()).as_bytes(),
        );
        assert_eq!(conflicts(&host), Vec::<String>::new());
    }

    #[test]
    fn a_glob_component_backtracks_to_its_last_star_and_no_further() {
        assert!(component_matches(b"*", b""));
        assert!(component_matches(b"x*-*-nopass", b"xudo-gate-nopass"));
        assert!(component_matches(b"*a*s", b"xudo-gate-nopass"));
        assert!(component_matches(b"??do", b"xudo"));
        assert!(!component_matches(b"??do", b"xudos"));
        assert!(!component_matches(b"*q", b"xudo"));
        assert!(!component_matches(b"", b"x"));
        // Many stars on a long name end quickly, not after an exponential walk.
        let stars = vec![b'*'; 64];
        assert!(!component_matches(
            &[stars.as_slice(), b"q"].concat(),
            &[b'a'; 64]
        ));
    }

    /// A root-run host with the helper installed as the package installs it.
    fn gate_host() -> MemoryHost {
        host(STOCK, &[])
            .dir("/usr", 0, 0, 0o755)
            .dir("/usr/libexec", 0, 0, 0o755)
            .dir("/usr/libexec/xudo", 0, 0, 0o755)
            .file(GATE_NOPASS, 0, 0, 0o755, b"\x7fELF")
    }

    #[test]
    fn a_helper_root_alone_can_change_is_trusted() {
        assert_eq!(gate_faults(&gate_host()), Vec::<String>::new());
        // A second name is a file's; a directory keeps its own count.
        assert_eq!(
            gate_faults(&gate_host().hard_linked("/usr")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_helper_anyone_but_root_could_swap_is_refused() {
        let cases: [(MemoryHost, &str); 8] = [
            (host(STOCK, &[]), "/usr is missing"),
            (
                gate_host().file(GATE_NOPASS, 1000, 0, 0o755, b"x"),
                "belongs to uid 1000",
            ),
            (
                gate_host().file(GATE_NOPASS, 0, 0, 0o757, b"x"),
                "writable by its group or by everyone (mode 0757)",
            ),
            (
                gate_host().dir("/usr/libexec/xudo", 0, 1000, 0o775),
                "/usr/libexec/xudo is writable",
            ),
            (
                gate_host().dir("/usr/libexec", 1000, 0, 0o755),
                "/usr/libexec belongs to uid 1000",
            ),
            (gate_host().hard_linked(GATE_NOPASS), "has 2 names"),
            (
                gate_host().link(GATE_NOPASS, "/usr/bin/true"),
                "is a symbolic link",
            ),
            (
                gate_host().fault("/usr/libexec/xudo", "scripted"),
                "could not examine /usr/libexec/xudo",
            ),
        ];
        for (host, want) in cases {
            let faults = gate_faults(&host);
            assert!(
                faults.iter().any(|f| f.contains(want)),
                "{want}: {faults:?}"
            );
        }
        let swapped = gate_host().file("/usr/libexec/xudo", 0, 0, 0o755, b"");
        let faults = gate_faults(&swapped);
        assert!(
            faults
                .iter()
                .any(|f| f.ends_with("xudo is not a directory"))
        );
        let faults = gate_faults(&gate_host().dir(GATE_NOPASS, 0, 0, 0o755));
        assert!(
            faults
                .iter()
                .any(|f| f.ends_with("nopass is not a regular file"))
        );
    }

    const PASSWD: &[u8] = b"root:x:0:0::/root:/bin/sh\nagent:x:990:990::/:/bin/sh\n\
                            lurker:x:991:997::/:/bin/sh\n";

    #[test]
    fn every_account_in_the_agent_group_is_found_listed_or_by_primary_gid() {
        let group = b"root:x:0:\nxudo-agent:x:997:agent,carol,,\\xff\n";
        let host = host(STOCK, &[])
            .file("/etc/group", 0, 0, 0o644, group)
            .file("/etc/passwd", 0, 0, 0o644, PASSWD);
        assert_eq!(
            agent_members(&host).unwrap(),
            ["\\\\xff", "agent", "carol", "lurker"]
        );
        // No group yet: nobody is in it, and /etc/passwd is not needed.
        let none = host.file("/etc/group", 0, 0, 0o644, b"root:x:0:\n");
        assert_eq!(agent_members(&none).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn the_agent_groups_members_unknown_is_an_error_not_an_empty_group() {
        let unreadable = host(STOCK, &[]).unreadable_file("/etc/group", 0, 0, 0o600);
        assert!(
            agent_members(&unreadable)
                .unwrap_err()
                .contains("could not examine")
        );
        let no_passwd = host(STOCK, &[]);
        assert_eq!(
            agent_members(&no_passwd).unwrap_err(),
            "/etc/passwd is missing"
        );
        let bad_gid = host(STOCK, &[])
            .file("/etc/group", 0, 0, 0o644, b"xudo-agent:x:x997:\n")
            .file("/etc/passwd", 0, 0, 0o644, PASSWD);
        assert!(
            agent_members(&bad_gid)
                .unwrap_err()
                .contains("no numeric gid")
        );
    }

    #[test]
    fn an_account_the_listing_asks_about_must_be_in_passwd() {
        // sudo answers `-l -U` for an unknown user on standard error, which
        // is no answer; the front-end checks first.
        let known = host(STOCK, &[]).file("/etc/passwd", 0, 0, 0o644, PASSWD);
        assert_eq!(account_exists(&known, "agent"), Ok(true));
        assert_eq!(account_exists(&known, "nobody"), Ok(false));
        assert_eq!(account_exists(&known, "agen"), Ok(false));
        assert_eq!(
            account_exists(&host(STOCK, &[]), "nobody").unwrap_err(),
            "/etc/passwd is missing"
        );
    }
}
