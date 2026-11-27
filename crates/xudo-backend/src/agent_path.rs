//! What must hold before `xudo install --agent-path` writes its one
//! passwordless line: no other line in any sudo or doas file names the agent
//! group or the passwordless helper.
//!
//! xudo's line grants `%xudo-agent` the `-nopass` helper with no arguments.
//! Every argument for why that is safe assumes it is the only line that does
//! anything for that group or that helper. A line an operator wrote, before
//! xudo's or after it, in any include order, breaks that assumption in a way
//! xudo cannot reason about, so the install stops and names it. Conservative,
//! like enrol's scan: a comment is skipped, anything else that mentions either
//! one counts, and a file or an include this cannot read counts too.
//!
//! Pure: everything is read through a [`HostView`].

use std::path::{Path, PathBuf};

use crate::enrol::{RULE_DIRS, RULE_FILES, contains, group_gid, names_numeric_group, names_token};
use crate::paths_to_root::{HostView, Lookup};
use crate::snippet::{SUDOERS_PATH, XUDO_AGENT_GROUP};

/// The helper's file name: any path that reaches it names it.
const HELPER_NAME: &[u8] = b"xudo-gate-nopass";

/// Every reason the passwordless line must not be written: one per line that
/// names the agent group or the helper, or includes what this cannot follow,
/// and one per file or directory that could not be read. Empty means go on.
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
                                "{} line {line} names the agent group or the passwordless \
                                 helper, or includes a file this cannot follow",
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

/// The 1-based numbers of the lines in `bytes` that name a token or the
/// helper, include anything but the standard drop-in directory, or, while the
/// group does not exist yet (`numeric`), name any group by number: a leftover
/// `%#996` would name the group once `groupadd` hands it that gid.
fn conflicting_lines(bytes: &[u8], tokens: &[String], numeric: bool) -> Vec<usize> {
    let is_word = |byte: &u8| byte.is_ascii_alphanumeric() || b"_.-#".contains(byte);
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
            contains(line, HELPER_NAME)
                || tokens
                    .iter()
                    .any(|token| names_token(line, token.as_bytes(), &is_word))
                || (numeric && names_numeric_group(line))
        };
        if hit {
            found.push(index.saturating_add(1));
        }
    }
    found
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
                "/etc/sudoers line 2 names the agent group or the passwordless helper, or includes a file this cannot follow"
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
}
