//! `/etc/passwd` and `/etc/group`, read the way the report needs them.
//!
//! Only the files. A directory service (LDAP, SSSD) is not consulted, because
//! that would mean linking `libc`'s name-service switch into a crate that is
//! pure by rule; the report says so wherever the gap could hide a membership.
//! Names stay bytes: they are compared, and a lossy conversion is how two
//! different names come to compare equal.

use std::path::PathBuf;

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;

/// The local accounts file.
pub(super) const PASSWD: &str = "/etc/passwd";

/// The local groups file.
pub(super) const GROUP: &str = "/etc/group";

/// One line of `/etc/passwd`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Account {
    pub(super) name: Vec<u8>,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) home: PathBuf,
}

/// One line of `/etc/group`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct GroupEntry {
    pub(super) name: Vec<u8>,
    pub(super) gid: u32,
    pub(super) members: Vec<Vec<u8>>,
}

/// Parses `/etc/passwd`: `name:password:uid:gid:gecos:home:shell`.
///
/// A line without the seven fields or with an id that is not a number is
/// skipped, as `getpwent(3)` would; so is a NIS `+`/`-` line, which names no
/// account by itself.
pub(super) fn parse_passwd(bytes: &[u8]) -> Vec<Account> {
    lines(bytes)
        .filter_map(|line| {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
            let [name, _, uid, gid, _, home, _] = fields.as_slice() else {
                return None;
            };
            Some(Account {
                name: name.to_vec(),
                uid: super::config::number(uid)?,
                gid: super::config::number(gid)?,
                home: PathBuf::from(OsString::from_vec(home.to_vec())),
            })
        })
        .collect()
}

/// Parses `/etc/group`: `name:password:gid:member,member`.
pub(super) fn parse_group(bytes: &[u8]) -> Vec<GroupEntry> {
    lines(bytes)
        .filter_map(|line| {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b':').collect();
            let [name, _, gid, members] = fields.as_slice() else {
                return None;
            };
            Some(GroupEntry {
                name: name.to_vec(),
                gid: super::config::number(gid)?,
                members: members
                    .split(|byte| *byte == b',')
                    .map(<[u8]>::trim_ascii)
                    .filter(|member| !member.is_empty())
                    .map(<[u8]>::to_vec)
                    .collect(),
            })
        })
        .collect()
}

/// The lines of an accounts file that can name an account.
fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !matches!(line.first(), None | Some(b'#' | b'+' | b'-')))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn passwd_lines_become_accounts_and_malformed_ones_are_skipped() {
        let accounts = parse_passwd(
            b"root:x:0:0:root:/root:/bin/bash\r\n\
              # a comment\n\
              +nisuser\n\
              yamin:x:1000:1000:Y:/home/yamin:/bin/zsh\n\
              short:x:1\n\
              bad:x:notanumber:0::/:/bin/sh\n\
              badgid:x:1:x::/:/bin/sh\n\
              \n",
        );
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].name, b"root");
        assert_eq!(accounts[0].home, PathBuf::from("/root"));
        assert_eq!(accounts[1].uid, 1000);
        assert_eq!(accounts[1].gid, 1000);
        assert!(format!("{:?}", accounts[1].clone()).contains("1000"));
    }

    #[test]
    fn group_lines_list_their_members_byte_exactly() {
        let groups = parse_group(
            b"docker:x:999:yamin, alice,,\n\
              sudo:x:27:\n\
              -excluded\n\
              broken:x:27\n\
              badgid:x:x:yamin\n",
        );
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0].members,
            vec![b"yamin".to_vec(), b"alice".to_vec()]
        );
        assert!(groups[1].members.is_empty());
        assert_eq!(groups[1].clone(), groups[1]);
        // A name that differs by a byte is a different name.
        assert!(!groups[0].members.contains(&b"yamin\xff".to_vec()));
    }
}
