//! Parsers for the `/proc` files this project reads.
//!
//! Pure functions over bytes, so every one of them is covered on any platform.

use bstr::ByteSlice;

use crate::error::SysError;

/// The fields of `/proc/<pid>/stat` that matter here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcStat {
    /// The process id.
    pub pid: u32,
    /// The executable name, as the kernel reports it. Arbitrary bytes.
    pub comm: Vec<u8>,
    /// The parent process id.
    pub ppid: u32,
    /// Start time in clock ticks since boot.
    ///
    /// Carried everywhere alongside the pid because a pid alone is not an
    /// identity: pids are reused, so a check on pid *N* can land on a different
    /// process than the one that was inspected. The pair is stable for the life
    /// of the process, which is what makes it usable as a pin.
    pub starttime: u64,
}

/// Parses `/proc/<pid>/stat`.
///
/// # The trap in this format
///
/// Field 2 is the executable name wrapped in parentheses, and it is **not
/// escaped**. A process can name itself `evil) 1 2 3 (` and a parser that
/// splits on whitespace, or that finds the *first* `)`, will read attacker-chosen
/// values for every field after it — including `ppid`, which is how an ancestry
/// walk gets pointed wherever the attacker likes.
///
/// The only correct approach is to find the **last** `)` in the whole line and
/// treat everything between the first `(` and that as the name. This is what
/// the kernel's own documentation implies and what every correct implementation
/// does.
///
/// # Errors
///
/// Returns [`SysError::Malformed`] when the parentheses are missing or
/// unbalanced, when a numeric field is not a number, or when the line is too
/// short to contain the fields we need.
pub fn parse_stat(path: &str, bytes: &[u8]) -> Result<ProcStat, SysError> {
    let open = bytes
        .find_byte(b'(')
        .ok_or_else(|| SysError::malformed(path, "no opening parenthesis around comm"))?;
    let close = bytes
        .rfind_byte(b')')
        .ok_or_else(|| SysError::malformed(path, "no closing parenthesis around comm"))?;
    if close < open {
        return Err(SysError::malformed(
            path,
            "closing parenthesis precedes the opening one",
        ));
    }

    // `open` and `close` are indices into `bytes` with `open <= close`, so both
    // slices below always exist. Taking them infallibly keeps the error set to
    // failures that can actually happen.
    let id_field = bytes.get(..open).unwrap_or_default();
    let pid = parse_u32(path, id_field.trim_ascii())?;

    let comm = bytes
        .get(open.saturating_add(1)..close)
        .unwrap_or_default()
        .to_vec();

    // Everything after the closing parenthesis: state, ppid, pgrp, session,
    // tty_nr, tpgid, flags, minflt, cminflt, majflt, cmajflt, utime, stime,
    // cutime, cstime, priority, nice, num_threads, itrealvalue, starttime.
    // These are field 3 onward, so ppid is index 1 and starttime is index 19.
    // `close` is an index into `bytes`, so `close + 1` is at most `len` and this
    // slice always exists; an empty tail simply means the line stopped at the
    // closing parenthesis, which the field checks below report.
    let rest = bytes.get(close.saturating_add(1)..).unwrap_or_default();
    let fields: Vec<&[u8]> = rest.split_str(" ").filter(|f| !f.is_empty()).collect();

    let parent_field = fields
        .get(1)
        .ok_or_else(|| SysError::malformed(path, "ppid field is absent"))?;
    let start_field = fields
        .get(19)
        .ok_or_else(|| SysError::malformed(path, "starttime field is absent"))?;

    Ok(ProcStat {
        pid,
        comm,
        ppid: parse_u32(path, parent_field)?,
        starttime: parse_u64(path, start_field)?,
    })
}

/// A cgroup v2 path, e.g. `/user.slice/user-1000.slice/session-3.scope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CgroupPath(String);

impl CgroupPath {
    /// The path as written in `/proc/<pid>/cgroup`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this path sits at or beneath `prefix`.
    ///
    /// A component-boundary test, not a string prefix: `/aido.slice-evil` is not
    /// beneath `/aido.slice`. The same bug class as path prefix matching, and it
    /// matters here because at M4 this is how an enrolled scope is recognised.
    pub fn is_under(&self, prefix: &str) -> bool {
        let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
        if self.0 == prefix {
            return true;
        }
        self.0
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1)
    }
}

/// Parses `/proc/<pid>/cgroup`, returning the unified (v2) hierarchy path.
///
/// The v2 line is `0::<path>`. A host running cgroup v1 only has no such line,
/// and this returns `None` for it rather than guessing from a v1 controller —
/// v1 has no single path that means what v2's does, and inventing one would
/// produce a confident wrong answer at exactly the point where M4 decides
/// whether a caller is an enrolled agent.
pub fn parse_cgroup(text: &str) -> Option<CgroupPath> {
    text.lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .map(|path| CgroupPath(path.trim_end().to_owned()))
        .next()
}

/// One line of `/proc/<pid>/mountinfo`, with every field the kernel writes.
///
/// The format is proc(5)'s: `1 2 3:3 4 5 6 [7...] - 9 10 11`. The text fields
/// are bytes, decoded from the kernel's octal escapes: a mount point is a path,
/// and a FUSE mount's type suffix and source are chosen by whoever mounted it,
/// so none of them is necessarily UTF-8 and none may be compared after a lossy
/// conversion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// Field 1: the mount's id. Unique among the mounts that exist at one time,
    /// and the `mnt_id` that `/proc/<pid>/fdinfo/<fd>` reports for a descriptor
    /// opened through this mount.
    pub mount_id: u32,
    /// Field 2: the id of the mount this one is mounted on.
    pub parent_id: u32,
    /// Field 3, before the colon: the major number of the filesystem's device.
    ///
    /// Not necessarily any descriptor's `st_dev`: btrfs gives every subvolume a
    /// device number of its own, and none of those appears in this file.
    pub major: u32,
    /// Field 3, after the colon: the minor number.
    pub minor: u32,
    /// Field 4: the directory, within its filesystem, that is this mount's root.
    /// `/` for a whole filesystem; a bind mount's source otherwise.
    pub root: Vec<u8>,
    /// Field 5: where it is mounted, relative to the reading process's root.
    pub mount_point: Vec<u8>,
    /// Field 6: the per-mount options, `rw` or `ro` first.
    pub mount_options: Vec<Vec<u8>>,
    /// Fields 7 onward: the optional tagged fields, such as `shared:1`.
    pub optional_fields: Vec<Vec<u8>>,
    /// Field 9: the filesystem type, with a subtype after a dot (`fuse.sshfs`).
    pub fs_type: Vec<u8>,
    /// Field 10: the source. `none` when there is none, and possibly empty.
    pub source: Vec<u8>,
    /// Field 11: the superblock's options, `rw` or `ro` first.
    pub super_options: Vec<Vec<u8>>,
}

impl MountEntry {
    /// Whether the mount carries a per-mount option (field 6), by exact name.
    pub fn has_mount_option(&self, name: &[u8]) -> bool {
        self.mount_options
            .iter()
            .any(|option| option.as_slice() == name)
    }

    /// The value of every superblock option (field 11) of the form `key=value`.
    ///
    /// Every one, not the first: a key that appears twice is a contradiction a
    /// caller must see, rather than one this function resolves by position.
    pub fn super_option_values<'a>(&'a self, key: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
        self.super_options.iter().filter_map(move |option| {
            option
                .strip_prefix(key)
                .and_then(|rest| rest.strip_prefix(b"="))
        })
    }
}

/// Parses `/proc/<pid>/mountinfo`.
///
/// Fields are split on single spaces, then decoded. That order is what makes
/// the split unambiguous: the kernel writes every field a user can name — the
/// root, the mount point, the type, the source — with space, tab, newline, and
/// backslash escaped, so the only raw spaces on a line are separators and the
/// first `" - "` is the one before the type. Splitting after decoding would let
/// a directory named `a - b` move every field after it.
///
/// Strict: a line that does not have the documented shape fails the whole
/// table. This table is evidence in a trust decision, and a skipped line is a
/// mount nobody looked at. The optional fields are the format's extension
/// point and any number of them is accepted; a field the kernel always writes
/// first — `rw` or `ro` at the head of both option lists — is checked, so a
/// format change that moved the fields is refused rather than misread.
///
/// # Errors
///
/// [`SysError::Malformed`], naming the line, for a line without the separator,
/// with fewer fields than the format requires, with an id or device number
/// that is not a decimal number, or with option lists that do not begin with
/// `rw` or `ro`; and for a table that ends in the middle of a line.
pub fn parse_mountinfo(path: &str, bytes: &[u8]) -> Result<Vec<MountEntry>, SysError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let Some(body) = bytes.strip_suffix(b"\n") else {
        return Err(SysError::malformed(
            path,
            "the table ends in the middle of a line",
        ));
    };
    body.split(|byte| *byte == b'\n')
        .enumerate()
        .map(|(index, line)| {
            parse_mount_line(line).map_err(|reason| {
                SysError::malformed(path, format!("line {}: {reason}", index.saturating_add(1)))
            })
        })
        .collect()
}

/// One line of mountinfo, or what is wrong with it.
fn parse_mount_line(line: &[u8]) -> Result<MountEntry, &'static str> {
    let (head, tail) = line
        .split_once_str(" - ")
        .ok_or("no \" - \" separator before the filesystem type")?;
    let head: Vec<&[u8]> = head.split(|byte| *byte == b' ').collect();
    let [
        id,
        parent,
        device,
        root,
        mount_point,
        options,
        optional @ ..,
    ] = head.as_slice()
    else {
        return Err("fewer than six fields before the separator");
    };
    // At most three: the superblock options are last, so nothing a filesystem
    // prints in them can shift a field before them.
    let tail: Vec<&[u8]> = tail.splitn(3, |byte| *byte == b' ').collect();
    let [fs_type, source, super_options] = tail.as_slice() else {
        return Err("fewer than three fields after the separator");
    };
    let (major, minor) = device
        .split_once_str(":")
        .ok_or("the device is not major:minor")?;
    let entry = MountEntry {
        mount_id: decimal(id).ok_or("the mount id is not a number")?,
        parent_id: decimal(parent).ok_or("the parent id is not a number")?,
        major: decimal(major).ok_or("the major number is not a number")?,
        minor: decimal(minor).ok_or("the minor number is not a number")?,
        root: unescape(root),
        mount_point: unescape(mount_point),
        mount_options: option_list(options),
        optional_fields: optional.iter().map(|field| field.to_vec()).collect(),
        fs_type: unescape(fs_type),
        source: unescape(source),
        super_options: option_list(super_options),
    };
    if !begins_with_access_mode(&entry.mount_options) {
        return Err("the mount options do not begin with rw or ro");
    }
    if !begins_with_access_mode(&entry.super_options) {
        return Err("the superblock options do not begin with rw or ro");
    }
    Ok(entry)
}

/// The mount a descriptor was opened through, from `/proc/<pid>/fdinfo/<fd>`.
///
/// The `mnt_id` line, present since Linux 3.15, is the same number as the
/// first field of that mount's mountinfo line.
///
/// # Errors
///
/// [`SysError::Malformed`] when there is no `mnt_id` line, more than one, or one
/// whose value is not a decimal number.
pub fn parse_fdinfo_mount_id(path: &str, bytes: &[u8]) -> Result<u32, SysError> {
    let mut values = bytes
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"mnt_id:"));
    match (values.next(), values.next()) {
        (Some(value), None) => decimal(value.trim_ascii())
            .ok_or_else(|| SysError::malformed(path, "mnt_id is not a number")),
        (None, _) => Err(SysError::malformed(path, "no mnt_id line")),
        (Some(_), Some(_)) => Err(SysError::malformed(path, "more than one mnt_id line")),
    }
}

/// A decimal number as the kernel prints one: digits only, nothing else.
///
/// Stricter than `str::parse`, which accepts a leading `+` the kernel never
/// writes.
fn decimal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse().ok())
}

/// An option list, split on commas and each option decoded.
///
/// Split first: a filesystem that prints a value containing a comma escapes it,
/// and decoding before the split would turn that comma into a separator.
fn option_list(field: &[u8]) -> Vec<Vec<u8>> {
    field.split(|byte| *byte == b',').map(unescape).collect()
}

/// Whether an option list starts the way the kernel always starts one.
fn begins_with_access_mode(options: &[Vec<u8>]) -> bool {
    matches!(options.first().map(Vec::as_slice), Some(b"rw" | b"ro"))
}

/// Decodes the kernel's octal escapes, byte for byte.
///
/// The kernel writes each byte it escapes as a backslash and three octal
/// digits: `\040` for a space, `\011` a tab, `\012` a newline, `\134` a
/// backslash. A backslash followed by anything else was not written by that
/// escaper — a filesystem printing its own options unescaped — and is kept as
/// it stands rather than guessed at.
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&byte, tail)) = rest.split_first() {
        if let (b'\\', Some(escaped)) = (byte, octal_byte(tail)) {
            decoded.push(escaped);
            // `octal_byte` matched three bytes, so they are there to skip.
            rest = tail.get(3..).unwrap_or_default();
        } else {
            decoded.push(byte);
            rest = tail;
        }
    }
    decoded
}

/// The byte three octal digits name, if the slice starts with three that name
/// one. The first digit is at most `3`, because `\377` is the largest byte.
fn octal_byte(digits: &[u8]) -> Option<u8> {
    match digits {
        [
            high @ b'0'..=b'3',
            middle @ b'0'..=b'7',
            low @ b'0'..=b'7',
            ..,
        ] => std::str::from_utf8(&[*high, *middle, *low])
            .ok()
            .and_then(|text| u8::from_str_radix(text, 8).ok()),
        _ => None,
    }
}

fn parse_u32(path: &str, bytes: &[u8]) -> Result<u32, SysError> {
    let text = bytes
        .to_str()
        .map_err(|_| SysError::malformed(path, "numeric field is not valid UTF-8"))?;
    text.parse()
        .map_err(|_| SysError::malformed(path, format!("{text:?} is not a u32")))
}

fn parse_u64(path: &str, bytes: &[u8]) -> Result<u64, SysError> {
    let text = bytes
        .to_str()
        .map_err(|_| SysError::malformed(path, "numeric field is not valid UTF-8"))?;
    text.parse()
        .map_err(|_| SysError::malformed(path, format!("{text:?} is not a u64")))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// A realistic line, with all 52 fields.
    fn stat_line(pid: u32, comm: &str, parent: u32, starttime: u64) -> String {
        let mut fields = vec![
            "S".to_owned(),       // 3 state
            parent.to_string(),   // 4 ppid
            "1".to_owned(),       // 5 pgrp
            "1".to_owned(),       // 6 session
            "0".to_owned(),       // 7 tty_nr
            "-1".to_owned(),      // 8 tpgid
            "4194304".to_owned(), // 9 flags
        ];
        // 10..=21: minflt through itrealvalue — twelve fields.
        for _ in 0..12 {
            fields.push("0".to_owned());
        }
        fields.push(starttime.to_string()); // 22 starttime
        for _ in 0..30 {
            fields.push("0".to_owned());
        }
        format!("{pid} ({comm}) {}", fields.join(" "))
    }

    #[test]
    fn a_normal_stat_line_parses() {
        let parsed = parse_stat("1/stat", stat_line(412, "bash", 411, 98_765).as_bytes()).unwrap();
        assert_eq!(
            parsed,
            ProcStat {
                pid: 412,
                comm: b"bash".to_vec(),
                ppid: 411,
                starttime: 98_765,
            }
        );
        assert!(format!("{parsed:?}").contains("412"));
    }

    #[test]
    fn a_comm_containing_a_close_paren_cannot_shift_the_later_fields() {
        // The attack this parser exists to defeat. A process named
        // `evil) 1 999 (` makes a first-paren parser read 999 as the ppid and
        // point an ancestry walk at a process of the attacker's choosing.
        let line = stat_line(412, "evil) 1 999 (", 411, 98_765);
        let parsed = parse_stat("1/stat", line.as_bytes()).unwrap();
        assert_eq!(parsed.ppid, 411, "ppid was shifted by a crafted comm");
        assert_eq!(parsed.starttime, 98_765);
        assert_eq!(parsed.comm, b"evil) 1 999 (".to_vec());
    }

    #[test]
    fn a_comm_containing_spaces_parses() {
        let line = stat_line(7, "Web Content", 6, 42);
        let parsed = parse_stat("7/stat", line.as_bytes()).unwrap();
        assert_eq!(parsed.comm, b"Web Content".to_vec());
        assert_eq!(parsed.ppid, 6);
    }

    #[test]
    fn a_comm_of_arbitrary_bytes_survives_as_bytes() {
        let mut line = b"9 (".to_vec();
        line.extend_from_slice(&[0xff, 0xfe]);
        line.extend_from_slice(
            stat_line(9, "x", 8, 5)
                .split_once(')')
                .unwrap()
                .1
                .as_bytes(),
        );
        // Rebuild with the invalid bytes inside the parens.
        let rebuilt = {
            let tail = stat_line(9, "x", 8, 5);
            let tail = tail.split_once(')').unwrap().1;
            let mut v = b"9 (".to_vec();
            v.extend_from_slice(&[0xff, 0xfe]);
            v.push(b')');
            v.extend_from_slice(tail.as_bytes());
            v
        };
        let parsed = parse_stat("9/stat", &rebuilt).unwrap();
        assert_eq!(parsed.comm, vec![0xff, 0xfe]);
        assert!(!line.is_empty());
    }

    #[test]
    fn malformed_stat_lines_fail_rather_than_guess() {
        let cases: [(&[u8], &str); 6] = [
            (b"412 bash S 411", "no opening parenthesis"),
            (b"412 (bash S 411", "no closing parenthesis"),
            (b"412 )bash( S 411", "precedes"),
            (b"(bash) S 411", "not a u32"),
            (b"412 (bash)", "ppid field is absent"),
            (b"412 (bash) S", "ppid field is absent"),
        ];
        for (input, expected) in cases {
            let err = parse_stat("x/stat", input).unwrap_err();
            assert!(
                err.to_string().contains(expected),
                "{input:?} gave {err}, wanted {expected}"
            );
        }
    }

    #[test]
    fn a_stat_line_missing_starttime_fails() {
        // Every field up to ppid present, but truncated before field 22.
        let short = "412 (bash) S 411 1 1 0 -1 0 0 0";
        let err = parse_stat("x/stat", short.as_bytes()).unwrap_err();
        assert!(
            err.to_string().contains("starttime field is absent"),
            "{err}"
        );
    }

    #[test]
    fn non_numeric_and_non_utf8_numeric_fields_fail() {
        let line = stat_line(412, "bash", 411, 1).replace(") S 411", ") S notanumber");
        let err = parse_stat("x/stat", line.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("not a u32"), "{err}");

        let mut bad_pid = vec![0xff];
        bad_pid.extend_from_slice(b" (bash) S 411");
        let err = parse_stat("x/stat", &bad_pid).unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");

        // The starttime field specifically, which is parsed as a u64 and so
        // travels a different path than the pid and ppid.
        let mut fields: Vec<String> = vec!["S".into(), "411".into()];
        for _ in 0..17 {
            fields.push("0".to_owned());
        }
        fields.push("notau64".to_owned());
        let bad_starttime = format!("412 (bash) {}", fields.join(" "));
        let err = parse_stat("x/stat", bad_starttime.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("is not a u64"), "{err}");

        // And a starttime that is not even text.
        let mut bad_bytes = format!("412 (bash) {}", fields[..19].join(" ")).into_bytes();
        bad_bytes.extend_from_slice(b" ");
        bad_bytes.push(0xff);
        let err = parse_stat("x/stat", &bad_bytes).unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn a_stat_line_with_extra_whitespace_still_parses() {
        // The kernel does not pad these fields, but a fixture or a reimplemented
        // /proc might, and mis-parsing the pid is not a failure worth having.
        let padded = format!("   {}", stat_line(412, "bash", 411, 777));
        let parsed = parse_stat("x", padded.as_bytes()).unwrap();
        assert_eq!(parsed.pid, 412);
        assert_eq!(parsed.ppid, 411);
        assert_eq!(parsed.starttime, 777);
    }

    #[test]
    fn the_unified_cgroup_path_is_extracted() {
        let text =
            "12:pids:/user.slice\n1:name=systemd:/user.slice\n0::/user.slice/session-3.scope\n";
        let path = parse_cgroup(text).unwrap();
        assert_eq!(path.as_str(), "/user.slice/session-3.scope");
        assert!(format!("{path:?}").contains("session-3"));
    }

    #[test]
    fn a_v1_only_host_yields_no_unified_path_rather_than_a_guess() {
        // Guessing here would produce a confident wrong answer at the point
        // where M4 decides whether a caller is an enrolled agent.
        let text = "12:pids:/user.slice\n1:name=systemd:/user.slice\n";
        assert!(parse_cgroup(text).is_none());
        assert!(parse_cgroup("").is_none());
    }

    #[test]
    fn cgroup_containment_respects_component_boundaries() {
        let scope = CgroupPath("/aido.slice/agent-3.scope".to_owned());
        assert!(scope.is_under("/aido.slice"));
        assert!(scope.is_under("/aido.slice/"));
        assert!(scope.is_under("/aido.slice/agent-3.scope"));
        // The prefix-match bug, in the place it would matter most.
        assert!(!scope.is_under("/aido.slice-evil"));
        assert!(!CgroupPath("/aido.slice-evil/x".to_owned()).is_under("/aido.slice"));
        assert!(!CgroupPath("/user.slice".to_owned()).is_under("/aido.slice"));
    }

    #[test]
    fn a_cgroup_path_equal_to_the_prefix_with_a_trailing_slash_is_not_a_child() {
        assert!(!CgroupPath("/aido.slice/".to_owned()).is_under("/aido.slice/"));
    }

    /// Lines in the shapes real kernels write: Docker's overlay root, a procfs,
    /// a tmpfs with an empty source, a mount with propagation tags, and the
    /// FUSE line `fusermount3` produced for uid 1000 on Linux 6.12.
    const MOUNTINFO: &str = "\
286 201 0:70 / / rw,relatime - overlay overlay rw,lowerdir=/l/1:/l/2,upperdir=/u,workdir=/w
288 286 0:95 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
301 286 0:99 / /run/empty rw,relatime shared:12 master:3 - tmpfs  rw,size=1024k
200 286 0:75 / /home/u/merged rw,nosuid,nodev,noatime - fuse.fuse-overlayfs fuse-overlayfs \
rw,user_id=1000,group_id=1000,default_permissions
";

    #[test]
    fn every_field_of_a_mountinfo_line_is_kept() {
        let entries = parse_mountinfo("self/mountinfo", MOUNTINFO.as_bytes()).unwrap();
        assert_eq!(entries.len(), 4);
        let fuse = &entries[3];
        assert_eq!(
            *fuse,
            MountEntry {
                mount_id: 200,
                parent_id: 286,
                major: 0,
                minor: 75,
                root: b"/".to_vec(),
                mount_point: b"/home/u/merged".to_vec(),
                mount_options: vec![
                    b"rw".to_vec(),
                    b"nosuid".to_vec(),
                    b"nodev".to_vec(),
                    b"noatime".to_vec(),
                ],
                optional_fields: Vec::new(),
                fs_type: b"fuse.fuse-overlayfs".to_vec(),
                source: b"fuse-overlayfs".to_vec(),
                super_options: vec![
                    b"rw".to_vec(),
                    b"user_id=1000".to_vec(),
                    b"group_id=1000".to_vec(),
                    b"default_permissions".to_vec(),
                ],
            }
        );
        assert!(fuse.has_mount_option(b"nosuid"));
        assert!(!fuse.has_mount_option(b"suid"));
        assert_eq!(
            fuse.super_option_values(b"user_id").collect::<Vec<_>>(),
            vec![b"1000".as_slice()]
        );
        // A key is matched whole: `group_id` is not a value of `id`.
        assert_eq!(fuse.super_option_values(b"id").count(), 0);
        assert!(format!("{fuse:?}").contains("200"));

        // The propagation tags are kept, and an empty source is a field, not
        // a reason to shift the superblock options into its place.
        let tmpfs = &entries[2];
        assert_eq!(
            tmpfs.optional_fields,
            vec![b"shared:12".to_vec(), b"master:3".to_vec()]
        );
        assert_eq!(tmpfs.source, b"");
        assert_eq!(tmpfs.super_options[1], b"size=1024k");
    }

    #[test]
    fn escaped_mount_points_decode_byte_exactly() {
        // A space, a tab, a newline, a backslash, and a byte that is not UTF-8,
        // each as the kernel escapes it. A backslash the kernel's escaper did
        // not write is kept as it stands.
        let line = b"40 1 8:1 /src\\040dir /mnt/a\\040b\\011c\\012d\\134e\\377 rw - ext4 \
/dev/disk\\040one rw,opt=x\\054y,raw\\9\n";
        let entries = parse_mountinfo("self/mountinfo", line).unwrap();
        let entry = &entries[0];
        assert_eq!(entry.root, b"/src dir");
        assert_eq!(entry.mount_point, b"/mnt/a b\tc\nd\\e\xff");
        assert_eq!(entry.source, b"/dev/disk one");
        // An escaped comma inside a value is not a separator.
        assert_eq!(entry.super_options[1], b"opt=x,y");
        assert_eq!(entry.super_options[2], b"raw\\9");
    }

    #[test]
    fn a_directory_named_like_the_separator_cannot_move_a_field() {
        // `a - b` arrives escaped, so the first raw " - " is still the one
        // before the type. Decoding before splitting would read "b" as the
        // type and push everything after it along.
        let line = b"41 1 8:1 / /mnt/a\\040-\\040b rw,nosuid - fuse.x - rw,user_id=1000\n";
        let entries = parse_mountinfo("self/mountinfo", line).unwrap();
        let entry = &entries[0];
        assert_eq!(entry.mount_point, b"/mnt/a - b");
        assert_eq!(entry.fs_type, b"fuse.x");
        assert_eq!(entry.source, b"-");
        assert!(entry.has_mount_option(b"nosuid"));
    }

    #[test]
    fn an_escape_that_names_no_byte_is_kept_as_written() {
        // `\4xx` would be above 255 and `\12` is cut short by the end of the
        // field; neither is something the kernel's escaper writes.
        let line = b"42 1 8:1 / /m\\400\\12 rw - ext4 src rw\n";
        let entry = &parse_mountinfo("self/mountinfo", line).unwrap()[0];
        assert_eq!(entry.mount_point, b"/m\\400\\12");
    }

    #[test]
    fn a_malformed_mountinfo_line_refuses_the_whole_table() {
        // Each of these, skipped instead, would be a mount nobody looked at.
        let good = "25 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";
        let cases: [(&str, &str); 12] = [
            (
                "25 1 8:1 / / rw ext4 /dev/sda1 rw\n",
                "no \" - \" separator",
            ),
            (
                "25 1 8:1 / / - ext4 /dev/sda1 rw\n",
                "fewer than six fields",
            ),
            ("25 1 8:1 / / rw - ext4\n", "fewer than three fields"),
            (
                "25 1 8:1 / / rw - ext4 /dev/sda1\n",
                "fewer than three fields",
            ),
            ("x 1 8:1 / / rw - ext4 /dev/sda1 rw\n", "mount id is not"),
            ("+25 1 8:1 / / rw - ext4 /dev/sda1 rw\n", "mount id is not"),
            ("25 y 8:1 / / rw - ext4 /dev/sda1 rw\n", "parent id is not"),
            ("25 1 8-1 / / rw - ext4 /dev/sda1 rw\n", "not major:minor"),
            (
                "25 1 :1 / / rw - ext4 /dev/sda1 rw\n",
                "major number is not",
            ),
            (
                "25 1 8:99999999999 / / rw - ext4 /dev/sda1 rw\n",
                "minor number is not",
            ),
            (
                "25 1 8:1 / / nosuid,rw - ext4 /dev/sda1 rw\n",
                "mount options do not",
            ),
            (
                "25 1 8:1 / / rw - ext4 /dev/sda1 user_id=0\n",
                "superblock options do not",
            ),
        ];
        for (line, expected) in cases {
            let table = format!("{good}{line}");
            let err = parse_mountinfo("self/mountinfo", table.as_bytes()).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("line 2: "), "{line:?} gave {message}");
            assert!(message.contains(expected), "{line:?} gave {message}");
            assert!(message.contains("self/mountinfo"), "{message}");
        }
    }

    #[test]
    fn a_table_that_stops_mid_line_is_refused() {
        // The kernel ends every line; a table that does not end one was cut
        // short, and its last mount is not all there.
        let err = parse_mountinfo("m", b"25 1 8:1 / / rw - ext4 /dev/sda1 rw").unwrap_err();
        assert!(err.to_string().contains("middle of a line"), "{err}");
        // A blank line inside the table is a line without a shape.
        assert!(parse_mountinfo("m", b"\n").is_err());
    }

    #[test]
    fn mountinfo_of_nothing_is_an_empty_table() {
        // Not an error here; a lookup in it finds nothing, and that refuses.
        assert_eq!(parse_mountinfo("m", b""), Ok(Vec::new()));
    }

    #[test]
    fn the_mount_of_a_descriptor_is_read_from_its_fdinfo() {
        let fdinfo = b"pos:\t0\nflags:\t02100000\nmnt_id:\t289\nino:\t5\n";
        assert_eq!(parse_fdinfo_mount_id("fdinfo/7", fdinfo), Ok(289));

        let cases: [(&[u8], &str); 4] = [
            (b"pos:\t0\nflags:\t0\n", "no mnt_id line"),
            (b"mnt_id:\t1\nmnt_id:\t2\n", "more than one mnt_id line"),
            (b"mnt_id:\t\n", "not a number"),
            (b"mnt_id:\t-1\n", "not a number"),
        ];
        for (bytes, expected) in cases {
            let err = parse_fdinfo_mount_id("fdinfo/7", bytes).unwrap_err();
            assert!(err.to_string().contains(expected), "{bytes:?} gave {err}");
            assert!(err.to_string().contains("fdinfo/7"), "{err}");
        }
    }
}
