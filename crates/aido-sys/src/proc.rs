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

/// One line of `/proc/self/mountinfo`, reduced to what matters here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// Where it is mounted.
    pub mount_point: String,
    /// The filesystem type.
    pub fs_type: String,
    /// Mount options, split on `,`.
    pub options: Vec<String>,
}

impl MountEntry {
    /// Whether the mount carries an option, by exact name.
    pub fn has_option(&self, name: &str) -> bool {
        self.options.iter().any(|o| o == name)
    }
}

/// Parses `/proc/self/mountinfo`.
///
/// Lines that do not have the documented shape are skipped rather than fatal:
/// the format has grown optional fields over time, and refusing to start
/// because one line is unfamiliar would fail closed in the unhelpful direction
/// — the caller uses this to *discover* that a path is on an untrustworthy
/// mount, so an empty answer is safer than no answer at all.
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            // ... 5:mount_point 6:options - fs_type source super_opts
            let (before, after) = line.split_once(" - ")?;
            let head: Vec<&str> = before.split(' ').collect();
            let mount_point = head.get(4)?;
            let options = head.get(5)?;
            // `split_once` rather than `split().next()`: the latter can never
            // yield `None`, so it would leave an untestable branch behind.
            let fs_type = after.split_once(' ').map_or(after, |(ty, _)| ty);
            Some(MountEntry {
                mount_point: (*mount_point).to_owned(),
                fs_type: fs_type.to_owned(),
                options: options.split(',').map(ToOwned::to_owned).collect(),
            })
        })
        .collect()
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

    #[test]
    fn mountinfo_lines_parse_into_options() {
        let text = "\
25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
26 30 0:24 / /sys rw,nosuid - sysfs sysfs rw
31 30 0:25 / /home/u/mnt rw,nosuid,nodev,relatime - fuse.sshfs user@host:/ rw,user_id=1000
";
        let entries = parse_mountinfo(text);
        assert_eq!(entries.len(), 3);
        let proc = entries.first().unwrap();
        assert_eq!(proc.mount_point, "/proc");
        assert_eq!(proc.fs_type, "proc");
        assert!(proc.has_option("nosuid"));
        assert!(proc.has_option("noexec"));
        assert!(!proc.has_option("suid"));
        assert_eq!(
            entries.get(2).map(|e| e.fs_type.as_str()),
            Some("fuse.sshfs")
        );
        assert!(format!("{proc:?}").contains("/proc"));
    }

    #[test]
    fn unfamiliar_mountinfo_lines_are_skipped_not_fatal() {
        // The format has grown optional fields; refusing to start because one
        // line is unfamiliar would fail closed in the unhelpful direction.
        let text = concat!(
            "garbage\n",
            "25 30 0:23 / /proc rw - proc proc rw\n",
            "also garbage - \n",
            // Five head fields: a mount point but no options column.
            "31 30 0:25 / /mnt - ext4\n",
            // No trailing columns after the type at all.
            "32 30 0:26 / /srv rw - tmpfs\n",
        );
        let entries = parse_mountinfo(text);
        // A line with no separator, and a line with a separator but too few
        // head fields, both contribute nothing rather than a half-parsed entry
        // a caller might trust. A line whose type column has nothing after it
        // is still usable.
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(
            entries.first().map(|e| e.mount_point.as_str()),
            Some("/proc")
        );
        let last = entries.get(1).unwrap();
        assert_eq!(last.mount_point, "/srv");
        assert_eq!(last.fs_type, "tmpfs");
    }

    #[test]
    fn mountinfo_of_nothing_is_empty() {
        assert!(parse_mountinfo("").is_empty());
    }
}
