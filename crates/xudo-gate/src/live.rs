//! What the gate reads from `/proc` about a process, for itself.
//!
//! The broker's entry says whose request this is and which uid they ran as.
//! Both are claims. The gate reads the uid from the live ancestor's own
//! `status`, and checks that the ancestor and the gate itself are in the same
//! namespaces as PID 1, through the pinned procfs descriptor. A caller in a
//! user, pid, cgroup, or mount namespace of its own can show the gate a `/proc`
//! or a cgroup tree that is not the host's, so the answer for such a caller is
//! "cannot attest", and the gate treats it as unattested.
//!
//! # Where the trust boundary sits
//!
//! "PID 1's namespaces" means PID 1 of the pid namespace of the pinned `/proc`.
//! On a normal host that is the host's init. Inside a container, or a setuid
//! sandbox that gives the caller its own pid and mount namespaces and a fresh
//! `/proc` (firejail), the checks compare against that namespace's init and
//! pass. Containers are not a supported deployment. No upgrade is known from
//! there: cgroup membership does not change, and an unprivileged user cannot
//! build that layout without a setuid helper. The stricter check, if it is
//! ever wanted, compares the fixed init inodes (user `0xEFFFFFFD`, pid
//! `0xEFFFFFFC`, cgroup `0xEFFFFFFB`).

use xudo_sys::{
    ProcRef, ProcSource, is_identity_uid_map, parse_nspid_count, parse_stat, parse_status_uids,
};

/// The namespace kinds that must equal PID 1's.
const KINDS: [&str; 4] = ["user", "pid", "cgroup", "mnt"];

/// What one process's `/proc` says about it right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveFacts {
    /// Its real uid, when its `status` parses and the process is still the one
    /// pinned. The real uid, not the effective one: the pinned `xudo` execs the
    /// setuid `sudo`, whose effective uid is root while its real uid stays the
    /// invoking user's, and the real uid is the account `sudo` authenticates.
    pub uid: Option<u32>,
    /// Whether its user, pid, cgroup, and mount namespaces are PID 1's, its
    /// `NSpid` has one level, and its `uid_map` is the identity map. False on
    /// any difference and on any read that failed.
    pub namespaces_match_init: bool,
}

/// Reads `process`'s facts through `proc`.
///
/// `stat` is read before and after the rest, and both must still name the
/// pinned `(pid, starttime)`: a pid that was reused halfway through yields
/// nothing rather than a mixture of two processes.
pub fn read(proc: &dyn ProcSource, process: &ProcRef) -> LiveFacts {
    let pid = process.pid;
    let before = pinned(proc, process);
    let status = proc.read(&format!("{pid}/status")).ok();
    let uid = status
        .as_deref()
        .and_then(|bytes| parse_status_uids("/proc/<pid>/status", bytes).ok())
        .map(|uids| uids.real);
    let namespaces = namespaces_match_init(proc, pid, status.as_deref());
    if before && pinned(proc, process) {
        LiveFacts {
            uid,
            namespaces_match_init: namespaces,
        }
    } else {
        LiveFacts {
            uid: None,
            namespaces_match_init: false,
        }
    }
}

fn pinned(proc: &dyn ProcSource, process: &ProcRef) -> bool {
    proc.read(&format!("{}/stat", process.pid))
        .and_then(|bytes| parse_stat("/proc/<pid>/stat", &bytes))
        .is_ok_and(|stat| stat.pid == process.pid && stat.starttime == process.starttime)
}

fn namespaces_match_init(proc: &dyn ProcSource, pid: u32, status: Option<&[u8]>) -> bool {
    status.and_then(parse_nspid_count) == Some(1)
        && proc
            .read(&format!("{pid}/uid_map"))
            .is_ok_and(|bytes| is_identity_uid_map(&bytes))
        && KINDS.iter().all(|kind| {
            let own = proc.namespace_inode(&format!("{pid}/ns/{kind}"));
            let init = proc.namespace_inode(&format!("1/ns/{kind}"));
            own.is_ok() && own == init
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;
    use xudo_sys::MapSource;

    const PID: u32 = 412;
    const START: u64 = 700;

    fn stat(pid: u32, starttime: u64) -> String {
        let mut fields = vec!["S".to_owned(), "1".to_owned()];
        for _ in 0..17 {
            fields.push("0".to_owned());
        }
        fields.push(starttime.to_string());
        format!("{pid} (test) {}", fields.join(" "))
    }

    fn status(uid: &str, nspid: &str) -> String {
        format!("Name:\ttest\nUid:\t{uid}\nNSpid:\t{nspid}\n")
    }

    /// A process in every namespace PID 1 is in.
    fn clean() -> MapSource {
        let mut source = MapSource::new()
            .with(format!("{PID}/stat"), stat(PID, START))
            .with(
                format!("{PID}/status"),
                status("1000\t1000\t1000\t1000", "412"),
            )
            .with(
                format!("{PID}/uid_map"),
                "         0          0 4294967295\n",
            );
        for (index, kind) in KINDS.iter().enumerate() {
            let inode = 4_026_531_800 + u64::try_from(index).unwrap();
            source = source
                .with_inode(format!("{PID}/ns/{kind}"), inode)
                .with_inode(format!("1/ns/{kind}"), inode);
        }
        source
    }

    fn process() -> ProcRef {
        ProcRef {
            pid: PID,
            starttime: START,
            comm: b"test".to_vec(),
        }
    }

    fn facts(source: &MapSource) -> LiveFacts {
        read(source, &process())
    }

    #[test]
    fn a_process_in_the_init_namespaces_reads_clean_with_its_live_uid() {
        assert_eq!(
            facts(&clean()),
            LiveFacts {
                uid: Some(1000),
                namespaces_match_init: true
            }
        );
    }

    #[test]
    fn the_gate_refuses_an_ancestor_in_another_namespace_of_each_kind() {
        // A literal list: it must not shrink when `KINDS` does.
        for kind in ["user", "pid", "cgroup", "mnt"] {
            let source = clean().with_inode(format!("{PID}/ns/{kind}"), 4_026_539_999);
            let seen = facts(&source);
            assert!(!seen.namespaces_match_init, "{kind}");
            // The uid is still read: the namespace flag is the verdict.
            assert_eq!(seen.uid, Some(1000), "{kind}");
        }
    }

    #[test]
    fn an_unreadable_namespace_link_is_a_difference_not_a_pass() {
        for target in [format!("{PID}/ns/mnt"), "1/ns/user".to_owned()] {
            let mut source = MapSource::new()
                .with(format!("{PID}/stat"), stat(PID, START))
                .with(
                    format!("{PID}/status"),
                    status("1000\t1000\t1000\t1000", "412"),
                )
                .with(format!("{PID}/uid_map"), "0 0 4294967295\n");
            for kind in KINDS {
                for owner in [PID.to_string(), "1".to_owned()] {
                    let name = format!("{owner}/ns/{kind}");
                    if name != target {
                        source = source.with_inode(name, 7);
                    }
                }
            }
            assert!(!facts(&source).namespaces_match_init, "{target}");
        }
    }

    #[test]
    fn a_nested_pid_namespace_or_a_mapped_uid_namespace_is_a_difference() {
        let nested = clean().with(
            format!("{PID}/status"),
            status("1000\t1000\t1000\t1000", "412\t1"),
        );
        assert!(!facts(&nested).namespaces_match_init);
        let mapped = clean().with(format!("{PID}/uid_map"), "0 100000 65536\n");
        assert!(!facts(&mapped).namespaces_match_init);
        let no_map = MapSource::new()
            .with(format!("{PID}/stat"), stat(PID, START))
            .with(
                format!("{PID}/status"),
                status("1000\t1000\t1000\t1000", "412"),
            );
        assert!(!facts(&no_map).namespaces_match_init);
        let no_nspid = clean().with(format!("{PID}/status"), "Uid:\t1000\t1000\t1000\t1000\n");
        assert!(!facts(&no_nspid).namespaces_match_init);
    }

    #[test]
    fn the_gate_reads_the_uid_from_the_live_ancestor() {
        let other = clean().with(
            format!("{PID}/status"),
            status("1001\t1001\t1001\t1001", "412"),
        );
        assert_eq!(facts(&other).uid, Some(1001));
    }

    #[test]
    fn a_setuid_sudo_ancestor_reads_as_its_real_uid() {
        // The pinned xudo execs sudo: real uid the user's, effective root.
        let sudo = clean().with(format!("{PID}/status"), status("1000\t0\t0\t0", "412"));
        assert_eq!(facts(&sudo).uid, Some(1000));
    }

    #[test]
    fn an_unparsable_uid_line_is_not_attributed() {
        for uid in ["x\t1000\t1000\t1000", "1000"] {
            let source = clean().with(format!("{PID}/status"), status(uid, "412"));
            assert_eq!(facts(&source).uid, None, "{uid}");
        }
        let no_status = MapSource::new().with(format!("{PID}/stat"), stat(PID, START));
        assert_eq!(facts(&no_status).uid, None);
    }

    /// A source whose `<pid>/stat` answers from a script, one entry per read.
    struct Sequenced {
        inner: MapSource,
        stats: std::cell::RefCell<Vec<String>>,
    }

    impl ProcSource for Sequenced {
        fn read(&self, relative: &str) -> Result<Vec<u8>, xudo_sys::SysError> {
            if relative == format!("{PID}/stat") {
                let mut stats = self.stats.borrow_mut();
                let next = if stats.len() > 1 {
                    stats.remove(0)
                } else {
                    stats.first().cloned().unwrap_or_default()
                };
                return Ok(next.into_bytes());
            }
            self.inner.read(relative)
        }

        fn namespace_inode(&self, relative: &str) -> Result<u64, xudo_sys::SysError> {
            self.inner.namespace_inode(relative)
        }
    }

    #[test]
    fn a_pid_reused_between_the_reads_yields_nothing() {
        // The first stat names the pinned process, the second a reused pid:
        // dropping the check after the reads would let this through.
        let source = Sequenced {
            inner: clean(),
            stats: std::cell::RefCell::new(vec![stat(PID, START), stat(PID, START + 1)]),
        };
        assert_eq!(
            read(&source, &process()),
            LiveFacts {
                uid: None,
                namespaces_match_init: false
            }
        );
        // The same fake with both answers right is clean, so the fake itself
        // is not what refuses.
        let steady = Sequenced {
            inner: clean(),
            stats: std::cell::RefCell::new(vec![stat(PID, START), stat(PID, START)]),
        };
        assert!(read(&steady, &process()).namespaces_match_init);
    }

    #[test]
    fn a_process_that_is_not_the_pinned_one_yields_nothing() {
        let reused = clean().with(format!("{PID}/stat"), stat(PID, START + 1));
        let wrong_pid = clean().with(format!("{PID}/stat"), stat(PID + 1, START));
        let gone = MapSource::new();
        for source in [reused, wrong_pid, gone] {
            assert_eq!(
                facts(&source),
                LiveFacts {
                    uid: None,
                    namespaces_match_init: false
                }
            );
        }
    }
}
