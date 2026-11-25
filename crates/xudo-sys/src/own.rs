//! What a process can read about itself, behind a seam.
//!
//! The unit-record helper (`xudo-session`) decides from its own uid, its own
//! parent and its own start time. Reading them behind a trait lets a test
//! stand in a helper that was not started by pid 1, without being root.

use crate::{ProcStat, SysError, parse_stat};

/// The calling process's own identity.
pub trait OwnFacts {
    /// The real user id.
    fn uid(&self) -> u32;

    /// `/proc/self/stat`: pid, parent and start time.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or does not parse, and
    /// always off Linux, where there is no such file to trust.
    fn stat(&self) -> Result<ProcStat, SysError>;
}

/// This process, on this host.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostOwn;

impl OwnFacts for HostOwn {
    fn uid(&self) -> u32 {
        rustix::process::getuid().as_raw()
    }

    fn stat(&self) -> Result<ProcStat, SysError> {
        parse_own_stat(std::fs::read("/proc/self/stat"))
    }
}

/// `/proc/self/stat` as read, or why it could not be.
fn parse_own_stat(read: std::io::Result<Vec<u8>>) -> Result<ProcStat, SysError> {
    let bytes = read.map_err(|error| SysError::read("/proc/self/stat", error.to_string()))?;
    parse_stat("/proc/self/stat", &bytes)
}

/// A scripted process, for tests.
#[cfg(any(test, feature = "fake"))]
#[derive(Clone, Debug)]
pub struct FakeOwn {
    /// The uid to report.
    pub uid: u32,
    /// What `stat` answers.
    pub stat: Result<ProcStat, SysError>,
}

#[cfg(any(test, feature = "fake"))]
impl FakeOwn {
    /// A process with `uid`, `pid`, `parent` and `starttime`.
    #[must_use]
    pub fn new(uid: u32, pid: u32, parent: u32, starttime: u64) -> Self {
        Self {
            uid,
            stat: Ok(ProcStat {
                pid,
                comm: b"xudo-session".to_vec(),
                ppid: parent,
                session: 0,
                tty_nr: 0,
                starttime,
            }),
        }
    }
}

#[cfg(any(test, feature = "fake"))]
impl OwnFacts for FakeOwn {
    fn uid(&self) -> u32 {
        self.uid
    }

    fn stat(&self) -> Result<ProcStat, SysError> {
        self.stat.clone()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_reads_its_own_stat_and_uid() {
        let stat = HostOwn.stat().unwrap();
        assert_eq!(stat.pid, std::process::id());
        assert_eq!(HostOwn.uid(), rustix::process::getuid().as_raw());
        assert_ne!(stat.starttime, 0);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_host_without_proc_has_no_stat_to_trust() {
        assert!(HostOwn.stat().is_err());
        let _ = HostOwn.uid();
    }

    #[test]
    fn an_unreadable_or_malformed_own_stat_is_an_error() {
        let gone = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(parse_own_stat(Err(gone)).is_err());
        assert!(parse_own_stat(Ok(b"junk".to_vec())).is_err());
        let ok = b"7 (x) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 55".to_vec();
        assert_eq!(parse_own_stat(Ok(ok)).unwrap().starttime, 55);
    }

    #[test]
    fn a_scripted_process_answers_what_it_was_given() {
        let own = FakeOwn::new(7, 3, 1, 99);
        assert_eq!(own.uid(), 7);
        let stat = own.stat().unwrap();
        assert_eq!((stat.pid, stat.ppid, stat.starttime), (3, 1, 99));
        let broken = FakeOwn {
            uid: 0,
            stat: Err(SysError::read("x", "gone")),
        };
        assert!(broken.stat().is_err());
        assert_eq!(broken.uid(), 0);
    }
}
