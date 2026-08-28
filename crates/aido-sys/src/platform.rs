//! Privileged operations, behind a trait, with a stub that always refuses.
//!
//! At this milestone nothing here actually escalates. The point of the trait
//! existing now is that the front-end can be written, tested, and reviewed
//! against the interface before any of it can do harm — and that a developer on
//! macOS exercises the fail-closed branch of every decision path rather than a
//! convenient approximation of the Linux one.

use aido_policy::{CallerFacts, Classification};

use crate::error::SysError;
use crate::provenance::{MAX_ANCESTRY_DEPTH, ancestry, hints};
use crate::source::{DirSource, ProcSource};

/// What the platform can be asked to do.
pub trait PrivilegedOps {
    /// A short label for the implementation, for `aido doctor` and audit
    /// records.
    fn platform(&self) -> &'static str;

    /// Classifies a caller.
    ///
    /// # The only honest answer available today
    ///
    /// Every implementation returns [`Classification::Unattested`], because
    /// attestation needs the root broker: `SO_PEERPIDFD` for a race-free peer
    /// identity, and a root-created cgroup scope under `aido.slice` to compare
    /// it against. Neither exists yet.
    ///
    /// This is not a placeholder that will be filled in with something
    /// permissive. Unattested routes to the human path with a password, so
    /// until the broker lands, every caller authenticates — including a real
    /// agent. That is the correct direction for the gap: the project's second
    /// invariant is that misclassification may only withhold capability.
    ///
    /// # Errors
    ///
    /// Returns [`SysError`] when the caller's own `/proc` entry cannot be read,
    /// since a caller that cannot be observed at all cannot be described in an
    /// audit record either.
    fn classify(&self, pid: u32) -> Result<CallerFacts, SysError>;

    /// Resolves an executable path to something safe to execute.
    ///
    /// # Errors
    ///
    /// Always returns [`SysError::Unsupported`] at this milestone: safe
    /// resolution requires `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH |
    /// RESOLVE_NO_MAGICLINKS)` from a pinned directory descriptor, an ancestor
    /// ownership walk, and `execveat` on the descriptor that was validated
    /// rather than the path that was checked. Those arrive with M2, together.
    /// Shipping a path-based approximation in the meantime would create exactly
    /// the swap window the real implementation exists to close.
    fn resolve_exe(&self, path: &str) -> Result<std::path::PathBuf, SysError>;
}

/// The Linux implementation.
///
/// Reads provenance from a [`ProcSource`], so it is testable against a fixture
/// tree on any platform. What it cannot yet do is attest anything.
#[derive(Clone, Debug)]
pub struct LinuxOps<S> {
    source: S,
    depth_limit: usize,
}

impl LinuxOps<DirSource> {
    /// Builds an implementation reading the real `/proc`.
    pub fn host() -> Self {
        Self::with_source(DirSource::proc())
    }
}

impl<S: ProcSource> LinuxOps<S> {
    /// Builds an implementation reading from `source`.
    pub fn with_source(source: S) -> Self {
        Self {
            source,
            depth_limit: MAX_ANCESTRY_DEPTH,
        }
    }

    /// Overrides the ancestry depth bound.
    #[must_use]
    pub fn with_depth_limit(mut self, limit: usize) -> Self {
        self.depth_limit = limit;
        self
    }
}

impl<S: ProcSource> PrivilegedOps for LinuxOps<S> {
    fn platform(&self) -> &'static str {
        "linux"
    }

    fn classify(&self, pid: u32) -> Result<CallerFacts, SysError> {
        // The walk is here for the audit record, not for the verdict. It is
        // also what makes the failure honest: if the caller cannot be observed,
        // say so rather than describing a caller nobody looked at.
        let chain = ancestry(&self.source, pid, self.depth_limit)?;

        let mut facts = CallerFacts::new(
            Classification::Unattested {
                reason: format!(
                    "no broker: SO_PEERPIDFD and cgroup attestation are not available \
                     until M3, so no caller can be attested (ancestry: {})",
                    chain.describe()
                ),
            },
            0,
        );
        for hint in hints(&self.source, pid) {
            facts = facts.with_hint(hint);
        }
        Ok(facts)
    }

    fn resolve_exe(&self, _path: &str) -> Result<std::path::PathBuf, SysError> {
        Err(SysError::unsupported(
            "resolve_exe (needs openat2 + execveat, which land together in M2)",
        ))
    }
}

/// The macOS implementation, which refuses everything.
///
/// Deliberately not a partial approximation of the Linux behaviour. A developer
/// running the test suite on macOS should be unable to convince themselves that
/// a Linux-only assumption holds, so every answer here is the fail-closed one.
#[derive(Clone, Copy, Debug)]
pub struct MacOsStub;

impl PrivilegedOps for MacOsStub {
    fn platform(&self) -> &'static str {
        "macos-stub"
    }

    fn classify(&self, _pid: u32) -> Result<CallerFacts, SysError> {
        Ok(CallerFacts::new(
            Classification::Unattested {
                reason: "this platform cannot attest a caller; aido performs no privileged \
                         operation here"
                    .to_owned(),
            },
            0,
        ))
    }

    fn resolve_exe(&self, _path: &str) -> Result<std::path::PathBuf, SysError> {
        Err(SysError::unsupported("resolve_exe on a non-Linux platform"))
    }
}

/// The implementation for the platform this binary was built for.
///
/// Chosen at compile time so a non-Linux build cannot contain a code path that
/// would attempt a privileged operation.
#[cfg(target_os = "linux")]
pub fn host_ops() -> Box<dyn PrivilegedOps> {
    Box::new(LinuxOps::host())
}

/// The implementation for the platform this binary was built for.
#[cfg(not(target_os = "linux"))]
pub fn host_ops() -> Box<dyn PrivilegedOps> {
    Box::new(MacOsStub)
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
    use crate::source::MapSource;

    fn stat(pid: u32, comm: &str, parent: u32, starttime: u64) -> String {
        let mut tail: Vec<String> = vec!["S".into(), parent.to_string()];
        for _ in 0..17 {
            tail.push("0".to_owned());
        }
        tail.push(starttime.to_string());
        format!("{pid} ({comm}) {}", tail.join(" "))
    }

    fn source() -> MapSource {
        MapSource::new()
            .with("412/stat", stat(412, "bash", 1, 5000))
            .with("1/stat", stat(1, "systemd", 0, 1))
            .with("412/comm", "bash\n")
            .with("412/environ", b"CLAUDECODE=1\0".to_vec())
    }

    #[test]
    fn the_linux_implementation_cannot_attest_anyone_yet() {
        // The headline property of this milestone, and the reason it is safe to
        // ship: nobody gets the passwordless path, because nobody is attested.
        let ops = LinuxOps::with_source(source());
        assert_eq!(ops.platform(), "linux");
        let facts = ops.classify(412).unwrap();
        assert!(!facts.classification.is_enrolled_agent());
        assert!(facts.classification.requires_password());
        assert_eq!(facts.classification.label(), "unattested");
    }

    #[test]
    fn a_forged_agent_marker_does_not_change_the_classification() {
        // The source above exports CLAUDECODE=1. It is recorded and ignored.
        let ops = LinuxOps::with_source(source());
        let facts = ops.classify(412).unwrap();
        assert!(
            facts.hints.iter().any(|h| h.key == "CLAUDECODE"),
            "the claim should be recorded"
        );
        assert!(
            facts.classification.requires_password(),
            "and it should change nothing"
        );
    }

    #[test]
    fn the_unattested_reason_names_the_missing_mechanism_and_the_ancestry() {
        let ops = LinuxOps::with_source(source());
        let facts = ops.classify(412).unwrap();
        // Asserted on the rendered classification rather than through a match,
        // so there is no arm for a variant no implementation can return.
        let rendered = format!("{:?}", facts.classification);
        assert!(rendered.starts_with("Unattested"), "{rendered}");
        assert!(rendered.contains("SO_PEERPIDFD"), "{rendered}");
        assert!(rendered.contains("bash(412)"), "{rendered}");
    }

    #[test]
    fn an_unobservable_caller_is_an_error_not_an_invented_record() {
        let ops = LinuxOps::with_source(MapSource::new());
        let err = ops.classify(412).unwrap_err();
        assert!(err.to_string().contains("cannot read"), "{err}");
    }

    #[test]
    fn the_depth_limit_is_configurable_and_enforced() {
        let mut deep = MapSource::new();
        for pid in 1..=50u32 {
            deep = deep.with(
                format!("{pid}/stat"),
                stat(pid, "deep", pid.saturating_sub(1), u64::from(pid)),
            );
        }
        let ops = LinuxOps::with_source(deep).with_depth_limit(4);
        assert_eq!(
            ops.classify(50).unwrap_err(),
            SysError::AncestryTooDeep { limit: 4 }
        );
    }

    #[test]
    fn resolving_an_executable_is_refused_until_the_real_thing_lands() {
        // A path-based approximation would create the swap window that
        // openat2 + execveat exist to close, so there is no interim version.
        let ops = LinuxOps::with_source(source());
        let err = ops.resolve_exe("/usr/bin/systemctl").unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
        assert!(err.to_string().contains("M2"), "{err}");
    }

    #[test]
    fn the_macos_stub_refuses_everything() {
        let ops = MacOsStub;
        assert_eq!(ops.platform(), "macos-stub");
        let facts = ops.classify(1).unwrap();
        assert!(facts.classification.requires_password());
        assert!(ops.resolve_exe("/bin/ls").is_err());
        assert!(format!("{ops:?}").contains("MacOsStub"));
        assert_eq!(MacOsStub.platform(), "macos-stub");
    }

    #[test]
    fn the_host_implementation_matches_the_build_target() {
        let ops = host_ops();
        #[cfg(target_os = "linux")]
        assert_eq!(ops.platform(), "linux");
        #[cfg(not(target_os = "linux"))]
        assert_eq!(ops.platform(), "macos-stub");
        // Whatever the platform, it cannot attest and cannot resolve.
        assert!(ops.resolve_exe("/bin/ls").is_err());
    }

    #[test]
    fn the_host_linux_constructor_reads_the_real_proc() {
        // Constructed, not exercised: on a machine with no /proc the read fails,
        // which is the fail-closed path and is asserted above.
        let ops = LinuxOps::host();
        assert_eq!(ops.platform(), "linux");
        assert!(format!("{ops:?}").contains("proc"));
    }
}
