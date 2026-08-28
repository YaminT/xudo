//! Which kernel this is, and therefore which attestation is available.
//!
//! `aido` cannot require a 2025 kernel. Ubuntu 20.04 ships 5.4, Debian 11 ships
//! 5.10, and RHEL 9 ships 5.14 — all of them still in service, and all of them
//! missing the syscall the primary attestation path is built on. So the path is
//! a **ladder**, and this module decides which rung a host is on.
//!
//! # The rungs, and what each one actually proves
//!
//! | Rung | Since | What the broker learns about its peer |
//! |---|---|---|
//! | [`Attestation::PeerPidfdInfo`] | 6.13 | A pidfd *and* its creds and cgroup id in one race-free `PIDFD_GET_INFO` |
//! | [`Attestation::PeerPidfd`] | 6.5 | A pidfd straight from the socket via `SO_PEERPIDFD`; creds read through it |
//! | [`Attestation::PidfdOpen`] | 5.3 | A pid from `SO_PEERCRED`, then `pidfd_open` on it, then a re-check |
//! | [`Attestation::PeerCredOnly`] | 2.2 | A pid, and no way to stop it being reused |
//!
//! The distinction that matters is not convenience, it is whether the process
//! can be **pinned**. `SO_PEERCRED` hands back a pid, and a pid is a name that
//! can be recycled: the process that connected may have exited and its number
//! been reissued to something else before the broker looks at `/proc`. A pidfd
//! is a handle to that specific process — once it is open, the number cannot
//! come to mean anything else.
//!
//! On [`Attestation::PidfdOpen`] the window is narrow but real, so the pidfd is
//! opened and then the identity is *re-read through it* and compared. If it
//! changed, the caller that connected is gone and the request is denied.
//!
//! On [`Attestation::PeerCredOnly`] there is no way to close the window at all.
//! That rung therefore **cannot carry the agent path**: see
//! [`Attestation::can_attest_an_agent`]. This is invariant 2 of the project —
//! misclassification may only withhold capability — applied to the kernel
//! itself. An old kernel loses passwordless operation. It does not lose `aido`;
//! the human path still works, because a human typing a password is not relying
//! on the broker knowing which process asked.
//!
//! # Path resolution degrades too, and loses nothing
//!
//! `openat2` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH` arrived in 5.6. Below
//! that, [`Resolution::NofollowWalk`] opens one component at a time with
//! `O_PATH | O_NOFOLLOW | O_DIRECTORY` from a pinned dirfd. For `aido` this is
//! not a weaker check: the ruleset walk **refuses** a symlinked component rather
//! than resolving it, and refuses `..` outright, so there is nothing for
//! `RESOLVE_BENEATH` to protect against that `O_NOFOLLOW` plus no-`..` does not
//! already cover. `openat2` is preferred because it is one syscall instead of N,
//! not because the fallback is unsound.
//!
//! # Failure posture
//!
//! An unparseable version is [`KernelVersion::UNKNOWN`], which sits below every
//! threshold and therefore lands on the lowest rung — no agent path. A kernel we
//! cannot identify is treated as the oldest one we support, never the newest.

use std::fmt;

/// A kernel version, to the precision that matters here.
///
/// Patch level is deliberately not carried: no capability below is gated on one,
/// and a distribution kernel's patch number does not mean what the upstream
/// number means anyway.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
}

impl KernelVersion {
    /// The version assumed when the real one cannot be read.
    ///
    /// Zero, so it compares below every threshold and every capability check
    /// answers no.
    pub const UNKNOWN: Self = Self { major: 0, minor: 0 };

    /// Builds a version.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Parses the leading `major.minor` of a `uname -r` release string.
    ///
    /// Distribution release strings are not a clean format:
    /// `6.8.0-90-generic`, `5.10.0-21-amd64`, `5.14.0-427.el9.x86_64`,
    /// `5.4.0-1103-aws`. All of them begin with the two numbers this needs, so
    /// the parse takes those and ignores everything after — including a suffix
    /// glued directly to the minor number.
    ///
    /// Returns [`Self::UNKNOWN`] rather than an error for anything it cannot
    /// read, because every caller's response to "unreadable" is the same as its
    /// response to "very old": use the lowest rung.
    pub fn parse(release: &str) -> Self {
        let mut parts = release.split('.');
        let Some(major) = parts.next().and_then(leading_number) else {
            return Self::UNKNOWN;
        };
        let Some(minor) = parts.next().and_then(leading_number) else {
            return Self::UNKNOWN;
        };
        Self { major, minor }
    }

    /// Whether this version is at least `major.minor`.
    pub fn at_least(self, major: u32, minor: u32) -> bool {
        self >= Self { major, minor }
    }

    /// The best attestation rung this kernel supports.
    pub fn attestation(self) -> Attestation {
        if self.at_least(6, 13) {
            Attestation::PeerPidfdInfo
        } else if self.at_least(6, 5) {
            Attestation::PeerPidfd
        } else if self.at_least(5, 3) {
            Attestation::PidfdOpen
        } else {
            Attestation::PeerCredOnly
        }
    }

    /// How this kernel resolves a path.
    pub fn resolution(self) -> Resolution {
        if self.at_least(5, 6) {
            Resolution::Openat2
        } else {
            Resolution::NofollowWalk
        }
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::UNKNOWN {
            return f.write_str("unknown");
        }
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The leading decimal digits of `text`, or `None` if it does not start with one.
///
/// Stops at the first non-digit, which is what makes `0-90-generic` read as `0`
/// and `14-427` read as `14`.
fn leading_number(text: &str) -> Option<u32> {
    let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// How the broker can identify the process on the other end of its socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attestation {
    /// `SO_PEERCRED` only. A pid that may already mean something else.
    PeerCredOnly,
    /// `SO_PEERCRED`, then `pidfd_open`, then re-read and compare.
    PidfdOpen,
    /// `SO_PEERPIDFD`: a pidfd directly from the socket.
    PeerPidfd,
    /// `SO_PEERPIDFD` plus `PIDFD_GET_INFO`: creds and cgroup in one call.
    PeerPidfdInfo,
}

impl Attestation {
    /// Whether this rung can carry the passwordless agent path.
    ///
    /// False for exactly one rung, and the reason is the whole point of the
    /// ladder: without a pidfd the peer cannot be **pinned**, so the broker
    /// cannot know that the `/proc` entry it inspected belongs to the process
    /// that connected rather than to a reused pid. Granting root without a
    /// password on that basis would be authorising a race.
    ///
    /// A false here withholds capability and never adds it, which is invariant 2
    /// applied to the kernel.
    pub fn can_attest_an_agent(self) -> bool {
        match self {
            Self::PeerCredOnly => false,
            Self::PidfdOpen | Self::PeerPidfd | Self::PeerPidfdInfo => true,
        }
    }

    /// Whether the peer's identity has to be re-read and compared after pinning.
    ///
    /// Only on [`Self::PidfdOpen`], where the pid arrives before the pin and the
    /// gap between them is the race. The higher rungs receive the pidfd itself,
    /// so there is no gap to close.
    pub fn needs_recheck_after_pinning(self) -> bool {
        self == Self::PidfdOpen
    }

    /// The syscall or socket option this rung rests on.
    pub fn mechanism(self) -> &'static str {
        match self {
            Self::PeerCredOnly => "SO_PEERCRED",
            Self::PidfdOpen => "SO_PEERCRED + pidfd_open",
            Self::PeerPidfd => "SO_PEERPIDFD",
            Self::PeerPidfdInfo => "SO_PEERPIDFD + PIDFD_GET_INFO",
        }
    }

    /// The kernel this rung first appeared in.
    pub fn since(self) -> KernelVersion {
        match self {
            Self::PeerCredOnly => KernelVersion::new(2, 2),
            Self::PidfdOpen => KernelVersion::new(5, 3),
            Self::PeerPidfd => KernelVersion::new(6, 5),
            Self::PeerPidfdInfo => KernelVersion::new(6, 13),
        }
    }
}

/// How a path is opened without giving a symlink a chance to move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// One `openat` per component, `O_PATH | O_NOFOLLOW | O_DIRECTORY`.
    NofollowWalk,
    /// `openat2` with `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`.
    Openat2,
}

impl Resolution {
    /// The syscall used.
    pub fn mechanism(self) -> &'static str {
        match self {
            Self::NofollowWalk => "openat(O_NOFOLLOW) per component",
            Self::Openat2 => "openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)",
        }
    }
}

/// The oldest kernel on which `aido` offers the passwordless agent path.
///
/// 5.3, where `pidfd_open` arrived. Below it `aido` still runs — the human path
/// needs no attestation — but an agent gets a password prompt like anyone else.
pub const OLDEST_ATTESTING_KERNEL: KernelVersion = KernelVersion::new(5, 3);

/// What a given kernel supports, as one value for the audit record and `doctor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelSupport {
    /// The version read.
    pub version: KernelVersion,
    /// The attestation rung.
    pub attestation: Attestation,
    /// The resolution mechanism.
    pub resolution: Resolution,
}

impl KernelSupport {
    /// Derives support from a version.
    pub fn of(version: KernelVersion) -> Self {
        Self {
            version,
            attestation: version.attestation(),
            resolution: version.resolution(),
        }
    }

    /// Derives support from a `uname -r` string.
    pub fn parse(release: &str) -> Self {
        Self::of(KernelVersion::parse(release))
    }

    /// Whether an agent can be authorised without a password here.
    pub fn agent_path_available(self) -> bool {
        self.attestation.can_attest_an_agent()
    }

    /// One line for `doctor`, naming the mechanism rather than a version alone.
    ///
    /// An operator debugging a password prompt needs to know *which* mechanism
    /// is in play; "kernel too old" sends them to upgrade when the real problem
    /// may be elsewhere.
    pub fn summary(self) -> String {
        let agent = if self.agent_path_available() {
            "agent path available"
        } else {
            "agent path WITHHELD: no pidfd, so a peer cannot be pinned"
        };
        format!(
            "{} via {} ({})",
            self.version,
            self.attestation.mechanism(),
            agent
        )
    }
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

    #[test]
    fn real_distribution_release_strings_parse() {
        // Every one of these is a kernel someone is running aido on.
        let cases = [
            ("6.8.0-90-generic", 6, 8),                 // Ubuntu 24.04
            ("6.14.0-33-generic", 6, 14),               // Ubuntu 25.04
            ("5.15.0-1051-azure", 5, 15),               // Ubuntu 22.04
            ("5.10.0-21-amd64", 5, 10),                 // Debian 11
            ("5.14.0-427.el9.x86_64", 5, 14),           // RHEL 9
            ("5.4.0-1103-aws", 5, 4),                   // Ubuntu 20.04
            ("6.1.0-13-arm64", 6, 1),                   // Debian 12
            ("4.19.0-25-amd64", 4, 19),                 // Debian 10
            ("6.6.87.2-microsoft-standard-WSL2", 6, 6), // WSL2
            ("5.6", 5, 6),                              // bare upstream
        ];
        for (release, major, minor) in cases {
            assert_eq!(
                KernelVersion::parse(release),
                KernelVersion::new(major, minor),
                "{release}"
            );
        }
    }

    #[test]
    fn an_unreadable_version_is_treated_as_the_oldest_kernel_we_support() {
        // Never the newest: a kernel we cannot identify must not be credited
        // with a capability it may not have.
        for release in ["", "unknown", "6", "linux-6.8", "-6.8.0", ".8.0", "6."] {
            let version = KernelVersion::parse(release);
            assert_eq!(version, KernelVersion::UNKNOWN, "{release}");
            assert!(
                !KernelSupport::of(version).agent_path_available(),
                "{release} must not get the agent path"
            );
        }
    }

    #[test]
    fn each_rung_starts_exactly_at_its_documented_kernel() {
        // Boundaries asserted on both sides, because an off-by-one here either
        // calls a syscall that does not exist or withholds one that does.
        let cases = [
            ("6.13", Attestation::PeerPidfdInfo),
            ("6.12", Attestation::PeerPidfd),
            ("6.5", Attestation::PeerPidfd),
            ("6.4", Attestation::PidfdOpen),
            ("5.3", Attestation::PidfdOpen),
            ("5.2", Attestation::PeerCredOnly),
            ("4.19", Attestation::PeerCredOnly),
        ];
        for (release, expected) in cases {
            assert_eq!(
                KernelVersion::parse(release).attestation(),
                expected,
                "{release}"
            );
        }
    }

    #[test]
    fn every_rung_reports_the_kernel_it_says_it_needs() {
        // The table in the module docs and the code cannot drift apart.
        for rung in [
            Attestation::PeerCredOnly,
            Attestation::PidfdOpen,
            Attestation::PeerPidfd,
            Attestation::PeerPidfdInfo,
        ] {
            let since = rung.since();
            assert_eq!(since.attestation(), rung, "{rung:?} at {since}");
            assert!(!rung.mechanism().is_empty());
        }
    }

    #[test]
    fn only_the_unpinnable_rung_withholds_the_agent_path() {
        // The security claim of this module, asserted directly: a kernel without
        // a pidfd cannot pin its peer, so it cannot authorise root without a
        // password. Everything above it can.
        assert!(!Attestation::PeerCredOnly.can_attest_an_agent());
        for rung in [
            Attestation::PidfdOpen,
            Attestation::PeerPidfd,
            Attestation::PeerPidfdInfo,
        ] {
            assert!(rung.can_attest_an_agent(), "{rung:?}");
        }
    }

    #[test]
    fn a_kernel_below_the_floor_still_runs_aido_for_a_human() {
        // Losing attestation loses passwordless operation, not the tool. A human
        // typing a password does not rely on the broker knowing which process
        // asked.
        let old = KernelSupport::parse("4.19.0-25-amd64");
        assert!(!old.agent_path_available());
        let summary = old.summary();
        assert!(summary.contains("WITHHELD"), "{summary}");
        assert!(summary.contains("cannot be pinned"), "{summary}");
    }

    #[test]
    fn the_declared_floor_is_the_lowest_version_that_can_attest() {
        // Asserted so the constant and the ladder cannot disagree.
        assert!(OLDEST_ATTESTING_KERNEL.attestation().can_attest_an_agent());
        let below = KernelVersion::new(
            OLDEST_ATTESTING_KERNEL.major,
            OLDEST_ATTESTING_KERNEL.minor - 1,
        );
        assert!(!below.attestation().can_attest_an_agent());
    }

    #[test]
    fn only_the_pid_first_rung_needs_a_recheck_after_pinning() {
        // On PidfdOpen the pid arrives before the pin, and that gap is the race.
        // The higher rungs are handed the pidfd itself, so there is no gap.
        assert!(Attestation::PidfdOpen.needs_recheck_after_pinning());
        for rung in [
            Attestation::PeerCredOnly,
            Attestation::PeerPidfd,
            Attestation::PeerPidfdInfo,
        ] {
            assert!(!rung.needs_recheck_after_pinning(), "{rung:?}");
        }
    }

    #[test]
    fn openat2_is_used_from_five_six_and_the_walk_below_it() {
        assert_eq!(
            KernelVersion::parse("5.6").resolution(),
            Resolution::Openat2
        );
        assert_eq!(
            KernelVersion::parse("5.5").resolution(),
            Resolution::NofollowWalk
        );
        assert_eq!(
            KernelVersion::UNKNOWN.resolution(),
            Resolution::NofollowWalk
        );
        assert!(
            Resolution::Openat2
                .mechanism()
                .contains("RESOLVE_NO_SYMLINKS")
        );
        assert!(Resolution::NofollowWalk.mechanism().contains("O_NOFOLLOW"));
    }

    #[test]
    fn losing_openat2_does_not_withhold_the_agent_path() {
        // Deliberate: the ruleset walk refuses a symlinked component rather than
        // resolving it, and refuses `..`, so O_NOFOLLOW per component gives the
        // same guarantee in more syscalls. Only attestation gates the agent
        // path.
        let old = KernelSupport::parse("5.4.0-1103-aws");
        assert_eq!(old.resolution, Resolution::NofollowWalk);
        assert!(old.agent_path_available());
    }

    #[test]
    fn the_summary_names_the_mechanism_not_just_the_version() {
        // An operator debugging a password prompt needs to know which mechanism
        // is in play.
        let current = KernelSupport::parse("6.8.0-90-generic");
        assert_eq!(
            current.summary(),
            "6.8 via SO_PEERPIDFD (agent path available)"
        );
        let newest = KernelSupport::parse("6.13.0").summary();
        assert!(newest.contains("PIDFD_GET_INFO"), "{newest}");
        assert_eq!(KernelVersion::UNKNOWN.to_string(), "unknown");
        assert!(KernelSupport::parse("").summary().starts_with("unknown"));
    }

    #[test]
    fn versions_order_and_compare_the_way_the_thresholds_assume() {
        assert!(KernelVersion::new(6, 8) > KernelVersion::new(6, 5));
        assert!(KernelVersion::new(6, 0) > KernelVersion::new(5, 99));
        assert!(KernelVersion::new(5, 3).at_least(5, 3));
        assert!(!KernelVersion::new(5, 3).at_least(5, 4));
        assert!(KernelVersion::UNKNOWN < OLDEST_ATTESTING_KERNEL);
        assert_eq!(KernelVersion::new(6, 8), KernelVersion::new(6, 8));
        assert!(Attestation::PeerPidfd > Attestation::PidfdOpen);
        assert!(format!("{:?}", Resolution::Openat2).contains("Openat2"));
        let support = KernelSupport::of(KernelVersion::new(6, 8));
        assert_eq!(support, KernelSupport::parse("6.8.0-90-generic"));
        assert!(format!("{support:?}").contains("PeerPidfd"));
    }
}
