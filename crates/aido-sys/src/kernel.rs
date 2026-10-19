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
//! | [`Attestation::PeerPidfdInfo`] | 6.13 | A pidfd straight from the socket, then its pid and cgroup id through `PIDFD_GET_INFO` |
//! | [`Attestation::PeerPidfd`] | 6.5 | A pidfd straight from the socket via `SO_PEERPIDFD` |
//! | [`Attestation::PidfdOpen`] | 5.3 | A pid from `SO_PEERCRED`, then `pidfd_open` on it, then a re-check |
//! | [`Attestation::PeerCredOnly`] | 2.2 | A pid, and no way to stop it being reused |
//!
//! On every rung the peer's uid and gid come from `SO_PEERCRED`, which the
//! kernel captured when the peer connected. `PIDFD_GET_INFO` also reports
//! credentials, but **current** ones, read at the moment of the call: a peer
//! that connected and then exec'd a set-user-ID program would report that
//! program's ids. What a pidfd makes race-free is *which process* it names,
//! not what that process's credentials or cgroup were at connect time.
//!
//! The distinction that matters is not convenience, it is whether the process
//! can be **pinned**. `SO_PEERCRED` hands back a pid, and a pid is a name that
//! can be recycled: the process that connected may have exited and its number
//! been reissued to something else before the broker looks at `/proc`. A pidfd
//! is a handle to that specific process, and it never comes to refer to
//! another one.
//!
//! It does **not** hold on to the process's number. The kernel releases a pid
//! number when the process is reaped, even while a pidfd still refers to the
//! process, and the next process may be issued it. So whatever the broker reads
//! from `/proc/<pid>` by number — the start time that pins a request to its
//! caller, and on 6.5 to 6.12 the cgroup too — may describe a different
//! process, unless the broker confirms through the pidfd *after* the last such
//! read that the process it pinned is still unreaped. Every rung that holds a
//! pidfd re-checks this way; see [`Attestation::needs_recheck_after_pinning`].
//!
//! On [`Attestation::PidfdOpen`] the pidfd is opened and the identity is then
//! *re-read through it* and compared, which closes the gap between the
//! broker's first look and the pin. It does not close the gap before that:
//! `SO_PEERCRED` reports the pid number the peer had at connect time, the
//! kernel returns that number to the allocator once the peer is reaped, and a
//! same-uid process that is issued it afterwards looks identical to every
//! re-check, because nothing the connection carries besides the number and the
//! uid is left to compare against. So the pin names *a* process, not provably
//! the one that connected. That is enough for an audit record and for binding
//! a human-path request, where the password is the authority; it is not enough
//! to grant root without one.
//!
//! On [`Attestation::PeerCredOnly`] there is no pin at all. Neither rung can
//! **carry the agent path**: see [`Attestation::can_attest_an_agent`]. A
//! re-check that binds the pinned process to *this* connection — finding the
//! client end of the accepted socket in the pinned process's descriptor table,
//! through `sock_diag` — could restore it on 5.3 to 6.4, and is M4's to build
//! or not. This is invariant 2 of the project —
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
    /// Only where the kernel hands over a pidfd for the peer itself, from the
    /// socket. Below that, the broker cannot know that the process it pinned
    /// is the process that connected rather than one issued a reused pid, and
    /// granting root without a password on that basis would be authorising a
    /// race. See the module docs for why the `pidfd_open` re-check does not
    /// close it.
    ///
    /// A false here withholds capability and never adds it, which is invariant 2
    /// applied to the kernel.
    pub fn can_attest_an_agent(self) -> bool {
        self.withheld_because().is_none()
    }

    /// Why this rung cannot carry the agent path, for `doctor`, or `None` if
    /// it can.
    pub fn withheld_because(self) -> Option<&'static str> {
        match self {
            Self::PeerCredOnly => Some("no pidfd, so a peer cannot be pinned"),
            Self::PidfdOpen => Some(
                "the pid SO_PEERCRED reports may be reissued before pidfd_open pins it, so the \
                 pin is not bound to the connection",
            ),
            Self::PeerPidfd | Self::PeerPidfdInfo => None,
        }
    }

    /// Whether the broker must confirm, through the pidfd, after its last read
    /// of `/proc/<pid>`, that the process it pinned has not been reaped.
    ///
    /// True on every rung that holds a pidfd. A pidfd pins the process, not its
    /// number: once the process is reaped its number can be reissued, and a
    /// read of `/proc/<pid>` after that describes whoever got it. Every rung
    /// reads `/proc/<pid>` at least once, for the start time a request is
    /// pinned by. [`Self::PeerCredOnly`] has no pidfd to check through, which is
    /// one more reason it cannot attest anyone.
    pub fn needs_recheck_after_pinning(self) -> bool {
        self != Self::PeerCredOnly
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
/// 6.5, where `SO_PEERPIDFD` arrived: the first kernel that hands the broker a
/// pidfd for its peer straight from the socket. Below it `aido` still runs —
/// the human path needs no attestation — but an agent gets a password prompt
/// like anyone else.
pub const OLDEST_ATTESTING_KERNEL: KernelVersion = KernelVersion::new(6, 5);

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
        let agent = self.attestation.withheld_because().map_or_else(
            || "agent path available".to_owned(),
            |why| format!("agent path WITHHELD: {why}"),
        );
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
    fn only_a_pidfd_from_the_socket_carries_the_agent_path() {
        // The security claim of this module, asserted directly. Without a pidfd
        // there is no pin; with one from pidfd_open the pin may name a process
        // issued a reused pid. Only SO_PEERPIDFD binds the pin to the
        // connection.
        for rung in [Attestation::PeerCredOnly, Attestation::PidfdOpen] {
            assert!(!rung.can_attest_an_agent(), "{rung:?}");
            assert!(rung.withheld_because().is_some(), "{rung:?}");
        }
        for rung in [Attestation::PeerPidfd, Attestation::PeerPidfdInfo] {
            assert!(rung.can_attest_an_agent(), "{rung:?}");
            assert_eq!(rung.withheld_because(), None, "{rung:?}");
        }
    }

    #[test]
    fn a_reissued_pid_is_why_pidfd_open_withholds_the_agent_path() {
        // Ubuntu 20.04, Debian 11, RHEL 9: aido works, an agent is prompted,
        // and doctor says why in words an operator can act on.
        let summary = KernelSupport::parse("5.14.0-427.el9.x86_64").summary();
        assert!(summary.contains("WITHHELD"), "{summary}");
        assert!(summary.contains("reissued"), "{summary}");
        assert!(summary.contains("SO_PEERCRED + pidfd_open"), "{summary}");
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
    fn every_rung_with_a_pidfd_rechecks_after_reading_proc_by_number() {
        // A pidfd pins the process, not its number. A read of /proc/<pid> that
        // is not followed by a liveness check through the pidfd can describe a
        // process that was issued the number after the peer was reaped — on
        // the top rung as much as on the bottom one, because every rung reads
        // the start time from /proc.
        for rung in [
            Attestation::PidfdOpen,
            Attestation::PeerPidfd,
            Attestation::PeerPidfdInfo,
        ] {
            assert!(rung.needs_recheck_after_pinning(), "{rung:?}");
        }
        assert!(!Attestation::PeerCredOnly.needs_recheck_after_pinning());
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
        // path. No real kernel has SO_PEERPIDFD without openat2, so the
        // combination is built by hand to keep the claim tested.
        let support = KernelSupport {
            version: KernelVersion::new(6, 5),
            attestation: Attestation::PeerPidfd,
            resolution: Resolution::NofollowWalk,
        };
        assert!(support.agent_path_available());
        assert!(!KernelSupport::parse("5.4.0-1103-aws").agent_path_available());
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
