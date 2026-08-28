//! Which backend is installed, and what it can be relied on to do.
//!
//! Detection is at **runtime, never build time**. The same binary runs on a
//! Debian with `sudo` 1.9 and an Ubuntu 26.04 with `sudo-rs`, and those two
//! honour different directives. Deciding at build time means shipping a package
//! that is wrong on half the machines it installs on.

use serde::{Deserialize, Serialize};

use crate::capability::{Capability, CapabilityMatrix};

/// Which implementation is present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    /// The original C `sudo`.
    Sudo,
    /// `sudo-rs`, the Rust reimplementation. Default on Ubuntu 26.04 LTS.
    ///
    /// Deliberately a distinct kind rather than a version of `Sudo`: it
    /// implements a subset of the sudoers grammar and **ignores** directives it
    /// does not support. Treating it as `sudo` is how a control silently goes
    /// missing.
    SudoRs,
    /// OpenBSD `doas`, or a Linux port of it.
    Doas,
}

impl BackendKind {
    /// The absolute path aido invokes.
    ///
    /// Absolute and hard-coded: there is no `PATH` search anywhere in this
    /// project, because `PATH` is caller-controlled.
    pub fn exe(self) -> &'static str {
        match self {
            Self::Sudo | Self::SudoRs => "/usr/bin/sudo",
            Self::Doas => "/usr/bin/doas",
        }
    }

    /// A short label for `aido doctor` and every audit record.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sudo => "sudo",
            Self::SudoRs => "sudo-rs",
            Self::Doas => "doas",
        }
    }
}

/// A detected, capability-probed backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    /// Which implementation.
    pub kind: BackendKind,
    /// The version string, verbatim, for the audit record.
    pub version: String,
    /// What it was found to support.
    pub capabilities: CapabilityMatrix,
}

impl Backend {
    /// Whether aido can operate on this backend.
    pub fn is_usable(&self) -> bool {
        self.capabilities.is_usable()
    }
}

/// Facts about the machine, gathered elsewhere.
///
/// A trait so the whole of detection is testable without a `sudo` to run: the
/// Linux implementation shells out, the test implementation returns strings.
pub trait Probe {
    /// Whether an executable exists at an absolute path.
    fn exists(&self, absolute_path: &str) -> bool;

    /// The output of `<path> --version`, or `None` if it could not be run.
    fn version_banner(&self, absolute_path: &str) -> Option<String>;

    /// Whether a directory exists at an absolute path.
    fn directory_exists(&self, absolute_path: &str) -> bool;

    /// Whether the backend honours a directive, given **exactly the text aido
    /// intends to write**.
    ///
    /// Probed rather than assumed, because `sudo-rs` **ignores** directives it
    /// does not implement and only logs a warning. A backend that accepts
    /// `timestamp_timeout=0` into its config and then ignores it has left aido
    /// advertising a control it does not have, so the question has to be asked
    /// rather than inferred from the implementation's name.
    fn honours_directive(&self, absolute_path: &str, directive: &str) -> bool;
}

/// Why detection failed. Both variants mean aido refuses to operate.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DetectError {
    /// Neither `sudo` nor `doas` is installed.
    ///
    /// aido delegates the uid transition and never performs one itself, so with
    /// no backend there is nothing it can do. It says so and exits rather than
    /// degrading to anything.
    #[error(
        "no privilege backend found: neither /usr/bin/sudo nor /usr/bin/doas exists. \
         aido delegates every uid transition and performs none itself, so it cannot \
         operate here"
    )]
    NoBackend,
    /// A backend exists but lacks a control with no substitute.
    #[error(
        "{kind} {version} is missing a required control ({missing}); aido refuses to \
         install rather than install something weaker than it advertises"
    )]
    Unusable {
        /// Which backend.
        kind: String,
        /// Its version.
        version: String,
        /// The missing capabilities, rendered.
        missing: String,
    },
}

/// Detects the installed backend and probes what it supports.
///
/// `sudo` is preferred over `doas` when both exist, because its drop-in
/// directory means aido can own one file rather than editing a shared one.
///
/// # Errors
///
/// Returns [`DetectError::NoBackend`] when neither is installed, and
/// [`DetectError::Unusable`] when the one that is installed lacks a required
/// capability.
pub fn detect(probe: &dyn Probe) -> Result<Backend, DetectError> {
    let backend = detect_kind(probe).ok_or(DetectError::NoBackend)?;
    if backend.is_usable() {
        return Ok(backend);
    }
    let missing = backend
        .capabilities
        .missing_required()
        .into_iter()
        .map(|c| c.rationale().to_owned())
        .collect::<Vec<_>>()
        .join("; ");
    Err(DetectError::Unusable {
        kind: backend.kind.label().to_owned(),
        version: backend.version,
        missing,
    })
}

/// Identifies the backend without judging it.
fn detect_kind(probe: &dyn Probe) -> Option<Backend> {
    let sudo = BackendKind::Sudo.exe();
    if probe.exists(sudo) {
        let banner = probe.version_banner(sudo).unwrap_or_default();
        let kind = classify_sudo_banner(&banner);
        return Some(Backend {
            capabilities: sudo_capabilities(kind, probe),
            version: first_line(&banner),
            kind,
        });
    }

    let doas = BackendKind::Doas.exe();
    if probe.exists(doas) {
        let banner = probe.version_banner(doas).unwrap_or_default();
        return Some(Backend {
            kind: BackendKind::Doas,
            capabilities: doas_capabilities(&banner, probe),
            version: first_line(&banner),
        });
    }

    None
}

/// Distinguishes `sudo-rs` from `sudo` by its banner.
///
/// An unrecognised banner is treated as `sudo-rs`, not as `sudo`. That is the
/// conservative direction: `sudo-rs` supports the smaller set of directives, so
/// guessing it means probing for each one rather than assuming it is honoured.
/// Guessing `sudo` for an unknown implementation is how a directive gets
/// assumed and silently ignored.
fn classify_sudo_banner(banner: &str) -> BackendKind {
    let lowered = banner.to_ascii_lowercase();
    if lowered.contains("sudo-rs") || lowered.contains("sudo_rs") {
        return BackendKind::SudoRs;
    }
    if lowered.contains("sudo version") {
        return BackendKind::Sudo;
    }
    BackendKind::SudoRs
}

/// What each sudo implementation supports.
fn sudo_capabilities(kind: BackendKind, probe: &dyn Probe) -> CapabilityMatrix {
    let exe = BackendKind::Sudo.exe();
    let mut matrix = CapabilityMatrix::empty().with(Capability::PersistentCredentialCache);

    // Asked, never assumed. These two are the required ones, and a backend that
    // silently ignores either has left aido advertising a control it lacks.
    // The exact text the snippet will carry, value included.
    if probe.honours_directive(exe, "timestamp_timeout=0") {
        matrix = matrix.with(Capability::DisableCredentialCache);
    }
    if probe.honours_directive(exe, "use_pty") {
        matrix = matrix.with(Capability::AllocatePty);
    }
    // The per-command scope is the `Defaults!ALIAS` syntax itself, which every
    // probe fragment uses, so any valid directive inside one proves it.
    if probe.honours_directive(exe, "!setenv") {
        matrix = matrix.with(Capability::PerCommandDefaults);
    }

    if probe.directory_exists("/etc/sudoers.d") {
        matrix = matrix.with(Capability::DropInDirectory);
    }

    match kind {
        // sudo-rs's visudo validates only /etc/sudoers, so a named file cannot
        // be checked in place; and it rejects argument wildcards outright.
        BackendKind::SudoRs => matrix.with(Capability::RejectsArgumentWildcards),
        BackendKind::Sudo => matrix.with(Capability::ValidateNamedFile),
        // Not reachable through `sudo_capabilities`, whose caller has already
        // established a sudo-family backend. Kept exhaustive rather than
        // wildcarded so adding a kind is a compile error here.
        BackendKind::Doas => matrix,
    }
}

/// What a doas port supports.
fn doas_capabilities(banner: &str, probe: &dyn Probe) -> CapabilityMatrix {
    let exe = BackendKind::Doas.exe();
    let mut matrix = CapabilityMatrix::empty().with(Capability::ValidateNamedFile);

    // doas has no credential cache to disable unless it was built with one,
    // which is the same practical guarantee — but it is still probed rather
    // than assumed, so a port that behaves differently is caught.
    if probe.honours_directive(exe, "nopersist") {
        matrix = matrix.with(Capability::DisableCredentialCache);
    }
    if probe.honours_directive(exe, "pty") {
        matrix = matrix.with(Capability::AllocatePty);
    }

    if probe.directory_exists("/etc/doas.d") {
        matrix = matrix.with(Capability::DropInDirectory);
    }

    // `OpenDoas` disables `persist` unless built --with-timestamp. Recorded, and
    // depended on in neither direction.
    if banner.to_ascii_lowercase().contains("with-timestamp") {
        matrix = matrix.with(Capability::PersistentCredentialCache);
    }

    matrix
}

/// The first line of a banner, trimmed. Version banners are multi-line and only
/// the first line identifies the implementation.
fn first_line(banner: &str) -> String {
    banner.lines().next().unwrap_or_default().trim().to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use std::collections::BTreeMap;

    use super::*;

    /// A machine described by a table.
    #[derive(Default)]
    struct FakeMachine {
        files: BTreeMap<String, String>,
        directories: Vec<String>,
        /// Directives this machine accepts into its config and then ignores.
        ignored_directives: Vec<String>,
    }

    impl FakeMachine {
        fn with_exe(mut self, path: &str, banner: &str) -> Self {
            self.files.insert(path.to_owned(), banner.to_owned());
            self
        }

        fn with_dir(mut self, path: &str) -> Self {
            self.directories.push(path.to_owned());
            self
        }

        /// Makes the machine silently ignore a directive, as sudo-rs does with
        /// the ones it has not implemented.
        fn ignoring(mut self, directive: &str) -> Self {
            self.ignored_directives.push(directive.to_owned());
            self
        }
    }

    impl Probe for FakeMachine {
        fn exists(&self, absolute_path: &str) -> bool {
            self.files.contains_key(absolute_path)
        }

        fn version_banner(&self, absolute_path: &str) -> Option<String> {
            self.files.get(absolute_path).cloned()
        }

        fn directory_exists(&self, absolute_path: &str) -> bool {
            self.directories.iter().any(|d| d == absolute_path)
        }

        fn honours_directive(&self, _absolute_path: &str, directive: &str) -> bool {
            !self.ignored_directives.iter().any(|d| d == directive)
        }
    }

    fn debian() -> FakeMachine {
        FakeMachine::default()
            .with_exe(
                "/usr/bin/sudo",
                "Sudo version 1.9.17p2\nSudoers policy plugin version 1.9.17p2\n",
            )
            .with_dir("/etc/sudoers.d")
    }

    fn ubuntu_2604() -> FakeMachine {
        FakeMachine::default()
            .with_exe("/usr/bin/sudo", "sudo-rs 0.2.8\n")
            .with_dir("/etc/sudoers.d")
    }

    fn alpine_doas() -> FakeMachine {
        FakeMachine::default().with_exe("/usr/bin/doas", "doas (OpenDoas) 6.8.2\n")
    }

    #[test]
    fn a_debian_with_sudo_is_detected_with_its_version() {
        let backend = detect(&debian()).unwrap();
        assert_eq!(backend.kind, BackendKind::Sudo);
        assert_eq!(backend.version, "Sudo version 1.9.17p2");
        assert!(backend.is_usable());
        assert!(backend.capabilities.has(Capability::DropInDirectory));
        assert!(backend.capabilities.has(Capability::ValidateNamedFile));
    }

    #[test]
    fn sudo_rs_is_a_distinct_kind_and_cannot_validate_a_named_file() {
        // The distinction is the point: sudo-rs's visudo validates only
        // /etc/sudoers, so a snippet must be checked by substitution instead.
        let backend = detect(&ubuntu_2604()).unwrap();
        assert_eq!(backend.kind, BackendKind::SudoRs);
        assert_eq!(backend.version, "sudo-rs 0.2.8");
        assert!(!backend.capabilities.has(Capability::ValidateNamedFile));
        assert!(
            backend
                .capabilities
                .has(Capability::RejectsArgumentWildcards)
        );
        assert!(backend.is_usable());
    }

    #[test]
    fn an_unrecognised_sudo_banner_is_assumed_to_be_the_stricter_implementation() {
        // The conservative direction. Guessing `sudo` for an unknown
        // implementation means assuming directives are honoured, which is how a
        // control silently goes missing.
        let odd = FakeMachine::default().with_exe("/usr/bin/sudo", "some fork 9.9\n");
        assert_eq!(detect(&odd).unwrap().kind, BackendKind::SudoRs);

        // And a backend that cannot even be asked its version.
        let mute = FakeMachine {
            files: BTreeMap::from([("/usr/bin/sudo".to_owned(), String::new())]),
            ..FakeMachine::default()
        };
        assert_eq!(detect(&mute).unwrap().kind, BackendKind::SudoRs);
        assert_eq!(detect(&mute).unwrap().version, "");
    }

    #[test]
    fn a_banner_naming_sudo_rs_either_way_round_is_recognised() {
        for banner in ["sudo-rs 0.2.8", "SUDO_RS build", "Sudo-Rs"] {
            let machine = FakeMachine::default().with_exe("/usr/bin/sudo", banner);
            assert_eq!(
                detect(&machine).unwrap().kind,
                BackendKind::SudoRs,
                "{banner}"
            );
        }
    }

    #[test]
    fn doas_is_detected_when_sudo_is_absent() {
        let backend = detect(&alpine_doas()).unwrap();
        assert_eq!(backend.kind, BackendKind::Doas);
        assert_eq!(backend.version, "doas (OpenDoas) 6.8.2");
        assert!(backend.is_usable());
        // Most ports have no drop-in directory, so the integration is a
        // delimited block instead.
        assert!(!backend.capabilities.has(Capability::DropInDirectory));
    }

    #[test]
    fn a_doas_port_with_a_drop_in_directory_gets_the_better_path() {
        let machine = alpine_doas().with_dir("/etc/doas.d");
        assert!(
            detect(&machine)
                .unwrap()
                .capabilities
                .has(Capability::DropInDirectory)
        );
    }

    #[test]
    fn doas_persistence_is_recorded_but_never_depended_on() {
        let without = detect(&alpine_doas()).unwrap();
        assert!(
            !without
                .capabilities
                .has(Capability::PersistentCredentialCache)
        );
        // Either way the backend is usable, because aido does not rely on it.
        assert!(without.is_usable());

        let with = FakeMachine::default()
            .with_exe("/usr/bin/doas", "doas (OpenDoas) 6.8.2 --with-timestamp\n");
        assert!(
            detect(&with)
                .unwrap()
                .capabilities
                .has(Capability::PersistentCredentialCache)
        );
    }

    #[test]
    fn sudo_is_preferred_when_both_are_installed() {
        // Not arbitrary: sudo's drop-in directory means aido owns one file
        // rather than editing a shared one, so install and uninstall cannot
        // damage an operator's own rules.
        let both = debian().with_exe("/usr/bin/doas", "doas (OpenDoas) 6.8.2\n");
        assert_eq!(detect(&both).unwrap().kind, BackendKind::Sudo);
    }

    #[test]
    fn a_machine_with_no_backend_is_refused_with_an_explanation() {
        let err = detect(&FakeMachine::default()).unwrap_err();
        assert_eq!(err, DetectError::NoBackend);
        let message = err.to_string();
        assert!(
            message.contains("neither /usr/bin/sudo nor /usr/bin/doas"),
            "{message}"
        );
        assert!(message.contains("performs none itself"), "{message}");
    }

    #[test]
    fn a_backend_that_silently_ignores_a_required_directive_is_refused() {
        // The sudo-rs failure mode, exactly: the directive is accepted into the
        // config and then ignored, so a file-shaped check would pass while the
        // control is absent. Detection must refuse rather than advertise it.
        let deaf = debian().ignoring("use_pty");
        let err = detect(&deaf).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("missing a required control"), "{message}");
        assert!(message.contains("fresh pty"), "{message}");
        assert!(message.contains("weaker than it advertises"), "{message}");

        // And the other one, to prove neither is special-cased.
        let uncached = debian().ignoring("timestamp_timeout=0");
        assert!(
            detect(&uncached)
                .unwrap_err()
                .to_string()
                .contains("credential")
        );
    }

    #[test]
    fn a_doas_port_that_ignores_a_required_directive_is_refused_too() {
        // Both required controls, so neither is special-cased on this backend
        // either.
        for directive in ["pty", "nopersist"] {
            let deaf = alpine_doas().ignoring(directive);
            assert!(detect(&deaf).is_err(), "{directive} was tolerated");
        }
    }

    #[test]
    fn a_backend_that_ignores_only_an_optional_directive_is_still_usable() {
        // Per-command defaults have a workaround; the required two do not.
        let backend = detect(&debian().ignoring("!setenv")).unwrap();
        assert!(backend.is_usable());
        assert!(!backend.capabilities.has(Capability::PerCommandDefaults));
    }

    #[test]
    fn a_backend_missing_a_required_control_is_refused_rather_than_weakened() {
        // Constructed directly, because no real backend lacks these — the
        // check exists for the one that eventually will.
        let crippled = Backend {
            kind: BackendKind::Sudo,
            version: "Sudo version 0.0".to_owned(),
            capabilities: CapabilityMatrix::empty().with(Capability::DropInDirectory),
        };
        assert!(!crippled.is_usable());
        assert_eq!(crippled.capabilities.missing_required().len(), 2);
    }

    #[test]
    fn the_unusable_error_names_the_backend_and_what_is_missing() {
        let err = DetectError::Unusable {
            kind: "sudo".to_owned(),
            version: "0.0".to_owned(),
            missing: Capability::AllocatePty.rationale().to_owned(),
        };
        let message = err.to_string();
        assert!(message.contains("sudo 0.0"), "{message}");
        assert!(message.contains("weaker than it advertises"), "{message}");
        assert!(message.contains("fresh pty"), "{message}");
    }

    #[test]
    fn every_kind_names_an_absolute_executable_and_a_label() {
        for kind in [BackendKind::Sudo, BackendKind::SudoRs, BackendKind::Doas] {
            assert!(kind.exe().starts_with('/'), "{kind:?} is not absolute");
            assert!(!kind.label().is_empty());
            assert!(format!("{kind:?}").len() > 3);
        }
        assert_eq!(BackendKind::Sudo.exe(), BackendKind::SudoRs.exe());
        assert_eq!(BackendKind::SudoRs.label(), "sudo-rs");
        assert_eq!(BackendKind::Doas.label(), "doas");
    }

    #[test]
    fn the_doas_arm_of_sudo_capabilities_is_inert() {
        // Unreachable through `detect`, and kept exhaustive so that adding a
        // backend kind is a compile error here rather than a silent fallthrough.
        let machine = debian();
        let matrix = sudo_capabilities(BackendKind::Doas, &machine);
        assert!(!matrix.has(Capability::ValidateNamedFile));
        assert!(matrix.is_usable());
    }

    #[test]
    fn a_backend_round_trips_and_rejects_unknown_keys() {
        let backend = detect(&debian()).unwrap();
        let json = serde_json::to_string(&backend).unwrap();
        assert_eq!(serde_json::from_str::<Backend>(&json).unwrap(), backend);
        assert!(
            serde_json::from_str::<Backend>(&json.replace("\"kind\"", "\"trusted\":true,\"kind\""))
                .is_err()
        );
        assert!(format!("{backend:?}").contains("Sudo"));
    }

    #[test]
    fn a_multi_line_banner_reports_only_its_first_line() {
        assert_eq!(first_line("a\nb\nc"), "a");
        assert_eq!(first_line("  padded  \nb"), "padded");
        assert_eq!(first_line(""), "");
    }
}
