//! What a backend can actually be relied on to do.
//!
//! Not a feature list for its own sake. Every entry here exists because
//! assuming it and being wrong produces a working-looking install with a
//! missing control, and the whole point of probing is to refuse rather than to
//! hope.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// One thing a backend either honours or does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// A drop-in directory exists, so aido can own one file instead of editing
    /// a shared one.
    ///
    /// `sudo` has `/etc/sudoers.d`. Most `doas` ports have nothing, which is why
    /// the doas path appends a delimited block instead.
    DropInDirectory,
    /// Validation can be pointed at a specific file.
    ///
    /// `sudo`'s `visudo -cf <file>` can. `sudo-rs`'s `visudo` validates only
    /// `/etc/sudoers`, so on that backend a snippet must be validated by
    /// substitution into a temporary copy rather than in place.
    ValidateNamedFile,
    /// A per-command settings scope, so aido's `Defaults` cannot leak onto
    /// unrelated commands.
    ///
    /// `sudo`'s `Defaults!<Cmnd_Alias>`. `doas` has per-rule options instead,
    /// which is a better shape but a different one.
    PerCommandDefaults,
    /// The credential cache can be disabled for aido's own rules.
    ///
    /// `timestamp_timeout=0` on sudo. **Load-bearing**: without it, the agent
    /// path can ride a credential a human cached with an earlier, unrelated
    /// `sudo`. Where this is unavailable, aido must treat every invocation as
    /// if a cached credential might exist and refuse the passwordless path.
    DisableCredentialCache,
    /// A fresh pty can be allocated for the privileged child.
    ///
    /// `use_pty`. The remedy for the TIOCSTI/TIOCLINUX tty-hijack class, which
    /// cannot be fixed by blocking individual ioctls.
    AllocatePty,
    /// Intra-argument wildcards are rejected by the backend itself.
    ///
    /// `sudo-rs` refuses rules that `sudo` accepts. Not something aido relies
    /// on — it never writes a wildcard — but worth recording, because a backend
    /// that rejects them will also reject a hand-edited rule that has one, and
    /// an operator deserves to know which backend refused their edit.
    RejectsArgumentWildcards,
    /// A credential cache that persists across invocations exists at all.
    ///
    /// `OpenDoas` disables `persist` unless built `--with-timestamp`. Recorded so
    /// aido can state that it does not depend on it either way.
    PersistentCredentialCache,
}

impl Capability {
    /// Every capability, for exhaustive reporting.
    pub const ALL: [Self; 7] = [
        Self::DropInDirectory,
        Self::ValidateNamedFile,
        Self::PerCommandDefaults,
        Self::DisableCredentialCache,
        Self::AllocatePty,
        Self::RejectsArgumentWildcards,
        Self::PersistentCredentialCache,
    ];

    /// Whether aido refuses to operate without this capability.
    ///
    /// Only two are required, and both for the same reason: without them there
    /// is a path by which a privileged command runs with less checking than the
    /// operator was promised.
    pub fn is_required(self) -> bool {
        matches!(self, Self::DisableCredentialCache | Self::AllocatePty)
    }

    /// Why aido cares, in one sentence, for `aido doctor`.
    pub fn rationale(self) -> &'static str {
        match self {
            Self::DropInDirectory => {
                "lets aido own one file instead of editing a shared one, so install \
                 and uninstall cannot damage an operator's own rules"
            }
            Self::ValidateNamedFile => {
                "lets a snippet be checked before it is installed; without it the \
                 snippet must be validated by substitution into a temporary copy"
            }
            Self::PerCommandDefaults => {
                "scopes aido's settings to aido's own commands, so they cannot leak \
                 onto unrelated rules"
            }
            Self::DisableCredentialCache => {
                "REQUIRED: without it the agent path can ride a credential a human \
                 cached with an earlier unrelated sudo, which is a published escape"
            }
            Self::AllocatePty => {
                "REQUIRED: a fresh pty for the privileged child is the only fix for \
                 terminal-injection attacks; blocking individual ioctls does not work"
            }
            Self::RejectsArgumentWildcards => {
                "the backend refuses argument wildcards itself, so a hand-edited rule \
                 containing one will be rejected rather than silently accepted"
            }
            Self::PersistentCredentialCache => {
                "recorded only so aido can state that it never depends on backend \
                 credential caching in either direction"
            }
        }
    }
}

/// What a specific backend was found to support.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityMatrix {
    supported: BTreeSet<Capability>,
}

impl CapabilityMatrix {
    /// An empty matrix: nothing is supported until something proves it is.
    ///
    /// The default direction matters. A matrix that starts full and is narrowed
    /// by probing reports a capability whenever a probe fails to run, which is
    /// exactly backwards.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a matrix from a list of supported capabilities.
    pub fn from_supported(items: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            supported: items.into_iter().collect(),
        }
    }

    /// Records support for one capability.
    #[must_use]
    pub fn with(mut self, capability: Capability) -> Self {
        self.supported.insert(capability);
        self
    }

    /// Whether the backend supports `capability`.
    pub fn has(&self, capability: Capability) -> bool {
        self.supported.contains(&capability)
    }

    /// How many capabilities are supported.
    pub fn len(&self) -> usize {
        self.supported.len()
    }

    /// Whether nothing at all is supported.
    pub fn is_empty(&self) -> bool {
        self.supported.is_empty()
    }

    /// Every required capability this backend lacks.
    ///
    /// A non-empty result means aido must refuse to install rather than install
    /// something weaker than advertised.
    pub fn missing_required(&self) -> Vec<Capability> {
        Capability::ALL
            .into_iter()
            .filter(|c| c.is_required() && !self.has(*c))
            .collect()
    }

    /// Whether aido can operate on this backend at all.
    pub fn is_usable(&self) -> bool {
        self.missing_required().is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    #[test]
    fn a_matrix_starts_empty_so_a_failed_probe_never_reports_support() {
        // The direction that matters: absence of evidence must read as absence
        // of the capability, not as its presence.
        let matrix = CapabilityMatrix::empty();
        assert!(matrix.is_empty());
        assert_eq!(matrix.len(), 0);
        for capability in Capability::ALL {
            assert!(!matrix.has(capability), "{capability:?}");
        }
        assert!(!matrix.is_usable());
    }

    #[test]
    fn support_is_recorded_and_queryable() {
        let matrix = CapabilityMatrix::empty()
            .with(Capability::AllocatePty)
            .with(Capability::DropInDirectory);
        assert!(matrix.has(Capability::AllocatePty));
        assert!(matrix.has(Capability::DropInDirectory));
        assert!(!matrix.has(Capability::PerCommandDefaults));
        assert_eq!(matrix.len(), 2);
        assert!(!matrix.is_empty());
    }

    #[test]
    fn recording_the_same_capability_twice_is_not_two_capabilities() {
        let matrix = CapabilityMatrix::empty()
            .with(Capability::AllocatePty)
            .with(Capability::AllocatePty);
        assert_eq!(matrix.len(), 1);
    }

    #[test]
    fn only_the_two_controls_with_no_substitute_are_required() {
        let required: Vec<Capability> = Capability::ALL
            .into_iter()
            .filter(|c| c.is_required())
            .collect();
        assert_eq!(
            required,
            vec![Capability::DisableCredentialCache, Capability::AllocatePty]
        );
    }

    #[test]
    fn a_backend_missing_a_required_capability_is_unusable() {
        // Refusing to install is the correct outcome. Installing something
        // weaker than advertised is the failure this check exists to prevent.
        let pty_only = CapabilityMatrix::empty().with(Capability::AllocatePty);
        assert!(!pty_only.is_usable());
        assert_eq!(
            pty_only.missing_required(),
            vec![Capability::DisableCredentialCache]
        );

        let cache_only = CapabilityMatrix::empty().with(Capability::DisableCredentialCache);
        assert_eq!(cache_only.missing_required(), vec![Capability::AllocatePty]);

        let neither = CapabilityMatrix::empty().with(Capability::DropInDirectory);
        assert_eq!(neither.missing_required().len(), 2);
    }

    #[test]
    fn a_backend_with_both_required_capabilities_is_usable_even_if_spartan() {
        // A doas port with no drop-in directory and no per-command defaults is
        // still usable; those have workarounds, the other two do not.
        let spartan = CapabilityMatrix::from_supported([
            Capability::DisableCredentialCache,
            Capability::AllocatePty,
        ]);
        assert!(spartan.is_usable());
        assert!(spartan.missing_required().is_empty());
        assert!(!spartan.has(Capability::DropInDirectory));
    }

    #[test]
    fn every_capability_explains_why_aido_cares() {
        for capability in Capability::ALL {
            let rationale = capability.rationale();
            assert!(rationale.len() > 40, "{capability:?}: {rationale}");
            // A required capability must say so where an operator will read it.
            if capability.is_required() {
                assert!(
                    rationale.starts_with("REQUIRED"),
                    "{capability:?} is required but does not say so: {rationale}"
                );
            }
        }
    }

    #[test]
    fn the_capability_list_is_complete_and_unique() {
        let mut sorted = Capability::ALL.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), count, "a capability is listed twice");
    }

    #[test]
    fn a_matrix_round_trips_and_is_debuggable() {
        let matrix = CapabilityMatrix::from_supported([Capability::AllocatePty]);
        let json = serde_json::to_string(&matrix).unwrap();
        assert_eq!(json, r#"["allocate-pty"]"#);
        assert_eq!(
            serde_json::from_str::<CapabilityMatrix>(&json).unwrap(),
            matrix
        );
        assert!(format!("{matrix:?}").contains("AllocatePty"));
        assert!(format!("{:?}", Capability::AllocatePty).contains("AllocatePty"));
    }
}
