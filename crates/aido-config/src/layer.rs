//! Where a setting came from, and which source wins.
//!
//! One precedence order, written down once, used by both binaries. The order is
//! deliberately boring; what matters is that two of its properties are
//! enforced rather than documented.

use core::fmt;

use serde::{Deserialize, Serialize};

/// A configuration source, in ascending order of precedence.
///
/// The derived `Ord` **is** the precedence order, so a later variant wins. That
/// makes the ordering a property of the type rather than of a comparison
/// function somebody can get backwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    /// Compiled into the binary and not configurable at all.
    ///
    /// Distinct from [`Self::BuiltInDefault`]: a reader must be able to see
    /// that `use_pty` is not something they can turn off, rather than wonder
    /// why setting it had no effect.
    Compiled,
    /// The value used when nothing sets it.
    BuiltInDefault,
    /// Root-owned system configuration.
    System,
    /// Per-user configuration.
    ///
    /// Exists for `ido` only. `aido` has no user layer, because a file the user
    /// can write is a file the agent can write.
    User,
    /// Per-project configuration, checked into a repository.
    Project,
    /// The process environment.
    ///
    /// Permitted for presentation settings and nothing else. See
    /// [`crate::settings::Setting::is_security_relevant`].
    Environment,
    /// A command-line flag. Always wins.
    CliFlag,
}

impl Layer {
    /// Every layer, lowest precedence first.
    pub const ALL: [Self; 7] = [
        Self::Compiled,
        Self::BuiltInDefault,
        Self::System,
        Self::User,
        Self::Project,
        Self::Environment,
        Self::CliFlag,
    ];

    /// Whether a value from this layer can be overridden by a later one.
    ///
    /// [`Self::Compiled`] cannot: it is not configuration, it is the program.
    pub fn is_overridable(self) -> bool {
        !matches!(self, Self::Compiled)
    }

    /// Whether this layer may only *narrow* what a higher-privileged layer
    /// allowed, never widen it.
    ///
    /// True for [`Self::Project`], because a checked-in file is writable by
    /// anyone who can open a pull request. A project file may tighten a limit
    /// or add a confirmation; it may never remove one.
    pub fn is_narrowing_only(self) -> bool {
        matches!(self, Self::Project)
    }

    /// A short label for `config list --origin`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Compiled => "compiled-in",
            Self::BuiltInDefault => "default",
            Self::System => "system",
            Self::User => "user",
            Self::Project => "project",
            Self::Environment => "environment",
            Self::CliFlag => "flag",
        }
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Exactly where a value came from.
///
/// The `file:line` half is what makes "why is confirmation off?" a
/// one-command question. Borrowed from `git config --show-origin`, which solved
/// this well.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// Which layer set it.
    pub layer: Layer,
    /// The file and line, when there is one.
    pub source: Option<String>,
}

impl Origin {
    /// A value that is not configurable.
    pub fn compiled() -> Self {
        Self {
            layer: Layer::Compiled,
            source: None,
        }
    }

    /// A value nobody set.
    pub fn default_value() -> Self {
        Self {
            layer: Layer::BuiltInDefault,
            source: None,
        }
    }

    /// A value from a file.
    pub fn file(layer: Layer, file: impl Into<String>, line: u32) -> Self {
        Self {
            layer,
            source: Some(format!("{}:{}", file.into(), line)),
        }
    }

    /// A value from a layer with no file, such as a flag.
    pub fn layer(layer: Layer) -> Self {
        Self {
            layer,
            source: None,
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{} ({source})", self.layer),
            None => write!(f, "<{}>", self.layer),
        }
    }
}

/// A value together with where it came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tracked<T> {
    /// The value.
    pub value: T,
    /// Where it came from.
    pub origin: Origin,
}

impl<T> Tracked<T> {
    /// A compiled-in value.
    pub fn compiled(value: T) -> Self {
        Self {
            value,
            origin: Origin::compiled(),
        }
    }

    /// A default value.
    pub fn default_value(value: T) -> Self {
        Self {
            value,
            origin: Origin::default_value(),
        }
    }

    /// A value from a specific origin.
    pub fn from(value: T, origin: Origin) -> Self {
        Self { value, origin }
    }

    /// Whether a later layer is allowed to replace this.
    pub fn is_overridable(&self) -> bool {
        self.origin.layer.is_overridable()
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
    fn the_declared_order_is_the_precedence_order() {
        // The type carries the ordering, so nobody can implement a comparison
        // backwards.
        assert!(Layer::BuiltInDefault < Layer::System);
        assert!(Layer::System < Layer::User);
        assert!(Layer::User < Layer::Project);
        assert!(Layer::Project < Layer::Environment);
        assert!(Layer::Environment < Layer::CliFlag);
        // And the list is in that order too.
        let mut sorted = Layer::ALL;
        sorted.sort_unstable();
        assert_eq!(sorted, Layer::ALL);
    }

    #[test]
    fn compiled_values_are_not_configuration_and_cannot_be_overridden() {
        assert!(!Layer::Compiled.is_overridable());
        for layer in Layer::ALL.into_iter().filter(|l| *l != Layer::Compiled) {
            assert!(layer.is_overridable(), "{layer:?}");
        }
        assert!(!Tracked::compiled(true).is_overridable());
        assert!(Tracked::default_value(true).is_overridable());
    }

    #[test]
    fn only_the_project_layer_is_narrowing_only() {
        // A checked-in file is writable by anyone who can open a pull request,
        // so it may tighten a limit and never remove one.
        assert!(Layer::Project.is_narrowing_only());
        for layer in Layer::ALL.into_iter().filter(|l| *l != Layer::Project) {
            assert!(!layer.is_narrowing_only(), "{layer:?}");
        }
    }

    #[test]
    fn every_layer_has_a_distinct_label() {
        let mut labels: Vec<&str> = Layer::ALL.into_iter().map(Layer::label).collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count);
        assert_eq!(Layer::Compiled.to_string(), "compiled-in");
        assert_eq!(Layer::System.to_string(), "system");
    }

    #[test]
    fn an_origin_from_a_file_names_the_file_and_line() {
        // The whole point: "why is confirmation off?" has a one-command answer.
        let origin = Origin::file(Layer::System, "/etc/aido/config.toml", 12);
        assert_eq!(origin.to_string(), "system (/etc/aido/config.toml:12)");
        assert_eq!(origin.layer, Layer::System);
    }

    #[test]
    fn an_origin_with_no_file_still_says_which_layer() {
        // Compiled-in values are shown as compiled-in, never omitted, so a
        // reader can see that a setting is not theirs to change.
        assert_eq!(Origin::compiled().to_string(), "<compiled-in>");
        assert_eq!(Origin::default_value().to_string(), "<default>");
        assert_eq!(Origin::layer(Layer::CliFlag).to_string(), "<flag>");
    }

    #[test]
    fn a_tracked_value_carries_both_halves() {
        let tracked = Tracked::from(42_u32, Origin::file(Layer::Project, ".aido/policy.toml", 3));
        assert_eq!(tracked.value, 42);
        assert_eq!(tracked.origin.layer, Layer::Project);
        assert!(tracked.origin.source.is_some());
        assert!(format!("{tracked:?}").contains("42"));
    }

    #[test]
    fn layers_and_origins_round_trip() {
        for layer in Layer::ALL {
            let json = serde_json::to_string(&layer).unwrap();
            assert_eq!(serde_json::from_str::<Layer>(&json).unwrap(), layer);
        }
        let origin = Origin::file(Layer::User, "~/.config/ido/config.toml", 1);
        let json = serde_json::to_string(&origin).unwrap();
        assert_eq!(serde_json::from_str::<Origin>(&json).unwrap(), origin);
        assert!(serde_json::from_str::<Origin>(r#"{"layer":"system","trusted":true}"#).is_err());

        let tracked = Tracked::default_value(true);
        let json = serde_json::to_string(&tracked).unwrap();
        assert_eq!(
            serde_json::from_str::<Tracked<bool>>(&json).unwrap(),
            tracked
        );
    }
}
