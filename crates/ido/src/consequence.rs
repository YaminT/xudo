//! How bad is it if this command is wrong?
//!
//! `ido` gates on *consequence*, not on uid: `aws s3 rm --recursive` needs no
//! root and can still delete production. This module reads the stored argv and
//! says what the human should know before running it — whether it escalates,
//! whether it drives a cloud CLI and against which profile, region, or project,
//! and whether the command name contains lookalike characters.
//!
//! Everything here is a *hint for the human*. Nothing runs or is refused on the
//! strength of it; the only behaviour it changes is that a high-consequence
//! entry needs a typed confirmation rather than a keypress.

use term_sanitize::flag_command_name;

/// Programs that run their arguments with someone else's privilege.
pub const ELEVATORS: [&str; 6] = ["sudo", "doas", "aido", "pkexec", "su", "run0"];

/// Command-line clients that hold long-lived credentials to remote systems.
pub const CLOUD_TOOLS: [&str; 12] = [
    "aws",
    "gcloud",
    "gsutil",
    "az",
    "kubectl",
    "helm",
    "terraform",
    "tofu",
    "pulumi",
    "doctl",
    "flyctl",
    "heroku",
];

/// Flags whose value names *where* a cloud command acts.
const TARGET_FLAGS: [&str; 5] = [
    "--profile",
    "--region",
    "--project",
    "--context",
    "--subscription",
];

/// What the human should know about one entry before running it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Consequence {
    /// The command runs something with elevated privilege.
    pub elevates: bool,
    /// The cloud CLI it drives, if any.
    pub cloud: Option<String>,
    /// Where it acts, as `(key, value)` pairs read from the argv. Untrusted
    /// text: render it through the sanitizer.
    pub targets: Vec<(&'static str, String)>,
    /// The command name contains non-ASCII characters, so it may not be the
    /// program it appears to be.
    pub lookalike: bool,
}

impl Consequence {
    /// Whether running it should take a typed confirmation, not a keypress.
    #[must_use]
    pub fn is_high(&self) -> bool {
        self.elevates || self.cloud.is_some() || self.lookalike
    }
}

/// Assesses a stored argv.
#[must_use]
pub fn assess(argv: &[String]) -> Consequence {
    let Some(command) = argv.first() else {
        return Consequence::default();
    };
    let name = basename(command);
    let cloud = CLOUD_TOOLS
        .iter()
        .find(|tool| **tool == name)
        .map(|tool| (*tool).to_owned());
    let targets = if cloud.is_some() {
        targets_of(argv)
    } else {
        Vec::new()
    };
    Consequence {
        elevates: ELEVATORS.contains(&name),
        cloud,
        targets,
        lookalike: !flag_command_name(command).is_empty(),
    }
}

/// The last path component of a command.
fn basename(command: &str) -> &str {
    command.rsplit_once('/').map_or(command, |(_, base)| base)
}

/// Every target flag in the argv, in either `--flag value` or `--flag=value`
/// spelling.
fn targets_of(argv: &[String]) -> Vec<(&'static str, String)> {
    let mut found = Vec::new();
    for (i, token) in argv.iter().enumerate() {
        for flag in TARGET_FLAGS {
            let key = flag.trim_start_matches('-');
            if token == flag {
                if let Some(value) = argv.get(i.saturating_add(1)) {
                    found.push((key, value.clone()));
                }
            } else if let Some(value) = token
                .strip_prefix(flag)
                .and_then(|rest| rest.strip_prefix('='))
            {
                found.push((key, value.to_owned()));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn argv(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| (*t).to_owned()).collect()
    }

    #[test]
    fn an_ordinary_command_is_low_consequence() {
        let c = assess(&argv(&["cargo", "build"]));
        assert_eq!(c, Consequence::default());
        assert!(!c.is_high());
    }

    #[test]
    fn an_elevator_is_high_consequence_by_path_or_by_name() {
        assert!(assess(&argv(&["sudo", "apt-get", "install", "x"])).elevates);
        let by_path = assess(&argv(&["/usr/bin/doas", "true"]));
        assert!(by_path.elevates);
        assert!(by_path.is_high());
    }

    #[test]
    fn a_cloud_command_names_where_it_acts_in_both_spellings() {
        let c = assess(&argv(&[
            "aws",
            "s3",
            "rm",
            "--recursive",
            "--profile",
            "prod",
            "--region=eu-west-1",
        ]));
        assert_eq!(c.cloud.as_deref(), Some("aws"));
        assert_eq!(
            c.targets,
            vec![
                ("profile", "prod".to_owned()),
                ("region", "eu-west-1".to_owned())
            ]
        );
        assert!(c.is_high());
    }

    #[test]
    fn a_dangling_target_flag_names_nothing() {
        let c = assess(&argv(&["gcloud", "--project"]));
        assert_eq!(c.cloud.as_deref(), Some("gcloud"));
        assert!(c.targets.is_empty());
    }

    #[test]
    fn a_target_flag_prefix_is_not_a_target() {
        // `--profiler` is not `--profile`.
        let c = assess(&argv(&["kubectl", "--profiler", "x", "--contextual"]));
        assert!(c.targets.is_empty());
    }

    #[test]
    fn a_homoglyph_binary_name_is_flagged() {
        // Cyrillic `а` in `аws`: a different program that reads as `aws`.
        let c = assess(&argv(&["\u{0430}ws", "s3", "ls"]));
        assert!(c.lookalike);
        assert!(c.cloud.is_none(), "the lookalike is not the real tool");
        assert!(c.is_high());
    }

    #[test]
    fn an_empty_argv_has_no_consequence() {
        assert_eq!(assess(&[]), Consequence::default());
    }
}
