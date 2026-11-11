//! `config get` and `config list`, rendered once for both binaries.
//!
//! Pure: it formats a [`Settings`] it is handed. Borrowed from
//! `git config --show-origin`, so "why is confirmation off?" has a one-command
//! answer naming the file and line.
//!
//! A value nobody set reads `<default>` and a value that cannot be set reads
//! `<compiled-in>`. Neither is ever shown as a file.

use crate::layer::Layer;
use crate::settings::{Setting, Settings};

/// What `config list` prints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListOptions {
    /// Add the origin column.
    pub origin: bool,
    /// Include settings nobody set (defaults) and compiled-in ones. Without it
    /// only values a file or flag set are listed.
    pub effective: bool,
}

/// One line for `setting`, with or without its origin.
fn row(settings: &Settings, setting: Setting, origin: bool) -> String {
    let tracked = settings.get(setting);
    if origin {
        format!(
            "{:<26} {:<10} {}",
            setting.key(),
            tracked.value.render(),
            tracked.origin
        )
    } else {
        format!("{:<26} {}", setting.key(), tracked.value.render())
    }
}

/// Renders `config list` over the `scope` settings, one per line.
pub fn list(settings: &Settings, scope: &[Setting], options: ListOptions) -> String {
    let mut text = String::new();
    for setting in scope {
        let layer = settings.get(*setting).origin.layer;
        let explicit = !matches!(layer, Layer::Compiled | Layer::BuiltInDefault);
        if options.effective || explicit {
            text.push_str(&row(settings, *setting, options.origin));
            text.push('\n');
        }
    }
    text
}

/// Renders `config get`: the value, then the origin when asked, tab separated
/// so a script can cut it.
pub fn get(settings: &Settings, setting: Setting, origin: bool) -> String {
    let tracked = settings.get(setting);
    if origin {
        format!("{}\t{}\n", tracked.value.render(), tracked.origin)
    } else {
        format!("{}\n", tracked.value.render())
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
    use crate::load::apply_file;

    fn with_file() -> Settings {
        let mut settings = Settings::default();
        apply_file(
            &mut settings,
            Layer::System,
            "/etc/xudo/config.toml",
            "# header\n\nfrozen = true\nconfirmation_timeout_secs = 30\n",
        )
        .unwrap();
        settings
    }

    #[test]
    fn origin_reporting_names_the_real_file_and_line() {
        let text = list(
            &with_file(),
            &Setting::ALL,
            ListOptions {
                origin: true,
                effective: false,
            },
        );
        assert!(text.contains("system (/etc/xudo/config.toml:3)"), "{text}");
        assert!(text.contains("system (/etc/xudo/config.toml:4)"), "{text}");
        assert_eq!(text.lines().count(), 2, "only explicit values: {text}");
        let one = get(&with_file(), Setting::Frozen, true);
        assert_eq!(one, "true\tsystem (/etc/xudo/config.toml:3)\n");
    }

    #[test]
    fn a_config_file_flag_origin_is_pinned() {
        let mut settings = Settings::default();
        apply_file(
            &mut settings,
            Layer::ConfigFile,
            "/tmp/x",
            "# c\nfrozen = true\n",
        )
        .unwrap();
        insta::assert_snapshot!(get(&settings, Setting::Frozen, true), @"
        true	--config-file (/tmp/x:2)
        ");
    }

    #[test]
    fn compiled_in_values_are_listed_as_compiled_in() {
        let settings = with_file();
        let all = ListOptions {
            origin: true,
            effective: true,
        };
        let text = list(&settings, &Setting::ALL, all);
        assert_eq!(text.lines().count(), Setting::ALL.len());
        let pty = text.lines().find(|l| l.starts_with("use_pty")).unwrap();
        assert!(pty.ends_with("<compiled-in>"), "{pty}");
        assert!(!pty.contains(".toml"), "{pty}");
        let color = text.lines().find(|l| l.starts_with("color")).unwrap();
        assert!(color.ends_with("<default>"), "{color}");
        assert!(!color.contains(".toml"), "{color}");
        // Without --effective a compiled-in or default value is not listed.
        let bare = list(&settings, &Setting::ALL, ListOptions::default());
        assert!(
            !bare.contains("use_pty") && !bare.contains("color"),
            "{bare}"
        );
        assert!(!bare.contains("system"), "no origin column: {bare}");
    }

    #[test]
    fn get_without_origin_prints_only_the_value() {
        assert_eq!(
            get(&with_file(), Setting::ConfirmationTimeoutSecs, false),
            "30\n"
        );
        assert_eq!(
            get(&Settings::default(), Setting::UsePty, true),
            "true\t<compiled-in>\n"
        );
    }

    #[test]
    fn a_key_names_its_setting_and_nothing_else_does() {
        for setting in Setting::ALL {
            assert_eq!(Setting::from_key(setting.key()), Some(setting));
        }
        assert_eq!(Setting::from_key("confirm_agent_action"), None);
        assert_eq!(Setting::from_key(""), None);
    }

    #[test]
    fn the_schema_is_pinned() {
        insta::assert_json_snapshot!(Settings::schema());
    }
}
