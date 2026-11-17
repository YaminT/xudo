//! Operator-authored deny rules. These rules can only turn an accepted command
//! into a refusal; they never create an allow.
//!
//! `any-arg` compares each argv element exactly. Option spellings are not
//! unified: clustered short options, GNU long-option abbreviations, and
//! `--option=value` are distinct elements and must be listed separately.

use serde::{Deserialize, Serialize};

use crate::argv::{Arg, Argv};
use crate::matcher::{Matcher, NameKind};
use crate::rule::{ActionId, Source};

/// Maximum number of configured deny rules in one ruleset.
pub const MAX_DENY_RULES: usize = if cfg!(miri) { 8 } else { 256 };
/// Maximum number of conjunctive clauses in one deny rule.
pub const MAX_DENY_CLAUSES: usize = 4;
/// Maximum number of members in one clause.
pub const MAX_DENY_MEMBERS: usize = 64;
/// Maximum encoded byte length of one member.
pub const MAX_DENY_MEMBER_BYTES: usize = 255;

/// One position-free clause in a configured deny rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DenyClause {
    /// Matches when any argv element exactly equals one listed value.
    #[serde(default)]
    pub any_arg: Option<Vec<String>>,
    /// Matches when any argv element normalizes to one listed Debian package name.
    #[serde(default)]
    pub any_deb_name: Option<Vec<String>>,
}

impl DenyClause {
    /// Whether this clause matches any argument.
    pub fn matches(&self, argv: &Argv) -> bool {
        match (&self.any_arg, &self.any_deb_name) {
            (Some(values), None) => argv
                .as_slice()
                .iter()
                .any(|arg| values.iter().any(|v| arg.as_bytes() == v.as_bytes())),
            (None, Some(values)) => argv.as_slice().iter().any(|arg| {
                let normalized = deb_name(arg.as_bytes());
                is_ambiguous_deb_pattern(normalized)
                    || values.iter().any(|v| normalized == v.as_bytes())
            }),
            _ => false,
        }
    }

    /// The single matcher kind and its members, if the clause is well formed.
    pub fn kind_and_values(&self) -> Option<(&'static [u8], &[String])> {
        match (&self.any_arg, &self.any_deb_name) {
            (Some(values), None) => Some((b"any-arg", values)),
            (None, Some(values)) => Some((b"any-deb-name", values)),
            _ => None,
        }
    }
}

fn deb_name(argument: &[u8]) -> &[u8] {
    let argument = argument
        .strip_suffix(b"-")
        .or_else(|| argument.strip_suffix(b"+"))
        .unwrap_or(argument);
    argument
        .split(|byte| matches!(byte, b':' | b'=' | b'/'))
        .next()
        .unwrap_or(argument)
}

/// Apt accepts several pattern syntaxes in package operands. A token that is
/// not a plain Debian package name may select a protected package, so a
/// package-name clause treats it as a match. Valid literal names (including
/// names with `.` and `+`) retain exact matching.
fn is_ambiguous_deb_pattern(value: &[u8]) -> bool {
    if is_plain_deb_name(value) || value.starts_with(b"-") || value.is_empty() {
        return false;
    }
    value.iter().any(|byte| {
        matches!(
            byte,
            b'^' | b'$' | b'?' | b'~' | b'*' | b'[' | b'(' | b'|' | b'.'
        )
    })
}

fn is_plain_deb_name(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'+')
        && value.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'.' | b'-')
        })
}

/// A root-authored refusal that only narrows an already accepted action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct DenyRule {
    /// Stable identifier, unique across actions and deny rules.
    pub id: ActionId,
    /// User-visible explanation of the refusal.
    pub reason: String,
    /// Executable basenames to which this rule applies.
    pub program: Vec<String>,
    /// Every clause must match; an empty list applies to every call of `program`.
    pub all: Vec<DenyClause>,
    /// Loader-assigned origin of this rule.
    #[serde(skip)]
    pub source: Source,
}

impl DenyRule {
    /// Whether this rule matches the executable basename and canonical argv.
    pub fn matches(&self, exe: &[u8], argv: &Argv) -> bool {
        let basename = exe.rsplit(|byte| *byte == b'/').next().unwrap_or(exe);
        self.program
            .iter()
            .any(|program| program.as_bytes() == basename)
            && self.all.iter().all(|clause| clause.matches(argv))
    }

    /// Validates all bounds and grammar constraints.
    ///
    /// # Errors
    ///
    /// Returns a reason when the rule violates a grammar or size bound.
    pub fn validate(&self) -> Result<(), String> {
        if self.reason.is_empty() || self.reason.len() > 200 || self.reason.chars().any(is_control)
        {
            return Err("reason must be 1–200 bytes and contain no control characters".into());
        }
        if self.program.is_empty()
            || self.program.len() > 8
            || self.program.iter().any(|p| {
                p.is_empty()
                    || p == "."
                    || p == ".."
                    || p.contains('/')
                    || p.as_bytes().contains(&0)
            })
        {
            return Err("program must contain 1–8 nonempty basenames".into());
        }
        if self.all.len() > MAX_DENY_CLAUSES {
            return Err(format!(
                "all may contain at most {MAX_DENY_CLAUSES} clauses"
            ));
        }
        for clause in &self.all {
            let Some((kind, values)) = clause.kind_and_values() else {
                return Err("each clause must contain exactly one matcher".into());
            };
            if values.is_empty() {
                let label = if kind == b"any-arg" {
                    "any-arg"
                } else {
                    "any-deb-name"
                };
                return Err(format!("{label} must contain at least one member"));
            }
            if values.len() > MAX_DENY_MEMBERS {
                let label = if kind == b"any-arg" {
                    "any-arg"
                } else {
                    "any-deb-name"
                };
                return Err(format!(
                    "{label} may contain at most {MAX_DENY_MEMBERS} members"
                ));
            }
            for value in values {
                if value.len() > MAX_DENY_MEMBER_BYTES || value.as_bytes().contains(&0) {
                    return Err("members must be at most 255 bytes and contain no NUL".into());
                }
                if clause.any_deb_name.is_some()
                    && !Matcher::Name(NameKind::DebNameLiteral)
                        .accepts(&Arg::new(value.as_bytes().to_vec()))
                {
                    return Err(format!("{value:?} is not a deb-name-literal"));
                }
            }
        }
        Ok(())
    }
}

fn is_control(character: char) -> bool {
    let value = u32::from(character);
    value <= 0x1f
        || (0x7f..=0x9f).contains(&value)
        || matches!(
            value,
            0x00ad
                | 0x0600..=0x0605
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x0890..=0x0891
                | 0x08e2
                | 0x180e
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x206f
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd..=0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
        )
}

/// Trace payload for a configured deny rule that matched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyRuleMatch {
    /// Stable rule identifier.
    pub id: ActionId,
    /// Loader-assigned source location.
    pub source: Source,
    /// User-visible reason for refusing the command.
    pub reason: String,
}

/// Returns every deny rule matching the executable and argument vector.
pub fn evaluate_deny_rules<'a>(
    rules: &'a [DenyRule],
    exe: &[u8],
    argv: &Argv,
) -> Vec<&'a DenyRule> {
    rules
        .iter()
        .filter(|rule| rule.matches(exe, argv))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;

    fn rule(all: Vec<DenyClause>) -> DenyRule {
        DenyRule {
            id: ActionId::new("xudo.protect.test"),
            reason: "protected package".into(),
            program: vec!["apt-get".into(), "apt".into()],
            all,
            source: Source::new("00-protect.toml", 3),
        }
    }

    #[test]
    fn deb_name_clauses_refuse_local_arch_version_and_repository_variants() {
        let deny = rule(vec![DenyClause {
            any_arg: None,
            any_deb_name: Some(vec!["xudo".into()]),
        }]);
        for name in [
            "xudo",
            "xudo-",
            "xudo+",
            "xudo:arm64",
            "xudo=0.1",
            "xudo/stable",
        ] {
            assert!(
                deny.matches(b"/usr/bin/apt-get", &Argv::new([name])),
                "{name}"
            );
        }
        for name in ["xudoo", "xudoish", "other-xudo", "xudo2"] {
            assert!(
                !deny.matches(b"/usr/bin/apt-get", &Argv::new([name])),
                "{name}"
            );
        }
    }

    fn pattern_denied(name: &str) -> bool {
        let deny = rule(vec![DenyClause {
            any_arg: None,
            any_deb_name: Some(vec!["xudo".into()]),
        }]);
        deny.matches(b"/usr/bin/apt-get", &Argv::new(["install", name]))
    }

    #[test]
    fn denies_removal_via_apt_name_pattern_caret() {
        assert!(pattern_denied("^xudo"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_dollar() {
        assert!(pattern_denied("xudo$"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_question() {
        assert!(pattern_denied("?name(^xudo$)"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_tilde() {
        assert!(pattern_denied("~nxudo"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_star() {
        assert!(pattern_denied("xud*"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_bracket() {
        assert!(pattern_denied("xudo[0-9]"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_parenthesis() {
        assert!(pattern_denied("xudo(foo)"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_pipe() {
        assert!(pattern_denied("xudo|other"));
    }
    #[test]
    fn denies_removal_via_apt_name_pattern_dot() {
        assert!(pattern_denied("xudo."));
    }

    #[test]
    fn install_deb_name_clauses_refuse_removal_suffix_with_architecture() {
        let deny = rule(vec![
            DenyClause {
                any_arg: Some(vec!["install".into()]),
                any_deb_name: None,
            },
            DenyClause {
                any_arg: None,
                any_deb_name: Some(vec!["xudo".into()]),
            },
        ]);
        assert!(deny.matches(b"/usr/bin/apt-get", &Argv::new(["install", "xudo:amd64-"])));
    }

    #[test]
    fn install_deb_name_clauses_refuse_removal_suffix_with_suite() {
        let deny = rule(vec![
            DenyClause {
                any_arg: Some(vec!["install".into()]),
                any_deb_name: None,
            },
            DenyClause {
                any_arg: None,
                any_deb_name: Some(vec!["sudo".into()]),
            },
        ]);
        assert!(deny.matches(b"/usr/bin/apt-get", &Argv::new(["install", "sudo/stable-"])));
    }

    #[test]
    fn valid_debian_names_with_dot_and_plus_match_exactly() {
        for protected in ["python3.12", "libstdc++6"] {
            let deny = rule(vec![DenyClause {
                any_arg: None,
                any_deb_name: Some(vec![protected.into()]),
            }]);
            assert!(deny.matches(b"/usr/bin/apt-get", &Argv::new([protected])));
        }
        assert!(!pattern_denied("python3.12"));
    }

    #[test]
    fn any_arg_keeps_option_spellings_byte_exact() {
        let deny = rule(vec![DenyClause {
            any_arg: Some(vec![
                "--purge".into(),
                "-Br".into(),
                "--option=value".into(),
            ]),
            any_deb_name: None,
        }]);
        assert!(deny.matches(b"/usr/bin/apt-get", &Argv::new(["--purge"])));
        assert!(!deny.matches(b"/usr/bin/apt-get", &Argv::new(["--purg"])));
        assert!(!deny.matches(b"/usr/bin/apt-get", &Argv::new(["--option", "value"])));
        assert!(!deny.matches(b"/usr/bin/apt-get", &Argv::new(["-B", "-r"])));
    }

    #[test]
    fn all_empty_refuses_every_call_to_a_named_program() {
        assert!(rule(Vec::new()).matches(b"/usr/bin/apt", &Argv::default()));
        assert!(!rule(Vec::new()).matches(b"/usr/bin/dpkg", &Argv::default()));
    }

    #[test]
    fn malformed_clauses_never_match() {
        let none = DenyClause {
            any_arg: None,
            any_deb_name: None,
        };
        let both = DenyClause {
            any_arg: Some(vec!["x".into()]),
            any_deb_name: Some(vec!["x".into()]),
        };
        let argv = Argv::new(["x"]);
        assert!(!none.matches(&argv));
        assert!(!both.matches(&argv));
    }

    #[test]
    fn program_basename_is_byte_exact_and_not_a_path_prefix() {
        let deny = rule(Vec::new());
        assert!(deny.matches(b"/usr/local/bin/apt", &Argv::default()));
        assert!(!deny.matches(b"/usr/bin/aptitude", &Argv::default()));
        assert!(!deny.matches(b"/usr/bin/apt\xff", &Argv::default()));
    }

    #[test]
    fn clauses_are_conjoined_but_each_matches_at_any_position() {
        let deny = rule(vec![
            DenyClause {
                any_arg: Some(vec!["remove".into()]),
                any_deb_name: None,
            },
            DenyClause {
                any_arg: None,
                any_deb_name: Some(vec!["xudo".into()]),
            },
        ]);
        assert!(deny.matches(
            b"/usr/bin/apt",
            &Argv::new(["-y", "remove", "--", "xudo:arm64"])
        ));
        assert!(!deny.matches(b"/usr/bin/apt", &Argv::new(["remove", "sudo"])));
    }

    #[test]
    fn deny_rule_bounds_and_member_grammar_are_validated() {
        let mut deny = rule(Vec::new());
        deny.reason.clear();
        assert!(deny.validate().is_err());
        deny.reason = "x".repeat(201);
        assert!(deny.validate().is_err());
        deny.reason = "bad\u{001b}reason".into();
        assert!(deny.validate().is_err());
        deny.reason = "bad\u{0085}reason".into();
        assert!(deny.validate().is_err());
        deny.reason = "bad\u{202e}reason".into();
        assert!(deny.validate().is_err());
        deny.reason = "ok".into();
        deny.program = vec!["/usr/bin/apt".into()];
        assert!(deny.validate().is_err());
        deny.program = vec![String::new()];
        assert!(deny.validate().is_err());
        deny.program = vec![".".into()];
        assert!(deny.validate().is_err());
        deny.program = vec!["..".into()];
        assert!(deny.validate().is_err());
        deny.program = (0..9).map(|i| format!("apt{i}")).collect();
        assert!(deny.validate().is_err());
        deny.program = vec!["apt".into()];
        deny.all = (0..=MAX_DENY_CLAUSES)
            .map(|_| DenyClause {
                any_arg: Some(Vec::new()),
                any_deb_name: None,
            })
            .collect();
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: None,
            any_deb_name: Some(vec!["xudo:arm64".into()]),
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: None,
            any_deb_name: Some(vec!["Xudo".into()]),
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: None,
            any_deb_name: Some((0..=MAX_DENY_MEMBERS).map(|i| format!("pkg{i}")).collect()),
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: None,
            any_deb_name: Some(vec![String::new()]),
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: Some(Vec::new()),
            any_deb_name: Some(Vec::new()),
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: Some(Vec::new()),
            any_deb_name: None,
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: None,
            any_deb_name: Some(Vec::new()),
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: None,
            any_deb_name: None,
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: Some(vec!["nul\0value".into()]),
            any_deb_name: None,
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: Some((0..=MAX_DENY_MEMBERS).map(|i| format!("arg{i}")).collect()),
            any_deb_name: None,
        }];
        assert!(deny.validate().is_err());
        deny.all = vec![DenyClause {
            any_arg: Some(vec!["x".repeat(MAX_DENY_MEMBER_BYTES + 1)]),
            any_deb_name: None,
        }];
        assert!(deny.validate().is_err());
    }

    #[test]
    fn deny_rule_reasons_reject_unicode_format_characters() {
        let mut deny = rule(Vec::new());
        for character in [
            '\u{00ad}',
            '\u{0600}',
            '\u{061c}',
            '\u{06dd}',
            '\u{070f}',
            '\u{0890}',
            '\u{08e2}',
            '\u{180e}',
            '\u{200b}',
            '\u{202a}',
            '\u{2060}',
            '\u{feff}',
            '\u{fff9}',
            '\u{110bd}',
            '\u{13430}',
            '\u{1bca0}',
            '\u{1d173}',
            '\u{e0001}',
            '\u{e0020}',
        ] {
            deny.reason = format!("reason{character}text");
            assert!(deny.validate().is_err());
        }
    }
}
