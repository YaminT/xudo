//! Operator-authored deny rules. These rules can only turn an accepted command
//! into a refusal; they never create an allow.

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
                values.iter().any(|v| normalized == v.as_bytes())
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
    value <= 0x1f || (0x7f..=0x9f).contains(&value)
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
}
