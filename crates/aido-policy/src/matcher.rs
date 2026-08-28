//! Typed, per-position argument matchers.
//!
//! # Why there are no globs here
//!
//! `sudoers` matches a rule's arguments by joining them into one string and
//! running `fnmatch` against it. That makes `*` cross whitespace *and* match
//! `/`, so a rule that reads as "run this one script" is a root shell:
//!
//! ```text
//! /usr/bin/python3 /opt/utils/*.py    ->  python3 /opt/utils/../../../tmp/x.py
//! cat /var/log/messages*              ->  cat /var/log/messages /etc/shadow
//! ```
//!
//! This module therefore offers no wildcard over a flattened argv, at any
//! position, ever. Each argument position declares a *type*, and the only
//! pattern matcher available ([`Matcher::Pattern`]) is anchored by the parser
//! and size-bounded, so a rule author cannot write an unanchored or
//! catastrophically-backtracking expression even by accident.
//!
//! # "No arguments" means zero arguments
//!
//! An [`ArgSpec`] list that is empty permits an argv of length zero and nothing
//! else. `doas` treats a missing `args` clause as "any arguments"; that default
//! is inverted here, because the permissive reading is how an allowlist becomes
//! a shell.

use core::fmt;
use std::collections::BTreeSet;

use bstr::ByteSlice;
use serde::{Deserialize, Serialize};

use crate::argv::{Arg, Argv};

/// Upper bound on a compiled pattern's memory, in bytes.
///
/// Bounds both the compiled program and its lazy DFA cache so a rule file
/// cannot exhaust memory. `regex`'s engine is a linear-time hybrid NFA/DFA with
/// no backtracking, so there is no exponential-blowup risk to bound as well.
const PATTERN_SIZE_LIMIT: usize = 64 * 1024;

/// Upper bound on how many arguments one variadic spec may consume.
///
/// Bounds the matcher's work and, more importantly, bounds blast radius: a rule
/// permitting "some package names" should not silently accept ten thousand.
pub const MAX_REPEAT: usize = 64;

/// How many arguments one [`ArgSpec`] consumes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Repeat {
    /// Exactly one argument. The default.
    #[default]
    One,
    /// Zero or one argument.
    Optional,
    /// Between `min` and `max` arguments, inclusive.
    Between {
        /// Fewest arguments accepted.
        min: usize,
        /// Most arguments accepted. Clamped to [`MAX_REPEAT`] at compile time.
        max: usize,
    },
}

impl Repeat {
    /// Returns the inclusive `(min, max)` bounds, clamped to [`MAX_REPEAT`].
    fn bounds(self) -> (usize, usize) {
        match self {
            Self::One => (1, 1),
            Self::Optional => (0, 1),
            Self::Between { min, max } => {
                let max = max.min(MAX_REPEAT);
                (min.min(max), max)
            }
        }
    }
}

/// A named validator for a class of identifier.
///
/// Each variant exists to make a specific escape unreachable rather than to be
/// tidy. The package-name kinds, for instance, all reject `/`, `=`, and `:`,
/// which is what makes `apt-get install ./local.deb`, a version-pinned
/// downgrade, and a URL install unrepresentable in a rule that only meant to
/// name a package from a configured repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum NameKind {
    /// A Debian binary package name.
    DebName,
    /// An RPM package name.
    RpmName,
    /// An Arch package name.
    ArchName,
    /// An Alpine package name.
    ApkName,
    /// A systemd unit name with an explicit unit suffix.
    UnitName,
    /// A DNS hostname label sequence.
    Hostname,
    /// A dotted `sysctl` key.
    SysctlKey,
}

impl NameKind {
    /// Validates `bytes` against this identifier class.
    fn accepts(self, bytes: &[u8]) -> bool {
        if bytes.is_empty() || bytes.len() > 255 {
            return false;
        }
        // Universally rejected, for every kind: a leading `-` (which every
        // getopt parser reads as a flag), a path separator, an `=` (version
        // pins and option assignment), and a `:` (URLs, architecture
        // qualifiers). Rejecting these once here is what makes the per-kind
        // rules below simple enough to audit.
        if bytes.first() == Some(&b'-')
            || bytes.iter().any(|b| matches!(b, b'/' | b'=' | b':'))
            || bytes.contains_str("..")
        {
            return false;
        }

        match self {
            Self::DebName | Self::ApkName => bytes.iter().all(|b| {
                b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'+' | b'.' | b'-' | b'_')
            }),
            Self::RpmName | Self::ArchName => bytes.iter().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-' | b'_' | b'@')
            }),
            Self::UnitName => Self::accepts_unit(bytes),
            Self::Hostname => {
                bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
                    && bytes.last() != Some(&b'-')
            }
            Self::SysctlKey => {
                bytes.iter().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_')
                }) && !bytes.starts_with(b".")
                    && !bytes.ends_with(b".")
            }
        }
    }

    /// A unit name must carry an explicit, known suffix.
    ///
    /// Requiring the suffix is not cosmetic: `systemctl restart foo` will
    /// happily resolve `foo` to `foo.service`, so a rule matching a
    /// suffix-less name matches more units than it appears to.
    fn accepts_unit(bytes: &[u8]) -> bool {
        const SUFFIXES: [&[u8]; 6] = [
            b".service",
            b".socket",
            b".timer",
            b".target",
            b".path",
            b".mount",
        ];
        if !SUFFIXES.iter().any(|s| bytes.ends_with(s)) {
            return false;
        }
        bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'@' | b'\\'))
    }
}

/// A pattern anchored and size-bounded at construction time.
///
/// The anchors are injected here rather than written by the rule author,
/// because an unanchored pattern is a substring match: `systemctl` written
/// without anchors also matches `evil-systemctl-wrapper`.
#[derive(Clone)]
pub struct AnchoredPattern {
    source: String,
    compiled: regex::bytes::Regex,
}

impl AnchoredPattern {
    /// Compiles `source` as a fully-anchored, size-bounded byte pattern.
    ///
    /// # Errors
    ///
    /// Returns [`MatchError::Pattern`] when the expression is invalid, exceeds
    /// [`PATTERN_SIZE_LIMIT`], or already carries its own anchors (which would
    /// otherwise nest confusingly with the injected ones).
    pub fn new(source: &str) -> Result<Self, MatchError> {
        if source.starts_with('^') || source.ends_with('$') {
            return Err(MatchError::Pattern {
                pattern: source.to_owned(),
                reason: "patterns are anchored automatically; remove the explicit ^ or $".into(),
            });
        }
        let compiled = regex::bytes::RegexBuilder::new(&format!("^(?:{source})$"))
            .size_limit(PATTERN_SIZE_LIMIT)
            .dfa_size_limit(PATTERN_SIZE_LIMIT)
            .unicode(false)
            .build()
            .map_err(|e| MatchError::Pattern {
                pattern: source.to_owned(),
                reason: e.to_string(),
            })?;
        Ok(Self {
            source: source.to_owned(),
            compiled,
        })
    }

    /// Returns the pattern as written by the rule author, without anchors.
    pub fn source(&self) -> &str {
        &self.source
    }

    fn accepts(&self, bytes: &[u8]) -> bool {
        self.compiled.is_match(bytes)
    }
}

impl fmt::Debug for AnchoredPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AnchoredPattern({:?})", self.source)
    }
}

impl PartialEq for AnchoredPattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Eq for AnchoredPattern {}

impl Serialize for AnchoredPattern {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.source)
    }
}

impl<'de> Deserialize<'de> for AnchoredPattern {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// What a single argument position accepts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Matcher {
    /// Exactly these bytes.
    Literal(String),
    /// Exactly one of these byte strings.
    OneOf(Vec<String>),
    /// A base-10 integer within an inclusive range.
    IntRange {
        /// Lowest accepted value.
        lo: i64,
        /// Highest accepted value.
        hi: i64,
    },
    /// An absolute path lexically beneath `prefix`.
    ///
    /// This is a **syntactic pre-filter, not a security boundary.** It cannot
    /// see symlinks, bind mounts, or hardlinks, because this crate performs no
    /// I/O. Actual containment is enforced in `aido-sys` with
    /// `openat2(RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`
    /// from a pinned directory file descriptor, and a match here is never
    /// sufficient authority to open anything.
    PathUnder {
        /// Absolute directory the argument must sit beneath.
        prefix: String,
    },
    /// A named identifier class.
    Name(NameKind),
    /// An anchored, size-bounded pattern.
    Pattern(AnchoredPattern),
}

impl Matcher {
    /// Returns `true` when `arg` satisfies this matcher.
    pub fn accepts(&self, arg: &Arg) -> bool {
        let bytes = arg.as_bytes();
        match self {
            Self::Literal(want) => bytes == want.as_bytes(),
            Self::OneOf(options) => options.iter().any(|o| bytes == o.as_bytes()),
            Self::IntRange { lo, hi } => parse_i64(bytes).is_some_and(|v| v >= *lo && v <= *hi),
            Self::PathUnder { prefix } => path_is_under(bytes, prefix.as_bytes()),
            Self::Name(kind) => kind.accepts(bytes),
            Self::Pattern(p) => p.accepts(bytes),
        }
    }

    /// A short human-readable description, used in `aido explain` traces.
    pub fn describe(&self) -> String {
        match self {
            Self::Literal(want) => format!("literal {want:?}"),
            Self::OneOf(options) => format!("one of {options:?}"),
            Self::IntRange { lo, hi } => format!("integer in {lo}..={hi}"),
            Self::PathUnder { prefix } => format!("path under {prefix:?}"),
            Self::Name(kind) => format!("{kind:?}"),
            Self::Pattern(p) => format!("pattern {:?}", p.source()),
        }
    }
}

/// Parses a strict base-10 integer.
///
/// Deliberately stricter than [`str::parse`]: no leading `+`, no surrounding
/// whitespace, no underscores. Anything the target program would parse
/// differently than this must not match, or the value the matcher checked is
/// not the value the program uses.
fn parse_i64(bytes: &[u8]) -> Option<i64> {
    let (negative, digits) = match bytes.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, bytes),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    // Reject a leading zero on a multi-digit number: "010" is octal to some
    // parsers and decimal to others, and a matcher must not have to guess.
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return None;
    }
    let mut value: i64 = 0;
    for d in digits {
        value = value.checked_mul(10)?;
        value = value.checked_add(i64::from(d.saturating_sub(b'0')))?;
    }
    if negative {
        value.checked_neg()
    } else {
        Some(value)
    }
}

/// Lexical containment test for an absolute path.
///
/// Rejects any relative path, any path containing a `..` component, and any
/// path containing an embedded NUL. Requires the candidate to equal the prefix
/// or to continue with a `/`, so `/etc/nginx-evil` is not "under" `/etc/nginx`.
fn path_is_under(candidate: &[u8], prefix: &[u8]) -> bool {
    if !candidate.starts_with(b"/") || !prefix.starts_with(b"/") || candidate.contains(&0) {
        return false;
    }
    if candidate.split_str("/").any(|c| c == b"..") {
        return false;
    }
    let prefix = prefix.strip_suffix(b"/").unwrap_or(prefix);
    if candidate == prefix {
        return true;
    }
    candidate
        .strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with(b"/") && rest.len() > 1)
}

/// One position (or run of positions) in a rule's argument list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgSpec {
    /// A name for this position, used in traces and audit records.
    pub name: String,
    /// What the position accepts.
    pub matcher: Matcher,
    /// How many arguments the position consumes.
    #[serde(default)]
    pub repeat: Repeat,
}

impl ArgSpec {
    /// Builds a spec consuming exactly one argument.
    pub fn one(name: impl Into<String>, matcher: Matcher) -> Self {
        Self {
            name: name.into(),
            matcher,
            repeat: Repeat::One,
        }
    }

    /// Builds a spec with an explicit repeat.
    pub fn repeated(name: impl Into<String>, matcher: Matcher, repeat: Repeat) -> Self {
        Self {
            name: name.into(),
            matcher,
            repeat,
        }
    }
}

/// Why a match failed, or why a rule could not be compiled.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MatchError {
    /// The argv did not fit the spec list.
    #[error("argv does not match the rule's argument list: {reason}")]
    Shape {
        /// A human-readable account of the mismatch.
        reason: String,
    },
    /// A pattern could not be compiled.
    #[error("invalid pattern {pattern:?}: {reason}")]
    Pattern {
        /// The pattern as written.
        pattern: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The argv exceeded the matcher's work bound.
    #[error("argv has {len} arguments, over the limit of {limit}")]
    TooManyArgs {
        /// How many arguments were supplied.
        len: usize,
        /// The limit.
        limit: usize,
    },
}

/// One argument position bound to the value that satisfied it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Binding {
    /// The [`ArgSpec::name`] that matched.
    pub name: String,
    /// The values it consumed, rendered for display.
    pub values: Vec<String>,
}

/// Total argv length accepted by the matcher, independent of the spec list.
///
/// A bound on the matcher's own work, so a pathological argv cannot be used to
/// stall the broker.
pub const MAX_ARGV_LEN: usize = 512;

/// Matches `argv` against `specs`, returning the bound positions.
///
/// # Algorithm
///
/// Reachability dynamic programming over `(spec index, argv index)`. This is
/// deliberately not a backtracking matcher: DP is `O(specs × argv × MAX_REPEAT)`
/// with no input that can make it blow up, whereas a backtracking matcher over
/// variadic positions has pathological cases an attacker chooses the input for.
///
/// # Errors
///
/// Returns [`MatchError::TooManyArgs`] when `argv` is longer than
/// [`MAX_ARGV_LEN`], and [`MatchError::Shape`] when no assignment of arguments
/// to specs consumes the argv exactly.
pub fn match_argv(specs: &[ArgSpec], argv: &Argv) -> Result<Vec<Binding>, MatchError> {
    let supplied = argv.as_slice();
    if supplied.len() > MAX_ARGV_LEN {
        return Err(MatchError::TooManyArgs {
            len: supplied.len(),
            limit: MAX_ARGV_LEN,
        });
    }
    let n_args = supplied.len();

    // `levels[i]` is every argv offset the first `i` specs can consume up to.
    // Sets rather than a flat table so there is no index arithmetic and no
    // "this bound cannot be exceeded" branch to leave untested.
    let mut levels: Vec<BTreeSet<usize>> = Vec::with_capacity(specs.len().saturating_add(1));
    levels.push(BTreeSet::from([0usize]));

    for spec in specs {
        let (min, max) = spec.repeat.bounds();
        let mut next: BTreeSet<usize> = BTreeSet::new();
        for start in levels.last().into_iter().flatten().copied() {
            for k in min..=max {
                let end = start.saturating_add(k);
                if end > n_args {
                    break;
                }
                if !run_matches(spec, supplied, start, end) {
                    break;
                }
                next.insert(end);
            }
        }
        levels.push(next);
    }

    let accepted = levels.last().is_some_and(|set| set.contains(&n_args));
    if !accepted {
        return Err(MatchError::Shape {
            reason: describe_failure(specs, supplied),
        });
    }

    Ok(backtrack(specs, supplied, &levels))
}

/// Whether every argument in `start..end` satisfies `spec`'s matcher.
fn run_matches(spec: &ArgSpec, supplied: &[Arg], start: usize, end: usize) -> bool {
    supplied
        .get(start..end)
        .is_some_and(|run| run.iter().all(|a| spec.matcher.accepts(a)))
}

/// Reconstructs one accepting assignment from the reachability levels.
///
/// Walks backwards, preferring the longest run at each step so a variadic
/// position reports every value it consumed. Any accepting path yields the same
/// verdict; this one is chosen for a legible trace.
fn backtrack(specs: &[ArgSpec], supplied: &[Arg], levels: &[BTreeSet<usize>]) -> Vec<Binding> {
    let mut bindings: Vec<Binding> = Vec::with_capacity(specs.len());
    let mut end = supplied.len();

    for (i, spec) in specs.iter().enumerate().rev() {
        let (min, max) = spec.repeat.bounds();
        let prior = levels.get(i);
        let mut chosen = min;
        for k in (min..=max).rev() {
            if k > end {
                continue;
            }
            let start = end.saturating_sub(k);
            if prior.is_some_and(|set| set.contains(&start))
                && run_matches(spec, supplied, start, end)
            {
                chosen = k;
                break;
            }
        }
        let start = end.saturating_sub(chosen);
        let values = supplied
            .get(start..end)
            .unwrap_or_default()
            .iter()
            .map(Arg::display)
            .collect();
        bindings.push(Binding {
            name: spec.name.clone(),
            values,
        });
        end = start;
    }

    bindings.reverse();
    bindings
}

/// Builds the operator-facing explanation for a failed match.
fn describe_failure(specs: &[ArgSpec], args: &[Arg]) -> String {
    if specs.is_empty() {
        return format!(
            "rule permits zero arguments, got {} ({})",
            args.len(),
            args.iter().map(Arg::display).collect::<Vec<_>>().join(" ")
        );
    }
    // Report the first position whose own matcher rejects the argument sitting
    // at its earliest possible offset. That is the position an operator should
    // look at first, even though the DP considered every alignment.
    let mut offset = 0usize;
    for spec in specs {
        let (min, _) = spec.repeat.bounds();
        match args.get(offset) {
            Some(arg) if !spec.matcher.accepts(arg) && min > 0 => {
                return format!(
                    "argument {} ({:?}) does not satisfy {} ({})",
                    offset,
                    arg.display(),
                    spec.name,
                    spec.matcher.describe()
                );
            }
            None if min > 0 => {
                return format!(
                    "argv ends before required position {} ({})",
                    spec.name,
                    spec.matcher.describe()
                );
            }
            _ => {}
        }
        offset = offset.saturating_add(min);
    }
    format!(
        "argv length {} cannot be split across {} argument positions",
        args.len(),
        specs.len()
    )
}

#[cfg(test)]
mod tests {
    // Tests are allowed to panic loudly: a failed `unwrap` here is a reported
    // test failure, whereas in the crate proper it would be undefined policy.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    fn lit(s: &str) -> Matcher {
        Matcher::Literal(s.to_owned())
    }

    #[test]
    fn repeat_default_is_exactly_one() {
        assert_eq!(Repeat::default(), Repeat::One);
        assert_eq!(Repeat::One.bounds(), (1, 1));
        assert_eq!(Repeat::Optional.bounds(), (0, 1));
        assert_eq!(Repeat::Between { min: 1, max: 3 }.bounds(), (1, 3));
    }

    #[test]
    fn repeat_clamps_max_to_the_work_bound() {
        assert_eq!(
            Repeat::Between {
                min: 0,
                max: 10_000
            }
            .bounds(),
            (0, MAX_REPEAT)
        );
    }

    #[test]
    fn repeat_clamps_min_to_max_rather_than_becoming_unsatisfiable() {
        assert_eq!(Repeat::Between { min: 9, max: 2 }.bounds(), (2, 2));
    }

    #[test]
    fn literal_matches_byte_exactly() {
        assert!(lit("install").accepts(&Arg::from("install")));
        assert!(!lit("install").accepts(&Arg::from("Install")));
        assert!(!lit("install").accepts(&Arg::from("install ")));
    }

    #[test]
    fn one_of_matches_any_option_and_nothing_else() {
        let m = Matcher::OneOf(vec!["start".into(), "stop".into()]);
        assert!(m.accepts(&Arg::from("start")));
        assert!(m.accepts(&Arg::from("stop")));
        assert!(!m.accepts(&Arg::from("mask")));
    }

    #[test]
    fn int_range_is_inclusive() {
        let m = Matcher::IntRange { lo: 1, hi: 10 };
        assert!(m.accepts(&Arg::from("1")));
        assert!(m.accepts(&Arg::from("10")));
        assert!(!m.accepts(&Arg::from("0")));
        assert!(!m.accepts(&Arg::from("11")));
    }

    #[test]
    fn int_range_accepts_negative_values_in_range() {
        let m = Matcher::IntRange { lo: -3, hi: 3 };
        assert!(m.accepts(&Arg::from("-3")));
        assert!(!m.accepts(&Arg::from("-4")));
    }

    #[test]
    fn int_parsing_rejects_forms_a_target_program_would_read_differently() {
        // Each of these is accepted by some parser somewhere. If the matcher
        // checked a different value than the program uses, the range is a lie.
        for bad in [
            " 1", "1 ", "+1", "0x10", "1_0", "010", "", "-", "--1", "1.0",
        ] {
            assert!(parse_i64(bad.as_bytes()).is_none(), "accepted {bad:?}");
        }
        assert_eq!(parse_i64(b"0"), Some(0));
        assert_eq!(parse_i64(b"-0"), Some(0));
        assert_eq!(parse_i64(b"9223372036854775807"), Some(i64::MAX));
    }

    #[test]
    fn int_parsing_rejects_overflow_instead_of_wrapping() {
        assert!(parse_i64(b"9223372036854775808").is_none());
        assert!(parse_i64(b"99999999999999999999999").is_none());
    }

    #[test]
    fn path_under_requires_a_real_directory_boundary() {
        let m = Matcher::PathUnder {
            prefix: "/etc/nginx".into(),
        };
        assert!(m.accepts(&Arg::from("/etc/nginx")));
        assert!(m.accepts(&Arg::from("/etc/nginx/nginx.conf")));
        // The classic prefix-match bug: a sibling directory whose name starts
        // with the prefix.
        assert!(!m.accepts(&Arg::from("/etc/nginx-evil/x")));
        assert!(!m.accepts(&Arg::from("/etc/nginxevil")));
    }

    #[test]
    fn path_under_rejects_traversal_relative_and_nul() {
        let m = Matcher::PathUnder {
            prefix: "/etc/nginx".into(),
        };
        assert!(!m.accepts(&Arg::from("/etc/nginx/../../shadow")));
        assert!(!m.accepts(&Arg::from("etc/nginx/x")));
        assert!(!m.accepts(&Arg::new(b"/etc/nginx/a\0b".to_vec())));
    }

    #[test]
    fn path_under_tolerates_a_trailing_slash_on_the_prefix() {
        let m = Matcher::PathUnder {
            prefix: "/etc/nginx/".into(),
        };
        assert!(m.accepts(&Arg::from("/etc/nginx/conf.d/a.conf")));
        assert!(!m.accepts(&Arg::from("/etc/nginx-evil")));
    }

    #[test]
    fn path_under_rejects_a_relative_prefix_rather_than_guessing() {
        assert!(!path_is_under(b"/etc/x", b"etc"));
    }

    #[test]
    fn path_under_rejects_a_bare_trailing_slash_as_a_child() {
        // "/etc/nginx/" is the directory itself, and the empty component after
        // the slash names nothing.
        assert!(!path_is_under(b"/etc/nginx/", b"/etc/nginx"));
    }

    #[test]
    fn deb_names_reject_every_local_and_pinned_install_form() {
        let m = Matcher::Name(NameKind::DebName);
        assert!(m.accepts(&Arg::from("ripgrep")));
        assert!(m.accepts(&Arg::from("lib32z1-dev")));
        for bad in [
            "./local.deb",
            "/tmp/x.deb",
            "ripgrep=1.0",
            "http://evil/x.deb",
            "-y",
            "arch:amd64",
            "..",
            "UPPER",
            "",
        ] {
            assert!(!m.accepts(&Arg::from(bad)), "accepted {bad:?}");
        }
    }

    #[test]
    fn rpm_and_arch_names_allow_mixed_case_but_not_paths() {
        for kind in [NameKind::RpmName, NameKind::ArchName] {
            let m = Matcher::Name(kind);
            assert!(m.accepts(&Arg::from("NetworkManager")));
            // The punctuation these ecosystems really use.
            assert!(m.accepts(&Arg::from("gcc-c++")));
            assert!(m.accepts(&Arg::from("python3.11-devel")));
            assert!(m.accepts(&Arg::from("kernel_devel")));
            assert!(m.accepts(&Arg::from("openssl@1.1")));
            assert!(!m.accepts(&Arg::from("/tmp/x.rpm")));
            assert!(!m.accepts(&Arg::from("pkg name")));
        }
    }

    #[test]
    fn deb_and_apk_names_allow_their_punctuation_but_not_uppercase() {
        for kind in [NameKind::DebName, NameKind::ApkName] {
            let m = Matcher::Name(kind);
            assert!(m.accepts(&Arg::from("libstdc++6")));
            assert!(m.accepts(&Arg::from("python3.11-dev")));
            assert!(m.accepts(&Arg::from("linux_headers")));
            assert!(!m.accepts(&Arg::from("libStdc++6")));
            assert!(!m.accepts(&Arg::from("pkg name")));
        }
    }

    #[test]
    fn apk_names_behave_like_deb_names() {
        let m = Matcher::Name(NameKind::ApkName);
        assert!(m.accepts(&Arg::from("busybox-extras")));
        assert!(!m.accepts(&Arg::from("Busybox")));
    }

    #[test]
    fn unit_names_require_an_explicit_suffix() {
        let m = Matcher::Name(NameKind::UnitName);
        assert!(m.accepts(&Arg::from("nginx.service")));
        assert!(m.accepts(&Arg::from("getty@tty1.service")));
        assert!(m.accepts(&Arg::from("docker.socket")));
        // Without a suffix, systemctl would resolve this to nginx.service, so
        // the rule would match more than it appears to.
        assert!(!m.accepts(&Arg::from("nginx")));
        assert!(!m.accepts(&Arg::from("nginx.mount/../x.service")));
        assert!(!m.accepts(&Arg::from("evil.socket;rm.service")));
    }

    #[test]
    fn unit_names_accept_every_supported_suffix() {
        let m = Matcher::Name(NameKind::UnitName);
        for unit in [
            "a.service",
            "a.socket",
            "a.timer",
            "a.target",
            "a.path",
            "a.mount",
        ] {
            assert!(m.accepts(&Arg::from(unit)), "rejected {unit}");
        }
        assert!(!m.accepts(&Arg::from("a.swap")));
    }

    #[test]
    fn hostnames_reject_paths_and_trailing_hyphens() {
        let m = Matcher::Name(NameKind::Hostname);
        assert!(m.accepts(&Arg::from("api.internal")));
        assert!(!m.accepts(&Arg::from("api-")));
        assert!(!m.accepts(&Arg::from("api/internal")));
        assert!(!m.accepts(&Arg::from("api_internal")));
    }

    #[test]
    fn sysctl_keys_are_dotted_lowercase() {
        let m = Matcher::Name(NameKind::SysctlKey);
        assert!(m.accepts(&Arg::from("vm.max_map_count")));
        assert!(!m.accepts(&Arg::from("vm/max_map_count")));
        assert!(!m.accepts(&Arg::from(".vm")));
        assert!(!m.accepts(&Arg::from("vm.")));
        assert!(!m.accepts(&Arg::from("VM.x")));
    }

    #[test]
    fn names_reject_oversized_input() {
        let m = Matcher::Name(NameKind::DebName);
        assert!(!m.accepts(&Arg::new(vec![b'a'; 256])));
        assert!(m.accepts(&Arg::new(vec![b'a'; 255])));
    }

    #[test]
    fn patterns_are_anchored_so_they_cannot_substring_match() {
        let p = AnchoredPattern::new("systemctl").unwrap();
        assert!(p.accepts(b"systemctl"));
        assert!(!p.accepts(b"evil-systemctl-wrapper"));
        assert_eq!(p.source(), "systemctl");
    }

    #[test]
    fn patterns_reject_author_supplied_anchors() {
        for bad in ["^systemctl", "systemctl$"] {
            let err = AnchoredPattern::new(bad).unwrap_err();
            assert!(err.to_string().contains("anchored automatically"), "{err}");
        }
    }

    #[test]
    fn patterns_reject_invalid_expressions() {
        let err = AnchoredPattern::new("a(").unwrap_err();
        assert!(err.to_string().contains("invalid pattern"), "{err}");
    }

    #[test]
    fn patterns_reject_expressions_over_the_size_limit() {
        // A large bounded repetition compiles to a program bigger than the
        // limit, which is exactly what the limit exists to refuse.
        let huge = "(?:abcdefghij){1000}".repeat(40);
        let err = AnchoredPattern::new(&huge).unwrap_err();
        assert!(err.to_string().contains("invalid pattern"), "{err}");
    }

    #[test]
    fn pattern_equality_and_debug_use_the_source() {
        let a = AnchoredPattern::new("a+").unwrap();
        let b = AnchoredPattern::new("a+").unwrap();
        let c = AnchoredPattern::new("b+").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(format!("{a:?}"), "AnchoredPattern(\"a+\")");
    }

    #[test]
    fn matcher_descriptions_name_the_position_type() {
        assert_eq!(lit("x").describe(), "literal \"x\"");
        assert_eq!(
            Matcher::OneOf(vec!["a".into()]).describe(),
            "one of [\"a\"]"
        );
        assert_eq!(
            Matcher::IntRange { lo: 1, hi: 2 }.describe(),
            "integer in 1..=2"
        );
        assert_eq!(
            Matcher::PathUnder {
                prefix: "/o".into()
            }
            .describe(),
            "path under \"/o\""
        );
        assert_eq!(Matcher::Name(NameKind::DebName).describe(), "DebName");
        assert_eq!(
            Matcher::Pattern(AnchoredPattern::new("a").unwrap()).describe(),
            "pattern \"a\""
        );
    }

    #[test]
    fn empty_spec_list_permits_exactly_zero_arguments() {
        // The inverted doas default: no spec list means no arguments, not any.
        assert_eq!(match_argv(&[], &Argv::default()), Ok(Vec::new()));
        let err = match_argv(&[], &Argv::new(["anything"])).unwrap_err();
        assert!(err.to_string().contains("permits zero arguments"));
    }

    #[test]
    fn fixed_spec_list_binds_each_position() {
        let specs = [
            ArgSpec::one("verb", Matcher::OneOf(vec!["restart".into()])),
            ArgSpec::one("unit", Matcher::Name(NameKind::UnitName)),
        ];
        let bindings = match_argv(&specs, &Argv::new(["restart", "nginx.service"])).unwrap();
        assert_eq!(
            bindings,
            vec![
                Binding {
                    name: "verb".into(),
                    values: vec!["restart".into()]
                },
                Binding {
                    name: "unit".into(),
                    values: vec!["nginx.service".into()]
                },
            ]
        );
    }

    #[test]
    fn variadic_spec_consumes_a_run_within_its_bounds() {
        let specs = [ArgSpec::repeated(
            "pkg",
            Matcher::Name(NameKind::DebName),
            Repeat::Between { min: 1, max: 3 },
        )];
        let bindings = match_argv(&specs, &Argv::new(["a", "b", "c"])).unwrap();
        assert_eq!(bindings.first().map(|b| b.values.len()), Some(3));
        assert!(match_argv(&specs, &Argv::new(["a", "b", "c", "d"])).is_err());
        assert!(match_argv(&specs, &Argv::default()).is_err());
    }

    #[test]
    fn optional_spec_may_be_absent_or_present() {
        let specs = [
            ArgSpec::one("verb", lit("install")),
            ArgSpec::repeated("flag", lit("-y"), Repeat::Optional),
        ];
        let without = match_argv(&specs, &Argv::new(["install"])).unwrap();
        assert_eq!(without.get(1).map(|b| b.values.len()), Some(0));
        let with = match_argv(&specs, &Argv::new(["install", "-y"])).unwrap();
        assert_eq!(with.get(1).map(|b| b.values.len()), Some(1));
    }

    #[test]
    fn matcher_finds_a_split_that_greedy_scanning_would_miss() {
        // Two adjacent variadic positions over the same alphabet: a greedy
        // left-to-right matcher lets the first consume everything and then
        // fails. The DP finds the split.
        let specs = [
            ArgSpec::repeated(
                "first",
                Matcher::Name(NameKind::DebName),
                Repeat::Between { min: 1, max: 3 },
            ),
            ArgSpec::one("last", lit("zzz")),
        ];
        let bindings = match_argv(&specs, &Argv::new(["a", "b", "zzz"])).unwrap();
        assert_eq!(
            bindings.first().map(|b| b.values.clone()),
            Some(vec!["a".to_owned(), "b".to_owned()])
        );
        assert_eq!(
            bindings.get(1).map(|b| b.values.clone()),
            Some(vec!["zzz".to_owned()])
        );
    }

    #[test]
    fn matcher_reports_the_position_an_operator_should_look_at() {
        let specs = [
            ArgSpec::one("verb", Matcher::OneOf(vec!["restart".into()])),
            ArgSpec::one("unit", Matcher::Name(NameKind::UnitName)),
        ];
        let err = match_argv(&specs, &Argv::new(["restart", "nginx"])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("argument 1"), "{msg}");
        assert!(msg.contains("unit"), "{msg}");
    }

    #[test]
    fn matcher_reports_a_truncated_argv() {
        let specs = [
            ArgSpec::one("verb", lit("restart")),
            ArgSpec::one("unit", Matcher::Name(NameKind::UnitName)),
        ];
        let err = match_argv(&specs, &Argv::new(["restart"])).unwrap_err();
        assert!(err.to_string().contains("ends before required position"));
    }

    #[test]
    fn matcher_reports_an_unsplittable_length() {
        // Every individual position is satisfiable at its earliest offset, so
        // the failure is about total length rather than one argument.
        let specs = [ArgSpec::repeated(
            "pkg",
            Matcher::Name(NameKind::DebName),
            Repeat::Optional,
        )];
        let err = match_argv(&specs, &Argv::new(["a", "b"])).unwrap_err();
        assert!(err.to_string().contains("cannot be split"), "{err}");
    }

    #[test]
    fn matcher_refuses_an_argv_over_the_work_bound() {
        let specs = [ArgSpec::repeated(
            "pkg",
            Matcher::Name(NameKind::DebName),
            Repeat::Between { min: 0, max: 64 },
        )];
        let argv = Argv::new(vec!["a"; MAX_ARGV_LEN.saturating_add(1)]);
        assert_eq!(
            match_argv(&specs, &argv),
            Err(MatchError::TooManyArgs {
                len: MAX_ARGV_LEN.saturating_add(1),
                limit: MAX_ARGV_LEN,
            })
        );
        assert!(
            match_argv(&specs, &argv)
                .unwrap_err()
                .to_string()
                .contains("over the limit")
        );
    }

    #[test]
    fn arg_spec_constructors_agree() {
        let a = ArgSpec::one("x", lit("v"));
        let b = ArgSpec::repeated("x", lit("v"), Repeat::One);
        assert_eq!(a, b);
    }

    #[test]
    fn specs_round_trip_through_toml() {
        let spec: ArgSpec = toml::from_str(
            r#"
            name = "unit"
            matcher = { name = "unit-name" }
            repeat = { between = { min = 1, max = 4 } }
            "#,
        )
        .unwrap();
        assert_eq!(spec.name, "unit");
        assert_eq!(spec.matcher, Matcher::Name(NameKind::UnitName));
        assert_eq!(spec.repeat, Repeat::Between { min: 1, max: 4 });
    }

    #[test]
    fn spec_repeat_defaults_when_omitted() {
        let spec: ArgSpec = toml::from_str(
            r#"
            name = "verb"
            matcher = { literal = "restart" }
            "#,
        )
        .unwrap();
        assert_eq!(spec.repeat, Repeat::One);
    }

    #[test]
    fn unknown_spec_key_is_a_hard_error() {
        // Silently ignoring an unrecognised key in a root-owned rule file is
        // the footgun this project exists to avoid.
        let err = toml::from_str::<ArgSpec>(
            r#"
            name = "verb"
            matcher = { literal = "restart" }
            allow_anything = true
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("allow_anything"), "{err}");
    }

    #[test]
    fn patterns_round_trip_and_reject_bad_input_during_deserialization() {
        let spec: ArgSpec = toml::from_str(
            r#"
            name = "prop"
            matcher = { pattern = "[A-Za-z]+" }
            "#,
        )
        .unwrap();
        assert!(spec.matcher.accepts(&Arg::from("ActiveState")));
        let json = serde_json::to_string(&spec.matcher).unwrap();
        assert!(json.contains("[A-Za-z]+"), "{json}");

        let err = toml::from_str::<ArgSpec>(
            r#"
            name = "prop"
            matcher = { pattern = "^bad" }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("anchored automatically"), "{err}");
    }

    #[test]
    fn a_pattern_that_is_not_a_string_is_rejected() {
        // Fail closed on a shape error too, not just a bad expression.
        let err = toml::from_str::<ArgSpec>(
            r#"
            name = "prop"
            matcher = { pattern = 5 }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("string"), "{err}");
    }

    #[test]
    fn binding_serializes_for_audit_records() {
        let b = Binding {
            name: "pkg".into(),
            values: vec!["ripgrep".into()],
        };
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, r#"{"name":"pkg","values":["ripgrep"]}"#);
        assert!(format!("{b:?}").contains("pkg"));
    }
}
