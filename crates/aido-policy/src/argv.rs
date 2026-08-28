//! Byte-exact argument vectors and their canonical form.
//!
//! Linux `argv` is a list of arbitrary NUL-terminated byte strings, not UTF-8.
//! A matcher that compares `String`s has already lost: the lossy conversion
//! maps invalid sequences onto `U+FFFD`, so two distinct argvs can compare
//! equal and a deny pattern can be stepped around with an invalid byte. Every
//! comparison in this crate is therefore on `[u8]`.

use core::fmt;

use bstr::ByteSlice;
use serde::{Deserialize, Serialize};

/// A single argument: an arbitrary byte string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Arg(Vec<u8>);

impl Arg {
    /// Wraps raw bytes as an argument.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrows the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the number of bytes in the argument.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the argument is the empty string.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Renders the argument for display, escaping non-printable bytes.
    ///
    /// This is a one-way rendering for humans and audit records. There is
    /// deliberately no inverse: re-parsing a rendered command string back into
    /// an argv is how injection is reintroduced.
    pub fn display(&self) -> String {
        self.0.as_bstr().to_string()
    }
}

impl From<&str> for Arg {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl fmt::Debug for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Arg({:?})", self.0.as_bstr())
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_bstr())
    }
}

/// An argument vector, excluding `argv[0]`.
///
/// `argv[0]` is deliberately not part of the matched vector: it is
/// caller-controlled and carries no authority. The executable a rule authorises
/// is named by the rule, resolved by `aido-sys`, and executed from a validated
/// file descriptor.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Argv(Vec<Arg>);

impl Argv {
    /// Builds an argument vector from anything convertible into [`Arg`]s.
    pub fn new<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<Arg>,
    {
        Self(args.into_iter().map(Into::into).collect())
    }

    /// Borrows the arguments as a slice.
    pub fn as_slice(&self) -> &[Arg] {
        &self.0
    }

    /// Returns the number of arguments.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when there are no arguments.
    ///
    /// Note that "no arguments" is a meaningful, matchable state: a rule whose
    /// spec list is empty permits *zero* arguments, never "any arguments".
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the argument at `index`, or `None`.
    pub fn get(&self, index: usize) -> Option<&Arg> {
        self.0.get(index)
    }

    /// Renders the whole vector for display and audit records.
    pub fn display(&self) -> String {
        self.0
            .iter()
            .map(Arg::display)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Produces the canonical form used for every comparison and for the
    /// deny-list.
    ///
    /// Canonicalization performs exactly one normalization: a trailing `--`
    /// with nothing after it is dropped, because it separates nothing. Only the
    /// *separator* is eligible — in `-- --` the first `--` is the separator and
    /// the second is a literal operand the program receives, so it stays.
    ///
    /// It deliberately does **not** unquote, unescape, expand, resolve, split,
    /// or interpret anything. Every such transformation is a place where the
    /// matcher's view of the argv can diverge from the kernel's, which is
    /// exactly the divergence CVE-2021-3156 exploited.
    ///
    /// # Why `--key=value` is not split
    ///
    /// An earlier version split `--key=value` into two arguments, so that a
    /// deny rule on a flag could not be evaded by joining its value with `=`.
    /// Fuzzing killed it: the *value* of a split can itself look like a long
    /// flag, so `---=---=-_` split differently on each pass and the function had
    /// no fixed point. Splitting recursively fixes idempotence and makes the
    /// problem worse — the matcher would see three arguments where the program
    /// sees one, which is the divergence this function exists to prevent.
    ///
    /// So the argv a rule matches is byte-for-byte the argv the kernel receives.
    /// Two consequences, both deliberate:
    ///
    /// * A rule that accepts both spellings must say so, with an enum or an
    ///   anchored pattern. It cannot rely on the engine to unify them.
    /// * The deny-list matches a joined flag by prefix as well as by exact
    ///   token, because there is no longer a normalization step to lean on.
    #[must_use]
    pub fn canonicalize(&self) -> Self {
        let mut out = self.0.clone();
        // The first bare `--` is the separator; a later one is an operand. Drop
        // the separator only when nothing follows it.
        let separator = out.iter().position(|arg| arg.as_bytes() == b"--");
        if separator.is_some_and(|at| at.saturating_add(1) == out.len()) {
            out.pop();
        }
        Self(out)
    }
}

impl fmt::Debug for Argv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl FromIterator<Arg> for Argv {
    fn from_iter<I: IntoIterator<Item = Arg>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_exposes_raw_bytes_without_lossy_conversion() {
        let invalid = Arg::new(vec![0xff, 0xfe]);
        assert_eq!(invalid.as_bytes(), &[0xff, 0xfe]);
        assert_eq!(invalid.len(), 2);
        assert!(!invalid.is_empty());
        assert!(Arg::new(Vec::new()).is_empty());
    }

    #[test]
    fn distinct_invalid_utf8_args_stay_distinct() {
        // The whole reason this crate compares bytes: both of these become
        // "\u{FFFD}" under a lossy conversion and would compare equal.
        let a = Arg::new(vec![0xff]);
        let b = Arg::new(vec![0xfe]);
        assert_ne!(a, b);
    }

    #[test]
    fn arg_renders_for_display_and_debug() {
        let a = Arg::from("nginx.service");
        assert_eq!(a.display(), "nginx.service");
        assert_eq!(a.to_string(), "nginx.service");
        assert_eq!(format!("{a:?}"), "Arg(\"nginx.service\")");
    }

    #[test]
    fn argv_basics() {
        let v = Argv::new(["install", "ripgrep"]);
        assert_eq!(v.len(), 2);
        assert!(!v.is_empty());
        assert_eq!(v.get(0), Some(&Arg::from("install")));
        assert_eq!(v.get(9), None);
        assert_eq!(v.as_slice().len(), 2);
        assert_eq!(v.display(), "install ripgrep");
        assert_eq!(format!("{v:?}"), "[Arg(\"install\"), Arg(\"ripgrep\")]");
        assert!(Argv::default().is_empty());
    }

    #[test]
    fn argv_collects_from_iterator() {
        let v: Argv = [Arg::from("a"), Arg::from("b")].into_iter().collect();
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn canonicalize_never_splits_a_joined_flag() {
        // Regression, found by fuzzing on the target's first run. Splitting
        // `--key=value` had no fixed point, because the value can itself look
        // like a long flag: `---=---=-_` split differently on every pass.
        // Splitting recursively would fix idempotence and make the real problem
        // worse — the matcher would see more arguments than the program
        // receives, which is the divergence canonicalization exists to prevent.
        for argv in [
            Argv::new(["--signal=SIGHUP", "nginx.service"]),
            Argv::new(["--option=DPkg::Pre-Invoke::=rm -rf /"]),
            Argv::new(["---=---=-_"]),
            Argv::new(["--=payload"]),
        ] {
            assert_eq!(argv.canonicalize(), argv, "{argv:?}");
            assert_eq!(argv.canonicalize().canonicalize(), argv, "{argv:?}");
        }
    }

    #[test]
    fn canonicalize_leaves_short_flags_and_operands_alone() {
        let v = Argv::new(["-u", "nginx.service", "key=value"]);
        assert_eq!(v.canonicalize(), v);
    }

    #[test]
    fn canonicalize_leaves_keyless_long_flag_alone() {
        let v = Argv::new(["--=payload"]);
        assert_eq!(v.canonicalize(), v);
    }

    #[test]
    fn canonicalize_leaves_bare_double_dash_prefix_alone() {
        // "--" with no "=" is not a long flag with a value.
        let v = Argv::new(["--verbose"]);
        assert_eq!(v.canonicalize(), v);
    }

    #[test]
    fn canonicalize_does_not_split_after_a_separator() {
        // After `--`, `--foo=bar` is a package name, not a flag. Splitting it
        // would let a rule matching two operands see three.
        let v = Argv::new(["install", "--", "--weird=name"]);
        assert_eq!(
            v.canonicalize(),
            Argv::new(["install", "--", "--weird=name"])
        );
    }

    #[test]
    fn canonicalize_drops_a_trailing_separator() {
        let v = Argv::new(["install", "--"]);
        assert_eq!(v.canonicalize(), Argv::new(["install"]));
    }

    #[test]
    fn canonicalize_keeps_a_separator_that_separates_something() {
        let v = Argv::new(["install", "--", "ripgrep"]);
        assert_eq!(v.canonicalize(), v);
    }

    #[test]
    fn canonicalize_keeps_a_literal_double_dash_operand() {
        // Regression, found by the idempotence property test. In `-- --` the
        // first `--` is the separator and the second is an operand the program
        // receives. Treating both as separators dropped one argument per pass,
        // so the matcher would have checked a shorter argv than the kernel got.
        let v = Argv::new(["--", "--"]);
        assert_eq!(v.canonicalize(), v);
        assert_eq!(v.canonicalize().canonicalize(), v);

        let three = Argv::new(["--", "--", "--"]);
        assert_eq!(three.canonicalize(), three);
    }

    #[test]
    fn canonicalize_is_idempotent() {
        let v = Argv::new(["--signal=SIGHUP", "--", "a=b", "--"]);
        let once = v.canonicalize();
        assert_eq!(once.canonicalize(), once);
    }

    #[test]
    fn canonicalize_drops_only_the_separator_and_only_when_it_is_last() {
        // A later `--` is an operand, so a trailing operand `--` stays.
        let v = Argv::new(["--", "a", "--"]);
        assert_eq!(v.canonicalize(), v);
    }

    #[test]
    fn canonicalize_of_empty_is_empty() {
        assert_eq!(Argv::default().canonicalize(), Argv::default());
    }
}
