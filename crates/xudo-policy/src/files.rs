//! Rule files to a ruleset, the same way for every reader.
//!
//! Three programs read the root-owned ruleset: the front-end, to explain; the
//! broker, to mint a request; the gate, to decide again. They must agree, byte
//! for byte, on two things:
//!
//! * **Which files are rule files.** Two readers that selected differently
//!   would decide under different policies while claiming the same one.
//! * **Which generation of the policy those files are.** A spool entry carries
//!   the generation it was minted under and the gate refuses one minted under
//!   other rules, so two readers that hashed the same directory differently
//!   would make every request look stale, and two that hashed different
//!   directories alike would let a request outlive the rules it was minted
//!   under.
//!
//! Both answers live here, in the pure crate, and nowhere else. Reading the
//! bytes is the caller's job — by path in the front-end, through verified
//! descriptors in the privileged binaries — and this module never touches a
//! filesystem.

use sha2::{Digest, Sha256};

use crate::deny_rule::{DenyClause, DenyRule};
use crate::harness::HarnessRegistry;
use crate::matcher::{ArgSpec, Matcher, NameKind, Repeat};
use crate::operation::{OpKind, Operation};
use crate::rule::{Action, ConfirmPolicy, RuleSet, RuleSetError, Source, Tier};
use crate::rule_test::RuleTest;

/// The suffix that makes a directory entry a rule file.
pub const RULE_FILE_SUFFIX: &[u8] = b".toml";

/// Separates this hash from every other SHA-256 the project computes, and
/// names the framing version so a later change cannot collide with this one.
const GENERATION_DOMAIN: &[u8] = b"xudo.ruleset.generation.v3\0";

/// The most `[[test]]` tables one ruleset may carry across all its files.
///
/// Every reader parses every test on every load, so the whole is bounded as
/// well as each file (see [`crate::rule::MAX_TESTS_PER_FILE`]).
pub const MAX_TESTS: usize = 4 * crate::rule::MAX_TESTS_PER_FILE;

/// Whether a directory entry is a rule file.
///
/// A name ending in `.toml` with something before it. A file named exactly
/// `.toml` has no name to cite in a decision, so it is not one. Compared on
/// the bytes the kernel returned, never on a lossy rendering of them.
pub fn is_rule_file_name(name: &[u8]) -> bool {
    name.len() > RULE_FILE_SUFFIX.len() && name.ends_with(RULE_FILE_SUFFIX)
}

/// One rule file as it was read: its name within the directory, and its
/// contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleFile {
    /// The file name, as the bytes the kernel returned.
    pub name: Vec<u8>,
    /// The file's contents.
    pub bytes: Vec<u8>,
}

/// One harness registry file, in the same shape as a [`RuleFile`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HarnessFile {
    /// The file name, as the bytes the kernel returned.
    pub name: Vec<u8>,
    /// The file's contents.
    pub bytes: Vec<u8>,
}

/// Which policy a set of rule files is.
///
/// A SHA-256 over the name of every rule file that defines actions or deny
/// rules, then its actions and deny rules in canonical form, each field
/// length-prefixed. Deny rules are sorted by their canonical form, since their
/// declaration order changes only trace ordering. The prefixes matter: hashing names and
/// contents back to back would give `1.toml` holding `#a2.toml#b` the same
/// generation as `1.toml` holding `#a` beside `2.toml` holding `#b`, two
/// different rulesets that a stale request could not tell apart.
///
/// The actions are hashed as parsed, not the file's bytes, so that what is not
/// policy is not in the digest: a `[[test]]` table (see [`crate::rule_test`]),
/// a comment, and the line an action sits on can all change without
/// invalidating a request minted under the same rules. Every field of
/// [`Action`] and [`DenyRule`] that can change a decision is hashed. Two things
/// that also bear on a decision are outside the generation: the settings, and
/// the compiled engine (the deny-list), which no rule file can change. The generation only
/// tells a stale request from a fresh one; the gate re-decides from root-owned
/// state, so it never trusts a generation to vouch for either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation([u8; 32]);

impl Generation {
    /// The whole digest, as 64 lowercase hex characters.
    ///
    /// What the front-end prints and stamps into generated agent
    /// documentation.
    pub fn hex(&self) -> String {
        use std::fmt::Write as _;

        self.0
            .iter()
            .fold(String::with_capacity(64), |mut out, byte| {
                // Writing into a String cannot fail.
                let _ = write!(out, "{byte:02x}");
                out
            })
    }

    /// The first eight bytes of the digest, big-endian.
    ///
    /// What a spool entry carries and the gate compares. Its hex rendering is
    /// a prefix of [`Self::hex`], so the two can be matched by eye.
    pub fn id(&self) -> u64 {
        let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = self.0;
        u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
    }
}

impl std::fmt::Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

/// A ruleset, and the generation of the files it was built from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedRuleSet {
    /// The validated ruleset.
    pub rules: RuleSet,
    /// Which policy it is.
    pub generation: Generation,
    /// The `[[test]]` tables of every file, in load order.
    ///
    /// Beside the ruleset and outside the generation: a test is not policy.
    pub tests: Vec<RuleTest>,
    /// The harness registry hashed into this generation when it is not empty.
    ///
    /// Empty when the registry failed to load: see [`Self::registry_fault`].
    pub harnesses: HarnessRegistry,
    /// Why the registry is empty although root wrote one, if it is.
    ///
    /// A registry that fails the trust walk or does not parse disarms every
    /// harness, and only harnesses: the rules still load, so a human keeps the
    /// password path. Recorded in audit evidence and shown by `doctor`.
    pub registry_fault: Option<String>,
}

/// A rule that names a harness label the registry does not have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnregisteredLabel {
    /// `action` or `operation`.
    pub kind: &'static str,
    /// The rule's id.
    pub id: String,
    /// The label nobody registered.
    pub label: String,
    /// Where the rule was written.
    pub at: Source,
}

impl LoadedRuleSet {
    /// Every rule whose label the registry lacks.
    ///
    /// Such a rule loads and grants nothing, since no caller can be attested
    /// as an unregistered label. `xudo check` refuses it.
    pub fn unregistered_labels(&self) -> Vec<UnregisteredLabel> {
        let actions = self
            .rules
            .actions()
            .iter()
            .map(|a| ("action", a.id.as_str(), &a.harness, a.source.clone()));
        let operations = self
            .rules
            .operations()
            .iter()
            .map(|o| ("operation", o.id.as_str(), &o.harness, o.source.clone()));
        let mut found = Vec::new();
        for (kind, id, labels, at) in actions.chain(operations) {
            for label in labels.iter().filter(|l| self.harnesses.get(l).is_none()) {
                found.push(UnregisteredLabel {
                    kind,
                    id: id.to_owned(),
                    label: label.clone(),
                    at: at.clone(),
                });
            }
        }
        found
    }
}

/// Why a set of rule files could not become a ruleset. Every variant fails
/// closed: a partially loaded ruleset is a ruleset nobody reviewed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuleFilesError {
    /// A file was handed in whose name is not a rule file's.
    ///
    /// Every reader selects with [`is_rule_file_name`] before reading, so this
    /// is a reader that selected some other way, and its generation would
    /// cover files the others do not see.
    #[error("{name} is not a rule file name: a rule file is named <name>.toml")]
    NotARuleFile {
        /// The name, with non-printable bytes escaped.
        name: String,
    },
    /// A file name is not UTF-8.
    ///
    /// A decision cites the file it came from, and a citation that has to be
    /// rendered lossily names a file nobody can find.
    #[error("rule file name {name} is not valid UTF-8, so no decision could cite it")]
    NameNotUtf8 {
        /// The name, with non-printable bytes escaped.
        name: String,
    },
    /// A file's contents are not UTF-8.
    ///
    /// Refused rather than read lossily: a rule file whose bytes do not mean
    /// what they appear to mean is not a rule file anyone reviewed.
    #[error("{file} is not valid UTF-8; a rule file must be text")]
    NotUtf8 {
        /// The file.
        file: String,
    },
    /// More `[[test]]` tables across all files than one ruleset may carry.
    #[error("more than {limit} [[test]] tables across the rule files")]
    TooManyTests {
        /// The bound.
        limit: usize,
    },
    /// The policy engine refused a file, or the files together.
    ///
    /// Transparent, because every [`RuleSetError`] already names the file and
    /// line it is about.
    #[error(transparent)]
    Rules(#[from] RuleSetError),
}

/// Builds the ruleset and its generation from rule files.
///
/// Files are evaluated in byte order of their names, whatever order they
/// arrive in, which is systemd's and polkit's convention and the one operators
/// already expect. The generation is computed over the same files in the same
/// order, so it describes exactly the policy that was loaded.
///
/// # Errors
///
/// The first file that is not a rule file, or whose name or contents are not
/// UTF-8, as the matching [`RuleFilesError`]; and anything the policy engine
/// refuses, as [`RuleFilesError::Rules`].
pub fn load_rule_files(files: Vec<RuleFile>) -> Result<LoadedRuleSet, RuleFilesError> {
    load_policy(files, &[])
}

/// [`load_rule_files`], plus the harness registry those rules may name.
///
/// An empty harness list leaves the generation unchanged. A non-empty list is
/// hashed after the rules, under a `harnesses-v1` frame, in label order.
///
/// # Errors
///
/// As [`load_rule_files`]. A harness file that does not parse is not an error
/// here: see [`load_policy_with_registry`].
pub fn load_policy(
    files: Vec<RuleFile>,
    harnesses: &[HarnessFile],
) -> Result<LoadedRuleSet, RuleFilesError> {
    load_policy_with_registry(files, Ok(harnesses))
}

/// [`load_policy`], where the registry may already have failed to be read.
///
/// A registry that cannot be read (`Err(why)`) or does not parse yields an
/// empty registry and a [`LoadedRuleSet::registry_fault`]; it is never a load
/// error, because that would lock every human out when a harness file is
/// removed or damaged. An action naming a label the registry lacks loads and
/// grants nothing.
///
/// # Errors
///
/// As [`load_rule_files`]. Nothing about the registry.
pub fn load_policy_with_registry(
    mut files: Vec<RuleFile>,
    harnesses: Result<&[HarnessFile], String>,
) -> Result<LoadedRuleSet, RuleFilesError> {
    let (registry, registry_fault) = match harnesses.and_then(harness_registry) {
        Ok(registry) => (registry, None),
        Err(why) => (HarnessRegistry::empty(), Some(why)),
    };
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let mut hasher = Sha256::new();
    hasher.update(GENERATION_DOMAIN);
    let mut actions: Vec<Action> = Vec::new();
    let mut deny_rules: Vec<DenyRule> = Vec::new();
    let mut operations: Vec<Operation> = Vec::new();
    let mut tests: Vec<RuleTest> = Vec::new();

    for file in &files {
        if !is_rule_file_name(&file.name) {
            return Err(RuleFilesError::NotARuleFile {
                name: escaped(&file.name),
            });
        }
        let name = std::str::from_utf8(&file.name).map_err(|_| RuleFilesError::NameNotUtf8 {
            name: escaped(&file.name),
        })?;
        let text = std::str::from_utf8(&file.bytes).map_err(|_| RuleFilesError::NotUtf8 {
            file: name.to_owned(),
        })?;

        let (parsed, file_tests) = RuleSet::from_toml_with_tests(name, text)?;

        // A file with no actions, deny rules, or operations is not policy, so
        // it is not hashed: a file of tests alone must not move the generation.
        // The operations frame is written only when the file has operations, so
        // an action-only file keeps the generation it had before operations
        // existed.
        if !parsed.actions().is_empty()
            || !parsed.deny_rules().is_empty()
            || !parsed.operations().is_empty()
        {
            framed(&mut hasher, &file.name);
            for action in parsed.actions() {
                framed(&mut hasher, &policy_form(action));
            }
            framed(&mut hasher, b"deny-rules-v1");
            let mut deny_forms: Vec<_> = parsed.deny_rules().iter().map(policy_form_deny).collect();
            deny_forms.sort_unstable();
            for form in deny_forms {
                framed(&mut hasher, &form);
            }
            if !parsed.operations().is_empty() {
                framed(&mut hasher, b"operations-v1");
                for operation in parsed.operations() {
                    framed(&mut hasher, &policy_form_operation(operation));
                }
            }
            // Closes the file, so the last action of one cannot be read as the
            // first of the next.
            framed(&mut hasher, b"");
        }

        actions.extend(parsed.actions().iter().cloned());
        deny_rules.extend(parsed.deny_rules().iter().cloned());
        operations.extend(parsed.operations().iter().cloned());
        tests.extend(file_tests);
        if tests.len() > MAX_TESTS {
            return Err(RuleFilesError::TooManyTests { limit: MAX_TESTS });
        }
    }

    // Hashed only when present, so a ruleset with no harness files keeps the
    // generation it had before the registry existed.
    if !registry.is_empty() {
        framed(&mut hasher, b"harnesses-v1");
        for entry in registry.entries() {
            framed(&mut hasher, &entry.canonical());
        }
    }

    Ok(LoadedRuleSet {
        rules: RuleSet::load_all(actions, deny_rules, operations)?,
        generation: Generation(hasher.finalize().into()),
        tests,
        harnesses: registry,
        registry_fault,
    })
}

/// Why the registry cannot be built, as the text a fault carries.
fn harness_registry(files: &[HarnessFile]) -> Result<HarnessRegistry, String> {
    let mut named = Vec::with_capacity(files.len());
    for file in files {
        let name = std::str::from_utf8(&file.name)
            .map_err(|_| format!("a registry file name is not UTF-8: {}", escaped(&file.name)))?;
        let text = std::str::from_utf8(&file.bytes)
            .map_err(|_| format!("registry file {name} is not UTF-8"))?;
        named.push((name.to_owned(), text.to_owned()));
    }
    HarnessRegistry::from_files(named).map_err(|error| error.to_string())
}

/// Exhaustive canonical encoding of every field that changes deny evaluation.
/// Provenance is excluded because it affects the trace only.
fn policy_form_deny(rule: &DenyRule) -> Vec<u8> {
    let DenyRule {
        id,
        reason,
        program,
        all,
        source: _,
    } = rule;
    let mut out = Vec::new();
    put(&mut out, b"deny-rule-v1");
    put(&mut out, id.as_str().as_bytes());
    put(&mut out, reason.as_bytes());
    put_len(&mut out, program.len());
    for item in program {
        put(&mut out, item.as_bytes());
    }
    put_len(&mut out, all.len());
    for clause in all {
        let DenyClause {
            any_arg,
            any_deb_name,
        } = clause;
        match (any_arg, any_deb_name) {
            (Some(values), None) => {
                put(&mut out, b"any-arg");
                put_len(&mut out, values.len());
                for value in values {
                    put(&mut out, value.as_bytes());
                }
            }
            (None, Some(values)) => {
                put(&mut out, b"any-deb-name");
                put_len(&mut out, values.len());
                for value in values {
                    put(&mut out, value.as_bytes());
                }
            }
            (Some(_), Some(_)) | (None, None) => put(&mut out, b"invalid-clause"),
        }
    }
    out
}

/// Everything about an action that can change a decision, as bytes.
///
/// A canonical encoding written out by hand, not the action's `Debug` output:
/// `Debug` is documented as unstable, and this feeds a wire value, so an impl
/// that dropped a field would let a real policy change keep its generation.
/// Every field is length-framed or a fixed tag, in struct order, and every
/// destructuring below is exhaustive with no `..`, so a field or variant added
/// to a policy type stops this module compiling until it is encoded. The
/// action's `source` is left out: where an action sits in its file is
/// provenance, not policy.
fn policy_form(action: &Action) -> Vec<u8> {
    let Action {
        id,
        tier,
        exe,
        args,
        confirm,
        agent_allowed,
        env_allow,
        harness,
        outcome,
        gtfobins_waiver,
        source: _,
    } = action;
    let mut out = Vec::new();
    put(&mut out, id.as_str().as_bytes());
    put(&mut out, tier_word(*tier).as_bytes());
    put(&mut out, exe.as_bytes());
    put_len(&mut out, args.len());
    for spec in args {
        let ArgSpec {
            name,
            matcher,
            repeat,
        } = spec;
        put(&mut out, name.as_bytes());
        put_matcher(&mut out, matcher);
        match repeat {
            Repeat::One => put(&mut out, b"one"),
            Repeat::Optional => put(&mut out, b"optional"),
            Repeat::Between { min, max } => {
                put(&mut out, b"between");
                put_len(&mut out, *min);
                put_len(&mut out, *max);
            }
        }
    }
    let confirm = match confirm {
        ConfirmPolicy::Default => "default",
        ConfirmPolicy::Always => "always",
        ConfirmPolicy::Never => "never",
    };
    put(&mut out, confirm.as_bytes());
    out.push(u8::from(*agent_allowed));
    put_len(&mut out, env_allow.len());
    for name in env_allow {
        put(&mut out, name.as_bytes());
    }
    // An unset outcome is omitted so an action that does not name
    // them keeps the canonical form it had before those fields existed.
    if !harness.is_empty() {
        put(&mut out, b"harness");
        put_len(&mut out, harness.len());
        for label in harness {
            put(&mut out, label.as_bytes());
        }
    }
    if !outcome.is_unset() {
        put(&mut out, b"outcome");
        put(&mut out, outcome.as_str().as_bytes());
    }
    if let Some(waiver) = gtfobins_waiver {
        put(&mut out, b"gtfobins-waiver");
        put(&mut out, waiver.as_bytes());
    }
    out
}

/// Canonical form of one operation. Every field that can change a decision is
/// included. `source` is provenance. An empty harness list is still encoded,
/// because this frame did not exist before operations did, so there is no old
/// digest to preserve inside it.
fn policy_form_operation(operation: &Operation) -> Vec<u8> {
    let Operation {
        id,
        op,
        under,
        recursive,
        max_depth,
        max_entries,
        owners,
        harness,
        outcome,
        source: _,
    } = operation;
    let mut out = Vec::new();
    put(&mut out, id.as_str().as_bytes());
    match op {
        OpKind::RemovePath => put(&mut out, b"remove-path"),
    }
    put(&mut out, under.as_bytes());
    out.push(u8::from(*recursive));
    put(&mut out, &max_depth.to_be_bytes());
    put(&mut out, &max_entries.to_be_bytes());
    match owners {
        None => put(&mut out, b"owners-any-but-root"),
        Some(names) => {
            put(&mut out, b"owners");
            put_len(&mut out, names.len());
            for name in names {
                put(&mut out, name.as_bytes());
            }
        }
    }
    put_len(&mut out, harness.len());
    for label in harness {
        put(&mut out, label.as_bytes());
    }
    // Written only when set, so an operation with no harness keeps the
    // generation it had before operations could grant.
    if !outcome.is_unset() {
        put(&mut out, b"outcome");
        put(&mut out, outcome.as_str().as_bytes());
    }
    out
}

fn tier_word(tier: Tier) -> &'static str {
    match tier {
        Tier::DiagRead => "diag-read",
        Tier::SvcControl => "svc-control",
        Tier::PkgInstall => "pkg-install",
        Tier::PkgRemove => "pkg-remove",
        Tier::SysTunable => "sys-tunable",
        Tier::NetFilter => "net-filter",
        Tier::Critical => "critical",
    }
}

fn put_matcher(out: &mut Vec<u8>, matcher: &Matcher) {
    match matcher {
        Matcher::Literal(want) => {
            put(out, b"literal");
            put(out, want.as_bytes());
        }
        Matcher::OneOf(options) => {
            put(out, b"one-of");
            put_len(out, options.len());
            for option in options {
                put(out, option.as_bytes());
            }
        }
        Matcher::IntRange { lo, hi } => {
            put(out, b"int-range");
            put(out, &lo.to_be_bytes());
            put(out, &hi.to_be_bytes());
        }
        Matcher::PathUnder { prefix } => {
            put(out, b"path-under");
            put(out, prefix.as_bytes());
        }
        Matcher::Name(kind) => {
            put(out, b"name");
            let word = match kind {
                NameKind::DebName => "deb-name",
                NameKind::DebNameLiteral => "deb-name-literal",
                NameKind::RpmName => "rpm-name",
                NameKind::ArchName => "arch-name",
                NameKind::ApkName => "apk-name",
                NameKind::UnitName => "unit-name",
                NameKind::ServiceUnitName => "service-unit-name",
                NameKind::Hostname => "hostname",
                NameKind::SysctlKey => "sysctl-key",
            };
            put(out, word.as_bytes());
        }
        Matcher::Pattern(pattern) => {
            put(out, b"pattern");
            put(out, pattern.canonical_form());
        }
    }
}

/// Appends one field preceded by its length, as [`framed`] does for the hash.
fn put(out: &mut Vec<u8>, field: &[u8]) {
    put_len(out, field.len());
    out.extend_from_slice(field);
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u64).to_be_bytes());
}

/// Feeds one field to the hash, preceded by its length as eight big-endian
/// bytes, so that no field can absorb the start of the next.
fn framed(hasher: &mut Sha256, field: &[u8]) {
    // A usize always fits in a u64 on the platforms this builds for, and
    // eight bytes, not `usize`'s own width, keeps the hash identical on every
    // one of them.
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// Renders bytes for an error message, escaping anything not printable ASCII.
///
/// For a human only; never compared.
fn escaped(bytes: &[u8]) -> String {
    bytes.escape_ascii().to_string()
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
    use crate::rule::{ActionId, Source};

    const ONE_ACTION: &str = r#"
[[action]]
id = "xudo.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;

    const OTHER_ACTION: &str = r#"
[[action]]
id = "xudo.pkg.update"
tier = "pkg-install"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]
"#;

    fn file(name: &str, contents: &str) -> RuleFile {
        RuleFile {
            name: name.as_bytes().to_vec(),
            bytes: contents.as_bytes().to_vec(),
        }
    }

    fn generation(files: Vec<RuleFile>) -> Generation {
        load_rule_files(files).unwrap().generation
    }

    fn harness_file(name: &str, account: &str, max_sessions: u32) -> HarnessFile {
        HarnessFile {
            name: format!("{name}.toml").into_bytes(),
            bytes: format!(
                "label = \"{name}\"\nway = \"service\"\naccount = \"{account}\"\nreviewers = [\"alice\"]\nmax-sessions = {max_sessions}\n"
            )
            .into_bytes(),
        }
    }

    #[test]
    fn a_rule_file_is_named_something_dot_toml() {
        for name in ["10-a.toml", "a.toml", ".hidden.toml", "x.y.toml"] {
            assert!(is_rule_file_name(name.as_bytes()), "{name}");
        }
        for name in [
            ".toml",
            "toml",
            "",
            "a.toml~",
            "a.toml.bak",
            "a.toml.dpkg-old",
            "a.TOML",
            // The packaged example lives beside the rules in the repo and must
            // not be loaded if a directory walk ever sees it.
            "20-services-lifecycle.toml.example",
        ] {
            assert!(!is_rule_file_name(name.as_bytes()), "{name}");
        }
        assert!(is_rule_file_name(b"\xff.toml"), "selection is on bytes");
    }

    #[test]
    fn files_are_evaluated_in_name_order_whatever_order_they_arrive_in() {
        let loaded = load_rule_files(vec![
            file("20-b.toml", ONE_ACTION),
            file("10-a.toml", OTHER_ACTION),
        ])
        .unwrap();
        let ids: Vec<String> = loaded
            .rules
            .actions()
            .iter()
            .map(|action| action.id.to_string())
            .collect();
        assert_eq!(ids, ["xudo.pkg.update", "xudo.svc.restart"]);
    }

    #[test]
    fn the_generation_does_not_depend_on_the_order_files_were_read_in() {
        let forward = generation(vec![
            file("10-a.toml", OTHER_ACTION),
            file("20-b.toml", ONE_ACTION),
        ]);
        let backward = generation(vec![
            file("20-b.toml", ONE_ACTION),
            file("10-a.toml", OTHER_ACTION),
        ]);
        assert_eq!(forward, backward);
    }

    #[test]
    fn the_generation_changes_with_a_name_or_a_change_of_policy() {
        let base = generation(vec![file("10-a.toml", ONE_ACTION)]);
        let renamed = generation(vec![file("99-z.toml", ONE_ACTION)]);
        let edited = generation(vec![file(
            "10-a.toml",
            &ONE_ACTION.replace("restart", "reload"),
        )]);
        // The name of a file that defines actions is hashed with them, so
        // moving a rule to another file is a different generation even when
        // the rules are identical.
        assert_ne!(base, renamed);
        assert_ne!(base, edited);
    }

    #[test]
    fn an_operation_is_hashed_and_a_test_file_is_not() {
        let action = generation(vec![file("10-a.toml", ONE_ACTION)]);
        let with_test = generation(vec![file(
            "10-a.toml",
            &format!(
                "{ONE_ACTION}\n[[test]]\nargv = [\"/usr/bin/systemctl\", \"restart\", \"nginx.service\"]\nexpect = \"allow\"\n"
            ),
        )]);
        assert_eq!(action, with_test);
        let operation = r#"
[[operation]]
id = "web.clean-build"
op = "remove-path"
under = "/srv/app/build"
recursive = true
max-depth = 8
max-entries = 10
"#;
        let only = generation(vec![file("50-remove.toml", operation)]);
        let changed = generation(vec![file(
            "50-remove.toml",
            &operation.replace("max-entries = 10", "max-entries = 11"),
        )]);
        assert_ne!(only, changed);
        assert_ne!(only, action);
        let alongside = generation(vec![
            file("10-a.toml", ONE_ACTION),
            file("50-remove.toml", operation),
        ]);
        assert_ne!(alongside, action);
    }

    #[test]
    fn an_operation_owner_and_harness_change_the_generation() {
        let base = "[[operation]]\nid = \"o\"\nop = \"remove-path\"\nunder = \"/srv/a\"\nrecursive = true\nmax-depth = 2\nmax-entries = 4\n";
        let harnesses = [harness_file("codex", "agent", 4)];
        let of = |text: &str| {
            load_policy(vec![file("50-remove.toml", text)], &harnesses)
                .unwrap()
                .generation
        };
        let plain = of(base);
        let owned = of(&format!("{base}owners = [\"agent\"]\n"));
        let other = of(&format!("{base}owners = [\"agent\", \"www-data\"]\n"));
        let labelled = of(&format!(
            "{base}harness = [\"codex\"]\noutcome = \"allow\"\n"
        ));
        assert_ne!(plain, owned);
        assert_ne!(owned, other);
        assert_ne!(plain, labelled);
    }

    const GHOST_OPERATION: &str = "[[operation]]\nid = \"o\"\nop = \"remove-path\"\nunder = \"/srv/a\"\nrecursive = true\nmax-depth = 2\nmax-entries = 4\nharness = [\"ghost\"]\noutcome = \"allow\"\n";

    #[test]
    fn an_operation_naming_an_unregistered_harness_loads_and_is_reported() {
        let loaded = load_rule_files(vec![file("50-remove.toml", GHOST_OPERATION)]).unwrap();
        let found = loaded.unregistered_labels();
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].kind, found[0].id.as_str(), found[0].label.as_str()),
            ("operation", "o", "ghost")
        );
        assert!(loaded.harnesses.get("ghost").is_none());
    }

    #[test]
    fn a_rule_naming_an_unregistered_label_grants_nothing() {
        let action =
            ONE_ACTION.replace("exe =", "harness = [\"codex\"]\noutcome = \"allow\"\nexe =");
        let action = action.replace("/usr/bin/systemctl", "/usr/bin/xudo-demo");
        let loaded = load_policy(vec![file("10-a.toml", &action)], &[]).unwrap();
        // No registry entry exists to attest any caller as `codex`.
        assert!(loaded.harnesses.get("codex").is_none());
        assert!(loaded.registry_fault.is_none());
        let found = loaded.unregistered_labels();
        assert_eq!(
            (found[0].kind, found[0].label.as_str()),
            ("action", "codex")
        );
        // Registered, the same rule has nothing to report.
        let registered = load_policy(
            vec![file("10-a.toml", &action)],
            &[harness_file("codex", "agent", 4)],
        )
        .unwrap();
        assert!(registered.unregistered_labels().is_empty());
    }

    #[test]
    fn a_bad_registry_file_keeps_the_human_path_and_grants_nothing() {
        let bad = HarnessFile {
            name: b"codex.toml".to_vec(),
            bytes: b"label = \"codex\"\nsurprise = 1\n".to_vec(),
        };
        let loaded = load_policy(
            vec![file("10-a.toml", ONE_ACTION)],
            &[harness_file("claude", "agent", 4), bad],
        )
        .unwrap();
        // The rules loaded, so a human is decided as before; every label is gone.
        assert_eq!(loaded.rules.actions().len(), 1);
        assert!(loaded.harnesses.is_empty());
        assert!(loaded.registry_fault.unwrap().contains("codex.toml"));
        // The fault is not hashed: the generation is the one of no registry.
        let none = load_policy(vec![file("10-a.toml", ONE_ACTION)], &[]).unwrap();
        let bad_only = load_policy(
            vec![file("10-a.toml", ONE_ACTION)],
            &[HarnessFile {
                name: b"x.toml".to_vec(),
                bytes: b"\xff".to_vec(),
            }],
        )
        .unwrap();
        assert_eq!(none.generation, bad_only.generation);
        assert!(bad_only.registry_fault.is_some());
    }

    #[test]
    fn an_unreadable_registry_withholds_every_label_and_names_why() {
        let action =
            ONE_ACTION.replace("exe =", "harness = [\"codex\"]\noutcome = \"allow\"\nexe =");
        let action = action.replace("/usr/bin/systemctl", "/usr/bin/xudo-demo");
        let loaded = load_policy_with_registry(
            vec![file("10-a.toml", &action)],
            Err("the registry directory is writable by a non-root user".to_owned()),
        )
        .unwrap();
        assert!(loaded.harnesses.is_empty());
        assert!(loaded.registry_fault.unwrap().contains("writable"));
        assert_eq!(loaded.rules.actions().len(), 1);
    }

    #[test]
    fn removing_a_registry_file_unregisters_its_harness() {
        let both = [
            harness_file("codex", "agent", 4),
            harness_file("claude", "agent2", 4),
        ];
        let full = load_policy(Vec::new(), &both).unwrap();
        let removed = load_policy(Vec::new(), &both[..1]).unwrap();
        assert!(full.harnesses.get("claude").is_some());
        // No fault, no error: the label is simply no longer anyone.
        assert!(removed.harnesses.get("claude").is_none());
        assert!(removed.registry_fault.is_none());
        assert!(removed.harnesses.get("codex").is_some());
    }

    #[test]
    fn the_generation_includes_the_current_harness_registry() {
        let empty = load_policy(Vec::new(), &[]).unwrap().generation;
        let registered = load_policy(Vec::new(), &[harness_file("codex", "agent", 4)])
            .unwrap()
            .generation;
        let changed = load_policy(Vec::new(), &[harness_file("codex", "agent", 5)])
            .unwrap()
            .generation;
        assert_ne!(empty, registered);
        assert_ne!(registered, changed);
    }

    #[test]
    fn an_action_with_a_registered_harness_loads() {
        let action =
            ONE_ACTION.replace("exe =", "harness = [\"codex\"]\noutcome = \"allow\"\nexe =");
        let action = action.replace("/usr/bin/systemctl", "/usr/bin/xudo-demo");
        let result = load_policy(
            vec![file("10-a.toml", &action)],
            &[harness_file("codex", "agent", 4)],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn malformed_harness_file_names_and_bytes_disarm_every_harness() {
        let bad = |name: &[u8], bytes: &[u8]| HarnessFile {
            name: name.to_vec(),
            bytes: bytes.to_vec(),
        };
        for file in [
            bad(&[0xff], b""),
            bad(b"codex.toml", &[0xff]),
            bad(b"codex.toml", b"label = \"codex\"\nway = \"service\"\n"),
        ] {
            let loaded = load_policy(Vec::new(), &[file]).unwrap();
            assert!(loaded.harnesses.is_empty());
            assert!(loaded.registry_fault.is_some());
        }
    }

    #[test]
    fn a_waiver_is_part_of_the_generation() {
        let waiver = |why: &str| {
            format!(
                "gtfobins-waiver = \"pager escape through the unit: {why} and nothing more can be passed to it\"\n"
            )
        };
        let rule = |why: &str| {
            let action = ONE_ACTION.replace(
                "exe =",
                &format!(
                    "harness = [\"codex\"]\noutcome = \"allow\"\n{}exe =",
                    waiver(why)
                ),
            );
            load_policy(
                vec![file("10-a.toml", &action)],
                &[harness_file("codex", "agent", 4)],
            )
            .unwrap()
            .generation
        };
        let long = "the unit is a name matcher and no option can reach the service manager at all";
        assert_ne!(rule(long), rule(&format!("{long} here")));
        assert_eq!(rule(long), rule(long));
    }

    #[test]
    fn two_rulesets_that_concatenate_alike_have_different_generations() {
        // Back to back, the actions of `1.toml` holding both and of `1.toml`
        // and `2.toml` holding one each are the same bytes. Without the length
        // prefixes and the file boundary they would be one generation, and a
        // request minted under either would stay valid under the other.
        let one_file = generation(vec![file("1.toml", &format!("{ONE_ACTION}{OTHER_ACTION}"))]);
        let two_files = generation(vec![
            file("1.toml", ONE_ACTION),
            file("2.toml", OTHER_ACTION),
        ]);
        assert_ne!(one_file, two_files);
    }

    #[test]
    fn the_generation_of_a_fixed_ruleset_is_pinned() {
        // The generation is a wire value: the broker writes it, the gate
        // compares it, generated docs carry it. A change to the framing must
        // be deliberate, so the exact digest is asserted.
        let pinned = generation(vec![
            file("10-a.toml", OTHER_ACTION),
            file("20-b.toml", ONE_ACTION),
        ]);
        assert_eq!(
            pinned.hex(),
            "5e0c3d2b07766bd3b976031f438a84848f7b32dfec78d3f836dba1e71c8b26e4"
        );
        assert_eq!(
            generation(Vec::new()).hex(),
            "d47cc9ca3477869250ac3e1dce298f8402a764028c123c228443e5485bb1ccc1"
        );
    }

    #[test]
    fn the_id_is_the_first_eight_bytes_of_the_digest() {
        let g = generation(vec![file("10-a.toml", ONE_ACTION)]);
        let hex = g.hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(format!("{:016x}", g.id()), hex[..16]);
        assert_eq!(g.to_string(), hex);
    }

    #[test]
    fn no_files_is_an_empty_ruleset_with_its_own_generation() {
        // Permits nothing, which is the right default for a fresh install, and
        // still has a generation, so an entry minted before the last rule file
        // was deleted is refused.
        let loaded = load_rule_files(Vec::new()).unwrap();
        assert!(loaded.rules.is_empty());
        assert_ne!(
            loaded.generation,
            generation(vec![file("10-a.toml", ONE_ACTION)])
        );
    }

    #[test]
    fn a_file_that_is_not_a_rule_file_is_refused_rather_than_hashed() {
        let err = load_rule_files(vec![file("notes.txt", "# x")]).unwrap_err();
        assert_eq!(
            err,
            RuleFilesError::NotARuleFile {
                name: "notes.txt".to_owned()
            }
        );
        assert!(err.to_string().contains("<name>.toml"), "{err}");
    }

    #[test]
    fn a_rule_file_name_that_is_not_utf8_is_refused_and_shown_escaped() {
        let err = load_rule_files(vec![RuleFile {
            name: b"\xff.toml".to_vec(),
            bytes: b"# x".to_vec(),
        }])
        .unwrap_err();
        assert_eq!(
            err,
            RuleFilesError::NameNotUtf8 {
                name: "\\xff.toml".to_owned()
            }
        );
        assert!(
            err.to_string().contains("no decision could cite it"),
            "{err}"
        );
    }

    #[test]
    fn a_rule_file_that_is_not_utf8_is_refused_rather_than_read_lossily() {
        let err = load_rule_files(vec![RuleFile {
            name: b"10-a.toml".to_vec(),
            bytes: vec![0xff, 0xfe, 0xfd],
        }])
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "10-a.toml is not valid UTF-8; a rule file must be text"
        );
    }

    #[test]
    fn a_malformed_file_fails_the_whole_load_naming_the_file() {
        let err = load_rule_files(vec![
            file("10-good.toml", ONE_ACTION),
            file("20-bad.toml", "[[action]\nid ="),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("20-bad.toml"), "{err}");
    }

    #[test]
    fn a_duplicate_id_across_two_files_fails_the_combined_load() {
        let err = load_rule_files(vec![
            file("10-a.toml", ONE_ACTION),
            file("20-b.toml", ONE_ACTION),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("duplicate rule id"), "{err}");
        assert!(format!("{err:?}").contains("DuplicateId"));
    }

    #[test]
    fn a_duplicate_deny_id_across_two_files_fails_the_combined_load() {
        let deny = "[[deny]]\nid = \"xudo.protect.same\"\nreason = \"protected package\"\nprogram = [\"apt-get\"]\nall = []\n";
        let err = load_rule_files(vec![
            file(
                "00-actions.toml",
                &ONE_ACTION.replace("systemctl", "apt-get"),
            ),
            file("10-a.toml", deny),
            file("20-b.toml", deny),
        ])
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("duplicate rule id xudo.protect.same"),
            "{err}"
        );
    }

    #[test]
    fn a_deny_rule_naming_an_unused_program_loads_inert() {
        let deny = "[[deny]]\nid = \"xudo.protect.pkg\"\nreason = \"protected package\"\nprogram = [\"apt-get\"]\nall = []\n";
        let loaded = load_rule_files(vec![
            file("10-actions.toml", ONE_ACTION),
            file("20-deny.toml", deny),
        ])
        .unwrap();
        assert!(
            loaded
                .rules
                .actions()
                .iter()
                .all(|action| action.exe != "/usr/bin/apt-get")
        );
        assert_eq!(loaded.rules.deny_rules()[0].id.as_str(), "xudo.protect.pkg");
    }

    const WITH_TESTS: &str = r#"
# a comment that is not policy
[[test]]
argv = ["/usr/bin/apt-get", "update"]
expect = "allow"
reason = "the refresh"

[[action]]
id = "xudo.pkg.update"
tier = "pkg-install"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]

[[test]]
argv = ["/usr/bin/apt-get", "install"]
expect = "deny"
"#;

    #[test]
    fn editing_adding_or_removing_a_test_never_changes_the_generation() {
        // A test is not policy: a request minted under these rules must not
        // go stale because someone added a case, and the line an action sits
        // on moved when they did.
        let plain = generation(vec![file("10-a.toml", OTHER_ACTION)]);
        let tested = load_rule_files(vec![file("10-a.toml", WITH_TESTS)]).unwrap();
        assert_eq!(tested.generation, plain);
        assert_eq!(tested.tests.len(), 2);
        let edited = WITH_TESTS.replace("\"deny\"", "\"allow\"");
        assert_eq!(generation(vec![file("10-a.toml", &edited)]), plain);
        assert_eq!(
            generation(vec![file("10-a.toml", &format!("# top\n{OTHER_ACTION}"))]),
            plain
        );
    }

    #[test]
    fn a_policy_change_still_changes_the_generation_beside_tests() {
        let base = generation(vec![file("10-a.toml", WITH_TESTS)]);
        let widened = WITH_TESTS.replace("\"update\" }", "\"upgrade\" }");
        assert_ne!(generation(vec![file("10-a.toml", &widened)]), base);
    }

    #[test]
    fn tests_are_collected_across_files_in_load_order_with_their_provenance() {
        let loaded = load_rule_files(vec![
            file("20-b.toml", WITH_TESTS),
            file("10-a.toml", WITH_TESTS),
        ])
        .unwrap_err();
        // Both files define the same action id, which the combined load refuses.
        assert!(loaded.to_string().contains("duplicate"), "{loaded}");
        let loaded = load_rule_files(vec![
            file(
                "20-b.toml",
                "[[test]]\nargv = [\"/x\"]\nexpect = \"deny\"\n",
            ),
            file("10-a.toml", WITH_TESTS),
        ])
        .unwrap();
        let places: Vec<String> = loaded.tests.iter().map(|t| t.source.to_string()).collect();
        assert_eq!(places, ["10-a.toml:3", "10-a.toml:14", "20-b.toml:1"]);
    }

    #[test]
    fn a_file_holding_only_tests_never_changes_the_generation() {
        // `xudo-rules(5)` promises that adding a test never bumps the
        // generation, and a file of tests alone has no actions to hash.
        let plain = generation(vec![file("10-a.toml", ONE_ACTION)]);
        let tests_only = "[[test]]\nargv = [\"/x\"]\nexpect = \"deny\"\n";
        assert_eq!(
            generation(vec![
                file("10-a.toml", ONE_ACTION),
                file("20-tests.toml", tests_only)
            ]),
            plain
        );
        assert_eq!(
            generation(vec![file("00-t.toml", tests_only)]),
            generation(Vec::new())
        );
        assert_eq!(
            generation(vec![file("00-t.toml", "# nothing")]),
            generation(Vec::new())
        );
    }

    fn digest(action: &Action) -> String {
        let mut hasher = Sha256::new();
        hasher.update(policy_form(action));
        Generation(hasher.finalize().into()).hex()
    }

    fn fixed_actions() -> Vec<Action> {
        RuleSet::from_toml(
            "f.toml",
            r#"
[[action]]
id = "a.one"
tier = "svc-control"
exe = "/usr/bin/systemctl"
confirm = "always"
agent-allowed = false
env-allow = ["LANG", "TERM"]
args = [
  { name = "verb", matcher = { one-of = ["start", "stop"] } },
  { name = "unit", matcher = { name = "unit-name" }, repeat = { between = { min = 1, max = 3 } } },
  { name = "n", matcher = { int-range = { lo = -5, hi = 9 } }, repeat = "optional" },
  { name = "p", matcher = { path-under = { prefix = "/etc" } } },
  { name = "r", matcher = { pattern = "a+b" } },
  { name = "l", matcher = { literal = "x" } },
]

[[action]]
id = "a.two"
tier = "critical"
exe = "/usr/bin/true"
args = [
  { name = "a", matcher = { name = "deb-name" } },
  { name = "b", matcher = { name = "rpm-name" } },
  { name = "c", matcher = { name = "arch-name" } },
  { name = "d", matcher = { name = "apk-name" } },
  { name = "e", matcher = { name = "hostname" } },
  { name = "f", matcher = { name = "sysctl-key" } },
  { name = "g", matcher = { name = "service-unit-name" } },
]

[[action]]
id = "a.three"
tier = "diag-read"
exe = "/usr/bin/id"
confirm = "never"
agent-allowed = true
args = [
  { name = "n", matcher = { literal = "-u" } },
]
"#,
        )
        .unwrap()
        .actions()
        .to_vec()
    }

    #[test]
    fn the_canonical_form_of_fixed_actions_is_pinned() {
        // The form is a wire value: a change to it must be deliberate.
        let digests: Vec<String> = fixed_actions().iter().map(digest).collect();
        assert_eq!(
            digests,
            [
                "b324748da0c3bfb72a2ff3ca4d054df8a837b80f9bf5a0f5f3c4b80bfa74238a",
                "27b11bb80a69d4e47885e979d84b7ca8064e83938ee1f008f63083ded7342d0c",
                "336bd13449dcfa10179cf3319d090841485898e4ff33c136104b13f4f6395095",
            ]
        );
    }

    #[test]
    fn where_an_action_sits_is_not_in_its_canonical_form() {
        let mut moved = fixed_actions();
        for action in &mut moved {
            action.source = Source::new("elsewhere.toml", 999);
        }
        assert_eq!(
            moved.iter().map(policy_form).collect::<Vec<_>>(),
            fixed_actions().iter().map(policy_form).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_deny_policy_field_is_canonical_and_provenance_is_not() {
        let base = DenyRule {
            id: crate::rule::ActionId::new("xudo.protect.test"),
            reason: "protected package".into(),
            program: vec!["apt-get".into()],
            all: vec![DenyClause {
                any_arg: Some(vec!["remove".into()]),
                any_deb_name: None,
            }],
            source: Source::new("a.toml", 1),
        };
        let mut variants = Vec::new();
        let mut changed = base.clone();
        changed.id = crate::rule::ActionId::new("xudo.protect.other");
        variants.push(changed);
        let mut changed = base.clone();
        changed.reason.push('!');
        variants.push(changed);
        let mut changed = base.clone();
        changed.program.push("apt".into());
        variants.push(changed);
        let mut changed = base.clone();
        changed.all[0].any_arg = Some(vec!["purge".into()]);
        variants.push(changed);
        let mut changed = base.clone();
        changed.all[0].any_arg = None;
        changed.all[0].any_deb_name = Some(vec!["xudo".into()]);
        variants.push(changed);
        for variant in variants {
            assert_ne!(policy_form_deny(&variant), policy_form_deny(&base));
        }
        let mut moved = base.clone();
        moved.source = Source::new("elsewhere.toml", 55);
        assert_eq!(policy_form_deny(&moved), policy_form_deny(&base));
        let mut invalid = base.clone();
        invalid.all[0].any_deb_name = Some(vec!["xudo".into()]);
        assert!(policy_form_deny(&invalid).ends_with(b"invalid-clause"));
    }

    mod canonical {
        use proptest::prelude::*;

        use super::*;
        use crate::matcher::AnchoredPattern;
        use crate::rule::Outcome;

        /// Every `NameKind`, as a fixed-size array so that adding a kind to the
        /// enum without listing it here is caught by the pin below.
        const ALL_NAME_KINDS: [NameKind; 9] = [
            NameKind::DebName,
            NameKind::DebNameLiteral,
            NameKind::RpmName,
            NameKind::ArchName,
            NameKind::ApkName,
            NameKind::UnitName,
            NameKind::ServiceUnitName,
            NameKind::Hostname,
            NameKind::SysctlKey,
        ];

        /// How many of the shared-payload texts to try; compiling each pattern
        /// is slow under miri, which runs this module.
        const SAME_TEXTS: usize = if cfg!(miri) { 1 } else { 5 };

        /// Whether to try a pattern too: compiling one is slow under miri.
        const PATTERNS: usize = if cfg!(miri) { 0 } else { 1 };

        /// How many fixed actions to mutate; every pattern mutation compiles a
        /// regex, and miri has the property test for the same mutations.
        const FIXED_BASES: usize = if cfg!(miri) { 0 } else { usize::MAX };

        const ALL_CONFIRMS: [ConfirmPolicy; 3] = [
            ConfirmPolicy::Default,
            ConfirmPolicy::Always,
            ConfirmPolicy::Never,
        ];

        const ALL_TIERS: [Tier; 7] = [
            Tier::DiagRead,
            Tier::SvcControl,
            Tier::PkgInstall,
            Tier::PkgRemove,
            Tier::SysTunable,
            Tier::NetFilter,
            Tier::Critical,
        ];

        fn matcher() -> impl Strategy<Value = Matcher> {
            prop_oneof![
                "[a-z/]{0,4}".prop_map(Matcher::Literal),
                proptest::collection::vec("[a-z]{0,3}", 0..3).prop_map(Matcher::OneOf),
                (-3i64..3, 0i64..6).prop_map(|(lo, hi)| Matcher::IntRange { lo, hi }),
                "[a-z/]{0,4}".prop_map(|prefix| Matcher::PathUnder { prefix }),
                proptest::sample::select(ALL_NAME_KINDS.to_vec()).prop_map(Matcher::Name),
                "[a-z]{1,3}[+*]?".prop_map(|s| Matcher::Pattern(AnchoredPattern::new(&s).unwrap())),
            ]
        }

        fn repeat() -> impl Strategy<Value = Repeat> {
            prop_oneof![
                Just(Repeat::One),
                Just(Repeat::Optional),
                (0usize..3, 0usize..5).prop_map(|(min, max)| Repeat::Between { min, max }),
            ]
        }

        fn spec() -> impl Strategy<Value = ArgSpec> {
            ("[a-z]{1,3}", matcher(), repeat()).prop_map(|(name, matcher, repeat)| ArgSpec {
                name,
                matcher,
                repeat,
            })
        }

        fn tier() -> impl Strategy<Value = Tier> {
            proptest::sample::select(ALL_TIERS.to_vec())
        }

        fn confirm() -> impl Strategy<Value = ConfirmPolicy> {
            proptest::sample::select(ALL_CONFIRMS.to_vec())
        }

        fn action() -> impl Strategy<Value = Action> {
            (
                "[a-z.]{1,6}",
                tier(),
                "/[a-z/]{1,6}",
                proptest::collection::vec(spec(), 0..4),
                confirm(),
                any::<bool>(),
                proptest::collection::vec("[A-Z]{1,3}", 0..3),
                1u32..500,
            )
                .prop_map(
                    |(id, tier, exe, args, confirm, agent_allowed, env_allow, line)| Action {
                        id: ActionId::new(id),
                        tier,
                        exe,
                        args,
                        confirm,
                        agent_allowed,
                        env_allow,
                        // Fixed non-default values ensure both mutation arms
                        // for these newly decision-relevant fields run on
                        // every platform, independent of proptest sampling.
                        harness: vec!["codex".to_owned()],
                        outcome: Outcome::AskHuman,
                        gtfobins_waiver: None,
                        source: Source::new("p.toml", line),
                    },
                )
        }

        /// Every way to change one decision-relevant field of an action.
        fn mutations(base: &Action, other: &Action) -> Vec<Action> {
            let mut out = Vec::new();
            let mut with = |f: &dyn Fn(&mut Action)| {
                let mut a = base.clone();
                f(&mut a);
                out.push(a);
            };
            with(&|a| a.id = ActionId::new(format!("{}x", a.id)));
            with(&|a| a.tier = other.tier);
            for tier in ALL_TIERS {
                with(&|a| a.tier = tier);
            }
            with(&|a| a.exe.push('x'));
            with(&|a| a.confirm = other.confirm);
            for confirm in ALL_CONFIRMS {
                with(&|a| a.confirm = confirm);
            }
            with(&|a| a.agent_allowed = !a.agent_allowed);
            with(&|a| a.env_allow.push("NEW".into()));
            with(&|a| {
                a.harness = if a.harness.is_empty() {
                    vec!["codex".into()]
                } else {
                    Vec::new()
                };
            });
            with(&|a| a.harness.push("claude".into()));
            with(&|a| {
                a.outcome = match a.outcome {
                    Outcome::Unset | Outcome::Allow => Outcome::AskHuman,
                    Outcome::AskHuman => Outcome::Allow,
                };
            });
            with(&|a| a.env_allow.reverse());
            with(&|a| {
                if let Some(first) = a.env_allow.first_mut() {
                    first.push('x');
                }
            });
            with(&|a| {
                a.args
                    .push(ArgSpec::one("extra", Matcher::Literal("e".into())));
            });
            with(&|a| a.args.reverse());
            with(&|a| {
                a.args.pop();
            });
            if let Some(spec) = other.args.first() {
                with(&|a| a.args.push(spec.clone()));
                with(&|a| a.args.insert(0, spec.clone()));
            }
            for index in 0..base.args.len() {
                with(&|a| a.args[index].name.push('x'));
                with(&|a| {
                    if let Some(spec) = other.args.first() {
                        a.args[index].matcher = spec.matcher.clone();
                    }
                });
                with(&|a| {
                    if let Some(spec) = other.args.first() {
                        a.args[index].repeat = spec.repeat;
                    }
                });
                with(&|a| match &mut a.args[index].matcher {
                    Matcher::Literal(s) | Matcher::PathUnder { prefix: s } => s.push('x'),
                    Matcher::OneOf(v) => v.push("x".into()),
                    Matcher::IntRange { lo, .. } => *lo = lo.saturating_sub(1),
                    Matcher::Name(_) => a.args[index].matcher = Matcher::Literal("n".into()),
                    Matcher::Pattern(p) => {
                        *p = AnchoredPattern::new(&format!("{}z", p.source())).unwrap();
                    }
                });
                // One field at a time, each directly, so that none depends on
                // the other action happening to differ in it.
                with(&|a| {
                    if let Matcher::IntRange { hi, .. } = &mut a.args[index].matcher {
                        *hi = hi.saturating_add(1);
                    }
                });
                with(&|a| {
                    if let Repeat::Between { min, .. } = &mut a.args[index].repeat {
                        *min = min.saturating_add(1);
                    }
                });
                with(&|a| {
                    if let Repeat::Between { max, .. } = &mut a.args[index].repeat {
                        *max = max.saturating_add(1);
                    }
                });
                for kind in ALL_NAME_KINDS {
                    with(&|a| {
                        if matches!(a.args[index].matcher, Matcher::Name(_)) {
                            a.args[index].matcher = Matcher::Name(kind);
                        }
                    });
                }
            }
            out
        }

        fn lone(matcher: Matcher) -> Action {
            Action {
                id: ActionId::new("lone.one"),
                tier: Tier::DiagRead,
                exe: "/usr/bin/true".to_owned(),
                args: vec![ArgSpec::one("a", matcher)],
                confirm: ConfirmPolicy::Default,
                agent_allowed: false,
                env_allow: Vec::new(),
                harness: Vec::new(),
                outcome: Outcome::Allow,
                gtfobins_waiver: None,
                source: Source::new("p.toml", 1),
            }
        }

        #[test]
        fn the_same_bytes_under_different_matchers_are_different_policy() {
            let kind_words = ["deb-name", "hostname", "unit-name", "service-unit-name"];
            let texts = ["a", "", "/etc", "/", "a/b"];
            let texts = texts.into_iter().take(SAME_TEXTS);
            for text in texts.chain(kind_words) {
                let mut forms = vec![
                    Matcher::Literal(text.into()),
                    Matcher::PathUnder {
                        prefix: text.into(),
                    },
                    Matcher::OneOf(vec![text.into()]),
                ];
                forms.extend(
                    [text]
                        .into_iter()
                        .take(PATTERNS)
                        .map(|t| Matcher::Pattern(AnchoredPattern::new(t).unwrap())),
                );
                let forms: Vec<_> = forms.into_iter().map(|m| policy_form(&lone(m))).collect();
                for (i, a) in forms.iter().enumerate() {
                    for b in &forms[i + 1..] {
                        assert_ne!(a, b, "{text:?}");
                    }
                }
            }
            // A name kind is not the literal spelled like it.
            assert_ne!(
                policy_form(&lone(Matcher::Name(NameKind::Hostname))),
                policy_form(&lone(Matcher::Literal("hostname".into())))
            );
        }

        #[test]
        fn every_name_kind_and_every_confirm_policy_is_its_own_form() {
            let kinds: Vec<_> = ALL_NAME_KINDS
                .iter()
                .map(|k| policy_form(&lone(Matcher::Name(*k))))
                .collect();
            let confirms: Vec<_> = ALL_CONFIRMS
                .iter()
                .map(|c| {
                    let mut a = lone(Matcher::Literal("x".into()));
                    a.confirm = *c;
                    policy_form(&a)
                })
                .collect();
            for set in [kinds, confirms] {
                for (i, a) in set.iter().enumerate() {
                    for b in &set[i + 1..] {
                        assert_ne!(a, b);
                    }
                }
            }
        }

        #[test]
        fn every_one_field_change_of_the_fixed_actions_changes_the_form() {
            let all = fixed_actions();
            for base in all.iter().take(FIXED_BASES) {
                for other in &all {
                    for mutated in mutations(base, other) {
                        if &mutated != base {
                            assert_ne!(policy_form(&mutated), policy_form(base));
                        }
                    }
                }
            }
        }

        // Miri runs the interpreter a thousand times slower: a handful of
        // cases there still draws every strategy, and the normal run keeps
        // proptest's 256.
        proptest! {
            #![proptest_config(ProptestConfig {
                // One name kind more lengthens every mutation. Two cases still
                // build every strategy; the full 256 is the non-miri run.
                cases: if cfg!(miri) { 2 } else { 256 },
                // Miri's isolation refuses the regression file's I/O.
                failure_persistence: if cfg!(miri) {
                    None
                } else {
                    ProptestConfig::default().failure_persistence
                },
                ..ProptestConfig::default()
            })]

            #[test]
            fn any_decision_relevant_difference_changes_the_canonical_form(
                base in action(),
                other in action(),
            ) {
                for mutated in mutations(&base, &other) {
                    if mutated != base {
                        prop_assert_ne!(policy_form(&mutated), policy_form(&base), "{:?} vs {:?}", mutated, base);
                    }
                }
            }

            #[test]
            fn equal_policy_gives_equal_form_whatever_the_provenance(
                base in action(),
                line in 1u32..9999,
            ) {
                let mut moved = base.clone();
                moved.source = Source::new("q.toml", line);
                prop_assert_eq!(policy_form(&moved), policy_form(&base));
            }
        }
    }

    #[test]
    fn a_ruleset_over_the_test_bound_is_refused_whatever_the_file_split() {
        let one = "[[test]]\nargv = [\"/x\"]\nexpect = \"deny\"\n";
        let full = one.repeat(crate::rule::MAX_TESTS_PER_FILE);
        let files = |n: usize| -> Vec<RuleFile> {
            (0..n).map(|i| file(&format!("{i}.toml"), &full)).collect()
        };
        let fit = 4;
        assert_eq!(fit * crate::rule::MAX_TESTS_PER_FILE, MAX_TESTS);
        assert_eq!(load_rule_files(files(fit)).unwrap().tests.len(), MAX_TESTS);
        let err = load_rule_files(files(fit + 1)).unwrap_err();
        assert_eq!(err, RuleFilesError::TooManyTests { limit: MAX_TESTS });
        assert!(err.to_string().contains(&MAX_TESTS.to_string()), "{err}");
    }
}
