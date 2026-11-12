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

use crate::rule::{Action, RuleSet, RuleSetError, Source};
use crate::rule_test::RuleTest;

/// The suffix that makes a directory entry a rule file.
pub const RULE_FILE_SUFFIX: &[u8] = b".toml";

/// Separates this hash from every other SHA-256 the project computes, and
/// names the framing version so a later change cannot collide with this one.
const GENERATION_DOMAIN: &[u8] = b"xudo.ruleset.generation.v2\0";

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

/// Which policy a set of rule files is.
///
/// A SHA-256 over every rule file's name and the actions it defines, in name
/// order, each field length-prefixed. The prefixes matter: hashing names and
/// contents back to back would give `1.toml` holding `#a2.toml#b` the same
/// generation as `1.toml` holding `#a` beside `2.toml` holding `#b`, two
/// different rulesets that a stale request could not tell apart.
///
/// The actions are hashed as parsed, not the file's bytes, so that what is not
/// policy is not in the digest: a `[[test]]` table (see [`crate::rule_test`]),
/// a comment, and the line an action sits on can all change without
/// invalidating a request minted under the same rules. Anything that can
/// change a decision is a field of [`Action`], and is hashed.
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
pub fn load_rule_files(mut files: Vec<RuleFile>) -> Result<LoadedRuleSet, RuleFilesError> {
    files.sort_by(|a, b| a.name.cmp(&b.name));

    let mut hasher = Sha256::new();
    hasher.update(GENERATION_DOMAIN);
    let mut actions: Vec<Action> = Vec::new();
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

        framed(&mut hasher, &file.name);
        for action in parsed.actions() {
            framed(&mut hasher, &policy_form(action));
        }
        // Closes the file, so the last action of one cannot be read as the
        // first of the next.
        framed(&mut hasher, b"");

        actions.extend(parsed.actions().iter().cloned());
        tests.extend(file_tests);
    }

    Ok(LoadedRuleSet {
        rules: RuleSet::load(actions)?,
        generation: Generation(hasher.finalize().into()),
        tests,
    })
}

/// Everything about an action that can change a decision, as bytes.
///
/// The derived `Debug` of the action with its line zeroed: every field is in it,
/// so a field added to [`Action`] is in the digest without anyone remembering to
/// add it, and the pinned digest in this module's tests fails to say so. The
/// line is zeroed because where an action sits in its file is provenance, not
/// policy.
fn policy_form(action: &Action) -> Vec<u8> {
    let mut action = action.clone();
    action.source = Source::new(action.source.file, 0);
    format!("{action:?}").into_bytes()
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
        // Moving a rule between files changes the file:line a decision cites,
        // so it is a different policy even when the rules are identical.
        assert_ne!(base, renamed);
        assert_ne!(base, edited);
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
            "82afb2b3a3764f8d324ce81d8245ffd8f6580383e91f11a87a96262af61f3230"
        );
        assert_eq!(
            generation(Vec::new()).hex(),
            "8890096d8c109ed7990ff882e1664a56d674b25f7cff7539a22ae46efcf6fd94"
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
            generation(vec![file("10-a.toml", "# nothing")])
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
        assert!(err.to_string().contains("duplicate action id"), "{err}");
        assert!(format!("{err:?}").contains("DuplicateId"));
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
}
