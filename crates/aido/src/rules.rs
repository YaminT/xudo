//! Loading the root-owned ruleset from disk.
//!
//! The parsing lives in `aido-policy`, which is pure; the reading lives here,
//! because the front-end is allowed to touch the filesystem and the policy
//! engine is not.
//!
//! # What this does not check, and where that check lives
//!
//! Ownership, mode, and mounts. This loader is the unprivileged front-end's, and
//! it reads by path so `aido explain` works on a checkout. The check the
//! privileged gate must use is `aido_sys::read_trusted_dir`: every component
//! opened through its parent's descriptor without following a link, every rule
//! file checked on its own descriptor, the mount under each refused if a
//! non-root user could have made it, and the bytes read through that same
//! descriptor. `aido doctor` already reports through it.
//!
//! Reading by path here is safe only because nothing here can execute anything:
//! the worst a tampered ruleset can do through this loader is make `aido
//! explain` print a wrong answer to a human who asked a question. When the gate
//! binary is written, it loads through `read_trusted_dir` and nothing else.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use aido_policy::{RuleFile, RuleFilesError, RuleSet, is_rule_file_name, load_rule_files};

/// The default location of the root-owned rule files.
pub const DEFAULT_RULES_DIR: &str = "/etc/aido/rules.d";

/// A loaded ruleset, with the provenance needed to talk about it.
#[derive(Clone, Debug)]
pub struct LoadedRules {
    rules: RuleSet,
    files: Vec<PathBuf>,
    generation: String,
}

impl LoadedRules {
    /// The validated ruleset.
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// The files that were read, in load order.
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// Which policy this is, as the 64 hex characters of
    /// [`aido_policy::Generation`].
    ///
    /// Stamped into generated agent documentation so CI can detect drift
    /// between what the docs promise and what the policy permits. Computed by
    /// the same function the broker and the gate use, so the front-end names
    /// the generation they will compare against.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Loads every rule file under `dir`.
    ///
    /// Which entries are rule files, the order they are evaluated in, and the
    /// generation are all decided by [`aido_policy::load_rule_files`], the one
    /// function every reader of the ruleset shares. This reads the bytes by
    /// path; the privileged binaries read them through verified descriptors
    /// and hand them to the same function. A file that fails to parse fails the
    /// whole load: a partially-loaded ruleset is a ruleset whose contents nobody
    /// reviewed.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::Directory`] if the directory cannot be read,
    /// [`LoadError::Read`] for an unreadable file, and [`LoadError::Rules`] for
    /// a file name or contents that are not UTF-8 or anything the policy engine
    /// rejects.
    pub fn from_dir(dir: &Path) -> Result<Self, LoadError> {
        // Rendered with `Path::display`, which is this project's one permitted
        // lossy conversion and only ever for text shown to a human. The bytes
        // that are compared and hashed are the entry's own name, untouched.
        // See CLAUDE.md § "Banned in privileged code".
        let mut entries: Vec<(PathBuf, OsString)> = std::fs::read_dir(dir)
            .map_err(|e| LoadError::Directory {
                dir: dir.display().to_string(),
                reason: e.to_string(),
            })?
            .filter_map(Result::ok)
            .map(|entry| (entry.path(), entry.file_name()))
            .filter(|(_, name)| is_rule_file_name(name.as_bytes()))
            .collect();
        entries.sort();

        let mut files = Vec::new();
        for (path, name) in &entries {
            let bytes = std::fs::read(path).map_err(|e| LoadError::Read {
                file: path.display().to_string(),
                reason: e.to_string(),
            })?;
            files.push(RuleFile {
                name: name.as_bytes().to_vec(),
                bytes,
            });
        }

        let loaded = load_rule_files(files)?;
        Ok(Self {
            rules: loaded.rules,
            files: entries.into_iter().map(|(path, _)| path).collect(),
            generation: loaded.generation.hex(),
        })
    }
}

/// Why a ruleset could not be loaded. Every variant fails closed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LoadError {
    /// The rules directory could not be listed.
    #[error("cannot read the rules directory {dir}: {reason}")]
    Directory {
        /// The directory.
        dir: String,
        /// Why it could not be read.
        reason: String,
    },
    /// A rule file could not be read.
    #[error("cannot read {file}: {reason}")]
    Read {
        /// The file.
        file: String,
        /// Why it could not be read.
        reason: String,
    },
    /// The files were read but are not a ruleset: a name or contents that are
    /// not UTF-8, or anything the policy engine refuses.
    ///
    /// Transparent, because [`RuleFilesError`] already names the file, and it
    /// is the same refusal the broker and the gate would report for the same
    /// bytes.
    #[error(transparent)]
    Rules(#[from] RuleFilesError),
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    /// Root for throwaway fixture directories.
    ///
    /// Under the workspace `target/` directory, never `/tmp`: a predictable
    /// path in a world-writable directory is a symlink race, and this project's
    /// own rules forbid it.
    fn test_tmp_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
    }

    /// Writes rule files into a fresh directory under the target dir.
    ///
    /// Deliberately not `/tmp`: a predictable path in a world-writable
    /// directory is a symlink race, and this project's own rules forbid it.
    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = test_tmp_root().join(name);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn write(self, file: &str, contents: &str) -> Self {
            std::fs::write(self.dir.join(file), contents).unwrap();
            self
        }

        fn load(&self) -> Result<LoadedRules, LoadError> {
            LoadedRules::from_dir(&self.dir)
        }
    }

    const ONE_ACTION: &str = r#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#;

    #[test]
    fn a_directory_of_rule_files_loads_in_lexical_order() {
        let fx = Fixture::new("load-order")
            .write("20-b.toml", ONE_ACTION)
            .write(
                "10-a.toml",
                r#"
[[action]]
id = "aido.pkg.update"
tier = "pkg-install"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]
"#,
            );
        let loaded = fx.load().unwrap();
        assert_eq!(loaded.rules().len(), 2);
        assert_eq!(loaded.files().len(), 2);
        // 10- before 20-, which is the convention operators expect.
        assert!(
            loaded
                .files()
                .first()
                .unwrap()
                .display()
                .to_string()
                .contains("10-a"),
        );
        assert!(!loaded.generation().is_empty());
        assert!(format!("{loaded:?}").contains("aido.pkg.update"));
    }

    #[test]
    fn non_toml_files_are_ignored() {
        // `.toml` alone is ignored too: it has no name for a decision to cite,
        // and the privileged readers select with the same predicate.
        let fx = Fixture::new("ignore-non-toml")
            .write("10-a.toml", ONE_ACTION)
            .write("README.md", "not a rule file")
            .write("10-a.toml.bak", "also not")
            .write(".toml", "[[action]]\nid =");
        let loaded = fx.load().unwrap();
        assert_eq!(loaded.files().len(), 1);
    }

    #[test]
    fn the_front_end_stamps_the_generation_the_broker_and_gate_compute() {
        // The front-end prints the generation; the broker writes it into a
        // spool entry; the gate compares. Same bytes, same function, same
        // answer — asserted rather than assumed.
        let other = ONE_ACTION
            .replace("aido.svc.restart", "aido.svc.reload")
            .replace("restart", "reload");
        let loaded = Fixture::new("gen-shared")
            .write("20-b.toml", ONE_ACTION)
            .write("10-a.toml", &other)
            .load()
            .unwrap();
        let shared = load_rule_files(vec![
            RuleFile {
                name: b"20-b.toml".to_vec(),
                bytes: ONE_ACTION.as_bytes().to_vec(),
            },
            RuleFile {
                name: b"10-a.toml".to_vec(),
                bytes: other.into_bytes(),
            },
        ])
        .unwrap();
        assert_eq!(loaded.generation(), shared.generation.hex());
        assert_eq!(loaded.rules(), &shared.rules);
    }

    /// Linux only: APFS refuses to create a name that is not UTF-8, so the
    /// case cannot be built on a macOS host. The refusal itself is pure and
    /// is tested in `aido_policy::files` on every platform.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_rule_file_whose_name_is_not_utf8_is_refused_rather_than_cited_lossily() {
        use std::os::unix::ffi::OsStringExt;

        let fx = Fixture::new("name-not-utf8");
        let name = std::ffi::OsString::from_vec(b"10-\xff.toml".to_vec());
        std::fs::write(fx.dir.join(name), ONE_ACTION).unwrap();
        let err = fx.load().unwrap_err();
        assert!(err.to_string().contains("10-\\xff.toml"), "{err}");
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    #[test]
    fn an_empty_directory_loads_an_empty_ruleset() {
        // Permits nothing, which is the right default for a fresh install.
        let loaded = Fixture::new("empty-dir").load().unwrap();
        assert!(loaded.rules().is_empty());
        assert!(loaded.files().is_empty());
    }

    #[test]
    fn a_missing_directory_is_an_error_naming_the_path() {
        let missing = test_tmp_root().join("definitely-not-here");
        let err = LoadedRules::from_dir(&missing).unwrap_err();
        assert!(
            err.to_string().contains("cannot read the rules directory"),
            "{err}"
        );
        assert!(err.to_string().contains("definitely-not-here"));
    }

    #[test]
    fn a_malformed_rule_file_fails_the_whole_load() {
        // Not "load what parses and warn about the rest": a partially-loaded
        // ruleset is a ruleset nobody reviewed.
        let fx = Fixture::new("malformed")
            .write("10-good.toml", ONE_ACTION)
            .write("20-bad.toml", "[[action]\nid =");
        let err = fx.load().unwrap_err();
        assert!(err.to_string().contains("20-bad.toml"), "{err}");
    }

    #[test]
    fn an_unknown_key_fails_the_load() {
        let fx = Fixture::new("unknown-key").write(
            "10-a.toml",
            r#"
[[action]]
id = "aido.x"
tier = "diag-read"
exe = "/usr/bin/true"
nopasswd = true
"#,
        );
        let err = fx.load().unwrap_err();
        assert!(err.to_string().contains("nopasswd"), "{err}");
    }

    #[test]
    fn a_duplicate_id_across_two_files_fails_the_combined_load() {
        let fx = Fixture::new("dup-id")
            .write("10-a.toml", ONE_ACTION)
            .write("20-b.toml", ONE_ACTION);
        let err = fx.load().unwrap_err();
        assert!(err.to_string().contains("duplicate action id"), "{err}");
    }

    #[test]
    fn a_non_utf8_rule_file_is_refused_rather_than_read_lossily() {
        let fx = Fixture::new("not-utf8");
        std::fs::write(fx.dir.join("10-a.toml"), [0xff, 0xfe, 0xfd]).unwrap();
        let err = fx.load().unwrap_err();
        assert!(err.to_string().contains("must be text"), "{err}");
    }

    #[test]
    fn the_generation_hash_changes_with_content_and_is_stable_without() {
        let a = Fixture::new("gen-a")
            .write("10-a.toml", ONE_ACTION)
            .load()
            .unwrap();
        let b = Fixture::new("gen-b")
            .write("10-a.toml", ONE_ACTION)
            .load()
            .unwrap();
        assert_eq!(a.generation(), b.generation(), "same content, same hash");

        let c = Fixture::new("gen-c")
            .write("10-a.toml", &ONE_ACTION.replace("restart", "reload"))
            .load()
            .unwrap();
        assert_ne!(
            a.generation(),
            c.generation(),
            "changed content, changed hash"
        );

        // The file name is hashed too, so moving a rule between files is a
        // change — it changes the file:line a decision cites.
        let d = Fixture::new("gen-d")
            .write("99-z.toml", ONE_ACTION)
            .load()
            .unwrap();
        assert_ne!(a.generation(), d.generation());
    }

    #[test]
    fn a_read_failure_on_a_listed_file_is_reported() {
        // A directory named `*.toml` lists as an entry but cannot be read as a
        // file, which exercises the read-failure path without racing anything.
        let fx = Fixture::new("unreadable");
        std::fs::create_dir_all(fx.dir.join("10-a.toml")).unwrap();
        let err = fx.load().unwrap_err();
        assert!(err.to_string().starts_with("cannot read"), "{err}");
    }

    #[test]
    fn the_default_rules_directory_is_the_root_owned_one() {
        assert_eq!(DEFAULT_RULES_DIR, "/etc/aido/rules.d");
    }
}
