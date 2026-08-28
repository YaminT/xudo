//! Loading the root-owned ruleset from disk.
//!
//! The parsing lives in `aido-policy`, which is pure; the reading lives here,
//! because the front-end is allowed to touch the filesystem and the policy
//! engine is not.
//!
//! # What this does not check yet
//!
//! Ownership and mode. The design requires refusing to load if any path
//! *component* is group- or world-writable, is a symlink, or sits on a
//! filesystem mounted by a non-root user, verified on the opened descriptor via
//! `fstat` rather than on the path string. That check needs `openat2` and the
//! ancestor walk, which arrive with M2 in `aido-sys`.
//!
//! It is safe to omit today only because nothing here can execute anything: the
//! worst a tampered ruleset can currently do is make `aido explain` print a
//! wrong answer to a human who asked a question. The moment an exec path exists,
//! this becomes a hole, so it is a stated precondition of M2 rather than a
//! nice-to-have.

use std::path::{Path, PathBuf};

use aido_policy::{Action, RuleSet};
use sha2::{Digest, Sha256};

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

    /// A stable hash over every rule file's contents.
    ///
    /// Stamped into generated agent documentation so CI can detect drift
    /// between what the docs promise and what the policy permits. Order-stable
    /// because the files are loaded in sorted order.
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Loads every `*.toml` under `dir`.
    ///
    /// Files are read in **lexical order of file name**, which is systemd's and
    /// polkit's convention and the one operators already expect. A file that
    /// fails to parse fails the whole load: a partially-loaded ruleset is a
    /// ruleset whose contents nobody reviewed.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::Directory`] if the directory cannot be read,
    /// [`LoadError::Read`] for an unreadable file, [`LoadError::NotUtf8`] for a
    /// file that is not text, and [`LoadError::Policy`] for anything the policy
    /// engine rejects.
    pub fn from_dir(dir: &Path) -> Result<Self, LoadError> {
        // The entry's own file name is kept alongside the path, because
        // `read_dir` always supplies one whereas `Path::file_name` has a `None`
        // case that cannot arise here.
        //
        // Rendered with `Path::display`, which is this project's one permitted
        // lossy conversion and only ever for text shown to a human — here, the
        // provenance in a trace. It is never compared against anything, so the
        // reason `to_string_lossy` is banned in a matcher does not apply. See
        // CLAUDE.md § "Banned in privileged code".
        let mut entries: Vec<(PathBuf, String)> = std::fs::read_dir(dir)
            .map_err(|e| LoadError::Directory {
                dir: dir.display().to_string(),
                reason: e.to_string(),
            })?
            .filter_map(Result::ok)
            .map(|entry| {
                let name = Path::new(&entry.file_name()).display().to_string();
                (entry.path(), name)
            })
            .filter(|(path, _)| path.extension().is_some_and(|ext| ext == "toml"))
            .collect();
        entries.sort();

        let mut actions: Vec<Action> = Vec::new();
        let mut hasher = Sha256::new();

        for (path, name) in &entries {
            let bytes = std::fs::read(path).map_err(|e| LoadError::Read {
                file: path.display().to_string(),
                reason: e.to_string(),
            })?;
            let text = String::from_utf8(bytes).map_err(|_| LoadError::NotUtf8 {
                file: path.display().to_string(),
            })?;

            // The file name, not the full path, is what a decision cites, so a
            // trace reads identically whether the rules came from /etc or a
            // checkout.
            hasher.update(name.as_bytes());
            hasher.update(text.as_bytes());

            let set = RuleSet::from_toml(name, &text).map_err(|e| LoadError::Policy {
                file: name.clone(),
                reason: e.to_string(),
            })?;
            actions.extend(set.actions().iter().cloned());
        }

        let rules = RuleSet::load(actions).map_err(|e| LoadError::Policy {
            file: dir.display().to_string(),
            reason: e.to_string(),
        })?;

        Ok(Self {
            rules,
            files: entries.into_iter().map(|(path, _)| path).collect(),
            generation: format!("{:x}", hasher.finalize()),
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
    /// A rule file was not valid UTF-8.
    ///
    /// Rejected rather than read lossily: a rule file whose bytes do not mean
    /// what they appear to mean is not a rule file anyone reviewed.
    #[error("{file} is not valid UTF-8; a rule file must be text")]
    NotUtf8 {
        /// The file.
        file: String,
    },
    /// The policy engine rejected the ruleset.
    #[error("{file}: {reason}")]
    Policy {
        /// The file, or the directory for a whole-set failure.
        file: String,
        /// The engine's account of why.
        reason: String,
    },
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
        let fx = Fixture::new("ignore-non-toml")
            .write("10-a.toml", ONE_ACTION)
            .write("README.md", "not a rule file")
            .write("10-a.toml.bak", "also not");
        let loaded = fx.load().unwrap();
        assert_eq!(loaded.files().len(), 1);
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
