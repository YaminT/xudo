//! Where `/proc` content comes from.
//!
//! Every read goes through [`ProcSource`], so the parsing and walking logic on
//! top can be driven by an in-memory map in tests. That is what lets the whole
//! provenance layer be covered on a macOS host with no `/proc` in sight.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::SysError;

/// A read-only view of a `/proc`-shaped tree.
///
/// Paths are relative to the root and always use `/`, e.g. `"self/stat"` or
/// `"412/cgroup"`.
pub trait ProcSource {
    /// Reads one file's bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Read`] when the file is absent or unreadable. An
    /// absent file is an ordinary outcome — a process can exit between two
    /// reads — and callers must treat it as "cannot attest", never as "nothing
    /// to worry about".
    fn read(&self, relative: &str) -> Result<Vec<u8>, SysError>;

    /// Reads one file as UTF-8, replacing invalid sequences.
    ///
    /// Only for content that is genuinely text by kernel contract: `stat`,
    /// `cgroup`, `mountinfo`. **Never** for `cmdline`, `environ`, or a resolved
    /// `exe` path, which are arbitrary bytes; those go through [`Self::read`]
    /// and stay as bytes, because a lossy conversion there is how two different
    /// values start comparing equal.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::read`]'s failure.
    fn read_text(&self, relative: &str) -> Result<String, SysError> {
        let bytes = self.read(relative)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// A source backed by a real directory.
///
/// Pointed at `/proc` in production and at a fixture tree in tests, which is
/// the same code path either way — a fixture that exercises different code than
/// production is a fixture that proves less than it appears to.
#[derive(Clone, Debug)]
pub struct DirSource {
    root: PathBuf,
}

impl DirSource {
    /// Builds a source rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Builds a source rooted at the real `/proc`.
    pub fn proc() -> Self {
        Self::new("/proc")
    }

    /// The root this source reads from.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Joins a relative path, refusing anything that could leave the root.
    ///
    /// This is a lexical check, not a resolution: it stops an obvious mistake
    /// rather than a determined attacker, and it does not need to stop one.
    /// Nothing read through this type can authorize anything, so the worst a
    /// traversal could achieve is reading a file the caller can already read as
    /// themselves. The symlink-resistant `openat2` resolution belongs on the
    /// exec path, where a lie does have consequences.
    fn resolve(&self, relative: &str) -> Result<PathBuf, SysError> {
        if relative.is_empty() {
            return Err(SysError::read(relative, "empty path"));
        }
        if relative.starts_with('/') {
            return Err(SysError::read(
                relative,
                "path must be relative to the root",
            ));
        }
        if relative
            .split('/')
            .any(|c| c == ".." || c == "." || c.is_empty())
        {
            return Err(SysError::read(
                relative,
                "path must not contain an empty, current, or parent component",
            ));
        }
        Ok(self.root.join(relative))
    }
}

impl ProcSource for DirSource {
    fn read(&self, relative: &str) -> Result<Vec<u8>, SysError> {
        let path = self.resolve(relative)?;
        std::fs::read(&path).map_err(|e| SysError::read(relative, e.to_string()))
    }
}

/// An in-memory source, for tests.
#[derive(Clone, Debug, Default)]
pub struct MapSource {
    files: BTreeMap<String, Vec<u8>>,
}

impl MapSource {
    /// Builds an empty source. Every read fails, which is the fail-closed case.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a file.
    #[must_use]
    pub fn with(mut self, relative: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.insert(relative.into(), contents.into());
        self
    }

    /// How many files the source holds.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the source is empty.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

impl ProcSource for MapSource {
    fn read(&self, relative: &str) -> Result<Vec<u8>, SysError> {
        self.files
            .get(relative)
            .cloned()
            .ok_or_else(|| SysError::read(relative, "not present in the in-memory source"))
    }
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

    #[test]
    fn a_map_source_returns_what_was_put_in_it() {
        let source = MapSource::new()
            .with("1/stat", "1 (init) S 0")
            .with("1/cgroup", "0::/init.scope");
        assert_eq!(source.len(), 2);
        assert!(!source.is_empty());
        assert_eq!(source.read("1/stat").unwrap(), b"1 (init) S 0");
        assert_eq!(source.read_text("1/cgroup").unwrap(), "0::/init.scope");
        assert!(format!("{source:?}").contains("1/stat"));
    }

    #[test]
    fn an_empty_map_source_fails_every_read() {
        // The fail-closed case, and the default.
        let source = MapSource::default();
        assert!(source.is_empty());
        let err = source.read("1/stat").unwrap_err();
        assert!(err.to_string().contains("not present"));
    }

    #[test]
    fn read_text_replaces_invalid_utf8_rather_than_failing() {
        // Only for kernel-text files. The replacement is why cmdline and
        // environ must never come through this method.
        let source = MapSource::new().with("x", vec![0xff, b'a']);
        assert_eq!(source.read_text("x").unwrap(), "\u{fffd}a");
    }

    #[test]
    fn a_dir_source_reads_a_real_fixture_tree() {
        let source = DirSource::new(fixture_root());
        assert_eq!(source.root(), fixture_root().as_path());
        let stat = source.read_text("100/stat").unwrap();
        assert!(stat.starts_with("100 "), "{stat}");
        assert!(format!("{source:?}").contains("fixtures"));
    }

    #[test]
    fn a_dir_source_reports_a_missing_file_rather_than_inventing_one() {
        let source = DirSource::new(fixture_root());
        let err = source.read("999999/stat").unwrap_err();
        assert!(err.to_string().contains("999999/stat"), "{err}");
        // The text reader propagates the same failure rather than yielding an
        // empty string, which a caller could mistake for an empty file.
        let text_err = source.read_text("999999/stat").unwrap_err();
        assert_eq!(err, text_err);
    }

    #[test]
    fn the_production_root_is_proc() {
        assert_eq!(DirSource::proc().root(), Path::new("/proc"));
    }

    #[test]
    fn a_dir_source_refuses_paths_that_could_leave_the_root() {
        let source = DirSource::new(fixture_root());
        for bad in [
            "",
            "/etc/passwd",
            "../../etc/passwd",
            "100/../../etc/passwd",
            "./100/stat",
            "100//stat",
        ] {
            let err = source.read(bad).unwrap_err();
            assert!(
                err.to_string().contains("cannot read"),
                "{bad:?} gave {err}"
            );
        }
        // And the well-formed version of the same path still works, so the
        // check is not simply refusing everything.
        assert!(source.read("100/stat").is_ok());
    }

    #[test]
    fn a_source_is_usable_behind_a_trait_object() {
        // The provenance layer takes `&dyn ProcSource`, so this has to work.
        let owned = MapSource::new().with("a", "b");
        let as_dyn: &dyn ProcSource = &owned;
        assert_eq!(as_dyn.read("a").unwrap(), b"b");
        let dir: &dyn ProcSource = &DirSource::new(fixture_root());
        assert!(dir.read("100/stat").is_ok());
    }

    fn fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("proc")
    }
}
