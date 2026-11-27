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

    /// The inode of the namespace a `ns/<kind>` link names, e.g.
    /// `"412/ns/user"`. Two processes share a namespace exactly when these
    /// numbers are equal.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Read`] when the link cannot be followed, or does
    /// not lead to a namespace file. Callers treat that as "cannot attest".
    fn namespace_inode(&self, relative: &str) -> Result<u64, SysError>;

    /// The inode a link under the root leads to (for example `"self/exe"`),
    /// opened through this source and not by a path of its own.
    ///
    /// The default refuses: a source that cannot open a file through its own
    /// descriptor cannot vouch for what a link leads to.
    ///
    /// # Errors
    ///
    /// Returns [`SysError`] when the link cannot be opened or inspected.
    fn file_identity(&self, relative: &str) -> Result<crate::FileId, SysError> {
        Err(SysError::read(
            relative,
            "this source cannot identify the file a link leads to",
        ))
    }

    /// The target of a link under the root (for example `"412/exe"`), as the
    /// bytes the kernel reports, never the file it leads to. For the audit
    /// trail only: a link's text is not a path anything may open.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Read`] when the link cannot be read. The default
    /// refuses: a source that keeps no links has none to report.
    fn read_link(&self, relative: &str) -> Result<Vec<u8>, SysError> {
        Err(SysError::read(relative, "this source keeps no links"))
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
    /// Do not mistake it for protection of an authorization decision. The
    /// broker reads the identity pin (`/proc/<pid>/stat`, `status`) through
    /// this type, by path, and nothing checks that the root is a procfs: the
    /// pin is only as true as the `/proc` of the process that reads it. That
    /// holds because the broker runs in root's own mount namespace, where an
    /// unprivileged caller cannot replace `/proc`, and because the pidfd
    /// re-check, not this read, is what ties the number to the process. The
    /// symlink-resistant `openat2` resolution belongs on the exec path, where
    /// a lie hands out root.
    fn resolve(&self, relative: &str) -> Result<PathBuf, SysError> {
        check_relative(relative)?;
        Ok(self.root.join(relative))
    }
}

/// Reads at most `cap` bytes of `reader`, however much it holds.
///
/// For a file a caller controls the size of, like `/proc/<pid>/cmdline`,
/// which the kernel lets reach about 6 MiB: the bound is on the read, so
/// nothing past it is ever copied.
///
/// # Errors
///
/// Returns the reader's error.
pub fn read_prefix(reader: &mut dyn std::io::Read, cap: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut bytes = Vec::new();
    reader.take(cap).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl DirSource {
    /// The first `cap` bytes of a file under the root, never more.
    ///
    /// # Errors
    ///
    /// Returns [`SysError::Read`] when the file cannot be opened or read.
    pub fn read_prefix(&self, relative: &str, cap: u64) -> Result<Vec<u8>, SysError> {
        let path = self.resolve(relative)?;
        std::fs::File::open(&path)
            .and_then(|mut file| read_prefix(&mut file, cap))
            .map_err(|e| SysError::read(relative, e.to_string()))
    }
}

/// Refuses a path that is empty, absolute, or has an empty, current, or parent
/// component: the lexical rule every source holds its relative paths to.
pub(crate) fn check_relative(relative: &str) -> Result<(), SysError> {
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
    Ok(())
}

impl ProcSource for DirSource {
    fn read(&self, relative: &str) -> Result<Vec<u8>, SysError> {
        let path = self.resolve(relative)?;
        std::fs::read(&path).map_err(|e| SysError::read(relative, e.to_string()))
    }

    fn namespace_inode(&self, relative: &str) -> Result<u64, SysError> {
        use std::os::unix::fs::MetadataExt as _;

        let path = self.resolve(relative)?;
        std::fs::metadata(&path)
            .map(|meta| meta.ino())
            .map_err(|e| SysError::read(relative, e.to_string()))
    }

    fn read_link(&self, relative: &str) -> Result<Vec<u8>, SysError> {
        use std::os::unix::ffi::OsStringExt as _;

        let path = self.resolve(relative)?;
        std::fs::read_link(&path)
            .map(|target| target.into_os_string().into_vec())
            .map_err(|e| SysError::read(relative, e.to_string()))
    }
}

/// An in-memory source, for tests.
#[derive(Clone, Debug, Default)]
pub struct MapSource {
    files: BTreeMap<String, Vec<u8>>,
    inodes: BTreeMap<String, u64>,
    links: BTreeMap<String, Vec<u8>>,
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

    /// Adds a namespace link and the inode it leads to.
    #[must_use]
    pub fn with_inode(mut self, relative: impl Into<String>, inode: u64) -> Self {
        self.inodes.insert(relative.into(), inode);
        self
    }

    /// Adds a link and the text it holds.
    #[must_use]
    pub fn with_link(mut self, relative: impl Into<String>, target: impl Into<Vec<u8>>) -> Self {
        self.links.insert(relative.into(), target.into());
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

    fn namespace_inode(&self, relative: &str) -> Result<u64, SysError> {
        self.inodes
            .get(relative)
            .copied()
            .ok_or_else(|| SysError::read(relative, "not present in the in-memory source"))
    }

    fn read_link(&self, relative: &str) -> Result<Vec<u8>, SysError> {
        self.links
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
    fn a_source_that_cannot_open_a_link_refuses_to_identify_it() {
        let error = MapSource::new().file_identity("self/exe").unwrap_err();
        assert!(error.to_string().contains("cannot identify"), "{error}");
    }

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
    fn a_map_source_answers_a_namespace_inode_only_where_one_was_put() {
        let source = MapSource::new().with_inode("1/ns/user", 4_026_531_837);
        assert_eq!(source.namespace_inode("1/ns/user").unwrap(), 4_026_531_837);
        assert!(source.namespace_inode("2/ns/user").is_err());
    }

    #[test]
    fn a_dir_source_reports_the_inode_of_a_file_and_refuses_a_missing_or_escaping_path() {
        use std::os::unix::fs::MetadataExt as _;

        let source = DirSource::new(fixture_root());
        let want = std::fs::metadata(fixture_root().join("100/stat"))
            .unwrap()
            .ino();
        assert_eq!(source.namespace_inode("100/stat").unwrap(), want);
        assert!(source.namespace_inode("999999/ns/user").is_err());
        assert!(source.namespace_inode("../x").is_err());
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

    /// A reader of `size` bytes that counts how many it handed out.
    struct Counting {
        left: usize,
        handed: usize,
    }

    impl std::io::Read for Counting {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.left);
            buf.iter_mut().take(n).for_each(|byte| *byte = b'x');
            self.left -= n;
            self.handed += n;
            Ok(n)
        }
    }

    #[test]
    fn a_six_mib_file_is_read_only_up_to_the_cap() {
        // The largest `cmdline` the kernel lets a caller make: the root
        // broker must not copy it to keep a few hundred bytes.
        let mut file = Counting {
            left: 6 << 20,
            handed: 0,
        };
        let bytes = read_prefix(&mut file, 64 * 1024 + 1).unwrap();
        assert_eq!(bytes.len(), 64 * 1024 + 1);
        assert_eq!(file.handed, 64 * 1024 + 1, "read past the cap");
        let mut short = Counting {
            left: 10,
            handed: 0,
        };
        assert_eq!(read_prefix(&mut short, 64).unwrap(), b"xxxxxxxxxx");
    }

    #[test]
    fn a_reader_that_fails_fails_the_prefix() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken"))
            }
        }
        assert!(read_prefix(&mut Broken, 8).is_err());
    }

    #[test]
    fn a_directory_source_reads_a_prefix_and_refuses_what_it_cannot_open() {
        let dir = DirSource::new(fixture_root());
        let whole = dir.read("100/stat").unwrap();
        assert_eq!(
            dir.read_prefix("100/stat", 5).unwrap(),
            whole.get(..5).unwrap()
        );
        assert_eq!(dir.read_prefix("100/stat", 1 << 20).unwrap(), whole);
        assert!(dir.read_prefix("100/missing", 5).is_err());
        assert!(dir.read_prefix("../100/stat", 5).is_err());
    }

    #[test]
    fn a_link_is_reported_as_its_text_and_never_followed() {
        // `100/exe` is a dangling link in the fixture tree: its text is all
        // there is, so a reader that followed it would fail.
        let dir = DirSource::new(fixture_root());
        assert_eq!(dir.read_link("100/exe").unwrap(), b"/usr/bin/fixture-exe");
        assert!(dir.read_link("100/stat").is_err(), "a file is not a link");
        assert!(dir.read_link("../100/exe").is_err());
        let map = MapSource::new().with_link("1/exe", "/sbin/init");
        assert_eq!(map.read_link("1/exe").unwrap(), b"/sbin/init");
        assert!(map.read_link("2/exe").is_err());
    }

    #[test]
    fn a_source_that_keeps_no_links_reports_none() {
        struct Plain;
        impl ProcSource for Plain {
            fn read(&self, relative: &str) -> Result<Vec<u8>, SysError> {
                Err(SysError::read(relative, "plain"))
            }
            fn namespace_inode(&self, relative: &str) -> Result<u64, SysError> {
                Err(SysError::read(relative, "plain"))
            }
        }
        let error = Plain.read_link("1/exe").unwrap_err();
        assert!(error.to_string().contains("keeps no links"), "{error}");
        assert!(Plain.read("x").is_err());
        assert!(Plain.namespace_inode("x").is_err());
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
