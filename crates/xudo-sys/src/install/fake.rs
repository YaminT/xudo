//! An in-memory [`InstallOps`], for driving the executor through every path.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::{DirLock, FileIdentity, InstallError, InstallOps, Removal, substitute};

/// The inode every candidate this fake writes has.
const WRITTEN: FileIdentity = FileIdentity {
    device: 1,
    inode: 100,
};

/// Records every call, and fails the ones it is told to.
pub(super) struct FakeInstallOps {
    uid: u32,
    calls: RefCell<Vec<String>>,
    failures: BTreeMap<&'static str, (usize, InstallError)>,
    group: bool,
    present: RefCell<BTreeSet<String>>,
    identity: FileIdentity,
    contents: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl FakeInstallOps {
    /// Root, with nothing on the machine and every call succeeding.
    pub(super) fn root() -> Self {
        Self::as_uid(0)
    }

    pub(super) fn as_uid(uid: u32) -> Self {
        Self {
            uid,
            calls: RefCell::new(Vec::new()),
            failures: BTreeMap::new(),
            group: false,
            present: RefCell::new(BTreeSet::new()),
            identity: WRITTEN,
            contents: RefCell::new(BTreeMap::new()),
        }
    }

    /// `path` holds these bytes of xudo's. A candidate path set this way keeps
    /// them when the run writes it, as if the write were tampered with.
    pub(super) fn with_contents(self, path: &str, bytes: &[u8]) -> Self {
        self.contents
            .borrow_mut()
            .insert(path.to_owned(), bytes.to_vec());
        self
    }

    /// Makes `method` fail with the error that method would plausibly raise.
    pub(super) fn failing(self, method: &'static str) -> Self {
        let error = match method {
            "group_exists" | "create_group" => InstallError::Group {
                name: "xudo".to_owned(),
                reason: "scripted".to_owned(),
            },
            "validate" | "validate_whole" => InstallError::ValidatorRejected {
                detail: "scripted".to_owned(),
            },
            _ => InstallError::Io {
                operation: "scripted",
                path: method.to_owned(),
                reason: "scripted".to_owned(),
            },
        };
        self.failing_with(method, error)
    }

    pub(super) fn failing_with(self, method: &'static str, error: InstallError) -> Self {
        self.failing_from(method, 0, error)
    }

    /// Makes `method` fail from its call after the first `succeed` on.
    pub(super) fn failing_from(
        mut self,
        method: &'static str,
        succeed: usize,
        error: InstallError,
    ) -> Self {
        self.failures.insert(method, (succeed, error));
        self
    }

    /// The group already exists.
    pub(super) fn with_group(mut self) -> Self {
        self.group = true;
        self
    }

    /// These paths already hold something of xudo's.
    pub(super) fn with_present(self, paths: &[&str]) -> Self {
        self.present
            .borrow_mut()
            .extend(paths.iter().map(|p| (*p).to_owned()));
        self
    }

    /// The inode `identity` reports from now on, as if the path were swapped.
    pub(super) fn with_identity_after_validate(mut self, identity: FileIdentity) -> Self {
        self.identity = identity;
        self
    }

    /// What `path` holds now, as a test reads it back.
    pub(super) fn holds(&self, path: &str) -> Option<Vec<u8>> {
        self.contents.borrow().get(path).cloned()
    }

    pub(super) fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn record(&self, method: &'static str, detail: &str) -> Result<(), InstallError> {
        let before = self
            .calls
            .borrow()
            .iter()
            .filter(|call| call.split(' ').next() == Some(method))
            .count();
        self.calls
            .borrow_mut()
            .push(format!("{method} {detail}").trim_end().to_owned());
        match self.failures.get(method) {
            Some((succeed, error)) if before >= *succeed => Err(error.clone()),
            _ => Ok(()),
        }
    }

    fn removal(&self, path: &str) -> Removal {
        if self.present.borrow_mut().remove(path) {
            Removal::Removed
        } else {
            Removal::Absent
        }
    }
}

impl InstallOps for FakeInstallOps {
    fn effective_uid(&self) -> u32 {
        self.uid
    }

    fn group_exists(&self, name: &str) -> Result<bool, InstallError> {
        self.record("group_exists", name)?;
        Ok(self.group)
    }

    fn create_group(&self, name: &str) -> Result<(), InstallError> {
        self.record("create_group", name)
    }

    fn write_candidate(
        &self,
        path: &str,
        contents: &[u8],
        _mode: u32,
    ) -> Result<FileIdentity, InstallError> {
        self.record("write_candidate", path)?;
        self.contents
            .borrow_mut()
            .entry(path.to_owned())
            .or_insert_with(|| contents.to_vec());
        Ok(WRITTEN)
    }

    /// A validator that names a candidate is `validate`; one that does not
    /// checks the whole configuration and is `validate_whole`, so a test can
    /// fail the one and not the other.
    fn validate(&self, argv: &[String]) -> Result<(), InstallError> {
        let method = if argv.iter().any(|arg| arg.ends_with(".candidate")) {
            "validate"
        } else {
            "validate_whole"
        };
        self.record(method, &argv.join(" "))
    }

    fn identity(&self, path: &str) -> Result<FileIdentity, InstallError> {
        self.record("identity", path)?;
        Ok(self.identity)
    }

    /// A rename: what was written at `from` is now at `to`.
    fn install(&self, from: &str, to: &str, _identity: FileIdentity) -> Result<(), InstallError> {
        self.record("install", &format!("{from} {to}"))?;
        let mut contents = self.contents.borrow_mut();
        let moved = contents.remove(from);
        contents.extend(moved.map(|bytes| (to.to_owned(), bytes)));
        Ok(())
    }

    fn discard(&self, path: &str, _identity: FileIdentity) -> Result<(), InstallError> {
        self.record("discard", path)
    }

    fn read_managed(&self, path: &str) -> Result<Option<Vec<u8>>, InstallError> {
        self.record("read_managed", path)?;
        Ok(self.contents.borrow().get(path).cloned())
    }

    fn remove_managed(&self, path: &str) -> Result<Removal, InstallError> {
        self.record("remove_managed", path)?;
        self.contents.borrow_mut().remove(path);
        Ok(self.removal(path))
    }

    fn append_block(
        &self,
        path: &str,
        _block: &str,
        validator: &[String],
    ) -> Result<(), InstallError> {
        self.record("append_block", &format!("{path} {}", validator.join(" ")))
    }

    fn remove_block(&self, path: &str) -> Result<Removal, InstallError> {
        self.record("remove_block", path)?;
        Ok(self.removal(path))
    }

    fn lock_dir(&self, path: &str) -> Result<DirLock, InstallError> {
        self.record("lock_dir", path).map(|()| DirLock::default())
    }
}

#[test]
fn the_fake_records_a_directory_lock() {
    let ops = FakeInstallOps::root();
    assert!(ops.lock_dir("/etc/xudo/rules.d").is_ok());
    assert_eq!(ops.calls(), ["lock_dir /etc/xudo/rules.d"]);
}

#[test]
fn the_fake_substitutes_like_the_real_thing() {
    // `substitute` is shared by the executor and the host; pinned here so the
    // fake's own arrangement cannot drift from it.
    assert_eq!(
        substitute(&["a".to_owned(), "{candidate}".to_owned()], "/p"),
        ["a", "/p"]
    );
}
