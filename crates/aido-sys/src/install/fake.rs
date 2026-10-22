//! An in-memory [`InstallOps`], for driving the executor through every path.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::{FileIdentity, InstallError, InstallOps, Removal, substitute};

/// The inode every candidate this fake writes has.
const WRITTEN: FileIdentity = FileIdentity {
    device: 1,
    inode: 100,
};

/// Records every call, and fails the ones it is told to.
pub(super) struct FakeInstallOps {
    uid: u32,
    calls: RefCell<Vec<String>>,
    failures: BTreeMap<&'static str, InstallError>,
    group: bool,
    present: RefCell<BTreeSet<String>>,
    identity: FileIdentity,
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
        }
    }

    /// Makes `method` fail with the error that method would plausibly raise.
    pub(super) fn failing(self, method: &'static str) -> Self {
        let error = match method {
            "group_exists" | "create_group" => InstallError::Group {
                name: "aido".to_owned(),
                reason: "scripted".to_owned(),
            },
            "validate" => InstallError::ValidatorRejected {
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

    pub(super) fn failing_with(mut self, method: &'static str, error: InstallError) -> Self {
        self.failures.insert(method, error);
        self
    }

    /// The group already exists.
    pub(super) fn with_group(mut self) -> Self {
        self.group = true;
        self
    }

    /// These paths already hold something of aido's.
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

    pub(super) fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn record(&self, method: &'static str, detail: &str) -> Result<(), InstallError> {
        self.calls
            .borrow_mut()
            .push(format!("{method} {detail}").trim_end().to_owned());
        self.failures.get(method).map_or(Ok(()), |e| Err(e.clone()))
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
        _contents: &[u8],
        _mode: u32,
    ) -> Result<FileIdentity, InstallError> {
        self.record("write_candidate", path)?;
        Ok(WRITTEN)
    }

    fn validate(&self, argv: &[String]) -> Result<(), InstallError> {
        self.record("validate", &argv.join(" "))
    }

    fn identity(&self, path: &str) -> Result<FileIdentity, InstallError> {
        self.record("identity", path)?;
        Ok(self.identity)
    }

    fn install(&self, from: &str, to: &str, _identity: FileIdentity) -> Result<(), InstallError> {
        self.record("install", &format!("{from} {to}"))
    }

    fn discard(&self, path: &str, _identity: FileIdentity) -> Result<(), InstallError> {
        self.record("discard", path)
    }

    fn remove_managed(&self, path: &str) -> Result<Removal, InstallError> {
        self.record("remove_managed", path)?;
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
