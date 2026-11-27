//! The machine as it would be once a plan has run.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::config::scan_doas_rules;
use super::{Answer, Caller, HostView, Kind, Lookup, Meta, is_own_doas_rule};
use crate::blocks;
use crate::plan::{InstallPlan, PlanStep};
use crate::snippet::{DOAS_BEGIN, DOAS_END};

/// What the plan does to its one file.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Change {
    /// The file is made, or replaced, with these contents.
    Write(Vec<u8>),
    /// The block is added to the end of the file that is there.
    Append(Vec<u8>),
}

/// `text` with xudo's block set, or why it cannot be.
fn insert_block(text: &[u8], block: &[u8]) -> Lookup<Vec<u8>> {
    match blocks::insert(text, block, DOAS_BEGIN.as_bytes(), DOAS_END.as_bytes()) {
        Ok(bytes) => Lookup::Found(bytes),
        Err(error) => Lookup::Unreadable(error.to_string()),
    }
}

/// A host that serves the file a plan would write as it would be, and
/// everything else as the real host has it.
///
/// This is how an install asks the same questions of the machine it is about
/// to make as `xudo doctor` asks of the one it made, so that the order of
/// xudo's rule among the others is read, never predicted a second way.
pub struct PlannedHost<'a> {
    host: &'a dyn HostView,
    file: PathBuf,
    change: Change,
}

impl<'a> PlannedHost<'a> {
    /// The host `host` becomes when `plan` has run, or `None` for a plan that
    /// writes no file this models.
    pub fn new(host: &'a dyn HostView, plan: &InstallPlan) -> Option<Self> {
        let candidate = |from: &str| {
            plan.steps.iter().find_map(|step| match step {
                PlanStep::WriteCandidate { path, contents, .. } if path == from => {
                    Some(contents.as_bytes().to_vec())
                }
                _ => None,
            })
        };
        plan.steps.iter().find_map(|step| {
            let (file, change) = match step {
                PlanStep::Install { from, to } => (to, Change::Write(candidate(from)?)),
                PlanStep::AppendBlock { path, block } => {
                    (path, Change::Append(block.as_bytes().to_vec()))
                }
                _ => return None,
            };
            Some(Self {
                host,
                file: PathBuf::from(file),
                change,
            })
        })
    }

    /// Whether the plan writes into `/etc/doas.d`.
    pub fn is_drop_in(&self) -> bool {
        matches!(self.change, Change::Write(_))
    }

    /// Whether xudo's own rule is in the file as the plan makes it. It is there
    /// by construction, so a file that cannot be read, or one the install would
    /// refuse, or one whose block does not hold the rule, answers `false`.
    pub fn holds_own_rule(&self) -> bool {
        match self.read(&self.file) {
            Lookup::Found(bytes) => scan_doas_rules(&bytes).iter().any(is_own_doas_rule),
            Lookup::Missing | Lookup::Unreadable(_) => false,
        }
    }

    fn is_ours(&self, path: &Path) -> bool {
        path == self.file
    }
}

impl HostView for PlannedHost<'_> {
    fn caller(&self) -> Caller {
        self.host.caller()
    }

    fn stat(&self, path: &Path) -> Lookup<Meta> {
        match (self.is_ours(path), &self.change, self.host.stat(path)) {
            (true, Change::Write(_), Lookup::Missing) => Lookup::Found(Meta {
                uid: 0,
                gid: 0,
                mode: 0o400,
                kind: Kind::File,
                nlink: 1,
            }),
            (_, _, other) => other,
        }
    }

    fn read(&self, path: &Path) -> Lookup<Vec<u8>> {
        if !self.is_ours(path) {
            return self.host.read(path);
        }
        match &self.change {
            Change::Write(contents) => Lookup::Found(contents.clone()),
            // The very function the install writes with, so the file read here
            // is the file it makes: an old block of xudo's is replaced where
            // it stands, and a last line without a newline gets one.
            Change::Append(block) => match self.host.read(path) {
                Lookup::Found(bytes) => insert_block(&bytes, block),
                Lookup::Missing => insert_block(&[], block),
                unreadable @ Lookup::Unreadable(_) => unreadable,
            },
        }
    }

    fn list(&self, path: &Path) -> Lookup<Vec<OsString>> {
        let listed = self.host.list(path);
        let (Change::Write(_), Some(name)) = (&self.change, self.file.file_name()) else {
            return listed;
        };
        if self.file.parent() != Some(path) {
            return listed;
        }
        let name = OsString::from(std::ffi::OsStr::from_bytes(name.as_bytes()));
        match listed {
            Lookup::Found(mut names) => {
                if !names.contains(&name) {
                    names.push(name);
                }
                Lookup::Found(names)
            }
            Lookup::Missing => Lookup::Found(vec![name]),
            unreadable @ Lookup::Unreadable(_) => unreadable,
        }
    }

    fn read_link(&self, path: &Path) -> Lookup<PathBuf> {
        self.host.read_link(path)
    }

    fn writable(&self, path: &Path) -> bool {
        self.host.writable(path)
    }

    fn ask_sudo(&self, exe: &str, user: &str) -> Answer {
        self.host.ask_sudo(exe, user)
    }

    fn ask_doas(&self, exe: &str, file: &Path, command: &str) -> Answer {
        self.host.ask_doas(exe, file, command)
    }
}
