#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use super::*;

const PASSWD: &str = "root:x:0:0::/root:/bin/sh\nagent:x:990:990::/h:/usr/sbin/nologin\nalice:x:1000:1000::/h:/bin/sh\n";
const SHADOW: &str = "agent:!:1::::::\n";
const GROUP: &str = "root:x:0:\nagent:x:990:\n";
const DROP_IN: &str = "/etc/systemd/system/xudo-agent@codex.service.d";

/// A machine in memory: files, directories, a unit that is on or off, and a
/// list of every call it was asked to make.
struct Machine {
    uid: u32,
    files: RefCell<BTreeMap<String, String>>,
    dirs: RefCell<BTreeSet<String>>,
    calls: RefCell<Vec<String>>,
    /// The first call whose text starts with this fails.
    fail: RefCell<Option<String>>,
    user: RefCell<String>,
    active: Cell<bool>,
    stuck: Cell<bool>,
    unreadable: RefCell<BTreeSet<String>>,
    /// A `systemctl` whose arguments start with this cannot be run at all.
    cannot_run: RefCell<Option<String>>,
    /// Listed in `/etc/xudo/harnesses.d` and gone before it is read.
    ghosts: RefCell<Vec<String>>,
    /// Read back as bytes that are not text.
    binary: RefCell<BTreeSet<String>>,
}

impl Machine {
    fn root() -> Self {
        let files = [
            ("/etc/passwd", PASSWD),
            ("/etc/shadow", SHADOW),
            ("/etc/group", GROUP),
        ];
        Self {
            uid: 0,
            files: RefCell::new(
                files
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            ),
            dirs: RefCell::new(
                ["/etc/xudo", "/etc/systemd/system"]
                    .iter()
                    .map(|d| (*d).to_owned())
                    .collect(),
            ),
            calls: RefCell::new(Vec::new()),
            fail: RefCell::new(None),
            user: RefCell::new("agent".to_owned()),
            active: Cell::new(false),
            stuck: Cell::new(false),
            unreadable: RefCell::new(BTreeSet::new()),
            cannot_run: RefCell::new(None),
            ghosts: RefCell::new(Vec::new()),
            binary: RefCell::new(BTreeSet::new()),
        }
    }

    fn failing(self, call: &str) -> Self {
        *self.fail.borrow_mut() = Some(call.to_owned());
        self
    }

    fn with_file(self, path: &str, text: &str) -> Self {
        self.files
            .borrow_mut()
            .insert(path.to_owned(), text.to_owned());
        let dir = path.rsplit_once('/').unwrap().0.to_owned();
        self.dirs.borrow_mut().insert(dir);
        self
    }

    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }

    fn position(&self, prefix: &str) -> usize {
        self.calls()
            .iter()
            .position(|c| c.starts_with(prefix))
            .unwrap_or_else(|| panic!("no call {prefix}: {:?}", self.calls()))
    }

    fn step(&self, call: String) -> Result<(), InstallError> {
        let failing = self
            .fail
            .borrow()
            .as_ref()
            .is_some_and(|prefix| call.starts_with(prefix.as_str()));
        self.calls.borrow_mut().push(call.clone());
        if failing {
            Err(InstallError::Io {
                operation: "scripted",
                path: call,
                reason: "scripted".to_owned(),
            })
        } else {
            Ok(())
        }
    }

    fn marked(&self, path: &str) -> bool {
        self.files
            .borrow()
            .get(path)
            .is_some_and(|text| text.starts_with(MANAGED_MARKER))
    }
}

impl InstallOps for Machine {
    fn effective_uid(&self) -> u32 {
        self.uid
    }

    fn group_exists(&self, _name: &str) -> Result<bool, InstallError> {
        Ok(true)
    }

    fn create_group(&self, _name: &str) -> Result<(), InstallError> {
        Ok(())
    }

    fn write_candidate(
        &self,
        path: &str,
        contents: &[u8],
        _mode: u32,
    ) -> Result<FileIdentity, InstallError> {
        self.step(format!("write_candidate {path}"))?;
        self.files.borrow_mut().insert(
            path.to_owned(),
            String::from_utf8(contents.to_vec()).unwrap(),
        );
        Ok(FileIdentity {
            device: 1,
            inode: 1,
        })
    }

    fn validate(&self, _argv: &[String]) -> Result<(), InstallError> {
        Ok(())
    }

    fn identity(&self, _path: &str) -> Result<FileIdentity, InstallError> {
        Ok(FileIdentity {
            device: 1,
            inode: 1,
        })
    }

    fn install(&self, from: &str, to: &str, _identity: FileIdentity) -> Result<(), InstallError> {
        self.step(format!("install {to}"))?;
        let text = self.files.borrow_mut().remove(from).unwrap();
        self.files.borrow_mut().insert(to.to_owned(), text);
        Ok(())
    }

    fn discard(&self, path: &str, _identity: FileIdentity) -> Result<(), InstallError> {
        self.step(format!("discard {path}"))?;
        self.files.borrow_mut().remove(path);
        Ok(())
    }

    fn remove_managed(&self, path: &str) -> Result<Removal, InstallError> {
        self.step(format!("remove_managed {path}"))?;
        if self.files.borrow().contains_key(path) && !self.marked(path) {
            return Err(InstallError::NotOurs {
                path: path.to_owned(),
                reason: "no marker".to_owned(),
            });
        }
        Ok(if self.files.borrow_mut().remove(path).is_some() {
            Removal::Removed
        } else {
            Removal::Absent
        })
    }

    fn append_block(
        &self,
        _path: &str,
        _block: &str,
        _validator: &[String],
    ) -> Result<(), InstallError> {
        Ok(())
    }

    fn remove_block(&self, _path: &str) -> Result<Removal, InstallError> {
        Ok(Removal::Absent)
    }
}

impl EnrolOps for Machine {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, InstallError> {
        if self.unreadable.borrow().contains(path) {
            return Err(InstallError::UnsafeFile {
                path: path.to_owned(),
                reason: "scripted".to_owned(),
            });
        }
        if self.binary.borrow().contains(path) {
            return Ok(Some(vec![0xff, 0xfe]));
        }
        Ok(self.files.borrow().get(path).map(|t| t.as_bytes().to_vec()))
    }

    fn list_dir(&self, path: &str) -> Result<Option<Vec<String>>, InstallError> {
        if self.unreadable.borrow().contains(path) {
            return Err(InstallError::UnsafeFile {
                path: path.to_owned(),
                reason: "owned by uid 1000".to_owned(),
            });
        }
        if !self.dirs.borrow().contains(path) {
            return Ok(None);
        }
        let prefix = format!("{path}/");
        let mut names: Vec<String> = self
            .files
            .borrow()
            .keys()
            .filter_map(|file| file.strip_prefix(&prefix))
            .filter(|rest| !rest.contains('/') && !rest.ends_with(".candidate"))
            .map(str::to_owned)
            .collect();
        if path == "/etc/xudo/harnesses.d" {
            names.extend(self.ghosts.borrow().iter().cloned());
        }
        Ok(Some(names))
    }

    fn make_dir(&self, path: &str, _mode: u32) -> Result<bool, InstallError> {
        self.step(format!("make_dir {path}"))?;
        Ok(self.dirs.borrow_mut().insert(path.to_owned()))
    }

    fn remove_dir(&self, path: &str) -> Result<Removal, InstallError> {
        self.step(format!("remove_dir {path}"))?;
        Ok(if self.dirs.borrow_mut().remove(path) {
            Removal::Removed
        } else {
            Removal::Absent
        })
    }

    fn systemctl(&self, args: &[&str]) -> Result<Systemctl, InstallError> {
        let line = args.join(" ");
        if self
            .cannot_run
            .borrow()
            .as_deref()
            .is_some_and(|prefix| line.starts_with(prefix))
        {
            return Err(InstallError::Io {
                operation: "run",
                path: "systemctl".to_owned(),
                reason: "scripted".to_owned(),
            });
        }
        self.step(format!("systemctl {line}"))
            .map(|()| Systemctl {
                success: true,
                stdout: String::new(),
            })
            .or_else(|error| {
                if self.fail.borrow().as_deref() == Some("systemctl is-active") {
                    return Err(error);
                }
                Ok(Systemctl {
                    success: false,
                    stdout: "scripted failure".to_owned(),
                })
            })
            .map(|mut answer| {
                if answer.success {
                    match args[0] {
                        "show" => answer.stdout = self.user.borrow().clone(),
                        "enable" => self.active.set(true),
                        "disable" if !self.stuck.get() => self.active.set(false),
                        "is-active" => {
                            answer.stdout = if self.active.get() {
                                "active"
                            } else {
                                "inactive"
                            }
                            .to_owned();
                        }
                        _ => {}
                    }
                }
                answer
            })
    }
}

fn request() -> EnrolRequest {
    EnrolRequest {
        label: "codex".to_owned(),
        account: "agent".to_owned(),
        reviewers: vec!["alice".to_owned()],
        argv: vec!["/usr/bin/codex".to_owned()],
    }
}

fn scan() -> AccountScan {
    AccountScan {
        uid: 990,
        blockers: Vec::new(),
    }
}

fn enrol(machine: &Machine) -> Result<EnrolPlan, AgentError> {
    let plan = plan_enrol(&request(), scan(), machine, machine)?;
    apply_enrol(&plan, machine, machine).map(|()| plan)
}

#[test]
fn enrol_writes_the_unit_files_before_it_tells_systemd() {
    let machine = Machine::root();
    let plan = enrol(&machine).unwrap();
    let files = machine.files.borrow();
    assert!(files[&plan.registry.path].contains("account = \"agent\""));
    assert!(files[&plan.drop_in.path].contains("User=agent"));
    assert!(files[&plan.env.path].starts_with(MANAGED_MARKER));
    // No candidate is left behind.
    assert!(!files.keys().any(|path| path.ends_with(".candidate")));
    drop(files);
    // The environment stub, then the drop-in, then the registry entry that
    // attests the harness, then systemd.
    assert!(
        machine.position("install /etc/xudo/agents") < machine.position("install /etc/systemd")
    );
    assert!(
        machine.position("install /etc/systemd")
            < machine.position("install /etc/xudo/harnesses.d")
    );
    assert!(
        machine.position("install /etc/xudo/harnesses.d")
            < machine.position("systemctl daemon-reload")
    );
    assert!(machine.position("systemctl daemon-reload") < machine.position("systemctl show"));
    assert!(
        machine.position("systemctl show")
            < machine.position("systemctl enable --now xudo-agent@codex.service")
    );
    assert!(machine.active.get());
}

#[test]
fn enrol_keeps_an_environment_file_an_operator_filled() {
    let machine = Machine::root().with_file("/etc/xudo/agents/codex.env", "KEY=secret\n");
    let plan = enrol(&machine).unwrap();
    assert!(plan.env.keep);
    assert_eq!(
        machine.files.borrow()["/etc/xudo/agents/codex.env"],
        "KEY=secret\n"
    );
    assert!(
        !machine
            .calls()
            .iter()
            .any(|c| c.contains("agents/codex.env"))
    );
}

#[test]
fn enrol_needs_root_in_every_entry_point() {
    let mut machine = Machine::root();
    machine.uid = 1000;
    let not_root = AgentError::NotRoot { uid: 1000 };
    assert_eq!(
        plan_enrol(&request(), scan(), &machine, &machine).unwrap_err(),
        not_root
    );
    let plan = plan_enrol(&request(), scan(), &Machine::root(), &Machine::root()).unwrap();
    assert_eq!(
        apply_enrol(&plan, &machine, &machine).unwrap_err(),
        not_root
    );
    assert_eq!(
        remove_agent("codex", &machine, &machine).unwrap_err(),
        not_root
    );
    assert_eq!(machine.calls(), Vec::<String>::new());
}

#[test]
fn enrol_refuses_when_the_password_file_cannot_be_read() {
    let machine = Machine::root();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/shadow".to_owned());
    assert_eq!(
        plan_enrol(&request(), scan(), &machine, &machine).unwrap_err(),
        AgentError::Refused(Refusal::PasswordUnknown("agent".to_owned()))
    );
    // A missing passwd is a read of nothing, and nothing names no account.
    let machine = Machine::root();
    machine.files.borrow_mut().remove("/etc/passwd");
    assert_eq!(
        plan_enrol(&request(), scan(), &machine, &machine).unwrap_err(),
        AgentError::Refused(Refusal::AccountUnknown("agent".to_owned()))
    );
}

#[test]
fn enrol_refuses_a_drop_in_directory_it_cannot_trust_or_that_is_in_use() {
    let machine = Machine::root();
    machine.unreadable.borrow_mut().insert(DROP_IN.to_owned());
    assert_eq!(
        plan_enrol(&request(), scan(), &machine, &machine).unwrap_err(),
        AgentError::Refused(Refusal::DropInUntrusted(
            "refusing to edit /etc/systemd/system/xudo-agent@codex.service.d: owned by uid 1000"
                .to_owned()
        ))
    );
    let machine =
        Machine::root().with_file(&format!("{DROP_IN}/99-evil.conf"), "[Service]\nUser=root\n");
    assert_eq!(
        plan_enrol(&request(), scan(), &machine, &machine).unwrap_err(),
        AgentError::Refused(Refusal::DropInOccupied("codex".to_owned()))
    );
    // An empty one is root's and fine.
    let machine = Machine::root();
    machine.dirs.borrow_mut().insert(DROP_IN.to_owned());
    plan_enrol(&request(), scan(), &machine, &machine).unwrap();
}

#[test]
fn enrol_reads_only_the_toml_files_of_the_registry() {
    let machine = Machine::root()
        .with_file("/etc/xudo/harnesses.d/README", "not a harness")
        .with_file("/etc/xudo/harnesses.d/claude.toml", "not toml {");
    assert!(matches!(
        plan_enrol(&request(), scan(), &machine, &machine).unwrap_err(),
        AgentError::Refused(Refusal::Registry(_))
    ));
    let machine = Machine::root().with_file("/etc/xudo/harnesses.d/README", "not a harness");
    plan_enrol(&request(), scan(), &machine, &machine).unwrap();
    // A registry file that is not text is a refusal, not a guess.
    let machine = Machine::root();
    machine
        .files
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d/x.toml".to_owned(), String::new());
    machine
        .dirs
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d".to_owned());
    assert_eq!(
        text("/p", vec![0xff]).unwrap_err(),
        AgentError::NotText("/p".to_owned())
    );
}

#[test]
fn a_failed_enrol_takes_back_what_it_wrote() {
    for call in [
        "make_dir /etc/systemd",
        "write_candidate /etc/xudo/agents",
        "write_candidate /etc/systemd",
        "install /etc/systemd",
        "install /etc/xudo/harnesses.d",
        "systemctl daemon-reload",
        "systemctl show",
        "systemctl enable",
    ] {
        let machine = Machine::root().failing(call);
        let error = enrol(&machine).unwrap_err();
        assert!(!matches!(error, AgentError::Refused(_)), "{call}: {error}");
        let leftovers: Vec<String> = machine
            .files
            .borrow()
            .keys()
            .filter(|path| path.contains("codex") || path.ends_with(".candidate"))
            .cloned()
            .collect();
        assert!(leftovers.is_empty(), "{call}: {leftovers:?}");
        assert!(!machine.dirs.borrow().contains(DROP_IN), "{call}");
        assert!(!machine.active.get(), "{call}");
    }
}

#[test]
fn a_drop_in_elsewhere_that_changes_user_stops_the_enrol() {
    let machine = Machine::root();
    *machine.user.borrow_mut() = "root".to_owned();
    assert_eq!(
        enrol(&machine).unwrap_err(),
        AgentError::UserMismatch {
            unit: "xudo-agent@codex.service".to_owned(),
            expected: "agent".to_owned(),
            found: "root".to_owned()
        }
    );
    assert!(
        !machine
            .calls()
            .iter()
            .any(|c| c.starts_with("systemctl enable"))
    );
    assert!(machine.files.borrow().keys().all(|p| !p.contains("codex")));
}

#[test]
fn a_systemctl_that_cannot_run_is_an_error_not_an_answer() {
    let machine = Machine::root().failing("systemctl is-active");
    machine.files.borrow_mut().insert(
        "/etc/xudo/harnesses.d/codex.toml".to_owned(),
        format!("{MANAGED_MARKER}\nlabel = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n"),
    );
    machine
        .dirs
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d".to_owned());
    assert!(matches!(
        list_agents(&machine).unwrap_err(),
        AgentError::Install(_)
    ));
}

fn enrolled() -> Machine {
    let machine = Machine::root();
    enrol(&machine).unwrap();
    machine.calls.borrow_mut().clear();
    machine
}

#[test]
fn list_shows_each_agent_and_whether_it_runs() {
    let machine = enrolled();
    let rows = list_agents(&machine).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].agent.label, "codex");
    assert_eq!(rows[0].state, "active");
    machine.active.set(false);
    assert_eq!(list_agents(&machine).unwrap()[0].state, "inactive");
    // Nothing enrolled is an empty list, and a registry that does not load is not.
    assert_eq!(list_agents(&Machine::root()).unwrap(), vec![]);
    let broken = Machine::root().with_file("/etc/xudo/harnesses.d/x.toml", "x");
    assert!(matches!(
        list_agents(&broken).unwrap_err(),
        AgentError::Refused(_)
    ));
}

#[test]
fn remove_stops_the_unit_first_and_deletes_the_registry_entry_last() {
    let machine = enrolled();
    let lines = remove_agent("codex", &machine, &machine).unwrap();
    assert!(
        machine.position("systemctl disable --now")
            < machine.position("remove_managed /etc/systemd")
    );
    assert!(machine.position("remove_managed /etc/systemd") < machine.position("remove_dir"));
    assert!(machine.position("remove_dir") < machine.position("systemctl daemon-reload"));
    assert_eq!(
        machine.position("remove_managed /etc/xudo/harnesses.d"),
        machine.calls().len() - 1
    );
    assert!(
        !machine
            .files
            .borrow()
            .contains_key("/etc/xudo/harnesses.d/codex.toml")
    );
    // Credentials an operator may have written stay.
    assert!(
        machine
            .files
            .borrow()
            .contains_key("/etc/xudo/agents/codex.env")
    );
    assert!(
        lines
            .last()
            .unwrap()
            .starts_with("kept /etc/xudo/agents/codex.env")
    );
    // The record helper insists pid 1 started it, so remove does not run it.
    assert!(
        machine
            .calls()
            .iter()
            .all(|c| !c.contains("void") && !c.contains("xudo-session"))
    );
}

#[test]
fn remove_keeps_the_registry_entry_of_a_unit_that_will_not_stop() {
    let machine = enrolled();
    machine.stuck.set(true);
    assert_eq!(
        remove_agent("codex", &machine, &machine).unwrap_err(),
        AgentError::StillRunning("xudo-agent@codex.service".to_owned())
    );
    assert!(
        machine
            .files
            .borrow()
            .contains_key("/etc/xudo/harnesses.d/codex.toml")
    );
    assert!(
        machine
            .files
            .borrow()
            .contains_key("/etc/systemd/system/xudo-agent@codex.service.d/10-xudo.conf")
    );
}

#[test]
fn remove_refuses_what_enrol_did_not_write() {
    let machine = enrolled();
    for label in ["gemini", "../codex", "Codex"] {
        assert_eq!(
            remove_agent(label, &machine, &machine).unwrap_err(),
            AgentError::NotEnrolled(label.to_owned()),
            "{label}"
        );
    }
    // An entry an operator wrote by hand has no marker: not stopped, not removed.
    let machine =
        Machine::root().with_file("/etc/xudo/harnesses.d/codex.toml", "label = \"codex\"\n");
    machine.active.set(true);
    assert_eq!(
        remove_agent("codex", &machine, &machine).unwrap_err(),
        AgentError::NotEnrolled("codex".to_owned())
    );
    assert!(machine.active.get());
    assert!(machine.calls().iter().all(|c| !c.starts_with("systemctl")));
}

#[test]
fn remove_stops_at_a_failed_stop_or_removal() {
    for call in [
        "systemctl disable",
        "remove_managed /etc/systemd",
        "remove_dir",
        "systemctl daemon-reload",
        "remove_managed /etc/xudo/harnesses.d",
    ] {
        let machine = enrolled();
        *machine.fail.borrow_mut() = Some(call.to_owned());
        assert!(remove_agent("codex", &machine, &machine).is_err(), "{call}");
        // Whatever failed, the entry stays until the very last step.
        assert!(
            machine
                .files
                .borrow()
                .contains_key("/etc/xudo/harnesses.d/codex.toml"),
            "{call}"
        );
    }
}

#[test]
fn the_test_machine_answers_every_question_the_traits_ask() {
    let machine = Machine::root();
    assert!(machine.group_exists("x").unwrap());
    machine.create_group("x").unwrap();
    machine.validate(&[]).unwrap();
    assert_eq!(machine.identity("/p").unwrap().inode, 1);
    machine.append_block("/p", "b", &[]).unwrap();
    assert_eq!(machine.remove_block("/p").unwrap(), Removal::Absent);
    let id = machine
        .write_candidate("/etc/x.candidate", b"a", 0o600)
        .unwrap();
    machine.discard("/etc/x.candidate", id).unwrap();
    assert_eq!(machine.remove_dir("/nope").unwrap(), Removal::Absent);
}

#[test]
fn every_read_that_fails_stops_the_plan_and_the_list() {
    let registered = || {
        let machine = enrolled();
        machine.calls.borrow_mut().clear();
        machine
    };
    for path in [
        "/etc/xudo/harnesses.d",
        "/etc/xudo/agents",
        "/etc/passwd",
        "/etc/group",
        "/etc/xudo/harnesses.d/codex.toml",
    ] {
        let machine = Machine::root().with_file("/etc/xudo/harnesses.d/claude.toml", "x");
        machine.unreadable.borrow_mut().insert(path.to_owned());
        machine
            .dirs
            .borrow_mut()
            .insert("/etc/xudo/agents".to_owned());
        assert!(
            plan_enrol(&request(), scan(), &machine, &machine).is_err(),
            "{path}"
        );
    }
    for path in ["/etc/xudo/harnesses.d", "/etc/xudo/harnesses.d/codex.toml"] {
        let machine = registered();
        machine.unreadable.borrow_mut().insert(path.to_owned());
        assert!(matches!(
            list_agents(&machine).unwrap_err(),
            AgentError::Install(_)
        ));
        if path.contains("codex.toml") {
            assert!(matches!(
                remove_agent("codex", &machine, &machine).unwrap_err(),
                AgentError::Install(_)
            ));
        }
    }
}

#[test]
fn a_systemctl_that_cannot_run_stops_enrol_and_remove() {
    for prefix in ["daemon-reload", "show", "enable"] {
        let machine = Machine::root();
        *machine.cannot_run.borrow_mut() = Some(prefix.to_owned());
        assert!(
            matches!(enrol(&machine).unwrap_err(), AgentError::Install(_)),
            "{prefix}"
        );
        assert!(machine.files.borrow().keys().all(|p| !p.contains("codex")));
    }
    for prefix in ["disable", "is-active"] {
        let machine = enrolled();
        *machine.cannot_run.borrow_mut() = Some(prefix.to_owned());
        assert!(
            remove_agent("codex", &machine, &machine).is_err(),
            "{prefix}"
        );
        assert!(
            machine
                .files
                .borrow()
                .contains_key("/etc/xudo/harnesses.d/codex.toml")
        );
    }
}

#[test]
fn a_directory_that_cannot_be_made_stops_enrol() {
    for dir in ["/etc/xudo/harnesses.d", "/etc/xudo/agents"] {
        let machine = Machine::root().failing(&format!("make_dir {dir}"));
        assert!(enrol(&machine).is_err(), "{dir}");
        assert!(machine.files.borrow().keys().all(|p| !p.contains("codex")));
    }
}

#[test]
fn an_empty_drop_in_directory_that_was_there_is_used_and_never_removed_on_failure() {
    let machine = Machine::root().failing("systemctl enable");
    machine.dirs.borrow_mut().insert(DROP_IN.to_owned());
    assert!(enrol(&machine).is_err());
    assert!(machine.dirs.borrow().contains(DROP_IN));
    let machine = Machine::root();
    machine.dirs.borrow_mut().insert(DROP_IN.to_owned());
    enrol(&machine).unwrap();
}
