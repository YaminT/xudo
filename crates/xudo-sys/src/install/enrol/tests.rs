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
pub(crate) struct Machine {
    pub(crate) uid: u32,
    pub(crate) files: RefCell<BTreeMap<String, String>>,
    pub(crate) dirs: RefCell<BTreeSet<String>>,
    calls: RefCell<Vec<String>>,
    /// The first call whose text starts with this fails.
    fail: RefCell<Option<String>>,
    user: RefCell<String>,
    /// What `DropInPaths` and `FragmentPath` say.
    drop_ins: RefCell<String>,
    fragment: RefCell<String>,
    /// Env files that are not private.
    open_env: RefCell<BTreeSet<String>>,
    active: Cell<bool>,
    stuck: Cell<bool>,
    /// What `is-active` says instead, when set.
    state: RefCell<Option<String>>,
    pub(crate) unreadable: RefCell<BTreeSet<String>>,
    /// A `systemctl` whose arguments start with this cannot be run at all.
    cannot_run: RefCell<Option<String>>,
    /// Listed in `/etc/xudo/harnesses.d` and gone before it is read.
    ghosts: RefCell<Vec<String>>,
    /// Read back as bytes that are not text.
    binary: RefCell<BTreeSet<String>>,
}

impl Machine {
    pub(crate) fn root() -> Self {
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
            drop_ins: RefCell::new(format!("{DROP_IN}/10-xudo.conf")),
            fragment: RefCell::new(TEMPLATE_PATH.to_owned()),
            open_env: RefCell::new(BTreeSet::new()),
            active: Cell::new(false),
            stuck: Cell::new(false),
            state: RefCell::new(None),
            unreadable: RefCell::new(BTreeSet::new()),
            cannot_run: RefCell::new(None),
            ghosts: RefCell::new(Vec::new()),
            binary: RefCell::new(BTreeSet::new()),
        }
    }

    pub(crate) fn failing(self, call: &str) -> Self {
        *self.fail.borrow_mut() = Some(call.to_owned());
        self
    }

    pub(crate) fn with_file(self, path: &str, text: &str) -> Self {
        self.files
            .borrow_mut()
            .insert(path.to_owned(), text.to_owned());
        let dir = path.rsplit_once('/').unwrap().0.to_owned();
        self.dirs.borrow_mut().insert(dir);
        self
    }

    pub(crate) fn calls(&self) -> Vec<String> {
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

    /// Edits the member list of one group line in `/etc/group`.
    fn edit_group(&self, group: &str, edit: impl FnOnce(&mut Vec<String>)) {
        let mut files = self.files.borrow_mut();
        let file = files.get_mut("/etc/group").unwrap();
        let mut lines: Vec<String> = file.lines().map(str::to_owned).collect();
        for line in &mut lines {
            let fields: Vec<&str> = line.split(':').collect();
            if fields[0] == group {
                let mut members: Vec<String> = fields[3]
                    .split(',')
                    .filter(|m| !m.is_empty())
                    .map(str::to_owned)
                    .collect();
                edit(&mut members);
                *line = format!(
                    "{}:{}:{}:{}",
                    fields[0],
                    fields[1],
                    fields[2],
                    members.join(",")
                );
                break;
            }
        }
        *file = lines.join("\n") + "\n";
    }

    fn members(&self, group: &str) -> Vec<String> {
        self.files.borrow()["/etc/group"]
            .lines()
            .find_map(|line| {
                let fields: Vec<&str> = line.split(':').collect();
                (fields[0] == group).then(|| {
                    fields[3]
                        .split(',')
                        .filter(|m| !m.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
            })
            .unwrap_or_default()
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

    fn group_exists(&self, name: &str) -> Result<bool, InstallError> {
        self.step(format!("group_exists {name}"))?;
        let prefix = format!("{name}:");
        Ok(self.files.borrow()["/etc/group"]
            .lines()
            .any(|line| line.starts_with(&prefix)))
    }

    fn create_group(&self, name: &str) -> Result<(), InstallError> {
        self.step(format!("create_group {name}"))?;
        let mut files = self.files.borrow_mut();
        let group = files.get_mut("/etc/group").unwrap();
        let gid = 800_usize.saturating_add(group.lines().count());
        let line = format!("{name}:x:{gid}:\n");
        group.push_str(&line);
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
            let mut bytes = MANAGED_MARKER.as_bytes().to_vec();
            bytes.extend([0xff, 0xfe]);
            return Ok(Some(bytes));
        }
        Ok(self.files.borrow().get(path).map(|t| t.as_bytes().to_vec()))
    }

    fn private_file(&self, path: &str) -> Result<(), InstallError> {
        if self.open_env.borrow().contains(path) {
            return Err(InstallError::UnsafeFile {
                path: path.to_owned(),
                reason: "it is open to group or others".to_owned(),
            });
        }
        Ok(())
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

    fn add_member(&self, group: &str, account: &str) -> Result<(), InstallError> {
        self.step(format!("add_member {group} {account}"))?;
        self.edit_group(group, |members| {
            members.push(account.to_owned());
        });
        Ok(())
    }

    fn remove_member(&self, group: &str, account: &str) -> Result<(), InstallError> {
        self.step(format!("remove_member {group} {account}"))?;
        self.edit_group(group, |members| members.retain(|m| m != account));
        Ok(())
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
                        "show" if line.contains("DropInPaths") => {
                            answer.stdout = self.drop_ins.borrow().clone();
                        }
                        "show" if line.contains("FragmentPath") => {
                            answer.stdout = self.fragment.borrow().clone();
                        }
                        "show" => answer.stdout = self.user.borrow().clone(),
                        "enable" => self.active.set(true),
                        "disable" if !self.stuck.get() => self.active.set(false),
                        "is-active" if self.state.borrow().is_some() => {
                            answer.stdout = self.state.borrow().clone().unwrap();
                        }
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
        doas: false,
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
fn denies_a_drop_in_in_another_directory_that_adds_groups() {
    for (drop_ins, fragment) in [
        (
            format!("{DROP_IN}/10-xudo.conf /etc/systemd/system/xudo-agent@.service.d/x.conf"),
            TEMPLATE_PATH,
        ),
        (
            "/run/systemd/system/service.d/x.conf".to_owned(),
            TEMPLATE_PATH,
        ),
        (String::new(), TEMPLATE_PATH),
        (
            format!("{DROP_IN}/10-xudo.conf"),
            "/etc/systemd/system/xudo-agent@.service",
        ),
        (format!("{DROP_IN}/10-xudo.conf"), ""),
    ] {
        let machine = Machine::root();
        *machine.drop_ins.borrow_mut() = drop_ins.clone();
        *machine.fragment.borrow_mut() = fragment.to_owned();
        let error = enrol(&machine).unwrap_err();
        assert_eq!(
            error,
            AgentError::UnitSources {
                unit: "xudo-agent@codex.service".to_owned(),
                drop_ins,
                fragment: fragment.to_owned(),
            }
        );
        assert!(error.to_string().contains("nothing was left"));
        assert!(
            !machine
                .calls()
                .iter()
                .any(|c| c.starts_with("systemctl enable"))
        );
        assert!(machine.files.borrow().keys().all(|p| !p.contains("codex")));
    }
}

#[test]
fn denies_an_existing_env_file_that_is_open_or_a_link() {
    let machine = Machine::root().with_file("/etc/xudo/agents/codex.env", "KEY=v\n");
    machine
        .open_env
        .borrow_mut()
        .insert("/etc/xudo/agents/codex.env".to_owned());
    let error = plan_enrol(&request(), scan(), &machine, &machine).unwrap_err();
    assert!(matches!(
        error,
        AgentError::Install(InstallError::UnsafeFile { .. })
    ));
    // A private one is kept.
    let machine = Machine::root().with_file("/etc/xudo/agents/codex.env", "KEY=v\n");
    assert!(
        plan_enrol(&request(), scan(), &machine, &machine)
            .unwrap()
            .env
            .keep
    );
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
fn denies_remove_while_the_unit_is_still_going_down() {
    for state in ["activating", "deactivating", "reloading", "active", ""] {
        let machine = enrolled();
        *machine.state.borrow_mut() = Some(state.to_owned());
        assert_eq!(
            remove_agent("codex", &machine, &machine).unwrap_err(),
            AgentError::StillRunning("xudo-agent@codex.service".to_owned()),
            "{state}"
        );
        assert!(
            machine
                .files
                .borrow()
                .contains_key("/etc/xudo/harnesses.d/codex.toml")
        );
    }
    for state in ["inactive", "failed"] {
        let machine = enrolled();
        *machine.state.borrow_mut() = Some(state.to_owned());
        remove_agent("codex", &machine, &machine).unwrap();
    }
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
    assert!(!machine.group_exists("x").unwrap());
    machine.create_group("x").unwrap();
    assert!(machine.group_exists("x").unwrap());
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

#[test]
fn a_failed_question_about_the_unit_sources_stops_the_enrol() {
    for call in [
        "systemctl show --property=DropInPaths",
        "systemctl show --property=FragmentPath",
    ] {
        let machine = Machine::root().failing(call);
        assert!(matches!(
            enrol(&machine).unwrap_err(),
            AgentError::Unit { .. }
        ));
        assert!(
            !machine
                .calls()
                .iter()
                .any(|c| c.starts_with("systemctl enable"))
        );
        assert!(machine.files.borrow().keys().all(|p| !p.contains("codex")));
    }
}

// ---- H2d: the agent groups ----

fn bare_groups() -> Machine {
    let machine = Machine::root();
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\nalice:x:1000:\n".to_owned(),
    );
    machine
}

#[test]
fn enrol_joins_the_account_to_both_groups_as_its_last_write() {
    let machine = bare_groups();
    let plan = enrol(&machine).unwrap();
    assert_eq!(machine.members("xudo"), ["agent"]);
    assert_eq!(machine.members("xudo-agent"), ["agent"]);
    // Both groups were created, empty, before anyone was added.
    assert!(machine.position("create_group xudo") < machine.position("add_member xudo agent"));
    assert!(
        machine.position("create_group xudo-agent")
            < machine.position("add_member xudo-agent agent")
    );
    // Every file and every check comes first: the membership is the last write,
    // and the unit is started after it so it starts holding its groups.
    let join = machine.position("add_member xudo agent");
    for before in [
        "install /etc/xudo/harnesses.d",
        "install /etc/systemd",
        "install /etc/xudo/agents",
        "systemctl daemon-reload",
        "systemctl show",
    ] {
        assert!(machine.position(before) < join, "{before}");
    }
    assert!(machine.position("add_member xudo-agent agent") < machine.position("systemctl enable"));
    // The registry says which groups enrol itself added, for `remove`.
    assert!(
        machine.files.borrow()[&plan.registry.path]
            .contains("# xudo-joined-groups: xudo xudo-agent\n")
    );
}

#[test]
fn enrol_adds_a_member_to_a_group_that_exists_and_never_redefines_it() {
    let machine = Machine::root();
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\nxudo:x:55:alice\nxudo-agent:x:56:\n".to_owned(),
    );
    enrol(&machine).unwrap();
    // Nothing was created, and the existing member and gid are untouched.
    assert!(
        !machine
            .calls()
            .iter()
            .any(|c| c.starts_with("create_group"))
    );
    assert_eq!(machine.members("xudo"), ["alice", "agent"]);
    assert_eq!(machine.members("xudo-agent"), ["agent"]);
    assert!(machine.files.borrow()["/etc/group"].contains("xudo:x:55:"));
}

#[test]
fn enrol_leaves_a_membership_that_was_already_there_alone() {
    // Already in both: no tool runs, and the registry claims nothing as its own.
    let machine = Machine::root();
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\nxudo:x:55:agent\nxudo-agent:x:56:agent\n".to_owned(),
    );
    let plan = enrol(&machine).unwrap();
    assert!(!machine.calls().iter().any(|c| c.starts_with("add_member")));
    assert!(!machine.files.borrow()[&plan.registry.path].contains("xudo-joined-groups"));
    // The account joined between the plan and the apply: the registry would
    // claim a membership that is the operator's, so the run refuses, and
    // nothing is added or left behind.
    let machine = bare_groups();
    let plan = plan_enrol(&request(), scan(), &machine, &machine).unwrap();
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\nxudo:x:55:agent\nxudo-agent:x:56:agent\n".to_owned(),
    );
    let error = apply_enrol(&plan, &machine, &machine).unwrap_err();
    assert!(matches!(
        error,
        AgentError::MembershipChanged { ref group, .. } if group == "xudo"
    ));
    assert!(error.to_string().contains("not enrol's"), "{error}");
    assert!(!machine.calls().iter().any(|c| c.starts_with("add_member")));
    assert!(
        !machine
            .files
            .borrow()
            .contains_key("/etc/xudo/harnesses.d/codex.toml")
    );
}

#[test]
fn remove_does_not_try_to_take_out_a_primary_group_it_never_listed() {
    // The registry says enrol added `xudo`; the account's primary gid has since
    // become `xudo`, and it is no longer listed. `gpasswd` could not remove a
    // primary group, so nothing is asked of it and the removal completes.
    let machine = Machine::root().with_file(
        "/etc/xudo/harnesses.d/codex.toml",
        &format!("{MANAGED_MARKER}\n# xudo-joined-groups: xudo\nlabel = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n"),
    );
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\nxudo:x:990:\n".to_owned(),
    );
    remove_agent("codex", &machine, &machine).unwrap();
    assert!(
        !machine
            .calls()
            .iter()
            .any(|c| c.starts_with("remove_member"))
    );
}

#[test]
fn a_failed_group_join_takes_back_what_the_run_added() {
    // The second add fails: the first membership is taken out, the files and
    // the unit go, and the groups this run created stay, empty.
    let machine = bare_groups().failing("add_member xudo-agent");
    let error = enrol(&machine).unwrap_err();
    assert!(error.to_string().contains("scripted"), "{error}");
    assert!(machine.members("xudo").is_empty());
    assert!(
        machine.position("remove_member xudo agent") > machine.position("add_member xudo-agent")
    );
    assert!(
        !machine
            .files
            .borrow()
            .contains_key("/etc/xudo/harnesses.d/codex.toml")
    );
    assert!(!machine.active.get());
    // A group that cannot be created stops before any member is added.
    let machine = bare_groups().failing("create_group xudo");
    assert!(enrol(&machine).is_err());
    assert!(!machine.calls().iter().any(|c| c.starts_with("add_member")));
    // A group file that cannot be read stops the join too.
    let machine = bare_groups();
    let plan = plan_enrol(&request(), scan(), &machine, &machine).unwrap();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/group".to_owned());
    assert!(apply_enrol(&plan, &machine, &machine).is_err());
    assert!(!machine.calls().iter().any(|c| c.starts_with("add_member")));
}

#[test]
fn enrol_on_doas_enrols_nothing() {
    let machine = bare_groups();
    let mut doas = scan();
    doas.doas = true;
    let error = plan_enrol(&request(), doas, &machine, &machine).unwrap_err();
    assert_eq!(error, AgentError::Refused(Refusal::AgentPathNeedsSudo));
    assert!(machine.calls().is_empty());
}

#[test]
fn remove_takes_the_account_out_of_the_groups_enrol_added_and_never_deletes_a_group() {
    let machine = bare_groups();
    enrol(&machine).unwrap();
    let lines = remove_agent("codex", &machine, &machine).unwrap();
    assert!(machine.members("xudo").is_empty());
    assert!(machine.members("xudo-agent").is_empty());
    assert!(
        lines
            .iter()
            .any(|l| l == "removed agent from group xudo-agent")
    );
    // Groups stay; the registry entry still goes last.
    assert!(machine.files.borrow()["/etc/group"].contains("xudo-agent:x:"));
    assert!(
        machine.position("remove_member xudo-agent agent")
            < machine.position("remove_managed /etc/xudo/harnesses.d")
    );
    assert!(machine.position("systemctl disable") < machine.position("remove_member"));
}

#[test]
fn remove_leaves_the_groups_an_operator_had_the_account_in() {
    // The operator put the account in `xudo` first; enrol added it to
    // `xudo-agent` only, and only that one is taken out.
    let machine = Machine::root();
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\nxudo:x:55:agent,alice\n".to_owned(),
    );
    enrol(&machine).unwrap();
    remove_agent("codex", &machine, &machine).unwrap();
    assert_eq!(machine.members("xudo"), ["agent", "alice"]);
    assert!(machine.members("xudo-agent").is_empty());
    assert!(
        !machine
            .calls()
            .iter()
            .any(|c| c == "remove_member xudo agent")
    );
    // An entry written before groups were recorded takes nothing out.
    let machine = Machine::root().with_file(
        "/etc/xudo/harnesses.d/codex.toml",
        &format!("{MANAGED_MARKER}\nlabel = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n"),
    );
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\nxudo:x:55:agent\n".to_owned(),
    );
    remove_agent("codex", &machine, &machine).unwrap();
    assert_eq!(machine.members("xudo"), ["agent"]);
    // A recorded group the account already left is not asked about again, and a
    // comment naming a group that is not an agent group is ignored.
    let machine = Machine::root().with_file(
        "/etc/xudo/harnesses.d/codex.toml",
        &format!("{MANAGED_MARKER}\n# xudo-joined-groups: xudo docker\nlabel = \"codex\"\nway = \"service\"\naccount = \"agent\"\nreviewers = [\"alice\"]\nmax-sessions = 1\n"),
    );
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nagent:x:990:\ndocker:x:9:agent\nxudo:x:55:\n".to_owned(),
    );
    remove_agent("codex", &machine, &machine).unwrap();
    assert!(
        !machine
            .calls()
            .iter()
            .any(|c| c.starts_with("remove_member"))
    );
    assert_eq!(machine.members("docker"), ["agent"]);
}

#[test]
fn a_membership_that_cannot_be_removed_keeps_the_registry_entry() {
    let machine = bare_groups();
    enrol(&machine).unwrap();
    *machine.fail.borrow_mut() = Some("remove_member xudo agent".to_owned());
    assert!(remove_agent("codex", &machine, &machine).is_err());
    assert!(
        machine
            .files
            .borrow()
            .contains_key("/etc/xudo/harnesses.d/codex.toml")
    );
    // A retry finishes the job.
    *machine.fail.borrow_mut() = None;
    remove_agent("codex", &machine, &machine).unwrap();
    assert!(
        !machine
            .files
            .borrow()
            .contains_key("/etc/xudo/harnesses.d/codex.toml")
    );
}

#[test]
fn remove_of_an_entry_with_no_account_takes_no_membership_out() {
    // A hand-marked session entry names users, not an account.
    let machine = Machine::root().with_file(
        "/etc/xudo/harnesses.d/codex.toml",
        &format!(
            "{MANAGED_MARKER}\n# xudo-joined-groups: xudo\nlabel = \"codex\"\nway = \"session\"\nusers = [\"alice\"]\nreviewers = [\"bob\"]\nmax-sessions = 1\n"
        ),
    );
    machine.files.borrow_mut().insert(
        "/etc/group".to_owned(),
        "root:x:0:\nxudo:x:55:alice\n".to_owned(),
    );
    remove_agent("codex", &machine, &machine).unwrap();
    assert!(
        !machine
            .calls()
            .iter()
            .any(|c| c.starts_with("remove_member"))
    );
    assert_eq!(machine.members("xudo"), ["alice"]);
}

#[test]
fn an_account_database_that_cannot_be_read_stops_the_join_and_the_leave() {
    // The passwd file goes unreadable between the plan and the apply.
    let machine = bare_groups();
    let plan = plan_enrol(&request(), scan(), &machine, &machine).unwrap();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/passwd".to_owned());
    assert!(apply_enrol(&plan, &machine, &machine).is_err());
    assert!(!machine.calls().iter().any(|c| c.starts_with("add_member")));
    // And remove stops, keeping the entry, when the group file cannot be read
    // (it asks about listed membership only, so passwd is not consulted).
    let machine = bare_groups();
    enrol(&machine).unwrap();
    machine
        .unreadable
        .borrow_mut()
        .insert("/etc/group".to_owned());
    assert!(remove_agent("codex", &machine, &machine).is_err());
    assert!(
        machine
            .files
            .borrow()
            .contains_key("/etc/xudo/harnesses.d/codex.toml")
    );
}

#[test]
fn a_registry_entry_that_is_not_text_or_does_not_load_stops_remove_untouched() {
    let machine = Machine::root().with_file("/etc/xudo/harnesses.d/codex.toml", "x");
    machine
        .binary
        .borrow_mut()
        .insert("/etc/xudo/harnesses.d/codex.toml".to_owned());
    assert!(matches!(
        remove_agent("codex", &machine, &machine).unwrap_err(),
        AgentError::NotText(_)
    ));
    let machine = Machine::root().with_file(
        "/etc/xudo/harnesses.d/codex.toml",
        &format!("{MANAGED_MARKER}\nnope = 1\n"),
    );
    assert!(matches!(
        remove_agent("codex", &machine, &machine).unwrap_err(),
        AgentError::Refused(Refusal::Registry(_))
    ));
    assert!(!machine.calls().iter().any(|c| c.starts_with("systemctl")));
}

#[test]
fn a_group_lookup_that_fails_stops_the_join() {
    let machine = bare_groups().failing("group_exists xudo");
    assert!(enrol(&machine).is_err());
    assert!(!machine.calls().iter().any(|c| c.starts_with("add_member")));
}
