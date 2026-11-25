//! Enrolling an agent against the real `/etc`, as real root.
//!
//! The unit tests prove the order and the refusals against a fake machine and
//! a temporary directory. What only uid 0 on a real filesystem can show is that
//! the files land owned by root with the modes the plan names, that the
//! directories are made `0700` and `0755` whatever the umask, that a drop-in
//! directory anyone can write is refused, and that `remove` takes back every
//! file it wrote and leaves the credentials file alone. systemd is not in this
//! container, so `systemctl` is scripted: the tests that need the real one are
//! in `ci/systemd/row.sh`. `ci/root-test.sh` runs this file (see `root_lane.rs`).

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // Tests run `id` and `useradd` by absolute path and read file names as bytes.
    clippy::disallowed_methods
)]

use std::cell::Cell;
use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use xudo_backend::enrol::{EnrolRequest, Refusal, scan_account};
use xudo_backend::paths_to_root::Input;
use xudo_sys::{
    AgentError, EnrolOps, HostInstallOps, InstallError, LiveHost, Removal, Systemctl, apply_enrol,
    plan_enrol, remove_agent,
};
use xudo_tests::root_lane::root_guard;

const LABEL: &str = "rootagent";
const ACCOUNT: &str = "xudoagent";
const REGISTRY: &str = "/etc/xudo/harnesses.d/rootagent.toml";
const DROP_IN_DIR: &str = "/etc/systemd/system/xudo-agent@rootagent.service.d";
const DROP_IN: &str = "/etc/systemd/system/xudo-agent@rootagent.service.d/10-xudo.conf";
const ENV: &str = "/etc/xudo/agents/rootagent.env";

/// The real filesystem, and a `systemctl` that says what a working one would.
struct Machine {
    real: HostInstallOps,
    active: Cell<bool>,
}

impl EnrolOps for Machine {
    fn read_file(&self, path: &str) -> Result<Option<Vec<u8>>, InstallError> {
        self.real.read_file(path)
    }

    fn private_file(&self, path: &str) -> Result<(), InstallError> {
        self.real.private_file(path)
    }

    fn list_dir(&self, path: &str) -> Result<Option<Vec<String>>, InstallError> {
        self.real.list_dir(path)
    }

    fn make_dir(&self, path: &str, mode: u32) -> Result<bool, InstallError> {
        self.real.make_dir(path, mode)
    }

    fn remove_dir(&self, path: &str) -> Result<Removal, InstallError> {
        self.real.remove_dir(path)
    }

    fn systemctl(&self, args: &[&str]) -> Result<Systemctl, InstallError> {
        let stdout = match args[0] {
            "show" if args.iter().any(|a| a.contains("DropInPaths")) => DROP_IN,
            "show" if args.iter().any(|a| a.contains("FragmentPath")) => {
                "/usr/lib/systemd/system/xudo-agent@.service"
            }
            "show" => ACCOUNT,
            "enable" => {
                self.active.set(true);
                ""
            }
            "disable" => {
                self.active.set(false);
                ""
            }
            "is-active" if self.active.get() => "active",
            "is-active" => "inactive",
            _ => "",
        };
        Ok(Systemctl {
            success: true,
            stdout: stdout.to_owned(),
        })
    }
}

fn machine() -> Machine {
    Machine {
        real: HostInstallOps::system(),
        active: Cell::new(false),
    }
}

fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    for path in [REGISTRY, DROP_IN, ENV] {
        let _ = fs::remove_file(path);
    }
    let _ = fs::remove_dir(DROP_IN_DIR);
    fs::create_dir_all("/etc/xudo").unwrap();
    fs::create_dir_all("/etc/systemd/system").unwrap();
    let exists = Command::new("/usr/bin/id")
        .arg(ACCOUNT)
        .output()
        .unwrap()
        .status
        .success();
    if !exists {
        let made = Command::new("/usr/sbin/useradd")
            .args([
                "--system",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                ACCOUNT,
            ])
            .status()
            .unwrap();
        assert!(made.success());
    }
    true
}

fn request(account: &str) -> EnrolRequest {
    EnrolRequest {
        label: LABEL.to_owned(),
        account: account.to_owned(),
        reviewers: vec!["xudotest".to_owned()],
        argv: vec!["/bin/sleep".to_owned(), "3600".to_owned()],
    }
}

fn enrol(machine: &Machine, account: &str) -> Result<(), AgentError> {
    let scan = scan_account(&LiveHost, account, &Input::default()).map_err(AgentError::Refused)?;
    let plan = plan_enrol(&request(account), scan, &machine.real, machine)?;
    apply_enrol(&plan, &machine.real, machine)
}

fn owner_mode(path: &str) -> (u32, u32, u32) {
    let meta = fs::symlink_metadata(path).unwrap();
    (meta.uid(), meta.gid(), meta.mode() & 0o7777)
}

#[test]
fn enrolled_files_are_root_owned_with_the_modes_the_plan_names() {
    if !begin_root_test("enrolled_files_are_root_owned_with_the_modes_the_plan_names") {
        return;
    }
    let machine = machine();
    // A hostile umask must not widen a directory or a file.
    let old = rustix::process::umask(rustix::fs::Mode::empty());
    let enrolled = enrol(&machine, ACCOUNT);
    rustix::process::umask(old);
    enrolled.unwrap();
    assert_eq!(owner_mode(REGISTRY), (0, 0, 0o644));
    assert_eq!(owner_mode(DROP_IN), (0, 0, 0o644));
    assert_eq!(owner_mode(ENV), (0, 0, 0o600));
    assert_eq!(owner_mode("/etc/xudo/agents"), (0, 0, 0o700));
    assert_eq!(owner_mode(DROP_IN_DIR), (0, 0, 0o755));
    let drop_in = fs::read_to_string(DROP_IN).unwrap();
    assert!(drop_in.contains("User=xudoagent\n"), "{drop_in}");
    assert!(
        drop_in.contains("ExecStart=\"/bin/sleep\" \"3600\"\n"),
        "{drop_in}"
    );
    let registry = fs::read_to_string(REGISTRY).unwrap();
    assert!(registry.contains("account = \"xudoagent\""), "{registry}");
    // Nothing is left beside them.
    for dir in ["/etc/xudo/harnesses.d", "/etc/xudo/agents", DROP_IN_DIR] {
        let stray: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.as_encoded_bytes().ends_with(b".candidate"))
            .collect();
        assert!(stray.is_empty(), "{dir}: {stray:?}");
    }
}

#[test]
fn enrolling_the_same_label_twice_changes_nothing_the_second_time() {
    if !begin_root_test("enrolling_the_same_label_twice_changes_nothing_the_second_time") {
        return;
    }
    let machine = machine();
    enrol(&machine, ACCOUNT).unwrap();
    let before = fs::read(REGISTRY).unwrap();
    let error = enrol(&machine, ACCOUNT).unwrap_err();
    assert!(
        matches!(error, AgentError::Refused(Refusal::LabelTaken(_))),
        "{error}"
    );
    assert_eq!(fs::read(REGISTRY).unwrap(), before);
}

#[test]
fn remove_takes_back_every_file_and_keeps_the_credentials() {
    if !begin_root_test("remove_takes_back_every_file_and_keeps_the_credentials") {
        return;
    }
    let machine = machine();
    enrol(&machine, ACCOUNT).unwrap();
    // The operator puts a key in the environment file.
    fs::write(ENV, "# Managed by xudo.\nKEY=secret\n").unwrap();
    let lines = remove_agent(LABEL, &machine.real, &machine).unwrap();
    assert!(!lines.is_empty());
    for gone in [REGISTRY, DROP_IN, DROP_IN_DIR] {
        assert!(!Path::new(gone).exists(), "{gone} survived remove");
    }
    assert_eq!(
        fs::read_to_string(ENV).unwrap().lines().last(),
        Some("KEY=secret")
    );
    assert!(!machine.active.get());
    // Enrolling again over the kept credentials keeps them as they are.
    enrol(&machine, ACCOUNT).unwrap();
    assert_eq!(
        fs::read_to_string(ENV).unwrap().lines().last(),
        Some("KEY=secret")
    );
}

#[test]
fn remove_refuses_a_registry_entry_an_operator_wrote() {
    if !begin_root_test("remove_refuses_a_registry_entry_an_operator_wrote") {
        return;
    }
    fs::create_dir_all("/etc/xudo/harnesses.d").unwrap();
    fs::write(
        REGISTRY,
        "label = \"rootagent\"\nway = \"service\"\naccount = \"xudoagent\"\nreviewers = [\"xudotest\"]\nmax-sessions = 1\n",
    )
    .unwrap();
    let machine = machine();
    let error = remove_agent(LABEL, &machine.real, &machine).unwrap_err();
    assert!(matches!(error, AgentError::NotEnrolled(_)), "{error}");
    assert!(Path::new(REGISTRY).exists());
    assert!(!machine.active.get());
}

#[test]
fn enrol_refuses_an_account_with_a_password_and_root() {
    if !begin_root_test("enrol_refuses_an_account_with_a_password_and_root") {
        return;
    }
    let machine = machine();
    // `xudotest` has a password the lane set: a login anyone who knows it could use.
    let error = enrol(&machine, "xudotest").unwrap_err();
    assert!(
        matches!(error, AgentError::Refused(Refusal::PasswordUsable(_))),
        "{error}"
    );
    let error = enrol(&machine, "root").unwrap_err();
    assert!(
        matches!(error, AgentError::Refused(Refusal::AccountIsRoot(_))),
        "{error}"
    );
    assert!(!Path::new(REGISTRY).exists());
    assert!(!Path::new(DROP_IN_DIR).exists());
}

#[test]
fn enrol_refuses_a_drop_in_directory_anyone_can_write() {
    if !begin_root_test("enrol_refuses_a_drop_in_directory_anyone_can_write") {
        return;
    }
    fs::create_dir(DROP_IN_DIR).unwrap();
    fs::set_permissions(DROP_IN_DIR, Permissions::from_mode(0o777)).unwrap();
    let machine = machine();
    let error = enrol(&machine, ACCOUNT).unwrap_err();
    assert!(
        matches!(error, AgentError::Refused(Refusal::DropInUntrusted(_))),
        "{error}"
    );
    assert!(!Path::new(REGISTRY).exists());
    fs::remove_dir(DROP_IN_DIR).unwrap();
}

#[test]
fn enrol_refuses_a_drop_in_that_could_set_user_after_ours() {
    if !begin_root_test("enrol_refuses_a_drop_in_that_could_set_user_after_ours") {
        return;
    }
    fs::create_dir(DROP_IN_DIR).unwrap();
    fs::write(
        format!("{DROP_IN_DIR}/99-evil.conf"),
        "[Service]\nUser=root\n",
    )
    .unwrap();
    let machine = machine();
    let error = enrol(&machine, ACCOUNT).unwrap_err();
    assert!(
        matches!(error, AgentError::Refused(Refusal::DropInOccupied(_))),
        "{error}"
    );
    assert!(!Path::new(REGISTRY).exists());
    fs::remove_file(format!("{DROP_IN_DIR}/99-evil.conf")).unwrap();
    fs::remove_dir(DROP_IN_DIR).unwrap();
}
