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

use xudo_backend::detect;
use xudo_backend::enrol::{EnrolRequest, Refusal, managed_snippet, scan_account};
use xudo_backend::paths_to_root::Input;
use xudo_sys::{
    AgentError, EnrolOps, HostInstallOps, HostProbe, InstallError, LiveHost, Removal, Systemctl,
    apply_enrol, plan_enrol, remove_agent, run_capture,
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

    fn add_member(&self, group: &str, account: &str) -> Result<(), InstallError> {
        self.real.add_member(group, account)
    }

    fn remove_member(&self, group: &str, account: &str) -> Result<(), InstallError> {
        self.real.remove_member(group, account)
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

/// Leaves the account in no agent group: `root_sudo_names` asks sudo about the
/// first member of `xudo`, which must be its own account. Every test ends with it.
fn leave_groups() {
    for group in ["xudo", "xudo-agent"] {
        let _ = run_capture("/usr/bin/gpasswd", &["-d", ACCOUNT, group], None);
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
    // Whatever an earlier test joined the account to.
    for group in ["xudo", "xudo-agent"] {
        let _ = run_capture("/usr/bin/gpasswd", &["-d", ACCOUNT, group], None);
    }
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
    let scan =
        scan_account(&LiveHost, account, &Input::default(), None).map_err(AgentError::Refused)?;
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
    leave_groups();
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
    leave_groups();
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
    leave_groups();
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
    leave_groups();
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
    leave_groups();
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
        matches!(error, AgentError::Refused(Refusal::DropInUntrusted(_)))
            || error.to_string().contains(DROP_IN_DIR),
        "{error}"
    );
    assert!(!Path::new(REGISTRY).exists());
    fs::remove_dir(DROP_IN_DIR).unwrap();
    leave_groups();
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
    leave_groups();
}

/// The members of a group, read from the real `/etc/group`; `None` when the
/// group does not exist.
fn members(group: &str) -> Option<Vec<String>> {
    let prefix = format!("{group}:");
    fs::read_to_string("/etc/group")
        .unwrap()
        .lines()
        .find(|line| line.starts_with(&prefix))
        .map(|line| {
            line.rsplit(':')
                .next()
                .unwrap()
                .split(',')
                .filter(|member| !member.is_empty())
                .map(str::to_owned)
                .collect()
        })
}

fn gid_of(group: &str) -> String {
    let prefix = format!("{group}:");
    fs::read_to_string("/etc/group")
        .unwrap()
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap()
        .split(':')
        .nth(2)
        .unwrap()
        .to_owned()
}

/// Starts a group test from no `xudo` and no `xudo-agent` group at all.
fn without_agent_groups() {
    for group in ["xudo", "xudo-agent"] {
        let _ = run_capture("/usr/sbin/groupdel", &[group], None);
    }
}

#[test]
fn enrol_creates_and_joins_the_real_groups_and_remove_leaves_them_empty() {
    if !begin_root_test("enrol_creates_and_joins_the_real_groups_and_remove_leaves_them_empty") {
        return;
    }
    without_agent_groups();
    let machine = machine();
    enrol(&machine, ACCOUNT).unwrap();
    assert_eq!(members("xudo").unwrap(), [ACCOUNT]);
    assert_eq!(members("xudo-agent").unwrap(), [ACCOUNT]);
    // The kernel's own view: the groups a login of the account would get.
    let groups = run_capture("/usr/bin/id", &["-Gn", ACCOUNT], None).unwrap();
    let groups: Vec<&str> = groups.stdout.split_whitespace().collect();
    assert!(
        groups.contains(&"xudo") && groups.contains(&"xudo-agent"),
        "{groups:?}"
    );
    assert!(
        fs::read_to_string(REGISTRY)
            .unwrap()
            .contains("# xudo-joined-groups: xudo xudo-agent\n")
    );
    remove_agent(LABEL, &machine.real, &machine).unwrap();
    // Out of both, and neither group is deleted.
    assert_eq!(members("xudo").unwrap(), Vec::<String>::new());
    assert_eq!(members("xudo-agent").unwrap(), Vec::<String>::new());
    without_agent_groups();
    leave_groups();
}

#[test]
fn enrol_adds_to_an_operators_groups_without_redefining_them_and_remove_leaves_them() {
    if !begin_root_test(
        "enrol_adds_to_an_operators_groups_without_redefining_them_and_remove_leaves_them",
    ) {
        return;
    }
    without_agent_groups();
    // The operator made both groups, with their own gids and members, and
    // already put the account in `xudo`.
    for (group, gid) in [("xudo", "4241"), ("xudo-agent", "4242")] {
        let made = run_capture("/usr/sbin/groupadd", &["-g", gid, group], None).unwrap();
        assert!(made.success, "{}", made.stderr);
    }
    for (group, member) in [
        ("xudo", "xudotest"),
        ("xudo-agent", "xudotest"),
        ("xudo", ACCOUNT),
    ] {
        let added = run_capture("/usr/sbin/usermod", &["-aG", group, member], None).unwrap();
        assert!(added.success, "{}", added.stderr);
    }
    let machine = machine();
    enrol(&machine, ACCOUNT).unwrap();
    assert_eq!(
        (gid_of("xudo").as_str(), gid_of("xudo-agent").as_str()),
        ("4241", "4242")
    );
    assert!(members("xudo-agent").unwrap().contains(&ACCOUNT.to_owned()));
    assert!(
        members("xudo-agent")
            .unwrap()
            .contains(&"xudotest".to_owned())
    );
    // Only `xudo-agent` was added by enrol, so only that is taken back.
    assert!(
        fs::read_to_string(REGISTRY)
            .unwrap()
            .contains("# xudo-joined-groups: xudo-agent\n")
    );
    remove_agent(LABEL, &machine.real, &machine).unwrap();
    assert!(members("xudo").unwrap().contains(&ACCOUNT.to_owned()));
    assert!(members("xudo").unwrap().contains(&"xudotest".to_owned()));
    assert_eq!(members("xudo-agent").unwrap(), ["xudotest"]);
    assert_eq!(
        (gid_of("xudo").as_str(), gid_of("xudo-agent").as_str()),
        ("4241", "4242")
    );
    without_agent_groups();
    leave_groups();
}

#[test]
fn a_real_sudo_lists_only_the_managed_helper_and_enrol_exempts_only_those_bytes() {
    if !begin_root_test(
        "a_real_sudo_lists_only_the_managed_helper_and_enrol_exempts_only_those_bytes",
    ) {
        return;
    }
    without_agent_groups();
    let backend = detect(&HostProbe).expect("the lane installs sudo before it runs");
    let managed = managed_snippet(Some(&backend)).unwrap();
    let machine = machine();
    enrol(&machine, ACCOUNT).unwrap();
    // The passwordless line, as the later step installs it; here, by hand.
    let snippet = "/etc/sudoers.d/xudo";
    let hand_written = "/etc/sudoers.d/90-xudoagent";
    let install = |text: &str| {
        fs::write(snippet, text).unwrap();
        fs::set_permissions(snippet, Permissions::from_mode(0o440)).unwrap();
    };
    let scan = || {
        let input = Input {
            sudo_exe: Some("/usr/bin/sudo"),
            ..Input::default()
        };
        scan_account(&LiveHost, ACCOUNT, &input, Some(&managed))
            .unwrap()
            .blockers
    };
    install(&managed);
    // The account is in `xudo-agent`, the line grants `-nopass`, and real sudo
    // says so in its listing: that exact file is the one thing not a blocker.
    let listing = run_capture("/usr/bin/sudo", &["-l", "-U", ACCOUNT], None).unwrap();
    assert!(
        listing.stdout.contains("NOPASSWD"),
        "{}{}",
        listing.stdout,
        listing.stderr
    );
    assert_eq!(scan(), Vec::<String>::new());
    // The same file with one byte more.
    install(&format!("{managed}\n"));
    assert!(!scan().is_empty());
    // The exact file, and a hand-written line beside it.
    install(&managed);
    fs::write(hand_written, "%xudo-agent ALL=(ALL) ALL\n").unwrap();
    fs::set_permissions(hand_written, Permissions::from_mode(0o440)).unwrap();
    let blockers = scan();
    assert!(
        blockers.iter().any(|b| b.contains("90-xudoagent")),
        "{blockers:?}"
    );
    fs::remove_file(hand_written).unwrap();
    fs::remove_file(snippet).unwrap();
    remove_agent(LABEL, &machine.real, &machine).unwrap();
    without_agent_groups();
    leave_groups();
}
