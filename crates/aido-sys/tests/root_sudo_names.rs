//! What real `sudo` makes of the file the install writes, and of the names it
//! ignores.
//!
//! `sudo` reads `/etc/sudoers.d` and silently skips every file whose name
//! contains a dot or ends in `~`, so a snippet written as `aido.conf` is a
//! working-looking install that grants nothing. A parser that accepts the file
//! (`visudo -cf`) cannot tell; only asking `sudo` what a user may run can. These
//! tests ask. The lane's script creates the account `aidotest` for the purpose
//! (see `ci/root-test.sh`); see `root_lane.rs` for how a root test starts.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use aido_tests::root_lane::root_guard;

use std::fs::{self, File, Permissions};
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;

use aido_backend::{BackendKind, InstallPlan, PlanStep, detect, snippet::GATE_AUTH};
use aido_sys::{
    Effect, HostInstallOps, HostProbe, HostRunner, InstallError, PendingGateProbe, check_effect,
    execute, run_capture,
};

const SUDOERS_D: &str = "/etc/sudoers.d";
const USER: &str = "aidotest";

fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    clean();
    // The group the rule grants to, with the test account in it.
    let _ = run_capture("/usr/sbin/groupadd", &["--system", "aido"], None);
    let added = run_capture("/usr/sbin/usermod", &["-aG", "aido", USER], None).unwrap();
    assert!(
        added.success,
        "the lane's account {USER} is missing: {}",
        added.stderr
    );
    true
}

fn clean() {
    for name in ["aido", "aido.conf", "aido~", "aido.candidate"] {
        let _ = fs::remove_file(format!("{SUDOERS_D}/{name}"));
    }
    fs::create_dir_all(SUDOERS_D).unwrap();
}

fn plan() -> InstallPlan {
    let backend = detect(&HostProbe).expect("the lane installs sudo before it runs");
    InstallPlan::human_only(&backend).unwrap()
}

/// What `sudo` says the account may run, as text.
fn what_sudo_grants() -> String {
    let output = run_capture("/usr/bin/sudo", &["-l", "-U", USER], None).unwrap();
    format!("{}{}", output.stdout, output.stderr)
}

/// The snippet's text, written under `name` by the test's own hand: the
/// executor would refuse the name, which is the point of writing it directly.
fn write_as(name: &str) {
    let contents = match &plan().steps[1] {
        PlanStep::WriteCandidate { contents, .. } => contents.clone(),
        other => panic!("the second step of the plan is {other:?}"),
    };
    let path = format!("{SUDOERS_D}/{name}");
    File::create(&path)
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o440)).unwrap();
}

#[test]
fn the_installed_snippet_is_in_effect_for_the_group() {
    if !begin_root_test("the_installed_snippet_is_in_effect_for_the_group") {
        return;
    }
    execute(&plan(), &HostInstallOps::system(), &PendingGateProbe).unwrap();
    let granted = what_sudo_grants();
    assert!(
        granted.contains(GATE_AUTH),
        "sudo does not list the gate for {USER}:\n{granted}"
    );
    assert!(granted.contains("PASSWD"), "{granted}");
    assert!(!granted.contains("NOPASSWD"), "{granted}");
    clean();
}

#[test]
fn sudo_ignores_a_snippet_named_with_a_dot() {
    if !begin_root_test("sudo_ignores_a_snippet_named_with_a_dot") {
        return;
    }
    write_as("aido.conf");
    let granted = what_sudo_grants();
    assert!(
        !granted.contains(GATE_AUTH),
        "sudo read a file named with a dot; the guard against that name rests on a false premise:\n{granted}"
    );
    clean();
}

#[test]
fn sudo_ignores_a_snippet_named_with_a_trailing_tilde() {
    if !begin_root_test("sudo_ignores_a_snippet_named_with_a_trailing_tilde") {
        return;
    }
    write_as("aido~");
    let granted = what_sudo_grants();
    assert!(!granted.contains(GATE_AUTH), "{granted}");
    clean();
}

#[test]
fn the_executor_refuses_the_names_sudo_ignores() {
    if !begin_root_test("the_executor_refuses_the_names_sudo_ignores") {
        return;
    }
    for name in ["aido.conf", "aido~"] {
        let mut plan = plan();
        let to = format!("{SUDOERS_D}/{name}");
        for step in &mut plan.steps {
            if let PlanStep::Install {
                to: destination, ..
            } = step
            {
                destination.clone_from(&to);
            }
        }
        let error = execute(&plan, &HostInstallOps::system(), &PendingGateProbe).unwrap_err();
        // Refused as a path aido does not manage, or as a name sudo ignores:
        // either way nothing was written under it.
        assert!(
            matches!(
                error,
                InstallError::NameSudoIgnores { .. } | InstallError::PathNotManaged { .. }
            ),
            "{name}: {error}"
        );
        assert!(fs::symlink_metadata(&to).is_err(), "{name} was written");
    }
    clean();
}

#[test]
fn the_effect_check_sees_the_installed_rule() {
    if !begin_root_test("the_effect_check_sees_the_installed_rule") {
        return;
    }
    execute(&plan(), &HostInstallOps::system(), &PendingGateProbe).unwrap();
    assert_eq!(
        check_effect(&HostRunner, BackendKind::Sudo),
        Effect::InEffect {
            user: USER.to_owned()
        }
    );
    clean();
}

#[test]
fn the_effect_check_sees_that_a_dotted_name_does_nothing() {
    if !begin_root_test("the_effect_check_sees_that_a_dotted_name_does_nothing") {
        return;
    }
    write_as("aido.conf");
    // The file is there, the parser would accept it, and it is not in effect:
    // the one thing a listing of `/etc/sudoers.d` cannot tell.
    assert_eq!(
        check_effect(&HostRunner, BackendKind::Sudo),
        Effect::NotInEffect {
            user: USER.to_owned()
        }
    );
    clean();
}
