//! The install executor against the real `/etc`, as real root.
//!
//! `HostInstallOps::system()` writes `root:root` files into `/etc/sudoers.d`,
//! which only uid 0 can do, and the claims worth proving about it are the ones
//! a mode cannot fake: the file that lands is owned by root and moded `0440`,
//! a candidate the backend's own parser rejects leaves the old file exactly as
//! it was, and a file aido did not write is neither replaced nor removed
//! however it is dressed. `ci/root-test.sh` runs this file in a container with
//! `sudo` installed (see `root_lane.rs` for how the lane works and for what a
//! root test must do first).
//!
//! The container is thrown away with the run, so these tests write straight to
//! `/etc`. Each one begins by clearing what the others leave there.

#![cfg(feature = "root-tests")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use aido_tests::root_lane::root_guard;

use std::fs::{self, File, OpenOptions, Permissions};
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use aido_backend::{InstallPlan, PlanStep, detect, uninstall_plan};
use aido_sys::{HostInstallOps, HostProbe, InstallError, PendingGateProbe, Verification, execute};

const SNIPPET: &str = "/etc/sudoers.d/aido";
const CANDIDATE: &str = "/etc/sudoers.d/aido.candidate";
const DOAS_CONF: &str = "/etc/doas.conf";
/// Somewhere an attacker's link or symlink target can sit: in `/etc`, root's.
const DOAS_COPY: &str = "/etc/doas.conf.aido-new";
const ELSEWHERE: &str = "/etc/aido-root-install-elsewhere";

/// `true` when the calling test should go on. See `root_lane.rs`.
fn begin_root_test(test: &str) -> bool {
    if !root_guard(test) {
        return false;
    }
    clean();
    true
}

/// Leaves `/etc` as a machine with sudo and nothing of aido's.
fn clean() {
    for path in [SNIPPET, CANDIDATE, DOAS_CONF, DOAS_COPY, ELSEWHERE] {
        let _ = fs::remove_file(path);
    }
    fs::create_dir_all("/etc/sudoers.d").unwrap();
}

/// The plan for the sudo this container has, built the way `aido install`
/// builds it.
fn plan() -> InstallPlan {
    let backend = detect(&HostProbe).expect("the lane installs sudo before it runs");
    InstallPlan::human_only(&backend).unwrap()
}

fn install(plan: &InstallPlan) -> Result<Verification, InstallError> {
    execute(plan, &HostInstallOps::system(), &PendingGateProbe).map(|report| report.verification)
}

fn marked(body: &str) -> String {
    format!("{}\n{body}", aido_backend::snippet::MANAGED_MARKER)
}

/// A file as an operator might leave it, owned by root.
fn operator_file(path: &str, contents: &str) {
    let mut file = File::create(path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o440)).unwrap();
}

#[test]
fn installed_snippet_is_0440_root_root() {
    if !begin_root_test("installed_snippet_is_0440_root_root") {
        return;
    }
    let verification = install(&plan()).unwrap();
    // Nothing exercised the gate, so nothing is claimed.
    assert!(matches!(verification, Verification::Unverified { .. }));

    let meta = fs::symlink_metadata(SNIPPET).unwrap();
    assert!(meta.file_type().is_file());
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o7777, meta.nlink()),
        (0, 0, 0o440, 1)
    );
    let text = fs::read_to_string(SNIPPET).unwrap();
    assert!(text.starts_with(aido_backend::snippet::MANAGED_MARKER));
    assert!(text.contains("PASSWD:"), "{text}");
    assert!(
        !text.contains("NOPASSWD"),
        "no passwordless rule is written before M4:\n{text}"
    );
    assert!(
        fs::symlink_metadata(CANDIDATE).is_err(),
        "the candidate was left behind"
    );
}

#[test]
fn installing_twice_changes_nothing_the_second_time() {
    if !begin_root_test("installing_twice_changes_nothing_the_second_time") {
        return;
    }
    install(&plan()).unwrap();
    let first = fs::read(SNIPPET).unwrap();
    install(&plan()).unwrap();
    assert_eq!(fs::read(SNIPPET).unwrap(), first);
    assert_eq!(fs::metadata(SNIPPET).unwrap().mode() & 0o7777, 0o440);
}

#[test]
fn uninstall_removes_what_install_wrote_and_nothing_else() {
    if !begin_root_test("uninstall_removes_what_install_wrote_and_nothing_else") {
        return;
    }
    let neighbour = "/etc/sudoers.d/operators-own";
    operator_file(neighbour, "# the operator's own\n");
    install(&plan()).unwrap();
    let removal = uninstall_plan(plan().backend);
    install(&removal).unwrap();
    assert!(fs::symlink_metadata(SNIPPET).is_err());
    assert_eq!(
        fs::read_to_string(neighbour).unwrap(),
        "# the operator's own\n"
    );
    fs::remove_file(neighbour).unwrap();
}

#[test]
fn rejected_candidate_leaves_previous_state() {
    if !begin_root_test("rejected_candidate_leaves_previous_state") {
        return;
    }
    install(&plan()).unwrap();
    let before = fs::read(SNIPPET).unwrap();
    let before_meta = fs::metadata(SNIPPET).unwrap();

    // A candidate sudo's own parser refuses, behind the real validator.
    let mut broken = plan();
    for step in &mut broken.steps {
        if let PlanStep::WriteCandidate { contents, .. } = step {
            *contents = marked("this is not a sudoers file ((\n");
        }
    }
    let error = install(&broken).unwrap_err();
    assert!(
        matches!(error, InstallError::ValidatorRejected { .. }),
        "{error}"
    );

    assert_eq!(fs::read(SNIPPET).unwrap(), before, "the old file changed");
    let after = fs::metadata(SNIPPET).unwrap();
    assert_eq!(
        (after.ino(), after.mode() & 0o7777, after.uid()),
        (before_meta.ino(), 0o440, 0),
        "the old file was replaced"
    );
    assert!(
        fs::symlink_metadata(CANDIDATE).is_err(),
        "a rejected candidate was left in /etc/sudoers.d, where sudo reads"
    );
}

#[test]
fn never_replaces_or_removes_an_operator_file() {
    if !begin_root_test("never_replaces_or_removes_an_operator_file") {
        return;
    }
    // Root's own file, with no marker: the operator's `aido`, not ours.
    let theirs = "# written by a human, for a reason\nroot ALL=(ALL) ALL\n";
    operator_file(SNIPPET, theirs);

    let error = install(&plan()).unwrap_err();
    assert!(matches!(error, InstallError::NotOurs { .. }), "{error}");
    assert_eq!(fs::read_to_string(SNIPPET).unwrap(), theirs);

    let error = install(&uninstall_plan(plan().backend)).unwrap_err();
    assert!(matches!(error, InstallError::NotOurs { .. }), "{error}");
    assert_eq!(fs::read_to_string(SNIPPET).unwrap(), theirs);
    assert!(
        fs::symlink_metadata(CANDIDATE).is_err(),
        "the refused install left its candidate"
    );
}

#[test]
fn refuses_to_follow_a_symlink_at_the_destination() {
    if !begin_root_test("refuses_to_follow_a_symlink_at_the_destination") {
        return;
    }
    operator_file(ELSEWHERE, &marked("# somewhere else\n"));
    symlink(ELSEWHERE, SNIPPET).unwrap();

    let error = install(&plan()).unwrap_err();
    assert!(matches!(error, InstallError::NotOurs { .. }), "{error}");
    let error = install(&uninstall_plan(plan().backend)).unwrap_err();
    assert!(matches!(error, InstallError::NotOurs { .. }), "{error}");

    assert!(
        fs::symlink_metadata(SNIPPET)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link was replaced"
    );
    assert_eq!(
        fs::read_to_string(ELSEWHERE).unwrap(),
        marked("# somewhere else\n"),
        "a write went through the link"
    );
}

#[test]
fn refuses_a_target_with_nlink_above_one() {
    if !begin_root_test("refuses_a_target_with_nlink_above_one") {
        return;
    }
    // Carries the marker, is root's, is a regular file: only the second name
    // says it is not ours alone. Replacing it would not touch the other name,
    // and removing it would leave one that still reads as aido's.
    operator_file(ELSEWHERE, &marked("# two names\n"));
    fs::hard_link(ELSEWHERE, SNIPPET).unwrap();
    assert_eq!(fs::metadata(SNIPPET).unwrap().nlink(), 2);

    let error = install(&plan()).unwrap_err();
    assert!(matches!(error, InstallError::NotOurs { .. }), "{error}");
    let error = install(&uninstall_plan(plan().backend)).unwrap_err();
    assert!(matches!(error, InstallError::NotOurs { .. }), "{error}");
    assert_eq!(
        fs::read_to_string(SNIPPET).unwrap(),
        marked("# two names\n")
    );
    assert_eq!(fs::metadata(SNIPPET).unwrap().nlink(), 2);
}

#[test]
fn refuses_to_edit_through_a_symlinked_shared_file() {
    if !begin_root_test("refuses_to_edit_through_a_symlinked_shared_file") {
        return;
    }
    // The shared file doas reads is a link to somewhere else. Editing it in
    // place would write wherever the link points. The validator is a stand-in
    // that accepts anything, so that only the symlink is on trial.
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(ELSEWHERE)
        .unwrap()
        .write_all(b"permit nopass root\n")
        .unwrap();
    symlink(ELSEWHERE, DOAS_CONF).unwrap();
    let plan = InstallPlan {
        backend: aido_backend::BackendKind::Doas,
        steps: vec![
            PlanStep::Validate {
                argv: vec!["/usr/bin/true".to_owned(), "{candidate}".to_owned()],
            },
            PlanStep::AppendBlock {
                path: DOAS_CONF.to_owned(),
                block: format!(
                    "{}\npermit :aido\n{}\n",
                    aido_backend::snippet::DOAS_BEGIN,
                    aido_backend::snippet::DOAS_END
                ),
            },
        ],
    };

    install(&plan).unwrap_err();
    assert_eq!(
        fs::read_to_string(ELSEWHERE).unwrap(),
        "permit nopass root\n",
        "the edit went through the link"
    );
    assert!(
        fs::symlink_metadata(DOAS_CONF)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link was replaced"
    );
    assert!(Path::new("/etc").read_dir().unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .as_encoded_bytes()
            .starts_with(b"doas.conf.")
    }));
}

/// A group no account in the container has, so a copy that was made `root:root`
/// shows.
const WHEEL_LIKE: u32 = 4321;

/// The doas install, with a stand-in validator that accepts anything: only the
/// file's owner and mode are on trial here.
fn doas_plan() -> InstallPlan {
    InstallPlan {
        backend: aido_backend::BackendKind::Doas,
        steps: vec![
            PlanStep::Validate {
                argv: vec!["/usr/bin/true".to_owned(), "{candidate}".to_owned()],
            },
            PlanStep::AppendBlock {
                path: DOAS_CONF.to_owned(),
                block: format!(
                    "{}\npermit :aido\n{}\n",
                    aido_backend::snippet::DOAS_BEGIN,
                    aido_backend::snippet::DOAS_END
                ),
            },
        ],
    }
}

/// A real `/etc/doas.conf`, `root:<group>` with `mode`.
fn operator_doas(contents: &str, group: u32, mode: u32) {
    fs::write(DOAS_CONF, contents).unwrap();
    std::os::unix::fs::chown(DOAS_CONF, Some(0), Some(group)).unwrap();
    fs::set_permissions(DOAS_CONF, Permissions::from_mode(mode)).unwrap();
}

fn owner_group_mode(path: &str) -> (u32, u32, u32) {
    let meta = fs::metadata(path).unwrap();
    (meta.uid(), meta.gid(), meta.mode() & 0o7777)
}

#[test]
fn a_doas_install_and_uninstall_keep_the_operators_owner_group_and_mode() {
    if !begin_root_test("a_doas_install_and_uninstall_keep_the_operators_owner_group_and_mode") {
        return;
    }
    // `root:wheel 0640`, as a distribution ships it. The copy that replaces it
    // must not come back `root:root 0400`.
    operator_doas("permit persist :wheel\n", WHEEL_LIKE, 0o640);
    install(&doas_plan()).unwrap();
    assert!(
        fs::read_to_string(DOAS_CONF)
            .unwrap()
            .contains("permit :aido")
    );
    assert_eq!(owner_group_mode(DOAS_CONF), (0, WHEEL_LIKE, 0o640));

    install(&uninstall_plan(aido_backend::BackendKind::Doas)).unwrap();
    assert_eq!(
        fs::read_to_string(DOAS_CONF).unwrap(),
        "permit persist :wheel\n"
    );
    assert_eq!(owner_group_mode(DOAS_CONF), (0, WHEEL_LIKE, 0o640));
}

#[test]
fn a_doas_install_refuses_a_file_with_a_set_id_bit_and_changes_nothing() {
    if !begin_root_test("a_doas_install_refuses_a_file_with_a_set_id_bit_and_changes_nothing") {
        return;
    }
    operator_doas("permit persist :wheel\n", 0, 0o4644);
    let error = install(&doas_plan()).unwrap_err();
    assert!(matches!(error, InstallError::UnsafeFile { .. }), "{error}");
    assert_eq!(
        fs::read_to_string(DOAS_CONF).unwrap(),
        "permit persist :wheel\n"
    );
    assert_eq!(owner_group_mode(DOAS_CONF), (0, 0, 0o4644));
    assert!(fs::symlink_metadata(DOAS_COPY).is_err());
}

/// What a run killed right after creating the copy leaves: root's, mode 0000
/// (which only root can read, so only this lane can show it is handled).
fn crash_left(path: &str, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o000)).unwrap();
}

#[test]
fn a_crash_left_doas_copy_does_not_block_the_next_install_or_uninstall() {
    if !begin_root_test("a_crash_left_doas_copy_does_not_block_the_next_install_or_uninstall") {
        return;
    }
    operator_doas("permit persist :wheel\n", WHEEL_LIKE, 0o640);
    crash_left(DOAS_COPY, "");
    install(&doas_plan()).unwrap();
    assert!(
        fs::symlink_metadata(DOAS_COPY).is_err(),
        "the copy was left"
    );
    assert_eq!(owner_group_mode(DOAS_CONF), (0, WHEEL_LIKE, 0o640));

    // And the uninstall's own: the text it would have written, cut short.
    crash_left(DOAS_COPY, "permit persi");
    install(&uninstall_plan(aido_backend::BackendKind::Doas)).unwrap();
    assert_eq!(
        fs::read_to_string(DOAS_CONF).unwrap(),
        "permit persist :wheel\n"
    );
    assert!(
        fs::symlink_metadata(DOAS_COPY).is_err(),
        "the copy was left"
    );
}

#[test]
fn a_doas_copy_aido_did_not_write_is_refused_and_kept() {
    if !begin_root_test("a_doas_copy_aido_did_not_write_is_refused_and_kept") {
        return;
    }
    operator_doas("permit persist :wheel\n", 0, 0o600);
    fs::write(DOAS_COPY, "an operator's own work in progress\n").unwrap();
    let error = install(&doas_plan()).unwrap_err();
    assert!(
        matches!(error, InstallError::StaleCandidate { .. }),
        "{error}"
    );
    assert!(error.to_string().contains(DOAS_COPY), "{error}");
    assert_eq!(
        fs::read_to_string(DOAS_COPY).unwrap(),
        "an operator's own work in progress\n"
    );
    assert_eq!(
        fs::read_to_string(DOAS_CONF).unwrap(),
        "permit persist :wheel\n"
    );
}

#[test]
fn a_crash_left_sudoers_candidate_does_not_block_install_or_uninstall() {
    if !begin_root_test("a_crash_left_sudoers_candidate_does_not_block_install_or_uninstall") {
        return;
    }
    // Empty, as a crash right after the create leaves it, and cut part-way
    // through the snippet.
    for left in ["", aido_backend::snippet::MANAGED_MARKER] {
        crash_left(CANDIDATE, left);
        install(&plan()).unwrap();
        assert!(fs::symlink_metadata(CANDIDATE).is_err(), "{left:?}");
        assert!(fs::symlink_metadata(SNIPPET).is_ok());

        crash_left(CANDIDATE, left);
        install(&uninstall_plan(plan().backend)).unwrap();
        assert!(fs::symlink_metadata(CANDIDATE).is_err(), "{left:?}");
        assert!(fs::symlink_metadata(SNIPPET).is_err(), "{left:?}");
    }
}

#[test]
fn a_sudoers_candidate_aido_did_not_write_is_refused_and_kept() {
    if !begin_root_test("a_sudoers_candidate_aido_did_not_write_is_refused_and_kept") {
        return;
    }
    operator_file(CANDIDATE, "# the operator's own\n");
    let error = install(&plan()).unwrap_err();
    assert!(
        matches!(error, InstallError::StaleCandidate { .. }),
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(CANDIDATE).unwrap(),
        "# the operator's own\n"
    );
    assert!(fs::symlink_metadata(SNIPPET).is_err());
}
