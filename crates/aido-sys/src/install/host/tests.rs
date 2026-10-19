#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::rc::Rc;

use super::*;
use crate::error::SysError;
use crate::exec::Output;

const DOAS: &str = "/etc/doas.conf";
const SUDOERS: &str = "/etc/sudoers.d/aido";
const CANDIDATE: &str = "/etc/sudoers.d/aido.candidate";
const BLOCK: &str = "### aido:begin — do not edit between the markers\n\
                     # Managed by aido. Do not edit between the markers.\n\
                     permit :aido as root cmd /usr/libexec/aido/aido-gate-auth args\n\
                     ### aido:end\n";
const DOAS_C: &str = "/usr/bin/doas";

/// A fresh directory under the workspace `target/`, never `/tmp`.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("test-tmp")
        .join(format!("install-host-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

fn running_as_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

/// Answers each executable with what it was told to, and records every call;
/// may run a hook first, to do something at the moment of the call.
#[derive(Default)]
struct Script {
    replies: RefCell<BTreeMap<String, Result<Output, SysError>>>,
    seen: RefCell<Vec<Vec<String>>>,
    hook: RefCell<Option<Box<dyn Fn()>>>,
}

impl Script {
    fn new() -> Rc<Self> {
        Rc::new(Self::default())
    }

    fn reply(self: &Rc<Self>, exe: &str, code: i32, stderr: &str) {
        let output = Output {
            success: code == 0,
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.to_owned(),
        };
        self.replies.borrow_mut().insert(exe.to_owned(), Ok(output));
    }

    fn on_run(self: &Rc<Self>, hook: impl Fn() + 'static) {
        *self.hook.borrow_mut() = Some(Box::new(hook));
    }

    fn seen(&self) -> Vec<Vec<String>> {
        self.seen.borrow().clone()
    }
}

impl Runner for Rc<Script> {
    fn run(
        &self,
        absolute_exe: &str,
        args: &[&str],
        _stdin: Option<&[u8]>,
    ) -> Result<Output, SysError> {
        let mut line = vec![absolute_exe.to_owned()];
        line.extend(args.iter().map(|a| (*a).to_owned()));
        self.seen.borrow_mut().push(line);
        if let Some(hook) = self.hook.borrow().as_ref() {
            hook();
        }
        self.replies
            .borrow()
            .get(absolute_exe)
            .cloned()
            .unwrap_or_else(|| Err(SysError::unsupported(format!("cannot run {absolute_exe}"))))
    }
}

/// Operations on `dir`, checking ownership against whoever owns it, which is
/// the test's own uid where production demands root.
fn ops_in(dir: &Path, script: &Rc<Script>) -> HostInstallOps {
    let meta = std::fs::metadata(dir).unwrap();
    ops_owned_by(dir, script, meta.uid(), meta.gid())
}

fn ops_owned_by(dir: &Path, script: &Rc<Script>, owner: u32, group: u32) -> HostInstallOps {
    let dir = dir.to_path_buf();
    HostInstallOps {
        open_dir: Box::new(move |_| {
            rustix::fs::open(
                &dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(Some)
            .map_err(|errno| TrustError::Unreadable {
                at: "the test directory".to_owned(),
                reason: errno.to_string(),
            })
        }),
        runner: Box::new(Rc::clone(script)),
        owner,
        group,
        lock_wait: Duration::from_millis(60),
    }
}

fn put(dir: &Path, name: &str, text: &str, mode: u32) {
    let _ = std::fs::remove_file(dir.join(name));
    std::fs::write(dir.join(name), text).unwrap();
    std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap()
}

fn mode_of(dir: &Path, name: &str) -> u32 {
    std::fs::metadata(dir.join(name)).unwrap().mode() & 0o7777
}

fn exists(dir: &Path, name: &str) -> bool {
    std::fs::symlink_metadata(dir.join(name)).is_ok()
}

fn ours(body: &str) -> String {
    format!("{MANAGED_MARKER} Do not edit.\n{body}")
}

fn validator() -> Vec<String> {
    vec![DOAS_C.to_owned(), "-C".to_owned(), "{candidate}".to_owned()]
}

// --- locating ------------------------------------------------------------

#[test]
fn a_path_that_names_no_file_is_refused_before_anything_is_opened() {
    let dir = scratch("locate");
    let ops = ops_in(&dir, &Script::new());
    for bad in ["", "relative", "/", "/etc/", "/etc/..", "/etc/."] {
        let err = ops.identity(bad).unwrap_err();
        assert!(
            matches!(
                err,
                InstallError::Io {
                    operation: "locate",
                    ..
                }
            ),
            "{bad:?}: {err}"
        );
    }
    // A file directly under `/` is in the directory `/`.
    put(&dir, "x", "x", 0o600);
    assert!(ops.identity("/x").is_ok());
}

#[test]
fn every_operation_refuses_a_path_that_names_no_file() {
    let dir = scratch("locate-all");
    let ops = ops_in(&dir, &Script::new());
    let identity = FileIdentity {
        device: 0,
        inode: 0,
    };
    let bad = "relative";
    let argv = validator();
    let results = [
        ops.write_candidate(bad, b"x", 0o440).map(|_| ()),
        ops.install(bad, SUDOERS, identity),
        ops.install(CANDIDATE, bad, identity),
        ops.discard(bad, identity),
        ops.remove_managed(bad).map(|_| ()),
        ops.append_block(bad, BLOCK, &argv, 0o400),
        ops.remove_block(bad).map(|_| ()),
    ];
    for result in results {
        assert!(
            matches!(
                result,
                Err(InstallError::Io {
                    operation: "locate",
                    ..
                })
            ),
            "{result:?}"
        );
    }
}

#[test]
fn a_directory_the_walk_refuses_is_never_written_to() {
    // The real walk. `/tmp` exists and is not a directory root alone can write
    // to, on every platform this runs on, so the walk refuses it and nothing is
    // created there.
    let ops = HostInstallOps::system();
    let err = ops
        .write_candidate("/tmp/aido-test-never-created", b"x", 0o440)
        .unwrap_err();
    assert!(matches!(err, InstallError::Untrusted(_)), "{err}");
    assert!(!Path::new("/tmp/aido-test-never-created").exists());
    assert_eq!(ops.effective_uid(), rustix::process::geteuid().as_raw());
}

#[test]
fn a_directory_that_is_not_there_is_nothing_to_remove_and_nowhere_to_write() {
    // Through the real walk: a machine with no /etc/sudoers.d at all.
    let ops = HostInstallOps::system();
    let missing = "/aido-test-no-such-directory/aido";
    assert_eq!(ops.remove_managed(missing).unwrap(), Removal::Absent);
    assert_eq!(ops.remove_block(missing).unwrap(), Removal::Absent);
    let err = ops.write_candidate(missing, b"x", 0o440).unwrap_err();
    assert!(
        err.to_string().contains("directory does not exist"),
        "{err}"
    );
    let err = ops
        .append_block(missing, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(matches!(err, InstallError::Missing { .. }), "{err}");
}

// --- the candidate -------------------------------------------------------

#[test]
fn a_candidate_is_created_exclusively_with_its_mode_and_owner_on_the_descriptor() {
    let dir = scratch("candidate");
    let ops = ops_in(&dir, &Script::new());
    let identity = ops.write_candidate(CANDIDATE, b"hello\n", 0o440).unwrap();
    assert_eq!(read(&dir, "aido.candidate"), "hello\n");
    assert_eq!(mode_of(&dir, "aido.candidate"), 0o440);
    let meta = std::fs::metadata(dir.join("aido.candidate")).unwrap();
    assert_eq!(identity.inode, meta.ino());
    assert_eq!(ops.identity(CANDIDATE).unwrap(), identity);

    // Writing again never overwrites: the name is somebody's file now.
    let err = ops
        .write_candidate(CANDIDATE, b"other\n", 0o440)
        .unwrap_err();
    assert!(
        matches!(
            err,
            InstallError::Io {
                operation: "create",
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(read(&dir, "aido.candidate"), "hello\n");
}

#[test]
fn a_candidate_is_never_written_through_a_planted_symlink() {
    // A link at the candidate's name, pointing at a file the attacker wants
    // overwritten. O_EXCL|O_NOFOLLOW refuses it and the target is untouched.
    let dir = scratch("candidate-link");
    put(&dir, "victim", "precious\n", 0o600);
    symlink(dir.join("victim"), dir.join("aido.candidate")).unwrap();
    let ops = ops_in(&dir, &Script::new());
    let err = ops
        .write_candidate(CANDIDATE, b"evil\n", 0o440)
        .unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }), "{err}");
    assert_eq!(read(&dir, "victim"), "precious\n");
}

#[test]
fn a_candidate_that_cannot_be_given_to_root_is_removed_not_left_with_the_wrong_owner() {
    if running_as_root() {
        return;
    }
    let dir = scratch("candidate-chown");
    let meta = std::fs::metadata(&dir).unwrap();
    // An owner this process may not give a file to.
    let ops = ops_owned_by(&dir, &Script::new(), meta.uid() + 1, meta.gid());
    let err = ops.write_candidate(CANDIDATE, b"x\n", 0o440).unwrap_err();
    assert!(
        matches!(
            err,
            InstallError::Io {
                operation: "chown",
                ..
            }
        ),
        "{err}"
    );
    assert!(
        !exists(&dir, "aido.candidate"),
        "a half-made candidate survived"
    );
}

#[test]
fn a_failed_read_is_reported_as_the_failure_it_is() {
    // Reading a directory descriptor fails on every platform.
    let dir = scratch("read-fails");
    let fd = rustix::fs::open(&dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
    assert!(read_head(fd, 4).is_err());
    let error = io_std("read", "/p")(std::io::Error::other("boom"));
    assert!(error.to_string().contains("boom"));
}

// --- validating ----------------------------------------------------------

#[test]
fn a_validator_is_judged_by_its_exit_status_and_its_words_are_kept() {
    let dir = scratch("validate");
    let script = Script::new();
    let ops = ops_in(&dir, &script);
    let argv = vec![
        "/usr/sbin/visudo".to_owned(),
        "-cf".to_owned(),
        "/p".to_owned(),
    ];

    script.reply("/usr/sbin/visudo", 0, "");
    ops.validate(&argv).unwrap();

    script.reply("/usr/sbin/visudo", 1, "syntax error near line 3");
    let err = ops.validate(&argv).unwrap_err();
    assert!(
        matches!(&err, InstallError::ValidatorRejected { detail } if detail.contains("line 3")),
        "{err}"
    );
    assert_eq!(script.seen()[0], ["/usr/sbin/visudo", "-cf", "/p"]);
}

#[test]
fn a_validator_that_cannot_run_or_is_not_absolute_rejects() {
    let dir = scratch("validate-missing");
    let ops = ops_in(&dir, &Script::new());
    for argv in [
        vec!["/usr/sbin/visudo".to_owned()],
        vec![],
        vec!["visudo".to_owned()],
    ] {
        let err = ops.validate(&argv).unwrap_err();
        assert!(
            matches!(err, InstallError::ValidatorRejected { .. }),
            "{err}"
        );
    }
}

// --- installing ----------------------------------------------------------

fn installed(dir: &Path, ops: &HostInstallOps, body: &str) -> FileIdentity {
    let _ = std::fs::remove_file(dir.join("aido.candidate"));
    ops.write_candidate(CANDIDATE, ours(body).as_bytes(), 0o440)
        .unwrap()
}

#[test]
fn an_install_atomically_replaces_aidos_own_previous_file() {
    let dir = scratch("install");
    let ops = ops_in(&dir, &Script::new());
    put(&dir, "aido", &ours("old\n"), 0o440);
    let identity = installed(&dir, &ops, "new\n");
    ops.install(CANDIDATE, SUDOERS, identity).unwrap();
    assert_eq!(read(&dir, "aido"), ours("new\n"));
    assert!(!exists(&dir, "aido.candidate"));
    assert_eq!(mode_of(&dir, "aido"), 0o440);
}

#[test]
fn an_install_creates_the_file_when_there_was_none() {
    let dir = scratch("install-fresh");
    let ops = ops_in(&dir, &Script::new());
    let identity = installed(&dir, &ops, "new\n");
    ops.install(CANDIDATE, SUDOERS, identity).unwrap();
    assert_eq!(read(&dir, "aido"), ours("new\n"));
}

#[test]
fn an_install_never_replaces_a_file_an_operator_made() {
    let dir = scratch("install-theirs");
    let ops = ops_in(&dir, &Script::new());
    put(&dir, "aido", "# my own rule\n%wheel ALL=(ALL) ALL\n", 0o440);
    let identity = installed(&dir, &ops, "new\n");
    let err = ops.install(CANDIDATE, SUDOERS, identity).unwrap_err();
    assert!(
        matches!(&err, InstallError::NotOurs { reason, .. } if reason.contains("marker")),
        "{err}"
    );
    assert_eq!(read(&dir, "aido"), "# my own rule\n%wheel ALL=(ALL) ALL\n");
    // The candidate is still there for the executor to discard.
    assert!(exists(&dir, "aido.candidate"));
}

#[test]
fn an_install_refuses_a_destination_that_is_a_symlink_even_to_aidos_own_file() {
    let dir = scratch("install-link");
    let ops = ops_in(&dir, &Script::new());
    put(&dir, "elsewhere", &ours("old\n"), 0o440);
    symlink(dir.join("elsewhere"), dir.join("aido")).unwrap();
    let identity = installed(&dir, &ops, "new\n");
    let err = ops.install(CANDIDATE, SUDOERS, identity).unwrap_err();
    assert!(
        matches!(&err, InstallError::NotOurs { reason, .. } if reason.contains("symbolic")),
        "{err}"
    );
    assert_eq!(read(&dir, "elsewhere"), ours("old\n"));
}

#[test]
fn an_install_refuses_a_directory_a_second_name_or_a_file_that_is_not_roots() {
    let dir = scratch("install-odd");
    let ops = ops_in(&dir, &Script::new());

    std::fs::create_dir(dir.join("aido")).unwrap();
    let identity = installed(&dir, &ops, "new\n");
    let err = ops.install(CANDIDATE, SUDOERS, identity).unwrap_err();
    assert!(err.to_string().contains("not a regular file"), "{err}");
    std::fs::remove_dir(dir.join("aido")).unwrap();

    put(&dir, "other-name", &ours("old\n"), 0o440);
    std::fs::hard_link(dir.join("other-name"), dir.join("aido")).unwrap();
    let identity = installed(&dir, &ops, "new\n");
    let err = ops.install(CANDIDATE, SUDOERS, identity).unwrap_err();
    assert!(err.to_string().contains("more than one name"), "{err}");
    assert_eq!(read(&dir, "other-name"), ours("old\n"));
    std::fs::remove_file(dir.join("aido")).unwrap();

    // A file owned by someone other than the trusted owner.
    put(&dir, "aido", &ours("old\n"), 0o440);
    let meta = std::fs::metadata(&dir).unwrap();
    let strict = ops_owned_by(&dir, &Script::new(), meta.uid() + 1, meta.gid());
    let identity = installed(&dir, &ops, "new\n");
    let err = strict.install(CANDIDATE, SUDOERS, identity).unwrap_err();
    assert!(err.to_string().contains("not owned by root"), "{err}");
}

#[test]
fn an_install_refuses_a_candidate_swapped_after_it_was_validated() {
    let dir = scratch("install-swapped");
    let ops = ops_in(&dir, &Script::new());
    let identity = installed(&dir, &ops, "validated\n");
    std::fs::remove_file(dir.join("aido.candidate")).unwrap();
    put(&dir, "aido.candidate", &ours("swapped in\n"), 0o440);
    let err = ops.install(CANDIDATE, SUDOERS, identity).unwrap_err();
    assert!(
        matches!(err, InstallError::CandidateReplaced { .. }),
        "{err}"
    );
    assert!(!exists(&dir, "aido"), "an unvalidated file was installed");
}

#[test]
fn an_install_without_a_candidate_or_with_an_unreadable_name_fails_cleanly() {
    let dir = scratch("install-missing");
    let ops = ops_in(&dir, &Script::new());
    let identity = FileIdentity {
        device: 0,
        inode: 0,
    };
    let err = ops.install(CANDIDATE, SUDOERS, identity).unwrap_err();
    assert!(
        matches!(
            err,
            InstallError::Io {
                operation: "stat",
                ..
            }
        ),
        "{err}"
    );

    let long = format!("/etc/sudoers.d/{}", "a".repeat(300));
    let identity = installed(&dir, &ops, "x\n");
    let err = ops.install(CANDIDATE, &long, identity).unwrap_err();
    assert!(
        matches!(
            err,
            InstallError::Io {
                operation: "open",
                ..
            }
        ),
        "{err}"
    );
    assert!(exists(&dir, "aido.candidate"));
}

// --- discarding and removing --------------------------------------------

#[test]
fn a_discard_removes_only_the_inode_it_was_given() {
    let dir = scratch("discard");
    let ops = ops_in(&dir, &Script::new());
    let identity = installed(&dir, &ops, "x\n");
    ops.discard(CANDIDATE, identity).unwrap();
    assert!(!exists(&dir, "aido.candidate"));
    // Already gone is fine.
    ops.discard(CANDIDATE, identity).unwrap();

    // Something else at the name now: left alone, and said so.
    put(&dir, "aido.candidate", "somebody else's\n", 0o600);
    let err = ops.discard(CANDIDATE, identity).unwrap_err();
    assert!(
        matches!(err, InstallError::CandidateReplaced { .. }),
        "{err}"
    );
    assert_eq!(read(&dir, "aido.candidate"), "somebody else's\n");

    let long = format!("/etc/sudoers.d/{}", "a".repeat(300));
    let err = ops.discard(&long, identity).unwrap_err();
    assert!(
        matches!(
            err,
            InstallError::Io {
                operation: "stat",
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn a_removal_deletes_aidos_file_and_nothing_else() {
    let dir = scratch("remove");
    let ops = ops_in(&dir, &Script::new());
    put(&dir, "aido", &ours("rule\n"), 0o440);
    put(&dir, "other", "keep me\n", 0o440);
    assert_eq!(ops.remove_managed(SUDOERS).unwrap(), Removal::Removed);
    assert!(!exists(&dir, "aido"));
    assert_eq!(read(&dir, "other"), "keep me\n");
    // Twice is fine.
    assert_eq!(ops.remove_managed(SUDOERS).unwrap(), Removal::Absent);
}

#[test]
fn a_removal_refuses_every_file_that_is_not_provably_aidos() {
    let dir = scratch("remove-refuse");
    let ops = ops_in(&dir, &Script::new());

    // An operator's own `aido`.
    put(&dir, "aido", "%me ALL=(ALL) NOPASSWD: ALL\n", 0o440);
    let err = ops.remove_managed(SUDOERS).unwrap_err();
    assert!(matches!(err, InstallError::NotOurs { .. }), "{err}");
    assert!(exists(&dir, "aido"));

    // Shorter than the marker: it cannot begin with it.
    put(&dir, "aido", "#", 0o440);
    assert!(ops.remove_managed(SUDOERS).is_err());
    std::fs::remove_file(dir.join("aido")).unwrap();

    // A link, to a file that is aido's own.
    put(&dir, "target", &ours("x\n"), 0o440);
    symlink(dir.join("target"), dir.join("aido")).unwrap();
    let err = ops.remove_managed(SUDOERS).unwrap_err();
    assert!(err.to_string().contains("symbolic"), "{err}");
    assert!(exists(&dir, "target"), "the link's target was removed");
    std::fs::remove_file(dir.join("aido")).unwrap();

    // A directory.
    std::fs::create_dir(dir.join("aido")).unwrap();
    assert!(ops.remove_managed(SUDOERS).is_err());
    std::fs::remove_dir(dir.join("aido")).unwrap();

    // A second hard link.
    std::fs::hard_link(dir.join("target"), dir.join("aido")).unwrap();
    let err = ops.remove_managed(SUDOERS).unwrap_err();
    assert!(err.to_string().contains("more than one name"), "{err}");
    assert!(exists(&dir, "target"));
}

// --- the group -----------------------------------------------------------

#[test]
fn the_group_is_looked_up_by_getent_and_its_answers_are_read_strictly() {
    let dir = scratch("group-exists");
    let script = Script::new();
    let ops = ops_in(&dir, &script);
    script.reply("/usr/bin/getent", 0, "");
    assert!(ops.group_exists("aido").unwrap());
    script.reply("/usr/bin/getent", 2, "");
    assert!(!ops.group_exists("aido").unwrap());
    // Any other answer is not "absent": creating a group on a guess could
    // collide with a real one.
    script.reply("/usr/bin/getent", 1, "usage");
    let err = ops.group_exists("aido").unwrap_err();
    assert!(matches!(err, InstallError::Group { .. }), "{err}");
    assert_eq!(script.seen()[0], ["/usr/bin/getent", "group", "aido"]);

    let missing = Script::new();
    assert!(ops_in(&dir, &missing).group_exists("aido").is_err());
}

#[test]
fn the_group_is_created_with_whichever_tool_the_distribution_has() {
    let dir = scratch("group-create");

    let debian = Script::new();
    debian.reply("/usr/sbin/groupadd", 0, "");
    ops_in(&dir, &debian).create_group("aido").unwrap();
    assert_eq!(
        debian.seen(),
        [vec!["/usr/sbin/groupadd", "--system", "aido"]]
    );

    // Alpine has no groupadd: the first tool cannot run, the second can.
    let alpine = Script::new();
    alpine.reply("/usr/sbin/addgroup", 0, "");
    ops_in(&dir, &alpine).create_group("aido").unwrap();
    assert_eq!(alpine.seen().len(), 2);
    assert_eq!(alpine.seen()[1], ["/usr/sbin/addgroup", "-S", "aido"]);

    // A tool that ran and refused is reported, and the next is still tried.
    let refused = Script::new();
    refused.reply("/usr/sbin/groupadd", 9, "group exists");
    let err = ops_in(&dir, &refused).create_group("aido").unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("group exists") && text.contains("addgroup"),
        "{text}"
    );
}

// --- a shared file -------------------------------------------------------

#[test]
fn a_block_is_added_to_the_operators_file_after_the_backend_accepts_the_whole_result() {
    let dir = scratch("block");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o644);
    let script = Script::new();
    script.reply(DOAS_C, 0, "");
    // What the parser was shown, at the moment it was shown it.
    let seen = Rc::new(RefCell::new(String::new()));
    let (watch, at) = (Rc::clone(&seen), dir.join("doas.conf.aido-new"));
    script.on_run(move || *watch.borrow_mut() = std::fs::read_to_string(&at).unwrap());
    let ops = ops_in(&dir, &script);

    ops.append_block(DOAS, BLOCK, &validator(), 0o400).unwrap();

    assert_eq!(
        read(&dir, "doas.conf"),
        format!("permit persist :wheel\n{BLOCK}")
    );
    assert_eq!(*seen.borrow(), read(&dir, "doas.conf"));
    assert_eq!(script.seen()[0], [DOAS_C, "-C", "/etc/doas.conf.aido-new"]);
    assert_eq!(mode_of(&dir, "doas.conf"), 0o400);
    assert!(!exists(&dir, "doas.conf.aido-new"));
}

#[test]
fn reinstalling_replaces_the_block_and_keeps_every_operator_line() {
    let dir = scratch("block-again");
    let old = format!(
        "# mine\n{}# also mine\n",
        BLOCK.replace("permit :aido", "permit :OLD")
    );
    put(&dir, "doas.conf", &old, 0o600);
    let script = Script::new();
    script.reply(DOAS_C, 0, "");
    ops_in(&dir, &script)
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap();
    assert_eq!(
        read(&dir, "doas.conf"),
        format!("# mine\n{BLOCK}# also mine\n")
    );
}

#[test]
fn a_block_the_backend_rejects_never_reaches_the_operators_file() {
    let dir = scratch("block-rejected");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o644);
    let script = Script::new();
    script.reply(DOAS_C, 1, "syntax error");
    let err = ops_in(&dir, &script)
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(
        matches!(err, InstallError::ValidatorRejected { .. }),
        "{err}"
    );
    assert_eq!(read(&dir, "doas.conf"), "permit persist :wheel\n");
    assert_eq!(mode_of(&dir, "doas.conf"), 0o644);
    assert!(
        !exists(&dir, "doas.conf.aido-new"),
        "the copy was left behind"
    );
}

#[test]
fn a_copy_swapped_while_the_backend_looked_at_it_is_not_installed_or_removed() {
    let dir = scratch("block-swapped");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o644);
    let script = Script::new();
    script.reply(DOAS_C, 0, "");
    let at = dir.join("doas.conf.aido-new");
    script.on_run(move || {
        std::fs::remove_file(&at).unwrap();
        std::fs::write(&at, "permit nopass keepenv :evil as root\n").unwrap();
    });
    let err = ops_in(&dir, &script)
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(
        matches!(err, InstallError::CandidateReplaced { .. }),
        "{err}"
    );
    assert_eq!(read(&dir, "doas.conf"), "permit persist :wheel\n");
    assert!(
        exists(&dir, "doas.conf.aido-new"),
        "a file aido did not write was removed"
    );
}

#[test]
fn a_rejected_copy_that_was_also_swapped_is_reported_as_left_behind() {
    let dir = scratch("block-left");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o644);
    let script = Script::new();
    script.reply(DOAS_C, 1, "no");
    let at = dir.join("doas.conf.aido-new");
    script.on_run(move || {
        std::fs::remove_file(&at).unwrap();
        std::fs::write(&at, "x\n").unwrap();
    });
    let err = ops_in(&dir, &script)
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(matches!(err, InstallError::LeftBehind { .. }), "{err}");
}

#[test]
fn a_stale_copy_blocks_the_edit_and_the_original_is_untouched() {
    let dir = scratch("block-stale");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o644);
    put(&dir, "doas.conf.aido-new", "left by a crash\n", 0o600);
    let script = Script::new();
    let err = ops_in(&dir, &script)
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(
        matches!(
            err,
            InstallError::Io {
                operation: "create",
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(read(&dir, "doas.conf"), "permit persist :wheel\n");
    assert_eq!(read(&dir, "doas.conf.aido-new"), "left by a crash\n");
    assert!(script.seen().is_empty());
}

#[test]
fn a_shared_file_that_is_missing_is_not_created() {
    let dir = scratch("block-missing");
    let script = Script::new();
    let err = ops_in(&dir, &script)
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(matches!(err, InstallError::Missing { .. }), "{err}");
    assert!(!exists(&dir, "doas.conf"));
    assert!(err.to_string().contains("never creates"));
}

#[test]
fn a_shared_file_that_is_a_symlink_is_never_edited_through_it() {
    let dir = scratch("block-link");
    put(&dir, "victim", "precious\n", 0o600);
    symlink(dir.join("victim"), dir.join("doas.conf")).unwrap();
    let script = Script::new();
    let err = ops_in(&dir, &script)
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(
        matches!(
            err,
            InstallError::Io {
                operation: "open",
                ..
            }
        ),
        "{err}"
    );
    assert_eq!(read(&dir, "victim"), "precious\n");
}

#[test]
fn a_shared_file_anyone_else_could_have_written_is_not_edited() {
    let dir = scratch("block-unsafe");
    let script = Script::new();
    let ops = ops_in(&dir, &script);

    for setup in [0o664, 0o606] {
        put(&dir, "doas.conf", "permit persist :wheel\n", setup);
        let err = ops
            .append_block(DOAS, BLOCK, &validator(), 0o400)
            .unwrap_err();
        assert!(
            matches!(&err, InstallError::UnsafeFile { reason, .. }
                if reason.contains("writable by group or others")),
            "{setup:o}: {err}"
        );
        assert_eq!(read(&dir, "doas.conf"), "permit persist :wheel\n");
    }
    std::fs::remove_file(dir.join("doas.conf")).unwrap();

    // Owned by someone who is not the trusted owner.
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o644);
    let meta = std::fs::metadata(&dir).unwrap();
    let strict = ops_owned_by(&dir, &script, meta.uid() + 1, meta.gid());
    let err = strict
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(err.to_string().contains("not owned by root"), "{err}");
    std::fs::remove_file(dir.join("doas.conf")).unwrap();

    // Too big to be a configuration file.
    std::fs::write(dir.join("doas.conf"), vec![b'#'; (1 << 20) + 1]).unwrap();
    std::fs::set_permissions(
        dir.join("doas.conf"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let err = ops
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
    assert!(script.seen().is_empty());
}

#[test]
fn sentinels_that_do_not_pair_stop_the_edit_and_nothing_is_guessed() {
    let dir = scratch("block-ambiguous");
    let text = "### aido:begin — do not edit between the markers\npermit :x\n";
    put(&dir, "doas.conf", text, 0o600);
    let script = Script::new();
    let ops = ops_in(&dir, &script);
    let err = ops
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(matches!(err, InstallError::Block { .. }), "{err}");
    let err = ops.remove_block(DOAS).unwrap_err();
    assert!(matches!(err, InstallError::Block { .. }), "{err}");
    assert_eq!(read(&dir, "doas.conf"), text);
    assert!(script.seen().is_empty());
}

#[test]
fn a_malformed_block_is_refused_before_a_copy_is_made() {
    let dir = scratch("block-bad");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o600);
    let script = Script::new();
    let err = ops_in(&dir, &script)
        .append_block(DOAS, "permit nopass :evil as root\n", &validator(), 0o400)
        .unwrap_err();
    assert!(matches!(err, InstallError::Block { .. }), "{err}");
    assert!(!exists(&dir, "doas.conf.aido-new"));
}

#[test]
fn the_shared_file_is_locked_and_a_busy_lock_is_waited_for_then_refused() {
    let dir = scratch("block-locked");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o600);
    let script = Script::new();
    script.reply(DOAS_C, 0, "");
    let ops = ops_in(&dir, &script);

    let holder = File::open(dir.join("doas.conf")).unwrap();
    flock(&holder, FlockOperation::LockExclusive).unwrap();
    let err = ops
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    assert!(matches!(err, InstallError::Locked { .. }), "{err}");
    assert_eq!(read(&dir, "doas.conf"), "permit persist :wheel\n");

    // A holder that lets go within the wait is waited for.
    let mut patient = ops_in(&dir, &script);
    patient.lock_wait = Duration::from_secs(10);
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        drop(holder);
    });
    patient
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap();
    release.join().unwrap();
    assert!(read(&dir, "doas.conf").contains("aido:begin"));
}

#[test]
fn a_shared_file_replaced_while_waiting_for_its_lock_is_not_edited() {
    // The lock is on an inode. If the name moved on while this writer waited,
    // it holds a lock on a file that is no longer the shared one.
    let dir = scratch("block-replaced");
    put(&dir, "doas.conf", "permit persist :wheel\n", 0o600);
    let script = Script::new();
    script.reply(DOAS_C, 0, "");
    let mut ops = ops_in(&dir, &script);
    ops.lock_wait = Duration::from_secs(10);

    let (ready, go) = std::sync::mpsc::channel();
    let at = dir.join("doas.conf");
    let holder = std::thread::spawn(move || {
        let file = File::open(&at).unwrap();
        flock(&file, FlockOperation::LockExclusive).unwrap();
        ready.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        std::fs::rename(&at, at.with_extension("moved")).unwrap();
        std::fs::write(&at, "a different file\n").unwrap();
        std::fs::set_permissions(&at, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(file);
    });
    go.recv().unwrap();
    let err = ops
        .append_block(DOAS, BLOCK, &validator(), 0o400)
        .unwrap_err();
    holder.join().unwrap();
    assert!(
        matches!(&err, InstallError::Locked { reason, .. } if reason.contains("replaced")),
        "{err}"
    );
    assert_eq!(read(&dir, "doas.conf"), "a different file\n");
}

#[test]
fn a_block_is_removed_alone_and_the_operators_lines_and_mode_are_kept() {
    let dir = scratch("block-remove");
    let text = format!("# mine\npermit persist :wheel\n{BLOCK}# also mine\n");
    put(&dir, "doas.conf", &text, 0o640);
    let script = Script::new();
    let ops = ops_in(&dir, &script);
    assert_eq!(ops.remove_block(DOAS).unwrap(), Removal::Removed);
    assert_eq!(
        read(&dir, "doas.conf"),
        "# mine\npermit persist :wheel\n# also mine\n"
    );
    assert_eq!(mode_of(&dir, "doas.conf"), 0o640);
    // Removing a block needs no parser: it only takes whole lines away.
    assert!(script.seen().is_empty());
    // Nothing left to remove.
    assert_eq!(ops.remove_block(DOAS).unwrap(), Removal::Absent);
    assert!(!exists(&dir, "doas.conf.aido-new"));
}

#[test]
fn removing_a_block_from_a_file_that_is_not_there_is_not_an_error() {
    let dir = scratch("block-remove-missing");
    let ops = ops_in(&dir, &Script::new());
    assert_eq!(ops.remove_block(DOAS).unwrap(), Removal::Absent);
    assert!(!exists(&dir, "doas.conf"));
}
