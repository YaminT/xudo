#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use aido_backend::capability::{Capability, CapabilityMatrix};
use aido_backend::{Backend, uninstall_plan};

use super::fake::FakeInstallOps;
use super::*;
use crate::SysError;
use crate::exec::Output;

fn backend(kind: BackendKind, drop_in: bool) -> Backend {
    let mut caps = CapabilityMatrix::from_supported([
        Capability::DisableCredentialCache,
        Capability::AllocatePty,
        Capability::PerCommandDefaults,
        Capability::ValidateNamedFile,
    ]);
    if drop_in {
        caps = caps.with(Capability::DropInDirectory);
    }
    Backend {
        kind,
        exe: kind.exe().to_owned(),
        version: "test".to_owned(),
        capabilities: caps,
    }
}

fn sudo_plan() -> InstallPlan {
    InstallPlan::human_only(&backend(BackendKind::Sudo, true)).unwrap()
}

fn doas_block_plan() -> InstallPlan {
    InstallPlan::human_only(&backend(BackendKind::Doas, false)).unwrap()
}

struct Probe(ProbeResult);

impl InstallProbe for Probe {
    fn verify(&self, _argv: &[String]) -> ProbeResult {
        self.0.clone()
    }
}

fn run(plan: &InstallPlan, ops: &FakeInstallOps) -> Result<InstallReport, InstallError> {
    execute(plan, ops, &PendingGateProbe)
}

#[test]
fn a_sudo_install_runs_in_the_order_that_makes_it_safe() {
    let ops = FakeInstallOps::root();
    let report = run(&sudo_plan(), &ops).unwrap();
    let calls = ops.calls();
    let at = |needle: &str| {
        calls
            .iter()
            .position(|c| c.starts_with(needle))
            .unwrap_or(usize::MAX)
    };
    // The group, then the candidate, then validation, then the identity
    // check, then the rename: the ordering is the security property.
    assert!(at("group_exists") < at("write_candidate"));
    assert!(at("write_candidate") < at("validate"));
    assert!(at("validate") < at("identity"));
    assert!(at("identity") < at("install"));
    assert!(calls.contains(&"create_group aido".to_owned()));
    assert_eq!(report.backend, BackendKind::Sudo);
    assert!(report.notices[0].contains("password-required"));
}

#[test]
fn a_completed_install_is_never_called_verified_without_the_probe() {
    let report = run(&sudo_plan(), &FakeInstallOps::root()).unwrap();
    assert!(
        matches!(&report.verification, Verification::Unverified { reason }
            if reason.contains("gate")),
        "claimed {:?} with no gate to run",
        report.verification
    );
}

#[test]
fn a_probe_that_passes_is_what_makes_an_install_verified() {
    let report = execute(
        &sudo_plan(),
        &FakeInstallOps::root(),
        &Probe(ProbeResult::Verified),
    )
    .unwrap();
    assert_eq!(report.verification, Verification::Verified);
}

#[test]
fn a_failed_probe_takes_off_what_the_install_put_on() {
    // An integration that is installed and not in effect looks installed.
    let ops = FakeInstallOps::root();
    let err = execute(
        &sudo_plan(),
        &ops,
        &Probe(ProbeResult::Failed {
            reason: "no rule permits it".to_owned(),
        }),
    )
    .unwrap_err();
    assert!(matches!(err, InstallError::ProbeFailed { .. }), "{err}");
    assert!(
        ops.calls()
            .contains(&"remove_managed /etc/sudoers.d/aido".to_owned())
    );
}

#[test]
fn a_failed_probe_that_cannot_clean_up_says_what_it_left() {
    let ops = FakeInstallOps::root().failing("remove_managed");
    let err = execute(
        &sudo_plan(),
        &ops,
        &Probe(ProbeResult::Failed {
            reason: "x".to_owned(),
        }),
    )
    .unwrap_err();
    assert!(
        matches!(&err, InstallError::LeftBehind { path, cause, .. }
            if path == "/etc/sudoers.d/aido"
                && matches!(**cause, InstallError::ProbeFailed { .. })),
        "{err}"
    );
}

#[test]
fn a_failed_probe_removes_a_block_it_appended() {
    let ops = FakeInstallOps::root();
    let err = execute(
        &doas_block_plan(),
        &ops,
        &Probe(ProbeResult::Failed {
            reason: "x".to_owned(),
        }),
    )
    .unwrap_err();
    assert!(matches!(err, InstallError::ProbeFailed { .. }));
    assert!(
        ops.calls()
            .contains(&"remove_block /etc/doas.conf".to_owned())
    );
}

#[test]
fn a_failed_probe_that_cannot_remove_a_block_says_what_it_left() {
    let ops = FakeInstallOps::root().failing("remove_block");
    let err = execute(
        &doas_block_plan(),
        &ops,
        &Probe(ProbeResult::Failed {
            reason: "x".to_owned(),
        }),
    )
    .unwrap_err();
    assert!(matches!(err, InstallError::LeftBehind { .. }), "{err}");
}

#[test]
fn refuses_to_run_as_anyone_but_root_before_reading_the_plan() {
    for uid in [1000, 1, 65534] {
        let ops = FakeInstallOps::as_uid(uid);
        let err = run(&sudo_plan(), &ops).unwrap_err();
        assert_eq!(err, InstallError::NotRoot { uid });
        assert_eq!(ops.calls(), Vec::<String>::new(), "touched the machine");
    }
    assert!(
        InstallError::NotRoot { uid: 5 }
            .to_string()
            .contains("requires root")
    );
}

#[test]
fn refuses_a_plan_that_names_a_file_aido_does_not_write() {
    for path in [
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers.d/other",
        "/etc/sudoers.d/aido/../../passwd",
        "/etc/sudoers.d/aido.candidate.candidate",
        "/etc/doas.conf.candidate",
        "etc/sudoers.d/aido",
        "",
    ] {
        let steps = [
            PlanStep::Remove {
                path: path.to_owned(),
            },
            PlanStep::WriteCandidate {
                path: path.to_owned(),
                contents: "x".to_owned(),
                mode: 0o440,
            },
            PlanStep::ValidateBySubstitution {
                candidate: path.to_owned(),
                reason: "r".to_owned(),
            },
            PlanStep::AppendBlock {
                path: path.to_owned(),
                block: "b".to_owned(),
            },
            PlanStep::RemoveBlock {
                path: path.to_owned(),
                begin: DOAS_BEGIN.to_owned(),
                end: DOAS_END.to_owned(),
            },
            PlanStep::Install {
                from: path.to_owned(),
                to: SUDOERS_PATH.to_owned(),
            },
            PlanStep::Install {
                from: format!("{SUDOERS_PATH}.candidate"),
                to: path.to_owned(),
            },
        ];
        for step in steps {
            let ops = FakeInstallOps::root();
            let plan = InstallPlan {
                backend: BackendKind::Sudo,
                steps: vec![
                    PlanStep::CreateGroup {
                        name: "aido".to_owned(),
                    },
                    step,
                ],
            };
            let err = run(&plan, &ops).unwrap_err();
            assert!(
                matches!(err, InstallError::PathNotManaged { .. }),
                "{path:?}: {err}"
            );
            // Refused before any step ran, the group step included.
            assert_eq!(ops.calls(), Vec::<String>::new());
        }
    }
    assert!(
        InstallError::PathNotManaged {
            path: "/etc/passwd".to_owned()
        }
        .to_string()
        .contains("not a file aido writes")
    );
}

#[test]
fn refuses_to_create_a_group_other_than_aidos() {
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![PlanStep::CreateGroup {
            name: "sudo".to_owned(),
        }],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(matches!(err, InstallError::GroupNotManaged { .. }));
    assert!(err.to_string().contains("sudo"));
    assert!(ops.calls().is_empty());
}

#[test]
fn refuses_to_install_over_a_name_sudo_ignores() {
    // `aido.conf` installs cleanly and grants nothing: sudo skips it.
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![PlanStep::Install {
            from: format!("{SUDOERS_PATH}.candidate"),
            to: format!("{SUDOERS_PATH}.candidate"),
        }],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(matches!(err, InstallError::NameSudoIgnores { .. }), "{err}");
    assert!(ops.calls().is_empty());
    assert!(err.to_string().contains("ignores"));
}

#[test]
fn the_shipped_sudoers_path_is_a_name_sudo_honours() {
    let (dir, name) = split(SUDOERS_PATH).unwrap();
    assert_eq!(dir, "/etc/sudoers.d");
    assert!(!sudo_skips(name), "{name} would be ignored by sudo");
    for ignored in ["aido.conf", "aido~", ".aido", "a.b", "aido.candidate", "x~"] {
        assert!(sudo_skips(ignored), "{ignored}");
    }
    assert!(!sudo_skips("aido"));
}

#[test]
fn refuses_to_rename_between_directories() {
    let plan = InstallPlan {
        backend: BackendKind::Doas,
        steps: vec![PlanStep::Install {
            from: format!("{SUDOERS_PATH}.candidate"),
            to: DOAS_DROP_IN_PATH.to_owned(),
        }],
    };
    let err = run(&plan, &FakeInstallOps::root()).unwrap_err();
    assert!(matches!(err, InstallError::CrossDirectory { .. }), "{err}");
    assert!(err.to_string().contains("not atomic"));
}

#[test]
fn a_doas_drop_in_installs_through_the_same_checks() {
    let ops = FakeInstallOps::root();
    let plan = InstallPlan::human_only(&backend(BackendKind::Doas, true)).unwrap();
    run(&plan, &ops).unwrap();
    assert!(
        ops.calls()
            .iter()
            .any(|c| c.starts_with("install /etc/doas.d/60-aido.conf.candidate"))
    );
}

#[test]
fn refuses_modes_that_are_writable_or_open_to_others() {
    for mode in [0o640, 0o660, 0o666, 0o444, 0o441, 0o4440, 0o200, 0o420] {
        let plan = InstallPlan {
            backend: BackendKind::Sudo,
            steps: vec![PlanStep::WriteCandidate {
                path: format!("{SUDOERS_PATH}.candidate"),
                contents: "x".to_owned(),
                mode,
            }],
        };
        let err = run(&plan, &FakeInstallOps::root()).unwrap_err();
        assert!(
            matches!(err, InstallError::UnsafeMode { .. }),
            "{mode:o}: {err}"
        );
    }
    assert!(
        InstallError::UnsafeMode {
            path: "p".to_owned(),
            mode: 0o644
        }
        .to_string()
        .contains("0644")
    );
}

#[test]
fn refuses_a_validator_that_does_not_validate_the_candidate() {
    for argv in [
        vec![],
        vec![
            "visudo".to_owned(),
            "-cf".to_owned(),
            "{candidate}".to_owned(),
        ],
        vec!["/usr/sbin/visudo".to_owned(), "-c".to_owned()],
        vec![
            "/usr/sbin/visudo".to_owned(),
            "-cf".to_owned(),
            "/etc/sudoers".to_owned(),
        ],
        vec![
            "/usr/sbin/visudo".to_owned(),
            "{candidate}".to_owned(),
            "{candidate}".to_owned(),
        ],
    ] {
        let plan = InstallPlan {
            backend: BackendKind::Sudo,
            steps: vec![PlanStep::Validate { argv: argv.clone() }],
        };
        let err = run(&plan, &FakeInstallOps::root()).unwrap_err();
        assert!(matches!(err, InstallError::BadValidator { .. }), "{argv:?}");
        assert!(err.to_string().contains("refusing the validator"));
    }
}

#[test]
fn refuses_to_edit_between_markers_aido_did_not_write() {
    let plan = InstallPlan {
        backend: BackendKind::Doas,
        steps: vec![PlanStep::RemoveBlock {
            path: DOAS_CONF_PATH.to_owned(),
            begin: "# my own section".to_owned(),
            end: DOAS_END.to_owned(),
        }],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert_eq!(err, InstallError::ForeignMarkers);
    assert!(ops.calls().is_empty());
    assert!(err.to_string().contains("markers"));
}

#[test]
fn refuses_to_install_before_the_candidate_is_validated() {
    // Install first, discover the file is wrong afterwards: by then
    // privilege has been granted. Refused structurally, whatever the plan.
    let candidate = format!("{SUDOERS_PATH}.candidate");
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![
            PlanStep::WriteCandidate {
                path: candidate.clone(),
                contents: "x".to_owned(),
                mode: 0o440,
            },
            PlanStep::Install {
                from: candidate.clone(),
                to: SUDOERS_PATH.to_owned(),
            },
        ],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(matches!(err, InstallError::OutOfOrder { .. }), "{err}");
    assert!(
        err.to_string()
            .contains("before the candidate was validated")
    );
    assert!(!ops.calls().iter().any(|c| c.starts_with("install ")));
    // And the candidate that was written is removed again.
    assert!(ops.calls().iter().any(|c| c.starts_with("discard ")));
}

#[test]
fn refuses_to_install_a_file_it_did_not_write() {
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![PlanStep::Install {
            from: format!("{SUDOERS_PATH}.candidate"),
            to: SUDOERS_PATH.to_owned(),
        }],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(matches!(err, InstallError::OutOfOrder { .. }), "{err}");
    assert!(!ops.calls().iter().any(|c| c.starts_with("install ")));
}

#[test]
fn refuses_to_install_a_different_candidate_than_the_one_validated() {
    let candidate = format!("{SUDOERS_PATH}.candidate");
    let plan = InstallPlan {
        backend: BackendKind::Doas,
        steps: vec![
            PlanStep::WriteCandidate {
                path: candidate,
                contents: "x".to_owned(),
                mode: 0o440,
            },
            PlanStep::Install {
                from: format!("{DOAS_DROP_IN_PATH}.candidate"),
                to: DOAS_DROP_IN_PATH.to_owned(),
            },
        ],
    };
    let err = run(&plan, &FakeInstallOps::root()).unwrap_err();
    assert!(matches!(err, InstallError::OutOfOrder { .. }), "{err}");
}

#[test]
fn refuses_a_second_candidate_while_one_is_pending() {
    let write = PlanStep::WriteCandidate {
        path: format!("{SUDOERS_PATH}.candidate"),
        contents: "x".to_owned(),
        mode: 0o440,
    };
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![write.clone(), write],
    };
    let err = run(&plan, &FakeInstallOps::root()).unwrap_err();
    assert!(err.to_string().contains("second candidate"));
}

#[test]
fn refuses_a_plan_that_ends_with_a_candidate_never_installed() {
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![PlanStep::WriteCandidate {
            path: format!("{SUDOERS_PATH}.candidate"),
            contents: "x".to_owned(),
            mode: 0o440,
        }],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(err.to_string().contains("never installed"));
    assert!(ops.calls().iter().any(|c| c.starts_with("discard ")));
}

#[test]
fn refuses_a_validator_that_validated_nothing() {
    let plan = InstallPlan {
        backend: BackendKind::Doas,
        steps: vec![PlanStep::Validate {
            argv: vec![
                "/usr/bin/doas".to_owned(),
                "-C".to_owned(),
                "{candidate}".to_owned(),
            ],
        }],
    };
    let err = run(&plan, &FakeInstallOps::root()).unwrap_err();
    assert!(err.to_string().contains("validated nothing"), "{err}");
}

#[test]
fn refuses_a_block_appended_without_a_validator_before_it() {
    let plan = InstallPlan {
        backend: BackendKind::Doas,
        steps: vec![PlanStep::AppendBlock {
            path: DOAS_CONF_PATH.to_owned(),
            block: "b".to_owned(),
        }],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(err.to_string().contains("no validator"), "{err}");
    assert!(ops.calls().is_empty());
}

#[test]
fn a_backend_that_cannot_validate_a_named_file_is_refused_not_trusted() {
    // sudo-rs's visudo checks only /etc/sudoers. A plan that can only
    // validate by substitution has no honest check, so nothing is written
    // after the candidate, and the candidate is removed.
    let candidate = format!("{SUDOERS_PATH}.candidate");
    let plan = InstallPlan {
        backend: BackendKind::SudoRs,
        steps: vec![
            PlanStep::WriteCandidate {
                path: candidate.clone(),
                contents: "x".to_owned(),
                mode: 0o440,
            },
            PlanStep::ValidateBySubstitution {
                candidate,
                reason: "visudo checks only /etc/sudoers".to_owned(),
            },
            PlanStep::Install {
                from: format!("{SUDOERS_PATH}.candidate"),
                to: SUDOERS_PATH.to_owned(),
            },
        ],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(
        matches!(err, InstallError::ValidationUnavailable { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("only /etc/sudoers"));
    assert!(!ops.calls().iter().any(|c| c.starts_with("install ")));
    assert!(ops.calls().iter().any(|c| c.starts_with("discard ")));
}

#[test]
fn a_rejected_candidate_is_removed_and_nothing_is_installed() {
    let ops = FakeInstallOps::root().failing("validate");
    let err = run(&sudo_plan(), &ops).unwrap_err();
    assert!(
        matches!(err, InstallError::ValidatorRejected { .. }),
        "{err}"
    );
    let calls = ops.calls();
    assert!(
        !calls.iter().any(|c| c.starts_with("install ")),
        "{calls:?}"
    );
    assert!(calls.iter().any(|c| c.starts_with("discard ")), "{calls:?}");
    assert!(err.to_string().contains("rejected the candidate"));
}

#[test]
fn a_candidate_swapped_after_validation_is_refused_and_left_alone() {
    // The parser blessed one inode; the path now names another. Removing it
    // would delete a file this run did not write, installing it would
    // install one nobody validated.
    let ops = FakeInstallOps::root().with_identity_after_validate(FileIdentity {
        device: 1,
        inode: 999,
    });
    let err = run(&sudo_plan(), &ops).unwrap_err();
    assert!(
        matches!(err, InstallError::CandidateReplaced { .. }),
        "{err}"
    );
    let calls = ops.calls();
    assert!(
        !calls.iter().any(|c| c.starts_with("install ")),
        "{calls:?}"
    );
    assert!(
        !calls.iter().any(|c| c.starts_with("discard ")),
        "{calls:?}"
    );
    assert!(err.to_string().contains("no longer the file"));
}

#[test]
fn an_identity_that_cannot_be_read_after_validation_fails_and_cleans_up() {
    let ops = FakeInstallOps::root().failing("identity");
    let err = run(&sudo_plan(), &ops).unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }), "{err}");
    assert!(ops.calls().iter().any(|c| c.starts_with("discard ")));
}

#[test]
fn a_failed_rename_leaves_the_old_file_and_removes_the_candidate() {
    let ops = FakeInstallOps::root().failing("install");
    let err = run(&sudo_plan(), &ops).unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }), "{err}");
    assert!(ops.calls().iter().any(|c| c.starts_with("discard ")));
    assert!(!ops.calls().iter().any(|c| c.starts_with("remove_managed")));
}

#[test]
fn a_failed_write_stops_before_anything_else() {
    let ops = FakeInstallOps::root().failing("write_candidate");
    let err = run(&sudo_plan(), &ops).unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }));
    assert!(!ops.calls().iter().any(|c| c.starts_with("validate")));
    // Nothing was created by this run, so nothing is discarded.
    assert!(!ops.calls().iter().any(|c| c.starts_with("discard")));
}

#[test]
fn a_candidate_that_cannot_be_removed_is_reported_with_its_cause() {
    let ops = FakeInstallOps::root()
        .failing("validate")
        .failing("discard");
    let err = run(&sudo_plan(), &ops).unwrap_err();
    assert!(
        matches!(&err, InstallError::LeftBehind { path, cause, .. }
            if path == "/etc/sudoers.d/aido.candidate"
                && matches!(**cause, InstallError::ValidatorRejected { .. })),
        "{err}"
    );
    assert!(err.to_string().contains("could not be removed"));
}

#[test]
fn an_existing_group_is_left_alone() {
    let ops = FakeInstallOps::root().with_group();
    let report = run(&sudo_plan(), &ops).unwrap();
    assert!(!ops.calls().iter().any(|c| c.starts_with("create_group")));
    assert!(report.events[0].contains("already exists"));
}

#[test]
fn a_group_that_cannot_be_looked_up_or_created_stops_the_install() {
    for method in ["group_exists", "create_group"] {
        let ops = FakeInstallOps::root().failing(method);
        let err = run(&sudo_plan(), &ops).unwrap_err();
        assert!(matches!(err, InstallError::Group { .. }), "{method}: {err}");
        assert!(!ops.calls().iter().any(|c| c.starts_with("write_candidate")));
    }
}

#[test]
fn a_doas_block_is_validated_on_a_copy_before_it_replaces_the_file() {
    let ops = FakeInstallOps::root();
    let report = run(&doas_block_plan(), &ops).unwrap();
    let append = ops
        .calls()
        .into_iter()
        .find(|c| c.starts_with("append_block"))
        .unwrap();
    assert!(append.contains("/etc/doas.conf"));
    assert!(append.contains("/usr/bin/doas -C {candidate}"), "{append}");
    assert!(report.events.iter().any(|e| e.contains("aido's block")));
}

#[test]
fn a_failed_block_append_installs_nothing_and_is_reported() {
    let ops = FakeInstallOps::root().failing("append_block");
    let err = run(&doas_block_plan(), &ops).unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }), "{err}");
    // The append failed, so there is nothing of this run's to take off.
    assert!(!ops.calls().iter().any(|c| c.starts_with("remove_block")));
}

#[test]
fn uninstall_removes_exactly_what_install_writes() {
    let ops = FakeInstallOps::root()
        .with_present(&["/etc/sudoers.d/aido", "/etc/sudoers.d/aido.candidate"]);
    let report = run(&uninstall_plan(BackendKind::Sudo), &ops).unwrap();
    assert_eq!(
        ops.calls(),
        [
            "remove_managed /etc/sudoers.d/aido",
            "remove_managed /etc/sudoers.d/aido.candidate"
        ]
    );
    assert!(report.events.iter().all(|e| e.starts_with("removed ")));
    assert_eq!(report.verification, Verification::NotRequired);
}

#[test]
fn a_second_uninstall_succeeds_and_says_nothing_was_there() {
    let ops = FakeInstallOps::root();
    let report = run(&uninstall_plan(BackendKind::Doas), &ops).unwrap();
    assert!(report.events.iter().any(|e| e.contains("was not present")));
    assert!(report.events.iter().any(|e| e.contains("no aido block")));
}

#[test]
fn a_doas_uninstall_removes_the_drop_in_and_the_block_it_wrote() {
    let ops = FakeInstallOps::root().with_present(&[DOAS_DROP_IN_PATH, DOAS_CONF_PATH]);
    let report = run(&uninstall_plan(BackendKind::Doas), &ops).unwrap();
    assert_eq!(
        ops.calls(),
        [
            "remove_managed /etc/doas.d/60-aido.conf".to_owned(),
            "remove_block /etc/doas.conf".to_owned()
        ]
    );
    assert!(
        report
            .events
            .iter()
            .any(|e| e.contains("removed aido's block"))
    );
}

#[test]
fn an_uninstall_whose_block_cannot_be_removed_stops_and_says_so() {
    let ops = FakeInstallOps::root().failing("remove_block");
    let err = run(&uninstall_plan(BackendKind::Doas), &ops).unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }), "{err}");
}

#[test]
fn an_uninstall_that_meets_a_file_that_is_not_aidos_stops() {
    let ops = FakeInstallOps::root().failing_with(
        "remove_managed",
        InstallError::NotOurs {
            path: SUDOERS_PATH.to_owned(),
            reason: "no marker".to_owned(),
        },
    );
    let err = run(&uninstall_plan(BackendKind::Sudo), &ops).unwrap_err();
    assert!(matches!(err, InstallError::NotOurs { .. }));
    assert!(err.to_string().contains("not a file aido wrote"));
}

#[test]
fn an_install_plan_without_a_probe_is_reported_unverified() {
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: sudo_plan()
            .steps
            .into_iter()
            .filter(|s| !matches!(s, PlanStep::FunctionalProbe { .. }))
            .collect(),
    };
    let report = run(&plan, &FakeInstallOps::root()).unwrap();
    assert!(
        matches!(&report.verification, Verification::Unverified { reason }
            if reason.contains("no functional probe")),
        "{:?}",
        report.verification
    );
}

#[test]
fn the_pending_probe_never_verifies_and_says_why() {
    let result = PendingGateProbe.verify(&[]);
    assert!(
        matches!(&result, ProbeResult::Unavailable { reason } if reason.contains("C1")),
        "{result:?}"
    );
}

#[test]
fn the_refusing_installer_changes_nothing() {
    let err = RefusingInstaller.run(&sudo_plan()).unwrap_err();
    assert_eq!(err, InstallError::NoInstaller);
    assert!(err.to_string().contains("cannot modify the machine"));
}

#[test]
fn the_host_installer_refuses_a_caller_that_is_not_root() {
    // The real installer on the real machine: refused first, so safe to
    // run anywhere a developer is not root. Under root it would be the real
    // thing, which no test may do.
    if rustix::process::geteuid().as_raw() == 0 {
        return;
    }
    let err = HostInstaller.run(&sudo_plan()).unwrap_err();
    assert!(matches!(err, InstallError::NotRoot { .. }), "{err}");
}

#[test]
fn every_error_has_words_an_operator_can_act_on() {
    let samples = [
        InstallError::Missing {
            path: "/etc/doas.conf".to_owned(),
        },
        InstallError::Locked {
            path: "p".to_owned(),
            reason: "busy".to_owned(),
        },
        InstallError::Block {
            path: "p".to_owned(),
            source: BlockError::Ambiguous,
        },
        InstallError::Group {
            name: "aido".to_owned(),
            reason: "r".to_owned(),
        },
        InstallError::Io {
            operation: "open",
            path: "p".to_owned(),
            reason: "r".to_owned(),
        },
        InstallError::ValidationUnavailable {
            reason: "why".to_owned(),
        },
        InstallError::CandidateReplaced {
            path: "p".to_owned(),
        },
    ];
    for sample in samples {
        assert!(!sample.to_string().is_empty());
    }
}

/// A runner that has nothing: every question about the backend is unchecked.
struct NoRunner;

impl Runner for NoRunner {
    fn run(&self, _exe: &str, _args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, SysError> {
        Err(SysError::Unsupported {
            operation: "anything".to_owned(),
        })
    }
}

fn report(verification: Verification) -> InstallReport {
    InstallReport {
        backend: BackendKind::Sudo,
        events: vec![],
        notices: vec!["first".to_owned()],
        verification,
    }
}

#[test]
fn a_finished_install_carries_the_backends_account_as_a_notice_of_its_own() {
    let finished = finish(
        Ok(report(Verification::Unverified {
            reason: "r".to_owned(),
        })),
        &NoRunner,
    )
    .unwrap();
    assert_eq!(finished.notices.len(), 2);
    assert_eq!(finished.notices[0], "first");
    assert!(
        finished.notices[1].contains("not checked"),
        "{:?}",
        finished.notices
    );
    // Whatever the check says, it did not make the install verified.
    assert!(matches!(
        finished.verification,
        Verification::Unverified { .. }
    ));
}

#[test]
fn an_install_that_wrote_nothing_is_not_asked_about() {
    let finished = finish(Ok(report(Verification::NotRequired)), &NoRunner).unwrap();
    assert_eq!(finished.notices, ["first"]);
}

#[test]
fn a_refusal_passes_through_the_check_unchanged() {
    let err = finish(Err(InstallError::NotRoot { uid: 7 }), &NoRunner).unwrap_err();
    assert_eq!(err, InstallError::NotRoot { uid: 7 });
}

mod dotted_names {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// `sudo` skips a drop-in whose name has a dot in it or ends in `~`, so
        /// an install onto one reports success and grants nothing. Whatever
        /// the name, the plan that installs there is refused before a single
        /// effect, and the refusal is never the "success" a dotted name looks
        /// like.
        #[test]
        fn no_name_sudo_ignores_is_ever_installed_to(
            stem in "[A-Za-z0-9_-]{0,8}",
            tail in prop_oneof![
                Just(String::new()),
                "\\.[A-Za-z0-9._~-]{0,8}",
                "[A-Za-z0-9._-]{0,4}~",
            ],
            dotted in any::<bool>(),
        ) {
            // A name sudo skips: a dot anywhere, or a trailing tilde.
            let name = if dotted {
                format!("{stem}.{tail}")
            } else {
                format!("{stem}{tail}~")
            };
            prop_assume!(!name.is_empty() && sudo_skips(&name));
            let to = format!("/etc/sudoers.d/{name}");
            let plan = InstallPlan {
                backend: BackendKind::Sudo,
                steps: vec![PlanStep::Install {
                    from: format!("{SUDOERS_PATH}.candidate"),
                    to,
                }],
            };
            let ops = FakeInstallOps::root();
            let err = run(&plan, &ops).unwrap_err();
            prop_assert!(
                matches!(
                    err,
                    InstallError::NameSudoIgnores { .. } | InstallError::PathNotManaged { .. }
                ),
                "{err}"
            );
            prop_assert!(ops.calls().is_empty());
        }
    }
}
