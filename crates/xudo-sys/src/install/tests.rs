#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use xudo_backend::capability::{Capability, CapabilityMatrix};
use xudo_backend::snippet::{PTRACE_DROP_IN, PTRACE_DROP_IN_PATH};
use xudo_backend::{Backend, uninstall_plan};

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
    execute(
        plan,
        ops,
        &Probe(ProbeResult::Unavailable {
            reason: "no gate to run".to_owned(),
        }),
    )
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
    assert!(calls.contains(&"create_group xudo".to_owned()));
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
fn a_probe_that_fails_keeps_the_validated_install_and_is_not_verified() {
    // The gate may refuse for a reason that is not the snippet's (a multicall
    // `id`). The snippet passed the backend's parser, so it stays.
    for plan in [sudo_plan(), doas_block_plan()] {
        let ops = FakeInstallOps::root();
        let report = execute(
            &plan,
            &ops,
            &Probe(ProbeResult::Failed {
                reason: "no rule permits it".to_owned(),
            }),
        )
        .unwrap();
        assert!(
            matches!(&report.verification, Verification::Unverified { reason }
                if reason == "the probe ran and failed: no rule permits it"),
            "{report:?}"
        );
        assert!(
            !ops.calls()
                .iter()
                .any(|c| c.starts_with("remove_managed") || c.starts_with("remove_block")),
            "a failed probe took the install off: {:?}",
            ops.calls()
        );
    }
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
fn refuses_a_plan_that_names_a_file_xudo_does_not_write() {
    for path in [
        "/etc/sudoers",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers.d/other",
        "/etc/sudoers.d/xudo/../../passwd",
        "/etc/sudoers.d/xudo.candidate.candidate",
        "/etc/doas.conf.candidate",
        "etc/sudoers.d/xudo",
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
                        name: "xudo".to_owned(),
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
        .contains("not a file xudo writes")
    );
}

#[test]
fn refuses_to_create_a_group_other_than_xudos() {
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
    // `xudo.conf` installs cleanly and grants nothing: sudo skips it.
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
    for ignored in ["xudo.conf", "xudo~", ".xudo", "a.b", "xudo.candidate", "x~"] {
        assert!(sudo_skips(ignored), "{ignored}");
    }
    assert!(!sudo_skips("xudo"));
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
            .any(|c| c.starts_with("install /etc/doas.d/60-xudo.conf.candidate"))
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
fn refuses_to_edit_between_markers_xudo_did_not_write() {
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
            if path == "/etc/sudoers.d/xudo.candidate"
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
    assert!(report.events.iter().any(|e| e.contains("xudo's block")));
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
        .with_present(&["/etc/sudoers.d/xudo", "/etc/sudoers.d/xudo.candidate"]);
    let report = run(&uninstall_plan(BackendKind::Sudo), &ops).unwrap();
    assert_eq!(
        ops.calls(),
        [
            "read_managed /etc/sudoers.d/xudo",
            format!("read_managed {PTRACE_DROP_IN_PATH}").as_str(),
            "remove_managed /etc/sudoers.d/xudo",
            "remove_managed /etc/sudoers.d/xudo.candidate",
            format!("remove_managed {PTRACE_DROP_IN_PATH}").as_str(),
            format!("remove_managed {PTRACE_DROP_IN_PATH}.candidate").as_str(),
        ]
    );
    let removed: Vec<&String> = report
        .events
        .iter()
        .filter(|e| e.starts_with("removed "))
        .collect();
    assert_eq!(
        removed,
        [
            "removed /etc/sudoers.d/xudo",
            "removed /etc/sudoers.d/xudo.candidate"
        ]
    );
    assert_eq!(report.verification, Verification::NotRequired);
}

// --- the agent path ------------------------------------------------------

/// A probe whose refusal check answers `refuses`.
struct Refusing(ProbeResult);

impl InstallProbe for Refusing {
    fn verify(&self, _argv: &[String]) -> ProbeResult {
        ProbeResult::Unavailable {
            reason: "no broker".to_owned(),
        }
    }

    fn refuses(&self, _argv: &[String]) -> ProbeResult {
        self.0.clone()
    }
}

fn nopass_plan(raise: bool) -> InstallPlan {
    InstallPlan::with_agent_path(&backend(BackendKind::Sudo, true), raise).unwrap()
}

fn run_agent(
    plan: &InstallPlan,
    ops: &FakeInstallOps,
    refuses: ProbeResult,
) -> Result<InstallReport, InstallError> {
    execute(plan, ops, &Refusing(refuses))
}

fn agent_text() -> String {
    xudo_backend::SudoersSnippet::with_agent_path(&backend(BackendKind::Sudo, true))
        .unwrap()
        .contents
}

#[test]
fn the_agent_path_installs_after_the_helper_refused() {
    let ops = FakeInstallOps::root();
    let report = run_agent(&nopass_plan(false), &ops, ProbeResult::Verified).unwrap();
    let calls = ops.calls();
    assert_eq!(calls[0], "group_exists xudo");
    assert!(calls.contains(&"create_group xudo-agent".to_owned()));
    assert!(
        calls.contains(&"install /etc/sudoers.d/xudo.candidate /etc/sudoers.d/xudo".to_owned())
    );
    assert_eq!(
        report.events[0],
        "the passwordless helper refused a caller it cannot attest"
    );
    assert!(!calls.iter().any(|c| c.contains("sysctl")), "{calls:?}");
    assert!(report.notices[0].starts_with("The agent path is on."));
}

#[test]
fn the_probe_failing_writes_nothing() {
    // A helper that ran something, or that could not be run at all: no group,
    // no candidate, no rule. The probe is the first step for that reason.
    for answer in [
        ProbeResult::Failed {
            reason: "it printed 0".to_owned(),
        },
        ProbeResult::Unavailable {
            reason: "no helper".to_owned(),
        },
    ] {
        let ops = FakeInstallOps::root();
        let err = run_agent(&nopass_plan(true), &ops, answer).unwrap_err();
        assert!(
            matches!(err, InstallError::HelperDidNotRefuse { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("nothing was written"), "{err}");
        assert!(ops.calls().is_empty(), "{:?}", ops.calls());
    }
    // A probe that only knows `verify` cannot show a refusal either.
    let ops = FakeInstallOps::root();
    let err = run(&nopass_plan(false), &ops).unwrap_err();
    assert!(
        err.to_string()
            .contains("cannot run the passwordless helper"),
        "{err}"
    );
    assert!(ops.calls().is_empty());
}

#[test]
fn an_edited_agent_file_is_never_replaced_or_removed() {
    // An operator added a line to xudo's agent file. Neither a second
    // `--agent-path` nor an uninstall touches it; both say why.
    let tampered = format!("{}%xudo-agent ALL=(ALL) NOPASSWD: ALL\n", agent_text());
    for plan in [nopass_plan(false), uninstall_plan(BackendKind::Sudo)] {
        let ops = FakeInstallOps::root()
            .with_present(&["/etc/sudoers.d/xudo"])
            .with_contents("/etc/sudoers.d/xudo", tampered.as_bytes());
        let err = run_agent(&plan, &ops, ProbeResult::Verified).unwrap_err();
        assert!(matches!(err, InstallError::Edited { .. }), "{err}");
        assert!(err.to_string().contains("was edited"), "{err}");
        let calls = ops.calls();
        assert!(
            !calls
                .iter()
                .any(|c| c.starts_with("write_candidate") || c.starts_with("remove_managed")),
            "{calls:?}"
        );
    }
}

#[test]
fn a_second_install_changes_nothing() {
    // xudo's own agent text is replaced by the same text: the edit check
    // passes, and the plan writes exactly what is already there.
    let ops = FakeInstallOps::root()
        .with_group()
        .with_contents("/etc/sudoers.d/xudo", agent_text().as_bytes());
    let report = run_agent(&nopass_plan(false), &ops, ProbeResult::Verified).unwrap();
    assert!(
        report
            .events
            .contains(&"/etc/sudoers.d/xudo holds no edit".to_owned())
    );
    let written = nopass_plan(false)
        .steps
        .iter()
        .find_map(|s| match s {
            PlanStep::WriteCandidate { contents, .. } => Some(contents.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(written, agent_text());
    assert!(!ops.calls().iter().any(|c| c.starts_with("create_group")));
}

#[test]
fn the_ptrace_drop_in_is_read_back_before_it_is_installed() {
    let ops = FakeInstallOps::root();
    let report = run_agent(&nopass_plan(true), &ops, ProbeResult::Verified).unwrap();
    let calls = ops.calls();
    let at = |needle: &str| calls.iter().position(|c| c == needle).unwrap();
    let candidate = format!("{PTRACE_DROP_IN_PATH}.candidate");
    assert!(at(&format!("write_candidate {candidate}")) < at(&format!("read_managed {candidate}")));
    assert!(
        at(&format!("read_managed {candidate}"))
            < at(&format!("install {candidate} {PTRACE_DROP_IN_PATH}"))
    );
    assert!(report.events.contains(&format!("read back {candidate}")));
}

#[test]
fn a_drop_in_that_does_not_read_back_is_not_installed() {
    let candidate = format!("{PTRACE_DROP_IN_PATH}.candidate");
    let ops = FakeInstallOps::root().with_contents(&candidate, b"kernel.yama.ptrace_scope = 0\n");
    let err = run_agent(&nopass_plan(true), &ops, ProbeResult::Verified).unwrap_err();
    assert!(
        err.to_string().contains("does not hold what was written"),
        "{err}"
    );
    assert!(
        !ops.calls()
            .iter()
            .any(|c| c.starts_with(&format!("install {candidate}")))
    );
    assert!(ops.calls().contains(&format!("discard {candidate}")));
    // Swapped after it read back: refused and left alone.
    let swapped = FakeInstallOps::root().with_identity_after_validate(FileIdentity {
        device: 9,
        inode: 9,
    });
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![
            PlanStep::WriteCandidate {
                path: candidate.clone(),
                contents: PTRACE_DROP_IN.to_owned(),
                mode: 0o440,
            },
            PlanStep::ReadBack {
                candidate: candidate.clone(),
            },
        ],
    };
    let err = run(&plan, &swapped).unwrap_err();
    assert!(
        matches!(err, InstallError::CandidateReplaced { .. }),
        "{err}"
    );
    // A read-back that cannot read is no read-back.
    let unreadable = FakeInstallOps::root().failing("read_managed");
    let err = run(&plan, &unreadable).unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }), "{err}");
}

#[test]
fn no_plan_can_put_another_value_in_the_ptrace_drop_in() {
    let lowered = PTRACE_DROP_IN.replace("= 1", "= 0");
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![PlanStep::WriteCandidate {
            path: format!("{PTRACE_DROP_IN_PATH}.candidate"),
            contents: lowered,
            mode: 0o440,
        }],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(matches!(err, InstallError::Edited { .. }), "{err}");
    assert!(ops.calls().is_empty());
}

#[test]
fn a_read_back_never_stands_in_for_the_sudoers_parser() {
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![
            PlanStep::WriteCandidate {
                path: "/etc/sudoers.d/xudo.candidate".to_owned(),
                contents: agent_text(),
                mode: 0o440,
            },
            PlanStep::ReadBack {
                candidate: "/etc/sudoers.d/xudo.candidate".to_owned(),
            },
            PlanStep::Install {
                from: "/etc/sudoers.d/xudo.candidate".to_owned(),
                to: "/etc/sudoers.d/xudo".to_owned(),
            },
        ],
    };
    let ops = FakeInstallOps::root();
    let err = run(&plan, &ops).unwrap_err();
    assert!(matches!(err, InstallError::ReadBackRefused { .. }), "{err}");
    assert!(ops.calls().is_empty());
}

#[test]
fn a_read_back_of_a_file_this_run_did_not_write_is_refused() {
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![PlanStep::ReadBack {
            candidate: format!("{PTRACE_DROP_IN_PATH}.candidate"),
        }],
    };
    let err = run(&plan, &FakeInstallOps::root()).unwrap_err();
    assert!(matches!(err, InstallError::OutOfOrder { .. }), "{err}");
}

#[test]
fn an_edit_check_that_cannot_read_stops_before_anything_is_removed() {
    let ops = FakeInstallOps::root()
        .with_present(&["/etc/sudoers.d/xudo"])
        .failing_with(
            "read_managed",
            InstallError::NotOurs {
                path: "/etc/sudoers.d/xudo".to_owned(),
                reason: "it is a symbolic link".to_owned(),
            },
        );
    let err = run(&uninstall_plan(BackendKind::Sudo), &ops).unwrap_err();
    assert!(err.to_string().contains("symbolic link"), "{err}");
    assert!(!ops.calls().iter().any(|c| c.starts_with("remove_managed")));
}

#[test]
fn uninstall_removes_the_agent_path_and_nothing_else() {
    // The agent file and the drop-in, each exactly as xudo wrote it, go; the
    // plan names no other file and no group.
    let ops = FakeInstallOps::root()
        .with_present(&["/etc/sudoers.d/xudo", PTRACE_DROP_IN_PATH])
        .with_contents("/etc/sudoers.d/xudo", agent_text().as_bytes())
        .with_contents(PTRACE_DROP_IN_PATH, PTRACE_DROP_IN.as_bytes());
    let report = run(&uninstall_plan(BackendKind::Sudo), &ops).unwrap();
    assert!(
        report
            .events
            .contains(&"removed /etc/sudoers.d/xudo".to_owned())
    );
    assert!(
        report
            .events
            .contains(&format!("removed {PTRACE_DROP_IN_PATH}"))
    );
    for call in ops.calls() {
        let path = call.split_once(' ').unwrap().1;
        assert!(
            path.starts_with("/etc/sudoers.d/xudo") || path.starts_with(PTRACE_DROP_IN_PATH),
            "{call}"
        );
    }
    // An edited drop-in (lowered to 0) stops the uninstall before anything goes.
    let lowered = PTRACE_DROP_IN.replace("= 1", "= 0");
    let ops = FakeInstallOps::root()
        .with_present(&["/etc/sudoers.d/xudo", PTRACE_DROP_IN_PATH])
        .with_contents(PTRACE_DROP_IN_PATH, lowered.as_bytes());
    let err = run(&uninstall_plan(BackendKind::Sudo), &ops).unwrap_err();
    assert!(err.to_string().contains(PTRACE_DROP_IN_PATH), "{err}");
    assert!(!ops.calls().iter().any(|c| c.starts_with("remove_managed")));
}

#[test]
fn the_agent_group_is_the_only_other_group_xudo_creates() {
    let plan = InstallPlan {
        backend: BackendKind::Sudo,
        steps: vec![PlanStep::CreateGroup {
            name: "xudo-agent".to_owned(),
        }],
    };
    let ops = FakeInstallOps::root();
    run(&plan, &ops).unwrap();
    assert_eq!(
        ops.calls(),
        ["group_exists xudo-agent", "create_group xudo-agent"]
    );
}

#[test]
fn a_second_uninstall_succeeds_and_says_nothing_was_there() {
    let ops = FakeInstallOps::root();
    let report = run(&uninstall_plan(BackendKind::Doas), &ops).unwrap();
    assert!(report.events.iter().any(|e| e.contains("was not present")));
    assert!(report.events.iter().any(|e| e.contains("no xudo block")));
}

#[test]
fn a_doas_uninstall_removes_the_drop_in_and_the_block_it_wrote() {
    let ops = FakeInstallOps::root().with_present(&[DOAS_DROP_IN_PATH, DOAS_CONF_PATH]);
    let report = run(&uninstall_plan(BackendKind::Doas), &ops).unwrap();
    assert_eq!(
        ops.calls(),
        [
            "remove_managed /etc/doas.d/60-xudo.conf".to_owned(),
            "remove_block /etc/doas.conf".to_owned()
        ]
    );
    assert!(
        report
            .events
            .iter()
            .any(|e| e.contains("removed xudo's block"))
    );
}

#[test]
fn an_uninstall_whose_block_cannot_be_removed_stops_and_says_so() {
    let ops = FakeInstallOps::root().failing("remove_block");
    let err = run(&uninstall_plan(BackendKind::Doas), &ops).unwrap_err();
    assert!(matches!(err, InstallError::Io { .. }), "{err}");
}

#[test]
fn an_uninstall_that_meets_a_file_that_is_not_xudos_stops() {
    let ops = FakeInstallOps::root().failing_with(
        "remove_managed",
        InstallError::NotOurs {
            path: SUDOERS_PATH.to_owned(),
            reason: "no marker".to_owned(),
        },
    );
    let err = run(&uninstall_plan(BackendKind::Sudo), &ops).unwrap_err();
    assert!(matches!(err, InstallError::NotOurs { .. }));
    assert!(err.to_string().contains("not a file xudo wrote"));
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
    let err = HostInstaller::new(&Probe(ProbeResult::Verified))
        .run(&sudo_plan())
        .unwrap_err();
    assert!(matches!(err, InstallError::NotRoot { .. }), "{err}");
}

fn agent_request() -> xudo_backend::enrol::EnrolRequest {
    xudo_backend::enrol::EnrolRequest {
        label: "codex".to_owned(),
        account: "agent".to_owned(),
        reviewers: vec!["alice".to_owned()],
        argv: vec!["/usr/bin/codex".to_owned()],
    }
}

fn agent_scan() -> xudo_backend::enrol::AccountScan {
    xudo_backend::enrol::AccountScan {
        uid: 990,
        blockers: Vec::new(),
        doas: false,
    }
}

fn agent_plan() -> xudo_backend::enrol::EnrolPlan {
    let file = |path: &str| xudo_backend::enrol::PlannedFile {
        path: path.to_owned(),
        contents: String::new(),
        mode: 0o644,
        keep: false,
    };
    xudo_backend::enrol::EnrolPlan {
        label: "codex".to_owned(),
        account: "agent".to_owned(),
        unit: "xudo-agent@codex.service".to_owned(),
        registry: file("/etc/xudo/harnesses.d/codex.toml"),
        drop_in_dir: "/etc/systemd/system/xudo-agent@codex.service.d".to_owned(),
        drop_in: file("/etc/systemd/system/xudo-agent@codex.service.d/10-xudo.conf"),
        env: file("/etc/xudo/agents/codex.env"),
        memberships: Vec::new(),
    }
}

#[test]
fn the_refusing_installer_enrols_nothing() {
    let none = || AgentError::Install(InstallError::NoInstaller);
    assert_eq!(
        RefusingInstaller
            .agent_plan(&agent_request(), agent_scan())
            .unwrap_err(),
        none()
    );
    assert_eq!(
        RefusingInstaller.agent_apply(&agent_plan()).unwrap_err(),
        none()
    );
    assert_eq!(RefusingInstaller.agent_list().unwrap_err(), none());
    assert_eq!(RefusingInstaller.agent_remove("codex").unwrap_err(), none());
    let request = PackRequest {
        bytes: Vec::new(),
        reviewed: String::new(),
        allow_waivers: false,
    };
    let no_pack = || PackError::Install(InstallError::NoInstaller);
    assert_eq!(RefusingInstaller.pack_add(&request).unwrap_err(), no_pack());
    assert_eq!(
        RefusingInstaller.pack_remove("x", "t").unwrap_err(),
        no_pack()
    );
}

#[test]
fn the_host_installer_refuses_to_enrol_or_remove_when_not_root() {
    if rustix::process::geteuid().as_raw() == 0 {
        return;
    }
    let installer = HostInstaller::new(&Probe(ProbeResult::Verified));
    let not_root = |error: AgentError| matches!(error, AgentError::NotRoot { .. });
    assert!(not_root(
        installer
            .agent_plan(&agent_request(), agent_scan())
            .unwrap_err()
    ));
    assert!(not_root(installer.agent_apply(&agent_plan()).unwrap_err()));
    assert!(not_root(installer.agent_remove("codex").unwrap_err()));
    let request = PackRequest {
        bytes: Vec::new(),
        reviewed: String::new(),
        allow_waivers: false,
    };
    let pack_not_root = |error: PackError| matches!(error, PackError::NotRoot { .. });
    assert!(pack_not_root(installer.pack_add(&request).unwrap_err()));
    assert!(pack_not_root(installer.pack_remove("x", "t").unwrap_err()));
    // Listing reads only, so it is not refused; what it finds is the machine's.
    let _ = installer.agent_list();
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
            name: "xudo".to_owned(),
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
        InstallError::HelperDidNotRefuse {
            reason: "r".to_owned(),
        },
        InstallError::Edited {
            path: "p".to_owned(),
            reason: "r",
        },
        InstallError::ReadBackRefused {
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

/// Answers `getent` with one member and `sudo -l` with `listing`.
struct Listing(&'static str);

impl Runner for Listing {
    fn run(&self, exe: &str, _args: &[&str], _stdin: Option<&[u8]>) -> Result<Output, SysError> {
        let stdout = if exe.ends_with("getent") {
            "xudo:x:900:alice\n"
        } else {
            self.0
        };
        Ok(Output {
            success: true,
            code: Some(0),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        })
    }
}

#[test]
fn a_probe_pass_does_not_stand_when_the_backend_does_not_list_the_gate() {
    let finished = finish(Ok(report(Verification::Verified)), &Listing("nothing")).unwrap();
    assert!(
        matches!(finished.verification, Verification::Unverified { .. }),
        "{:?}",
        finished.verification
    );
}

#[test]
fn a_probe_pass_stands_when_the_backend_lists_the_gate() {
    let listed = Listing("(root) PASSWD: /usr/libexec/xudo/xudo-gate-auth");
    let finished = finish(Ok(report(Verification::Verified)), &listed).unwrap();
    assert_eq!(finished.verification, Verification::Verified);
}

#[test]
fn a_probe_pass_stands_when_the_backend_cannot_be_asked() {
    let finished = finish(Ok(report(Verification::Verified)), &NoRunner).unwrap();
    assert_eq!(finished.verification, Verification::Verified);
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
