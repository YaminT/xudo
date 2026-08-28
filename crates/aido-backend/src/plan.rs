//! The ordered steps that install or remove aido's backend integration.
//!
//! A plan rather than an installer. Producing the steps as data means the whole
//! sequence — including its ordering, which is the part that matters — is
//! reviewable and testable without a machine to run it on. Executing them is
//! `aido-sys`'s job and needs a real kernel.
//!
//! # Why the order is the security property
//!
//! Validate before installing, never after. Verify functionally, never by
//! checking that a file exists. Create the group empty, and never add anyone to
//! it. Each of those is an ordering or omission rather than a check, so a plan
//! that runs its steps in sequence gets them right and a hand-written installer
//! that drifts does not.

use serde::{Deserialize, Serialize};

use crate::detect::{Backend, BackendKind};
use crate::snippet::{
    AIDO_GROUP, DOAS_BEGIN, DOAS_END, DoasSnippet, GATE_AUTH, SnippetError, SudoersSnippet,
};

/// One step, described rather than performed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PlanStep {
    /// Create the unix group, if it does not exist.
    ///
    /// Idempotent, and **empty**. Group membership is the privilege grant, so
    /// adding a user is the operator's explicit act, never a package's.
    CreateGroup {
        /// The group name.
        name: String,
    },
    /// Write a candidate file next to its destination, on the same filesystem
    /// so the later rename is atomic.
    WriteCandidate {
        /// Where the candidate goes.
        path: String,
        /// Its contents.
        contents: String,
        /// Its mode.
        mode: u32,
    },
    /// Run a validation command against the candidate.
    ///
    /// `{candidate}` in the argv is substituted with the candidate's path.
    Validate {
        /// The command to run.
        argv: Vec<String>,
    },
    /// Validate by substitution, for a backend that cannot check a named file.
    ///
    /// `sudo-rs`'s `visudo` validates only `/etc/sudoers`, so the only honest
    /// check is to assemble a full config containing the candidate and validate
    /// that. Described as its own step so it cannot be mistaken for the cheaper
    /// one.
    ValidateBySubstitution {
        /// The candidate whose contents must be spliced in.
        candidate: String,
        /// Why the cheaper check is unavailable.
        reason: String,
    },
    /// Atomically move the validated candidate into place.
    Install {
        /// The candidate.
        from: String,
        /// The destination.
        to: String,
    },
    /// Append a sentinel-delimited block to a shared file, under a lock.
    AppendBlock {
        /// The shared file.
        path: String,
        /// The block, including its sentinels.
        block: String,
        /// The mode the file must end up with.
        mode: u32,
    },
    /// Remove a sentinel-delimited block from a shared file, and nothing else.
    RemoveBlock {
        /// The shared file.
        path: String,
        /// The opening sentinel.
        begin: String,
        /// The closing sentinel.
        end: String,
    },
    /// Delete a file aido owns.
    Remove {
        /// The path.
        path: String,
    },
    /// Confirm the integration works by using it.
    ///
    /// **Not a file-existence check.** `sudo-rs` ignores directives it does not
    /// support, and `sudo` ignores a badly-named drop-in entirely, so the only
    /// evidence that a rule is in effect is that the helper ran as uid 0.
    FunctionalProbe {
        /// What to run.
        argv: Vec<String>,
        /// What must be true afterwards.
        expectation: String,
    },
    /// Print something the operator must read.
    Notice {
        /// The text.
        text: String,
    },
}

impl PlanStep {
    /// Whether failing this step must abort the whole install.
    ///
    /// Everything except a notice. A partially-installed privilege broker is
    /// worse than an uninstalled one, because it looks installed.
    pub fn is_fatal_on_failure(&self) -> bool {
        !matches!(self, Self::Notice { .. })
    }

    /// A one-line description for a dry run.
    pub fn describe(&self) -> String {
        match self {
            Self::CreateGroup { name } => format!("create group {name} (empty)"),
            Self::WriteCandidate { path, mode, .. } => {
                format!("write candidate {path} mode {mode:04o}")
            }
            Self::Validate { argv } => format!("validate: {}", argv.join(" ")),
            Self::ValidateBySubstitution { candidate, .. } => {
                format!("validate {candidate} by substitution into a full config")
            }
            Self::Install { from, to } => format!("atomically install {from} -> {to}"),
            Self::AppendBlock { path, .. } => format!("append aido's block to {path}"),
            Self::RemoveBlock { path, .. } => format!("remove aido's block from {path}"),
            Self::Remove { path } => format!("remove {path}"),
            Self::FunctionalProbe { expectation, .. } => {
                format!("probe: {expectation}")
            }
            Self::Notice { text } => format!("notice: {}", first_sentence(text)),
        }
    }
}

/// The first sentence of a notice, for a one-line summary.
fn first_sentence(text: &str) -> String {
    text.split_once(". ")
        .map_or_else(|| text.to_owned(), |(head, _)| format!("{head}."))
}

/// An ordered install plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallPlan {
    /// The backend this plan was built for.
    pub backend: BackendKind,
    /// The steps, in order.
    pub steps: Vec<PlanStep>,
}

impl InstallPlan {
    /// Builds the plan that installs the human-only integration.
    ///
    /// # Errors
    ///
    /// Propagates [`SnippetError`] when the backend cannot be given a snippet
    /// it will actually honour.
    pub fn human_only(backend: &Backend) -> Result<Self, SnippetError> {
        let mut steps = vec![PlanStep::CreateGroup {
            name: AIDO_GROUP.to_owned(),
        }];

        match backend.kind {
            BackendKind::Sudo | BackendKind::SudoRs => {
                let snippet = SudoersSnippet::human_only(backend)?;
                let destination = SudoersSnippet::path();
                let candidate = format!("{destination}.candidate");

                steps.push(PlanStep::WriteCandidate {
                    path: candidate.clone(),
                    contents: snippet.contents,
                    mode: SudoersSnippet::mode(),
                });
                steps.push(match snippet.validate_argv {
                    Some(argv) => PlanStep::Validate { argv },
                    None => PlanStep::ValidateBySubstitution {
                        candidate: candidate.clone(),
                        reason: "this backend's visudo validates only /etc/sudoers, so a \
                                 named-file check would silently examine the wrong file"
                            .to_owned(),
                    },
                });
                steps.push(PlanStep::Install {
                    from: candidate,
                    to: destination.to_owned(),
                });
            }
            BackendKind::Doas => {
                let snippet = DoasSnippet::human_only(backend)?;
                if snippet.is_drop_in {
                    let candidate = format!("{}.candidate", snippet.path);
                    steps.push(PlanStep::WriteCandidate {
                        path: candidate.clone(),
                        contents: snippet.contents,
                        mode: DoasSnippet::mode(),
                    });
                    steps.push(PlanStep::Validate {
                        argv: snippet.validate_argv,
                    });
                    steps.push(PlanStep::Install {
                        from: candidate,
                        to: snippet.path,
                    });
                } else {
                    // No drop-in directory: append a removable block. Validation
                    // still happens first, against a temporary full copy.
                    steps.push(PlanStep::Validate {
                        argv: snippet.validate_argv,
                    });
                    steps.push(PlanStep::AppendBlock {
                        path: snippet.path,
                        block: snippet.contents,
                        mode: DoasSnippet::mode(),
                    });
                }
            }
        }

        steps.push(PlanStep::FunctionalProbe {
            argv: vec![
                backend.kind.exe().to_owned(),
                "-n".to_owned(),
                GATE_AUTH.to_owned(),
            ],
            expectation: "the helper refuses without a password rather than reporting that \
                          no rule permits it, which proves the rule is in effect and that \
                          no credential is cached"
                .to_owned(),
        });

        steps.push(PlanStep::Notice {
            text: "aido is installed in its password-required form. Every invocation will \
                   prompt. The passwordless agent path is not part of this release, and its \
                   helper is not installed. No user was added to the aido group: membership \
                   is the privilege grant, so run `aido doctor --fix` to review and grant it \
                   deliberately. Agent detection is not a security boundary; the allowlist \
                   and the compiled-in deny-list are."
                .to_owned(),
        });

        Ok(Self {
            backend: backend.kind,
            steps,
        })
    }

    /// Every step, described, for a dry run.
    pub fn describe(&self) -> Vec<String> {
        self.steps.iter().map(PlanStep::describe).collect()
    }

    /// How many steps must succeed for the install to be sound.
    pub fn fatal_step_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| s.is_fatal_on_failure())
            .count()
    }
}

/// Builds the plan that removes aido's integration.
///
/// **An uninstall that leaves a sudoers rule behind is a security defect, not
/// an untidiness.** The group is deliberately *not* removed: an operator may
/// have granted membership for their own reasons, and silently revoking it on a
/// package removal is a surprise in the other direction.
pub fn uninstall_plan(backend: BackendKind) -> InstallPlan {
    let steps = match backend {
        BackendKind::Sudo | BackendKind::SudoRs => vec![
            PlanStep::Remove {
                path: SudoersSnippet::path().to_owned(),
            },
            PlanStep::Remove {
                path: format!("{}.candidate", SudoersSnippet::path()),
            },
        ],
        BackendKind::Doas => vec![
            PlanStep::Remove {
                path: crate::snippet::DOAS_DROP_IN_PATH.to_owned(),
            },
            PlanStep::RemoveBlock {
                path: crate::snippet::DOAS_CONF_PATH.to_owned(),
                begin: DOAS_BEGIN.to_owned(),
                end: DOAS_END.to_owned(),
            },
        ],
    };
    InstallPlan { backend, steps }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::capability::{Capability, CapabilityMatrix};

    fn backend(kind: BackendKind, drop_in: bool, validate_named: bool) -> Backend {
        let mut caps = CapabilityMatrix::from_supported([
            Capability::DisableCredentialCache,
            Capability::AllocatePty,
            Capability::PerCommandDefaults,
        ]);
        if drop_in {
            caps = caps.with(Capability::DropInDirectory);
        }
        if validate_named {
            caps = caps.with(Capability::ValidateNamedFile);
        }
        Backend {
            kind,
            exe: kind.exe().to_owned(),
            version: format!("{} test", kind.label()),
            capabilities: caps,
        }
    }

    #[test]
    fn the_group_is_created_first_and_left_empty() {
        // Membership is the privilege grant, so no plan step adds anyone to it.
        let plan = InstallPlan::human_only(&backend(BackendKind::Sudo, true, true)).unwrap();
        assert_eq!(
            plan.steps.first(),
            Some(&PlanStep::CreateGroup {
                name: "aido".to_owned()
            })
        );
        let described = plan.describe().join("\n");
        assert!(described.contains("create group aido (empty)"));
        assert!(
            !described.contains("usermod") && !described.contains("gpasswd"),
            "no step may add a member: {described}"
        );
    }

    #[test]
    fn validation_happens_before_installation_always() {
        // The ordering is the property. A plan that installs first has already
        // granted privilege by the time it discovers the file is wrong.
        for (kind, drop_in, named) in [
            (BackendKind::Sudo, true, true),
            (BackendKind::SudoRs, true, false),
            (BackendKind::Doas, true, true),
        ] {
            let plan = InstallPlan::human_only(&backend(kind, drop_in, named)).unwrap();
            let validate = plan
                .steps
                .iter()
                .position(|s| {
                    matches!(
                        s,
                        PlanStep::Validate { .. } | PlanStep::ValidateBySubstitution { .. }
                    )
                })
                .expect("every plan validates before installing");
            let install = plan
                .steps
                .iter()
                .position(|s| matches!(s, PlanStep::Install { .. } | PlanStep::AppendBlock { .. }))
                .expect("every plan installs something");
            assert!(validate < install, "{kind:?} installs before validating");
        }
    }

    #[test]
    fn the_candidate_is_written_beside_its_destination_so_the_rename_is_atomic() {
        let plan = InstallPlan::human_only(&backend(BackendKind::Sudo, true, true)).unwrap();
        let (candidate, destination) = plan
            .steps
            .iter()
            .find_map(|s| match s {
                PlanStep::Install { from, to } => Some((from.clone(), to.clone())),
                _ => None,
            })
            .unwrap();
        assert_eq!(destination, "/etc/sudoers.d/aido");
        assert!(candidate.starts_with(&destination), "{candidate}");
        // A candidate in /tmp would be a symlink race and a cross-filesystem
        // rename; both are why it sits beside the destination.
        assert!(!candidate.starts_with("/tmp"));
    }

    #[test]
    fn a_backend_that_cannot_check_a_named_file_gets_the_substitution_step() {
        // And it says why, so nobody replaces it with the cheaper check. Built
        // through the helper with every required capability present, because a
        // backend missing one is refused before a plan exists at all.
        let plan = InstallPlan::human_only(&backend(BackendKind::SudoRs, true, false)).unwrap();
        let reason = plan
            .steps
            .iter()
            .find_map(|s| match s {
                PlanStep::ValidateBySubstitution { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .unwrap();
        assert!(reason.contains("only /etc/sudoers"), "{reason}");
        assert!(reason.contains("wrong file"), "{reason}");
        assert!(
            plan.describe()
                .iter()
                .any(|d| d.contains("by substitution"))
        );
    }

    #[test]
    fn every_plan_ends_with_a_functional_probe_and_then_a_notice() {
        // A file-existence check proves nothing: sudo-rs ignores unsupported
        // directives and sudo ignores a badly-named drop-in entirely.
        for kind in [BackendKind::Sudo, BackendKind::SudoRs, BackendKind::Doas] {
            let plan = InstallPlan::human_only(&backend(kind, true, true)).unwrap();
            // Scanned over every step, so the non-probe arm is exercised too,
            // and there is exactly one probe.
            let probes: Vec<(Vec<String>, String)> = plan
                .steps
                .iter()
                .filter_map(|s| match s {
                    PlanStep::FunctionalProbe { argv, expectation } => {
                        Some((argv.clone(), expectation.clone()))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(probes.len(), 1, "{kind:?}");
            let (argv, expectation) = probes.first().expect("just asserted one probe");
            assert_eq!(argv[0], kind.exe());
            assert!(argv.contains(&"-n".to_owned()), "{argv:?}");
            assert!(expectation.contains("in effect"), "{expectation}");
            // And it is second-to-last, before the notice.
            assert_eq!(
                plan.steps
                    .iter()
                    .position(|s| matches!(s, PlanStep::FunctionalProbe { .. })),
                Some(plan.steps.len().saturating_sub(2))
            );
            // Described rather than pattern-matched, so there is no arm for a
            // variant this assertion never sees.
            let last = plan
                .steps
                .last()
                .map(PlanStep::describe)
                .unwrap_or_default();
            assert!(last.starts_with("notice: "), "{kind:?} ends with {last}");
        }
    }

    #[test]
    fn the_notice_states_what_this_release_does_and_does_not_do() {
        let plan = InstallPlan::human_only(&backend(BackendKind::Sudo, true, true)).unwrap();
        let text = plan
            .steps
            .iter()
            .find_map(|s| match s {
                PlanStep::Notice { text } => Some(text.clone()),
                _ => None,
            })
            .unwrap();
        assert!(text.contains("Every invocation will prompt"), "{text}");
        assert!(text.contains("not part of this release"), "{text}");
        assert!(text.contains("No user was added"), "{text}");
        assert!(text.contains("not a security boundary"), "{text}");
    }

    #[test]
    fn a_doas_port_without_a_drop_in_appends_rather_than_installing() {
        let plan = InstallPlan::human_only(&backend(BackendKind::Doas, false, true)).unwrap();
        assert!(
            plan.steps
                .iter()
                .any(|s| matches!(s, PlanStep::AppendBlock { .. }))
        );
        assert!(
            !plan
                .steps
                .iter()
                .any(|s| matches!(s, PlanStep::Install { .. })),
            "there is no file to install atomically when appending to a shared one"
        );
    }

    #[test]
    fn only_a_notice_is_survivable() {
        // A partially-installed privilege broker is worse than an uninstalled
        // one, because it looks installed.
        let plan = InstallPlan::human_only(&backend(BackendKind::Sudo, true, true)).unwrap();
        assert_eq!(plan.fatal_step_count(), plan.steps.len().saturating_sub(1));
        assert!(
            !PlanStep::Notice {
                text: "x".to_owned()
            }
            .is_fatal_on_failure()
        );
        assert!(
            PlanStep::Remove {
                path: "x".to_owned()
            }
            .is_fatal_on_failure()
        );
    }

    #[test]
    fn uninstalling_sudo_removes_the_rule_and_any_stale_candidate() {
        // Leaving a sudoers rule behind is a security defect, not untidiness.
        // Both plans are scanned in one pass so the non-Remove arm — doas's
        // RemoveBlock — is exercised by the same filter.
        let paths: Vec<String> = [
            uninstall_plan(BackendKind::Sudo),
            uninstall_plan(BackendKind::Doas),
        ]
        .iter()
        .flat_map(|plan| plan.steps.clone())
        .filter_map(|s| match s {
            PlanStep::Remove { path } => Some(path),
            _ => None,
        })
        .collect();
        assert!(paths.contains(&"/etc/sudoers.d/aido".to_owned()));
        assert!(paths.iter().any(|p| p.ends_with(".candidate")));
    }

    #[test]
    fn uninstalling_doas_removes_exactly_aidos_block() {
        let plan = uninstall_plan(BackendKind::Doas);
        let block = plan
            .steps
            .iter()
            .find_map(|s| match s {
                PlanStep::RemoveBlock { begin, end, path } => {
                    Some((begin.clone(), end.clone(), path.clone()))
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(block.0, DOAS_BEGIN);
        assert_eq!(block.1, DOAS_END);
        assert_eq!(block.2, "/etc/doas.conf");
    }

    #[test]
    fn uninstalling_never_removes_the_group() {
        // An operator may have granted membership for their own reasons;
        // revoking it on a package removal is a surprise in the other direction.
        for kind in [BackendKind::Sudo, BackendKind::SudoRs, BackendKind::Doas] {
            let plan = uninstall_plan(kind);
            assert!(
                !plan
                    .steps
                    .iter()
                    .any(|s| matches!(s, PlanStep::CreateGroup { .. })),
                "{kind:?}"
            );
            assert!(!plan.describe().join(" ").contains("group"), "{kind:?}");
        }
    }

    #[test]
    fn a_backend_that_cannot_be_given_an_honest_snippet_yields_no_plan() {
        let crippled = Backend {
            exe: "/usr/bin/sudo".to_owned(),
            kind: BackendKind::Sudo,
            version: "0.0".to_owned(),
            capabilities: CapabilityMatrix::empty(),
        };
        assert!(InstallPlan::human_only(&crippled).is_err());

        let crippled_doas = Backend {
            exe: "/usr/bin/doas".to_owned(),
            kind: BackendKind::Doas,
            version: "0.0".to_owned(),
            capabilities: CapabilityMatrix::empty(),
        };
        assert!(InstallPlan::human_only(&crippled_doas).is_err());
    }

    #[test]
    fn every_step_variant_describes_itself() {
        let steps = [
            PlanStep::CreateGroup {
                name: "aido".to_owned(),
            },
            PlanStep::WriteCandidate {
                path: "/p".to_owned(),
                contents: "c".to_owned(),
                mode: 0o440,
            },
            PlanStep::Validate {
                argv: vec!["/usr/sbin/visudo".to_owned()],
            },
            PlanStep::ValidateBySubstitution {
                candidate: "/p".to_owned(),
                reason: "r".to_owned(),
            },
            PlanStep::Install {
                from: "/a".to_owned(),
                to: "/b".to_owned(),
            },
            PlanStep::AppendBlock {
                path: "/p".to_owned(),
                block: "b".to_owned(),
                mode: 0o400,
            },
            PlanStep::RemoveBlock {
                path: "/p".to_owned(),
                begin: "b".to_owned(),
                end: "e".to_owned(),
            },
            PlanStep::Remove {
                path: "/p".to_owned(),
            },
            PlanStep::FunctionalProbe {
                argv: vec!["/usr/bin/sudo".to_owned()],
                expectation: "e".to_owned(),
            },
            PlanStep::Notice {
                text: "First. Second.".to_owned(),
            },
        ];
        for step in &steps {
            assert!(step.describe().len() > 4, "{step:?}");
        }
        assert!(steps[1].describe().contains("0440"));
        // A notice is summarised to its first sentence.
        assert_eq!(steps[9].describe(), "notice: First.");
        assert_eq!(
            PlanStep::Notice {
                text: "Only one".to_owned()
            }
            .describe(),
            "notice: Only one"
        );
    }

    #[test]
    fn a_plan_round_trips_and_rejects_unknown_keys() {
        let plan = InstallPlan::human_only(&backend(BackendKind::Sudo, true, true)).unwrap();
        let json = serde_json::to_string(&plan).unwrap();
        assert_eq!(serde_json::from_str::<InstallPlan>(&json).unwrap(), plan);
        assert!(
            serde_json::from_str::<InstallPlan>(&json.replace("\"steps\"", "\"skip\":1,\"steps\""))
                .is_err()
        );
        assert!(format!("{plan:?}").contains("CreateGroup"));
    }
}
