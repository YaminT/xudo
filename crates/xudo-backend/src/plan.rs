//! The ordered steps that install or remove xudo's backend integration.
//!
//! A plan rather than an installer. Producing the steps as data means the whole
//! sequence — including its ordering, which is the part that matters — is
//! reviewable and testable without a machine to run it on. Executing them is
//! `xudo-sys`'s job and needs a real kernel.
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
    DOAS_BEGIN, DOAS_END, DoasSnippet, GATE_AUTH, GATE_NOPASS, PTRACE_DROP_IN, PTRACE_DROP_IN_PATH,
    SUDOERS_PATH, SnippetError, SudoersSnippet, VISUDO, XUDO_AGENT_GROUP, XUDO_GROUP,
    names_agent_path, recognize,
};

/// Why `--agent-path` refuses a doas host.
pub const AGENT_PATH_SUDO_ONLY: &str = "the agent path is for sudo and sudo-rs only: it rests on \
     `Defaults!command` scoping and a rule with exactly no arguments for the passwordless \
     helper, and xudo writes no doas equivalent";

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
    ///
    /// The file keeps the owner, group and mode it has: it is the operator's,
    /// and an edit that changed who can read it would be a second, unannounced
    /// change. There is no mode here to get wrong.
    AppendBlock {
        /// The shared file.
        path: String,
        /// The block, including its sentinels.
        block: String,
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
    /// Delete a file xudo owns.
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
    /// Run the passwordless helper as a caller it cannot attest, and require a
    /// refusal. First in the plan: a helper that does not refuse gets no rule,
    /// and nothing has been written yet.
    RefusalProbe {
        /// What to run.
        argv: Vec<String>,
        /// What must be true afterwards.
        expectation: String,
    },
    /// Stop when the file at `path` holds an edit: a file xudo would replace or
    /// remove only while it is still the text xudo wrote.
    RefuseEdited {
        /// The file.
        path: String,
    },
    /// Read the candidate back and require exactly the bytes written. The
    /// check for the sysctl drop-in, which has no parser to ask; never for a
    /// sudoers file.
    ReadBack {
        /// The candidate.
        candidate: String,
    },
    /// After the rename, ask the backend to parse its whole configuration.
    /// A file that is valid alone can clash with another (an alias defined
    /// twice). Failing it restores everything this run installed; a plan with
    /// this step is all or nothing from its first install on.
    ValidateWhole {
        /// The command to run; it names no candidate.
        argv: Vec<String>,
    },
    /// Ask the backend whether it lists the passwordless helper for `argv`'s
    /// user and arguments, and require that it does not. Listed means the line
    /// grants more than it says, and restores what this run installed.
    MustNotList {
        /// What to run.
        argv: Vec<String>,
        /// What must be true.
        expectation: String,
    },
    /// Ask the backend whether it lists the passwordless helper for `argv`'s
    /// user, and require that it does: the control that shows the listing
    /// works, so a `MustNotList` that is answered no means no. A listing that
    /// does not work, or says no here, restores what this run installed.
    MustList {
        /// What to run.
        argv: Vec<String>,
        /// What must be true.
        expectation: String,
    },
    /// Delete a file xudo owns unless it holds an edit, in which case leave it
    /// and warn: for the sysctl drop-in, whose edit must never keep the
    /// passwordless line in place.
    RemoveUnlessEdited {
        /// The path.
        path: String,
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
            Self::AppendBlock { path, .. } => format!("append xudo's block to {path}"),
            Self::RemoveBlock { path, .. } => format!("remove xudo's block from {path}"),
            Self::Remove { path } => format!("remove {path}"),
            Self::FunctionalProbe { expectation, .. } => {
                format!("probe: {expectation}")
            }
            Self::Notice { text } => format!("notice: {}", first_sentence(text)),
            Self::RefusalProbe { expectation, .. } => format!("probe first: {expectation}"),
            Self::RefuseEdited { path } => format!("stop if {path} was edited"),
            Self::ReadBack { candidate } => format!("read back {candidate}"),
            Self::ValidateWhole { argv } => {
                format!("validate the whole configuration: {}", argv.join(" "))
            }
            Self::MustNotList { expectation, .. } | Self::MustList { expectation, .. } => {
                format!("check: {expectation}")
            }
            Self::RemoveUnlessEdited { path } => {
                format!("remove {path}, or leave it with a warning if it was edited")
            }
        }
    }
}

/// What the agent path checks once its file is in place: the whole
/// configuration parses, the backend lists the helper for root (the
/// control), and not for nobody nor with an argument for `member`.
fn checks_after_rename(exe: &str, member: &str) -> [PlanStep; 4] {
    let listing = |user: &str, extra: &[&str]| {
        let mut argv = vec![
            exe.to_owned(),
            "-n".to_owned(),
            "-l".to_owned(),
            "-U".to_owned(),
            user.to_owned(),
            GATE_NOPASS.to_owned(),
        ];
        argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
        argv
    };
    [
        // `-f` names the file sudo reads, so its includes are parsed
        // with it, and skips the mode check that `-c` alone makes:
        // Ubuntu 26.04's sudo-rs ships it 0644, which sudo accepts.
        PlanStep::ValidateWhole {
            argv: [VISUDO, "-c", "-f", "/etc/sudoers"]
                .map(str::to_owned)
                .to_vec(),
        },
        // The control: root, whom the stock configuration gives `ALL`,
        // is listed. Without it a listing that cannot work at all (no
        // `-U`, a configuration the backend will not read) would pass
        // the two checks after it.
        PlanStep::MustList {
            argv: listing("root", &[]),
            expectation: "the backend lists the passwordless helper for root, so the \
                          listing works"
                .to_owned(),
        },
        PlanStep::MustNotList {
            argv: listing("nobody", &[]),
            expectation: "the backend does not list the passwordless helper for nobody, \
                          who is not in the agent group"
                .to_owned(),
        },
        PlanStep::MustNotList {
            argv: listing(member, &["x"]),
            expectation: format!(
                "the backend does not list the passwordless helper with an argument for \
                 {member}"
            ),
        },
    ]
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
            name: XUDO_GROUP.to_owned(),
        }];

        match backend.kind {
            BackendKind::Sudo | BackendKind::SudoRs => {
                steps.extend(sudoers_steps(SudoersSnippet::human_only(backend)?));
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
                    });
                }
            }
        }

        steps.push(auth_probe(&backend.exe));

        steps.push(PlanStep::Notice {
            text: "xudo is installed in its password-required form. Every invocation will \
                   prompt. The passwordless agent path is off: no rule names its helper \
                   (`xudo install --agent-path` is the opt-in). No user was added to the xudo \
                   group: membership is the privilege grant, so run `xudo doctor --fix` to \
                   review and grant it deliberately. Agent detection is not a security \
                   boundary; the allowlist and the compiled-in deny-list are."
                .to_owned(),
        });

        Ok(Self {
            backend: backend.kind,
            steps,
        })
    }

    /// Builds the opt-in plan that also turns on the passwordless agent path:
    /// the human-only file plus one `%xudo-agent` `NOPASSWD` line for the
    /// `-nopass` helper with no arguments. Before anything is written, the
    /// helper must refuse a caller it cannot attest and no file xudo would
    /// replace may hold an edit. After the rename, the backend parses its whole
    /// configuration and must not list the helper for `nobody`, nor with an
    /// argument for `member` (a member of the agent group, or `nobody` when
    /// there is none); any of those failing restores what the run installed.
    /// `raise_ptrace` adds the sysctl drop-in; the caller decides it, from the
    /// flag and the live value.
    ///
    /// # Errors
    ///
    /// [`SnippetError::Unsupported`] for doas ([`AGENT_PATH_SUDO_ONLY`]) or a
    /// backend that cannot be given a snippet.
    pub fn with_agent_path(
        backend: &Backend,
        raise_ptrace: bool,
        member: Option<&str>,
    ) -> Result<Self, SnippetError> {
        if backend.kind == BackendKind::Doas {
            return Err(SnippetError::Unsupported {
                backend: backend.kind.label().to_owned(),
                reason: AGENT_PATH_SUDO_ONLY.to_owned(),
            });
        }
        let snippet = SudoersSnippet::with_agent_path(backend)?;
        // The backend detection found, not the kind's usual path: Ubuntu's
        // sudo-rs package installs `/usr/bin/sudo-rs` alone.
        let exe = backend.exe.clone();
        let mut steps = vec![
            PlanStep::RefusalProbe {
                argv: vec![exe.clone(), "-n".to_owned(), GATE_NOPASS.to_owned()],
                expectation: "the passwordless helper, run through the backend by a caller it \
                              cannot attest, refuses and runs nothing"
                    .to_owned(),
            },
            // Every edit check before the first change, groups included.
            PlanStep::RefuseEdited {
                path: SUDOERS_PATH.to_owned(),
            },
        ];
        if raise_ptrace {
            steps.push(PlanStep::RefuseEdited {
                path: PTRACE_DROP_IN_PATH.to_owned(),
            });
        }
        steps.extend([
            PlanStep::CreateGroup {
                name: XUDO_GROUP.to_owned(),
            },
            PlanStep::CreateGroup {
                name: XUDO_AGENT_GROUP.to_owned(),
            },
        ]);
        steps.extend(sudoers_steps(snippet));
        steps.extend(checks_after_rename(&exe, member.unwrap_or("nobody")));
        if raise_ptrace {
            let candidate = format!("{PTRACE_DROP_IN_PATH}.candidate");
            steps.extend([
                PlanStep::WriteCandidate {
                    path: candidate.clone(),
                    contents: PTRACE_DROP_IN.to_owned(),
                    mode: 0o440,
                },
                PlanStep::ReadBack {
                    candidate: candidate.clone(),
                },
                PlanStep::Install {
                    from: candidate,
                    to: PTRACE_DROP_IN_PATH.to_owned(),
                },
            ]);
        }
        steps.push(auth_probe(&exe));
        steps.push(PlanStep::Notice {
            text: "The agent path is on. A member of xudo-agent may run the passwordless helper \
                   with no arguments and no password; the helper runs a command only when the \
                   kernel attests a registered harness and a root-written rule grants that \
                   harness that command. The group stays as enrol left it: this install added \
                   nobody. `xudo install` turns the agent path off again, and \
                   `xudo install --uninstall` removes everything xudo wrote."
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

/// Write, validate and install one sudoers snippet.
fn sudoers_steps(snippet: SudoersSnippet) -> [PlanStep; 3] {
    let destination = SudoersSnippet::path();
    let candidate = format!("{destination}.candidate");
    [
        PlanStep::WriteCandidate {
            path: candidate.clone(),
            contents: snippet.contents,
            mode: SudoersSnippet::mode(),
        },
        match snippet.validate_argv {
            Some(argv) => PlanStep::Validate { argv },
            None => PlanStep::ValidateBySubstitution {
                candidate: candidate.clone(),
                reason: "this backend's visudo validates only /etc/sudoers, so a \
                         named-file check would silently examine the wrong file"
                    .to_owned(),
            },
        },
        PlanStep::Install {
            from: candidate,
            to: destination.to_owned(),
        },
    ]
}

/// The probe that shows the password rule is in effect, through the backend
/// detection found.
fn auth_probe(exe: &str) -> PlanStep {
    PlanStep::FunctionalProbe {
        argv: vec![exe.to_owned(), "-n".to_owned(), GATE_AUTH.to_owned()],
        expectation: "the helper refuses without a password rather than reporting that \
                      no rule permits it, which proves the rule is in effect and that \
                      no credential is cached"
            .to_owned(),
    }
}

/// Why the file at `path` must not be replaced or removed: it holds an edit.
/// `None` when it is xudo's own text, or a file this has no exact text for.
///
/// The drop-in must be exactly [`PTRACE_DROP_IN`]. The sudoers file must be
/// exactly one of xudo's texts once it names the agent path in any spelling;
/// one that does not is held to the marker alone, as before the agent path,
/// so an older xudo's human-only file still uninstalls.
#[must_use]
pub fn edited(path: &str, bytes: &[u8]) -> Option<&'static str> {
    if path == PTRACE_DROP_IN_PATH {
        return (bytes != PTRACE_DROP_IN.as_bytes())
            .then_some("it is not byte for byte the drop-in xudo writes, so it was edited");
    }
    (path == SUDOERS_PATH && names_agent_path(bytes) && recognize(bytes).is_none()).then_some(
        "it names the agent path and is not byte for byte a text xudo writes, so it was edited; \
         remove or restore it by hand",
    )
}

/// Builds the plan that removes xudo's integration.
///
/// **An uninstall that leaves a sudoers rule behind is a security defect, not
/// an untidiness.** The group is deliberately *not* removed: an operator may
/// have granted membership for their own reasons, and silently revoking it on a
/// package removal is a surprise in the other direction.
pub fn uninstall_plan(backend: BackendKind) -> InstallPlan {
    let steps = match backend {
        // An edited sudoers file stops the uninstall before anything is
        // removed: it is not xudo's to remove.
        BackendKind::Sudo | BackendKind::SudoRs => vec![
            PlanStep::RefuseEdited {
                path: SUDOERS_PATH.to_owned(),
            },
            PlanStep::Remove {
                path: SUDOERS_PATH.to_owned(),
            },
            PlanStep::Remove {
                path: format!("{SUDOERS_PATH}.candidate"),
            },
            // After the sudoers file: an edited drop-in is left with a
            // warning, and never keeps the passwordless line in place.
            PlanStep::RemoveUnlessEdited {
                path: PTRACE_DROP_IN_PATH.to_owned(),
            },
            PlanStep::Remove {
                path: format!("{PTRACE_DROP_IN_PATH}.candidate"),
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
                name: "xudo".to_owned()
            })
        );
        let described = plan.describe().join("\n");
        assert!(described.contains("create group xudo (empty)"));
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
        assert_eq!(destination, "/etc/sudoers.d/xudo");
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
        assert!(text.contains("agent path is off"), "{text}");
        assert!(text.contains("--agent-path"), "{text}");
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
        assert!(paths.contains(&"/etc/sudoers.d/xudo".to_owned()));
        assert!(paths.iter().any(|p| p.ends_with(".candidate")));
    }

    #[test]
    fn uninstalling_doas_removes_exactly_xudos_block() {
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
                name: "xudo".to_owned(),
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
            PlanStep::RefusalProbe {
                argv: vec!["/usr/bin/sudo".to_owned()],
                expectation: "e".to_owned(),
            },
            PlanStep::RefuseEdited {
                path: "/p".to_owned(),
            },
            PlanStep::ReadBack {
                candidate: "/p".to_owned(),
            },
            PlanStep::ValidateWhole {
                argv: vec!["/usr/sbin/visudo".to_owned()],
            },
            PlanStep::MustNotList {
                argv: vec!["/usr/bin/sudo".to_owned()],
                expectation: "e".to_owned(),
            },
            PlanStep::MustList {
                argv: vec!["/usr/bin/sudo".to_owned()],
                expectation: "e".to_owned(),
            },
            PlanStep::RemoveUnlessEdited {
                path: "/p".to_owned(),
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

    /// Every line of every file a plan writes.
    fn written(plan: &InstallPlan) -> Vec<String> {
        plan.steps
            .iter()
            .flat_map(|step| match step {
                PlanStep::WriteCandidate { contents, .. } => {
                    contents.lines().map(str::to_owned).collect()
                }
                _ => Vec::new(),
            })
            .collect()
    }

    fn agent_plan(kind: BackendKind, raise: bool) -> InstallPlan {
        InstallPlan::with_agent_path(&backend(kind, true, true), raise, None).unwrap()
    }

    #[test]
    fn install_without_agent_path_writes_no_nopasswd() {
        // The default, for every backend: nothing it writes names the
        // passwordless helper, its alias, its group, or the tag.
        for kind in [BackendKind::Sudo, BackendKind::SudoRs, BackendKind::Doas] {
            let plan = InstallPlan::human_only(&backend(kind, true, true)).unwrap();
            for line in written(&plan) {
                assert!(!names_agent_path(line.as_bytes()), "{kind:?}: {line}");
            }
            assert!(
                !plan
                    .steps
                    .iter()
                    .any(|s| matches!(s, PlanStep::RefusalProbe { .. }))
            );
        }
    }

    #[test]
    fn nopass_rule_names_only_the_nopass_file() {
        // Exactly one passwordless line, for `%xudo-agent` (never `%xudo`),
        // on an alias naming only the `-nopass` file with no arguments.
        for kind in [BackendKind::Sudo, BackendKind::SudoRs] {
            let lines = written(&agent_plan(kind, false));
            let nopass: Vec<&String> = lines.iter().filter(|l| l.contains("NOPASSWD")).collect();
            assert_eq!(nopass, ["%xudo-agent ALL=(root) NOPASSWD: XUDO_NOPASS"]);
            let alias: Vec<&String> = lines
                .iter()
                .filter(|l| l.starts_with("Cmnd_Alias XUDO_NOPASS"))
                .collect();
            assert_eq!(
                alias,
                ["Cmnd_Alias XUDO_NOPASS = /usr/libexec/xudo/xudo-gate-nopass \"\""]
            );
        }
    }

    #[test]
    fn the_auth_rule_never_carries_nopasswd() {
        for plan in [
            agent_plan(BackendKind::Sudo, true),
            InstallPlan::human_only(&backend(BackendKind::Sudo, true, true)).unwrap(),
        ] {
            let lines = written(&plan);
            for line in lines.iter().filter(|l| l.contains("XUDO_AUTH")) {
                assert!(!line.contains("NOPASSWD"), "{line}");
                assert!(!line.contains("!authenticate"), "{line}");
            }
            assert!(lines.contains(&"%xudo ALL=(root) PASSWD:   XUDO_AUTH".to_owned()));
        }
    }

    #[test]
    fn the_agent_path_refuses_doas() {
        let refused =
            InstallPlan::with_agent_path(&backend(BackendKind::Doas, true, true), false, None)
                .unwrap_err();
        assert!(
            refused.to_string().contains("sudo and sudo-rs only"),
            "{refused}"
        );
    }

    #[test]
    fn the_agent_path_plan_probes_first_and_writes_the_drop_in_only_when_asked() {
        let plan = agent_plan(BackendKind::Sudo, false);
        assert_eq!(
            plan.steps.first(),
            Some(&PlanStep::RefusalProbe {
                argv: vec![
                    "/usr/bin/sudo".to_owned(),
                    "-n".to_owned(),
                    GATE_NOPASS.to_owned()
                ],
                expectation: "the passwordless helper, run through the backend by a caller it \
                              cannot attest, refuses and runs nothing"
                    .to_owned(),
            })
        );
        let described = plan.describe();
        let at = |needle: &str| described.iter().position(|d| d.contains(needle)).unwrap();
        assert!(at("was edited") < at("write candidate"));
        assert!(!described.join("\n").contains("sysctl"));

        let raised = agent_plan(BackendKind::SudoRs, true).describe();
        let at = |needle: &str| raised.iter().position(|d| d.contains(needle)).unwrap();
        assert!(at("stop if /etc/sysctl.d/05-xudo-ptrace-scope.conf was edited") < at("read back"));
        assert!(at("read back") < at("-> /etc/sysctl.d/05-xudo-ptrace-scope.conf"));
        assert!(
            raised
                .last()
                .unwrap()
                .starts_with("notice: The agent path is on.")
        );
        assert!(
            written(&agent_plan(BackendKind::Sudo, true))
                .contains(&"kernel.yama.ptrace_scope = 1".to_owned())
        );
    }

    #[test]
    fn an_edited_file_stops_the_agent_path_before_any_group_is_created() {
        for raise in [false, true] {
            let described = agent_plan(BackendKind::Sudo, raise).describe();
            let last_check = described
                .iter()
                .rposition(|d| d.starts_with("stop if"))
                .unwrap();
            let first_group = described
                .iter()
                .position(|d| d.starts_with("create group"))
                .unwrap();
            assert!(last_check < first_group, "{described:?}");
        }
    }

    #[test]
    fn the_whole_configuration_is_parsed_and_the_helper_never_listed_wider_after_the_rename() {
        let sudo_rs_only = Backend {
            exe: "/usr/bin/sudo-rs".to_owned(),
            ..backend(BackendKind::SudoRs, true, true)
        };
        let plan = InstallPlan::with_agent_path(&sudo_rs_only, false, Some("agent")).unwrap();
        let install = plan
            .steps
            .iter()
            .position(|s| matches!(s, PlanStep::Install { to, .. } if to == SUDOERS_PATH))
            .unwrap();
        assert_eq!(
            plan.steps[install + 1],
            PlanStep::ValidateWhole {
                argv: ["/usr/sbin/visudo", "-c", "-f", "/etc/sudoers"]
                    .map(str::to_owned)
                    .to_vec()
            }
        );
        let listings: Vec<Vec<String>> = plan
            .steps
            .iter()
            .filter_map(|s| match s {
                PlanStep::MustNotList { argv, .. } | PlanStep::MustList { argv, .. } => {
                    Some(argv.clone())
                }
                _ => None,
            })
            .collect();
        let nopass = GATE_NOPASS.to_owned();
        // The control first: root is listed, so a no below is a real no.
        assert_eq!(
            plan.steps[install + 2].describe(),
            "check: the backend lists the passwordless helper for root, so the listing works"
        );
        assert_eq!(
            listings,
            [
                ["/usr/bin/sudo-rs", "-n", "-l", "-U", "root", &nopass]
                    .map(String::from)
                    .to_vec(),
                ["/usr/bin/sudo-rs", "-n", "-l", "-U", "nobody", &nopass]
                    .map(String::from)
                    .to_vec(),
                ["/usr/bin/sudo-rs", "-n", "-l", "-U", "agent", &nopass, "x"]
                    .map(String::from)
                    .to_vec()
            ]
        );
        // Every probe goes through the backend detection found.
        for step in &plan.steps {
            if let PlanStep::FunctionalProbe { argv, .. } | PlanStep::RefusalProbe { argv, .. } =
                step
            {
                assert_eq!(argv[0], "/usr/bin/sudo-rs", "{step:?}");
            }
        }
        // With no member to ask about, nobody stands in for one.
        let alone = agent_plan(BackendKind::Sudo, false);
        assert!(
            alone
                .describe()
                .contains(&"check: the backend does not list the passwordless helper with an argument for nobody".to_owned())
        );
    }

    #[test]
    fn a_backend_with_no_honest_snippet_gets_no_agent_path() {
        let crippled = Backend {
            exe: "/usr/bin/sudo".to_owned(),
            kind: BackendKind::Sudo,
            version: "0.0".to_owned(),
            capabilities: CapabilityMatrix::empty(),
        };
        assert!(InstallPlan::with_agent_path(&crippled, false, None).is_err());
    }

    #[test]
    fn an_edited_drop_in_never_keeps_the_passwordless_line_in_place() {
        // The sudoers file is checked and removed before the drop-in is
        // looked at, and an edited drop-in is left with a warning, not a stop.
        let plan = uninstall_plan(BackendKind::Sudo);
        let described = plan.describe();
        let at = |want: &str| described.iter().position(|d| d == want).unwrap();
        assert_eq!(at("stop if /etc/sudoers.d/xudo was edited"), 0);
        assert!(
            at("remove /etc/sudoers.d/xudo")
                < at(
                    "remove /etc/sysctl.d/05-xudo-ptrace-scope.conf, or leave it with a \
                      warning if it was edited"
                )
        );
        assert!(!plan.steps.contains(&PlanStep::RefuseEdited {
            path: PTRACE_DROP_IN_PATH.to_owned()
        }));
    }

    #[test]
    fn an_edited_agent_file_or_drop_in_is_never_removed() {
        let sudo = backend(BackendKind::Sudo, true, true);
        let agent = SudoersSnippet::with_agent_path(&sudo).unwrap().contents;
        let human = SudoersSnippet::human_only(&sudo).unwrap().contents;
        assert_eq!(edited(SUDOERS_PATH, agent.as_bytes()), None);
        assert_eq!(edited(SUDOERS_PATH, human.as_bytes()), None);
        // An older xudo's human-only text names no agent path: the marker rule.
        assert_eq!(
            edited(
                SUDOERS_PATH,
                b"# Managed by xudo.\n%xudo ALL=(root) PASSWD: X\n"
            ),
            None
        );
        let tampered = format!("{agent}%xudo-agent ALL=(ALL) NOPASSWD: ALL\n");
        assert!(
            edited(SUDOERS_PATH, tampered.as_bytes())
                .unwrap()
                .contains("edited")
        );
        assert_eq!(edited(PTRACE_DROP_IN_PATH, PTRACE_DROP_IN.as_bytes()), None);
        let lowered = PTRACE_DROP_IN.replace("= 1", "= 0");
        assert!(edited(PTRACE_DROP_IN_PATH, lowered.as_bytes()).is_some());
        assert_eq!(edited("/etc/doas.d/60-xudo.conf", b"anything"), None);
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
