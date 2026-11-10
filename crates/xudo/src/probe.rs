//! The install probe: ask the broker for `id -u`, run the gate, expect `0`.
//!
//! Two shipped programs share that shape (`rules/05-probe.toml`). The first
//! whose executable is a regular file is the one that runs. The gate runs as a
//! child of this process, so the entry the broker pinned to us is in its
//! lineage. Verified means the gate printed `0` and nothing else. A symlink or
//! a missing program is not executed.

use std::path::Path;
use std::time::Duration;

use xudo_backend::snippet::GATE_AUTH;
use xudo_sys::{InstallProbe, ProbeResult, Runner};
use xudo_wire::{Answer, BrokerRequest};

use crate::exec::{TIMEOUT, ask};

/// One shipped probe command: an absolute program and its one argument.
struct ProbeCommand {
    program: &'static str,
    argument: &'static str,
}

/// Shipped probe commands, first choice first (`rules/05-probe.toml`).
///
/// `/usr/bin/id` is a regular file on Debian and Ubuntu 24.04. On Ubuntu 26.04
/// it is a uutils symlink and `/usr/bin/gnuid` is the regular GNU binary.
const PROBES: &[ProbeCommand] = &[
    ProbeCommand {
        program: "/usr/bin/id",
        argument: "-u",
    },
    ProbeCommand {
        program: "/usr/bin/gnuid",
        argument: "-u",
    },
];

/// Whether a path is a regular file the probe may name.
///
/// An implementation must not follow a symlink, must not search `PATH`, and
/// must not decide from a string prefix of the path. A symlink, a missing
/// path, and anything else that is not a regular file are `false`.
pub trait ProbeFiles {
    /// `true` only when `path` is a regular non-symlink file.
    fn is_regular_file(&self, path: &Path) -> bool;
}

/// The host's answer, through `xudo-sys`'s trust walk.
///
/// `stat` does not follow a final symlink. [`xudo_sys::trust::verify_path`]
/// then refuses a symlink in any ancestor, a `..` component, and a path that
/// is not root's. The gate opens whatever this selects and refuses it again
/// on the descriptor it will run, so a path that only looked regular is not
/// executed.
#[derive(Clone, Copy, Debug)]
pub struct HostProbeFiles;

/// The [`HostProbeFiles`] [`BrokerProbe::live`] holds.
const HOST_PROBE_FILES: HostProbeFiles = HostProbeFiles;

impl ProbeFiles for HostProbeFiles {
    fn is_regular_file(&self, path: &Path) -> bool {
        // A relative path would be a `PATH` search or a lookup from the
        // working directory. Neither is a probe.
        if !path.is_absolute() {
            return false;
        }
        // `stat_path` is `lstat`: a final symlink is a symlink, not the target.
        let Ok(facts) = xudo_sys::trust::stat_path(path) else {
            return false;
        };
        if facts.kind != xudo_sys::trust::Kind::File {
            return false;
        }
        xudo_sys::trust::verify_path(path).is_ok()
    }
}

/// The first probe command whose program is a regular file, if any.
fn chosen_probe(files: &dyn ProbeFiles) -> Option<&'static ProbeCommand> {
    PROBES
        .iter()
        .find(|probe| files.is_regular_file(Path::new(probe.program)))
}

/// Why the probe did not run when no candidate was a regular file.
fn no_regular_probe() -> String {
    let mut listed = String::new();
    for (index, probe) in PROBES.iter().enumerate() {
        if index > 0 {
            listed.push_str(", ");
        }
        listed.push_str(probe.program);
    }
    format!(
        "no probe program is a regular file ({listed}); a symlink or a missing program was not run"
    )
}

/// Probes through the broker at `socket`, running the gate with `runner`.
pub struct BrokerProbe<'a> {
    /// The broker's socket.
    pub socket: &'a Path,
    /// How long it gets to answer.
    pub timeout: Duration,
    /// Runs the backend and gate.
    pub runner: &'a dyn Runner,
    /// Which probe executables are regular files right now.
    pub files: &'a dyn ProbeFiles,
}

impl BrokerProbe<'_> {
    /// The real broker socket, the real timeout, and the host's files.
    #[must_use]
    pub fn live(runner: &dyn Runner) -> BrokerProbe<'_> {
        BrokerProbe {
            socket: Path::new(xudo_wire::BROKER_SOCKET),
            timeout: TIMEOUT,
            runner,
            files: &HOST_PROBE_FILES,
        }
    }
}

impl InstallProbe for BrokerProbe<'_> {
    fn verify(&self, plan: &[String]) -> ProbeResult {
        let unavailable = |reason: String| ProbeResult::Unavailable { reason };
        let Some((backend, rest)) = plan.split_first() else {
            return unavailable("the plan names nothing to run".to_owned());
        };
        // doas asks root for a password too. Not a failed install, and nothing
        // is minted for a probe that cannot run.
        if Path::new(backend).file_name().is_some_and(|n| n == "doas") {
            return unavailable(
                "doas asks root for a password; check with `xudo exec -- /usr/bin/id -u` \
                 or `xudo exec -- /usr/bin/gnuid -u` as a member of xudo"
                    .to_owned(),
            );
        }
        // Chosen before the broker is asked, so a symlink is never minted and
        // never executed. The gate repeats the check on the descriptor it runs.
        let Some(probe) = chosen_probe(self.files) else {
            return unavailable(no_regular_probe());
        };
        let request =
            BrokerRequest::new(probe.program, vec![probe.argument.to_owned()], "unattested");
        let response = match ask(self.socket, self.timeout, &request) {
            Ok(response) => response,
            Err(why) => return unavailable(format!("the broker is unreachable: {why}")),
        };
        match response.answer {
            Answer::Refused { code, .. } => {
                return unavailable(format!("the broker refused the probe ({code:?})"));
            }
            Answer::Pending { .. } | Answer::Watching { .. } | Answer::Done => {
                return unavailable(
                    "the broker returned an answer for an unsupported question".to_owned(),
                );
            }
            Answer::Decided { decision, minted } => {
                if !decision.verdict.is_permitted() {
                    return unavailable(
                        "the broker denied the probe; is rules/05-probe.toml installed?".to_owned(),
                    );
                }
                // The gate we are about to run is the one install put in the rule.
                if minted.is_none_or(|m| m.gate != GATE_AUTH) {
                    return unavailable(
                        "the broker minted no entry for the installed gate".to_owned(),
                    );
                }
            }
        }
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        match self.runner.run(backend, &rest, None) {
            Ok(out) if out.success && out.stdout.trim() == "0" => ProbeResult::Verified,
            Ok(out) => ProbeResult::Failed {
                reason: format!(
                    "the gate ran through {backend} and did not print 0 (status {:?}): {}",
                    out.code,
                    out.stderr.trim()
                ),
            },
            Err(why) => ProbeResult::Failed {
                reason: format!("{backend} could not be run: {why}"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use xudo_policy::{Decision, DenialCode, Verdict};
    use xudo_sys::{Output, SysError};
    use xudo_wire::{BrokerResponse, Minted, RefusalCode};

    use super::*;

    /// A gate that answers `Ok(out)` or fails, and records what it was asked to run.
    struct Gate(Result<Output, ()>, RefCell<Vec<String>>);

    impl Runner for Gate {
        fn run(&self, exe: &str, args: &[&str], _: Option<&[u8]>) -> Result<Output, SysError> {
            self.1
                .borrow_mut()
                .push(format!("{exe} {}", args.join(" ")));
            self.0.clone().map_err(|()| SysError::Unsupported {
                operation: "run".to_owned(),
            })
        }
    }

    fn printed(stdout: &str, success: bool) -> Gate {
        let out = Output {
            success,
            code: Some(i32::from(!success)),
            stdout: stdout.to_owned(),
            stderr: "why".to_owned(),
        };
        Gate(Ok(out), RefCell::default())
    }

    fn argv() -> Vec<String> {
        ["/usr/bin/sudo", "-n", GATE_AUTH]
            .map(String::from)
            .to_vec()
    }

    fn allow() -> Decision {
        let mut d = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        d.verdict = Verdict::Allow;
        d.denial = None;
        d
    }

    fn minted(gate: &str) -> Minted {
        Minted {
            nonce: "0".repeat(64),
            expires_in_ms: 1,
            gate: gate.into(),
        }
    }

    fn decided(decision: Decision, minted: Option<Minted>) -> Vec<u8> {
        serde_json::to_vec(&BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided { decision, minted },
        })
        .unwrap()
    }

    /// Paths the test says are regular files, and the paths the probe asked about.
    struct KnownFiles {
        regular: &'static [&'static str],
        asked: RefCell<Vec<std::path::PathBuf>>,
    }

    impl KnownFiles {
        fn only(regular: &'static [&'static str]) -> Self {
            Self {
                regular,
                asked: RefCell::default(),
            }
        }
    }

    impl ProbeFiles for KnownFiles {
        fn is_regular_file(&self, path: &Path) -> bool {
            self.asked.borrow_mut().push(path.to_path_buf());
            self.regular.iter().any(|one| Path::new(one) == path)
        }
    }

    /// `/usr/bin/id` is a regular file, which is the Debian and Ubuntu 24.04 case.
    fn id_is_regular() -> KnownFiles {
        KnownFiles::only(&["/usr/bin/id"])
    }

    /// Verifies against a broker that sends `reply`; returns the result and what it was asked.
    fn against(reply: Vec<u8>, gate: &Gate, files: &KnownFiles) -> (ProbeResult, BrokerRequest) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            s.read_to_end(&mut request).unwrap();
            let _ = s.write_all(&reply);
            request
        });
        let probe = BrokerProbe {
            socket: &socket,
            timeout: TIMEOUT,
            runner: gate,
            files,
        };
        let result = probe.verify(&argv());
        (
            result,
            BrokerRequest::parse(&broker.join().unwrap()).unwrap(),
        )
    }

    /// The result as text, after checking it is `Unavailable`.
    fn unavailable(result: &ProbeResult) -> String {
        assert!(
            format!("{result:?}").starts_with("Unavailable"),
            "{result:?}"
        );
        format!("{result:?}")
    }

    #[test]
    fn a_gate_that_prints_zero_is_verified() {
        let gate = printed("0\r\n", true);
        let files = id_is_regular();
        let (result, request) = against(decided(allow(), Some(minted(GATE_AUTH))), &gate, &files);
        assert_eq!(result, ProbeResult::Verified);
        assert_eq!(
            request.run_fields().map(|(p, a, _)| (p, a.to_vec())),
            Some(("/usr/bin/id", vec!["-u".to_owned()]))
        );
        assert_eq!(*gate.1.borrow(), [format!("/usr/bin/sudo -n {GATE_AUTH}")]);
    }

    #[test]
    fn a_gate_that_prints_anything_but_zero_is_not_verified() {
        for stdout in ["1000", "", "00", "0 0", "root", "0x0"] {
            let (result, _) = against(
                decided(allow(), Some(minted(GATE_AUTH))),
                &printed(stdout, true),
                &id_is_regular(),
            );
            assert!(
                format!("{result:?}").starts_with("Failed"),
                "{stdout:?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_gate_that_fails_is_not_verified_even_if_it_printed_zero() {
        let (result, _) = against(
            decided(allow(), Some(minted(GATE_AUTH))),
            &printed("0", false),
            &id_is_regular(),
        );
        assert!(
            matches!(&result, ProbeResult::Failed { reason } if reason.contains("why")),
            "{result:?}"
        );
    }

    #[test]
    fn a_backend_that_cannot_run_is_not_verified() {
        let gate = Gate(Err(()), RefCell::default());
        let (result, _) = against(
            decided(allow(), Some(minted(GATE_AUTH))),
            &gate,
            &id_is_regular(),
        );
        assert!(format!("{result:?}").starts_with("Failed"), "{result:?}");
    }

    #[test]
    fn an_unreachable_broker_never_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let gate = printed("0", true);
        let files = id_is_regular();
        let probe = BrokerProbe {
            socket: &dir.path().join("none.sock"),
            timeout: TIMEOUT,
            runner: &gate,
            files: &files,
        };
        let result = probe.verify(&argv());
        assert!(unavailable(&result).contains("unreachable"), "{result:?}");
        assert!(gate.1.borrow().is_empty(), "the gate ran without a broker");
    }

    #[test]
    fn a_refusing_broker_never_runs_the_gate() {
        let gate = printed("0", true);
        let reply =
            serde_json::to_vec(&BrokerResponse::refused(RefusalCode::ProgramNotAbsolute)).unwrap();
        let (result, _) = against(reply, &gate, &id_is_regular());
        assert!(unavailable(&result).contains("refused"), "{result:?}");
        assert!(gate.1.borrow().is_empty());
    }

    #[test]
    fn a_non_run_answer_from_the_broker_does_not_verify_install() {
        let id = "a".repeat(64);
        for answer in [
            Answer::Pending {
                id: id.clone(),
                expires_in_ms: 1,
            },
            Answer::Watching {
                prompts: Vec::new(),
                omitted: 0,
            },
            Answer::Done,
        ] {
            let gate = printed("0", true);
            let response = BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer,
            };
            let (result, _) = against(response.to_json().into_bytes(), &gate, &id_is_regular());
            assert!(unavailable(&result).contains("unsupported question"));
            assert!(gate.1.borrow().is_empty());
        }
    }

    #[test]
    fn a_denied_probe_never_runs_the_gate() {
        let gate = printed("0", true);
        let deny = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        let (result, _) = against(
            decided(deny, Some(minted(GATE_AUTH))),
            &gate,
            &id_is_regular(),
        );
        assert!(unavailable(&result).contains("denied"), "{result:?}");
        assert!(gate.1.borrow().is_empty());
    }

    #[test]
    fn a_permit_with_no_entry_or_a_foreign_gate_never_runs_the_gate() {
        for entry in [None, Some(minted("/tmp/evil"))] {
            let gate = printed("0", true);
            let (result, _) = against(decided(allow(), entry), &gate, &id_is_regular());
            assert!(
                unavailable(&result).contains("minted no entry"),
                "{result:?}"
            );
            assert!(gate.1.borrow().is_empty());
        }
    }

    #[test]
    fn a_doas_install_is_never_rolled_back_by_a_probe_that_cannot_ask() {
        let dir = tempfile::tempdir().unwrap();
        let gate = printed("0", true);
        let files = id_is_regular();
        let probe = BrokerProbe {
            // Nothing listens: asking the broker would say "unreachable".
            socket: &dir.path().join("none.sock"),
            timeout: TIMEOUT,
            runner: &gate,
            files: &files,
        };
        let plan = ["/usr/bin/doas", "-n", GATE_AUTH].map(String::from);
        let text = unavailable(&probe.verify(&plan));
        assert!(text.contains("asks root for a password"), "{text}");
        assert!(gate.1.borrow().is_empty());
    }

    #[test]
    fn a_plan_with_nothing_to_run_is_unavailable() {
        let gate = printed("0", true);
        let probe = BrokerProbe::live(&gate);
        assert_eq!(probe.socket, Path::new(xudo_wire::BROKER_SOCKET));
        assert!(unavailable(&probe.verify(&[])).contains("nothing to run"));
    }

    /// The paths a probe asked the seam about, in order.
    fn asked(files: &KnownFiles) -> Vec<String> {
        files
            .asked
            .borrow()
            .iter()
            .map(|path| path.display().to_string())
            .collect()
    }

    #[test]
    fn a_symlinked_probe_is_never_chosen() {
        // The seam answers `false` for a symlink and for a missing file. Neither
        // is minted and neither is executed, even when the gate would print 0.
        let dir = tempfile::tempdir().unwrap();
        let gate = printed("0", true);
        let files = KnownFiles::only(&[]);
        let probe = BrokerProbe {
            socket: &dir.path().join("none.sock"),
            timeout: TIMEOUT,
            runner: &gate,
            files: &files,
        };
        let text = unavailable(&probe.verify(&argv()));
        assert!(text.contains("was not run"), "{text}");
        assert!(
            text.contains("/usr/bin/id") && text.contains("/usr/bin/gnuid"),
            "{text}"
        );
        assert!(gate.1.borrow().is_empty(), "a probe program was executed");
        assert_eq!(asked(&files), ["/usr/bin/id", "/usr/bin/gnuid"]);
    }

    #[test]
    fn the_probe_falls_back_to_gnuid_when_id_is_a_symlink() {
        let gate = printed("0\n", true);
        let files = KnownFiles::only(&["/usr/bin/gnuid"]);
        let (result, request) = against(decided(allow(), Some(minted(GATE_AUTH))), &gate, &files);
        assert_eq!(result, ProbeResult::Verified);
        assert_eq!(
            request
                .run_fields()
                .map(|(program, args, _)| (program, args.to_vec())),
            Some(("/usr/bin/gnuid", vec!["-u".to_owned()]))
        );
        assert_eq!(asked(&files), ["/usr/bin/id", "/usr/bin/gnuid"]);
        assert_eq!(*gate.1.borrow(), [format!("/usr/bin/sudo -n {GATE_AUTH}")]);
    }

    #[test]
    fn a_regular_id_is_chosen_and_gnuid_is_not_asked() {
        let gate = printed("0", true);
        let files = KnownFiles::only(&["/usr/bin/id", "/usr/bin/gnuid"]);
        let (result, request) = against(decided(allow(), Some(minted(GATE_AUTH))), &gate, &files);
        assert_eq!(result, ProbeResult::Verified);
        assert_eq!(
            request.run_fields().map(|(program, _, _)| program),
            Some("/usr/bin/id")
        );
        assert_eq!(asked(&files), ["/usr/bin/id"]);
    }

    #[test]
    fn the_probe_candidates_are_the_shipped_rules_in_order() {
        let rules = include_str!("../../../rules/05-probe.toml");
        let id = rules.find("exe = \"/usr/bin/id\"").unwrap();
        let gnu = rules.find("exe = \"/usr/bin/gnuid\"").unwrap();
        assert!(id < gnu, "gnuid is listed ahead of id");
        assert_eq!(PROBES.len(), 2);
        assert_eq!(PROBES[0].program, "/usr/bin/id");
        assert_eq!(PROBES[1].program, "/usr/bin/gnuid");
        assert!(PROBES.iter().all(|probe| probe.argument == "-u"));
        assert!(rules.contains("id = \"xudo.probe.id\""));
        assert!(rules.contains("id = \"xudo.probe.gnuid\""));
    }

    #[test]
    fn a_symlink_or_a_missing_exe_does_not_qualify() {
        let host = HostProbeFiles;
        assert!(format!("{host:?}").contains("HostProbeFiles"));
        assert!(!host.is_regular_file(Path::new("id")));
        assert!(!host.is_regular_file(Path::new("usr/bin/id")));
        assert!(!host.is_regular_file(Path::new("/usr/bin/xudo-no-such-probe")));
        assert!(
            !host.is_regular_file(Path::new("/usr/bin")),
            "a directory qualified"
        );
        assert!(
            !host.is_regular_file(Path::new("/usr/bin/id/../../etc/passwd")),
            "a path with .. qualified"
        );

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("regular");
        std::fs::write(&file, b"x").unwrap();
        assert!(
            !host.is_regular_file(&file),
            "a file outside the trust walk qualified"
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(!host.is_regular_file(&link), "a symlink qualified");

        let stock = [
            "/usr/bin/id",
            "/usr/bin/gnuid",
            "/usr/bin/true",
            "/bin/true",
            "/bin/ls",
        ];
        assert!(
            stock
                .iter()
                .any(|path| host.is_regular_file(Path::new(path))),
            "no root-owned regular file among {stock:?}; the true branch was not run"
        );
    }
}
