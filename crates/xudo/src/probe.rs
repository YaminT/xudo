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

/// The phrase `ci/deb/row.sh` greps in the package install log.
const NO_REGULAR_PROBE: &str = "no probe program is a regular file";

/// Why the probe did not run when no candidate was a regular file.
fn no_regular_probe() -> String {
    let mut listed = String::new();
    for (index, probe) in PROBES.iter().enumerate() {
        if index > 0 {
            listed.push_str(", ");
        }
        listed.push_str(probe.program);
    }
    format!("{NO_REGULAR_PROBE} ({listed}); a symlink or a missing program was not run")
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

impl BrokerProbe<'_> {
    /// Runs a `-l -U <user> <helper>` listing: `Ok(true)` and what it printed
    /// when listed, `Ok(false)` when not. `-l` with a command exits 0 only
    /// when it would run it, and refuses silently with 1. Anything on
    /// standard error (an unknown user, a configuration the backend will not
    /// read, an option it does not know) also exits 1, so it is no answer.
    fn listing(&self, plan: &[String]) -> Result<(bool, String), String> {
        let Some((backend, rest)) = plan.split_first() else {
            return Err("the plan names nothing to run".to_owned());
        };
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        let out = self
            .runner
            .run(backend, &rest, None)
            .map_err(|why| format!("{backend} could not be run: {why}"))?;
        if !out.stderr.trim().is_empty() {
            return Err(format!(
                "`{}` gave no answer (status {:?}): {}",
                plan.join(" "),
                out.code,
                out.stderr.trim()
            ));
        }
        Ok((out.success, out.stdout.trim().to_owned()))
    }
}

/// How the gate's refusal line begins (`xudo_gate::run`'s exit message).
const GATE_REFUSED: &str = "xudo-gate: refused (";

impl InstallProbe for BrokerProbe<'_> {
    /// Runs the passwordless helper through the backend, as root and with no
    /// request minted for it: a caller it cannot attest. Refused means a
    /// non-zero status, nothing on standard output, and the gate's own refusal
    /// line, so sudo saying no (a password, no rule) is not taken for it.
    fn refuses(&self, plan: &[String]) -> ProbeResult {
        let Some((backend, rest)) = plan.split_first() else {
            return ProbeResult::Unavailable {
                reason: "the plan names nothing to run".to_owned(),
            };
        };
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        match self.runner.run(backend, &rest, None) {
            Ok(out)
                if !out.success
                    && out.stdout.is_empty()
                    && out.stderr.lines().any(|l| l.starts_with(GATE_REFUSED)) =>
            {
                ProbeResult::Verified
            }
            Ok(out) => ProbeResult::Failed {
                reason: format!(
                    "the helper, run through {backend}, did not refuse as the gate refuses \
                     (status {:?}, {} bytes on standard output): {}",
                    out.code,
                    out.stdout.len(),
                    out.stderr.trim()
                ),
            },
            Err(why) => ProbeResult::Unavailable {
                reason: format!("{backend} could not be run: {why}"),
            },
        }
    }

    /// Asks the backend whether it lists the passwordless helper, and
    /// requires that it does not. See [`Self::listed`] for what counts as
    /// an answer.
    fn not_listed(&self, plan: &[String]) -> ProbeResult {
        match self.listing(plan) {
            Ok((true, stdout)) => ProbeResult::Failed {
                reason: format!(
                    "`{}` lists the passwordless helper: {stdout}",
                    plan.join(" ")
                ),
            },
            Ok((false, _)) => ProbeResult::Verified,
            Err(reason) => ProbeResult::Unavailable { reason },
        }
    }

    /// Asks the backend whether it lists the passwordless helper, and
    /// requires that it does: the control that shows the listing works.
    fn listed(&self, plan: &[String]) -> ProbeResult {
        match self.listing(plan) {
            Ok((true, _)) => ProbeResult::Verified,
            Ok((false, _)) => ProbeResult::Failed {
                reason: format!("`{}` does not list the passwordless helper", plan.join(" ")),
            },
            Err(reason) => ProbeResult::Unavailable { reason },
        }
    }

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
            Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::QueueListed { .. }
            | Answer::Done => {
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
    use std::os::unix::net::UnixListener;

    use xudo_backend::snippet::GATE_NOPASS;
    use xudo_policy::{Decision, DenialCode, Verdict};
    use xudo_sys::{Output, SysError};
    use xudo_wire::{BrokerResponse, Minted, RefusalCode};

    use super::*;

    /// A deadline a passing test never waits for, so a loaded runner cannot
    /// expire it.
    const PATIENT: Duration = Duration::from_secs(60);

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
            claim_token: None,
            harness: None,
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
        let broker = crate::test_broker::serve_once(listener, reply);
        let probe = BrokerProbe {
            socket: &socket,
            timeout: PATIENT,
            runner: gate,
            files,
        };
        let result = probe.verify(&argv());
        (result, BrokerRequest::parse(&broker.finish()).unwrap())
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

    /// What the refusal check judges `stdout`, `stderr` and `success` to be.
    fn refusal_of(stdout: &str, stderr: &str, success: bool) -> (ProbeResult, Vec<String>) {
        let gate = Gate(
            Ok(Output {
                success,
                code: Some(if success { 0 } else { 19 }),
                stdout: stdout.to_owned(),
                stderr: stderr.to_owned(),
            }),
            RefCell::default(),
        );
        let files = id_is_regular();
        let probe = BrokerProbe {
            socket: Path::new("/nonexistent/broker.sock"),
            timeout: PATIENT,
            runner: &gate,
            files: &files,
        };
        let nopass = ["/usr/bin/sudo", "-n", GATE_NOPASS].map(String::from);
        let result = probe.refuses(&nopass);
        let ran = gate.1.borrow().clone();
        (result, ran)
    }

    #[test]
    fn the_helper_refusing_an_unattested_caller_is_the_only_pass() {
        let refused = "xudo-gate: refused (no_pending_request, severity high)\n";
        let (result, ran) = refusal_of("", refused, false);
        assert_eq!(result, ProbeResult::Verified);
        // Through the backend, with no request asked of the broker first.
        assert_eq!(ran, ["/usr/bin/sudo -n /usr/libexec/xudo/xudo-gate-nopass"]);
    }

    #[test]
    fn the_probe_failing_is_never_taken_for_a_refusal() {
        // It ran something and exited 0; it printed; sudo asked a password or
        // had no rule; a refusal line on a success: each one is a failure.
        let refused = "xudo-gate: refused (no_pending_request, severity high)";
        for (stdout, stderr, success) in [
            ("0\n", "", true),
            ("", refused, true),
            ("0\n", refused, false),
            ("", "sudo: a password is required", false),
            ("", "sudo: xudo-gate-nopass: command not found", false),
            ("", "  xudo-gate: refused (indented)", false),
        ] {
            let (result, _) = refusal_of(stdout, stderr, success);
            assert!(
                format!("{result:?}").starts_with("Failed"),
                "{stdout:?} {stderr:?} {success}: {result:?}"
            );
        }
    }

    #[test]
    fn a_helper_that_cannot_be_run_or_is_not_named_is_not_a_refusal() {
        let gate = Gate(Err(()), RefCell::default());
        let files = id_is_regular();
        let probe = BrokerProbe {
            socket: Path::new("/nonexistent/broker.sock"),
            timeout: PATIENT,
            runner: &gate,
            files: &files,
        };
        let result = probe.refuses(&argv());
        assert!(
            unavailable(&result).contains("could not be run"),
            "{result:?}"
        );
        assert!(unavailable(&probe.refuses(&[])).contains("names nothing"));
    }

    /// What the listing check makes of one answer from the backend.
    fn listing_of(answer: Result<Output, ()>) -> (ProbeResult, Vec<String>) {
        listing_with(answer, false)
    }

    /// The same answer, to the control (`listed`) or to the check.
    fn listing_with(answer: Result<Output, ()>, control: bool) -> (ProbeResult, Vec<String>) {
        let gate = Gate(answer, RefCell::default());
        let files = id_is_regular();
        let probe = BrokerProbe {
            socket: Path::new("/nonexistent/broker.sock"),
            timeout: PATIENT,
            runner: &gate,
            files: &files,
        };
        let argv = ["/usr/bin/sudo-rs", "-n", "-l", "-U", "nobody", GATE_NOPASS].map(String::from);
        let result = if control {
            probe.listed(&argv)
        } else {
            probe.not_listed(&argv)
        };
        let ran = gate.1.borrow().clone();
        (result, ran)
    }

    fn output(success: bool, stdout: &str) -> Output {
        Output {
            success,
            code: Some(i32::from(!success)),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    #[test]
    fn a_helper_the_backend_lists_is_a_failed_check() {
        // A zero status is a listing, whatever is printed.
        let (result, ran) = listing_of(Ok(output(true, "")));
        assert!(format!("{result:?}").starts_with("Failed"), "{result:?}");
        assert_eq!(
            ran,
            [format!("/usr/bin/sudo-rs -n -l -U nobody {GATE_NOPASS}")]
        );
        // A refusal may name the helper as it refuses; it is still a refusal.
        for stdout in [
            "",
            &format!("Sorry, user nobody may not run {GATE_NOPASS}\n"),
        ] {
            let (result, _) = listing_of(Ok(output(false, stdout)));
            assert_eq!(result, ProbeResult::Verified);
        }
    }

    #[test]
    fn a_refusal_with_anything_on_standard_error_is_no_answer() {
        // sudo exits 1 for `unknown user`, a usage error, or a configuration
        // it will not read, as it does for a refusal. Only a silent 1 is no.
        for stderr in [
            "sudo: unknown user nobody",
            "sudo-rs: invalid configuration: No such file or directory (os error 2)",
            "sudo: invalid option -- 'U'",
        ] {
            let answer = Output {
                stderr: format!("{stderr}\n"),
                ..output(false, "")
            };
            let (result, _) = listing_of(Ok(answer.clone()));
            assert!(unavailable(&result).contains(stderr), "{result:?}");
            let (result, _) = listing_with(Ok(answer), true);
            assert!(
                unavailable(&result).contains("gave no answer"),
                "{result:?}"
            );
        }
    }

    #[test]
    fn the_control_passes_only_when_root_is_listed() {
        let (result, ran) = listing_with(Ok(output(true, GATE_NOPASS)), true);
        assert_eq!(result, ProbeResult::Verified);
        assert_eq!(ran.len(), 1);
        // A silent refusal for root: the listing cannot be trusted to say yes.
        let (result, _) = listing_with(Ok(output(false, "")), true);
        assert_eq!(
            result,
            ProbeResult::Failed {
                reason: format!(
                    "`/usr/bin/sudo-rs -n -l -U nobody {GATE_NOPASS}` does not list the \
                     passwordless helper"
                )
            }
        );
        let (result, _) = listing_with(Err(()), true);
        assert!(unavailable(&result).contains("could not be run"));
        let gate = printed("", false);
        assert!(unavailable(&BrokerProbe::live(&gate).listed(&[])).contains("names nothing"));
    }

    #[test]
    fn a_listing_the_backend_could_not_be_asked_for_is_not_a_pass() {
        let (result, _) = listing_of(Err(()));
        assert!(
            unavailable(&result).contains("could not be run"),
            "{result:?}"
        );
        let gate = printed("", false);
        let probe = BrokerProbe::live(&gate);
        assert!(unavailable(&probe.not_listed(&[])).contains("names nothing"));
    }

    #[test]
    fn an_unreachable_broker_never_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let gate = printed("0", true);
        let files = id_is_regular();
        let probe = BrokerProbe {
            socket: &dir.path().join("none.sock"),
            timeout: PATIENT,
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
            timeout: PATIENT,
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
            timeout: PATIENT,
            runner: &gate,
            files: &files,
        };
        let text = unavailable(&probe.verify(&argv()));
        // `ci/deb/row.sh` greps this phrase. `was not run` is a weaker substring.
        assert_eq!(NO_REGULAR_PROBE, "no probe program is a regular file");
        assert!(text.contains(NO_REGULAR_PROBE), "{text}");
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
        assert!(xudo_sys::trust::verify_path(&link).is_err());

        // A `..` component has to be refused by the trust walk, not by lstat.
        // `/usr/bin/id/../../etc/passwd` dies in lstat because `id` is not a
        // directory, so it never reaches that refusal. The same regular file
        // written with `..` (`/usr/bin/id` becomes `/usr/bin/../bin/id`) lstats
        // as a file, and `verify_path` then refuses `..`.
        let stock = [
            "/usr/bin/id",
            "/usr/bin/gnuid",
            "/usr/bin/true",
            "/bin/true",
            "/bin/ls",
        ];
        let regular = stock
            .iter()
            .copied()
            .find(|path| host.is_regular_file(Path::new(path)));
        assert!(
            regular.is_some(),
            "no root-owned regular file among {stock:?}"
        );
        let regular = regular.unwrap();
        let plain = Path::new(regular);
        let parent = plain.parent().unwrap();
        let parent_name = parent.file_name().unwrap();
        let dotted = parent
            .join("..")
            .join(parent_name)
            .join(plain.file_name().unwrap());
        let facts = xudo_sys::trust::stat_path(&dotted).unwrap();
        assert_eq!(facts.kind, xudo_sys::trust::Kind::File);
        let refusal = xudo_sys::trust::verify_path(&dotted).unwrap_err();
        assert_eq!(
            refusal,
            xudo_sys::trust::TrustError::NotAbsolute {
                at: dotted.display().to_string()
            }
        );
        assert!(!host.is_regular_file(&dotted), "a path with .. qualified");
    }
}
