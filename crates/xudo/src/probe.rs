//! The install probe: ask the broker for `id -u`, run the gate, expect `0`.
//!
//! The gate runs as a child of this process, so the entry the broker pinned to
//! us is in its lineage. Verified means the gate printed `0` and nothing else.

use std::path::Path;
use std::time::Duration;

use xudo_backend::snippet::GATE_AUTH;
use xudo_sys::{InstallProbe, ProbeResult, Runner};
use xudo_wire::{Answer, BrokerRequest};

use crate::exec::{TIMEOUT, ask};

/// The shipped action's program and its one argument (`rules/05-probe.toml`).
const PROGRAM: &str = "/usr/bin/id";
const ARGUMENT: &str = "-u";

/// Probes through the broker at `socket`, running the gate with `runner`.
pub struct BrokerProbe<'a> {
    /// The broker's socket.
    pub socket: &'a Path,
    /// How long it gets to answer.
    pub timeout: Duration,
    /// Runs the backend and gate.
    pub runner: &'a dyn Runner,
}

impl BrokerProbe<'_> {
    /// The real broker socket, the real timeout.
    #[must_use]
    pub fn live(runner: &dyn Runner) -> BrokerProbe<'_> {
        BrokerProbe {
            socket: Path::new(xudo_wire::BROKER_SOCKET),
            timeout: TIMEOUT,
            runner,
        }
    }
}

impl InstallProbe for BrokerProbe<'_> {
    fn verify(&self, plan: &[String]) -> ProbeResult {
        let unavailable = |reason: String| ProbeResult::Unavailable { reason };
        let Some((backend, rest)) = plan.split_first() else {
            return unavailable("the plan names nothing to run".to_owned());
        };
        let request = BrokerRequest::new(PROGRAM, vec![ARGUMENT.to_owned()], "unattested");
        let response = match ask(self.socket, self.timeout, &request) {
            Ok(response) => response,
            Err(why) => return unavailable(format!("the broker is unreachable: {why}")),
        };
        match response.answer {
            Answer::Refused { code, .. } => {
                return unavailable(format!("the broker refused the probe ({code:?})"));
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
            deadline: 1,
            ttl_secs: 1,
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

    /// Verifies against a broker that sends `reply`; returns the result and what it was asked.
    fn against(reply: Vec<u8>, gate: &Gate) -> (ProbeResult, BrokerRequest) {
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
        let (result, request) = against(decided(allow(), Some(minted(GATE_AUTH))), &gate);
        assert_eq!(result, ProbeResult::Verified);
        assert_eq!(
            (request.program.as_str(), request.argv),
            ("/usr/bin/id", vec!["-u".to_owned()])
        );
        assert_eq!(*gate.1.borrow(), [format!("/usr/bin/sudo -n {GATE_AUTH}")]);
    }

    #[test]
    fn a_gate_that_prints_anything_but_zero_is_not_verified() {
        for stdout in ["1000", "", "00", "0 0", "root", "0x0"] {
            let (result, _) = against(
                decided(allow(), Some(minted(GATE_AUTH))),
                &printed(stdout, true),
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
        );
        assert!(
            matches!(&result, ProbeResult::Failed { reason } if reason.contains("why")),
            "{result:?}"
        );
    }

    #[test]
    fn a_backend_that_cannot_run_is_not_verified() {
        let gate = Gate(Err(()), RefCell::default());
        let (result, _) = against(decided(allow(), Some(minted(GATE_AUTH))), &gate);
        assert!(format!("{result:?}").starts_with("Failed"), "{result:?}");
    }

    #[test]
    fn an_unreachable_broker_never_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let gate = printed("0", true);
        let probe = BrokerProbe {
            socket: &dir.path().join("none.sock"),
            timeout: TIMEOUT,
            runner: &gate,
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
        let (result, _) = against(reply, &gate);
        assert!(unavailable(&result).contains("refused"), "{result:?}");
        assert!(gate.1.borrow().is_empty());
    }

    #[test]
    fn a_denied_probe_never_runs_the_gate() {
        let gate = printed("0", true);
        let deny = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        let (result, _) = against(decided(deny, Some(minted(GATE_AUTH))), &gate);
        assert!(unavailable(&result).contains("denied"), "{result:?}");
        assert!(gate.1.borrow().is_empty());
    }

    #[test]
    fn a_permit_with_no_entry_or_a_foreign_gate_never_runs_the_gate() {
        for entry in [None, Some(minted("/tmp/evil"))] {
            let gate = printed("0", true);
            let (result, _) = against(decided(allow(), entry), &gate);
            assert!(
                unavailable(&result).contains("minted no entry"),
                "{result:?}"
            );
            assert!(gate.1.borrow().is_empty());
        }
    }

    #[test]
    fn a_plan_with_nothing_to_run_is_unavailable() {
        let gate = printed("0", true);
        let probe = BrokerProbe::live(&gate);
        assert_eq!(probe.socket, Path::new(xudo_wire::BROKER_SOCKET));
        assert!(unavailable(&probe.verify(&[])).contains("nothing to run"));
    }
}
