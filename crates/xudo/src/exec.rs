//! `xudo exec`: ask the broker, then let `main` swap this process for the backend.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use xudo_backend::Probe;
use xudo_backend::snippet::GATE_AUTH;
use xudo_policy::{DenialCode, ExitCode};
use xudo_wire::{Answer, BrokerRequest, BrokerResponse, MAX_RESPONSE_BYTES};

use crate::cli::{Cli, emit};

/// How long a broker gets to answer before we give up on it.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// What `main` execs, in place: `backend gate`, nothing else.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecPlan {
    /// The backend, an absolute path.
    pub backend: &'static str,
    /// The gate, its only argument.
    pub gate: &'static str,
    /// Run as a child and wait, instead of exec in place. doas does not fork,
    /// so the pinned process would be the gate itself; the gate only looks at
    /// its ancestors. sudo forks, so it stays an in-place exec.
    pub spawn: bool,
}

/// [`plan`] against this machine's backend and the real broker socket.
///
/// # Errors
///
/// As [`plan`].
pub fn plan_live(
    cli: &Cli,
    argv: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExecPlan, ExitCode> {
    let socket = Path::new(xudo_wire::BROKER_SOCKET);
    plan(cli, argv, &xudo_sys::HostProbe, socket, TIMEOUT, out, err)
}

/// Asks the broker about `argv`. `Ok` means exec the plan; `Err` is the exit status.
///
/// # Errors
///
/// The exit status to return when there is nothing to exec.
pub fn plan(
    cli: &Cli,
    argv: &[String],
    probe: &dyn Probe,
    socket: &Path,
    timeout: Duration,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExecPlan, ExitCode> {
    let Some((program, operands)) = argv.split_first() else {
        let _ = writeln!(err, "xudo: nothing to run; pass a command after `--`");
        return Err(ExitCode::Unusable);
    };
    // Cheap pick on purpose: `detect` runs slow probes, and this runs every time.
    let Some(backend) = ["/usr/bin/sudo", "/usr/bin/doas"]
        .into_iter()
        .find(|path| probe.exists(path))
    else {
        let _ = writeln!(err, "xudo: no sudo or doas installed; run `xudo doctor`");
        return Err(ExitCode::Unusable);
    };

    // "unattested" is a hint the broker ignores; it works out who we are itself.
    let request = BrokerRequest::new(program.clone(), operands.to_vec(), "unattested");
    let response = match ask(socket, timeout, &request) {
        Ok(response) => response,
        Err(why) => {
            let _ = writeln!(
                err,
                "xudo: the broker is unreachable ({why}); run `xudo doctor`"
            );
            return Err(ExitCode::Unusable);
        }
    };

    match response.answer {
        Answer::Refused { code, remediation } => {
            let _ = writeln!(err, "xudo: the broker refused ({code:?}): {remediation}");
            Err(ExitCode::Unusable)
        }
        Answer::Decided { decision, minted } => {
            if !decision.verdict.is_permitted() {
                let status = emit(cli, &decision, out);
                if decision.denial == Some(DenialCode::HumanPathOnly) {
                    let _ = writeln!(
                        err,
                        "xudo: a human must run this; queue it with:\n  ido queue -- {}",
                        display_quoted(argv)
                    );
                }
                return Err(status);
            }
            // Permitted but nothing minted means the gate has nothing to find.
            let Some(minted) = minted else {
                let _ = writeln!(err, "xudo: permitted, but the broker minted no entry");
                return Err(ExitCode::Unusable);
            };
            // Only ever run the one gate that install put in the sudo rule.
            if minted.gate != GATE_AUTH {
                let _ = writeln!(err, "xudo: the broker named an unexpected gate; refusing");
                return Err(ExitCode::Unusable);
            }
            Ok(ExecPlan {
                backend,
                gate: GATE_AUTH,
                spawn: backend == "/usr/bin/doas",
            })
        }
    }
}

/// One request, one response, both bounded.
pub(crate) fn ask(
    socket: &Path,
    timeout: Duration,
    request: &BrokerRequest,
) -> Result<BrokerResponse, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| e.to_string())?;
    // A failed write shows up as a failed read below, so it isn't checked twice.
    let _ = stream.write_all(request.to_json().as_bytes());
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut bytes = Vec::new();
    // One byte past the limit, so an oversized answer is seen and refused.
    let limit = u64::try_from(MAX_RESPONSE_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    stream
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    BrokerResponse::parse(&bytes).map_err(|e| e.to_string())
}

/// The argv as a shell line, for a human to read and paste. Display only.
fn display_quoted(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            let plain = !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/._-=:,+@%".contains(c));
            if plain {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use std::os::unix::net::UnixListener;
    use std::thread;

    use clap::Parser;
    use xudo_policy::{Decision, Verdict};
    use xudo_wire::{Minted, RefusalCode};

    use super::*;

    struct Has(&'static [&'static str]);

    impl Probe for Has {
        fn exists(&self, path: &str) -> bool {
            self.0.contains(&path)
        }
        fn version_banner(&self, _: &str) -> Option<String> {
            None
        }
        fn directory_exists(&self, _: &str) -> bool {
            false
        }
        fn honours_directive(&self, _: &str, _: &str) -> bool {
            false
        }
        fn honours_scoped_directive(&self, _: &str, _: &str) -> bool {
            false
        }
        fn validates_named_file(&self, _: &str) -> bool {
            false
        }
        fn accepts_argument_wildcard(&self, _: &str) -> bool {
            false
        }
    }

    fn cli() -> Cli {
        Cli::parse_from(["xudo", "exec", "--", "x"])
    }

    fn argv() -> Vec<String> {
        ["/usr/bin/apt-get", "install", "ripgrep"]
            .map(String::from)
            .to_vec()
    }

    fn minted(gate: &str) -> Minted {
        Minted {
            nonce: "0".repeat(64),
            deadline: 1,
            ttl_secs: 1,
            gate: gate.into(),
        }
    }

    fn allow() -> Decision {
        let mut d = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        d.verdict = Verdict::Allow;
        d.denial = None;
        d
    }

    /// Runs `plan` against a broker thread that answers `reply` (raw bytes).
    fn against(
        reply: Vec<u8>,
        probe: &dyn Probe,
        argv: &[String],
    ) -> (Result<ExecPlan, ExitCode>, String, String) {
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
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(&cli(), argv, probe, &socket, TIMEOUT, &mut out, &mut err);
        let request = broker.join().unwrap();
        // What the broker received is exactly what the caller typed.
        let sent = BrokerRequest::parse(&request).unwrap();
        assert_eq!(sent.program, argv[0]);
        assert_eq!(sent.argv, argv[1..]);
        (
            result,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn json(answer: &Answer) -> Vec<u8> {
        let response = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: answer.clone(),
        };
        serde_json::to_vec(&response).unwrap()
    }

    fn decided(decision: Decision, minted: Option<Minted>) -> Vec<u8> {
        json(&Answer::Decided { decision, minted })
    }

    const SUDO: Has = Has(&["/usr/bin/sudo"]);

    #[test]
    fn a_permitted_command_returns_the_plan_for_the_installed_gate() {
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (result, _, err) = against(reply, &SUDO, &argv());
        assert_eq!(
            result,
            Ok(ExecPlan {
                backend: "/usr/bin/sudo",
                gate: GATE_AUTH,
                spawn: false
            })
        );
        assert!(err.is_empty());
    }

    #[test]
    fn doas_is_used_when_sudo_is_absent() {
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (result, _, _) = against(reply, &Has(&["/usr/bin/doas"]), &argv());
        assert_eq!(result.unwrap().backend, "/usr/bin/doas");
    }

    #[test]
    fn doas_is_run_as_a_child_so_xudo_stays_an_ancestor() {
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (result, _, _) = against(reply, &Has(&["/usr/bin/doas"]), &argv());
        assert!(result.unwrap().spawn);
    }

    #[test]
    fn a_gate_path_other_than_the_installed_one_is_refused() {
        let reply = decided(allow(), Some(minted("/tmp/evil")));
        let (result, _, err) = against(reply, &SUDO, &argv());
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(err.contains("unexpected gate"), "{err}");
    }

    #[test]
    fn permitted_without_a_minted_entry_fails_closed() {
        let (result, _, err) = against(decided(allow(), None), &SUDO, &argv());
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(err.contains("minted no entry"), "{err}");
    }

    #[test]
    fn a_denial_exits_denied_and_execs_nothing() {
        let deny = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        // Even a minted entry beside a denial must not run.
        let reply = decided(deny, Some(minted(GATE_AUTH)));
        let (result, out, err) = against(reply, &SUDO, &argv());
        assert_eq!(result, Err(ExitCode::Denied));
        assert!(!out.is_empty());
        assert!(!err.contains("ido queue"), "{err}");
    }

    #[test]
    fn a_human_only_denial_prints_the_ido_line() {
        let deny = Decision::deny(DenialCode::HumanPathOnly, Vec::new(), Vec::new());
        let mut args = argv();
        args.push("it's here".into());
        let (result, _, err) = against(decided(deny, None), &SUDO, &args);
        assert_eq!(result, Err(ExitCode::Denied));
        assert!(
            err.contains("ido queue -- /usr/bin/apt-get install ripgrep 'it'\\''s here'"),
            "{err}"
        );
    }

    #[test]
    fn a_refusal_exits_unusable_with_its_remediation() {
        let reply =
            serde_json::to_vec(&BrokerResponse::refused(RefusalCode::ProgramNotAbsolute)).unwrap();
        let (result, _, err) = against(reply, &SUDO, &argv());
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(err.contains("ProgramNotAbsolute"), "{err}");
    }

    #[test]
    fn an_oversized_response_is_refused() {
        let (result, _, err) = against(vec![b' '; MAX_RESPONSE_BYTES + 10], &SUDO, &argv());
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(err.contains("unreachable"), "{err}");
    }

    #[test]
    fn a_garbage_response_is_unusable() {
        let (result, _, _) = against(b"not json".to_vec(), &SUDO, &argv());
        assert_eq!(result, Err(ExitCode::Unusable));
    }

    #[test]
    fn a_broker_that_never_answers_times_out_unusable() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let held = thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            // Keep the connection open and silent until the client gives up.
            thread::sleep(Duration::from_millis(500));
            drop(s);
        });
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let started = std::time::Instant::now();
        let result = plan(
            &cli(),
            &argv(),
            &SUDO,
            &socket,
            Duration::from_millis(100),
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(started.elapsed() < Duration::from_millis(450));
        held.join().unwrap();
    }

    #[test]
    fn a_zero_timeout_is_unusable_not_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &cli(),
            &argv(),
            &SUDO,
            &socket,
            Duration::ZERO,
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
    }

    #[test]
    fn no_broker_is_unusable_and_says_doctor() {
        let dir = tempfile::tempdir().unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &cli(),
            &argv(),
            &SUDO,
            &dir.path().join("none.sock"),
            TIMEOUT,
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(String::from_utf8(err).unwrap().contains("xudo doctor"));
    }

    #[test]
    fn no_backend_installed_is_unusable() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &cli(),
            &argv(),
            &Has(&[]),
            Path::new("/nonexistent"),
            TIMEOUT,
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(String::from_utf8(err).unwrap().contains("no sudo or doas"));
    }

    #[test]
    fn nothing_to_run_is_unusable() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &cli(),
            &[],
            &SUDO,
            Path::new("/x"),
            TIMEOUT,
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
    }

    #[test]
    fn plan_live_stops_on_an_empty_command_before_touching_anything() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            plan_live(&cli(), &[], &mut out, &mut err),
            Err(ExitCode::Unusable)
        );
    }

    #[test]
    fn exec_asks_the_backend_nothing_but_whether_it_exists() {
        // The cheap pick must not need the slow probes; this fake answers
        // "no" to them all, and the pick still works.
        let p = Has(&["/usr/bin/sudo"]);
        assert!(p.exists("/usr/bin/sudo"));
        assert!(p.version_banner("x").is_none());
        assert!(!p.directory_exists("x"));
        assert!(!p.honours_directive("x", "y"));
        assert!(!p.honours_scoped_directive("x", "y"));
        assert!(!p.validates_named_file("x"));
        assert!(!p.accepts_argument_wildcard("x"));
    }

    #[test]
    fn quoting_keeps_an_empty_or_hostile_argument_one_word() {
        let quoted = display_quoted(&["a".into(), String::new(), "$(x) y".into()]);
        assert_eq!(quoted, "a '' '$(x) y'");
    }

    #[test]
    fn run_with_never_execs_even_for_exec() {
        // No backend, so it stops before the real socket is touched.
        let cli = Cli::parse_from(["xudo", "exec", "--", "/usr/bin/true"]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = crate::run_with(
            &cli,
            &crate::Platform {
                ops: xudo_sys::host_ops().as_ref(),
                probe: &Has(&[]),
                host: &xudo_sys::LiveHost,
                path: None,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(status, ExitCode::Unusable);
    }
}
