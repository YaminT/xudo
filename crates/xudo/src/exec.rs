//! `xudo exec`: ask the broker, then let `main` swap this process for the backend.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use xudo_backend::Probe;
use xudo_backend::snippet::GATE_AUTH;
use xudo_config::{Layer, Setting, Settings as ConfigSettings, Value as ConfigValue, apply_file};
use xudo_policy::{DenialCode, ExitCode};
use xudo_wire::{Answer, BrokerRequest, BrokerResponse, Question};

use crate::cli::{Cli, emit, emit_queued};

type StatusPoll<'a> =
    dyn FnMut(Duration, &BrokerRequest) -> Result<Option<BrokerResponse>, ExitCode> + 'a;

fn selected_backend(probe: &dyn Probe, err: &mut dyn Write) -> Option<&'static str> {
    // Cheap pick on purpose: `detect` runs slow probes, and this runs every time.
    let Some(backend) = ["/usr/bin/sudo", "/usr/bin/sudo-rs", "/usr/bin/doas"]
        .into_iter()
        .find(|path| probe.exists(path))
    else {
        let _ = writeln!(
            err,
            "xudo: no sudo, sudo-rs, or doas installed; run `xudo doctor`"
        );
        return None;
    };
    Some(backend)
}

/// How long a broker gets to answer before we give up on it.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// What `main` execs, in place: `backend gate`, nothing else.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecPlan {
    /// The backend, one of the compiled-in absolute paths.
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
    queue: Option<&ido::Host>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExecPlan, ExitCode> {
    let socket = Path::new(xudo_wire::BROKER_SOCKET);
    let Some(timeout) = configured_timeout(cli, err) else {
        return Err(ExitCode::Unusable);
    };
    plan_with_confirmation_timeout(
        cli,
        argv,
        &xudo_sys::HostProbe,
        socket,
        TIMEOUT,
        timeout,
        queue,
        out,
        err,
    )
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
    plan_with_confirmation_timeout(
        cli,
        argv,
        probe,
        socket,
        timeout,
        Duration::ZERO,
        None,
        out,
        err,
    )
}

/// Asks the broker and waits for an out-of-band approval for at most `wait`.
///
/// # Errors
///
/// Returns the exit status when the request is refused, remains pending, or
/// the broker cannot be used.
#[allow(clippy::too_many_arguments)]
pub fn plan_with_confirmation_timeout(
    cli: &Cli,
    argv: &[String],
    probe: &dyn Probe,
    socket: &Path,
    timeout: Duration,
    wait: Duration,
    queue: Option<&ido::Host>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExecPlan, ExitCode> {
    plan_paced(
        cli, argv, probe, socket, timeout, wait, None, queue, out, err,
    )
}

/// The clock and the sleep behind the approval wait.
///
/// The wall clock and a real sleep make the wait depend on machine load, so a
/// test substitutes a virtual pair and the wait becomes deterministic.
struct Pace<'a> {
    elapsed: &'a mut dyn FnMut() -> Duration,
    sleep: &'a mut dyn FnMut(Duration),
}

/// [`plan_with_confirmation_timeout`] with the wait paced by `pace`, or by the
/// real clock when it is `None`.
#[allow(clippy::too_many_arguments)]
fn plan_paced(
    cli: &Cli,
    argv: &[String],
    probe: &dyn Probe,
    socket: &Path,
    timeout: Duration,
    wait: Duration,
    mut pace: Option<&mut Pace<'_>>,
    queue: Option<&ido::Host>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExecPlan, ExitCode> {
    let Some((program, operands)) = argv.split_first() else {
        let _ = writeln!(err, "xudo: nothing to run; pass a command after `--`");
        return Err(ExitCode::Unusable);
    };
    let Some(backend) = selected_backend(probe, err) else {
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
        Answer::Refused {
            code, remediation, ..
        } => {
            let _ = writeln!(err, "xudo: the broker refused ({code:?}): {remediation}");
            Err(ExitCode::Unusable)
        }
        Answer::Pending { id, expires_in_ms } => pending_or_wait(
            cli,
            &id,
            expires_in_ms,
            wait,
            out,
            err,
            &mut |wait, status_request| {
                let mut status = |remaining| {
                    ask(
                        socket,
                        timeout.min(remaining).min(Duration::from_millis(500)),
                        status_request,
                    )
                };
                if let Some(pace) = pace.as_deref_mut() {
                    return poll_status_with(&id, wait, &mut status, pace.elapsed, pace.sleep);
                }
                let started = Instant::now();
                let mut elapsed = || started.elapsed();
                let mut sleep = std::thread::sleep;
                poll_status_with(&id, wait, &mut status, &mut elapsed, &mut sleep)
            },
        )
        .and_then(|answer| match answer {
            None => Err(ExitCode::NotConfirmed),
            Some(answer) => handle_status_answer(
                cli, answer, &id, &request, socket, timeout, backend, err, out,
            ),
        }),
        Answer::Watching { .. } | Answer::Done => {
            let _ = writeln!(
                err,
                "xudo: broker returned an answer for an unsupported question"
            );
            Err(ExitCode::Unusable)
        }
        Answer::Decided { decision, minted } => {
            if !decision.verdict.is_permitted() {
                return Err(report_denial(cli, &decision, argv, queue, out, err));
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
            let spawn = backend == "/usr/bin/doas";
            Ok(ExecPlan {
                backend,
                gate: GATE_AUTH,
                spawn,
            })
        }
    }
}

fn valid_request_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn configured_timeout(cli: &Cli, err: &mut dyn Write) -> Option<Duration> {
    let mut config = ConfigSettings::default();
    let contents = match std::fs::read_to_string(&cli.config_file) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => {
            let _ = writeln!(
                err,
                "xudo: failing closed; the settings file could not be read"
            );
            return None;
        }
    };
    if !contents.is_empty() {
        let name = cli.config_file.display().to_string();
        if let Err(load_err) = apply_file(&mut config, Layer::System, &name, &contents) {
            let _ = writeln!(err, "xudo: {load_err}");
            let _ = writeln!(
                err,
                "xudo: failing closed; the settings file was not applied"
            );
            return None;
        }
    }
    timeout_from_value(&config.get(Setting::ConfirmationTimeoutSecs).value, err)
}

fn timeout_from_value(value: &ConfigValue, err: &mut dyn Write) -> Option<Duration> {
    match value {
        ConfigValue::Integer(seconds) => Some(Duration::from_secs(*seconds)),
        ConfigValue::Bool(_) | ConfigValue::Text(_) => {
            let _ = writeln!(err, "xudo: confirmation_timeout_secs has an invalid value");
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn pending_or_wait(
    cli: &Cli,
    id: &str,
    expires_in_ms: u64,
    wait: Duration,
    out: &mut dyn Write,
    err: &mut dyn Write,
    poll: &mut StatusPoll<'_>,
) -> Result<Option<BrokerResponse>, ExitCode> {
    if !valid_request_id(id) {
        let _ = writeln!(err, "xudo: broker returned an invalid request id");
        return Err(ExitCode::Unusable);
    }
    let request = BrokerRequest {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        question: Question::Status { id: id.to_owned() },
    };
    let mut pending = || match cli.output {
        crate::cli::Format::Human => {
            write!(out, "{}", crate::render::pending_human(id, expires_in_ms))
        }
        crate::cli::Format::Json => {
            writeln!(out, "{}", crate::render::pending_json(id, expires_in_ms))
        }
    };
    if wait.is_zero() {
        let _ = pending();
        let _ = writeln!(
            err,
            "xudo: pending approval on xudo watch, request {}…",
            crate::render::short_id(id)
        );
        return Ok(None);
    }
    let seconds = wait.as_secs();
    let _ = pending();
    let _ = writeln!(
        err,
        "xudo: waiting for approval on xudo watch, request {}…, {seconds} s",
        crate::render::short_id(id)
    );
    let result = poll(wait, &request);
    if result.as_ref().is_ok_and(Option::is_none) {
        let _ = pending();
    }
    result
}

fn poll_status_with(
    id: &str,
    wait: Duration,
    status: &mut dyn FnMut(Duration) -> Result<BrokerResponse, String>,
    elapsed: &mut dyn FnMut() -> Duration,
    sleep: &mut dyn FnMut(Duration),
) -> Result<Option<BrokerResponse>, ExitCode> {
    let mut silent = false;
    loop {
        let passed = elapsed();
        // The n-second window, and its optional five-second silence extension,
        // start after the initial Pending answer reaches the front end.
        let deadline = if silent {
            wait.saturating_add(Duration::from_secs(5))
        } else {
            wait
        };
        if passed >= deadline {
            return if silent {
                Err(ExitCode::Unusable)
            } else {
                Ok(None)
            };
        }
        sleep(Duration::from_millis(500).min(deadline.saturating_sub(passed)));
        let remaining = deadline.saturating_sub(elapsed());
        if remaining.is_zero() {
            return if silent {
                Err(ExitCode::Unusable)
            } else {
                Ok(None)
            };
        }
        match status(Duration::from_millis(500).min(remaining)) {
            Ok(response) => match &response.answer {
                Answer::Pending { id: status_id, .. } if status_id == id => silent = false,
                Answer::Pending { .. } => return Err(ExitCode::Unusable),
                Answer::Decided { .. } => return Ok(Some(response)),
                Answer::Refused { .. } | Answer::Watching { .. } | Answer::Done => {
                    return Err(ExitCode::Unusable);
                }
            },
            Err(_) => silent = true,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_status_answer(
    cli: &Cli,
    response: BrokerResponse,
    id: &str,
    request: &BrokerRequest,
    socket: &Path,
    timeout: Duration,
    backend: &'static str,
    err: &mut dyn Write,
    out: &mut dyn Write,
) -> Result<ExecPlan, ExitCode> {
    let Answer::Decided { decision, minted } = response.answer else {
        return Err(ExitCode::NotConfirmed);
    };
    if !decision.verdict.is_permitted() {
        if matches!(
            decision.denial,
            Some(DenialCode::ConfirmationRefused | DenialCode::ConfirmationExpired)
        ) {
            return Err(emit(cli, &decision, out));
        }
        let _ = writeln!(err, "xudo: the broker returned an invalid approval status");
        return Err(ExitCode::Unusable);
    }
    let Some(minted) = minted else {
        let _ = writeln!(err, "xudo: permitted, but the broker minted no entry");
        return Err(ExitCode::Unusable);
    };
    if minted.nonce != id || minted.gate != GATE_AUTH {
        let _ = writeln!(err, "xudo: the broker named an unexpected gate; refusing");
        return Err(ExitCode::Unusable);
    }
    // The extra n+5 s bound begins after the first watch answer. Keep the
    // consuming run short even when the original broker timeout is longer.
    let consumed = ask(socket, timeout.min(Duration::from_secs(5)), request).map_err(|why| {
        let _ = writeln!(
            err,
            "xudo: the broker is unreachable ({why}); run `xudo doctor`"
        );
        ExitCode::Unusable
    })?;
    let Answer::Decided { decision, minted } = consumed.answer else {
        if matches!(consumed.answer, Answer::Refused { .. }) {
            let _ = writeln!(err, "xudo: the broker refused the approval re-run");
            return Err(ExitCode::Unusable);
        }
        // Expiry or a concurrent consumer can invalidate the approval between
        // status and this run. The broker has atomically taken or expired it;
        // report pending/refused (18), never a generic unusable result.
        let _ = writeln!(err, "xudo: the approval expired or was already consumed");
        return Err(ExitCode::NotConfirmed);
    };
    if !decision.verdict.is_permitted() {
        return Err(emit(cli, &decision, out));
    }
    let Some(minted) = minted else {
        let _ = writeln!(err, "xudo: permitted, but the broker minted no entry");
        return Err(ExitCode::Unusable);
    };
    if minted.nonce != id || minted.gate != GATE_AUTH {
        let _ = writeln!(err, "xudo: the broker named an unexpected gate; refusing");
        return Err(ExitCode::Unusable);
    }
    Ok(ExecPlan {
        backend,
        gate: GATE_AUTH,
        spawn: backend == "/usr/bin/doas",
    })
}

/// One request and one response, on one deadline.
///
/// Connect, the write, and the read share `timeout`. A signal retries the
/// interrupted call with only the time still left.
///
/// # Errors
///
/// Returns a connection, deadline, size, or parse error.
pub(crate) fn ask(
    socket: &Path,
    timeout: Duration,
    request: &BrokerRequest,
) -> Result<BrokerResponse, String> {
    let bytes = crate::exchange::exchange(socket, request.to_json().as_bytes(), timeout)?;
    BrokerResponse::parse(&bytes).map_err(|error| error.to_string())
}

/// Shows a denial, queueing it first when `--queue` asks and a person can
/// resolve it. The verdict and the exit status are the denial's either way.
fn report_denial(
    cli: &Cli,
    decision: &xudo_policy::Decision,
    argv: &[String],
    queue: Option<&ido::Host>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let human_only = matches!(
        decision.denial,
        Some(DenialCode::HumanPathOnly | DenialCode::NoConfirmationChannel)
    );
    let queued = match (human_only, queue) {
        (true, Some(host)) => queue_denied(host, argv, decision, err),
        _ => None,
    };
    let status = emit_queued(cli, decision, queued.map(|q| q.id), out);
    match queued {
        Some(q) => {
            let _ = write!(err, "{}", crate::render::queued_human(q.id, q.already));
        }
        None if human_only => {
            let _ = writeln!(
                err,
                "xudo: a human must run this; queue it with:\n  ido queue -- {}",
                display_quoted(argv)
            );
        }
        None => {}
    }
    status
}

/// Writes the denied command to the caller's `ido` queue, as `ido queue` would.
///
/// `None` on any failure, after saying why: the caller then prints the plain
/// denial, so a failed write is never read as queued. The command is stored as
/// the vector it arrived as; the denial code is display-only provenance in the
/// entry's reason, which `ido` sanitizes wherever it shows it.
fn queue_denied(
    host: &ido::Host,
    argv: &[String],
    decision: &xudo_policy::Decision,
    err: &mut dyn Write,
) -> Option<ido::Enqueued> {
    let code = decision
        .denial
        .map_or_else(String::new, |code| format!("{code:?}"));
    let reason = format!("xudo denied this ({code}); a human must run it");
    match ido::enqueue(host, argv.to_vec(), Some(reason)) {
        Ok(queued) => Some(queued),
        Err(error) => {
            let _ = writeln!(
                err,
                "xudo: could not queue the command ({}); nothing was queued",
                term_sanitize::display_str(
                    &error.to_string(),
                    term_sanitize::Limits::single_line(200)
                )
                .text
            );
            None
        }
    }
}

/// The argv as a shell line, for a human to read and paste. Display only.
pub(crate) fn display_quoted(argv: &[String]) -> String {
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

    use std::io::Read;
    use std::os::unix::net::UnixListener;
    use std::thread;

    use clap::Parser;
    use xudo_policy::{Decision, Verdict};
    use xudo_wire::{MAX_RESPONSE_BYTES, Minted, RefusalCode};

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
            expires_in_ms: 1,
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
        against_queueing(reply, probe, argv, &cli(), None)
    }

    /// [`against`], with `--queue` pointed at `queue` and the given flags.
    fn against_queueing(
        reply: Vec<u8>,
        probe: &dyn Probe,
        argv: &[String],
        cli: &Cli,
        queue: Option<&ido::Host>,
    ) -> (Result<ExecPlan, ExitCode>, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            s.read_to_end(&mut request).unwrap();
            s.write_all(&reply).unwrap();
            request
        });
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan_with_confirmation_timeout(
            cli,
            argv,
            probe,
            &socket,
            TIMEOUT,
            Duration::ZERO,
            queue,
            &mut out,
            &mut err,
        );
        let request = broker.join().unwrap();
        // What the broker received is exactly what the caller typed.
        let sent = BrokerRequest::parse(&request).unwrap();
        assert_eq!(
            sent.run_fields().map(|(program, args, _)| (program, args)),
            Some((argv[0].as_str(), &argv[1..]))
        );
        (
            result,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    /// The plan, or a panic that includes the captured stderr.
    fn expect_plan(result: Result<ExecPlan, ExitCode>, err: &str) -> ExecPlan {
        result.unwrap_or_else(|status| panic!("plan returned {status:?}: {err}"))
    }

    #[test]
    fn a_failed_plan_is_reported_with_the_brokers_stderr() {
        let panic = std::panic::catch_unwind(|| {
            expect_plan(
                Err(ExitCode::Unusable),
                "the broker is unreachable (timed out)",
            );
        })
        .unwrap_err();
        let message = panic.downcast_ref::<String>().unwrap().clone();
        assert!(message.contains("Unusable"), "{message}");
        assert!(message.contains("timed out"), "{message}");
    }

    fn json(answer: &Answer) -> Vec<u8> {
        let response = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: answer.clone(),
        };
        serde_json::to_vec(&response).unwrap()
    }

    fn confirmation_denied(code: DenialCode) -> BrokerResponse {
        BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: Decision::deny(code, Vec::new(), Vec::new()),
                minted: None,
            },
        }
    }

    fn one_reply(
        reply: &BrokerResponse,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        thread::JoinHandle<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let reply = reply.to_json().into_bytes();
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(&reply).unwrap();
        });
        (dir, socket, broker)
    }

    fn decided(decision: Decision, minted: Option<Minted>) -> Vec<u8> {
        json(&Answer::Decided { decision, minted })
    }

    const SUDO: Has = Has(&["/usr/bin/sudo"]);

    #[test]
    fn exec_with_timeout_zero_returns_pending_at_once_and_leaves_the_entry() {
        use std::sync::{Arc, Mutex};

        let id = "b".repeat(64);
        let spool_entry = Arc::new(Mutex::new(Some(id.clone())));
        let server_spool = Arc::clone(&spool_entry);
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_listener = listener.try_clone().unwrap();
        let response = json(&Answer::Pending {
            id: id.clone(),
            expires_in_ms: 20_000,
        });
        let entry_id = id.clone();
        let broker = thread::spawn(move || {
            let (mut stream, _) = server_listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            assert!(
                BrokerRequest::parse(&request)
                    .unwrap()
                    .run_fields()
                    .is_some()
            );
            *server_spool.lock().unwrap() = Some(entry_id);
            stream.write_all(&response).unwrap();
        });
        let cli = cli();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan_with_confirmation_timeout(
            &cli,
            &["/usr/bin/apt-get".to_owned(), "remove".to_owned()],
            &SUDO,
            &socket,
            TIMEOUT,
            Duration::ZERO,
            None,
            &mut out,
            &mut err,
        );
        broker.join().unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(result, Err(ExitCode::NotConfirmed));
        assert_eq!(*spool_entry.lock().unwrap(), Some(id));
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        drop(dir);
    }

    #[test]
    fn a_wait_on_the_real_clock_that_is_over_before_polling_leaves_it_pending() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let response = json(&Answer::Pending {
            id: "c".repeat(64),
            expires_in_ms: 20_000,
        });
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            stream.write_all(&response).unwrap();
        });
        let (mut out, mut err) = (Vec::new(), Vec::new());
        // The first sleep lasts the whole window, so no status is asked: the
        // outcome does not depend on how fast the machine is.
        let result = plan_with_confirmation_timeout(
            &cli(),
            &["/usr/bin/apt-get".to_owned(), "remove".to_owned()],
            &SUDO,
            &socket,
            TIMEOUT,
            Duration::from_millis(1),
            None,
            &mut out,
            &mut err,
        );
        broker.join().unwrap();
        assert_eq!(result, Err(ExitCode::NotConfirmed));
    }

    #[test]
    fn timeout_zero_renders_pending_output_and_watch_hint() {
        let cli = cli();
        let id = "a".repeat(64);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = pending_or_wait(
            &cli,
            &id,
            25_000,
            Duration::ZERO,
            &mut out,
            &mut err,
            &mut no_status_reply,
        );
        assert_eq!(result, Ok(None));
        let out = String::from_utf8(out).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert!(out.contains("PENDING"), "{out}");
        assert!(err.contains("pending approval on xudo watch"), "{err}");
        assert_eq!(err.lines().count(), 1);
    }

    #[allow(clippy::unnecessary_wraps)]
    fn no_status_reply(_: Duration, _: &BrokerRequest) -> Result<Option<BrokerResponse>, ExitCode> {
        Ok(None)
    }

    #[test]
    fn a_wait_that_gets_no_status_reply_reports_pending_again() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = pending_or_wait(
            &cli(),
            &"a".repeat(64),
            25_000,
            Duration::from_secs(1),
            &mut out,
            &mut err,
            &mut no_status_reply,
        );
        assert_eq!(result, Ok(None));
        assert_eq!(
            String::from_utf8(out).unwrap().matches("PENDING").count(),
            2
        );
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("waiting for approval")
        );
    }

    #[test]
    fn broker_pending_ids_must_be_exact_lowercase_hex() {
        assert!(valid_request_id(&"a".repeat(64)));
        assert!(valid_request_id(&"0".repeat(64)));
        assert!(!valid_request_id(&"A".repeat(64)));
        assert!(!valid_request_id(&"g".repeat(64)));
        assert!(!valid_request_id(&"a".repeat(63)));
        assert!(!valid_request_id(&format!("{}x", "a".repeat(64))));
    }

    #[test]
    fn refuses_an_invalid_pending_id_before_rendering_it() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = pending_or_wait(
            &cli(),
            &"A".repeat(64),
            10_000,
            Duration::ZERO,
            &mut out,
            &mut err,
            &mut no_status_reply,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(out.is_empty());
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("invalid request id")
        );
    }

    #[test]
    fn exec_never_waits_past_the_configured_timeout() {
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let mut slept = Duration::ZERO;
        let response = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Pending {
                id: "a".repeat(64),
                expires_in_ms: 10_000,
            },
        };
        let result = poll_status_with(
            &"a".repeat(64),
            Duration::from_secs(1),
            &mut |_| Ok(response.clone()),
            &mut || elapsed.get(),
            &mut |duration| {
                elapsed.set(elapsed.get() + duration);
                slept += duration;
            },
        );
        assert_eq!(result, Ok(None));
        assert_eq!(slept, Duration::from_secs(1));
        assert_eq!(elapsed.get(), Duration::from_secs(1));
    }

    #[test]
    fn status_polling_rejects_another_request_and_unsupported_answers() {
        let id = "a".repeat(64);
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let other = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Pending {
                id: "b".repeat(64),
                expires_in_ms: 5_000,
            },
        };
        assert_eq!(
            poll_status_with(
                &id,
                Duration::from_secs(1),
                &mut |_| Ok(other.clone()),
                &mut || elapsed.get(),
                &mut |duration| elapsed.set(elapsed.get() + duration),
            ),
            Err(ExitCode::Unusable)
        );
        for answer in [
            Answer::Refused {
                code: RefusalCode::RequestUnknown,
                remediation: "retry".into(),
                detail: None,
            },
            Answer::Watching {
                prompts: Vec::new(),
                omitted: 0,
            },
            Answer::Done,
        ] {
            let elapsed = std::cell::Cell::new(Duration::ZERO);
            let response = BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer,
            };
            assert_eq!(
                poll_status_with(
                    &id,
                    Duration::from_secs(1),
                    &mut |_| Ok(response.clone()),
                    &mut || elapsed.get(),
                    &mut |duration| elapsed.set(elapsed.get() + duration),
                ),
                Err(ExitCode::Unusable)
            );
        }
    }

    #[test]
    fn status_polling_stops_before_sleeping_or_polling_after_its_deadline() {
        let polls = std::cell::Cell::new(0);
        let sleeps = std::cell::Cell::new(0);
        let mut status = |_: Duration| {
            polls.set(polls.get() + 1);
            Err("must not poll".into())
        };
        let mut sleep = |_: Duration| sleeps.set(sleeps.get() + 1);
        let _ = status(Duration::ZERO);
        sleep(Duration::ZERO);
        polls.set(0);
        sleeps.set(0);
        assert_eq!(
            poll_status_with(
                &"a".repeat(64),
                Duration::from_secs(1),
                &mut status,
                &mut || Duration::from_secs(1),
                &mut sleep,
            ),
            Ok(None)
        );
        assert_eq!(polls.get(), 0);
        assert_eq!(sleeps.get(), 0);

        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let result = poll_status_with(
            &"a".repeat(64),
            Duration::from_secs(1),
            &mut |_| {
                elapsed.set(Duration::from_secs(6));
                Err("silent".into())
            },
            &mut || elapsed.get(),
            &mut |duration| elapsed.set(elapsed.get() + duration),
        );
        assert_eq!(result, Err(ExitCode::Unusable));
    }

    #[test]
    fn exec_prints_a_pending_envelope_then_a_denied_one_when_denied_during_the_wait() {
        let cli = cli();
        let id = "b".repeat(64);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let response = confirmation_denied(DenialCode::ConfirmationRefused);
        let polled = pending_or_wait(
            &cli,
            &id,
            10_000,
            Duration::from_secs(1),
            &mut out,
            &mut err,
            &mut |wait, request| {
                assert_eq!(wait, Duration::from_secs(1));
                assert_eq!(
                    std::mem::discriminant(&request.question),
                    std::mem::discriminant(&Question::Status { id: String::new() })
                );
                Ok(Some(response.clone()))
            },
        )
        .unwrap()
        .unwrap();
        let request = BrokerRequest::new(argv()[0].clone(), argv()[1..].to_vec(), "unattested");
        let _ = handle_status_answer(
            &cli,
            polled,
            &id,
            &request,
            Path::new("/nonexistent"),
            TIMEOUT,
            "/usr/bin/sudo",
            &mut err,
            &mut out,
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("PENDING"), "{out}");
        assert!(out.contains("DENY"), "{out}");
        assert!(out.contains("confirmation_refused"), "{out}");
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("waiting for approval")
        );
    }

    #[test]
    fn a_positive_timeout_that_expires_renders_the_pending_envelope_again() {
        let cli = cli();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            pending_or_wait(
                &cli,
                &"a".repeat(64),
                9_000,
                Duration::from_secs(1),
                &mut out,
                &mut err,
                &mut |_, _| Ok(None),
            ),
            Ok(None)
        );
        assert_eq!(
            String::from_utf8(out).unwrap().matches("PENDING").count(),
            2
        );
        assert!(String::from_utf8(err).unwrap().contains("1 s"));
    }

    #[test]
    fn status_denial_codes_are_rendered_as_not_confirmed() {
        for code in [
            DenialCode::ConfirmationRefused,
            DenialCode::ConfirmationExpired,
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                handle_status_answer(
                    &cli(),
                    confirmation_denied(code),
                    &"a".repeat(64),
                    &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                    Path::new("/nonexistent"),
                    TIMEOUT,
                    "/usr/bin/sudo",
                    &mut err,
                    &mut out,
                ),
                Err(ExitCode::NotConfirmed)
            );
            assert!(String::from_utf8(out).unwrap().contains(code.as_str()));
        }
    }

    #[test]
    fn status_without_a_terminal_decision_is_not_consumed() {
        let response = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Pending {
                id: "a".repeat(64),
                expires_in_ms: 1,
            },
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            handle_status_answer(
                &cli(),
                response,
                &"a".repeat(64),
                &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                Path::new("/nonexistent"),
                TIMEOUT,
                "/usr/bin/sudo",
                &mut err,
                &mut out,
            ),
            Err(ExitCode::NotConfirmed)
        );
    }

    #[test]
    fn an_invalid_or_unminted_status_approval_fails_closed() {
        for response in [
            confirmation_denied(DenialCode::UnknownAction),
            BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer: Answer::Decided {
                    decision: allow(),
                    minted: None,
                },
            },
        ] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                handle_status_answer(
                    &cli(),
                    response,
                    &"a".repeat(64),
                    &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                    Path::new("/nonexistent"),
                    TIMEOUT,
                    "/usr/bin/sudo",
                    &mut err,
                    &mut out,
                ),
                Err(ExitCode::Unusable)
            );
        }
    }

    #[test]
    fn an_approved_status_cannot_continue_when_the_broker_is_unreachable() {
        let id = "a".repeat(64);
        let response = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: allow(),
                minted: Some(Minted {
                    nonce: id.clone(),
                    expires_in_ms: 1,
                    gate: GATE_AUTH.into(),
                }),
            },
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            handle_status_answer(
                &cli(),
                response,
                &id,
                &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                Path::new("/nonexistent/broker.sock"),
                TIMEOUT,
                "/usr/bin/sudo",
                &mut err,
                &mut out,
            ),
            Err(ExitCode::Unusable)
        );
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("broker is unreachable")
        );
    }

    #[test]
    fn a_rerun_that_does_not_consume_approval_exits_not_confirmed() {
        let id = "a".repeat(64);
        let status = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: allow(),
                minted: Some(Minted {
                    nonce: id.clone(),
                    expires_in_ms: 1,
                    gate: GATE_AUTH.into(),
                }),
            },
        };
        let (dir, socket, broker) = one_reply(&BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Done,
        });
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            handle_status_answer(
                &cli(),
                status,
                &id,
                &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                &socket,
                TIMEOUT,
                "/usr/bin/sudo",
                &mut err,
                &mut out,
            ),
            Err(ExitCode::NotConfirmed)
        );
        broker.join().unwrap();
        drop(dir);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("expired or was already consumed")
        );
    }

    #[test]
    fn a_consumed_approval_must_return_the_same_gate_and_nonce() {
        let id = "a".repeat(64);
        for minted_entry in [
            Minted {
                nonce: id.clone(),
                expires_in_ms: 1,
                gate: "/other".into(),
            },
            Minted {
                nonce: "b".repeat(64),
                expires_in_ms: 1,
                gate: GATE_AUTH.into(),
            },
        ] {
            let status = BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer: Answer::Decided {
                    decision: allow(),
                    minted: Some(Minted {
                        nonce: id.clone(),
                        expires_in_ms: 1,
                        gate: GATE_AUTH.into(),
                    }),
                },
            };
            let (dir, socket, broker) = one_reply(&BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer: Answer::Decided {
                    decision: allow(),
                    minted: Some(minted_entry),
                },
            });
            let mut out = Vec::new();
            let mut err = Vec::new();
            assert_eq!(
                handle_status_answer(
                    &cli(),
                    status,
                    &id,
                    &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                    &socket,
                    TIMEOUT,
                    "/usr/bin/sudo",
                    &mut err,
                    &mut out,
                ),
                Err(ExitCode::Unusable)
            );
            broker.join().unwrap();
            drop(dir);
        }
    }

    #[test]
    fn a_rerun_that_denies_after_approval_still_exits_not_confirmed() {
        let id = "a".repeat(64);
        let status = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: allow(),
                minted: Some(Minted {
                    nonce: id.clone(),
                    expires_in_ms: 1,
                    gate: GATE_AUTH.into(),
                }),
            },
        };
        let denied = confirmation_denied(DenialCode::ConfirmationRefused);
        let (dir, socket, broker) = one_reply(&denied);
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            handle_status_answer(
                &cli(),
                status,
                &id,
                &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                &socket,
                TIMEOUT,
                "/usr/bin/sudo",
                &mut err,
                &mut out,
            ),
            Err(ExitCode::NotConfirmed)
        );
        broker.join().unwrap();
        drop(dir);
    }

    #[test]
    fn a_refused_approval_rerun_exits_unusable() {
        let id = "a".repeat(64);
        let status = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: allow(),
                minted: Some(Minted {
                    nonce: id.clone(),
                    expires_in_ms: 1,
                    gate: GATE_AUTH.into(),
                }),
            },
        };
        let (dir, socket, broker) =
            one_reply(&BrokerResponse::refused(RefusalCode::BrokerUnusable));
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            handle_status_answer(
                &cli(),
                status,
                &id,
                &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                &socket,
                TIMEOUT,
                "/usr/bin/sudo",
                &mut err,
                &mut out,
            ),
            Err(ExitCode::Unusable)
        );
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("broker refused the approval re-run")
        );
        broker.join().unwrap();
        drop(dir);
    }

    #[test]
    fn a_consumed_run_without_a_minted_entry_fails_closed() {
        let id = "a".repeat(64);
        let status = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: allow(),
                minted: Some(Minted {
                    nonce: id.clone(),
                    expires_in_ms: 1,
                    gate: GATE_AUTH.into(),
                }),
            },
        };
        let (dir, socket, broker) = one_reply(&BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: allow(),
                minted: None,
            },
        });
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            handle_status_answer(
                &cli(),
                status,
                &id,
                &BrokerRequest::new("/usr/bin/apt-get", Vec::new(), "unattested"),
                &socket,
                TIMEOUT,
                "/usr/bin/sudo",
                &mut err,
                &mut out,
            ),
            Err(ExitCode::Unusable)
        );
        broker.join().unwrap();
        drop(dir);
        assert!(String::from_utf8(err).unwrap().contains("minted no entry"));
    }

    #[test]
    fn a_broker_that_goes_silent_while_pending_is_exit_19() {
        let elapsed = std::cell::Cell::new(Duration::ZERO);
        let result = poll_status_with(
            &"a".repeat(64),
            Duration::from_secs(1),
            &mut |_| Err("silent".to_owned()),
            &mut || elapsed.get(),
            &mut |duration| elapsed.set(elapsed.get() + duration),
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        assert_eq!(elapsed.get(), Duration::from_secs(6));
    }

    #[test]
    fn an_approved_status_naming_another_gate_is_refused() {
        let response = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: allow(),
                minted: Some(Minted {
                    nonce: "c".repeat(64),
                    expires_in_ms: 1,
                    gate: "/usr/libexec/xudo/other-gate".into(),
                }),
            },
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            handle_status_answer(
                &cli(),
                response,
                &"c".repeat(64),
                &BrokerRequest::new("/usr/bin/apt-get", vec!["install".into()], "unattested"),
                Path::new("/nonexistent"),
                TIMEOUT,
                "/usr/bin/sudo",
                &mut err,
                &mut out
            ),
            Err(ExitCode::Unusable)
        );
    }

    #[test]
    fn the_front_end_reads_the_bounded_confirmation_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = cli();
        cli.config_file = dir.path().join("config.toml");
        let mut err = Vec::new();
        assert_eq!(configured_timeout(&cli, &mut err), Some(Duration::ZERO));
        std::fs::write(&cli.config_file, "confirmation_timeout_secs = 7\n").unwrap();
        assert_eq!(
            configured_timeout(&cli, &mut err),
            Some(Duration::from_secs(7))
        );
        std::fs::write(&cli.config_file, "confirmation_timeout_secs = 601\n").unwrap();
        assert_eq!(configured_timeout(&cli, &mut err), None);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("at most 600 seconds")
        );
        cli.config_file = dir.path().to_path_buf();
        let mut err = Vec::new();
        assert_eq!(configured_timeout(&cli, &mut err), None);
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("settings file could not be read")
        );
        assert_eq!(
            timeout_from_value(&ConfigValue::Integer(2), &mut Vec::new()),
            Some(Duration::from_secs(2))
        );
        for value in [ConfigValue::Bool(true), ConfigValue::Text("x".into())] {
            let mut err = Vec::new();
            assert_eq!(timeout_from_value(&value, &mut err), None);
            assert!(String::from_utf8(err).unwrap().contains("invalid value"));
        }
    }

    #[test]
    fn a_rerun_consumes_one_approval_for_the_same_user_and_argv() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let id = "d".repeat(64);
        let pending = json(&Answer::Pending {
            id: id.clone(),
            expires_in_ms: 30_000,
        });
        let matching_mint = Minted {
            nonce: id.clone(),
            expires_in_ms: 30_000,
            gate: GATE_AUTH.into(),
        };
        let approved_status = decided(allow(), Some(matching_mint.clone()));
        let consumed_run = decided(allow(), Some(matching_mint));
        let broker = thread::spawn(move || {
            let mut received = Vec::new();
            for (index, response) in [pending, approved_status, consumed_run]
                .into_iter()
                .enumerate()
            {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                received.push(BrokerRequest::parse(&request).unwrap());
                if index == 1 {
                    assert_eq!(
                        std::mem::discriminant(&received[index].question),
                        std::mem::discriminant(&Question::Status { id: String::new() })
                    );
                }
                stream.write_all(&response).unwrap();
            }
            received
        });
        let mut cli = cli();
        cli.output = crate::cli::Format::Json;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        // A virtual clock that the sleep advances: the wait cannot overrun its
        // window however loaded the machine is.
        let virtual_now = std::cell::Cell::new(Duration::ZERO);
        let mut elapsed = || virtual_now.get();
        let mut sleep = |slept: Duration| virtual_now.set(virtual_now.get() + slept);
        let result = plan_paced(
            &cli,
            &argv(),
            &SUDO,
            &socket,
            TIMEOUT,
            Duration::from_secs(1),
            Some(&mut Pace {
                elapsed: &mut elapsed,
                sleep: &mut sleep,
            }),
            None,
            &mut out,
            &mut err,
        );
        assert!(result.is_ok());
        let requests = broker.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0], requests[2]);
        assert_eq!(
            std::mem::discriminant(&requests[0].question),
            std::mem::discriminant(&Question::Run {
                program: String::new(),
                argv: Vec::new(),
                claimed_classification: String::new(),
            })
        );
    }

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
            }),
            "{err}"
        );
        assert!(err.is_empty());
    }

    #[test]
    fn a_non_run_answer_from_the_broker_fails_closed() {
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
            let is_pending = matches!(answer, Answer::Pending { .. });
            let response = BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer,
            };
            let (result, _, err) = against(response.to_json().into_bytes(), &SUDO, &argv());
            if is_pending {
                assert_eq!(result, Err(ExitCode::NotConfirmed));
                assert_eq!(err.lines().count(), 1);
            } else {
                assert_eq!(result, Err(ExitCode::Unusable));
            }
        }
    }

    #[test]
    fn a_host_with_only_sudo_rs_uses_it() {
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (result, _, err) = against(reply, &Has(&["/usr/bin/sudo-rs"]), &argv());
        assert_eq!(expect_plan(result, &err).backend, "/usr/bin/sudo-rs");
    }

    #[test]
    fn doas_is_used_when_sudo_is_absent() {
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (result, _, err) = against(reply, &Has(&["/usr/bin/doas"]), &argv());
        assert_eq!(expect_plan(result, &err).backend, "/usr/bin/doas");
    }

    #[test]
    fn doas_is_run_as_a_child_so_xudo_stays_an_ancestor() {
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (result, _, err) = against(reply, &Has(&["/usr/bin/doas"]), &argv());
        assert!(expect_plan(result, &err).spawn, "{err}");
    }

    #[test]
    fn a_reply_already_in_hand_is_used_when_the_broker_does_not_hang_up() {
        // The broker writes a full reply and keeps the socket open past the
        // client's timeout. `read_to_end` would block until `SO_RCVTIMEO` and
        // fail with `WouldBlock` — the macOS failure — even though the reply
        // is already received.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (release, hold) = std::sync::mpsc::channel();
        let broker = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut request = Vec::new();
            s.read_to_end(&mut request).unwrap();
            s.write_all(&reply).unwrap();
            let _ = hold.recv();
            request
        });
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let started = std::time::Instant::now();
        let result = plan(
            &cli(),
            &argv(),
            &SUDO,
            &socket,
            Duration::from_secs(5),
            &mut out,
            &mut err,
        );
        let elapsed = started.elapsed();
        let _ = release.send(());
        let err = String::from_utf8(err).unwrap();
        assert_eq!(expect_plan(result, &err).backend, "/usr/bin/sudo");
        assert!(
            elapsed < Duration::from_secs(2),
            "waited {elapsed:?} for the broker to hang up: {err}"
        );
        let sent = BrokerRequest::parse(&broker.join().unwrap()).unwrap();
        assert_eq!(
            sent.run_fields().map(|(program, _, _)| program),
            Some(argv()[0].as_str())
        );
    }

    #[test]
    fn a_trickling_broker_cannot_extend_the_exchange_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            for byte in reply {
                if stream.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });
        let started = std::time::Instant::now();
        let result = ask(
            &socket,
            Duration::from_millis(180),
            &BrokerRequest::new(argv()[0].clone(), argv()[1..].to_vec(), "unattested"),
        );
        let elapsed = started.elapsed();
        assert!(result.is_err(), "trickling reply was accepted: {result:?}");
        assert!(
            elapsed < Duration::from_millis(500),
            "deadline took {elapsed:?}"
        );
        broker.join().unwrap();
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

    /// A queue under a fresh temporary home, as `ido` would find it.
    fn queue_host(dir: &Path) -> ido::Host {
        use std::os::unix::fs::MetadataExt;
        ido::Host {
            home: Some(dir.join("home")),
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_cache_home: None,
            xdg_runtime_dir: Some(dir.join("run").to_str().unwrap().to_owned()),
            cwd: Some(dir.to_path_buf()),
            uid: std::fs::metadata(dir).unwrap().uid(),
            now_unix: 1_000_000,
            stdin_tty: false,
            stdout_tty: false,
            no_color: true,
            no_animation: true,
            queued_by: Some("xudo".to_owned()),
            lock_wait: Duration::from_secs(1),
            frame_delay: Duration::ZERO,
        }
    }

    /// What is in the queue, read back through `ido`'s own store.
    fn queued_entries(host: &ido::Host) -> Vec<ido::Entry> {
        let paths = xudo_config::XdgPaths::resolve(
            host.home.as_deref().unwrap(),
            None,
            None,
            None,
            host.xdg_runtime_dir.as_deref(),
        );
        ido::store::Store::open(&paths.state, &paths.runtime, host.uid)
            .unwrap()
            .load()
            .unwrap()
    }

    fn queueing_cli(output: &str) -> Cli {
        Cli::parse_from(["xudo", "--output", output, "exec", "--queue", "--", "x"])
    }

    fn denied(code: DenialCode) -> Vec<u8> {
        decided(
            Decision::deny(code, Vec::new(), Vec::new()),
            Some(minted(GATE_AUTH)),
        )
    }

    #[test]
    fn a_denial_with_queue_writes_one_entry_with_exact_argv() {
        for code in [DenialCode::HumanPathOnly, DenialCode::NoConfirmationChannel] {
            let dir = tempfile::tempdir().unwrap();
            let host = queue_host(dir.path());
            let mut args = argv();
            args.extend(["it's here".into(), String::new(), "a b\n$(c)".into()]);
            let (plain, _, _) = against(denied(code), &SUDO, &args);
            let (result, out, err) = against_queueing(
                denied(code),
                &SUDO,
                &args,
                &queueing_cli("human"),
                Some(&host),
            );
            // The denial's own exit status; the action did not run.
            assert_eq!(result, plain);
            assert!(result.is_err());
            assert!(!out.is_empty());
            assert!(err.contains("queued as #1, run `ido` to execute"), "{err}");
            assert!(!err.contains("ido queue --"), "{err}");
            let entries = queued_entries(&host);
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].argv, args);
            assert_eq!(entries[0].queued_by.as_deref(), Some("xudo"));
            let reason = entries[0].reason.as_deref().unwrap();
            assert!(reason.contains(&format!("{code:?}")), "{reason}");
            // The same command again is the same entry, not a second.
            let (_, _, err) = against_queueing(
                denied(code),
                &SUDO,
                &args,
                &queueing_cli("human"),
                Some(&host),
            );
            assert!(err.contains("already queued as #1"), "{err}");
            assert_eq!(queued_entries(&host).len(), 1);
        }
    }

    #[test]
    fn a_json_denial_with_queue_carries_the_entry_id() {
        let dir = tempfile::tempdir().unwrap();
        let host = queue_host(dir.path());
        let (result, out, _) = against_queueing(
            denied(DenialCode::HumanPathOnly),
            &SUDO,
            &argv(),
            &queueing_cli("json"),
            Some(&host),
        );
        assert_eq!(result, Err(ExitCode::Denied));
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["queued"]["id"], 1);
        assert_eq!(parsed["verdict"], "deny");
    }

    #[test]
    fn queue_never_runs_anything() {
        // A minted entry rides beside the denial; nothing may be planned from it.
        for code in [DenialCode::HumanPathOnly, DenialCode::NoConfirmationChannel] {
            let dir = tempfile::tempdir().unwrap();
            let host = queue_host(dir.path());
            let (result, _, _) = against_queueing(
                denied(code),
                &SUDO,
                &argv(),
                &queueing_cli("human"),
                Some(&host),
            );
            assert!(result.is_err(), "{result:?}");
        }
        // An allowed command is planned as without the flag, and queues nothing.
        let dir = tempfile::tempdir().unwrap();
        let host = queue_host(dir.path());
        let reply = decided(allow(), Some(minted(GATE_AUTH)));
        let (result, out, err) = against_queueing(
            reply.clone(),
            &SUDO,
            &argv(),
            &queueing_cli("human"),
            Some(&host),
        );
        let (plain, plain_out, plain_err) = against(reply, &SUDO, &argv());
        assert_eq!((&result, &out, &err), (&plain, &plain_out, &plain_err));
        assert!(result.is_ok());
        assert!(!dir.path().join("home").exists());
    }

    #[test]
    fn queue_ignores_denials_that_are_not_human_path() {
        for code in [
            DenialCode::UnknownAction,
            DenialCode::ArgvRejected,
            DenialCode::DenyListed,
            DenialCode::PolicyUnloadable,
            DenialCode::Frozen,
            DenialCode::ExeMismatch,
            DenialCode::ConfirmationRefused,
            DenialCode::ConfirmationExpired,
            DenialCode::ConfirmationThrottled,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let host = queue_host(dir.path());
            let (plain, plain_out, plain_err) = against(denied(code), &SUDO, &argv());
            let (result, out, err) = against_queueing(
                denied(code),
                &SUDO,
                &argv(),
                &queueing_cli("human"),
                Some(&host),
            );
            assert_eq!((&result, &out, &err), (&plain, &plain_out, &plain_err));
            assert!(!err.contains("queued"), "{err}");
            assert!(
                !dir.path().join("home").exists(),
                "{code:?} touched the queue"
            );
        }
    }

    #[test]
    fn a_non_utf8_argv_is_queued_byte_for_byte() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        // Bytes that are not UTF-8 never reach the queue altered: the command
        // line parser refuses them, so nothing lossy can be written.
        let bad = OsString::from_vec(b"/usr/bin/tool\xff\xfe".to_vec());
        let parsed = Cli::try_parse_from([
            OsString::from("xudo"),
            "exec".into(),
            "--queue".into(),
            "--".into(),
            bad,
        ]);
        assert!(parsed.is_err());
        // And text with every byte `ido` must not reinterpret is stored exactly.
        let dir = tempfile::tempdir().unwrap();
        let host = queue_host(dir.path());
        let args: Vec<String> = [
            "/bin/x",
            "\u{1b}[31m",
            "a\nb",
            "\u{202e}",
            "\\x00",
            "$(id)",
            "--",
        ]
        .map(String::from)
        .to_vec();
        let (result, _, _) = against_queueing(
            denied(DenialCode::HumanPathOnly),
            &SUDO,
            &args,
            &queueing_cli("human"),
            Some(&host),
        );
        assert_eq!(result, Err(ExitCode::Denied));
        let entries = queued_entries(&host);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].argv, args);
    }

    #[test]
    fn a_failed_queue_write_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let mut host = queue_host(dir.path());
        host.home = None;
        for format in ["human", "json"] {
            let (result, out, err) = against_queueing(
                denied(DenialCode::HumanPathOnly),
                &SUDO,
                &argv(),
                &queueing_cli(format),
                Some(&host),
            );
            assert_eq!(result, Err(ExitCode::Denied));
            assert!(err.contains("could not queue the command"), "{err}");
            assert!(err.contains("nothing was queued"), "{err}");
            assert!(!err.contains("queued as"), "{err}");
            // The denial still tells the agent how to hand it over by hand.
            assert!(err.contains("ido queue --"), "{err}");
            assert!(!out.contains("\"queued\""), "{out}");
        }
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
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("no sudo, sudo-rs, or doas")
        );
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
            plan_live(&cli(), &[], None, &mut out, &mut err),
            Err(ExitCode::Unusable)
        );
    }

    #[test]
    fn plan_live_refuses_a_settings_path_it_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = cli();
        cli.config_file = dir.path().to_path_buf();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            plan_live(&cli, &argv(), None, &mut out, &mut err),
            Err(ExitCode::Unusable)
        );
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("settings file could not be read")
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
        assert_eq!(display_quoted(&["a".into(), "b".into()]), "a b");
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
