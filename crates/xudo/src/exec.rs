//! `xudo exec`: ask the broker, then let `main` swap this process for the backend.

use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::time::{Duration, Instant};

use xudo_backend::Probe;
use xudo_backend::snippet::GATE_AUTH;
use xudo_config::{Layer, Setting, Settings as ConfigSettings, Value as ConfigValue, apply_file};
use xudo_policy::{DenialCode, ExitCode};
use xudo_wire::{Answer, BrokerRequest, BrokerResponse, Question};

use crate::cli::{Cli, emit};

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

/// A claimed queue entry, ready for the password gate.
///
/// The working directory is always [`QUEUED_CWD`]. The queue file still holds
/// the directory the agent named; this run does not use it.
#[derive(Debug, PartialEq, Eq)]
pub struct QueuedRun {
    /// `sudo` or `doas`, always spawned so this process can finish the claim.
    pub plan: ExecPlan,
    /// The queue id that was claimed.
    pub id: String,
    /// Where the child runs. Fixed, never the entry's stored directory.
    pub cwd: &'static str,
    /// The token the claimant must present to complete or release.
    pub claim_token: String,
}

/// Fixed working directory of a queued run.
pub const QUEUED_CWD: &str = "/";

/// What happened to the claim after the child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuedFinish {
    /// The gate's audit record completed the entry.
    Completed,
    /// The claim went back to pending. A password refusal does this.
    Released,
    /// Complete and release both failed. The claim stays until it expires.
    Stuck,
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
    let cwd = std::env::current_dir()
        .map(|path| path.into_os_string().into_vec())
        .unwrap_or_default();
    let request =
        BrokerRequest::new(program.clone(), operands.to_vec(), "unattested").with_cwd_bytes(cwd);
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
        Answer::Watching { .. } | Answer::QueueListed { .. } | Answer::Done => {
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
                Answer::Refused { .. }
                | Answer::Watching { .. }
                | Answer::QueueListed { .. }
                | Answer::Done => {
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

/// Claims `id` and returns the password-gate plan.
///
/// The broker re-decides the stored argv against the current rules. A denial
/// is printed here and the claim is failed by the broker; this function does
/// not exec. A permitted claim always uses [`GATE_AUTH`] and [`QUEUED_CWD`],
/// and always spawns, including under sudo, so the caller can complete or
/// release the claim after the child.
///
/// # Errors
///
/// The exit status to return when there is nothing to exec.
///
/// `tty` is true only when both stdin and stderr are terminals. The confirm
/// word is read from stdin and the prompt is written to stderr.
#[allow(clippy::too_many_arguments)]
pub fn plan_queued(
    cli: &Cli,
    id: &str,
    probe: &dyn Probe,
    socket: &Path,
    timeout: Duration,
    tty: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<QueuedRun, ExitCode> {
    if !valid_request_id(id) {
        let _ = writeln!(err, "xudo: a queued id is 64 lowercase hex characters");
        return Err(ExitCode::Unusable);
    }
    // A non-terminal cannot show the command or take the confirmation word.
    // Refuse before the claim so no spool entry is minted.
    if !tty {
        let _ = writeln!(
            err,
            "xudo: a queued run needs a terminal to show the command and confirm it"
        );
        return Err(ExitCode::Unusable);
    }
    let Some(backend) = selected_backend(probe, err) else {
        return Err(ExitCode::Unusable);
    };
    let request = queue_question(Question::QueueClaim { id: id.to_owned() });
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
    queued_plan(cli, id, backend, response, socket, timeout, input, out, err)
}

/// [`plan_queued`] against this machine and the real broker socket.
///
/// # Errors
///
/// As [`plan_queued`]. A settings file that cannot be read fails closed first.
pub fn plan_queued_live(
    cli: &Cli,
    id: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<QueuedRun, ExitCode> {
    // The duration is the watch wait, which a queued run does not use. The
    // read itself is the point: an unreadable settings file fails closed.
    if configured_timeout(cli, err).is_none() {
        return Err(ExitCode::Unusable);
    }
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    let tty = queued_terminal(stdin.is_terminal(), stderr.is_terminal());
    let mut input = stdin.lock();
    plan_queued(
        cli,
        id,
        &xudo_sys::HostProbe,
        Path::new(xudo_wire::BROKER_SOCKET),
        TIMEOUT,
        tty,
        &mut input,
        out,
        err,
    )
}

/// Completes the claim from the gate's audit record, or asks the broker to
/// release it.
///
/// A child that started may have been allowed by the gate before it exec'd,
/// even when the command's own status is non-zero, so completion is tried
/// first. Anything except [`Answer::Done`] from that completion sends a
/// release. The broker keeps the entry terminal when a gate record binds, or
/// when the spool file was already consumed, instead of returning it to
/// pending. A child that never started is only released. A storage failure on
/// the broker leaves the claim until the queue TTL; this returns
/// [`QueuedFinish::Stuck`].
pub fn finish_queued(
    id: &str,
    child_started: bool,
    claim_token: &str,
    socket: &Path,
    timeout: Duration,
    err: &mut dyn Write,
) -> QueuedFinish {
    if !valid_request_id(id) {
        let _ = writeln!(err, "xudo: a queued id is 64 lowercase hex characters");
        return QueuedFinish::Stuck;
    }
    if child_started && queue_done(id, true, claim_token, socket, timeout, err) {
        return QueuedFinish::Completed;
    }
    if queue_done(id, false, claim_token, socket, timeout, err) {
        QueuedFinish::Released
    } else {
        let _ = writeln!(
            err,
            "xudo: the queued claim was not released; it stays until it expires"
        );
        QueuedFinish::Stuck
    }
}

/// [`finish_queued`] against the real broker socket.
///
/// The library binary uses this so it does not name the wire crate. An id
/// that is not 64 lowercase hex characters is refused before any connection.
pub fn finish_queued_live(
    id: &str,
    child_started: bool,
    claim_token: &str,
    err: &mut dyn Write,
) -> QueuedFinish {
    finish_queued(
        id,
        child_started,
        claim_token,
        Path::new(xudo_wire::BROKER_SOCKET),
        TIMEOUT,
        err,
    )
}

/// Both streams must be terminals.
///
/// The flags are arguments so each one is evaluated. A short-circuit `&&`
/// would skip the stderr check wherever stdin is not a terminal, and that
/// line would be uncovered on CI.
#[must_use]
pub(crate) fn queued_terminal(stdin_tty: bool, stderr_tty: bool) -> bool {
    stdin_tty && stderr_tty
}

fn queue_question(question: Question) -> BrokerRequest {
    BrokerRequest {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        question,
    }
}

#[allow(clippy::too_many_arguments)]
fn queued_plan(
    cli: &Cli,
    id: &str,
    backend: &'static str,
    response: BrokerResponse,
    socket: &Path,
    timeout: Duration,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<QueuedRun, ExitCode> {
    match response.answer {
        Answer::Refused {
            code, remediation, ..
        } => {
            let _ = writeln!(err, "xudo: the broker refused ({code:?}): {remediation}");
            Err(ExitCode::Unusable)
        }
        Answer::Pending { .. }
        | Answer::Watching { .. }
        | Answer::QueueListed { .. }
        | Answer::Done => {
            let _ = writeln!(
                err,
                "xudo: broker returned an answer for an unsupported question"
            );
            Err(ExitCode::Unusable)
        }
        Answer::Decided { decision, minted } => {
            if !decision.verdict.is_permitted() {
                // Not `report_denial`: an ask-human verdict here is a fresh
                // refusal of this run, not a new submission to the queue.
                let status = emit(cli, &decision, out);
                let _ = writeln!(
                    err,
                    "xudo: the queued command was refused when it was re-decided"
                );
                return Err(status);
            }
            let Some(minted) = minted else {
                let _ = writeln!(err, "xudo: permitted, but the broker minted no entry");
                return Err(ExitCode::Unusable);
            };
            if minted.gate != GATE_AUTH {
                let _ = writeln!(err, "xudo: the broker named an unexpected gate; refusing");
                return Err(ExitCode::Unusable);
            }
            let claim_token = claim_secret(&minted);
            if !confirm_queued(id, &decision, minted.harness.as_deref(), input, err) {
                let _ = writeln!(err, "xudo: confirmation was not run; releasing the claim");
                let _ = queue_done(id, false, &claim_token, socket, timeout, err);
                return Err(ExitCode::Unusable);
            }
            Ok(QueuedRun {
                plan: ExecPlan {
                    backend,
                    gate: GATE_AUTH,
                    spawn: true,
                },
                id: id.to_owned(),
                cwd: QUEUED_CWD,
                claim_token,
            })
        }
    }
}

/// The secret recorded on the claim. The mint returns it beside the nonce.
fn claim_secret(minted: &xudo_wire::Minted) -> String {
    match minted.claim_token.as_deref() {
        Some(token) if !token.is_empty() => token.to_owned(),
        Some(_) | None => minted.nonce.clone(),
    }
}

/// Prints the sanitized command and requires the confirm word on `input`.
fn confirm_queued(
    id: &str,
    decision: &xudo_policy::Decision,
    harness: Option<&str>,
    input: &mut dyn BufRead,
    err: &mut dyn Write,
) -> bool {
    let limits = term_sanitize::Limits {
        max_cols: 4096,
        max_lines: 1,
    };
    let shown: Vec<String> = decision
        .resolved_command()
        .iter()
        .map(|arg| term_sanitize::display_str(arg, limits).text)
        .collect();
    let command = shown.join(" ");
    let label = term_sanitize::display_str(harness.unwrap_or(""), limits).text;
    let _ = writeln!(err, "xudo: queued {id} harness {label}");
    let _ = writeln!(err, "xudo: command: {command}");
    let _ = write!(err, "type {} and press enter: ", ido::picker::CONFIRM_WORD);
    let _ = err.flush();
    let mut line = String::new();
    if input.read_line(&mut line).is_err() {
        return false;
    }
    line.trim_end_matches(['\r', '\n']) == ido::picker::CONFIRM_WORD
}

/// `complete` asks [`Question::QueueComplete`]; otherwise [`Question::QueueRelease`].
fn queue_done(
    id: &str,
    complete: bool,
    claim_token: &str,
    socket: &Path,
    timeout: Duration,
    err: &mut dyn Write,
) -> bool {
    let question = if complete {
        Question::QueueComplete {
            id: id.to_owned(),
            audit_seq: 0,
            claim_token: claim_token.to_owned(),
        }
    } else {
        Question::QueueRelease {
            id: id.to_owned(),
            claim_token: claim_token.to_owned(),
        }
    };
    match ask(socket, timeout, &queue_question(question)) {
        Ok(response) if matches!(response.answer, Answer::Done) => true,
        Ok(_) => {
            let _ = writeln!(err, "xudo: the queued run was not completed");
            false
        }
        Err(why) => {
            let _ = writeln!(
                err,
                "xudo: the broker is unreachable ({why}); run `xudo doctor`"
            );
            false
        }
    }
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

/// Shows a denial. Privileged denials are never written into the caller-owned ido queue.
fn report_denial(
    cli: &Cli,
    decision: &xudo_policy::Decision,
    argv: &[String],
    _queue: Option<&ido::Host>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let human_only = matches!(
        decision.denial,
        Some(DenialCode::HumanPathOnly | DenialCode::NoConfirmationChannel)
    );
    let status = emit(cli, decision, out);
    if human_only {
        let _ = writeln!(
            err,
            "xudo: a human must run this; review it and run it with:\n  ido queue -- {}",
            display_quoted(argv)
        );
    } else if decision.denial == Some(DenialCode::AskHuman) {
        let _ = writeln!(
            err,
            "xudo: request submitted to the root-held human review queue"
        );
    }
    status
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

    /// A deadline a passing test over a real socket never waits for, so a
    /// loaded runner cannot expire it.
    const PATIENT: Duration = Duration::from_secs(60);

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
            claim_token: None,
            harness: None,
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
        let broker = crate::test_broker::serve_once(listener, reply);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan_with_confirmation_timeout(
            cli,
            argv,
            probe,
            &socket,
            PATIENT,
            Duration::ZERO,
            queue,
            &mut out,
            &mut err,
        );
        let request = broker.finish();
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
        crate::test_broker::Served,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let reply = reply.to_json().into_bytes();
        let broker = crate::test_broker::serve_once(listener, reply);
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
        let broker = crate::test_broker::serve_many_with(
            server_listener,
            vec![response],
            move |_, request| {
                assert!(
                    BrokerRequest::parse(request)
                        .unwrap()
                        .run_fields()
                        .is_some()
                );
                *server_spool.lock().unwrap() = Some(entry_id.clone());
            },
        );
        let cli = cli();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan_with_confirmation_timeout(
            &cli,
            &["/usr/bin/apt-get".to_owned(), "remove".to_owned()],
            &SUDO,
            &socket,
            PATIENT,
            Duration::ZERO,
            None,
            &mut out,
            &mut err,
        );
        broker.finish();
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
        let broker = crate::test_broker::serve_once(listener, response);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        // The first sleep lasts the whole window, so no status is asked: the
        // outcome does not depend on how fast the machine is.
        let result = plan_with_confirmation_timeout(
            &cli(),
            &["/usr/bin/apt-get".to_owned(), "remove".to_owned()],
            &SUDO,
            &socket,
            PATIENT,
            Duration::from_millis(1),
            None,
            &mut out,
            &mut err,
        );
        broker.finish();
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
                    claim_token: None,
                    harness: None,
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
                    claim_token: None,
                    harness: None,
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
        broker.finish();
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
                claim_token: None,
                harness: None,
            },
            Minted {
                nonce: "b".repeat(64),
                expires_in_ms: 1,
                gate: GATE_AUTH.into(),
                claim_token: None,
                harness: None,
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
                        claim_token: None,
                        harness: None,
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
            broker.finish();
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
                    claim_token: None,
                    harness: None,
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
        broker.finish();
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
                    claim_token: None,
                    harness: None,
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
        broker.finish();
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
                    claim_token: None,
                    harness: None,
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
        broker.finish();
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
                    claim_token: None,
                    harness: None,
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
            claim_token: None,
            harness: None,
        };
        let approved_status = decided(allow(), Some(matching_mint.clone()));
        let consumed_run = decided(allow(), Some(matching_mint));
        let broker =
            crate::test_broker::serve_many(listener, vec![pending, approved_status, consumed_run]);
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
            PATIENT,
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
        let report = broker.finish_report();
        let requests = report
            .requests
            .iter()
            .map(|request| BrokerRequest::parse(request).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(report.accept_error, None);
        assert_eq!(
            report.writes,
            vec![crate::test_broker::ReplyWrite::Written; 3]
        );
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0], requests[2]);
        assert_eq!(
            std::mem::discriminant(&requests[1].question),
            std::mem::discriminant(&Question::Status { id: String::new() })
        );
        assert_eq!(
            std::mem::discriminant(&requests[0].question),
            std::mem::discriminant(&Question::Run {
                program: String::new(),
                argv: Vec::new(),
                cwd: Vec::new(),
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
        let result = plan(&cli(), &argv(), &SUDO, &socket, PATIENT, &mut out, &mut err);
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
            xudo_front_end: std::path::PathBuf::from(ido::XUDO_FRONT_END),
            root_entries: Vec::new(),
            root_queue_unavailable: false,
            root_release: None,
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
        Cli::parse_from(["xudo", "--output", output, "exec", "--", "x"])
    }

    fn denied(code: DenialCode) -> Vec<u8> {
        decided(
            Decision::deny(code, Vec::new(), Vec::new()),
            Some(minted(GATE_AUTH)),
        )
    }

    #[test]
    fn a_privileged_denial_is_never_written_to_the_callers_ido_queue() {
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
            assert!(!err.contains("queued as"), "{err}");
            assert!(err.contains("ido queue --"), "{err}");
            assert!(queued_entries(&host).is_empty());
            let (_, _, err) = against_queueing(
                denied(code),
                &SUDO,
                &args,
                &queueing_cli("human"),
                Some(&host),
            );
            assert!(!err.contains("queued as"), "{err}");
            assert!(queued_entries(&host).is_empty());
        }
    }

    #[test]
    fn a_json_human_path_denial_has_no_user_queue_id() {
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
        assert!(parsed.get("queued").is_none());
        assert_eq!(parsed["verdict"], "deny");
    }

    #[test]
    fn ask_human_reports_submission_to_the_root_held_queue() {
        let (result, _, err) = against_queueing(
            denied(DenialCode::AskHuman),
            &SUDO,
            &argv(),
            &queueing_cli("human"),
            None,
        );
        assert_eq!(result, Err(ExitCode::Denied));
        assert!(err.contains("request submitted to the root-held human review queue"));
        assert!(!err.contains("ido queue --"));
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
            // No plan was produced: the denial's own status, and one entry.
            let (plain, _, _) = against(denied(code), &SUDO, &argv());
            assert!(plain.is_err(), "{plain:?}");
            assert_eq!(result, plain);
            assert!(queued_entries(&host).is_empty());
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
    fn a_non_utf8_argument_is_refused_by_the_parser_without_queue_flags() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        // `ido`'s `Entry.argv` is `Vec<String>`, so non-UTF-8 bytes cannot be
        // queued byte for byte: the command line parser refuses them first,
        // and nothing lossy ever reaches the queue.
        let bad = OsString::from_vec(b"/usr/bin/tool\xff\xfe".to_vec());
        let parsed = Cli::try_parse_from([OsString::from("xudo"), "exec".into(), "--".into(), bad]);
        assert!(parsed.is_err());
        // The refusal happens before any queue is opened.
        let dir = tempfile::tempdir().unwrap();
        assert!(!dir.path().join("home").exists());
    }

    #[test]
    fn control_characters_in_a_denial_are_not_written_to_a_user_queue() {
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
        assert!(queued_entries(&host).is_empty());
    }

    #[test]
    fn a_denial_does_not_try_to_write_a_user_queue() {
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
            assert!(!err.contains("could not queue the command"), "{err}");
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
        let (accepted_tx, accepted_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let held = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            // The clock starts once the broker is holding a silent socket, so
            // probing sudo and opening the connection are not part of the
            // deadline. The peer stays up until the client returns, or for two
            // seconds if the client waits for the hang-up.
            let _ = accepted_tx.send(std::time::Instant::now());
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
            drop(stream);
        });
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan(
            &cli(),
            &argv(),
            &SUDO,
            &socket,
            Duration::from_millis(100),
            &mut out,
            &mut err,
        );
        let accepted = accepted_rx.recv_timeout(Duration::from_millis(50)).unwrap();
        let elapsed = accepted.elapsed();
        let _ = release_tx.send(());
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(
            elapsed < Duration::from_millis(450),
            "silent broker held the client for {elapsed:?}"
        );
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

    fn queued_id() -> String {
        "ab".repeat(32)
    }

    // `serve_many` maps this over owned answers, so the argument is by value.
    #[allow(clippy::needless_pass_by_value)]
    fn response(answer: Answer) -> Vec<u8> {
        json(&answer)
    }

    fn claim_once(
        reply: Vec<u8>,
        probe: &dyn Probe,
    ) -> (Result<QueuedRun, ExitCode>, String, String, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = crate::test_broker::serve_once(listener, reply);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut input = std::io::Cursor::new(b"run\n");
        let result = plan_queued(
            &cli(),
            &queued_id(),
            probe,
            &socket,
            PATIENT,
            true,
            &mut input,
            &mut out,
            &mut err,
        );
        let request = broker.finish();
        (
            result,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
            request,
        )
    }

    #[test]
    fn a_queued_entry_runs_only_through_the_password_path() {
        // The shipped sudoers rule disables the credential cache. A queued run
        // uses that same rule: the gate is the password helper, never the
        // passwordless one, and sudo must ask even after an earlier login.
        let backend = xudo_backend::Backend {
            exe: "/usr/bin/sudo".to_owned(),
            kind: xudo_backend::BackendKind::Sudo,
            version: "Sudo version 1.9.17p2".to_owned(),
            capabilities: xudo_backend::CapabilityMatrix::from_supported([
                xudo_backend::Capability::DisableCredentialCache,
                xudo_backend::Capability::AllocatePty,
                xudo_backend::Capability::PerCommandDefaults,
                xudo_backend::Capability::DropInDirectory,
                xudo_backend::Capability::ValidateNamedFile,
            ]),
        };
        let snippet = xudo_backend::SudoersSnippet::human_only(&backend).unwrap();
        assert!(!snippet.includes_nopass);
        assert!(snippet.contents.contains("timestamp_timeout=0"));
        assert!(!snippet.contents.contains("NOPASSWD"));
        assert!(
            !snippet
                .contents
                .contains(xudo_backend::snippet::GATE_NOPASS)
        );

        let (result, _, _err, request) =
            claim_once(decided(allow(), Some(minted(GATE_AUTH))), &SUDO);
        let run = result.unwrap();
        assert_eq!(run.cwd, "/");
        assert_eq!(run.id, queued_id());
        assert_eq!(
            run.plan,
            ExecPlan {
                backend: "/usr/bin/sudo",
                gate: GATE_AUTH,
                spawn: true,
            }
        );
        let sent = BrokerRequest::parse(&request).unwrap();
        assert_eq!(sent.question, Question::QueueClaim { id: queued_id() });
    }

    #[test]
    fn a_queued_run_spawns_whichever_backend_is_installed() {
        for (paths, backend) in [
            (&["/usr/bin/sudo-rs"][..], "/usr/bin/sudo-rs"),
            (&["/usr/bin/doas"][..], "/usr/bin/doas"),
        ] {
            let (result, _, _err, _) =
                claim_once(decided(allow(), Some(minted(GATE_AUTH))), &Has(paths));
            let run = result.unwrap();
            assert_eq!(run.plan.backend, backend);
            assert!(run.plan.spawn);
            assert_eq!(run.cwd, "/");
        }
    }

    #[test]
    fn a_queued_claim_refuses_a_bad_id_a_missing_backend_and_a_dead_broker() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        for id in ["", "ab", &"g".repeat(64), &"A".repeat(64)] {
            assert_eq!(
                plan_queued(
                    &cli(),
                    id,
                    &SUDO,
                    Path::new("/no/such/sock"),
                    PATIENT,
                    true,
                    &mut std::io::Cursor::new(b"run\n"),
                    &mut out,
                    &mut err
                ),
                Err(ExitCode::Unusable)
            );
        }
        assert!(
            String::from_utf8(err.clone())
                .unwrap()
                .contains("64 lowercase hex")
        );

        err.clear();
        assert_eq!(
            plan_queued(
                &cli(),
                &queued_id(),
                &Has(&[]),
                Path::new("/no/such/sock"),
                PATIENT,
                true,
                &mut std::io::Cursor::new(b"run\n"),
                &mut out,
                &mut err,
            ),
            Err(ExitCode::Unusable)
        );
        assert!(String::from_utf8(err.clone()).unwrap().contains("no sudo"));

        err.clear();
        assert_eq!(
            plan_queued(
                &cli(),
                &queued_id(),
                &SUDO,
                Path::new("/no/such/sock"),
                PATIENT,
                true,
                &mut std::io::Cursor::new(b"run\n"),
                &mut out,
                &mut err,
            ),
            Err(ExitCode::Unusable)
        );
        assert!(String::from_utf8(err).unwrap().contains("unreachable"));
    }

    #[test]
    fn a_queued_claim_fails_closed_on_the_wrong_answer() {
        let refused = BrokerResponse::refused(RefusalCode::RequestUnknown)
            .to_json()
            .into_bytes();
        let (result, _, err, _) = claim_once(refused, &SUDO);
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(err.contains("refused"), "{err}");

        let decision = Decision::deny(DenialCode::AskHuman, Vec::new(), Vec::new());
        let (result, out, err, _) = claim_once(decided(decision.clone(), None), &SUDO);
        assert_eq!(result, Err(decision.exit_code()));
        assert!(!out.is_empty());
        assert!(err.contains("re-decided"), "{err}");
        assert!(!err.contains("request submitted"), "{err}");
        assert!(!err.contains("ido queue"), "{err}");

        let (result, _, err, _) = claim_once(decided(allow(), None), &SUDO);
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(err.contains("minted no entry"), "{err}");

        let (result, _, err, _) = claim_once(decided(allow(), Some(minted("/tmp/evil"))), &SUDO);
        assert_eq!(result, Err(ExitCode::Unusable));
        assert!(err.contains("unexpected gate"), "{err}");

        for answer in [
            Answer::Pending {
                id: queued_id(),
                expires_in_ms: 1,
            },
            Answer::Watching {
                prompts: Vec::new(),
                omitted: 0,
            },
            Answer::QueueListed {
                entries: Vec::new(),
                next: None,
            },
            Answer::Done,
        ] {
            let (result, _, err, _) = claim_once(response(answer), &SUDO);
            assert_eq!(result, Err(ExitCode::Unusable));
            assert!(err.contains("unsupported question"), "{err}");
        }
    }

    #[test]
    fn plan_queued_live_fails_closed_before_and_after_the_settings_read() {
        let id = queued_id();
        let dir = tempfile::tempdir().unwrap();
        let mut unreadable = cli();
        unreadable.config_file = dir.path().to_path_buf();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            plan_queued_live(&unreadable, &id, &mut out, &mut err),
            Err(ExitCode::Unusable)
        );
        assert!(
            String::from_utf8(err.clone())
                .unwrap()
                .contains("could not be read")
        );

        let mut missing = cli();
        missing.config_file = dir.path().join("missing.toml");
        err.clear();
        // A missing settings file is the default timeout, so the call continues
        // into `plan_queued`. A bad id stops there, on every host, before a
        // backend probe or the broker socket.
        assert_eq!(
            plan_queued_live(&missing, "not-an-id", &mut out, &mut err),
            Err(ExitCode::Unusable)
        );
        let text = String::from_utf8(err).unwrap();
        assert!(
            text.contains("a queued id is 64 lowercase hex characters"),
            "{text}"
        );
    }

    fn finish_with(
        replies: Vec<Answer>,
        child_started: bool,
    ) -> (QueuedFinish, String, Vec<Vec<u8>>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker =
            crate::test_broker::serve_many(listener, replies.into_iter().map(response).collect());
        let mut err = Vec::new();
        let finish = finish_queued(&queued_id(), child_started, "", &socket, PATIENT, &mut err);
        let report = broker.finish_report();
        (finish, String::from_utf8(err).unwrap(), report.requests)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn finish_queued_completes_from_the_gate_or_releases_the_claim() {
        let (finish, err, requests) = finish_with(vec![Answer::Done], true);
        assert_eq!(finish, QueuedFinish::Completed, "{err}");
        assert!(err.is_empty(), "{err}");
        let sent = BrokerRequest::parse(&requests[0]).unwrap();
        assert_eq!(
            sent.question,
            Question::QueueComplete {
                id: queued_id(),
                audit_seq: 0,
                claim_token: String::new(),
            }
        );

        let (finish, _, requests) = finish_with(vec![Answer::Done], false);
        assert_eq!(finish, QueuedFinish::Released);
        let sent = BrokerRequest::parse(&requests[0]).unwrap();
        assert_eq!(
            sent.question,
            Question::QueueRelease {
                id: queued_id(),
                claim_token: String::new(),
            }
        );

        let (finish, err, requests) = finish_with(
            vec![
                Answer::Refused {
                    code: RefusalCode::AnswerRejected,
                    remediation: "no".into(),
                    detail: None,
                },
                Answer::Done,
            ],
            true,
        );
        assert_eq!(finish, QueuedFinish::Released, "{err}");
        assert!(err.contains("not completed"), "{err}");
        assert!(!err.contains("not released"), "{err}");
        assert_eq!(requests.len(), 2);

        let (finish, err, _) = finish_with(
            vec![
                Answer::Decided {
                    decision: Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new()),
                    minted: None,
                },
                Answer::Refused {
                    code: RefusalCode::RequestUnknown,
                    remediation: "gone".into(),
                    detail: None,
                },
            ],
            true,
        );
        assert_eq!(finish, QueuedFinish::Stuck, "{err}");
        assert!(err.contains("not released"), "{err}");

        let mut err = Vec::new();
        assert_eq!(
            finish_queued(
                "nope",
                true,
                "",
                Path::new("/no/such/sock"),
                PATIENT,
                &mut err,
            ),
            QueuedFinish::Stuck
        );
        assert!(
            String::from_utf8(err.clone())
                .unwrap()
                .contains("64 lowercase hex")
        );

        err.clear();
        assert_eq!(
            finish_queued(
                &queued_id(),
                true,
                "cd".repeat(32).as_str(),
                Path::new("/no/such/sock"),
                PATIENT,
                &mut err
            ),
            QueuedFinish::Stuck
        );
        let text = String::from_utf8(err).unwrap();
        assert!(text.contains("unreachable"), "{text}");
        assert!(text.contains("not released"), "{text}");

        // The live wrapper refuses a bad id before it opens the broker socket.
        let mut live = Vec::new();
        assert_eq!(
            finish_queued_live("nope", false, "", &mut live),
            QueuedFinish::Stuck
        );
        assert!(
            String::from_utf8(live)
                .unwrap()
                .contains("64 lowercase hex")
        );
    }

    #[test]
    fn the_library_reports_a_queued_plan_without_executing_it() {
        // The library path reads the process terminal. A test has none, so the
        // claim is refused before any broker connection.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let mut cli = Cli::parse_from(["xudo", "exec", "--queued", &queued_id()]);
        cli.config_file = dir.path().join("missing.toml");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let ops = xudo_sys::host_ops();
        let platform = crate::Platform {
            ops: ops.as_ref(),
            probe: &SUDO,
            host: &xudo_sys::LiveHost,
            path: None,
        };
        let status = crate::cli::run_with_installer_at_socket(
            &cli,
            &platform,
            &xudo_sys::RefusingInstaller,
            &socket,
            &mut out,
            &mut err,
        );
        assert_eq!(status, ExitCode::Unusable);
        let text = String::from_utf8(err.clone()).unwrap();
        assert!(text.contains("needs a terminal"), "{text}");

        let mut bad = Cli::parse_from(["xudo", "exec", "--queued", "nope"]);
        bad.config_file = dir.path().join("missing.toml");
        let status = crate::cli::run_with_installer_at_socket(
            &bad,
            &platform,
            &xudo_sys::RefusingInstaller,
            &socket,
            &mut out,
            &mut err,
        );
        assert_eq!(status, ExitCode::Unusable);
        assert!(String::from_utf8(err).unwrap().contains("64 lowercase hex"));
    }

    #[test]
    fn xudo_exec_queued_shows_the_argv_and_asks_before_running() {
        let mut decision = allow();
        decision.resolved_exe = Some("/usr/bin/apt-get".to_owned());
        decision.resolved_argv = vec!["\u{1b}[31mupgrade".to_owned()];
        let token = "cd".repeat(32);
        let mut issued = minted(GATE_AUTH);
        issued.claim_token = Some(token.clone());
        issued.harness = Some("codex".to_owned());
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = crate::test_broker::serve_once(listener, decided(decision, Some(issued)));
        let mut input = std::io::Cursor::new(b"run\n");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan_queued(
            &cli(),
            &queued_id(),
            &SUDO,
            &socket,
            PATIENT,
            true,
            &mut input,
            &mut out,
            &mut err,
        );
        let run = result.unwrap();
        assert_eq!(run.claim_token, token);
        assert!(run.plan.spawn);
        let shown = String::from_utf8(err).unwrap();
        assert!(shown.contains(&queued_id()), "{shown}");
        assert!(shown.contains("harness codex"), "{shown}");
        assert!(shown.contains("upgrade"), "{shown}");
        assert!(!shown.contains('\u{1b}'), "{shown}");
        assert!(shown.contains("type run and press enter"), "{shown}");
        let sent = BrokerRequest::parse(&broker.finish()).unwrap();
        assert_eq!(sent.question, Question::QueueClaim { id: queued_id() });

        let mut empty = minted(GATE_AUTH);
        empty.claim_token = Some(String::new());
        assert_eq!(claim_secret(&empty), empty.nonce);
        empty.claim_token = Some(token.clone());
        assert_eq!(claim_secret(&empty), token);

        let mut hostile = allow();
        hostile.resolved_exe = Some("/usr/bin/true".to_owned());
        hostile.resolved_argv = vec!["ok".to_owned()];
        let mut input = std::io::Cursor::new(b"run\n");
        let mut err = Vec::new();
        let label = "co\u{202e}dex\u{1b}[31m";
        assert!(confirm_queued(
            &queued_id(),
            &hostile,
            Some(label),
            &mut input,
            &mut err
        ));
        let shown = String::from_utf8(err).unwrap();
        assert!(shown.contains("harness"), "{shown}");
        assert!(!shown.contains('\u{202e}'), "{shown}");
        assert!(!shown.contains('\u{1b}'), "{shown}");
        assert!(!confirm_queued(
            &queued_id(),
            &hostile,
            None,
            &mut std::io::Cursor::new(b"no\n"),
            &mut Vec::new()
        ));
    }

    #[test]
    fn queued_terminal_requires_stdin_and_stderr() {
        assert!(queued_terminal(true, true));
        assert!(!queued_terminal(true, false));
        assert!(!queued_terminal(false, true));
        assert!(!queued_terminal(false, false));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn xudo_exec_queued_refuses_without_a_terminal() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan_queued(
            &cli(),
            &queued_id(),
            &SUDO,
            Path::new("/no/such/sock"),
            PATIENT,
            false,
            &mut std::io::Cursor::new(b"run\n"),
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        let shown = String::from_utf8(err).unwrap();
        assert!(shown.contains("needs a terminal"), "{shown}");
        assert!(!shown.contains("unreachable"), "{shown}");

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = crate::test_broker::serve_many(
            listener,
            vec![
                decided(allow(), Some(minted(GATE_AUTH))),
                json(&Answer::Done),
            ],
        );
        let mut input = std::io::Cursor::new(b"no\n");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = plan_queued(
            &cli(),
            &queued_id(),
            &SUDO,
            &socket,
            PATIENT,
            true,
            &mut input,
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        let shown = String::from_utf8(err).unwrap();
        assert!(shown.contains("releasing the claim"), "{shown}");
        let requests = broker.finish_report().requests;
        assert_eq!(requests.len(), 2);
        let release = BrokerRequest::parse(&requests[1]).unwrap();
        assert_eq!(
            release.question,
            Question::QueueRelease {
                id: queued_id(),
                claim_token: "0".repeat(64),
            }
        );

        // A confirmation read that fails releases the claim and does not spawn.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("b.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = crate::test_broker::serve_many(
            listener,
            vec![
                decided(allow(), Some(minted(GATE_AUTH))),
                json(&Answer::Done),
            ],
        );
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut closed = ClosedInput;
        let mut buf = [0u8; 1];
        let read = std::io::Read::read(&mut closed, &mut buf);
        assert_eq!(read.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
        std::io::BufRead::consume(&mut closed, 1);
        let result = plan_queued(
            &cli(),
            &queued_id(),
            &SUDO,
            &socket,
            PATIENT,
            true,
            &mut closed,
            &mut out,
            &mut err,
        );
        assert_eq!(result, Err(ExitCode::Unusable));
        let shown = String::from_utf8(err).unwrap();
        assert!(shown.contains("releasing the claim"), "{shown}");
        let requests = broker.finish_report().requests;
        assert_eq!(requests.len(), 2);
    }

    /// `read_line` fails. Used so that arm is taken on every platform.
    struct ClosedInput;

    impl std::io::Read for ClosedInput {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ))
        }
    }

    impl std::io::BufRead for ClosedInput {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ))
        }

        fn consume(&mut self, _amt: usize) {}
    }
}
