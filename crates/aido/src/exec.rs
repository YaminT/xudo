//! `aido exec`: ask the broker, then let the backend ask for the password.
//!
//! The one path here that ends in a privileged command, and the one where this
//! crate has the least say. It decides nothing and holds no secret:
//!
//! 1. It matches the command against the ruleset, the same call `aido explain`
//!    makes. That is **advisory**. It lets a request the engine would refuse
//!    fail here with the same envelope, instead of costing a round trip. The
//!    broker and the gate decide again, from root-owned state, on their own.
//! 2. It asks the broker, over [`BROKER_SOCKET`], one question: the program and
//!    its operands. What it says about itself,
//!    [`BrokerRequest::claimed_classification`], is the constant [`CLAIMED`]:
//!    no input reaches it, and the broker records it and reads it never.
//! 3. If the broker minted a request, it runs the backend's password hop,
//!    `sudo -- /usr/libexec/aido/aido-gate-auth`, and waits for it.
//!
//! # What the human types, and what this reads
//!
//! The backend asks for the password on `/dev/tty`. That prompt is the human's
//! authentication, not an aido confirmation, and nothing here reads stdin,
//! stdout, or a terminal. Standard input and output are handed to the child
//! as they are.
//!
//! # Spawn and wait, never exec
//!
//! The gate finds the request the broker minted by the identity of an ancestor:
//! this process. If `aido` replaced itself with `sudo`, the ancestor the broker
//! pinned would be gone and the gate would find nothing. So `aido` stays alive,
//! as the gate's ancestor, until the child ends.
//!
//! # An exit status 17, 18 or 19 is ambiguous, and how that is resolved
//!
//! The gate execs the command in place, so the status that comes back is the
//! command's own, and a command may exit 17, 18 or 19 as easily as `aido`
//! does. The gate's refusal is told apart by its last line on standard error,
//! `aido-gate: refused (<code>, severity <level>)`. The status is **always**
//! passed through unchanged; when it is in `17..=19` and that line is the last
//! thing the child wrote, a note says the gate refused.
//!
//! Nothing is authorized on that line. A command that prints it, and then
//! exits 18, gets a note that the gate refused: it changed a sentence and
//! nothing else, and the status was the command's all along.

use std::ffi::{OsStr, OsString};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitStatus, Stdio};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use aido_backend::snippet::GATE_AUTH;
use aido_backend::{DetectError, detect};
use aido_policy::{Arg, Argv, DenialCode, ExitCode};
use aido_wire::{
    Answer, BROKER_SOCKET, BrokerRequest, BrokerResponse, MAX_RESPONSE_BYTES, RefusalCode,
    ResponseError,
};

use crate::cli::{self, Cli, Platform};
use crate::doctor::{safe, shell_quote};
use crate::rules::LoadedRules;

/// What this front-end claims its caller is, on the wire.
///
/// A constant. The broker classifies from what the kernel attests and treats
/// this as a hint it writes to the audit trail, so a front-end that claimed
/// anything else would change nothing; claiming the weakest thing makes that
/// obvious to whoever reads the record.
pub const CLAIMED: &str = "unattested";

/// The longest answer the broker is waited for.
const BROKER_TIMEOUT: Duration = Duration::from_secs(30);

/// How long after the child exits its standard error is still collected.
///
/// Not "until end of file": a background process the command started may hold
/// the pipe open for as long as it likes, and `aido` must not hang on it. The
/// gate writes its line before it execs or exits, so by the time the child has
/// exited the line is already in the pipe.
const STDERR_GRACE: Duration = Duration::from_millis(250);

/// The longest line of the child's standard error that is kept for matching.
const LINE_CAP: usize = 4096;

/// Why `aido exec` stopped before, or instead of, a command running.
///
/// Every variant is a refusal and every refusal is exit status 19, "aido could
/// not operate and failed closed". None of them falls back to running anything
/// some other way.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecError {
    /// No command was given.
    #[error("nothing to run; pass a command after `--`")]
    NothingToRun,
    /// An argument is not UTF-8.
    ///
    /// Refused here, never converted: a lossy conversion is how two different
    /// arguments start to compare equal, and the broker's request carries
    /// strings.
    #[error(
        "argument {index} is not valid UTF-8, and aido never converts one lossily; nothing was sent"
    )]
    NonUtf8Argument {
        /// Position in the command, `0` being the program.
        index: usize,
    },
    /// An argument contains a NUL byte.
    #[error(
        "argument {index} contains a NUL byte, which the kernel would cut short; nothing was sent"
    )]
    InteriorNul {
        /// Position in the command, `0` being the program.
        index: usize,
    },
    /// The program is not an absolute path.
    #[error("name the program by its absolute path; aido never searches PATH")]
    ProgramNotAbsolute,
    /// The broker could not be asked.
    #[error(
        "the broker at {} did not answer; an administrator must check that aidod.socket is \
         active and that you are in the aido group. aido does not fall back to running sudo \
         itself",
        BROKER_SOCKET
    )]
    BrokerUnreachable,
    /// The broker's answer is not one this front-end can read.
    #[error("the broker's answer could not be read ({0}); failing closed")]
    BrokerAnswerUnreadable(ResponseError),
    /// The broker permitted the command and minted nothing to run it with.
    #[error("the broker permitted the command but minted nothing to run it with; failing closed")]
    PermittedWithoutMint,
    /// The broker minted a request for a command it did not permit.
    #[error("the broker minted a request for a command it did not permit; failing closed")]
    MintedWithoutPermission,
    /// The gate the broker named is not the gate compiled into this build.
    #[error("the broker named a gate other than the one this aido runs; failing closed")]
    GateNotTheCompiledOne,
    /// No usable backend.
    #[error("{0}")]
    NoBackend(DetectError),
    /// The backend could not be started.
    #[error("the backend could not be started; failing closed")]
    BackendNotStarted,
}

/// What can talk to the broker.
pub trait BrokerLink {
    /// Sends one request and reads the whole answer.
    ///
    /// # Errors
    ///
    /// Whatever stopped the exchange.
    fn round_trip(&self, request: &[u8]) -> io::Result<Vec<u8>>;
}

/// The broker's socket.
#[derive(Clone, Debug)]
pub struct SocketLink {
    path: PathBuf,
}

impl SocketLink {
    /// A link to the broker listening at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl BrokerLink for SocketLink {
    fn round_trip(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        UnixStream::connect(&self.path).and_then(|mut stream| {
            stream
                .set_read_timeout(Some(BROKER_TIMEOUT))
                .and_then(|()| stream.write_all(request))
                .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
                .and_then(|()| {
                    // One byte past the limit, so an oversized answer is seen
                    // as oversized rather than quietly cut to the limit.
                    let mut answer = Vec::new();
                    let limit = u64::try_from(MAX_RESPONSE_BYTES)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1);
                    stream.take(limit).read_to_end(&mut answer).map(|_| answer)
                })
        })
    }
}

/// How a child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// It exited with this status.
    Exited(i32),
    /// A signal killed it.
    Signalled(i32),
}

/// What the password hop did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopOutcome {
    /// How the child ended.
    pub ended: Ended,
    /// The last line the child wrote to standard error, without its newline,
    /// capped at 4 KiB. Bytes: never converted.
    pub last_stderr_line: Option<Vec<u8>>,
}

/// What can run the backend's password hop.
pub trait Hop {
    /// Runs `program` with `args`, waits for it, and reports how it ended.
    ///
    /// # Errors
    ///
    /// When the child could not be started.
    fn run(&self, program: &Path, args: &[&OsStr]) -> io::Result<HopOutcome>;
}

/// Where the child's standard error is copied to as it arrives.
#[derive(Clone, Debug)]
enum Tee {
    /// This process's own standard error.
    Stderr,
    /// A buffer, for a test to read.
    Captured(Arc<Mutex<Vec<u8>>>),
}

impl Tee {
    fn write(&self, bytes: &[u8]) {
        match self {
            Self::Stderr => {
                let _ = io::stderr().lock().write_all(bytes);
            }
            Self::Captured(buffer) => {
                if let Ok(mut held) = buffer.lock() {
                    held.extend_from_slice(bytes);
                }
            }
        }
    }
}

/// Runs the hop as a real child process.
///
/// The child's standard input and output are this process's own, so the
/// backend can reach the terminal. Its standard error is a pipe, copied to this
/// process's standard error byte for byte as it arrives and watched for the
/// gate's last line.
#[derive(Clone, Debug)]
pub struct ProcessHop {
    tee: Tee,
}

impl ProcessHop {
    /// A hop that copies the child's standard error to this process's.
    pub fn new() -> Self {
        Self { tee: Tee::Stderr }
    }

    /// A hop that copies the child's standard error into `buffer`.
    pub fn capturing(buffer: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            tee: Tee::Captured(buffer),
        }
    }
}

impl Default for ProcessHop {
    fn default() -> Self {
        Self::new()
    }
}

impl Hop for ProcessHop {
    // The absolute-path check below precedes Command::new; no PATH lookup.
    #[allow(clippy::disallowed_methods)]
    fn run(&self, program: &Path, args: &[&OsStr]) -> io::Result<HopOutcome> {
        // An absolute path and an empty environment: nothing is searched for
        // and nothing the caller exported is inherited. The backend resets the
        // environment of what it runs anyway. Detection only ever reports a
        // path from its own closed list of absolute ones; a relative path
        // here is refused all the same, because `Command` would search `PATH`
        // for it.
        if !program.is_absolute() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        Process::new(program)
            .args(args)
            .env_clear()
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                let (lines, heard) = mpsc::channel();
                let tee = self.tee.clone();
                // Detached on purpose: see `STDERR_GRACE`.
                let _reader = child
                    .stderr
                    .take()
                    .map(|pipe| thread::spawn(move || pump(pipe, &tee, &lines)));
                child.wait().map(|status| {
                    let started = Instant::now();
                    let mut last = None;
                    while let Ok(line) =
                        heard.recv_timeout(STDERR_GRACE.saturating_sub(started.elapsed()))
                    {
                        last = Some(line);
                    }
                    HopOutcome {
                        ended: ended(status),
                        last_stderr_line: last,
                    }
                })
            })
    }
}

/// How a wait status reads, as the shell's convention would.
fn ended(status: ExitStatus) -> Ended {
    match status.signal() {
        Some(signal) => Ended::Signalled(signal),
        // The wait status of a normal exit holds the code in its second byte.
        None => Ended::Exited((status.into_raw() >> 8) & 0xff),
    }
}

/// Copies `pipe` to `tee` as it arrives and sends each finished line.
fn pump(pipe: impl Read, tee: &Tee, lines: &Sender<Vec<u8>>) {
    let mut reader = BufReader::new(pipe);
    let mut line: Vec<u8> = Vec::new();
    while let Ok(chunk) = reader.fill_buf() {
        if chunk.is_empty() {
            break;
        }
        tee.write(chunk);
        for piece in chunk.split_inclusive(|byte| *byte == b'\n') {
            let (body, finished) = match piece.strip_suffix(b"\n") {
                Some(body) => (body, true),
                None => (piece, false),
            };
            let room = LINE_CAP.saturating_sub(line.len());
            line.extend(body.iter().take(room));
            if finished {
                let _ = lines.send(std::mem::take(&mut line));
            }
        }
        let consumed = chunk.len();
        reader.consume(consumed);
    }
    if !line.is_empty() {
        let _ = lines.send(line);
    }
}

/// What `aido exec` runs against: the broker, and the process that runs the
/// hop.
#[derive(Clone, Copy)]
pub struct Env<'a> {
    /// The broker.
    pub link: &'a dyn BrokerLink,
    /// The password hop.
    pub hop: &'a dyn Hop,
}

/// The gate's refusal code, if `line` is exactly the line the gate writes.
///
/// `aido-gate: refused (<code>, severity <level>)`, with the code and the
/// level lowercase letters (and underscores in the code) and nothing before or
/// after. Strict on purpose: it is matched against bytes a command may have
/// written, and the restricted alphabet is also what keeps an escape sequence
/// out of the note that quotes the code.
pub fn gate_refusal_code(line: &[u8]) -> Option<String> {
    let rest = line.strip_prefix(b"aido-gate: refused (")?;
    let (code, rest) = split_class(rest, |byte| byte.is_ascii_lowercase() || byte == b'_');
    let rest = rest.strip_prefix(b", severity ")?;
    let (level, rest) = split_class(rest, |byte| byte.is_ascii_lowercase());
    if code.is_empty() || level.is_empty() || rest != b")" {
        return None;
    }
    Some(code.iter().map(|byte| char::from(*byte)).collect())
}

/// Splits `bytes` after its longest prefix of bytes satisfying `class`.
fn split_class(bytes: &[u8], class: impl Fn(u8) -> bool) -> (&[u8], &[u8]) {
    bytes.split_at(bytes.iter().take_while(|byte| class(**byte)).count())
}

/// The note a gate refusal adds.
pub fn gate_note(code: &str) -> String {
    format!(
        "aido: the gate refused ({}); see the audit trail",
        safe(code)
    )
}

/// The line printed when a signal killed the backend.
pub fn signal_line(label: &str, signal: i32) -> String {
    format!("aido: {label} killed by signal {signal}")
}

/// The sentence `ido queue` shows the human, per denial a human must handle.
///
/// Exhaustive on purpose: a new denial code does not compile until someone has
/// decided whether it is the kind a person can act on.
pub fn queue_reason(code: DenialCode) -> Option<&'static str> {
    match code {
        DenialCode::HumanPathOnly => Some("aido refused this for an agent: a person must run it"),
        DenialCode::Frozen => Some("aido is frozen for agents: a person must run it"),
        DenialCode::UnknownAction
        | DenialCode::ArgvRejected
        | DenialCode::DenyListed
        | DenialCode::PolicyUnloadable
        | DenialCode::NoConfirmationChannel
        | DenialCode::ExeMismatch => None,
    }
}

/// The `ido queue` line a human runs instead, quoted for display only.
///
/// Never parsed back: the words are the command's own, one quoted word each,
/// and the whole line is made safe for a terminal.
pub fn queue_line(reason: &str, command: &[String]) -> String {
    let words: Vec<String> = command.iter().map(|word| shell_quote(word)).collect();
    safe(&format!(
        "ido queue -m {} -- {}",
        shell_quote(reason),
        words.join(" ")
    ))
}

/// Prints the `ido queue` line for a denial a person can act on.
fn offer_queue(code: Option<DenialCode>, command: &[String], err: &mut dyn Write) {
    if let Some(reason) = code.and_then(queue_reason) {
        let _ = writeln!(err, "aido: hand this to a person, who runs:");
        let _ = writeln!(err, "  {}", queue_line(reason, command));
    }
}

/// Turns the command into the strings the broker's request carries.
fn convert(argv: &[OsString]) -> Result<(String, Vec<String>), ExecError> {
    let mut words = Vec::with_capacity(argv.len());
    for (index, word) in argv.iter().enumerate() {
        let text = word.to_str().ok_or(ExecError::NonUtf8Argument { index })?;
        if text.contains('\0') {
            return Err(ExecError::InteriorNul { index });
        }
        words.push(text.to_owned());
    }
    let mut words = words.into_iter();
    let program = words.next().ok_or(ExecError::NothingToRun)?;
    if !program.starts_with('/') {
        return Err(ExecError::ProgramNotAbsolute);
    }
    Ok((program, words.collect()))
}

/// Prints a refusal and returns the status that means "aido failed closed".
fn refuse(error: &ExecError, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "aido: {}", safe(&error.to_string()));
    ExitCode::Unusable.as_i32()
}

/// Runs `argv` through the broker and the backend.
///
/// Returns the status `aido` exits with: the command's own when it ran, one of
/// `aido`'s refusal codes when it did not.
pub fn run(
    env: &Env<'_>,
    cli: &Cli,
    platform: &Platform<'_>,
    loaded: &LoadedRules,
    argv: &[OsString],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let (program, operands) = match convert(argv) {
        Ok(converted) => converted,
        Err(error) => return refuse(&error, err),
    };
    let command: Vec<String> = std::iter::once(program.clone())
        .chain(operands.iter().cloned())
        .collect();

    // Advisory, and said so: the same call `aido explain` makes, so a command
    // the engine refuses is refused here with the same envelope and without a
    // round trip. Neither the broker nor the gate takes this verdict on trust.
    let Some(settings) = cli::engine_settings(cli, err) else {
        return ExitCode::Unusable.as_i32();
    };
    let caller = cli::classify(platform.ops, err);
    let requested = Argv::new(operands.iter().map(String::as_str).collect::<Vec<_>>());
    let advice = aido_policy::evaluate_command(
        loaded.rules(),
        &caller,
        &Arg::from(program.as_str()),
        &requested,
        settings,
    );
    if !advice.verdict.is_permitted() {
        let status = cli::emit(cli, &advice, out).as_i32();
        offer_queue(advice.denial, &command, err);
        return status;
    }

    let request = BrokerRequest::new(program, operands, CLAIMED);
    let Ok(answer) = env.link.round_trip(request.to_json().as_bytes()) else {
        return refuse(&ExecError::BrokerUnreachable, err);
    };
    let response = match BrokerResponse::parse(&answer) {
        Ok(response) => response,
        Err(error) => return refuse(&ExecError::BrokerAnswerUnreadable(error), err),
    };

    match response.answer {
        Answer::Refused { code, remediation } => refused(code, &remediation, err),
        Answer::Decided {
            decision,
            minted: None,
        } => {
            if decision.verdict.is_permitted() {
                return refuse(&ExecError::PermittedWithoutMint, err);
            }
            let status = cli::emit(cli, &decision, out).as_i32();
            offer_queue(decision.denial, &command, err);
            status
        }
        Answer::Decided {
            decision,
            minted: Some(minted),
        } => {
            if !decision.verdict.is_permitted() {
                return refuse(&ExecError::MintedWithoutPermission, err);
            }
            // Compared byte for byte with the constant, and the constant is
            // what runs: the string off the wire is never executed.
            if minted.gate != GATE_AUTH {
                return refuse(&ExecError::GateNotTheCompiledOne, err);
            }
            hop(env, platform, err)
        }
    }
}

/// The line printed for a broker refusal.
///
/// The remediation came over a socket, so it is made safe for a terminal.
pub fn refusal_line(code: RefusalCode, remediation: &str) -> String {
    format!(
        "aido: the broker refused the request ({}): {}",
        code.as_str(),
        safe(remediation)
    )
}

/// Prints the broker's refusal.
fn refused(code: RefusalCode, remediation: &str, err: &mut dyn Write) -> i32 {
    let _ = writeln!(err, "{}", refusal_line(code, remediation));
    ExitCode::Unusable.as_i32()
}

/// Runs the backend's password hop and reports how it ended.
fn hop(env: &Env<'_>, platform: &Platform<'_>, err: &mut dyn Write) -> i32 {
    let backend = match detect(platform.probe) {
        Ok(backend) => backend,
        Err(error) => return refuse(&ExecError::NoBackend(error), err),
    };
    // The path detection found it at, not one derived from its kind: Ubuntu's
    // `sudo-rs` lives at `/usr/bin/sudo-rs`.
    let exe = Path::new(&backend.exe);
    // `--` ends the backend's own options in `sudo`, `sudo-rs` and `doas`, and
    // the rule the install wrote allows the gate with no arguments at all.
    let args = [OsStr::new("--"), OsStr::new(GATE_AUTH)];
    let Ok(outcome) = env.hop.run(exe, &args) else {
        return refuse(&ExecError::BackendNotStarted, err);
    };
    match outcome.ended {
        Ended::Signalled(signal) => {
            let _ = writeln!(err, "{}", signal_line(backend.kind.label(), signal));
            128_i32.saturating_add(signal)
        }
        Ended::Exited(status) => {
            let reserved = [ExitCode::Denied, ExitCode::NotConfirmed, ExitCode::Unusable]
                .map(ExitCode::as_i32)
                .contains(&status);
            if reserved
                && let Some(code) = outcome
                    .last_stderr_line
                    .as_deref()
                    .and_then(gate_refusal_code)
            {
                let _ = writeln!(err, "{}", gate_note(&code));
            }
            status
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use std::cell::RefCell;
    use std::os::unix::ffi::OsStrExt;
    use std::sync::OnceLock;

    use aido_backend::Probe;
    use aido_backend::snippet::GATE_AUTH;
    use aido_policy::{Classification, Decision, Verdict};
    use aido_sys::{LiveHost, host_ops};
    use aido_wire::Minted;
    use clap::Parser;

    use super::*;

    const PROGRAM: &str = "/usr/local/libexec/aido-test/whoami-exit";

    const RULES: &str = r#"
[[action]]
id = "aido.test.whoami"
tier = "diag-read"
exe = "/usr/local/libexec/aido-test/whoami-exit"
args = [{ name = "verb", matcher = { literal = "go" } }]
"#;

    fn test_tmp() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
    }

    /// The rules every test runs against, written once.
    fn rules_dir() -> &'static Path {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = test_tmp().join("exec-rules");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("10-rules.toml"), RULES).unwrap();
            dir
        })
    }

    struct FakeLink {
        reply: Option<Vec<u8>>,
        sent: RefCell<Vec<Vec<u8>>>,
    }

    impl FakeLink {
        fn replying(reply: Vec<u8>) -> Self {
            Self {
                reply: Some(reply),
                sent: RefCell::default(),
            }
        }

        fn dead() -> Self {
            Self {
                reply: None,
                sent: RefCell::default(),
            }
        }
    }

    impl BrokerLink for FakeLink {
        fn round_trip(&self, request: &[u8]) -> io::Result<Vec<u8>> {
            self.sent.borrow_mut().push(request.to_vec());
            self.reply
                .clone()
                .ok_or_else(|| io::Error::from(io::ErrorKind::ConnectionRefused))
        }
    }

    struct FakeHop {
        outcome: Option<HopOutcome>,
        calls: RefCell<Vec<(PathBuf, Vec<OsString>)>>,
    }

    impl FakeHop {
        fn ending(ended: Ended, last: Option<&[u8]>) -> Self {
            Self {
                outcome: Some(HopOutcome {
                    ended,
                    last_stderr_line: last.map(<[u8]>::to_vec),
                }),
                calls: RefCell::default(),
            }
        }

        fn never() -> Self {
            Self::ending(Ended::Exited(0), None)
        }

        fn broken() -> Self {
            Self {
                outcome: None,
                calls: RefCell::default(),
            }
        }
    }

    impl Hop for FakeHop {
        fn run(&self, program: &Path, args: &[&OsStr]) -> io::Result<HopOutcome> {
            self.calls.borrow_mut().push((
                program.to_path_buf(),
                args.iter().map(|arg| (*arg).to_owned()).collect(),
            ));
            self.outcome
                .clone()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    /// A machine whose backend is at `exe`, or none, or a broken one.
    struct FakeProbe {
        exe: &'static str,
        banner: &'static str,
        works: bool,
    }

    const SUDO: FakeProbe = FakeProbe {
        exe: "/usr/bin/sudo",
        banner: "Sudo version 1.9.17p2\n",
        works: true,
    };

    impl Probe for FakeProbe {
        fn exists(&self, absolute_path: &str) -> bool {
            absolute_path == self.exe
        }
        fn version_banner(&self, _absolute_path: &str) -> Option<String> {
            Some(self.banner.to_owned())
        }
        fn directory_exists(&self, _absolute_path: &str) -> bool {
            self.works
        }
        fn honours_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
            self.works
        }
        fn honours_scoped_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
            self.works
        }
        fn validates_named_file(&self, _absolute_path: &str) -> bool {
            self.works
        }
        fn accepts_argument_wildcard(&self, _absolute_path: &str) -> bool {
            self.works
        }
    }

    fn words(argv: &[&str]) -> Vec<OsString> {
        argv.iter().map(OsString::from).collect()
    }

    fn go_with(
        link: &FakeLink,
        hop: &FakeHop,
        probe: &dyn Probe,
        argv: &[OsString],
    ) -> (i32, String, String) {
        go_in(link, hop, probe, rules_dir(), &[], argv)
    }

    fn go_in(
        link: &dyn BrokerLink,
        hop: &dyn Hop,
        probe: &dyn Probe,
        rules: &Path,
        extra: &[&str],
        argv: &[OsString],
    ) -> (i32, String, String) {
        let mut full = vec!["aido", "--rules", rules.to_str().unwrap()];
        full.extend_from_slice(extra);
        full.extend(["exec", "--", "x"]);
        let cli = Cli::try_parse_from(full).unwrap();
        let loaded = LoadedRules::from_dir(rules).unwrap();
        let ops = host_ops();
        let platform = Platform {
            ops: ops.as_ref(),
            probe,
            host: &LiveHost,
            path: None,
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let status = run(
            &Env { link, hop },
            &cli,
            &platform,
            &loaded,
            argv,
            &mut out,
            &mut err,
        );
        (
            status,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    fn go(link: &FakeLink, hop: &FakeHop, argv: &[&str]) -> (i32, String, String) {
        go_with(link, hop, &SUDO, &words(argv))
    }

    const PERMITTED: [&str; 2] = [PROGRAM, "go"];

    fn allow() -> Decision {
        let loaded = LoadedRules::from_dir(rules_dir()).unwrap();
        let decision = aido_policy::evaluate_command(
            loaded.rules(),
            &aido_policy::CallerFacts::new(Classification::Human, 1000),
            &Arg::from(PROGRAM),
            &Argv::new(["go"]),
            aido_policy::engine::Settings::default(),
        );
        assert_eq!(decision.verdict, Verdict::Allow);
        decision
    }

    fn minted(gate: &str) -> Minted {
        Minted {
            nonce: "0".repeat(64),
            deadline: 1,
            ttl_secs: 900,
            gate: gate.to_owned(),
        }
    }

    fn answer(decision: Decision, minted: Option<Minted>) -> Vec<u8> {
        serde_json::to_vec(&BrokerResponse::decided(decision, minted)).unwrap()
    }

    fn minting() -> FakeLink {
        FakeLink::replying(answer(allow(), Some(minted(GATE_AUTH))))
    }

    #[test]
    fn the_claimed_classification_is_a_constant_no_input_reaches() {
        assert_eq!(CLAIMED, "unattested");
        for argv in [
            PERMITTED.to_vec(),
            vec![PROGRAM, "go", "claude-code", "human", "enrolled"],
        ] {
            let link = minting();
            go(&link, &FakeHop::never(), &argv);
            for sent in link.sent.borrow().iter() {
                let request = BrokerRequest::parse(sent).unwrap();
                assert_eq!(request.claimed_classification, "unattested");
                assert_eq!(request.program, PROGRAM);
            }
        }
    }

    #[test]
    fn refuses_non_utf8_argument_without_converting_it() {
        let link = minting();
        let argv = vec![
            OsString::from(PROGRAM),
            OsStr::from_bytes(b"go\xff").to_owned(),
        ];
        let (status, _, err) = go_with(&link, &FakeHop::never(), &SUDO, &argv);
        assert_eq!(status, 19);
        assert!(err.contains("argument 1 is not valid UTF-8"), "{err}");
        assert!(!err.contains('\u{fffd}'), "{err}");
        assert!(link.sent.borrow().is_empty());
    }

    #[test]
    fn refuses_nul_in_argument() {
        let link = minting();
        let argv = vec![
            OsString::from(PROGRAM),
            OsStr::from_bytes(b"g\0o").to_owned(),
        ];
        let (status, _, err) = go_with(&link, &FakeHop::never(), &SUDO, &argv);
        assert_eq!(status, 19);
        assert!(err.contains("argument 1 contains a NUL"), "{err}");
        assert!(link.sent.borrow().is_empty());
    }

    #[test]
    fn refuses_a_relative_program_without_searching_path() {
        let link = minting();
        let (status, _, err) = go(&link, &FakeHop::never(), &["whoami-exit", "go"]);
        assert_eq!(status, 19);
        assert!(err.contains("absolute path"), "{err}");
        assert!(link.sent.borrow().is_empty());
    }

    #[test]
    fn refuses_an_empty_command() {
        let link = minting();
        let (status, _, err) = go_with(&link, &FakeHop::never(), &SUDO, &[]);
        assert_eq!(status, 19);
        assert!(err.contains("nothing to run"), "{err}");
        assert!(link.sent.borrow().is_empty());
    }

    #[test]
    fn refuses_a_minted_gate_path_that_is_not_the_compiled_one() {
        for gate in ["/tmp/evil", "/usr/libexec/aido/aido-gate-nopass", ""] {
            let link = FakeLink::replying(answer(allow(), Some(minted(gate))));
            let hop = FakeHop::never();
            let (status, _, err) = go(&link, &hop, &PERMITTED);
            assert_eq!(status, 19, "{gate}");
            assert!(err.contains("a gate other than"), "{err}");
            assert!(hop.calls.borrow().is_empty());
        }
    }

    #[test]
    fn refuses_a_mint_on_a_non_permitted_decision() {
        let denied = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        let link = FakeLink::replying(answer(denied, Some(minted(GATE_AUTH))));
        let hop = FakeHop::never();
        let (status, _, err) = go(&link, &hop, &PERMITTED);
        assert_eq!(status, 19);
        assert!(err.contains("did not permit"), "{err}");
        assert!(hop.calls.borrow().is_empty());
    }

    #[test]
    fn refuses_a_permitted_decision_with_no_mint() {
        let link = FakeLink::replying(answer(allow(), None));
        let hop = FakeHop::never();
        let (status, _, err) = go(&link, &hop, &PERMITTED);
        assert_eq!(status, 19);
        assert!(err.contains("minted nothing"), "{err}");
        assert!(hop.calls.borrow().is_empty());
    }

    #[test]
    fn refuses_a_relative_backend_path() {
        let error = ProcessHop::new()
            .run(Path::new("sudo"), &[OsStr::new("--")])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn refuses_an_unusable_backend() {
        let probe = FakeProbe {
            works: false,
            ..SUDO
        };
        let hop = FakeHop::never();
        let (status, _, err) = go_with(&minting(), &hop, &probe, &words(&PERMITTED));
        assert_eq!(status, 19);
        assert!(err.contains("missing a required control"), "{err}");
        assert!(hop.calls.borrow().is_empty());
    }

    #[test]
    fn refuses_when_there_is_no_backend_at_all() {
        let probe = FakeProbe { exe: "", ..SUDO };
        let hop = FakeHop::never();
        let (status, _, err) = go_with(&minting(), &hop, &probe, &words(&PERMITTED));
        assert_eq!(status, 19);
        assert!(err.contains("no privilege backend found"), "{err}");
        assert!(hop.calls.borrow().is_empty());
    }

    #[test]
    fn the_hop_runs_the_backend_where_it_was_found_with_the_gate_and_nothing_else() {
        for (exe, banner, kind) in [
            ("/usr/bin/sudo", "Sudo version 1.9.17p2", "sudo"),
            ("/usr/bin/sudo-rs", "sudo-rs 0.2.2", "sudo-rs"),
        ] {
            let probe = FakeProbe {
                exe,
                banner,
                works: true,
            };
            let hop = FakeHop::ending(Ended::Exited(7), None);
            let (status, out, err) = go_with(&minting(), &hop, &probe, &words(&PERMITTED));
            assert_eq!(status, 7, "{kind}");
            assert!(out.is_empty() && err.is_empty(), "{kind}: {out}{err}");
            assert_eq!(
                *hop.calls.borrow(),
                vec![(
                    PathBuf::from(exe),
                    vec![OsString::from("--"), OsString::from(GATE_AUTH)]
                )]
            );
        }
    }

    #[test]
    fn a_backend_that_cannot_be_started_is_refused() {
        let (status, _, err) = go(&minting(), &FakeHop::broken(), &PERMITTED);
        assert_eq!(status, 19);
        assert!(err.contains("could not be started"), "{err}");
    }

    #[test]
    fn a_child_exiting_18_without_the_gate_line_is_reported_as_its_own() {
        for last in [
            None,
            Some(&b"hello"[..]),
            Some(&b"aido-gate: refused (x, severity low) and more"[..]),
        ] {
            for status in [17, 18, 19] {
                let hop = FakeHop::ending(Ended::Exited(status), last);
                let (got, _, err) = go_with(&minting(), &hop, &SUDO, &words(&PERMITTED));
                assert_eq!(got, status);
                assert!(!err.contains("the gate refused"), "{err}");
            }
        }
    }

    #[test]
    fn a_gate_refusal_line_with_18_is_reported_as_the_gate() {
        let line = b"aido-gate: refused (no_pending_request, severity low)";
        for status in [17, 18, 19] {
            let hop = FakeHop::ending(Ended::Exited(status), Some(line));
            let (got, _, err) = go_with(&minting(), &hop, &SUDO, &words(&PERMITTED));
            assert_eq!(got, status, "the status is never rewritten");
            assert_eq!(
                err,
                "aido: the gate refused (no_pending_request); see the audit trail\n"
            );
        }
    }

    #[test]
    fn a_gate_line_with_other_statuses_adds_no_note() {
        let line = b"aido-gate: refused (no_pending_request, severity low)";
        for status in [0, 1, 7, 16, 20, 126, 255] {
            let hop = FakeHop::ending(Ended::Exited(status), Some(line));
            let (got, _, err) = go_with(&minting(), &hop, &SUDO, &words(&PERMITTED));
            assert_eq!(got, status);
            assert!(err.is_empty(), "{status}: {err}");
        }
    }

    #[test]
    fn a_gate_line_with_exit_0_adds_no_note() {
        let hop = FakeHop::ending(
            Ended::Exited(0),
            Some(b"aido-gate: refused (a, severity low)"),
        );
        let (status, _, err) = go_with(&minting(), &hop, &SUDO, &words(&PERMITTED));
        assert_eq!(status, 0);
        assert!(err.is_empty(), "{err}");
    }

    #[test]
    fn a_gate_line_with_escape_bytes_is_not_recognised() {
        for line in [
            &b"aido-gate: refused (\x1b[31mred, severity low)"[..],
            b"aido-gate: refused (a\x1b, severity low)",
            b"aido-gate: refused (a, severity \x1b[2J)",
            b"aido-gate: refused (A, severity low)",
            b"aido-gate: refused (a1, severity low)",
            b"aido-gate: refused (, severity low)",
            b"aido-gate: refused (a, severity )",
            b"aido-gate: refused (a, severity low) ",
            b" aido-gate: refused (a, severity low)",
            b"aido-gate: refused (a,severity low)",
            b"aido-gate: refused (a, severity low",
            b"aido-gate: refused (a",
            b"",
        ] {
            assert_eq!(gate_refusal_code(line), None, "{line:?}");
        }
        assert_eq!(
            gate_refusal_code(b"aido-gate: refused (gate_failed_audit, severity high)"),
            Some("gate_failed_audit".to_owned())
        );
    }

    #[test]
    fn a_signal_death_is_reported_as_one() {
        let hop = FakeHop::ending(Ended::Signalled(9), None);
        let (status, _, err) = go_with(&minting(), &hop, &SUDO, &words(&PERMITTED));
        assert_eq!(status, 137);
        assert_eq!(err, "aido: sudo killed by signal 9\n");
        let outcome = sh("kill -9 $$");
        assert_eq!(outcome.ended, Ended::Signalled(9));
    }

    /// Runs `script` as a real child, with its standard error captured.
    fn sh(script: &str) -> HopOutcome {
        ProcessHop::capturing(Arc::default())
            .run(
                Path::new("/bin/sh"),
                &[OsStr::new("-c"), OsStr::new(script)],
            )
            .unwrap()
    }

    #[test]
    fn a_child_exit_status_is_read_from_the_wait_status() {
        for status in [0, 1, 7, 18, 255] {
            assert_eq!(sh(&format!("exit {status}")).ended, Ended::Exited(status));
        }
    }

    #[test]
    fn a_grandchild_holding_stderr_does_not_hang_exec() {
        let started = Instant::now();
        let outcome = sh("sleep 5 & echo hi >&2");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(outcome.ended, Ended::Exited(0));
        assert_eq!(outcome.last_stderr_line.as_deref(), Some(&b"hi"[..]));
    }

    #[test]
    fn stderr_is_teed_byte_for_byte() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let outcome = ProcessHop::capturing(Arc::clone(&captured))
            .run(
                Path::new("/bin/sh"),
                &[
                    OsStr::new("-c"),
                    OsStr::new("printf 'a\\377\\000b\\nlast\\n' >&2; printf tail >&2"),
                ],
            )
            .unwrap();
        assert_eq!(*captured.lock().unwrap(), b"a\xff\0b\nlast\ntail");
        assert_eq!(outcome.last_stderr_line.as_deref(), Some(&b"tail"[..]));
    }

    #[test]
    fn a_long_stderr_line_is_kept_only_up_to_the_cap() {
        let outcome = sh("head -c 9000 /dev/zero | tr '\\0' a >&2; echo >&2");
        assert_eq!(outcome.last_stderr_line.unwrap().len(), LINE_CAP);
    }

    #[test]
    fn a_program_that_does_not_exist_is_an_error_not_a_search() {
        let error = ProcessHop::default()
            .run(Path::new("/nonexistent/aido/backend"), &[])
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn the_default_hop_copies_to_this_processs_own_stderr() {
        let outcome = ProcessHop::new()
            .run(
                Path::new("/bin/sh"),
                &[OsStr::new("-c"), OsStr::new("echo teed >&2; exit 3")],
            )
            .unwrap();
        assert_eq!(outcome.ended, Ended::Exited(3));
        assert_eq!(outcome.last_stderr_line.as_deref(), Some(&b"teed"[..]));
    }

    #[test]
    fn the_hop_does_not_hand_the_child_the_callers_environment() {
        let outcome = sh("test -z \"$HOME$USER$LOGNAME\" && echo clean >&2");
        assert_eq!(outcome.last_stderr_line.as_deref(), Some(&b"clean"[..]));
    }

    #[test]
    fn an_oversized_broker_response_is_refused() {
        let link = FakeLink::replying(vec![b' '; MAX_RESPONSE_BYTES + 1]);
        let hop = FakeHop::never();
        let (status, _, err) = go(&link, &hop, &PERMITTED);
        assert_eq!(status, 19);
        assert!(err.contains("longer than"), "{err}");
        assert!(hop.calls.borrow().is_empty());
    }

    #[test]
    fn a_malformed_broker_response_is_refused_fail_closed() {
        for reply in [&b"not json"[..], b"", b"{}", b"\xff"] {
            let hop = FakeHop::never();
            let (status, _, err) = go(&FakeLink::replying(reply.to_vec()), &hop, &PERMITTED);
            assert_eq!(status, 19, "{reply:?}");
            assert!(err.contains("could not be read"), "{err}");
            assert!(hop.calls.borrow().is_empty());
        }
    }

    #[test]
    fn no_socket_means_refusal_not_fallback() {
        let hop = FakeHop::never();
        let (status, _, err) = go(&FakeLink::dead(), &hop, &PERMITTED);
        assert_eq!(status, 19);
        assert!(err.contains(BROKER_SOCKET), "{err}");
        assert!(err.contains("does not fall back"), "{err}");
        assert!(hop.calls.borrow().is_empty());

        let link = SocketLink::new(test_tmp().join("exec-no-such-socket"));
        let (status, _, _) = go_in(&link, &hop, &SUDO, rules_dir(), &[], &words(&PERMITTED));
        assert_eq!(status, 19);
        assert!(hop.calls.borrow().is_empty());
    }

    #[test]
    fn every_broker_refusal_is_refused_with_its_code_and_runs_nothing() {
        for code in RefusalCode::ALL {
            let link =
                FakeLink::replying(serde_json::to_vec(&BrokerResponse::refused(code)).unwrap());
            let hop = FakeHop::never();
            let (status, _, err) = go(&link, &hop, &PERMITTED);
            assert_eq!(status, 19, "{code:?}");
            assert_eq!(err, format!("{}\n", refusal_line(code, code.remediation())));
            assert!(err.contains(code.as_str()));
            assert!(hop.calls.borrow().is_empty());
        }
    }

    #[test]
    fn a_broker_remediation_is_made_safe_for_a_terminal() {
        let line = refusal_line(RefusalCode::BrokerUnusable, "\u{1b}[2Jgo away");
        assert!(!line.contains('\u{1b}'), "{line:?}");
    }

    #[test]
    fn a_human_only_denial_prints_the_ido_queue_line_quoted() {
        let denied = Decision::deny(DenialCode::HumanPathOnly, Vec::new(), Vec::new());
        let link = FakeLink::replying(answer(denied, None));
        let hop = FakeHop::never();
        let (status, out, err) = go(&link, &hop, &PERMITTED);
        assert_eq!(status, 17);
        assert!(out.starts_with("DENY"), "{out}");
        assert!(
            err.contains(
                "  ido queue -m 'aido refused this for an agent: a person must run it' -- \
                 /usr/local/libexec/aido-test/whoami-exit go\n"
            ),
            "{err}"
        );
        assert!(hop.calls.borrow().is_empty());
    }

    #[test]
    fn a_frozen_denial_prints_the_ido_queue_line_too() {
        let denied = Decision::deny(DenialCode::Frozen, Vec::new(), Vec::new());
        let (status, _, err) = go(
            &FakeLink::replying(answer(denied, None)),
            &FakeHop::never(),
            &PERMITTED,
        );
        assert_eq!(status, 17);
        assert!(
            err.contains("ido queue -m 'aido is frozen for agents"),
            "{err}"
        );
    }

    #[test]
    fn a_queue_line_quotes_every_word_for_display_and_never_splits_one() {
        let command = ["/bin/x", "two words", "it's", "$(id)", "", "*", "a;b"].map(String::from);
        assert_eq!(
            queue_line("why", &command),
            "ido queue -m why -- /bin/x 'two words' 'it'\\''s' '$(id)' '' '*' 'a;b'"
        );
    }

    #[test]
    fn a_queue_line_is_made_safe_for_a_terminal() {
        let line = queue_line("why", &["/bin/true".to_owned(), "\u{1b}[2J".to_owned()]);
        assert!(!line.contains('\u{1b}'), "{line:?}");
    }

    #[test]
    fn a_denial_a_person_cannot_act_on_prints_no_queue_line() {
        for code in [
            DenialCode::UnknownAction,
            DenialCode::ArgvRejected,
            DenialCode::DenyListed,
            DenialCode::PolicyUnloadable,
            DenialCode::NoConfirmationChannel,
            DenialCode::ExeMismatch,
        ] {
            assert_eq!(queue_reason(code), None, "{code:?}");
            let denied = Decision::deny(code, Vec::new(), Vec::new());
            let (_, _, err) = go(
                &FakeLink::replying(answer(denied, None)),
                &FakeHop::never(),
                &PERMITTED,
            );
            assert!(!err.contains("ido queue"), "{code:?}: {err}");
        }
    }

    #[test]
    fn the_advisory_match_never_contacts_the_broker_on_denial() {
        let link = minting();
        let hop = FakeHop::never();
        let (status, out, _) = go(&link, &hop, &["/bin/sh", "-c", "id"]);
        assert_eq!(status, 17);
        assert!(out.starts_with("DENY"), "{out}");
        assert!(link.sent.borrow().is_empty());
        assert!(hop.calls.borrow().is_empty());

        // A command no rule names is refused the same way.
        let (status, out, _) = go(&link, &hop, &["/usr/bin/nothing", "x"]);
        assert_eq!(status, 17);
        assert!(out.contains("unknown_action"), "{out}");
        assert!(link.sent.borrow().is_empty());
    }

    #[test]
    fn a_denial_from_the_broker_is_rendered_like_explain_and_exits_with_it() {
        let denied = Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new());
        let (status, out, err) = go(
            &FakeLink::replying(answer(denied, None)),
            &FakeHop::never(),
            &PERMITTED,
        );
        assert_eq!(status, 17);
        assert!(out.contains("deny_listed"), "{out}");
        assert!(err.is_empty(), "{err}");
    }

    #[test]
    fn a_settings_file_that_does_not_parse_fails_closed_before_the_broker() {
        let file = test_tmp().join("exec-bad-config.toml");
        std::fs::create_dir_all(test_tmp()).unwrap();
        std::fs::write(&file, "this is not toml = = =").unwrap();
        let link = minting();
        let (status, _, err) = go_in(
            &link,
            &FakeHop::never(),
            &SUDO,
            rules_dir(),
            &["--config-file", file.to_str().unwrap()],
            &words(&PERMITTED),
        );
        assert_eq!(status, 19);
        assert!(err.contains("failing closed"), "{err}");
        assert!(link.sent.borrow().is_empty());
    }

    /// A broker that reads one request and answers `reply`, on a socket under a
    /// path short enough for a socket address.
    fn serve_once(name: &str, reply: Vec<u8>) -> (SocketLink, std::thread::JoinHandle<Vec<u8>>) {
        use std::os::unix::net::UnixListener;
        let dir = PathBuf::from("../../target/test-tmp").join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            conn.read_to_end(&mut request).unwrap();
            let _ = conn.write_all(&reply);
            request
        });
        (SocketLink::new(socket), server)
    }

    #[test]
    fn the_socket_link_sends_the_whole_request_and_reads_the_whole_answer() {
        let (link, server) = serve_once("exec-echo", b"the answer".to_vec());
        assert_eq!(link.round_trip(b"the question").unwrap(), b"the answer");
        assert_eq!(server.join().unwrap(), b"the question");
    }

    #[test]
    fn the_socket_link_reads_one_byte_past_the_limit_and_no_more() {
        let (link, server) = serve_once("exec-flood", vec![b'x'; MAX_RESPONSE_BYTES * 2]);
        let answer = link.round_trip(b"q").unwrap();
        assert_eq!(answer.len(), MAX_RESPONSE_BYTES + 1);
        let _ = server.join();
    }

    #[test]
    fn a_broker_that_hangs_up_without_answering_is_an_empty_answer_then_a_refusal() {
        let (link, server) = serve_once("exec-mute", Vec::new());
        let hop = FakeHop::never();
        let (status, _, err) = go_in(&link, &hop, &SUDO, rules_dir(), &[], &words(&PERMITTED));
        server.join().unwrap();
        assert_eq!(status, 19);
        assert!(err.contains("could not be read"), "{err}");
        assert!(hop.calls.borrow().is_empty());
    }
}
