//! The out-of-band confirmation terminal.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::termios::{self, QueueSelector};
use xudo_policy::rule::ActionId;
pub use xudo_policy::{ExitCode, RuleSet};
pub use xudo_wire::WIRE_SCHEMA_VERSION;
pub use xudo_wire::{Answer, BrokerRequest, BrokerResponse, Question, RefusalCode, WatchPrompt};

const HEARTBEAT: Duration = Duration::from_secs(1);
const DISPLAY_LIMIT: usize = 2_000;

/// Terminal operations needed by the watcher loop.
pub trait Terminal {
    /// Whether stdin is this process's controlling terminal.
    fn is_terminal(&self) -> bool;
    /// Prepares input without changing terminal modes.
    ///
    /// # Errors
    ///
    /// Returns an error if terminal settings cannot be read or updated.
    fn begin(&mut self) -> io::Result<()>;
    /// Discards bytes typed before the current prompt appeared.
    ///
    /// # Errors
    ///
    /// Returns an error if terminal input cannot be flushed.
    fn flush_typeahead(&mut self) -> io::Result<()>;
    /// Reads a complete line if one became ready before the heartbeat interval.
    ///
    /// # Errors
    ///
    /// Returns an error if terminal input cannot be read.
    fn read_line_tick(&mut self) -> io::Result<Option<String>>;
}

/// The real terminal, accessed only by the separate `xudo watch` process.
pub struct StdTerminal {
    input: TerminalInput,
}

enum TerminalInput {
    Stdin,
    Fd(File),
}

impl StdTerminal {
    /// Creates an adapter for the current process terminal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            input: TerminalInput::Stdin,
        }
    }

    /// Uses an explicitly supplied terminal descriptor.
    #[must_use]
    pub fn from_fd(fd: OwnedFd) -> Self {
        Self {
            input: TerminalInput::Fd(File::from(fd)),
        }
    }
}

impl Default for StdTerminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminal for StdTerminal {
    fn is_terminal(&self) -> bool {
        match &self.input {
            TerminalInput::Stdin => controlling_terminal(std::io::stdin().as_fd()),
            TerminalInput::Fd(fd) => controlling_terminal(fd.as_fd()),
        }
    }

    fn begin(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn flush_typeahead(&mut self) -> io::Result<()> {
        match &self.input {
            TerminalInput::Stdin => flush_input(std::io::stdin().as_fd()),
            TerminalInput::Fd(fd) => flush_input(fd.as_fd()),
        }
    }

    fn read_line_tick(&mut self) -> io::Result<Option<String>> {
        match &self.input {
            TerminalInput::Stdin => {
                let stdin = std::io::stdin();
                read_line_tick(stdin.as_fd(), &mut stdin.lock())
            }
            TerminalInput::Fd(fd) => read_line_tick_fd(fd, &mut SystemFileCloner),
        }
    }
}

fn controlling_terminal(fd: BorrowedFd<'_>) -> bool {
    if !termios::isatty(fd) {
        return false;
    }
    matching_session(
        termios::tcgetsid(fd).ok(),
        rustix::process::getsid(None).ok(),
    )
}

fn matching_session(
    terminal: Option<rustix::process::Pid>,
    process: Option<rustix::process::Pid>,
) -> bool {
    matches!((terminal, process), (Some(terminal), Some(process)) if terminal == process)
}

trait FileCloner {
    fn clone_file(&mut self, file: &File) -> io::Result<File>;
}

struct SystemFileCloner;

impl FileCloner for SystemFileCloner {
    fn clone_file(&mut self, file: &File) -> io::Result<File> {
        file.try_clone()
    }
}

fn read_line_tick_fd(fd: &File, cloner: &mut dyn FileCloner) -> io::Result<Option<String>> {
    let mut reader = BufReader::new(cloner.clone_file(fd)?);
    read_line_tick(fd.as_fd(), &mut reader)
}

fn flush_input(fd: BorrowedFd<'_>) -> io::Result<()> {
    Ok(termios::tcflush(fd, QueueSelector::IFlush)?)
}

fn read_line_tick(fd: BorrowedFd<'_>, input: &mut dyn BufRead) -> io::Result<Option<String>> {
    read_line_tick_with(fd, input, &mut SystemPoller)
}

trait Poller {
    fn poll(
        &mut self,
        fds: &mut [PollFd<'_>],
        timeout: Option<&Timespec>,
    ) -> rustix::io::Result<usize>;
}

struct SystemPoller;

impl Poller for SystemPoller {
    fn poll(
        &mut self,
        fds: &mut [PollFd<'_>],
        timeout: Option<&Timespec>,
    ) -> rustix::io::Result<usize> {
        poll(fds, timeout)
    }
}

fn read_line_tick_with(
    fd: BorrowedFd<'_>,
    input: &mut dyn BufRead,
    poller: &mut dyn Poller,
) -> io::Result<Option<String>> {
    let mut fds = [PollFd::new(&fd, PollFlags::IN)];
    let timeout = Timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    if poller.poll(&mut fds, Some(&timeout))? == 0 {
        return Ok(None);
    }
    let mut line = String::new();
    let read = input.read_line(&mut line)?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "terminal closed",
        ));
    }
    Ok(Some(line))
}

type Ask<'a> = dyn FnMut(&Path, &BrokerRequest) -> Result<BrokerResponse, String> + 'a;

/// Lists this user's requests without requiring a terminal or answering them.
pub fn pending(
    socket: &Path,
    rules: &RuleSet,
    out: &mut dyn Write,
    err: &mut dyn Write,
    ask: &mut Ask<'_>,
) -> ExitCode {
    let request = BrokerRequest {
        schema_version: WIRE_SCHEMA_VERSION,
        question: Question::Pending,
    };
    match ask(socket, &request) {
        Ok(response) => match response.answer {
            Answer::Watching { prompts, omitted } => {
                for prompt in prompts {
                    render_prompt(&prompt, rules, out, err, true);
                }
                if omitted > 0 {
                    let _ = writeln!(
                        out,
                        "xudo: {omitted} additional pending request(s) omitted to fit the response"
                    );
                }
                ExitCode::Delegated
            }
            answer => refused_or_unusable(answer, err),
        },
        Err(error) => broker_unusable(&error, err),
    }
}

/// Watches and answers prompts, sending a heartbeat once each second.
pub fn watch_live(
    socket: &Path,
    rules: &RuleSet,
    out: &mut dyn Write,
    err: &mut dyn Write,
    ask: &mut Ask<'_>,
) -> ExitCode {
    let mut terminal = StdTerminal::new();
    watch_with(socket, rules, &mut terminal, out, err, ask)
}

/// Runs the watcher loop against injected terminal and broker seams.
pub fn watch_with(
    socket: &Path,
    rules: &RuleSet,
    terminal: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
    ask: &mut Ask<'_>,
) -> ExitCode {
    if !terminal.is_terminal() {
        let _ = writeln!(err, "xudo: watch requires a terminal on stdin");
        return ExitCode::Unusable;
    }
    if let Err(error) = terminal.begin() {
        let error = safe_error(&error);
        let _ = writeln!(err, "xudo: cannot prepare terminal input: {error}");
        return ExitCode::Unusable;
    }
    let mut active: Option<WatchPrompt> = None;
    loop {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Watch,
        };
        let response = match ask(socket, &request) {
            Ok(response) => response,
            Err(error) => return broker_unusable(&error, err),
        };
        let prompts = match response.answer {
            Answer::Watching { prompts, .. } => prompts,
            answer => return refused_or_unusable(answer, err),
        };
        let delivered = prompts.into_iter().next();
        let active_is_delivered = active
            .as_ref()
            .zip(delivered.as_ref())
            .is_some_and(|(active, delivered)| active.id == delivered.id);
        if !active_is_delivered {
            active = None;
        }
        if active.is_none()
            && let Some(prompt) = delivered
        {
            if let Err(error) = terminal.flush_typeahead() {
                let error = safe_error(&error);
                let _ = writeln!(err, "xudo: cannot flush terminal input: {error}");
                return ExitCode::Unusable;
            }
            render_prompt(&prompt, rules, out, err, false);
            active = Some(prompt);
        }
        let Some(prompt) = active.as_ref() else {
            std::thread::sleep(HEARTBEAT);
            continue;
        };
        let line = match terminal.read_line_tick() {
            Ok(Some(line)) => line,
            Ok(None) => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                let _ = writeln!(out, "xudo: watch stopped");
                return ExitCode::Delegated;
            }
            Err(error) => {
                let error = safe_error(&error);
                let _ = writeln!(err, "xudo: cannot read terminal input: {error}");
                return ExitCode::Unusable;
            }
        };
        let word = line.trim();
        let approve = word != "n";
        if word.is_empty() {
            let _ = writeln!(out, "xudo: empty answer; type the requested word or n");
            active = None;
            std::thread::sleep(HEARTBEAT);
            continue;
        }
        let answer = BrokerRequest {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            question: Question::Answer {
                id: prompt.id.clone(),
                token: word.to_owned(),
                approve,
            },
        };
        match ask(socket, &answer) {
            Ok(reply) => match reply.answer {
                Answer::Done => {
                    active = None;
                    let _ = writeln!(out, "xudo: answer recorded");
                }
                Answer::Refused {
                    code: RefusalCode::AnswerRejected,
                    ..
                } => {
                    let _ = writeln!(out, "xudo: answer rejected; checking pending requests");
                    active = None;
                }
                other => return refused_or_unusable(other, err),
            },
            Err(error) => return broker_unusable(&error, err),
        }
        std::thread::sleep(HEARTBEAT);
    }
}

fn render_prompt(
    prompt: &WatchPrompt,
    rules: &RuleSet,
    out: &mut dyn Write,
    err: &mut dyn Write,
    is_pending_list: bool,
) {
    let mut warnings = Vec::new();
    let action = clean(&prompt.action, &mut warnings);
    let id = clean(&prompt.id, &mut warnings);
    let program = clean(&prompt.program, &mut warnings);
    let program_findings = term_sanitize::flag_command_name(&prompt.program);
    if !program_findings.is_empty() {
        warnings.extend(program_findings.iter().map(ToString::to_string));
    }
    let argv = prompt
        .argv
        .iter()
        .map(|arg| escaped_display(arg, &mut warnings))
        .collect::<Vec<_>>();
    let classification = escaped_display(&prompt.classification, &mut warnings);
    let evidence = clean(&prompt.evidence, &mut warnings);
    let time = clean(&format!("{} ms", prompt.expires_in_ms), &mut warnings);
    let source = match rules.get(&ActionId::from(prompt.action.as_str())) {
        Some(item) => item.source.to_string(),
        None => "unknown source".to_owned(),
    };
    let source = clean(&source, &mut warnings);
    let command = std::iter::once(program).chain(argv).collect::<Vec<_>>();
    let command = crate::exec::display_quoted(&command);
    let command = clean(&command, &mut warnings);
    let word = prompt.action.rsplit('.').next().unwrap_or("approve");
    let word = clean(word, &mut warnings);
    for warning in warnings {
        let warning =
            term_sanitize::display_str(&warning, term_sanitize::Limits::single_line(DISPLAY_LIMIT));
        let _ = writeln!(err, "xudo: warning: {}", warning.text);
    }
    let _ = writeln!(out, "PENDING {id}");
    let _ = writeln!(out, "  command         {command}");
    let _ = writeln!(out, "  action          {action} at {source}");
    let _ = writeln!(
        out,
        "  classification  claimed (unverified): {classification}"
    );
    let _ = writeln!(out, "  broker evidence  {evidence}");
    let _ = writeln!(out, "  time left       {time}");
    if is_pending_list {
        let _ = writeln!(
            out,
            "  answer          approve in xudo watch by typing '{word}'"
        );
    } else {
        let _ = writeln!(out, "  answer          type '{word}' to approve, n to deny");
    }
    let _ = out.flush();
}

fn escape_controls(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch == '\\' {
            escaped.push_str("\\\\");
        } else if ch == '\n' {
            escaped.push_str("\\n");
        } else if ch.is_control() {
            use std::fmt::Write as _;
            let _ = write!(escaped, "\\x{:02x}", u32::from(ch));
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

fn escaped_display(value: &str, warnings: &mut Vec<String>) -> String {
    let escaped = escape_controls(value);
    let warning = "backslashes and control characters escaped for display";
    if escaped != value && !warnings.iter().any(|item| item == warning) {
        warnings.push(warning.to_owned());
    }
    clean(&escaped, warnings)
}

fn clean(value: &str, warnings: &mut Vec<String>) -> String {
    let safe = term_sanitize::display_str(value, term_sanitize::Limits::single_line(DISPLAY_LIMIT));
    warnings.extend(safe.findings.iter().map(ToString::to_string));
    safe.text
}

fn safe_error(error: &impl std::fmt::Display) -> String {
    term_sanitize::display_str(
        &error.to_string(),
        term_sanitize::Limits::single_line(DISPLAY_LIMIT),
    )
    .text
}

fn broker_unusable(error: &str, err: &mut dyn Write) -> ExitCode {
    let safe = term_sanitize::display_str(error, term_sanitize::Limits::single_line(DISPLAY_LIMIT));
    let _ = writeln!(err, "xudo: broker unavailable: {}", safe.text);
    ExitCode::Unusable
}

fn refused_or_unusable(answer: Answer, err: &mut dyn Write) -> ExitCode {
    if let Answer::Refused { code, detail, .. } = answer {
        let _ = writeln!(err, "xudo: broker refused the request ({code:?})");
        if let Some(detail) = detail {
            let safe = term_sanitize::display_str(
                &detail,
                term_sanitize::Limits::single_line(DISPLAY_LIMIT),
            );
            let _ = writeln!(err, "xudo: {detail}", detail = safe.text);
        }
        ExitCode::Unusable
    } else {
        let _ = writeln!(err, "xudo: broker returned an unexpected answer");
        ExitCode::Unusable
    }
}

/// One request and one response. Connect, the write, and the read share the
/// heartbeat as one deadline.
///
/// # Errors
///
/// Returns a connection, deadline, size, or response parsing error.
pub fn ask_live(socket: &Path, request: &BrokerRequest) -> Result<BrokerResponse, String> {
    ask_within(socket, request, HEARTBEAT)
}

/// [`ask_live`] with the deadline given, so a test over a real socket can
/// allow far longer than a loaded machine needs and never depend on the clock.
fn ask_within(
    socket: &Path,
    request: &BrokerRequest,
    deadline: Duration,
) -> Result<BrokerResponse, String> {
    let bytes = crate::exchange::exchange(socket, request.to_json().as_bytes(), deadline)?;
    BrokerResponse::parse(&bytes).map_err(display_error)
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::disallowed_methods
    )]

    use std::collections::VecDeque;
    use std::io::{self, Read};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use xudo_wire::RefusalCode;

    #[allow(clippy::struct_excessive_bools)]
    struct FakeTerminal {
        tty: bool,
        flushes: usize,
        discard_next: bool,
        fail_begin: bool,
        fail_flush: bool,
        lines: VecDeque<io::Result<Option<String>>>,
    }

    impl Terminal for FakeTerminal {
        fn is_terminal(&self) -> bool {
            self.tty
        }

        fn begin(&mut self) -> io::Result<()> {
            if self.fail_begin {
                Err(io::Error::other("begin failed"))
            } else {
                Ok(())
            }
        }

        fn flush_typeahead(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::other("flush failed"));
            }
            self.flushes = self.flushes.saturating_add(1);
            if self.discard_next {
                self.lines.pop_front();
                self.discard_next = false;
            }
            Ok(())
        }

        fn read_line_tick(&mut self) -> io::Result<Option<String>> {
            self.lines.pop_front().unwrap_or(Ok(None))
        }
    }

    fn rules() -> RuleSet {
        RuleSet::from_toml(
            "20-packages.toml",
            r#"[[action]]
id = "xudo.pkg.remove"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "remove" } }]
"#,
        )
        .unwrap()
    }

    fn prompt() -> WatchPrompt {
        WatchPrompt {
            id: "ab".repeat(32),
            action: "xudo.pkg.remove".to_owned(),
            program: "/usr/bin/apt-get".to_owned(),
            argv: vec!["remove".to_owned(), "nginx".to_owned()],
            classification: "unattested".to_owned(),
            evidence: "watch approval is pending; the password remains required".to_owned(),
            expires_in_ms: 87_000,
        }
    }

    #[test]
    fn terminal_helpers_flush_and_read_a_real_pty() {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name.to_str().unwrap())
            .unwrap();
        flush_input(slave.as_fd()).unwrap();

        let mut reader = std::io::BufReader::new(slave.try_clone().unwrap());
        assert!(read_line_tick_with(slave.as_fd(), &mut reader, &mut FailingPoller).is_err());
        assert_eq!(read_line_tick(slave.as_fd(), &mut reader).unwrap(), None);
        rustix::io::write(&master, b"remove\n").unwrap();
        assert_eq!(
            read_line_tick(slave.as_fd(), &mut reader)
                .unwrap()
                .as_deref(),
            Some("remove\n")
        );
        drop(master);
        assert_eq!(
            read_line_tick(slave.as_fd(), &mut reader)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut failed_reader = io::BufReader::new(FailedReader);
        assert!(read_line_tick_with(slave.as_fd(), &mut failed_reader, &mut SystemPoller).is_err());
        let mut failed_reader = io::BufReader::new(FailedReader);
        assert!(read_line_tick_with(slave.as_fd(), &mut failed_reader, &mut ReadyPoller).is_err());
    }

    #[test]
    fn std_terminal_does_not_treat_an_unowned_pty_as_the_controlling_terminal() {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let name = ptsname(&master, Vec::new()).unwrap();
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(name.to_str().unwrap())
            .unwrap();
        let mut terminal = StdTerminal::from_fd(slave.into());
        assert!(!terminal.is_terminal());
        terminal.begin().unwrap();
        terminal.flush_typeahead().unwrap();
        rustix::io::write(&master, b"remove\n").unwrap();
        assert_eq!(
            terminal.read_line_tick().unwrap().as_deref(),
            Some("remove\n")
        );
        drop(terminal);
        drop(master);
    }

    #[test]
    fn a_terminal_session_must_match_the_watchers_session() {
        let session = rustix::process::Pid::from_raw(10);
        let other = rustix::process::Pid::from_raw(11);
        assert!(matching_session(session, session));
        assert!(!matching_session(session, other));
        assert!(!matching_session(None, session));
    }

    struct FailingFileCloner;

    impl FileCloner for FailingFileCloner {
        fn clone_file(&mut self, _: &File) -> io::Result<File> {
            Err(io::Error::other("descriptor clone failed"))
        }
    }

    #[test]
    fn terminal_descriptor_clone_errors_are_reported() {
        let file = File::open("/dev/null").unwrap();
        assert_eq!(
            read_line_tick_fd(&file, &mut FailingFileCloner)
                .unwrap_err()
                .to_string(),
            "descriptor clone failed"
        );
    }

    #[test]
    fn terminal_syscall_errors_are_closed() {
        let file = File::open("/dev/null").unwrap();
        assert!(flush_input(file.as_fd()).is_err());
    }

    struct FailingPoller;

    impl Poller for FailingPoller {
        fn poll(
            &mut self,
            _: &mut [PollFd<'_>],
            _: Option<&Timespec>,
        ) -> rustix::io::Result<usize> {
            Err(rustix::io::Errno::IO)
        }
    }

    struct ReadyPoller;

    impl Poller for ReadyPoller {
        fn poll(
            &mut self,
            _: &mut [PollFd<'_>],
            _: Option<&Timespec>,
        ) -> rustix::io::Result<usize> {
            Ok(1)
        }
    }

    struct IdlePoller;

    impl Poller for IdlePoller {
        fn poll(
            &mut self,
            _: &mut [PollFd<'_>],
            _: Option<&Timespec>,
        ) -> rustix::io::Result<usize> {
            Ok(0)
        }
    }

    struct FailedReader;

    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read failure"))
        }
    }

    #[test]
    fn std_terminal_reports_non_terminal_input_errors() {
        let mut terminal = StdTerminal::default();
        assert!(!terminal.is_terminal());
        terminal.begin().unwrap();
        assert!(terminal.flush_typeahead().is_err());
        let _ = terminal.read_line_tick();
        let stdin = std::io::stdin();
        assert_eq!(
            read_line_tick_with(stdin.as_fd(), &mut stdin.lock(), &mut IdlePoller).unwrap(),
            None
        );
    }

    fn watching(prompts: Vec<WatchPrompt>) -> BrokerResponse {
        BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Watching {
                prompts,
                omitted: 0,
            },
        }
    }

    fn refused(code: RefusalCode, detail: Option<&str>) -> BrokerResponse {
        BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Refused {
                code,
                remediation: "retry later".to_owned(),
                detail: detail.map(str::to_owned),
            },
        }
    }

    #[test]
    fn prompt_layout_is_snapshotted() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_prompt(&prompt(), &rules(), &mut out, &mut err, false);
        insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        "###);
        assert!(err.is_empty());
    }

    #[test]
    fn prompt_without_a_local_action_source_is_snapshotted() {
        let mut prompt = prompt();
        prompt.action = "xudo.future.action".to_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_prompt(&prompt, &rules(), &mut out, &mut err, false);
        insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.future.action at unknown source
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'action' to approve, n to deny
        "###);
        assert!(err.is_empty());
    }

    #[test]
    fn displayed_io_and_wire_errors_are_snapshotted() {
        insta::assert_snapshot!(display_error(io::Error::other("socket closed")), @"socket closed");
        insta::assert_snapshot!(display_error(xudo_wire::ResponseError::Malformed {
            reason: "missing answer".to_owned(),
        }), @"the response is not a broker response: missing answer");
    }

    #[test]
    fn ansi_in_argv_is_not_rendered() {
        let mut prompt = prompt();
        *prompt.argv.get_mut(1).unwrap() = "nginx\u{1b}[31mEVIL".to_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_prompt(&prompt, &rules(), &mut out, &mut err, false);
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains('\u{1b}'));
        assert!(out.contains(r"nginx\x1b[31mEVIL"));
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: warning: backslashes and control characters escaped for display
        "###);
    }

    #[test]
    fn bidi_override_in_argv_is_flagged() {
        let mut prompt = prompt();
        *prompt.argv.get_mut(1).unwrap() = "nginx\u{202e}txt".to_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_prompt(&prompt, &rules(), &mut out, &mut err, false);
        assert!(String::from_utf8(out).unwrap().contains("nginxtxt"));
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: warning: 1 bidirectional override(s) removed — displayed order may have been forged
        "###);
    }

    #[test]
    fn a_homoglyph_program_is_flagged() {
        let mut prompt = prompt();
        prompt.program = "/usr/bin/аpt-get".to_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_prompt(&prompt, &rules(), &mut out, &mut err, false);
        assert!(String::from_utf8(out).unwrap().contains("/usr/bin/аpt-get"));
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: warning: 'а' (U+0430) looks like 'a' but is a different character
        "###);
    }

    #[test]
    fn a_newline_in_argv_cannot_draw_a_second_prompt() {
        let mut prompt = prompt();
        *prompt.argv.get_mut(1).unwrap() = "nginx\nPENDING forged".to_owned();
        prompt.argv.push(r"literal\nPENDING forged".to_owned());
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_prompt(&prompt, &rules(), &mut out, &mut err, false);
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out.lines()
                .filter(|line| line.starts_with("PENDING "))
                .count(),
            1
        );
        assert!(out.contains(r"'nginx\nPENDING forged'"), "{out}");
        assert!(out.contains(r"'literal\\nPENDING forged'"), "{out}");
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: warning: backslashes and control characters escaped for display
        "###);
    }

    #[test]
    fn argument_boundaries_are_visible() {
        let mut spaced = prompt();
        spaced.argv = vec!["a b".to_owned()];
        let mut split = prompt();
        split.argv = vec!["a".to_owned(), "b".to_owned()];
        let render = |item: &WatchPrompt| {
            let mut out = Vec::new();
            let mut err = Vec::new();
            render_prompt(item, &rules(), &mut out, &mut err, false);
            String::from_utf8(out).unwrap()
        };
        assert_ne!(render(&spaced), render(&split));
    }

    #[test]
    fn watch_refuses_to_start_without_a_terminal() {
        let mut terminal = FakeTerminal {
            tty: false,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut ask_live,
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: watch requires a terminal on stdin
        "###);
    }

    #[test]
    fn type_ahead_before_the_prompt_is_flushed() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: true,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::from([
                Ok(Some("wrong\n".to_owned())),
                Ok(None),
                Ok(Some("remove\n".to_owned())),
                Err(io::ErrorKind::Interrupted.into()),
            ]),
        };
        let mut answered = false;
        let mut watches = 0;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, request| {
                if let Question::Answer { approve, token, .. } = &request.question {
                    assert!(*approve);
                    assert_eq!(token, "remove");
                    answered = true;
                    Ok(BrokerResponse {
                        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                        answer: Answer::Done,
                    })
                } else {
                    watches += 1;
                    let mut next = prompt();
                    if watches > 2 {
                        next.id = "cd".repeat(32);
                    }
                    Ok(watching(vec![next]))
                }
            },
        );
        assert!(answered);
        assert_eq!(terminal.flushes, 2);
        assert_eq!(result, ExitCode::Delegated);
        insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        xudo: answer recorded
        PENDING cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        xudo: watch stopped
        "###);
        assert!(err.is_empty());
    }

    #[test]
    fn an_expired_prompt_does_not_block_the_next_request() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::from([
                Ok(Some("remove\n".to_owned())),
                Err(io::ErrorKind::Interrupted.into()),
            ]),
        };
        let mut answers = 0;
        let mut watches = 0;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, request| {
                if matches!(&request.question, Question::Answer { .. }) {
                    answers += 1;
                    assert_eq!(answers, 1);
                    Ok(refused(RefusalCode::AnswerRejected, None))
                } else {
                    watches += 1;
                    let mut next = prompt();
                    if watches > 1 {
                        next.id = "cd".repeat(32);
                    }
                    Ok(watching(vec![next]))
                }
            },
        );
        assert_eq!(answers, 1);
        assert_eq!(terminal.flushes, 2);
        assert_eq!(result, ExitCode::Delegated);
        insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        xudo: answer rejected; checking pending requests
        PENDING cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        xudo: watch stopped
        "###);
    }

    #[test]
    fn pending_lists_without_a_terminal_and_never_answers() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut calls: usize = 0;
        let result = pending(
            Path::new("socket"),
            &rules(),
            &mut out,
            &mut err,
            &mut |_, _request| {
                calls += 1;
                Ok(watching(vec![prompt()]))
            },
        );
        assert_eq!(result, ExitCode::Delegated);
        assert_eq!(calls, 1);
        assert!(err.is_empty());
        insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          approve in xudo watch by typing 'remove'
        "###);
    }

    #[test]
    fn pending_reports_omitted_request_count() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = pending(
            Path::new("socket"),
            &rules(),
            &mut out,
            &mut err,
            &mut |_, _| {
                Ok(BrokerResponse {
                    schema_version: WIRE_SCHEMA_VERSION,
                    answer: Answer::Watching {
                        prompts: Vec::new(),
                        omitted: 7,
                    },
                })
            },
        );
        assert_eq!(result, ExitCode::Delegated);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "xudo: 7 additional pending request(s) omitted to fit the response\n"
        );
        assert!(err.is_empty());
    }

    #[test]
    fn a_second_watcher_sees_the_first_watchers_pid_and_tty() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, _| {
                Ok(refused(
                    RefusalCode::ChannelUntrusted,
                    Some("watcher already active: pid 45, tty 34816"),
                ))
            },
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker refused the request (ChannelUntrusted)
        xudo: watcher already active: pid 45, tty 34816
        "###);
    }

    #[test]
    fn a_watcher_refusal_without_detail_is_snapshotted() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, _| Ok(refused(RefusalCode::ChannelUntrusted, None)),
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker refused the request (ChannelUntrusted)
        "###);
    }

    #[test]
    fn pending_broker_failures_are_sanitized() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = pending(
            Path::new("socket"),
            &rules(),
            &mut out,
            &mut err,
            &mut |_, _| Err("bad\u{1b}[31m socket".to_owned()),
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker unavailable: bad socket
        "###);
    }

    #[test]
    fn terminal_setup_failure_exits_unusable() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: true,
            fail_flush: false,
            lines: VecDeque::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut ask_live,
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: cannot prepare terminal input: begin failed
        "###);
    }

    #[test]
    fn terminal_flush_failure_exits_unusable() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: true,
            lines: VecDeque::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, _| Ok(watching(vec![prompt()])),
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: cannot flush terminal input: flush failed
        "###);
    }

    #[test]
    fn an_empty_answer_shows_the_pending_line_again() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::from([
                Ok(Some("\n".to_owned())),
                Ok(Some("remove\n".to_owned())),
                Err(io::ErrorKind::Interrupted.into()),
            ]),
        };
        let mut watches = 0;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, request| {
                if matches!(&request.question, Question::Answer { .. }) {
                    Ok(BrokerResponse {
                        schema_version: WIRE_SCHEMA_VERSION,
                        answer: Answer::Done,
                    })
                } else {
                    watches += 1;
                    let mut current = prompt();
                    if watches > 2 {
                        current.id = "cd".repeat(32);
                    }
                    Ok(watching(vec![current]))
                }
            },
        );
        assert_eq!(result, ExitCode::Delegated);
        assert_eq!(terminal.flushes, 3);
        insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        xudo: empty answer; type the requested word or n
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        xudo: answer recorded
        PENDING cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
          command         /usr/bin/apt-get remove nginx
          action          xudo.pkg.remove at 20-packages.toml:2
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        xudo: watch stopped
        "###);
    }

    #[test]
    fn pending_unexpected_answer_is_reported() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = pending(
            Path::new("socket"),
            &rules(),
            &mut out,
            &mut err,
            &mut |_, _| {
                Ok(BrokerResponse {
                    schema_version: WIRE_SCHEMA_VERSION,
                    answer: Answer::Done,
                })
            },
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker returned an unexpected answer
        "###);
    }

    /// A deadline a passing test never waits for, so a loaded runner cannot
    /// expire it.
    const PATIENT: Duration = Duration::from_secs(60);

    #[test]
    fn live_broker_exchange_round_trips_one_question_and_answer() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            let _request = BrokerRequest::parse(&bytes).unwrap();
            stream
                .write_all(watching(Vec::new()).to_json().as_bytes())
                .unwrap();
        });
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Pending,
        };
        let response = ask_within(&socket, &request, PATIENT).unwrap();
        assert_eq!(
            response.answer,
            Answer::Watching {
                prompts: Vec::new(),
                omitted: 0,
            }
        );
        broker.join().unwrap();
    }

    #[test]
    fn a_garbage_reply_is_not_a_broker_response() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            stream.write_all(b"not json").unwrap();
        });
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Pending,
        };
        let err = ask_within(&socket, &request, PATIENT).unwrap_err();
        assert!(err.contains("broker response"), "{err}");
        broker.join().unwrap();
    }

    #[test]
    fn live_broker_connection_failure_is_reported() {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Pending,
        };
        assert!(ask_within(Path::new("/dev/null/xudo-watch.sock"), &request, PATIENT).is_err());
    }

    #[test]
    fn watch_broker_failure_is_reported() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, _| Err("watch socket closed".to_owned()),
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker unavailable: watch socket closed
        "###);
    }

    #[test]
    fn an_unexpected_watch_answer_fails_closed() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::new(),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, _| {
                Ok(BrokerResponse {
                    schema_version: WIRE_SCHEMA_VERSION,
                    answer: Answer::Done,
                })
            },
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker returned an unexpected answer
        "###);
    }

    #[test]
    fn no_pending_prompt_keeps_the_watcher_heartbeat_alive() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::new(),
        };
        let mut calls: usize = 0;
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, _| {
                calls = calls.saturating_add(1);
                if calls == 1 {
                    Ok(watching(Vec::new()))
                } else {
                    Err("stop test loop".to_owned())
                }
            },
        );
        assert_eq!(calls, 2);
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker unavailable: stop test loop
        "###);
    }

    #[test]
    fn terminal_read_failure_exits_unusable() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::from([Err(io::Error::other("read failed"))]),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, _| Ok(watching(vec![prompt()])),
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: cannot read terminal input: read failed
        "###);
    }

    #[test]
    fn an_answer_exchange_failure_is_reported() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::from([Ok(Some("remove\n".to_owned()))]),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, request| {
                if matches!(&request.question, Question::Watch) {
                    Ok(watching(vec![prompt()]))
                } else {
                    Err("answer socket closed".to_owned())
                }
            },
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker unavailable: answer socket closed
        "###);
    }

    #[test]
    fn an_unexpected_answer_reply_fails_closed() {
        let mut terminal = FakeTerminal {
            tty: true,
            flushes: 0,
            discard_next: false,
            fail_begin: false,
            fail_flush: false,
            lines: VecDeque::from([Ok(Some("remove\n".to_owned()))]),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let result = watch_with(
            Path::new("socket"),
            &rules(),
            &mut terminal,
            &mut out,
            &mut err,
            &mut |_, request| {
                if matches!(&request.question, Question::Watch) {
                    Ok(watching(vec![prompt()]))
                } else {
                    Ok(watching(Vec::new()))
                }
            },
        );
        assert_eq!(result, ExitCode::Unusable);
        insta::assert_snapshot!(String::from_utf8(err).unwrap(), @r###"
        xudo: broker returned an unexpected answer
        "###);
    }

    #[test]
    fn a_missing_local_action_source_is_displayed_as_unknown() {
        let mut prompt = prompt();
        prompt.action = "xudo.missing.remove".to_owned();
        let mut out = Vec::new();
        let mut err = Vec::new();
        render_prompt(&prompt, &rules(), &mut out, &mut err, false);
        assert!(err.is_empty());
        insta::assert_snapshot!(String::from_utf8(out).unwrap(), @r###"
        PENDING abababababababababababababababababababababababababababababababab
          command         /usr/bin/apt-get remove nginx
          action          xudo.missing.remove at unknown source
          classification  claimed (unverified): unattested
          broker evidence  watch approval is pending; the password remains required
          time left       87000 ms
          answer          type 'remove' to approve, n to deny
        "###);
    }
}
