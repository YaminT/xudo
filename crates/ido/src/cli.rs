//! The command surface, and the boundary where the outside world becomes data.
//!
//! The binary collects the environment, the clock, the uid, and tty-ness once,
//! and hands them over as a [`Host`]. Output, typed confirmations, and the raw
//! terminal arrive as an [`Io`]. Everything below that boundary is
//! deterministic, so every command and every refusal is a unit test.

use std::ffi::OsString;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aido_audit::Outcome;
use aido_config::XdgPaths;
use clap::{ArgGroup, Args, Parser, Subcommand};

use crate::agents_doc::{self, Added};
use crate::celebrate::{Style, celebrate};
use crate::entry::Entry;
use crate::error::IdoError;
use crate::picker::{Action, CONFIRM_WORD, Picker, Terminal, pick};
use crate::render::{self, FIELD_COLS};
use crate::run::{RunContext, run_ids};
use crate::status::{Status, run_order, status_of};
use crate::store::Store;

/// The second name the binary answers to. Queued as a command, it plays the
/// acceptance celebration.
pub const CELEBRATION_NAME: &str = "willyoumarryme";

/// Everything `ido` knows about the world it is running in.
///
/// A snapshot of facts, not a state machine, so its flags are plain booleans.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct Host {
    /// `$HOME`.
    pub home: Option<PathBuf>,
    /// `$XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<String>,
    /// `$XDG_STATE_HOME`.
    pub xdg_state_home: Option<String>,
    /// `$XDG_CACHE_HOME`.
    pub xdg_cache_home: Option<String>,
    /// `$XDG_RUNTIME_DIR`.
    pub xdg_runtime_dir: Option<String>,
    /// The working directory.
    pub cwd: Option<PathBuf>,
    /// The real uid; the queue must belong to it.
    pub uid: u32,
    /// Unix seconds now.
    pub now_unix: u64,
    /// Whether stdin is a terminal.
    pub stdin_tty: bool,
    /// Whether stdout is a terminal.
    pub stdout_tty: bool,
    /// `NO_COLOR` is set.
    pub no_color: bool,
    /// `IDO_NO_ANIMATION` is set.
    pub no_animation: bool,
    /// Who is queueing, by the caller's own claim. Recorded, never trusted.
    pub queued_by: Option<String>,
    /// How long to wait for the queue lock.
    pub lock_wait: Duration,
    /// Delay between celebration frames.
    pub frame_delay: Duration,
}

/// Opens the raw terminal for the picker.
pub type OpenTerminal<'a> = dyn FnMut() -> std::io::Result<Box<dyn Terminal>> + 'a;

/// Where `ido` reads and writes.
pub struct Io<'a> {
    /// Standard output.
    pub out: &'a mut dyn Write,
    /// Standard error.
    pub err: &'a mut dyn Write,
    /// Standard input, for typed confirmations outside the picker.
    pub input: &'a mut dyn BufRead,
    /// Puts the terminal into raw mode for the picker.
    pub terminal: &'a mut OpenTerminal<'a>,
}

/// The buffered human-run command queue.
#[derive(Debug, Parser)]
#[command(
    name = "ido",
    version,
    about = "An agent queues commands; you pick what to run, in your own terminal",
    long_about = "An agent queues the commands it cannot or should not run. You run `ido`, \
                  see the queue, and choose what to run. Nothing runs without you. \
                  `ido` holds no privilege; a queued `sudo` command asks for your password \
                  as it always would."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Buffer a command for the human. Prints the id and exits; never waits.
    Queue(QueueArgs),
    /// Write the agent instructions into AGENTS.md, or the file named.
    Add {
        /// AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, or
        /// copilot-instructions.md, or a directory holding one. Relative paths
        /// may not leave the current directory.
        path: Option<PathBuf>,
    },
    /// Print the queue without the picker.
    List {
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Run entries without the picker.
    Run(RunArgs),
    /// Discard entries.
    Drop(DropArgs),
    /// Show what was run, and how it exited.
    Log {
        /// How many of the most recent runs.
        #[arg(short = 'n', default_value_t = 20)]
        n: usize,
    },
    /// Play the celebration and print `ido works.`
    Celebrate {
        /// Print the last line only.
        #[arg(long)]
        no_animation: bool,
    },
}

#[derive(Debug, Args)]
struct QueueArgs {
    /// Why. Shown to the human.
    #[arg(short = 'm', long = "reason", value_name = "TEXT")]
    reason: Option<String>,
    /// Put the command in a group of related commands.
    #[arg(long, value_name = "NAME")]
    group: Option<String>,
    /// Its place in the group; steps run one by one, in order.
    #[arg(long, value_name = "N")]
    step: Option<u32>,
    /// Wait for this queued entry to succeed first. Repeatable.
    #[arg(long, value_name = "ID")]
    needs: Vec<u64>,
    /// Directory to run in. Defaults to the current one.
    #[arg(long, value_name = "DIR")]
    cwd: Option<PathBuf>,
    /// One token of a no-side-effect preview command, shown at selection
    /// time and never run automatically. Repeat for each token.
    #[arg(long = "dry-run-of", value_name = "ARG", allow_hyphen_values = true)]
    dry_run_of: Vec<OsString>,
    /// The command, as separate arguments after `--`. Never a shell string.
    #[arg(last = true, required = true, value_name = "ARGV")]
    argv: Vec<OsString>,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("which").required(true).args(["ids", "group", "all"])))]
struct RunArgs {
    /// Entry ids, run in the order given.
    ids: Vec<u64>,
    /// Every step of this group, in order.
    #[arg(long, value_name = "NAME")]
    group: Option<String>,
    /// Everything runnable, in queue order. Failed entries are left for an
    /// explicit retry by id.
    #[arg(long)]
    all: bool,
    /// Skip the typed confirmation. For scripts only: refused on a terminal.
    #[arg(long)]
    yes: bool,
    /// Ask children that celebrate to skip the animation.
    #[arg(long)]
    no_animation: bool,
}

#[derive(Debug, Args)]
#[command(group(ArgGroup::new("which").required(true).args(["ids", "all", "stale"])))]
struct DropArgs {
    /// Entry ids.
    ids: Vec<u64>,
    /// Everything.
    #[arg(long)]
    all: bool,
    /// Everything older than the retention window.
    #[arg(long)]
    stale: bool,
}

/// Runs `ido` with `args` (including the program name) and returns the exit
/// status.
pub fn run_with(args: Vec<OsString>, host: &Host, io: &mut Io<'_>) -> i32 {
    if invoked_as_celebration(&args) {
        let quiet = args.iter().skip(1).any(|a| a == "--no-animation");
        return celebrate_command(host, quiet, io);
    }
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let text = e.render().to_string();
            let stream: &mut dyn Write = if e.use_stderr() {
                &mut *io.err
            } else {
                &mut *io.out
            };
            let _ = write!(stream, "{text}");
            return e.exit_code();
        }
    };
    match dispatch(cli, host, io) {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(io.err, "ido: {e}");
            e.exit_code()
        }
    }
}

/// Whether the program was started under its second name.
fn invoked_as_celebration(args: &[OsString]) -> bool {
    args.first()
        .and_then(|zero| Path::new(zero).file_name())
        .is_some_and(|name| name == CELEBRATION_NAME)
}

fn dispatch(cli: Cli, host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    match cli.command {
        None => picker_or_list(host, io),
        Some(Command::Queue(args)) => queue(args, host, io),
        Some(Command::Add { path }) => add(path.as_deref(), host, io),
        Some(Command::List { json }) => list(json, host, io),
        Some(Command::Run(args)) => run(&args, host, io),
        Some(Command::Drop(args)) => drop_command(&args, host, io),
        Some(Command::Log { n }) => log(n, host, io),
        Some(Command::Celebrate { no_animation }) => Ok(celebrate_command(host, no_animation, io)),
    }
}

/// The store for this user.
fn store(host: &Host) -> Result<Store, IdoError> {
    let home = host.home.as_deref().ok_or(IdoError::NoHome)?;
    let paths = XdgPaths::resolve(
        home,
        host.xdg_config_home.as_deref(),
        host.xdg_state_home.as_deref(),
        host.xdg_cache_home.as_deref(),
        host.xdg_runtime_dir.as_deref(),
    );
    Store::open(&paths.state, &paths.runtime, host.uid)
}

fn color(host: &Host) -> bool {
    host.stdout_tty && !host.no_color
}

fn ids_text(ids: &[u64]) -> String {
    ids.iter()
        .map(|id| format!("#{id}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Converts arguments to text, refusing rather than altering bytes that are
/// not UTF-8.
fn utf8_all(args: Vec<OsString>, what: &str) -> Result<Vec<String>, IdoError> {
    args.into_iter()
        .map(|a| {
            a.into_string().map_err(|_| {
                IdoError::Refused(format!(
                    "{what} contains bytes that are not UTF-8; ido stores the command as \
                     text and will not alter it to fit"
                ))
            })
        })
        .collect()
}

/// The directory a queued command will run in.
fn resolve_cwd(given: Option<&Path>, host: &Host) -> Result<Option<String>, IdoError> {
    let dir = match (given, host.cwd.as_deref()) {
        (Some(dir), _) if dir.is_absolute() => dir.to_path_buf(),
        (Some(dir), Some(here)) => here.join(dir),
        (Some(_), None) => {
            return Err(IdoError::Refused(
                "--cwd is relative and there is no current directory to resolve it against"
                    .to_owned(),
            ));
        }
        (None, Some(here)) => here.to_path_buf(),
        (None, None) => return Ok(None),
    };
    let text = utf8_all(vec![dir.into_os_string()], "the directory name")?;
    let dir = text.into_iter().next().unwrap_or_default();
    if !Path::new(&dir).is_dir() {
        return Err(IdoError::Refused(format!("{dir} is not a directory")));
    }
    Ok(Some(dir))
}

fn queue(args: QueueArgs, host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    let command = utf8_all(args.argv, "the command")?;
    let dry_run_of = utf8_all(args.dry_run_of, "--dry-run-of")?;
    let cwd = resolve_cwd(args.cwd.as_deref(), host)?;
    let store = store(host)?;
    let _lock = store.lock_waiting(host.lock_wait)?;
    let existing = store.load()?;
    if let Some(same) = existing
        .iter()
        .find(|e| e.argv == command && e.cwd == cwd && e.group == args.group && e.step == args.step)
    {
        let _ = writeln!(
            io.out,
            "ido: already queued as #{}; not queued again",
            same.id
        );
        return Ok(0);
    }
    let entry = Entry::build(
        &existing,
        command,
        args.reason,
        args.group,
        args.step,
        args.needs,
        cwd,
        dry_run_of,
        host.now_unix,
        host.queued_by.clone(),
    )?;
    store.append(&entry)?;
    let shown = render::argv_line(&entry.argv, FIELD_COLS);
    let _ = writeln!(io.out, "ido: queued #{}: {}", entry.id, shown.text);
    let _ = writeln!(io.out, "Run `ido` to execute it.");
    Ok(0)
}

fn add(path: Option<&Path>, host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    let cwd = host
        .cwd
        .as_deref()
        .ok_or_else(|| IdoError::Refused("there is no current directory".to_owned()))?;
    let file = agents_doc::target(path, cwd)?;
    let message = match agents_doc::add(&file)? {
        Added::Created(f) => format!("wrote the agent instructions to {}", f.display()),
        Added::Updated(f) => format!(
            "updated the agent instructions in {}; the original is kept beside it as \
             .ido-backup",
            f.display()
        ),
        Added::Unchanged(f) => format!("{} already has the current instructions", f.display()),
    };
    let _ = writeln!(io.out, "ido: {message}");
    Ok(0)
}

fn list(json: bool, host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    let queue = store(host)?.load()?;
    let text = if json {
        render::json(&queue, host.now_unix)
    } else {
        render::list(&queue, host.now_unix)
    };
    let _ = write!(io.out, "{text}");
    Ok(0)
}

/// `ido` with no subcommand: the picker on a terminal, the list otherwise.
fn picker_or_list(host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    if !(host.stdin_tty && host.stdout_tty) {
        return list(false, host, io);
    }
    let store = store(host)?;
    let mut message: Option<String> = None;
    loop {
        let queue = store.load()?;
        if queue.is_empty() {
            if let Some(m) = message.take() {
                let _ = writeln!(io.out, "ido: {m}");
            }
            let _ = writeln!(io.out, "ido: nothing queued");
            return Ok(0);
        }
        let mut picker = Picker::new(queue, host.now_unix, color(host));
        if let Some(m) = message.take() {
            picker = picker.with_message(m);
        }
        let mut terminal = (io.terminal)().map_err(IdoError::Terminal)?;
        let outcome = pick(terminal.as_mut(), &mut picker);
        let restored = terminal.restore();
        drop(terminal);
        let action = outcome.map_err(IdoError::Terminal)?;
        restored.map_err(IdoError::Terminal)?;
        match action {
            Action::Drop(ids) => {
                drop_matching(&store, host, &|_| Ok(ids.clone()))?;
                message = Some(format!("dropped {}", ids_text(&ids)));
            }
            Action::Run(ids) => return run_selected(&store, &ids, host, &[], io),
            Action::Quit | Action::Continue => return Ok(0),
        }
    }
}

fn run_selected(
    store: &Store,
    ids: &[u64],
    host: &Host,
    child_env: &[(String, String)],
    io: &mut Io<'_>,
) -> Result<i32, IdoError> {
    let ctx = RunContext {
        now_unix: host.now_unix,
        child_env,
        lock_wait: host.lock_wait,
    };
    let report = run_ids(store, ids, &ctx, io.out)?;
    let _ = write!(io.out, "{}", report.summary());
    Ok(report.exit_code())
}

fn run(args: &RunArgs, host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    if args.yes && host.stdin_tty {
        return Err(IdoError::Refused(
            "--yes skips the confirmation and is for scripts; on a terminal, leave it off \
             and confirm by typing run"
                .to_owned(),
        ));
    }
    if !args.yes && !host.stdin_tty {
        return Err(IdoError::Refused(
            "there is no terminal to confirm on; pass --yes to run without one".to_owned(),
        ));
    }
    let store = store(host)?;
    let queue = store.load()?;
    let ids = choose(args, &queue, host, io)?;
    if ids.is_empty() {
        let _ = writeln!(io.out, "ido: nothing to run");
        return Ok(0);
    }
    if !args.yes && !confirmed(&ids, &queue, host, io)? {
        let _ = writeln!(io.out, "ido: not confirmed; nothing ran");
        return Ok(1);
    }
    let child_env = if args.no_animation {
        vec![("IDO_NO_ANIMATION".to_owned(), "1".to_owned())]
    } else {
        Vec::new()
    };
    run_selected(&store, &ids, host, &child_env, io)
}

/// The ids a `run` names, in the order they will run.
fn choose(
    args: &RunArgs,
    queue: &[Entry],
    host: &Host,
    io: &mut Io<'_>,
) -> Result<Vec<u64>, IdoError> {
    let in_order = |keep: &dyn Fn(&Entry) -> bool| -> Vec<u64> {
        run_order(queue)
            .into_iter()
            .filter(|id| queue.iter().any(|e| e.id == *id && keep(e)))
            .collect()
    };
    if args.all {
        let failed =
            in_order(&|e| matches!(status_of(e, queue, host.now_unix), Status::Failed { .. }));
        if !failed.is_empty() {
            let _ = writeln!(
                io.out,
                "ido: leaving {} for an explicit retry by id",
                ids_text(&failed)
            );
        }
        return Ok(in_order(&|e| !failed.contains(&e.id)));
    }
    if let Some(group) = &args.group {
        let members = in_order(&|e| e.group.as_deref() == Some(group.as_str()));
        if members.is_empty() {
            return Err(IdoError::Refused(format!(
                "no queued entry is in group {}",
                render::group_name(group)
            )));
        }
        return Ok(members);
    }
    if let Some(missing) = args
        .ids
        .iter()
        .find(|id| !queue.iter().any(|e| e.id == **id))
    {
        return Err(IdoError::Refused(format!("no queued entry #{missing}")));
    }
    Ok(args.ids.clone())
}

/// Shows what will run and takes the typed confirmation.
fn confirmed(ids: &[u64], queue: &[Entry], host: &Host, io: &mut Io<'_>) -> Result<bool, IdoError> {
    let _ = writeln!(
        io.out,
        "ido: about to run, in order, stopping at the first failure:"
    );
    for entry in ids
        .iter()
        .filter_map(|id| queue.iter().find(|e| e.id == *id))
    {
        let row = render::row(entry, queue, host.now_unix);
        let _ = writeln!(io.out, "  #{} {}", entry.id, row.head);
        let _ = writeln!(io.out, "      {}", row.meta);
        for warning in &row.warnings {
            let _ = writeln!(io.out, "      {warning}");
        }
    }
    let _ = write!(io.out, "type {CONFIRM_WORD} and press enter: ");
    let _ = io.out.flush();
    let mut line = String::new();
    io.input.read_line(&mut line).map_err(IdoError::Terminal)?;
    Ok(line.trim_end_matches(['\r', '\n']) == CONFIRM_WORD)
}

/// Picks the ids to drop from the queue as it stands under the lock.
type Chooser<'a> = dyn Fn(&[Entry]) -> Result<Vec<u64>, IdoError> + 'a;

/// Chooses entries and removes them, in one pass under the lock, so the
/// choice is made against the queue that is actually rewritten.
///
/// Returns how many were dropped. An id the chooser names that is already gone
/// is not an error: the picker's view may be a moment old, and an entry that is
/// gone is dropped.
fn drop_matching(store: &Store, host: &Host, choose: &Chooser<'_>) -> Result<usize, IdoError> {
    let _lock = store.lock_waiting(host.lock_wait)?;
    let queue = store.load()?;
    let ids = choose(&queue)?;
    let before = queue.len();
    let kept: Vec<Entry> = queue.into_iter().filter(|e| !ids.contains(&e.id)).collect();
    let dropped = before.saturating_sub(kept.len());
    store.replace(&kept)?;
    Ok(dropped)
}

fn drop_command(args: &DropArgs, host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    let store = store(host)?;
    let dropped = drop_matching(&store, host, &|queue| {
        if args.all {
            return Ok(queue.iter().map(|e| e.id).collect());
        }
        if args.stale {
            return Ok(queue
                .iter()
                .filter(|e| status_of(e, queue, host.now_unix) == Status::Stale)
                .map(|e| e.id)
                .collect());
        }
        match args
            .ids
            .iter()
            .find(|id| !queue.iter().any(|e| e.id == **id))
        {
            Some(missing) => Err(IdoError::Refused(format!("no queued entry #{missing}"))),
            None => Ok(args.ids.clone()),
        }
    })?;
    let _ = writeln!(io.out, "ido: dropped {dropped}");
    Ok(0)
}

fn log(n: usize, host: &Host, io: &mut Io<'_>) -> Result<i32, IdoError> {
    let chain = store(host)?.read_log()?;
    if chain.is_empty() {
        let _ = writeln!(io.out, "ido: nothing has run yet");
        return Ok(0);
    }
    let records = chain.records();
    for record in records.iter().skip(records.len().saturating_sub(n)) {
        let when = record
            .evidence
            .iter()
            .find_map(|e| e.strip_prefix("ran_at="))
            .and_then(|t| t.parse::<u64>().ok())
            .map_or_else(|| "unknown".to_owned(), |t| render::age(host.now_unix, t));
        let outcome = match &record.outcome {
            Outcome::Exited { code } => format!("exit {code}"),
            Outcome::Signalled { signal } => format!("signal {signal}"),
            Outcome::Failed { reason } => {
                format!("could not start: {}", render::field(reason, 60).text)
            }
            Outcome::NotExecuted => "not executed".to_owned(),
        };
        let _ = writeln!(
            io.out,
            "{:>4}  {when:<9} {outcome:<12} {}",
            record.seq.get(),
            render::argv_line(&record.argv, FIELD_COLS).text
        );
    }
    Ok(0)
}

fn celebrate_command(host: &Host, no_animation: bool, io: &mut Io<'_>) -> i32 {
    let style = Style {
        animate: host.stdout_tty && !no_animation && !host.no_animation,
        color: color(host),
        frame_delay: host.frame_delay,
    };
    match celebrate(io.out, style) {
        Ok(()) => 0,
        Err(e) => {
            let _ = writeln!(io.err, "ido: {e}");
            1
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

    use std::io::Cursor;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::MetadataExt;

    use super::*;

    /// A fresh home under the workspace target dir — never `/tmp`.
    fn host(name: &str) -> Host {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("ido-cli-{name}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("work")).unwrap();
        let uid = std::fs::metadata(&root).unwrap().uid();
        Host {
            home: Some(root.join("home")),
            xdg_config_home: None,
            xdg_state_home: None,
            xdg_cache_home: None,
            xdg_runtime_dir: Some(root.join("run").to_str().unwrap().to_owned()),
            cwd: Some(root.join("work")),
            uid,
            now_unix: 1_000_000,
            stdin_tty: false,
            stdout_tty: false,
            no_color: false,
            no_animation: false,
            queued_by: Some("claude-code".into()),
            lock_wait: Duration::from_millis(20),
            frame_delay: Duration::ZERO,
        }
    }

    /// A terminal that replays scripted reads.
    struct Scripted {
        inputs: Vec<Vec<u8>>,
        fail_restore: bool,
    }

    impl Terminal for Scripted {
        fn size(&self) -> (usize, usize) {
            (100, 30)
        }
        fn read_input(&mut self) -> std::io::Result<Vec<u8>> {
            if self.inputs.is_empty() {
                return Err(std::io::Error::other("script ran out"));
            }
            Ok(self.inputs.remove(0))
        }
        fn draw(&mut self, _frame: &str) -> std::io::Result<()> {
            Ok(())
        }
        fn restore(&mut self) -> std::io::Result<()> {
            if self.fail_restore {
                return Err(std::io::Error::other("restore failed"));
            }
            Ok(())
        }
    }

    struct Outcome {
        code: i32,
        out: String,
        err: String,
    }

    /// Runs `ido` with typed `input` and one scripted terminal per picker
    /// session.
    fn ido_with(host: &Host, args: &[&str], input: &str, sessions: Vec<Scripted>) -> Outcome {
        let mut full: Vec<OsString> = vec!["ido".into()];
        full.extend(args.iter().map(OsString::from));
        run_os(host, full, input, sessions)
    }

    /// The terminal factory for a host where none can be opened.
    fn no_terminal() -> std::io::Result<Box<dyn Terminal>> {
        Err(std::io::Error::other("no terminal"))
    }

    fn run_os(host: &Host, argv: Vec<OsString>, input: &str, sessions: Vec<Scripted>) -> Outcome {
        let mut sessions = sessions.into_iter();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut reader = Cursor::new(input.as_bytes().to_vec());
        let mut open = || -> std::io::Result<Box<dyn Terminal>> {
            sessions
                .next()
                .map_or_else(no_terminal, |s| Ok(Box::new(s) as Box<dyn Terminal>))
        };
        let mut io = Io {
            out: &mut out,
            err: &mut err,
            input: &mut reader,
            terminal: &mut open,
        };
        let code = run_with(argv, host, &mut io);
        Outcome {
            code,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    fn ido(host: &Host, args: &[&str]) -> Outcome {
        ido_with(host, args, "", Vec::new())
    }

    fn queue_ids(host: &Host) -> Vec<u64> {
        store(host)
            .unwrap()
            .load()
            .unwrap()
            .iter()
            .map(|e| e.id)
            .collect()
    }

    fn tty(mut host: Host) -> Host {
        host.stdin_tty = true;
        host.stdout_tty = true;
        host
    }

    #[test]
    fn queue_prints_the_id_and_list_shows_it() {
        let h = host("queue-list");
        let q = ido(
            &h,
            &[
                "queue",
                "-m",
                "install it",
                "--",
                "apt-get",
                "install",
                "-y",
                "rg",
            ],
        );
        assert_eq!(q.code, 0, "{}", q.err);
        assert_eq!(
            q.out,
            "ido: queued #1: apt-get install -y rg\nRun `ido` to execute it.\n"
        );
        let entry = &store(&h).unwrap().load().unwrap()[0];
        assert_eq!(entry.argv, ["apt-get", "install", "-y", "rg"]);
        assert_eq!(
            entry.cwd.as_deref(),
            h.cwd.as_deref().and_then(Path::to_str)
        );
        assert_eq!(entry.queued_by.as_deref(), Some("claude-code"));

        let list = ido(&h, &["list"]);
        assert!(
            list.out.contains("#1 ready   apt-get install -y rg"),
            "{}",
            list.out
        );
        assert!(
            list.out.contains("by claude-code (unverified)"),
            "{}",
            list.out
        );
        let json = ido(&h, &["list", "--json"]);
        let parsed: serde_json::Value = serde_json::from_str(&json.out).unwrap();
        assert_eq!(parsed[0]["argv"][3], "rg");

        // Without a terminal, bare `ido` lists and runs nothing.
        let bare = ido(&h, &[]);
        assert_eq!(bare.code, 0);
        assert_eq!(bare.out, list.out);
        assert_eq!(queue_ids(&h), vec![1]);
    }

    #[test]
    fn the_same_command_is_not_queued_twice() {
        let h = host("dedup");
        ido(&h, &["queue", "--", "make", "install"]);
        let again = ido(&h, &["queue", "--", "make", "install"]);
        assert_eq!(again.code, 0);
        assert!(again.out.contains("already queued as #1"), "{}", again.out);
        assert_eq!(queue_ids(&h), vec![1]);
    }

    #[test]
    fn queue_refuses_what_it_cannot_store_faithfully() {
        let h = host("queue-refusals");
        // No `--`: clap's usage error.
        let missing = ido(&h, &["queue", "true"]);
        assert_eq!(missing.code, 2);
        assert!(!missing.err.is_empty());
        // A step without a group.
        let step = ido(&h, &["queue", "--step", "1", "--", "true"]);
        assert_eq!(step.code, 2);
        assert!(step.err.contains("--group"), "{}", step.err);
        // A directory that does not exist.
        let cwd = ido(
            &h,
            &["queue", "--cwd", "/definitely/not/here", "--", "true"],
        );
        assert_eq!(cwd.code, 2);
        assert!(cwd.err.contains("not a directory"), "{}", cwd.err);
        // Bytes that are not UTF-8, in the command and in the preview.
        for flag in [None, Some("--dry-run-of")] {
            let mut argv: Vec<OsString> = vec!["ido".into(), "queue".into()];
            if let Some(flag) = flag {
                argv.push(flag.into());
                argv.push(OsString::from_vec(vec![0xFF]));
            }
            argv.push("--".into());
            argv.push(OsString::from_vec(vec![b'x', 0xFE]));
            if flag.is_some() {
                argv.pop();
                argv.push("true".into());
            }
            let out = run_os(&h, argv, "", Vec::new());
            assert_eq!(out.code, 2);
            assert!(out.err.contains("not UTF-8"), "{}", out.err);
        }
        assert!(queue_ids(&h).is_empty());
    }

    #[test]
    fn the_working_directory_is_resolved_or_refused() {
        let h = host("cwd");
        std::fs::create_dir_all(h.cwd.as_ref().unwrap().join("sub")).unwrap();
        ido(&h, &["queue", "--cwd", "sub", "--", "true"]);
        let abs = h.cwd.as_ref().unwrap().join("sub");
        ido(
            &h,
            &["queue", "--cwd", abs.to_str().unwrap(), "--", "false"],
        );
        let entries = store(&h).unwrap().load().unwrap();
        assert_eq!(entries[0].cwd.as_deref(), abs.to_str());
        assert_eq!(entries[1].cwd.as_deref(), abs.to_str());

        let mut nowhere = host("cwd-none");
        nowhere.cwd = None;
        let relative = ido(&nowhere, &["queue", "--cwd", "sub", "--", "true"]);
        assert!(
            relative.err.contains("no current directory"),
            "{}",
            relative.err
        );
        assert_eq!(ido(&nowhere, &["queue", "--", "true"]).code, 0);
        assert_eq!(store(&nowhere).unwrap().load().unwrap()[0].cwd, None);
    }

    #[test]
    fn help_goes_to_stdout_and_a_bad_command_to_stderr() {
        let h = host("help");
        let help = ido(&h, &["--help"]);
        assert_eq!(help.code, 0);
        assert!(help.out.contains("ido"), "{}", help.out);
        let bad = ido(&h, &["frobnicate"]);
        assert_eq!(bad.code, 2);
        assert!(!bad.err.is_empty());
    }

    #[test]
    fn without_a_home_there_is_no_queue() {
        let mut h = host("no-home");
        h.home = None;
        let out = ido(&h, &["list"]);
        assert_eq!(out.code, 1);
        assert!(out.err.contains("no home directory"), "{}", out.err);
    }

    #[test]
    fn run_confirms_on_a_terminal_and_refuses_yes_there() {
        let h = tty(host("run-tty"));
        ido(&h, &["queue", "--", "true"]);
        let yes = ido(&h, &["run", "1", "--yes"]);
        assert_eq!(yes.code, 2);
        assert!(yes.err.contains("for scripts"), "{}", yes.err);

        let declined = ido_with(&h, &["run", "1"], "no\n", Vec::new());
        assert_eq!(declined.code, 1);
        assert!(
            declined.out.contains("type run and press enter"),
            "{}",
            declined.out
        );
        assert!(declined.out.contains("nothing ran"), "{}", declined.out);
        assert_eq!(queue_ids(&h), vec![1]);

        let confirmed = ido_with(&h, &["run", "1"], "run\n", Vec::new());
        assert_eq!(confirmed.code, 0, "{}", confirmed.out);
        assert!(
            confirmed.out.contains("ido: 1 succeeded"),
            "{}",
            confirmed.out
        );
        assert!(queue_ids(&h).is_empty());
    }

    #[test]
    fn run_without_a_terminal_needs_yes() {
        let h = host("run-notty");
        ido(&h, &["queue", "--", "true"]);
        let out = ido(&h, &["run", "--all"]);
        assert_eq!(out.code, 2);
        assert!(out.err.contains("pass --yes"), "{}", out.err);
        assert_eq!(queue_ids(&h), vec![1]);
    }

    #[test]
    fn an_unreadable_confirmation_is_an_error_not_a_yes() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("stdin gone"))
            }
        }
        let h = tty(host("run-broken-input"));
        ido(&h, &["queue", "--", "true"]);
        let mut reader = std::io::BufReader::new(Broken);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut open = no_terminal;
        let mut io = Io {
            out: &mut out,
            err: &mut err,
            input: &mut reader,
            terminal: &mut open,
        };
        let code = run_with(vec!["ido".into(), "run".into(), "1".into()], &h, &mut io);
        assert_eq!(code, 1);
        assert!(String::from_utf8(err).unwrap().contains("stdin gone"));
        assert_eq!(queue_ids(&h), vec![1]);
    }

    #[test]
    fn a_failed_step_halts_its_group_and_all_leaves_it_for_retry() {
        let h = host("group");
        ido(
            &h,
            &["queue", "--group", "deploy", "--step", "1", "--", "false"],
        );
        ido(
            &h,
            &["queue", "--group", "deploy", "--step", "2", "--", "true"],
        );
        let group = ido(&h, &["run", "--group", "deploy", "--yes"]);
        assert_eq!(group.code, 1);
        assert!(group.out.contains("#1 failed with exit 1"), "{}", group.out);
        assert!(
            group.out.contains("not run after the failure: #2"),
            "{}",
            group.out
        );

        let all = ido(&h, &["run", "--all", "--yes"]);
        assert_eq!(all.code, 1);
        assert!(
            all.out.contains("leaving #1 for an explicit retry"),
            "{}",
            all.out
        );
        assert!(all.out.contains("skipped #2: halted"), "{}", all.out);
        assert_eq!(queue_ids(&h), vec![1, 2]);
    }

    #[test]
    fn run_refuses_what_is_not_queued() {
        let h = host("run-missing");
        let id = ido(&h, &["run", "7", "--yes"]);
        assert_eq!(id.code, 2);
        assert!(id.err.contains("no queued entry #7"), "{}", id.err);
        let group = ido(&h, &["run", "--group", "nope", "--yes"]);
        assert!(
            group.err.contains("no queued entry is in group nope"),
            "{}",
            group.err
        );
        let all = ido(&h, &["run", "--all", "--yes"]);
        assert_eq!(all.code, 0);
        assert_eq!(all.out, "ido: nothing to run\n");
        assert_eq!(
            ido(&h, &["run", "--yes"]).code,
            2,
            "one of ids, --group, --all"
        );
    }

    #[test]
    fn no_animation_is_passed_to_children() {
        let h = host("no-animation");
        ido(
            &h,
            &["queue", "--", "sh", "-c", "test \"$IDO_NO_ANIMATION\" = 1"],
        );
        let out = ido(&h, &["run", "--all", "--yes", "--no-animation"]);
        assert_eq!(out.code, 0, "{}", out.out);
    }

    #[test]
    fn drop_by_id_stale_and_all() {
        let mut h = host("drop");
        ido(&h, &["queue", "--", "a"]);
        h.now_unix = 2_000_000;
        ido(&h, &["queue", "--", "b"]);
        ido(&h, &["queue", "--", "c"]);
        let missing = ido(&h, &["drop", "9"]);
        assert_eq!(missing.code, 2);
        assert_eq!(ido(&h, &["drop", "3"]).out, "ido: dropped 1\n");
        assert_eq!(ido(&h, &["drop", "--stale"]).out, "ido: dropped 1\n");
        assert_eq!(queue_ids(&h), vec![2]);
        assert_eq!(ido(&h, &["drop", "--all"]).out, "ido: dropped 1\n");
        assert!(queue_ids(&h).is_empty());
    }

    #[test]
    fn the_log_shows_every_fate() {
        let h = host("log");
        assert_eq!(ido(&h, &["log"]).out, "ido: nothing has run yet\n");
        for argv in [
            vec!["true"],
            vec!["/definitely/not/a/program"],
            vec!["sh", "-c", "kill -9 $$"],
        ] {
            let mut args = vec!["queue", "--"];
            args.extend(argv);
            ido(&h, &args);
        }
        for id in ["1", "2", "3"] {
            ido(&h, &["run", id, "--yes"]);
        }
        // A record with no time and no execution, written by another tool.
        let store = store(&h).unwrap();
        let chain = store.read_log().unwrap();
        store
            .append_log(&aido_audit::Record::after(
                chain.records().last(),
                aido_audit::Decision::Denied,
                vec!["x".into()],
                "other",
            ))
            .unwrap();
        let log = ido(&h, &["log"]);
        assert_eq!(log.code, 0);
        let lines: Vec<&str> = log.out.lines().collect();
        assert_eq!(lines.len(), 4, "{}", log.out);
        let (first, second, third, fourth) = (lines[0], lines[1], lines[2], lines[3]);
        assert!(
            first.contains("exit 0") && first.contains("just now"),
            "{first}"
        );
        assert!(second.contains("could not start"), "{second}");
        assert!(third.contains("signal 9"), "{third}");
        assert!(
            fourth.contains("unknown") && fourth.contains("not executed"),
            "{fourth}"
        );
        assert_eq!(ido(&h, &["log", "-n", "1"]).out.lines().count(), 1);
    }

    #[test]
    fn celebrate_by_command_and_by_second_name() {
        let mut h = host("celebrate");
        assert_eq!(ido(&h, &["celebrate"]).out, "ido works.\n");
        let named = run_os(
            &h,
            vec!["/usr/local/bin/willyoumarryme".into()],
            "",
            Vec::new(),
        );
        assert_eq!(named.code, 0);
        assert_eq!(named.out, "ido works.\n");
        // On a terminal it animates, unless told not to either way.
        h.stdout_tty = true;
        let animated = ido(&h, &["celebrate"]);
        assert!(animated.out.len() > "ido works.\n".len());
        assert!(animated.out.ends_with("ido works.\n"));
        assert_eq!(
            ido(&h, &["celebrate", "--no-animation"]).out,
            "ido works.\n"
        );
        let quiet = run_os(
            &h,
            vec!["willyoumarryme".into(), "--no-animation".into()],
            "",
            Vec::new(),
        );
        assert_eq!(quiet.out, "ido works.\n");
        h.no_animation = true;
        assert_eq!(ido(&h, &["celebrate"]).out, "ido works.\n");
    }

    #[test]
    fn a_celebration_that_cannot_write_says_so() {
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let h = host("celebrate-full");
        let (mut out, mut err, mut input) = (Full, Vec::new(), Cursor::new(Vec::new()));
        let mut open = no_terminal;
        let mut io = Io {
            out: &mut out,
            err: &mut err,
            input: &mut input,
            terminal: &mut open,
        };
        assert_eq!(
            run_with(vec!["ido".into(), "celebrate".into()], &h, &mut io),
            1
        );
        assert!(String::from_utf8(err).unwrap().contains("disk full"));
        assert!(out.flush().is_ok(), "only writing fails");
    }

    #[test]
    fn add_writes_then_updates_then_leaves_alone() {
        let h = host("add");
        let first = ido(&h, &["add"]);
        assert!(
            first.out.contains("wrote the agent instructions"),
            "{}",
            first.out
        );
        let same = ido(&h, &["add"]);
        assert!(same.out.contains("already has the current"), "{}", same.out);
        std::fs::write(h.cwd.as_ref().unwrap().join("CLAUDE.md"), "# mine\n").unwrap();
        let updated = ido(&h, &["add", "CLAUDE.md"]);
        assert!(
            updated.out.contains("updated the agent instructions"),
            "{}",
            updated.out
        );
        let escape = ido(&h, &["add", "../AGENTS.md"]);
        assert_eq!(escape.code, 2);

        let mut nowhere = host("add-nowhere");
        nowhere.cwd = None;
        assert!(ido(&nowhere, &["add"]).err.contains("no current directory"));
    }

    #[test]
    fn the_picker_runs_what_was_selected() {
        let h = tty(host("picker-run"));
        ido(&h, &["queue", "--", "true"]);
        let session = Scripted {
            inputs: vec![b" \r".to_vec()],
            fail_restore: false,
        };
        let out = ido_with(&h, &[], "", vec![session]);
        assert_eq!(out.code, 0, "{}{}", out.out, out.err);
        assert!(out.out.contains("ido: running #1: true"), "{}", out.out);
        assert!(queue_ids(&h).is_empty());
        // And an empty queue says so instead of opening a picker.
        assert_eq!(ido(&h, &[]).out, "ido: nothing queued\n");
    }

    #[test]
    fn the_picker_drops_then_reopens_or_quits() {
        let h = tty(host("picker-drop"));
        ido(&h, &["queue", "--", "a"]);
        ido(&h, &["queue", "--", "b"]);
        let drop_one = Scripted {
            inputs: vec![b"dy".to_vec()],
            fail_restore: false,
        };
        let quit = Scripted {
            inputs: vec![b"q".to_vec()],
            fail_restore: false,
        };
        let out = ido_with(&h, &[], "", vec![drop_one, quit]);
        assert_eq!(out.code, 0, "{}", out.err);
        assert_eq!(queue_ids(&h), vec![2]);

        let drop_last = Scripted {
            inputs: vec![b"dy".to_vec()],
            fail_restore: false,
        };
        let out = ido_with(&h, &[], "", vec![drop_last]);
        assert_eq!(out.out, "ido: dropped #2\nido: nothing queued\n");
    }

    #[test]
    fn terminal_failures_are_reported_and_run_nothing() {
        let h = tty(host("picker-fail"));
        ido(&h, &["queue", "--", "true"]);
        // No terminal could be opened.
        let none = ido_with(&h, &[], "", Vec::new());
        assert_eq!(none.code, 1);
        assert!(none.err.contains("terminal: no terminal"), "{}", none.err);
        // Reading failed mid-pick.
        let dead = Scripted {
            inputs: Vec::new(),
            fail_restore: false,
        };
        assert!(
            ido_with(&h, &[], "", vec![dead])
                .err
                .contains("script ran out")
        );
        // The pick worked but restoring the terminal did not: refuse to run on
        // a terminal left in raw mode.
        let sticky = Scripted {
            inputs: vec![b" \r".to_vec()],
            fail_restore: true,
        };
        let out = ido_with(&h, &[], "", vec![sticky]);
        assert!(out.err.contains("restore failed"), "{}", out.err);
        assert_eq!(queue_ids(&h), vec![1]);
    }

    /// Appends a line no version of `ido` wrote.
    fn corrupt_queue(host: &Host) {
        let path = store(host).unwrap().queue_path().to_path_buf();
        let mut text = std::fs::read_to_string(&path).unwrap_or_default();
        text.push_str("{\"tampered\":true}\n");
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn every_command_fails_closed_without_a_home() {
        let commands: [&[&str]; 7] = [
            &["queue", "--", "true"],
            &["list"],
            &[],
            &["run", "--all", "--yes"],
            &["drop", "--all"],
            &["log"],
            &["run", "1"],
        ];
        for (i, args) in commands.into_iter().enumerate() {
            let mut h = host(&format!("no-home-{i}"));
            h.home = None;
            // The last one on a terminal, so the picker path is checked too.
            if i == 6 {
                h = tty(h);
            }
            let out = ido(&h, args);
            assert_eq!(out.code, 1, "{args:?}");
            assert!(
                out.err.contains("no home directory"),
                "{args:?}: {}",
                out.err
            );
        }
        let mut picker = tty(host("no-home-picker"));
        picker.home = None;
        assert!(ido(&picker, &[]).err.contains("no home directory"));
    }

    #[test]
    fn every_command_refuses_a_tampered_queue() {
        let h = host("tampered");
        ido(&h, &["queue", "--", "true"]);
        corrupt_queue(&h);
        for args in [
            &["queue", "--", "false"][..],
            &["list"],
            &["run", "--all", "--yes"],
            &["drop", "--all"],
        ] {
            let out = ido(&h, args);
            assert_eq!(out.code, 1, "{args:?}");
            assert!(
                out.err.contains("cannot be parsed"),
                "{args:?}: {}",
                out.err
            );
        }
        let picker = ido(&tty(h.clone()), &[]);
        assert!(picker.err.contains("cannot be parsed"), "{}", picker.err);

        let log = store(&h).unwrap().log_path().to_path_buf();
        std::fs::write(log, "not a record\n").unwrap();
        assert!(ido(&h, &["log"]).err.contains("is unreadable"));
    }

    #[test]
    fn a_held_lock_stops_drops_and_runs_cleanly() {
        let h = tty(host("lock-everywhere"));
        ido(&h, &["queue", "--", "true"]);
        let store = store(&h).unwrap();
        let held = store.lock().unwrap();
        let mut script = h.clone();
        script.stdin_tty = false;
        assert!(
            ido(&script, &["drop", "1"])
                .err
                .contains("another ido process")
        );
        assert!(
            ido(&script, &["run", "1", "--yes"])
                .err
                .contains("another ido process")
        );
        let session = Scripted {
            inputs: vec![b"dy".to_vec()],
            fail_restore: false,
        };
        let picker = ido_with(&h, &[], "", vec![session]);
        assert!(picker.err.contains("another ido process"), "{}", picker.err);
        drop(held);
        assert_eq!(queue_ids(&h), vec![1]);
    }

    #[test]
    fn a_drop_that_cannot_rewrite_the_queue_changes_nothing() {
        let h = host("drop-blocked");
        ido(&h, &["queue", "--", "true"]);
        let queue = store(&h).unwrap().queue_path().to_path_buf();
        let tmp = queue.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = ido(&h, &["drop", "--all"]);
        assert_eq!(out.code, 1);
        assert!(out.err.starts_with("ido: create"), "{}", out.err);
        std::fs::remove_dir_all(tmp).unwrap();
        assert_eq!(queue_ids(&h), vec![1]);
    }

    #[test]
    fn a_queue_that_cannot_be_appended_to_says_so() {
        use std::os::unix::fs::PermissionsExt;
        let h = host("append-blocked");
        ido(&h, &["queue", "--", "true"]);
        let queue = store(&h).unwrap().queue_path().to_path_buf();
        std::fs::set_permissions(&queue, std::fs::Permissions::from_mode(0o400)).unwrap();
        let out = ido(&h, &["queue", "--", "false"]);
        // Root ignores file modes, so the refusal is only observable without it.
        assert!(
            h.uid == 0 || (out.code == 1 && out.err.starts_with("ido: open")),
            "{}",
            out.err
        );
    }

    #[test]
    fn a_relative_cwd_that_is_not_utf8_is_refused_before_anything_else() {
        let h = host("cwd-bytes");
        let argv = vec![
            "ido".into(),
            "queue".into(),
            "--cwd".into(),
            OsString::from_vec(vec![b'd', 0xFF]),
            "--".into(),
            "true".into(),
        ];
        let out = run_os(&h, argv, "", Vec::new());
        assert_eq!(out.code, 2);
        assert!(
            out.err.contains("directory name contains bytes"),
            "{}",
            out.err
        );
    }

    #[test]
    fn add_reports_a_refused_file() {
        let h = host("add-symlink");
        let cwd = h.cwd.clone().unwrap();
        std::fs::write(cwd.join("elsewhere.md"), "x").unwrap();
        std::os::unix::fs::symlink(cwd.join("elsewhere.md"), cwd.join("AGENTS.md")).unwrap();
        let out = ido(&h, &["add"]);
        assert_eq!(out.code, 2);
        assert!(out.err.contains("symlink"), "{}", out.err);
    }

    #[test]
    fn the_man_page_documents_every_subcommand() {
        use clap::CommandFactory;
        let page = include_str!("../../../docs/man/ido.1");
        for sub in Cli::command().get_subcommands() {
            let name = sub.get_name();
            assert!(
                page.contains(&format!(".B ido {name}")) && page.contains(&format!(".B {name}\n")),
                "ido(1) does not document `ido {name}`"
            );
        }
    }

    #[test]
    fn a_held_lock_turns_a_queue_into_a_clear_error() {
        let h = host("locked");
        ido(&h, &["queue", "--", "true"]);
        let store = store(&h).unwrap();
        let _held = store.lock().unwrap();
        let out = ido(&h, &["queue", "--", "false"]);
        assert_eq!(out.code, 1);
        assert!(out.err.contains("another ido process holds"), "{}", out.err);
    }
}
