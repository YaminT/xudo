//! The command surface.
//!
//! The password-authenticated privileged path is built. Passwordless agent
//! execution is not available in this beta.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};
use xudo_backend::paths_to_root::HostView;
use xudo_backend::{BackendKind, InstallPlan, PlanStep, Probe, detect, uninstall_plan};
use xudo_config::report::{self, ListOptions};
use xudo_config::{Layer, Setting, Settings as ConfigSettings, Value as ConfigValue, apply_file};
use xudo_policy::{
    Arg, Argv, CallerFacts, Decision, DenialCode, ExitCode, Request, RuleSet, Verdict,
    engine::Settings,
};
use xudo_sys::{
    HostInstaller, HostProbe, HostRunner, InstallReport, Installer, LiveHost, PrivilegedOps,
    RefusingInstaller, Runner, Verification, host_ops,
};

use crate::agentdoc::{self, DocFormat};
use crate::doctor;
use crate::exec;
use crate::probe::BrokerProbe;
use crate::render;
use crate::rules::{DEFAULT_RULES_DIR, LoadedRules};
use crate::watch;

/// The root-owned settings file.
pub const DEFAULT_CONFIG_FILE: &str = "/etc/xudo/config.toml";

/// How to render output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Prose, with the decision trace.
    Human,
    /// The versioned decision envelope.
    Json,
}

/// Linux privilege broker. This beta uses the human password path.
#[derive(Debug, Parser)]
#[command(
    name = "xudo",
    version = concat!(env!("CARGO_PKG_VERSION"), " (beta, not externally audited)"),
    about = "Linux privilege broker; this beta uses the human password path",
    long_about = "xudo checks requests against root-owned rules. `xudo exec` uses the \
                  password-authenticated path through the host backend. The passwordless \
                  agent path is not available in this beta (M4)."
)]
pub struct Cli {
    /// Directory of rule files to load.
    #[arg(long, global = true, default_value = DEFAULT_RULES_DIR, value_name = "DIR")]
    pub rules: PathBuf,

    /// The global settings file.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_FILE, value_name = "FILE")]
    pub config_file: PathBuf,

    /// Output format.
    #[arg(long, global = true, value_enum, default_value_t = Format::Human)]
    pub output: Format,

    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Arguments shared by the commands that evaluate an argv.
#[derive(Debug, Args)]
pub struct EvalArgs {
    /// Ask about this action instead of searching the ruleset for one. Every
    /// other action that accepts the same command still contributes its
    /// requirement: overlapping rules resolve to the strictest.
    #[arg(long, value_name = "ACTION_ID")]
    pub action: Option<String>,

    /// The command and its arguments, after `--`.
    #[arg(trailing_var_arg = true, value_name = "ARGV")]
    pub argv: Vec<String>,
}

/// What `xudo config` can do.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print one setting's effective value.
    Get {
        /// The setting, as written in the settings file.
        key: String,
        /// Also name the file and line (or `<default>`, `<compiled-in>`).
        #[arg(long)]
        origin: bool,
    },
    /// List settings. Without `--effective`, only those a file set.
    List {
        /// Add the origin of each value.
        #[arg(long)]
        origin: bool,
        /// Include defaults and compiled-in values.
        #[arg(long)]
        effective: bool,
    },
    /// Print the machine-readable schema, so an editor or an agent can validate
    /// a settings file before it is installed.
    Schema {
        /// Accepted for symmetry; the schema is always JSON.
        #[arg(long)]
        json: bool,
    },
}

/// The subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show what the policy would decide, and why. Executes nothing.
    Explain(EvalArgs),

    /// Show why one specific action would refuse this argv.
    WhyNot {
        /// The action to interrogate.
        #[arg(long, value_name = "ACTION_ID")]
        action: String,

        /// The command and its arguments, after `--`.
        #[arg(trailing_var_arg = true, value_name = "ARGV")]
        argv: Vec<String>,
    },

    /// Run a command as root, if the broker permits it. Asks for your password.
    Exec {
        /// The command and its arguments, after `--`. The program is an absolute path.
        #[arg(trailing_var_arg = true, required = true, value_name = "ARGV")]
        argv: Vec<String>,
    },

    /// Lint the ruleset. Exits non-zero if anything is wrong with it.
    Check,

    /// List the effective policy.
    List {
        /// Show only this tier.
        #[arg(long, value_name = "TIER")]
        tier: Option<String>,
    },

    /// Report the platform, the ruleset, how this caller would be classified,
    /// and every other path to root on this machine.
    ///
    /// Reads as you. What you cannot read is reported as unverified, never as
    /// absent: run it as root as well to read what this account cannot.
    Doctor {
        /// Print the versioned machine-readable envelope instead of prose.
        /// The same as `--output json`.
        #[arg(long)]
        json: bool,

        /// Also propose a fix for each path to root: what it means, and the
        /// exact command a human runs. Applies nothing.
        #[arg(long)]
        fix: bool,
    },

    /// Show the effective configuration and where each value came from.
    ///
    /// With no subcommand, lists every setting with its origin. `get`, `list`
    /// and `schema` follow `git config`.
    Config {
        /// Print the machine-readable schema instead of the current values.
        #[arg(long)]
        schema: bool,

        /// What to do; with none, the full report.
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// Integrate xudo with the local sudo or doas backend, or remove it again.
    ///
    /// Needs root. Every step is validated by the backend's own parser before
    /// anything is moved into place, and only files xudo wrote are ever replaced
    /// or removed. `--dry-run` prints the plan and changes nothing.
    ///
    /// An install is reported as verified only when the functional probe passed:
    /// the broker minted a request for `id -u`, the gate ran through the backend
    /// and printed `0`, and the backend lists the gate for a member of the group.
    /// Anything less (no broker running yet, or a probe that ran and failed)
    /// keeps the validated install, then says NOT VERIFIED and exits non-zero.
    Install {
        /// Print the plan without performing any step.
        #[arg(long)]
        dry_run: bool,

        /// Print the file contents each step would write, not just its summary.
        #[arg(long)]
        show_contents: bool,

        /// Remove what an install wrote, and nothing else.
        #[arg(long)]
        uninstall: bool,
    },

    /// Verify that the audit log has not been edited.
    Audit {
        /// The log to read. Defaults to `$HOME/.local/state/ido/log.jsonl`;
        /// pass this if `XDG_STATE_HOME` is set, because the environment is not
        /// consulted.
        #[arg(long, value_name = "PATH")]
        log: Option<PathBuf>,

        /// Compare file records with the journal's root-written xudo entries.
        /// This can expose records removed from the end or replaced after a cut.
        #[arg(long)]
        against_journal: bool,
    },

    /// List pending confirmation requests without answering them.
    Pending,

    /// Watch for confirmation requests on this terminal and answer them.
    Watch,

    /// Stop your own agents' requests until thawed (root: everyone's).
    Freeze {
        /// Why the broker is being frozen.
        #[arg(long, required = true, value_name = "TEXT")]
        reason: String,
    },

    /// Lift your own freeze (root lifts every freeze). Not for agents.
    Thaw,

    /// Print the block that tells an agent what it may do.
    Agentdoc {
        /// Which harness to write for.
        #[arg(long, value_enum, default_value = "agents")]
        format: DocFormatArg,
    },
}

/// `--format` for `agentdoc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum DocFormatArg {
    /// `CLAUDE.md`.
    Claude,
    /// `AGENTS.md`.
    Agents,
    /// Codex CLI.
    Codex,
}

impl From<DocFormatArg> for DocFormat {
    fn from(arg: DocFormatArg) -> Self {
        match arg {
            DocFormatArg::Claude => Self::Claude,
            DocFormatArg::Agents => Self::Agents,
            DocFormatArg::Codex => Self::Codex,
        }
    }
}

/// What the entry point collected from the process, once, as data.
///
/// The library reads no environment. The one variable it reports on is handed
/// to it here, by `xudo-bin`, so that nothing in a decision path can reach for
/// another.
#[derive(Clone, Debug, Default)]
pub struct Invocation {
    /// `PATH` as the caller exported it. `doctor` inspects its entries for a
    /// directory anyone else can write ahead of the backend; nothing searches
    /// it and nothing decides on it.
    pub path: Option<OsString>,
}

/// What a command runs against: this machine, or a test's description of one.
#[derive(Clone, Copy)]
pub struct Platform<'a> {
    /// Classification, kernel facts, and executable resolution.
    pub ops: &'a dyn PrivilegedOps,
    /// The backend detector's questions.
    pub probe: &'a dyn Probe,
    /// The filesystem and credentials, as the report of other paths to root
    /// sees them.
    pub host: &'a dyn HostView,
    /// `PATH`, as [`Invocation::path`].
    pub path: Option<&'a OsStr>,
}

/// Runs a parsed command, writing to `out` and `err`.
///
/// Returns the process exit status. Every failure path returns a non-zero
/// [`ExitCode`]; there is no path that reports success on an error.
pub fn run(
    cli: &Cli,
    invocation: &Invocation,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let ops = host_ops();
    let platform = Platform {
        ops: ops.as_ref(),
        probe: &HostProbe,
        host: &LiveHost,
        path: invocation.path.as_deref(),
    };
    let probe = BrokerProbe::live(&HostRunner);
    run_with_installer(cli, &platform, &HostInstaller::new(&probe), out, err)
}

/// Runs a parsed command against an injected platform.
///
/// The platform is a parameter rather than a global so the fail-closed branches
/// — a caller that cannot be observed, a platform that cannot attest — are
/// reachable from a test. A branch that only executes on a broken machine is a
/// branch that only gets exercised on a broken machine.
///
/// Cannot modify the machine: `install` without `--dry-run` is refused here, so
/// a caller that injects a platform for a test is never one `sudo` away from
/// writing under `/etc`.
pub fn run_with(
    cli: &Cli,
    platform: &Platform<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    run_with_installer(cli, platform, &RefusingInstaller, out, err)
}

/// [`run_with`], with the installer injected as well.
pub fn run_with_installer(
    cli: &Cli,
    platform: &Platform<'_>,
    installer: &dyn Installer,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    run_with_installer_at_socket(
        cli,
        platform,
        installer,
        Path::new(xudo_wire::BROKER_SOCKET),
        out,
        err,
    )
}

/// [`run_with_installer`], with the broker socket supplied by the caller.
pub fn run_with_installer_at_socket(
    cli: &Cli,
    platform: &Platform<'_>,
    installer: &dyn Installer,
    socket: &Path,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let ops = platform.ops;
    let probe = platform.probe;
    // Loaded up front but not unwrapped: `doctor` is the command an operator
    // reaches for precisely when the ruleset is broken, so it must not require
    // the broken thing.
    let loaded = LoadedRules::from_dir(&cli.rules);

    macro_rules! with_rules {
        ($body:expr) => {
            match &loaded {
                Ok(loaded) => $body(loaded),
                Err(load_err) => {
                    let _ = writeln!(err, "xudo: {load_err}");
                    let _ = writeln!(
                        err,
                        "xudo: failing closed; run `xudo doctor` for the platform report"
                    );
                    return ExitCode::Unusable;
                }
            }
        };
    }

    match &cli.command {
        Command::Doctor { json, fix } => doctor::run(
            &cli.rules,
            loaded.as_ref(),
            platform,
            *json || cli.output == Format::Json,
            *fix,
            out,
        ),
        Command::Config { schema, action } => config(cli, *schema, action.as_ref(), out, err),
        Command::Install {
            dry_run,
            show_contents,
            uninstall,
        } => install(
            probe,
            installer,
            InstallMode {
                dry_run: *dry_run,
                show_contents: *show_contents,
                uninstall: *uninstall,
            },
            out,
            err,
        ),
        Command::Explain(args) => {
            with_rules!(|l: &LoadedRules| explain(cli, ops, l, args, out, err))
        }
        Command::WhyNot { action, argv } => {
            with_rules!(|l: &LoadedRules| why_not(cli, ops, l, action, argv, out, err))
        }
        // The library never execs; `xudo-bin` calls `exec::plan_live` and does that.
        Command::Exec { argv } => {
            let Some(wait) = exec::configured_timeout(cli, err) else {
                return ExitCode::Unusable;
            };
            exec::plan_with_confirmation_timeout(
                cli,
                argv,
                probe,
                Path::new(xudo_wire::BROKER_SOCKET),
                exec::TIMEOUT,
                wait,
                out,
                err,
            )
            .err()
            .unwrap_or(ExitCode::Unusable)
        }
        Command::Check => with_rules!(|l: &LoadedRules| check(l, out, err)),
        Command::List { tier } => {
            with_rules!(|l: &LoadedRules| list(l, tier.as_deref(), out, err))
        }
        Command::Audit {
            log,
            against_journal,
        } => audit(
            log.clone().or_else(default_log_file),
            *against_journal,
            &HostRunner,
            out,
            err,
        ),
        Command::Pending => with_rules!(|l: &LoadedRules| {
            watch::pending(socket, l.rules(), out, err, &mut watch::ask_live)
        }),
        Command::Watch => with_rules!(|l: &LoadedRules| {
            watch::watch_live(socket, l.rules(), out, err, &mut watch::ask_live)
        }),
        Command::Freeze { .. } | Command::Thaw => {
            broker_control_command(socket, &cli.command, out, err)
        }
        Command::Agentdoc { format } => with_rules!(|l: &LoadedRules| {
            let _ = write!(
                out,
                "{}",
                agentdoc::render(l.rules(), l.generation(), (*format).into())
            );
            ExitCode::Delegated
        }),
    }
}

fn broker_control_command(
    socket: &Path,
    command: &Command,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let question = match command {
        Command::Freeze { reason } => xudo_wire::Question::Freeze {
            reason: reason.clone(),
        },
        Command::Thaw => xudo_wire::Question::Thaw,
        _ => return ExitCode::Unusable,
    };
    broker_control(socket, question, out, err, &watch::ask_live)
}

fn broker_control(
    socket: &Path,
    question: xudo_wire::Question,
    out: &mut dyn Write,
    err: &mut dyn Write,
    ask: &dyn Fn(&Path, &xudo_wire::BrokerRequest) -> Result<xudo_wire::BrokerResponse, String>,
) -> ExitCode {
    let request = xudo_wire::BrokerRequest {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        question,
    };
    match ask(socket, &request) {
        Ok(response) if response.answer == xudo_wire::Answer::Done => {
            let _ = writeln!(out, "done");
            ExitCode::Delegated
        }
        Ok(response) => {
            let _ = writeln!(err, "xudo: {:?}", response.answer);
            ExitCode::Denied
        }
        Err(error) => {
            let _ = writeln!(err, "xudo: {error}");
            ExitCode::Unusable
        }
    }
}

/// What `install` was asked to do.
#[derive(Clone, Copy, Debug)]
struct InstallMode {
    dry_run: bool,
    show_contents: bool,
    uninstall: bool,
}

/// Plans the install, or the removal, and performs it unless `--dry-run`.
///
/// The plans are built by `xudo-backend`, which is pure, so a dry run prints
/// exactly the data the executor then performs — printing it is how the steps
/// get reviewed before anything runs as root.
///
/// A removal needs no backend: it takes away what xudo wrote whichever backend
/// is installed now, or none, so a machine whose `sudo` was uninstalled first
/// can still be cleaned up. Both backends' removals run, each of them removing
/// nothing it did not write.
fn install(
    probe: &dyn Probe,
    installer: &dyn Installer,
    mode: InstallMode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let plans = if mode.uninstall {
        vec![
            uninstall_plan(BackendKind::Sudo),
            uninstall_plan(BackendKind::Doas),
        ]
    } else {
        // One refusal path, not two. A backend that cannot be given a snippet
        // is a backend xudo cannot use, so the snippet failure is folded into
        // the same answer rather than given its own arm — an arm that
        // detection's usability guarantee means nothing could ever reach.
        match detect(probe)
            .map_err(|source| source.to_string())
            .and_then(|backend| plan_for(&backend))
        {
            Ok(plan) => vec![plan],
            Err(reason) => {
                let _ = writeln!(err, "xudo: no usable backend: {reason}");
                return ExitCode::Unusable;
            }
        }
    };

    if mode.dry_run {
        for plan in &plans {
            print_plan(plan, mode.show_contents, out);
        }
        let _ = writeln!(
            out,
            "\nNothing was written. This build grants the human path only: every rule it\n\
             would install requires a password, and no passwordless rule exists in it."
        );
        return ExitCode::Delegated;
    }

    let mut unverified = None;
    for plan in &plans {
        match installer.run(plan) {
            Ok(report) => {
                print_report(&report, out);
                if let Verification::Unverified { reason } = report.verification {
                    unverified = Some(reason);
                }
            }
            Err(failure) => {
                let _ = writeln!(err, "xudo: {} failed: {failure}", plan_verb(mode));
                return ExitCode::Unusable;
            }
        }
    }
    match unverified {
        // Files were written and nothing proved they take effect. Said in so
        // many words, with a failing status, because a quiet success here is
        // exactly the claim xudo must not make.
        Some(reason) => {
            let _ = writeln!(
                err,
                "xudo: installed, but NOT VERIFIED: {reason}. The integration has not been \
                 shown to work; do not rely on it."
            );
            ExitCode::Unusable
        }
        None => ExitCode::Delegated,
    }
}

/// The word for what is being done, for a failure message.
fn plan_verb(mode: InstallMode) -> &'static str {
    if mode.uninstall {
        "uninstall"
    } else {
        "install"
    }
}

/// Prints one plan, step by step.
fn print_plan(plan: &InstallPlan, show_contents: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "plan for     {}", plan.backend.label());
    let _ = writeln!(out, "steps        {}", plan.steps.len());
    for (index, step) in plan.steps.iter().enumerate() {
        let ordinal = index.saturating_add(1);
        let _ = writeln!(out, "  {ordinal:>2}. {}", step.describe());
        if show_contents {
            for line in step_contents(step).lines() {
                let _ = writeln!(out, "      | {line}");
            }
        }
    }
}

/// Prints what a plan did, and whether that was shown to work.
fn print_report(report: &InstallReport, out: &mut dyn Write) {
    let _ = writeln!(out, "done         {}", report.backend.label());
    for event in &report.events {
        let _ = writeln!(out, "  - {event}");
    }
    if report.verification == Verification::Verified {
        let _ = writeln!(out, "verified     the functional probe passed");
    }
    for notice in &report.notices {
        let _ = writeln!(out, "\n{notice}");
    }
}

/// The plan for one backend, with the failure rendered as text.
///
/// Split out so the failure is reachable from a test: detection refuses an
/// unusable backend before `install` ever asks for a plan, so this arm cannot be
/// reached through the command — but it is still a real failure mode of the
/// planner, and an untested error path in a privileged tool is one nobody has
/// read.
fn plan_for(backend: &xudo_backend::Backend) -> Result<InstallPlan, String> {
    InstallPlan::human_only(backend).map_err(|source| source.to_string())
}

/// The text a step would write, or an empty string for a step that writes none.
fn step_contents(step: &PlanStep) -> &str {
    match step {
        PlanStep::WriteCandidate { contents, .. } => contents,
        PlanStep::AppendBlock { block, .. } => block,
        PlanStep::Notice { text } => text,
        PlanStep::CreateGroup { .. }
        | PlanStep::Validate { .. }
        | PlanStep::ValidateBySubstitution { .. }
        | PlanStep::Install { .. }
        | PlanStep::RemoveBlock { .. }
        | PlanStep::Remove { .. }
        | PlanStep::FunctionalProbe { .. } => "",
    }
}

/// Verifies the audit log, naming the first position that does not hold.
///
/// Reads only; it cannot repair a log, because a tool that can rewrite the
/// evidence is a tool an attacker can use to launder it.
/// Takes the path already resolved, so "there is no log path" is a case a test
/// can produce on a machine that has a home directory.
///
/// Reads bytes, so a line that is not UTF-8 is reported by its number, and
/// checks the end of the log as a privileged writer does
/// (`xudo_audit::verify_log`), so every damaged ending that writer refuses is
/// reported here too.
///
/// With `against_journal`, checks file records against root-written journal
/// entries. The chain that remains after a tail cut still verifies.
///
/// Every failure is one `<2>` line. Under the pasban unit's
/// `SyslogLevelPrefix=yes` that is journal priority 2. A person running the
/// command sees the prefix.
fn audit(
    log: Option<PathBuf>,
    against_journal: bool,
    runner: &dyn Runner,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let Some(path) = log else {
        crit(
            err,
            "xudo: no log path: HOME is unset and --log was not given",
        );
        return ExitCode::Unusable;
    };

    let contents = match std::fs::read(&path) {
        Ok(contents) => contents,
        Err(source) => {
            crit(
                err,
                format!("xudo: cannot read {}: {source}", path.display()),
            );
            // An unreadable log is not a verified log. A missing file is the
            // same answer as a corrupt one here on purpose: "nothing to check"
            // and "I could not check" must not print the same reassurance.
            return ExitCode::Unusable;
        }
    };

    let chain = match xudo_audit::verify_log(&contents) {
        Ok(chain) => chain,
        Err(source) => {
            crit(
                err,
                format!("xudo: {} is not intact: {source}", path.display()),
            );
            return ExitCode::Denied;
        }
    };

    // `None` means the journal was not consulted.
    let checked = if against_journal {
        match journal_tail(runner) {
            Ok(journal_entries) => {
                match compare_journal_chain(chain.records(), &journal_entries) {
                    JournalFinding::RemovedTail { seq, file_last } => {
                        crit(
                            err,
                            format!(
                                "xudo: {} is not intact: journal seq {seq} links to the file's last record ({file_last}); a record was removed from the end",
                                path.display(),
                            ),
                        );
                        return ExitCode::Denied;
                    }
                    JournalFinding::Replaced { seq } => {
                        crit(
                            err,
                            format!(
                                "xudo: {} is not intact: journal seq {seq} continues a file record with a different hash; records were replaced after a cut",
                                path.display(),
                            ),
                        );
                        return ExitCode::Denied;
                    }
                    JournalFinding::Unlinked => {
                        crit(
                            err,
                            format!(
                                "xudo: {} is not intact: no journal entry matches any file record",
                                path.display(),
                            ),
                        );
                        return ExitCode::Denied;
                    }
                    JournalFinding::NoLink => {}
                }
                Some((chain.records(), journal_entries))
            }
            Err(reason) => {
                crit(
                    err,
                    format!(
                        "xudo: cannot check {} against the journal: {reason}",
                        path.display()
                    ),
                );
                return ExitCode::Unusable;
            }
        }
    } else {
        None
    };

    let _ = writeln!(
        out,
        "audit  {} record(s) in {}: chain intact",
        chain.len(),
        path.display()
    );
    if let Some((file_records, journal_entries)) = checked {
        let _ = writeln!(out, "{}", journal_note(file_records, &journal_entries));
    }
    let _ = writeln!(
        out,
        "note   an unbroken chain proves nothing was edited in place. It cannot \
         prove the log was never truncated and rebuilt, because the hashes are \
         all in the log."
    );
    ExitCode::Delegated
}

/// One failure line, at syslog crit once the pasban unit's journal stream reads it.
///
/// `SyslogLevel=` would raise every line, including a clean result, and
/// `LogLevelMax=` only discards lines. A `<2>` prefix with `SyslogLevelPrefix=yes`
/// is what journald stores as priority 2.
fn crit(err: &mut dyn Write, message: impl std::fmt::Display) {
    let _ = writeln!(err, "<2>{message}");
}

/// What the journal comparison found, when it did not find a removed tail.
fn journal_note(file_records: &[xudo_audit::Record], entries: &[JournalEntry]) -> String {
    if entries.is_empty() {
        return "note   the journal has no root-written xudo audit entry, so a tail removed \
                from the file would not show"
            .to_owned();
    }
    if let Some(tail) = file_records.last() {
        let by_hash = file_index(file_records);
        if entries
            .iter()
            .any(|entry| entry.seq == tail.seq.get() && entry.hash == tail.hash)
        {
            return format!(
                "note   journal seq {} matches the file's last record",
                tail.seq.get()
            );
        }
        let journal_max = entries.iter().map(|entry| entry.seq).max();
        let links_to_file = entries.iter().any(|entry| {
            by_hash
                .get(entry.hash.as_str())
                .is_some_and(|&(seq, _)| seq == entry.seq)
        });
        if let (Some(journal), true) = (journal_max, links_to_file)
            && journal < tail.seq.get()
        {
            return format!(
                "note   journal seq {journal} is behind the file's last record ({}), so the journal \
                 cannot show whether a tail was removed",
                tail.seq.get()
            );
        }
    }
    "note   the journal has no link to this file's last record, so it cannot show whether a tail \
     was removed"
        .to_owned()
}

/// `/usr/bin/journalctl`, never a `PATH` search.
const JOURNALCTL: &str = "/usr/bin/journalctl";

/// The arguments of the trusted journal query, program name not included.
fn journal_args() -> Vec<String> {
    let mut args = xudo_audit::journal::trusted_matches(&[]);
    args.extend(
        [
            "--output=json",
            "--output-fields=XUDO_SEQ,XUDO_HASH,XUDO_PREV_HASH",
            "--no-pager",
        ]
        .map(str::to_owned),
    );
    args
}

/// One root-written xudo record returned by the trusted query.
#[derive(Clone, Debug, PartialEq, Eq)]
struct JournalEntry {
    seq: u64,
    hash: String,
    prev_hash: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JournalFinding {
    NoLink,
    Unlinked,
    RemovedTail { seq: u64, file_last: u64 },
    Replaced { seq: u64 },
}

fn compare_journal_chain(file: &[xudo_audit::Record], journal: &[JournalEntry]) -> JournalFinding {
    let Some(last) = file.last() else {
        return JournalFinding::NoLink;
    };
    let by_hash = file_index(file);
    let any_record_matches = journal.iter().any(|entry| {
        by_hash
            .get(entry.hash.as_str())
            .is_some_and(|&(seq, _)| seq == entry.seq)
    });
    if !journal.is_empty() && !any_record_matches {
        return JournalFinding::Unlinked;
    }
    for entry in journal {
        // Genesis has no predecessor and cannot identify which chain it belongs to.
        if entry.prev_hash.is_empty() {
            continue;
        }
        if let Some(&(_, index)) = by_hash.get(entry.prev_hash.as_str()) {
            match index
                .checked_add(1)
                .and_then(|next_index| file.get(next_index))
            {
                Some(next) if entry.hash != next.hash => {
                    return JournalFinding::Replaced { seq: entry.seq };
                }
                None => {
                    return JournalFinding::RemovedTail {
                        seq: entry.seq,
                        file_last: last.seq.get(),
                    };
                }
                Some(_) => {}
            }
        }
    }
    JournalFinding::NoLink
}

/// Hash each record once so journal comparisons stay linear.
fn file_index(records: &[xudo_audit::Record]) -> std::collections::BTreeMap<&str, (u64, usize)> {
    records
        .iter()
        .enumerate()
        .map(|(index, record)| (record.hash.as_str(), (record.seq.get(), index)))
        .collect()
}

/// Root-written chain links returned by journalctl. Missing or malformed hash
/// fields fail closed because the comparison could not establish its claim.
fn journal_tail(runner: &dyn Runner) -> Result<Vec<JournalEntry>, String> {
    let args = journal_args();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = runner
        .run(JOURNALCTL, &refs, None)
        .map_err(|source| source.to_string())?;
    if !output.stderr.trim().is_empty() {
        return Err(format!(
            "journalctl wrote to standard error: {}",
            output.stderr.trim()
        ));
    }
    if !output.success {
        let status = match output.code {
            Some(code) => code.to_string(),
            None => "on a signal".to_owned(),
        };
        return Err(format!("journalctl exited {status}"));
    }
    parse_journal_entries(&output.stdout)
}

/// The chain fields in `journalctl --output=json` text.
///
/// Every nonempty line must be one complete JSON object with chain fields.
/// Anything else is a query this check cannot trust.
fn parse_journal_entries(text: &str) -> Result<Vec<JournalEntry>, String> {
    let mut entries = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let line_no = index.saturating_add(1);
        let value: serde_json::Value = serde_json::from_str(line).map_err(|source| {
            format!("line {line_no} of the journal query is not json: {source}")
        })?;
        let serde_json::Value::Object(fields) = value else {
            return Err(format!(
                "line {line_no} of the journal query is not a journal entry"
            ));
        };
        let field = |name: &str| -> Result<&str, String> {
            fields
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("line {line_no} of the journal query has no text {name}"))
        };
        let seq_text = field("XUDO_SEQ")?;
        let seq = seq_text.parse::<u64>().map_err(|_| {
            format!(
                "line {line_no} of the journal query has an XUDO_SEQ that is not a sequence number"
            )
        })?;
        entries.push(JournalEntry {
            seq,
            hash: field("XUDO_HASH")?.to_owned(),
            prev_hash: field("XUDO_PREV_HASH")?.to_owned(),
        });
    }
    Ok(entries)
}

/// The per-user log, resolved the way `xudo-config` resolves it.
///
/// The XDG variables are deliberately **not** read here. `std::env::var` is on
/// this project's disallowed list because a privileged binary must not take a
/// path from its environment, and carving an exception for the convenient case
/// is how that rule stops meaning anything. A caller whose `XDG_STATE_HOME` is
/// set passes `--log`, which `--help` says.
fn default_log_file() -> Option<PathBuf> {
    log_file_for(std::env::home_dir())
}

/// The per-user log under `home`, or `None` if there is no home directory.
///
/// Split out from [`default_log_file`] so the no-home case is reachable from a
/// test on a machine that has one.
fn log_file_for(home: Option<PathBuf>) -> Option<PathBuf> {
    Some(xudo_config::XdgPaths::resolve(&home?, None, None, None, None).log_file())
}

/// Evaluates an argv against one action, or against every action.
fn explain(
    cli: &Cli,
    ops: &dyn PrivilegedOps,
    loaded: &LoadedRules,
    args: &EvalArgs,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    if args.argv.is_empty() {
        let _ = writeln!(err, "xudo: nothing to explain; pass a command after `--`");
        return ExitCode::Unusable;
    }

    let Some(settings) = engine_settings(cli, err) else {
        return ExitCode::Unusable;
    };
    let caller = classify(ops, err);
    // argv[0] is the program, the rest are its operands. Splitting here and
    // handing both to the engine is what makes the program part of the decision:
    // before this split the whole command was matched against the argument list,
    // so a rule for /usr/bin/systemctl would happily accept a bare `restart
    // nginx.service` with no program named at all.
    let (program, operands) = split_program(&args.argv);
    let requested = Argv::new(operands.iter().map(String::as_str).collect::<Vec<_>>());

    let decision = if let Some(action) = &args.action {
        evaluate_one(
            loaded.rules(),
            &caller,
            action,
            program,
            &requested,
            settings,
        )
    } else {
        // Every action that accepts the command decides it together, and the
        // engine does the searching: which rule governs a command is a
        // decision, and this crate makes none. Overlapping rules resolve to
        // the strictest, so the sort order of two rule files cannot decide
        // whether a human is asked.
        let decision = xudo_policy::evaluate_command(
            loaded.rules(),
            &caller,
            &Arg::from(program),
            &requested,
            settings,
        );
        if decision.denial == Some(DenialCode::UnknownAction) {
            let _ = writeln!(
                err,
                "xudo: no action in {} runs {program}",
                cli.rules.display()
            );
        }
        decision
    };

    emit(cli, &decision, out)
}

/// Explains one action's refusal specifically.
fn why_not(
    cli: &Cli,
    ops: &dyn PrivilegedOps,
    loaded: &LoadedRules,
    action: &str,
    argv: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let Some(settings) = engine_settings(cli, err) else {
        return ExitCode::Unusable;
    };
    let caller = classify(ops, err);
    let (program, operands) = split_program(argv);
    let argv = Argv::new(operands.iter().map(String::as_str).collect::<Vec<_>>());
    let decision = evaluate_one(loaded.rules(), &caller, action, program, &argv, settings);
    if decision.verdict.is_permitted() {
        let _ = writeln!(err, "xudo: {action} does not refuse this command");
    }
    emit(cli, &decision, out)
}

/// Splits a command into its program and its operands.
///
/// The program is `argv[0]`. There is no `PATH` search and no resolution: the
/// bytes are handed to the engine, which compares them to the rule's own
/// absolute path byte-exactly.
fn split_program(argv: &[String]) -> (&str, &[String]) {
    const NOTHING: &[String] = &[];
    argv.split_first()
        .map_or(("", NOTHING), |(first, rest)| (first.as_str(), rest))
}

fn evaluate_one(
    rules: &RuleSet,
    caller: &CallerFacts,
    action: &str,
    program: &str,
    argv: &Argv,
    settings: Settings,
) -> Decision {
    xudo_policy::evaluate(
        rules,
        caller,
        &Request::for_program(action, program, argv.clone()),
        settings,
    )
}

/// Lints the ruleset.
fn check(loaded: &LoadedRules, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    let offenders = loaded.rules().self_denying_actions();
    if !offenders.is_empty() {
        for (id, classes) in &offenders {
            let _ = writeln!(
                err,
                "xudo: {id} allowlists an executable the deny-list refuses: {classes:?}"
            );
        }
        let _ = writeln!(
            err,
            "xudo: a rule that allowlists a shell-capable binary defeats the design"
        );
        return ExitCode::Denied;
    }

    let _ = writeln!(
        out,
        "ok: {} action(s) in {} file(s), generation {}",
        loaded.rules().len(),
        loaded.files().len(),
        loaded.generation().get(..12).unwrap_or(loaded.generation())
    );

    // Reported, not refused: the engine resolves a command more than one
    // action accepts to the strictest of them, so an overlap is not a hole.
    // It is still two rules whose interaction nobody wrote down, and the
    // report never stays silent about a pair it cannot decide.
    let overlaps = loaded.rules().overlaps();
    for overlap in &overlaps {
        let _ = writeln!(out, "{overlap}");
    }
    if !overlaps.is_empty() {
        let _ = writeln!(
            out,
            "{} overlapping pair(s): a command more than one action accepts is refused to an \
             agent if any of them is human-only, and confirmed as strictly as the strictest \
             demands",
            overlaps.len()
        );
    }
    ExitCode::Delegated
}

/// Lists the effective policy.
fn list(
    loaded: &LoadedRules,
    tier: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let mut shown = 0usize;
    for action in loaded.rules().actions() {
        let label = format!("{:?}", action.tier).to_lowercase();
        if let Some(wanted) = tier {
            if !label.contains(&wanted.replace('-', "")) {
                continue;
            }
        }
        let _ = writeln!(
            out,
            "{:<28} {:<12} {:<26} {}",
            action.id.as_str(),
            label,
            action.exe,
            action.source
        );
        shown = shown.saturating_add(1);
    }
    if shown == 0 {
        let _ = writeln!(err, "xudo: no action matched");
        return ExitCode::Denied;
    }
    ExitCode::Delegated
}

/// Loads the settings file and derives the engine's view of it.
///
/// Without this the layered configuration would be reported by `xudo config` and
/// then ignored by every decision, which is worse than having no configuration
/// at all: an operator would set `confirm_agent_actions` and be told it took
/// effect while the engine ran on its defaults.
///
/// A broken file yields `None` and the caller fails closed. Falling back to the
/// defaults would be *safe* — they are the strict values — but it would also be
/// silent, and a settings file that does not mean what it says is exactly the
/// condition this project refuses to paper over.
fn engine_settings(cli: &Cli, err: &mut dyn Write) -> Option<Settings> {
    let mut config = ConfigSettings::default();

    // A missing file is not an error: the defaults are the configuration until
    // somebody writes one.
    if let Ok(contents) = std::fs::read_to_string(&cli.config_file) {
        let name = Path::new(&cli.config_file).display().to_string();
        if let Err(load_err) = apply_file(&mut config, Layer::System, &name, &contents) {
            let _ = writeln!(err, "xudo: {load_err}");
            let _ = writeln!(
                err,
                "xudo: failing closed; the settings file was not applied"
            );
            return None;
        }
    }

    Some(Settings {
        confirm_agent_actions: config.get(Setting::ConfirmAgentActions).value
            == ConfigValue::Bool(true),
        confirm_human_path: config.get(Setting::ConfirmHumanPath).value == ConfigValue::Bool(true),
        frozen: config.get(Setting::Frozen).value == ConfigValue::Bool(true),
    })
}

/// The layer a settings file is reported as: only the default path is the
/// system file.
fn origin_layer(path: &Path) -> Layer {
    if path == Path::new(DEFAULT_CONFIG_FILE) {
        Layer::System
    } else {
        Layer::ConfigFile
    }
}

/// Reports the effective configuration, or the schema.
///
/// Every value names the file and line that set it, and a compiled-in value says
/// so rather than being omitted — "why is confirmation off?" must have a
/// one-command answer, or somebody will answer it by guessing.
fn config(
    cli: &Cli,
    schema: bool,
    action: Option<&ConfigAction>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    if schema || matches!(action, Some(ConfigAction::Schema { .. })) {
        let _ = writeln!(out, "{}", render::json_of(&ConfigSettings::schema()));
        return ExitCode::Delegated;
    }

    let mut settings = ConfigSettings::default();

    // The system layer, if it is readable. A missing file is not an error: the
    // defaults are the configuration until somebody writes one.
    if let Ok(contents) = std::fs::read_to_string(&cli.config_file) {
        let name = Path::new(&cli.config_file).display().to_string();
        // A file given on the command line is not the system file, and
        // scriptable output must not say it is.
        let layer = origin_layer(&cli.config_file);
        if let Err(load_err) = apply_file(&mut settings, layer, &name, &contents) {
            // A broken configuration file fails closed: the defaults are safe,
            // but continuing while pretending the file was applied is not.
            let _ = writeln!(err, "xudo: {load_err}");
            let _ = writeln!(err, "xudo: failing closed; the file was not applied");
            return ExitCode::Unusable;
        }
    }

    match action {
        Some(ConfigAction::Get { key, origin }) => {
            let Some(setting) = Setting::from_key(key) else {
                let _ = writeln!(err, "xudo: {key} is not a setting; see `xudo config list`");
                return ExitCode::Unusable;
            };
            let _ = write!(out, "{}", report::get(&settings, setting, *origin));
        }
        Some(ConfigAction::List { origin, effective }) => {
            let options = ListOptions {
                origin: *origin,
                effective: *effective,
            };
            let _ = write!(out, "{}", report::list(&settings, &Setting::ALL, options));
        }
        // No subcommand is the legacy report. The schema was answered above.
        _ => legacy_report(&settings, out),
    }
    ExitCode::Delegated
}

/// The report `xudo config` printed before it had subcommands.
fn legacy_report(settings: &ConfigSettings, out: &mut dyn Write) {
    for (setting, value, origin) in settings.report() {
        let marker = if setting.is_security_relevant() {
            "*"
        } else {
            " "
        };
        let _ = writeln!(out, "{marker} {:<26} {:<10} {origin}", setting.key(), value);
    }
    let _ = writeln!(
        out,
        "\n* security-relevant: never settable from the environment."
    );
    let _ = writeln!(out, "confirm_agent_actions has no effect until M4.");
}

/// Classifies the current process, falling back to a password-requiring caller.
fn classify(ops: &dyn PrivilegedOps, err: &mut dyn Write) -> CallerFacts {
    match ops.classify(std::process::id()) {
        Ok(facts) => facts,
        Err(e) => {
            // Failing closed: unattested requires a password, which is the
            // conservative direction when the platform cannot answer.
            let _ = writeln!(
                err,
                "xudo: cannot observe this caller ({e}); treating as unattested"
            );
            CallerFacts::new(
                xudo_policy::Classification::Unattested {
                    reason: e.to_string(),
                },
                0,
            )
        }
    }
}

/// Renders a decision in the requested format and maps it to an exit status.
pub(crate) fn emit(cli: &Cli, decision: &Decision, out: &mut dyn Write) -> ExitCode {
    match cli.output {
        Format::Human => {
            let _ = write!(out, "{}", render::human(decision));
        }
        Format::Json => {
            let _ = writeln!(out, "{}", render::json(decision));
        }
    }
    // `explain` reports; it does not execute. A refusal still exits non-zero so
    // a script or an agent can branch without parsing prose.
    match decision.verdict {
        Verdict::Allow => ExitCode::Delegated,
        _ => decision.exit_code(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use xudo_backend::Capability;
    use xudo_backend::paths_to_root::{Caller, Lookup, MemoryHost};
    use xudo_config::Setting;

    /// Runs `cli` against `ops` and `probe`, with this machine's filesystem and
    /// no `PATH` to report on.
    fn run_on(
        cli: &Cli,
        ops: &dyn PrivilegedOps,
        probe: &dyn Probe,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> ExitCode {
        let platform = Platform {
            ops,
            probe,
            host: &LiveHost,
            path: None,
        };
        run_with(cli, &platform, out, err)
    }

    /// Root for throwaway fixture directories.
    ///
    /// Under the workspace `target/` directory, never `/tmp`: a predictable
    /// path in a world-writable directory is a symlink race, and this project's
    /// own rules forbid it.
    fn test_tmp_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
    }

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = test_tmp_root().join(name);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn write(self, file: &str, contents: &str) -> Self {
            std::fs::write(self.dir.join(file), contents).unwrap();
            self
        }

        /// A settings-file path *beside* the rules directory, never inside it.
        ///
        /// Mirrors production, where `/etc/xudo/config.toml` sits next to
        /// `/etc/xudo/rules.d/`. A `.toml` file inside the rules directory is a
        /// rule file by definition, and the loader is right to try to parse it.
        fn config_path(&self) -> PathBuf {
            let path = self.dir.with_extension("config");
            std::fs::create_dir_all(&path).unwrap();
            path.join("config.toml")
        }

        /// Runs argv against this fixture, returning (exit, stdout, stderr).
        fn run(&self, args: &[&str]) -> (ExitCode, String, String) {
            let mut full = vec!["xudo", "--rules", self.dir.to_str().unwrap()];
            full.extend_from_slice(args);
            let cli = Cli::try_parse_from(full).unwrap();
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run_on(&cli, host_ops().as_ref(), &HostProbe, &mut out, &mut err);
            (
                code,
                String::from_utf8_lossy(&out).into_owned(),
                String::from_utf8_lossy(&err).into_owned(),
            )
        }

        fn run_at_socket(&self, args: &[&str], socket: &Path) -> (ExitCode, String, String) {
            let mut full = vec!["xudo", "--rules", self.dir.to_str().unwrap()];
            full.extend_from_slice(args);
            let cli = Cli::try_parse_from(full).unwrap();
            let ops = host_ops();
            let platform = Platform {
                ops: ops.as_ref(),
                probe: &HostProbe,
                host: &LiveHost,
                path: None,
            };
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run_with_installer_at_socket(
                &cli,
                &platform,
                &RefusingInstaller,
                socket,
                &mut out,
                &mut err,
            );
            (
                code,
                String::from_utf8_lossy(&out).into_owned(),
                String::from_utf8_lossy(&err).into_owned(),
            )
        }
    }

    #[test]
    fn pending_command_uses_the_read_only_broker_question() {
        let fixture = fixture("cli-pending");
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let broker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            let request = xudo_wire::BrokerRequest::parse(&bytes).unwrap();
            assert_eq!(request.question, xudo_wire::Question::Pending);
            let response = xudo_wire::BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer: xudo_wire::Answer::Watching {
                    prompts: Vec::new(),
                    omitted: 0,
                },
            };
            stream.write_all(response.to_json().as_bytes()).unwrap();
        });
        let (code, out, err) = fixture.run_at_socket(&["pending"], &socket);
        broker.join().unwrap();
        assert_eq!(code, ExitCode::Delegated);
        assert_eq!(out, "");
        assert_eq!(err, "");
    }

    #[test]
    fn freeze_command_dispatches_and_fails_closed_without_the_broker() {
        let (code, _, _) =
            fixture("cli-freeze-no-broker").run(&["freeze", "--reason", "maintenance"]);
        assert_eq!(code, ExitCode::Unusable);
        let (code, _, _) = fixture("cli-thaw-no-broker").run(&["thaw"]);
        assert_eq!(code, ExitCode::Unusable);
    }

    #[test]
    fn broker_control_renders_done_refusal_and_transport_error() {
        let seen_question = std::cell::RefCell::new(None);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let ask_done = |_: &Path, request: &xudo_wire::BrokerRequest| {
            *seen_question.borrow_mut() = Some(request.question.clone());
            Ok(xudo_wire::BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer: xudo_wire::Answer::Done,
            })
        };
        assert_eq!(
            broker_control(
                Path::new("socket"),
                xudo_wire::Question::Thaw,
                &mut out,
                &mut err,
                &ask_done
            ),
            ExitCode::Delegated
        );
        assert_eq!(*seen_question.borrow(), Some(xudo_wire::Question::Thaw));
        assert_eq!(out, b"done\n");

        let ask_refused = |_: &Path, request: &xudo_wire::BrokerRequest| {
            assert!(
                matches!(&request.question, xudo_wire::Question::Freeze { reason } if reason == "maintenance")
            );
            Ok(xudo_wire::BrokerResponse {
                schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
                answer: xudo_wire::Answer::Refused {
                    code: xudo_wire::RefusalCode::RequestUnknown,
                    remediation: "refused".to_owned(),
                    detail: None,
                },
            })
        };
        assert_eq!(
            broker_control(
                Path::new("socket"),
                xudo_wire::Question::Freeze {
                    reason: "maintenance".to_owned()
                },
                &mut out,
                &mut err,
                &ask_refused
            ),
            ExitCode::Denied
        );
        assert!(String::from_utf8(err.clone()).unwrap().contains("Refused"));

        let ask_error = |_: &Path, _: &xudo_wire::BrokerRequest| Err("offline".to_owned());
        assert_eq!(
            broker_control(
                Path::new("socket"),
                xudo_wire::Question::Thaw,
                &mut out,
                &mut err,
                &ask_error
            ),
            ExitCode::Unusable
        );
        assert!(String::from_utf8(err.clone()).unwrap().contains("offline"));

        assert_eq!(
            broker_control_command(
                Path::new("socket"),
                &Command::Doctor {
                    json: false,
                    fix: false
                },
                &mut out,
                &mut Vec::new()
            ),
            ExitCode::Unusable
        );
        assert_eq!(
            broker_control_command(
                Path::new("missing-socket"),
                &Command::Thaw,
                &mut out,
                &mut err
            ),
            ExitCode::Unusable
        );
    }

    #[test]
    fn watch_command_refuses_a_non_terminal_before_contacting_the_broker() {
        let fixture = fixture("cli-watch-notty");
        let socket = fixture.dir.join("no-broker.sock");
        let (code, out, err) = fixture.run_at_socket(&["watch"], &socket);
        assert_eq!(code, ExitCode::Unusable);
        assert_eq!(out, "");
        assert!(err.contains("watch requires a terminal on stdin"), "{err}");
    }

    #[test]
    fn doctor_names_the_attestation_rung_not_just_the_kernel_version() {
        // "Why did this agent get a password prompt" is answered by the rung and
        // by nothing else in the output.
        let fx = fixture("cli-doctor-kernel");
        let (_, out, _) = run_ops(&fx, &BlindOps, &["doctor"]);
        assert!(
            out.contains("kernel       6.8 via SO_PEERPIDFD (kernel supports attestation for the planned agent path; agent path not in this build)"),
            "{out}"
        );
    }

    #[test]
    fn doctor_reports_the_ruleset_as_untrusted_in_a_checkout() {
        // A development checkout is owned by the developer, not root, so the
        // honest answer is UNTRUSTED. A doctor that said otherwise here would
        // be telling operators the check works when it does not.
        let fx = fixture("cli-doctor-trust");
        let (code, out, _) = fx.run(&["doctor"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("rules trust  UNTRUSTED"), "{out}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_trust_line_reports_a_root_owned_path_as_trusted() {
        // Not a claim about xudo's own directory: a claim that the line can say
        // yes at all, so a bug that always refuses cannot hide behind the test
        // above.
        let cli = Cli::try_parse_from(["xudo", "--rules", "/usr/bin", "doctor"]).unwrap();
        let mut out = Vec::new();
        let code = run_on(&cli, &BlindOps, &NoBackendProbe, &mut out, &mut Vec::new());
        let out = String::from_utf8_lossy(&out).into_owned();
        assert_eq!(code, ExitCode::Delegated);
        assert!(
            out.contains(
                "rules trust  root-owned, no writable component, no user-made mount; 0 rule \
                 file(s) checked on their descriptors"
            ),
            "{out}"
        );
    }

    /// A described machine for the doctor tests that run through the CLI:
    /// one passwordless group, one writable directory ahead of sudo, and a
    /// sudoers file this account cannot read.
    fn described_machine() -> MemoryHost {
        MemoryHost::new(Caller {
            uid: 1000,
            gid: 1000,
            groups: Lookup::Found(vec![1000, 999]),
        })
        .dir("/", 0, 0, 0o755)
        .dir("/etc", 0, 0, 0o755)
        .file(
            "/etc/passwd",
            0,
            0,
            0o644,
            b"root:x:0:0::/root:/bin/sh\nyamin:x:1000:1000::/home/yamin:/bin/sh\n",
        )
        .file(
            "/etc/group",
            0,
            0,
            0o644,
            b"docker:x:999:yamin\nxudo:x:998:\nyamin:x:1000:\n",
        )
        .unreadable_file("/etc/sudoers", 0, 0, 0o440)
        .dir("/usr", 0, 0, 0o755)
        .dir("/usr/bin", 0, 0, 0o755)
        .file("/usr/bin/sudo", 0, 0, 0o4755, b"")
        .file("/usr/bin/gpasswd", 0, 0, 0o755, b"")
        .dir("/usr/sbin", 0, 0, 0o755)
        .file("/usr/sbin/usermod", 0, 0, 0o755, b"")
        .sealed_dir("/root", 0, 0, 0o700)
        .dir("/home", 0, 0, 0o755)
        .dir("/home/yamin", 1000, 1000, 0o755)
        .dir("/home/yamin/bin", 1000, 1000, 0o755)
    }

    /// Runs `doctor` with `args` against `host`, in a fixture of its own: the
    /// tests run in parallel, and two sharing a directory delete each other's.
    fn doctor_on(name: &str, host: &MemoryHost, args: &[&str]) -> (ExitCode, String) {
        let fx = fixture(name);
        let mut full = vec!["xudo", "--rules", fx.dir.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let platform = Platform {
            ops: &BlindOps,
            probe: &WorkingSudoProbe,
            host,
            path: Some(OsStr::new("/home/yamin/bin:/usr/bin")),
        };
        let code = run_with(&cli, &platform, &mut out, &mut Vec::new());
        (code, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn doctor_reports_every_other_path_to_root_it_was_handed() {
        let (code, out) = doctor_on("cli-doctor-paths", &described_machine(), &["doctor"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(
            out.contains(
                "other paths to root, as yamin (uid 1000): 2 found, and 3 check(s) could not be \
                 completed"
            ),
            "{out}"
        );
        assert!(out.contains("docker (gid 999)"), "{out}");
        assert!(
            out.contains("/home/yamin/bin: /home/yamin, above it"),
            "{out}"
        );
        assert!(out.contains("comes before /usr/bin/sudo"), "{out}");
        // Unreadable is unverified, never clean, and it says how to see more.
        assert!(out.contains("cannot verify /etc/sudoers"), "{out}");
        assert!(out.contains("unverified is not clean"), "{out}");
        // Without --fix, nothing is proposed.
        assert!(!out.contains("proposed fixes"), "{out}");
        // The lines the differential matrix reads are where they were.
        assert!(
            out.contains("\nexec path    xudo exec runs /usr/bin/sudo on the gate\n"),
            "{out}"
        );
        assert!(out.contains("\nbackend caps 6 of 7 supported\n"), "{out}");
    }

    #[test]
    fn doctor_fix_proposes_with_the_exact_command_and_changes_nothing() {
        let (code, out) = doctor_on("cli-doctor-fix", &described_machine(), &["doctor", "--fix"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(
            out.contains("proposed fixes: xudo applies none of them"),
            "{out}"
        );
        assert!(
            out.contains("run       /usr/bin/sudo /usr/sbin/usermod --append --groups xudo yamin"),
            "{out}"
        );
        assert!(
            out.contains("run       /usr/bin/sudo /usr/bin/gpasswd --delete yamin docker"),
            "{out}"
        );
        assert!(out.contains("Nothing was changed."), "{out}");
    }

    #[test]
    fn doctor_json_is_the_versioned_envelope_and_the_global_flag_agrees() {
        let (code, out) = doctor_on(
            "cli-doctor-json",
            &described_machine(),
            &["doctor", "--json", "--fix"],
        );
        assert_eq!(code, ExitCode::Delegated);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["schema_version"], doctor::DOCTOR_SCHEMA_VERSION);
        assert_eq!(parsed["backend"]["implementation"], "sudo");
        assert_eq!(parsed["backend"]["status"], "usable");
        assert_eq!(parsed["paths_to_root"]["status"], "found");
        assert_eq!(parsed["proposals"][0]["id"], "join-xudo");
        assert!(
            parsed["exec_path"]
                .as_str()
                .unwrap()
                .starts_with("xudo exec runs")
        );
        // `--output json` selects the same envelope; without --fix there are
        // no proposals, which is null rather than an empty list.
        let (_, global) = doctor_on(
            "cli-doctor-global",
            &described_machine(),
            &["--output", "json", "doctor"],
        );
        let parsed: serde_json::Value = serde_json::from_str(&global).unwrap();
        assert_eq!(parsed["proposals"], serde_json::Value::Null);
        assert_eq!(
            parsed["paths_to_root"]["checks"][0]["check"],
            "passwordless_rules"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn doctor_names_the_mount_that_makes_a_ruleset_untrusted() {
        // /proc/sys passes every ownership check; the mount under /proc is
        // what refuses it, and the line says which mount and why.
        let cli = Cli::try_parse_from(["xudo", "--rules", "/proc/sys", "doctor"]).unwrap();
        let mut out = Vec::new();
        let code = run_on(
            &cli,
            host_ops().as_ref(),
            &HostProbe,
            &mut out,
            &mut Vec::new(),
        );
        assert_eq!(code, ExitCode::Delegated);
        let out = String::from_utf8_lossy(&out).into_owned();
        assert!(
            out.contains(
                "rules trust  UNTRUSTED: /proc is on proc at /proc, mounted nosuid, the mark of \
                 removable media and of mounts a user may make, so what is on it need not be \
                 root's"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_trusted_walk_is_reported_with_how_many_files_it_checked() {
        let files = vec![xudo_sys::TrustedFile {
            name: "10-a.toml".into(),
            bytes: Vec::new(),
        }];
        assert_eq!(
            doctor::trust_line(&doctor::trust_report(&Ok(files))),
            "root-owned, no writable component, no user-made mount; 1 rule file(s) checked on \
             their descriptors"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn the_trust_line_cannot_say_yes_off_linux() {
        // No mount table, so no mount can be judged, so nothing is trusted —
        // and the line says that is why, rather than blaming the ruleset.
        let line = doctor::trust_line(&doctor::trust_report(&xudo_sys::read_trusted_dir(
            Path::new("/usr/bin"),
        )));
        assert!(
            line.starts_with("UNTRUSTED: the mount table cannot be checked"),
            "{line}"
        );
        assert!(line.contains("not supported on this platform"), "{line}");
    }

    #[test]
    fn audit_verify_accepts_an_intact_log_and_states_what_it_does_not_prove() {
        let fx = Fixture::new("audit-intact");
        let mut chain = xudo_audit::Chain::new();
        chain.append(
            xudo_audit::Decision::Allowed,
            vec!["/usr/bin/systemctl".to_owned(), "restart".to_owned()],
            "human",
        );
        chain.append(
            xudo_audit::Decision::Denied,
            vec!["/bin/sh".to_owned()],
            "unattested",
        );
        let log = fx.dir.join("log.jsonl");
        std::fs::write(&log, chain.to_jsonl()).unwrap();

        let (code, out, err) = fx.run(&["audit", "--log", log.to_str().unwrap()]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("2 record(s)"), "{out}");
        assert!(out.contains("chain intact"), "{out}");
        // The limit is printed with the good news, not buried in a man page.
        assert!(out.contains("truncated and rebuilt"), "{out}");
        assert_eq!(err, "");
    }

    #[test]
    fn audit_verify_names_the_position_where_an_edited_log_stops_matching() {
        let fx = Fixture::new("audit-edited");
        let mut chain = xudo_audit::Chain::new();
        chain.append(
            xudo_audit::Decision::Allowed,
            vec!["/usr/bin/systemctl".to_owned()],
            "human",
        );
        chain.append(
            xudo_audit::Decision::Allowed,
            vec!["/usr/bin/apt-get".to_owned()],
            "human",
        );
        let tampered = chain
            .to_jsonl()
            .replace("/usr/bin/apt-get", "/usr/bin/HACKED");
        let log = fx.dir.join("log.jsonl");
        std::fs::write(&log, tampered).unwrap();

        let (code, out, err) = fx.run(&["audit", "--log", log.to_str().unwrap()]);
        assert_eq!(code, ExitCode::Denied);
        assert_eq!(out, "");
        assert!(err.starts_with("<2>"), "{err}");
        assert!(err.contains("is not intact"), "{err}");
        assert!(err.contains("record 2 was edited"), "{err}");
    }

    #[test]
    fn audit_verify_rejects_a_line_that_is_not_a_record() {
        let fx = Fixture::new("audit-garbage");
        let log = fx.dir.join("log.jsonl");
        std::fs::write(&log, "not json\n").unwrap();

        let (code, _, err) = fx.run(&["audit", "--log", log.to_str().unwrap()]);
        assert_eq!(code, ExitCode::Denied);
        assert!(err.starts_with("<2>"), "{err}");
        assert!(err.contains("line 1 is not an audit record"), "{err}");
    }

    #[test]
    fn audit_reports_an_ending_the_privileged_writer_refuses_instead_of_calling_it_intact() {
        // More than 128 KiB of blank space after the last record: every record
        // verifies, and the broker and the gate still refuse every decision
        // over it, sending the operator here. "chain intact" would contradict
        // the refusal that sent them.
        let fx = Fixture::new("audit-blank-tail");
        let mut chain = xudo_audit::Chain::new();
        chain.append(
            xudo_audit::Decision::Denied,
            vec!["/bin/sh".to_owned()],
            "unattested",
        );
        let mut bytes = chain.to_jsonl().into_bytes();
        bytes.extend(std::iter::repeat_n(b' ', xudo_audit::TAIL_WINDOW + 1));
        bytes.push(b'\n');
        let log = fx.dir.join("log.jsonl");
        std::fs::write(&log, bytes).unwrap();

        let (code, out, err) = fx.run(&["audit", "--log", log.to_str().unwrap()]);
        assert_eq!(code, ExitCode::Denied);
        assert_eq!(out, "");
        assert!(err.starts_with("<2>"), "{err}");
        assert!(err.contains("is not intact"), "{err}");
        assert!(
            err.contains("every record verifies, but a privileged writer refuses"),
            "{err}"
        );
        assert!(err.contains("the last 131072 bytes"), "{err}");
    }

    #[test]
    fn audit_names_the_line_of_a_tail_that_is_not_text() {
        // Read as text, a stray non-UTF-8 byte made the whole log "unreadable"
        // with no position; read as bytes, it is damage at a line.
        let fx = Fixture::new("audit-binary-tail");
        let mut chain = xudo_audit::Chain::new();
        chain.append(
            xudo_audit::Decision::Allowed,
            vec!["/usr/bin/systemctl".to_owned()],
            "human",
        );
        let mut bytes = chain.to_jsonl().into_bytes();
        bytes.extend_from_slice(b"\0\xff\xfe\n");
        let log = fx.dir.join("log.jsonl");
        std::fs::write(&log, bytes).unwrap();

        let (code, _, err) = fx.run(&["audit", "--log", log.to_str().unwrap()]);
        assert_eq!(code, ExitCode::Denied);
        assert!(err.starts_with("<2>"), "{err}");
        assert!(err.contains("line 2 is not an audit record"), "{err}");
    }

    #[test]
    fn an_unreadable_log_is_unusable_rather_than_reported_as_clean() {
        // "Nothing to check" and "I could not check" must not print the same
        // reassurance, so a missing file is Unusable and not Delegated.
        let fx = Fixture::new("audit-missing");
        let log = fx.dir.join("absent.jsonl");

        let (code, out, err) = fx.run(&["audit", "--log", log.to_str().unwrap()]);
        assert_eq!(code, ExitCode::Unusable);
        assert_eq!(out, "");
        assert!(err.starts_with("<2>"), "{err}");
        assert!(err.contains("cannot read"), "{err}");
    }

    #[test]
    fn an_empty_log_verifies_because_nothing_has_happened_yet() {
        let fx = Fixture::new("audit-empty");
        let log = fx.dir.join("log.jsonl");
        std::fs::write(&log, "").unwrap();

        let (code, out, _) = fx.run(&["audit", "--log", log.to_str().unwrap()]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("0 record(s)"), "{out}");
    }

    #[test]
    fn the_default_log_path_ignores_the_environment() {
        // Reading XDG_STATE_HOME here would be a path taken from the
        // environment, which this project forbids. Assert the resolved default
        // instead, so the day someone "fixes" it for convenience, this fails.
        let path = log_file_for(Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(path, PathBuf::from("/home/u/.local/state/ido/log.jsonl"));
        // No home directory is not a default path.
        assert_eq!(log_file_for(None), None);
        // And the real resolution goes through the same helper.
        let _ = default_log_file();
    }

    #[test]
    fn audit_without_a_log_argument_resolves_a_path_or_says_why_not() {
        // Runs against the real home directory, where the log almost certainly
        // does not exist. Either answer is correct; reporting the log as clean
        // is not.
        let fx = Fixture::new("audit-default");
        let (code, out, err) = fx.run(&["audit"]);
        assert_ne!(code, ExitCode::Delegated, "out={out} err={err}");
        assert!(!err.is_empty(), "a failure must say something");
    }

    #[test]
    fn audit_with_no_resolvable_path_refuses_rather_than_guessing_one() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = audit(None, false, &RefuseJournal, &mut out, &mut err);
        assert_eq!(code, ExitCode::Unusable);
        assert!(out.is_empty());
        let message = String::from_utf8_lossy(&err).into_owned();
        assert!(message.starts_with("<2>"), "{message}");
        assert!(message.contains("HOME is unset"), "{message}");
    }

    /// A runner the chain check must not call. A panic here means `audit`
    /// consulted the journal without being asked.
    struct RefuseJournal;

    impl xudo_sys::Runner for RefuseJournal {
        fn run(
            &self,
            _: &str,
            _: &[&str],
            _: Option<&[u8]>,
        ) -> Result<xudo_sys::Output, xudo_sys::SysError> {
            panic!("the chain check must not run a program");
        }
    }

    /// One scripted answer from `journalctl`, and the argv it was given.
    struct ScriptedJournal {
        output: Result<xudo_sys::Output, xudo_sys::SysError>,
        exe: std::cell::RefCell<String>,
        args: std::cell::RefCell<Vec<String>>,
    }

    impl ScriptedJournal {
        fn new(output: Result<xudo_sys::Output, xudo_sys::SysError>) -> Self {
            Self {
                output,
                exe: std::cell::RefCell::new(String::new()),
                args: std::cell::RefCell::new(Vec::new()),
            }
        }

        fn ok(stdout: &str) -> Self {
            Self::new(Ok(xudo_sys::Output {
                success: true,
                code: Some(0),
                stdout: stdout.to_owned(),
                stderr: String::new(),
            }))
        }
    }

    impl xudo_sys::Runner for ScriptedJournal {
        fn run(
            &self,
            exe: &str,
            args: &[&str],
            stdin: Option<&[u8]>,
        ) -> Result<xudo_sys::Output, xudo_sys::SysError> {
            assert!(stdin.is_none(), "the journal query takes no stdin");
            *self.exe.borrow_mut() = exe.to_owned();
            *self.args.borrow_mut() = args.iter().map(|arg| (*arg).to_owned()).collect();
            self.output.clone()
        }
    }

    fn audit_file(
        log: &Path,
        against_journal: bool,
        runner: &dyn xudo_sys::Runner,
    ) -> (ExitCode, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = audit(
            Some(log.to_path_buf()),
            against_journal,
            runner,
            &mut out,
            &mut err,
        );
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn write_chain(dir: &Path, records: usize) -> PathBuf {
        let mut chain = xudo_audit::Chain::new();
        for index in 0..records {
            chain.append(
                xudo_audit::Decision::Allowed,
                vec![format!("/usr/bin/true{index}")],
                "human",
            );
        }
        let log = dir.join("log.jsonl");
        std::fs::write(&log, chain.to_jsonl()).unwrap();
        log
    }

    fn journal_object(record: &xudo_audit::Record) -> String {
        serde_json::json!({
            "XUDO_SEQ": record.seq.get().to_string(),
            "XUDO_HASH": record.hash,
            "XUDO_PREV_HASH": record.prev_hash,
        })
        .to_string()
    }

    fn linked_object(seq: u64, hash: &str, prev_hash: &str) -> String {
        serde_json::json!({
            "XUDO_SEQ": seq.to_string(),
            "XUDO_HASH": hash,
            "XUDO_PREV_HASH": prev_hash,
        })
        .to_string()
    }

    fn records_at(log: &Path) -> Vec<xudo_audit::Record> {
        xudo_audit::verify_log(&std::fs::read(log).unwrap())
            .unwrap()
            .records()
            .to_vec()
    }

    #[test]
    fn the_journal_refusal_panics_if_the_chain_check_runs_a_program() {
        // The body has to run once, or the guard that audit must not trip is
        // itself an uncovered line. audit's own test is the one that proves
        // the check does not call it.
        let caught = std::panic::catch_unwind(|| {
            let _ = xudo_sys::Runner::run(&RefuseJournal, "/usr/bin/journalctl", &[], None);
        });
        assert!(caught.is_err(), "the refusal has to panic");
    }

    #[test]
    fn without_against_journal_a_higher_sequence_is_not_consulted() {
        let fx = Fixture::new("audit-file-only");
        let log = write_chain(&fx.dir, 1);
        let (code, out, err) = audit_file(&log, false, &RefuseJournal);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("chain intact"), "{out}");
        assert!(
            !out.lines()
                .any(|line| line.starts_with("note") && line.contains("journal")),
            "{out}"
        );
        assert_eq!(err, "");
    }

    #[test]
    fn a_tail_cut_back_to_a_record_boundary_is_caught_against_the_journal() {
        // One valid record. The chain verifies. The journal still holds seq 2,
        // which is the record that was taken off the end.
        let fx = Fixture::new("audit-tail-cut");
        let log = write_chain(&fx.dir, 1);
        let file_record = records_at(&log)[0].clone();
        let next = linked_object(2, "different-chain-hash", &file_record.hash);
        let journal = ScriptedJournal::ok(&format!("{}\n{}\n", journal_object(&file_record), next));
        let (code, out, err) = audit_file(&log, true, &journal);
        assert_eq!(code, ExitCode::Denied);
        assert_eq!(out, "");
        assert!(err.starts_with("<2>"), "{err}");
        assert!(err.contains("is not intact"), "{err}");
        assert!(
            err.contains("journal seq 2 links to the file's last record (1)"),
            "{err}"
        );
        assert!(err.contains("removed from the end"), "{err}");
        assert_eq!(journal.exe.borrow().as_str(), "/usr/bin/journalctl");
        let args = journal.args.borrow();
        assert_eq!(args[0], xudo_audit::journal::TRUSTED_SENDER);
        assert_eq!(
            args[1],
            format!("MESSAGE_ID={}", xudo_audit::journal::MESSAGE_ID)
        );
        for flag in [
            "--output=json",
            "--output-fields=XUDO_SEQ,XUDO_HASH,XUDO_PREV_HASH",
            "--no-pager",
        ] {
            assert!(
                args.iter().any(|arg| arg == flag),
                "{flag} missing: {args:?}"
            );
        }
    }

    #[test]
    fn a_forged_chain_the_journal_never_saw_is_caught() {
        let fx = Fixture::new("audit-other-chain");
        let log = write_chain(&fx.dir, 1);
        let unrelated = linked_object(40, "old-chain-hash", "old-chain-prev");
        let journal = ScriptedJournal::ok(&unrelated);
        let (code, out, err) = audit_file(&log, true, &journal);
        assert_eq!(code, ExitCode::Denied);
        assert_eq!(out, "");
        assert!(err.starts_with("<2>"), "{err}");
        assert!(
            err.contains("no journal entry matches any file record"),
            "{err}"
        );
    }

    #[test]
    fn a_new_chain_is_accepted_when_its_first_record_is_in_the_journal() {
        let fx = Fixture::new("audit-new-chain");
        let log = write_chain(&fx.dir, 1);
        let current = records_at(&log).remove(0);
        let old = linked_object(8, "old-chain-hash", "older-chain-hash");
        let journal = ScriptedJournal::ok(&format!("{old}\n{}", journal_object(&current)));
        let (code, out, err) = audit_file(&log, true, &journal);
        assert_eq!(code, ExitCode::Delegated, "{err}");
        assert!(out.contains("chain intact"), "{out}");
        assert_eq!(err, "");
    }

    #[test]
    fn thousands_of_file_and_journal_records_are_compared() {
        let fx = Fixture::new("audit-linear-chain");
        let log = write_chain(&fx.dir, 3_000);
        let records = records_at(&log);
        let entries = records
            .iter()
            .map(journal_object)
            .collect::<Vec<_>>()
            .join("\n");
        let journal = ScriptedJournal::ok(&entries);
        let (code, out, err) = audit_file(&log, true, &journal);
        assert_eq!(code, ExitCode::Delegated, "{err}");
        assert!(out.contains("3000 record(s)"), "{out}");
        assert!(
            out.contains("journal seq 3000 matches the file's last record"),
            "{out}"
        );
        assert_eq!(err, "");
    }

    #[test]
    fn a_tail_cut_and_then_continued_is_caught() {
        let fx = Fixture::new("audit-tail-continued");
        let log = write_chain(&fx.dir, 2);
        let records = records_at(&log);
        let replacement = linked_object(2, "replacement-hash", &records[0].hash);
        let journal = ScriptedJournal::ok(&format!(
            "{}\n{}\n",
            journal_object(&records[0]),
            replacement
        ));
        let (code, out, err) = audit_file(&log, true, &journal);
        assert_eq!(code, ExitCode::Denied);
        assert_eq!(out, "");
        assert!(err.contains("records were replaced after a cut"), "{err}");
    }

    #[test]
    fn an_empty_log_has_no_hash_link_to_attribute_a_journal_chain() {
        let fx = Fixture::new("audit-emptied");
        let log = fx.dir.join("log.jsonl");
        std::fs::write(&log, "").unwrap();
        let journal = ScriptedJournal::ok(&linked_object(3, "old-chain-hash", "older-chain-hash"));
        let (code, out, err) = audit_file(&log, true, &journal);
        assert_eq!(code, ExitCode::Delegated, "{err}");
        assert!(out.contains("chain intact"), "{out}");
        assert!(
            out.contains("cannot show whether a tail was removed"),
            "{out}"
        );
        assert_eq!(err, "");
    }

    #[test]
    fn a_journal_that_matches_or_trails_the_file_does_not_accuse_it() {
        let fx = Fixture::new("audit-journal-match");
        let log = write_chain(&fx.dir, 2);
        let records = records_at(&log);
        let matched = ScriptedJournal::ok(&format!(
            "{}\n{}\n",
            journal_object(&records[0]),
            journal_object(&records[1])
        ));
        let (code, out, err) = audit_file(&log, true, &matched);
        assert_eq!(code, ExitCode::Delegated, "{err}");
        assert!(out.contains("2 record(s)"), "{out}");
        assert!(out.contains("chain intact"), "{out}");
        assert!(
            out.contains("journal seq 2 matches the file's last record"),
            "{out}"
        );
        assert_eq!(err, "");

        // Behind: vacuum, or a dropped entry. Not a tail cut.
        let behind = ScriptedJournal::ok(&journal_object(&records[0]));
        let (code, out, err) = audit_file(&log, true, &behind);
        assert_eq!(code, ExitCode::Delegated, "{err}");
        assert!(
            out.contains("journal seq 1 is behind the file's last record (2)"),
            "{out}"
        );
        assert!(
            out.contains("cannot show whether a tail was removed"),
            "{out}"
        );
        let newer_unlinked = ScriptedJournal::ok(&format!(
            "{}\n{}",
            journal_object(&records[0]),
            linked_object(3, "other-chain-hash", "other-chain-prev")
        ));
        let (code, out, err) = audit_file(&log, true, &newer_unlinked);
        assert_eq!(code, ExitCode::Delegated, "{err}");
        assert!(out.contains("no link to this file's last record"), "{out}");

        let different_hash =
            ScriptedJournal::ok(&linked_object(2, "different-hash", "unrelated-prev"));
        let (code, out, err) = audit_file(&log, true, &different_hash);
        assert_eq!(code, ExitCode::Denied);
        assert_eq!(out, "");
        assert!(
            err.contains("no journal entry matches any file record"),
            "{err}"
        );
    }

    #[test]
    fn a_journal_with_no_root_written_entry_does_not_pretend_the_tail_was_checked() {
        let fx = Fixture::new("audit-journal-empty");
        let log = write_chain(&fx.dir, 1);
        let journal = ScriptedJournal::ok("\n");
        let (code, out, err) = audit_file(&log, true, &journal);
        assert_eq!(code, ExitCode::Delegated, "{err}");
        assert!(out.contains("chain intact"), "{out}");
        assert!(out.contains("no root-written xudo audit entry"), "{out}");
        assert!(out.contains("would not show"), "{out}");
    }

    #[test]
    fn an_unreadable_journal_is_not_an_intact_log() {
        let fx = Fixture::new("audit-journal-dead");
        let log = write_chain(&fx.dir, 1);
        let cases = [
            ScriptedJournal::new(Err(xudo_sys::SysError::unsupported(
                "cannot run journalctl",
            ))),
            ScriptedJournal::new(Ok(xudo_sys::Output {
                success: false,
                code: Some(1),
                stdout: String::new(),
                stderr: String::new(),
            })),
            ScriptedJournal::new(Ok(xudo_sys::Output {
                success: false,
                code: Some(1),
                stdout: String::new(),
                stderr: "permission denied\n".to_owned(),
            })),
            ScriptedJournal::new(Ok(xudo_sys::Output {
                success: false,
                code: None,
                stdout: String::new(),
                stderr: String::new(),
            })),
            ScriptedJournal::new(Ok(xudo_sys::Output {
                success: true,
                code: Some(0),
                stdout: String::new(),
                stderr: "journal file skipped\n".to_owned(),
            })),
            ScriptedJournal::ok("not json\n"),
            ScriptedJournal::ok("[1]\n"),
            ScriptedJournal::ok("{\"XUDO_SEQ\":4}\n"),
            ScriptedJournal::ok("{\"XUDO_SEQ\":\"1\"}\n"),
            ScriptedJournal::ok("{\"XUDO_SEQ\":\"nope\"}\n"),
            ScriptedJournal::ok("{\"XUDO_SEQ\":\"1\",\"XUDO_HASH\":\"h\"}\n"),
        ];
        for journal in cases {
            let (code, out, err) = audit_file(&log, true, &journal);
            assert_eq!(code, ExitCode::Unusable, "{err}");
            assert_eq!(out, "");
            assert!(err.starts_with("<2>"), "{err}");
            assert!(err.contains("cannot check"), "{err}");
            assert!(!err.contains("chain intact"), "{err}");
        }
    }

    #[test]
    fn the_journal_parser_requires_complete_chain_fields() {
        let entry = linked_object(9, "hash", "prev");
        let parsed = parse_journal_entries(&format!("\n{entry}\n")).unwrap();
        assert_eq!(parsed[0].seq, 9);
        assert_eq!(parse_journal_entries("").unwrap(), Vec::new());
        let bad = parse_journal_entries("nope\n").unwrap_err();
        assert!(bad.contains("line 1"), "{bad}");
        let not_entry = parse_journal_entries("[]\n").unwrap_err();
        assert!(not_entry.contains("not a journal entry"), "{not_entry}");
        let not_text = parse_journal_entries("{\"XUDO_SEQ\":1}\n").unwrap_err();
        assert!(not_text.contains("no text XUDO_SEQ"), "{not_text}");
        let not_seq = parse_journal_entries(&linked_object(0, "h", "p").replace("\"0\"", "\"x\""))
            .unwrap_err();
        assert!(not_seq.contains("not a sequence number"), "{not_seq}");
    }

    const RULES: &str = r#"
[[action]]
id = "xudo.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "xudo.pkg.update"
tier = "pkg-install"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]
"#;

    fn fixture(name: &str) -> Fixture {
        Fixture::new(name).write("10-rules.toml", RULES)
    }

    /// A platform that cannot observe a caller at all.
    ///
    /// Exists so the "cannot attest, fail closed" branch is reachable from a
    /// test rather than only on a broken machine.
    struct BlindOps;

    impl PrivilegedOps for BlindOps {
        fn kernel(&self) -> xudo_sys::KernelSupport {
            xudo_sys::KernelSupport::parse("6.8.0-90-generic")
        }

        fn platform(&self) -> &'static str {
            "blind-test-stub"
        }

        fn classify(&self, _pid: u32) -> Result<xudo_sys::CallerFacts, xudo_sys::SysError> {
            Err(xudo_sys::SysError::read("self/stat", "test stub refuses"))
        }

        fn resolve_exe(&self, _path: &str) -> Result<PathBuf, xudo_sys::SysError> {
            Err(xudo_sys::SysError::unsupported("resolve_exe"))
        }
    }

    /// A platform that reports an attested agent.
    ///
    /// No real platform can do this yet. It is here to cover the reporting
    /// branch for the day one can, and to prove the renderer does not assume
    /// every caller needs a password.
    struct AttestingOps;

    impl PrivilegedOps for AttestingOps {
        fn kernel(&self) -> xudo_sys::KernelSupport {
            xudo_sys::KernelSupport::parse("6.8.0-90-generic")
        }

        fn platform(&self) -> &'static str {
            "attesting-test-stub"
        }

        fn classify(&self, _pid: u32) -> Result<xudo_sys::CallerFacts, xudo_sys::SysError> {
            Ok(xudo_sys::CallerFacts::new(
                xudo_sys::Classification::EnrolledAgent {
                    agent_id: "claude-code".into(),
                    session_id: "s-1".into(),
                    declared_yolo: true,
                },
                1000,
            ))
        }

        fn resolve_exe(&self, _path: &str) -> Result<PathBuf, xudo_sys::SysError> {
            Err(xudo_sys::SysError::unsupported("resolve_exe"))
        }
    }

    fn run_ops(fx: &Fixture, ops: &dyn PrivilegedOps, args: &[&str]) -> (ExitCode, String, String) {
        let mut full = vec!["xudo", "--rules", fx.dir.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_on(&cli, ops, &HostProbe, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn the_test_platforms_refuse_to_resolve_an_executable() {
        // Every PrivilegedOps implementation, real or fake, must refuse this
        // until the openat2 + execveat path lands.
        for ops in [&BlindOps as &dyn PrivilegedOps, &AttestingOps] {
            let err = ops.resolve_exe("/usr/bin/systemctl").unwrap_err();
            assert!(err.to_string().contains("not supported"), "{err}");
        }
    }

    #[test]
    fn a_caller_that_cannot_be_observed_is_treated_as_unattested() {
        // Fail closed: an unobservable caller still gets an answer, and that
        // answer is the password-requiring one.
        let fx = fixture("cli-blind");
        let (code, out, err) = run_ops(
            &fx,
            &BlindOps,
            &[
                "explain",
                "--",
                "/usr/bin/systemctl",
                "restart",
                "nginx.service",
            ],
        );
        assert!(err.contains("cannot observe this caller"), "{err}");
        assert!(err.contains("treating as unattested"), "{err}");
        // The decision is still made, and still correct.
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.starts_with("ALLOW"), "{out}");
    }

    #[test]
    fn doctor_reports_a_platform_that_cannot_classify() {
        let fx = fixture("cli-doctor-blind");
        let (code, out, _) = run_ops(&fx, &BlindOps, &["doctor"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("platform     blind-test-stub"), "{out}");
        assert!(out.contains("classified   unavailable"), "{out}");
        assert!(
            out.contains("password     required (failing closed)"),
            "{out}"
        );
    }

    #[test]
    fn doctor_reports_an_attested_caller_as_not_needing_a_password() {
        let fx = fixture("cli-doctor-attested");
        let (code, out, _) = run_ops(&fx, &AttestingOps, &["doctor"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("classified   enrolled-agent"), "{out}");
        assert!(out.contains("password     not required"), "{out}");
    }

    #[test]
    fn an_attested_agent_is_told_a_human_must_confirm() {
        // The headline requirement, exercised through the CLI: even a yolo
        // agent gets a confirmation, so the exit status is not success.
        let fx = fixture("cli-agent-confirm");
        let (code, out, _) = run_ops(
            &fx,
            &AttestingOps,
            &[
                "explain",
                "--",
                "/usr/bin/systemctl",
                "restart",
                "nginx.service",
            ],
        );
        assert_eq!(code, ExitCode::NotConfirmed);
        assert!(out.contains("ALLOW, after a human confirms"), "{out}");
    }

    #[test]
    fn why_not_uses_the_injected_platform_too() {
        let fx = fixture("cli-whynot-ops");
        let (_, out, _) = run_ops(
            &fx,
            &AttestingOps,
            &[
                "why-not",
                "--action",
                "xudo.svc.restart",
                "--",
                "/usr/bin/systemctl",
                "restart",
                "nginx",
            ],
        );
        assert!(out.contains("argv_rejected"), "{out}");
    }

    #[test]
    fn explain_finds_the_matching_action_without_being_told_which() {
        let (code, out, _) = fixture("cli-explain").run(&[
            "explain",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ]);
        // ALLOW, and note what that does *not* mean: the human path's password
        // is sudo's job, not the verdict's. `confirm_agent_actions` applies to
        // an attested agent, and nobody is attested in this build, so the
        // policy answer here is a plain allow.
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.starts_with("ALLOW\n"), "{out}");
        assert!(out.contains("xudo.svc.restart"), "{out}");
        assert!(out.contains("10-rules.toml:3"), "{out}");
    }

    #[test]
    fn explain_reports_the_argv_rejection_when_nothing_permits_it() {
        let (code, out, _) =
            fixture("cli-reject").run(&["explain", "--", "/usr/bin/systemctl", "restart", "nginx"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(out.contains("DENY"), "{out}");
        assert!(out.contains("argv_rejected"), "{out}");
    }

    #[test]
    fn explain_reports_the_nearest_refusal_rather_than_giving_up() {
        // Every action rejects this argv on shape, and that is more useful to
        // report than "unknown", because it tells the operator a rule exists
        // and the arguments were wrong.
        let (code, out, _) = fixture("cli-unknown").run(&[
            "explain",
            "--",
            "/usr/bin/systemctl",
            "wat",
            "is",
            "this",
        ]);
        assert_eq!(code, ExitCode::Denied);
        assert!(out.contains("argv_rejected"), "{out}");
    }

    #[test]
    fn explain_against_an_empty_ruleset_says_nothing_matches() {
        // The only way there is no nearest refusal: no rules at all, which is
        // exactly the state of a fresh install.
        let empty = Fixture::new("cli-empty-rules");
        let (code, out, err) = empty.run(&[
            "explain",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ]);
        assert_eq!(code, ExitCode::Denied);
        assert!(err.contains("no action in"), "{err}");
        assert!(out.contains("unknown_action"), "{out}");
    }

    #[test]
    fn explain_can_be_pinned_to_one_action() {
        let (_, out, _) = fixture("cli-pinned").run(&[
            "explain",
            "--action",
            "xudo.pkg.update",
            "--",
            "/usr/bin/apt-get",
            "restart",
            "nginx.service",
        ]);
        // Pinned to the wrong rule on purpose: the answer must be about that
        // rule, not about whichever rule happens to match. Names the rule's own
        // program, so the refusal is about the arguments rather than the
        // program.
        assert!(out.contains("argv_rejected"), "{out}");
    }

    #[test]
    fn asking_a_rule_to_run_a_program_it_does_not_name_is_its_own_refusal() {
        // Not argv_rejected: a caller asking to run apt-get under a rule for
        // systemctl is not making an argument mistake, and an audit record that
        // called it one would bury an attempted bypass among ordinary typos.
        let (code, out, _) = fixture("cli-exe-mismatch").run(&[
            "explain",
            "--action",
            "xudo.svc.restart",
            "--",
            "/usr/bin/apt-get",
            "restart",
            "nginx.service",
        ]);
        assert_eq!(code, ExitCode::Denied);
        assert!(out.contains("exe_mismatch"), "{out}");
        assert!(
            out.contains("/usr/bin/systemctl, not the requested"),
            "{out}"
        );
    }

    #[test]
    fn splitting_an_empty_command_yields_no_program_and_no_operands() {
        // Reachable rather than defensive: an empty program matches no rule's
        // exe, so the split still fails closed if a caller ever skips the
        // emptiness check above it.
        let (program, operands) = split_program(&[]);
        assert_eq!(program, "");
        assert!(operands.is_empty());
    }

    #[test]
    fn every_rule_for_the_program_reports_why_it_refused() {
        // Two rules for the same binary, both refusing. Each one's reason is
        // in the trace, in declaration order, so the answer does not depend on
        // which happened to sort first.
        let fx = Fixture::new("cli-two-rules").write(
            "10-two.toml",
            r#"
[[action]]
id = "xudo.svc.aaa"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [{ name = "verb", matcher = { literal = "start" } }]

[[action]]
id = "xudo.svc.bbb"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [{ name = "verb", matcher = { literal = "stop" } }]
"#,
        );
        let (code, out, _) = fx.run(&["explain", "--", "/usr/bin/systemctl", "reload"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(out.contains("argv_rejected"), "{out}");
        let first = out.find("skipped xudo.svc.aaa").expect("the first refusal");
        let second = out
            .find("skipped xudo.svc.bbb")
            .expect("the second refusal");
        assert!(first < second, "{out}");
    }

    /// Two rule files that accept the same command: one always confirms, the
    /// other does not ask at all.
    const CONFIRMING: &str = r#"
[[action]]
id = "xudo.pkg.remove-toolchain"
tier = "pkg-remove"
confirm = "always"
exe = "/usr/bin/apt-get"
args = [
  { name = "verb", matcher = { literal = "remove" } },
  { name = "pkg", matcher = { one-of = ["gcc", "make"] } },
]
"#;

    const PERMISSIVE: &str = r#"
[[action]]
id = "xudo.pkg.remove-quick"
tier = "pkg-remove"
confirm = "never"
exe = "/usr/bin/apt-get"
args = [
  { name = "verb", matcher = { literal = "remove" } },
  { name = "pkg", matcher = { name = "deb-name" } },
]
"#;

    #[test]
    fn reordering_rule_files_cannot_drop_a_confirmation_from_explain() {
        // The hole step 2b closed, through the command an operator runs: with
        // the first permitting action winning, renaming one file so it sorted
        // first turned "a human confirms" into a bare allow.
        for (name, files) in [
            (
                "cli-overlap-forward",
                [("10-a.toml", CONFIRMING), ("20-b.toml", PERMISSIVE)],
            ),
            (
                "cli-overlap-backward",
                [("10-a.toml", PERMISSIVE), ("20-b.toml", CONFIRMING)],
            ),
        ] {
            let fx = files
                .iter()
                .fold(Fixture::new(name), |fx, (file, body)| fx.write(file, body));
            let (code, out, _) = fx.run(&["explain", "--", "/usr/bin/apt-get", "remove", "gcc"]);
            assert_eq!(code, ExitCode::NotConfirmed, "{name}: {out}");
            assert!(out.starts_with("ALLOW, after a human confirms"), "{out}");
            assert!(out.contains("action    xudo.pkg.remove-toolchain"), "{out}");
            assert!(out.contains("matched xudo.pkg.remove-quick"), "{out}");
            assert!(out.contains("strictest requirement among the 2"), "{out}");

            // Naming the permissive rule does not help either.
            let (code, _, _) = fx.run(&[
                "explain",
                "--action",
                "xudo.pkg.remove-quick",
                "--",
                "/usr/bin/apt-get",
                "remove",
                "gcc",
            ]);
            assert_eq!(code, ExitCode::NotConfirmed, "{name}");
        }
    }

    #[test]
    fn check_reports_actions_that_can_accept_the_same_command() {
        let fx = Fixture::new("cli-check-overlap")
            .write("10-a.toml", CONFIRMING)
            .write("20-b.toml", PERMISSIVE)
            .write(
                "30-c.toml",
                r#"
[[action]]
id = "xudo.net.lookup-internal"
tier = "diag-read"
exe = "/usr/bin/host"
args = [{ name = "host", matcher = { pattern = "[a-z]+\\.internal" } }]

[[action]]
id = "xudo.net.lookup-any"
tier = "diag-read"
exe = "/usr/bin/host"
args = [{ name = "target", matcher = { pattern = "[a-z.]+" } }]
"#,
            );
        let (code, out, err) = fx.run(&["check"]);
        // Reported, not refused: the engine resolves an overlap safely.
        assert_eq!(code, ExitCode::Delegated, "{err}");
        insta::assert_snapshot!("check_reports_overlaps", out);
    }

    #[test]
    fn check_reports_no_overlap_in_the_shipped_rules() {
        let shipped = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("rules");
        let cli =
            Cli::try_parse_from(["xudo", "--rules", shipped.to_str().unwrap(), "check"]).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_on(&cli, host_ops().as_ref(), &HostProbe, &mut out, &mut err);
        let out = String::from_utf8_lossy(&out).into_owned();
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.starts_with("ok: "), "{out}");
        assert!(!out.contains("overlap"), "{out}");
    }

    #[test]
    fn a_command_with_no_program_named_matches_nothing() {
        // Before the program became part of the decision, a bare `restart
        // nginx.service` was matched against the argument list and *allowed* by
        // a rule for /usr/bin/systemctl — with no program named at all.
        let (code, out, _) =
            fixture("cli-no-program").run(&["explain", "--", "restart", "nginx.service"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(!out.contains("ALLOW"), "{out}");
    }

    #[test]
    fn explain_with_no_command_is_an_error_rather_than_an_empty_answer() {
        let (code, _, err) = fixture("cli-noargv").run(&["explain"]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("pass a command after"), "{err}");
    }

    #[test]
    fn explain_emits_the_envelope_in_json_mode() {
        let (_, out, _) = fixture("cli-json").run(&[
            "--output",
            "json",
            "explain",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["action"], "xudo.svc.restart");
    }

    #[test]
    fn why_not_interrogates_one_action() {
        let (code, out, _) = fixture("cli-whynot").run(&[
            "why-not",
            "--action",
            "xudo.svc.restart",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx",
        ]);
        assert_eq!(code, ExitCode::Denied);
        assert!(out.contains("does not satisfy unit"), "{out}");
    }

    #[test]
    fn why_not_says_so_when_the_action_actually_permits_the_command() {
        let (_, _, err) = fixture("cli-whynot-ok").run(&[
            "why-not",
            "--action",
            "xudo.svc.restart",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ]);
        assert!(err.contains("does not refuse"), "{err}");
    }

    #[test]
    fn check_passes_on_a_clean_ruleset() {
        let (code, out, _) = fixture("cli-check").run(&["check"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.starts_with("ok: 2 action(s)"), "{out}");
        assert!(out.contains("generation "), "{out}");
    }

    #[test]
    fn check_fails_on_a_rule_that_allowlists_a_shell() {
        let fx = Fixture::new("cli-check-shell").write(
            "10-oops.toml",
            r#"
[[action]]
id = "xudo.oops"
tier = "diag-read"
exe = "/bin/sh"
args = [{ name = "c", matcher = { literal = "-c" } }]
"#,
        );
        let (code, _, err) = fx.run(&["check"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(err.contains("SpawnsShell"), "{err}");
        assert!(err.contains("defeats the design"), "{err}");
    }

    #[test]
    fn list_shows_every_action_and_can_filter_by_tier() {
        let fx = fixture("cli-list");
        let (code, out, _) = fx.run(&["list"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("xudo.svc.restart"));
        assert!(out.contains("xudo.pkg.update"));

        let (_, filtered, _) = fx.run(&["list", "--tier", "svc-control"]);
        assert!(filtered.contains("xudo.svc.restart"));
        assert!(!filtered.contains("xudo.pkg.update"), "{filtered}");
    }

    #[test]
    fn list_reports_when_a_filter_matches_nothing() {
        let (code, _, err) = fixture("cli-list-empty").run(&["list", "--tier", "critical"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(err.contains("no action matched"));
    }

    #[test]
    fn agentdoc_renders_the_block_stamped_with_the_generation() {
        let fx = fixture("cli-agentdoc");
        for format in ["agents", "claude", "codex"] {
            let (code, out, _) = fx.run(&["agentdoc", "--format", format]);
            assert_eq!(code, ExitCode::Delegated);
            assert!(out.contains("xudo:begin"), "{out}");
            assert!(out.contains("xudo.svc.restart"), "{out}");
            assert!(out.contains(&format!("--format {format}")), "{out}");
        }
    }

    #[test]
    fn doctor_works_even_when_the_ruleset_does_not_load() {
        // The whole point of doctor: it is what an operator runs when something
        // is broken, so it must not require the broken thing.
        let broken = Fixture::new("cli-doctor-broken").write("10-a.toml", "[[action]\nid =");
        let (code, out, _) = broken.run(&["doctor"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("ruleset      NOT LOADED"), "{out}");
        assert!(out.contains("platform     "), "{out}");
    }

    /// A machine with no privilege backend at all.
    struct NoBackendProbe;

    impl Probe for NoBackendProbe {
        fn exists(&self, _absolute_path: &str) -> bool {
            false
        }
        fn version_banner(&self, _absolute_path: &str) -> Option<String> {
            None
        }
        fn directory_exists(&self, _absolute_path: &str) -> bool {
            false
        }
        fn honours_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
            false
        }

        fn honours_scoped_directive(&self, path: &str, directive: &str) -> bool {
            self.honours_directive(path, directive)
        }

        fn validates_named_file(&self, _path: &str) -> bool {
            true
        }

        fn accepts_argument_wildcard(&self, _path: &str) -> bool {
            true
        }
    }

    /// A machine with a fully working sudo.
    struct WorkingSudoProbe;

    impl Probe for WorkingSudoProbe {
        fn exists(&self, absolute_path: &str) -> bool {
            absolute_path == "/usr/bin/sudo"
        }
        fn version_banner(&self, _absolute_path: &str) -> Option<String> {
            Some("Sudo version 1.9.17p2\n".to_owned())
        }
        fn directory_exists(&self, absolute_path: &str) -> bool {
            absolute_path == "/etc/sudoers.d"
        }
        fn honours_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
            true
        }

        fn honours_scoped_directive(&self, path: &str, directive: &str) -> bool {
            self.honours_directive(path, directive)
        }

        fn validates_named_file(&self, _path: &str) -> bool {
            true
        }

        fn accepts_argument_wildcard(&self, _path: &str) -> bool {
            true
        }
    }

    fn run_probe(fx: &Fixture, probe: &dyn Probe, args: &[&str]) -> String {
        let mut full = vec!["xudo", "--rules", fx.dir.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _ = run_on(&cli, host_ops().as_ref(), probe, &mut out, &mut err);
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Runs a command with a probe, returning (exit, stdout, stderr).
    fn run_probe_full(
        fx: &Fixture,
        probe: &dyn Probe,
        args: &[&str],
    ) -> (ExitCode, String, String) {
        let mut full = vec!["xudo", "--rules", fx.dir.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_on(&cli, host_ops().as_ref(), probe, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn the_probe_doubles_answer_every_question_in_the_trait() {
        // These are part of each double's contract even when the command under
        // test stops before asking. A double that silently answered differently
        // from what a test assumes is a test proving nothing.
        assert!(WorkingSudoProbe.honours_scoped_directive("/usr/bin/sudo", "use_pty"));
        assert!(WorkingSudoProbe.validates_named_file("/usr/bin/sudo"));
        assert!(WorkingSudoProbe.accepts_argument_wildcard("/usr/bin/sudo"));
        assert!(!NoBackendProbe.honours_scoped_directive("/usr/bin/sudo", "use_pty"));
        assert!(NoBackendProbe.validates_named_file("/usr/bin/sudo"));
        assert!(NoBackendProbe.accepts_argument_wildcard("/usr/bin/sudo"));
    }

    #[test]
    fn a_backend_that_cannot_be_given_a_snippet_reports_why() {
        // Unreachable through the command, because detection refuses an unusable
        // backend first. Exercised directly so the planner's own error path is
        // one somebody has read.
        let crippled = xudo_backend::Backend {
            kind: xudo_backend::BackendKind::Sudo,
            exe: "/usr/bin/sudo".to_owned(),
            version: "Sudo version 0.0".to_owned(),
            capabilities: xudo_backend::CapabilityMatrix::empty(),
        };
        let reason = plan_for(&crippled).unwrap_err();
        assert!(reason.contains("cannot generate a snippet"), "{reason}");
    }

    #[test]
    fn install_prints_the_plan_and_writes_nothing() {
        let fx = fixture("cli-install");
        let (code, out, err) = run_probe_full(&fx, &WorkingSudoProbe, &["install", "--dry-run"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("plan for     sudo"), "{out}");
        // The order is the security property: validate before install, and a
        // functional probe after it, because a file existing proves nothing.
        let validate = out.find("validate:").expect("a validate step");
        let install = out.find("atomically install").expect("an install step");
        let probe_at = out.find("probe:").expect("a functional probe step");
        assert!(validate < install, "{out}");
        assert!(install < probe_at, "{out}");
        assert!(out.contains("Nothing was written"), "{out}");
        assert_eq!(err, "");
    }

    #[test]
    fn install_without_dry_run_cannot_modify_the_machine_from_an_injected_platform() {
        // `run_with` is what every test drives. It must be impossible for one of
        // them, run as root in a container, to write under /etc.
        let fx = fixture("cli-install-bare");
        let (code, out, err) = run_probe_full(&fx, &WorkingSudoProbe, &["install"]);
        assert_eq!(code, ExitCode::Unusable);
        assert_eq!(out, "");
        assert!(err.contains("cannot modify the machine"), "{err}");
        assert!(err.contains("install failed"), "{err}");
    }

    /// An installer that records the plans it was given and answers as told.
    struct ScriptedInstaller {
        plans: std::cell::RefCell<Vec<InstallPlan>>,
        answers: std::cell::RefCell<Vec<Result<InstallReport, xudo_sys::InstallError>>>,
    }

    impl ScriptedInstaller {
        fn answering(answers: Vec<Result<InstallReport, xudo_sys::InstallError>>) -> Self {
            Self {
                plans: std::cell::RefCell::new(Vec::new()),
                answers: std::cell::RefCell::new(answers.into_iter().rev().collect()),
            }
        }
    }

    impl Installer for ScriptedInstaller {
        fn run(&self, plan: &InstallPlan) -> Result<InstallReport, xudo_sys::InstallError> {
            self.plans.borrow_mut().push(plan.clone());
            self.answers
                .borrow_mut()
                .pop()
                .unwrap_or(Err(xudo_sys::InstallError::NoInstaller))
        }
    }

    fn report(backend: BackendKind, verification: Verification) -> InstallReport {
        InstallReport {
            backend,
            events: vec!["installed /etc/sudoers.d/xudo".to_owned()],
            notices: vec!["every invocation will prompt".to_owned()],
            verification,
        }
    }

    fn run_installing(
        fx: &Fixture,
        probe: &dyn Probe,
        installer: &dyn Installer,
        args: &[&str],
    ) -> (ExitCode, String, String) {
        let mut full = vec!["xudo", "--rules", fx.dir.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let ops = host_ops();
        let platform = Platform {
            ops: ops.as_ref(),
            probe,
            host: &LiveHost,
            path: None,
        };
        let code = run_with_installer(&cli, &platform, installer, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn an_install_that_could_not_be_verified_says_so_and_exits_non_zero() {
        // The honest outcome of this build: files written, nothing proving they
        // take effect. A quiet success here is the claim xudo must not make.
        let fx = fixture("cli-install-unverified");
        let installer = ScriptedInstaller::answering(vec![Ok(report(
            BackendKind::Sudo,
            Verification::Unverified {
                reason: "the front-end cannot yet ask the broker for a request".to_owned(),
            },
        ))]);
        let (code, out, err) = run_installing(&fx, &WorkingSudoProbe, &installer, &["install"]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("NOT VERIFIED"), "{err}");
        assert!(err.contains("cannot yet ask the broker"), "{err}");
        assert!(out.contains("installed /etc/sudoers.d/xudo"), "{out}");
        assert!(out.contains("every invocation will prompt"), "{out}");
        assert!(
            !out.contains("verified     "),
            "claimed verification: {out}"
        );
        // The plan it ran is the one a dry run prints: for the detected backend.
        let plans = installer.plans.borrow();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].backend, BackendKind::Sudo);
    }

    #[test]
    fn an_install_whose_probe_passed_is_reported_verified_and_exits_zero() {
        let fx = fixture("cli-install-verified");
        let installer = ScriptedInstaller::answering(vec![Ok(report(
            BackendKind::Sudo,
            Verification::Verified,
        ))]);
        let (code, out, err) = run_installing(&fx, &WorkingSudoProbe, &installer, &["install"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(
            out.contains("verified     the functional probe passed"),
            "{out}"
        );
        assert_eq!(err, "");
    }

    #[test]
    fn a_failed_install_prints_why_and_exits_unusable() {
        let fx = fixture("cli-install-fails");
        let installer =
            ScriptedInstaller::answering(vec![Err(xudo_sys::InstallError::NotRoot { uid: 1000 })]);
        let (code, out, err) = run_installing(&fx, &WorkingSudoProbe, &installer, &["install"]);
        assert_eq!(code, ExitCode::Unusable);
        assert_eq!(out, "");
        assert!(err.contains("install failed"), "{err}");
        assert!(err.contains("requires root"), "{err}");
    }

    #[test]
    fn an_install_with_no_usable_backend_runs_nothing() {
        let fx = fixture("cli-install-nobackend");
        let installer = ScriptedInstaller::answering(vec![]);
        let (code, _, err) = run_installing(&fx, &NoBackendProbe, &installer, &["install"]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("no usable backend"), "{err}");
        assert!(installer.plans.borrow().is_empty());
    }

    #[test]
    fn a_dry_run_never_reaches_the_installer() {
        let fx = fixture("cli-install-dry");
        let installer = ScriptedInstaller::answering(vec![]);
        let (code, _, _) = run_installing(
            &fx,
            &WorkingSudoProbe,
            &installer,
            &["install", "--dry-run"],
        );
        assert_eq!(code, ExitCode::Delegated);
        assert!(installer.plans.borrow().is_empty());
    }

    #[test]
    fn an_uninstall_needs_no_backend_and_removes_for_both() {
        // sudo may have been removed before xudo was; the file it wrote must
        // still go.
        let fx = fixture("cli-uninstall");
        let removed = |backend| InstallReport {
            backend,
            events: vec!["removed something".to_owned()],
            notices: vec![],
            verification: Verification::NotRequired,
        };
        let installer = ScriptedInstaller::answering(vec![
            Ok(removed(BackendKind::Sudo)),
            Ok(removed(BackendKind::Doas)),
        ]);
        let (code, out, err) = run_installing(
            &fx,
            &NoBackendProbe,
            &installer,
            &["install", "--uninstall"],
        );
        assert_eq!(code, ExitCode::Delegated, "{err}");
        let plans = installer.plans.borrow();
        assert_eq!(
            plans.iter().map(|p| p.backend).collect::<Vec<_>>(),
            [BackendKind::Sudo, BackendKind::Doas]
        );
        assert!(out.contains("removed something"), "{out}");
        assert!(!err.contains("NOT VERIFIED"), "{err}");
    }

    #[test]
    fn an_uninstall_that_fails_stops_and_says_it_was_an_uninstall() {
        let fx = fixture("cli-uninstall-fails");
        let installer = ScriptedInstaller::answering(vec![Err(xudo_sys::InstallError::NotOurs {
            path: "/etc/sudoers.d/xudo".to_owned(),
            reason: "it does not begin with xudo's marker".to_owned(),
        })]);
        let (code, _, err) = run_installing(
            &fx,
            &NoBackendProbe,
            &installer,
            &["install", "--uninstall"],
        );
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("uninstall failed"), "{err}");
        assert!(err.contains("not a file xudo wrote"), "{err}");
        // The second plan was not attempted after the first refused.
        assert_eq!(installer.plans.borrow().len(), 1);
    }

    #[test]
    fn an_uninstall_dry_run_prints_both_removals_and_writes_nothing() {
        let fx = fixture("cli-uninstall-dry");
        let installer = ScriptedInstaller::answering(vec![]);
        let (code, out, _) = run_installing(
            &fx,
            &NoBackendProbe,
            &installer,
            &["install", "--uninstall", "--dry-run"],
        );
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("plan for     sudo"), "{out}");
        assert!(out.contains("plan for     doas"), "{out}");
        assert!(out.contains("remove /etc/sudoers.d/xudo"), "{out}");
        assert!(
            out.contains("remove xudo's block from /etc/doas.conf"),
            "{out}"
        );
        assert!(installer.plans.borrow().is_empty());
    }

    #[test]
    fn install_shows_the_file_it_would_write_when_asked() {
        let fx = fixture("cli-install-contents");
        let (_, out, _) = run_probe_full(
            &fx,
            &WorkingSudoProbe,
            &["install", "--dry-run", "--show-contents"],
        );
        // The two tokens that carry the whole security argument for the file.
        assert!(out.contains("timestamp_timeout=0"), "{out}");
        assert!(out.contains("use_pty"), "{out}");
        // And no passwordless rule, in the build that ships.
        assert!(!out.contains("NOPASSWD"), "{out}");
    }

    #[test]
    fn install_refuses_when_there_is_no_backend_to_install_into() {
        let fx = fixture("cli-install-nobackend");
        let (code, _, err) = run_probe_full(&fx, &NoBackendProbe, &["install", "--dry-run"]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("no usable backend"), "{err}");
    }

    #[test]
    fn install_refuses_a_backend_that_cannot_be_given_a_snippet() {
        // A backend that answers no to every directive fails detection first,
        // which is the same refusal an operator needs to see: xudo declines
        // rather than installing something weaker than it advertises.
        struct MuteProbe;
        impl Probe for MuteProbe {
            fn exists(&self, absolute_path: &str) -> bool {
                absolute_path == "/usr/bin/sudo"
            }
            fn version_banner(&self, _absolute_path: &str) -> Option<String> {
                Some("Sudo version 1.9.17p2\n".to_owned())
            }
            fn directory_exists(&self, _absolute_path: &str) -> bool {
                true
            }
            fn honours_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
                false
            }
            fn honours_scoped_directive(&self, _path: &str, _directive: &str) -> bool {
                false
            }
            fn validates_named_file(&self, _path: &str) -> bool {
                false
            }
            fn accepts_argument_wildcard(&self, _path: &str) -> bool {
                false
            }
        }
        let fx = fixture("cli-install-mute");
        let (code, _, err) = run_probe_full(&fx, &MuteProbe, &["install", "--dry-run"]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("no usable backend"), "{err}");
    }

    #[test]
    fn every_plan_step_reports_the_text_it_would_write_or_none() {
        // step_contents must stay exhaustive: a step added later that writes a
        // file and is not listed here would print nothing under
        // --show-contents, which is the one flag whose job is to show it.
        let writes = [
            PlanStep::WriteCandidate {
                path: "/p".to_owned(),
                contents: "body".to_owned(),
                mode: 0o440,
            },
            PlanStep::AppendBlock {
                path: "/p".to_owned(),
                block: "body".to_owned(),
            },
            PlanStep::Notice {
                text: "body".to_owned(),
            },
        ];
        for step in &writes {
            assert_eq!(step_contents(step), "body", "{step:?}");
        }
        let silent = [
            PlanStep::CreateGroup {
                name: "xudo".to_owned(),
            },
            PlanStep::Validate { argv: Vec::new() },
            PlanStep::ValidateBySubstitution {
                candidate: "/c".to_owned(),
                reason: "r".to_owned(),
            },
            PlanStep::Install {
                from: "/a".to_owned(),
                to: "/b".to_owned(),
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
                argv: Vec::new(),
                expectation: "e".to_owned(),
            },
        ];
        for step in &silent {
            assert_eq!(step_contents(step), "", "{step:?}");
        }
    }

    #[test]
    fn a_probe_that_finds_nothing_answers_every_question_negatively() {
        // The stub's other methods are part of its contract even though
        // detection short-circuits before reaching them.
        let probe = NoBackendProbe;
        assert!(probe.version_banner("/usr/bin/sudo").is_none());
        assert!(!probe.directory_exists("/etc/sudoers.d"));
        assert!(!probe.honours_directive("/usr/bin/sudo", "use_pty"));
    }

    #[test]
    fn a_settings_file_actually_changes_a_decision() {
        // Blocker 7. Before this, the layered configuration was reported by
        // `xudo config` and then ignored by every decision, so an operator
        // would set a value and be told it took effect while the engine ran on
        // its defaults.
        let fx = fixture("cli-config-effective");
        let path = fx.config_path();
        std::fs::write(&path, "frozen = true\n").unwrap();

        // An enrolled agent is refused while frozen.
        let mut full = vec![
            "xudo",
            "--rules",
            fx.dir.to_str().unwrap(),
            "--config-file",
            path.to_str().unwrap(),
            "explain",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ];
        let cli = Cli::try_parse_from(full.clone()).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_on(&cli, &AttestingOps, &HostProbe, &mut out, &mut err);
        assert_eq!(code, ExitCode::Denied);
        let rendered = String::from_utf8_lossy(&out).into_owned();
        assert!(rendered.contains("frozen"), "{rendered}");
        // And it says so plainly rather than sending the operator hunting for a
        // missing rule.
        assert!(!rendered.contains("unknown_action"), "{rendered}");

        // And the human path stays open, so an operator can always recover.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_on(&cli, host_ops().as_ref(), &HostProbe, &mut out, &mut err);
        assert_eq!(code, ExitCode::Delegated);

        // With the file removed the same agent is permitted again, which proves
        // the verdict came from the file rather than from a default.
        full.retain(|a| *a != path.to_str().unwrap() && *a != "--config-file");
        let bare = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_on(&bare, &AttestingOps, &HostProbe, &mut out, &mut err);
        assert_eq!(code, ExitCode::NotConfirmed);
    }

    #[test]
    fn a_broken_settings_file_fails_closed_for_a_decision_too() {
        // Not just for `xudo config`: a settings file that does not mean what it
        // says must not silently fall back to the defaults on the path that
        // actually decides things.
        let fx = fixture("cli-config-decide-broken");
        let path = fx.config_path();
        std::fs::write(&path, "frozen = \"yes\"\n").unwrap();
        let (code, _, err) = fx.run(&[
            "--config-file",
            path.to_str().unwrap(),
            "explain",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("settings file was not applied"), "{err}");

        // `why-not` decides too, so it fails closed on the same file rather
        // than quietly answering from the defaults.
        let (code, _, err) = fx.run(&[
            "--config-file",
            path.to_str().unwrap(),
            "why-not",
            "--action",
            "xudo.svc.restart",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx",
        ]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("settings file was not applied"), "{err}");

        let (code, _, err) = fx.run(&[
            "--config-file",
            path.to_str().unwrap(),
            "exec",
            "--",
            "/usr/bin/systemctl",
            "restart",
            "nginx.service",
        ]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("settings file was not applied"), "{err}");
    }

    #[test]
    fn config_lists_every_setting_with_its_origin() {
        let (code, out, _) = fixture("cli-config").run(&["config"]);
        assert_eq!(code, ExitCode::Delegated);
        // Every setting appears, defaults say they are defaults, and a
        // compiled-in value says it is compiled in rather than being omitted.
        assert!(out.contains("confirm_agent_actions      true"), "{out}");
        assert!(out.contains("<default>"), "{out}");
        assert!(out.contains("use_pty"), "{out}");
        assert!(out.contains("<compiled-in>"), "{out}");
        assert!(
            out.contains("confirm_agent_actions has no effect until M4"),
            "{out}"
        );
        // Security-relevant settings are marked, and the legend explains it.
        assert!(out.contains("* confirm_agent_actions"), "{out}");
        assert!(out.contains("  color"), "{out}");
        assert!(out.contains("never settable from the environment"), "{out}");
    }

    #[test]
    fn config_reads_the_named_file_and_cites_its_line() {
        let fx = fixture("cli-config-file");
        let path = fx.config_path();
        std::fs::write(&path, "# ours\nconfirmation_timeout_secs = 15\n").unwrap();
        let (code, out, _) = fx.run(&["--config-file", path.to_str().unwrap(), "config"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("confirmation_timeout_secs  15"), "{out}");
        assert!(out.contains("config.toml:2"), "{out}");
    }

    #[test]
    fn config_fails_closed_on_a_broken_settings_file() {
        // The defaults are safe, but continuing while pretending the file was
        // applied is not.
        let fx = fixture("cli-config-broken");
        let path = fx.config_path();
        std::fs::write(&path, "confirm_agent_action = false\n").unwrap();
        let (code, _, err) = fx.run(&["--config-file", path.to_str().unwrap(), "config"]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(err.contains("confirm_agent_action"), "{err}");
        assert!(err.contains("failing closed"), "{err}");
    }

    #[test]
    fn a_missing_settings_file_leaves_the_defaults_in_force() {
        // Not an error: the defaults are the configuration until somebody
        // writes one, and they are the safe values.
        let (code, out, _) = fixture("cli-config-absent").run(&[
            "--config-file",
            "/nonexistent/xudo/config.toml",
            "config",
        ]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("confirm_agent_actions      true"), "{out}");
        assert!(out.contains("<default>"), "{out}");
    }

    #[test]
    fn the_default_settings_file_is_the_root_owned_one() {
        let cli = Cli::try_parse_from(["xudo", "config"]).unwrap();
        assert_eq!(cli.config_file, PathBuf::from(DEFAULT_CONFIG_FILE));
    }

    #[test]
    fn config_schema_is_machine_readable_and_states_the_environment_rule() {
        let (code, out, _) = fixture("cli-config-schema").run(&["config", "--schema"]);
        assert_eq!(code, ExitCode::Delegated);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let entries = parsed.as_array().unwrap();
        assert_eq!(entries.len(), Setting::ALL.len());
        let confirm = entries
            .iter()
            .find(|e| e["key"] == "confirm_agent_actions")
            .unwrap();
        assert_eq!(confirm["settable_from_environment"], false);
        assert_eq!(confirm["default"], "true");
        let color = entries.iter().find(|e| e["key"] == "color").unwrap();
        assert_eq!(color["settable_from_environment"], true);
    }

    #[test]
    fn a_config_file_flag_is_never_labelled_system() {
        assert_eq!(origin_layer(Path::new(DEFAULT_CONFIG_FILE)), Layer::System);
        assert_eq!(origin_layer(Path::new("/tmp/x")), Layer::ConfigFile);
    }

    #[test]
    fn config_get_names_the_real_file_and_line() {
        let fx = fixture("cli-config-get");
        let path = fx.config_path();
        std::fs::write(&path, "# ours\n\nfrozen = true\n").unwrap();
        let file = path.to_str().unwrap();
        let (code, out, _) =
            fx.run(&["--config-file", file, "config", "get", "frozen", "--origin"]);
        assert_eq!(code, ExitCode::Delegated);
        assert_eq!(out, format!("true\t--config-file ({file}:3)\n"));
        let (_, out, _) = fx.run(&["--config-file", file, "config", "get", "frozen"]);
        assert_eq!(out, "true\n");
    }

    #[test]
    fn config_get_refuses_a_key_that_is_not_a_setting() {
        let (code, out, err) =
            fixture("cli-config-get-bad").run(&["config", "get", "confirm_agent_action"]);
        assert_eq!(code, ExitCode::Unusable);
        assert!(out.is_empty(), "{out}");
        assert!(err.contains("not a setting"), "{err}");
    }

    #[test]
    fn config_list_shows_defaults_and_compiled_in_only_when_effective() {
        let fx = fixture("cli-config-list");
        let (code, out, _) = fx.run(&[
            "--config-file",
            "/nonexistent/xudo/config.toml",
            "config",
            "list",
            "--origin",
        ]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.is_empty(), "nothing is set by a file: {out}");
        let (_, out, _) = fx.run(&[
            "--config-file",
            "/nonexistent/xudo/config.toml",
            "config",
            "list",
            "--origin",
            "--effective",
        ]);
        assert_eq!(out.lines().count(), Setting::ALL.len(), "{out}");
        assert!(
            out.lines()
                .any(|l| l.starts_with("use_pty") && l.ends_with("<compiled-in>")),
            "{out}"
        );
    }

    #[test]
    fn config_schema_subcommand_matches_the_flag() {
        let fx = fixture("cli-config-schema-sub");
        let (_, flag, _) = fx.run(&["config", "--schema"]);
        let (code, sub, _) = fx.run(&["config", "schema", "--json"]);
        assert_eq!(code, ExitCode::Delegated);
        assert_eq!(flag, sub);
    }

    #[test]
    fn doctor_reports_a_working_backend_with_its_capability_count() {
        let out = run_probe(&fixture("cli-doctor-ok"), &WorkingSudoProbe, &["doctor"]);
        assert!(
            out.contains("backend      sudo (Sudo version 1.9.17p2)"),
            "{out}"
        );
        // Six of seven: the C sudo accepts argument wildcards, so it does not
        // have the capability that consists of rejecting them. That is a
        // property of sudo, not a defect, and both required controls are present.
        assert!(out.contains("backend caps 6 of 7 supported"), "{out}");
        assert!(out.contains("absent: rejects argument wildcards"), "{out}");
        assert!(
            !out.contains("REQUIRED"),
            "a required control is missing: {out}"
        );
    }

    #[test]
    fn doctor_names_the_capabilities_a_backend_lacks() {
        // A doas port: no drop-in directory, so it appends a delimited block to
        // a shared file instead. It does scope its settings — doas options live
        // on the rule itself — so it stays usable.
        struct DoasProbe;
        impl Probe for DoasProbe {
            fn exists(&self, absolute_path: &str) -> bool {
                absolute_path == "/usr/bin/doas"
            }
            fn version_banner(&self, _absolute_path: &str) -> Option<String> {
                Some("doas (OpenDoas) 6.8.2".to_owned())
            }
            fn directory_exists(&self, _absolute_path: &str) -> bool {
                false
            }
            fn honours_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
                true
            }

            fn honours_scoped_directive(&self, path: &str, directive: &str) -> bool {
                self.honours_directive(path, directive)
            }

            fn validates_named_file(&self, _path: &str) -> bool {
                true
            }

            fn accepts_argument_wildcard(&self, _path: &str) -> bool {
                true
            }
        }
        // Asked directly: doas capabilities are derived from the doas probe, so
        // the sudo-family questions are never put to this double by the command.
        assert!(DoasProbe.honours_scoped_directive("/usr/bin/doas", "pty"));
        assert!(DoasProbe.validates_named_file("/usr/bin/doas"));
        assert!(DoasProbe.accepts_argument_wildcard("/usr/bin/doas"));

        let out = run_probe(&fixture("cli-doctor-doas"), &DoasProbe, &["doctor"]);
        assert!(out.contains("backend      doas"), "{out}");
        assert!(out.contains("absent: drop-in directory"), "{out}");
    }

    #[test]
    fn doctor_says_when_a_version_could_not_be_probed_rather_than_leaving_it_blank() {
        struct MuteSudoProbe;
        impl Probe for MuteSudoProbe {
            fn exists(&self, absolute_path: &str) -> bool {
                absolute_path == "/usr/bin/sudo"
            }
            fn version_banner(&self, _absolute_path: &str) -> Option<String> {
                None
            }
            fn directory_exists(&self, _absolute_path: &str) -> bool {
                true
            }
            fn honours_directive(&self, _absolute_path: &str, _directive: &str) -> bool {
                true
            }

            fn honours_scoped_directive(&self, path: &str, directive: &str) -> bool {
                self.honours_directive(path, directive)
            }

            fn validates_named_file(&self, _path: &str) -> bool {
                true
            }

            fn accepts_argument_wildcard(&self, _path: &str) -> bool {
                true
            }
        }
        let out = run_probe(&fixture("cli-doctor-mute"), &MuteSudoProbe, &["doctor"]);
        assert!(out.contains("no version banner"), "{out}");
        // An unreadable banner is assumed to be the stricter implementation.
        assert!(out.contains("backend      sudo-rs"), "{out}");
    }

    #[test]
    fn doctor_says_plainly_when_there_is_no_backend_at_all() {
        let out = run_probe(&fixture("cli-doctor-none"), &NoBackendProbe, &["doctor"]);
        assert!(out.contains("backend      NONE"), "{out}");
        assert!(out.contains("cannot operate on this machine"), "{out}");
        assert!(out.contains("performs none itself"), "{out}");
    }

    #[test]
    fn doctor_reports_a_backend_that_refuses_a_required_directive_as_unusable() {
        // The sudo-rs failure mode: the backend exists and answers its version,
        // but silently ignores a control xudo depends on.
        struct DeafSudoProbe;
        impl Probe for DeafSudoProbe {
            fn exists(&self, absolute_path: &str) -> bool {
                absolute_path == "/usr/bin/sudo"
            }
            fn version_banner(&self, _absolute_path: &str) -> Option<String> {
                Some("sudo-rs 0.2.2".to_owned())
            }
            fn directory_exists(&self, _absolute_path: &str) -> bool {
                true
            }
            fn honours_directive(&self, _absolute_path: &str, directive: &str) -> bool {
                directive != "use_pty"
            }

            fn honours_scoped_directive(&self, path: &str, directive: &str) -> bool {
                self.honours_directive(path, directive)
            }

            fn validates_named_file(&self, _path: &str) -> bool {
                true
            }

            fn accepts_argument_wildcard(&self, _path: &str) -> bool {
                true
            }
        }
        let out = run_probe(&fixture("cli-doctor-deaf"), &DeafSudoProbe, &["doctor"]);
        assert!(out.contains("backend      UNUSABLE"), "{out}");
        assert!(out.contains("fresh pty"), "{out}");
        assert!(!out.contains("backend caps "), "{out}");
    }

    #[test]
    fn doctor_reports_whatever_this_machine_actually_has() {
        // `HostProbe` now runs a real functional probe — it feeds a fragment to
        // the backend's own parser through /dev/stdin — so the answer depends on
        // the machine. Any of three shapes is correct; what must never happen is
        // a usable verdict without the capability count behind it.
        let out = run_probe(&fixture("cli-doctor-host"), &HostProbe, &["doctor"]);
        let line = out
            .lines()
            .find(|l| l.starts_with("backend  "))
            .unwrap_or_default();
        let shapes = ["UNUSABLE", "NONE", "sudo", "doas"];
        assert!(
            shapes.iter().any(|s| line.contains(s)),
            "unrecognised backend line: {line}"
        );
        // That a *named* backend always carries its capability count is asserted
        // by the two fake-probe tests above, which can guarantee the shape. This
        // one only checks that whatever this machine has is recognised.
    }

    #[test]
    fn every_capability_has_a_short_label_for_the_report() {
        for capability in Capability::ALL {
            let label = doctor::capability_label(capability);
            assert!(label.len() > 5, "{capability:?}");
            // A required capability must be marked where an operator reads it.
            assert_eq!(
                label.contains("REQUIRED"),
                capability.is_required(),
                "{capability:?}: {label}"
            );
        }
    }

    #[test]
    fn doctor_reports_the_platform_and_that_nothing_is_trusted() {
        let (code, out, _) = fixture("cli-doctor").run(&["doctor"]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("ruleset      2 action(s)"), "{out}");
        assert!(out.contains("0 trusted"), "{out}");
        assert!(out.contains("exec path    "), "{out}");
        assert!(out.contains("not a"), "{out}");
        #[cfg(not(target_os = "linux"))]
        assert!(out.contains("macos-stub"), "{out}");
    }

    #[test]
    fn a_broken_ruleset_fails_closed_for_every_command_that_needs_it() {
        let broken = Fixture::new("cli-broken").write("10-a.toml", "[[action]\nid =");
        for args in [
            vec!["explain", "--", "x"],
            vec!["check"],
            vec!["list"],
            vec!["agentdoc"],
        ] {
            let (code, _, err) = broken.run(&args);
            assert_eq!(code, ExitCode::Unusable, "{args:?}");
            assert!(err.contains("failing closed"), "{args:?}: {err}");
        }
    }

    #[test]
    fn a_missing_rules_directory_fails_closed() {
        let cli = Cli::try_parse_from(["xudo", "--rules", "/nonexistent/xudo", "check"]).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run(&cli, &Invocation::default(), &mut out, &mut err),
            ExitCode::Unusable
        );
        assert!(String::from_utf8_lossy(&err).contains("cannot read the rules directory"));
    }

    #[test]
    fn the_default_rules_directory_is_the_root_owned_one() {
        let cli = Cli::try_parse_from(["xudo", "check"]).unwrap();
        assert_eq!(cli.rules, PathBuf::from(DEFAULT_RULES_DIR));
        assert_eq!(cli.output, Format::Human);
    }

    #[test]
    fn the_help_text_describes_the_beta_password_path() {
        let err = Cli::try_parse_from(["xudo", "--help"]).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("password-authenticated path"), "{text}");
        assert!(
            text.contains("passwordless agent path is not available"),
            "{text}"
        );
    }

    #[test]
    fn doc_format_args_map_onto_the_renderer() {
        assert_eq!(DocFormat::from(DocFormatArg::Claude), DocFormat::Claude);
        assert_eq!(DocFormat::from(DocFormatArg::Agents), DocFormat::Agents);
        assert_eq!(DocFormat::from(DocFormatArg::Codex), DocFormat::Codex);
        assert!(format!("{:?}", DocFormatArg::Agents).contains("Agents"));
        assert_eq!(DocFormatArg::Agents, DocFormatArg::Agents);
        assert_ne!(DocFormatArg::Agents, DocFormatArg::Codex);
    }

    #[test]
    fn formats_are_debuggable_and_comparable() {
        assert_eq!(Format::Human, Format::Human);
        assert_ne!(Format::Human, Format::Json);
        assert!(format!("{:?}", Format::Json).contains("Json"));
    }

    #[test]
    fn the_parsed_command_is_debuggable() {
        let cli = Cli::try_parse_from(["xudo", "explain", "--", "x"]).unwrap();
        assert!(format!("{cli:?}").contains("Explain"));
    }
}
