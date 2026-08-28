//! The command surface.
//!
//! At this milestone every subcommand is introspection: nothing here executes a
//! privileged command, because no privileged path exists yet. That is worth
//! saying in the `--help` text too, so nobody installs this expecting it to run
//! something.

use std::io::Write;
use std::path::{Path, PathBuf};

use aido_backend::{Capability, DetectError, Probe, detect};
use aido_config::{Layer, Setting, Settings as ConfigSettings, Value as ConfigValue, apply_file};
use aido_policy::{
    Argv, CallerFacts, Decision, DenialCode, ExitCode, Request, RuleSet, Verdict, engine::Settings,
};
use aido_sys::{HostProbe, PrivilegedOps, host_ops};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::agentdoc::{self, DocFormat};
use crate::render;
use crate::rules::{DEFAULT_RULES_DIR, LoadedRules};

/// The root-owned settings file.
pub const DEFAULT_CONFIG_FILE: &str = "/etc/aido/config.toml";

/// How to render output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// Prose, with the decision trace.
    Human,
    /// The versioned decision envelope.
    Json,
}

/// Agent-aware privilege broker. This build performs no privileged operation.
#[derive(Debug, Parser)]
#[command(
    name = "aido",
    version,
    about = "Agent-aware privilege broker for Linux (beta: introspection only, executes nothing)",
    long_about = "aido decides whether a privileged command is permitted by a root-owned \
                  allowlist.\n\nThis build contains no privileged path: `explain`, `check`, \
                  `rule`, `doctor`, and `agentdoc` inspect the policy and execute nothing. \
                  Passwordless agent execution arrives with the broker."
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
    /// Evaluate only this action, instead of every action in the ruleset.
    #[arg(long, value_name = "ACTION_ID")]
    pub action: Option<String>,

    /// The command and its arguments, after `--`.
    #[arg(trailing_var_arg = true, value_name = "ARGV")]
    pub argv: Vec<String>,
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

    /// Lint the ruleset. Exits non-zero if anything is wrong with it.
    Check,

    /// List the effective policy.
    List {
        /// Show only this tier.
        #[arg(long, value_name = "TIER")]
        tier: Option<String>,
    },

    /// Report the platform, the ruleset, and how this caller would be classified.
    Doctor,

    /// Show the effective configuration and where each value came from.
    Config {
        /// Print the machine-readable schema instead of the current values.
        #[arg(long)]
        schema: bool,
    },

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

/// Runs a parsed command, writing to `out` and `err`.
///
/// Returns the process exit status. Every failure path returns a non-zero
/// [`ExitCode`]; there is no path that reports success on an error.
pub fn run(cli: &Cli, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    run_with(cli, host_ops().as_ref(), &HostProbe, out, err)
}

/// Runs a parsed command against an injected platform.
///
/// The platform is a parameter rather than a global so the fail-closed branches
/// — a caller that cannot be observed, a platform that cannot attest — are
/// reachable from a test. A branch that only executes on a broken machine is a
/// branch that only gets exercised on a broken machine.
pub fn run_with(
    cli: &Cli,
    ops: &dyn PrivilegedOps,
    probe: &dyn Probe,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    // Loaded up front but not unwrapped: `doctor` is the command an operator
    // reaches for precisely when the ruleset is broken, so it must not require
    // the broken thing.
    let loaded = LoadedRules::from_dir(&cli.rules);

    macro_rules! with_rules {
        ($body:expr) => {
            match &loaded {
                Ok(loaded) => $body(loaded),
                Err(load_err) => {
                    let _ = writeln!(err, "aido: {load_err}");
                    let _ = writeln!(
                        err,
                        "aido: failing closed; run `aido doctor` for the platform report"
                    );
                    return ExitCode::Unusable;
                }
            }
        };
    }

    match &cli.command {
        Command::Doctor => doctor(cli, ops, probe, loaded.as_ref().ok(), out),
        Command::Config { schema } => config(cli, *schema, out, err),
        Command::Explain(args) => {
            with_rules!(|l: &LoadedRules| explain(cli, ops, l, args, out, err))
        }
        Command::WhyNot { action, argv } => {
            with_rules!(|l: &LoadedRules| why_not(cli, ops, l, action, argv, out, err))
        }
        Command::Check => with_rules!(|l: &LoadedRules| check(l, out, err)),
        Command::List { tier } => {
            with_rules!(|l: &LoadedRules| list(l, tier.as_deref(), out, err))
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
        let _ = writeln!(err, "aido: nothing to explain; pass a command after `--`");
        return ExitCode::Unusable;
    }

    let Some(settings) = engine_settings(cli, err) else {
        return ExitCode::Unusable;
    };
    let caller = classify(ops, err);
    let requested = Argv::new(args.argv.iter().map(String::as_str).collect::<Vec<_>>());

    let decision = if let Some(action) = &args.action {
        evaluate_one(loaded.rules(), &caller, action, &requested, settings)
    } else if let Some(found) = best_match(loaded.rules(), &caller, &requested, settings) {
        found
    } else {
        // Nothing in the ruleset resembles this command, which only happens
        // with an empty ruleset. Reported as an unknown action rather than by
        // inventing a rule that refused it.
        let _ = writeln!(
            err,
            "aido: no action in {} matches this command",
            cli.rules.display()
        );
        Decision::deny(DenialCode::UnknownAction, Vec::new(), Vec::new())
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
    let argv = Argv::new(argv.iter().map(String::as_str).collect::<Vec<_>>());
    let decision = evaluate_one(loaded.rules(), &caller, action, &argv, settings);
    if decision.verdict.is_permitted() {
        let _ = writeln!(err, "aido: {action} does not refuse this command");
    }
    emit(cli, &decision, out)
}

/// Tries every action, returning the most favourable outcome.
///
/// "Most favourable" means a permitted verdict wins, and otherwise the first
/// refusal that got furthest — an argv-shape rejection is more informative than
/// an unknown action, because it means the operator picked the right rule and
/// the wrong arguments.
fn best_match(
    rules: &RuleSet,
    caller: &CallerFacts,
    argv: &Argv,
    settings: Settings,
) -> Option<Decision> {
    let mut best: Option<Decision> = None;
    for action in rules.actions() {
        let decision = aido_policy::evaluate(
            rules,
            caller,
            &Request::new(action.id.clone(), argv.clone()),
            settings,
        );
        if decision.verdict.is_permitted() {
            return Some(decision);
        }
        // A freeze is a property of the broker's state, not of this argv, so
        // every action returns it and the first one is the whole answer.
        // Reporting "unknown action" instead would send an operator hunting for
        // a missing rule while the real cause is that they froze the agent path.
        if decision.denial == Some(DenialCode::Frozen) {
            return Some(decision);
        }
        // Keep the first refusal, whatever it is. An earlier version listed the
        // codes it considered informative, which meant a code added later would
        // be silently dropped and reported as "unknown action" — exactly the
        // failure the freeze case above was fixing.
        if best.is_none() {
            best = Some(decision);
        }
    }
    best
}

fn evaluate_one(
    rules: &RuleSet,
    caller: &CallerFacts,
    action: &str,
    argv: &Argv,
    settings: Settings,
) -> Decision {
    aido_policy::evaluate(rules, caller, &Request::new(action, argv.clone()), settings)
}

/// Lints the ruleset.
fn check(loaded: &LoadedRules, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    let offenders = loaded.rules().self_denying_actions();
    if !offenders.is_empty() {
        for (id, classes) in &offenders {
            let _ = writeln!(
                err,
                "aido: {id} allowlists an executable the deny-list refuses: {classes:?}"
            );
        }
        let _ = writeln!(
            err,
            "aido: a rule that allowlists a shell-capable binary defeats the design"
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
        let _ = writeln!(err, "aido: no action matched");
        return ExitCode::Denied;
    }
    ExitCode::Delegated
}

/// Reports the platform and how this caller would be classified.
fn doctor(
    cli: &Cli,
    ops: &dyn PrivilegedOps,
    probe: &dyn Probe,
    loaded: Option<&LoadedRules>,
    out: &mut dyn Write,
) -> ExitCode {
    let _ = writeln!(out, "platform     {}", ops.platform());
    let _ = writeln!(out, "rules dir    {}", cli.rules.display());

    match loaded {
        Some(loaded) => {
            let _ = writeln!(
                out,
                "ruleset      {} action(s), {} file(s), generation {}",
                loaded.rules().len(),
                loaded.files().len(),
                loaded.generation().get(..12).unwrap_or("")
            );
        }
        None => {
            let _ = writeln!(
                out,
                "ruleset      NOT LOADED (run `aido check` for the parse error)"
            );
        }
    }

    match ops.classify(std::process::id()) {
        Ok(facts) => {
            let _ = writeln!(out, "classified   {}", facts.classification.label());
            let _ = writeln!(
                out,
                "password     {}",
                if facts.classification.requires_password() {
                    "required"
                } else {
                    "not required"
                }
            );
            let _ = writeln!(
                out,
                "hints        {} recorded, 0 trusted",
                facts.hints.len()
            );
        }
        Err(e) => {
            let _ = writeln!(out, "classified   unavailable: {e}");
            let _ = writeln!(out, "password     required (failing closed)");
        }
    }

    report_backend(probe, out);

    let _ = writeln!(out, "exec path    absent in this build");
    let _ = writeln!(
        out,
        "\nThis build performs no privileged operation. Agent detection is not a"
    );
    let _ = writeln!(
        out,
        "security boundary; the allowlist and the compiled-in deny-list are."
    );
    ExitCode::Delegated
}

/// Loads the settings file and derives the engine's view of it.
///
/// Without this the layered configuration would be reported by `aido config` and
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
            let _ = writeln!(err, "aido: {load_err}");
            let _ = writeln!(
                err,
                "aido: failing closed; the settings file was not applied"
            );
            return None;
        }
    }

    Some(Settings {
        confirm_agent_actions: config.get(Setting::ConfirmAgentActions).value
            == ConfigValue::Bool(true),
        frozen: config.get(Setting::Frozen).value == ConfigValue::Bool(true),
    })
}

/// Reports the effective configuration, or the schema.
///
/// Every value names the file and line that set it, and a compiled-in value says
/// so rather than being omitted — "why is confirmation off?" must have a
/// one-command answer, or somebody will answer it by guessing.
fn config(cli: &Cli, schema: bool, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    if schema {
        let _ = writeln!(out, "{}", render::json_of(&ConfigSettings::schema()));
        return ExitCode::Delegated;
    }

    let mut settings = ConfigSettings::default();

    // The system layer, if it is readable. A missing file is not an error: the
    // defaults are the configuration until somebody writes one.
    if let Ok(contents) = std::fs::read_to_string(&cli.config_file) {
        let name = Path::new(&cli.config_file).display().to_string();
        if let Err(load_err) = apply_file(&mut settings, Layer::System, &name, &contents) {
            // A broken configuration file fails closed: the defaults are safe,
            // but continuing while pretending the file was applied is not.
            let _ = writeln!(err, "aido: {load_err}");
            let _ = writeln!(err, "aido: failing closed; the file was not applied");
            return ExitCode::Unusable;
        }
    }

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
    ExitCode::Delegated
}

/// Reports the privilege backend, or why there is none.
///
/// Detection is pure and lives in `aido-backend`; this only renders it. The
/// version banner is not yet readable — running the backend needs the process
/// handling that lands with the rest of M2 — so the detector assumes the
/// stricter implementation, which is the safe direction and is said out loud
/// rather than hidden.
fn report_backend(probe: &dyn Probe, out: &mut dyn Write) {
    match detect(probe) {
        Ok(backend) => {
            let _ = writeln!(
                out,
                "backend      {} ({})",
                backend.kind.label(),
                if backend.version.is_empty() {
                    "version not probed yet"
                } else {
                    backend.version.as_str()
                }
            );
            // Reported as a count and then one line per absent capability.
            // No "all present" special case: 7 of 7 is not reachable for any
            // real backend — the C sudo does not reject argument wildcards and
            // sudo-rs cannot validate a named file — so a branch for it would be
            // dead code pretending to be thoroughness.
            let missing: Vec<&str> = Capability::ALL
                .into_iter()
                .filter(|c| !backend.capabilities.has(*c))
                .map(capability_label)
                .collect();
            let _ = writeln!(
                out,
                "backend caps {} of {} supported",
                backend.capabilities.len(),
                Capability::ALL.len(),
            );
            for absent in missing {
                let _ = writeln!(out, "             absent: {absent}");
            }
        }
        Err(DetectError::NoBackend) => {
            let _ = writeln!(
                out,
                "backend      NONE — aido cannot operate on this machine"
            );
            let _ = writeln!(
                out,
                "             aido delegates every uid transition and performs none itself"
            );
        }
        Err(err) => {
            let _ = writeln!(out, "backend      UNUSABLE: {err}");
        }
    }
}

/// A short name for a capability, for the doctor report.
fn capability_label(capability: Capability) -> &'static str {
    match capability {
        Capability::DropInDirectory => "drop-in directory",
        Capability::ValidateNamedFile => "validate named file",
        Capability::PerCommandDefaults => "per-command defaults",
        Capability::DisableCredentialCache => "disable credential cache (REQUIRED)",
        Capability::AllocatePty => "allocate pty (REQUIRED)",
        Capability::RejectsArgumentWildcards => "rejects argument wildcards",
        Capability::PersistentCredentialCache => "persistent credential cache",
    }
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
                "aido: cannot observe this caller ({e}); treating as unattested"
            );
            CallerFacts::new(
                aido_policy::Classification::Unattested {
                    reason: e.to_string(),
                },
                0,
            )
        }
    }
}

/// Renders a decision in the requested format and maps it to an exit status.
fn emit(cli: &Cli, decision: &Decision, out: &mut dyn Write) -> ExitCode {
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
    use aido_config::Setting;

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
        /// Mirrors production, where `/etc/aido/config.toml` sits next to
        /// `/etc/aido/rules.d/`. A `.toml` file inside the rules directory is a
        /// rule file by definition, and the loader is right to try to parse it.
        fn config_path(&self) -> PathBuf {
            let path = self.dir.with_extension("config");
            std::fs::create_dir_all(&path).unwrap();
            path.join("config.toml")
        }

        /// Runs argv against this fixture, returning (exit, stdout, stderr).
        fn run(&self, args: &[&str]) -> (ExitCode, String, String) {
            let mut full = vec!["aido", "--rules", self.dir.to_str().unwrap()];
            full.extend_from_slice(args);
            let cli = Cli::try_parse_from(full).unwrap();
            let mut out = Vec::new();
            let mut err = Vec::new();
            let code = run_with(&cli, host_ops().as_ref(), &HostProbe, &mut out, &mut err);
            (
                code,
                String::from_utf8_lossy(&out).into_owned(),
                String::from_utf8_lossy(&err).into_owned(),
            )
        }
    }

    const RULES: &str = r#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]

[[action]]
id = "aido.pkg.update"
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
        fn platform(&self) -> &'static str {
            "blind-test-stub"
        }

        fn classify(&self, _pid: u32) -> Result<aido_sys::CallerFacts, aido_sys::SysError> {
            Err(aido_sys::SysError::read("self/stat", "test stub refuses"))
        }

        fn resolve_exe(&self, _path: &str) -> Result<PathBuf, aido_sys::SysError> {
            Err(aido_sys::SysError::unsupported("resolve_exe"))
        }
    }

    /// A platform that reports an attested agent.
    ///
    /// No real platform can do this yet. It is here to cover the reporting
    /// branch for the day one can, and to prove the renderer does not assume
    /// every caller needs a password.
    struct AttestingOps;

    impl PrivilegedOps for AttestingOps {
        fn platform(&self) -> &'static str {
            "attesting-test-stub"
        }

        fn classify(&self, _pid: u32) -> Result<aido_sys::CallerFacts, aido_sys::SysError> {
            Ok(aido_sys::CallerFacts::new(
                aido_sys::Classification::EnrolledAgent {
                    agent_id: "claude-code".into(),
                    session_id: "s-1".into(),
                    declared_yolo: true,
                },
                1000,
            ))
        }

        fn resolve_exe(&self, _path: &str) -> Result<PathBuf, aido_sys::SysError> {
            Err(aido_sys::SysError::unsupported("resolve_exe"))
        }
    }

    fn run_ops(fx: &Fixture, ops: &dyn PrivilegedOps, args: &[&str]) -> (ExitCode, String, String) {
        let mut full = vec!["aido", "--rules", fx.dir.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with(&cli, ops, &HostProbe, &mut out, &mut err);
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
            &["explain", "--", "restart", "nginx.service"],
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
            &["explain", "--", "restart", "nginx.service"],
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
                "aido.svc.restart",
                "--",
                "restart",
                "nginx",
            ],
        );
        assert!(out.contains("argv_rejected"), "{out}");
    }

    #[test]
    fn explain_finds_the_matching_action_without_being_told_which() {
        let (code, out, _) =
            fixture("cli-explain").run(&["explain", "--", "restart", "nginx.service"]);
        // ALLOW, and note what that does *not* mean: the human path's password
        // is sudo's job, not the verdict's. `confirm_agent_actions` applies to
        // an attested agent, and nobody is attested in this build, so the
        // policy answer here is a plain allow.
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.starts_with("ALLOW\n"), "{out}");
        assert!(out.contains("aido.svc.restart"), "{out}");
        assert!(out.contains("10-rules.toml:3"), "{out}");
    }

    #[test]
    fn explain_reports_the_argv_rejection_when_nothing_permits_it() {
        let (code, out, _) = fixture("cli-reject").run(&["explain", "--", "restart", "nginx"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(out.contains("DENY"), "{out}");
        assert!(out.contains("argv_rejected"), "{out}");
    }

    #[test]
    fn explain_reports_the_nearest_refusal_rather_than_giving_up() {
        // Every action rejects this argv on shape, and that is more useful to
        // report than "unknown", because it tells the operator a rule exists
        // and the arguments were wrong.
        let (code, out, _) = fixture("cli-unknown").run(&["explain", "--", "wat", "is", "this"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(out.contains("argv_rejected"), "{out}");
    }

    #[test]
    fn explain_against_an_empty_ruleset_says_nothing_matches() {
        // The only way there is no nearest refusal: no rules at all, which is
        // exactly the state of a fresh install.
        let empty = Fixture::new("cli-empty-rules");
        let (code, out, err) = empty.run(&["explain", "--", "restart", "nginx.service"]);
        assert_eq!(code, ExitCode::Denied);
        assert!(err.contains("no action in"), "{err}");
        assert!(out.contains("unknown_action"), "{out}");
    }

    #[test]
    fn explain_can_be_pinned_to_one_action() {
        let (_, out, _) = fixture("cli-pinned").run(&[
            "explain",
            "--action",
            "aido.pkg.update",
            "--",
            "restart",
            "nginx.service",
        ]);
        // Pinned to the wrong rule on purpose: the answer must be about that
        // rule, not about whichever rule happens to match.
        assert!(out.contains("argv_rejected"), "{out}");
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
            "restart",
            "nginx.service",
        ]);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["action"], "aido.svc.restart");
    }

    #[test]
    fn why_not_interrogates_one_action() {
        let (code, out, _) = fixture("cli-whynot").run(&[
            "why-not",
            "--action",
            "aido.svc.restart",
            "--",
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
            "aido.svc.restart",
            "--",
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
id = "aido.oops"
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
        assert!(out.contains("aido.svc.restart"));
        assert!(out.contains("aido.pkg.update"));

        let (_, filtered, _) = fx.run(&["list", "--tier", "svc-control"]);
        assert!(filtered.contains("aido.svc.restart"));
        assert!(!filtered.contains("aido.pkg.update"), "{filtered}");
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
            assert!(out.contains("aido:begin"), "{out}");
            assert!(out.contains("aido.svc.restart"), "{out}");
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
    }

    fn run_probe(fx: &Fixture, probe: &dyn Probe, args: &[&str]) -> String {
        let mut full = vec!["aido", "--rules", fx.dir.to_str().unwrap()];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _ = run_with(&cli, host_ops().as_ref(), probe, &mut out, &mut err);
        String::from_utf8_lossy(&out).into_owned()
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
        // `aido config` and then ignored by every decision, so an operator
        // would set a value and be told it took effect while the engine ran on
        // its defaults.
        let fx = fixture("cli-config-effective");
        let path = fx.config_path();
        std::fs::write(&path, "frozen = true\n").unwrap();

        // An enrolled agent is refused while frozen.
        let mut full = vec![
            "aido",
            "--rules",
            fx.dir.to_str().unwrap(),
            "--config-file",
            path.to_str().unwrap(),
            "explain",
            "--",
            "restart",
            "nginx.service",
        ];
        let cli = Cli::try_parse_from(full.clone()).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with(&cli, &AttestingOps, &HostProbe, &mut out, &mut err);
        assert_eq!(code, ExitCode::Denied);
        let rendered = String::from_utf8_lossy(&out).into_owned();
        assert!(rendered.contains("frozen"), "{rendered}");
        // And it says so plainly rather than sending the operator hunting for a
        // missing rule.
        assert!(!rendered.contains("unknown_action"), "{rendered}");

        // And the human path stays open, so an operator can always recover.
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with(&cli, host_ops().as_ref(), &HostProbe, &mut out, &mut err);
        assert_eq!(code, ExitCode::Delegated);

        // With the file removed the same agent is permitted again, which proves
        // the verdict came from the file rather than from a default.
        full.retain(|a| *a != path.to_str().unwrap() && *a != "--config-file");
        let bare = Cli::try_parse_from(full).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_with(&bare, &AttestingOps, &HostProbe, &mut out, &mut err);
        assert_eq!(code, ExitCode::NotConfirmed);
    }

    #[test]
    fn a_broken_settings_file_fails_closed_for_a_decision_too() {
        // Not just for `aido config`: a settings file that does not mean what it
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
            "aido.svc.restart",
            "--",
            "restart",
            "nginx",
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
            "/nonexistent/aido/config.toml",
            "config",
        ]);
        assert_eq!(code, ExitCode::Delegated);
        assert!(out.contains("confirm_agent_actions      true"), "{out}");
        assert!(out.contains("<default>"), "{out}");
    }

    #[test]
    fn the_default_settings_file_is_the_root_owned_one() {
        let cli = Cli::try_parse_from(["aido", "config"]).unwrap();
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
        // A doas port: no drop-in directory, no per-command defaults.
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
        }
        let out = run_probe(&fixture("cli-doctor-doas"), &DoasProbe, &["doctor"]);
        assert!(out.contains("backend      doas"), "{out}");
        assert!(out.contains("absent: drop-in directory"), "{out}");
        assert!(out.contains("absent: per-command defaults"), "{out}");
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
        }
        let out = run_probe(&fixture("cli-doctor-mute"), &MuteSudoProbe, &["doctor"]);
        assert!(out.contains("version not probed yet"), "{out}");
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
        // but silently ignores a control aido depends on.
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
            let label = capability_label(capability);
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
        assert!(out.contains("exec path    absent in this build"), "{out}");
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
        let cli = Cli::try_parse_from(["aido", "--rules", "/nonexistent/aido", "check"]).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(run(&cli, &mut out, &mut err), ExitCode::Unusable);
        assert!(String::from_utf8_lossy(&err).contains("cannot read the rules directory"));
    }

    #[test]
    fn the_default_rules_directory_is_the_root_owned_one() {
        let cli = Cli::try_parse_from(["aido", "check"]).unwrap();
        assert_eq!(cli.rules, PathBuf::from(DEFAULT_RULES_DIR));
        assert_eq!(cli.output, Format::Human);
    }

    #[test]
    fn the_help_text_says_this_build_executes_nothing() {
        // Someone must not install this expecting it to run a command.
        let err = Cli::try_parse_from(["aido", "--help"]).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("execute nothing"), "{text}");
        assert!(text.contains("no privileged path"), "{text}");
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
        let cli = Cli::try_parse_from(["aido", "explain", "--", "x"]).unwrap();
        assert!(format!("{cli:?}").contains("Explain"));
    }
}
