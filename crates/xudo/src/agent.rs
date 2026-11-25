//! `xudo agent`: enrol, list and remove a harness that runs as its own account.
//!
//! Enrolling writes a registry entry, a drop-in and an environment stub, and
//! enables the unit. It grants nothing: no rule names the harness, so every
//! command it asks for still asks for the sudo password. Run as root, like
//! `xudo install`, through the machine's own `sudo`; this process never sees
//! the password.

use std::io::Write;

use clap::Subcommand;
use xudo_backend::enrol::{EnrolRequest, Listed, scan_account};
use xudo_backend::paths_to_root::Input;
use xudo_backend::{Backend, BackendKind, identify};
use xudo_policy::ExitCode;
use xudo_sys::Installer;

use crate::cli::Platform;

/// What `xudo agent` can do.
#[derive(Debug, Subcommand)]
pub enum AgentAction {
    /// Enrol a harness that runs headless as an existing account.
    ///
    /// Needs root. Prints exactly what it will write, then writes a registry
    /// entry, a systemd drop-in and a private environment file, and enables
    /// `xudo-agent@<label>.service`. Refuses an account that is root, has a
    /// password, is in a group that is root by another name, or has a sudo or
    /// doas rule of its own. Grants nothing: the harness still asks for the
    /// password for every command.
    Enrol {
        /// The harness's name: letters, digits and `-`.
        label: String,

        /// The existing account it runs as.
        #[arg(long)]
        account: String,

        /// Who decides what the harness queues. Repeat for more. Never the
        /// account itself.
        #[arg(long = "reviewer", required = true)]
        reviewers: Vec<String>,

        /// Print what would be written and write nothing.
        #[arg(long)]
        dry_run: bool,

        /// The program and its arguments, after `--`. The program is an
        /// absolute path.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },

    /// List the enrolled harnesses and whether each is running.
    List,

    /// Stop a harness enrolled with `xudo agent enrol` and remove its files.
    ///
    /// Needs root. The environment file stays: it may hold credentials.
    Remove {
        /// The harness's name.
        label: String,
    },
}

/// Runs one `xudo agent` action.
pub(crate) fn run(
    platform: &Platform<'_>,
    installer: &dyn Installer,
    action: &AgentAction,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    match action {
        AgentAction::Enrol {
            label,
            account,
            reviewers,
            dry_run,
            argv,
        } => {
            let request = EnrolRequest {
                label: label.clone(),
                account: account.clone(),
                reviewers: reviewers.clone(),
                argv: argv.clone(),
            };
            enrol(platform, installer, &request, *dry_run, out, err)
        }
        AgentAction::List => list(installer, out, err),
        AgentAction::Remove { label } => remove(installer, label, out, err),
    }
}

fn enrol(
    platform: &Platform<'_>,
    installer: &dyn Installer,
    request: &EnrolRequest,
    dry_run: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let backend = identify(platform.probe);
    let exe_of = |wanted: fn(BackendKind) -> bool| {
        backend
            .as_ref()
            .filter(|found| wanted(found.kind))
            .map(|found| found.exe.as_str())
    };
    let input = Input {
        user_path: None,
        backend_exe: None,
        sudo_exe: exe_of(|kind| matches!(kind, BackendKind::Sudo | BackendKind::SudoRs)),
        doas_exe: exe_of(|kind| matches!(kind, BackendKind::Doas)),
        doas_ignores_drop_ins: backend.as_ref().is_some_and(Backend::doas_ignores_drop_ins),
    };
    let scan = match scan_account(platform.host, &request.account, &input) {
        Ok(scan) => scan,
        Err(refusal) => return refuse(err, &refusal.to_string()),
    };
    let plan = match installer.agent_plan(request, scan) {
        Ok(plan) => plan,
        Err(failure) => return refuse(err, &failure.to_string()),
    };
    let _ = write!(out, "{}", plan.render());
    if dry_run {
        let _ = writeln!(out, "\nNothing was written (--dry-run).");
        return ExitCode::Delegated;
    }
    if let Err(failure) = installer.agent_apply(&plan) {
        return refuse(err, &failure.to_string());
    }
    let _ = writeln!(
        out,
        "\nenrolled {label}: {unit} runs as {account}.\n\
         It grants nothing: no rule names this harness, so every command it asks for\n\
         still asks for the sudo password. Put its credentials in {env} (root only),\n\
         and add {account} to the xudo group so it can reach the broker.",
        label = plan.label,
        unit = plan.unit,
        account = plan.account,
        env = plan.env.path,
    );
    ExitCode::Delegated
}

fn list(installer: &dyn Installer, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    match installer.agent_list() {
        Ok(rows) if rows.is_empty() => {
            let _ = writeln!(out, "No agents enrolled.");
            ExitCode::Delegated
        }
        Ok(rows) => {
            for row in rows {
                let Listed {
                    label,
                    account,
                    reviewers,
                } = row.agent;
                let _ = writeln!(
                    out,
                    "{label}  account={account}  {state}  reviewers={reviewers}",
                    state = row.state,
                    reviewers = reviewers.join(",")
                );
            }
            ExitCode::Delegated
        }
        Err(failure) => refuse(err, &failure.to_string()),
    }
}

fn remove(
    installer: &dyn Installer,
    label: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    match installer.agent_remove(label) {
        Ok(lines) => {
            for line in lines {
                let _ = writeln!(out, "{line}");
            }
            ExitCode::Delegated
        }
        Err(failure) => refuse(err, &failure.to_string()),
    }
}

fn refuse(err: &mut dyn Write, reason: &str) -> ExitCode {
    let _ = writeln!(err, "xudo: {reason}");
    ExitCode::Unusable
}
