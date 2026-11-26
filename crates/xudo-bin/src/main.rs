//! The `xudo` entry point.
//!
//! Deliberately the whole of it. Everything worth testing lives in the `xudo`
//! library and is driven by unit tests; what remains here is argument parsing,
//! the one environment variable `doctor` reports on, and the exit status a
//! shell receives, all asserted end to end by `tests/binary.rs`.

#![forbid(unsafe_code)]

use std::os::unix::process::ExitStatusExt;

/// `PATH` as the caller exported it, handed to the library as data.
///
/// The workspace bans reading the environment because, in a decision path, it
/// puts the caller in charge of the safety defaults. This is not one: `doctor`
/// inspects each entry for a directory someone else could plant a `sudo` in,
/// and shows the caller their own `PATH` back. Nothing searches it, and nothing
/// is decided on it. Read here, once, so the library itself reads nothing.
#[allow(clippy::disallowed_methods)]
fn caller_path() -> Option<std::ffi::OsString> {
    std::env::var_os("PATH")
}

/// `xudo op remove-path`: if the broker said yes, become the password gate.
///
/// The gate performs the walk. This process does not unlink anything.
fn exec_operation(
    cli: &xudo::Cli,
    target: &std::ffi::OsStr,
    dry_run: bool,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> std::process::ExitCode {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    let plan = match xudo::exec::plan_remove_live(cli, target.as_bytes(), dry_run, out, err) {
        Ok(plan) => plan,
        Err(status) => return exit_status(status.as_i32()),
    };
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(plan.backend);
    command.args(plan.backend_args());
    if plan.spawn {
        return match command.status() {
            Ok(status) => {
                let code = status
                    .code()
                    .or(status.signal().and_then(|n| n.checked_add(128)));
                exit_status(code.unwrap_or(19))
            }
            Err(error) => {
                let _ = writeln!(err, "xudo: cannot run {}: {error}", plan.backend);
                exit_status(19)
            }
        };
    }
    let error = command.exec();
    let _ = writeln!(err, "xudo: cannot run {}: {error}", plan.backend);
    exit_status(19)
}

/// `xudo exec`: if the broker said yes, become the backend running the gate.
///
/// Same pid and start time, so the gate finds the entry pinned to us, and the
/// backend's exit status is the shell's. Absolute path, no `PATH` search.
fn exec(
    cli: &xudo::Cli,
    argv: &[String],
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> std::process::ExitCode {
    use std::os::unix::process::CommandExt;
    let plan = match xudo::exec::plan_live(cli, argv, None, out, err) {
        Ok(plan) => plan,
        Err(status) => return exit_status(status.as_i32()),
    };
    // The path is absolute and never searched for.
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(plan.backend);
    command.args(plan.backend_args());
    // doas does not fork: stay its parent, so the gate finds us as an ancestor.
    // `sudo -n` for -nopass is spawned too, so its refusal can be explained.
    // No signal handler; Ctrl-C reaches the whole foreground group anyway.
    if plan.spawn {
        return match command.status() {
            Ok(status) => {
                use std::os::unix::process::ExitStatusExt;
                xudo::exec::after_backend(&plan, status.code(), err);
                let code = status
                    .code()
                    .or(status.signal().and_then(|n| n.checked_add(128)));
                exit_status(code.unwrap_or(19))
            }
            Err(error) => {
                let _ = writeln!(err, "xudo: cannot run {}: {error}", plan.backend);
                exit_status(19)
            }
        };
    }
    let error = command.exec();
    let _ = writeln!(err, "xudo: cannot run {}: {error}", plan.backend);
    exit_status(19)
}

/// `xudo exec --queued`: claim, spawn the gate in `/`, then complete or release.
///
/// Always a child. An in-place exec would replace this process before it could
/// tell the broker how the run ended, and the stored directory is the agent's.
fn exec_queued(
    cli: &xudo::Cli,
    id: &str,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> std::process::ExitCode {
    let run = match xudo::exec::plan_queued_live(cli, id, out, err) {
        Ok(run) => run,
        Err(status) => return exit_status(status.as_i32()),
    };
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(run.plan.backend);
    command.args(run.plan.backend_args());
    command.current_dir(run.cwd);
    match command.status() {
        Ok(status) => {
            let _ = xudo::exec::finish_queued_live(&run.id, true, &run.claim_token, err);
            let code = status
                .code()
                .or(status.signal().and_then(|n| n.checked_add(128)));
            exit_status(code.unwrap_or(19))
        }
        Err(error) => {
            let _ = writeln!(err, "xudo: cannot run {}: {error}", run.plan.backend);
            let _ = xudo::exec::finish_queued_live(&run.id, false, &run.claim_token, err);
            exit_status(19)
        }
    }
}

fn exit_status(status: i32) -> std::process::ExitCode {
    // Falls back to "xudo is unusable" rather than 0 if the status ever exceeds
    // a u8, so an unexpected value can never be read as success.
    std::process::ExitCode::from(u8::try_from(status).unwrap_or(19))
}

fn main() -> std::process::ExitCode {
    let cli = <xudo::Cli as clap::Parser>::parse();
    let invocation = xudo::Invocation {
        path: caller_path(),
    };
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    if let xudo::Command::Exec { argv, queued } = &cli.command {
        if let Some(id) = queued {
            return exec_queued(&cli, id, &mut out, &mut err);
        }
        return exec(&cli, argv, &mut out, &mut err);
    }
    if let xudo::Command::Op {
        command: xudo::OpCommand::RemovePath { target, dry_run },
    } = &cli.command
    {
        return exec_operation(&cli, target, *dry_run, &mut out, &mut err);
    }
    let status = xudo::run(&cli, &invocation, &mut out, &mut err);
    exit_status(status.as_i32())
}
