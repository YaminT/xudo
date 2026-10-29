//! The `xudo` entry point.
//!
//! Deliberately the whole of it. Everything worth testing lives in the `xudo`
//! library and is driven by unit tests; what remains here is argument parsing,
//! the one environment variable `doctor` reports on, and the exit status a
//! shell receives, all asserted end to end by `tests/binary.rs`.

#![forbid(unsafe_code)]

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
    let plan = match xudo::exec::plan_live(cli, argv, out, err) {
        Ok(plan) => plan,
        Err(status) => return exit_status(status.as_i32()),
    };
    // The path is a constant from the library, absolute, never searched for.
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(plan.backend);
    let error = command.arg(plan.gate).exec();
    let _ = writeln!(err, "xudo: cannot run {}: {error}", plan.backend);
    exit_status(19)
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
    if let xudo::Command::Exec { argv } = &cli.command {
        return exec(&cli, argv, &mut out, &mut err);
    }
    let status = xudo::run(&cli, &invocation, &mut out, &mut err);
    exit_status(status.as_i32())
}
