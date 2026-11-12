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

/// One variable as text, for the queue location only.
#[allow(clippy::disallowed_methods)]
fn var(name: &str) -> Option<String> {
    std::env::var_os(name).and_then(|v| v.into_string().ok())
}

/// Where `xudo exec --queue` writes: the invoking user's own `ido` queue, found
/// the way `ido` finds it. Read here, once, and handed to the library as data.
/// It places a file and decides nothing: the queue is the caller's own, written
/// only after the broker has already denied the command.
fn queue_host() -> ido::Host {
    ido::Host {
        home: std::env::home_dir(),
        xdg_config_home: var("XDG_CONFIG_HOME"),
        xdg_state_home: var("XDG_STATE_HOME"),
        xdg_cache_home: var("XDG_CACHE_HOME"),
        xdg_runtime_dir: var("XDG_RUNTIME_DIR"),
        cwd: std::env::current_dir().ok(),
        uid: rustix::process::getuid().as_raw(),
        now_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        stdin_tty: false,
        stdout_tty: false,
        no_color: true,
        no_animation: true,
        queued_by: Some("xudo".to_owned()),
        lock_wait: std::time::Duration::from_secs(2),
        frame_delay: std::time::Duration::ZERO,
        xudo_front_end: std::path::PathBuf::from(ido::XUDO_FRONT_END),
    }
}

/// `xudo exec`: if the broker said yes, become the backend running the gate.
///
/// Same pid and start time, so the gate finds the entry pinned to us, and the
/// backend's exit status is the shell's. Absolute path, no `PATH` search.
fn exec(
    cli: &xudo::Cli,
    argv: &[String],
    queue: bool,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
) -> std::process::ExitCode {
    use std::os::unix::process::CommandExt;
    let host = queue.then(queue_host);
    let plan = match xudo::exec::plan_live(cli, argv, host.as_ref(), out, err) {
        Ok(plan) => plan,
        Err(status) => return exit_status(status.as_i32()),
    };
    // The path is absolute and never searched for.
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(plan.backend);
    command.arg(plan.gate);
    // doas does not fork: stay its parent, so the gate finds us as an ancestor.
    // No signal handler; Ctrl-C reaches the whole foreground group anyway.
    if plan.spawn {
        return match command.status() {
            Ok(status) => {
                use std::os::unix::process::ExitStatusExt;
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
    if let xudo::Command::Exec { argv, queue } = &cli.command {
        return exec(&cli, argv, *queue, &mut out, &mut err);
    }
    let status = xudo::run(&cli, &invocation, &mut out, &mut err);
    exit_status(status.as_i32())
}
