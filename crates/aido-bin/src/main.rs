//! The `aido` entry point.
//!
//! Deliberately the whole of it. Everything worth testing lives in the `aido`
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

fn main() -> std::process::ExitCode {
    let cli = <aido::Cli as clap::Parser>::parse();
    let invocation = aido::Invocation {
        path: caller_path(),
    };
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let status = aido::run(&cli, &invocation, &mut out, &mut err);
    // Falls back to "aido is unusable" rather than 0 if the status ever exceeds
    // a u8, so an unexpected value can never be read as success.
    std::process::ExitCode::from(u8::try_from(status.as_i32()).unwrap_or(19))
}
