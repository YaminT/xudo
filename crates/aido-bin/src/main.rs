//! The `aido` entry point.
//!
//! Deliberately the whole of it. Everything worth testing lives in the `aido`
//! library and is driven by unit tests; what remains here is argument parsing
//! and the exit status a shell receives, both asserted end to end by
//! `aido-tests`.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let cli = <aido::Cli as clap::Parser>::parse();
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let status = aido::run(&cli, &mut out, &mut err);
    // Falls back to "aido is unusable" rather than 0 if the status ever exceeds
    // a u8, so an unexpected value can never be read as success.
    std::process::ExitCode::from(u8::try_from(status.as_i32()).unwrap_or(19))
}
