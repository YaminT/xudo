//! The `ido` entry point.
//!
//! Two jobs, both of which need the real process: collect the environment,
//! clock, uid, and tty-ness once and hand them to the library as data; and own
//! the raw terminal the picker draws on. Everything else lives in the `ido`
//! library, where it is unit-tested. This package is excluded from coverage and
//! asserted instead through real processes in `tests/`, including a
//! pseudo-terminal test that types into the picker.

#![forbid(unsafe_code)]

use std::io::{IsTerminal, Write};
use std::os::fd::AsFd;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustix::termios::{self, OptionalActions, Termios};

/// The terminal in raw mode on the alternate screen, restored on drop.
struct RawTerminal {
    original: Termios,
    restored: bool,
}

impl RawTerminal {
    fn enter() -> std::io::Result<Self> {
        let stdin = std::io::stdin();
        let original = termios::tcgetattr(stdin.as_fd())?;
        let mut raw = original.clone();
        raw.make_raw();
        termios::tcsetattr(stdin.as_fd(), OptionalActions::Flush, &raw)?;
        let mut out = std::io::stdout().lock();
        out.write_all(b"\x1b[?1049h\x1b[?25l")?;
        out.flush()?;
        Ok(Self {
            original,
            restored: false,
        })
    }
}

impl ido::Terminal for RawTerminal {
    fn size(&self) -> (usize, usize) {
        termios::tcgetwinsize(std::io::stdout().as_fd())
            .ok()
            .filter(|w| w.ws_col > 0 && w.ws_row > 0)
            .map_or((80, 24), |w| (usize::from(w.ws_col), usize::from(w.ws_row)))
    }

    fn read_input(&mut self) -> std::io::Result<Vec<u8>> {
        let mut buffer = [0_u8; 64];
        let read = rustix::io::read(std::io::stdin().as_fd(), &mut buffer)?;
        Ok(buffer.get(..read).unwrap_or_default().to_vec())
    }

    fn draw(&mut self, frame: &str) -> std::io::Result<()> {
        let mut out = std::io::stdout().lock();
        // Raw mode turns off output processing, so lines end in \r\n here.
        out.write_all(b"\x1b[H\x1b[2J")?;
        out.write_all(frame.replace('\n', "\r\n").as_bytes())?;
        out.flush()
    }

    fn restore(&mut self) -> std::io::Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        let mut out = std::io::stdout().lock();
        out.write_all(b"\x1b[?25h\x1b[?1049l")?;
        out.flush()?;
        termios::tcsetattr(
            std::io::stdin().as_fd(),
            OptionalActions::Flush,
            &self.original,
        )?;
        Ok(())
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        // A panic or an early return must not leave the human's terminal raw.
        let _ = ido::Terminal::restore(self);
    }
}

/// Reads one variable as text.
///
/// The workspace bans reading the environment because, in a *privileged*
/// decision path, it puts the caller in charge of the safety defaults. `ido`
/// holds no privilege and the XDG locations, `NO_COLOR`, and the agent hint are
/// supposed to come from the environment; reading them here, once, and passing
/// them to the library as data keeps the library itself free of it.
#[allow(clippy::disallowed_methods)]
fn var(name: &str) -> Option<String> {
    std::env::var_os(name).and_then(|v| v.into_string().ok())
}

/// Who is queueing, by the caller's own claim. Recorded and shown as
/// unverified; nothing is decided on it.
fn queued_by() -> Option<String> {
    var("CLAUDECODE").map(|_| "claude-code".to_owned())
}

fn main() -> std::process::ExitCode {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let host = ido::Host {
        home: std::env::home_dir(),
        xdg_config_home: var("XDG_CONFIG_HOME"),
        xdg_state_home: var("XDG_STATE_HOME"),
        xdg_cache_home: var("XDG_CACHE_HOME"),
        xdg_runtime_dir: var("XDG_RUNTIME_DIR"),
        cwd: std::env::current_dir().ok(),
        uid: rustix::process::getuid().as_raw(),
        now_unix,
        stdin_tty: std::io::stdin().is_terminal(),
        stdout_tty: std::io::stdout().is_terminal(),
        no_color: var("NO_COLOR").is_some_and(|v| !v.is_empty()),
        no_animation: var("IDO_NO_ANIMATION").is_some(),
        queued_by: queued_by(),
        lock_wait: Duration::from_secs(2),
        frame_delay: Duration::from_millis(120),
    };

    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let mut input = std::io::stdin().lock();
    let mut open =
        || -> std::io::Result<Box<dyn ido::Terminal>> { Ok(Box::new(RawTerminal::enter()?)) };
    let mut io = ido::Io {
        out: &mut out,
        err: &mut err,
        input: &mut input,
        terminal: &mut open,
    };
    let code = ido::run_with(std::env::args_os().collect(), &host, &mut io);
    let _ = out.flush();
    // An exit status that does not fit a byte is never read as success.
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
