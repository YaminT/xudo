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

/// One page of the root-held queue, or the fact that the broker could not be asked.
struct RootFetch {
    root_entries: Vec<ido::RootView>,
    unavailable: bool,
}

/// Reads every page. A failure discards a partial list: showing half of it
/// would look like the rest did not exist.
fn fetch_root_queue() -> RootFetch {
    let mut entries = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..64 {
        let request = match &after {
            None => ido::queue_list_request(),
            Some(cursor) => ido::queue_list_page_request(cursor),
        };
        let Ok(bytes) = exchange(&request) else {
            return RootFetch {
                root_entries: Vec::new(),
                unavailable: true,
            };
        };
        let Ok(page) = ido::parse_queue_page(&bytes) else {
            return RootFetch {
                root_entries: Vec::new(),
                unavailable: true,
            };
        };
        let Some(next) = ido::append_page(&mut entries, page) else {
            return RootFetch {
                root_entries: entries,
                unavailable: false,
            };
        };
        after = Some(next);
    }
    RootFetch {
        root_entries: entries,
        unavailable: false,
    }
}

fn exchange(request: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;
    let mut stream =
        UnixStream::connect(xudo_wire::BROKER_SOCKET).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(request)
        .map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if buf.len() > xudo_wire::MAX_RESPONSE_BYTES {
            return Err("the broker's queue list was too large".to_owned());
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if let Some(bytes) = chunk.get(..read) {
                    buf.extend_from_slice(bytes);
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(buf)
}

fn send_release(id: &str) -> Result<(), String> {
    let bytes = exchange(&ido::queue_release_request(id))?;
    ido::parse_release_answer(&bytes)
}

fn main() -> std::process::ExitCode {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let args: Vec<_> = std::env::args_os().collect();
    // Only the picker and `ido list` show the root-held queue. `ido queue`
    // is the agent's command and must not ask the broker.
    let fetch = if ido::command_shows_root_queue(&args) {
        fetch_root_queue()
    } else {
        RootFetch {
            root_entries: Vec::new(),
            unavailable: false,
        }
    };
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
        xudo_front_end: std::path::PathBuf::from(ido::XUDO_FRONT_END),
        root_entries: fetch.root_entries,
        root_queue_unavailable: fetch.unavailable,
        root_release: Some(send_release),
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
    let code = ido::run_with(args, &host, &mut io);
    let _ = out.flush();
    // An exit status that does not fit a byte is never read as success.
    std::process::ExitCode::from(u8::try_from(code).unwrap_or(1))
}
