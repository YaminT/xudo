//! `ido` — the buffered human-run command queue.
//!
//! An agent queues the commands it cannot or should not run. The human runs
//! `ido`, sees the queue, chooses what to run, and runs it in their own
//! terminal. Nothing executes without a keystroke from a person who went
//! looking for the queue.
//!
//! # Why this is a better trust story than `aido`, not a weaker one
//!
//! `aido` fights impersonation: the agent owns `aido`'s stdin, stdout, and
//! pty, so confirmation needs a root broker and an out-of-band channel. `ido`
//! sidesteps all of it — the human is already the one running the program.
//! **`ido` needs no root, no cgroups, no broker, and no policy engine.** It
//! gates on *consequence*, not privilege: `aws s3 rm` against the prod profile
//! needs no uid 0 and still deserves a human.
//!
//! # The queue file is untrusted input
//!
//! The agent writes the queue; the human reads it in a terminal and then
//! executes what it says. Every field is attacker-controlled text destined
//! for a terminal and then for execution, so every rendered field passes
//! through [`term_sanitize`], argv is stored and executed as a vector (no
//! shell, ever), and a queue file this crate cannot fully parse refuses to
//! load rather than loading the part that looked fine.
//!
//! # Environment and clock as data
//!
//! The library reads no environment and takes no time of its own: the binary
//! collects XDG variables, the clock, and tty-ness once at startup and passes
//! them in as a [`cli::Host`]. Everything below that boundary is
//! deterministic and tested. The raw terminal is the one exception, and it
//! lives in the `ido-bin` package behind [`picker::Terminal`].

#![forbid(unsafe_code)]

pub mod agents_doc;
pub mod celebrate;
pub mod cli;
pub mod consequence;
pub mod entry;
pub mod error;
pub mod keys;
pub mod picker;
pub mod render;
pub mod run;
pub mod status;
pub mod store;

pub use cli::{CELEBRATION_NAME, Host, Io, OpenTerminal, run_with};
pub use entry::{Entry, QUEUE_SCHEMA_VERSION};
pub use error::IdoError;
pub use picker::Terminal;
pub use status::Status;
