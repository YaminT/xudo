//! Typed failures. Every error path refuses; nothing logs and continues.

use std::path::PathBuf;

/// Everything that can go wrong, exhaustively matchable.
#[derive(Debug, thiserror::Error)]
pub enum IdoError {
    /// A filesystem operation failed.
    #[error("{op} {path}: {source}")]
    Io {
        /// What was being attempted, e.g. "create".
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The queue file contains a line this version cannot fully parse.
    ///
    /// The whole load refuses. A queue file with one line we do not
    /// understand is a queue file something else wrote, and running the part
    /// that looked fine is how a tampered entry hides among good ones.
    #[error("queue line {line} cannot be parsed: {source}")]
    QueueParse {
        /// 1-based line number.
        line: usize,
        /// The parse failure.
        #[source]
        source: serde_json::Error,
    },
    /// The run log exists but its chain does not parse or verify.
    #[error("run log {path} is unreadable: {detail}")]
    LogUnreadable {
        /// The log path.
        path: PathBuf,
        /// What went wrong.
        detail: String,
    },
    /// A request was refused before anything ran.
    #[error("{0}")]
    Refused(String),
    /// Another `ido` holds the queue lock.
    #[error("another ido process holds {path}; if none is running, remove it")]
    Locked {
        /// The lock file.
        path: PathBuf,
    },
    /// The terminal could not be read, written, or put into raw mode.
    #[error("terminal: {0}")]
    Terminal(#[source] std::io::Error),
    /// The home directory could not be determined.
    #[error("no home directory; ido stores its queue under $HOME/.local/state")]
    NoHome,
}

impl IdoError {
    /// The process exit status for this failure.
    ///
    /// `2` for refusals (bad request, nothing ran), `1` for everything else.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Refused(_) => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    #[test]
    fn every_variant_renders_and_maps_to_an_exit_code() {
        let io = IdoError::Io {
            op: "create",
            path: PathBuf::from("/x"),
            source: std::io::Error::other("boom"),
        };
        let parse_failure = serde_json::from_str::<u32>("nope").unwrap_err();
        let cases = [
            (io, 1),
            (
                IdoError::QueueParse {
                    line: 3,
                    source: parse_failure,
                },
                1,
            ),
            (
                IdoError::LogUnreadable {
                    path: PathBuf::from("/log"),
                    detail: "broken".into(),
                },
                1,
            ),
            (IdoError::Refused("nothing to queue".into()), 2),
            (
                IdoError::Locked {
                    path: PathBuf::from("/lock"),
                },
                1,
            ),
            (IdoError::Terminal(std::io::Error::other("gone")), 1),
            (IdoError::NoHome, 1),
        ];
        for (error, code) in cases {
            assert!(error.to_string().len() > 5, "{error:?}");
            assert_eq!(error.exit_code(), code, "{error:?}");
        }
    }
}
