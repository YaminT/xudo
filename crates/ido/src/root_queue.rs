//! The broker's root-held queue, as `ido` shows it.
//!
//! The user-side queue in [`crate::store`] is a file the agent can rewrite.
//! This list is not: the broker stores it, filters it to a human reviewer, and
//! `ido` only displays what [`parse_queue_page`] accepted. Running an entry
//! builds `xudo exec --queued <id>` in [`QUEUED_CWD`]. The agent's command
//! text is never an argument of that process and never goes through a shell.

use std::path::Path;
use std::process::Command;

use xudo_wire::{Answer, BrokerRequest, BrokerResponse, Question};

/// Where a queued run executes. Never the directory stored on the entry.
pub const QUEUED_CWD: &str = "/";

/// One root-held entry, display fields only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootView {
    /// The 64-character queue id.
    pub id: String,
    /// The command the agent asked for, program first.
    pub argv: Vec<String>,
    /// The harness label from the root registry.
    pub harness: String,
    /// Pending, claimed, or another broker state word.
    pub state: String,
}

/// One page of the root-held queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuePage {
    /// Entries on this page.
    pub entries: Vec<RootView>,
    /// Exclusive cursor for the next page.
    pub next: Option<String>,
}

/// The first page. Empty `after` is not used; that question is [`Question::QueueList`].
#[must_use]
pub fn queue_list_request() -> Vec<u8> {
    request(Question::QueueList)
}

/// A later page. `after` is the previous page's cursor.
#[must_use]
pub fn queue_list_page_request(after: &str) -> Vec<u8> {
    request(Question::QueueListPage {
        after: after.to_owned(),
    })
}

/// Asks the broker to put a claimed entry back to pending.
#[must_use]
pub fn queue_release_request(id: &str) -> Vec<u8> {
    request(Question::QueueRelease { id: id.to_owned() })
}

fn request(question: Question) -> Vec<u8> {
    BrokerRequest {
        schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
        question,
    }
    .to_json()
    .into_bytes()
}

/// Parses one broker answer into a page.
///
/// # Errors
///
/// The bytes were not a queue-list answer. A refusal is named; any other
/// answer is not a list.
pub fn parse_queue_page(bytes: &[u8]) -> Result<QueuePage, String> {
    let response = BrokerResponse::parse(bytes).map_err(|error| error.to_string())?;
    match response.answer {
        Answer::QueueListed { entries, next } => Ok(QueuePage {
            entries: entries
                .into_iter()
                .map(|entry| RootView {
                    id: entry.id,
                    argv: entry.argv,
                    harness: entry.harness,
                    state: entry.state,
                })
                .collect(),
            next,
        }),
        Answer::Refused {
            code, remediation, ..
        } => Err(format!(
            "the broker refused the queue list ({code:?}): {remediation}"
        )),
        _ => Err("the broker did not return a queue list".to_owned()),
    }
}

/// Whether a release answer put the entry back.
///
/// # Errors
///
/// The broker refused, or it answered something other than done.
pub fn parse_release_answer(bytes: &[u8]) -> Result<(), String> {
    let response = BrokerResponse::parse(bytes).map_err(|error| error.to_string())?;
    match response.answer {
        Answer::Done => Ok(()),
        Answer::Refused {
            code, remediation, ..
        } => Err(format!(
            "the broker refused the release ({code:?}): {remediation}"
        )),
        _ => Err("the broker did not release the entry".to_owned()),
    }
}

/// Appends one page and returns the next cursor, when there is another page.
#[must_use]
pub fn append_page(entries: &mut Vec<RootView>, page: QueuePage) -> Option<String> {
    entries.extend(page.entries);
    page.next.filter(|next| !next.is_empty())
}

/// `xudo exec --queued <id>`, in [`QUEUED_CWD`], with no shell.
///
/// `front_end` is an absolute path. The entry's argv is not on this command
/// line: the broker still has those bytes, and the human already saw them.
#[must_use]
pub fn queued_exec_command(front_end: &Path, id: &str) -> Command {
    // Absolute path, so this `Command::new` does not search `PATH`. The lint
    // bans the call because a privileged exec must not search; this process
    // holds no privilege and the path is the installed front-end or a test
    // double the caller named in full.
    #[allow(clippy::disallowed_methods)]
    let mut command = Command::new(front_end);
    command.arg("exec").arg("--queued").arg(id);
    command.current_dir(QUEUED_CWD);
    command
}

/// A child's exit code, or 1 when a signal took it.
#[must_use]
pub fn child_exit(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(1)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use std::os::unix::process::ExitStatusExt;

    use super::*;

    fn listed(argv: Vec<String>, next: Option<String>) -> Vec<u8> {
        let entry = xudo_wire::QueueListEntry {
            id: "cd".repeat(32),
            argv,
            cwd: "/home/agent/evil".to_owned(),
            harness: "codex".to_owned(),
            uid: 1000,
            rule_id: "xudo.queue.review".to_owned(),
            generation: 1,
            queued_at: 1,
            expires_at: 2,
            reason: Some("because".to_owned()),
            state: "pending".to_owned(),
        };
        BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::QueueListed {
                entries: vec![entry],
                next,
            },
        }
        .to_json()
        .into_bytes()
    }

    #[test]
    fn queue_requests_round_trip_and_pages_keep_later_entries() {
        let list = BrokerRequest::parse(&queue_list_request()).unwrap();
        assert_eq!(list.question, Question::QueueList);
        let page = BrokerRequest::parse(&queue_list_page_request("ab")).unwrap();
        assert_eq!(
            page.question,
            Question::QueueListPage {
                after: "ab".to_owned()
            }
        );
        let release = BrokerRequest::parse(&queue_release_request(&"ab".repeat(32))).unwrap();
        assert_eq!(
            release.question,
            Question::QueueRelease {
                id: "ab".repeat(32)
            }
        );

        let mut entries = Vec::new();
        let first =
            parse_queue_page(&listed(vec!["/usr/bin/true".into()], Some("cd".repeat(32)))).unwrap();
        let cursor = append_page(&mut entries, first);
        assert_eq!(cursor.as_deref(), Some("cd".repeat(32).as_str()));
        let second = parse_queue_page(&listed(vec!["/usr/bin/false".into()], None)).unwrap();
        assert!(append_page(&mut entries, second).is_none());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].argv, vec!["/usr/bin/false".to_owned()]);
        assert!(
            append_page(
                &mut entries,
                QueuePage {
                    entries: Vec::new(),
                    next: Some(String::new()),
                }
            )
            .is_none()
        );
    }

    #[test]
    fn a_queue_page_refuses_a_non_list_and_a_release_needs_done() {
        assert!(parse_queue_page(b"nope").is_err());
        let refused = BrokerResponse::refused(xudo_wire::RefusalCode::ChannelUntrusted)
            .to_json()
            .into_bytes();
        let error = parse_queue_page(&refused).unwrap_err();
        assert!(error.contains("refused"), "{error}");
        let done = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::Done,
        }
        .to_json()
        .into_bytes();
        assert!(
            parse_queue_page(&done)
                .unwrap_err()
                .contains("did not return")
        );
        assert!(parse_release_answer(&done).is_ok());
        assert!(
            parse_release_answer(&refused)
                .unwrap_err()
                .contains("refused")
        );
        let other = BrokerResponse {
            schema_version: xudo_wire::WIRE_SCHEMA_VERSION,
            answer: Answer::QueueListed {
                entries: Vec::new(),
                next: None,
            },
        }
        .to_json()
        .into_bytes();
        assert!(
            parse_release_answer(&other)
                .unwrap_err()
                .contains("did not release")
        );
        assert!(parse_release_answer(b"{").is_err());
    }

    #[test]
    fn child_exit_uses_the_code_or_one_when_a_signal_took_the_child() {
        assert_eq!(child_exit(std::process::ExitStatus::from_raw(0)), 0);
        assert_eq!(child_exit(std::process::ExitStatus::from_raw(2 << 8)), 2);
        assert_eq!(child_exit(std::process::ExitStatus::from_raw(9)), 1);
    }
}
