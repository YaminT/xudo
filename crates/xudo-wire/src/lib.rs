//! The broker's wire protocol: what the `xudo` front-end asks `xudod`, and
//! what `xudod` answers.
//!
//! Two programs speak it, on opposite sides of the privilege boundary. The
//! front-end runs as the caller and asks. The broker runs as root, learns who
//! asked from the kernel rather than from the request, decides, and — only on a
//! permitted decision — mints the spool entry the gate will act on.
//!
//! # Why a crate of its own
//!
//! If these types lived in `xudod`, the front-end would link the broker's spool
//! writer and peer identification just to build a request. If they lived in the
//! front-end, the root broker would link `clap` and a terminal renderer just to
//! parse one. Here they are pure data and their parsers, depending only on
//! `xudo-policy` for the decision envelope both sides already share. Nothing in
//! this crate opens a file, a socket, or a process.
//!
//! # One question, one answer
//!
//! The front-end connects to [`BROKER_SOCKET`], writes one [`BrokerRequest`] as
//! JSON, and shuts down its writing half. The broker reads to end of file —
//! never more than [`MAX_REQUEST_BYTES`] — writes one [`BrokerResponse`], and
//! closes. There is no second message, no session, and no negotiation: a
//! connection is one question.
//!
//! # What a request may say
//!
//! Only the question: the absolute program and its operands. Nothing in a
//! request identifies the caller, because the broker learns that from the
//! kernel; the one field that describes the caller,
//! [`BrokerRequest::claimed_classification`], is an unauthenticated hint the
//! broker records and never reads.
//!
//! Every message carries a schema version and rejects unknown keys, so a field
//! this build does not understand is a refusal, never a silently ignored line.
//!
//! # A refusal is a contract, not a story
//!
//! A refusal carries a [`RefusalCode`] — append-only, like the policy engine's
//! denial taxonomy — and a fixed remediation sentence. It carries no detail.
//! What went wrong on the broker's side, with the paths and the errno, goes to
//! the audit record that only root reads, not back to the process that asked.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use xudo_policy::Decision;
use xudo_policy::decision::ENVELOPE_SCHEMA_VERSION;

/// Where the broker listens.
///
/// A socket systemd creates `0660 root:xudo` in a `0755` `/run/xudo`, so only
/// members of the `xudo` group can ask at all.
pub const BROKER_SOCKET: &str = "/run/xudo/broker.sock";

/// The wire version of both messages.
pub const WIRE_SCHEMA_VERSION: u32 = 2;

/// Maximum UTF-8 bytes in a program path.
pub const MAX_PROGRAM_BYTES: usize = 4096;
/// Maximum number of operands.
pub const MAX_ARGV_COUNT: usize = 256;
/// Maximum UTF-8 bytes in one operand.
pub const MAX_ARGUMENT_BYTES: usize = 4096;
/// Maximum UTF-8 bytes in the caller classification hint.
pub const MAX_CLASSIFICATION_BYTES: usize = 128;
/// Exact nonce identifier length.
pub const NONCE_HEX_LEN: usize = 64;
/// Maximum UTF-8 bytes in an answer token.
pub const MAX_TOKEN_BYTES: usize = 256;
/// Maximum UTF-8 bytes in a freeze reason.
pub const MAX_REASON_BYTES: usize = 1024;
/// Maximum number of watcher prompts.
pub const MAX_PROMPTS: usize = 64;
/// Maximum UTF-8 bytes in one watcher prompt or remediation.
pub const MAX_PROMPT_BYTES: usize = 4096;
/// Maximum entries returned by one `QueueList` response.
pub const MAX_QUEUE_LIST: usize = 32;

/// The largest request the broker reads, in bytes.
///
/// Sixteen KiB. The widest shipped rule takes twenty package names, so a
/// request longer than this is not one any rule could permit, and a root
/// process that reads whatever it is sent is a root process any member of the
/// `xudo` group can make allocate.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// The largest response the front-end reads, in bytes.
///
/// A response carries the decision's full trace, which grows with the number
/// of rules considered, so this is wider than a request. Bounded all the same:
/// the front-end runs in the caller's tree and must not be made to allocate
/// without limit by anything listening on the socket path.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

// A response carries a decision about a request, so it is never the smaller.
const _: () = assert!(MAX_RESPONSE_BYTES > MAX_REQUEST_BYTES);

/// Marker program stored on a typed-operation spool entry. Never executed.
pub const OPERATION_PROGRAM: &str = "/usr/libexec/xudo/xudo-op";

/// What the front-end asks. Every connection carries exactly one question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequest {
    /// Wire version; must be [`WIRE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The one question on this connection.
    pub question: Question,
}

/// A question for the broker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Question {
    /// Evaluate a command using the broker's root-owned policy.
    Run {
        /// Absolute path of the program to execute.
        program: String,
        /// Operands after the program.
        argv: Vec<String>,
        /// Caller working directory bytes. Empty only for legacy/test requests.
        #[serde(default)]
        cwd: Vec<u8>,
        /// Unauthenticated classification hint for the audit record.
        claimed_classification: String,
    },
    /// Read the status of a pending or completed request.
    Status {
        /// The 64 character lowercase hexadecimal nonce.
        id: String,
    },
    /// Receive available confirmation prompts.
    Watch,
    /// List this peer's pending confirmation requests without claiming a watcher slot.
    Pending,
    /// Answer a confirmation prompt.
    Answer {
        /// The request nonce.
        id: String,
        /// The one use token issued to a watcher.
        token: String,
        /// Whether the human approves.
        approve: bool,
    },
    /// Freeze confirmation handling with an operator supplied reason.
    Freeze {
        /// Short operator supplied reason.
        reason: String,
    },
    /// Resume confirmation handling.
    Thaw,
    /// List the peer's authorized root-held queue entries.
    QueueList,
    /// Atomically claim one pending entry for a fresh human-path run.
    QueueClaim {
        /// The 64-character queue id.
        id: String,
    },
    /// Mark a claimed entry done, bound to the gate's audit record.
    QueueComplete {
        /// The 64-character queue id.
        id: String,
        /// Sequence of the gate record. Zero searches the trail for a match.
        audit_seq: u64,
        /// Token returned when the entry was claimed. Empty only for a stale recovery.
        #[serde(default, skip_serializing_if = "str::is_empty")]
        claim_token: String,
    },
    /// Return a claimed entry to pending after a denied run.
    ///
    /// A fresh claim accepts only the peer that holds `claim_token`. An empty
    /// token never matches, so another reviewer can use it only once the claim
    /// is stale and the audit trail has no gate record for the entry.
    QueueRelease {
        /// The 64-character queue id.
        id: String,
        /// Token returned when the entry was claimed. Empty only for a stale recovery.
        #[serde(default, skip_serializing_if = "str::is_empty")]
        claim_token: String,
    },
    /// A later page of [`Question::QueueList`]. `after` is exclusive.
    QueueListPage {
        /// The last id of the previous page, or empty for the first page.
        after: String,
    },
    /// Remove one path under a `remove-path` rule: the password gate, or
    /// `-nopass` for a live harness the rule grants.
    ///
    /// The broker mints a spool entry. The gate walks the tree itself and does
    /// not exec [`OPERATION_PROGRAM`].
    RemovePath {
        /// Absolute target bytes. No NUL. At most [`MAX_PROGRAM_BYTES`].
        target: Vec<u8>,
        /// List the paths and unlink nothing.
        dry_run: bool,
        /// Unauthenticated classification hint for the audit record.
        claimed_classification: String,
    },
}

impl BrokerRequest {
    /// Builds a schema 2 run request.
    pub fn new(
        program: impl Into<String>,
        argv: Vec<String>,
        claimed_classification: impl Into<String>,
    ) -> Self {
        Self::new_owned(program.into(), argv, claimed_classification.into())
    }

    fn new_owned(program: String, argv: Vec<String>, claimed_classification: String) -> Self {
        Self {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Run {
                program,
                argv,
                cwd: Vec::new(),
                claimed_classification,
            },
        }
    }

    /// Adds the caller's exact cwd bytes for possible queue persistence.
    #[must_use]
    pub fn with_cwd_bytes(mut self, cwd: Vec<u8>) -> Self {
        if let Question::Run { cwd: stored, .. } = &mut self.question {
            *stored = cwd;
        }
        self
    }

    /// Parses and validates one request.
    ///
    /// # Errors
    ///
    /// Returns the first size, encoding, schema, shape, or content refusal.
    pub fn parse(bytes: &[u8]) -> Result<Self, RequestError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(RequestError::TooLarge {
                limit: MAX_REQUEST_BYTES,
            });
        }
        let text = std::str::from_utf8(bytes).map_err(|error| RequestError::NotUtf8 {
            offset: error.valid_up_to(),
        })?;
        let value = parse_json_object(text).map_err(|reason| RequestError::Malformed { reason })?;
        if let Some(found) = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|number| u32::try_from(number).ok())
            && found != WIRE_SCHEMA_VERSION
        {
            return Err(RequestError::WrongSchema {
                found,
                expected: WIRE_SCHEMA_VERSION,
            });
        }
        if value
            .get("question")
            .is_none_or(|question| !valid_question_shape(question))
        {
            return Err(RequestError::Malformed {
                reason: "question must use its object or unit string form".to_owned(),
            });
        }
        let request: Self =
            serde_json::from_str(text).map_err(|error| RequestError::Malformed {
                reason: error.to_string(),
            })?;
        request.check()?;
        Ok(request)
    }

    fn check(&self) -> Result<(), RequestError> {
        if self.schema_version != WIRE_SCHEMA_VERSION {
            return Err(RequestError::WrongSchema {
                found: self.schema_version,
                expected: WIRE_SCHEMA_VERSION,
            });
        }
        match &self.question {
            Question::Run {
                program,
                argv,
                cwd,
                claimed_classification,
            } => {
                bounded("program", program, MAX_PROGRAM_BYTES)?;
                if !program.starts_with('/') {
                    return Err(RequestError::ProgramNotAbsolute {
                        program: program.clone(),
                    });
                }
                refuse_nul("program", program)?;
                if !cwd.is_empty()
                    && (!cwd.starts_with(b"/") || cwd.contains(&0) || cwd.len() > MAX_PROGRAM_BYTES)
                {
                    return Err(RequestError::Malformed {
                        reason: "cwd must be an absolute byte path without NUL".to_owned(),
                    });
                }
                if argv.len() > MAX_ARGV_COUNT {
                    return Err(RequestError::FieldTooLarge {
                        field: "argv count".to_owned(),
                        limit: MAX_ARGV_COUNT,
                    });
                }
                for (i, arg) in argv.iter().enumerate() {
                    bounded(&format!("argv[{i}]"), arg, MAX_ARGUMENT_BYTES)?;
                    refuse_nul(&format!("argv[{i}]"), arg)?;
                }
                bounded(
                    "claimed_classification",
                    claimed_classification,
                    MAX_CLASSIFICATION_BYTES,
                )?;
                refuse_nul("claimed_classification", claimed_classification)?;
            }
            Question::Status { id } | Question::QueueClaim { id } => check_id(id)?,
            Question::QueueRelease { id, claim_token }
            | Question::QueueComplete {
                id, claim_token, ..
            } => {
                check_id(id)?;
                check_claim_token(claim_token)?;
            }
            Question::QueueListPage { after } => check_page_cursor(after)?,
            Question::Watch | Question::Pending | Question::Thaw | Question::QueueList => {}
            Question::Answer { id, token, .. } => {
                check_id(id)?;
                bounded("token", token, MAX_TOKEN_BYTES)?;
                refuse_nul("token", token)?;
                if token.is_empty() {
                    return Err(RequestError::Malformed {
                        reason: "answer token is empty".to_owned(),
                    });
                }
            }
            Question::Freeze { reason } => {
                bounded("reason", reason, MAX_REASON_BYTES)?;
                refuse_nul("reason", reason)?;
                if reason.is_empty() {
                    return Err(RequestError::Malformed {
                        reason: "freeze reason is empty".to_owned(),
                    });
                }
            }
            Question::RemovePath {
                target,
                claimed_classification,
                ..
            } => {
                if target.is_empty() || !target.starts_with(b"/") || target.contains(&0) {
                    return Err(RequestError::Malformed {
                        reason: "target must be an absolute path without NUL".to_owned(),
                    });
                }
                if target.len() > MAX_PROGRAM_BYTES {
                    return Err(RequestError::FieldTooLarge {
                        field: "target".to_owned(),
                        limit: MAX_PROGRAM_BYTES,
                    });
                }
                bounded(
                    "claimed_classification",
                    claimed_classification,
                    MAX_CLASSIFICATION_BYTES,
                )?;
                refuse_nul("claimed_classification", claimed_classification)?;
            }
        }
        Ok(())
    }

    /// Run fields, if this is a run question.
    pub fn run_fields(&self) -> Option<(&str, &[String], &str)> {
        match &self.question {
            Question::Run {
                program,
                argv,
                claimed_classification,
                ..
            } => Some((program, argv, claimed_classification)),
            _ => None,
        }
    }

    /// Remove-path fields, if this is that question.
    pub fn remove_fields(&self) -> Option<(&[u8], bool, &str)> {
        match &self.question {
            Question::RemovePath {
                target,
                dry_run,
                claimed_classification,
            } => Some((target, *dry_run, claimed_classification)),
            _ => None,
        }
    }

    /// Renders JSON; fallback is a malformed request and therefore fails closed.
    pub fn to_json(&self) -> String {
        rendered_or(serde_json::to_string(self), "{}")
    }
}

fn bounded(field: &str, value: &str, limit: usize) -> Result<(), RequestError> {
    if value.len() > limit {
        return Err(RequestError::FieldTooLarge {
            field: field.to_owned(),
            limit,
        });
    }
    Ok(())
}
fn check_page_cursor(after: &str) -> Result<(), RequestError> {
    if after.is_empty() {
        return Ok(());
    }
    if after.len() > NONCE_HEX_LEN
        || !after
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RequestError::Malformed {
            reason: "queue page cursor must be empty or at most 64 lowercase hex characters"
                .to_owned(),
        });
    }
    Ok(())
}

fn check_claim_token(token: &str) -> Result<(), RequestError> {
    if token.is_empty() {
        return Ok(());
    }
    if token.len() != NONCE_HEX_LEN
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RequestError::Malformed {
            reason: "claim token must be empty or 64 lowercase hexadecimal characters".to_owned(),
        });
    }
    Ok(())
}

fn check_id(id: &str) -> Result<(), RequestError> {
    if id.len() != NONCE_HEX_LEN
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(RequestError::Malformed {
            reason: "id must be 64 lowercase hexadecimal characters".to_owned(),
        });
    }
    Ok(())
}
fn refuse_nul(field: &str, value: &str) -> Result<(), RequestError> {
    if value.contains('\0') {
        return Err(RequestError::InteriorNul {
            field: field.to_owned(),
        });
    }
    Ok(())
}

/// Why a request was refused before it was evaluated.
///
/// Every variant is a refusal. The order of the checks is the order of the
/// variants: size before encoding, encoding before shape, shape before
/// content, so a message never describes a field that was never parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The request is longer than [`MAX_REQUEST_BYTES`].
    #[error("the request is longer than {limit} bytes")]
    TooLarge {
        /// The limit it exceeded.
        limit: usize,
    },
    /// The request's bytes are not UTF-8.
    ///
    /// Refused here rather than replaced: a lossy conversion is how two
    /// different arguments start comparing equal.
    #[error("the request is not UTF-8: the first invalid byte is at offset {offset}")]
    NotUtf8 {
        /// How many leading bytes were valid.
        offset: usize,
    },
    /// The request is not this wire format: not JSON, an unknown key, a
    /// missing key, or a value of the wrong type.
    #[error("the request is not a broker request: {reason}")]
    Malformed {
        /// The parser's account of why.
        reason: String,
    },
    /// A field exceeds its protocol bound.
    #[error("{field} exceeds its {limit}-byte or item limit")]
    FieldTooLarge {
        /// Field that exceeded its bound.
        field: String,
        /// Maximum byte or item count.
        limit: usize,
    },
    /// The request declares a schema this build does not implement.
    #[error("the request declares schema {found}, this broker implements {expected}")]
    WrongSchema {
        /// What the request said.
        found: u32,
        /// What this build understands.
        expected: u32,
    },
    /// The program is not an absolute path.
    #[error("program {program:?} is not absolute, and the broker never searches PATH")]
    ProgramNotAbsolute {
        /// What was given.
        program: String,
    },
    /// A string the kernel would see contains a NUL byte.
    ///
    /// `execve` takes NUL-terminated strings, so the kernel would run a prefix
    /// of what was reviewed.
    #[error("{field} contains a NUL byte, so the kernel would see only the part before it")]
    InteriorNul {
        /// Which field.
        field: String,
    },
}

impl RequestError {
    /// The refusal code this sends back.
    pub fn code(&self) -> RefusalCode {
        match self {
            Self::TooLarge { .. } => RefusalCode::RequestTooLarge,
            Self::FieldTooLarge { field, .. }
                if field == "program" || field.starts_with("argv[") || field == "argv count" =>
            {
                RefusalCode::RequestTooLarge
            }
            Self::NotUtf8 { .. } => RefusalCode::RequestNotUtf8,
            Self::FieldTooLarge { .. } | Self::Malformed { .. } => RefusalCode::RequestMalformed,
            Self::WrongSchema { .. } => RefusalCode::RequestWrongSchema,
            Self::ProgramNotAbsolute { .. } => RefusalCode::ProgramNotAbsolute,
            Self::InteriorNul { .. } => RefusalCode::InteriorNul,
        }
    }
}

/// What the broker answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerResponse {
    /// Wire version; must be [`WIRE_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// What happened to the request.
    pub answer: Answer,
}

/// One broker-checked request shown to a watcher.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchPrompt {
    /// The one-use request nonce.
    pub id: String,
    /// Governing action id.
    pub action: String,
    /// Canonical absolute program.
    pub program: String,
    /// Canonical operands.
    pub argv: Vec<String>,
    /// The requester's unauthenticated classification hint.
    pub classification: String,
    /// Why the password remains required after approval.
    pub evidence: String,
    /// Remaining request lifetime in milliseconds.
    pub expires_in_ms: u64,
}

/// Display-only item returned by the broker's root-held queue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueListEntry {
    /// Queue identifier.
    pub id: String,
    /// Sanitized command including the program at index zero.
    pub argv: Vec<String>,
    /// Sanitized working directory.
    pub cwd: String,
    /// Root registry label.
    pub harness: String,
    /// Kernel-attested requester uid.
    pub uid: u32,
    /// Policy action id.
    pub rule_id: String,
    /// Policy generation id.
    pub generation: u64,
    /// Queue time in `CLOCK_BOOTTIME` milliseconds.
    pub queued_at: u64,
    /// Expiry time in `CLOCK_BOOTTIME` milliseconds.
    pub expires_at: u64,
    /// Sanitized requester reason.
    pub reason: Option<String>,
    /// State text, such as pending or done.
    pub state: String,
}

/// What happened to a request.
///
/// `Decided` holds the policy decision and any minted spool entry. Those
/// fields are large on purpose; boxing them would touch every caller without
/// changing the wire. The other answers stay short.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Answer {
    /// The policy engine evaluated it.
    ///
    /// The decision is the same versioned envelope `xudo explain` prints,
    /// produced by the same function, so the two cannot disagree about a
    /// command.
    Decided {
        /// The engine's decision.
        decision: Decision,
        /// The spool entry minted for it, present exactly when the decision is
        /// permitted and the entry was written.
        minted: Option<Minted>,
    },
    /// A confirmation decision is awaiting an answer.
    Pending {
        /// Request nonce.
        id: String,
        /// Remaining lifetime in milliseconds.
        expires_in_ms: u64,
    },
    /// A watcher heartbeat and its bounded prompt list.
    Watching {
        /// The checked, bounded prompt list.
        prompts: Vec<WatchPrompt>,
        /// Number of additional pending prompts omitted to fit the response.
        #[serde(default)]
        omitted: usize,
    },
    /// Bounded entries the peer may see in the root-held queue.
    QueueListed {
        /// Bounded entries visible to this peer.
        entries: Vec<QueueListEntry>,
        /// Exclusive cursor for the next page. Absent on the last page.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next: Option<String>,
    },
    /// A question completed without a decision.
    Done,
    /// The broker refused before, or instead of, a decision.
    Refused {
        /// Why, as a stable code.
        code: RefusalCode,
        /// What to do about it. A fixed sentence per code.
        remediation: String,
        /// Bounded broker detail for a channel refusal, when useful.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

/// A spool entry the broker minted, and how to use it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Minted {
    /// The entry's one-use nonce: 64 lowercase hex characters.
    ///
    /// For correlation with the audit trail. The gate finds the entry by the
    /// caller's pinned identity, not by a nonce anyone presents to it.
    pub nonce: String,
    /// Remaining lifetime, relative to this response.
    pub expires_in_ms: u64,
    /// The gate to run, by absolute path, through the backend (`sudo` or
    /// `doas`) and with no arguments at all.
    pub gate: String,
    /// Claim token for a queued run. Equal to [`Self::nonce`] when the broker
    /// minted the entry for a queue claim. Absent for an ordinary human-path mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_token: Option<String>,
    /// Harness label of a queued command, for the reviewer to read before sudo.
    /// Absent for an ordinary human-path mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<String>,
}

/// Why the broker refused a request without a decision.
///
/// A stable, append-only code: the numeric and string values are a wire
/// contract. Never renumber, never reuse, only append.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    /// The request is longer than [`MAX_REQUEST_BYTES`].
    RequestTooLarge,
    /// No complete request arrived before the broker's receive timeout.
    RequestTimedOut,
    /// The connection failed while the request was being read.
    RequestUnreadable,
    /// The request's bytes are not UTF-8.
    RequestNotUtf8,
    /// The request is not this wire format.
    RequestMalformed,
    /// The request declares a schema this build does not implement.
    RequestWrongSchema,
    /// The program is not an absolute path.
    ProgramNotAbsolute,
    /// A string the kernel would see contains a NUL byte.
    InteriorNul,
    /// The broker could not establish which process asked.
    PeerUnidentified,
    /// The spool cannot be verified as root's, or cannot be written.
    SpoolUnusable,
    /// The spool holds as many pending requests as it may.
    SpoolFull,
    /// The root-owned ruleset or settings could not be loaded.
    PolicyUnloadable,
    /// The nonce drawn already names an entry.
    NonceCollision,
    /// The broker could not complete the request for a reason of its own.
    BrokerUnusable,
    /// The peer is not trusted for this channel.
    ChannelUntrusted,
    /// The requested identifier is unknown.
    RequestUnknown,
    /// The requested answer was rejected.
    AnswerRejected,
    /// A service harness asked for a command no rule grants it. It has no
    /// password to type, so nothing was minted. Carries the action id only.
    HarnessNotGranted,
}

impl RefusalCode {
    /// Every code, in numeric order.
    pub const ALL: [Self; 18] = [
        Self::RequestTooLarge,
        Self::RequestTimedOut,
        Self::RequestUnreadable,
        Self::RequestNotUtf8,
        Self::RequestMalformed,
        Self::RequestWrongSchema,
        Self::ProgramNotAbsolute,
        Self::InteriorNul,
        Self::PeerUnidentified,
        Self::SpoolUnusable,
        Self::SpoolFull,
        Self::PolicyUnloadable,
        Self::NonceCollision,
        Self::BrokerUnusable,
        Self::ChannelUntrusted,
        Self::RequestUnknown,
        Self::AnswerRejected,
        Self::HarnessNotGranted,
    ];

    /// The stable numeric code. Append-only.
    pub fn as_u32(self) -> u32 {
        match self {
            Self::RequestTooLarge => 1,
            Self::RequestTimedOut => 2,
            Self::RequestUnreadable => 3,
            Self::RequestNotUtf8 => 4,
            Self::RequestMalformed => 5,
            Self::RequestWrongSchema => 6,
            Self::ProgramNotAbsolute => 7,
            Self::InteriorNul => 8,
            Self::PeerUnidentified => 9,
            Self::SpoolUnusable => 10,
            Self::SpoolFull => 11,
            Self::PolicyUnloadable => 12,
            Self::NonceCollision => 13,
            Self::BrokerUnusable => 14,
            Self::ChannelUntrusted => 15,
            Self::RequestUnknown => 16,
            Self::AnswerRejected => 17,
            Self::HarnessNotGranted => 18,
        }
    }

    /// The stable string code, as it appears in the JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestTooLarge => "request_too_large",
            Self::RequestTimedOut => "request_timed_out",
            Self::RequestUnreadable => "request_unreadable",
            Self::RequestNotUtf8 => "request_not_utf8",
            Self::RequestMalformed => "request_malformed",
            Self::RequestWrongSchema => "request_wrong_schema",
            Self::ProgramNotAbsolute => "program_not_absolute",
            Self::InteriorNul => "interior_nul",
            Self::PeerUnidentified => "peer_unidentified",
            Self::SpoolUnusable => "spool_unusable",
            Self::SpoolFull => "spool_full",
            Self::PolicyUnloadable => "policy_unloadable",
            Self::NonceCollision => "nonce_collision",
            Self::BrokerUnusable => "broker_unusable",
            Self::ChannelUntrusted => "channel_untrusted",
            Self::RequestUnknown => "request_unknown",
            Self::AnswerRejected => "answer_rejected",
            Self::HarnessNotGranted => "harness_not_granted",
        }
    }

    /// The concrete next step, for whoever reads the refusal.
    ///
    /// Fixed per code, so a response can never carry a path, an errno, or
    /// anything else from the broker's side of the boundary.
    pub fn remediation(self) -> &'static str {
        match self {
            Self::RequestTooLarge => {
                "the request is longer than the broker reads; no rule permits a command this \
                 long, so shorten it rather than retrying"
            }
            Self::RequestTimedOut => {
                "the request did not arrive complete before the broker's timeout; xudo sends it \
                 in one write, so retry the xudo command"
            }
            Self::RequestUnreadable => {
                "the connection failed while the request was being read; retry the xudo command"
            }
            Self::RequestNotUtf8 => {
                "the request is not UTF-8; xudo refuses a non-UTF-8 argument before it sends \
                 anything, so this request did not come from xudo"
            }
            Self::RequestMalformed => {
                "the request is not a broker request; install xudo and xudod from the same \
                 release"
            }
            Self::RequestWrongSchema => {
                "the request declares a schema this broker does not implement; install xudo and \
                 xudod from the same release"
            }
            Self::ProgramNotAbsolute => {
                "name the program by its absolute path; the broker never searches PATH"
            }
            Self::InteriorNul => {
                "an argument contains a NUL byte, which the kernel would cut short; remove it"
            }
            Self::PeerUnidentified => {
                "the broker could not establish which process asked; retry, and if it persists \
                 run `xudo doctor` to see whether this host can identify a caller"
            }
            Self::SpoolUnusable => {
                "the broker cannot use its spool; an administrator must check that /run/xudo/req \
                 is a root-owned 0700 directory (systemd-tmpfiles --create)"
            }
            Self::SpoolFull => {
                "too many requests are pending; wait for them to be used or to expire, then retry \
                 the xudo command"
            }
            Self::PolicyUnloadable => {
                "the root-owned ruleset or settings could not be loaded and the broker is failing \
                 closed; an administrator must run `xudo check` and `xudo doctor`"
            }
            Self::NonceCollision => {
                "the broker drew a nonce that already names a request, so its random source is \
                 broken; an administrator must investigate before anything is retried"
            }
            Self::BrokerUnusable => {
                "the broker could not complete the request and failed closed; an administrator \
                 should read the broker's audit record in the journal"
            }
            Self::ChannelUntrusted => "the peer is not trusted for this broker channel",
            Self::RequestUnknown => {
                "the request is unknown or this question is not implemented yet"
            }
            Self::AnswerRejected => "the broker rejected this confirmation answer",
            Self::HarnessNotGranted => {
                "no rule grants this harness the command, and a service harness has no password \
                 to type; ask root to add a rule that names the harness, or use the queue"
            }
        }
    }
}

/// The response sent if a response could not be rendered.
///
/// Exactly what [`BrokerResponse::refused`] with [`RefusalCode::BrokerUnusable`]
/// renders to, which a test asserts, so the fallback is a refusal any
/// front-end parses, never an empty answer it might read as success.
pub const FALLBACK_RESPONSE: &str = concat!(
    r#"{"schema_version":2,"answer":{"refused":{"code":"broker_unusable","remediation":"#,
    r#""the broker could not complete the request and failed closed; an administrator "#,
    r#"should read the broker's audit record in the journal"}}}"#,
);

fn check_nonce(id: &str) -> Result<(), String> {
    check_id(id).map_err(|_| "id must be 64 lowercase hexadecimal characters".to_owned())
}

/// Why a response could not be read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    /// The response is longer than [`MAX_RESPONSE_BYTES`].
    #[error("the response is longer than {limit} bytes")]
    TooLarge {
        /// The limit it exceeded.
        limit: usize,
    },
    /// The response's bytes are not UTF-8.
    #[error("the response is not UTF-8: the first invalid byte is at offset {offset}")]
    NotUtf8 {
        /// How many leading bytes were valid.
        offset: usize,
    },
    /// The response is not this wire format.
    #[error("the response is not a broker response: {reason}")]
    Malformed {
        /// The parser's account of why.
        reason: String,
    },
    /// The response declares a schema this build does not implement.
    #[error("the response declares schema {found}, this front-end implements {expected}")]
    WrongSchema {
        /// What the response said.
        found: u32,
        /// What this build understands.
        expected: u32,
    },
    /// The decision inside the response is an envelope of another version.
    ///
    /// The envelope has a version of its own, and a front-end that read one
    /// it does not implement would be reading fields whose meaning it can
    /// only guess at.
    #[error("the decision declares envelope schema {found}, this front-end implements {expected}")]
    WrongEnvelope {
        /// What the decision said.
        found: u32,
        /// What this build understands.
        expected: u32,
    },
}

impl BrokerResponse {
    /// A response carrying the engine's decision, and the entry minted for it
    /// if there is one.
    pub fn decided(decision: Decision, minted: Option<Minted>) -> Self {
        Self {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Decided { decision, minted },
        }
    }

    /// A refusal, with the code's fixed remediation.
    pub fn refused(code: RefusalCode) -> Self {
        Self {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Refused {
                code,
                remediation: code.remediation().to_owned(),
                detail: None,
            },
        }
    }

    /// A service harness's refusal: the code and the action id, nothing else.
    ///
    /// No decision and no trace, so the agent learns which action matched and
    /// not how the ruleset is written.
    pub fn harness_not_granted(action: Option<&str>) -> Self {
        Self {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Refused {
                code: RefusalCode::HarnessNotGranted,
                remediation: RefusalCode::HarnessNotGranted.remediation().to_owned(),
                detail: action.map(str::to_owned),
            },
        }
    }

    /// A refusal with bounded diagnostic detail.
    pub fn refused_with_detail(code: RefusalCode, detail: String) -> Self {
        Self {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Refused {
                code,
                remediation: code.remediation().to_owned(),
                detail: Some(detail),
            },
        }
    }

    /// Parses one response, as the front-end received it.
    ///
    /// # Errors
    ///
    /// The first check that fails, as the matching [`ResponseError`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ResponseError> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ResponseError::TooLarge {
                limit: MAX_RESPONSE_BYTES,
            });
        }
        let text = response_text(bytes)?;
        let value =
            parse_json_object(text).map_err(|reason| ResponseError::Malformed { reason })?;
        if let Some(found) = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|number| u32::try_from(number).ok())
            && found != WIRE_SCHEMA_VERSION
        {
            return Err(ResponseError::WrongSchema {
                found,
                expected: WIRE_SCHEMA_VERSION,
            });
        }
        if value
            .get("answer")
            .is_none_or(|answer| !valid_answer_shape(answer))
        {
            return Err(ResponseError::Malformed {
                reason: "answer must use its object or unit string form".to_owned(),
            });
        }
        let response: Self =
            serde_json::from_str(text).map_err(|error| ResponseError::Malformed {
                reason: error.to_string(),
            })?;
        response.check()?;
        Ok(response)
    }

    fn check(&self) -> Result<(), ResponseError> {
        if self.schema_version != WIRE_SCHEMA_VERSION {
            return Err(ResponseError::WrongSchema {
                found: self.schema_version,
                expected: WIRE_SCHEMA_VERSION,
            });
        }
        match &self.answer {
            Answer::Decided { minted, .. } => {
                if let Some(minted) = minted {
                    if let Err(reason) = check_nonce(&minted.nonce) {
                        return Err(ResponseError::Malformed { reason });
                    }
                    if minted.gate.len() > MAX_PROGRAM_BYTES
                        || !minted.gate.starts_with('/')
                        || minted.gate.contains('\0')
                    {
                        return Err(ResponseError::Malformed {
                            reason: "minted gate is invalid or too long".to_owned(),
                        });
                    }
                }
            }
            Answer::Pending { id, .. } => {
                check_nonce(id).map_err(|reason| ResponseError::Malformed { reason })?;
            }
            Answer::Watching { prompts, .. } => {
                if prompts.len() > MAX_PROMPTS || prompts.iter().any(|p| !valid_watch_prompt(p)) {
                    return Err(ResponseError::Malformed {
                        reason: "watch prompt list exceeds its bound".to_owned(),
                    });
                }
            }
            Answer::QueueListed { entries, next } => {
                if entries.len() > MAX_QUEUE_LIST
                    || entries.iter().any(|entry| !valid_queue_entry(entry))
                {
                    return Err(ResponseError::Malformed {
                        reason: "queue list exceeds its bounds or contains an invalid entry"
                            .to_owned(),
                    });
                }
                if let Some(cursor) = next
                    && check_nonce(cursor).is_err()
                {
                    return Err(ResponseError::Malformed {
                        reason: "queue list cursor is not a queue id".to_owned(),
                    });
                }
            }
            Answer::Refused {
                remediation,
                detail,
                ..
            } => {
                if remediation.len() > MAX_PROMPT_BYTES || remediation.contains('\0') {
                    return Err(ResponseError::Malformed {
                        reason: "remediation exceeds its bound".to_owned(),
                    });
                }
                if detail
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_PROMPT_BYTES || value.contains('\0'))
                {
                    return Err(ResponseError::Malformed {
                        reason: "refusal detail exceeds its bound".to_owned(),
                    });
                }
            }
            Answer::Done => {}
        }
        // A refusal carries no envelope, so it has nothing to disagree about.
        let envelope = match &self.answer {
            Answer::Decided { decision, .. } => decision.schema_version,
            Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::QueueListed { .. }
            | Answer::Done
            | Answer::Refused { .. } => ENVELOPE_SCHEMA_VERSION,
        };
        if envelope != ENVELOPE_SCHEMA_VERSION {
            return Err(ResponseError::WrongEnvelope {
                found: envelope,
                expected: ENVELOPE_SCHEMA_VERSION,
            });
        }
        Ok(())
    }

    /// Renders the response as JSON.
    ///
    /// Falls back to [`FALLBACK_RESPONSE`] rather than panicking, for the same
    /// reason [`BrokerRequest::to_json`] does: plain data cannot fail to
    /// serialize, and if it ever did, the caller must receive a refusal.
    pub fn to_json(&self) -> String {
        rendered_or(serde_json::to_string(self), FALLBACK_RESPONSE)
    }
}

fn valid_question_shape(value: &serde_json::Value) -> bool {
    if value.is_string() {
        return true;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 1 {
        return false;
    }
    object.iter().any(|(name, payload)| {
        let unit = matches!(name.as_str(), "watch" | "pending" | "thaw" | "queue_list");
        let data = matches!(
            name.as_str(),
            "run"
                | "status"
                | "answer"
                | "freeze"
                | "queue_claim"
                | "queue_complete"
                | "queue_release"
                | "queue_list_page"
                | "remove_path"
        );
        (unit && payload.is_null()) || (data && payload.is_object())
    })
}

#[derive(Clone, Copy)]
#[cfg(test)]
enum QuestionShape {
    Variant(&'static str, bool),
}

#[cfg(test)]
fn question_shape(question: &Question) -> QuestionShape {
    match question {
        Question::Run { .. } => QuestionShape::Variant("run", false),
        Question::Status { .. } => QuestionShape::Variant("status", false),
        Question::Watch => QuestionShape::Variant("watch", true),
        Question::Pending => QuestionShape::Variant("pending", true),
        Question::Answer { .. } => QuestionShape::Variant("answer", false),
        Question::Freeze { .. } => QuestionShape::Variant("freeze", false),
        Question::Thaw => QuestionShape::Variant("thaw", true),
        Question::QueueList => QuestionShape::Variant("queue_list", true),
        Question::QueueClaim { .. } => QuestionShape::Variant("queue_claim", false),
        Question::QueueComplete { .. } => QuestionShape::Variant("queue_complete", false),
        Question::QueueRelease { .. } => QuestionShape::Variant("queue_release", false),
        Question::QueueListPage { .. } => QuestionShape::Variant("queue_list_page", false),
        Question::RemovePath { .. } => QuestionShape::Variant("remove_path", false),
    }
}

#[derive(Clone, Copy)]
#[cfg(test)]
enum AnswerShape {
    Variant(&'static str, bool),
}

#[cfg(test)]
fn answer_shape(answer: &Answer) -> AnswerShape {
    match answer {
        Answer::Decided { .. } => AnswerShape::Variant("decided", false),
        Answer::Pending { .. } => AnswerShape::Variant("pending", false),
        Answer::Watching { .. } => AnswerShape::Variant("watching", false),
        Answer::QueueListed { .. } => AnswerShape::Variant("queue_listed", false),
        Answer::Done => AnswerShape::Variant("done", true),
        Answer::Refused { .. } => AnswerShape::Variant("refused", false),
    }
}

fn valid_answer_shape(value: &serde_json::Value) -> bool {
    if value.is_string() {
        return true;
    }
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.len() != 1 {
        return false;
    }
    object.iter().any(|(name, payload)| {
        matches!(name.as_str(), "done") && payload.is_null()
            || matches!(
                name.as_str(),
                "decided" | "pending" | "watching" | "queue_listed" | "refused"
            ) && payload.is_object()
    })
}

fn parse_json_object(text: &str) -> Result<serde_json::Value, String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    if !value.is_object() {
        return Err("top-level JSON value must be an object".to_owned());
    }
    Ok(value)
}

fn valid_watch_prompt(prompt: &WatchPrompt) -> bool {
    prompt.id.len() == NONCE_HEX_LEN
        && prompt
            .id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && prompt.program.starts_with('/')
        && prompt.program.len() <= MAX_PROGRAM_BYTES
        && !prompt.program.contains('\0')
        && !prompt.action.is_empty()
        && prompt.action.len() <= MAX_PROMPT_BYTES
        && !prompt.action.contains('\0')
        && prompt.argv.len() <= MAX_ARGV_COUNT
        && prompt
            .argv
            .iter()
            .all(|arg| arg.len() <= MAX_ARGUMENT_BYTES && !arg.contains('\0'))
        && prompt.classification.len() <= MAX_CLASSIFICATION_BYTES
        && !prompt.classification.contains('\0')
        && prompt.evidence.len() <= MAX_PROMPT_BYTES
        && !prompt.evidence.contains('\0')
}

fn valid_queue_entry(entry: &QueueListEntry) -> bool {
    check_nonce(&entry.id).is_ok()
        && entry.argv.len() <= MAX_ARGV_COUNT + 1
        && entry
            .argv
            .iter()
            .all(|arg| arg.len() <= MAX_ARGUMENT_BYTES && !arg.contains('\0'))
        && [
            entry.cwd.as_str(),
            entry.harness.as_str(),
            entry.rule_id.as_str(),
            entry.state.as_str(),
        ]
        .iter()
        .all(|value| value.len() <= MAX_PROMPT_BYTES && !value.contains('\0'))
        && valid_queue_reason(entry.reason.as_deref())
}

fn response_text(bytes: &[u8]) -> Result<&str, ResponseError> {
    match std::str::from_utf8(bytes) {
        Ok(text) => Ok(text),
        Err(error) => Err(ResponseError::NotUtf8 {
            offset: error.valid_up_to(),
        }),
    }
}

fn valid_queue_reason(reason: Option<&str>) -> bool {
    match reason {
        Some(reason) => reason.len() <= MAX_REASON_BYTES && !reason.contains('\0'),
        None => true,
    }
}

/// Returns the rendered JSON, or `fallback` if rendering failed.
///
/// A plain function handed a value, not a closure, so that its failure arm is
/// reachable from a test holding a genuine `serde_json` error.
fn rendered_or(rendered: Result<String, serde_json::Error>, fallback: &str) -> String {
    match rendered {
        Ok(json) => json,
        Err(_) => fallback.to_owned(),
    }
}

/// Whether `candidate` is a canonical lowercase UUID boot id.
pub fn is_boot_id(candidate: &str) -> bool {
    candidate.len() == 36
        && candidate.bytes().enumerate().all(|(offset, byte)| {
            if matches!(offset, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use xudo_policy::{DenialCode, Verdict};

    use super::*;

    #[test]
    fn is_boot_id_accepts_a_lowercase_dashed_uuid() {
        assert!(is_boot_id("0123abcd-4567-89ab-cdef-0123456789ab"));
    }

    #[test]
    fn is_boot_id_refuses_every_malformed_spelling() {
        for bad in [
            "0123ABCD-4567-89ab-cdef-0123456789ab",
            "0123abcd-4567-89ab-cdef-0123456789a",
            "0123abcd-4567-89ab-cdef-0123456789abc",
            "0123abcd4-567-89ab-cdef-0123456789ab",
            "0123abcd-4567-89ab-cdef0-123456789ab",
            "0123abcd-4567-89ab-cdef-0123456789ag",
            "",
            "0123abcd-4567-89ab-cdef-0123456789ab\n",
            "0123abcd-4567-89ab-cdef-0123456789a\0",
        ] {
            assert!(!is_boot_id(bad), "{bad:?}");
        }
    }

    fn request() -> BrokerRequest {
        BrokerRequest::new(
            "/usr/bin/systemctl",
            vec!["restart".to_owned(), "nginx.service".to_owned()],
            "unattested",
        )
    }

    fn json_with(key: &str, value: serde_json::Value) -> Vec<u8> {
        let mut object: serde_json::Value = serde_json::from_str(&request().to_json()).unwrap();
        if key == "schema_version" {
            object
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), value);
        } else {
            object["question"]["run"]
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), value);
        }
        object.to_string().into_bytes()
    }

    #[test]
    fn a_question_without_a_schema_version_is_malformed() {
        let bytes = br#"{"question":{"watch":null}}"#;
        assert_eq!(
            BrokerRequest::parse(bytes).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn an_array_form_request_is_refused() {
        let bytes = br#"[2,"watch"]"#;
        assert_eq!(
            BrokerRequest::parse(bytes).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn struct_variant_questions_must_use_the_map_form() {
        for bytes in [
            br#"{"schema_version":2,"question":{"run":["/usr/bin/true",[],"x"]}}"#.as_slice(),
            br#"{"schema_version":2,"question":{"status":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}"#.as_slice(),
            br#"{"schema_version":2,"question":{"answer":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","tok",true]}}"#.as_slice(),
            br#"{"schema_version":2,"question":{"freeze":["maintenance"]}}"#.as_slice(),
        ] {
            assert_eq!(
                BrokerRequest::parse(bytes).unwrap_err().code(),
                RefusalCode::RequestMalformed
            );
        }
    }

    #[test]
    fn every_question_variant_uses_the_expected_external_shape() {
        let id = "a".repeat(NONCE_HEX_LEN);
        let variants = [
            Question::Run {
                program: "/x".into(),
                argv: Vec::new(),
                cwd: Vec::new(),
                claimed_classification: "x".into(),
            },
            Question::Status { id: id.clone() },
            Question::Watch,
            Question::Pending,
            Question::Answer {
                id: id.clone(),
                token: "x".into(),
                approve: true,
            },
            Question::Freeze { reason: "x".into() },
            Question::Thaw,
            Question::QueueList,
            Question::QueueClaim { id: id.clone() },
            Question::QueueComplete {
                id: id.clone(),
                audit_seq: 0,
                claim_token: String::new(),
            },
            Question::QueueRelease {
                id: id.clone(),
                claim_token: String::new(),
            },
            Question::QueueListPage {
                after: String::new(),
            },
            Question::RemovePath {
                target: b"/srv/app/build/cache".to_vec(),
                dry_run: true,
                claimed_classification: "x".into(),
            },
        ];
        for question in variants {
            let serialized = serde_json::to_value(&question).unwrap();
            let QuestionShape::Variant(name, unit) = question_shape(&question);
            if unit {
                assert_eq!(serialized, serde_json::Value::String(name.to_owned()));
            } else {
                let object = serialized.as_object().unwrap();
                assert_eq!(object.len(), 1);
                assert!(object[name].is_object());
            }
            assert!(valid_question_shape(&serialized), "variant {name}");
            if unit {
                let mut object = serde_json::Map::new();
                object.insert(name.to_owned(), serde_json::Value::Null);
                assert!(valid_question_shape(&serde_json::Value::Object(object)));
            }
        }
    }

    #[test]
    fn question_shape_rejects_non_variant_objects_and_wrong_payload_shapes() {
        for value in [
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!({"watch": null, "pending": null}),
            serde_json::json!({"run": null}),
            serde_json::json!({"watch": {}}),
            serde_json::json!({"unknown": {}}),
        ] {
            assert!(!valid_question_shape(&value), "unexpected shape: {value}");
        }
    }

    #[test]
    fn every_answer_variant_uses_the_expected_external_shape() {
        let id = "a".repeat(NONCE_HEX_LEN);
        let decision = Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new());
        let answers = [
            Answer::Decided {
                decision,
                minted: None,
            },
            Answer::Pending {
                id: id.clone(),
                expires_in_ms: 1,
            },
            Answer::Watching {
                prompts: Vec::new(),
                omitted: 0,
            },
            Answer::QueueListed {
                entries: Vec::new(),
                next: None,
            },
            Answer::Done,
            Answer::Refused {
                code: RefusalCode::SpoolFull,
                remediation: "x".into(),
                detail: None,
            },
        ];
        for answer in answers {
            let serialized = serde_json::to_value(&answer).unwrap();
            let AnswerShape::Variant(name, unit) = answer_shape(&answer);
            if unit {
                assert_eq!(serialized, serde_json::Value::String(name.to_owned()));
            } else {
                let object = serialized.as_object().unwrap();
                assert_eq!(object.len(), 1);
                assert!(object[name].is_object());
            }
            assert!(valid_answer_shape(&serialized), "variant {name}");
            if unit {
                let mut object = serde_json::Map::new();
                object.insert(name.to_owned(), serde_json::Value::Null);
                assert!(valid_answer_shape(&serde_json::Value::Object(object)));
            }
        }
    }

    fn run_with(cwd: Vec<u8>, argv: Vec<String>) -> BrokerRequest {
        BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Run {
                program: "/usr/bin/systemctl".to_owned(),
                argv,
                cwd,
                claimed_classification: "unattested".to_owned(),
            },
        }
    }

    #[test]
    fn run_validation_rejects_bad_cwd_and_oversized_argv_count() {
        let mut too_long = vec![b'/'];
        too_long.resize(MAX_PROGRAM_BYTES + 1, b'a');
        for cwd in [b"relative".to_vec(), b"/a\0b".to_vec(), too_long] {
            let refused =
                BrokerRequest::parse(run_with(cwd, Vec::new()).to_json().as_bytes()).unwrap_err();
            assert_eq!(
                refused,
                RequestError::Malformed {
                    reason: "cwd must be an absolute byte path without NUL".to_owned(),
                }
            );
        }

        let many = vec![String::new(); MAX_ARGV_COUNT + 1];
        let refused =
            BrokerRequest::parse(run_with(Vec::new(), many).to_json().as_bytes()).unwrap_err();
        assert_eq!(
            refused,
            RequestError::FieldTooLarge {
                field: "argv count".to_owned(),
                limit: MAX_ARGV_COUNT,
            }
        );
    }

    #[test]
    fn a_cwd_is_only_attached_to_a_run_question() {
        let thaw = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Thaw,
        };
        let same = thaw.clone().with_cwd_bytes(b"/tmp".to_vec());
        assert_eq!(same, thaw);
    }

    #[test]
    fn queue_list_response_validation_rejects_invalid_entry_fields() {
        let response = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::QueueListed {
                entries: vec![QueueListEntry {
                    id: "bad".into(),
                    argv: vec!["/usr/bin/true".into()],
                    cwd: "/tmp".into(),
                    harness: "codex".into(),
                    uid: 1000,
                    rule_id: "test.run".into(),
                    generation: 1,
                    queued_at: 1,
                    expires_at: 2,
                    reason: None,
                    state: "pending".into(),
                }],
                next: None,
            },
        };
        assert_eq!(
            BrokerResponse::parse(response.to_json().as_bytes()),
            Err(ResponseError::Malformed {
                reason: "queue list exceeds its bounds or contains an invalid entry".to_owned(),
            })
        );
    }

    #[test]
    fn answer_shape_rejects_non_variant_objects_and_wrong_payload_shapes() {
        for value in [
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!({"done": null, "pending": {}}),
            serde_json::json!({"pending": null}),
            serde_json::json!({"done": {}}),
            serde_json::json!({"unknown": {}}),
        ] {
            assert!(!valid_answer_shape(&value), "unexpected shape: {value}");
        }
    }

    #[test]
    fn answer_tokens_and_run_hints_are_bounded_and_clean() {
        let id = "a".repeat(64);
        let cases = [
            (
                Question::Answer {
                    id: id.clone(),
                    token: String::new(),
                    approve: true,
                },
                RefusalCode::RequestMalformed,
            ),
            (
                Question::Answer {
                    id: id.clone(),
                    token: "bad\0token".to_owned(),
                    approve: true,
                },
                RefusalCode::InteriorNul,
            ),
            (
                Question::Run {
                    program: "/usr/bin/id".to_owned(),
                    argv: Vec::new(),
                    cwd: Vec::new(),
                    claimed_classification: "x".repeat(MAX_CLASSIFICATION_BYTES + 1),
                },
                RefusalCode::RequestMalformed,
            ),
            (
                Question::Run {
                    program: "/usr/bin/id".to_owned(),
                    argv: Vec::new(),
                    cwd: Vec::new(),
                    claimed_classification: "bad\0hint".to_owned(),
                },
                RefusalCode::InteriorNul,
            ),
            (
                Question::Freeze {
                    reason: "bad\0reason".to_owned(),
                },
                RefusalCode::InteriorNul,
            ),
        ];
        for (question, code) in cases {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question,
            };
            assert_eq!(
                BrokerRequest::parse(request.to_json().as_bytes())
                    .unwrap_err()
                    .code(),
                code
            );
        }
    }

    #[test]
    fn run_fields_are_absent_for_every_non_run_question() {
        let id = "a".repeat(64);
        for question in [
            Question::Status { id: id.clone() },
            Question::Watch,
            Question::Pending,
            Question::Answer {
                id: id.clone(),
                token: "token".to_owned(),
                approve: false,
            },
            Question::Freeze {
                reason: "maintenance".to_owned(),
            },
            Question::Thaw,
            Question::QueueList,
            Question::QueueClaim { id: id.clone() },
            Question::QueueComplete {
                id: id.clone(),
                audit_seq: 4,
                claim_token: String::new(),
            },
            Question::QueueRelease {
                id,
                claim_token: String::new(),
            },
            Question::QueueListPage {
                after: "ab".to_owned(),
            },
            Question::RemovePath {
                target: b"/srv/app/build/cache".to_vec(),
                dry_run: false,
                claimed_classification: "unattested".into(),
            },
        ] {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question,
            };
            assert_eq!(request.run_fields(), None);
            if let Question::RemovePath {
                target, dry_run, ..
            } = &request.question
            {
                assert_eq!(
                    request.remove_fields(),
                    Some((target.as_slice(), *dry_run, "unattested"))
                );
            } else {
                assert_eq!(request.remove_fields(), None);
            }
        }
    }

    #[test]
    fn a_remove_path_question_rejects_a_bad_target() {
        let cases = [
            Question::RemovePath {
                target: Vec::new(),
                dry_run: false,
                claimed_classification: "x".into(),
            },
            Question::RemovePath {
                target: b"relative".to_vec(),
                dry_run: false,
                claimed_classification: "x".into(),
            },
            Question::RemovePath {
                target: b"/has\0nul".to_vec(),
                dry_run: true,
                claimed_classification: "x".into(),
            },
            Question::RemovePath {
                target: vec![b'/'; MAX_PROGRAM_BYTES + 1],
                dry_run: false,
                claimed_classification: "x".into(),
            },
            Question::RemovePath {
                target: b"/srv/app/build/cache".to_vec(),
                dry_run: false,
                claimed_classification: "\0".into(),
            },
            Question::RemovePath {
                target: b"/srv/app/build/cache".to_vec(),
                dry_run: false,
                claimed_classification: "x".repeat(MAX_CLASSIFICATION_BYTES + 1),
            },
        ];
        for question in cases {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question,
            };
            assert!(BrokerRequest::parse(request.to_json().as_bytes()).is_err());
        }
        let ok = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::RemovePath {
                target: b"/srv/app/build/cache".to_vec(),
                dry_run: true,
                claimed_classification: "unattested".into(),
            },
        };
        let parsed = BrokerRequest::parse(ok.to_json().as_bytes()).unwrap();
        assert_eq!(parsed, ok);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn queue_mutations_reject_a_bad_id_and_a_bad_page_cursor() {
        let claim = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::QueueClaim { id: "nope".into() },
        };
        assert_eq!(
            BrokerRequest::parse(claim.to_json().as_bytes()).unwrap_err(),
            RequestError::Malformed {
                reason: "id must be 64 lowercase hexadecimal characters".to_owned(),
            }
        );
        for question in [
            Question::QueueRelease {
                id: "nope".into(),
                claim_token: String::new(),
            },
            Question::QueueComplete {
                id: "nope".into(),
                audit_seq: 0,
                claim_token: String::new(),
            },
        ] {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question,
            };
            assert_eq!(
                BrokerRequest::parse(request.to_json().as_bytes()).unwrap_err(),
                RequestError::Malformed {
                    reason: "id must be 64 lowercase hexadecimal characters".to_owned(),
                }
            );
        }
        let page = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::QueueListPage { after: "GG".into() },
        };
        assert_eq!(
            BrokerRequest::parse(page.to_json().as_bytes()).unwrap_err(),
            RequestError::Malformed {
                reason: "queue page cursor must be empty or at most 64 lowercase hex characters"
                    .to_owned(),
            }
        );
        let listed = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::QueueListed {
                entries: Vec::new(),
                next: Some("short".into()),
            },
        };
        assert_eq!(
            BrokerResponse::parse(listed.to_json().as_bytes()).unwrap_err(),
            ResponseError::Malformed {
                reason: "queue list cursor is not a queue id".to_owned(),
            }
        );
        let id = "a".repeat(NONCE_HEX_LEN);
        for question in [
            Question::QueueRelease {
                id: id.clone(),
                claim_token: String::new(),
            },
            Question::QueueComplete {
                id: id.clone(),
                audit_seq: 1,
                claim_token: String::new(),
            },
            Question::QueueListPage {
                after: String::new(),
            },
            Question::QueueListPage { after: "ab".into() },
        ] {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question: question.clone(),
            };
            assert_eq!(
                BrokerRequest::parse(request.to_json().as_bytes())
                    .unwrap()
                    .question,
                question
            );
        }
        let bad_token = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::QueueRelease {
                id: id.clone(),
                claim_token: "GG".into(),
            },
        };
        assert_eq!(
            BrokerRequest::parse(bad_token.to_json().as_bytes()).unwrap_err(),
            RequestError::Malformed {
                reason: "claim token must be empty or 64 lowercase hexadecimal characters"
                    .to_owned(),
            }
        );
        let upper = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::QueueRelease {
                id: id.clone(),
                claim_token: "A".repeat(NONCE_HEX_LEN),
            },
        };
        assert_eq!(
            BrokerRequest::parse(upper.to_json().as_bytes()).unwrap_err(),
            RequestError::Malformed {
                reason: "claim token must be empty or 64 lowercase hexadecimal characters"
                    .to_owned(),
            }
        );
        let token = "ab".repeat(32);
        let good = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::QueueComplete {
                id: id.clone(),
                audit_seq: 0,
                claim_token: token.clone(),
            },
        };
        assert_eq!(
            BrokerRequest::parse(good.to_json().as_bytes())
                .unwrap()
                .question,
            Question::QueueComplete {
                id,
                audit_seq: 0,
                claim_token: token,
            }
        );
    }

    #[test]
    fn run_fields_return_the_run_question_fields() {
        let request = BrokerRequest::new("/usr/bin/true", vec!["-v".into()], "unattested");
        assert_eq!(
            request.run_fields(),
            Some(("/usr/bin/true", &["-v".to_owned()][..], "unattested"))
        );
    }

    #[test]
    fn a_schema_1_request_is_refused_wrong_schema() {
        let bytes = br#"{"schema_version":1,"program":"/usr/bin/id","argv":[],"claimed_classification":"x"}"#;
        assert_eq!(
            BrokerRequest::parse(bytes).unwrap_err().code(),
            RefusalCode::RequestWrongSchema
        );
    }

    #[test]
    fn a_duplicate_key_request_is_refused() {
        let repeated_schema =
            br#"{"schema_version":2,"schema_version":2,"question":{"thaw":null}}"#;
        assert_eq!(
            BrokerRequest::parse(repeated_schema).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
        let repeated_program = br#"{"schema_version":2,"question":{"run":{"program":"/usr/bin/true","program":"/usr/bin/false","argv":[],"claimed_classification":"x"}}}"#;
        assert_eq!(
            BrokerRequest::parse(repeated_program).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn a_request_with_a_different_schema_is_refused_before_shape_parsing() {
        let bytes = br#"{"schema_version":3,"question":{"watch":null}}"#;
        assert_eq!(
            BrokerRequest::parse(bytes).unwrap_err(),
            RequestError::WrongSchema {
                found: 3,
                expected: WIRE_SCHEMA_VERSION,
            }
        );
    }

    #[test]
    fn decoded_request_schema_is_rechecked() {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION + 1,
            question: Question::Thaw,
        };
        assert_eq!(
            request.check(),
            Err(RequestError::WrongSchema {
                found: WIRE_SCHEMA_VERSION + 1,
                expected: WIRE_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn an_unknown_question_is_malformed() {
        let bytes = br#"{"schema_version":2,"question":{"launch":{"program":"/bin/sh"}}}"#;
        assert_eq!(
            BrokerRequest::parse(bytes).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn an_answer_without_a_token_is_malformed() {
        let bytes = format!(
            r#"{{"schema_version":2,"question":{{"answer":{{"id":"{}","approve":true}}}}}}"#,
            "a".repeat(64)
        );
        assert_eq!(
            BrokerRequest::parse(bytes.as_bytes()).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn a_status_id_that_is_not_a_nonce_is_malformed() {
        let bytes = br#"{"schema_version":2,"question":{"status":{"id":"ABC"}}}"#;
        assert_eq!(
            BrokerRequest::parse(bytes).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn an_answer_id_that_is_not_a_nonce_is_malformed() {
        let bytes = br#"{"schema_version":2,"question":{"answer":{"id":"ABC","token":"token","approve":true}}}"#;
        assert_eq!(
            BrokerRequest::parse(bytes).unwrap_err().code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn new_request_fields_are_bounded_before_they_cross_the_boundary() {
        let fields = [
            (
                Question::Run {
                    program: format!("/{}", "x".repeat(MAX_PROGRAM_BYTES)),
                    argv: Vec::new(),
                    cwd: Vec::new(),
                    claimed_classification: "x".to_owned(),
                },
                "program",
            ),
            (
                Question::Run {
                    program: "/".to_owned(),
                    argv: vec!["x".repeat(MAX_ARGUMENT_BYTES + 1)],
                    cwd: Vec::new(),
                    claimed_classification: "x".to_owned(),
                },
                "argument",
            ),
            (
                Question::Run {
                    program: "/".to_owned(),
                    argv: vec!["x".to_owned(); MAX_ARGV_COUNT + 1],
                    cwd: Vec::new(),
                    claimed_classification: "x".to_owned(),
                },
                "count",
            ),
            (
                Question::Freeze {
                    reason: "x".repeat(MAX_REASON_BYTES + 1),
                },
                "reason",
            ),
            (
                Question::Answer {
                    id: "a".repeat(64),
                    token: "x".repeat(MAX_TOKEN_BYTES + 1),
                    approve: true,
                },
                "token",
            ),
        ];
        for (question, field) in fields {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question,
            };
            assert_eq!(
                BrokerRequest::parse(request.to_json().as_bytes())
                    .unwrap_err()
                    .code(),
                if field == "token" || field == "reason" {
                    RefusalCode::RequestMalformed
                } else {
                    RefusalCode::RequestTooLarge
                }
            );
        }
    }

    #[test]
    fn a_run_request_keeps_the_exact_cwd_bytes_for_queue_storage() {
        let request = BrokerRequest::new("/bin/tool", vec!["arg".to_owned()], "harness")
            .with_cwd_bytes(vec![b'/', b't', b'm', b'p', 0xff]);
        assert!(matches!(
            request.question,
            Question::Run { cwd, .. } if cwd == [b'/', b't', b'm', b'p', 0xff]
        ));
    }

    #[test]
    fn denies_a_token_nul_with_the_shared_interior_nul_code() {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Answer {
                id: "a".repeat(NONCE_HEX_LEN),
                token: "secret\0suffix".to_owned(),
                approve: true,
            },
        };
        assert_eq!(
            BrokerRequest::parse(request.to_json().as_bytes())
                .unwrap_err()
                .code(),
            RefusalCode::InteriorNul
        );
    }

    #[test]
    fn denies_an_empty_freeze_reason() {
        let request = BrokerRequest {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Freeze {
                reason: String::new(),
            },
        };
        assert_eq!(
            BrokerRequest::parse(request.to_json().as_bytes())
                .unwrap_err()
                .code(),
            RefusalCode::RequestMalformed
        );
    }

    #[test]
    fn refuses_an_overlong_or_nul_freeze_reason() {
        for reason in ["x".repeat(MAX_REASON_BYTES + 1), "bad\0reason".to_owned()] {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question: Question::Freeze { reason },
            };
            assert!(request.check().is_err());
        }
    }

    #[test]
    fn every_question_round_trips() {
        let id = "a".repeat(64);
        for question in [
            Question::Run {
                program: "/usr/bin/id".to_owned(),
                argv: vec!["-u".to_owned()],
                cwd: Vec::new(),
                claimed_classification: "unattested".to_owned(),
            },
            Question::Status { id: id.clone() },
            Question::Watch,
            Question::Pending,
            Question::Answer {
                id: id.clone(),
                token: "one-use".to_owned(),
                approve: true,
            },
            Question::Freeze {
                reason: "maintenance".to_owned(),
            },
            Question::Thaw,
        ] {
            let request = BrokerRequest {
                schema_version: WIRE_SCHEMA_VERSION,
                question,
            };
            assert_eq!(
                BrokerRequest::parse(request.to_json().as_bytes()).unwrap(),
                request
            );
        }
    }

    #[test]
    fn a_well_formed_request_round_trips() {
        let parsed = BrokerRequest::parse(request().to_json().as_bytes()).unwrap();
        assert_eq!(parsed, request());
        assert_eq!(parsed.schema_version, WIRE_SCHEMA_VERSION);
    }

    #[test]
    fn denies_a_request_one_byte_over_the_limit_and_accepts_one_at_it() {
        // A root process that reads whatever it is sent is one any member of
        // the group can make allocate, so the limit is exact.
        let over = vec![b' '; MAX_REQUEST_BYTES + 1];
        assert_eq!(
            BrokerRequest::parse(&over),
            Err(RequestError::TooLarge {
                limit: MAX_REQUEST_BYTES
            })
        );
        let mut at = request().to_json().into_bytes();
        at.resize(MAX_REQUEST_BYTES, b' ');
        assert_eq!(BrokerRequest::parse(&at), Ok(request()));
    }

    #[test]
    fn denies_non_utf8_bytes_instead_of_replacing_them() {
        // The bytes 0xff in an argument: a lossy decoder would turn them into
        // U+FFFD and a rule would then be matched against something nobody
        // typed.
        let mut bytes =
            br#"{"schema_version":2,"question":{"run":{"program":"/usr/bin/systemctl","argv":["restart",""#.to_vec();
        let offset = bytes.len();
        bytes.extend_from_slice(b"\xffnginx.service\"],\"claimed_classification\":\"x\"}");
        let error = BrokerRequest::parse(&bytes).unwrap_err();
        assert_eq!(error, RequestError::NotUtf8 { offset });
        assert_eq!(error.code(), RefusalCode::RequestNotUtf8);
    }

    #[test]
    fn denies_a_lone_surrogate_escape_rather_than_decoding_it() {
        // Valid UTF-8 on the wire, but a JSON escape for half a character:
        // the parser refuses it rather than inventing a replacement.
        let bytes = br#"{"schema_version":2,"question":{"run":{"program":"/usr/bin/systemctl","argv":["\ud800"],"claimed_classification":"x"}}}"#;
        let error = BrokerRequest::parse(bytes).unwrap_err();
        assert_eq!(error.code(), RefusalCode::RequestMalformed);
    }

    #[test]
    fn denies_a_request_that_is_not_json() {
        let error = BrokerRequest::parse(b"restart nginx").unwrap_err();
        assert_eq!(error.code(), RefusalCode::RequestMalformed);
        assert!(
            error.to_string().contains("not a broker request"),
            "{error}"
        );
    }

    #[test]
    fn denies_a_request_carrying_an_unknown_key() {
        // A directive this build does not understand is a refusal, never a
        // silently ignored line.
        let error = BrokerRequest::parse(&json_with(
            "skip_confirmation",
            serde_json::Value::Bool(true),
        ))
        .unwrap_err();
        assert_eq!(error.code(), RefusalCode::RequestMalformed);
    }

    #[test]
    fn denies_a_request_that_tries_to_name_its_own_caller() {
        // The caller is the kernel's to say. A request that claims a pid or a
        // uid is refused for the key, not believed for its value.
        for key in ["caller_pid", "uid", "classification"] {
            let error =
                BrokerRequest::parse(&json_with(key, serde_json::Value::from(0))).unwrap_err();
            assert_eq!(error.code(), RefusalCode::RequestMalformed, "{key}");
        }
    }

    #[test]
    fn denies_a_request_missing_a_key() {
        let mut object: serde_json::Value = serde_json::from_str(&request().to_json()).unwrap();
        object["question"]["run"]
            .as_object_mut()
            .unwrap()
            .remove("claimed_classification");
        let error = BrokerRequest::parse(object.to_string().as_bytes()).unwrap_err();
        assert_eq!(error.code(), RefusalCode::RequestMalformed);
    }

    #[test]
    fn denies_a_schema_this_build_does_not_implement() {
        let error = BrokerRequest::parse(&json_with("schema_version", serde_json::Value::from(3)))
            .unwrap_err();
        assert_eq!(
            error,
            RequestError::WrongSchema {
                found: 3,
                expected: WIRE_SCHEMA_VERSION
            }
        );
        assert_eq!(error.code(), RefusalCode::RequestWrongSchema);
    }

    #[test]
    fn denies_a_program_that_would_be_resolved_against_a_path_or_a_cwd() {
        for program in ["systemctl", "./systemctl", "../bin/sh", ""] {
            let error =
                BrokerRequest::parse(&json_with("program", serde_json::Value::from(program)))
                    .unwrap_err();
            assert_eq!(
                error,
                RequestError::ProgramNotAbsolute {
                    program: program.to_owned()
                },
                "{program:?}"
            );
            assert_eq!(error.code(), RefusalCode::ProgramNotAbsolute);
        }
    }

    #[test]
    fn denies_an_interior_nul_in_the_program_or_any_operand() {
        // execve takes NUL-terminated strings: an accepted NUL means a human
        // reviewed one command and the kernel ran a prefix of it.
        let error = BrokerRequest::parse(&json_with(
            "program",
            serde_json::Value::from("/usr/bin/systemctl\0/../../bin/sh"),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            RequestError::InteriorNul {
                field: "program".to_owned()
            }
        );
        let error = BrokerRequest::parse(&json_with(
            "argv",
            serde_json::json!(["restart", "nginx\0 --force"]),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            RequestError::InteriorNul {
                field: "argv[1]".to_owned()
            }
        );
        assert_eq!(error.code(), RefusalCode::InteriorNul);
    }

    #[test]
    fn every_request_refusal_renders_a_sentence_and_its_own_code() {
        let all = [
            RequestError::TooLarge { limit: 1 },
            RequestError::NotUtf8 { offset: 3 },
            RequestError::Malformed {
                reason: "trailing comma".to_owned(),
            },
            RequestError::FieldTooLarge {
                field: "program".to_owned(),
                limit: 1,
            },
            RequestError::WrongSchema {
                found: 2,
                expected: 1,
            },
            RequestError::ProgramNotAbsolute {
                program: "sh".to_owned(),
            },
            RequestError::InteriorNul {
                field: "argv[0]".to_owned(),
            },
        ];
        let mut codes: Vec<u32> = all.iter().map(|e| e.code().as_u32()).collect();
        for error in &all {
            assert!(error.to_string().len() > 20, "{error:?}");
        }
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "two request refusals share a code");
    }

    #[test]
    fn refusal_codes_are_unique_contiguous_and_render_as_serde_does() {
        // The wire contract: if this needs editing, a deployed front-end's
        // handling of a refusal has just changed meaning.
        for (index, code) in RefusalCode::ALL.iter().enumerate() {
            assert_eq!(usize::try_from(code.as_u32()).unwrap(), index + 1);
            assert_eq!(
                serde_json::to_string(code).unwrap(),
                format!("\"{}\"", code.as_str())
            );
            assert_eq!(
                serde_json::from_str::<RefusalCode>(&format!("\"{}\"", code.as_str())).unwrap(),
                *code
            );
            assert!(code.remediation().len() > 40, "{code:?}");
        }
        let mut names: Vec<&str> = RefusalCode::ALL.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), RefusalCode::ALL.len());
    }

    #[test]
    fn the_fallback_response_is_exactly_the_unusable_refusal() {
        // If rendering ever failed, the front-end must still read a refusal.
        let unusable = BrokerResponse::refused(RefusalCode::BrokerUnusable);
        assert_eq!(unusable.to_json(), FALLBACK_RESPONSE);
        assert_eq!(
            BrokerResponse::parse(FALLBACK_RESPONSE.as_bytes()).unwrap(),
            unusable
        );
    }

    #[test]
    fn serialization_failure_falls_back_instead_of_panicking() {
        let failed: Result<String, serde_json::Error> = serde_json::from_str("not json");
        assert_eq!(rendered_or(failed, "{}"), "{}");
        assert_eq!(rendered_or(Ok("rendered".to_owned()), "{}"), "rendered");
        assert_ne!(request().to_json(), "{}");
    }

    #[test]
    fn response_rejects_non_utf8_and_an_invalid_minted_nonce() {
        assert_eq!(response_text(b"{}"), Ok("{}"));
        let refused = BrokerResponse::parse(&[0xff]).unwrap_err();
        assert_eq!(refused, ResponseError::NotUtf8 { offset: 0 });
        assert!(valid_queue_reason(None));
        assert!(valid_queue_reason(Some("review requested")));
        assert!(!valid_queue_reason(Some("bad\0reason")));
        let response = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Decided {
                decision: Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new()),
                minted: Some(Minted {
                    nonce: "invalid".to_owned(),
                    expires_in_ms: 1,
                    gate: "/usr/libexec/xudo/xudo-gate-auth".to_owned(),
                    claim_token: None,
                    harness: None,
                }),
            },
        };
        let refused = BrokerResponse::parse(response.to_json().as_bytes()).unwrap_err();
        assert_eq!(
            refused,
            ResponseError::Malformed {
                reason: "id must be 64 lowercase hexadecimal characters".to_owned(),
            }
        );
    }

    fn minted() -> Minted {
        Minted {
            nonce: "ab".repeat(32),
            expires_in_ms: 900_000,
            gate: "/usr/libexec/xudo/xudo-gate-auth".to_owned(),
            claim_token: None,
            harness: None,
        }
    }

    /// The verdict an answer carries, if it carries a decision.
    ///
    /// A helper rather than a match in each test, so both arms run here and
    /// neither is a region only a broken test could reach.
    fn verdict_of(answer: &Answer) -> Option<Verdict> {
        match answer {
            Answer::Decided { decision, .. } => Some(decision.verdict),
            Answer::Refused { .. }
            | Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::QueueListed { .. }
            | Answer::Done => None,
        }
    }

    #[test]
    fn every_answer_round_trips() {
        let decision = Decision::deny(DenialCode::ArgvRejected, vec!["x".to_owned()], Vec::new());
        let id = "a".repeat(64);
        for answer in [
            Answer::Decided {
                decision: decision.clone(),
                minted: None,
            },
            Answer::Pending {
                id: id.clone(),
                expires_in_ms: 1234,
            },
            Answer::Watching {
                prompts: vec![WatchPrompt {
                    id: "a".repeat(64),
                    action: "xudo.pkg.remove".to_owned(),
                    program: "/usr/bin/apt-get".to_owned(),
                    argv: vec!["remove".to_owned()],
                    classification: "unattested".to_owned(),
                    evidence: "password remains required".to_owned(),
                    expires_in_ms: 1_000,
                }],
                omitted: 0,
            },
            Answer::QueueListed {
                entries: vec![QueueListEntry {
                    id: "a".repeat(64),
                    argv: vec!["/usr/bin/true".into()],
                    cwd: "/tmp".into(),
                    harness: "codex".into(),
                    uid: 1000,
                    rule_id: "test.run".into(),
                    generation: 1,
                    queued_at: 1,
                    expires_at: 2,
                    reason: Some("review requested".into()),
                    state: "pending".into(),
                }],
                next: None,
            },
            Answer::Done,
            BrokerResponse::refused(RefusalCode::RequestUnknown).answer,
        ] {
            let response = BrokerResponse {
                schema_version: WIRE_SCHEMA_VERSION,
                answer,
            };
            assert_eq!(
                BrokerResponse::parse(response.to_json().as_bytes()).unwrap(),
                response
            );
        }
    }

    #[test]
    fn response_nonce_gate_and_remediation_are_checked() {
        let bad_id = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Pending {
                id: "ABC".to_owned(),
                expires_in_ms: 1,
            },
        };
        assert_eq!(
            BrokerResponse::parse(bad_id.to_json().as_bytes()),
            Err(ResponseError::Malformed {
                reason: "id must be 64 lowercase hexadecimal characters".to_owned()
            })
        );
        let invalid_nonce = BrokerResponse::decided(
            Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new()),
            Some(Minted {
                nonce: "ABC".to_owned(),
                expires_in_ms: 1,
                gate: "/bin/id".to_owned(),
                claim_token: None,
                harness: None,
            }),
        );
        assert_eq!(
            BrokerResponse::parse(invalid_nonce.to_json().as_bytes()),
            Err(ResponseError::Malformed {
                reason: "id must be 64 lowercase hexadecimal characters".to_owned()
            })
        );
        for gate in [
            "relative".to_owned(),
            format!("/{}", "x".repeat(MAX_PROGRAM_BYTES)),
            "/bin\0evil".to_owned(),
        ] {
            let response = BrokerResponse::decided(
                Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new()),
                Some(Minted {
                    nonce: "a".repeat(64),
                    expires_in_ms: 1,
                    gate,
                    claim_token: None,
                    harness: None,
                }),
            );
            assert_eq!(
                BrokerResponse::parse(response.to_json().as_bytes()),
                Err(ResponseError::Malformed {
                    reason: "minted gate is invalid or too long".to_owned()
                })
            );
        }
        let response = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Refused {
                code: RefusalCode::RequestUnknown,
                remediation: "x".repeat(MAX_PROMPT_BYTES + 1),
                detail: None,
            },
        };
        assert_eq!(
            BrokerResponse::parse(response.to_json().as_bytes()),
            Err(ResponseError::Malformed {
                reason: "remediation exceeds its bound".to_owned()
            })
        );
    }

    #[test]
    fn response_prompt_bounds_are_enforced() {
        let response = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Watching {
                prompts: vec![watch_prompt(); MAX_PROMPTS + 1],
                omitted: 0,
            },
        };
        assert_eq!(
            BrokerResponse::parse(response.to_json().as_bytes()),
            Err(ResponseError::Malformed {
                reason: "watch prompt list exceeds its bound".to_owned()
            })
        );
        let response = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Watching {
                prompts: vec![WatchPrompt {
                    action: "x".repeat(MAX_PROMPT_BYTES + 1),
                    ..watch_prompt()
                }],
                omitted: 0,
            },
        };
        assert_eq!(
            BrokerResponse::parse(response.to_json().as_bytes()),
            Err(ResponseError::Malformed {
                reason: "watch prompt list exceeds its bound".to_owned()
            })
        );
        let response = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION,
            answer: Answer::Watching {
                prompts: vec![WatchPrompt {
                    program: "/bad\0program".to_owned(),
                    ..watch_prompt()
                }],
                omitted: 0,
            },
        };
        assert_eq!(
            BrokerResponse::parse(response.to_json().as_bytes()),
            Err(ResponseError::Malformed {
                reason: "watch prompt list exceeds its bound".to_owned()
            })
        );
    }

    #[test]
    fn response_refuses_every_malformed_watch_prompt_field() {
        let mut bad_id = watch_prompt();
        bad_id.id = "A".repeat(NONCE_HEX_LEN);
        let mut relative_program = watch_prompt();
        relative_program.program = "bin/apt-get".to_owned();
        let mut long_program = watch_prompt();
        long_program.program = format!("/{}", "x".repeat(MAX_PROGRAM_BYTES));
        let mut empty_action = watch_prompt();
        empty_action.action.clear();
        let mut nul_action = watch_prompt();
        nul_action.action.push('\0');
        let mut many_args = watch_prompt();
        many_args.argv = vec!["x".to_owned(); MAX_ARGV_COUNT + 1];
        let mut long_arg = watch_prompt();
        long_arg.argv = vec!["x".repeat(MAX_ARGUMENT_BYTES + 1)];
        let mut nul_arg = watch_prompt();
        nul_arg.argv = vec!["bad\0arg".to_owned()];
        let mut long_class = watch_prompt();
        long_class.classification = "x".repeat(MAX_CLASSIFICATION_BYTES + 1);
        let mut nul_class = watch_prompt();
        nul_class.classification.push('\0');
        let mut long_evidence = watch_prompt();
        long_evidence.evidence = "x".repeat(MAX_PROMPT_BYTES + 1);
        let mut nul_evidence = watch_prompt();
        nul_evidence.evidence.push('\0');

        for prompt in [
            bad_id,
            relative_program,
            long_program,
            empty_action,
            nul_action,
            many_args,
            long_arg,
            nul_arg,
            long_class,
            nul_class,
            long_evidence,
            nul_evidence,
        ] {
            let response = BrokerResponse {
                schema_version: WIRE_SCHEMA_VERSION,
                answer: Answer::Watching {
                    prompts: vec![prompt],
                    omitted: 0,
                },
            };
            assert_eq!(
                BrokerResponse::parse(response.to_json().as_bytes()).unwrap_err(),
                ResponseError::Malformed {
                    reason: "watch prompt list exceeds its bound".to_owned()
                }
            );
        }
    }

    fn watch_prompt() -> WatchPrompt {
        WatchPrompt {
            id: "a".repeat(64),
            action: "xudo.pkg.remove".to_owned(),
            program: "/usr/bin/apt-get".to_owned(),
            argv: vec!["remove".to_owned()],
            classification: "unattested".to_owned(),
            evidence: "password remains required".to_owned(),
            expires_in_ms: 1_000,
        }
    }

    #[test]
    fn refusal_detail_is_optional_but_bounded_and_single_line() {
        let valid = BrokerResponse::refused_with_detail(
            RefusalCode::ChannelUntrusted,
            "watcher already active: pid 77, tty 34816".to_owned(),
        );
        assert!(BrokerResponse::parse(valid.to_json().as_bytes()).is_ok());
        for detail in ["x".repeat(MAX_PROMPT_BYTES + 1), "bad\0detail".to_owned()] {
            let response =
                BrokerResponse::refused_with_detail(RefusalCode::ChannelUntrusted, detail);
            assert_eq!(
                BrokerResponse::parse(response.to_json().as_bytes()),
                Err(ResponseError::Malformed {
                    reason: "refusal detail exceeds its bound".to_owned()
                })
            );
        }
    }

    #[test]
    fn a_decided_response_round_trips_with_and_without_an_entry() {
        let decision = Decision::deny(DenialCode::ArgvRejected, vec!["x".to_owned()], Vec::new());
        for response in [
            BrokerResponse::decided(decision.clone(), None),
            BrokerResponse::decided(decision.clone(), Some(minted())),
            BrokerResponse::refused(RefusalCode::SpoolFull),
        ] {
            let parsed = BrokerResponse::parse(response.to_json().as_bytes()).unwrap();
            assert_eq!(parsed, response);
        }
        let parsed =
            BrokerResponse::parse(BrokerResponse::decided(decision, None).to_json().as_bytes())
                .unwrap();
        assert_eq!(verdict_of(&parsed.answer), Some(Verdict::Deny));
        assert_eq!(
            verdict_of(&BrokerResponse::refused(RefusalCode::SpoolFull).answer),
            None
        );
    }

    #[test]
    fn an_array_form_response_is_refused() {
        assert_eq!(
            BrokerResponse::parse(br#"[2,"done"]"#),
            Err(ResponseError::Malformed {
                reason: "top-level JSON value must be an object".to_owned(),
            })
        );
    }

    #[test]
    fn struct_variant_answers_must_use_the_map_form() {
        let id = "a".repeat(NONCE_HEX_LEN);
        let bytes = format!(r#"{{"schema_version":2,"answer":{{"pending":["{id}",1]}}}}"#);
        assert!(BrokerResponse::parse(bytes.as_bytes()).is_err());
    }

    #[test]
    fn a_response_with_a_different_schema_is_refused() {
        let bytes = br#"{"schema_version":3,"answer":{"done":null}}"#;
        assert_eq!(
            BrokerResponse::parse(bytes),
            Err(ResponseError::WrongSchema {
                found: 3,
                expected: WIRE_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn decoded_response_schema_is_rechecked() {
        let response = BrokerResponse {
            schema_version: WIRE_SCHEMA_VERSION + 1,
            answer: Answer::Done,
        };
        assert_eq!(
            response.check(),
            Err(ResponseError::WrongSchema {
                found: WIRE_SCHEMA_VERSION + 1,
                expected: WIRE_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn a_duplicate_key_response_is_refused() {
        let repeated_schema = br#"{"schema_version":2,"schema_version":2,"answer":"done"}"#;
        let duplicate_error = serde_json::from_slice::<BrokerResponse>(repeated_schema)
            .unwrap_err()
            .to_string();
        assert_eq!(
            BrokerResponse::parse(repeated_schema),
            Err(ResponseError::Malformed {
                reason: duplicate_error,
            })
        );

        let nested_duplicate = format!(
            "{{\"schema_version\":2,\"answer\":{{\"decided\":{{\"decision\":{},\"minted\":{{\"nonce\":\"{}\",\"nonce\":\"{}\",\"expires_in_ms\":900000,\"gate\":\"/usr/libexec/xudo/xudo-gate-auth\"}}}}}}}}",
            serde_json::to_string(&Decision::deny(
                DenialCode::ArgvRejected,
                vec!["x".to_owned()],
                Vec::new(),
            ))
            .unwrap(),
            "ab".repeat(32),
            "cd".repeat(32),
        );
        assert_eq!(
            BrokerResponse::parse(nested_duplicate.as_bytes()).unwrap_err(),
            ResponseError::Malformed {
                reason: serde_json::from_str::<BrokerResponse>(&nested_duplicate)
                    .unwrap_err()
                    .to_string(),
            }
        );
    }

    #[test]
    fn a_response_is_bounded_checked_and_strict() {
        let over = vec![b' '; MAX_RESPONSE_BYTES + 1];
        assert_eq!(
            BrokerResponse::parse(&over),
            Err(ResponseError::TooLarge {
                limit: MAX_RESPONSE_BYTES
            })
        );
        assert_eq!(
            BrokerResponse::parse(b"\xff"),
            Err(ResponseError::NotUtf8 { offset: 0 })
        );
        let malformed = BrokerResponse::parse(b"{}").unwrap_err();
        assert!(malformed.to_string().contains("not a broker response"));

        // An answer that smuggles in a key the front-end does not know.
        let mut object: serde_json::Value = serde_json::from_str(
            &BrokerResponse::decided(
                Decision::deny(DenialCode::DenyListed, Vec::new(), Vec::new()),
                Some(minted()),
            )
            .to_json(),
        )
        .unwrap();
        object["answer"]["decided"]["minted"]
            .as_object_mut()
            .unwrap()
            .insert("confirmed".to_owned(), serde_json::Value::Bool(true));
        let smuggled = BrokerResponse::parse(object.to_string().as_bytes()).unwrap_err();
        assert!(
            smuggled.to_string().contains("unknown field `confirmed`"),
            "{smuggled}"
        );

        let mut future: serde_json::Value =
            serde_json::from_str(&BrokerResponse::refused(RefusalCode::SpoolFull).to_json())
                .unwrap();
        future["schema_version"] = serde_json::Value::from(3);
        let error = BrokerResponse::parse(future.to_string().as_bytes()).unwrap_err();
        assert_eq!(
            error,
            ResponseError::WrongSchema {
                found: 3,
                expected: WIRE_SCHEMA_VERSION
            }
        );
        for error in [
            ResponseError::TooLarge { limit: 1 },
            ResponseError::NotUtf8 { offset: 0 },
            error,
        ] {
            assert!(error.to_string().len() > 20, "{error:?}");
        }
    }

    #[test]
    fn a_decision_in_an_envelope_of_another_version_is_refused() {
        // The wire version can match while the envelope inside it does not:
        // a broker built against a newer engine. The front-end refuses it
        // rather than reading fields it does not understand.
        let mut decision = Decision::deny(DenialCode::ArgvRejected, Vec::new(), Vec::new());
        decision.schema_version = ENVELOPE_SCHEMA_VERSION + 1;
        let newer = BrokerResponse::decided(decision, None).to_json();
        let error = BrokerResponse::parse(newer.as_bytes()).unwrap_err();
        assert_eq!(
            error,
            ResponseError::WrongEnvelope {
                found: ENVELOPE_SCHEMA_VERSION + 1,
                expected: ENVELOPE_SCHEMA_VERSION
            }
        );
        assert!(error.to_string().contains("envelope schema"), "{error}");
    }

    #[test]
    fn the_socket_and_limits_are_the_documented_ones() {
        assert_eq!(BROKER_SOCKET, "/run/xudo/broker.sock");
        assert!(!BROKER_SOCKET.starts_with("/tmp"));
        assert_eq!(MAX_REQUEST_BYTES, 16 * 1024);
        assert_eq!(MAX_RESPONSE_BYTES, 256 * 1024);
    }
}
