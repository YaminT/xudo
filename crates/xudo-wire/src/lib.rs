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
}

impl BrokerRequest {
    /// Builds a schema 2 run request.
    pub fn new(
        program: impl Into<String>,
        argv: Vec<String>,
        claimed_classification: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: WIRE_SCHEMA_VERSION,
            question: Question::Run {
                program: program.into(),
                argv,
                claimed_classification: claimed_classification.into(),
            },
        }
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
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(found) = value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
            {
                if found != WIRE_SCHEMA_VERSION {
                    return Err(RequestError::WrongSchema {
                        found,
                        expected: WIRE_SCHEMA_VERSION,
                    });
                }
            }
        }
        let request: Self =
            serde_json::from_str(text).map_err(|error| RequestError::Malformed {
                reason: error.to_string(),
            })?;
        request.check()?;
        Ok(request)
    }

    fn check(&self) -> Result<(), RequestError> {
        match &self.question {
            Question::Run {
                program,
                argv,
                claimed_classification,
            } => {
                bounded("program", program, MAX_PROGRAM_BYTES)?;
                if !program.starts_with('/') {
                    return Err(RequestError::ProgramNotAbsolute {
                        program: program.clone(),
                    });
                }
                refuse_nul("program", program)?;
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
            Question::Status { id } => check_id(id)?,
            Question::Watch | Question::Thaw => {}
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
            } => Some((program, argv, claimed_classification)),
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

/// What happened to a request.
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
        prompts: Vec<String>,
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
}

impl RefusalCode {
    /// Every code, in numeric order.
    pub const ALL: [Self; 17] = [
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
        let text = std::str::from_utf8(bytes).map_err(|error| ResponseError::NotUtf8 {
            offset: error.valid_up_to(),
        })?;
        let response: Self =
            serde_json::from_str(text).map_err(|error| ResponseError::Malformed {
                reason: error.to_string(),
            })?;
        if response.schema_version != WIRE_SCHEMA_VERSION {
            return Err(ResponseError::WrongSchema {
                found: response.schema_version,
                expected: WIRE_SCHEMA_VERSION,
            });
        }
        match &response.answer {
            Answer::Decided { minted, .. } => {
                if let Some(minted) = minted {
                    check_nonce(&minted.nonce)
                        .map_err(|reason| ResponseError::Malformed { reason })?;
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
            Answer::Watching { prompts } => {
                if prompts.len() > MAX_PROMPTS
                    || prompts
                        .iter()
                        .any(|p| p.len() > MAX_PROMPT_BYTES || p.contains('\0'))
                {
                    return Err(ResponseError::Malformed {
                        reason: "watch prompt list exceeds its bound".to_owned(),
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
        let envelope = match &response.answer {
            Answer::Decided { decision, .. } => decision.schema_version,
            Answer::Pending { .. }
            | Answer::Watching { .. }
            | Answer::Done
            | Answer::Refused { .. } => ENVELOPE_SCHEMA_VERSION,
        };
        if envelope != ENVELOPE_SCHEMA_VERSION {
            return Err(ResponseError::WrongEnvelope {
                found: envelope,
                expected: ENVELOPE_SCHEMA_VERSION,
            });
        }
        Ok(response)
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use xudo_policy::{DenialCode, Verdict};

    use super::*;

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
                    claimed_classification: "x".repeat(MAX_CLASSIFICATION_BYTES + 1),
                },
                RefusalCode::RequestMalformed,
            ),
            (
                Question::Run {
                    program: "/usr/bin/id".to_owned(),
                    argv: Vec::new(),
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
            Question::Answer {
                id: id.clone(),
                token: "token".to_owned(),
                approve: false,
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
            assert_eq!(request.run_fields(), None);
        }
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
                    claimed_classification: "x".to_owned(),
                },
                "program",
            ),
            (
                Question::Run {
                    program: "/".to_owned(),
                    argv: vec!["x".repeat(MAX_ARGUMENT_BYTES + 1)],
                    claimed_classification: "x".to_owned(),
                },
                "argument",
            ),
            (
                Question::Run {
                    program: "/".to_owned(),
                    argv: vec!["x".to_owned(); MAX_ARGV_COUNT + 1],
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
    fn every_question_round_trips() {
        let id = "a".repeat(64);
        for question in [
            Question::Run {
                program: "/usr/bin/id".to_owned(),
                argv: vec!["-u".to_owned()],
                claimed_classification: "unattested".to_owned(),
            },
            Question::Status { id: id.clone() },
            Question::Watch,
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

    fn minted() -> Minted {
        Minted {
            nonce: "ab".repeat(32),
            expires_in_ms: 900_000,
            gate: "/usr/libexec/xudo/xudo-gate-auth".to_owned(),
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
                prompts: vec!["approve remove".to_owned()],
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
                prompts: vec!["x".to_owned(); MAX_PROMPTS + 1],
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
                prompts: vec!["x".repeat(MAX_PROMPT_BYTES + 1)],
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
                prompts: vec!["bad\0prompt".to_owned()],
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
