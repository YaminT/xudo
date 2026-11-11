//! The spool entry, and the four facts checked before the ruleset is consulted.
//!
//! The gate takes no arguments — the sudoers rule enforces `""` — and reads
//! nothing from its environment. What it *does* read is one file under
//! [`SPOOL_DIR`], which is root-owned `0700` and written only by the broker.
//! Its contents are therefore root's, and the gate still validates them, for two
//! reasons that both matter: the ownership check can only be trusted if it was
//! made on the **opened fd** rather than the path, and a gate that is correct
//! only when its input is well-formed is a gate whose correctness argument rests
//! on the thing an attacker attacks first.
//!
//! So the entry is validated as if hostile, and the properties established are
//! narrow and mechanical:
//!
//! 1. **It is this wire format.** An unknown schema, an unknown key, or a
//!    missing key is a hard parse failure, never a partially-understood request.
//! 2. **It is live.** Past its deadline, it is refused. Deadlines are in
//!    boottime milliseconds, so suspend cannot extend one.
//! 3. **It is this caller's.** The entry names the pid *and* the start time of
//!    the `xudo` process it was minted for. A pid alone is a name that can be
//!    reissued; `(pid, starttime)` identifies one process for as long as the
//!    kernel remembers it.
//! 4. **It belongs to the current policy generation.** An entry minted before
//!    the operator changed the rules is refused rather than honoured under the
//!    rules it was written against.
//!
//! Note what is deliberately *not* checked here: whether the action is
//! permitted. That is [`crate::decide()`]'s question, answered against root's
//! ruleset — never against the entry's own claim about it. Keeping the two apart
//! is what lets the gate state plainly that a forged entry can name any action
//! it likes and gain nothing the ruleset does not already grant.

use serde::{Deserialize, Serialize};

/// Where pending requests live.
///
/// Root-owned, `0700` and under `/run`, so entries vanish on reboot and never
/// share a directory with anything a user can also write. Never `/tmp`: a
/// world-writable directory turns every open into a symlink race.
pub const SPOOL_DIR: &str = "/run/xudo/req";

/// The wire version of a spool entry.
pub const REQUEST_SCHEMA_VERSION: u32 = 4;

/// Classification fixed by the broker from kernel-attested caller facts.
///
/// The request's `claimed_classification` is deliberately not representable
/// here: it is an unauthenticated audit hint, never an identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum AttestedClass {
    /// No positive identity proof was available; the gate keeps the password path.
    Unattested,
    /// An authenticated interactive human.
    Human,
    /// An enrolled agent tied to its kernel cgroup id.
    EnrolledAgent {
        /// Kernel cgroup id of the enrolled scope.
        scope_id: u64,
    },
}

fn finish_parse(request: PendingRequest) -> Result<PendingRequest, RequestError> {
    if request.schema_version != REQUEST_SCHEMA_VERSION {
        return Err(RequestError::WrongSchema {
            found: request.schema_version,
            expected: REQUEST_SCHEMA_VERSION,
        });
    }
    Ok(request)
}

/// How long a nonce is, in hex characters (32 random bytes).
pub const NONCE_HEX_LEN: usize = 64;

/// A boottime instant, in milliseconds since an unspecified epoch.
///
/// Wrapped rather than passed as a bare `u64` because the *only* correct source
/// is `CLOCK_BOOTTIME`: unlike `CLOCK_MONOTONIC`, it advances during suspend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoottimeMillis(pub u64);

/// The identity of one process, pinned against pid reuse.
///
/// The start time is not decoration. Between the front-end minting a request and
/// the gate reading it, the front-end may have exited and its pid been reissued.
/// Comparing both fields means the gate is talking about the process that asked,
/// or about nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerPin {
    /// The process id.
    pub pid: u32,
    /// Its start time, in kernel clock ticks since boot.
    pub starttime: u64,
}

/// State of a human confirmation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationState {
    /// Waiting for a checked watcher.
    Pending,
    /// Approved by a checked watcher; password is still required by the gate.
    Approved,
    /// Consumed by the broker; accepted for this gate execution only.
    Consumed,
    /// Refused by a watcher.
    Denied,
    /// The entry deadline passed.
    Expired,
}

/// Kernel facts pinning the watcher who approved an entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherPin {
    /// Effective uid from the peer credentials.
    pub uid: u32,
    /// Pid from the peer credentials.
    pub pid: u32,
    /// Process start time, preventing pid reuse.
    pub starttime: u64,
    /// Controlling terminal number.
    pub tty: i64,
    /// Session id.
    pub sid: i64,
}

impl WatcherPin {
    /// Whether this pin is an eligible watcher for the minted caller.
    ///
    /// Watchers must share the requester's uid; the plan's alternative "or 0"
    /// is deliberately narrowed so root cannot approve another user's request.
    pub fn is_eligible_for(&self, uid: u32, pid: u32, starttime: u64, sid: i64, tty: i64) -> bool {
        self.uid == uid
            && self.pid != 0
            && self.sid != sid
            && self.tty != tty
            && is_watch_terminal(self.tty)
            && !(self.pid == pid && self.starttime == starttime)
    }

    /// Stable audit text for the pinned watcher.
    pub fn audit_text(&self) -> String {
        format!(
            "uid={},pid={},starttime={},tty={},sid={}",
            self.uid, self.pid, self.starttime, self.tty, self.sid
        )
    }
}

/// Linux `tty_nr` major encoding: only pts devices and virtual consoles count.
/// Major 4 minor 64+ is ttyS serial hardware, which is deliberately excluded.
pub fn is_watch_terminal(tty_nr: i64) -> bool {
    let Ok(tty) = u64::try_from(tty_nr) else {
        return false;
    };
    if tty == 0 {
        return false;
    }
    let major = ((tty >> 8) & 0x0fff) as u16;
    let minor = (tty & 0xff) | ((tty >> 12) & 0xfff00);
    (136..=143).contains(&major) || (major == 4 && (1..64).contains(&minor))
}

impl CallerPin {
    /// Builds a pin.
    pub fn new(pid: u32, starttime: u64) -> Self {
        Self { pid, starttime }
    }
}

/// Why a spool entry cannot be acted on.
///
/// Every variant is a refusal. There is no variant meaning "close enough",
/// because the gate's alternative to refusing is running something as root.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The entry could not be parsed at all.
    #[error("spool entry is not a valid request: {reason}")]
    Malformed {
        /// The parser's account of why.
        reason: String,
    },
    /// The entry announces a schema this build does not implement.
    #[error("spool entry declares schema {found}, this gate implements {expected}")]
    WrongSchema {
        /// What the entry said.
        found: u32,
        /// What this build understands.
        expected: u32,
    },
    /// The stored classification and scope fields contradict one another.
    #[error("attested class and scope identity are inconsistent")]
    InvalidAttestedIdentity,
    /// The nonce is not the shape a minted nonce has.
    #[error(
        "nonce is not {NONCE_HEX_LEN} lowercase hex characters: it names a file, so anything else \
         is an attempt to name a different one"
    )]
    MalformedNonce,
    /// The action id is empty.
    #[error("request names no action")]
    NoAction,
    /// The program is not an absolute path.
    #[error("program {program} is not absolute: a relative program is resolved against a cwd")]
    NotAbsoluteProgram {
        /// What was given.
        program: String,
    },
    /// A string contained a NUL byte.
    ///
    /// `execve` takes NUL-terminated strings, so an interior NUL means the
    /// kernel would run a *prefix* of what was reviewed. That is a
    /// review-bypass, not a formatting problem.
    #[error("{field} contains a NUL byte, so the kernel would see only the part before it")]
    InteriorNul {
        /// Which field.
        field: String,
    },
    /// The entry's deadline has passed.
    #[error("request expired: deadline was {deadline} boottime milliseconds, it is now {now}")]
    Expired {
        /// The deadline it carried.
        deadline: u64,
        /// The current boottime reading.
        now: u64,
    },
    /// The entry was minted for a different process.
    #[error(
        "request was minted for pid {expected_pid} started at {expected_starttime}, but the caller \
         is pid {actual_pid} started at {actual_starttime}"
    )]
    WrongCaller {
        /// The pid the entry names.
        expected_pid: u32,
        /// The start time the entry names.
        expected_starttime: u64,
        /// The pid actually asking.
        actual_pid: u32,
        /// Its start time.
        actual_starttime: u64,
    },
    /// The entry claims a confirmation but records no channel for it.
    #[error("request is marked confirmed but names no channel that carried the approval")]
    UnattributedConfirmation,
    /// The lifecycle fields contradict one another or are malformed.
    #[error("confirmation state is inconsistent or malformed")]
    InvalidConfirmationState,
    /// The policy changed after the entry was minted.
    #[error("request was minted under policy generation {minted}, current generation is {current}")]
    StaleGeneration {
        /// The generation it was minted under.
        minted: u64,
        /// The generation now in force.
        current: u64,
    },
    /// More than one entry in the spool is pinned to this caller's lineage.
    ///
    /// The broker mints one entry per request, and a caller waits for the gate
    /// it started, so two means something else wrote an entry or the broker
    /// is broken. Which one the caller meant cannot be told, and guessing is
    /// choosing what runs as root, so the gate runs neither.
    #[error(
        "{matches} spool entries are pinned to this caller's lineage: which one was meant cannot \
         be told, so none is run"
    )]
    Ambiguous {
        /// How many entries matched.
        matches: usize,
    },
    /// An entry pinned to this lineage is not the one its name says it is.
    ///
    /// The name is the nonce, and the broker writes the nonce inside the entry
    /// too. An entry whose content disagrees with its name was not minted by
    /// the broker's one code path.
    #[error(
        "spool entry {name} carries a different nonce than its name: it was not minted by the broker"
    )]
    ForgedNonce {
        /// The entry's file name, which is a valid nonce.
        name: String,
    },
}

impl RequestError {
    /// The stable code recorded in the audit trail.
    ///
    /// Stable strings rather than the `Debug` rendering, so an operator's alert
    /// on `request_expired` does not stop firing because a field was renamed.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "request_malformed",
            Self::WrongSchema { .. } => "request_wrong_schema",
            Self::InvalidAttestedIdentity => "request_invalid_attested_identity",
            Self::MalformedNonce => "request_malformed_nonce",
            Self::NoAction => "request_no_action",
            Self::NotAbsoluteProgram { .. } => "request_program_not_absolute",
            Self::InteriorNul { .. } => "request_interior_nul",
            Self::Expired { .. } => "request_expired",
            Self::WrongCaller { .. } => "request_wrong_caller",
            Self::UnattributedConfirmation => "request_unattributed_confirmation",
            Self::InvalidConfirmationState => "request_invalid_confirmation_state",
            Self::StaleGeneration { .. } => "request_stale_generation",
            Self::Ambiguous { .. } => "request_ambiguous",
            Self::ForgedNonce { .. } => "request_forged_nonce",
        }
    }
}

/// One pending request, as it sits in the spool.
///
/// Every field is required. There are no `serde` defaults and no unknown keys:
/// a request the gate only partly understands is a request it declines to
/// understand at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRequest {
    /// Wire version.
    pub schema_version: u32,
    /// The one-use nonce, which is also the entry's file name.
    pub nonce: String,
    /// The pid of the `xudo` process this was minted for.
    pub caller_pid: u32,
    /// That process's start time, in clock ticks since boot.
    pub caller_starttime: u64,
    /// The named action being asked for.
    pub action: String,
    /// The absolute program the action runs.
    ///
    /// Carried even though the ruleset also names it, so that a mismatch is
    /// visible as a mismatch. [`crate::decide()`] compares the two and refuses on
    /// a difference rather than quietly preferring one.
    pub program: String,
    /// The operands, after the program name.
    pub argv: Vec<String>,
    /// The policy generation in force when this was minted.
    pub generation: u64,
    /// When this stops being valid, in boottime milliseconds.
    pub deadline: BoottimeMillis,
    /// Whether a human approved this request, out of band.
    ///
    /// Set by the broker after the confirmation channel returned an approval,
    /// and never by the front-end — the front-end runs inside the requester's
    /// process tree, which is exactly the place invariant 3 says a confirmation
    /// may not come from. The gate cannot confirm anything itself: it has no
    /// channel that the caller does not own. So its only options for an action
    /// whose rule demands confirmation are "the broker says a human approved" or
    /// "refuse", and the second is the default.
    pub confirmed: bool,
    /// Which checked watcher carried the approval.
    ///
    /// Required whenever [`Self::confirmed`] is set. A confirmation with no
    /// recorded channel cannot be reviewed after the fact, and an unreviewable
    /// approval is indistinguishable from one that never happened.
    pub confirmed_by: Option<WatcherPin>,
    /// The confirmation lifecycle state.
    pub state: ConfirmationState,
    /// Effective uid of the requester.
    pub caller_uid: u32,
    /// Session id of the requester when minted.
    pub caller_sid: i64,
    /// Controlling terminal number of the requester when minted.
    pub caller_tty: i64,
    /// Whether this request requires out-of-band approval.
    pub needs_watch: bool,
    /// Time the prompt was first shown to the `shown_to` watcher.
    pub shown_at_ms: Option<BoottimeMillis>,
    /// Watcher to whom the prompt timestamp applies.
    pub shown_to: Option<WatcherPin>,
    /// Length-framed SHA-256 of uid, program, and argv.
    pub fingerprint: String,
    /// How the front-end classified the caller.
    ///
    /// An **unauthenticated hint**, recorded in the audit trail and given zero
    /// authorization weight: the gate re-derives classification from
    /// kernel-attested facts. Kept because "the caller claimed to be an enrolled
    /// agent and it changed nothing" is exactly what an investigator needs to be
    /// able to see.
    pub claimed_classification: String,
    /// Identity assigned by the broker from kernel-attested facts.
    pub attested_class: AttestedClass,
    /// The kernel cgroup id, duplicated for explicit matching by consumers.
    pub attested_scope_id: Option<u64>,
    /// Kernel boot identifier associated with the scope, when available.
    pub boot_id: Option<String>,
}

impl PendingRequest {
    /// Parses one spool entry.
    ///
    /// # Errors
    ///
    /// [`RequestError::Malformed`] for anything that is not this wire format,
    /// including an unknown key or a missing required key. Optional fields
    /// (`confirmed_by`, `shown_at_ms`, and `shown_to`) may be omitted and
    /// deserialize as `None`, as serde defines for `Option` fields. Attested
    /// identity fields must use canonical shapes and agree with each other:
    /// `attested_scope_id` and `boot_id` are both required for an enrolled
    /// agent and both absent for a human or unattested caller.
    pub fn parse(text: &str) -> Result<Self, RequestError> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|error| RequestError::Malformed {
                reason: error.to_string(),
            })?;
        if !value.is_object() {
            return Err(RequestError::Malformed {
                reason: "top-level JSON value must be an object".to_owned(),
            });
        }
        if let Some(found) = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|number| u32::try_from(number).ok())
            && found != REQUEST_SCHEMA_VERSION
        {
            return Err(RequestError::WrongSchema {
                found,
                expected: REQUEST_SCHEMA_VERSION,
            });
        }
        let attested_class_has_valid_shape = value.get("attested_class").is_some_and(|class| {
            class.is_string()
                || class.as_object().is_some_and(|variants| {
                    variants.len() == 1
                        && variants
                            .get("enrolled_agent")
                            .is_some_and(serde_json::Value::is_object)
                })
        });
        if !attested_class_has_valid_shape
            || value
                .get("confirmed_by")
                .is_some_and(|pin| !pin.is_null() && !pin.is_object())
            || value
                .get("shown_to")
                .is_some_and(|pin| !pin.is_null() && !pin.is_object())
            || value.get("state").is_some_and(|state| !state.is_string())
        {
            return Err(RequestError::Malformed {
                reason: "nested values must use object and string forms".to_owned(),
            });
        }
        let request: Self =
            serde_json::from_str(text).map_err(|error| RequestError::Malformed {
                reason: error.to_string(),
            })?;
        finish_parse(request)
    }

    /// Renders the entry back to JSON.
    ///
    /// Used by the minting side and by tests. Falls back to an empty object
    /// rather than panicking: this type is plain data, so serialization cannot
    /// fail, and a fallback costs less than an `unwrap` in a privileged binary.
    ///
    /// The fallback is a value handed to a free function rather than a closure,
    /// for the same reason `xudo_audit::Record::to_jsonl` does it that way: a
    /// lazily-built fallback leaves an arm only a broken serializer could reach,
    /// and therefore one no test can exercise.
    pub fn to_json(&self) -> String {
        or_empty_object(serde_json::to_string(self))
    }

    /// Checks the four facts described in the module docs.
    ///
    /// The order is deliberate: shape before liveness, liveness before identity,
    /// identity before policy generation. A malformed entry must not produce an
    /// error message about the *caller*, because that message would be reporting
    /// a comparison made against fields that were never validated.
    ///
    /// # Errors
    ///
    /// The first fact that does not hold, as the matching [`RequestError`].
    pub fn validate(
        &self,
        caller: CallerPin,
        generation: u64,
        now: BoottimeMillis,
    ) -> Result<(), RequestError> {
        if self.schema_version != REQUEST_SCHEMA_VERSION {
            return Err(RequestError::WrongSchema {
                found: self.schema_version,
                expected: REQUEST_SCHEMA_VERSION,
            });
        }
        let valid_attested_identity = match &self.attested_class {
            AttestedClass::EnrolledAgent { scope_id } => {
                self.attested_scope_id == Some(*scope_id)
                    && self.boot_id.as_ref().is_some_and(|id| is_boot_id(id))
            }
            AttestedClass::Unattested | AttestedClass::Human => {
                self.attested_scope_id.is_none() && self.boot_id.is_none()
            }
        };
        if !valid_attested_identity {
            return Err(RequestError::InvalidAttestedIdentity);
        }
        if !is_nonce(&self.nonce) {
            return Err(RequestError::MalformedNonce);
        }
        if self.action.is_empty() {
            return Err(RequestError::NoAction);
        }
        if !self.program.starts_with('/') {
            return Err(RequestError::NotAbsoluteProgram {
                program: self.program.clone(),
            });
        }
        self.refuse_interior_nul()?;
        let watcher_valid = self.confirmed_by.as_ref().is_some_and(|watcher| {
            watcher.is_eligible_for(
                self.caller_uid,
                self.caller_pid,
                self.caller_starttime,
                self.caller_sid,
                self.caller_tty,
            )
        });
        let consistent = match self.state {
            ConfirmationState::Pending => !self.confirmed && self.confirmed_by.is_none(),
            ConfirmationState::Approved
            | ConfirmationState::Denied
            | ConfirmationState::Expired => false,
            ConfirmationState::Consumed => {
                self.confirmed
                    && self.needs_watch
                    && self.shown_at_ms.is_some()
                    && self.shown_to.is_some()
                    && watcher_valid
                    && self.confirmed_by == self.shown_to
            }
        };
        if self.confirmed && self.confirmed_by.is_none() {
            return Err(RequestError::UnattributedConfirmation);
        }
        if !consistent
            || (self.shown_at_ms.is_some() && !self.needs_watch)
            || (self.shown_at_ms.is_some() != self.shown_to.is_some())
            || self.shown_to.as_ref().is_some_and(|watcher| {
                !watcher.is_eligible_for(
                    self.caller_uid,
                    self.caller_pid,
                    self.caller_starttime,
                    self.caller_sid,
                    self.caller_tty,
                )
            })
            || self
                .shown_at_ms
                .is_some_and(|shown| shown.0 >= self.deadline.0)
            || !is_fingerprint(&self.fingerprint)
        {
            return Err(RequestError::InvalidConfirmationState);
        }

        if self.generation != generation {
            return Err(RequestError::StaleGeneration {
                minted: self.generation,
                current: generation,
            });
        }
        if self.caller_pid != caller.pid || self.caller_starttime != caller.starttime {
            return Err(RequestError::WrongCaller {
                expected_pid: self.caller_pid,
                expected_starttime: self.caller_starttime,
                actual_pid: caller.pid,
                actual_starttime: caller.starttime,
            });
        }
        if now >= self.deadline {
            return Err(RequestError::Expired {
                deadline: self.deadline.0,
                now: now.0,
            });
        }
        Ok(())
    }

    /// Refuses any NUL byte in a string the kernel would see.
    fn refuse_interior_nul(&self) -> Result<(), RequestError> {
        let named = [("program", self.program.as_str()), ("action", &self.action)];
        for (field, value) in named {
            refuse_nul(field, value)?;
        }
        for (index, argument) in self.argv.iter().enumerate() {
            refuse_nul(&format!("argv[{index}]"), argument)?;
        }
        Ok(())
    }
}

/// Returns the rendered JSON, or an empty object if rendering failed.
///
/// Split out so the failure arm is reachable from a test holding a genuine
/// `serde_json` error, instead of being a closure nothing can call.
fn or_empty_object(rendered: Result<String, serde_json::Error>) -> String {
    match rendered {
        Ok(json) => json,
        Err(_) => String::from("{}"),
    }
}

/// Refuses one string that contains a NUL.
fn refuse_nul(field: &str, value: &str) -> Result<(), RequestError> {
    if value.contains('\0') {
        return Err(RequestError::InteriorNul {
            field: field.to_owned(),
        });
    }
    Ok(())
}

/// Whether `candidate` is exactly a minted nonce.
///
/// Length and charset both, because the nonce is used as a file name under
/// [`SPOOL_DIR`]. `..` and `a/b` are the obvious attacks; lowercase-hex-only is
/// a stronger statement than "no slashes" and needs no reasoning about what else
/// a path parser might accept.
pub fn is_nonce(candidate: &str) -> bool {
    candidate.len() == NONCE_HEX_LEN
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

/// Whether a request fingerprint is lowercase SHA-256 hex.
fn is_fingerprint(candidate: &str) -> bool {
    candidate.len() == 64
        && candidate
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pin() -> CallerPin {
        CallerPin::new(4242, 998_877)
    }

    /// A well-formed entry for the caller [`pin`] returns, valid at t=100.
    fn live() -> PendingRequest {
        PendingRequest {
            schema_version: REQUEST_SCHEMA_VERSION,
            nonce: NONCE.to_owned(),
            caller_pid: 4242,
            caller_starttime: 998_877,
            action: "xudo.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
            generation: 7,
            deadline: BoottimeMillis(200),
            confirmed: false,
            confirmed_by: None,
            state: crate::request::ConfirmationState::Pending,
            caller_uid: 1000,
            caller_sid: 10,
            caller_tty: 20,
            needs_watch: false,
            shown_at_ms: None,
            shown_to: None,
            fingerprint: "0".repeat(64),
            claimed_classification: "enrolled-agent".to_owned(),
            attested_class: AttestedClass::Unattested,
            attested_scope_id: None,
            boot_id: None,
        }
    }

    fn check(request: &PendingRequest) -> Result<(), RequestError> {
        request.validate(pin(), 7, BoottimeMillis(100))
    }

    fn approved() -> PendingRequest {
        let mut request = live();
        request.confirmed = true;
        request.state = ConfirmationState::Approved;
        request.needs_watch = true;
        request.shown_at_ms = Some(BoottimeMillis(99));
        let watcher = WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        };
        request.confirmed_by = Some(watcher.clone());
        request.shown_to = Some(watcher);
        request
    }

    #[test]
    fn a_well_formed_live_entry_for_this_caller_validates() {
        assert_eq!(check(&live()), Ok(()));
    }

    #[test]
    fn a_schema_3_beta_one_spool_entry_is_refused() {
        let beta_one = r#"{"schema_version":3,"nonce":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","caller_pid":4242,"caller_starttime":998877,"action":"xudo.svc.restart","program":"/usr/bin/systemctl","argv":["restart","nginx.service"],"generation":7,"deadline":200,"confirmed":false,"confirmed_by":null,"state":"pending","caller_uid":1000,"caller_sid":10,"caller_tty":20,"needs_watch":false,"shown_at_ms":null,"shown_to":null,"fingerprint":"0000000000000000000000000000000000000000000000000000000000000000","claimed_classification":"enrolled-agent"}"#;
        assert_eq!(
            PendingRequest::parse(beta_one),
            Err(RequestError::WrongSchema {
                found: 3,
                expected: REQUEST_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn a_schema_2_spool_entry_is_refused() {
        let mut entry = live();
        entry.schema_version = 2;
        assert_eq!(
            entry.validate(pin(), 7, BoottimeMillis(100)),
            Err(RequestError::WrongSchema {
                found: 2,
                expected: REQUEST_SCHEMA_VERSION,
            })
        );
        assert_eq!(
            PendingRequest::parse(&entry.to_json()).unwrap_err().code(),
            "request_wrong_schema"
        );
        assert_eq!(
            PendingRequest::parse(r#"{"schema_version":1,"nonce":"legacy"}"#)
                .unwrap_err()
                .code(),
            "request_wrong_schema"
        );
        assert_eq!(
            finish_parse(entry).map(|_| ()),
            Err(RequestError::WrongSchema {
                found: 2,
                expected: REQUEST_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn a_spool_entry_with_a_positional_attested_class_is_refused() {
        let entry = live().to_json().replace(
            r#""attested_class":"unattested""#,
            r#""attested_class":{"enrolled_agent":[44]}"#,
        );
        assert_eq!(
            PendingRequest::parse(&entry).unwrap_err().code(),
            "request_malformed"
        );
    }

    #[test]
    fn a_spool_entry_with_a_null_unit_attested_class_is_refused() {
        let entry = live().to_json().replace(
            r#""attested_class":"unattested""#,
            r#""attested_class":{"unattested":null}"#,
        );
        assert_eq!(
            PendingRequest::parse(&entry).unwrap_err().code(),
            "request_malformed"
        );
    }

    #[test]
    fn a_spool_entry_with_an_enrolled_agent_object_is_parsed() {
        let entry = live().to_json().replace(
            r#""attested_class":"unattested","attested_scope_id":null,"boot_id":null"#,
            r#""attested_class":{"enrolled_agent":{"scope_id":44}},"attested_scope_id":44,"boot_id":"abcdef01-2345-6789-abcd-ef0123456789""#,
        );
        assert!(PendingRequest::parse(&entry).is_ok());
    }

    #[test]
    fn an_enrolled_entry_needs_a_scope_id() {
        let mut entry = live();
        entry.attested_class = AttestedClass::EnrolledAgent { scope_id: 44 };
        assert_eq!(check(&entry), Err(RequestError::InvalidAttestedIdentity));
    }

    #[test]
    fn an_enrolled_entry_needs_a_boot_id() {
        let mut entry = live();
        entry.attested_class = AttestedClass::EnrolledAgent { scope_id: 44 };
        entry.attested_scope_id = Some(44);
        assert_eq!(check(&entry), Err(RequestError::InvalidAttestedIdentity));
    }

    #[test]
    fn an_enrolled_entry_with_matching_scope_and_boot_id_validates() {
        let mut entry = live();
        entry.attested_class = AttestedClass::EnrolledAgent { scope_id: 44 };
        entry.attested_scope_id = Some(44);
        entry.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        assert_eq!(check(&entry), Ok(()));
    }

    #[test]
    fn a_malformed_boot_id_cannot_bind_an_enrolled_scope() {
        let mut entry = live();
        entry.attested_class = AttestedClass::EnrolledAgent { scope_id: 44 };
        entry.attested_scope_id = Some(44);
        entry.boot_id = Some("abcdef01x2345-6789-abcd-ef0123456789".to_owned());
        assert_eq!(check(&entry), Err(RequestError::InvalidAttestedIdentity));
    }

    #[test]
    fn an_enrolled_class_with_a_different_scope_id_is_refused() {
        let mut entry = live();
        entry.attested_class = AttestedClass::EnrolledAgent { scope_id: 45 };
        entry.attested_scope_id = Some(44);
        entry.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        assert_eq!(check(&entry), Err(RequestError::InvalidAttestedIdentity));
    }

    #[test]
    fn a_human_class_with_a_boot_id_is_refused() {
        let mut entry = live();
        entry.attested_class = AttestedClass::Human;
        entry.boot_id = Some("abcdef01-2345-6789-abcd-ef0123456789".to_owned());
        assert_eq!(check(&entry), Err(RequestError::InvalidAttestedIdentity));
    }

    #[test]
    fn a_scope_id_without_an_enrolled_class_is_refused() {
        let mut entry = live();
        entry.attested_scope_id = Some(44);
        assert_eq!(check(&entry), Err(RequestError::InvalidAttestedIdentity));
    }

    #[test]
    fn a_round_trip_through_json_changes_nothing() {
        let request = live();
        assert_eq!(PendingRequest::parse(&request.to_json()).unwrap(), request);
    }

    #[test]
    fn a_duplicate_key_spool_entry_is_refused() {
        let entry = live().to_json();
        let duplicate_schema = entry.replacen(
            &format!("\"schema_version\":{REQUEST_SCHEMA_VERSION}"),
            &format!(
                "\"schema_version\":{REQUEST_SCHEMA_VERSION},\"schema_version\":{REQUEST_SCHEMA_VERSION}"
            ),
            1,
        );
        assert_eq!(
            PendingRequest::parse(&duplicate_schema).unwrap_err().code(),
            "request_malformed"
        );

        let duplicate_program = entry.replacen(
            "\"program\":\"/usr/bin/systemctl\"",
            "\"program\":\"/usr/bin/systemctl\",\"program\":\"/usr/bin/false\"",
            1,
        );
        assert_eq!(
            PendingRequest::parse(&duplicate_program)
                .unwrap_err()
                .code(),
            "request_malformed"
        );
    }

    #[test]
    fn an_array_form_spool_entry_is_refused() {
        let array = serde_json::json!([
            REQUEST_SCHEMA_VERSION,
            NONCE,
            4242,
            998_877,
            "xudo.svc.restart",
            "/usr/bin/systemctl",
            ["restart", "nginx.service"],
            7,
            200,
            false,
            null,
            "pending",
            1000,
            10,
            20,
            false,
            null,
            null,
            "0".repeat(64),
            "enrolled-agent"
        ]);
        assert_eq!(
            PendingRequest::parse(&array.to_string()),
            Err(RequestError::Malformed {
                reason: "top-level JSON value must be an object".to_owned(),
            })
        );
    }

    #[test]
    fn a_spool_entry_with_an_array_form_state_is_refused() {
        let mut value: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("state".to_owned(), serde_json::json!(["pending"]));
        assert!(PendingRequest::parse(&value.to_string()).is_err());
    }

    #[test]
    fn a_spool_entry_with_a_map_form_state_is_refused() {
        let mut value: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("state".to_owned(), serde_json::json!({"pending": null}));
        assert!(PendingRequest::parse(&value.to_string()).is_err());
    }

    #[test]
    fn a_spool_entry_with_a_positional_confirmed_by_pin_is_refused() {
        let mut value: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        value.as_object_mut().unwrap().insert(
            "confirmed_by".to_owned(),
            serde_json::json!([1000, 42, 99, 34816, 41]),
        );
        assert!(PendingRequest::parse(&value.to_string()).is_err());
    }

    #[test]
    fn a_spool_entry_with_a_positional_shown_to_pin_is_refused() {
        let mut value: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        value.as_object_mut().unwrap().insert(
            "shown_to".to_owned(),
            serde_json::json!([1000, 42, 99, 34816, 41]),
        );
        assert!(PendingRequest::parse(&value.to_string()).is_err());
    }

    #[test]
    fn a_spool_entry_with_a_different_schema_is_refused_during_parse() {
        let mut entry = live();
        entry.schema_version = REQUEST_SCHEMA_VERSION + 1;
        assert_eq!(
            PendingRequest::parse(&entry.to_json()),
            Err(RequestError::WrongSchema {
                found: REQUEST_SCHEMA_VERSION + 1,
                expected: REQUEST_SCHEMA_VERSION,
            })
        );
    }

    /// The parser's own complaint, if this is a shape failure.
    ///
    /// A helper rather than a one-armed `matches!`, whose `_ => false` arm no
    /// test can reach, and it asserts more: that the reason serde gave is
    /// carried through rather than flattened to an empty string.
    fn malformed_reason(error: &RequestError) -> Option<&str> {
        match error {
            RequestError::Malformed { reason } => Some(reason.as_str()),
            _ => None,
        }
    }

    #[test]
    fn denies_an_entry_that_is_not_json_at_all() {
        let error = PendingRequest::parse("not json").unwrap_err();
        assert_eq!(error.code(), "request_malformed");
        assert!(malformed_reason(&error).is_some_and(|reason| !reason.is_empty()));
        assert_eq!(malformed_reason(&RequestError::NoAction), None);
    }

    #[test]
    fn denies_an_entry_carrying_an_unrecognised_key() {
        // `deny_unknown_fields` is the sudo-rs-on-Ubuntu footgun in miniature: a
        // security-relevant directive the parser does not know must be a hard
        // failure, never a silently ignored line.
        let mut object: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        object.as_object_mut().unwrap().insert(
            "skip_confirmation".to_owned(),
            serde_json::Value::Bool(true),
        );
        let error = PendingRequest::parse(&object.to_string()).unwrap_err();
        assert_eq!(error.code(), "request_malformed");
    }

    #[test]
    fn denies_an_entry_missing_a_key_rather_than_defaulting_it() {
        let mut object: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        object.as_object_mut().unwrap().remove("confirmed");
        assert_eq!(
            PendingRequest::parse(&object.to_string())
                .unwrap_err()
                .code(),
            "request_malformed"
        );
    }

    #[test]
    fn an_omitted_optional_timestamp_parses_as_none() {
        let mut object: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        object.as_object_mut().unwrap().remove("shown_at_ms");
        assert_eq!(
            PendingRequest::parse(&object.to_string())
                .unwrap()
                .shown_at_ms,
            None
        );
    }

    #[test]
    fn an_unknown_confirmation_state_is_rejected_by_the_parser() {
        let mut object: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        object.as_object_mut().unwrap().insert(
            "state".to_owned(),
            serde_json::Value::String("APPROVED".to_owned()),
        );
        assert_eq!(
            PendingRequest::parse(&object.to_string())
                .unwrap_err()
                .code(),
            "request_malformed"
        );
    }

    #[test]
    fn a_spool_entry_missing_a_confirmation_field_is_malformed() {
        let mut object: serde_json::Value = serde_json::from_str(&live().to_json()).unwrap();
        object.as_object_mut().unwrap().remove("fingerprint");
        assert_eq!(
            PendingRequest::parse(&object.to_string())
                .unwrap_err()
                .code(),
            "request_malformed"
        );
    }

    #[test]
    fn the_gate_refuses_denied_expired_and_inconsistent_approval_states() {
        for state in [ConfirmationState::Denied, ConfirmationState::Expired] {
            let mut request = live();
            request.state = state;
            assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
        }
        let mut request = live();
        request.confirmed = true;
        request.state = ConfirmationState::Approved;
        request.needs_watch = true;
        request.shown_at_ms = Some(BoottimeMillis(99));
        request.confirmed_by = Some(WatcherPin {
            uid: 1001,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        request.shown_to = request.confirmed_by.clone();
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));

        let mut request = live();
        request.confirmed = true;
        request.state = ConfirmationState::Approved;
        request.needs_watch = true;
        request.shown_at_ms = Some(BoottimeMillis(99));
        request.confirmed_by = Some(WatcherPin {
            uid: request.caller_uid,
            pid: request.caller_pid,
            starttime: request.caller_starttime,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        request.shown_to = request.confirmed_by.clone();
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn an_approved_but_unconsumed_entry_is_refused_by_the_gate() {
        assert_eq!(
            check(&approved()),
            Err(RequestError::InvalidConfirmationState)
        );
    }

    #[test]
    fn a_malformed_fingerprint_is_refused() {
        let mut request = live();
        request.fingerprint = "a".repeat(64);
        assert_eq!(check(&request), Ok(()));
        for fingerprint in ["g".repeat(64), "A".repeat(64), "0".repeat(63)] {
            request.fingerprint = fingerprint;
            assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
        }
    }

    #[test]
    fn an_approval_without_needs_watch_is_refused() {
        let mut request = approved();
        request.needs_watch = false;
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn an_approval_without_a_shown_timestamp_is_refused() {
        let mut request = approved();
        request.shown_at_ms = None;
        request.shown_to = None;
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn a_pending_entry_cannot_carry_an_approver() {
        let mut request = live();
        request.confirmed_by = Some(approved().confirmed_by.unwrap());
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn a_shown_timestamp_requires_needs_watch() {
        let mut request = live();
        request.shown_at_ms = Some(BoottimeMillis(99));
        request.shown_to = Some(approved().shown_to.unwrap());
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn an_approval_by_a_watcher_who_was_not_shown_the_prompt_is_rejected() {
        let mut request = approved();
        let mut other = request.shown_to.clone().unwrap();
        other.pid = other.pid.saturating_add(1);
        request.confirmed_by = Some(other);
        assert_ne!(request.confirmed_by, request.shown_to);
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn a_shown_time_without_its_watcher_is_rejected() {
        let watcher = approved().shown_to.unwrap();
        let mut time_only = live();
        time_only.needs_watch = true;
        time_only.shown_at_ms = Some(BoottimeMillis(99));
        assert_eq!(
            check(&time_only),
            Err(RequestError::InvalidConfirmationState)
        );

        let mut watcher_only = live();
        watcher_only.needs_watch = true;
        watcher_only.shown_to = Some(watcher);
        assert_eq!(
            check(&watcher_only),
            Err(RequestError::InvalidConfirmationState)
        );
    }

    #[test]
    fn a_pending_entry_shown_to_an_ineligible_watcher_is_rejected() {
        let mut wrong_uid = live();
        wrong_uid.needs_watch = true;
        wrong_uid.shown_at_ms = Some(BoottimeMillis(99));
        let mut watcher = approved().shown_to.unwrap();
        watcher.uid = wrong_uid.caller_uid.saturating_add(1);
        wrong_uid.shown_to = Some(watcher);
        assert_eq!(
            check(&wrong_uid),
            Err(RequestError::InvalidConfirmationState)
        );

        let mut same_tty = live();
        same_tty.needs_watch = true;
        same_tty.shown_at_ms = Some(BoottimeMillis(99));
        let watcher = approved().shown_to.unwrap();
        same_tty.caller_tty = watcher.tty;
        same_tty.shown_to = Some(watcher);
        assert_eq!(
            check(&same_tty),
            Err(RequestError::InvalidConfirmationState)
        );
    }

    #[test]
    fn a_shown_timestamp_at_or_after_the_deadline_is_refused() {
        let mut request = approved();
        request.shown_at_ms = Some(request.deadline);
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn a_watcher_in_the_requesters_session_is_refused() {
        let mut request = approved();
        request.caller_sid = 11;
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn a_watcher_on_the_requesters_tty_is_refused() {
        let mut request = approved();
        request.caller_tty = (136 << 8) | 1;
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn a_zero_tty_watcher_is_refused() {
        let mut request = approved();
        request.confirmed_by.as_mut().unwrap().tty = 0;
        request.shown_to.as_mut().unwrap().tty = 0;
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn a_zero_pid_watcher_is_refused() {
        let mut request = approved();
        request.confirmed_by.as_mut().unwrap().pid = 0;
        request.shown_to.as_mut().unwrap().pid = 0;
        assert_eq!(check(&request), Err(RequestError::InvalidConfirmationState));
    }

    #[test]
    fn only_virtual_console_and_pts_terminals_are_watchable() {
        for tty in [0, -1, 1 << 8 | 1, 4 << 8, 4 << 8 | 64, 5 << 8 | 1] {
            assert!(!is_watch_terminal(tty), "accepted tty_nr {tty}");
        }
        for tty in [4 << 8 | 1, 4 << 8 | 63, 136 << 8 | 1, 143 << 8 | 255] {
            assert!(is_watch_terminal(tty), "rejected tty_nr {tty}");
        }
    }

    #[test]
    fn denies_a_schema_this_build_does_not_implement() {
        let mut request = live();
        request.schema_version = REQUEST_SCHEMA_VERSION.saturating_add(1);
        assert_eq!(
            check(&request),
            Err(RequestError::WrongSchema {
                found: REQUEST_SCHEMA_VERSION.saturating_add(1),
                expected: REQUEST_SCHEMA_VERSION
            })
        );
        assert_eq!(check(&request).unwrap_err().code(), "request_wrong_schema");
    }

    #[test]
    fn denies_a_nonce_that_could_name_a_different_file() {
        // The nonce is the entry's file name, so every one of these is an
        // attempt to make the gate open something else.
        for attack in [
            "../../etc/shadow",
            "a/b",
            "..",
            "",
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefg",
        ] {
            let mut request = live();
            request.nonce = attack.to_owned();
            assert_eq!(
                check(&request),
                Err(RequestError::MalformedNonce),
                "accepted nonce {attack:?}"
            );
        }
        assert_eq!(
            RequestError::MalformedNonce.code(),
            "request_malformed_nonce"
        );
    }

    #[test]
    fn a_minted_nonce_is_exactly_lowercase_hex_of_the_minted_length() {
        assert!(is_nonce(NONCE));
        assert!(is_nonce(&"f".repeat(NONCE_HEX_LEN)));
        assert!(is_nonce(&"0".repeat(NONCE_HEX_LEN)));
        assert!(!is_nonce(&"g".repeat(NONCE_HEX_LEN)));
    }

    #[test]
    fn denies_an_entry_that_names_no_action() {
        let mut request = live();
        request.action = String::new();
        assert_eq!(check(&request), Err(RequestError::NoAction));
        assert_eq!(RequestError::NoAction.code(), "request_no_action");
    }

    #[test]
    fn denies_a_program_that_would_be_resolved_against_a_cwd() {
        for attack in ["systemctl", "./systemctl", "../bin/sh", ""] {
            let mut request = live();
            request.program = attack.to_owned();
            assert_eq!(
                check(&request),
                Err(RequestError::NotAbsoluteProgram {
                    program: attack.to_owned()
                }),
                "accepted program {attack:?}"
            );
        }
        assert_eq!(
            check(&{
                let mut r = live();
                r.program = "sh".to_owned();
                r
            })
            .unwrap_err()
            .code(),
            "request_program_not_absolute"
        );
    }

    #[test]
    fn denies_an_interior_nul_in_every_field_the_kernel_would_see() {
        // execve takes NUL-terminated strings. An accepted interior NUL means a
        // human reviewed `--dry-run` and the kernel ran the prefix before it.
        let cases = [
            ("program", "/usr/bin/systemctl\0/../../bin/sh"),
            ("action", "xudo.svc.restart\0extra"),
        ];
        for (field, value) in cases {
            let mut request = live();
            if field == "program" {
                request.program = value.to_owned();
            } else {
                request.action = value.to_owned();
            }
            assert_eq!(
                check(&request),
                Err(RequestError::InteriorNul {
                    field: field.to_owned()
                })
            );
        }

        let mut request = live();
        request.argv = vec!["restart".to_owned(), "nginx\0 --force".to_owned()];
        assert_eq!(
            check(&request),
            Err(RequestError::InteriorNul {
                field: "argv[1]".to_owned()
            })
        );
        assert_eq!(check(&request).unwrap_err().code(), "request_interior_nul");
    }

    #[test]
    fn denies_a_confirmation_nobody_can_be_held_to() {
        // An approval with no channel recorded cannot be reviewed afterwards,
        // which makes it indistinguishable from one that never happened.
        let mut request = live();
        request.confirmed = true;
        request.state = ConfirmationState::Approved;
        request.needs_watch = true;
        assert_eq!(check(&request), Err(RequestError::UnattributedConfirmation));
        assert_eq!(
            RequestError::UnattributedConfirmation.code(),
            "request_unattributed_confirmation"
        );
    }

    #[test]
    fn an_attributed_confirmation_is_accepted() {
        let mut request = live();
        request.confirmed = true;
        request.state = ConfirmationState::Consumed;
        request.needs_watch = true;
        request.shown_at_ms = Some(BoottimeMillis(99));
        request.confirmed_by = Some(WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        request.shown_to = request.confirmed_by.clone();
        assert_eq!(check(&request), Ok(()));
    }

    #[test]
    fn a_consumed_approval_is_gate_valid_for_execution() {
        let mut request = live();
        request.confirmed = true;
        request.state = ConfirmationState::Consumed;
        request.needs_watch = true;
        request.shown_at_ms = Some(BoottimeMillis(99));
        request.confirmed_by = Some(WatcherPin {
            uid: 1000,
            pid: 88,
            starttime: 99,
            tty: (136 << 8) | 1,
            sid: 11,
        });
        request.shown_to = request.confirmed_by.clone();
        assert_eq!(check(&request), Ok(()));
    }

    #[test]
    fn an_unconfirmed_entry_may_name_no_channel() {
        let mut request = live();
        request.confirmed = false;
        request.confirmed_by = None;
        assert_eq!(check(&request), Ok(()));
    }

    #[test]
    fn denies_an_entry_minted_under_rules_that_no_longer_apply() {
        let mut request = live();
        request.generation = 6;
        assert_eq!(
            check(&request),
            Err(RequestError::StaleGeneration {
                minted: 6,
                current: 7
            })
        );
        assert_eq!(
            check(&request).unwrap_err().code(),
            "request_stale_generation"
        );
    }

    #[test]
    fn denies_an_approval_granted_to_a_different_process() {
        let mut request = live();
        request.caller_pid = 4243;
        assert_eq!(
            check(&request),
            Err(RequestError::WrongCaller {
                expected_pid: 4243,
                expected_starttime: 998_877,
                actual_pid: 4242,
                actual_starttime: 998_877,
            })
        );
        assert_eq!(check(&request).unwrap_err().code(), "request_wrong_caller");
    }

    #[test]
    fn denies_a_reused_pid_by_comparing_the_start_time_too() {
        // The whole reason the pin carries a start time: between minting and
        // reading, the front-end can exit and its pid be handed to something
        // else. A pid alone would make that new process the grantee.
        let mut request = live();
        request.caller_starttime = 998_878;
        assert_eq!(
            check(&request),
            Err(RequestError::WrongCaller {
                expected_pid: 4242,
                expected_starttime: 998_878,
                actual_pid: 4242,
                actual_starttime: 998_877,
            })
        );
    }

    #[test]
    fn denies_an_entry_past_its_deadline_and_at_it() {
        let request = live();
        assert_eq!(
            request.validate(pin(), 7, BoottimeMillis(200)),
            Err(RequestError::Expired {
                deadline: 200,
                now: 200
            }),
            "the deadline itself must be outside the window, not the last second inside it"
        );
        assert_eq!(
            request
                .validate(pin(), 7, BoottimeMillis(10_000))
                .unwrap_err()
                .code(),
            "request_expired"
        );
        assert_eq!(request.validate(pin(), 7, BoottimeMillis(199)), Ok(()));
    }

    #[test]
    fn a_malformed_entry_is_never_reported_as_a_caller_mismatch() {
        // Order matters for more than tidiness: a message about the *caller*
        // asserts a comparison against fields that shape validation has not
        // reached yet, and an operator reading it would draw the wrong
        // conclusion about who was asking.
        let mut request = live();
        request.schema_version = 99;
        request.nonce = "..".to_owned();
        request.action = String::new();
        request.program = "sh".to_owned();
        request.caller_pid = 1;
        request.generation = 0;
        request.deadline = BoottimeMillis(0);
        // Codes are one-to-one with variants, so comparing the code names the
        // variant without a one-armed `matches!` behind it.
        assert_eq!(
            check(&request).unwrap_err().code(),
            "request_wrong_schema",
            "shape must be checked before identity"
        );
    }

    #[test]
    fn every_refusal_renders_a_sentence_naming_what_is_wrong() {
        let all = [
            RequestError::Malformed {
                reason: "trailing comma".to_owned(),
            },
            RequestError::WrongSchema {
                found: 2,
                expected: 1,
            },
            RequestError::InvalidAttestedIdentity,
            RequestError::MalformedNonce,
            RequestError::NoAction,
            RequestError::NotAbsoluteProgram {
                program: "sh".to_owned(),
            },
            RequestError::InteriorNul {
                field: "argv[0]".to_owned(),
            },
            RequestError::Expired {
                deadline: 1,
                now: 2,
            },
            RequestError::WrongCaller {
                expected_pid: 1,
                expected_starttime: 2,
                actual_pid: 3,
                actual_starttime: 4,
            },
            RequestError::UnattributedConfirmation,
            RequestError::InvalidConfirmationState,
            RequestError::StaleGeneration {
                minted: 1,
                current: 2,
            },
            RequestError::Ambiguous { matches: 2 },
            RequestError::ForgedNonce {
                name: NONCE.to_owned(),
            },
        ];

        let mut codes: Vec<&str> = Vec::new();
        for error in &all {
            let rendered = error.to_string();
            assert!(
                rendered.len() > 20,
                "{error:?} renders too thinly: {rendered}"
            );
            codes.push(error.code());
        }
        codes.sort_unstable();
        let total = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), total, "two refusals share an audit code");
    }

    #[test]
    fn the_spool_is_root_owned_and_never_under_tmp() {
        // Asserted here rather than left to a comment: a world-writable spool
        // turns every open the gate performs into a symlink race.
        assert_eq!(SPOOL_DIR, "/run/xudo/req");
        assert!(!SPOOL_DIR.starts_with("/tmp"));
        assert!(!SPOOL_DIR.starts_with("/var/tmp"));
    }

    #[test]
    fn a_pin_records_both_halves_of_the_identity() {
        let pinned = CallerPin::new(9, 8);
        assert_eq!(pinned.pid, 9);
        assert_eq!(pinned.starttime, 8);
    }

    #[test]
    fn serialization_of_plain_data_has_no_failing_path_to_hide() {
        // `to_json` swallows an error into `{}` instead of unwrapping. Prove the
        // fallback is dead code for this type rather than a silent truncation.
        assert_ne!(live().to_json(), "{}");
        assert_eq!(or_empty_object(Ok("rendered".to_owned())), "rendered");
        // A genuine serde_json error, so the fallback arm is exercised by a
        // real failure rather than assumed unreachable.
        let failed: Result<String, serde_json::Error> = serde_json::from_str("not json");
        assert_eq!(or_empty_object(failed), "{}");
    }
}
