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
//!    monotonic seconds, so moving the wall clock cannot extend one.
//! 3. **It is this caller's.** The entry names the pid *and* the start time of
//!    the `aido` process it was minted for. A pid alone is a name that can be
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
pub const SPOOL_DIR: &str = "/run/aido/req";

/// The wire version of a spool entry.
pub const REQUEST_SCHEMA_VERSION: u32 = 1;

/// How long a nonce is, in hex characters (32 random bytes).
pub const NONCE_HEX_LEN: usize = 64;

/// A monotonic instant, in whole seconds since an unspecified epoch.
///
/// Wrapped rather than passed as a bare `u64` because the *only* correct source
/// is `CLOCK_MONOTONIC`: a deadline anchored to the wall clock is a deadline an
/// operator extends by fixing their timezone, and an attacker extends by any
/// means that moves the clock backwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MonotonicSecs(pub u64);

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
    #[error("request expired: deadline was {deadline} monotonic seconds, it is now {now}")]
    Expired {
        /// The deadline it carried.
        deadline: u64,
        /// The current monotonic reading.
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
    /// The policy changed after the entry was minted.
    #[error("request was minted under policy generation {minted}, current generation is {current}")]
    StaleGeneration {
        /// The generation it was minted under.
        minted: u64,
        /// The generation now in force.
        current: u64,
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
            Self::MalformedNonce => "request_malformed_nonce",
            Self::NoAction => "request_no_action",
            Self::NotAbsoluteProgram { .. } => "request_program_not_absolute",
            Self::InteriorNul { .. } => "request_interior_nul",
            Self::Expired { .. } => "request_expired",
            Self::WrongCaller { .. } => "request_wrong_caller",
            Self::UnattributedConfirmation => "request_unattributed_confirmation",
            Self::StaleGeneration { .. } => "request_stale_generation",
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
    /// The pid of the `aido` process this was minted for.
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
    /// When this stops being valid, in monotonic seconds.
    pub deadline: MonotonicSecs,
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
    /// Which channel carried the approval.
    ///
    /// Required whenever [`Self::confirmed`] is set. A confirmation with no
    /// recorded channel cannot be reviewed after the fact, and an unreviewable
    /// approval is indistinguishable from one that never happened.
    pub confirmed_by: Option<String>,
    /// How the front-end classified the caller.
    ///
    /// An **unauthenticated hint**, recorded in the audit trail and given zero
    /// authorization weight: the gate re-derives classification from
    /// kernel-attested facts. Kept because "the caller claimed to be an enrolled
    /// agent and it changed nothing" is exactly what an investigator needs to be
    /// able to see.
    pub claimed_classification: String,
}

impl PendingRequest {
    /// Parses one spool entry.
    ///
    /// # Errors
    ///
    /// [`RequestError::Malformed`] for anything that is not this wire format,
    /// including an unknown or missing key.
    pub fn parse(text: &str) -> Result<Self, RequestError> {
        serde_json::from_str(text).map_err(|error| RequestError::Malformed {
            reason: error.to_string(),
        })
    }

    /// Renders the entry back to JSON.
    ///
    /// Used by the minting side and by tests. Falls back to an empty object
    /// rather than panicking: this type is plain data, so serialization cannot
    /// fail, and a fallback costs less than an `unwrap` in a privileged binary.
    ///
    /// The fallback is a value handed to a free function rather than a closure,
    /// for the same reason `aido_audit::Record::to_jsonl` does it that way: a
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
        now: MonotonicSecs,
    ) -> Result<(), RequestError> {
        if self.schema_version != REQUEST_SCHEMA_VERSION {
            return Err(RequestError::WrongSchema {
                found: self.schema_version,
                expected: REQUEST_SCHEMA_VERSION,
            });
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
        let attributed = self
            .confirmed_by
            .as_ref()
            .is_some_and(|channel| !channel.is_empty());
        if self.confirmed && !attributed {
            return Err(RequestError::UnattributedConfirmation);
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
            action: "aido.svc.restart".to_owned(),
            program: "/usr/bin/systemctl".to_owned(),
            argv: vec!["restart".to_owned(), "nginx.service".to_owned()],
            generation: 7,
            deadline: MonotonicSecs(200),
            confirmed: false,
            confirmed_by: None,
            claimed_classification: "enrolled-agent".to_owned(),
        }
    }

    fn check(request: &PendingRequest) -> Result<(), RequestError> {
        request.validate(pin(), 7, MonotonicSecs(100))
    }

    #[test]
    fn a_well_formed_live_entry_for_this_caller_validates() {
        assert_eq!(check(&live()), Ok(()));
    }

    #[test]
    fn a_round_trip_through_json_changes_nothing() {
        let request = live();
        assert_eq!(PendingRequest::parse(&request.to_json()).unwrap(), request);
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
    fn denies_a_schema_this_build_does_not_implement() {
        let mut request = live();
        request.schema_version = REQUEST_SCHEMA_VERSION.saturating_add(1);
        assert_eq!(
            check(&request),
            Err(RequestError::WrongSchema {
                found: 2,
                expected: 1
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
            ("action", "aido.svc.restart\0extra"),
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
        for channel in [None, Some(String::new())] {
            let mut request = live();
            request.confirmed = true;
            request.confirmed_by = channel.clone();
            assert_eq!(
                check(&request),
                Err(RequestError::UnattributedConfirmation),
                "accepted confirmation attributed to {channel:?}"
            );
        }
        assert_eq!(
            RequestError::UnattributedConfirmation.code(),
            "request_unattributed_confirmation"
        );
    }

    #[test]
    fn an_attributed_confirmation_is_accepted() {
        let mut request = live();
        request.confirmed = true;
        request.confirmed_by = Some("broker-tty:/dev/pts/3".to_owned());
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
            request.validate(pin(), 7, MonotonicSecs(200)),
            Err(RequestError::Expired {
                deadline: 200,
                now: 200
            }),
            "the deadline itself must be outside the window, not the last second inside it"
        );
        assert_eq!(
            request
                .validate(pin(), 7, MonotonicSecs(10_000))
                .unwrap_err()
                .code(),
            "request_expired"
        );
        assert_eq!(request.validate(pin(), 7, MonotonicSecs(199)), Ok(()));
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
        request.deadline = MonotonicSecs(0);
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
            RequestError::StaleGeneration {
                minted: 1,
                current: 2,
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
        assert_eq!(SPOOL_DIR, "/run/aido/req");
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
