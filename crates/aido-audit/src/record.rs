//! What one audit record contains.
//!
//! Shaped by one question: six months from now, with the machine in front of
//! you, can you reconstruct what happened and why? So every record carries the
//! decision, the rule that produced it, the canonical argv, the caller's
//! classification **and the evidence for it**, and the version of the deny-list
//! that ran.

use serde::{Deserialize, Serialize};

/// Schema version of a record.
///
/// Bump on any change to the serialized shape, so a reader can refuse a record
/// it does not understand rather than misread one.
pub const RECORD_SCHEMA_VERSION: u32 = 1;

/// A monotonic position in the chain.
///
/// Starts at 1, so a zero is always a bug rather than an ambiguous first entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sequence(u64);

impl Sequence {
    /// The first position in a chain.
    pub fn first() -> Self {
        Self(1)
    }

    /// The position after this one.
    ///
    /// Saturating rather than wrapping: a chain that wrapped to zero would
    /// silently look like a fresh log, which is exactly the confusion a
    /// tamper-evident record exists to prevent. At one record per microsecond
    /// this saturates in about half a million years.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// The raw position.
    pub fn get(self) -> u64 {
        self.0
    }
}

/// What the policy engine decided.
///
/// Deliberately a separate, smaller enum than `aido_policy::Verdict`: an audit
/// record is a wire format that must stay readable across versions, and coupling
/// it to an internal type means an internal refactor silently changes the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Permitted outright.
    Allowed,
    /// Permitted once a human approves.
    AwaitingConfirmation,
    /// Refused.
    Denied,
}

/// What actually happened afterwards.
///
/// Separate from [`Decision`] because they answer different questions and
/// conflating them loses the interesting case: a request that was *allowed* and
/// then failed to run is not the same event as one that was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Nothing was executed. The only outcome this release can produce.
    NotExecuted,
    /// A child ran and exited with this status.
    Exited {
        /// Its exit code.
        code: i32,
    },
    /// A child ran and was killed by a signal.
    Signalled {
        /// The signal number.
        signal: i32,
    },
    /// Execution was attempted and could not start.
    Failed {
        /// Why.
        reason: String,
    },
}

impl Outcome {
    /// Whether this outcome means a privileged command actually ran.
    ///
    /// Used by `aido audit query` to answer "what has actually executed on this
    /// machine", which is a different and more urgent question than "what was
    /// permitted".
    pub fn executed(&self) -> bool {
        matches!(self, Self::Exited { .. } | Self::Signalled { .. })
    }
}

/// One audit record, before it is chained.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Schema version.
    pub schema_version: u32,
    /// Position in the chain.
    pub seq: Sequence,
    /// Hash of the previous record, hex-encoded. Empty for the first.
    pub prev_hash: String,
    /// Hash of this record's content, hex-encoded.
    pub hash: String,
    /// What was decided.
    pub decision: Decision,
    /// The stable denial code, when refused.
    pub denial: Option<String>,
    /// The action that matched, when one did.
    pub action: Option<String>,
    /// Where the matching rule lives, as `file:line`.
    pub rule_source: Option<String>,
    /// The canonical argv the decision was made about.
    pub argv: Vec<String>,
    /// How the caller was classified.
    pub classification: String,
    /// The evidence for that classification.
    ///
    /// Recorded because a classification without its evidence is unreviewable:
    /// an investigator needs to see that the caller *claimed* to be an agent and
    /// that the claim carried no weight.
    pub evidence: Vec<String>,
    /// Version of the compiled-in deny-list that ran.
    ///
    /// So a decision can be replayed against the exact list that produced it.
    pub deny_list_version: u32,
    /// What happened after the decision.
    pub outcome: Outcome,
}

impl Record {
    /// Builds the first record of a chain.
    pub fn first(decision: Decision, argv: Vec<String>, classification: impl Into<String>) -> Self {
        Self::after(None, decision, argv, classification)
    }

    /// Builds a record following `previous`.
    ///
    /// The hash covers every field except `hash` itself, so a change to any of
    /// them breaks the chain from here onward.
    pub fn after(
        previous: Option<&Self>,
        decision: Decision,
        argv: Vec<String>,
        classification: impl Into<String>,
    ) -> Self {
        let mut record = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            seq: previous.map_or_else(Sequence::first, |p| p.seq.next()),
            prev_hash: previous.map(|p| p.hash.clone()).unwrap_or_default(),
            hash: String::new(),
            decision,
            denial: None,
            action: None,
            rule_source: None,
            argv,
            classification: classification.into(),
            evidence: Vec::new(),
            deny_list_version: 0,
            outcome: Outcome::NotExecuted,
        };
        record.hash = record.content_hash();
        record
    }

    /// Records why a request was refused.
    #[must_use]
    pub fn with_denial(mut self, code: impl Into<String>) -> Self {
        self.denial = Some(code.into());
        self.reseal()
    }

    /// Records the rule that matched.
    #[must_use]
    pub fn with_rule(mut self, action: impl Into<String>, source: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self.rule_source = Some(source.into());
        self.reseal()
    }

    /// Records the unauthenticated claims the caller made.
    #[must_use]
    pub fn with_evidence(mut self, evidence: Vec<String>) -> Self {
        self.evidence = evidence;
        self.reseal()
    }

    /// Records which deny-list ran.
    #[must_use]
    pub fn with_deny_list_version(mut self, version: u32) -> Self {
        self.deny_list_version = version;
        self.reseal()
    }

    /// Records what happened after the decision.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.outcome = outcome;
        self.reseal()
    }

    /// Recomputes the hash after a field changed.
    ///
    /// Every builder method calls this, so a record is never left with a hash
    /// that does not cover its own contents. A stale hash would not be caught by
    /// verification — it would be *consistent*, and wrong.
    fn reseal(mut self) -> Self {
        self.hash = self.content_hash();
        self
    }

    /// The hash over everything except the hash field.
    ///
    /// Fields are fed in a fixed order with length prefixes, so two different
    /// records cannot produce the same digest by moving text across a boundary —
    /// the classic concatenation ambiguity, where `("ab", "c")` and `("a", "bc")`
    /// hash alike.
    pub fn content_hash(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        let mut field = |bytes: &[u8]| {
            hasher.update(bytes.len().to_le_bytes());
            hasher.update(bytes);
        };

        field(&self.schema_version.to_le_bytes());
        field(&self.seq.get().to_le_bytes());
        field(self.prev_hash.as_bytes());
        field(format!("{:?}", self.decision).as_bytes());
        field(self.denial.as_deref().unwrap_or_default().as_bytes());
        field(self.action.as_deref().unwrap_or_default().as_bytes());
        field(self.rule_source.as_deref().unwrap_or_default().as_bytes());
        field(&self.argv.len().to_le_bytes());
        for arg in &self.argv {
            field(arg.as_bytes());
        }
        field(self.classification.as_bytes());
        field(&self.evidence.len().to_le_bytes());
        for item in &self.evidence {
            field(item.as_bytes());
        }
        field(&self.deny_list_version.to_le_bytes());
        field(format!("{:?}", self.outcome).as_bytes());

        format!("{:x}", hasher.finalize())
    }

    /// Whether this record's hash still covers its contents.
    pub fn is_sealed(&self) -> bool {
        self.hash == self.content_hash()
    }

    /// Renders the record as one JSON line, for an append-only log.
    ///
    /// Infallible. A record is plain data — strings, enums, integers — so
    /// `serde_json` has no failure mode on it, and an audit log is the last place
    /// to introduce one: a writer that can refuse to render loses the record it
    /// was about to write. If serialization ever did fail, this emits a
    /// self-describing line that still carries the sequence and hash, so the
    /// chain remains verifiable across the gap.
    pub fn to_jsonl(&self) -> String {
        // The fallback is computed eagerly and handed over as a value rather
        // than a closure. It costs one `format!` per record, and it means this
        // function has no branch at all — a lazily-built fallback leaves an
        // arm that only a broken serializer could reach, and therefore one no
        // test can exercise.
        or_fallback(serde_json::to_string(self), self.unrenderable_line())
    }

    /// The line emitted if this record could not be serialized.
    ///
    ///
    /// Hand-built from the two fields a verifier needs, so a gap is visible and
    /// the chain is still checkable rather than simply broken.
    fn unrenderable_line(&self) -> String {
        format!(
            "{{\"schema_version\":{},\"seq\":{},\"hash\":\"{}\",\"unrenderable\":true}}",
            self.schema_version,
            self.seq.get(),
            self.hash
        )
    }
}

/// Returns the rendered line, or the fallback if rendering failed.
fn or_fallback(rendered: Result<String, serde_json::Error>, fallback: String) -> String {
    rendered.unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;

    fn first() -> Record {
        Record::first(
            Decision::Allowed,
            vec!["restart".to_owned(), "nginx.service".to_owned()],
            "unattested",
        )
    }

    #[test]
    fn a_sequence_starts_at_one_so_zero_is_always_a_bug() {
        assert_eq!(Sequence::first().get(), 1);
        assert_eq!(Sequence::first().next().get(), 2);
        assert!(Sequence::first() < Sequence::first().next());
        assert!(format!("{:?}", Sequence::first()).contains('1'));
    }

    #[test]
    fn a_sequence_saturates_rather_than_wrapping_to_zero() {
        // A wrapped chain would look like a fresh log, which is the exact
        // confusion a tamper-evident record exists to prevent.
        let huge = Sequence(u64::MAX);
        assert_eq!(huge.next().get(), u64::MAX);
    }

    #[test]
    fn the_first_record_has_no_predecessor_and_seals_itself() {
        let record = first();
        assert_eq!(record.seq, Sequence::first());
        assert!(record.prev_hash.is_empty());
        assert!(!record.hash.is_empty());
        assert!(record.is_sealed());
        assert_eq!(record.schema_version, RECORD_SCHEMA_VERSION);
        // Nothing ran, and this release cannot make anything run.
        assert_eq!(record.outcome, Outcome::NotExecuted);
        assert!(!record.outcome.executed());
    }

    #[test]
    fn a_following_record_carries_its_predecessors_hash() {
        let a = first();
        let b = Record::after(Some(&a), Decision::Denied, vec!["x".to_owned()], "human");
        assert_eq!(b.seq.get(), 2);
        assert_eq!(b.prev_hash, a.hash);
        assert_ne!(b.hash, a.hash);
        assert!(b.is_sealed());
    }

    #[test]
    fn every_builder_reseals_so_a_hash_never_goes_stale() {
        // A stale hash would not be caught by verification — it would be
        // consistent, and wrong.
        let record = first()
            .with_denial("deny_listed")
            .with_rule("aido.svc.restart", "20-services.toml:15")
            .with_evidence(vec!["CLAUDECODE=1".to_owned()])
            .with_deny_list_version(1)
            .with_outcome(Outcome::Exited { code: 0 });
        assert!(record.is_sealed());
        assert_eq!(record.denial.as_deref(), Some("deny_listed"));
        assert_eq!(record.action.as_deref(), Some("aido.svc.restart"));
        assert_eq!(record.rule_source.as_deref(), Some("20-services.toml:15"));
        assert_eq!(record.evidence, vec!["CLAUDECODE=1".to_owned()]);
        assert_eq!(record.deny_list_version, 1);
    }

    #[test]
    fn editing_any_field_breaks_the_seal() {
        // The property the whole crate rests on: the hash covers the contents.
        let sealed = first();
        for mutate in [
            (|r: &mut Record| r.decision = Decision::Denied) as fn(&mut Record),
            |r| r.argv.push("extra".to_owned()),
            |r| r.classification = "enrolled-agent".to_owned(),
            |r| r.denial = Some("frozen".to_owned()),
            |r| r.action = Some("other".to_owned()),
            |r| r.rule_source = Some("elsewhere:1".to_owned()),
            |r| r.evidence.push("forged".to_owned()),
            |r| r.deny_list_version = 99,
            |r| r.outcome = Outcome::Exited { code: 0 },
            |r| r.seq = Sequence(42),
            |r| r.prev_hash = "deadbeef".to_owned(),
            |r| r.schema_version = 99,
        ] {
            let mut tampered = sealed.clone();
            mutate(&mut tampered);
            assert!(
                !tampered.is_sealed(),
                "a field was changed without breaking the seal: {tampered:?}"
            );
        }
    }

    #[test]
    fn the_hash_is_unambiguous_across_field_boundaries() {
        // Length-prefixed fields, so text cannot be moved across a boundary to
        // produce the same digest. Without prefixes these two would collide.
        let a = Record::first(
            Decision::Allowed,
            vec!["ab".to_owned(), "c".to_owned()],
            "h",
        );
        let b = Record::first(
            Decision::Allowed,
            vec!["a".to_owned(), "bc".to_owned()],
            "h",
        );
        assert_ne!(a.hash, b.hash);

        // And across the argv/classification boundary.
        let c = Record::first(Decision::Allowed, vec!["x".to_owned()], "yz");
        let d = Record::first(Decision::Allowed, vec!["xy".to_owned()], "z");
        assert_ne!(c.hash, d.hash);
    }

    #[test]
    fn identical_content_hashes_identically() {
        // Determinism, so a record can be re-derived and compared rather than
        // trusted. Nothing in the hash comes from a clock or a random source.
        assert_eq!(first().hash, first().hash);
    }

    #[test]
    fn an_outcome_distinguishes_ran_from_was_permitted() {
        // Conflating them loses the interesting case: allowed and then failed is
        // not the same event as refused.
        assert!(Outcome::Exited { code: 1 }.executed());
        assert!(Outcome::Signalled { signal: 9 }.executed());
        assert!(!Outcome::NotExecuted.executed());
        assert!(
            !Outcome::Failed {
                reason: "no such file".to_owned()
            }
            .executed()
        );
    }

    #[test]
    fn a_record_round_trips_as_one_json_line_and_rejects_unknown_keys() {
        let record = first().with_denial("argv_rejected");
        let line = record.to_jsonl();
        assert!(!line.contains('\n'), "a record must be one line");
        assert_eq!(serde_json::from_str::<Record>(&line).unwrap(), record);
        // An unknown key is refused, so a reader cannot be fed extra fields it
        // would ignore.
        let tampered = line.replace("\"seq\"", "\"trusted\":true,\"seq\"");
        assert!(serde_json::from_str::<Record>(&tampered).is_err());
    }

    #[test]
    fn rendering_falls_back_only_when_serialization_fails() {
        assert_eq!(
            or_fallback(Ok("real".to_owned()), "fallback".to_owned()),
            "real"
        );
        // A genuine serde_json error, obtained without a closure that would
        // otherwise never run.
        let failed: Result<String, serde_json::Error> = serde_json::from_str("not json");
        assert!(failed.is_err());
        assert_eq!(or_fallback(failed, "fallback".to_owned()), "fallback");
    }

    #[test]
    fn an_unrenderable_record_still_carries_its_sequence_and_hash() {
        // Unreachable for a real record, which is why the fallback is exercised
        // directly. The property that matters is that a gap stays verifiable
        // rather than simply breaking the chain.
        let record = first();
        let line = record.unrenderable_line();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["seq"], 1);
        assert_eq!(parsed["unrenderable"], true);
        assert_eq!(parsed["hash"], record.hash);
    }

    #[test]
    fn every_decision_and_outcome_variant_serializes() {
        for decision in [
            Decision::Allowed,
            Decision::AwaitingConfirmation,
            Decision::Denied,
        ] {
            let json = serde_json::to_string(&decision).unwrap();
            assert_eq!(serde_json::from_str::<Decision>(&json).unwrap(), decision);
            assert!(format!("{decision:?}").len() > 5);
        }
        for outcome in [
            Outcome::NotExecuted,
            Outcome::Exited { code: 17 },
            Outcome::Signalled { signal: 15 },
            Outcome::Failed {
                reason: "r".to_owned(),
            },
        ] {
            let json = serde_json::to_string(&outcome).unwrap();
            assert_eq!(serde_json::from_str::<Outcome>(&json).unwrap(), outcome);
            assert!(format!("{outcome:?}").len() > 5);
        }
    }
}
