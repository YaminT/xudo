//! Whether a queued run is still claimed for this nonce.
//!
//! The gate reads the broker's queue itself. It does not ask the broker: the
//! broker minted the spool entry, and a queued run is authorized only while
//! the root-owned queue record is `claimed` for this nonce. A missing record,
//! any other state, or a different nonce is not a claim.

use serde::Deserialize;

use xudo_sys::SpoolError;

/// Root-owned queue the broker persists. The gate opens it with `openat2`.
pub const QUEUE_DIR: &str = "/var/lib/xudo/queue";

/// A root-owned queue the gate can read and not write.
pub trait QueueClaim {
    /// One record's bytes. `name` is `{id}.json`.
    ///
    /// # Errors
    ///
    /// [`SpoolError`] when the name is not one component or the file cannot be
    /// read as a private root-owned entry.
    fn read(&self, name: &str) -> Result<Vec<u8>, SpoolError>;
}

/// The queue record fields the gate looks at. Extra keys are ignored: the
/// broker's record carries argv and claimant fields this check does not use.
#[derive(Deserialize)]
struct StoredClaim {
    #[serde(default)]
    state: String,
    #[serde(default)]
    run_nonce: Option<String>,
}

/// Whether `bytes` is a queue record currently claimed for `nonce`.
#[must_use]
pub fn queued_claim_holds(bytes: &[u8], nonce: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Ok(stored) = serde_json::from_str::<StoredClaim>(text) else {
        return false;
    };
    stored.state == "claimed" && stored.run_nonce.as_deref() == Some(nonce)
}

/// The file name of one queue record.
///
/// `id` has already been checked to be 64 lowercase hex, so this cannot name
/// a parent directory.
#[must_use]
pub fn queue_file_name(id: &str) -> String {
    format!("{id}.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn a_claimed_record_for_this_nonce_holds_and_every_other_shape_does_not() {
        let claimed =
            format!(r#"{{"id":"{NONCE}","state":"claimed","run_nonce":"{NONCE}","argv":[]}}"#);
        assert!(queued_claim_holds(claimed.as_bytes(), NONCE));
        let pending = format!(r#"{{"state":"pending","run_nonce":"{NONCE}"}}"#);
        assert!(!queued_claim_holds(pending.as_bytes(), NONCE));
        let other = format!(r#"{{"state":"claimed","run_nonce":"{}"}}"#, "b".repeat(64));
        assert!(!queued_claim_holds(other.as_bytes(), NONCE));
        let missing_nonce = r#"{"state":"claimed"}"#;
        assert!(!queued_claim_holds(missing_nonce.as_bytes(), NONCE));
        assert!(!queued_claim_holds(b"not json", NONCE));
        assert!(!queued_claim_holds(b"\xff", NONCE));
        assert_eq!(queue_file_name(NONCE), format!("{NONCE}.json"));
        assert_eq!(QUEUE_DIR, "/var/lib/xudo/queue");
    }
}
