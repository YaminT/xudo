//! The queue entry: what an agent buffered for the human to run.

use serde::{Deserialize, Serialize};

use crate::error::IdoError;

/// Version of the queue-line schema. Bump on any change to the shape.
pub const QUEUE_SCHEMA_VERSION: u32 = 1;

/// After this many seconds an unrun entry is shown greyed as stale.
///
/// Stale entries are never deleted automatically — losing queued work
/// silently is worse than showing old work greyed. `ido drop --stale` clears
/// them deliberately.
pub const STALE_AFTER_SECS: u64 = 7 * 24 * 60 * 60;

/// One buffered command.
///
/// `deny_unknown_fields` on purpose: an unrecognized key means a newer `ido`
/// or a hand edit wrote this file, and silently ignoring a field that might
/// say "needs approval" is the failure mode this project exists to avoid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// Queue-line schema version.
    pub schema_version: u32,
    /// Monotonic id, unique within the queue file's history.
    pub id: u64,
    /// The command as a real argument vector. Executed exactly as stored,
    /// with no shell involved, which makes the quoting-and-injection class
    /// unreachable.
    pub argv: Vec<String>,
    /// Why the agent queued it. Untrusted text, sanitized at render.
    #[serde(default)]
    pub reason: Option<String>,
    /// Group name, for related commands.
    #[serde(default)]
    pub group: Option<String>,
    /// Order within the group; enforces one-by-one execution.
    #[serde(default)]
    pub step: Option<u32>,
    /// Ids this entry depends on, across groups.
    #[serde(default)]
    pub needs: Vec<u64>,
    /// Working directory to run in. Untrusted text, sanitized at render.
    #[serde(default)]
    pub cwd: Option<String>,
    /// A no-side-effect preview command, shown at selection time.
    #[serde(default)]
    pub dry_run_of: Vec<String>,
    /// Unix seconds when queued.
    pub queued_at: u64,
    /// Who queued it — a self-declared hint, never verified.
    #[serde(default)]
    pub queued_by: Option<String>,
    /// How many times a run has been attempted.
    #[serde(default)]
    pub attempts: u32,
    /// Exit code of the last failed attempt. A successful run removes the
    /// entry instead, so `Some(0)` never occurs.
    #[serde(default)]
    pub last_exit: Option<i32>,
}

impl Entry {
    /// Builds a new entry, validating it against the rest of the queue.
    ///
    /// # Errors
    ///
    /// Refuses an empty argv, a `step` without a `group`, a step of zero, a
    /// `(group, step)` pair already queued, and a `needs` id that names no
    /// existing entry — which is also what makes a dependency cycle
    /// unrepresentable from the command line: edges can only point at entries
    /// that already exist, so they only ever point backwards.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        existing: &[Entry],
        argv: Vec<String>,
        reason: Option<String>,
        group: Option<String>,
        step: Option<u32>,
        needs: Vec<u64>,
        cwd: Option<String>,
        dry_run_of: Vec<String>,
        queued_at: u64,
        queued_by: Option<String>,
    ) -> Result<Entry, IdoError> {
        if argv.is_empty() {
            return Err(IdoError::Refused(
                "nothing to queue: give the command after `--`".into(),
            ));
        }
        if step.is_some() && group.is_none() {
            return Err(IdoError::Refused(
                "--step orders a group; give --group too".into(),
            ));
        }
        if step == Some(0) {
            return Err(IdoError::Refused("steps are numbered from 1".into()));
        }
        if let (Some(g), Some(s)) = (&group, step)
            && existing
                .iter()
                .any(|e| e.group.as_deref() == Some(g.as_str()) && e.step == Some(s))
        {
            return Err(IdoError::Refused(format!(
                "group '{g}' already has a step {s}; steps are one command each"
            )));
        }
        for id in &needs {
            if !existing.iter().any(|e| e.id == *id) {
                return Err(IdoError::Refused(format!(
                    "--needs {id}: no queued entry has that id, and a dependency \
                     may only name an entry that already exists"
                )));
            }
        }
        let id = existing
            .iter()
            .map(|e| e.id)
            .max()
            .map_or(1, |m| m.saturating_add(1));
        Ok(Entry {
            schema_version: QUEUE_SCHEMA_VERSION,
            id,
            argv,
            reason,
            group,
            step,
            needs,
            cwd,
            dry_run_of,
            queued_at,
            queued_by,
            attempts: 0,
            last_exit: None,
        })
    }

    /// One JSONL line, newline included.
    ///
    /// Infallible by construction — every field is plain data — and degrading
    /// eagerly rather than panicking: a serializer failure yields a line that
    /// still parses as an entry whose argv is empty, which nothing will run.
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        let fallback = format!(
            "{{\"schema_version\":{QUEUE_SCHEMA_VERSION},\"id\":{},\"argv\":[],\"queued_at\":{}}}\n",
            self.id, self.queued_at
        );
        jsonl_or(fallback, self)
    }
}

/// Serializes one JSONL line, handing back `fallback` on failure.
///
/// A free function taking the fallback as a value, so a test can exercise the
/// failure arm with a type that genuinely cannot serialize.
fn jsonl_or<T: Serialize>(fallback: String, value: &T) -> String {
    serde_json::to_string(value).map_or(fallback, |mut line| {
        line.push('\n');
        line
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn minimal(id: u64, group: Option<&str>, step: Option<u32>) -> Entry {
        Entry {
            schema_version: QUEUE_SCHEMA_VERSION,
            id,
            argv: vec!["true".into()],
            reason: None,
            group: group.map(str::to_owned),
            step,
            needs: Vec::new(),
            cwd: None,
            dry_run_of: Vec::new(),
            queued_at: 0,
            queued_by: None,
            attempts: 0,
            last_exit: None,
        }
    }

    fn build(existing: &[Entry], argv: &[&str]) -> Result<Entry, IdoError> {
        Entry::build(
            existing,
            argv.iter().map(|s| (*s).to_owned()).collect(),
            None,
            None,
            None,
            Vec::new(),
            None,
            Vec::new(),
            42,
            None,
        )
    }

    #[test]
    fn ids_are_monotonic_and_start_at_one() {
        let first = build(&[], &["echo"]).unwrap();
        assert_eq!(first.id, 1);
        let second = build(&[first], &["echo"]).unwrap();
        assert_eq!(second.id, 2);
    }

    #[test]
    fn an_empty_argv_is_refused() {
        let err = build(&[], &[]).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("--"), "{err}");
    }

    #[test]
    fn a_step_without_a_group_is_refused() {
        let err = Entry::build(
            &[],
            vec!["x".into()],
            None,
            None,
            Some(1),
            Vec::new(),
            None,
            Vec::new(),
            0,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--group"), "{err}");
    }

    #[test]
    fn step_zero_is_refused() {
        let err = Entry::build(
            &[],
            vec!["x".into()],
            None,
            Some("g".into()),
            Some(0),
            Vec::new(),
            None,
            Vec::new(),
            0,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("numbered from 1"), "{err}");
    }

    #[test]
    fn a_duplicate_step_in_a_group_is_refused() {
        let existing = [minimal(1, Some("deploy"), Some(1))];
        let err = Entry::build(
            &existing,
            vec!["x".into()],
            None,
            Some("deploy".into()),
            Some(1),
            Vec::new(),
            None,
            Vec::new(),
            0,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already has a step 1"), "{err}");
    }

    #[test]
    fn a_dependency_cycle_is_refused_at_queue_time() {
        // Edges may only name entries that already exist, so they only point
        // backwards and a cycle is unrepresentable — enforced by refusing an
        // unknown id, which is also the self-reference case, since the new
        // entry has no id yet.
        let err = Entry::build(
            &[],
            vec!["x".into()],
            None,
            None,
            None,
            vec![99],
            None,
            Vec::new(),
            0,
            None,
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
    }

    #[test]
    fn a_valid_dependency_is_kept() {
        let existing = [minimal(1, None, None)];
        let entry = Entry::build(
            &existing,
            vec!["x".into()],
            None,
            None,
            None,
            vec![1],
            None,
            Vec::new(),
            0,
            None,
        )
        .unwrap();
        assert_eq!(entry.needs, vec![1]);
        assert_eq!(entry.id, 2);
    }

    #[test]
    fn a_line_round_trips() {
        let entry = minimal(7, Some("g"), Some(2));
        let line = entry.to_jsonl();
        assert!(line.ends_with('\n'));
        let back: Entry = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(back, entry);
    }

    #[test]
    fn an_unknown_field_is_a_hard_parse_failure() {
        let line = r#"{"schema_version":1,"id":1,"argv":["x"],"queued_at":0,"surprise":true}"#;
        assert!(serde_json::from_str::<Entry>(line).is_err());
    }

    #[test]
    fn a_serializer_failure_degrades_to_an_unrunnable_line() {
        struct Broken;
        impl Serialize for Broken {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("no"))
            }
        }
        let line = jsonl_or("{\"argv\":[]}\n".to_owned(), &Broken);
        assert_eq!(line, "{\"argv\":[]}\n");
        // And the real fallback parses back to an entry nothing will run.
        let entry = minimal(1, None, None);
        let fallback = format!(
            "{{\"schema_version\":{QUEUE_SCHEMA_VERSION},\"id\":{},\"argv\":[],\"queued_at\":{}}}\n",
            entry.id, entry.queued_at
        );
        let parsed: Entry = serde_json::from_str(fallback.trim_end()).unwrap();
        assert!(parsed.argv.is_empty());
    }
}
