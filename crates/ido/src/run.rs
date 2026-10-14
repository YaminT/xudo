//! Executes what the human selected, exactly as stored.
//!
//! The argv runs as a vector with no shell involved — the quoting-and-
//! injection class is unreachable because nothing re-parses a string. Output
//! streams to the human's terminal live (the child inherits stdio), the exit
//! status is recorded in the hash-chained run log before `ido` moves on, and
//! a failure stops the run: nothing after a failed command executes without a
//! fresh human decision.
//!
//! The queue lock is held only around bookkeeping, never while a command runs.
//! A `terraform apply` can take twenty minutes, and an agent's `ido queue` in
//! that window must still succeed. So each entry is re-read and re-checked
//! under the lock immediately before it starts: a step whose predecessor just
//! failed, or an entry dropped from another terminal, is skipped rather than
//! run on the strength of a decision made before the facts changed.

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::Duration;

use aido_audit::{Decision, Outcome, Record};

use crate::entry::Entry;
use crate::error::IdoError;
use crate::render;
use crate::status::status_of;
use crate::store::Store;

/// The exit code recorded on an entry when its command could not start.
///
/// `127` is the shell convention for "command not found", the overwhelmingly
/// common cause; the audit record carries the precise reason.
pub const SPAWN_FAILURE_EXIT: i32 = 127;

/// What one run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Entries that ran and exited 0, in order.
    pub succeeded: Vec<u64>,
    /// The entry that failed and the code recorded for it, if one did.
    pub failed: Option<(u64, i32)>,
    /// Entries that were selected but not reached because of the failure.
    pub not_reached: Vec<u64>,
    /// Entries that were not runnable when their turn came, and why.
    pub skipped: Vec<(u64, String)>,
}

impl Report {
    /// The process exit status: `0` only when everything selected ran and
    /// succeeded.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(self.failed.is_some() || !self.skipped.is_empty())
    }

    /// A one-paragraph account of the run, for the human.
    #[must_use]
    pub fn summary(&self) -> String {
        let ids = |list: &[u64]| -> String {
            list.iter()
                .map(|id| format!("#{id}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let mut lines = vec![format!("ido: {} succeeded", self.succeeded.len())];
        if let Some((id, code)) = self.failed {
            lines.push(format!(
                "ido: #{id} failed with exit {code}; it stays queued. Retry it, or drop it \
                 to unblock what depends on it"
            ));
        }
        if !self.not_reached.is_empty() {
            lines.push(format!(
                "ido: not run after the failure: {}",
                ids(&self.not_reached)
            ));
        }
        for (id, why) in &self.skipped {
            lines.push(format!("ido: skipped #{id}: {why}"));
        }
        let mut text = lines.join("\n");
        text.push('\n');
        text
    }
}

/// How a run is carried out.
#[derive(Clone, Copy, Debug)]
pub struct RunContext<'a> {
    /// The time recorded for the run, and against which staleness is judged.
    pub now_unix: u64,
    /// Variables added to the human's own environment for each child.
    pub child_env: &'a [(String, String)],
    /// How long to wait for the queue lock.
    pub lock_wait: Duration,
}

/// Runs `ids`, in order, stopping on the first failure.
///
/// Each success removes its entry and each failure marks it, with the log
/// appended and the queue rewritten *before* the next command starts — a crash
/// mid-run loses at most the record of the command running at that moment.
///
/// # Errors
///
/// Store failures. A failing *command* is not an error: it is reported in the
/// [`Report`] and recorded in the log.
pub fn run_ids(
    store: &Store,
    ids: &[u64],
    ctx: &RunContext<'_>,
    out: &mut dyn Write,
) -> Result<Report, IdoError> {
    let mut report = Report::default();
    for (i, id) in ids.iter().enumerate() {
        let entry = {
            let _lock = store.lock_waiting(ctx.lock_wait)?;
            let queue = store.load()?;
            let Some(entry) = queue.iter().find(|e| e.id == *id).cloned() else {
                report.skipped.push((*id, "no longer queued".to_owned()));
                continue;
            };
            let status = status_of(&entry, &queue, ctx.now_unix);
            if !status.selectable() {
                report.skipped.push((
                    *id,
                    format!(
                        "{}: {}",
                        status.label(),
                        status.detail().unwrap_or_default()
                    ),
                ));
                continue;
            }
            entry
        };

        let shown = render::argv_line(&entry.argv, render::FIELD_COLS);
        let _ = writeln!(out, "ido: running #{id}: {}", shown.text);
        let _ = out.flush();
        let outcome = spawn_and_wait(&entry, ctx.child_env);
        let exit = exit_code_of(&outcome);
        {
            let _lock = store.lock_waiting(ctx.lock_wait)?;
            record_run(store, &entry, &outcome, ctx.now_unix)?;
            let mut queue = store.load()?;
            if exit == 0 {
                queue.retain(|e| e.id != *id);
            } else {
                mark_failed(&mut queue, *id, exit);
            }
            store.replace(&queue)?;
        }

        if exit == 0 {
            report.succeeded.push(*id);
            continue;
        }
        report.failed = Some((*id, exit));
        report
            .not_reached
            .extend(ids.get(i.saturating_add(1)..).unwrap_or_default());
        let _ = writeln!(out, "ido: #{id} failed with exit {exit}; stopping");
        break;
    }
    Ok(report)
}

/// Spawns the entry's argv and waits, mapping every fate to an [`Outcome`].
fn spawn_and_wait(entry: &Entry, child_env: &[(String, String)]) -> Outcome {
    // `Command::new` performs a PATH search, which the workspace lint bans
    // because in a *privileged* exec path, PATH is attacker leverage. Here it
    // is the point: ido runs the command with the human's own shell
    // semantics, as the human, with the human's PATH — ido holds no
    // privilege to leak. The argv executed is byte-identical to what was
    // stored and displayed.
    #[allow(clippy::disallowed_methods)]
    let mut command = std::process::Command::new(entry.argv.first().map_or("", String::as_str));
    command.args(entry.argv.get(1..).unwrap_or_default());
    if let Some(cwd) = &entry.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in child_env {
        command.env(key, value);
    }
    match command.status() {
        Ok(status) => status_to_outcome(status),
        Err(e) => Outcome::Failed {
            reason: e.to_string(),
        },
    }
}

/// Maps a wait status to the audit outcome.
fn status_to_outcome(status: ExitStatus) -> Outcome {
    match (status.code(), status.signal()) {
        (Some(code), _) => Outcome::Exited { code },
        (None, Some(signal)) => Outcome::Signalled { signal },
        // A wait status with neither a code nor a signal does not occur on
        // the platforms ido runs on; refuse to call it success.
        (None, None) => Outcome::Failed {
            reason: "wait returned neither an exit code nor a signal".to_owned(),
        },
    }
}

/// The exit code an outcome contributes to the run report.
fn exit_code_of(outcome: &Outcome) -> i32 {
    match outcome {
        Outcome::Exited { code } => *code,
        Outcome::Signalled { signal } => 128_i32.saturating_add(*signal),
        Outcome::Failed { .. } | Outcome::NotExecuted => SPAWN_FAILURE_EXIT,
    }
}

/// Marks an entry failed in place.
fn mark_failed(queue: &mut [Entry], id: u64, exit: i32) {
    for entry in queue.iter_mut() {
        if entry.id == id {
            entry.attempts = entry.attempts.saturating_add(1);
            entry.last_exit = Some(exit);
        }
    }
}

/// Appends the run to the hash-chained log.
fn record_run(
    store: &Store,
    entry: &Entry,
    outcome: &Outcome,
    now_unix: u64,
) -> Result<(), IdoError> {
    let chain = store.read_log()?;
    let mut evidence = vec![format!("entry={}", entry.id), format!("ran_at={now_unix}")];
    if let Some(reason) = &entry.reason {
        evidence.push(format!("reason={reason}"));
    }
    let record = Record::after(
        chain.records().last(),
        Decision::Allowed,
        entry.argv.clone(),
        "human:ido",
    )
    .with_evidence(evidence)
    .with_outcome(outcome.clone());
    store.append_log(&record)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;

    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    use crate::entry::QUEUE_SCHEMA_VERSION;

    fn store(name: &str) -> (PathBuf, Store) {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("test-tmp")
            .join(format!("ido-run-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let store = Store::open(&dir.join("state"), &dir.join("run"), uid).unwrap();
        (dir, store)
    }

    fn entry(id: u64, argv: &[&str]) -> Entry {
        Entry {
            schema_version: QUEUE_SCHEMA_VERSION,
            id,
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            reason: Some("because".into()),
            group: None,
            step: None,
            needs: Vec::new(),
            cwd: None,
            dry_run_of: Vec::new(),
            queued_at: 100,
            queued_by: None,
            attempts: 0,
            last_exit: None,
        }
    }

    const CTX: RunContext<'static> = RunContext {
        now_unix: 100,
        child_env: &[],
        lock_wait: Duration::from_millis(50),
    };

    #[test]
    fn a_failure_stops_the_run_and_is_recorded() {
        let (_, store) = store("failure");
        store
            .replace(&[
                entry(1, &["true"]),
                entry(2, &["sh", "-c", "exit 3"]),
                entry(3, &["true"]),
            ])
            .unwrap();
        let mut out = Vec::new();
        let report = run_ids(&store, &[1, 2, 3], &CTX, &mut out).unwrap();
        assert_eq!(report.succeeded, vec![1]);
        assert_eq!(report.failed, Some((2, 3)));
        assert_eq!(report.not_reached, vec![3]);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("ido: running #1: true"), "{text}");
        assert!(text.contains("#2 failed with exit 3; stopping"), "{text}");

        let left = store.load().unwrap();
        assert_eq!(left.iter().map(|e| e.id).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(left[0].last_exit, Some(3));
        assert_eq!(left[0].attempts, 1);

        let log = store.read_log().unwrap();
        assert_eq!(log.len(), 2, "both runs are in the chained log");
        assert!(
            log.records()[0]
                .evidence
                .contains(&"reason=because".to_owned())
        );
    }

    #[test]
    fn an_entry_that_vanished_or_became_blocked_is_skipped_not_run() {
        let (_, store) = store("skip");
        let mut step1 = entry(1, &["true"]);
        step1.group = Some("g".into());
        step1.step = Some(1);
        step1.last_exit = Some(1);
        let mut step2 = entry(2, &["true"]);
        step2.group = Some("g".into());
        step2.step = Some(2);
        store.replace(&[step1, step2]).unwrap();
        let mut out = Vec::new();
        let report = run_ids(&store, &[9, 2], &CTX, &mut out).unwrap();
        assert!(report.succeeded.is_empty());
        assert_eq!(
            report.skipped,
            vec![
                (9, "no longer queued".to_owned()),
                (2, "halted: step 1 failed with exit 1".to_owned())
            ]
        );
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn the_stored_directory_and_extra_environment_reach_the_child() {
        let (dir, store) = store("cwd-env");
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut e = entry(
            1,
            &[
                "sh",
                "-c",
                "test \"$PWD\" = \"$WANT\" && test \"$IDO_X\" = 1",
            ],
        );
        e.cwd = Some(work.to_str().unwrap().to_owned());
        store.replace(&[e]).unwrap();
        let want = std::fs::canonicalize(&work).unwrap();
        let env = [
            ("IDO_X".to_owned(), "1".to_owned()),
            ("WANT".to_owned(), want.to_str().unwrap().to_owned()),
        ];
        let ctx = RunContext {
            child_env: &env,
            ..CTX
        };
        let report = run_ids(&store, &[1], &ctx, &mut Vec::new()).unwrap();
        assert_eq!(report.succeeded, vec![1], "{report:?}");
        assert!(store.load().unwrap().is_empty());
    }

    #[test]
    fn a_command_that_cannot_start_is_a_recorded_failure() {
        let (_, store) = store("spawn");
        let mut missing_dir = entry(2, &["true"]);
        missing_dir.cwd = Some("/definitely/not/a/dir".into());
        store.replace(&[entry(1, &[]), missing_dir]).unwrap();
        let report = run_ids(&store, &[1], &CTX, &mut Vec::new()).unwrap();
        assert_eq!(report.failed, Some((1, SPAWN_FAILURE_EXIT)));
        let report = run_ids(&store, &[2], &CTX, &mut Vec::new()).unwrap();
        assert_eq!(report.failed, Some((2, SPAWN_FAILURE_EXIT)));
        let log = store.read_log().unwrap();
        assert!(!log.records()[0].outcome.executed());
    }

    #[test]
    fn a_held_lock_stops_the_run_before_anything_starts() {
        let (_, store) = store("locked");
        store.replace(&[entry(1, &["true"])]).unwrap();
        let _held = store.lock().unwrap();
        let err = run_ids(&store, &[1], &CTX, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("another ido process"), "{err}");
    }

    /// Runs one entry whose command sabotages the store mid-run, and
    /// returns the error `run_ids` reports afterwards.
    fn sabotaged(name: &str, script: &str) -> String {
        let (dir, store) = store(name);
        store.replace(&[entry(1, &["sh", "-c", script])]).unwrap();
        let tmp = store
            .queue_path()
            .with_extension(format!("tmp.{}", std::process::id()));
        let env = [
            (
                "LOCK".to_owned(),
                dir.join("run").join("lock").to_str().unwrap().to_owned(),
            ),
            (
                "LOG".to_owned(),
                store.log_path().to_str().unwrap().to_owned(),
            ),
            (
                "QUEUE".to_owned(),
                store.queue_path().to_str().unwrap().to_owned(),
            ),
            ("TMP".to_owned(), tmp.to_str().unwrap().to_owned()),
        ];
        let ctx = RunContext {
            child_env: &env,
            ..CTX
        };
        run_ids(&store, &[1], &ctx, &mut Vec::new())
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn bookkeeping_after_a_run_fails_closed_whatever_breaks() {
        // The command ran; what it did to the store must surface as an error
        // rather than be papered over.
        assert!(sabotaged("took-lock", "echo 1 > \"$LOCK\"").contains("another ido process"));
        assert!(sabotaged("broke-log", "echo junk > \"$LOG\"").contains("is unreadable"));
        assert!(sabotaged("broke-queue", "echo junk >> \"$QUEUE\"").contains("cannot be parsed"));
        assert!(sabotaged("blocked-tmp", "mkdir \"$TMP\"").starts_with("create"));
    }

    #[test]
    fn a_tampered_queue_is_refused_before_anything_runs() {
        let (_, store) = store("tampered");
        std::fs::write(store.queue_path(), "junk\n").unwrap();
        let err = run_ids(&store, &[1], &CTX, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("cannot be parsed"), "{err}");
        assert!(store.read_log().unwrap().is_empty(), "nothing ran");
    }

    #[test]
    fn every_wait_fate_maps_to_a_recorded_outcome_and_a_code() {
        let exited = ExitStatus::from_raw(0x0300); // exit 3
        assert_eq!(status_to_outcome(exited), Outcome::Exited { code: 3 });
        let signalled = ExitStatus::from_raw(0x0009); // SIGKILL
        assert_eq!(
            status_to_outcome(signalled),
            Outcome::Signalled { signal: 9 }
        );
        // A stopped child reports neither; it must not read as success.
        let stopped = ExitStatus::from_raw(0x137f);
        assert_eq!(
            status_to_outcome(stopped),
            Outcome::Failed {
                reason: "wait returned neither an exit code nor a signal".to_owned()
            }
        );

        assert_eq!(exit_code_of(&Outcome::Exited { code: 3 }), 3);
        assert_eq!(exit_code_of(&Outcome::Signalled { signal: 9 }), 137);
        assert_eq!(
            exit_code_of(&Outcome::Failed { reason: "x".into() }),
            SPAWN_FAILURE_EXIT
        );
        assert_eq!(exit_code_of(&Outcome::NotExecuted), SPAWN_FAILURE_EXIT);
    }

    #[test]
    fn a_report_is_zero_only_when_nothing_failed() {
        let clean = Report {
            succeeded: vec![1],
            ..Report::default()
        };
        assert_eq!(clean.exit_code(), 0);
        assert_eq!(clean.summary(), "ido: 1 succeeded\n");
        let dirty = Report {
            succeeded: Vec::new(),
            failed: Some((1, 3)),
            not_reached: vec![2, 3],
            skipped: vec![(4, "blocked: step 1 has not run".into())],
        };
        assert_eq!(dirty.exit_code(), 1);
        let text = dirty.summary();
        assert!(text.contains("#1 failed with exit 3"), "{text}");
        assert!(text.contains("not run after the failure: #2 #3"), "{text}");
        assert!(
            text.contains("skipped #4: blocked: step 1 has not run"),
            "{text}"
        );
        let skipped_only = Report {
            skipped: vec![(4, "gone".into())],
            ..Report::default()
        };
        assert_eq!(skipped_only.exit_code(), 1);
    }
}
