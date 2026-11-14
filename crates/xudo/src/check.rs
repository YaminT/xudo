//! `xudo check`: lint the ruleset, then run the `[[test]]` tables in its files.
//!
//! Three kinds of problem, three exit codes, so a pipeline can gate each on its
//! own: a lint warning ([`ExitCode::LintWarning`]), a lint error
//! ([`ExitCode::LintError`]) and a failing rule test ([`ExitCode::TestFailure`]).
//! One run that finds several prints every one and exits with the most severe,
//! which is the largest of the three numbers.
//!
//! The tests are decided by [`xudo_policy::run_tests`], which asks the engine
//! `xudo explain` asks, for an unattested human and the default settings, so
//! the answer does not depend on the machine or its configuration.

use std::io::Write;

use serde_json::{Map, Value, json};
use term_sanitize::{Clean, Limits};
use xudo_policy::{
    CallerFacts, Classification, DenialCode, ExitCode, TestError, TestOutcome, TestResult,
    engine::Settings,
    fuzz_check::{Finding, FindingKind, FuzzConfig, FuzzReport, fuzz},
    run_tests,
};

use crate::cli::{CheckArgs, Cli, Format};
use crate::rules::LoadedRules;

/// The envelope's schema version.
const SCHEMA_VERSION: u32 = 1;

/// One rendered line is at most this many columns.
const LIMITS: Limits = Limits {
    max_cols: 200,
    max_lines: 1,
};

/// A systemctl rule that can start or stop a unit it does not name.
struct OpenUnit {
    action: String,
    file: String,
    line: u32,
    message: String,
}

/// Everything one run found.
struct Report {
    /// A rule that allowlists what the deny-list refuses: the id and the classes.
    errors: Vec<(String, Vec<String>)>,
    /// A systemctl rule whose unit matcher is not a finite list.
    open_units: Vec<OpenUnit>,
    /// One rendered overlap each.
    warnings: Vec<String>,
    results: Vec<TestResult>,
    /// What the fuzz found, when it ran.
    fuzz: Option<FuzzReport>,
}

impl Report {
    fn failed(&self) -> usize {
        self.results
            .iter()
            .filter(|result| !result.outcome.passed())
            .count()
    }

    /// The most severe problem found, or [`ExitCode::Delegated`] for none.
    fn status(&self) -> ExitCode {
        [
            (self.failed() > 0).then_some(ExitCode::TestFailure),
            (!self.errors.is_empty()
                || !self.open_units.is_empty()
                || self.fuzz.as_ref().is_some_and(|f| !f.clean()))
            .then_some(ExitCode::LintError),
            (!self.warnings.is_empty()).then_some(ExitCode::LintWarning),
        ]
        .into_iter()
        .flatten()
        .max_by_key(|code| code.as_i32())
        .unwrap_or(ExitCode::Delegated)
    }
}

/// Lints and tests `loaded`, writes the report, and returns the exit status.
///
/// `--tests-only` skips the lint. `--fuzz` also runs the differential fuzz, whose
/// findings are lint errors.
pub(crate) fn run(
    cli: &Cli,
    loaded: &LoadedRules,
    args: &CheckArgs,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let tests_only = args.tests_only;
    let fuzz_config = args.fuzz.then(|| FuzzConfig {
        budget: usize::try_from(args.fuzz_budget).unwrap_or(usize::MAX),
        seed: args.fuzz_seed,
    });
    let overlaps = if tests_only && !args.fuzz {
        Vec::new()
    } else {
        loaded.rules().overlaps()
    };
    let (errors, open_units, warnings) = if tests_only {
        (Vec::new(), Vec::new(), Vec::new())
    } else {
        (
            loaded
                .rules()
                .self_denying_actions()
                .into_iter()
                .map(|(id, classes)| {
                    (
                        id.to_string(),
                        classes.iter().map(|class| format!("{class:?}")).collect(),
                    )
                })
                .collect(),
            loaded
                .rules()
                .open_unit_actions()
                .iter()
                .map(|lint| OpenUnit {
                    action: lint.id.to_string(),
                    file: lint.source.file.clone(),
                    line: lint.source.line,
                    message: lint.message(),
                })
                .collect(),
            overlaps.iter().map(ToString::to_string).collect(),
        )
    };
    let human = CallerFacts::new(Classification::Human, 1000);
    let report = Report {
        errors,
        open_units,
        warnings,
        results: run_tests(loaded.rules(), loaded.tests(), &human, Settings::default()),
        fuzz: fuzz_config.map(|config| fuzz(loaded.rules(), &overlaps, config)),
    };
    let status = report.status();
    let note =
        crate::lifecycle_note::missing(loaded.rules()).then_some(crate::lifecycle_note::TEXT);
    match cli.output {
        Format::Human => human_report(loaded, &report, tests_only, note, out, err),
        Format::Json => {
            let _ = writeln!(out, "{}", envelope(&report, status, note));
        }
    }
    status
}

fn human_report(
    loaded: &LoadedRules,
    report: &Report,
    tests_only: bool,
    note: Option<&str>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) {
    for (id, classes) in &report.errors {
        let _ = writeln!(
            err,
            "xudo: {} allowlists an executable the deny-list refuses: [{}]",
            safe(id),
            classes.join(", ")
        );
    }
    if !report.errors.is_empty() {
        let _ = writeln!(
            err,
            "xudo: a rule that allowlists a shell-capable binary defeats the design"
        );
    }
    for open in &report.open_units {
        let _ = writeln!(err, "xudo: {}", safe(&open.message));
    }

    if !tests_only {
        if report.errors.is_empty() && report.open_units.is_empty() {
            let _ = writeln!(
                out,
                "ok: {} action(s) in {} file(s), generation {}",
                loaded.rules().len(),
                loaded.files().len(),
                loaded.generation().get(..12).unwrap_or(loaded.generation())
            );
        }
        // A note, not a finding: the exit status above does not count it.
        if let Some(note) = note {
            let _ = writeln!(out, "{note}");
        }
        // Reported, not refused: the engine resolves a command more than one
        // action accepts to the strictest of them, so an overlap is not a hole.
        // It is still two rules whose interaction nobody wrote down, and the
        // report never stays silent about a pair it cannot decide.
        for warning in &report.warnings {
            let _ = writeln!(out, "{}", safe(warning));
        }
        if !report.warnings.is_empty() {
            let _ = writeln!(
                out,
                "{} overlapping pair(s): a command more than one action accepts is refused to \
                 an agent if any of them is human-only, and confirmed as strictly as the \
                 strictest demands",
                report.warnings.len()
            );
        }
    } else if let Some(note) = note {
        let _ = writeln!(out, "{note}");
    }
    if let Some(fuzz) = &report.fuzz {
        fuzz_lines(fuzz, out, err);
    }

    if report.results.is_empty() {
        if tests_only {
            let _ = writeln!(out, "tests: none");
        }
        return;
    }
    let failed = report.failed();
    let _ = writeln!(
        out,
        "tests: {} passed, {failed} failed",
        report.results.len().saturating_sub(failed)
    );
    for result in &report.results {
        failure(result, out);
    }
}

/// The fuzz summary on `out`, its findings on `err`. Every command is shown
/// twice, sanitized for the terminal and as hexadecimal bytes, because the
/// sanitized form cannot say which bytes were removed.
fn fuzz_lines(fuzz: &FuzzReport, out: &mut dyn Write, err: &mut dyn Write) {
    for finding in &fuzz.findings {
        let _ = writeln!(err, "xudo: fuzz: {}", safe(&finding.summary()));
        let _ = writeln!(err, "  command: {}", safe(&finding.escaped()));
        let _ = writeln!(err, "  bytes:   {}", finding.hex());
    }
    if fuzz.omitted > 0 {
        let _ = writeln!(
            err,
            "xudo: fuzz: {} more finding(s) not listed",
            fuzz.omitted
        );
    }
    let _ = writeln!(
        out,
        "fuzz: seed {}, {} candidate(s): {} accepted by one action, {} by several, {} by none; \
         {} finding(s)",
        fuzz.seed,
        fuzz.candidates,
        fuzz.accepted_by_one,
        fuzz.accepted_by_several,
        fuzz.accepted_by_none,
        fuzz.findings.len().saturating_add(fuzz.omitted)
    );
}

fn finding_json(finding: &Finding) -> Value {
    let (kind, actions) = match &finding.kind {
        FindingKind::MissedOverlap { first, second } => (
            "missed-overlap",
            vec![first.to_string(), second.to_string()],
        ),
        FindingKind::CanonicalizationUnstable => ("canonicalization-unstable", Vec::new()),
        FindingKind::AppendingWidens { .. } => ("appending-widens", Vec::new()),
    };
    json!({
        "kind": kind,
        "summary": finding.summary(),
        "actions": actions,
        "command_escaped": finding.escaped(),
        "command_hex": finding.hex(),
    })
}

fn fuzz_json(fuzz: &FuzzReport) -> Value {
    json!({
        "seed": fuzz.seed,
        "budget": fuzz.budget,
        "candidates": fuzz.candidates,
        "accepted_by_one": fuzz.accepted_by_one,
        "accepted_by_several": fuzz.accepted_by_several,
        "accepted_by_none": fuzz.accepted_by_none,
        "omitted": fuzz.omitted,
        "findings": fuzz.findings.iter().map(finding_json).collect::<Vec<_>>(),
    })
}

/// One failing test: what was expected, what happened, and what it ran. A
/// passing test says nothing.
fn failure(result: &TestResult, out: &mut dyn Write) {
    let test = &result.test;
    let (label, what) = match &result.outcome {
        TestOutcome::Fail {
            actual,
            denial,
            decided_by,
        } => (
            "FAIL",
            format!(
                "expected {}{}, got {actual}{}{}",
                test.expect,
                test.action
                    .as_ref()
                    .map_or(String::new(), |id| format!(" from {}", safe(id.as_str()))),
                denial.map_or(String::new(), |code| format!(" ({})", code.as_str())),
                decided_by
                    .as_ref()
                    .map_or(String::new(), |id| format!(" by {}", safe(id.as_str())))
            ),
        ),
        TestOutcome::Error(error) => ("ERROR", safe(&error.to_string())),
        TestOutcome::Pass => return,
    };
    let _ = writeln!(
        out,
        "{label} {}:{}: {what}",
        safe(&test.source.file),
        test.source.line
    );
    let argv: Vec<String> = test.argv.iter().map(|word| safe(word)).collect();
    let _ = writeln!(out, "  argv: {}", argv.join(" "));
    if let Some(reason) = &test.reason {
        let _ = writeln!(out, "  reason: {}", safe(reason));
    }
}

/// The machine-readable report. Strings are JSON-escaped, not sanitized: the
/// consumer is a program, and it gets the bytes the rule file holds.
fn envelope(report: &Report, status: ExitCode, note: Option<&str>) -> Value {
    let results: Vec<Value> = report.results.iter().map(result_json).collect();
    // A map, not `json!` then `as_object_mut`: that `if let` has a `None` arm
    // `json!` can never take, and coverage has nothing to mark it with.
    let mut fields = Map::new();
    fields.insert("schema_version".to_owned(), json!(SCHEMA_VERSION));
    fields.insert("exit_code".to_owned(), json!(status.as_i32()));
    let mut lint = Map::new();
    lint.insert(
        "errors".to_owned(),
        json!(
            report
                .errors
                .iter()
                .map(|(id, classes)| json!({ "action": id, "classes": classes }))
                .collect::<Vec<_>>()
        ),
    );
    lint.insert("warnings".to_owned(), json!(report.warnings));
    // Absent when nothing matched, so a run with no such rule stays byte for
    // byte what it was.
    if !report.open_units.is_empty() {
        lint.insert(
            "open_unit_lints".to_owned(),
            json!(
                report
                    .open_units
                    .iter()
                    .map(|open| json!({
                        "action": open.action,
                        "file": open.file,
                        "line": open.line,
                        "message": open.message,
                    }))
                    .collect::<Vec<_>>()
            ),
        );
    }
    fields.insert("lint".to_owned(), Value::Object(lint));
    fields.insert(
        "tests".to_owned(),
        json!({
            "total": report.results.len(),
            "failed": report.failed(),
            "results": results,
        }),
    );
    // Only when asked for, so a run without `--fuzz` is byte for byte what it
    // was. The lifecycle note is the same: absent when the rule is loaded.
    if let Some(fuzz) = &report.fuzz {
        fields.insert("fuzz".to_owned(), fuzz_json(fuzz));
    }
    if let Some(note) = note {
        fields.insert("note".to_owned(), json!(note));
    }
    Value::Object(fields)
}

fn result_json(result: &TestResult) -> Value {
    let test = &result.test;
    let mut fields: Vec<(&str, Value)> = vec![
        ("file", json!(test.source.file)),
        ("line", json!(test.source.line)),
        ("argv", json!(test.argv)),
        ("expect", json!(test.expect)),
        ("action", json!(test.action)),
        ("reason", json!(test.reason)),
    ];
    match &result.outcome {
        TestOutcome::Pass => fields.push(("outcome", json!("pass"))),
        TestOutcome::Fail {
            actual,
            denial,
            decided_by,
        } => fields.extend([
            ("outcome", json!("fail")),
            ("actual", json!(actual)),
            ("denial", json!(denial.map(DenialCode::as_str))),
            ("decided_by", json!(decided_by)),
        ]),
        TestOutcome::Error(error) => fields.extend([
            ("outcome", json!("error")),
            (
                "error",
                json!(match error {
                    TestError::EmptyArgv => "empty-argv",
                    TestError::UnknownAction(_) => "unknown-action",
                }),
            ),
            ("message", json!(error.to_string())),
        ]),
    }
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

/// Text from a rule file, made safe for a terminal and flagged when anything
/// was removed.
fn safe(text: &str) -> String {
    let Clean { text, findings } = term_sanitize::display_str(text, LIMITS);
    if findings.is_empty() {
        return text;
    }
    let what: Vec<String> = findings.iter().map(ToString::to_string).collect();
    format!("{text} [{}]", what.join("; "))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use xudo_policy::{ActionId, Arg, Argv};

    use super::*;

    fn report() -> FuzzReport {
        let finding = |kind| Finding {
            kind,
            exe: Arg::from("/usr/bin/x"),
            argv: Argv::new([Arg::new(b"a\x1b[2J\xff".to_vec())]),
        };
        FuzzReport {
            seed: 9,
            budget: 100,
            candidates: 100,
            accepted_by_one: 60,
            accepted_by_several: 10,
            accepted_by_none: 30,
            findings: vec![
                finding(FindingKind::MissedOverlap {
                    first: ActionId::new("a.one"),
                    second: ActionId::new("a.two"),
                }),
                finding(FindingKind::CanonicalizationUnstable),
                finding(FindingKind::AppendingWidens {
                    appended: Arg::from("x"),
                }),
            ],
            omitted: 2,
        }
    }

    #[test]
    fn a_fuzz_finding_is_shown_sanitized_and_as_bytes() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        fuzz_lines(&report(), &mut out, &mut err);
        let (out, err) = (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        );
        assert!(!err.contains('\u{1b}'), "{err:?}");
        insta::assert_snapshot!("fuzz_stdout", out);
        insta::assert_snapshot!("fuzz_stderr", err);
    }

    #[test]
    fn a_hostile_action_id_in_a_fuzz_finding_is_not_printed_raw() {
        let mut hostile = report();
        hostile.findings = vec![Finding {
            kind: FindingKind::MissedOverlap {
                first: ActionId::new("a\u{1b}[31mred\nxudo: forged\u{202e}"),
                second: ActionId::new("a.two"),
            },
            exe: Arg::from("/usr/bin/x"),
            argv: Argv::new([Arg::from("a")]),
        }];
        let (mut out, mut err) = (Vec::new(), Vec::new());
        fuzz_lines(&hostile, &mut out, &mut err);
        let err = String::from_utf8(err).unwrap();
        assert!(!err.contains('\u{1b}'), "{err:?}");
        assert!(!err.contains('\u{202e}'), "{err:?}");
        let finding_lines = err.lines().filter(|l| l.starts_with("xudo: fuzz:")).count();
        assert_eq!(finding_lines, 2, "the id forged a line: {err:?}");
        assert!(!err.contains("\nxudo: forged"), "{err:?}");
    }

    #[test]
    fn a_fuzz_finding_sets_the_lint_error_status_and_the_envelope_lists_it() {
        let mut found = Report {
            errors: Vec::new(),
            open_units: Vec::new(),
            warnings: Vec::new(),
            results: Vec::new(),
            fuzz: Some(report()),
        };
        assert_eq!(found.status(), ExitCode::LintError);
        let json = envelope(&found, found.status(), None);
        insta::assert_snapshot!(
            "fuzz_envelope",
            serde_json::to_string_pretty(&json).unwrap()
        );

        found.fuzz = found.fuzz.map(|mut f| {
            f.findings.clear();
            f.omitted = 0;
            f
        });
        assert_eq!(found.status(), ExitCode::Delegated);
    }
}
