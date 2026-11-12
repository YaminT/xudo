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

use serde_json::{Value, json};
use term_sanitize::{Clean, Limits};
use xudo_policy::{
    CallerFacts, Classification, DenialCode, ExitCode, TestError, TestOutcome, TestResult,
    engine::Settings, run_tests,
};

use crate::cli::{Cli, Format};
use crate::rules::LoadedRules;

/// The envelope's schema version.
const SCHEMA_VERSION: u32 = 1;

/// One rendered line is at most this many columns.
const LIMITS: Limits = Limits {
    max_cols: 200,
    max_lines: 1,
};

/// Everything one run found.
struct Report {
    /// A rule that allowlists what the deny-list refuses: the id and the classes.
    errors: Vec<(String, Vec<String>)>,
    /// One rendered overlap each.
    warnings: Vec<String>,
    results: Vec<TestResult>,
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
            (!self.errors.is_empty()).then_some(ExitCode::LintError),
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
/// `tests_only` skips the lint.
pub(crate) fn run(
    cli: &Cli,
    loaded: &LoadedRules,
    tests_only: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    let (errors, warnings) = if tests_only {
        (Vec::new(), Vec::new())
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
                .overlaps()
                .iter()
                .map(ToString::to_string)
                .collect(),
        )
    };
    let human = CallerFacts::new(Classification::Human, 1000);
    let report = Report {
        errors,
        warnings,
        results: run_tests(loaded.rules(), loaded.tests(), &human, Settings::default()),
    };
    let status = report.status();
    match cli.output {
        Format::Human => human_report(loaded, &report, tests_only, out, err),
        Format::Json => {
            let _ = writeln!(out, "{}", envelope(&report, status));
        }
    }
    status
}

fn human_report(
    loaded: &LoadedRules,
    report: &Report,
    tests_only: bool,
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

    if !tests_only {
        if report.errors.is_empty() {
            let _ = writeln!(
                out,
                "ok: {} action(s) in {} file(s), generation {}",
                loaded.rules().len(),
                loaded.files().len(),
                loaded.generation().get(..12).unwrap_or(loaded.generation())
            );
        }
        // Reported, not refused: the engine resolves a command more than one
        // action accepts to the strictest of them, so an overlap is not a hole.
        // It is still two rules whose interaction nobody wrote down, and the
        // report never stays silent about a pair it cannot decide.
        for warning in &report.warnings {
            let _ = writeln!(out, "{warning}");
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
fn envelope(report: &Report, status: ExitCode) -> Value {
    let results: Vec<Value> = report.results.iter().map(result_json).collect();
    json!({
        "schema_version": SCHEMA_VERSION,
        "exit_code": status.as_i32(),
        "lint": {
            "errors": report
                .errors
                .iter()
                .map(|(id, classes)| json!({ "action": id, "classes": classes }))
                .collect::<Vec<_>>(),
            "warnings": report.warnings,
        },
        "tests": {
            "total": report.results.len(),
            "failed": report.failed(),
            "results": results,
        },
    })
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
