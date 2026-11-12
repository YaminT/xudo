//! Executable tests that live inside a rule file.
//!
//! A rule file may carry `[[test]]` tables beside its `[[action]]` tables:
//!
//! ```toml
//! [[test]]
//! argv = ["/usr/bin/apt-get", "install", "ripgrep"]
//! expect = "allow"            # or "deny", or "confirm"
//! action = "xudo.pkg.install" # optional: the action that must decide it
//! reason = "the common case"  # optional: shown when the test fails
//! ```
//!
//! # A test is not policy
//!
//! A test can never change a decision. It is parsed into a [`RuleTest`] that
//! the loader keeps *beside* the [`RuleSet`], never inside it, so nothing the
//! engine reads has a test in it. It is also not part of the ruleset
//! generation (see [`crate::files::Generation`]): editing a test must not
//! invalidate a request the broker minted, because the policy did not change.
//! The property `test_blocks_never_affect_evaluation` pins both.
//!
//! # One engine
//!
//! [`run_tests`] asks the same two functions `xudo explain` asks:
//! [`evaluate_command`] when a test names no action, and [`evaluate`] pinned
//! to the named action when it does. There is no second evaluator to drift.
//!
//! A test is decided for the caller and settings handed in. `xudo check`
//! passes an unattested human and the default settings, so a result never
//! depends on the machine it ran on.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::argv::{Arg, Argv};
use crate::caller::CallerFacts;
use crate::decision::{DenialCode, Verdict};
use crate::engine::{Request, Settings, evaluate, evaluate_command};
use crate::rule::{ActionId, RuleSet, Source};

/// What a test expects the engine to decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Expectation {
    /// Permitted with no confirmation.
    Allow,
    /// Refused.
    Deny,
    /// Permitted once a human approves.
    Confirm,
}

impl Expectation {
    /// The word the rule file and the reports use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Confirm => "confirm",
        }
    }

    fn of(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Allow,
            Verdict::AllowWithConfirmation => Self::Confirm,
            Verdict::Deny => Self::Deny,
        }
    }
}

impl fmt::Display for Expectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `[[test]]` table.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuleTest {
    /// The program, then its operands, compared byte for byte.
    pub argv: Vec<String>,
    /// What the engine must decide.
    pub expect: Expectation,
    /// The action that must decide it: evaluated pinned to it, as `xudo
    /// explain --action` does, and a permitted command must be cited to it,
    /// not to a stricter action that also accepts the command. Without one,
    /// every action that runs the program takes part, as in `xudo explain`.
    #[serde(default)]
    pub action: Option<ActionId>,
    /// Human text shown when the test fails. Display only.
    #[serde(default)]
    pub reason: Option<String>,
    /// Where the test is declared. Assigned by the loader, never the file.
    #[serde(skip)]
    pub source: Source,
}

/// Why a test could not be run at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "kebab-case")]
pub enum TestError {
    /// The test names no program.
    #[error("argv is empty: a test names a program first")]
    EmptyArgv,
    /// The test names an action the ruleset does not define.
    #[error("unknown action id {0}")]
    UnknownAction(ActionId),
}

/// What running one test showed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TestOutcome {
    /// The engine decided what the test expected.
    Pass,
    /// The engine decided otherwise.
    Fail {
        /// What the engine decided.
        actual: Expectation,
        /// The denial code, when it refused.
        denial: Option<DenialCode>,
        /// The action the decision cites, when one matched.
        decided_by: Option<ActionId>,
    },
    /// The test could not be run.
    Error(TestError),
}

impl TestOutcome {
    /// Whether the test passed.
    pub fn passed(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// One test with what running it showed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TestResult {
    /// The test.
    pub test: RuleTest,
    /// The outcome.
    pub outcome: TestOutcome,
}

/// Runs every test against `rules`, in order.
///
/// Pure, and read-only: it evaluates, it does not change `rules`.
pub fn run_tests(
    rules: &RuleSet,
    tests: &[RuleTest],
    caller: &CallerFacts,
    settings: Settings,
) -> Vec<TestResult> {
    tests
        .iter()
        .map(|test| TestResult {
            outcome: run_one(rules, test, caller, settings),
            test: test.clone(),
        })
        .collect()
}

fn run_one(
    rules: &RuleSet,
    test: &RuleTest,
    caller: &CallerFacts,
    settings: Settings,
) -> TestOutcome {
    let Some((program, operands)) = test.argv.split_first() else {
        return TestOutcome::Error(TestError::EmptyArgv);
    };
    let argv = Argv::new(operands.iter().map(String::as_str).collect::<Vec<_>>());
    let decision = if let Some(action) = &test.action {
        if rules.get(action).is_none() {
            return TestOutcome::Error(TestError::UnknownAction(action.clone()));
        }
        evaluate(
            rules,
            caller,
            &Request::for_program(action.clone(), program.as_str(), argv),
            settings,
        )
    } else {
        evaluate_command(rules, caller, &Arg::from(program.as_str()), &argv, settings)
    };
    let actual = Expectation::of(decision.verdict);
    // `action` is the action that must decide the command. A refusal cites no
    // action, so it is judged on the verdict alone; a permitted command must be
    // cited to the named action, which it is not when a stricter overlapping
    // action carried the decision.
    let cited_elsewhere = test
        .action
        .as_ref()
        .is_some_and(|named| decision.action.as_ref().is_some_and(|by| by != named));
    if actual == test.expect && !cited_elsewhere {
        TestOutcome::Pass
    } else {
        TestOutcome::Fail {
            actual,
            denial: decision.denial,
            decided_by: decision.action,
        }
    }
}

/// Finds the 1-based line of the `index`th `[[test]]` header, or 0.
pub(crate) fn line_of_test(contents: &str, index: usize) -> u32 {
    contents
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim_start().starts_with("[[test]]"))
        .nth(index)
        .map_or(0, |(line, _)| {
            u32::try_from(line.saturating_add(1)).unwrap_or(u32::MAX)
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use crate::caller::Classification;

    const RULES: &str = r#"
[[action]]
id = "xudo.pkg.update"
tier = "pkg-install"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]

[[action]]
id = "xudo.pkg.purge"
tier = "critical"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "purge" } }]
"#;

    fn load(tests: &str) -> (RuleSet, Vec<RuleTest>) {
        RuleSet::from_toml_with_tests("t.toml", &format!("{RULES}\n{tests}")).unwrap()
    }

    fn run(tests: &str) -> Vec<TestOutcome> {
        let (rules, tests) = load(tests);
        let human = CallerFacts::new(Classification::Human, 1000);
        run_tests(&rules, &tests, &human, Settings::default())
            .into_iter()
            .map(|r| r.outcome)
            .collect()
    }

    #[test]
    fn expectations_render_and_parse_in_kebab_case() {
        for (word, want) in [
            ("allow", Expectation::Allow),
            ("deny", Expectation::Deny),
            ("confirm", Expectation::Confirm),
        ] {
            assert_eq!(want.as_str(), word);
            assert_eq!(want.to_string(), word);
            let parsed: RuleTest =
                toml::from_str(&format!("argv = [\"/x\"]\nexpect = \"{word}\"\n")).unwrap();
            assert_eq!(parsed.expect, want);
        }
        assert_eq!(
            Expectation::of(Verdict::AllowWithConfirmation),
            Expectation::Confirm
        );
    }

    #[test]
    fn a_test_block_with_an_unknown_key_is_a_hard_parse_failure() {
        for body in [
            "argv = [\"/x\"]\nexpect = \"allow\"\nnopasswd = true\n",
            "argv = [\"/x\"]\nexpect = \"allow\"\nsource = { file = \"a\", line = 1 }\n",
        ] {
            let err =
                RuleSet::from_toml_with_tests("t.toml", &format!("[[test]]\n{body}")).unwrap_err();
            assert!(err.to_string().contains("t.toml"));
            // `from_toml` refuses it too: the gate and the broker load through it.
            assert!(RuleSet::from_toml("t.toml", &format!("[[test]]\n{body}")).is_err());
        }
    }

    #[test]
    fn malformed_test_blocks_are_refused() {
        for body in [
            "argv = \"/usr/bin/id\"\nexpect = \"allow\"\n",
            "argv = [\"/x\", 1]\nexpect = \"allow\"\n",
            "argv = [\"/x\"]\nexpect = \"maybe\"\n",
            "argv = [\"/x\"]\nexpect = \"Allow\"\n",
            "argv = [\"/x\"]\n",
            "expect = \"allow\"\n",
        ] {
            assert!(
                RuleSet::from_toml_with_tests("t.toml", &format!("[[test]]\n{body}")).is_err(),
                "{body}"
            );
        }
    }

    #[test]
    fn a_test_cannot_sit_where_an_action_does() {
        // `test` is a top-level table; one nested in an action is an unknown key.
        let nested = format!("{RULES}\n[[action.test]]\nargv = [\"/x\"]\nexpect = \"deny\"\n");
        assert!(RuleSet::from_toml("t.toml", &nested).is_err());
    }

    #[test]
    fn tests_pass_fail_and_keep_their_provenance() {
        let (rules, tests) = load(
            r#"
[[test]]
argv = ["/usr/bin/apt-get", "update"]
expect = "allow"

[[test]]
argv = ["/usr/bin/apt-get", "update"]
expect = "deny"
reason = "wrong on purpose"

[[test]]
argv = ["/usr/bin/apt-get", "purge"]
expect = "confirm"
action = "xudo.pkg.purge"
"#,
        );
        let human = CallerFacts::new(Classification::Human, 1000);
        let results = run_tests(&rules, &tests, &human, Settings::default());
        assert_eq!(results.len(), 3);
        assert!(results.first().unwrap().outcome.passed());
        assert_eq!(
            results.get(1).unwrap().outcome,
            TestOutcome::Fail {
                actual: Expectation::Allow,
                denial: None,
                decided_by: Some(ActionId::new("xudo.pkg.update")),
            }
        );
        assert!(results.get(2).unwrap().outcome.passed());
        assert_eq!(
            results.get(1).unwrap().test.reason.as_deref(),
            Some("wrong on purpose")
        );
        assert_eq!(results.get(1).unwrap().test.source.line, 19);
    }

    #[test]
    fn a_denied_command_fails_an_allow_test_and_names_the_code() {
        let outcomes = run(
            "[[test]]\nargv = [\"/usr/bin/apt-get\", \"update\", \"-y\"]\nexpect = \"allow\"\n",
        );
        assert_eq!(
            outcomes,
            [TestOutcome::Fail {
                actual: Expectation::Deny,
                denial: Some(DenialCode::ArgvRejected),
                decided_by: None,
            }]
        );
    }

    #[test]
    fn a_test_that_names_an_unknown_action_fails() {
        let outcomes = run(
            "[[test]]\nargv = [\"/usr/bin/apt-get\", \"update\"]\nexpect = \"deny\"\naction = \"xudo.nope\"\n",
        );
        // Not a pass, though the engine would deny an unknown action: the test
        // is wrong, and a wrong test that happens to expect a denial is the
        // quiet kind.
        assert_eq!(
            outcomes,
            [TestOutcome::Error(TestError::UnknownAction(ActionId::new(
                "xudo.nope"
            )))]
        );
        assert!(!outcomes.first().unwrap().passed());
        assert_eq!(
            TestError::UnknownAction(ActionId::new("xudo.nope")).to_string(),
            "unknown action id xudo.nope"
        );
    }

    #[test]
    fn a_test_with_no_program_is_an_error() {
        let outcomes = run("[[test]]\nargv = []\nexpect = \"deny\"\n");
        assert_eq!(outcomes, [TestOutcome::Error(TestError::EmptyArgv)]);
        assert!(TestError::EmptyArgv.to_string().contains("empty"));
    }

    #[test]
    fn a_named_action_decides_even_when_another_would_accept() {
        // Pinned to the action that does not accept the argv: a refusal about
        // that action, as `xudo explain --action` gives.
        let outcomes = run(
            "[[test]]\nargv = [\"/usr/bin/apt-get\", \"purge\"]\nexpect = \"deny\"\naction = \"xudo.pkg.update\"\n",
        );
        assert_eq!(outcomes, [TestOutcome::Pass]);
    }

    #[test]
    fn a_stricter_overlapping_action_deciding_fails_a_test_that_names_another() {
        let rules = RuleSet::from_toml(
            "t.toml",
            r#"
[[action]]
id = "xudo.a"
tier = "pkg-install"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]

[[action]]
id = "xudo.b"
tier = "critical"
exe = "/usr/bin/apt-get"
args = [{ name = "verb", matcher = { literal = "update" } }]
"#,
        )
        .unwrap();
        let human = CallerFacts::new(Classification::Human, 1000);
        let test = |action: &str| RuleTest {
            argv: vec!["/usr/bin/apt-get".into(), "update".into()],
            expect: Expectation::Confirm,
            action: Some(ActionId::new(action)),
            reason: None,
            source: Source::default(),
        };
        let run = |action: &str| {
            run_tests(&rules, &[test(action)], &human, Settings::default())
                .remove(0)
                .outcome
        };
        // The verdicts agree; the citation does not.
        assert_eq!(
            run("xudo.a"),
            TestOutcome::Fail {
                actual: Expectation::Confirm,
                denial: None,
                decided_by: Some(ActionId::new("xudo.b")),
            }
        );
        assert_eq!(run("xudo.b"), TestOutcome::Pass);
    }

    #[test]
    fn the_test_header_is_located_by_order() {
        let text = "x\n[[test]]\n  [[test]]\n";
        assert_eq!(line_of_test(text, 0), 2);
        assert_eq!(line_of_test(text, 1), 3);
        assert_eq!(line_of_test(text, 2), 0);
    }
}
