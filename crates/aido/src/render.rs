//! Turning a decision into something a human or an agent can act on.
//!
//! Two renderers over the same decision, deliberately: a human reads the trace,
//! and an agent branches on the envelope. Neither is a summary of the other.

use std::fmt::Write as _;

use aido_policy::{Confirm, Decision, TraceStep, Verdict};

/// Renders a decision as prose, with the trace.
///
/// The trace is the point. An allowlist nobody can interrogate is an allowlist
/// nobody trusts, so this shows every rule considered, why each was skipped, and
/// which `file:line` decided the outcome.
pub fn human(decision: &Decision) -> String {
    let mut out = String::new();

    let headline = match decision.verdict {
        Verdict::Allow => "ALLOW",
        Verdict::AllowWithConfirmation => "ALLOW, after a human confirms",
        Verdict::Deny => "DENY",
    };
    let _ = writeln!(out, "{headline}");

    if !decision.resolved_argv.is_empty() {
        let _ = writeln!(out, "  command   {}", decision.resolved_argv.join(" "));
    }
    if let Some(action) = &decision.action {
        let _ = writeln!(out, "  action    {action}");
    }
    if let Some(source) = &decision.rule_source {
        let _ = writeln!(out, "  rule      {source}");
    }
    if let Some(code) = decision.denial {
        let _ = writeln!(out, "  reason    {}", code.as_str());
    }
    if let Confirm::Required { reason } = &decision.confirm {
        let _ = writeln!(out, "  confirm   {}", reason.explain());
    }

    let _ = writeln!(out, "\n  trace");
    for step in &decision.trace {
        let _ = writeln!(out, "    {}", trace_line(step));
    }

    if let Some(remediation) = &decision.remediation {
        let _ = writeln!(out, "\n  next      {remediation}");
    }

    out
}

/// One trace step, as a single line.
fn trace_line(step: &TraceStep) -> String {
    match step {
        TraceStep::Canonicalized { before, after } => {
            if before == after {
                format!("canonicalized: unchanged ({before})")
            } else {
                format!("canonicalized: {before}  ->  {after}")
            }
        }
        TraceStep::ActionRejected { action, reason } => format!("skipped {action}: {reason}"),
        TraceStep::ActionMatched { action, source } => format!("matched {action} at {source}"),
        TraceStep::DenyListEvaluated { version, matched } => {
            if matched.is_empty() {
                format!("deny-list v{version}: no capability class matched")
            } else {
                format!("deny-list v{version}: {}", matched.join("; "))
            }
        }
        TraceStep::ConfirmationDecided { required, reason } => {
            let state = if *required {
                "required"
            } else {
                "not required"
            };
            format!("confirmation {state}: {reason}")
        }
    }
}

/// Renders a decision as the machine-readable envelope.
///
/// Infallible by construction. `Decision` holds only strings, enums, `Vec`,
/// `Option`, and `u32`, so `serde_json` has no failure mode on it — but rather
/// than propagate an error nobody can trigger, or unwrap and risk a panic in a
/// decision path, a serializer failure degrades to [`fallback`]: a denial
/// envelope. Failing closed is the only correct answer to "aido cannot describe
/// its own decision".
pub fn json(decision: &Decision) -> String {
    to_pretty(decision)
}

/// Renders any serializable value, degrading the same way [`json`] does.
///
/// Used for the configuration schema, which is plain data for the same reason a
/// `Decision` is, and which therefore needs no error path either.
pub fn json_of<T: serde::Serialize>(value: &T) -> String {
    to_pretty(value)
}

/// Serializes anything, degrading to a denial envelope on failure.
fn to_pretty<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|e| fallback(&e))
}

/// The envelope emitted when serialization itself fails.
///
/// Hand-built from string literals so it cannot fail for the same reason the
/// original did, and shaped as a denial so a consumer that only reads
/// `verdict` still refuses to proceed.
fn fallback(error: &serde_json::Error) -> String {
    format!(
        "{{\n  \"schema_version\": {},\n  \"verdict\": \"deny\",\n  \
         \"denial\": \"policy_unloadable\",\n  \"remediation\": \
         \"aido could not serialize its own decision ({error}); treat this as a denial \
         and report it as a bug\"\n}}",
        aido_policy::decision::ENVELOPE_SCHEMA_VERSION
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use aido_policy::{
        Argv, CallerFacts, Classification, DenialCode, Request, RuleSet, engine::Settings,
    };

    fn decide(argv: &[&str], agent: bool) -> Decision {
        let set = RuleSet::from_toml(
            "20-services.toml",
            r#"
[[action]]
id = "aido.svc.restart"
tier = "svc-control"
exe = "/usr/bin/systemctl"
args = [
  { name = "verb", matcher = { literal = "restart" } },
  { name = "unit", matcher = { name = "unit-name" } },
]
"#,
        )
        .unwrap();
        let caller = if agent {
            CallerFacts::new(
                Classification::EnrolledAgent {
                    agent_id: "claude-code".into(),
                    session_id: "s".into(),
                    declared_yolo: true,
                },
                1000,
            )
        } else {
            CallerFacts::new(Classification::Human, 1000)
        };
        aido_policy::evaluate(
            &set,
            &caller,
            &Request::new("aido.svc.restart", Argv::new(argv.to_vec())),
            Settings::default(),
        )
    }

    #[test]
    fn an_allow_renders_the_rule_and_the_trace() {
        let text = human(&decide(&["restart", "nginx.service"], false));
        assert!(text.starts_with("ALLOW\n"), "{text}");
        assert!(text.contains("restart nginx.service"));
        assert!(text.contains("aido.svc.restart"));
        assert!(text.contains("20-services.toml:3"));
        assert!(text.contains("no capability class matched"));
        assert!(text.contains("confirmation not required"));
        assert!(!text.contains("next "), "an allow has no remediation");
    }

    #[test]
    fn a_confirmation_renders_the_reason_a_human_will_be_shown() {
        let text = human(&decide(&["restart", "nginx.service"], true));
        assert!(text.starts_with("ALLOW, after a human confirms"), "{text}");
        assert!(text.contains("confirm_agent_actions is on"), "{text}");
        assert!(text.contains("confirmation required"), "{text}");
    }

    #[test]
    fn a_denial_renders_the_code_and_the_next_step() {
        let text = human(&decide(&["restart", "nginx"], false));
        assert!(text.starts_with("DENY\n"), "{text}");
        assert!(text.contains("argv_rejected"));
        assert!(text.contains("next "), "a denial must name a next step");
        assert!(text.contains("aido explain"), "{text}");
        assert!(text.contains("does not satisfy unit"), "{text}");
    }

    #[test]
    fn an_unchanged_canonicalization_says_so_rather_than_repeating_itself() {
        let text = human(&decide(&["restart", "nginx.service"], false));
        assert!(text.contains("canonicalized: unchanged"), "{text}");
    }

    #[test]
    fn a_changed_canonicalization_shows_both_forms() {
        // A trailing separator is dropped, so before and after differ.
        let set = RuleSet::from_toml(
            "f.toml",
            r#"
[[action]]
id = "a"
tier = "diag-read"
exe = "/usr/bin/true"
args = [{ name = "v", matcher = { literal = "x" } }]
"#,
        )
        .unwrap();
        let decision = aido_policy::evaluate(
            &set,
            &CallerFacts::new(Classification::Human, 0),
            &Request::new("a", Argv::new(["x", "--"])),
            Settings::default(),
        );
        let text = human(&decision);
        assert!(text.contains("->"), "{text}");
    }

    #[test]
    fn a_deny_listed_command_names_the_capability_class_in_the_trace() {
        let set = RuleSet::from_toml(
            "99-oops.toml",
            r#"
[[action]]
id = "aido.oops"
tier = "diag-read"
exe = "/bin/sh"
args = [{ name = "c", matcher = { literal = "-c" } }]
"#,
        )
        .unwrap();
        let decision = aido_policy::evaluate(
            &set,
            &CallerFacts::new(Classification::Human, 0),
            &Request::new("aido.oops", Argv::new(["-c"])),
            Settings::default(),
        );
        let text = human(&decision);
        assert!(text.contains("deny_listed"));
        assert!(text.contains("SpawnsShell"), "{text}");
        // The rule matched first, and the trace has to show that, or an
        // operator cannot tell why their rule had no effect.
        assert!(text.contains("matched aido.oops"), "{text}");
    }

    #[test]
    fn an_unknown_action_renders_without_an_action_or_a_rule_line() {
        let set = RuleSet::default();
        let decision = aido_policy::evaluate(
            &set,
            &CallerFacts::new(Classification::Human, 0),
            &Request::new("aido.nope", Argv::default()),
            Settings::default(),
        );
        let text = human(&decision);
        assert!(text.contains("unknown_action"));
        assert!(!text.contains("  action  "), "{text}");
        assert!(!text.contains("  rule  "), "{text}");
        assert!(!text.contains("  command  "), "{text}");
    }

    #[test]
    fn the_envelope_is_valid_json_carrying_the_schema_version() {
        let decision = decide(&["restart", "nginx.service"], false);
        let text = json(&decision);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["verdict"], "allow");
        assert_eq!(parsed["action"], "aido.svc.restart");
        assert!(parsed["trace"].is_array());
    }

    #[test]
    fn a_denial_envelope_carries_a_stable_code_and_a_remediation() {
        // What an agent branches on. The code must be the stable string, not a
        // human sentence.
        let decision = decide(&["restart", "nginx"], false);
        let text = json(&decision);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["denial"], DenialCode::ArgvRejected.as_str());
        assert!(parsed["remediation"].as_str().is_some_and(|s| s.len() > 20));
    }

    #[test]
    fn a_serializer_failure_degrades_to_a_denial_envelope() {
        // Unreachable for a Decision, which is why the fallback is exercised
        // through a type that genuinely cannot serialize. The property that
        // matters is the direction of the degradation: a denial, never a
        // half-written allow.
        struct Unserializable;

        impl serde::Serialize for Unserializable {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("test: cannot serialize"))
            }
        }

        let text = to_pretty(&Unserializable);
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["verdict"], "deny");
        assert_eq!(parsed["denial"], "policy_unloadable");
        assert_eq!(parsed["schema_version"], 1);
        assert!(
            parsed["remediation"]
                .as_str()
                .is_some_and(|s| s.contains("cannot serialize")),
            "{text}"
        );
    }

    #[test]
    fn every_trace_step_variant_has_a_rendering() {
        let steps = [
            TraceStep::Canonicalized {
                before: "a".into(),
                after: "a".into(),
            },
            TraceStep::Canonicalized {
                before: "a".into(),
                after: "b".into(),
            },
            TraceStep::ActionRejected {
                action: "x".into(),
                reason: "y".into(),
            },
            TraceStep::ActionMatched {
                action: "x".into(),
                source: "f:1".into(),
            },
            TraceStep::DenyListEvaluated {
                version: 1,
                matched: Vec::new(),
            },
            TraceStep::DenyListEvaluated {
                version: 1,
                matched: vec!["SpawnsShell: /bin/sh".into()],
            },
            TraceStep::ConfirmationDecided {
                required: true,
                reason: "r".into(),
            },
            TraceStep::ConfirmationDecided {
                required: false,
                reason: "r".into(),
            },
        ];
        for step in &steps {
            assert!(trace_line(step).len() > 5, "{step:?}");
        }
    }
}
