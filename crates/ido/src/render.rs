//! Turning queue entries into text a human can trust.
//!
//! Every field an agent wrote — argv, reason, cwd, group, cloud target — goes
//! through [`term_sanitize`] before it reaches a terminal, and every warning the
//! sanitizer raises is shown beside the entry rather than swallowed. The argv
//! is rendered token by token, quoting any token that is not plainly safe, so
//! the human sees exactly the vector that will be executed and never a
//! reconstructed shell string.
//!
//! The rendered text is for eyes only. Execution uses the stored bytes.

use std::fmt::Write as _;

use serde_json::json;
use term_sanitize::{Clean, Finding, Limits, display_str, flag_command_name};

use crate::consequence::assess;
use crate::entry::Entry;
use crate::status::{Status, run_order, status_of};

/// Width budget for one rendered field, before the caller's own clamp.
pub const FIELD_COLS: usize = 200;

/// Renders an argv as one display line, with everything to warn about.
#[must_use]
pub fn argv_line(argv: &[String], max_cols: usize) -> Clean {
    let mut text = String::new();
    let mut findings = Vec::new();
    if let Some(command) = argv.first() {
        findings.extend(flag_command_name(command));
    }
    for (i, token) in argv.iter().enumerate() {
        if i > 0 {
            text.push(' ');
        }
        let clean = display_str(token, Limits::single_line(max_cols));
        findings.extend(clean.findings);
        if is_plain(token) {
            text.push_str(&clean.text);
        } else {
            push_quoted(&mut text, &clean.text);
        }
    }
    let whole = display_str(&text, Limits::single_line(max_cols));
    findings.extend(whole.findings);
    Clean {
        text: whole.text,
        findings: dedup(findings),
    }
}

/// Renders one untrusted text field as a single display line.
#[must_use]
pub fn field(text: &str, max_cols: usize) -> Clean {
    display_str(text, Limits::single_line(max_cols))
}

/// Whether a token renders unambiguously without quotes.
fn is_plain(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/:=@%+,-".contains(c))
}

/// Appends `text` in double quotes, escaping the quote and the backslash.
fn push_quoted(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
}

/// Drops repeated findings, keeping the first of each.
fn dedup(findings: Vec<Finding>) -> Vec<Finding> {
    let mut kept: Vec<Finding> = Vec::new();
    for finding in findings {
        if !kept.contains(&finding) {
            kept.push(finding);
        }
    }
    kept
}

/// How long ago, coarsely.
#[must_use]
pub fn age(now_unix: u64, then_unix: u64) -> String {
    let secs = now_unix.saturating_sub(then_unix);
    match secs {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{}m ago", secs.checked_div(60).unwrap_or_default()),
        3600..86_400 => format!("{}h ago", secs.checked_div(3600).unwrap_or_default()),
        _ => format!("{}d ago", secs.checked_div(86_400).unwrap_or_default()),
    }
}

/// Everything a list row or a picker row shows about one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The argv, sanitized and quoted.
    pub head: String,
    /// One line of context: privilege, cloud target, age, author, reason.
    pub meta: String,
    /// One line per sanitizer finding, each starting with a warning sign.
    pub warnings: Vec<String>,
    /// Where the entry stands.
    pub status: Status,
    /// Whether running it needs a typed confirmation.
    pub high: bool,
}

/// Builds the row for `entry`.
#[must_use]
pub fn row(entry: &Entry, queue: &[Entry], now_unix: u64) -> Row {
    let head = argv_line(&entry.argv, FIELD_COLS);
    let mut findings = head.findings;
    let consequence = assess(&entry.argv);

    let mut meta: Vec<String> = Vec::new();
    meta.push(if consequence.elevates {
        "needs root".to_owned()
    } else {
        "no root".to_owned()
    });
    if let Some(tool) = &consequence.cloud {
        let mut cloud = tool.clone();
        for (key, value) in &consequence.targets {
            let value = field(value, 40);
            findings.extend(value.findings);
            let _ = write!(cloud, " {key}={}", value.text);
        }
        meta.push(cloud);
    }
    meta.push(format!("queued {}", age(now_unix, entry.queued_at)));
    if let Some(by) = &entry.queued_by {
        let by = field(by, 30);
        findings.extend(by.findings);
        meta.push(format!("by {} (unverified)", by.text));
    }
    if let Some(reason) = &entry.reason {
        let reason = field(reason, 80);
        findings.extend(reason.findings);
        meta.push(format!("\"{}\"", reason.text));
    }
    if let Some(cwd) = &entry.cwd {
        let cwd = field(cwd, 60);
        findings.extend(cwd.findings);
        meta.push(format!("in {}", cwd.text));
    }
    if !entry.needs.is_empty() {
        let ids: Vec<String> = entry.needs.iter().map(|id| format!("#{id}")).collect();
        meta.push(format!("needs {}", ids.join(" ")));
    }

    Row {
        head: head.text,
        meta: meta.join(" · "),
        warnings: dedup(findings)
            .iter()
            .map(|f| format!("\u{26A0} {f}"))
            .collect(),
        status: status_of(entry, queue, now_unix),
        high: consequence.is_high(),
    }
}

/// A group name for display.
#[must_use]
pub fn group_name(group: &str) -> String {
    field(group, 40).text
}

/// The plain-text queue, for `ido list` and for `ido` without a terminal.
#[must_use]
pub fn list(queue: &[Entry], now_unix: u64) -> String {
    if queue.is_empty() {
        return "ido: nothing queued\n".to_owned();
    }
    let mut out = format!("ido: {} queued\n", queue.len());
    let mut current_group: Option<&str> = None;
    let ordered = run_order(queue)
        .into_iter()
        .filter_map(|id| queue.iter().find(|e| e.id == id));
    for entry in ordered {
        let id = entry.id;
        let indent = if let Some(group) = &entry.group {
            if current_group != Some(group.as_str()) {
                let _ = writeln!(out, "\ngroup {}", group_name(group));
                current_group = Some(group.as_str());
            }
            "  "
        } else {
            if current_group.is_some() {
                out.push('\n');
            }
            current_group = None;
            ""
        };
        let row = row(entry, queue, now_unix);
        let step = entry.step.map(|s| format!("{s}. ")).unwrap_or_default();
        let _ = writeln!(
            out,
            "{indent}{step}#{id} {:<7} {}",
            row.status.label(),
            row.head
        );
        if let Some(detail) = row.status.detail() {
            let _ = writeln!(out, "{indent}    {}: {detail}", row.status.label());
        }
        let _ = writeln!(out, "{indent}    {}", row.meta);
        for warning in &row.warnings {
            let _ = writeln!(out, "{indent}    {warning}");
        }
    }
    out
}

/// The queue as JSON, for scripts.
///
/// The argv is exact — this is the machine interface — and the whole document
/// is ASCII: every non-ASCII character is written as a `\u` escape, so a
/// bidirectional override or a lookalike cannot act on a terminal that the
/// JSON happens to be printed to.
#[must_use]
pub fn json(queue: &[Entry], now_unix: u64) -> String {
    let entries: Vec<serde_json::Value> = run_order(queue)
        .into_iter()
        .filter_map(|id| queue.iter().find(|e| e.id == id))
        .map(|entry| {
            let status = status_of(entry, queue, now_unix);
            json!({
                "id": entry.id,
                "argv": entry.argv,
                "reason": entry.reason,
                "group": entry.group,
                "step": entry.step,
                "needs": entry.needs,
                "cwd": entry.cwd,
                "queued_at": entry.queued_at,
                "queued_by": entry.queued_by,
                "attempts": entry.attempts,
                "last_exit": entry.last_exit,
                "status": status.label(),
                "detail": status.detail(),
            })
        })
        .collect();
    let mut text = ascii_only(&serde_json::Value::Array(entries).to_string());
    text.push('\n');
    text
}

/// Escapes every non-ASCII character as `\uXXXX` (UTF-16, surrogate pairs
/// above the BMP). Valid only for JSON, where non-ASCII appears in strings.
fn ascii_only(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0_u16; 2];
            for unit in c.encode_utf16(&mut units) {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

    use super::*;
    use crate::entry::QUEUE_SCHEMA_VERSION;

    fn entry(id: u64, argv: &[&str]) -> Entry {
        Entry {
            schema_version: QUEUE_SCHEMA_VERSION,
            id,
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            reason: None,
            group: None,
            step: None,
            needs: Vec::new(),
            cwd: None,
            dry_run_of: Vec::new(),
            queued_at: 1000,
            queued_by: None,
            attempts: 0,
            last_exit: None,
        }
    }

    #[test]
    fn a_plain_argv_renders_as_its_tokens() {
        let line = argv_line(&["apt-get".into(), "install".into(), "-y".into()], 80);
        assert_eq!(line.text, "apt-get install -y");
        assert!(line.findings.is_empty());
    }

    #[test]
    fn a_token_with_spaces_or_shell_syntax_is_quoted_not_reinterpreted() {
        let line = argv_line(
            &[
                "echo".into(),
                "$(id)".into(),
                "a b".into(),
                String::new(),
                "say \"hi\" \\o/".into(),
            ],
            80,
        );
        assert_eq!(line.text, r#"echo "$(id)" "a b" "" "say \"hi\" \\o/""#);
    }

    #[test]
    fn ansi_escapes_in_a_reason_cannot_redraw_the_screen() {
        let mut e = entry(1, &["true"]);
        e.reason = Some("fine\u{1B}[2J\u{1B}[Hrm -rf /".into());
        let row = row(&e, std::slice::from_ref(&e), 1000);
        assert!(!row.meta.contains('\u{1B}'), "{:?}", row.meta);
        assert!(row.meta.contains("\"finerm -rf /\""), "{}", row.meta);
        assert!(
            row.warnings.iter().any(|w| w.contains("escape sequence")),
            "{:?}",
            row.warnings
        );
    }

    #[test]
    fn bidi_overrides_in_a_command_cannot_reorder_the_display() {
        // U+202E would display `echo safe` while the bytes say otherwise.
        let line = argv_line(&["echo".into(), "\u{202E}efas\u{2066}".into()], 80);
        assert!(!line.text.contains('\u{202E}'));
        assert!(!line.text.contains('\u{2066}'));
        // Rendered order is byte order: the remaining characters, in sequence.
        assert_eq!(line.text, "echo \"efas\"");
        assert!(
            line.findings.contains(&Finding::BidiOverrides { count: 2 }),
            "{:?}",
            line.findings
        );
    }

    #[test]
    fn a_homoglyph_binary_name_is_flagged_once() {
        let e = entry(1, &["\u{0430}ws", "s3", "ls"]);
        let row = row(&e, std::slice::from_ref(&e), 1000);
        let flagged: Vec<&String> = row
            .warnings
            .iter()
            .filter(|w| w.contains("U+0430"))
            .collect();
        assert_eq!(flagged.len(), 1, "{:?}", row.warnings);
        assert!(row.high);
    }

    #[test]
    fn an_overlong_argv_is_clamped_and_says_so() {
        let long = "x".repeat(500);
        let line = argv_line(&["echo".into(), long], 40);
        // At most the limit, plus the ellipsis that marks the cut.
        assert!(line.text.chars().count() <= 41, "{}", line.text);
        assert!(line.text.ends_with('\u{2026}'), "{}", line.text);
        assert!(line.findings.contains(&Finding::Truncated));
    }

    #[test]
    fn ages_are_coarse() {
        assert_eq!(age(100, 90), "just now");
        assert_eq!(age(1000, 100), "15m ago");
        assert_eq!(age(10_000, 0), "2h ago");
        assert_eq!(age(200_000, 0), "2d ago");
        assert_eq!(
            age(0, 100),
            "just now",
            "a future timestamp is not negative"
        );
    }

    #[test]
    fn a_row_carries_every_untrusted_field_sanitized() {
        let mut e = entry(2, &["aws", "s3", "rm", "--profile", "pr\u{1B}[0mod"]);
        e.reason = Some("clean up".into());
        e.queued_by = Some("claude-code".into());
        e.cwd = Some("/srv/app".into());
        e.needs = vec![1];
        let dep = entry(1, &["true"]);
        let row = row(&e, &[dep, e.clone()], 1000);
        assert_eq!(
            row.meta,
            "no root · aws profile=prod · queued just now · by claude-code (unverified) \
             · \"clean up\" · in /srv/app · needs #1"
        );
        assert!(row.high);
        assert_eq!(row.status.label(), "blocked");
        assert!(!row.warnings.is_empty());
    }

    #[test]
    fn an_elevated_command_says_it_needs_root() {
        let e = entry(1, &["sudo", "true"]);
        assert!(
            row(&e, std::slice::from_ref(&e), 1000)
                .meta
                .starts_with("needs root")
        );
    }

    #[test]
    fn the_list_groups_steps_under_their_group() {
        let a = entry(1, &["true"]);
        let mut s1 = entry(2, &["terraform", "plan"]);
        s1.group = Some("deploy".into());
        s1.step = Some(1);
        let mut s2 = entry(3, &["terraform", "apply"]);
        s2.group = Some("deploy".into());
        s2.step = Some(2);
        let b = entry(4, &["false"]);
        let text = list(&[a, s1, s2, b], 1000);
        assert!(text.starts_with("ido: 4 queued\n"), "{text}");
        assert!(text.contains("\ngroup deploy\n  1. #2 ready"), "{text}");
        assert!(text.contains("  2. #3 blocked"), "{text}");
        assert!(text.contains("blocked: step 1 has not run"), "{text}");
        assert!(text.contains("\n\n#4 ready   false"), "{text}");
    }

    #[test]
    fn an_empty_queue_lists_as_nothing_queued() {
        assert_eq!(list(&[], 0), "ido: nothing queued\n");
    }

    #[test]
    fn json_is_exact_and_pure_ascii() {
        let mut e = entry(1, &["echo", "\u{202E}x", "\u{1F600}"]);
        e.reason = Some("caf\u{e9}".into());
        let text = json(&[e], 1000);
        assert!(text.is_ascii(), "{text}");
        assert!(text.contains("\\u202e"), "{text}");
        assert!(text.contains("\\ud83d\\ude00"), "{text}");
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed[0]["argv"][1], "\u{202E}x", "exact bytes survive");
        assert_eq!(parsed[0]["reason"], "caf\u{e9}");
        assert_eq!(parsed[0]["status"], "ready");
    }

    #[test]
    fn group_names_are_sanitized() {
        assert_eq!(group_name("dep\u{1B}[31mloy"), "deploy");
    }
}
