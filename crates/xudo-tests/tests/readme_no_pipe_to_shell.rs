//! The README never teaches `curl ... | sh`.
//!
//! The install is a checksum-verified download (docs/todo/phase-3), and the
//! reasoning for refusing a piped installer belongs in the README, so the
//! pattern may be named in prose but never given as a command.

#![allow(clippy::unwrap_used)]

use std::fs;
use std::mem;
use std::path::Path;

/// Joins a trailing `\` so a command split across lines is still one command.
/// A doubled `\\` is a literal backslash, not a continuation.
fn logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim_end();
        if let Some(body) = trimmed.strip_suffix('\\') {
            if !body.ends_with('\\') {
                current.push_str(body);
                current.push(' ');
                continue;
            }
        }
        current.push_str(line);
        lines.push(mem::take(&mut current));
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn is_shell(word: &str) -> bool {
    matches!(word, "sh" | "bash" | "dash" | "zsh")
}

/// The program a pipeline stage runs. `sudo` flags (`-E`) are skipped.
fn stage_command(stage: &str) -> Option<&str> {
    let mut words = stage.split_whitespace();
    let first = words.next()?;
    if first != "sudo" {
        return Some(first);
    }
    loop {
        let word = words.next()?;
        if word == "--" {
            return words.next();
        }
        if !word.starts_with('-') {
            return Some(word);
        }
    }
}

/// A command that downloads and pipes into a shell: `curl`/`wget`, then a `|`,
/// then `sh`, `bash`, `dash` or `zsh` (optionally after `sudo` and its flags).
fn line_pipes_download_to_shell(line: &str) -> bool {
    let Some(start) = line.find("curl").or_else(|| line.find("wget")) else {
        return false;
    };
    line[start..]
        .split('|')
        .skip(1)
        .any(|stage| stage_command(stage).is_some_and(is_shell))
}

fn pipes_download_to_shell(text: &str) -> bool {
    logical_lines(text)
        .iter()
        .any(|line| line_pipes_download_to_shell(line))
}

#[test]
fn readme_has_no_curl_pipe_to_shell() {
    let readme = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    let text = fs::read_to_string(readme).unwrap();
    let bad: Vec<_> = logical_lines(&text)
        .into_iter()
        .filter(|line| line_pipes_download_to_shell(line))
        .collect();
    assert!(
        bad.is_empty(),
        "README pipes a download into a shell: {bad:?}"
    );
}

#[test]
fn the_check_notices_a_piped_installer() {
    assert!(pipes_download_to_shell(
        "curl -fsSL https://x.example/i | sh"
    ));
    assert!(pipes_download_to_shell(
        "wget -qO- https://x | sudo bash -s"
    ));
    assert!(pipes_download_to_shell(
        "curl -fsSL https://x | sudo -E bash"
    ));
    assert!(pipes_download_to_shell("curl -fsSL https://x | sudo bash"));
    assert!(pipes_download_to_shell("curl -fsSL https://x \\\n  | sh"));
    assert!(pipes_download_to_shell(
        "curl -fsSL https://x \\\n  | sudo -E bash"
    ));
    assert!(pipes_download_to_shell(
        "curl -fsSL https://x | sudo -- bash"
    ));
    assert!(pipes_download_to_shell("curl -fsSL https://x | dash"));
    assert!(pipes_download_to_shell("wget -qO- https://x | zsh"));
    assert!(pipes_download_to_shell("curl -fsSL https://x | sh \\\n"));
    assert!(!pipes_download_to_shell("curl -O https://x/xudo.deb"));
    assert!(!pipes_download_to_shell("curl |"));
    assert!(!pipes_download_to_shell("curl | sudo --"));
    assert!(!pipes_download_to_shell(
        "there is no curl | shell installer"
    ));
    assert!(!pipes_download_to_shell(
        "curl -fsSL https://x | sudo apt install bash"
    ));
    assert!(!pipes_download_to_shell("curl -fsSL https://x | sudo -E"));
    assert!(!pipes_download_to_shell("curl -fsSL https://x \\\\\n| sh"));
    assert!(!pipes_download_to_shell("echo nothing to see here"));
}
