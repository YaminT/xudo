//! `xudo(1)` stays in step with the binary.
//!
//! `xudo --help` is the list of subcommands the program actually has. The man
//! page is a separate file, and the two drift the moment a command is added to
//! one of them. This runs the real binary, the same way a user reads the help,
//! and fails when a command it lists is absent from `docs/man/xudo.1`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;

#[test]
fn the_man_page_documents_every_subcommand() {
    let help = Command::cargo_bin("xudo")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    assert!(
        help.status.success(),
        "{}",
        String::from_utf8_lossy(&help.stderr)
    );
    let text = String::from_utf8(help.stdout).unwrap();
    let commands = subcommands_from_help(&text);
    assert!(
        commands.iter().any(|name| name == "explain") && commands.len() > 1,
        "could not read the command list from --help:\n{text}"
    );

    // Roff writes an option dash as `\-`. The page documents `why-not` when it
    // contains `why\-not`; compare the text a reader sees.
    let page = include_str!("../../../docs/man/xudo.1").replace("\\-", "-");
    let commands_section = page.split(".SH COMMANDS\n").nth(1).unwrap_or("");
    let commands_section = commands_section.split(".SH ").next().unwrap_or("");
    for name in &commands {
        assert!(
            commands_section.contains(&format!(".TP\n.B {name}\n")),
            "xudo(1) does not document `xudo {name}`"
        );
    }
}

/// The command names in the `Commands:` section of clap's `--help`.
///
/// A command line is indented two spaces and starts with the name. A wrapped
/// description line is indented further. The section ends at the blank line
/// before `Options:`.
fn subcommands_from_help(help: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_commands = false;
    for line in help.lines() {
        if line == "Commands:" {
            in_commands = true;
            continue;
        }
        if !in_commands {
            continue;
        }
        if line.is_empty() {
            break;
        }
        if let Some(name) = line.strip_prefix("  ").and_then(|rest| {
            let rest = rest.strip_prefix(' ').is_none().then_some(rest)?;
            rest.split_whitespace().next()
        }) {
            names.push(name.to_owned());
        }
    }
    names
}
