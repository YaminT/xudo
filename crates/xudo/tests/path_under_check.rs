//! `xudo check` warns on every `path-under` matcher.
//!
//! Exit 20 is the lint warning. A rule that also allowlists a file tool is a
//! lint error (21) and the warning is still printed: every use is reported,
//! and the more severe status wins.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;

use clap::Parser;

fn rules_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &std::path::Path, file: &str, body: &str) {
    std::fs::write(dir.join(file), body).unwrap();
}

fn check(dir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let mut full = vec!["xudo", "--rules", dir.to_str().unwrap()];
    full.extend_from_slice(args);
    let cli = xudo::Cli::try_parse_from(full).unwrap();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = xudo::run(&cli, &xudo::Invocation::default(), &mut out, &mut err);
    (
        code.as_i32(),
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

const TWO: &str = r#"
[[action]]
id = "xudo.files.copy-names"
tier = "diag-read"
exe = "/usr/bin/true"
args = [
  { name = "path", matcher = { path-under = { prefix = "/home/agent" } } },
  { name = "dest", matcher = { path-under = { prefix = "/srv/agent" } } },
]
"#;

const ONE: &str = r#"
[[action]]
id = "xudo.files.echo-path"
tier = "diag-read"
exe = "/bin/echo"
args = [
  { name = "path", matcher = { path-under = { prefix = "/var/agent" } } },
]
"#;

const NONE: &str = r#"
[[action]]
id = "xudo.files.safe-literal"
tier = "diag-read"
exe = "/usr/bin/printf"
args = [
  { name = "word", matcher = { literal = "ok" } },
]
"#;

const RM: &str = r#"
[[action]]
id = "xudo.files.rm-home"
tier = "diag-read"
exe = "/bin/rm"
args = [
  { name = "path", matcher = { path-under = { prefix = "/home/agent" } } },
]
"#;

#[test]
fn check_warns_on_every_path_under_matcher() {
    let dir = rules_dir("path-under-warn");
    write(&dir, "10-two.toml", TWO);
    write(&dir, "20-one.toml", ONE);
    write(&dir, "30-none.toml", NONE);

    let (code, out, err) = check(&dir, &["check"]);
    assert_eq!(code, 20, "{out}{err}");
    assert!(err.is_empty(), "{err}");
    assert_eq!(
        out.matches("is lexical only").count(),
        3,
        "one warning per path-under matcher, and not for the literal: {out}"
    );
    assert!(out.contains("xudo.files.copy-names"), "{out}");
    assert!(out.contains("argument 0 (path)"), "{out}");
    assert!(out.contains("argument 1 (dest)"), "{out}");
    assert!(out.contains("xudo.files.echo-path"), "{out}");
    assert!(
        !out.contains("xudo.files.safe-literal"),
        "a literal matcher is not a path-under warning: {out}"
    );
    assert!(
        !out.contains("overlapping pair"),
        "these actions do not overlap: {out}"
    );
    assert!(
        out.contains("nothing in xudo enforces containment for argument paths"),
        "{out}"
    );
    assert!(
        out.contains("never use it for a program that opens the path as root"),
        "{out}"
    );

    let (code, json, err) = check(&dir, &["--output", "json", "check"]);
    assert_eq!(code, 20, "{json}{err}");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed.get("exit_code").and_then(serde_json::Value::as_i64),
        Some(20),
        "{json}"
    );
    let warnings = parsed
        .pointer("/lint/warnings")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    assert_eq!(warnings.len(), 3, "{json}");
    assert!(warnings.iter().all(|line| {
        line.as_str()
            .is_some_and(|text| text.contains("is lexical only"))
    }));

    let (code, out, err) = check(&dir, &["check", "--tests-only"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(!out.contains("lexical only"), "{out}");

    let rm = rules_dir("path-under-rm");
    write(&rm, "10-rm.toml", RM);
    let (code, out, err) = check(&rm, &["check"]);
    assert_eq!(
        code, 21,
        "a file tool is a lint error, which outranks the warning: {out}{err}"
    );
    assert!(err.contains("ChangesPathMetadataOrExistence"), "{err}");
    assert!(
        out.contains("is lexical only"),
        "the path-under warning is still printed when the rule is also self-denying: {out}"
    );
}
