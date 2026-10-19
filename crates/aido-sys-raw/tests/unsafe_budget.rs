//! `unsafe` lives in `aido-sys-raw`'s `sys` module, within its published
//! budget, and nowhere else.
//!
//! The compiler enforces most of this: every other crate forbids
//! `unsafe_code`, and this one denies it outside `sys`. What the compiler
//! cannot see is the *configuration* that makes that true. A crate that stops
//! inheriting the workspace lints, an `allow` or `expect` of `unsafe_code`
//! anywhere in this crate (where the lint is only `deny`) — its tests and
//! build script included — a second crate depending on this one, or a sixth
//! block in `sys` all compile cleanly. These tests are the review that does
//! not get tired.
//!
//! # Tokens, not substrings
//!
//! The first version matched substrings such as `unsafe {` and
//! `allow(unsafe_code)`, and review defeated it five ways: `unsafe{`,
//! `#[expect(unsafe_code)]`, `#[allow(dead_code, unsafe_code)]`,
//! `#[unsafe(no_mangle)]`, and two blocks on one line counted as one. So the
//! source is lexed: comments, strings, and character literals are removed with
//! their delimiters understood, and what remains is judged as tokens. Outside
//! `sys.rs` the keyword `unsafe` may not appear at all, in any position, and no
//! lint attribute may name `unsafe_code` except to deny or forbid it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn workspace_root() -> PathBuf {
    Path::new(MANIFEST_DIR)
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read_toml(path: &Path) -> toml::Table {
    fs::read_to_string(path).unwrap().parse().unwrap()
}

/// The one file allowed `unsafe`.
fn raw_rs() -> PathBuf {
    Path::new(MANIFEST_DIR)
        .join("src/sys.rs")
        .canonicalize()
        .unwrap()
}

fn this_file() -> PathBuf {
    Path::new(MANIFEST_DIR)
        .join("tests/unsafe_budget.rs")
        .canonicalize()
        .unwrap()
}

/// What remains of Rust source once comments, strings, and character
/// literals are gone.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    /// An identifier, keyword, or number.
    Word(String),
    /// Any other single character.
    Punct(char),
}

fn word(token: Option<&Token>, expected: &str) -> bool {
    matches!(token, Some(Token::Word(w)) if w == expected)
}

/// Lexes `source` far enough to tell code from the text inside comments,
/// strings, and character literals.
///
/// Not a Rust parser, and it does not need to be: it only has to find every
/// place where the `unsafe` keyword could be code. When unsure it keeps text
/// as code, which can only produce a false alarm, never a miss.
fn tokens(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i = skip_block_comment(&chars, i);
        } else if c == '"' {
            i = skip_quoted(&chars, i + 1, '"');
        } else if c == '\'' {
            i = skip_char_or_lifetime(&chars, i, &mut out);
        } else if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            i = after_word(&chars, i, text, &mut out);
        } else {
            out.push(Token::Punct(c));
            i += 1;
        }
    }
    out
}

/// Skips a block comment starting at `i`, honouring nesting.
fn skip_block_comment(chars: &[char], mut i: usize) -> usize {
    let mut depth = 0usize;
    while i < chars.len() {
        if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            depth += 1;
            i += 2;
        } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    i
}

/// Skips to just past the unescaped `close`, starting inside the literal.
fn skip_quoted(chars: &[char], mut i: usize, close: char) -> usize {
    while i < chars.len() {
        if chars[i] == '\\' {
            i += 2;
        } else if chars[i] == close {
            return i + 1;
        } else {
            i += 1;
        }
    }
    i
}

/// A `'` opens a character literal (`'x'`, `'\n'`, `'"'`) or a lifetime or
/// label (`'a`). Only the literal is skipped; a lifetime's name stays code.
fn skip_char_or_lifetime(chars: &[char], i: usize, out: &mut Vec<Token>) -> usize {
    if chars.get(i + 1) == Some(&'\\') {
        return skip_quoted(chars, i + 1, '\'');
    }
    if chars.get(i + 2) == Some(&'\'') {
        return i + 3;
    }
    out.push(Token::Punct('\''));
    i + 1
}

/// Decides what a word that was just read means, given what follows it: a
/// string prefix (`b"`, `r#"`, `c"`), a byte literal (`b'x'`), a raw
/// identifier (`r#name`), or an ordinary word.
fn after_word(chars: &[char], i: usize, text: String, out: &mut Vec<Token>) -> usize {
    let next = chars.get(i).copied();
    match (text.as_str(), next) {
        ("b" | "c", Some('"')) => skip_quoted(chars, i + 1, '"'),
        ("b", Some('\'')) => skip_quoted(chars, i + 1, '\''),
        ("r" | "br" | "cr", Some('"' | '#')) => {
            let mut hashes = 0;
            let mut j = i;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) == Some(&'"') {
                skip_raw_string(chars, j + 1, hashes)
            } else {
                // `r#name`: a raw identifier. Kept as the word it spells, so
                // `r#unsafe` is judged like `unsafe`, which is the cautious way.
                out.push(Token::Word(text));
                j
            }
        }
        _ => {
            out.push(Token::Word(text));
            i
        }
    }
}

/// Skips the body of a raw string with `hashes` hashes, starting inside it.
fn skip_raw_string(chars: &[char], mut i: usize, hashes: usize) -> usize {
    while i < chars.len() {
        if chars[i] == '"' && (1..=hashes).all(|k| chars.get(i + k) == Some(&'#')) {
            return i + 1 + hashes;
        }
        i += 1;
    }
    i
}

/// Every `unsafe` keyword in the tokens, with whether it opens a block.
fn unsafe_uses(tokens: &[Token]) -> (usize, usize) {
    let mut blocks = 0;
    let mut other = 0;
    for (index, token) in tokens.iter().enumerate() {
        if word(Some(token), "unsafe") {
            if tokens.get(index + 1) == Some(&Token::Punct('{')) {
                blocks += 1;
            } else {
                other += 1;
            }
        }
    }
    (blocks, other)
}

/// How many `allow(...)`, `expect(...)`, or `warn(...)` groups name
/// `unsafe_code` — each one lifts or weakens the lint.
fn unsafe_code_lifts(tokens: &[Token]) -> usize {
    let mut lifts = 0;
    for (index, token) in tokens.iter().enumerate() {
        let lifting = ["allow", "expect", "warn"]
            .iter()
            .any(|level| word(Some(token), level));
        if lifting && tokens.get(index + 1) == Some(&Token::Punct('(')) {
            let mut depth = 0usize;
            for inner in &tokens[index + 1..] {
                match inner {
                    Token::Punct('(') => depth += 1,
                    Token::Punct(')') => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    other if word(Some(other), "unsafe_code") => {
                        lifts += 1;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    lifts
}

/// How many places pull code in from another file: `include!(...)` and
/// `#[path = ...]`. Either one can bring in a file the scan never reads, and in
/// `sys.rs` blocks the budget never counts. `include_str!` and `include_bytes!`
/// bring in data, not code, and are not counted.
fn inclusions(tokens: &[Token]) -> usize {
    tokens
        .windows(2)
        .filter(|pair| word(pair.first(), "include") && pair.get(1) == Some(&Token::Punct('!')))
        .count()
        + tokens
            .windows(4)
            .filter(|w| {
                w[0] == Token::Punct('#')
                    && w[1] == Token::Punct('[')
                    && word(w.get(2), "path")
                    && w[3] == Token::Punct('=')
            })
            .count()
}

/// Why a file other than `sys.rs` is an offender, if it is one.
fn offence(source: &str) -> Option<String> {
    let toks = tokens(source);
    let (blocks, other) = unsafe_uses(&toks);
    let lifts = unsafe_code_lifts(&toks);
    let included = inclusions(&toks);
    (blocks + other + lifts + included > 0).then(|| {
        format!(
            "{blocks} unsafe block(s), {other} other unsafe use(s), {lifts} lift(s) of \
             unsafe_code, {included} inclusion(s) of another file's code"
        )
    })
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap();
        if path.is_dir() {
            // Build output and fuzzing inputs, never source.
            if !["target", "corpus", "artifacts"]
                .iter()
                .any(|skip| name == *skip)
            {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path.canonicalize().unwrap());
        }
    }
}

/// Every Rust file of every workspace member, whole tree — `src/`, `tests/`,
/// `benches/`, `examples/`, `build.rs` — plus the fuzz crate, which sits
/// outside the workspace with no lint table of its own.
fn every_rust_file() -> Vec<PathBuf> {
    let root = workspace_root();
    let manifest = read_toml(&root.join("Cargo.toml"));
    let mut dirs: Vec<PathBuf> = manifest["workspace"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| root.join(member.as_str().unwrap()))
        .collect();
    dirs.push(root.join("fuzz"));
    let mut files = Vec::new();
    for dir in &dirs {
        assert!(
            dir.is_dir(),
            "{} is not a directory: a glob member must be expanded for the scan",
            dir.display()
        );
        rust_files(dir, &mut files);
    }
    files
}

#[test]
fn no_unsafe_appears_outside_raw_anywhere_in_the_workspace() {
    let files = every_rust_file();
    assert!(
        files.len() > 30,
        "the scan found too little to be looking in the right place"
    );
    let raw = raw_rs();
    let me = this_file();
    assert!(files.contains(&raw), "the scan must reach sys.rs itself");
    assert!(
        files.contains(&me),
        "the scan must reach this file's own tree"
    );

    let offenders: Vec<String> = files
        .iter()
        .filter(|f| **f != raw && **f != me)
        .filter_map(|f| {
            offence(&fs::read_to_string(f).unwrap()).map(|why| format!("{}: {why}", f.display()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "unsafe outside aido-sys-raw's sys module:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn raw_stays_within_the_budget_its_docs_publish() {
    let text = fs::read_to_string(raw_rs()).unwrap();
    let budget: usize = text
        .split("**Budget: ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse().ok())
        .expect("sys.rs must publish `**Budget: N `unsafe` blocks.**` in its module docs");

    let toks = tokens(&text);
    let (blocks, other) = unsafe_uses(&toks);
    assert_eq!(
        blocks, budget,
        "sys.rs has {blocks} unsafe blocks against a published budget of {budget}; \
         a change to either is a reviewed change to both"
    );
    assert_eq!(
        other, 0,
        "sys.rs may use `unsafe` only to open a block: no unsafe fn, impl, trait, extern, or \
         attribute"
    );
    assert_eq!(
        unsafe_code_lifts(&toks),
        1,
        "sys.rs lifts unsafe_code exactly once, in its inner attribute"
    );
    assert_eq!(
        inclusions(&toks),
        0,
        "sys.rs may not include code from another file, whose blocks the budget would not count"
    );
}

/// Whether `tokens` contain the inner attribute `#![<level>(unsafe_code)]`.
fn has_crate_lint(tokens: &[Token], level: &str) -> bool {
    let attribute = [
        Token::Punct('#'),
        Token::Punct('!'),
        Token::Punct('['),
        Token::Word(level.into()),
        Token::Punct('('),
        Token::Word("unsafe_code".into()),
        Token::Punct(')'),
        Token::Punct(']'),
    ];
    tokens.windows(attribute.len()).any(|w| w == attribute)
}

#[test]
fn this_crate_denies_unsafe_at_its_root_and_aido_sys_forbids_it() {
    let lib = tokens(&fs::read_to_string(Path::new(MANIFEST_DIR).join("src/lib.rs")).unwrap());
    assert!(
        has_crate_lint(&lib, "deny"),
        "aido-sys-raw's lib.rs must deny unsafe_code"
    );
    let sys_declarations = lib
        .windows(3)
        .filter(|w| word(w.first(), "mod") && word(w.get(1), "sys") && w[2] == Token::Punct(';'))
        .count();
    assert_eq!(sys_declarations, 1, "sys must be declared exactly once");

    // The crate that wraps these calls goes back to forbidding unsafe, which
    // no inner attribute can lift: the compiler keeps aido-sys clean.
    let aido_sys = workspace_root().join("crates/aido-sys/src/lib.rs");
    assert!(
        has_crate_lint(&tokens(&fs::read_to_string(aido_sys).unwrap()), "forbid"),
        "aido-sys must forbid unsafe_code"
    );
}

#[test]
fn only_aido_sys_depends_on_this_crate() {
    // Every other crate reaches these calls through aido-sys's Syscalls trait,
    // where a fake can stand in for the kernel. A second dependent would be a
    // second path to them that no fake covers.
    let root = workspace_root();
    let manifest = read_toml(&root.join("Cargo.toml"));
    let mut manifests: Vec<PathBuf> = manifest["workspace"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| root.join(m.as_str().unwrap()).join("Cargo.toml"))
        .collect();
    manifests.push(root.join("fuzz/Cargo.toml"));
    let dependents: Vec<String> = manifests
        .iter()
        .filter(|path| {
            !path.ends_with("crates/aido-sys/Cargo.toml")
                && !path.ends_with("crates/aido-sys-raw/Cargo.toml")
        })
        .filter(|path| fs::read_to_string(path).unwrap().contains("aido-sys-raw"))
        .map(|path| path.display().to_string())
        .collect();
    assert!(
        dependents.is_empty(),
        "only aido-sys may depend on aido-sys-raw: {dependents:?}"
    );
    assert!(
        fs::read_to_string(root.join("crates/aido-sys/Cargo.toml"))
            .unwrap()
            .contains("aido-sys-raw"),
        "aido-sys is the one crate that does"
    );
}

#[test]
fn this_crates_lints_are_the_workspaces_but_for_unsafe_code() {
    let root = workspace_root();
    let mut expected = read_toml(&root.join("Cargo.toml"))["workspace"]["lints"].clone();
    expected["rust"]["unsafe_code"] = toml::Value::from("deny");
    assert_eq!(
        read_toml(&Path::new(MANIFEST_DIR).join("Cargo.toml"))["lints"],
        expected,
        "aido-sys-raw's [lints] must equal [workspace.lints] with only unsafe_code lowered to deny"
    );
    assert_eq!(
        read_toml(&root.join("Cargo.toml"))["workspace"]["lints"]["rust"]["unsafe_code"].as_str(),
        Some("forbid"),
        "the workspace default must stay forbid"
    );
}

#[test]
fn every_other_crate_inherits_the_workspace_lints() {
    let root = workspace_root();
    let manifest = read_toml(&root.join("Cargo.toml"));
    let members = manifest["workspace"]["members"].as_array().unwrap();
    assert!(members.len() > 5);
    let strays: Vec<&str> = members
        .iter()
        .map(|m| m.as_str().unwrap())
        .filter(|m| *m != "crates/aido-sys-raw")
        .filter(|m| {
            let lints = read_toml(&root.join(m).join("Cargo.toml"));
            lints
                .get("lints")
                .and_then(|l| l.get("workspace"))
                .and_then(toml::Value::as_bool)
                != Some(true)
        })
        .collect();
    assert!(
        strays.is_empty(),
        "these crates do not inherit the workspace lints: {strays:?}"
    );
}

// The scanner is itself security-relevant: a blind spot in it is a way past
// the budget. Each case below is a bypass found in review, or a way a naive
// lexer loses track of what is code.

#[test]
fn the_scanner_catches_every_form_that_beat_the_substring_version() {
    for (case, source) in [
        ("no space", "fn f() { unsafe{ g() } }"),
        ("newline", "fn f() { unsafe\n{ g() } }"),
        ("expect", "#[expect(unsafe_code)] fn f() {}"),
        ("grouped", "#[allow(dead_code, unsafe_code)] fn f() {}"),
        ("reordered", "#[allow(unsafe_code, dead_code)] fn f() {}"),
        ("cfg_attr", "#![cfg_attr(test, allow(unsafe_code))]"),
        ("warn", "#![warn(unsafe_code)]"),
        (
            "attribute",
            "#[unsafe(no_mangle)] pub extern \"C\" fn f() {}",
        ),
        ("extern block", "unsafe extern \"C\" { fn g(); }"),
        ("impl", "unsafe impl Send for X {}"),
        ("fn", "pub unsafe fn f() {}"),
        ("trait", "unsafe trait T {}"),
        (
            "macro body",
            "macro_rules! m { ($e:expr) => { unsafe { $e } } }",
        ),
        ("raw ident", "fn f() { r#unsafe(); }"),
        ("include", "include!(\"../../elsewhere.rs\");"),
        ("path attribute", "#[path = \"/elsewhere.rs\"] mod m;"),
    ] {
        assert!(offence(source).is_some(), "{case}: {source}");
    }
}

#[test]
fn the_scanner_counts_blocks_not_lines() {
    let (blocks, other) = unsafe_uses(&tokens("fn f() { unsafe { a() }; unsafe{ b() } }"));
    assert_eq!((blocks, other), (2, 0));
}

#[test]
fn the_scanner_ignores_unsafe_in_comments_strings_and_lint_denials() {
    for source in [
        "// unsafe { x() }",
        "/// unsafe fn in a doc comment",
        "/* unsafe { x() } */",
        "/* outer /* inner */ unsafe { x() } */",
        "let s = \"unsafe { x() }\";",
        "let s = r#\"unsafe { \" x() }\"#;",
        "let s = br\"unsafe\";",
        "let s = b\"unsafe {\";",
        "let s = c\"unsafe {\";",
        "let c = 'u'; let d = '\\''; let e = b'\"';",
        "#![forbid(unsafe_code)] #![deny(unsafe_code)]",
        "fn f<'a>(x: &'a str) -> &'a str { x } // unsafe_code is only a lint name",
        "let not_unsafe = 1; let unsafe_code = 2;",
        "const RULES: &str = include_str!(\"../rules/10-a.toml\");",
        "#[doc = include_str!(\"README.md\")] mod m {}",
    ] {
        assert_eq!(offence(source), None, "{source}");
    }
}

#[test]
fn the_scanner_does_not_lose_code_after_a_literal_that_looks_like_a_comment() {
    // A comment stripper that does not understand strings and characters
    // would swallow the unsafe block on each of these lines.
    for source in [
        "let s = \"//\"; unsafe { x() }",
        "let s = \"/*\"; unsafe { x() } /* */",
        "let q = '\"'; unsafe { x() } // \"",
        "let s = r#\"a \" b\"#; unsafe { x() }",
        "let s = \"\\\"\"; unsafe { x() }",
        "let l = 'a; unsafe { x() }",
    ] {
        assert!(offence(source).is_some(), "{source}");
    }
}
