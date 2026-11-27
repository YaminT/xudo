//! No decision reads a caller hint (invariant 1).
//!
//! A caller chooses its `comm`, `exe`, command line and environment, so the
//! hints read from them are recorded in the audit trail and nowhere else. This
//! reads every library source in the workspace, outside its test modules and
//! comments, and counts the hint tokens in it. A file not listed below may name
//! none; a listed file must name exactly as many as listed. So a new use, an
//! alias or a re-export, even in a file that reads or records hints, fails
//! here until someone reviews it and changes the count.
//!
//! Standard library alone, like the crate inventory.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// How a token must stand in the code to count.
#[derive(Clone, Copy)]
enum Bound {
    /// A whole word: `hints`, but not `hints_recorded` or `MAX_HINTS`.
    Word,
    /// The start of a word: `hint_` in `hint_exe`, but not in `the_hint_`.
    Prefix,
}

/// What names a hint in code.
const TOKENS: &[(&str, Bound)] = &[
    ("hints", Bound::Word),
    ("CallerHints", Bound::Word),
    ("caller_hints", Bound::Word),
    ("pinned_hints", Bound::Word),
    ("requester_hints", Bound::Word),
    ("peer_hints", Bound::Word),
    ("hint_", Bound::Prefix),
    ("HINT_", Bound::Prefix),
    ("Exe", Bound::Word),
    ("Cmdline", Bound::Word),
    ("Environ", Bound::Word),
    ("comm", Bound::Word),
];

/// The files that may name a hint, how many times, and why. Nothing else may.
const ALLOWED: &[(&str, usize, &str)] = &[
    (
        "crates/xudo-sys/src/caller_hints.rs",
        38,
        "defines the hints; they render to audit lines only",
    ),
    (
        "crates/xudo-sys/src/lib.rs",
        6,
        "declares and re-exports the module and the front end's collector",
    ),
    (
        "crates/xudo-sys/src/peer.rs",
        16,
        "the bounded /proc reads behind the broker's seam",
    ),
    (
        "crates/xudo-sys/src/provenance.rs",
        8,
        "the front end's collector, shown by `xudo doctor`, sent nowhere",
    ),
    (
        "crates/xudo-sys/src/platform.rs",
        2,
        "calls that collector for the front end",
    ),
    (
        "crates/xudo-policy/src/caller.rs",
        4,
        "holds the front end's hints in CallerFacts, which the engine never reads",
    ),
    (
        "crates/xudo/src/doctor.rs",
        2,
        "counts the front end's hints for the operator",
    ),
    (
        "crates/xudod/src/identify.rs",
        10,
        "reads the peer's hints while the pidfd holds it, and its comm from stat, beside the identity",
    ),
    (
        "crates/xudod/src/record.rs",
        1,
        "writes them into the audit record",
    ),
    (
        "crates/xudo-sys/src/proc.rs",
        5,
        "parses comm out of stat, its field and two error messages; the identity never keeps it",
    ),
    (
        "crates/xudo-sys/src/own.rs",
        1,
        "the test double's stat names a comm",
    ),
    (
        "crates/xudod/src/unit_record.rs",
        1,
        "hands the gate's namespace check a process with an empty comm",
    ),
    (
        "crates/xudo-gate/src/run.rs",
        7,
        "reads the requester's hints straight into the audit evidence",
    ),
];

fn repo() -> PathBuf {
    Path::new(MANIFEST_DIR).join("../..")
}

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|e| e == "rs") {
            found.push(path);
        }
    }
}

/// Every library source, as a path relative to the repository.
fn library_sources() -> Vec<String> {
    let mut found = Vec::new();
    for krate in fs::read_dir(repo().join("crates")).unwrap() {
        let src = krate.unwrap().path().join("src");
        if src.is_dir() {
            sources(&src, &mut found);
        }
    }
    let root = repo().canonicalize().unwrap();
    let mut relative: Vec<String> = found
        .iter()
        .map(|path| {
            let path = path.canonicalize().unwrap();
            path.strip_prefix(&root).unwrap().display().to_string()
        })
        .collect();
    relative.sort();
    relative
}

/// The files that are a `#[cfg(test)] mod name;` of another: test code too.
fn test_module_files(files: &[String]) -> BTreeSet<String> {
    let mut tests = BTreeSet::new();
    for name in files {
        let source = fs::read_to_string(repo().join(name)).unwrap();
        let dir = if name.ends_with("/mod.rs") || name.ends_with("/lib.rs") {
            Path::new(name).parent().unwrap().to_path_buf()
        } else {
            Path::new(name).with_extension("")
        };
        let mut rest = source.as_str();
        while let Some(at) = rest.find("#[cfg(test)]") {
            rest = &rest[at + "#[cfg(test)]".len()..];
            let item = skip_attributes(rest);
            if let Some(module) = item.strip_prefix("mod ")
                && let Some((ident, _)) = module.split_once(';')
                && ident.chars().all(|c| c.is_alphanumeric() || c == '_')
            {
                for candidate in [format!("{ident}.rs"), format!("{ident}/mod.rs")] {
                    let path = dir.join(candidate).display().to_string();
                    if files.contains(&path) {
                        tests.insert(path);
                    }
                }
            }
        }
    }
    tests
}

/// `text` after leading whitespace and any further `#[...]` attributes.
fn skip_attributes(text: &str) -> &str {
    let mut text = text.trim_start();
    while text.starts_with("#[") {
        let end = text.find(']').unwrap();
        text = text[end + 1..].trim_start();
    }
    text
}

/// The index just past the `}` closing the `{` at `open`, skipping
/// comments, strings and character literals. Panics on an unbalanced file,
/// so a source the scan cannot follow fails the test rather than hiding.
fn matching_brace(chars: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '/' if chars.get(i + 1) == Some(&'/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                let mut nest = 0usize;
                loop {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        nest += 1;
                        i += 2;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        nest -= 1;
                        i += 2;
                        if nest == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
                continue;
            }
            'r' if matches!(chars.get(i + 1), Some('"' | '#')) && starts_raw(chars, i) => {
                let mut hashes = 0;
                let mut j = i + 1;
                while chars[j] == '#' {
                    hashes += 1;
                    j += 1;
                }
                if chars[j] == '"' {
                    j += 1;
                    loop {
                        if chars[j] == '"' && (1..=hashes).all(|k| chars[j + k] == '#') {
                            break;
                        }
                        j += 1;
                    }
                    i = j + hashes;
                }
            }
            '"' => {
                i += 1;
                while chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            '\'' => {
                if chars.get(i + 1) == Some(&'\\') {
                    i += 3;
                    while chars[i] != '\'' {
                        i += 1;
                    }
                } else if chars.get(i + 2) == Some(&'\'') {
                    i += 2;
                }
            }
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("unbalanced braces from offset {open}");
}

/// Whether the `r` at `i` opens a raw string: it starts a word, or follows
/// the `b` that does.
fn starts_raw(chars: &[char], i: usize) -> bool {
    let word_start = |at: usize| at == 0 || !is_ident(chars[at - 1]);
    word_start(i) || (chars[i - 1] == 'b' && word_start(i - 1))
}

/// The source without its inline test modules and its comment lines: tests
/// may build any hint they like, and prose may name one.
fn without_tests(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let text: String = chars.iter().collect();
    let mut kept = String::new();
    let mut from = 0;
    let mut search = 0;
    while let Some(found) = text[search..].find("#[cfg(test)]") {
        let at = search + found;
        let after = &text[at + "#[cfg(test)]".len()..];
        let item = skip_attributes(after);
        let module = item
            .strip_prefix("pub(crate) ")
            .or_else(|| item.strip_prefix("pub "))
            .unwrap_or(item)
            .strip_prefix("mod ");
        let inline = module.and_then(|rest| {
            let ident_end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap();
            rest[ident_end..]
                .trim_start()
                .starts_with('{')
                .then_some(())
        });
        if inline.is_some() {
            let open = text.len() - item.len() + item.find('{').unwrap();
            // Byte offsets and char offsets agree only on ASCII prefixes, so
            // count the brace in chars.
            let open_char = text[..open].chars().count();
            let close_char = matching_brace(&chars, open_char);
            let close = chars[..close_char].iter().map(|c| c.len_utf8()).sum();
            kept.push_str(&text[from..at]);
            from = close;
            search = close;
        } else {
            search = at + "#[cfg(test)]".len();
        }
    }
    kept.push_str(&text[from..]);
    kept.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// How many times `token` stands in `code` as `bound` says.
fn occurrences(code: &str, token: &str, bound: Bound) -> usize {
    code.match_indices(token)
        .filter(|(at, _)| {
            let before = code[..*at].chars().next_back();
            let after = code[at + token.len()..].chars().next();
            !before.is_some_and(is_ident)
                && match bound {
                    Bound::Word => !after.is_some_and(is_ident),
                    Bound::Prefix => true,
                }
        })
        .count()
}

/// Every hint token in `code`, by token.
fn named(code: &str) -> Vec<(&'static str, usize)> {
    TOKENS
        .iter()
        .map(|(token, bound)| (*token, occurrences(code, token, *bound)))
        .filter(|(_, count)| *count > 0)
        .collect()
}

/// What is wrong with the hint tokens `source` names outside its tests.
fn problems(name: &str, source: &str) -> Vec<String> {
    let code = without_tests(source);
    let found = named(&code);
    let total: usize = found.iter().map(|(_, count)| count).sum();
    match ALLOWED.iter().find(|(allowed, _, _)| *allowed == name) {
        Some((_, want, _)) if total == *want => Vec::new(),
        Some((_, want, why)) => vec![format!(
            "{name} ({why}) names a hint {total} times, not {want}: {found:?}. \
             Review the change, then update the count"
        )],
        None => found
            .iter()
            .map(|(token, _)| format!("{name}: names `{token}` outside its tests"))
            .collect(),
    }
}

#[test]
fn no_decision_code_reads_a_caller_hint() {
    let files = library_sources();
    assert!(files.len() > 50, "found only {} sources", files.len());
    let tests = test_module_files(&files);
    assert!(
        tests.contains("crates/xudo-sys/src/install/tests.rs"),
        "{tests:?}"
    );
    let found: Vec<String> = files
        .iter()
        .filter(|name| !tests.contains(*name))
        .flat_map(|name| problems(name, &fs::read_to_string(repo().join(name)).unwrap()))
        .collect();
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn every_allowed_file_exists_and_names_a_hint() {
    // A stale entry would let a new file of the same name in unread.
    for (name, count, why) in ALLOWED {
        let source = fs::read_to_string(repo().join(name)).unwrap();
        assert!(*count > 0, "{name} ({why}) is allowed nothing: drop it");
        assert!(
            !named(&without_tests(&source)).is_empty(),
            "{name} ({why}) names no hint any more: drop it from ALLOWED"
        );
    }
}

#[test]
fn the_hints_type_has_no_accessor_a_decision_could_read() {
    // Only constructors and the audit rendering: no field is public and no
    // method hands out a single value to branch on.
    let source = fs::read_to_string(repo().join("crates/xudo-sys/src/caller_hints.rs")).unwrap();
    let code = without_tests(&source);
    let public: Vec<&str> = code
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .filter(|line| !line.starts_with("pub const") && !line.starts_with("pub struct"))
        .map(|line| {
            let name = line.strip_prefix("pub fn ").unwrap_or(line);
            name.split(['(', '<']).next().unwrap_or(name)
        })
        .collect();
    assert_eq!(
        public,
        [
            "unavailable",
            "from_reads",
            "with_comm",
            "evidence",
            "peer_hints",
            "pinned_hints"
        ]
    );
    // The fields are private, and `Debug` is written by hand to print none.
    assert!(
        code.contains("pub struct CallerHints {\n    exe: String,"),
        "{code}"
    );
    assert!(code.contains("impl fmt::Debug for CallerHints"), "{code}");
    assert!(!code.contains("derive(Clone, Debug"), "{code}");
}

/// The field names of `pub struct <name> { .. }` in `code`, outside tests.
fn struct_fields(code: &str, name: &str) -> Vec<String> {
    let open = format!("pub struct {name} {{");
    let start = code.find(&open).unwrap() + open.len();
    let body = &code[start..start + code[start..].find("\n}").unwrap()];
    body.lines()
        .map(str::trim_start)
        .filter_map(|line| line.strip_prefix("pub "))
        .filter_map(|line| line.split_once(':'))
        .map(|(field, _)| field.trim().to_owned())
        .collect()
}

/// What in `identify.rs` would hand a decision a hint: a field of
/// `PeerIdentity` that is a hint word, or an `Identified` that holds more
/// than the identity and the hints, or derefs to anything but the identity.
fn identity_leaks(source: &str) -> Vec<String> {
    let code = without_tests(source);
    let mut leaks: Vec<String> = struct_fields(&code, "PeerIdentity")
        .into_iter()
        .filter(|field| !named(field).is_empty() || field.contains("hint"))
        .map(|field| format!("PeerIdentity.{field}"))
        .collect();
    let beside = struct_fields(&code, "Identified");
    if beside != ["identity", "hints"] {
        leaks.push(format!("Identified holds {beside:?}"));
    }
    if !code.contains("type Target = PeerIdentity;") {
        leaks.push("Identified derefs to something else".to_owned());
    }
    leaks
}

#[test]
fn the_identity_decisions_are_handed_carries_no_hint() {
    // The broker hands decisions a `PeerIdentity`; the hints, `comm` among
    // them, sit beside it in `Identified`, which only the record reads.
    let source = fs::read_to_string(repo().join("crates/xudod/src/identify.rs")).unwrap();
    let code = without_tests(&source);
    let fields = struct_fields(&code, "PeerIdentity");
    for kernel in ["pid", "uid", "starttime", "cgroup_attestation"] {
        assert!(fields.contains(&kernel.to_owned()), "{fields:?}");
    }
    assert_eq!(identity_leaks(&source), Vec::<String>::new());
}

#[test]
fn the_identity_check_catches_a_hint_put_back_into_the_identity() {
    let source = fs::read_to_string(repo().join("crates/xudod/src/identify.rs")).unwrap();
    let with_comm = source.replacen(
        "pub struct PeerIdentity {\n",
        "pub struct PeerIdentity {\n    pub comm: Vec<u8>,\n",
        1,
    );
    assert_eq!(identity_leaks(&with_comm), ["PeerIdentity.comm"]);
    let with_exe = source.replacen(
        "pub struct PeerIdentity {\n",
        "pub struct PeerIdentity {\n    pub hint_exe: String,\n",
        1,
    );
    assert_eq!(identity_leaks(&with_exe), ["PeerIdentity.hint_exe"]);
    let beside = source.replacen(
        "    pub hints: CallerHints,\n",
        "    pub hints: CallerHints,\n    pub comm: Vec<u8>,\n",
        1,
    );
    assert_eq!(
        identity_leaks(&beside),
        ["Identified holds [\"identity\", \"hints\", \"comm\"]"]
    );
    let deref = source.replacen("type Target = PeerIdentity;", "type Target = Self;", 1);
    assert_eq!(
        identity_leaks(&deref),
        ["Identified derefs to something else"]
    );
}

/// A decision that destructures the hints and branches on their `Debug`
/// form: the mutation that once got past this scan.
const SMUGGLED: &str = "fn decide(peer: &Identified) -> bool {\n    \
                        let Identified { hints: smuggled, .. } = peer;\n    \
                        format!(\"{smuggled:?}\").contains(\"claude\")\n}\n";

#[test]
fn the_scan_catches_a_decision_that_branches_on_a_hint() {
    assert_eq!(
        problems("crates/xudod/src/policy.rs", SMUGGLED),
        ["crates/xudod/src/policy.rs: names `hints` outside its tests"]
    );
    let field = "fn decide(identity: &Identified) -> bool {\n    \
                 identity.hints.evidence()[2] == \"hint_claudecode=set:\\\"1\\\"\"\n}\n";
    assert_eq!(
        problems("crates/xudod/src/serve.rs", field),
        [
            "crates/xudod/src/serve.rs: names `hints` outside its tests",
            "crates/xudod/src/serve.rs: names `hint_` outside its tests",
        ]
    );
    // A process's name is a hint too, wherever it was parsed.
    let named_comm = "fn decide(stat: &ProcStat) -> bool {\n    stat.comm == b\"claude\"\n}\n";
    assert_eq!(
        problems("crates/xudo-gate/src/decide.rs", named_comm),
        ["crates/xudo-gate/src/decide.rs: names `comm` outside its tests"]
    );
    // The same text in an inline test module is fine.
    let tested = format!("fn x() {{}}\n#[cfg(test)]\nmod tests {{\n{SMUGGLED}}}\n");
    assert!(problems("crates/xudod/src/policy.rs", &tested).is_empty());
}

#[test]
fn the_scan_reads_past_a_test_module_declared_in_another_file() {
    // `#[cfg(test)] mod x;` ends nothing: the code after it is scanned.
    let source = format!("#[cfg(test)]\nmod fake;\n\n{SMUGGLED}");
    assert_eq!(problems("crates/xudod/src/policy.rs", &source).len(), 1);
    // And after a whole inline test module, braces in strings and chars and
    // comments and all.
    let source = format!(
        "#[cfg(test)]\n#[allow(x)]\nmod tests {{\n    // }}\n    const A: &str = \"}}\";\n    \
         const B: char = '}}';\n    const C: &str = r#\"}}\"#;\n    fn f<'a>(x: &'a str) {{}}\n}}\n\n{SMUGGLED}"
    );
    assert_eq!(problems("crates/xudod/src/policy.rs", &source).len(), 1);
}

#[test]
fn the_scan_catches_a_new_use_in_an_allowed_file() {
    // An alias re-exported from the crate root, or one more read in the file
    // that reads hints for the record, changes the count.
    let lib = fs::read_to_string(repo().join("crates/xudo-sys/src/lib.rs")).unwrap();
    assert!(problems("crates/xudo-sys/src/lib.rs", &lib).is_empty());
    let aliased = format!("{lib}\npub use caller_hints::CallerHints as Facts;\n");
    assert_eq!(problems("crates/xudo-sys/src/lib.rs", &aliased).len(), 1);
    let identify = fs::read_to_string(repo().join("crates/xudod/src/identify.rs")).unwrap();
    let smuggling = format!("{identify}\n{SMUGGLED}");
    assert_eq!(
        problems("crates/xudod/src/identify.rs", &smuggling).len(),
        1
    );
}

#[test]
fn a_word_counts_only_whole_and_a_prefix_only_at_a_start() {
    assert_eq!(
        occurrences("hints x.hints (hints)", "hints", Bound::Word),
        3
    );
    assert_eq!(
        occurrences("hints_recorded max_hints hintsy", "hints", Bound::Word),
        0
    );
    assert_eq!(
        occurrences("hint_exe the_hint_ x", "hint_", Bound::Prefix),
        1
    );
    assert_eq!(without_tests("a\n  // hints\n/// hints\nb"), "a\nb");
}
