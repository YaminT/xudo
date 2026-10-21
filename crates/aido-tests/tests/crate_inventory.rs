//! The crate inventories name exactly the workspace's members.
//!
//! `CLAUDE.md`, `docs/design-plan.md`, and `docs/todo/README.md` each keep a
//! table of the crates, and a list kept by hand is a list that drifts: the plan
//! said "twelve crates" while the manifest had thirteen, and the todo index's
//! table left out `aido-audit`, `aido-gate`, and `aido-sys-raw`. A map of a
//! privilege broker with a crate missing from it is a map with a hole in it.
//!
//! So each table is checked against `[workspace] members` in `Cargo.toml`, in
//! both directions:
//!
//! * a member with no row fails;
//! * a row for a crate the workspace lacks fails, unless the row opens with
//!   `**in review (M2b).**`, which is how a crate that is built but not merged
//!   is told apart from one that was renamed away;
//! * a row still marked in review for a crate that has become a member fails,
//!   so the change that merges a crate must flip its marker, and cannot forget.
//!
//! The one sentence that states the member count in words is held to it too.
//!
//! # A reader that cannot be fooled into passing
//!
//! A guard that always passes is worse than none, so the readers refuse what
//! they do not understand rather than skip it: a glob in `members`, an array
//! that never closes, a table that is not the crate table, a row that names no
//! crate. They read `Cargo.toml` with the standard library alone, because this
//! package has no dependencies and a guard on the workspace's layout should not
//! add a node to the graph it guards. The self-tests below feed the readers
//! each shape that could make a crate invisible.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// The marker a row opens its description with while its crate is built but
/// not yet a workspace member. Only at the start: a row for `aido-gate` may say
/// that `aido-gate-bin` is in review without being marked itself.
const IN_REVIEW_OPEN: &str = "**in review (";
const IN_REVIEW_CLOSE: &str = ").**";

// --- reading `Cargo.toml` ---------------------------------------------------

/// A manifest line without its comment. A `#` inside quotes is text.
fn without_comment(line: &str) -> &str {
    let mut open = None;
    for (at, c) in line.char_indices() {
        match (open, c) {
            (None, '#') => return line.get(..at).unwrap_or_default(),
            (None, '"' | '\'') => open = Some(c),
            (Some(quote), _) if quote == c => open = None,
            _ => {}
        }
    }
    line
}

/// The value in `key = value` when the line sets exactly `key`, so that
/// `default-members` is not mistaken for `members`.
fn value_of<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start().strip_prefix('=')?;
    Some(rest.trim())
}

/// A string with no escapes, in basic or literal quotes.
fn unquote(text: &str) -> Result<&str, String> {
    let inner = ['"', '\'']
        .iter()
        .find_map(|quote| text.strip_prefix(*quote)?.strip_suffix(*quote));
    match inner {
        Some(plain) if !plain.contains(['"', '\'', '\\']) => Ok(plain),
        _ => Err(format!("`{text}` is not a plain quoted string")),
    }
}

/// The strings of an array written inline, a trailing comma allowed.
fn strings(array: &str) -> Result<Vec<&str>, String> {
    let inner = array
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .ok_or_else(|| format!("`{array}` is not one array"))?;
    inner
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(unquote)
        .collect()
}

/// The paths in `[workspace] members`: only that table, only that key,
/// comments ignored, and nothing that could hide a crate accepted.
fn workspace_members(manifest: &str) -> Result<Vec<String>, String> {
    let mut table = "";
    let mut array: Option<String> = None;
    for raw in manifest.lines() {
        let line = without_comment(raw).trim();
        if let Some(open) = array.as_mut() {
            open.push_str(line);
        } else if line.starts_with('[') {
            table = line.trim_matches(['[', ']', ' ']);
        } else if table == "workspace" {
            array = value_of(line, "members").map(str::to_owned);
        }
        if array.as_deref().is_some_and(|text| text.ends_with(']')) {
            break;
        }
    }
    let array = array.ok_or("there is no `members` key in the `[workspace]` table")?;
    if !array.ends_with(']') {
        return Err("the `members` array is never closed".to_owned());
    }
    let members = strings(&array)?;
    if members.is_empty() {
        return Err("`members` is empty, so there is nothing to check a table against".to_owned());
    }
    let mut seen = BTreeSet::new();
    for member in &members {
        if member.contains(['*', '?', '[', ']']) {
            return Err(format!(
                "`{member}` is a glob: name each crate, so none hides in it"
            ));
        }
        if !seen.insert(*member) {
            return Err(format!("`{member}` is listed twice"));
        }
    }
    Ok(members.into_iter().map(str::to_owned).collect())
}

/// The name in a crate manifest's `[package]` table.
fn package_name(manifest: &str) -> Result<String, String> {
    let mut in_package = false;
    for raw in manifest.lines() {
        let line = without_comment(raw).trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package {
            if let Some(value) = value_of(line, "name") {
                return unquote(value).map(str::to_owned);
            }
        }
    }
    Err("there is no `name` in the `[package]` table".to_owned())
}

// --- reading an inventory table ---------------------------------------------

/// One crate row of an inventory table.
#[derive(Debug, PartialEq, Eq)]
struct Row {
    name: String,
    /// The `M2b` of `**in review (M2b).**`, when the description opens with it.
    in_review: Option<String>,
}

/// A row's first cell and everything after it. Only the first cell is split
/// off, so a `|` inside a later cell's code span cannot shift the columns.
fn first_cell(row: &str) -> Option<(&str, &str)> {
    let (first, rest) = row.trim().strip_prefix('|')?.split_once('|')?;
    Some((first.trim(), rest.trim()))
}

/// A crate's name: alone in the first cell, in backticks, and spelled the way
/// Cargo allows a package name to be.
fn crate_name(cell: &str) -> Result<&str, String> {
    let name = cell
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'));
    match name {
        Some(plain)
            if !plain.is_empty()
                && plain.chars().all(|c| {
                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
                }) =>
        {
            Ok(plain)
        }
        _ => Err(format!("`{cell}` is not a crate name alone in backticks")),
    }
}

/// The label of an `**in review (M2b).**` marker the description opens with.
fn in_review(description: &str) -> Option<&str> {
    let (label, _) = description
        .strip_prefix(IN_REVIEW_OPEN)?
        .split_once(IN_REVIEW_CLOSE)?;
    (!label.is_empty()).then_some(label)
}

/// The crate rows of the first table after the one line that opens with
/// `anchor`: a heading, which is stable, rather than a position in the file.
fn inventory(doc: &str, anchor: &str) -> Result<Vec<Row>, String> {
    let opens = doc.lines().filter(|line| line.starts_with(anchor)).count();
    if opens != 1 {
        return Err(format!(
            "expected one line opening with `{anchor}`, found {opens}"
        ));
    }
    let mut table = doc
        .lines()
        .skip_while(|line| !line.starts_with(anchor))
        .skip(1)
        .skip_while(|line| !line.trim_start().starts_with('|'))
        .take_while(|line| line.trim_start().starts_with('|'));
    let header = table
        .next()
        .ok_or_else(|| format!("no table follows `{anchor}`"))?;
    if first_cell(header).map(|(first, _)| first) != Some("Crate") {
        return Err(format!(
            "the table after `{anchor}` is not a Crate table: `{header}`"
        ));
    }
    let rule = table.next().unwrap_or_default();
    let is_rule = rule.trim().trim_matches('|').split('|').all(|cell| {
        let cell = cell.trim();
        !cell.is_empty() && cell.chars().all(|c| c == '-' || c == ':')
    });
    if !is_rule {
        return Err(format!(
            "the header is not followed by a rule row: `{rule}`"
        ));
    }
    let rows = table
        .map(|row| {
            let (first, rest) = first_cell(row).ok_or_else(|| format!("`{row}` is not a row"))?;
            Ok(Row {
                name: crate_name(first)?.to_owned(),
                in_review: in_review(rest).map(str::to_owned),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if rows.is_empty() {
        return Err(format!("the table after `{anchor}` has no rows"));
    }
    Ok(rows)
}

/// Everything wrong with an inventory, given the names of the workspace's
/// members. Empty means the table is the workspace.
fn problems(doc: &str, rows: &[Row], members: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let name = &row.name;
        if !seen.insert(name.as_str()) {
            found.push(format!("{doc} has two rows for `{name}`"));
        }
        match (&row.in_review, members.contains(name)) {
            (None, false) => found.push(format!(
                "{doc} names `{name}`, which is not a workspace member and is not marked \
                 `{IN_REVIEW_OPEN}M2b{IN_REVIEW_CLOSE}`"
            )),
            (Some(label), true) => found.push(format!(
                "{doc} still marks `{name}` in review ({label}), but it is a workspace member: \
                 delete the marker"
            )),
            _ => {}
        }
    }
    for member in members {
        if !seen.contains(member.as_str()) {
            found.push(format!("{doc} has no row for workspace member `{member}`"));
        }
    }
    found
}

// --- reading a count --------------------------------------------------------

const NUMBER_WORDS: [&str; 31] = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
    "twenty",
    "twenty-one",
    "twenty-two",
    "twenty-three",
    "twenty-four",
    "twenty-five",
    "twenty-six",
    "twenty-seven",
    "twenty-eight",
    "twenty-nine",
    "thirty",
];

/// The number a line gives for its crates: the word or digits just before the
/// first ` crates`. A word this does not know is no count, never a guess.
fn claimed_count(line: &str) -> Option<usize> {
    let word = line
        .split_once(" crates")?
        .0
        .split_whitespace()
        .next_back()?
        .to_ascii_lowercase();
    word.parse()
        .ok()
        .or_else(|| NUMBER_WORDS.iter().position(|known| *known == word))
}

// --- the real files ---------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(MANIFEST_DIR)
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn read(root: &Path, relative: &str) -> String {
    let path = root.join(relative);
    fs::read_to_string(&path).unwrap_or_else(|why| panic!("cannot read {}: {why}", path.display()))
}

/// The package name of every workspace member.
fn members(root: &Path) -> Vec<String> {
    let paths = workspace_members(&read(root, "Cargo.toml")).unwrap_or_else(|why| panic!("{why}"));
    paths
        .iter()
        .map(|path| {
            package_name(&read(root, &format!("{path}/Cargo.toml")))
                .unwrap_or_else(|why| panic!("{path}: {why}"))
        })
        .collect()
}

fn inventory_problems(file: &str, anchor: &str) -> Vec<String> {
    let root = workspace_root();
    match inventory(&read(&root, file), anchor) {
        Ok(rows) => problems(file, &rows, &members(&root)),
        Err(why) => vec![format!("{file}: {why}")],
    }
}

fn assert_clean(found: &[String]) {
    assert!(
        found.is_empty(),
        "a crate inventory has drifted from the workspace in Cargo.toml. A merged crate needs its \
         row (and no `{IN_REVIEW_OPEN}…{IN_REVIEW_CLOSE}` marker); a crate still in review needs \
         its row marked:\n{}",
        found.join("\n")
    );
}

#[test]
fn claude_md_crate_table_is_exactly_the_workspace_members() {
    assert_clean(&inventory_problems("CLAUDE.md", "## Crate layout"));
}

#[test]
fn the_design_plans_crate_layout_is_exactly_the_workspace_members() {
    assert_clean(&inventory_problems(
        "docs/design-plan.md",
        "### Crate layout",
    ));
}

#[test]
fn the_todo_indexs_done_table_is_exactly_the_workspace_members() {
    assert_clean(&inventory_problems(
        "docs/todo/README.md",
        "## Where the project actually stands",
    ));
}

#[test]
fn the_design_plans_crate_count_is_the_manifests() {
    let root = workspace_root();
    let plan = read(&root, "docs/design-plan.md");
    let mut hits = plan
        .lines()
        .filter(|line| line.contains("crates, not five"));
    let (Some(line), None) = (hits.next(), hits.next()) else {
        panic!("docs/design-plan.md must have exactly one line saying `<N> crates, not five`");
    };
    let members = members(&root).len();
    assert_eq!(
        claimed_count(line),
        Some(members),
        "docs/design-plan.md says `{line}`, but Cargo.toml has {members} workspace members"
    );
}

#[test]
fn the_check_is_looking_at_this_workspace_and_not_at_nothing() {
    let names = members(&workspace_root());
    for expected in ["aido-policy", "aido-sys-raw", "aido-gate", "aido-tests"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} is not read as a member"
        );
    }
}

// --- the readers, against every shape that could hide a crate ---------------

#[test]
fn the_manifest_reader_refuses_every_shape_that_could_hide_a_member() {
    for (case, manifest) in [
        ("no workspace table", "[package]\nname = \"x\"\n"),
        (
            "a workspace with no members",
            "[workspace]\nresolver = \"3\"\n",
        ),
        (
            "members under another table",
            "[workspace]\nresolver = \"3\"\n[workspace.metadata]\nmembers = [\"crates/a\"]\n",
        ),
        (
            "only default-members",
            "[workspace]\ndefault-members = [\"crates/a\"]\n",
        ),
        ("a glob", "[workspace]\nmembers = [\"crates/*\"]\n"),
        ("an empty list", "[workspace]\nmembers = []\n"),
        (
            "every entry commented out",
            "[workspace]\nmembers = [\n  # \"crates/a\",\n]\n",
        ),
        (
            "an array that never closes",
            "[workspace]\nmembers = [\n  \"crates/a\",\n",
        ),
        (
            "a member listed twice",
            "[workspace]\nmembers = [\"crates/a\", \"crates/a\"]\n",
        ),
        ("an unquoted entry", "[workspace]\nmembers = [crates/a]\n"),
        (
            "an escaped entry",
            "[workspace]\nmembers = [\"crates/\\u0061\"]\n",
        ),
    ] {
        assert!(workspace_members(manifest).is_err(), "{case}");
    }
}

#[test]
fn the_manifest_reader_reads_the_members_the_way_cargo_does() {
    let spread = "[workspace]\nresolver = \"3\"\nmembers = [\n  \"crates/a\", # first\n  \
                  # \"crates/gone\",\n  'crates/b',\n]\nexclude = [\"fuzz\"]\n\n\
                  [workspace.package]\nversion = \"0.0.1\"\n";
    assert_eq!(workspace_members(spread).unwrap(), ["crates/a", "crates/b"]);

    let inline = "[workspace]\nmembers = [\"crates/a\", \"crates/b\"] # all of them\n";
    assert_eq!(workspace_members(inline).unwrap(), ["crates/a", "crates/b"]);

    let hash = "[workspace]\nmembers = [\"crates/a#b\"]\n";
    assert_eq!(workspace_members(hash).unwrap(), ["crates/a#b"]);
}

#[test]
fn the_package_name_is_the_package_tables_and_not_a_bin_targets() {
    let bin_last = "[package]\nname = \"aido-bin\"\n\n[[bin]]\nname = \"aido\"\n";
    assert_eq!(package_name(bin_last).unwrap(), "aido-bin");
    let bin_first = "[[bin]]\nname = \"aido\"\n[package]\nname = \"aido-bin\" # the crate\n";
    assert_eq!(package_name(bin_first).unwrap(), "aido-bin");
    assert!(package_name("[[bin]]\nname = \"aido\"\n").is_err());
}

/// A document whose crate table holds `rows`, with a pipe in the prose above
/// it and a stray row after it, neither of which is part of the table.
fn doc(rows: &str) -> String {
    format!(
        "# Doc\n\n## Crates\n\nA | in the prose.\n\n| Crate | Role |\n|---|---|\n{rows}\nAfter.\n\n\
         | `stray` | Not part of the table. |\n"
    )
}

#[test]
fn the_table_reader_reads_the_table_and_stops_where_it_stops() {
    let rows = inventory(
        &doc("| `a` | The first, with `x|y` in code. |\n\
              | `b` | **in review (M2b).** Not merged. |\n\
              | `c-1_d` | A name Cargo allows. |\n"),
        "## Crates",
    )
    .unwrap();
    let expected = [
        Row {
            name: "a".into(),
            in_review: None,
        },
        Row {
            name: "b".into(),
            in_review: Some("M2b".into()),
        },
        Row {
            name: "c-1_d".into(),
            in_review: None,
        },
    ];
    assert_eq!(rows, expected);
}

#[test]
fn a_review_marker_in_the_middle_of_a_description_marks_nothing() {
    let rows = inventory(
        &doc("| `a` | Its binary is **in review (M2b).** here. |\n"),
        "## Crates",
    );
    assert_eq!(
        rows.unwrap(),
        [Row {
            name: "a".into(),
            in_review: None
        }]
    );
}

#[test]
fn the_table_reader_refuses_a_table_it_cannot_be_sure_is_the_crate_table() {
    let head = "## Crates\n\n| Crate | Role |\n|---|---|\n";
    for (case, text) in [
        ("no anchor", "# Doc\n".to_owned()),
        (
            "the anchor twice",
            format!("{head}| `a` | x |\n{head}| `b` | x |\n"),
        ),
        (
            "no table after the anchor",
            "## Crates\n\nJust text.\n".to_owned(),
        ),
        (
            "a table of something else",
            "## Crates\n\n| Item | Role |\n|---|---|\n| `a` | x |\n".into(),
        ),
        (
            "no rule under the header",
            "## Crates\n\n| Crate | Role |\n| `a` | x |\n".to_owned(),
        ),
        ("a name not in backticks", format!("{head}| aido | x |\n")),
        (
            "a name with a space",
            format!("{head}| `aido tool` | x |\n"),
        ),
        ("two names in a cell", format!("{head}| `a` `b` | x |\n")),
        ("an empty table", head.to_owned()),
    ] {
        assert!(inventory(&text, "## Crates").is_err(), "{case}");
    }
}

fn rows(spec: &[(&str, bool)]) -> Vec<Row> {
    let marked = |review: bool| review.then(|| "M2b".to_owned());
    spec.iter()
        .map(|(name, review)| Row {
            name: (*name).to_owned(),
            in_review: marked(*review),
        })
        .collect()
}

#[test]
fn the_checker_accepts_a_table_that_is_the_workspace_plus_crates_in_review() {
    let members = ["a", "b"].map(String::from);
    assert!(
        problems(
            "doc",
            &rows(&[("a", false), ("b", false), ("c", true)]),
            &members
        )
        .is_empty()
    );
}

#[test]
fn the_checker_reports_every_way_an_inventory_can_drift() {
    let members = ["a", "b"].map(String::from);
    for (case, spec, expected) in [
        (
            "a member with no row",
            &[("a", false)][..],
            "no row for workspace member `b`",
        ),
        (
            "a row for a crate that is gone",
            &[("a", false), ("b", false), ("gone", false)][..],
            "names `gone`, which is not a workspace member",
        ),
        (
            "a merged crate still marked in review",
            &[("a", false), ("b", true)][..],
            "still marks `b` in review",
        ),
        (
            "a crate listed twice",
            &[("a", false), ("a", false), ("b", false)][..],
            "two rows for `a`",
        ),
    ] {
        let found = problems("doc", &rows(spec), &members);
        assert!(
            found.iter().any(|problem| problem.contains(expected)),
            "{case}: {found:?}"
        );
    }
}

#[test]
fn a_count_is_read_from_words_and_from_digits_and_never_guessed() {
    for (line, count) in [
        ("> - Thirteen crates, not five.", Some(13)),
        ("**Done.** 13 crates, below.", Some(13)),
        ("- seventeen crates", Some(17)),
        ("- Thirty crates", Some(30)),
        ("- Thirty-one crates", None),
        ("- thirteen member crates", None),
        ("- many crates", None),
        ("- no count at all", None),
    ] {
        assert_eq!(claimed_count(line), count, "{line}");
    }
}
